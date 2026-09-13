package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.AttachmentRef
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executors
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * quality-tests--5 (polish audit 2026-07-27): the desktop suite's ONLY harness was
 * [EndpointSwitchTest]'s QueueDispatcher, which deliberately captures launched coroutines and never
 * runs them — so every asynchronous path in [DesktopState] (the launch-time probe, op()'s error
 * routing, the sign-out revoke-then-teardown) had ZERO executed coverage while looking covered.
 * This is the complement: a dispatcher that really RUNS them, against a real local HTTP server, so
 * the assertions are on what the coroutine actually did.
 *
 * Deliberately narrow: the flows reachable without a bound [io.silencelen.andvari.core.client.SyncEngine]
 * (which needs a live account + master-password KDF). The engine-gated lane — runSync's
 * single-flight/timeout and the backup verify — stays inspection-only for now; the idle lock, the
 * one engine-gated rule that is pure decision-making, is covered below via [idleLockDecision].
 */
class DesktopAsyncFlowsTest {
    private val root = Files.createTempDirectory("andvari-desktop-async-test").toFile()

    // The deliberate opposite of EndpointSwitchTest's QueueDispatcher: one real thread that
    // executes what DesktopState launches. Single-threaded so the launched work is serialized and
    // the assertions below can't interleave with a half-applied state write.
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "andvari-async-test").apply { isDaemon = true } }
    private val scope = CoroutineScope(executor.asCoroutineDispatcher())
    private var server: HttpServer? = null

    @AfterTest
    fun cleanup() {
        scope.cancel()
        executor.shutdownNow()
        server?.stop(0)
        root.deleteRecursively()
    }

    /** Poll for an asynchronous outcome. The launched work crosses threads (ktor's IO threads
     *  resume onto our dispatcher), so there is no join to await — a bounded poll is the honest
     *  shape, and a timeout FAILS rather than falling through to a vacuous assertion. */
    private fun awaitUntil(what: String, timeoutMs: Long = 15_000, cond: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cond()) return
            Thread.sleep(10)
        }
        fail("timed out after ${timeoutMs}ms waiting for: $what")
    }

    private fun storeAt(baseUrl: String) = DesktopSessionStore(root).also { it.baseUrl = baseUrl }

    /** A port nothing is listening on — bind then release, so the connect is REFUSED immediately
     *  (an unroutable address would instead sit on the 10 s connect timeout). */
    private fun closedPort(): Int = ServerSocket(0).use { it.localPort }

    // ---- ux-parity--4 + op()'s 426 branch, executed end to end ----

    /**
     * The A9 escape's load-bearing half: a 426 raises the blocking screen, and sign-out must LIFT
     * it. Both legs are launched coroutines, so neither had ever run under test — and a signOut
     * that left `upgradeRequired` set would re-brick the app over Welcome, making the new escape
     * button a no-op that LOOKS like it worked.
     */
    @Test
    fun aServerVersionPinBlocksAndSignOutIsTheEscape() {
        val logoutAuth = ConcurrentHashMap<String, String>()
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server = s
        s.createContext("/api/v1/auth/prelogin") { ex ->
            // The contract errorFrom() keys on is the BODY code, not the 426 status.
            val body = """{"error":"upgrade_required","message":"this client is too old"}""".toByteArray()
            ex.sendResponseHeaders(426, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        s.createContext("/api/v1/auth/logout") { ex ->
            logoutAuth["seen"] = ex.requestHeaders.getFirst("Authorization") ?: ""
            ex.sendResponseHeaders(204, -1)
            ex.close()
        }
        s.start()
        val base = "http://127.0.0.1:${s.address.port}"

        val store = storeAt(base)
        store.save(DesktopSession(base, "u1", "e@x", "access-A", "refresh-A"))
        val state = DesktopState(scope, store)

        state.signIn("e@x", "hunter2")
        awaitUntil("the 426 to raise the blocking screen") { state.upgradeRequired != null }
        assertFalse(state.busy, "the 426 branch releases busy — the blocking screen is not a spinner")
        assertNull(state.error, "a 426 is the blocking screen, never also a per-action error toast")

        state.signOut()
        awaitUntil("sign-out to land on Welcome") { state.screen is DesktopScreen.Welcome }

        assertNull(state.upgradeRequired, "sign-out must LIFT the 426 block or the escape re-bricks over Welcome")
        assertNull(store.load(), "the persisted session is gone")
        assertFalse(state.busy)
        // …and the revoke leg really ran: a LOCKED sign-out builds a short-lived holder purely to
        // revoke the persisted refresh token (the fire-and-forget version left it valid ~30 days).
        assertEquals("Bearer access-A", logoutAuth["seen"], "sign-out must await a REAL authorized logout")
    }

    // ---- start(): the launch-time probe, executed ----

    /**
     * §3 honesty flag. start() launches the policy probe and routes the first screen off it; with
     * the probe inert (QueueDispatcher) neither effect existed. An offline cold start must land on
     * the stored session's Unlock screen AND admit the probe failed — the flag is what stops the
     * enroll pane rendering "no recovery key configured" off a fetch that never answered.
     */
    @Test
    fun offlineStartAdmitsTheProbeFailedAndRoutesToTheStoredSession() {
        val base = "http://127.0.0.1:${closedPort()}" // connection refused, not a timeout
        val store = storeAt(base)
        store.save(DesktopSession(base, "u1", "member@example.org", "access-A", "refresh-A"))
        val state = DesktopState(scope, store)

        state.start()
        awaitUntil("start() to route off the failed probe") { state.screen !is DesktopScreen.Loading }

        assertIs<DesktopScreen.Unlock>(state.screen).let { assertEquals("member@example.org", it.email) }
        assertTrue(state.policyFetchFailed, "a refused probe must be admitted, never rendered as a verdict")
        assertNull(state.policy, "nothing was learned, so no policy is published")
    }

    /** The same launch path with NO stored session lands on Welcome (and still admits the failure). */
    @Test
    fun offlineStartWithoutASessionLandsOnWelcome() {
        val store = storeAt("http://127.0.0.1:${closedPort()}")
        val state = DesktopState(scope, store)

        state.start()
        awaitUntil("start() to route off the failed probe") { state.screen !is DesktopScreen.Loading }

        assertIs<DesktopScreen.Welcome>(state.screen)
        assertTrue(state.policyFetchFailed)
    }

    /**
     * §4.3 (B2-9) reconcile runs INSIDE start()'s coroutine, before anything trusts the stored
     * session — the ordering the switch state machine rests on, and the one leg EndpointSwitchTest
     * could only drive by calling reconcilePendingMarker() by hand.
     */
    @Test
    fun startReconcilesAnUncommittedSwitchMarkerBeforeRouting() {
        val store = storeAt("http://127.0.0.1:${closedPort()}")
        store.setPendingServer(PendingServer("https://invite.example", "new@x", 1))
        val state = DesktopState(scope, store)

        state.start()
        awaitUntil("start() to reconcile the marker") { state.pendingReconcile != null }

        assertEquals("https://invite.example", assertNotNull(state.pendingReconcile).origin)
    }

    // ---- the idle lock's decision rule (spec 01 §8), exhaustively ----

    /**
     * The auto-lock is the security control with the widest blast radius on this client and it had
     * no coverage at all: it lives on the 1 Hz watcher the QueueDispatcher never ran. The rule is
     * now a pure function ([idleLockDecision]), so the whole matrix is assertable here.
     */
    @Test
    fun idleLockWaitsInsideTheWindowAndLocksPastIt() {
        // 60 s window: 59 s idle waits, 60 s locks (the boundary is inclusive of the lock).
        assertEquals(IdleLockDecision.Wait, idleLockDecision(60, 59_999, opInFlight = false, editorOpen = false, recoveryRevealUp = false))
        assertEquals(IdleLockDecision.Lock, idleLockDecision(60, 60_000, opInFlight = false, editorOpen = false, recoveryRevealUp = false))
        assertEquals(IdleLockDecision.Lock, idleLockDecision(60, 10 * 60_000, opInFlight = false, editorOpen = false, recoveryRevealUp = false))
    }

    @Test
    fun anInFlightOpDefersTheLockWithoutStandingTheWarningDown() {
        // Defer, NOT Wait: an op finishing is not the user coming back, so an already-raised
        // imminent warning must survive it (maybeIdleLock only clears the flag on Wait).
        assertEquals(IdleLockDecision.Defer, idleLockDecision(60, 10 * 60_000, opInFlight = true, editorOpen = false, recoveryRevealUp = false))
        assertEquals(IdleLockDecision.Defer, idleLockDecision(60, 0, opInFlight = true, editorOpen = true, recoveryRevealUp = false))
    }

    @Test
    fun anOpenEditorBuysOneBoundedGraceAndNoMore() {
        // (v2 #15): the editor's draft is remember-scoped and dies with the screen swap, so a
        // walked-away editor gets ONE extra window — and is told the clock is running.
        assertEquals(IdleLockDecision.GraceImminent, idleLockDecision(60, 60_000, opInFlight = false, editorOpen = true, recoveryRevealUp = false))
        assertEquals(IdleLockDecision.GraceImminent, idleLockDecision(60, 119_999, opInFlight = false, editorOpen = true, recoveryRevealUp = false))
        // …and no more: the grace serves the walked-away editor, it never disables the lock.
        assertEquals(IdleLockDecision.Lock, idleLockDecision(60, 120_000, opInFlight = false, editorOpen = true, recoveryRevealUp = false))
    }

    @Test
    fun theEditorGraceIsCappedSoALongWindowOrgDoesNotSeeItsLockDouble() {
        // 30 min window: the grace caps at EDITOR_LOCK_GRACE_MAX_MS (5 min), not another 30.
        assertEquals(5L * 60 * 1000, editorGraceMs(30 * 60))
        assertEquals(60_000L, editorGraceMs(60), "under the cap the grace is one whole window")
        val window = 30 * 60
        assertEquals(IdleLockDecision.GraceImminent, idleLockDecision(window, window * 1000L + 4 * 60_000, opInFlight = false, editorOpen = true, recoveryRevealUp = false))
        assertEquals(IdleLockDecision.Lock, idleLockDecision(window, window * 1000L + 5 * 60_000, opInFlight = false, editorOpen = true, recoveryRevealUp = false))
    }

    @Test
    fun aMidRevealRecoveryPhraseGetsNoGrace() {
        // §F.7: the shown-once phrase is ON SCREEN — leaving it up on an unattended machine is the
        // worse trade, and the §F.9 capture gate re-issues a fresh one at the next unlock.
        assertEquals(IdleLockDecision.Lock, idleLockDecision(60, 60_000, opInFlight = false, editorOpen = true, recoveryRevealUp = true))
    }

    @Test
    fun theClampIsWhatStopsAHostileServerDisablingTheLock() {
        // §2.3 (B1-1): a server-supplied 0 ("never lock") clamps to the CEILING, never to "off" —
        // so even the most hostile policy still locks; it just locks late.
        assertEquals(IdleLockDecision.Lock, idleLockDecision(clampAutoLockSeconds(0), Long.MAX_VALUE / 2, opInFlight = false, editorOpen = false, recoveryRevealUp = false))
        assertEquals(IdleLockDecision.Wait, idleLockDecision(clampAutoLockSeconds(0), 60_000, opInFlight = false, editorOpen = false, recoveryRevealUp = false))
    }

    // ---- audit H10: every op{} is bounded — executed against a server that accepts and never answers ----

    /**
     * G10 bounded the attachment download and the two pre-export syncs; the other op{} legs still
     * held [DesktopState.busy] over an unbounded call on the connect-only client, and the idle lock
     * returns Defer on every tick while busy is up — so a black-holed server held the vault
     * unlocked for as long as it held the socket. This is the black hole: the TCP accept succeeds,
     * the prelogin exchange never answers. With the op bound injected at 1.5 s, busy must clear
     * and the failure must read as the canon's transport row (a timeout IS an IOException), never
     * "Sign-in failed. Please try again."
     */
    @Test
    fun aBlackHoledServerCannotHoldBusyPastTheOpBound() {
        val release = CountDownLatch(1)
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server = s
        s.createContext("/api/v1/auth/prelogin") { ex ->
            release.await(60, TimeUnit.SECONDS) // never answers within the test's lifetime
            ex.sendResponseHeaders(204, -1); ex.close()
        }
        s.start()
        val base = "http://127.0.0.1:${s.address.port}"
        val state = DesktopState(scope, storeAt(base), opTimeoutMs = 1_500)
        try {
            val t0 = System.currentTimeMillis()
            state.signIn("e@x", "hunter2")
            awaitUntil("busy to be released by the op bound", timeoutMs = 10_000) { !state.busy }
            val took = System.currentTimeMillis() - t0
            assertTrue(took < 8_000, "the bound fired at ~1.5 s, not the 10 s connect cap or never (took ${took}ms)")
            // op()'s catch clears `busy` one statement BEFORE it assigns `error`, and this thread
            // polls both from outside the coroutine — so on a loaded machine the wait above can
            // win that gap and read a null error (it did, once the suite grew). Compose never sees
            // the gap (both are read in the same frame); only a poller can, so the wait belongs
            // here rather than a reorder in production code.
            awaitUntil("the op's error to be published after busy cleared", timeoutMs = 5_000) { state.error != null }
            assertEquals(HouseholdCopy.UNREACHABLE, state.error, "a timeout maps to the transport row, never the 'try again' fallback")
            assertNull(state.upgradeRequired)
        } finally {
            release.countDown()
        }
    }

    /** The size-scaled bounds for the byte-carrying legs, as pure arithmetic. */
    @Test
    fun theByteCarryingLegsScaleTheirBoundWithTheBytesTheyMove() {
        val flat = DesktopState.SYNC_TIMEOUT_MS
        val rate = DesktopState.ATTACHMENT_MIN_BYTES_PER_SEC
        assertEquals(flat, DesktopState.attachmentTimeoutMs(0))
        assertEquals(flat, DesktopState.uploadsTimeoutMs(emptyList()), "a save with no uploads gets the flat window")
        val oneMiB = PendingUpload(AttachmentRef("a", "a.bin", 1L shl 20, "k"), ByteArray(1 shl 20))
        assertEquals(flat + (1L shl 20) * 1000 / rate, DesktopState.uploadsTimeoutMs(listOf(oneMiB)))
        assertEquals(flat + 2 * (1L shl 20) * 1000 / rate, DesktopState.uploadsTimeoutMs(listOf(oneMiB, oneMiB)), "the total across uploads, not the largest")
        // Import: one flat window per pushed batch (never open-ended, never absurdly short for a big file).
        assertEquals(flat, DesktopState.importTimeoutMs(0))
        assertEquals(2 * flat, DesktopState.importTimeoutMs(1))
        // R18: sized off core's own (public) batch constant — no hand copy to drift.
        assertEquals(2 * flat, DesktopState.importTimeoutMs(SyncEngine.SERVER_BATCH_MAX))
        assertEquals(3 * flat, DesktopState.importTimeoutMs(SyncEngine.SERVER_BATCH_MAX + 1))
        assertEquals(51 * flat, DesktopState.importTimeoutMs(10_000))
    }

    // ---- audit H12: the CR-02 idle cap on the self-recovery reset step ----

    /**
     * Web's Recover.tsx bounds the window in which the raw recovery secret (UVK-equivalent, spec 05
     * R9) sits in memory: 300 s idle, then zero it and bounce to sign-in with a notice. The natives
     * copied the two-phase flow and not the clock — and the reset step runs pre-session, so the
     * vault idle lock never reaches it. Executed here: a fake verify accepts, the injected 1.5 s cap
     * elapses with no interaction, and the flow must be gone — secret zeroed, screen left, web's
     * notice up — without anyone pressing anything.
     */
    @Test
    fun anAcceptedRecoveryPhraseExpiresAfterTheIdleCapWithWebsNotice() {
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server = s
        s.createContext("/api/v1/recovery/self/verify") { ex ->
            val body = """{"userId":"u1","recoveryTicket":"t","recoveryWrappedUvk":"AA","encryptedIdentitySeed":"AA","identityPub":"AA"}""".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        s.start()
        val base = "http://127.0.0.1:${s.address.port}"
        val state = DesktopState(scope, storeAt(base), recoverIdleTimeoutMs = 1_500)
        val phrase = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })

        state.openRecover()
        awaitUntil("the recover screen") { state.screen is DesktopScreen.Recover }
        // openRecover kicks a policy re-probe under busy (the reset step needs kdfParams); the
        // verify submit is busy-gated, so let the (404) probe land first.
        awaitUntil("the policy probe to settle") { !state.busy }
        state.recoverVerifySubmit("member@example.org", phrase)
        awaitUntil("verify to accept and arm the clock") { state.recoverVerified }

        awaitUntil("the idle cap to expire the reset step") { !state.recoverVerified && state.screen !is DesktopScreen.Recover }
        assertIs<DesktopScreen.Welcome>(state.screen, "no stored session ⇒ the expiry lands on Welcome, exactly like Cancel")
        assertEquals(DesktopState.RECOVER_TIMEOUT_NOTICE, state.notice, "web's REVEAL_TIMEOUT_NOTICE, byte-equal")
        assertNull(state.recoverError)
    }

    @Test
    fun theRecoverIdleRuleExpiresOnlyWhenIdleForTheWholeWindowAndNoCommitIsInFlight() {
        val window = DesktopState.RECOVER_IDLE_TIMEOUT_MS
        assertEquals(300_000L, window, "web parity: REVEAL_TIMEOUT_S = 300")
        assertFalse(recoverIdleExpired(window - 1, window, busy = false))
        assertTrue(recoverIdleExpired(window, window, busy = false))
        assertTrue(recoverIdleExpired(10 * window, window, busy = false))
        // A commit in flight defers ONE tick — Account.recover is reading the secret — but never
        // stands the clock down (the next idle tick past busy expires it).
        assertFalse(recoverIdleExpired(10 * window, window, busy = true))
    }
}
