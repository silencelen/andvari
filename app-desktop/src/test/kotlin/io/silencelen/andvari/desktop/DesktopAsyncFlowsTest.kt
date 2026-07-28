package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
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
}
