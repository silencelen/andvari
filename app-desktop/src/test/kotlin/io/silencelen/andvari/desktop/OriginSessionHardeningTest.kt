package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import java.io.File
import java.net.InetSocketAddress
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import io.silencelen.andvari.core.crypto.MemberRecovery
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Security review 2026-10, branch A12 — invite-origin switching and session storage.
 *
 * Invariant under test: no password-derived value, token or vault-cache decision may be driven by
 * an origin the user has not signed in to or verified.
 *
 *  - row 39: a second invite re-point while one is pending, then Cancel, must land on the HOME
 *    origin — never on the first, unverified one with the sign-in lockout lifted.
 *  - row 80: a late policy reply from an abandoned origin must not replace the current origin's.
 *  - row 81: tokens never reach session.json when at-rest storage was declined.
 *  - row 82: the rescue copy's total bound is independent of the co-member-controlled item count.
 */
class OriginSessionHardeningTest {
    private val root = Files.createTempDirectory("andvari-desktop-a12-test").toFile()
    private val servers = mutableListOf<HttpServer>()

    /** Captures launched coroutines and never runs them (the EndpointSwitchTest idiom). */
    private class QueueDispatcher : CoroutineDispatcher() {
        override fun dispatch(context: CoroutineContext, block: Runnable) { /* captured, never run */ }
    }
    private val inertScope = CoroutineScope(QueueDispatcher())

    /** One real thread (the DesktopAsyncFlowsTest idiom) for the probe-race tests. */
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "andvari-a12-test").apply { isDaemon = true } }
    private val liveScope = CoroutineScope(executor.asCoroutineDispatcher())

    @AfterTest
    fun cleanup() {
        inertScope.cancel()
        liveScope.cancel()
        executor.shutdownNow()
        servers.forEach { it.stop(0) }
        root.deleteRecursively()
    }

    private fun storeAt(baseUrl: String) = DesktopSessionStore(root).also { it.baseUrl = baseUrl }

    private fun awaitUntil(what: String, timeoutMs: Long = 15_000, cond: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cond()) return
            Thread.sleep(10)
        }
        fail("timed out after ${timeoutMs}ms waiting for: $what")
    }

    /** A policy server. [hold], when given, parks the reply until it is counted down; [arrived]
     *  is counted down when the request lands (so the test knows the probe is in flight). */
    private fun policyServer(fingerprint: String, offlineCacheAllowed: Boolean, hold: CountDownLatch? = null, arrived: CountDownLatch? = null): String {
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        s.executor = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
        s.createContext("/api/v1/client-policy") { ex ->
            arrived?.countDown()
            hold?.await(20, TimeUnit.SECONDS)
            runCatching {
                val body = """{"recoveryFingerprint":"$fingerprint","offlineCacheAllowed":$offlineCacheAllowed}""".toByteArray()
                ex.responseHeaders.add("Content-Type", "application/json")
                ex.sendResponseHeaders(200, body.size.toLong())
                ex.responseBody.use { it.write(body) }
            }
            ex.close()
        }
        s.start()
        servers += s
        return "http://127.0.0.1:${s.address.port}"
    }

    // ---- row 39: the restore point is the verified home origin, captured once ----

    @Test
    fun cancelAfterASecondRepointRestoresHomeNotTheFirstUnverifiedOrigin() {
        val store = storeAt("https://home.example")
        val state = DesktopState(inertScope, store)

        state.beginEnrollSwitch("https://hostile.example", "m@x")
        state.trustGateConnect() // now dialing hostile (runtime only)
        state.beginEnrollSwitch("https://other.example", "m@x") // paste again
        state.cancelPendingSwitch()

        assertNull(state.pendingServer)
        assertEquals("https://home.example", state.baseUrl, "Cancel must land on HOME, never on the unverified first origin")
        assertEquals("https://home.example", store.baseUrl)
    }

    @Test
    fun aSecondRepointReplacesTheTargetButNeverTheRestorePoint() {
        val store = storeAt("https://home.example")
        val state = DesktopState(inertScope, store)

        state.beginEnrollSwitch("https://hostile.example", "m@x")
        state.trustGateConnect()
        state.beginEnrollSwitch("https://other.example", "m@x")

        assertEquals("https://other.example", state.pendingServer?.origin, "the pending target is replaced")
        assertEquals("https://home.example", state.pendingReturnOrigin, "the restore point never moves to a pending origin")
        assertFalse(state.pendingConnected, "the new target is behind its own gate")
        assertEquals("https://home.example", state.baseUrl, "nothing keeps dialing the first unverified origin behind the second gate")

        state.trustGateConnect()
        assertEquals("https://other.example", state.baseUrl)
        state.cancelPendingSwitch()
        assertEquals("https://home.example", state.baseUrl)
    }

    @Test
    fun anUnconnectedSecondRepointThenCancelStillRestoresHome() {
        val store = storeAt("https://home.example")
        val state = DesktopState(inertScope, store)
        state.beginEnrollSwitch("https://hostile.example", "m@x")
        state.beginEnrollSwitch("https://other.example", "m@x") // neither connected
        state.cancelPendingSwitch()
        assertEquals("https://home.example", state.baseUrl)
        assertNull(state.pendingReturnOrigin)
    }

    @Test
    fun signInIsRefusedWhileTheAppDialsAnUnverifiedOrigin() {
        // The lockout at the STATE layer: the UI hides Sign in while a switch is pending, but a
        // stale frame or a future caller must not be able to post an authKey to the pending origin.
        val store = storeAt("https://home.example")
        val state = DesktopState(inertScope, store)
        state.beginEnrollSwitch("https://hostile.example", "m@x")
        state.trustGateConnect()

        state.signIn("m@x", "correct horse battery staple")

        assertNotNull(state.error, "sign-in against an unverified origin is refused with a message")
        assertFalse(state.busy, "the refusal never starts an op")
    }

    // ---- row 80: a late reply from an abandoned origin never lands ----

    @Test
    fun aLatePolicyReplyFromAnAbandonedOriginDoesNotReplaceHomesPolicy() {
        val home = policyServer("home-fp", offlineCacheAllowed = true)
        val hold = CountDownLatch(1)
        val arrived = CountDownLatch(1)
        val hostile = policyServer("hostile-fp", offlineCacheAllowed = false, hold = hold, arrived = arrived)

        val store = storeAt(home)
        val state = DesktopState(liveScope, store)

        state.beginEnrollSwitch(hostile, "m@x")
        state.trustGateConnect()
        assertTrue(arrived.await(10, TimeUnit.SECONDS), "the hostile probe is in flight")

        state.cancelPendingSwitch() // back to home; home's probe answers at once
        awaitUntil("home's policy to apply") { state.policy?.recoveryFingerprint == "home-fp" }

        hold.countDown() // the abandoned origin answers late
        Thread.sleep(500)
        awaitUntil("the executor to drain") { true }

        assertEquals("home-fp", state.policy?.recoveryFingerprint, "the abandoned origin's late reply must not replace home's policy")
        assertEquals(true, state.policy?.offlineCacheAllowed, "a hostile offlineCacheAllowed=false must never reach home's next bind")
        assertTrue(store.orgCacheAllowed(originKey(home)), "home's persisted fallback is untouched")
    }

    @Test
    fun aPolicyProbeThatNeverAnswersIsBounded() {
        val hold = CountDownLatch(1) // never released
        val blackHole = policyServer("never", offlineCacheAllowed = true, hold = hold)
        val store = storeAt("https://home.example")
        val state = DesktopState(liveScope, store, policyProbeTimeoutMs = 300)

        state.beginEnrollSwitch(blackHole, "m@x")
        state.trustGateConnect()

        awaitUntil("the probe to give up", timeoutMs = 10_000) { state.policyFetchFailed }
        assertNull(state.policy)
        hold.countDown()
    }

    // ---- row 81: declined at-rest storage keeps the tokens in memory only ----

    @Test
    fun theStoreKeepsTokensInMemoryWhenAtRestStorageIsDeclined() {
        val store = DesktopSessionStore(root)
        store.tokensAtRest = false
        store.save(DesktopSession("https://home.example", "u1", "m@x", "access", "refresh"))

        assertFalse(File(root, "session.json").exists(), "no token may reach disk")
        assertEquals("access", store.load()?.accessToken, "the running app still holds the session")
        assertNull(DesktopSessionStore(root).load(), "a restart re-authenticates: nothing was persisted")
    }

    @Test
    fun decliningConsentMovesAPersistedSessionOffDisk() {
        val store = storeAt("https://home.example")
        store.setOrgCacheAllowed(originKey("https://home.example"), true)
        store.save(DesktopSession("https://home.example", "u1", "m@x", "access", "refresh"))
        assertTrue(File(root, "session.json").exists())
        val state = DesktopState(inertScope, store)

        state.answerCacheConsent(false)

        assertFalse(File(root, "session.json").exists(), "a declined at-rest store must not leave tokens in session.json")
        assertEquals("refresh", store.load()?.refreshToken, "the live session is kept in memory")
    }

    @Test
    fun anOrgForbidMovesAPersistedSessionOffDisk() {
        val home = policyServer("home-fp", offlineCacheAllowed = false)
        val store = storeAt(home)
        store.setCacheConsent(originKey(home), true)
        store.save(DesktopSession(home, "u1", "m@x", "access", "refresh"))
        val state = DesktopState(liveScope, store)

        state.start()
        awaitUntil("start() to route") { state.screen !is DesktopScreen.Loading }

        assertFalse(File(root, "session.json").exists(), "an org that forbids at-rest storage gets no tokens on disk")
        assertEquals("m@x", (state.screen as? DesktopScreen.Unlock)?.email, "this run still offers Unlock")
    }

    @Test
    fun grantingConsentPersistsTheMemorySession() {
        val store = DesktopSessionStore(root)
        store.tokensAtRest = false
        store.save(DesktopSession("https://home.example", "u1", "m@x", "access", "refresh"))
        store.tokensAtRest = true
        assertTrue(File(root, "session.json").exists(), "allowing at-rest storage writes the held session")
        assertEquals("access", DesktopSessionStore(root).load()?.accessToken)
    }

    @Test
    fun tokenPersistenceFollowsBothLegs() {
        assertTrue(tokensMayPersist(orgAllowed = true, consent = true))
        // A12 review LOW-3: an unanswered prompt is NOT consent — memory only until it is answered.
        assertFalse(tokensMayPersist(orgAllowed = true, consent = null), "an unanswered prompt does not allow at-rest storage")
        assertFalse(tokensMayPersist(orgAllowed = true, consent = false), "the user declined")
        assertFalse(tokensMayPersist(orgAllowed = false, consent = true), "the org declined")
        assertFalse(tokensMayPersist(orgAllowed = false, consent = null))
    }

    // ---- row 82: the rescue copy is bounded independent of item count ----

    @Test
    fun theRescueCopyBoundIgnoresAHugeItemCount() {
        val honest = DesktopState.rescueCopyTimeoutMs(bytes = 0, itemCount = 3, perItemMs = 60_000)
        assertEquals(DesktopState.attachmentTimeoutMs(0) + 3 * 60_000, honest, "a small vault keeps its full budget")
        val hostile = DesktopState.rescueCopyTimeoutMs(bytes = Long.MAX_VALUE, itemCount = 5_000, perItemMs = 60_000)
        assertEquals(DesktopState.RESCUE_COPY_CEILING_MS, hostile, "5,000 co-member items cannot buy 83 hours")
        assertTrue(DesktopState.rescueCopyTimeoutMs(0, Int.MAX_VALUE, Long.MAX_VALUE) <= DesktopState.RESCUE_COPY_CEILING_MS, "no overflow past the ceiling")
    }

    // ---- A12 review LOW-1: the recovery path honours the pending-switch lockout ----

    /** A hostile origin that answers its policy and COUNTS every recovery request it is sent. */
    private fun countingHostile(hits: AtomicInteger): String {
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        s.createContext("/api/v1/client-policy") { ex ->
            val body = """{"recoveryFingerprint":"hostile-fp"}""".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, body.size.toLong()); ex.responseBody.use { it.write(body) }
        }
        s.createContext("/api/v1/recovery") { ex -> hits.incrementAndGet(); ex.sendResponseHeaders(500, -1); ex.close() }
        s.start(); servers += s
        return "http://127.0.0.1:${s.address.port}"
    }

    /** Home answers its policy and a (structurally valid, cryptographically dummy) verify. */
    private fun recoveryHome(): String {
        val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        s.createContext("/api/v1/client-policy") { ex ->
            val body = """{"recoveryFingerprint":"home-fp"}""".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, body.size.toLong()); ex.responseBody.use { it.write(body) }
        }
        s.createContext("/api/v1/recovery/self/verify") { ex ->
            val body = """{"userId":"u1","recoveryTicket":"t","recoveryWrappedUvk":"AA","encryptedIdentitySeed":"AA","identityPub":"AA"}""".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, body.size.toLong()); ex.responseBody.use { it.write(body) }
        }
        s.start(); servers += s
        return "http://127.0.0.1:${s.address.port}"
    }

    private val phrase = MemberRecovery.displayForm(ByteArray(32) { 7 })

    @Test
    fun recoverVerifyIsRefusedWhileTheAppDialsAnUnverifiedOrigin() {
        val hits = AtomicInteger(0)
        val hostile = countingHostile(hits)
        val store = storeAt("https://home.example")
        val state = DesktopState(liveScope, store)
        state.beginEnrollSwitch(hostile, "m@x")
        state.trustGateConnect()
        awaitUntil("the hostile policy to land") { state.policy != null }

        state.recoverVerifySubmit("m@x", phrase)
        Thread.sleep(500)

        assertEquals(DesktopState.RECOVERY_LOCKED_OUT, state.recoverError, "recover verify is refused with the lockout copy")
        assertFalse(state.busy)
        assertEquals(0, hits.get(), "no recovery authKey reaches the unverified origin")
    }

    @Test
    fun recoverResetIsRefusedWhileTheAppDialsAnUnverifiedOrigin() {
        val hits = AtomicInteger(0)
        val home = recoveryHome()
        val hostile = countingHostile(hits)
        val store = storeAt(home)
        val state = DesktopState(liveScope, store)
        state.openRecover("m@x")
        awaitUntil("home's policy") { state.policy != null && !state.busy }
        state.recoverVerifySubmit("m@x", phrase)
        awaitUntil("phase 1 to pass at home") { state.recoverVerified }

        state.beginEnrollSwitch(hostile, "m@x") // a pasted invite while the reset is staged
        state.trustGateConnect()
        awaitUntil("the hostile policy to land") { state.policy?.recoveryFingerprint == "hostile-fp" }

        state.recoverCommitSubmit("Tr0ub4dor&3-horse-Battery")
        Thread.sleep(500)

        assertEquals(DesktopState.RECOVERY_LOCKED_OUT, state.recoverError, "recover reset is refused with the lockout copy")
        assertFalse(state.busy)
        assertEquals(0, hits.get(), "no reset commit reaches the unverified origin")
    }

    // ---- A12 review LOW-3: an unanswered consent prompt keeps the tokens off disk ----

    @Test
    fun anUnansweredConsentPromptKeepsTokensOffDisk() {
        val home = policyServer("home-fp", offlineCacheAllowed = true)
        val store = storeAt(home)
        // consent never answered (null), org allows
        store.save(DesktopSession(home, "u1", "m@x", "access", "refresh"))
        val state = DesktopState(liveScope, store)

        state.start()
        awaitUntil("start() to route") { state.screen !is DesktopScreen.Loading }

        assertFalse(File(root, "session.json").exists(), "consent null: nothing in session.json")
        assertEquals("access", store.load()?.accessToken, "the run keeps its session in memory")
    }
}
