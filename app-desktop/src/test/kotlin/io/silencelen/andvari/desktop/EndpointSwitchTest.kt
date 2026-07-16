package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpServer
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.Tokens
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import java.io.File
import java.net.InetSocketAddress
import java.nio.file.Files
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.CoroutineContext
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * §4.1/§4.3/§4.4 endpoint-switch state machine + token isolation (design
 * 2026-07-15-multi-tenant-endpoints, desktop lane): the invite-driven pending switch commits ONLY on
 * enrollment success, cancel/reconcile revert to the prior origin, and NO bearer token ever crosses
 * a baseUrl change (B1-5, the HARD MUST).
 *
 * DesktopState's launched coroutines (the idle/poll loops + the async policy probe) are captured by a
 * queue dispatcher and never run, so every assertion is on the SYNCHRONOUS switch effects — no
 * network, no flakiness. The token-isolation HTTP proof uses a real header-capturing server against
 * the shared [AndvariApi].
 */
class EndpointSwitchTest {
    private val root = Files.createTempDirectory("andvari-desktop-switch-test").toFile()

    // A dispatcher that QUEUES launched coroutines without ever running them — the probe/idle/poll
    // coroutines are inert, so the tests observe only the synchronous state transitions.
    private class QueueDispatcher : CoroutineDispatcher() {
        override fun dispatch(context: CoroutineContext, block: Runnable) { /* captured, never run */ }
    }
    private val scope = CoroutineScope(QueueDispatcher())

    @AfterTest
    fun cleanup() {
        scope.cancel()
        root.deleteRecursively()
    }

    private fun storeAt(dir: File = root, baseUrl: String): DesktopSessionStore =
        DesktopSessionStore(dir).also { it.baseUrl = baseUrl }

    // ---- §4.1 rule 1 (B1-5): token isolation over a baseUrl change ----

    // The exact contract, at the HTTP layer with a real header-capturing server: a TOKENED client
    // sends Authorization (the baseline the switch must break); the client the desktop rebuilds for
    // the new origin is TOKENLESS (newApi()'s tokens default null once session.json is dropped), so
    // NO Authorization crosses.
    @Test
    fun noAuthorizationHeaderCrossesABaseUrlChange() = runBlocking {
        val seen = ConcurrentHashMap<String, Boolean>()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/") { ex ->
            seen[ex.requestURI.path] = ex.requestHeaders.getFirst("Authorization") != null
            ex.sendResponseHeaders(200, -1)
            ex.close()
        }
        server.start()
        val base = "http://127.0.0.1:${server.address.port}"
        try {
            // origin A, holding a live session → Authorization IS sent (sanity: the header exists to leak)
            val tokened = AndvariApi(base, HttpClient(Java), Tokens("access-A", "refresh-A"), platform = "linux")
            tokened.logout()
            tokened.close()
            assertEquals(true, seen["/api/v1/auth/logout"], "a tokened client must send Authorization")

            // origin B, after the switch dropped session.json → the rebuilt client carries no bearer
            seen.clear()
            val switched = AndvariApi(base, HttpClient(Java), null, platform = "linux")
            switched.logout()
            switched.close()
            assertEquals(false, seen["/api/v1/auth/logout"], "no Authorization may cross a baseUrl change")
        } finally {
            server.stop(0)
        }
    }

    // The store half of the token drop: a switch removes session.json (the token source) but PRESERVES
    // the origin's at-rest namespace (B2-7 — a switch is not a sign-out; a round trip keeps A's cache).
    @Test
    fun clearSessionDropsTokensButKeepsOriginNamespace() {
        val store = storeAt(baseUrl = "https://home.example")
        val a = originKey("https://home.example")
        store.save(DesktopSession("https://home.example", "u1", "e@x", "at", "rt"))
        store.nsDir(a, "u1").mkdirs()
        File(store.nsDir(a, "u1"), "account-keys.json").writeText("{}")
        store.cacheDbFile(a, "u1").writeText("cache")

        store.clearSession()

        assertNull(store.load(), "the persisted session (tokens) must be gone")
        assertTrue(File(store.nsDir(a, "u1"), "account-keys.json").exists(), "the origin's account-keys survive a switch (B2-7)")
        assertTrue(store.cacheDbFile(a, "u1").exists(), "the origin's vault cache survives a switch (B2-7)")
    }

    // ---- §4.3 (B2-9) crash-window marker persistence ----

    @Test
    fun pendingServerMarkerRoundTrips() {
        val store = DesktopSessionStore(root)
        assertNull(store.loadPendingServer())
        store.setPendingServer(PendingServer("https://invite.example", "new@x", 42))
        val m = store.loadPendingServer()!!
        assertEquals("https://invite.example", m.origin)
        assertEquals("new@x", m.email)
        assertEquals(42, m.ts)
        store.clearPendingServer()
        assertNull(store.loadPendingServer())
    }

    // ---- §4.4 Desktop: arm / connect / commit / cancel ----

    // Arming holds the pending origin WITHOUT switching anything (the gate is the gesture); Connect
    // dials it (runtime) + drops tokens, but the persisted default stays put — commit is deferred.
    @Test
    fun connectDialsPendingOriginDropsTokensButDoesNotCommit() {
        val store = storeAt(baseUrl = "https://home.example")
        store.save(DesktopSession("https://home.example", "u1", "e@x", "at", "rt")) // stale tokens the switch must not replay
        val state = DesktopState(scope, store)

        state.beginEnrollSwitch("https://invite.example", "new@x")
        assertEquals("https://invite.example", state.pendingServer?.origin)
        assertFalse(state.pendingConnected)
        assertEquals("https://home.example", state.baseUrl, "arming must not dial the pending origin")
        assertEquals("https://home.example", store.baseUrl, "arming must not commit the persisted default")

        state.trustGateConnect()
        assertTrue(state.pendingConnected)
        assertEquals("https://invite.example", state.baseUrl, "Connect dials the pending origin (runtime)")
        assertEquals("https://home.example", store.baseUrl, "the persisted default stays uncommitted until enroll success")
        assertNull(store.load(), "§4.1 rule 1: tokens dropped before the first request to the new origin")
    }

    // §4.1 rule 3: the persisted default commits ONLY through the enroll-success primitive, never on
    // Connect — and the crash marker drops with it.
    @Test
    fun commitOnlyOnEnrollSuccessMovesPersistedDefaultAndClearsMarker() {
        val store = storeAt(baseUrl = "https://home.example")
        val state = DesktopState(scope, store)
        state.beginEnrollSwitch("https://invite.example", "new@x")
        state.trustGateConnect()
        // enrollOp writes the marker before register; simulate that pre-register state:
        store.setPendingServer(PendingServer(state.baseUrl, "new@x", 1))
        assertEquals("https://home.example", store.baseUrl, "still uncommitted before register succeeds")

        state.commitPendingSwitch() // the enroll-SUCCESS primitive

        assertEquals("https://invite.example", store.baseUrl, "enroll success commits the persisted default")
        assertNull(store.loadPendingServer(), "the crash marker is dropped on commit")
        assertNull(state.pendingServer)
        assertFalse(state.pendingConnected)
    }

    // §4.4 Desktop: Cancel after Connect reverts the runtime origin to the (never-moved) prior
    // default; the persisted default was never touched.
    @Test
    fun cancelRevertsToPriorOrigin() {
        val store = storeAt(baseUrl = "https://home.example")
        val state = DesktopState(scope, store)
        state.beginEnrollSwitch("https://invite.example", "new@x")
        state.trustGateConnect()
        assertEquals("https://invite.example", state.baseUrl)

        state.cancelPendingSwitch()

        assertNull(state.pendingServer)
        assertFalse(state.pendingConnected)
        assertEquals("https://home.example", state.baseUrl, "cancel reverts the runtime origin to the prior default")
        assertEquals("https://home.example", store.baseUrl, "the persisted default never moved")
    }

    // ---- §4.4 Desktop: manual ServerField gate (commit-on-Connect) ----

    @Test
    fun manualSwitchGatesThenCommitsOnConnect() {
        val store = storeAt(baseUrl = "https://home.example")
        val state = DesktopState(scope, store)

        state.beginManualSwitch("https://other.example/") // trailing slash trimmed
        assertEquals("https://other.example", state.manualSwitchTarget, "the manual gate is armed, not yet committed")
        assertEquals("https://home.example", store.baseUrl)

        state.manualSwitchConnect() // the gate IS the gesture — commit
        assertNull(state.manualSwitchTarget)
        assertEquals("https://other.example", store.baseUrl, "a manual repoint commits at the gate")
        assertEquals("https://other.example", state.baseUrl)
    }

    @Test
    fun manualSwitchIgnoresNoopTarget() {
        val store = storeAt(baseUrl = "https://home.example")
        val state = DesktopState(scope, store)
        state.beginManualSwitch("https://home.example") // same origin
        assertNull(state.manualSwitchTarget)
    }

    // §4.4 (review 2026-07-16 MEDIUM): a userinfo/path input that would spoof the gate (`…@evil` shows
    // a reassuring host while dialing evil.example) is REFUSED — no gate armed, error surfaced, nothing
    // dialed — so it can never reach updateServer's dialer. Drives the real DesktopState (non-vacuous).
    @Test
    fun manualSwitchRefusesTheUserinfoPhishingVector() {
        val store = storeAt(baseUrl = "https://home.example")
        val state = DesktopState(scope, store)
        state.beginManualSwitch("https://home.example@evil.example") // reassuring prefix, HTTP dials evil.example
        assertNull(state.manualSwitchTarget, "a userinfo origin must NOT arm the gate")
        assertTrue(state.error != null, "the refusal is surfaced")
        assertEquals("https://home.example", store.baseUrl, "nothing dialed or committed")
    }

    @Test
    fun manualSwitchArmsWithTheCanonicalOrigin() {
        val store = storeAt(baseUrl = "https://home.example")
        val state = DesktopState(scope, store)
        state.beginManualSwitch("https://Other.Example:443/") // case + default port + trailing slash
        assertEquals("https://other.example", state.manualSwitchTarget, "the gate is armed with the CANONICAL origin, not the raw string")
    }

    // ---- §4.3 (B2-9) launch-time reconcile ----

    @Test
    fun reconcileUncommittedMarkerThenFinishRepoints() {
        val store = storeAt(baseUrl = "https://home.example")
        store.setPendingServer(PendingServer("https://invite.example", "new@x", 1))
        val state = DesktopState(scope, store)

        state.reconcilePendingMarker()
        assertEquals("https://invite.example", state.pendingReconcile?.origin, "an uncommitted marker owes a reconcile")

        state.finishPendingReconcile() // re-show the raw-origin (baseline) gate, then repoint
        assertNull(state.pendingReconcile)
        assertEquals("https://invite.example", state.manualSwitchTarget, "Finish routes through the raw-origin gate")
        assertNull(store.loadPendingServer())
    }

    @Test
    fun reconcileDiscardKeepsPriorOriginAndClearsMarker() {
        val store = storeAt(baseUrl = "https://home.example")
        store.setPendingServer(PendingServer("https://invite.example", "new@x", 1))
        val state = DesktopState(scope, store)

        state.reconcilePendingMarker()
        assertEquals("https://invite.example", state.pendingReconcile?.origin)

        state.discardPendingReconcile()
        assertNull(state.pendingReconcile)
        assertNull(store.loadPendingServer())
        assertEquals("https://home.example", store.baseUrl, "Discard keeps the prior default (never moved)")
    }

    // A crash between the store.baseUrl commit and the marker clear leaves a straggler whose origin
    // equals the committed default — no prompt, silent clear.
    @Test
    fun reconcileAlreadyCommittedMarkerClearsSilently() {
        val store = storeAt(baseUrl = "https://invite.example")
        store.setPendingServer(PendingServer("https://invite.example", "new@x", 1))
        val state = DesktopState(scope, store)

        state.reconcilePendingMarker()
        assertNull(state.pendingReconcile, "a committed straggler must not prompt")
        assertNull(store.loadPendingServer(), "and it is cleared silently")
    }
}
