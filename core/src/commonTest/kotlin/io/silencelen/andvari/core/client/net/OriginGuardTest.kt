package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogHost
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §4.4 "The stop is enforced where the client dials" (hostile-server finding H1) and "A fork stops traffic, not
 * reading": every request through the guard to a forked, damaged or unreadable origin is refused before it is sent, the
 * token refresh included, and the engine's own stores neither sign nor write under such a pin. Traffic is recorded at
 * the client below the guard (and, for the [Dialer], at the HTTP engine), so "nothing is sent" is observed, not assumed.
 */
class OriginGuardTest {
    private val crypto = createCryptoProvider()
    private val origin = "https://home.example"
    private val userId = "22222222-2222-4222-8222-222222222222"

    /** Records every call that reaches it and answers nothing useful. */
    private class Recording(override val origin: String) : WireClient {
        val calls = ArrayList<WireRoute>()
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += route
            return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        }
    }

    private fun pin(o: String = origin) = CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), o, "Home", "private",
        "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64))

    private fun forked(state: DeviceState = MemoryDeviceState()): DeviceState = state.also { PinStore(it).put(pin()); PinStore(it).markForked(pin()) }

    private fun damaged(state: DeviceState = MemoryDeviceState()): DeviceState = state.also { it.set(PinStore.KEY_PREFIX + origin, "{not a pin") }

    private fun unreadable(): DeviceState = object : DeviceState {
        override fun get(key: String): String? = throw IllegalStateException("storage locked")
        override fun set(key: String, value: String?) = throw IllegalStateException("storage locked")
    }

    @Test fun everyRouteToAStoppedOriginIsRefusedBeforeItIsSent() = runBlocking<Unit> {
        for ((why, state) in listOf("forked" to forked(), "damaged" to damaged(), "unreadable" to unreadable())) {
            val inner = Recording(origin)
            val c = OriginGuard(PinStore(state)).guard(inner)
            assertTrue(c.stopped, why)
            for (route in WireRoute.entries) {
                assertTrue(c.call(route, decode = { it }).originStopped, "$why: $route")
            }
            assertTrue(inner.calls.isEmpty(), "$why: nothing reached the network layer")
        }
    }

    @Test fun anUnpinnedOriginAndAPinInForceAreDialed() = runBlocking<Unit> {
        // The Trust Gate's public card fetch needs an origin with no pin; a pin in force is open too.
        val none = Recording(origin)
        assertTrue(!OriginGuard(PinStore(MemoryDeviceState())).guard(none).call(WireRoute.INSTANCE, decode = { it }).originStopped)
        assertEquals(listOf(WireRoute.INSTANCE), none.calls)
        val pinned = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val inner = Recording(origin)
        val c = OriginGuard(PinStore(pinned)).guard(inner)
        assertTrue(!c.stopped)
        c.call(WireRoute.SYNC, decode = { it })
        assertEquals(listOf(WireRoute.SYNC), inner.calls)
    }

    @Test fun aForkMarkedDuringASessionStopsTheNextRequestOfAClientAlreadyHandedOut() = runBlocking<Unit> {
        val state = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val inner = Recording(origin)
        val c = OriginGuard(PinStore(state)).guard(inner)
        c.call(WireRoute.SYNC, decode = { it })
        PinStore(state).markForked(pin())
        assertTrue(c.call(WireRoute.PUSH, bodyJson = "{}", decode = { it }).originStopped)
        assertEquals(listOf(WireRoute.SYNC), inner.calls)
    }

    @Test fun theDialerSendsNothingAndRefreshesNoTokenUnderAFork() = runBlocking<Unit> {
        var requests = 0
        val http = HttpClient(MockEngine { requests++; respond("""{"error":"invalid_credentials","message":"m"}""", HttpStatusCode.Unauthorized) })
        var refreshes = 0
        var reads = 0
        val tokens = object : TokenSource {
            override fun accessToken(): String { reads++; return "t" }
            override suspend fun refresh(staleAccessToken: String): Boolean { refreshes++; return true }
        }
        val state = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val dialer = Dialer(PinStore(state), http, "linux")
        val c = dialer.open(origin, tokens)
        c.call(WireRoute.SYNC, decode = { it })
        assertTrue(requests > 0 && refreshes == 1, "in force: sent, and a 401 refreshes once")
        val sent = requests
        PinStore(state).markForked(pin())
        assertTrue(!dialer.guard.mayDial(origin), "a WebSocket asks the same guard")
        val tokenReads = reads
        for (route in listOf(WireRoute.SYNC, WireRoute.PUSH, WireRoute.ACCOUNT_STATE_GET, WireRoute.ACCOUNT_STATE_PUT, WireRoute.LOG_FETCH, WireRoute.LOG_APPEND, WireRoute.REFRESH)) {
            assertTrue(c.call(route, mapOf("vaultId" to "v1"), decode = { it }).originStopped, "$route")
        }
        assertEquals(sent, requests, "no request left the device")
        assertEquals(1, refreshes, "no token refresh")
        assertEquals(tokenReads, reads, "not even the bearer was read")
        val guardedTokens = dialer.guard.guard(origin, tokens)
        assertNull(guardedTokens.accessToken())
        assertTrue(!guardedTokens.refresh("t"))
    }

    @Test fun attachmentBytesGoThroughTheSameGuardBearerAndRefresh() = runBlocking<Unit> {
        val seen = ArrayList<String>()
        val http = HttpClient(MockEngine { req ->
            val auth = req.headers["Authorization"]
            seen += "${req.method.value} ${req.url.encodedPath}?${req.url.encodedQuery} $auth ${req.body.contentType}"
            when {
                auth == "Bearer old" -> respond("""{"error":"invalid_credentials","message":"m"}""", HttpStatusCode.Unauthorized)
                req.method.value == "POST" -> respond("""{"attachmentId":"a1"}""", HttpStatusCode.OK)
                req.url.encodedPath.endsWith("/missing") -> respond("""{"error":"not_found","message":"m"}""", HttpStatusCode.NotFound)
                else -> respond(byteArrayOf(0, 1, 2, -1), HttpStatusCode.OK)
            }
        })
        var token = "old"
        val tokens = object : TokenSource {
            override fun accessToken() = token
            override suspend fun refresh(staleAccessToken: String): Boolean { token = "new"; return true }
        }
        val state = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val c = Dialer(PinStore(state), http, "linux").open(origin, tokens)
        val up = assertIs<WireResult.Ok<String>>(c.callBytes(WireRoute.ATTACHMENT_UPLOAD, mapOf("attachmentId" to "a1"), "vaultId=v&itemId=i", byteArrayOf(9, 8, 7), decode = { it }))
        assertTrue("a1" in up.value)
        assertTrue(seen.last().startsWith("POST /api/v1/attachments/a1?vaultId=v&itemId=i Bearer new application/octet-stream"), seen.last())
        val down = assertIs<WireResult.Ok<ByteArray>>(c.fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to "a1")))
        assertTrue(down.value.contentEquals(byteArrayOf(0, 1, 2, -1)))
        assertEquals("not_found", assertIs<WireResult.Refused>(c.fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to "missing"))).code)
        assertEquals(KtorWireClient.BAD_PATH_SEGMENT, assertIs<WireResult.Refused>(c.fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to "../x"))).code)
        val before = seen.size
        PinStore(state).markForked(pin())
        assertTrue(c.callBytes(WireRoute.ATTACHMENT_UPLOAD, mapOf("attachmentId" to "a2"), null, byteArrayOf(1), decode = { it }).originStopped)
        assertTrue(c.fetchBytes(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to "a1")).originStopped)
        assertEquals(before, seen.size, "no attachment traffic under a fork")
    }

    // ---- the engine's stores under a stopped origin: nothing signed, nothing written, nothing sent ----

    private fun host() = object : VaultLogHost {
        override fun grantRow(vaultId: String): SyncGrant? = null
        override fun isCurrentContact(userId: String, identityPub: String) = false
        override fun currentContact(userId: String): Pair<String, Boolean>? = null
        override fun labelFor(userId: String, identityPub: String): String? = null
        override fun vaultName(vaultId: String, vk: ByteArray): String? = null
        override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
        override fun serverOwnerName(vaultId: String): String? = null
    }

    /** A device state that records every write after [arm]. */
    private class Watched(private val inner: MemoryDeviceState = MemoryDeviceState()) : DeviceState {
        var armed = false
        val writes = ArrayList<String>()
        fun arm() { armed = true }
        override fun get(key: String) = inner.get(key)
        override fun set(key: String, value: String?) { if (armed) writes += key; inner.set(key, value) }
        override fun keys() = inner.keys()
    }

    @Test fun underAForkNoVaultLogIsSignedFetchedOrWrittenAndNoAccountStateIsReadOrWritten() = runBlocking<Unit> {
        val state = Watched()
        forked(state)
        val inner = Recording(origin)
        val client = OriginGuard(PinStore(state)).guard(inner)
        val account = StoredAccountState(userId, ByteArray(32) { 3 }, client, crypto, state)
        val seed = ByteArray(32) { 5 }
        val logs = StoredVaultLogs(userId, crypto.signKeypairFromSeed(seed), crypto.boxKeypairFromSeed(seed), ByteArray(32) { 3 }, client, crypto,
            state, account, host(), { 1_763_164_800_000 }, { null })
        state.arm()
        assertEquals(AppendOutcome.NotAllowed(ORIGIN_STOPPED), logs.append(null, LogAction.Create("Family")))
        assertEquals(AppendOutcome.NotAllowed(ORIGIN_STOPPED), logs.append("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", LogAction.Leave))
        logs.refresh("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", null, null, force = true)
        logs.noteItemHead("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 3, "c".repeat(64))
        logs.retryPending()
        assertEquals(AccountStateRead.Stopped(ORIGIN_STOPPED), account.read())
        assertEquals(AccountStateWrite.Refused(ORIGIN_STOPPED), account.update { it.copy(seq = it.seq) })
        assertTrue(inner.calls.isEmpty(), "nothing was sent: ${inner.calls}")
        assertTrue(state.writes.isEmpty(), "nothing was written: ${state.writes}")
    }

    // ---- design §4.4 "A trust record that cannot be read is not an empty one" ----

    @Test fun anAccountCopyOrMarkThatCannotBeReadStopsReadAndUpdateAndIsNeverOverwritten() = runBlocking<Unit> {
        for (key in listOf("ovh.acct|$userId|sealed", "ovh.acct|$userId|hw")) {
            val state = Watched()
            state.set(key, "garbage")
            val inner = Recording(origin)
            val account = StoredAccountState(userId, ByteArray(32) { 3 }, inner, crypto, state)
            state.arm()
            assertTrue(!account.localReadable(), key)
            assertEquals(AccountStateRead.Stopped(StoredAccountState.RECORD_UNREADABLE), account.read(), key)
            assertEquals(AccountStateWrite.Refused(StoredAccountState.RECORD_UNREADABLE), account.update { it }, key)
            account.raiseHighWater(9)
            assertTrue(inner.calls.isEmpty(), "$key: nothing fetched")
            assertTrue(state.writes.isEmpty(), "$key: nothing written over it: ${state.writes}")
        }
    }

    @Test fun aVaultWhoseTrustRecordsCannotBeReadIsClosedAndNotRebuiltFromTheServer() = runBlocking<Unit> {
        val vault = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
        for (key in listOf("hashes", "pending")) {
            val state = Watched()
            state.set("ovh.log|$userId|$vault|$key", "garbage")
            val inner = Recording(origin)
            val account = StoredAccountState(userId, ByteArray(32) { 3 }, inner, crypto, state)
            val seed = ByteArray(32) { 5 }
            val logs = StoredVaultLogs(userId, crypto.signKeypairFromSeed(seed), crypto.boxKeypairFromSeed(seed), ByteArray(32) { 3 }, inner, crypto,
                state, account, host(), { 1_763_164_800_000 }, { null })
            state.arm()
            assertEquals(StoredVaultLogs.RECORD_UNREADABLE, assertIs<VaultLogStatus.Failed>(logs.refresh(vault, null, null, force = true), key).verdict)
            assertTrue(!logs.writeAllowed(vault))
            assertTrue(inner.calls.isEmpty(), "$key: nothing fetched")
            assertTrue(state.writes.isEmpty(), "$key: nothing written: ${state.writes}")
        }
    }

    @Test fun aDeviceStateFileThatDoesNotParseIsNeverReadAsEmptyNorWrittenOver() {
        var text: String? = "{not json"
        var replaced = 0
        val s = JsonDeviceState(object : DeviceStateFile {
            override fun read(): String? = text
            override fun replace(text: String) { replaced++ }
        })
        assertFailsWith<IllegalStateException> { s.get(PinStore.KEY_PREFIX + origin) }
        assertFailsWith<IllegalStateException> { s.set("k", "v") }
        assertEquals(0, replaced, "the whole map is never written back over a file that does not parse")
        assertEquals(io.silencelen.andvari.core.client.pin.PinState.Damaged, PinStore(s).state(origin), "and a pin in it reads as damaged")
        text = null
        assertNull(s.get("k"))
    }
}
