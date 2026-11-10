package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.ClientPolicy
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Step 5: the manual server switch and its policy probe, against in-memory seams. */
class ServerSwitchTest {
    private val home = "https://home.example"
    private val other = "https://other.example"
    private val homeKey = OriginCanon.originKey(home)

    private val clocks = FakeClocks(wall = 5_000L)
    private val store = FakeSessionPersistence(home)
    private val session = VaultSession(clocks)
    private val artifacts = RecordingArtifacts()
    private val coordinator = PolicyCoordinator(store, artifacts, session, clocks, OriginProbeFence())

    private val json = Json { encodeDefaults = true }
    private val headers = headersOf(HttpHeaders.ContentType, "application/json")
    private fun policyJson(p: ClientPolicy = ClientPolicy()) = json.encodeToString(ClientPolicy.serializer(), p)

    /** What the server under test answers; a test swaps it. */
    private var answer: suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData = { respond(policyJson(), HttpStatusCode.OK, headers) }

    private val http = object : HttpClients {
        override fun create() = HttpClient(MockEngine { answer(it) })
        override val wirePlatform = "test"
        override val deviceName = "test device"
    }
    private val clients = SessionClients(http, store, coordinator)
    private val switch = ServerSwitch(store, session, coordinator, clients, setOf("127.0.0.1"))

    private companion object {
        val crypto = createCryptoProvider()
        val account: Account by lazy {
            val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            val fp = Escrow.fingerprint(crypto, recovery.publicKey)
            Account.enroll("invite", "u@example.com", "u", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fp, "device", crypto).account
        }
    }

    private fun storedSession(origin: String = home) = StoredSession(origin, "u1", "u@example.com", "a", "r").also { store.save(it) }

    // ---- prepare: what a typed address means (§4.4) ----

    @Test
    fun anAddressWithAUserinfoPathOrQueryIsRefused() {
        assertEquals(ServerAddress.Invalid, switch.prepare("https://real.example@evil.example"))
        assertEquals(ServerAddress.Invalid, switch.prepare("https://home.example/login"))
        assertEquals(ServerAddress.Invalid, switch.prepare("https://home.example?next=x"))
        assertEquals(ServerAddress.Invalid, switch.prepare("not a url"))
    }

    @Test
    fun theCurrentOriginRetypedNeedsNoGate() {
        assertEquals(ServerAddress.Current("https://home.example"), switch.prepare("https://HOME.example:443/"))
    }

    @Test
    fun aRealChangeShowsTheRawOriginOnTheGate() {
        val idn = assertIs<ServerAddress.NeedsGate>(switch.prepare("https://XN--bcher-kva.example"))
        assertEquals("https://xn--bcher-kva.example", idn.origin)
        assertEquals("https://xn--bcher-kva.example", idn.render.displayOrigin, "the punycode the client dials, never the lookalike")
        assertTrue(idn.render.punycodeCaution)
        val lan = assertIs<ServerAddress.NeedsGate>(switch.prepare("http://192.168.1.9:8080"))
        assertTrue(lan.render.cleartextBlocked, "a platform's cleartext ban is said before Connect")
    }

    @Test
    fun aFirstChoiceWithNoOriginYetIsGated() {
        store.baseUrl = null // iOS first launch: no default server
        assertIs<ServerAddress.NeedsGate>(switch.prepare(home))
    }

    // ---- connect: probe first, commit second (audit F27) ----

    @Test
    fun anUnreachableTargetChangesNothing() = runBlocking<Unit> {
        storedSession()
        answer = { throw IOException("connect timed out") }
        val r = switch.connect(other)
        assertIs<SwitchResult.Unreachable>(r)
        assertEquals(home, store.baseUrl, "the origin stays")
        assertNotNull(store.stored, "and so does the session")
        assertTrue(store.writes.isEmpty())
    }

    @Test
    fun aTargetThatAnsweredBecomesTheOriginAndEndsTheOldSession() = runBlocking<Unit> {
        storedSession()
        val live = clients.forSession(store.stored!!, home)
        session.bind(live, account, SyncEngine(live, account, InMemoryVaultCache()))
        answer = { respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers) } // any answer counts
        val r = assertIs<SwitchResult.Switched>(switch.connect(other))
        assertEquals(other, r.origin)
        assertTrue(r.droppedSession)
        assertNull(session.get(), "the old session's api and engine closed before anything reached the new origin")
        assertNull(store.stored)
        assertEquals(listOf("drop-session", "origin:$other"), store.writes, "§4.1 rule 1 / F8: the tokens go before the origin moves")
    }

    @Test
    fun theProbeOfTheTargetCarriesNoToken() = runBlocking<Unit> {
        storedSession()
        var sawAuth: String? = "unset"
        answer = { request -> sawAuth = request.headers[HttpHeaders.Authorization]; respond(policyJson(), HttpStatusCode.OK, headers) }
        switch.connect(other)
        assertNull(sawAuth, "no bearer crosses an origin change, the probe included")
    }

    // ---- moveTo ----

    @Test
    fun aRespelledOriginKeepsTheSession() {
        storedSession()
        assertFalse(switch.moveTo("https://HOME.example/"))
        assertNotNull(store.stored)
        assertEquals(listOf("origin:https://HOME.example/"), store.writes)
    }

    @Test
    fun aProbeStartedBeforeAMoveIsStaleAndTheLivePolicyIsForgotten() {
        val tag = coordinator.tag(homeKey)
        assertTrue(coordinator.applyPolicy(ClientPolicy(autoLockSeconds = 60), tag))
        assertNotNull(coordinator.livePolicy)
        val late = coordinator.tag(homeKey)
        switch.moveTo(other)
        assertNull(coordinator.livePolicy, "the live policy was the old origin's")
        assertFalse(coordinator.applyPolicy(ClientPolicy(autoLockSeconds = 30), late), "a late reply from the abandoned origin writes nothing")
    }

    // ---- probePolicy ----

    @Test
    fun aForbiddingAnswerIsAppliedAndPurgesThatOriginsNamespace() = runBlocking<Unit> {
        storedSession()
        answer = { respond(policyJson(ClientPolicy(offlineCacheAllowed = false, autoLockSeconds = 60)), HttpStatusCode.OK, headers) }
        val r = assertIs<PolicyProbe.Applied>(switch.probePolicy())
        assertFalse(r.policy.offlineCacheAllowed)
        assertFalse(store.origin(homeKey).cacheAllowed, "the mirror is written")
        assertEquals(60, store.origin(homeKey).autoLockSeconds)
        assertEquals(listOf("blob:$homeKey/u1", "cache:$homeKey/u1"), artifacts.events, "the stored session's namespace at the probed origin")
        assertFalse(coordinator.cacheAllowed(homeKey))
    }

    @Test
    fun anAnswerThatLandsAfterTheClientMovedWritesNothing() = runBlocking<Unit> {
        answer = {
            switch.moveTo(other) // the user re-pointed while the probe of home was in flight
            respond(policyJson(ClientPolicy(offlineCacheAllowed = false)), HttpStatusCode.OK, headers)
        }
        assertEquals(PolicyProbe.Stale, switch.probePolicy())
        assertTrue(store.origin(homeKey).cacheAllowed, "home's mirror is untouched")
        assertTrue(artifacts.events.isEmpty())
    }

    @Test
    fun aFailedProbeSaysWhetherItWasStillCurrent() = runBlocking<Unit> {
        answer = { throw IOException("unreachable") }
        val r = assertIs<PolicyProbe.Failed>(switch.probePolicy())
        assertTrue(r.current)
        store.baseUrl = null
        assertEquals(PolicyProbe.NoOrigin, switch.probePolicy(), "nothing to probe before an origin is chosen")
    }
}
