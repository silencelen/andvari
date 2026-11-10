package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Step 7: sign-in and the same-origin enroll, against in-memory seams and a mock server. Both save the session
 * under the origin their client dialed and only while the client still dials it, write no tokens before the
 * commit, and land after their first sync only on a session that survived it.
 */
class SessionEntryTest {
    private val home = "https://home.example"
    private val other = "https://other.example"
    private val homeKey = OriginCanon.originKey(home)

    private val clocks = FakeClocks(wall = 1_000_000L, mono = 5_000L, boot = "7")
    private val store = FakeSessionPersistence(home)
    private val session = VaultSession(clocks)
    private val artifacts = RecordingArtifacts()
    private val coordinator = PolicyCoordinator(store, artifacts, session, clocks, OriginProbeFence())
    private val namespaces = FakeNamespaces()

    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }
    private val headers = headersOf(HttpHeaders.ContentType, "application/json")
    private val calls = mutableListOf<String>()
    private fun ok(body: String): suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData = { respond(body, HttpStatusCode.OK, headers) }
    private fun refused(code: String, status: HttpStatusCode = HttpStatusCode.Unauthorized): suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData =
        { respond("""{"error":"$code","message":"refused"}""", status, headers) }

    private fun HttpRequestData.text(): String = (body as OutgoingContent.ByteArrayContent).bytes().decodeToString()

    /** What the server answers, per route; a test swaps them. */
    private var prelogin = ok(json.encodeToString(PreloginResponse.serializer(), PreloginResponse(reg.kdfSalt, reg.kdfParams)))
    private var login: suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData = { respond(sessionJson(keys), HttpStatusCode.OK, headers) }
    private var register: suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData = { request ->
        val req = json.decodeFromString(RegisterRequest.serializer(), request.text())
        registered = req
        respond(sessionJson(keysOf(req), userId = req.userId, pieceId = "piece-1"), HttpStatusCode.OK, headers)
    }
    private var sync = ok(EMPTY_SYNC)
    private var registered: RegisterRequest? = null

    private val http = object : HttpClients {
        override fun create() = HttpClient(
            MockEngine { request ->
                val path = request.url.encodedPath
                calls += path
                when {
                    path.endsWith("/auth/prelogin") -> prelogin(request)
                    path.endsWith("/auth/login") -> login(request)
                    path.endsWith("/auth/register") -> register(request)
                    path.endsWith("/auth/logout") -> respond("{}", HttpStatusCode.OK, headers)
                    path.endsWith("/auth/refresh") -> refused("unauthorized")(request)
                    path.endsWith("/sync") -> sync(request)
                    else -> respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                }
            },
        )
        override val wirePlatform = "test"
        override val deviceName = "test device"
    }
    private val clients = SessionClients(http, store, coordinator)
    private val binder = SessionBinder(store, session, coordinator, namespaces, clocks)
    private val entry = SessionEntry(store, session, coordinator, clients, binder)

    /** The first sync after the bind: the engine's own. */
    private val engineSync: suspend (io.silencelen.andvari.core.client.SyncEngine) -> Unit = { it.sync() }

    private companion object {
        val crypto = createCryptoProvider()
        const val PASSWORD = "correct horse battery staple 42!"
        const val EMAIL = "u@example.com"
        const val DEVICE = "00000000-0000-4000-8000-000000000001"
        const val EMPTY_SYNC = """{"rev":1,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[]}"""

        /** Enrolled once at the policy floor: the server's KDF fence refuses anything weaker, and sign-in derives under it. */
        val reg: RegisterRequest by lazy {
            val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            Account.enroll("invite", EMAIL, "u", PASSWORD, KdfParams(), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "device", crypto).request
        }

        fun keysOf(r: RegisterRequest, confirmed: Boolean = true) = AccountKeys(
            kdfSalt = r.kdfSalt, kdfParams = r.kdfParams, wrappedUvk = r.wrappedUvk,
            encryptedIdentitySeed = r.encryptedIdentitySeed, identityPub = r.identityPub,
            escrowFingerprint = r.escrow?.fingerprint ?: "", recoveryConfirmed = confirmed,
        )

        val keys: AccountKeys by lazy { keysOf(reg) }
    }

    private fun sessionJson(k: AccountKeys, userId: String = reg.userId, mustChange: Boolean = false, pieceId: String? = null) = json.encodeToString(
        SessionResponse.serializer(),
        SessionResponse(userId, DEVICE, "a1", "r1", k, isAdmin = false, mustChangePassword = mustChange, recoveryPieceId = pieceId),
    )

    // ---- sign-in ----

    @Test
    fun aPendingInviteSwitchRefusesTheSignInBeforeAnythingIsDerived() = runBlocking<Unit> {
        val pending = PendingServer(origin = home, previousOrigin = other, ts = 1L)
        store.pendingServer = pending
        assertEquals(SignInResult.PendingSwitch(pending), entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertTrue(calls.isEmpty(), "B2-6: no authKey reaches an unverified origin")
    }

    @Test
    fun aSecondFactorIsAskedForAndAWrongCodeSaysSo() = runBlocking<Unit> {
        login = refused("totp_required", HttpStatusCode.Forbidden)
        assertEquals(SignInResult.TotpRequired(codeWasWrong = false), entry.signIn(EMAIL, PASSWORD, null, engineSync))
        login = refused("bad_totp_code", HttpStatusCode.Forbidden)
        assertEquals(SignInResult.TotpRequired(codeWasWrong = true), entry.signIn(EMAIL, PASSWORD, "000000", engineSync))
        assertNull(store.stored)
        assertNull(session.get())
    }

    @Test
    fun aSignInSavesUnderItsOriginBindsAndStamps() = runBlocking<Unit> {
        login = { request ->
            val sent = json.decodeFromString(LoginRequest.serializer(), request.text())
            assertEquals("test", sent.device.platform, "the platform's wire tag")
            assertEquals("test device", sent.device.name)
            respond(sessionJson(keys, mustChange = true), HttpStatusCode.OK, headers)
        }
        val r = assertIs<SignInResult.SignedIn>(entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertNull(r.captureProof, "a confirmed piece needs no capture")
        assertTrue(r.mustChangePassword)
        assertTrue(store.mustChangePassword, "F58: persisted, since only a login response carries it")
        assertEquals(StoredSession(home, reg.userId, EMAIL, "a1", "r1"), store.stored)
        assertSame(r.unlocked, session.get())
        assertEquals(VaultSession.UnlockProvenance.PASSWORD, r.unlocked.provenance)
        assertNotNull(store.origin(homeKey).stamps[reg.userId], "A1: a full-password sign-in stamps the window")
        assertEquals(keys, store.origin(homeKey).accountKeys, "and keeps the keys for offline unlock")
        assertEquals(FirstSync.Done, r.firstSync)
    }

    @Test
    fun anUnconfirmedRecoveryPieceHandsTheCaptureItsProof() = runBlocking<Unit> {
        login = { respond(sessionJson(keysOf(reg, confirmed = false)), HttpStatusCode.OK, headers) }
        val r = assertIs<SignInResult.SignedIn>(entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertEquals(Account.deriveAuthKey(PASSWORD, reg.kdfSalt, reg.kdfParams), r.captureProof, "§F.9: the login authKey is the fresh reauth")
    }

    @Test
    fun aSignInWhoseOriginMovedIsEndedWhereItWasIssuedAndNotSaved() = runBlocking<Unit> {
        login = {
            store.moveOrigin(other) // the client was re-pointed while login and the KDF ran
            coordinator.originChanged()
            respond(sessionJson(keys), HttpStatusCode.OK, headers)
        }
        assertEquals(SignInResult.OriginMoved(home), entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertTrue(calls.last().endsWith("/auth/logout"), "revoked at the issuer")
        assertNull(store.stored)
        assertNull(session.get())
    }

    @Test
    fun aRefusedSignInKeepsNothing() = runBlocking<Unit> {
        login = refused("invalid_credentials")
        val r = assertIs<SignInResult.Failed>(entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertEquals(401, (r.cause as io.silencelen.andvari.core.client.ApiException).status)
        assertNull(store.stored)
        assertNull(session.get())
    }

    @Test
    fun aSessionRejectedDuringItsFirstSyncLandsNowhere() = runBlocking<Unit> {
        sync = refused("unauthorized")
        assertEquals(SignInResult.EndedBeforeLanding, entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertNull(session.get())
    }

    // ---- survey gap 5: no issued session is left behind ----

    @Test
    fun aLoginWhoseAccountDoesNotOpenIsEndedWhereItWasIssued() = runBlocking<Unit> {
        // The login answered, but the keys it served do not open under this password.
        val wrongSalt = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.randomBytes(16))
        login = { respond(sessionJson(keys.copy(kdfSalt = wrongSalt)), HttpStatusCode.OK, headers) }
        val r = assertIs<SignInResult.Failed>(entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertIs<io.silencelen.andvari.core.crypto.CryptoException>(r.cause)
        val loggedIn = calls.indexOfFirst { it.endsWith("/auth/login") }
        assertTrue(calls.indexOfFirst { it.endsWith("/auth/logout") } > loggedIn, "the session the login issued is revoked, not orphaned")
        assertNull(store.stored)
        assertNull(session.get())
    }

    @Test
    fun aSignInThatFailsBeforeAnySessionIsIssuedRevokesNothing() = runBlocking<Unit> {
        prelogin = refused("not_found", HttpStatusCode.NotFound)
        assertIs<SignInResult.Failed>(entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertFalse(calls.any { it.endsWith("/auth/logout") })
    }

    @Test
    fun aSavedSessionThatFailedToBindIsKeptForTheNextUnlock() = runBlocking<Unit> {
        namespaces.failOpen = IllegalStateException("corrupt cache file")
        assertIs<SignInResult.Failed>(entry.signIn(EMAIL, PASSWORD, null, engineSync))
        assertFalse(calls.any { it.endsWith("/auth/logout") }, "an unlock can still reach a saved session")
        assertNotNull(store.stored)
        assertNull(session.get())
    }

    // ---- enroll ----

    private fun waived(email: String = "new@example.com", password: String = PASSWORD, policy: ClientPolicy? = ClientPolicy()) =
        EnrollRequest(invite = "invite", email = email, name = "", password = password, waived = true, typedShortFp = "", gatePolicy = policy)

    @Test
    fun aWeakMasterPasswordSendsNothing() = runBlocking<Unit> {
        assertEquals(EnrollOutcome.WeakPassword, entry.enroll(waived(password = "password"), engineSync))
        assertTrue(calls.isEmpty())
    }

    @Test
    fun aSheetThatNoLongerMatchesThePolicySendsNothing() = runBlocking<Unit> {
        val policy = ClientPolicy(recoveryFingerprint = "ab".repeat(32))
        val request = EnrollRequest("invite", "new@example.com", "", PASSWORD, waived = false, typedShortFp = "cd".repeat(16), gatePolicy = policy)
        assertEquals(EnrollOutcome.AnchorMismatch, entry.enroll(request, engineSync))
        assertTrue(calls.isEmpty(), "CR-06: no escrow is sealed to a fingerprint the person did not check")
    }

    @Test
    fun aWaivedEnrollCommitsItsPieceAndHandsItOverOnce() = runBlocking<Unit> {
        val r = assertIs<EnrollOutcome.Enrolled>(entry.enroll(waived(), engineSync))
        val sent = assertNotNull(registered)
        assertNull(sent.escrow, "a waived invite seals no org escrow")
        assertFalse(calls.any { it.endsWith("/recovery-pubkey") }, "and fetches no org key")
        assertEquals("piece-1", r.pieceId)
        assertFalse(r.recoverySecret.all { it == 0.toByte() }, "the shown-once piece, for the reveal")
        assertEquals(StoredSession(home, sent.userId, "new@example.com", "a1", "r1"), store.stored)
        assertSame(r.unlocked, session.get())
        assertNotNull(store.origin(homeKey).stamps[sent.userId])
        assertEquals("new", sent.displayName, "a blank name falls back to the address")
    }

    @Test
    fun anEnrollHonoursAPendingSwitchsMarkerAndCommitsIt() = runBlocking<Unit> {
        store.pendingServer = PendingServer(origin = home, previousOrigin = other, ts = 1L)
        val inner = register
        var markerAtRegister: PendingServer? = null
        register = { request -> markerAtRegister = store.pendingServer; inner(request) }
        assertIs<EnrollOutcome.Enrolled>(entry.enroll(waived(), engineSync))
        assertEquals("new@example.com", markerAtRegister?.email, "B2-9: the crash marker names the address before register")
        assertNull(store.pendingServer, "B2-6: success commits the switch")
    }

    @Test
    fun anEnrollWhoseOriginMovedIsEndedAndNotSaved() = runBlocking<Unit> {
        val inner = register
        register = { request ->
            store.moveOrigin(other)
            coordinator.originChanged()
            inner(request)
        }
        assertEquals(EnrollOutcome.OriginMoved(home), entry.enroll(waived(), engineSync))
        assertTrue(calls.last().endsWith("/auth/logout"))
        assertNull(store.stored)
        assertNull(session.get())
    }

    @Test
    fun anEnrollWhoseSessionEndsInItsFirstSyncShowsNoPhrase() = runBlocking<Unit> {
        sync = refused("unauthorized")
        assertEquals(EnrollOutcome.EndedBeforeLanding, entry.enroll(waived(), engineSync))
        assertNull(session.get())
    }
}
