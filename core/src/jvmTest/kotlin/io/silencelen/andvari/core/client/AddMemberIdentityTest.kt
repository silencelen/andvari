package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.crypto.GrantOutcome
import io.silencelen.andvari.core.crypto.GrantPin
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.SignedGrant
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.model.GrantReissueRequest
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A11 (q00, HIGH) — core twin of web `addmember-identity.test.ts`. The add-member
 * confirm trusted the SERVER's display name: `lookup(email)` returns `{userId, displayName, identityPub}`, the pin gate
 * was keyed by the RETURNED userId, and a server plus one pinned colluder C could answer a lookup for B's email with C's
 * account under B's name. Now a pin records the email the human typed for the ceremony, an add whose typed email the
 * pin contradicts is refused, and a pre-A11 pin (no email) needs the human to confirm the PIN's own label.
 */
class AddMemberIdentityTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys) {
        val userId get() = reg.userId
    }

    private fun enroll(tag: String, params: KdfParams = kdf): Enrolled {
        val email = "$tag-${crypto.randomBytes(4).joinToString("") { (it.toInt() and 0xff).toString(16) }}@example.com"
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, params, recovery.publicKey, fp, "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint, personalWrap = reg.personalWrap,
            ),
        )
    }

    private fun unlock(e: Enrolled) = Account.unlock(e.userId, password, e.keys, crypto)

    /** A scripted hostile-capable server. */
    private class FakeServer(var feed: SyncResponse, val keys: AccountKeys? = null, val selfUserId: String? = null) {
        val adds = mutableListOf<Pair<String, VaultMemberAdd>>()
        val reissues = mutableListOf<Triple<String, String, String>>() // vaultId, userId, signedGrant
        val offers = mutableListOf<Pair<String, TransferOfferRequest>>()
        val removals = mutableListOf<Pair<String, String>>()
        val members = HashMap<String, List<VaultMemberSummary>>()
        var accountState: String? = null
        var accountSeq: Long = 0
    }

    private fun body(req: io.ktor.client.request.HttpRequestData): String = when (val b = req.body) {
        is TextContent -> b.text
        is OutgoingContent.ByteArrayContent -> b.bytes().decodeToString()
        else -> ""
    }

    private fun api(server: FakeServer): AndvariApi {
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            val members = Regex("^/api/v1/vaults/([^/]+)/members$").find(path)
            val member = Regex("^/api/v1/vaults/([^/]+)/members/([^/]+)$").find(path)
            val reissue = Regex("^/api/v1/vaults/([^/]+)/members/([^/]+)/grant$").find(path)
            val transfer = Regex("^/api/v1/vaults/([^/]+)/transfer$").find(path)
            when {
                path == "/api/v1/sync" -> {
                    val since = req.url.parameters["since"]?.toLongOrNull() ?: 0L
                    val resp = when {
                        since == 0L -> server.feed
                        since < server.feed.rev -> server.feed.copy(full = false)
                        else -> SyncResponse(server.feed.rev, false, emptyList(), emptyList(), emptyList(), emptyList())
                    }
                    respond(json.encodeToString(SyncResponse.serializer(), resp), HttpStatusCode.OK, ct)
                }
                path == "/api/v1/account/keys" && server.keys != null ->
                    respond(json.encodeToString(AccountKeys.serializer(), server.keys), HttpStatusCode.OK, ct)
                path == "/api/v1/account/state" && req.method == HttpMethod.Get ->
                    respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(server.accountState, server.accountSeq)), HttpStatusCode.OK, ct)
                path == "/api/v1/account/state" && req.method == HttpMethod.Put -> {
                    val put = json.decodeFromString(AccountStatePut.serializer(), body(req))
                    if (put.baseSeq != server.accountSeq) {
                        respond("""{"error":"stale_state","message":"stale"}""", HttpStatusCode.Conflict, ct)
                    } else {
                        server.accountState = put.sealedState
                        server.accountSeq += 1
                        respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(put.sealedState, server.accountSeq)), HttpStatusCode.OK, ct)
                    }
                }
                path == "/api/v1/vaults" && req.method == HttpMethod.Post -> {
                    // The created vault joins the creator's feed, with the creator's own UVK-wrapped owner row.
                    val cv = json.decodeFromString(CreateVaultRequest.serializer(), body(req))
                    val rev = server.feed.rev + 1
                    server.feed = server.feed.copy(
                        rev = rev,
                        vaults = server.feed.vaults + WireVault(cv.vaultId, "shared", rev, cv.metaBlob, 0),
                        grants = server.feed.grants + WireGrant(cv.vaultId, server.selfUserId!!, "owner", cv.wrappedVk, rev, null),
                    )
                    respond("""{"rev":$rev}""", HttpStatusCode.Created, ct)
                }
                members != null && req.method == HttpMethod.Get ->
                    respond(json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), server.members[members.groupValues[1]].orEmpty()), HttpStatusCode.OK, ct)
                members != null && req.method == HttpMethod.Post -> {
                    server.adds.add(members.groupValues[1] to json.decodeFromString(VaultMemberAdd.serializer(), body(req)))
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.Created, ct)
                }
                member != null && req.method == HttpMethod.Delete -> {
                    server.removals.add(member.groupValues[1] to member.groupValues[2])
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                reissue != null && req.method == HttpMethod.Put -> {
                    val r = json.decodeFromString(GrantReissueRequest.serializer(), body(req))
                    server.reissues.add(Triple(reissue.groupValues[1], reissue.groupValues[2], r.signedGrant))
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                transfer != null && req.method == HttpMethod.Post -> {
                    server.offers.add(transfer.groupValues[1] to json.decodeFromString(TransferOfferRequest.serializer(), body(req)))
                    respond("""{"rev":${server.feed.rev + 1},"expiresAt":0}""", HttpStatusCode.OK, ct)
                }
                req.method == HttpMethod.Put && path.endsWith("/grant/self-wrap") ->
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private fun pinOf(e: Enrolled, label: String) = Contact(e.userId, e.reg.identityPub, label, 1_000, Contact.METHOD_TYPED)
    private fun personalRow(e: Enrolled) = WireVault(e.reg.personalVault.vaultId, "personal", 2, e.reg.personalVault.metaBlob, 0)
    private fun personalGrant(e: Enrolled) = WireGrant(e.reg.personalVault.vaultId, e.userId, "owner", e.reg.personalVault.wrappedVk, 2, null)
    /** The owner's device, with a vault it CREATED through the engine (its own evidence of ownership). */
    private suspend fun ownerWithCreatedVault(owner: Enrolled, deviceState: DeviceState? = null, cache: VaultCache = InMemoryVaultCache()):
        Triple<SyncEngine, FakeServer, String> {
        val server = FakeServer(
            SyncResponse(5, true, listOf(personalRow(owner)), listOf(personalGrant(owner)), emptyList(), emptyList()),
            selfUserId = owner.userId,
        )
        val engine = SyncEngine(api(server), unlock(owner), cache, deviceState = deviceState)
        engine.sync()
        val vaultId = engine.createSharedVault("Family")
        assertTrue(engine.ownsVault(vaultId), "creating the vault records ownership")
        return Triple(engine, server, vaultId)
    }


    private fun emailOf(e: Enrolled) = e.reg.email

    /** The ceremony: the owner typed [who]'s 32-hex code from their screen, after looking them up by [typedEmail]. */
    private suspend fun verify(engine: SyncEngine, who: Enrolled, label: String, typedEmail: String?): Contact {
        val short = SharedGrant.fingerprint(crypto, Bytes.fromB64(who.reg.identityPub)).take(32)
        val c = engine.verifyMemberTyped(io.silencelen.andvari.core.model.UserLookupResponse(who.userId, label, who.reg.identityPub), short, typedEmail)
        assertNotNull(c)
        return c
    }

    @Test
    fun `the ceremony records the typed email, normalised - no typed email records none`() = runBlocking {
        val owner = enroll("q00-owner")
        val bea = enroll("q00-bea")
        val (engine, _, _) = ownerWithCreatedVault(owner)
        assertEquals(emailOf(bea).lowercase(), verify(engine, bea, "Bea", "  " + emailOf(bea).uppercase() + " ").email)
        val carl = enroll("q00-carl")
        assertNull(verify(engine, carl, "Carl", null).email)
        assertEquals("a@b.c", ContactPin.normalizeEmail(" A@B.C "))
    }

    @Test
    fun `pure check - match, mismatch, legacy, another pin claiming the typed email`() {
        val b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        val c = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        val pinB = Contact(b, "x", "Bea", 1, Contact.METHOD_TYPED, email = "bea@example.com")
        val pinC = Contact(c, "y", "Carl", 1, Contact.METHOD_TYPED, email = "carl@example.com")
        val legacyC = Contact(c, "y", "Carl", 1, Contact.METHOD_TYPED)
        assertTrue(ContactPin.addIdentity(b, "Bea@example.com ", listOf(pinB, pinC)) is ContactPin.AddIdentity.Match)
        assertTrue(ContactPin.addIdentity(c, "bea@example.com", listOf(pinB, pinC)) is ContactPin.AddIdentity.Mismatch)
        assertTrue(ContactPin.addIdentity(c, "bea@example.com", listOf(pinB, legacyC)) is ContactPin.AddIdentity.Mismatch, "B's pin claims the email")
        val legacy = ContactPin.addIdentity(c, "bea@example.com", listOf(legacyC))
        assertTrue(legacy is ContactPin.AddIdentity.Legacy)
        assertEquals("Carl", legacy.pin.label, "the legacy confirm shows C's VERIFIED label")
        assertTrue(ContactPin.addIdentity(b, "bea@example.com", emptyList()) is ContactPin.AddIdentity.Unpinned)
    }

    @Test
    fun `lookup of B's email answered with pinned C's account under B's name is REFUSED`() = runBlocking {
        val owner = enroll("q00-owner")
        val bea = enroll("q00-bea")
        val carl = enroll("q00-carl")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        verify(engine, carl, "Carl", emailOf(carl))
        assertEquals(SyncEngine.MemberPinState.PINNED, engine.memberPinState(carl.userId, carl.reg.identityPub), "the old gate passes")
        assertTrue(engine.addMemberIdentity(emailOf(bea), carl.userId) is ContactPin.AddIdentity.Mismatch)
        assertFailsWith<MemberIdentityMismatchException> { engine.addVaultMember(vaultId, carl.userId, "writer", emailOf(bea)) }
        assertFailsWith<MemberIdentityMismatchException>("a confirmation cannot override a recorded mismatch") {
            engine.addVaultMember(vaultId, carl.userId, "writer", emailOf(bea), legacyPinConfirmed = true)
        }
        assertTrue(server.adds.isEmpty())
    }

    @Test
    fun `legacy pin - the confirm names C's verified label, refused until the human confirms it`() = runBlocking {
        val owner = enroll("q00-owner")
        val bea = enroll("q00-bea")
        val carl = enroll("q00-carl")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        verify(engine, carl, "Carl", null)
        val id = engine.addMemberIdentity(emailOf(bea), carl.userId)
        assertTrue(id is ContactPin.AddIdentity.Legacy)
        assertEquals("Carl", id.pin.label)
        assertFailsWith<LegacyPinConfirmRequiredException> { engine.addVaultMember(vaultId, carl.userId, "writer", emailOf(bea)) }
        assertTrue(server.adds.isEmpty())
        engine.addVaultMember(vaultId, carl.userId, "writer", emailOf(bea), legacyPinConfirmed = true)
        assertEquals(listOf(carl.userId), server.adds.map { it.second.userId })
    }

    @Test
    fun `genuine B works - unpinned is still refused`() = runBlocking {
        val owner = enroll("q00-owner")
        val bea = enroll("q00-bea")
        val carl = enroll("q00-carl")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        assertFailsWith<MemberNotVerifiedException> { engine.addVaultMember(vaultId, bea.userId, "writer", emailOf(bea)) }
        verify(engine, bea, "Bea", emailOf(bea))
        verify(engine, carl, "Carl", emailOf(carl))
        engine.addVaultMember(vaultId, bea.userId, "writer", " " + emailOf(bea).uppercase())
        assertEquals(listOf(bea.userId), server.adds.map { it.second.userId })
    }

    @Test
    fun `codec carries the email strictly and omits it while absent`() {
        val u = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        val b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        val key = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU"
        val legacy = AccountState.empty(u).copy(contacts = listOf(Contact(b, key, "Bea", 1, Contact.METHOD_TYPED)))
        val enc = AccountState.encode(legacy)
        assertFalse("email" in enc, "a pre-A11 contact encodes without an email key")
        assertNull(AccountState.decode(u, enc).contacts.single().email)
        val withEmail = legacy.copy(contacts = listOf(legacy.contacts.single().copy(email = "bea@example.com")))
        val enc2 = AccountState.encode(withEmail)
        assertEquals("bea@example.com", AccountState.decode(u, enc2).contacts.single().email)
        for (bad in listOf("\"Bea@example.com\"", "\" bea@example.com\"", "\"bea\"", "\"\"", "\"a b@example.com\"", "7")) {
            val tampered = enc2.replace("\"bea@example.com\"", bad)
            assertFailsWith<AccountStateException>("email $bad") { AccountState.decode(u, tampered) }
        }
    }
}
