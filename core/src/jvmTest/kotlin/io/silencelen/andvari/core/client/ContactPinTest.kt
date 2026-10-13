package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A §4.2 / §7.2 (branch A5): a contact is pinned ONLY from a human
 * verification — a full-hash QR scan, or a human-typed 32-hex match against SHA-256 of the served key, or
 * the in-person enrolment link under its typed in-person code. A key the server served is never pinned on
 * its own: not on sync, not on a member grant, not from a machine-supplied prefix.
 */
class ContactPinTest {
    private val crypto = createCryptoProvider()
    private val bea = crypto.boxKeypairFromSeed(ByteArray(32) { 5 })
    private val mallory = crypto.boxKeypairFromSeed(ByteArray(32) { 6 })
    private val beaId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val beaFp = SharedGrant.fingerprint(crypto, bea.publicKey)
    private val served = ServedIdentity(beaId, Bytes.toB64(bea.publicKey))
    private val substituted = ServedIdentity(beaId, Bytes.toB64(mallory.publicKey))

    @Test
    fun typedPinNeedsExactly32HexFromAHumanAgainstTheServedKey() {
        assertNotNull(ContactPin.fromTyped(crypto, Fingerprint.groupedShort(beaFp), served, "Bea", 1), "the human typed Bea's 32 hex off Bea's screen")
        assertNull(ContactPin.fromTyped(crypto, beaFp, served, "Bea", 1), "a full 64-hex value is a machine value, never a typed entry")
        assertNull(ContactPin.fromTyped(crypto, beaFp.take(16), served, "Bea", 1), "16 hex (64 bits) is not enough")
        assertNull(ContactPin.fromTyped(crypto, beaFp.take(32), substituted, "Bea", 1), "the server substituted Bea's key: the typed code does not match it")
    }

    @Test
    fun qrPinComparesTheFullFingerprint() {
        val qr = IdentityQr.compose(crypto, beaId, bea.publicKey)
        assertEquals(Contact.METHOD_QR, ContactPin.fromQr(crypto, qr, served, "Bea", 1)?.method)
        assertNull(ContactPin.fromQr(crypto, qr, substituted, "Bea", 1), "served key does not hash to the scanned fingerprint")
        assertNull(ContactPin.fromQr(crypto, "${IdentityQr.PREFIX}$beaId:${beaFp.take(32)}", served, "Bea", 1), "a QR carries the full value or nothing")
        assertNull(ContactPin.fromQr(crypto, qr, ServedIdentity("cccccccc-cccc-4ccc-8ccc-cccccccccccc", served.identityPub), "Bea", 1), "the QR names a different user")
        assertNull(IdentityQr.parse(qr.uppercase()))
    }

    @Test
    fun enrolPinNeedsTheInPersonCodeAndTheFullFingerprint() {
        val p = EnrollPayload(1, "https://vault.example", "t", "e", rfp = null, ifp = beaFp, iu = beaId)
        assertNull(ContactPin.fromEnrolLink(crypto, p, inPersonVerified = false, served, "Admin", 1), "a navigated or pasted link is not in-person evidence")
        assertEquals(Contact.METHOD_ENROL, ContactPin.fromEnrolLink(crypto, p, inPersonVerified = true, served, "Admin", 1)?.method)
        assertNull(ContactPin.fromEnrolLink(crypto, p, inPersonVerified = true, substituted, "Admin", 1), "never pin a key the server chose")
        val code = EnrollLink.checkCode(crypto, p)!!
        assertTrue(EnrollLink.checkCodeMatches(crypto, p, code))
        // A server that composes its own link (its key's ifp) yields a different in-person code.
        val forged = p.copy(ifp = SharedGrant.fingerprint(crypto, mallory.publicKey))
        assertTrue(!EnrollLink.checkCodeMatches(crypto, forged, code), "the admin's on-screen code does not match a server-composed link")
    }

    @Test
    fun pinStateDetectsAKeyChange() {
        val doc = AccountState.withContact(AccountState.empty("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), Contact(beaId, served.identityPub, "Bea", 1, Contact.METHOD_TYPED))
        assertEquals(ContactPin.PinState.PINNED_MATCH, ContactPin.pinState(doc, served))
        assertEquals(ContactPin.PinState.PINNED_MISMATCH, ContactPin.pinState(doc, substituted))
        assertEquals(ContactPin.PinState.UNPINNED, ContactPin.pinState(doc, ServedIdentity("cccccccc-cccc-4ccc-8ccc-cccccccccccc", served.identityPub)))
    }

    /** End to end: a sync that delivers a household member's grant pins NOTHING, and writes no state. */
    @Test
    fun aSyncNeverAutoPinsAServedKey() = runBlocking<Unit> {
        val kdf = KdfParams(ops = 1, memBytes = 8192)
        val rk = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (vReg, victim) = Account.enroll("inv", "v@example.com", "v", "pw pw pw pw", kdf, rk.publicKey, Escrow.fingerprint(crypto, rk.publicKey), "d", crypto)
        val (_, owner) = Account.enroll("inv", "o@example.com", "o", "pw pw pw pw", kdf, rk.publicKey, Escrow.fingerprint(crypto, rk.publicKey), "d", crypto)
        val shared = owner.buildCreateSharedVault("Household")
        val feed = SyncResponse(
            9, true,
            listOf(WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0)),
            listOf(WireGrant(shared.vaultId, vReg.userId, "writer", "", 3, owner.wrapVkForMember(victim.identityPub, shared.vaultId))),
            emptyList(), emptyList(),
        )
        val json = Json { encodeDefaults = true }
        val stateWrites = mutableListOf<String>()
        val engine = MockEngine { req ->
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            when {
                req.url.encodedPath == "/api/v1/sync" -> respond(json.encodeToString(SyncResponse.serializer(), feed), HttpStatusCode.OK, ct)
                req.url.encodedPath == "/api/v1/account/state" && req.method == HttpMethod.Put -> {
                    val put = json.decodeFromString(io.silencelen.andvari.core.model.AccountStatePut.serializer(), (req.body as io.ktor.http.content.TextContent).text)
                    stateWrites.add(put.sealedState); respond("""{"sealedState":null,"seq":1}""", HttpStatusCode.OK, ct)
                }
                req.url.encodedPath == "/api/v1/account/state" -> respond("""{"sealedState":null,"seq":0}""", HttpStatusCode.OK, ct)
                else -> respond("""{"error":"not_found","message":"x"}""", HttpStatusCode.NotFound, ct)
            }
        }
        val sync = SyncEngine(AndvariApi("http://fake", HttpClient(engine), Tokens("a", "r")), victim, InMemoryVaultCache())
        sync.sync()
        assertTrue(victim.hasVault(shared.vaultId))
        assertTrue(sync.accountState.contacts().isEmpty(), "the owner's served key is NOT a contact")
        // The only write a sync makes on its own is the A1b (LOW-R) member-provenance record: never a contact.
        for (w in stateWrites) {
            val doc = victim.openAccountState(w)
            assertTrue(doc.contacts.isEmpty(), "nothing pinned: no human verified anyone")
            assertEquals(setOf(shared.vaultId), doc.memberReceived.keys, "only the member provenance is recorded")
        }
    }
}
