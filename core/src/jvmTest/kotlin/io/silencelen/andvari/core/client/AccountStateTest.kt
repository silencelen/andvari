package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A §4.2 (branch A5): the account-state blob. Vector rows from
 * `spec/test-vectors/accountstate.json` (shared with web `vault/accountstate.test.ts`), then the sync
 * client against a scripted hostile server: a rolled-back blob is REFUSED (the local copy wins and is
 * written back), and an injected blob does not open.
 */
class AccountStateTest {
    private val crypto = createCryptoProvider()
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "accountstate.json").readText()).jsonObject
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun docOf(o: kotlinx.serialization.json.JsonElement): AccountStateDoc? =
        if (o is JsonNull) null else AccountState.decode(o.jsonObject.getValue("userId").jsonPrimitive.content, o.toString())

    @Test
    fun vectorBlobOpensAndInjectionsDoNot() {
        val userId = v.getValue("userId").jsonPrimitive.content
        val uvk = Bytes.fromB64(v.getValue("uvkB64").jsonPrimitive.content)
        assertEquals(v.getValue("adUtf8").jsonPrimitive.content, Ad.accountState(userId).decodeToString())
        val plain = Envelope.openB64(crypto, uvk, v.getValue("sampleBlobB64").jsonPrimitive.content, Ad.accountState(userId)).decodeToString()
        assertEquals(docOf(v.getValue("sample")), AccountState.decode(userId, plain))
        for (r in v.getValue("rejectOpen").jsonArray.map { it.jsonObject }) {
            assertFailsWith<CryptoException>(r.getValue("name").jsonPrimitive.content) {
                Envelope.openB64(crypto, uvk, r.getValue("blobB64").jsonPrimitive.content, Ad.accountState(userId))
            }
        }
        for (r in v.getValue("rejectDecode").jsonArray.map { it.jsonObject }) {
            assertFailsWith<AccountStateException>(r.getValue("name").jsonPrimitive.content) {
                AccountState.decode(userId, r.getValue("plaintext").jsonPrimitive.content)
            }
        }
    }

    @Test
    fun mergeRows() {
        val userId = v.getValue("userId").jsonPrimitive.content
        for (r in v.getValue("merge").jsonArray.map { it.jsonObject }) {
            val name = r.getValue("name").jsonPrimitive.content
            val m = AccountState.merge(userId, docOf(r.getValue("local")), docOf(r.getValue("served")), r.getValue("highWater").jsonPrimitive.long)
            val exp = r.getValue("expected").jsonObject
            assertEquals(exp.getValue("rollback").jsonPrimitive.boolean, m.rollback, "rollback $name")
            assertEquals(docOf(exp.getValue("doc")), m.doc, "doc $name")
        }
    }

    // ---- the sync client against a scripted server ----

    private class Server {
        var sealed: String? = null
        var seq: Long = 0
        val puts = mutableListOf<AccountStatePut>()
    }

    private fun api(s: Server): AndvariApi {
        val engine = MockEngine { req ->
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            if (req.url.encodedPath != "/api/v1/account/state") return@MockEngine respond("{}", HttpStatusCode.NotFound, ct)
            if (req.method == HttpMethod.Put) {
                val put = json.decodeFromString(AccountStatePut.serializer(), (req.body as TextContent).text)
                if (put.baseSeq != s.seq) return@MockEngine respond("""{"error":"stale_state","message":"x"}""", HttpStatusCode.Conflict, ct)
                s.puts.add(put)
                s.sealed = put.sealedState
                s.seq += 1
            }
            respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(s.sealed, s.seq)), HttpStatusCode.OK, ct)
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("a", "r"))
    }

    private fun account(): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (_, a) = Account.enroll("inv", "state@example.com", "s", "pw pw pw pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "dev", crypto)
        return a
    }

    private fun contact(userId: String, at: Long) =
        Contact(userId, Bytes.toB64(ByteArray(32) { 3 }), "Bea", at, Contact.METHOD_TYPED)

    @Test
    fun aRolledBackStateIsRefusedAndTheLocalCopyWins() = runBlocking<Unit> {
        val a = account()
        val server = Server()
        val cache = InMemoryVaultCache()
        val sync = AccountStateSync(api(server), a, cache) { 1000 }
        sync.pin(contact("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 100))
        val oldBlob = server.sealed!! // seq 1: Bea pinned
        sync.pin(contact("cccccccc-cccc-4ccc-8ccc-cccccccccccc", 200))
        assertEquals(2, sync.contacts().size)

        // The server rolls the blob back to the one-pin version (and its own counter, to look consistent).
        server.sealed = oldBlob
        server.seq = 1
        val again = AccountStateSync(api(server), a, cache)
        again.refresh()
        assertEquals(AccountStateSync.Anomaly.ROLLBACK, again.anomaly)
        assertEquals(2, again.contacts().size, "the rollback cannot remove a pin this device holds")
        // …and the merged copy was written back above the high-water mark.
        val back = a.openAccountState(server.sealed!!)
        assertEquals(2, back.contacts.size)
        assertTrue(back.seq > 2)
    }

    @Test
    fun aWithheldStateAfterOneWasSeenIsARollback() = runBlocking<Unit> {
        val a = account()
        val server = Server()
        val cache = InMemoryVaultCache()
        AccountStateSync(api(server), a, cache).pin(contact("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 100))
        server.sealed = null
        server.seq = 0
        val again = AccountStateSync(api(server), a, cache)
        again.refresh()
        assertEquals(AccountStateSync.Anomaly.ROLLBACK, again.anomaly)
        assertEquals(1, again.contacts().size)
    }

    /** The server cannot ADD a pin: a blob it mints does not open under our UVK/AD. */
    @Test
    fun anInjectedStateDoesNotOpenAndAddsNothing() = runBlocking<Unit> {
        val a = account()
        val attacker = account() // a different UVK
        val forged = AccountState.withContact(AccountState.empty(a.userId).copy(seq = 50), contact("dddddddd-dddd-4ddd-8ddd-dddddddddddd", 1))
        val server = Server().apply {
            // Sealed for OUR userId but under a key the server chose.
            sealed = Envelope.sealB64(crypto, ByteArray(32) { 9 }, AccountState.encode(forged).encodeToByteArray(), Ad.accountState(a.userId))
            seq = 7
        }
        val sync = AccountStateSync(api(server), a, InMemoryVaultCache())
        sync.refresh()
        assertEquals(AccountStateSync.Anomaly.UNREADABLE, sync.anomaly)
        assertTrue(sync.contacts().isEmpty(), "an injected pin is never adopted")
        // Another account's genuine blob does not open in our slot either.
        assertFailsWith<Exception> { a.openAccountState(attacker.sealAccountState(AccountState.empty(attacker.userId))) }
    }

    @Test
    fun aStaleWriteRetriesAfterAMerge() = runBlocking<Unit> {
        val a = account()
        val server = Server()
        val cache = InMemoryVaultCache()
        val first = AccountStateSync(api(server), a, cache)
        val second = AccountStateSync(api(server), a, InMemoryVaultCache()) // another device of the same account
        first.pin(contact("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 100))
        second.pin(contact("cccccccc-cccc-4ccc-8ccc-cccccccccccc", 200))
        assertEquals(setOf("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"), a.openAccountState(server.sealed!!).contacts.map { it.userId }.toSet())
    }

    // ---- A13 (security review 2026-10, q01): a human unpin / re-pin wins the merge under cross-device clock skew ----

    private val u = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val me = "33333333-3333-4333-8333-333333333333"

    @Test
    fun anUnpinOnASlowClockStillRemovesThePinAnotherDeviceRecordedLater() {
        // Device A (clock ahead) pinned at 5000; device B (clock behind) unpins at 1000.
        val pinned = AccountState.withContact(AccountState.empty(me).copy(seq = 1), contact(u, 5_000))
        val unpinned = AccountState.withoutContact(pinned, u, 1_000)
        assertTrue((unpinned.contactTombstones[u] ?: -1) >= 5_000, "the tombstone is pushed to the pin it removes")
        // The next refresh merges B's copy with A's (still pinned): the human's unpin holds.
        val merged = AccountState.merge(me, unpinned, pinned, 0).doc
        assertTrue(merged.contacts.none { it.userId == u }, "a merge must not revive an unpinned contact")
        assertTrue(AccountState.merge(me, pinned, unpinned, 0).doc.contacts.none { it.userId == u }, "order-independent")
    }

    @Test
    fun aRePinOnASlowClockSurvivesTheTombstoneItReplaces() {
        val tomb = AccountState.withoutContact(AccountState.withContact(AccountState.empty(me).copy(seq = 1), contact(u, 100)), u, 5_000)
        val repinned = AccountState.withContact(tomb, contact(u, 1_000))
        val merged = AccountState.merge(me, repinned, tomb, 0).doc
        assertEquals(listOf(u), merged.contacts.map { it.userId }, "the re-pin outranks the older-in-intent tombstone")
    }

    @Test
    fun aReVerificationWithAChangedKeyOnASlowClockWinsTheMerge() {
        val oldPin = AccountState.withContact(AccountState.empty(me).copy(seq = 1), contact(u, 5_000))
        val newKey = Contact(u, Bytes.toB64(ByteArray(32) { 9 }), "Bea", 1_000, Contact.METHOD_TYPED)
        val reverified = AccountState.withContact(oldPin, newKey)
        val merged = AccountState.merge(me, reverified, oldPin, 0).doc
        assertEquals(newKey.identityPub, merged.contact(u)?.identityPub, "the newer human act wins, not the faster clock")
        // The same pin re-saved does not churn its time.
        assertEquals(5_000, AccountState.withContact(oldPin, contact(u, 1_000)).contact(u)?.verifiedAt)
    }
}
