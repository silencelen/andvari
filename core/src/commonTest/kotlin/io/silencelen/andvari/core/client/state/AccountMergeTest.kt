package io.silencelen.andvari.core.client.state

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Design §5.4 / spec 02 §9 merges, the document codec, and the store's CAS loop. accountstate.json grades these when it lands. */
class AccountMergeTest {
    private val u = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
    private val v = "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f"
    private val dev = "2d8a5e4f-6f7c-4d9e-8f10-2b3c4d5e6f70"
    private val k1 = "A".repeat(43)
    private val k2 = "B".repeat(42) + "A"
    private val ga = "a".repeat(64)
    private val gb = "b".repeat(64)

    private fun c(key: String, at: Long, compared: Boolean = false, label: String = "QWxpY2U") = ContactRecord(v, key, label, verifiedAt = at, compared = compared, madeOn = dev)
    private fun doc(seq: Long = 1, contacts: List<ContactRecord> = emptyList(), tombs: List<ContactTombstone> = emptyList(), vaults: List<VaultRecord> = emptyList(),
                    accepted: List<AcceptedRecord> = emptyList(), recovery: RecoveryRecord? = null, unknown: Map<String, String> = emptyMap()) =
        AccountDocument(seq, contacts.associateBy { it.userId }, tombs.associateBy { it.userId }, vaults.associateBy { it.vaultId }, accepted.associateBy { it.vaultId }, recovery, unknown)

    @Test fun encodeWritesKeysInUtf8ByteOrder() {
        // U+FFFF is EF BF BF in UTF-8 and sorts before U+1F600 (F0 9F 98 80); UTF-16 order puts the
        // surrogate pair (D83D) first. The writer must use byte order (design §5.4).
        val bmp = "\uFFFF"; val astral = "\uD83D\uDE00"
        val text = AccountDocumentCodec.encode(u, doc(unknown = mapOf(astral to "1", bmp to "2")))
        assertTrue(text.indexOf(bmp) in 0 until text.indexOf(astral), text)
        assertTrue(AccountDocumentCodec.compareBytes(bmp.encodeToByteArray(), astral.encodeToByteArray()) < 0)
        assertEquals(listOf("a", "b", "ba"), AccountDocumentCodec.inByteOrder(mapOf("ba" to 1, "b" to 2, "a" to 3)).keys.toList())
    }

    @Test fun edgesUnknownRecordFieldsSurviveAMerge() {
        // §5.4 "Edges": a record with a field this build does not know is kept, the field as written.
        val text = AccountDocumentCodec.encode(u, doc(seq = 3, contacts = listOf(c(k1, 5)), vaults = listOf(VaultRecord(v, ga, 2, gb)),
            accepted = listOf(AcceptedRecord(v, u, 1, 9, AcceptedRecord.ACCEPT)), recovery = RecoveryRecord("private", "none", 4)))
        val withExtras = text
            .replace("\"madeOn\":\"$dev\"", "\"madeOn\":\"$dev\",\"nick\":{\"a\":[1,2]}")
            .replace("\"hash\":\"$gb\"", "\"hash\":\"$gb\",\"pinnedBy\":\"x\"")
            .replace("\"decision\":\"accept\"", "\"decision\":\"accept\",\"why\":7")
            .replace("\"fp\":\"none\"", "\"fp\":\"none\",\"hint\":null")
        val decoded = AccountDocumentCodec.decode(u, withExtras)!!
        assertEquals(0, decoded.droppedRecords)
        val d = decoded.document
        assertEquals(mapOf("nick" to "{\"a\":[1,2]}"), d.contacts.getValue(v).extra)
        assertEquals(mapOf("pinnedBy" to "\"x\""), d.vaults.getValue(v).extra)
        assertEquals(mapOf("why" to "7"), d.accepted.getValue(v).extra)
        assertEquals(mapOf("hint" to "null"), d.recovery!!.extra)
        val merged = AccountMerge.merge(d, doc(seq = 2)).document
        val again = AccountDocumentCodec.decode(u, AccountDocumentCodec.encode(u, merged))!!.document
        assertEquals(d, again, "every extra field written back as it came")
    }

    @Test fun edgesMissingMapsAndABadSeq() {
        assertEquals(AccountDocument.EMPTY.copy(seq = 4), AccountDocumentCodec.decode(u, "{\"v\":2,\"userId\":\"$u\",\"seq\":4}")!!.document)
        assertNull(AccountDocumentCodec.decode(u, "{\"v\":2,\"userId\":\"$u\",\"seq\":\"4\"}"))
        assertNull(AccountDocumentCodec.decode(u, "{\"v\":2,\"userId\":\"$u\",\"seq\":4.5}"))
        assertNull(AccountDocumentCodec.decode(u, "{\"v\":2,\"userId\":\"$u\"}"))
    }

    @Test fun edgesTombstonesApplyBeforeTheirCap() {
        // A tombstone the cap then drops has still removed its contact in that merge.
        val oldTomb = ContactTombstone(v, 10)
        val other1 = ContactTombstone(u, 50)
        val other2 = ContactTombstone(dev, 60)
        val m = AccountMerge.merge(doc(contacts = listOf(c(k1, 9)), tombs = listOf(other1, other2)), doc(tombs = listOf(oldTomb)), AccountLimits(tombstones = 2))
        assertTrue(m.document.contacts.isEmpty(), "bob's pin went with the tombstone")
        assertEquals(setOf(u, dev), m.document.contactTombstones.keys)
    }

    @Test fun edgesLeftVaultsShedOldestThenSmallerVaultId() {
        val ids = listOf("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        val vaults = ids.map { VaultRecord(it, ga, 1, gb) }
        // b and c left at the same time, a left later; recovery is never dropped.
        val acc = listOf(AcceptedRecord(ids[0], u, 1, 30, AcceptedRecord.DECLINE), AcceptedRecord(ids[1], u, 1, 20, AcceptedRecord.DECLINE),
            AcceptedRecord(ids[2], u, 1, 20, AcceptedRecord.DECLINE))
        val full = doc(vaults = vaults, accepted = acc, recovery = RecoveryRecord("private", "none", 1))
        val minusB = full.copy(vaults = full.vaults - ids[1], accepted = full.accepted - ids[1])
        val limit = AccountMerge.sealedChars(minusB)
        val b = AccountMerge.bound(full, AccountLimits(sealedChars = limit))
        assertTrue(b.fits)
        assertEquals(minusB, b.document, "the smaller vaultId of the two oldest goes first")
        val none = AccountMerge.bound(full, AccountLimits(sealedChars = 10))
        assertFalse(none.fits, "still over after every drop: not written")
        assertEquals(RecoveryRecord("private", "none", 1), none.document.recovery)
        assertTrue(none.document.vaults.isEmpty() && none.document.accepted.isEmpty())
    }

    @Test fun edgesFullAndDamagedAreNotWrittenButStillRead() = runBlocking {
        val crypto = createCryptoProvider()
        val uvk = crypto.randomBytes(32)
        val server = Server(u)
        val state = MemoryDeviceState()
        val store = StoredAccountState(u, uvk, server, crypto, state, limits = AccountLimits(sealedChars = 400))
        val big = (1..5).map { i -> ContactRecord("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5$i", k1, "QWxpY2U", verifiedAt = i.toLong(), compared = false, madeOn = dev) }
        val w = store.update { it.copy(contacts = big.associateBy { c -> c.userId }) }
        assertEquals(AccountStateWrite.Refused(StoredAccountState.FULL), w)
        assertEquals(0, server.puts, "nothing written")
    }

    @Test fun contacts() {
        val m = AccountMerge.merge(doc(contacts = listOf(c(k1, 5, compared = true))), doc(contacts = listOf(c(k1, 9))))
        assertEquals(9, m.document.contacts.getValue(v).verifiedAt, "newest verifiedAt wins")
        assertTrue(m.document.contacts.getValue(v).compared, "compared merges as OR")
        val kc = AccountMerge.merge(doc(contacts = listOf(c(k1, 5))), doc(contacts = listOf(c(k2, 9, compared = true))))
        assertEquals(k1, kc.document.contacts.getValue(v).identityPub, "the key this device uses stays")
        assertFalse(kc.document.contacts.getValue(v).compared)
        assertIs<MergeAnomaly.ContactKeyChange>(kc.anomalies.single())
        val gone = AccountMerge.merge(doc(contacts = listOf(c(k1, 5))), doc(tombs = listOf(ContactTombstone(v, 5))))
        assertNull(gone.document.contacts[v], "a tombstone not older than the pin removes it")
        val back = AccountMerge.merge(doc(contacts = listOf(c(k1, 6))), doc(tombs = listOf(ContactTombstone(v, 5))))
        assertEquals(6, back.document.contacts.getValue(v).verifiedAt, "a newer pin survives an older tombstone")
        val removed = AccountMerge.removeContact(doc(contacts = listOf(c(k1, 100))), v, nowMs = 50)
        assertEquals(101, removed.contactTombstones.getValue(v).removedAt, "the tombstone is stamped after the pin it removes (§5.4)")
        // design §5.4: a tombstone written on a device whose clock runs behind still removes the pin, and supersedes an earlier tombstone.
        val slow = AccountMerge.removeContact(doc(contacts = listOf(c(k1, 5_000))), v, nowMs = 10)
        assertEquals(5_001, slow.contactTombstones.getValue(v).removedAt)
        assertNull(AccountMerge.merge(doc(contacts = listOf(c(k1, 5_000))), slow).document.contacts[v], "the slow device's removal sticks")
        assertEquals(5_002, AccountMerge.removeContact(slow, v, nowMs = 10).contactTombstones.getValue(v).removedAt)
        // A contact pinned again after its removal is stamped after the tombstone, so the tombstone does not remove it again.
        val again = AccountMerge.supersedingContactAt(slow, v, nowMs = 10)
        assertEquals(5_002, again)
        val repinned = slow.copy(contacts = slow.contacts + (v to c(k1, again)))
        assertEquals(again, AccountMerge.merge(repinned, slow).document.contacts.getValue(v).verifiedAt, "the new pin survives the tombstone it supersedes")
        assertEquals(7, AccountMerge.supersedingAt(7, null), "nothing held: the device's own clock")
        assertEquals(9, AccountMerge.supersedingAt(9, 3), "a clock ahead of the held record keeps its own time")
        val many = (0 until 1005).map { ContactTombstone("00000000-0000-4000-8000-" + it.toString().padStart(12, '0'), it.toLong()) }
        val capped = AccountMerge.merge(doc(tombs = many), doc()).document.contactTombstones
        assertEquals(AccountDocument.MAX_TOMBSTONES, capped.size)
        assertNull(capped["00000000-0000-4000-8000-000000000000"], "the oldest tombstones are dropped first")
    }

    @Test fun vaults() {
        val up = AccountMerge.merge(doc(vaults = listOf(VaultRecord(u, ga, 3, ga))), doc(vaults = listOf(VaultRecord(u, ga, 7, gb))))
        assertEquals(7, up.document.vaults.getValue(u).seq)
        val g = AccountMerge.merge(doc(vaults = listOf(VaultRecord(u, ga, 3, ga))), doc(vaults = listOf(VaultRecord(u, gb, 9, gb))))
        assertEquals(ga, g.document.vaults.getValue(u).genesisHash, "genesisHash is immutable")
        assertIs<MergeAnomaly.VaultGenesisMismatch>(g.anomalies.single())
        val f = AccountMerge.merge(doc(vaults = listOf(VaultRecord(u, ga, 3, ga))), doc(vaults = listOf(VaultRecord(u, ga, 3, gb))))
        assertEquals(ga, f.document.vaults.getValue(u).hash)
        assertIs<MergeAnomaly.VaultRecordFork>(f.anomalies.single())
        assertTrue(VaultRecordBatching.due(null, VaultRecord(u, ga, 0, ga), null, 0))
        assertFalse(VaultRecordBatching.due(VaultRecord(u, ga, 1, ga), VaultRecord(u, ga, 2, ga), 1_000, 1_000 + 60_000))
        assertTrue(VaultRecordBatching.due(VaultRecord(u, ga, 1, ga), VaultRecord(u, ga, 2, ga), 1_000, 1_000 + VaultRecordBatching.INTERVAL_MS))
    }

    @Test fun acceptedAndRecovery() {
        val a = AcceptedRecord(u, v, 3, 10, AcceptedRecord.ACCEPT)
        assertEquals(5, AccountMerge.merge(doc(accepted = listOf(a)), doc(accepted = listOf(a.copy(addSeq = 5, at = 1)))).document.accepted.getValue(u).addSeq)
        assertEquals(AcceptedRecord.DECLINE, AccountMerge.merge(doc(accepted = listOf(a)), doc(accepted = listOf(a.copy(decision = AcceptedRecord.DECLINE)))).document.accepted.getValue(u).decision)
        // §5.4 as revised: for the same addSeq a decline wins whatever `at` says (a newer accept cannot outlive a leave).
        for ((l, s) in listOf(a.copy(at = 11) to a.copy(decision = AcceptedRecord.DECLINE), a.copy(decision = AcceptedRecord.DECLINE) to a.copy(at = 11))) {
            assertEquals(AcceptedRecord.DECLINE, AccountMerge.merge(doc(accepted = listOf(l)), doc(accepted = listOf(s))).document.accepted.getValue(u).decision)
        }
        assertEquals(12, AccountMerge.merge(doc(accepted = listOf(a.copy(at = 12))), doc(accepted = listOf(a.copy(at = 11)))).document.accepted.getValue(u).at, "same decision: newest at")
        val d = doc(accepted = listOf(a))
        assertEquals(Acceptance.ACCEPT, AccountMerge.acceptance(d, u, 3))
        assertEquals(Acceptance.ASK, AccountMerge.acceptance(d, u, 4), "a record for an older add answers nothing")
        assertEquals(Acceptance.ASK, AccountMerge.acceptance(d, v, 3))
        val p = RecoveryRecord("private", "none", 5)
        val o = RecoveryRecord("operator", ga, 5)
        assertEquals(p, AccountMerge.pickRecovery(o, p), "ties go to private")
        assertEquals(o.copy(at = 6), AccountMerge.pickRecovery(o.copy(at = 6), p))
    }

    @Test fun unknownKeysSurviveAndCodecRoundTrips() {
        val local = doc(seq = 2, unknown = mapOf("future" to "{\"x\":1}"))
        val served = doc(seq = 4, contacts = listOf(c(k1, 1)), recovery = RecoveryRecord("private", "none", 1), unknown = mapOf("future" to "{\"x\":2}", "other" to "[1]"))
        val m = AccountMerge.merge(local, served).document
        assertEquals(4, m.seq)
        assertEquals("{\"x\":2}", m.unknown["future"])
        assertEquals("[1]", m.unknown["other"])
        val text = AccountDocumentCodec.encode(u, m)
        val back = AccountDocumentCodec.decode(u, text)!!
        assertEquals(0, back.droppedRecords)
        assertEquals(m, back.document)
        assertNull(AccountDocumentCodec.decode(v, text), "another account's document is refused")
        val badMethod = text.replace("\"method\":\"link\"", "\"method\":\"setup\"")
        val dec = AccountDocumentCodec.decode(u, badMethod)!!
        assertEquals(1, dec.droppedRecords)
        assertTrue(dec.document.contacts.isEmpty(), "a contact with another method is refused")
    }

    @Test fun capsHoldOnMerge() {
        val many = (0 until 1001).map { ContactRecord("00000000-0000-4000-8000-" + it.toString().padStart(12, '0'), k1, "QWxpY2U", verifiedAt = it.toLong(), compared = false, madeOn = dev) }
        val merged = AccountMerge.merge(doc(contacts = many), doc()).document.contacts
        assertEquals(AccountDocument.MAX_CONTACTS, merged.size)
        assertNull(merged["00000000-0000-4000-8000-000000000000"], "the oldest contact goes first")
    }

    @Test fun aDocumentAtTheSeqLimitIsDamagedAndUnknownKeysArePrunedFirst() = runBlocking<Unit> {
        val crypto = createCryptoProvider()
        val uvk = crypto.randomBytes(32)
        val server = Server(u)
        fun serve(d: AccountDocument) { server.sealed = Envelope.sealB64(crypto, uvk, AccountDocumentCodec.encode(u, d).encodeToByteArray(), Ad.accountState(u)) }
        serve(doc(seq = StoredAccountState.MAX_SEQ))
        val store = StoredAccountState(u, uvk, server, crypto, MemoryDeviceState())
        val before = server.sealed
        assertEquals(StoredAccountState.DAMAGED, assertIs<AccountStateWrite.Refused>(store.update { it.copy(contacts = mapOf(v to c(k1, 1))) }).code)
        assertEquals(before, server.sealed, "nothing written")
        // A UVK holder fills the document with unknown keys up to the cap: they are dropped, largest first, before any record.
        serve(doc(seq = 3, unknown = mapOf("junk" to "\"" + "x".repeat(800_000) + "\"", "small" to "1")))
        val store2 = StoredAccountState(u, uvk, server, crypto, MemoryDeviceState())
        val w = assertIs<AccountStateWrite.Written>(store2.update { it.copy(contacts = mapOf(v to c(k1, 1)), accepted = mapOf(u to AcceptedRecord(u, v, 1, 1, AcceptedRecord.DECLINE))) })
        assertEquals(setOf("small"), w.document.unknown.keys)
        assertEquals(setOf(v), w.document.contacts.keys)
    }

    private class Server(val userId: String) : WireClient {
        override val origin = "https://h.example"
        var sealed: String? = null
        var cas = 0L
        var staleOnce = false
        var puts = 0
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val enc = { WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(sealed, cas)) }
            return when (route) {
                WireRoute.ACCOUNT_STATE_GET -> WireResult.Ok(decode(enc()), 200)
                WireRoute.ACCOUNT_STATE_PUT -> {
                    puts++
                    val put = WireJson.json.decodeFromString(AccountStatePut.serializer(), bodyJson!!)
                    if (staleOnce || put.baseSeq != cas) { staleOnce = false; cas++; return WireResult.Refused(409, WireError("stale_state", "m")) }
                    sealed = put.sealedState; cas++
                    WireResult.Ok(decode(enc()), 200)
                }
                else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            }
        }
    }

    @Test fun storeMergesRetriesAndDetectsRollback() = runBlocking<Unit> {
        val crypto = createCryptoProvider()
        val uvk = crypto.randomBytes(32)
        val server = Server(u)
        val state = MemoryDeviceState()
        val store = StoredAccountState(u, uvk, server, crypto, state)
        server.staleOnce = true
        val w = assertIs<AccountStateWrite.Written>(store.update { it.copy(contacts = mapOf(v to c(k1, 1))) })
        assertEquals(1, w.document.seq)
        val firstBlob = server.sealed!!
        assertIs<AccountStateWrite.Written>(store.update { it.copy(vaults = mapOf(u to VaultRecord(u, ga, 1, ga))) })
        assertIs<AccountStateWrite.Unchanged>(store.update { it })
        // Another device (same UVK) reads and merges.
        val other = StoredAccountState(u, uvk, server, crypto, MemoryDeviceState())
        val r = assertIs<AccountStateRead.Ok>(other.read())
        assertEquals(setOf(v), r.document.contacts.keys)
        assertEquals(setOf(u), r.document.vaults.keys)
        // The server rolls back to the first blob: reported, and nothing local is lost.
        server.sealed = firstBlob
        val rb = assertIs<AccountStateRead.Ok>(store.read())
        assertTrue(rb.anomalies.any { it is MergeAnomaly.Rollback })
        assertEquals(setOf(u), rb.document.vaults.keys)
        server.sealed = null
        assertTrue(assertIs<AccountStateRead.Ok>(store.read()).anomalies.contains(MergeAnomaly.Withheld))
        // A blob sealed for another account does not open.
        server.sealed = Envelope.sealB64(crypto, uvk, AccountDocumentCodec.encode(v, AccountDocument.EMPTY).encodeToByteArray(), Ad.accountState(v))
        assertIs<AccountStateRead.Unopenable>(store.read())
        assertEquals(setOf(u), store.local().vaults.keys)
    }
}
