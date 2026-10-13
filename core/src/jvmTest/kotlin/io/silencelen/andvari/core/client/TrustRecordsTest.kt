package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (plugin scan, F1/F2): the device-local trust records (vouches, held keys, member-granted,
 * declined invitations, issued tombstones, confirmed pins, consumed removal nonces) are JSON records with a strict
 * decode, never delimiter-joined lines. A legacy line record is parsed ONCE on first read: lines whose ids are not
 * UUIDs are ignored, the well-formed lines survive and are re-persisted as JSON. A JSON record of an unknown shape
 * is refused. Twin of web trustrecords.test.ts.
 */
class TrustRecordsTest {
    private val v1 = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b"
    private val v2 = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
    private val u1 = "33333333-3333-4333-8333-333333333333"
    private val tagA = "a".repeat(64)
    private val tagB = "b".repeat(64)

    @Test
    fun legacyVouchLines_migrate_andAMalformedLineIsIgnored() {
        // The scan's shape: a decoy vault id carrying a line break and a forged line for ANOTHER vault.
        val forged = "$v1\n$v2|$tagB|confirmed"
        val legacy = listOf("$forged|$tagA|frozen", "$v2|$tagA|confirmed", "not-a-uuid|$tagA|confirmed", "$v1|short|confirmed", v1).joinToString("\n")
        val d = TrustRecords.decodeVouches(legacy)
        assertTrue(d.rewrite, "a legacy record is re-persisted")
        // Only the well-formed line survives: the forged line's first half has no tag, its second half is for a vault
        // nobody vouched for... except it IS well-formed as a line, which is exactly the bug — so the record must be
        // keyed by the ids the decode accepts, never by splitting the raw text.
        assertEquals(listOf(TrustRecords.Vouch(v2, tagA, "confirmed")), d.rows.filter { it.vaultId == v2 })
        assertFalse(d.rows.any { it.vaultId == v1 }, "the decoy's own lines (no tag / short tag / bare id) are ignored")
        assertEquals(1, d.rows.size)
        val json = TrustRecords.encodeVouches(d.rows)
        assertTrue(json!!.startsWith("["), json)
        val again = TrustRecords.decodeVouches(json)
        assertFalse(again.rewrite)
        assertEquals(d.rows, again.rows)
    }

    @Test
    fun aJsonVouchRecordIsDecodedStrictly() {
        val good = """[{"vaultId":"$v1","tag":"$tagA","kind":"frozen"}]"""
        assertEquals(listOf(TrustRecords.Vouch(v1, tagA, "frozen")), TrustRecords.decodeVouches(good).rows)
        // Unknown keys, a wrong type, an unknown kind, a non-UUID id: the row is refused and the record rewritten.
        for (bad in listOf(
            """[{"vaultId":"$v1","tag":"$tagA","kind":"frozen","extra":1}]""",
            """[{"vaultId":"$v1","tag":5,"kind":"frozen"}]""",
            """[{"vaultId":"$v1","tag":"$tagA","kind":"maybe"}]""",
            """[{"vaultId":"$v1\n$v2","tag":"$tagA","kind":"confirmed"}]""",
            """[{"vaultId":"$v1","tag":"$tagA"}]""",
            """["$v1"]""",
            """{"vaultId":"$v1"}""",
        )) {
            val d = TrustRecords.decodeVouches(bad)
            assertTrue(d.rows.isEmpty(), "accepted: $bad")
            assertTrue(d.rewrite, "not rewritten: $bad")
        }
        assertEquals(emptyList(), TrustRecords.decodeVouches(null).rows)
        assertFalse(TrustRecords.decodeVouches(null).rewrite)
        assertNull(TrustRecords.encodeVouches(emptyList()))
    }

    @Test
    fun anEncoderNeverWritesARowWithAMalformedId() {
        val rows = listOf(TrustRecords.Vouch("$v1\n$v2|$tagB|confirmed", tagA, "confirmed"), TrustRecords.Vouch(v2, tagA, "confirmed"))
        val json = TrustRecords.encodeVouches(rows)!!
        assertEquals(listOf(TrustRecords.Vouch(v2, tagA, "confirmed")), TrustRecords.decodeVouches(json).rows)
        assertFalse(json.contains("\n"))
    }

    @Test
    fun heldKeys_memberGranted_declined_migrateTheSameWay() {
        val held = TrustRecords.decodeHeldKeys("$v1|$tagA\n$v1\n$v2|$tagB|confirmed\nbad|$tagA\n$v2|$tagB")
        assertTrue(held.rewrite)
        assertEquals(listOf(TrustRecords.HeldKey(v1, tagA), TrustRecords.HeldKey(v2, tagB)), held.rows)
        assertEquals(held.rows, TrustRecords.decodeHeldKeys(TrustRecords.encodeHeldKeys(held.rows)).rows)

        val granted = TrustRecords.decodeIdSet("$v1\nnot-a-uuid\n$v2|x\n$v2")
        assertTrue(granted.rewrite)
        assertEquals(setOf(v1, v2), granted.rows.toSet())
        assertEquals(setOf(v1, v2), TrustRecords.decodeIdSet(TrustRecords.encodeIdSet(granted.rows)).rows.toSet())
        assertTrue(TrustRecords.decodeIdSet("""["$v1","$v2|x",7]""").rows == listOf(v1))

        // Declined invitations are keyed by the grantId's base64url form (not a UUID): the token grammar applies.
        val declined = TrustRecords.decodeTokenSet("AAAAAAAAAAAAAAAAAAAAAA\nbad token\n")
        assertEquals(listOf("AAAAAAAAAAAAAAAAAAAAAA"), declined.rows)
        assertTrue(declined.rewrite)
    }

    @Test
    fun tombstones_confirmedPins_consumedNonces_migrateTheSameWay() {
        val tomb = TrustRecords.decodeTombstones("$v1|$u1|1700000000000\n$v1|$u1|x\n$v1\n$v2|$u1|5")
        assertTrue(tomb.rewrite)
        assertEquals(listOf(TrustRecords.Tombstone(v1, u1, 1700000000000L), TrustRecords.Tombstone(v2, u1, 5L)), tomb.rows)
        assertEquals(tomb.rows, TrustRecords.decodeTombstones(TrustRecords.encodeTombstones(tomb.rows)).rows)

        val pins = TrustRecords.decodeConfirmedPins("$u1|$tagA\n$u1|short\n$v1\n$v2|$tagB")
        assertTrue(pins.rewrite)
        assertEquals(listOf(TrustRecords.ConfirmedPin(u1, tagA), TrustRecords.ConfirmedPin(v2, tagB)), pins.rows)
        assertEquals(pins.rows, TrustRecords.decodeConfirmedPins(TrustRecords.encodeConfirmedPins(pins.rows)).rows)

        val nonces = TrustRecords.decodeConsumedNonces("$v1|AAAAAAAAAAAAAAAAAAAAAA|7\nbad|AAAAAAAAAAAAAAAAAAAAAA|7\n$v1|a b|7\n$v1|AAAAAAAAAAAAAAAAAAAAAA|x")
        assertTrue(nonces.rewrite)
        assertEquals(listOf(TrustRecords.ConsumedNonce(v1, "AAAAAAAAAAAAAAAAAAAAAA", 7L)), nonces.rows)
        assertEquals(nonces.rows, TrustRecords.decodeConsumedNonces(TrustRecords.encodeConsumedNonces(nonces.rows)).rows)
    }
}
