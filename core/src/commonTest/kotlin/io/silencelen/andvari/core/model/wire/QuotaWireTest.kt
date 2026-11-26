package io.silencelen.andvari.core.model.wire

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** `quota` on the sync answer and on the operator's accounts row (spec 03 §4, §7.1, §14.4): additive, and never fatal. */
class QuotaWireTest {
    private val json = WireJson.json

    private val meters = """{"accountBytes":{"used":1834,"limit":104857600},"items":{"used":12,"limit":5000},""" +
        """"ownedSharedVaults":{"used":1,"limit":50},"openLinks":{"used":0,"limit":20}}"""
    private val example = QuotaUse(QuotaMeter(1834, 104857600), QuotaMeter(12, 5000), QuotaMeter(1, 50), QuotaMeter(0, 20))

    private val olderSync = """{"rev":7,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[],"removedGrantsInfo":[],"linkAnswers":2,"recoveryRequests":1}"""
    private fun sync(quota: String) = olderSync.dropLast(1) + ""","quota":$quota}"""

    private val olderRow = """{"userId":"u","email":"a@b.example","displayName":"A","role":"member","status":"active","createdAt":1,""" +
        """"lastSeenAt":null,"recovery":"private","usedBytes":1834,"itemCount":12,"ownedVaultCount":2,"liveDeviceCount":1}"""
    private fun row(quota: String) = olderRow.dropLast(1) + ""","quota":$quota}"""

    private fun syncOf(text: String) = json.decodeFromString(SyncResponse.serializer(), text)
    private fun rowOf(text: String) = json.decodeFromString(AccountSummary.serializer(), text)

    @Test
    fun anOlderServersAnswersStillDecodeWithNoQuota() {
        val s = syncOf(olderSync)
        assertNull(s.quota)
        assertEquals(7, s.rev)
        assertEquals(2, s.linkAnswers)
        assertNull(rowOf(olderRow).quota)
        assertEquals(1834, rowOf(olderRow).usedBytes)
    }

    @Test
    fun theSpecsExampleDecodesOnBothAnswers() {
        assertEquals(example, syncOf(sync(meters)).quota)
        assertEquals(example, rowOf(row(meters)).quota)
        // A later quota name is a key this client does not know: ignored, the four it knows are read.
        assertEquals(example, syncOf(sync(meters.dropLast(1) + ""","vaultMembers":{"used":3,"limit":9}}""")).quota)
        // Nineteen digits, the largest a meter can carry (the server's 293-byte bound).
        val top = """{"used":${Long.MAX_VALUE},"limit":${Long.MAX_VALUE}}"""
        val edge = syncOf(sync("""{"accountBytes":$top,"items":$top,"ownedSharedVaults":$top,"openLinks":$top}""")).quota
        assertEquals(QuotaMeter(Long.MAX_VALUE, Long.MAX_VALUE), edge?.openLinks)
    }

    @Test
    fun itEncodesAsTheServerWritesItTheLastKeyAndAbsentWhenNull() {
        val s = syncOf(olderSync)
        val text = json.encodeToString(SyncResponse.serializer(), s.copy(quota = example))
        assertEquals(sync(meters), text, "the server's JSON: `quota` appended as the last key")
        assertEquals(example, syncOf(text).quota)
        assertEquals(olderSync, json.encodeToString(SyncResponse.serializer(), s), "no quota, no key")
        val r = rowOf(olderRow)
        assertEquals(row(meters), json.encodeToString(AccountSummary.serializer(), r.copy(quota = example)))
    }

    /** What a lying server can put there: each is unknown (null), and the rest of the answer is read as it was. */
    @Test
    fun anObjectThatCannotBeMetersIsUnknownAndNeverFailsTheAnswer() {
        val lies = listOf(
            "null",
            "0",
            "\"lots\"",
            "[]",
            "{}",
            meters.replace("\"used\":12", "\"used\":-1"),
            meters.replace("\"limit\":5000", "\"limit\":-5000"),
            meters.replace("\"limit\":20", "\"limit\":${Long.MIN_VALUE}"),
            meters.replace("\"used\":1834", "\"used\":9223372036854775808"),
            meters.replace("\"limit\":104857600", "\"limit\":1e40"),
            meters.replace("\"used\":1,", "\"used\":1.5,"),
            meters.replace("\"used\":0", "\"used\":null"),
            meters.replace("\"used\":0", "\"used\":true"),
            meters.replace(""","openLinks":{"used":0,"limit":20}""", ""),
            meters.replace("""{"used":12,"limit":5000}""", "[12,5000]"),
        )
        for (lie in lies) {
            val s = syncOf(sync(lie))
            assertNull(s.quota, lie)
            assertEquals(7, s.rev, lie)
            assertEquals(1, s.recoveryRequests, lie)
            val r = rowOf(row(lie))
            assertNull(r.quota, lie)
            assertEquals(12, r.itemCount, lie)
        }
    }

    @Test
    fun wholeNumbersAreWhatAMeterIs() {
        assertTrue(example.isWhole())
        assertFalse(example.copy(items = QuotaMeter(-1, 5)).isWhole())
        assertFalse(example.copy(openLinks = QuotaMeter(0, -1)).isWhole())
        val obj: JsonObject = json.parseToJsonElement(json.encodeToString(QuotaUse.serializer(), example)).jsonObject
        assertEquals(listOf(QuotaName.ACCOUNT_BYTES, QuotaName.ITEMS, QuotaName.OWNED_SHARED_VAULTS, QuotaName.OPEN_LINKS), obj.keys.toList(), "the keys are the quota names")
    }
}
