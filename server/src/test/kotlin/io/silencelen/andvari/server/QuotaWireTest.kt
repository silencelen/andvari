package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.RemovedGrantInfo
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The use-and-limits object is now written through core's own types ([SyncResponse.quota], [AccountSummary.quota]),
 * not added by the server to the encoded object. The JSON must stay byte for byte what it was: both answers are held
 * against a stored example, and so is the way the server wrote them until now (encode the type, append `quota`).
 */
class QuotaWireTest {
    private val v1 = "11111111-1111-4111-8111-111111111111"
    private val u1 = "22222222-2222-4222-8222-222222222222"
    private val v2 = "44444444-4444-4444-8444-444444444444"
    private val m = Long.MAX_VALUE

    private fun stored(name: String): String =
        QuotaWireTest::class.java.getResourceAsStream("/quota-wire/$name")!!.readBytes().decodeToString().trimEnd('\n')

    /** How the server wrote the object before core had the field: the type encoded without it, `quota` appended. */
    private fun <T> appended(ser: KSerializer<T>, value: T, quota: QuotaUse): JsonObject =
        JsonObject(WireJson.json.encodeToJsonElement(ser, value).jsonObject + ("quota" to WireJson.json.encodeToJsonElement(QuotaUse.serializer(), quota)))

    private val q1 = QuotaUse(QuotaMeter(12, 104_857_600), QuotaMeter(1, 5_000), QuotaMeter(0, 50), QuotaMeter(0, 20))
    private val q2 = QuotaUse(QuotaMeter(m, m), QuotaMeter(0, 0), QuotaMeter(0, 1), QuotaMeter(3, 2))

    @Test
    fun theSyncAnswer_isByteForByteTheStoredExample() {
        val resp = SyncResponse(
            rev = 42, full = false,
            vaults = listOf(SyncVault(v1, "shared", 40, "AAAA", 1_800_000_000_000)),
            grants = listOf(SyncGrant(v1, u1, "writer", "BBBB", 41)),
            items = listOf(SyncItem("33333333-3333-4333-8333-333333333333", v1, 42, 1_800_000_000_001, 1_800_000_000_002, true, false, 2, emptyList(), null)),
            removedGrants = listOf(v2),
            removedGrantsInfo = listOf(RemovedGrantInfo(v2, "deleted", 1_800_000_000_003, 1_802_592_000_003)),
            linkAnswers = 1, recoveryRequests = 0,
        )
        assertEquals(stored("sync.json"), QuotaUses.syncJson(resp, q1))
        assertEquals(stored("sync.json"), WireJson.json.encodeToString(JsonObject.serializer(), appended(SyncResponse.serializer(), resp, q1)))
    }

    @Test
    fun theAccountsAnswer_isByteForByteTheStoredExample() {
        val rows = listOf(
            AccountSummary(u1, "me@example.com", "Me", "member", "active", 1_800_000_000_000, null, null, "private", 12, 1, 2, 1, quota = q1),
            AccountSummary("55555555-5555-4555-8555-555555555555", "jo@example.com", "Jo \"J\" Søren", "operator", "disabled", 1_800_000_000_004, 1_800_000_000_005, 1_800_000_000_006, "operator", m, 0, 1, 0, quota = q2),
        )
        assertEquals(stored("accounts.json"), QuotaUses.accountsJson(rows))
        val before = JsonArray(rows.map { appended(AccountSummary.serializer(), it.copy(quota = null), it.quota!!) })
        assertEquals(stored("accounts.json"), WireJson.json.encodeToString(JsonArray.serializer(), before))
    }
}
