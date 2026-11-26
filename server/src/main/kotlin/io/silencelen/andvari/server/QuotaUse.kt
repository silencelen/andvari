package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaUse
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import java.sql.Connection

/**
 * `quota` on `GET /sync` and on each `GET /admin/accounts` row (spec 03 §4, §7.1, §14.4), written through core's own
 * wire types: [QuotaUse] and [QuotaMeter], the last field of [SyncResponse] and of [AccountSummary]. Until those types
 * existed the server added the key to the encoded object itself; the JSON is byte for byte the same (QuotaWireTest
 * holds both answers against a stored example). At most [QuotaUses.MAX_JSON_BYTES] bytes with its key.
 */
object QuotaUses {
    /** `,"quota":` and the object with every number at `Long.MAX_VALUE` (19 digits): 9 + 284 bytes. */
    const val MAX_JSON_BYTES = 293

    /**
     * [userId]'s meters, read in the caller's transaction with the same counting functions the checks use
     * ([Quotas] and [Policy.quotaOf]), so "used + what I add > limit" is exactly the check's refusal at that instant.
     */
    fun of(s: Services, c: Connection, userId: String, nowMs: Long, p: AdminPolicy = s.policy.get()): QuotaUse {
        val q = s.policy.quotaOf(c, userId, p)
        return QuotaUse(
            accountBytes = QuotaMeter(Quotas.ownedBytes(c, userId), q.accountBytes),
            items = QuotaMeter(Quotas.ownedItems(c, userId), q.items),
            ownedSharedVaults = QuotaMeter(Quotas.ownedSharedVaults(c, userId), q.ownedSharedVaults),
            openLinks = QuotaMeter(Quotas.openLinks(c, userId, nowMs), q.openLinks),
        )
    }

    /** The `GET /sync` answer: [resp] with its meters, `quota` its last key. */
    fun syncJson(resp: SyncResponse, quota: QuotaUse): String = WireJson.json.encodeToString(SyncResponse.serializer(), resp.copy(quota = quota))

    /** The `GET /admin/accounts` answer: each row carries its own meters, `quota` its last key. */
    fun accountsJson(rows: List<AccountSummary>): String = WireJson.json.encodeToString(ListSerializer(AccountSummary.serializer()), rows)
}
