package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.items.Shortfall
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.QuotaUse
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/** The exit code of a copy that did not start because the account is short of space (spec 03 §14.4). */
const val EXIT_SHORT_OF_SPACE = 4

/** Its message key. */
const val KEY_SHORT_OF_SPACE = "account_short_of_space"

/** The account's meters (spec 03 §14.4) as the tool shows them, and the refusal of a copy the account has no room for. */
object Quotas {
    private val METERS = listOf(QuotaName.ACCOUNT_BYTES, QuotaName.ITEMS, QuotaName.OWNED_SHARED_VAULTS, QuotaName.OPEN_LINKS)

    /** A meter's name in words. */
    fun words(quota: String): String = when (quota) {
        QuotaName.ACCOUNT_BYTES -> "storage"
        QuotaName.ITEMS -> "items"
        QuotaName.OWNED_SHARED_VAULTS -> "shared vaults it owns"
        QuotaName.OPEN_LINKS -> "open links"
        else -> quota
    }

    private fun meter(q: QuotaUse, name: String): QuotaMeter = when (name) {
        QuotaName.ACCOUNT_BYTES -> q.accountBytes
        QuotaName.ITEMS -> q.items
        QuotaName.OWNED_SHARED_VAULTS -> q.ownedSharedVaults
        else -> q.openLinks
    }

    private fun amount(quota: String, n: Long): String = if (quota == QuotaName.ACCOUNT_BYTES) "$n bytes" else "$n"

    /** Each meter as `name used of limit`, in the spec's order; [q] null (the server gave none) is said as unknown. */
    fun lines(q: QuotaUse?): List<String> =
        if (q == null || !q.isWhole()) listOf("the server gave no usage figures (unknown)")
        else METERS.map { m -> meter(q, m).let { "${words(m)}: ${amount(m, it.used)} used of ${amount(m, it.limit)}" } }

    /** The meters on one line, for a listing: `items 3/5000  storage 120/1048576 bytes  ...`, or `quota unknown`. */
    fun short(q: QuotaUse?): String =
        if (q == null || !q.isWhole()) "quota unknown"
        else METERS.joinToString("  ") { m -> meter(q, m).let { "${words(m).substringBefore(' ')} ${it.used}/${it.limit}" } }

    /** The meters as `--json` gives them: `{accountBytes: {used, limit}, ...}`, or null when unknown. */
    fun json(q: QuotaUse?): JsonElement =
        if (q == null || !q.isWhole()) JsonNull
        else JsonObject(METERS.associateWith { m -> meter(q, m).let { buildJsonObject { put("used", JsonPrimitive(it.used)); put("limit", JsonPrimitive(it.limit)) } } })

    /** A copy the account has no room for, as `--json` gives it on standard output: `{error, short: [{quota, used, limit, adds, by}]}`. */
    fun shortDocument(limits: List<Shortfall>): JsonObject = buildJsonObject {
        put("error", JsonPrimitive(KEY_SHORT_OF_SPACE))
        put("short", JsonArray(limits.map { f ->
            buildJsonObject {
                put("quota", JsonPrimitive(f.quota)); put("used", JsonPrimitive(f.used)); put("limit", JsonPrimitive(f.limit))
                put("adds", JsonPrimitive(f.adds)); put("by", JsonPrimitive(f.by))
            }
        }))
    }

    /** [what] did not start: which limit, by how much, and that the operator can raise it. */
    fun shortError(limits: List<Shortfall>, what: String): CliError = CliError.lines(
        listOf("the account is short of space, so $what did not start and nothing was written:") +
            limits.map { f -> "  - ${words(f.quota)}: ${amount(f.quota, f.used)} used of ${amount(f.quota, f.limit)}; it would add ${amount(f.quota, f.adds)}, ${amount(f.quota, f.by)} too many" } +
            "The server's operator can raise the limit (`andvari-cli operator quota`), or make room first",
        EXIT_SHORT_OF_SPACE, KEY_SHORT_OF_SPACE,
    )
}
