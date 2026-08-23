package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The usage ledger (spec 02 §8.2) — "when did I last use this login", the signal behind the
 * vault-health staleness ranking. Shared by the native clients; the KOTLIN TWIN of
 * web/src/vault/usage.ts and extension/src/usage.ts.
 *
 * **The merge rule must stay identical across all three or the clients stop converging and start
 * clobbering each other's entries** — a bug that surfaces much later as "my phone's usage keeps
 * disappearing". [UsageLedgerTest] pins it on this side; the other two pin the same cases.
 *
 * ONE SEALED BLOB PER USER, never a field on the item and never a row per item. A `usedAt` in the
 * item document would make every use an item overwrite, and spec 02 §7 caps `item_versions` at
 * ten per item — so roughly ten uses would evict an item's whole real edit history. Per-item rows
 * would leak the same behavioural timing through row metadata instead.
 *
 * Pure and platform-free so commonTest can pin every decision; [Account.sealUsage] does the
 * crypto and the callers own the network and the batching.
 */
object UsageLedger {

    /** One item's record. [useCount] is a FLOOR, not an exact total — see [merge]. */
    data class Entry(val lastUsedAt: Long, val useCount: Long)

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Merge two ledgers. **Both fields take the MAX, so `useCount` is a floor rather than a true
     * total.** Summing is the intuitive choice and is wrong: a flush re-merges against the server
     * copy, so the same use would be re-counted on every round trip and inflate without bound.
     * Max is idempotent and order-independent, so any sequence of merges between any number of
     * clients converges — which matters far more here than exactness, since nothing but a column
     * reads it.
     */
    fun merge(a: Map<String, Entry>, b: Map<String, Entry>): Map<String, Entry> {
        val out = a.toMutableMap()
        for ((itemId, entry) in b) {
            val held = out[itemId]
            out[itemId] = if (held == null) entry
            else Entry(maxOf(held.lastUsedAt, entry.lastUsedAt), maxOf(held.useCount, entry.useCount))
        }
        return out
    }

    /** Stamp one use. Clamps backwards so a device whose clock runs slow cannot walk a stamp down. */
    fun record(map: Map<String, Entry>, itemId: String, now: Long): Map<String, Entry> {
        val held = map[itemId]
        return map + (itemId to Entry(maxOf(held?.lastUsedAt ?: 0L, now), (held?.useCount ?: 0L) + 1L))
    }

    /** Drop entries whose item is gone, so a long-lived ledger cannot grow without bound.
     *  The caller MUST pass the COMPLETE live item set — a partial one would silently discard
     *  usage for items that are merely not loaded yet, which is why this is explicit. */
    fun prune(map: Map<String, Entry>, liveItemIds: Set<String>): Map<String, Entry> =
        map.filterKeys { it in liveItemIds }

    /** Tolerant parse: anything malformed reads as an EMPTY ledger and never throws. A corrupt
     *  ledger must cost one health column, never an unlock or a fill. */
    fun parse(text: String): Map<String, Entry> = runCatching {
        val root = json.parseToJsonElement(text) as? JsonObject ?: return emptyMap()
        buildMap {
            for ((itemId, v) in root) {
                val o = v as? JsonObject ?: continue
                // Encoded as JSON numbers; read through Double because the web twin writes them
                // as IEEE-754 and epoch millis sit far inside the exactly-representable range.
                val last = o["lastUsedAt"]?.jsonPrimitive?.doubleOrNull ?: continue
                if (!last.isFinite()) continue
                val count = o["useCount"]?.jsonPrimitive?.doubleOrNull?.takeIf { it.isFinite() } ?: 1.0
                put(itemId, Entry(last.toLong(), count.toLong()))
            }
        }
    }.getOrDefault(emptyMap())

    /** Serialize in the shape the web and extension twins read. Built through the JSON tree
     *  rather than string concatenation so an itemId can never break out of its own key. */
    fun serialize(map: Map<String, Entry>): String =
        buildJsonObject {
            for ((itemId, e) in map) {
                put(
                    itemId,
                    buildJsonObject {
                        put("lastUsedAt", e.lastUsedAt)
                        put("useCount", e.useCount)
                    },
                )
            }
        }.toString()
}
