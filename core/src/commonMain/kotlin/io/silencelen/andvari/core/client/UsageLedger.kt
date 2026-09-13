package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonObject

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

    /**
     * The prune keep-set a client builds from a landed FULL sync (audit G04, corrected by H36):
     * the id of EVERY live envelope the server holds — decryptable or not — with tombstones
     * excluded. Twin of web Vault.tsx (`store.list()` ∪ `store.undecryptable()`) and the
     * extension's resync (`sync.items.filter(!deleted)`).
     *
     * WHY THE RAW ENVELOPES AND NEVER THE DECRYPTED ITEM LIST. `SyncEngine.items()` is the
     * WORKING set: it silently omits an envelope whose formatVersion is newer than this build's
     * ceiling (fail-closed, spec 02 §3 — the "N items need an app update" state) and every
     * envelope in a vault whose key this device does not hold yet (an unopened grant, a recovery
     * in progress). Those items are live on the server and readable on the user's other, newer
     * devices. Feeding [prune] the working set erased their usage on every 5-min poll of the
     * older device, and the newer devices then ranked those logins as unused — the exact false
     * "stale" verdict the ledger exists to prevent. An entry may only be dropped for an item the
     * SERVER no longer has, which is precisely "not in the envelope feed".
     */
    fun liveItemIds(envelopes: List<WireItem>): Set<String> =
        envelopes.filter { !it.deleted }.mapTo(HashSet()) { it.itemId }

    /**
     * What a flush learned about the server's copy before deciding whether to write (spec 02
     * §8.2, audit H05). Three DISTINCT outcomes rather than a nullable map, because two of them
     * used to collapse into "empty" — and an empty server view merged with one session's buffer
     * and PUT back is how one device's handful of uses overwrote the whole household's ledger.
     */
    sealed interface ServerCopy {
        /** The GET succeeded and answered `sealedUsage: null`: this account has never written a
         *  ledger. The ONLY case in which a write with no server merge is a first write rather
         *  than an overwrite. */
        object Absent : ServerCopy

        /** The GET succeeded and the blob opened under our key — [map] is authoritative. A blob
         *  that opens but parses as garbage is a PRESENT, EMPTY ledger ([parse] is tolerant by
         *  contract on every twin): it authenticated under this user's key, so replacing it is
         *  the "corrupt ledger costs one health column" posture, not a cross-client overwrite. */
        data class Present(val map: Map<String, Entry>) : ServerCopy

        /** The GET failed (offline, 5xx, 401, timeout) OR a blob came back that would NOT open
         *  (wrong key, AD mismatch, a future encoding). Either way this client cannot see what it
         *  would be replacing, and spec 02 §8.2 says it MUST leave the ledger untouched. */
        object Unreadable : ServerCopy
    }

    /**
     * Decide what ONE flush round PUTs — the ledger to store, or null for "do not write this
     * round". Pure, and the KOTLIN TWIN of `planFlush` in web/src/vault/usage.ts and
     * extension/src/usage.ts: the three clients pin the same cases so they cannot drift.
     *
     *  - [ServerCopy.Unreadable] → null, ALWAYS, even with buffered uses. The endpoint is
     *    last-writer-wins with no server-side merge, so a PUT here would replace the household's
     *    whole ledger with [mine] — spec 02 §8.2's "a client that cannot open the ledger MUST
     *    leave it untouched". The shell re-buffers [mine] and the next flush retries; the
     *    conservative direction loses at most one session's ranking hints.
     *  - [ServerCopy.Absent] → [mine] if non-empty (the first write), else null.
     *  - [ServerCopy.Present] → merge, then prune when [liveItemIds] was handed in (against the
     *    live set PLUS [mine]'s keys — a use buffered after the caller's snapshot is inherently
     *    live: you cannot copy a deleted item's secret — so a stale snapshot may under-prune,
     *    never drop a live entry), and write ONLY if something changed: buffered uses, or a
     *    prune that dropped an entry. A quiet post-sync prune therefore costs one GET and no
     *    `updatedAt` bump (spec 03 §3: batched, never spurious).
     */
    fun planFlush(server: ServerCopy, mine: Map<String, Entry>, liveItemIds: Set<String>?): Map<String, Entry>? = when (server) {
        ServerCopy.Unreadable -> null
        ServerCopy.Absent -> mine.takeIf { it.isNotEmpty() }
        is ServerCopy.Present -> {
            var merged = merge(server.map, mine)
            if (liveItemIds != null) merged = prune(merged, liveItemIds + mine.keys)
            if (mine.isNotEmpty() || merged.size != server.map.size) merged else null
        }
    }

    /**
     * Tolerant parse: anything malformed reads as an EMPTY ledger and never throws. A corrupt
     * ledger must cost one health column, never an unlock or a fill.
     *
     * The tolerance is PER ENTRY and the typing is STRICT — the contract spec 02 §8.2 states and
     * `spec/test-vectors/usageledger.json` pins for all three twins ([UsageLedgerVectorsTest]):
     *  - a value that is not a JSON number (a string "1755…", a boolean, an object, an array)
     *    is NOT a number: a string-typed stamp drops that entry, a string-typed count defaults
     *    to 1 — exactly what `typeof x === "number"` does in the web and extension twins. Reading
     *    "1755000000000" as a number here would make this client rank an item the other two
     *    consider unstamped, and the first flush would then write that stamp back for everyone.
     *  - one bad ENTRY costs that entry and never the ledger. There is deliberately NO
     *    `runCatching` around the entry loop: the previous one turned a single nested-object
     *    stamp (which made `jsonPrimitive` throw) into "read as empty", and because a flush
     *    re-merges against what it parsed, "empty" became "overwrite the household's ledger with
     *    this session's few uses" (audit H92 + H05). The only guard is around the JSON parse
     *    itself, where the document as a whole is garbage and there is no entry to save.
     *  - unknown entry keys are dropped, not preserved (unlike item documents, spec 02 §3): the
     *    blob is wholly rewritten by one writer at a time and carries nothing user-authored.
     */
    fun parse(text: String): Map<String, Entry> {
        val root = runCatching { json.parseToJsonElement(text) }.getOrNull() as? JsonObject ?: return emptyMap()
        return buildMap {
            for ((itemId, v) in root) {
                val o = v as? JsonObject ?: continue
                // Encoded as JSON numbers; read through Double because the web twin writes them
                // as IEEE-754 and epoch millis sit far inside the exactly-representable range.
                // 1e999 lexes as a literal whose Double is infinite, so the finiteness check is
                // what rejects it — the same `Number.isFinite` gate the twins apply.
                val last = o["lastUsedAt"].asFiniteNumber() ?: continue
                val count = o["useCount"].asFiniteNumber() ?: 1.0
                put(itemId, Entry(last.toLong(), count.toLong()))
            }
        }
    }

    /** A JSON NUMBER as a finite Double, or null for anything else — a quoted number is a string. */
    private fun JsonElement?.asFiniteNumber(): Double? =
        (this as? JsonPrimitive)?.takeIf { !it.isString }?.doubleOrNull?.takeIf { it.isFinite() }

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
