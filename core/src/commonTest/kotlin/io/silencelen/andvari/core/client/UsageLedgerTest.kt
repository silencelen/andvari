package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.UsageLedger.Entry
import io.silencelen.andvari.core.client.UsageLedger.ServerCopy
import io.silencelen.andvari.core.model.WireItem
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Usage ledger (spec 02 §8.2) — the Kotlin third of a three-way twin with
 * web/src/vault/usage.ts and extension/src/usage.ts.
 *
 * These are CONVERGENCE pins. All three clients write the same server-side blob, so if their
 * merge rules diverge they stop converging and start clobbering each other's entries — a bug
 * that surfaces long after the change, as "my phone's usage keeps disappearing".
 */
class UsageLedgerTest {

    private val T = 1_755_000_000_000L

    @Test
    fun mergeKeepsTheMostRecentUsePerItem() {
        val a = mapOf("x" to Entry(T, 2))
        val b = mapOf("x" to Entry(T + 1000, 1))
        assertEquals(Entry(T + 1000, 2), UsageLedger.merge(a, b)["x"])
    }

    /** Max and not sum: a flush re-merges against the server copy, so summing would re-count the
     *  same uses on every round trip and inflate without bound. */
    @Test
    fun mergeIsIdempotent() {
        val m = mapOf("x" to Entry(T, 5))
        assertEquals(m, UsageLedger.merge(m, m))
        assertEquals(m, UsageLedger.merge(UsageLedger.merge(m, m), m))
    }

    @Test
    fun mergeIsOrderIndependentSoClientsConverge() {
        val a = mapOf("x" to Entry(T + 5, 1), "y" to Entry(T, 9))
        val b = mapOf("x" to Entry(T, 4), "z" to Entry(T + 2, 1))
        assertEquals(UsageLedger.merge(a, b), UsageLedger.merge(b, a))
    }

    @Test
    fun mergeKeepsEntriesOnlyOneSideHas() {
        val out = UsageLedger.merge(mapOf("a" to Entry(T, 1)), mapOf("b" to Entry(T, 1)))
        assertEquals(setOf("a", "b"), out.keys)
    }

    @Test
    fun recordStampsAndIncrements() {
        assertEquals(Entry(T, 1), UsageLedger.record(emptyMap(), "x", T)["x"])
        assertEquals(Entry(T + 5, 2), UsageLedger.record(mapOf("x" to Entry(T, 1)), "x", T + 5)["x"])
    }

    /** A device whose clock runs backwards must not walk an item's stamp down. */
    @Test
    fun recordNeverMovesAStampBackwards() {
        assertEquals(T, UsageLedger.record(mapOf("x" to Entry(T, 1)), "x", T - 99_999)["x"]!!.lastUsedAt)
    }

    @Test
    fun pruneDropsEntriesWhoseItemIsGone() {
        val m = mapOf("alive" to Entry(T, 1), "deleted" to Entry(T, 1))
        assertEquals(setOf("alive"), UsageLedger.prune(m, setOf("alive")).keys)
    }

    /** The hazard prune's contract exists for: a PARTIAL set discards usage for items merely not
     *  loaded yet. Pinned so nobody wires it to a mid-sync snapshot. */
    @Test
    fun pruneWithAnEmptySetDropsEverything() {
        assertTrue(UsageLedger.prune(mapOf("a" to Entry(T, 1)), emptySet()).isEmpty())
    }

    /**
     * THE CROSS-IMPL PIN: the exact wire shape. web's `JSON.stringify` produces this byte-for-byte,
     * and both TS twins parse it. If this string ever drifts, the native clients and the browser
     * clients stop reading each other's ledgers.
     */
    @Test
    fun serializeMatchesTheJavaScriptWireShape() {
        assertEquals(
            """{"x":{"lastUsedAt":1755000000000,"useCount":2}}""",
            UsageLedger.serialize(mapOf("x" to Entry(T, 2))),
        )
    }

    @Test
    fun parseRoundTripsItsOwnOutput() {
        val m = mapOf("x" to Entry(T, 2), "y" to Entry(T + 1, 1))
        assertEquals(m, UsageLedger.parse(UsageLedger.serialize(m)))
    }

    /** A corrupt ledger must cost one health column, never an unlock or a fill. */
    @Test
    fun parseReadsGarbageAsEmptyInsteadOfThrowing() {
        for (bad in listOf("", "not json", "null", "[]", "42", "\"str\"")) {
            assertEquals(emptyMap(), UsageLedger.parse(bad), "input=$bad")
        }
    }

    @Test
    fun parseSkipsMalformedEntriesAndDefaultsAMissingCount() {
        val parsed = UsageLedger.parse(
            """{"good":{"lastUsedAt":$T},"noStamp":{"useCount":4},"nullEntry":null}""",
        )
        assertEquals(setOf("good"), parsed.keys)
        assertEquals(Entry(T, 1), parsed["good"])
    }

    // ---- planFlush (spec 02 §8.2 — audit H05 / H35; the same cases are pinned on web and the
    // extension, so the three flush engines cannot drift in WHEN they write) ----

    private val mine = mapOf("local" to Entry(T + 1000, 1))

    /** THE H05 rule: a server copy this client could not fetch or open is never overwritten,
     *  buffered uses or not. A PUT here would replace the household's ledger with one session's
     *  handful of entries — the endpoint has no server-side merge to save it. */
    @Test
    fun planFlushNeverWritesOverAnUnreadableServerCopy() {
        assertNull(UsageLedger.planFlush(ServerCopy.Unreadable, mine, liveItemIds = null))
        assertNull(UsageLedger.planFlush(ServerCopy.Unreadable, mine, liveItemIds = setOf("local")))
        assertNull(UsageLedger.planFlush(ServerCopy.Unreadable, emptyMap(), liveItemIds = setOf("x")))
    }

    /** `sealedUsage: null` is the ONE case a merge-less write is a first write, not an overwrite. */
    @Test
    fun planFlushWritesTheBufferAsAFirstLedgerWhenTheServerHasNone() {
        assertEquals(mine, UsageLedger.planFlush(ServerCopy.Absent, mine, liveItemIds = null))
        assertEquals(mine, UsageLedger.planFlush(ServerCopy.Absent, mine, liveItemIds = setOf("other")))
        assertNull(UsageLedger.planFlush(ServerCopy.Absent, emptyMap(), liveItemIds = null), "nothing buffered, nothing to create")
        assertNull(UsageLedger.planFlush(ServerCopy.Absent, emptyMap(), liveItemIds = setOf("x")), "a prune request against no ledger writes nothing")
    }

    @Test
    fun planFlushMergesTheBufferOverAReadableServerCopy() {
        val server = mapOf("other-device-item" to Entry(T, 2))
        val put = UsageLedger.planFlush(ServerCopy.Present(server), mine, liveItemIds = null)
        assertEquals(setOf("other-device-item", "local"), put?.keys, "the other device's entry survives our flush")
    }

    /** H35: a prune request with an EMPTY buffer must still drop a deleted item's entry — the
     *  post-sync prune is the growth bound, and a sync almost never lands inside the debounce
     *  window, so gating it on buffered uses left it inert (the web/extension defect). */
    @Test
    fun planFlushPrunesWithAnEmptyBuffer() {
        val server = mapOf("alive" to Entry(T, 3), "deleted" to Entry(T, 9))
        val put = UsageLedger.planFlush(ServerCopy.Present(server), emptyMap(), liveItemIds = setOf("alive"))
        assertEquals(setOf("alive"), put?.keys)
        assertEquals(Entry(T, 3), put?.get("alive"), "the live entry is untouched")
    }

    /** Batched, never spurious (spec 03 §3): a quiet prune that drops nothing and has nothing
     *  buffered must not write — no `updatedAt` bump on every 5-min poll. */
    @Test
    fun planFlushDoesNotWriteWhenAPruneChangesNothing() {
        val server = mapOf("alive" to Entry(T, 1))
        assertNull(UsageLedger.planFlush(ServerCopy.Present(server), emptyMap(), liveItemIds = setOf("alive")))
        assertNull(UsageLedger.planFlush(ServerCopy.Present(server), emptyMap(), liveItemIds = null), "a bare flush with nothing buffered writes nothing")
    }

    /** A use buffered AFTER the caller snapshotted the live set is inherently live and must
     *  survive the prune — a stale snapshot may under-prune, never drop a live entry. */
    @Test
    fun planFlushKeepsABufferedUseTheSnapshotDoesNotKnow() {
        val server = mapOf("alive" to Entry(T, 1))
        val fresh = mapOf("fresh" to Entry(T + 1000, 1))
        val put = UsageLedger.planFlush(ServerCopy.Present(server), fresh, liveItemIds = setOf("alive"))
        assertEquals(setOf("alive", "fresh"), put?.keys)
    }

    // ---- liveItemIds (audit H36) ----

    private fun envelope(id: String, vaultId: String, fv: Int, deleted: Boolean = false) = WireItem(
        itemId = id, vaultId = vaultId, rev = 1, createdAt = 0, updatedAt = 0,
        deleted = deleted, conflict = false, formatVersion = fv, attachmentIds = emptyList(), blob = if (deleted) null else "sealed",
    )

    /** The keep-set is every LIVE envelope — a newer-fv item this build cannot open and an item
     *  in a vault whose key has not arrived are live on the server and must not be pruned; only
     *  a tombstone is out. */
    @Test
    fun liveItemIdsKeepsUnreadableEnvelopesAndDropsTombstones() {
        val ids = UsageLedger.liveItemIds(
            listOf(
                envelope("readable", "personal", fv = 1),
                envelope("newer-fv", "personal", fv = 99),
                envelope("unheld-vault", "not-ours", fv = 1),
                envelope("gone", "personal", fv = 1, deleted = true),
            ),
        )
        assertEquals(setOf("readable", "newer-fv", "unheld-vault"), ids)
    }
}
