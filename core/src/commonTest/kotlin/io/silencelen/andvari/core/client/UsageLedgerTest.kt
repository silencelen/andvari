package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.UsageLedger.Entry
import kotlin.test.Test
import kotlin.test.assertEquals
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
}
