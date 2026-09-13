package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.UsageLedger.Entry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Consumes `spec/test-vectors/usageledger.json` — the SAME file web `usage.vectors.test.ts` and
 * extension `usage.vectors.test.ts` run — so the three ledger twins (spec 02 §8.2) parse, merge,
 * record, prune and serialize identically.
 *
 * Why a shared file when [UsageLedgerTest] already pins the merge rule: those three suites were
 * hand-mirrored, and by the 2026-09-13 audit (H92) the Kotlin parse had drifted from its two
 * twins while every suite stayed green — string-typed numbers were accepted, and one malformed
 * nested field emptied the WHOLE ledger instead of dropping one entry. Combined with a flush that
 * re-merges against what it parsed, "read as empty" on one client is "overwrite the household's
 * ledger with this session's few entries" (H05). Only a corpus all three read catches a drift all
 * three consider correct.
 *
 * `expected` is the TS twins' behaviour (the ledger names web `parseUsage` as the sibling that is
 * right): a string is never a number; a bad ENTRY costs that entry, never the ledger.
 */
class UsageLedgerVectorsTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "usageledger.json").readText()).jsonObject

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.cases(k: String) = getValue(k).jsonArray.map { it.jsonObject }

    /** A ledger literal from the vector: `{ itemId: { lastUsedAt, useCount } }`, insertion order kept. */
    private fun ledger(o: JsonObject): Map<String, Entry> = LinkedHashMap<String, Entry>().also { out ->
        for ((id, e) in o) out[id] = Entry(e.jsonObject.getValue("lastUsedAt").jsonPrimitive.long, e.jsonObject.getValue("useCount").jsonPrimitive.long)
    }

    @Test
    fun parseMatchesTheSharedCorpus() {
        for (c in v.cases("parse")) {
            assertEquals(ledger(c.getValue("expected").jsonObject), UsageLedger.parse(c.s("inputUtf8")), "parse ${c.s("name")}")
        }
    }

    /** The parse block must keep carrying the two drifts H92 found, or the loop above grades the
     *  easy cases only: a string-typed number that must NOT parse, and a nested field that must
     *  cost one entry while the good entry beside it survives. */
    @Test
    fun theParseBlockStillCoversTheTwoDrifts() {
        val cases = v.cases("parse")
        assertTrue(cases.any { it.s("inputUtf8").contains("\"lastUsedAt\":\"") }, "a string-typed stamp case")
        assertTrue(
            cases.any { c -> c.s("inputUtf8").contains("\"lastUsedAt\":{") && c.getValue("expected").jsonObject.isNotEmpty() },
            "a nested-object stamp beside a surviving good entry",
        )
    }

    @Test
    fun mergeMatchesTheSharedCorpus() {
        for (c in v.cases("merge")) {
            assertEquals(
                ledger(c.getValue("expected").jsonObject),
                UsageLedger.merge(ledger(c.getValue("a").jsonObject), ledger(c.getValue("b").jsonObject)),
                "merge ${c.s("name")}",
            )
        }
    }

    @Test
    fun recordMatchesTheSharedCorpus() {
        for (c in v.cases("record")) {
            assertEquals(
                ledger(c.getValue("expected").jsonObject),
                UsageLedger.record(ledger(c.getValue("map").jsonObject), c.s("itemId"), c.getValue("now").jsonPrimitive.long),
                "record ${c.s("name")}",
            )
        }
    }

    @Test
    fun pruneMatchesTheSharedCorpus() {
        for (c in v.cases("prune")) {
            val live = c.getValue("liveItemIds").jsonArray.map { it.jsonPrimitive.content }.toSet()
            assertEquals(ledger(c.getValue("expected").jsonObject), UsageLedger.prune(ledger(c.getValue("map").jsonObject), live), "prune ${c.s("name")}")
        }
    }

    /** Byte-exact: this is the wire the other two clients read. */
    @Test
    fun serializeMatchesTheSharedCorpusByteForByte() {
        for (c in v.cases("serialize")) {
            assertEquals(c.s("expectedUtf8"), UsageLedger.serialize(ledger(c.getValue("map").jsonObject)), "serialize ${c.s("name")}")
        }
    }
}
