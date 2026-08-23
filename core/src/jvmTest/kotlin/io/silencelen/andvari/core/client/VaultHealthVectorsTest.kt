package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Consumes `spec/test-vectors/vaulthealth.json` — the SAME file the web twin
 * (`web/src/ui/vaulthealth.vectors.test.ts`) checks — so the two engines can never disagree
 * about which login is worst, which copies are duplicates, or which password is weak
 * (design 2026-08-23 §3.2).
 *
 * Why this file exists when both sides already have exhaustive unit suites: those suites were
 * ported from one another, so they can agree with each other and both be wrong about the SAME
 * thing. Only a shared corpus catches a divergence that both impls consider correct. And a
 * ranking divergence is the worst kind to ship — invisible (both orderings look plausible),
 * unreportable (no user can say which is right), and corrosive to trust in the whole feature.
 *
 * **ORDER IS THE ASSERTION** for the staleness lists. A set comparison would pass while the
 * ranking — the entire point of the view — was reversed.
 */
class VaultHealthVectorsTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "vaulthealth.json").readText()).jsonObject
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val now: Long = v.getValue("now").jsonPrimitive.long

    private val items: List<VaultItem> = v.getValue("items").jsonArray.map { e ->
        val o = e.jsonObject
        VaultItem(
            itemId = o.getValue("itemId").jsonPrimitive.content,
            vaultId = o.getValue("vaultId").jsonPrimitive.content,
            rev = 1,
            updatedAt = o.getValue("updatedAt").jsonPrimitive.long,
            doc = json.decodeFromString(ItemDoc.serializer(), o.getValue("docJson").jsonPrimitive.content),
        )
    }

    /** Every fixture vault is personal, so none carries a grant and none has a role. */
    private val roleFor: (String) -> String? = { null }

    private fun JsonObject.longOrNull(k: String): Long? =
        if (this[k] == null || this[k] == JsonNull) null else getValue(k).jsonPrimitive.long

    private fun JsonObject.strOrNull(k: String): String? =
        if (this[k] == null || this[k] == JsonNull) null else getValue(k).jsonPrimitive.content

    @Test
    fun healthRowsMatchTheSharedCorpus() {
        val expected = v.getValue("healthRows").jsonArray.map { it.jsonObject }
        val actual = VaultHealth.healthRows(items)
        assertEquals(expected.size, actual.size, "row count")
        for ((e, a) in expected.zip(actual)) {
            assertEquals(e.getValue("itemId").jsonPrimitive.content, a.itemId)
            assertEquals(e.getValue("name").jsonPrimitive.content, a.name, "name of ${a.itemId}")
            assertEquals(e.getValue("strength").jsonPrimitive.int, a.strength, "strength of ${a.itemId}")
            assertEquals(e.getValue("reused").jsonPrimitive.int, a.reused, "reused of ${a.itemId}")
            assertEquals(e.getValue("hasTotp").jsonPrimitive.boolean, a.hasTotp, "hasTotp of ${a.itemId}")
        }
    }

    @Test
    fun healthSummaryMatchesTheSharedCorpus() {
        val e = v.getValue("healthSummary").jsonObject
        val a = VaultHealth.summarize(VaultHealth.healthRows(items))
        assertEquals(e.getValue("logins").jsonPrimitive.int, a.logins)
        assertEquals(e.getValue("weak").jsonPrimitive.int, a.weak)
        assertEquals(e.getValue("reused").jsonPrimitive.int, a.reused)
    }

    private fun assertStaleness(key: String, includeSnoozed: Boolean) {
        val expected = v.getValue("staleness").jsonObject.getValue(key).jsonArray.map { it.jsonObject }
        val actual = Staleness.stalenessRows(
            items,
            Staleness.StalenessOptions(now = now, includeSnoozed = includeSnoozed),
        )
        // ORDER IS THE ASSERTION — the ranking is the feature.
        assertEquals(
            expected.map { it.getValue("itemId").jsonPrimitive.content },
            actual.map { it.itemId },
            "$key ordering",
        )
        for ((e, a) in expected.zip(actual)) {
            assertEquals(e.getValue("bucket").jsonPrimitive.content, a.bucket.wire, "bucket of ${a.itemId}")
            assertEquals(e.longOrNull("checkedAt"), a.checkedAt, "checkedAt of ${a.itemId}")
            assertEquals(e.getValue("snoozed").jsonPrimitive.boolean, a.snoozed, "snoozed of ${a.itemId}")
            assertEquals(e.strOrNull("firstUri"), a.firstUri, "firstUri of ${a.itemId}")
        }
    }

    @Test
    fun stalenessDefaultOrderingMatchesTheSharedCorpus() = assertStaleness("default", includeSnoozed = false)

    @Test
    fun stalenessIncludeSnoozedMatchesTheSharedCorpus() = assertStaleness("includeSnoozed", includeSnoozed = true)

    @Test
    fun stalenessSummaryMatchesTheSharedCorpus() {
        val e = v.getValue("staleness").jsonObject.getValue("summary").jsonObject
        val a = Staleness.stalenessSummary(Staleness.stalenessRows(items, Staleness.StalenessOptions(now = now)))
        assertEquals(e.getValue("unchecked").jsonPrimitive.int, a.unchecked)
        assertEquals(e.getValue("failing").jsonPrimitive.int, a.failing)
    }

    @Test
    fun duplicateClustersMatchTheSharedCorpus() {
        val expected = v.getValue("duplicates").jsonArray.map { it.jsonObject }
        val actual = Duplicates.duplicateClusters(items, roleFor)
        assertEquals(expected.size, actual.size, "cluster count")
        for ((e, a) in expected.zip(actual)) {
            assertEquals(e.getValue("sites").jsonArray.map { it.jsonPrimitive.content }, a.sites)
            assertEquals(e.getValue("kind").jsonPrimitive.content, if (a.kind == Duplicates.Kind.EXACT) "exact" else "differs")
            // Member order carries meaning too: newest-first, so "which copy is likely current".
            assertEquals(
                e.getValue("memberIds").jsonArray.map { it.jsonPrimitive.content },
                a.members.map { it.itemId },
            )
            assertEquals(e.getValue("signature").jsonPrimitive.content, a.signature)
            assertEquals(e.getValue("dismissed").jsonPrimitive.boolean, a.dismissed)
            assertEquals(e.strOrNull("survivorId"), a.merge?.survivorId, "survivor of ${a.signature}")
            assertEquals(
                e.getValue("loserIds").jsonArray.map { it.jsonPrimitive.content },
                a.merge?.loserIds ?: emptyList(),
            )
            // The refusal is user-facing copy — compared verbatim, not merely for presence.
            assertEquals(e.strOrNull("mergeRefusal"), a.mergeRefusal)
        }
    }

    /**
     * The corpus must actually exercise the two forward-compat properties, or it is grading
     * nothing: an unknown verdict that stays non-failing, and a future client clock that clamps.
     * A fixture that quietly lost these would still pass every assertion above.
     */
    @Test
    fun theCorpusStillCoversTheForwardCompatProperties() {
        val rows = Staleness.stalenessRows(items, Staleness.StalenessOptions(now = now))
        val unknown = rows.first { it.itemId == "unknown-verdict" }
        assertEquals(Staleness.StaleBucket.RECENT, unknown.bucket, "an unrecognized verdict must never be failing")
        val skewed = rows.first { it.itemId == "skewed-future" }
        assertEquals(now, skewed.checkedAt, "a future check.at must clamp to now")
    }
}
