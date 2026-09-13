package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

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
 *
 * The `writes` block (audit H42, 2026-09-13) grades what the engines WRITE, not only what they
 * derive: the composed merge doc, planKeep (passwordHistory's only writer), planDismiss,
 * planCheck's okAt carry-forward and snooze horizon, planUnsnooze, and every reader / cross-vault
 * refusal string verbatim under a real roles map. Those are the outputs that land in the vault
 * and sync to every device — a divergence there is the silent write-side drift the corpus's own
 * rationale calls the worst kind.
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

    // ---------------------------------------------------------------------------------------
    // Write-side cases (H42). Docs are compared as CANONICAL JSON: encode with defaults and
    // nulls omitted, then drop any remaining null-valued keys and empty arrays on BOTH sides.
    // "Absent" and "null" / "[]" are one value to every reader in the tree (`?.`, `?: emptyList()`,
    // `?? []`) but two encodings across the language boundary — Kotlin omits a default, web
    // spreads whatever key the input had — so comparing raw strings would grade the serializers,
    // not the engines. Everything else (key presence, values, ORDER inside arrays such as uris and
    // passwordHistory) is compared exactly.
    // ---------------------------------------------------------------------------------------
    private val writes: JsonObject = v.getValue("writes").jsonObject
    private val writeRoles: Map<String, String> = writes.getValue("roles").jsonObject.mapValues { it.value.jsonPrimitive.content }
    private val writeRoleFor: (String) -> String? = { writeRoles[it] }
    private val writeItems: List<VaultItem> = writes.getValue("items").jsonArray.map { e ->
        val o = e.jsonObject
        VaultItem(
            itemId = o.getValue("itemId").jsonPrimitive.content,
            vaultId = o.getValue("vaultId").jsonPrimitive.content,
            rev = 1,
            updatedAt = o.getValue("updatedAt").jsonPrimitive.long,
            doc = json.decodeFromString(ItemDoc.serializer(), o.getValue("docJson").jsonPrimitive.content),
        )
    }
    /** Defaults omitted — the generator's own encoding, so the doc a plan composes is compared in
     *  the same shape the corpus pinned it in. */
    private val docJson = Json { encodeDefaults = false }

    private fun canon(e: JsonElement): JsonElement = when (e) {
        is JsonObject -> JsonObject(
            e.entries
                .filter { (_, v) -> v != JsonNull && !(v is JsonArray && v.isEmpty()) }
                .associate { (k, v) -> k to canon(v) },
        )
        is JsonArray -> JsonArray(e.map { canon(it) })
        else -> e
    }

    private fun assertDocMatches(expectedDocJson: String, actual: ItemDoc, label: String) {
        val expected = canon(Json.parseToJsonElement(expectedDocJson))
        val got = canon(docJson.encodeToJsonElement(ItemDoc.serializer(), actual))
        assertEquals(expected, got, label)
    }

    private fun JsonObject.strList(k: String) = getValue(k).jsonArray.map { it.jsonPrimitive.content }

    @Test
    fun writeFixtureClustersAndMergeDocsMatchTheSharedCorpus() {
        val expected = writes.getValue("duplicates").jsonArray.map { it.jsonObject }
        val actual = Duplicates.duplicateClusters(writeItems, writeRoleFor)
        assertEquals(expected.map { it.getValue("signature").jsonPrimitive.content }, actual.map { it.signature }, "cluster order")
        for ((e, a) in expected.zip(actual)) {
            val label = "cluster ${a.signature}"
            assertEquals(e.strList("sites"), a.sites, label)
            assertEquals(e.getValue("kind").jsonPrimitive.content, if (a.kind == Duplicates.Kind.EXACT) "exact" else "differs", label)
            assertEquals(e.strList("memberIds"), a.members.map { it.itemId }, label)
            assertEquals(e.getValue("dismissed").jsonPrimitive.boolean, a.dismissed, label)
            assertEquals(e.strOrNull("survivorId"), a.merge?.survivorId, label)
            assertEquals(e.strList("loserIds"), a.merge?.loserIds ?: emptyList(), label)
            assertEquals(e.strOrNull("mergeRefusal"), a.mergeRefusal, label)
            // THE point of this block: the doc the merge would save, not just who survives.
            val doc = e.strOrNull("mergeDocJson")
            if (doc == null) assertNull(a.merge, "$label: refused clusters carry no plan")
            else assertDocMatches(doc, assertNotNull(a.merge, label).doc, "$label merge doc")
        }
    }

    @Test
    fun planKeepMatchesTheSharedCorpus() {
        for (c in writes.getValue("planKeep").jsonArray.map { it.jsonObject }) {
            val name = c.getValue("name").jsonPrimitive.content
            val plan = Duplicates.planKeep(
                writeItems, c.strList("memberIds"), c.getValue("keepId").jsonPrimitive.content,
                writeRoleFor, c.getValue("retiredAt").jsonPrimitive.long,
            )
            assertEquals(c.strOrNull("refusal"), plan.keepRefusal, "$name refusal")
            assertEquals(c.strOrNull("survivorId"), plan.keep?.survivorId, "$name survivor")
            assertEquals(c.strList("loserIds"), plan.keep?.loserIds ?: emptyList(), "$name losers")
            val doc = c.strOrNull("docJson")
            if (doc == null) assertNull(plan.keep, "$name: a refusal carries no plan")
            else assertDocMatches(doc, assertNotNull(plan.keep, name).doc, "$name doc (passwordHistory incl.)")
        }
    }

    @Test
    fun planDismissMatchesTheSharedCorpus() {
        for (c in writes.getValue("planDismiss").jsonArray.map { it.jsonObject }) {
            val name = c.getValue("name").jsonPrimitive.content
            val plan = Duplicates.planDismiss(writeItems, c.strList("memberIds"), c.getValue("signature").jsonPrimitive.content, writeRoleFor)
            assertEquals(c.strOrNull("refusal"), plan.dismissRefusal, "$name refusal")
            val ew = c["writes"]
            if (ew == null || ew == JsonNull) {
                assertNull(plan.writes, "$name: a refusal carries no writes")
            } else {
                val actual = assertNotNull(plan.writes, name)
                val expected = ew.jsonArray.map { it.jsonObject }
                assertEquals(expected.map { it.getValue("itemId").jsonPrimitive.content }, actual.map { it.itemId }, "$name write order")
                for ((e, a) in expected.zip(actual)) assertDocMatches(e.getValue("docJson").jsonPrimitive.content, a.doc, "$name write ${a.itemId}")
            }
        }
    }

    private fun assertCheckPlan(c: JsonObject, plan: Staleness.CheckPlan) {
        val name = c.getValue("name").jsonPrimitive.content
        assertEquals(c.strOrNull("refusal"), plan.refusal, "$name refusal")
        val ew = c["write"]
        if (ew == null || ew == JsonNull) {
            assertNull(plan.write, "$name: no write")
        } else {
            val actual = assertNotNull(plan.write, name)
            assertEquals(ew.jsonObject.getValue("itemId").jsonPrimitive.content, actual.itemId, "$name write target")
            assertDocMatches(ew.jsonObject.getValue("docJson").jsonPrimitive.content, actual.doc, "$name doc (check incl.)")
        }
    }

    @Test
    fun planCheckMatchesTheSharedCorpus() {
        for (c in writes.getValue("planCheck").jsonArray.map { it.jsonObject }) {
            assertCheckPlan(
                c,
                Staleness.planCheck(
                    writeItems, c.getValue("itemId").jsonPrimitive.content, c.getValue("result").jsonPrimitive.content,
                    c.getValue("now").jsonPrimitive.long, writeRoleFor, c.longOrNull("snoozeMs"),
                ),
            )
        }
    }

    @Test
    fun planUnsnoozeMatchesTheSharedCorpus() {
        for (c in writes.getValue("planUnsnooze").jsonArray.map { it.jsonObject }) {
            assertCheckPlan(c, Staleness.planUnsnooze(writeItems, c.getValue("itemId").jsonPrimitive.content, writeRoleFor))
        }
    }

    /** The write fixture must keep exercising what it was added for, or the tests above grade
     *  nothing: a reader vault in the roles map, a planKeep that actually retires a password, a
     *  dismissed cluster, and a planCheck that carries okAt forward under a non-ok verdict. */
    @Test
    fun theWriteFixtureStillCoversItsReasonsForExisting() {
        assertTrue(writeRoles.containsValue("reader"), "a reader vault")
        val keeps = writes.getValue("planKeep").jsonArray.map { it.jsonObject }
        assertTrue(keeps.any { it.strOrNull("docJson")?.contains("passwordHistory") == true }, "a planKeep that writes passwordHistory")
        assertTrue(keeps.any { it.strOrNull("refusal") != null }, "a planKeep refusal")
        assertTrue(writes.getValue("duplicates").jsonArray.any { it.jsonObject.getValue("dismissed").jsonPrimitive.boolean }, "a dismissed cluster")
        val checks = writes.getValue("planCheck").jsonArray.map { it.jsonObject }
        assertTrue(
            checks.any { c ->
                c.getValue("result").jsonPrimitive.content != "ok" &&
                    (c["write"] as? JsonObject)?.getValue("docJson")?.jsonPrimitive?.content?.contains("okAt") == true
            },
            "a non-ok planCheck that carries okAt forward",
        )
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
