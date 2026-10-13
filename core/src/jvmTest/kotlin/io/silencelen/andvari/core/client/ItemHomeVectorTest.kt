package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Consumes spec/test-vectors/itemhome.json (security review 2026-10, root cause A §5; branch A1b) — the SAME file web
 * `vault/itemhome.vectors.test.ts` and the extension's `itemhome.vectors.test.ts` grade. Graded against [ItemHome], the
 * rules [SyncEngine] calls (applyPull/hydrate admit, materializeOutstandingConflicts, the push-side copy, the editor
 * save and every item seal). The `pulls` rows replay a pull the way applyPull does: admit every row in order, then the
 * flagged rows that were admitted go through the INV-CONFLICT check against the in-memory twin and the home.
 */
class ItemHomeVectorTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "itemhome.json").readText()).jsonObject

    private fun JsonElement?.str(): String? = if (this == null || this is JsonNull) null else jsonPrimitive.contentOrNull

    @Test
    fun admit() {
        for (c in v["admit"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c["expect"].str(), ItemHome.admit(c["home"].str(), c["vaultId"].str()!!).code, c["name"].str())
        }
    }

    @Test
    fun pulls() {
        val rows = v["pulls"]!!.jsonArray.map { it.jsonObject }
        assertTrue(rows.any { it["name"].str()!!.startsWith("§5.3 fixture, flagged") } && rows.any { it["name"].str()!!.startsWith("§5.3 fixture, genuine") }, "both orders of the §5.3 fixture")
        for (c in rows) {
            val name = c["name"].str()
            val homes = c["homes"]!!.jsonObject.mapValues { it.value.str()!! }.toMutableMap()
            val tally = ItemHome.Tally()
            val twins = HashMap<String, String>() // itemId → vault of the live row the working set holds
            val flagged = mutableListOf<Pair<String, String>>()
            val verdicts = mutableListOf<String>()
            for (r in c["rows"]!!.jsonArray.map { it.jsonObject }) {
                val itemId = r["itemId"].str()!!
                val vaultId = r["vaultId"].str()!!
                val verdict = ItemHome.admit(homes[itemId], vaultId)
                verdicts += verdict.code
                when (verdict) {
                    ItemHome.Admit.NEW_HOME -> homes[itemId] = vaultId
                    ItemHome.Admit.HOME -> {}
                    ItemHome.Admit.QUARANTINE -> { tally.note(vaultId); continue }
                }
                if (r["deleted"]?.jsonPrimitive?.booleanOrNull == true) twins.remove(itemId) else twins[itemId] = vaultId
                if (r["conflict"]?.jsonPrimitive?.booleanOrNull == true) flagged += itemId to vaultId
            }
            val materialize = flagged.filter { (itemId, vaultId) ->
                val ok = ItemHome.conflict(twins[itemId], vaultId, homes[itemId]) == ItemHome.Conflict.MATERIALIZE
                if (!ok) tally.note(vaultId)
                ok
            }
            val e = c["expect"]!!.jsonObject
            assertEquals(e["verdicts"]!!.jsonArray.map { it.str() }, verdicts, "$name: verdicts")
            assertEquals(e["homes"]!!.jsonObject.mapValues { it.value.str() }, homes.toMap(), "$name: homes")
            assertEquals(e["anomalies"]!!.jsonPrimitive.int, tally.anomalies(), "$name: anomalies")
            assertEquals(
                e["materialize"]!!.jsonArray.map { it.jsonObject.let { m -> m["itemId"].str() to m["vaultId"].str() } },
                materialize.map { it.first to it.second }, "$name: materialize",
            )
        }
    }

    @Test
    fun conflict() {
        for (c in v["conflict"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c["expect"].str(), ItemHome.conflict(c["twin"].str(), c["flagged"].str()!!, c["home"].str()).code, c["name"].str())
        }
    }

    @Test
    fun serverItem() {
        for (c in v["serverItem"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c["expect"].str(), ItemHome.serverItem(c["pushed"].str()!!, c["losing"].str()!!, c["home"].str()).code, c["name"].str())
        }
    }

    @Test
    fun edit() {
        for (c in v["edit"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c["expect"].str(), ItemHome.edit(c["home"].str(), c["editor"].str()).code, c["name"].str())
        }
    }

    @Test
    fun seal() {
        for (c in v["seal"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c["expect"].str(), ItemHome.seal(c["home"].str(), c["vaultId"].str()!!).code, c["name"].str())
        }
    }
}
