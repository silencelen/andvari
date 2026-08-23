package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The 0.26.0 `check` / `dupeAck` promotion (design 2026-08-23 §3.1), pinned.
 *
 * Both keys have been on the wire since 0.25.0, written by web and carried by every native
 * client as UNKNOWN keys through [ExtrasOverlaySerializer]. Promoting them to typed fields on
 * [ItemDoc] is the highest-risk item in that design for one reason: if the promotion is not a
 * faithful round trip, the failure mode is not a missing screen — it is silent conflict churn
 * across a household, on data written by a client that is behaving perfectly.
 *
 * So the property under test is **a 0.25.0-written doc survives a 0.26.0 decode → edit → encode
 * with its `check`/`dupeAck` payload intact at the same JSON paths**, in both directions.
 */
class ItemDocCheckRoundTripTest {
    /** Account's private json config, mirrored (ItemDocRoundTripTest's idiom). */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** Exactly what web writes today: doc-level `check` + `dupeAck`, beside unknown keys. */
    private val webWritten = """
        {"type":"login","name":"Netflix","favorite":false,
         "dupeAck":"sig-abc123",
         "check":{"at":1755900000000,"result":"ok","okAt":1755900000000},
         "login":{"username":"jacob","password":"hunter2","uris":["https://netflix.com/login"]},
         "x-future":"kept"}
    """.trimIndent()

    private fun decode(text: String): ItemDoc = json.decodeFromString(ItemDoc.serializer(), text)
    private fun encode(doc: ItemDoc): JsonObject =
        Json.parseToJsonElement(json.encodeToString(ItemDoc.serializer(), doc)).jsonObject

    @Test
    fun promotedKeys_landOnTypedFieldsAndLeaveExtras() {
        val doc = decode(webWritten)
        assertEquals("sig-abc123", doc.dupeAck)
        assertEquals(1755900000000L, doc.check?.at)
        assertEquals("ok", doc.check?.result)
        assertEquals(1755900000000L, doc.check?.okAt)
        assertNull(doc.check?.until)
        // The whole point of promoting them: they are no longer untyped extras entries.
        assertFalse("check" in doc.extras, "check stayed in extras after promotion: ${doc.extras.keys}")
        assertFalse("dupeAck" in doc.extras, "dupeAck stayed in extras after promotion: ${doc.extras.keys}")
        // Genuinely-unknown neighbours still ride along untouched.
        assertEquals(JsonPrimitive("kept"), doc.extras["x-future"])
    }

    @Test
    fun reencode_putsThemBackAtTheSamePathsWithTheSameValues() {
        val out = encode(decode(webWritten))
        assertEquals("sig-abc123", out.getValue("dupeAck").jsonPrimitive.content)
        val check = out.getValue("check").jsonObject
        assertEquals(1755900000000L, check.getValue("at").jsonPrimitive.long)
        assertEquals("ok", check.getValue("result").jsonPrimitive.content)
        assertEquals(1755900000000L, check.getValue("okAt").jsonPrimitive.long)
        assertEquals(JsonPrimitive("kept"), out["x-future"])
        assertNoExtrasKey(out)
    }

    /** The realistic 0.26.0 write: the phone records a verdict on a doc web created. */
    @Test
    fun editingOneFieldNeverDisturbsTheOther() {
        val doc = decode(webWritten)
        val edited = doc.copy(check = ItemCheck(at = 1755999999999L, result = "bad", okAt = doc.check?.okAt))
        val out = encode(edited)
        // The new verdict landed…
        assertEquals("bad", out.getValue("check").jsonObject.getValue("result").jsonPrimitive.content)
        // …okAt carried forward (spec 02 §3: "last worked in March, failed in August")…
        assertEquals(1755900000000L, out.getValue("check").jsonObject.getValue("okAt").jsonPrimitive.long)
        // …and nothing else on the doc moved.
        assertEquals("sig-abc123", out.getValue("dupeAck").jsonPrimitive.content)
        assertEquals(JsonPrimitive("kept"), out["x-future"])
        assertEquals("hunter2", out.getValue("login").jsonObject.getValue("password").jsonPrimitive.content)
    }

    /**
     * [ItemCheck.result] is an OPEN vocabulary (spec 02 §3). A verdict this client has never
     * heard of must survive decode → encode verbatim, not be normalized, dropped, or defaulted.
     * This is the forward-compat property most likely to be lost in a port, because at every
     * call site it looks like a defect.
     */
    @Test
    fun unknownVerdict_survivesVerbatim() {
        val doc = decode("""{"type":"login","name":"X","check":{"at":1,"result":"quarantined-by-a-future-client"}}""")
        assertEquals("quarantined-by-a-future-client", doc.check?.result)
        val out = encode(doc)
        assertEquals("quarantined-by-a-future-client", out.getValue("check").jsonObject.getValue("result").jsonPrimitive.content)
    }

    /** [ItemCheck] carries its own extras overlay, so a FUTURE field inside check survives too. */
    @Test
    fun unknownFieldsInsideCheck_survive() {
        val doc = decode("""{"type":"login","name":"X","check":{"at":1,"result":"ok","x-by":"fold","x-n":{"deep":true}}}""")
        assertEquals(JsonPrimitive("fold"), doc.check?.extras?.get("x-by"))
        assertEquals(buildJsonObject { put("deep", JsonPrimitive(true)) }, doc.check?.extras?.get("x-n"))
        val out = encode(doc)
        val check = out.getValue("check").jsonObject
        assertEquals(JsonPrimitive("fold"), check["x-by"])
        assertEquals("ok", check.getValue("result").jsonPrimitive.content)
        assertNoExtrasKey(out)
    }

    /** A doc that predates both keys must not gain meaning it never had. */
    @Test
    fun absentCheckAndDupeAck_decodeToNull() {
        val doc = decode("""{"type":"login","name":"Bare","x-only":"kept"}""")
        assertNull(doc.check)
        assertNull(doc.dupeAck)
        val out = encode(doc.copy(name = "Bare (renamed)"))
        assertEquals("Bare (renamed)", out.getValue("name").jsonPrimitive.content)
        assertEquals(JsonPrimitive("kept"), out["x-only"])
    }

    /**
     * Under `encodeDefaults = true` an absent optional encodes as an explicit null — the
     * pre-existing behaviour of `notes` / `login` / `card`, which the promotion joins rather
     * than changes. Pinned so the shape is a recorded decision and not a surprise: web reads
     * `check: null` as falsy exactly like an absent key, and an older client parks it in extras
     * and hands it back unchanged. **If this ever becomes intolerable the fix is
     * `explicitNulls = false` on the shared config — a whole-doc change, never a per-field one.**
     */
    @Test
    fun absentOptionals_encodeAsExplicitNulls_sameAsTheFieldsThatCameBefore() {
        val out = encode(ItemDoc(type = "note", name = "Bare"))
        // Concretely: explicit nulls ARE emitted under this config, for the promotion and for
        // the optionals that predate it alike. Asserted concretely rather than as
        // notes-equals-check, which would pass whichever way the config went and pin nothing.
        assertTrue("notes" in out, "encodeDefaults=true should emit an absent optional as null")
        assertTrue("check" in out)
        assertTrue("dupeAck" in out)
        assertEquals(kotlinx.serialization.json.JsonNull, out["check"])
        assertEquals(kotlinx.serialization.json.JsonNull, out["dupeAck"])
        // …and whichever way that goes, a null is never mistaken for a value.
        val doc = decode(json.encodeToString(ItemDoc.serializer(), ItemDoc(type = "note", name = "Bare")))
        assertNull(doc.check)
        assertNull(doc.dupeAck)
    }

    /** Typed fields beat a stale same-named extras entry — the existing contract, extended. */
    @Test
    fun typedCheckWins_overAStaleExtrasCopy() {
        val doc = ItemDoc(
            type = "login",
            name = "Real",
            check = ItemCheck(at = 2, result = "ok"),
            dupeAck = "real-sig",
            extras = mapOf(
                "check" to JsonPrimitive("evil"),
                "dupeAck" to JsonPrimitive("evil-sig"),
                "x-keep" to JsonPrimitive(1),
            ),
        )
        val out = encode(doc)
        assertEquals("ok", out.getValue("check").jsonObject.getValue("result").jsonPrimitive.content)
        assertEquals("real-sig", out.getValue("dupeAck").jsonPrimitive.content)
        assertEquals(JsonPrimitive(1), out["x-keep"])
    }

    /** Strict Json (no ignoreUnknownKeys, no encodeDefaults) — the web-like sparse shape. */
    @Test
    fun strictSparseEncoding_keepsCheckAndDropsAbsentOptionals() {
        val strict = Json
        val doc = strict.decodeFromString(ItemDoc.serializer(), webWritten)
        assertEquals("ok", doc.check?.result)
        val out = Json.parseToJsonElement(strict.encodeToString(ItemDoc.serializer(), doc)).jsonObject
        assertEquals("sig-abc123", out.getValue("dupeAck").jsonPrimitive.content)
        assertEquals("ok", out.getValue("check").jsonObject.getValue("result").jsonPrimitive.content)
        // Sparse: an absent optional inside check is simply not emitted.
        assertFalse("until" in out.getValue("check").jsonObject)
        assertNoExtrasKey(out)
    }

    private fun assertNoExtrasKey(el: kotlinx.serialization.json.JsonElement) {
        when (el) {
            is JsonObject -> {
                assertFalse("extras" in el, "literal \"extras\" key leaked into the wire format: $el")
                el.values.forEach { assertNoExtrasKey(it) }
            }
            is kotlinx.serialization.json.JsonArray -> el.forEach { assertNoExtrasKey(it) }
            else -> {}
        }
    }

    /** Sanity: the promotion did not disturb the four pre-existing extras levels. */
    @Test
    fun preExistingOverlayLevels_stillWork() {
        val doc = decode(
            """{"type":"login","name":"G","x-top":1,
                "login":{"username":"u","x-login":2,
                         "passwordHistory":[{"password":"p","retiredAt":1,"x-hist":3}]},
                "attachments":[{"id":"i","name":"n","size":1,"fileKey":"k","x-att":4}]}""",
        )
        assertEquals(JsonPrimitive(1), doc.extras["x-top"])
        assertEquals(JsonPrimitive(2), doc.login?.extras?.get("x-login"))
        assertEquals(JsonPrimitive(3), doc.login?.passwordHistory?.single()?.extras?.get("x-hist"))
        assertEquals(JsonPrimitive(4), doc.attachments.single().extras["x-att"])
        assertTrue(doc.extras.keys.none { it in setOf("check", "dupeAck") })
    }
}
