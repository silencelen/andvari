package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pure unit tests for the spec 02 §3 unknown-field contract on [ItemDoc] and its
 * ExtrasOverlaySerializer (Account.kt): unknown JSON keys survive decode → copy-edit →
 * re-encode at every level, the mechanism never leaks a literal "extras" key, and typed
 * fields always beat a stale same-named extras entry. Cross-impl fixtures live in
 * spec/test-vectors/itemdoc.json (ItemDocVectorsTest + web itemdoc.test.ts); these tests
 * pin the Kotlin-side mechanics that the shared vectors cannot see (extras maps, copy()).
 */
class ItemDocRoundTripTest {
    /** Mirrors Account's private json config. */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** Unknown fields at all 4 contract levels: top, login, history entry, attachment. */
    private val docWithUnknowns = """
        {"type":"login","name":"GitHub","notes":"work","favorite":true,
         "x-top":{"a":[1,"two",null]},
         "login":{"username":"jacob","password":"hunter2","uris":["https://github.com/login","https://gist.github.com"],
                  "x-login":true,
                  "passwordHistory":[{"password":"old1","retiredAt":1700000000000,"x-hist":"note"}]},
         "attachments":[{"id":"id-1","name":"scan.pdf","size":12345,"fileKey":"a2V5","x-att":7}]}
    """.trimIndent()

    private val itemDocKnown = setOf("type", "name", "notes", "favorite", "login", "attachments")
    private val loginKnown = setOf("username", "password", "uris", "totp", "passwordHistory")

    private fun decode(text: String = docWithUnknowns): ItemDoc = json.decodeFromString(ItemDoc.serializer(), text)
    private fun encode(doc: ItemDoc): JsonObject = Json.parseToJsonElement(json.encodeToString(ItemDoc.serializer(), doc)).jsonObject

    @Test
    fun decode_populatesTypedFieldsAndExtrasAtEveryLevel() {
        val doc = decode()
        // Typed fields intact.
        assertEquals("login", doc.type)
        assertEquals("GitHub", doc.name)
        assertEquals("work", doc.notes)
        assertTrue(doc.favorite)
        assertEquals("jacob", doc.login?.username)
        assertEquals(listOf("https://github.com/login", "https://gist.github.com"), doc.login?.uris)
        assertEquals(1700000000000, doc.login?.passwordHistory?.single()?.retiredAt)
        assertEquals("scan.pdf", doc.attachments.single().name)
        // Extras populated at each level with the exact JSON values.
        assertEquals(buildJsonObject { put("a", JsonArray(listOf(JsonPrimitive(1), JsonPrimitive("two"), JsonNull))) }, doc.extras["x-top"])
        assertEquals(JsonPrimitive(true), doc.login?.extras?.get("x-login"))
        assertEquals(JsonPrimitive("note"), doc.login?.passwordHistory?.single()?.extras?.get("x-hist"))
        assertEquals(JsonPrimitive(7), doc.attachments.single().extras["x-att"])
    }

    @Test
    fun reencode_preservesUnknownsAndNeverEmitsExtrasKey() {
        val out = encode(decode())
        assertEquals(buildJsonObject { put("a", JsonArray(listOf(JsonPrimitive(1), JsonPrimitive("two"), JsonNull))) }, out["x-top"])
        assertEquals(JsonPrimitive(true), out.getValue("login").jsonObject["x-login"])
        assertEquals(JsonPrimitive("note"), out.getValue("login").jsonObject.getValue("passwordHistory").jsonArray[0].jsonObject["x-hist"])
        assertEquals(JsonPrimitive(7), out.getValue("attachments").jsonArray[0].jsonObject["x-att"])
        // The overlay is @Transient — a literal "extras" key must never reach the wire.
        assertNoExtrasKey(out)
        // Typed content unchanged too.
        assertEquals("GitHub", out.getValue("name").jsonPrimitive.content)
        assertEquals("https://gist.github.com", out.getValue("login").jsonObject.getValue("uris").jsonArray[1].jsonPrimitive.content)
    }

    private fun assertNoExtrasKey(el: JsonElement) {
        when (el) {
            is JsonObject -> {
                assertFalse("extras" in el, "literal \"extras\" key leaked into the wire format: $el")
                el.values.forEach { assertNoExtrasKey(it) }
            }
            is JsonArray -> el.forEach { assertNoExtrasKey(it) }
            else -> {}
        }
    }

    @Test
    fun copyEdit_carriesExtrasAtEveryLevel() {
        val doc = decode()
        // The real editor shape: data-class copy() at whatever depth the edit touches.
        val edited = doc.copy(
            name = "GitHub (renamed)",
            login = doc.login?.copy(password = "n3w"),
        )
        assertEquals(doc.extras, edited.extras)
        assertEquals(doc.login?.extras, edited.login?.extras)
        assertEquals(doc.login?.passwordHistory?.single()?.extras, edited.login?.passwordHistory?.single()?.extras)
        assertEquals(doc.attachments.single().extras, edited.attachments.single().extras)

        val out = encode(edited)
        assertEquals("GitHub (renamed)", out.getValue("name").jsonPrimitive.content)
        assertEquals("n3w", out.getValue("login").jsonObject.getValue("password").jsonPrimitive.content)
        assertEquals(JsonPrimitive(true), out.getValue("login").jsonObject["x-login"])
        assertEquals(JsonPrimitive("note"), out.getValue("login").jsonObject.getValue("passwordHistory").jsonArray[0].jsonObject["x-hist"])
        assertEquals(JsonPrimitive(7), out.getValue("attachments").jsonArray[0].jsonObject["x-att"])
    }

    @Test
    fun typedFieldsWin_staleExtrasNeverShadowOnEncode() {
        // A manually constructed doc whose extras carries a KNOWN key must encode the
        // typed value — judged against the descriptor, so even a defaulted field wins.
        val doc = ItemDoc(
            type = "login",
            name = "Real",
            extras = mapOf("name" to JsonPrimitive("evil"), "favorite" to JsonPrimitive(true), "x-keep" to JsonPrimitive(1)),
            login = LoginData(username = "real-u", extras = mapOf("username" to JsonPrimitive("evil-u"))),
        )
        val out = encode(doc)
        assertEquals("Real", out.getValue("name").jsonPrimitive.content)
        assertEquals(false, out.getValue("favorite").jsonPrimitive.boolean) // typed default, not the stale extras copy
        assertEquals(1, out.getValue("x-keep").jsonPrimitive.int) // genuinely-unknown entries still ride along
        assertEquals("real-u", out.getValue("login").jsonObject.getValue("username").jsonPrimitive.content)
    }

    @Test
    fun decode_neverYieldsKnownKeysInExtras() {
        val doc = decode()
        assertTrue(doc.extras.keys.none { it in itemDocKnown }, "extras leaked known keys: ${doc.extras.keys}")
        assertTrue(doc.login!!.extras.keys.none { it in loginKnown }, "login extras leaked known keys: ${doc.login!!.extras.keys}")
        assertTrue(doc.login!!.passwordHistory.single().extras.keys.none { it in setOf("password", "retiredAt") })
        assertTrue(doc.attachments.single().extras.keys.none { it in setOf("id", "name", "size", "fileKey") })
    }

    @Test
    fun strictJson_decodesUnknownsSafelyThroughOverlay() {
        // No ignoreUnknownKeys: the overlay strips unknowns before delegating, so even a
        // strict Json instance must decode cleanly and still capture the extras.
        val strict = Json // defaults: ignoreUnknownKeys = false, encodeDefaults = false
        val doc = strict.decodeFromString(ItemDoc.serializer(), docWithUnknowns)
        assertEquals("GitHub", doc.name)
        assertEquals(JsonPrimitive(true), doc.login?.extras?.get("x-login"))
        // And re-encoding under encodeDefaults=false (web-like sparse shape) keeps unknowns.
        val out = Json.parseToJsonElement(strict.encodeToString(ItemDoc.serializer(), doc)).jsonObject
        assertEquals(JsonPrimitive(7), out.getValue("attachments").jsonArray[0].jsonObject["x-att"])
        assertNoExtrasKey(out)
    }

    @Test
    fun absentOptionals_roundTripWithoutCorruptingUnknowns() {
        val doc = decode("""{"type":"note","name":"Bare","x-only":"kept"}""")
        assertNull(doc.notes)
        assertNull(doc.login)
        assertFalse(doc.favorite)
        assertEquals(JsonPrimitive("kept"), doc.extras["x-only"])
        val out = encode(doc.copy(favorite = true))
        assertEquals(JsonPrimitive("kept"), out["x-only"])
        assertEquals(true, out.getValue("favorite").jsonPrimitive.boolean)
    }
}
