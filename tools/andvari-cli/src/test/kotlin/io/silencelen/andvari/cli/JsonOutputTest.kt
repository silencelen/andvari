package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * `--json` (README "Machine-readable output"): each command that prints a list or a state prints exactly one JSON document
 * on standard output, which parses as the documented shape; on a failure standard output is empty.
 */
class JsonOutputTest {
    private lateinit var w: CliWorld

    /** Standard output of a run that must succeed, parsed as ONE JSON document (a second document would not parse). */
    private fun json(home: java.io.File, vararg args: String): JsonElement {
        val r = w.run(home, *args, "--json")
        assertEquals(0, r.code, "${args.toList()}: ${r.out}${r.err}")
        return Json.parseToJsonElement(r.out)
    }

    private fun JsonElement.obj(): JsonObject = assertIs<JsonObject>(this, toString())
    private fun JsonElement.arr(): JsonArray = assertIs<JsonArray>(this, toString())
    private fun JsonObject.str(k: String): String? = (this[k] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it !is JsonNull }?.content

    @Test fun everyListAndStateParsesAsItsDocumentedShape() {
        TestServer().use { s ->
            w = CliWorld(s)
            val me = w.account("me@example.org")
            val alice = w.account("alice@example.org")
            val (_, aliceId) = w.connect(me, alice)
            val v = CliWorld.vaultId(w.run(me, "vault", "create", "Family").ok())
            w.run(me, "item", "put", "personal", stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}""")).ok()
            w.run(me, "link", "create").ok()

            val who = json(me, "whoami").obj()
            assertEquals(s.origin, who.str("origin")); assertEquals("me@example.org", who.str("account")); assertEquals("open", who.str("state"))
            assertTrue(who.getValue("server").obj().containsKey("pinnedThrough"), who.toString())

            val card = json(me, "card", "show").obj()
            assertEquals(w.card0, card.str("card0Hash"))
            for (k in listOf("origin", "name", "kind", "instanceId", "cardSeq", "cardHash", "operator", "operatorKey", "recoveryFp", "pinnedVia")) assertTrue(k in card, k)

            assertTrue(json(me, "sync").obj().getValue("vaults").jsonPrimitive.int >= 2)

            val contact = json(me, "contacts").arr().map { it.obj() }.single { it.str("userId") == aliceId }
            assertTrue(contact.getValue("compared").jsonPrimitive.boolean); assertTrue("label" in contact && "code" in contact, contact.toString())

            val vaults = json(me, "vault", "list").arr().map { it.obj() }
            assertEquals("personal", vaults.single { it.str("kind") == "personal" }.str("kind"))
            val family = vaults.single { it.str("vaultId") == v }
            assertEquals("Family", family.str("name")); assertEquals("shared", family.str("kind")); assertEquals(1, family.getValue("members").jsonPrimitive.int)

            val items = json(me, "item", "list", "personal").arr().map { it.obj() }
            assertEquals("GitHub", items.single().getValue("doc").jsonObject.str("name"))

            val linksRun = w.run(me, "link", "list", "--json")
            assertFalse(linksRun.out.contains("://"), "a link is never printed: ${linksRun.out}")
            val link = Json.parseToJsonElement(linksRun.out).arr().single().obj()
            assertEquals("connect", link.str("kind")); assertTrue("linkId" in link && "shares" in link)

            val requests = json(me, "recovery-requests").obj()
            // A private card: the device asks (offered), and there are none.
            assertEquals(true, requests.getValue("offered").jsonPrimitive.boolean); assertTrue(requests.getValue("requests").jsonArray.isEmpty())
            val posture = json(me, "recovery", "show").obj()
            assertEquals("private", posture.str("posture")); assertTrue("operatorOffered" in posture && "recorded" in posture && "fp" in posture)

            val devices = json(me, "account", "devices").arr().map { it.obj() }
            assertEquals(1, devices.count { it.getValue("current").jsonPrimitive.boolean }, devices.toString())
            assertTrue(devices.all { "deviceId" in it && "live" in it && "how" in it })

            val accounts = json(w.op, "operator", "accounts").arr().map { it.obj().str("email") }
            assertTrue(accounts.containsAll(listOf("op@example.org", "me@example.org", "alice@example.org")), accounts.toString())
            assertTrue("serverVersion" in json(w.op, "operator", "status").obj())
            val audit = json(w.op, "operator", "audit").obj()
            assertTrue(audit.getValue("rows").arr().all { "type" in it.obj() && "at" in it.obj() })
            assertEquals(false, audit.getValue("more").jsonPrimitive.boolean)
            assertEquals(JsonNull, audit.getValue("after"))
            assertTrue(json(w.op, "operator", "devices", "me@example.org").arr().isNotEmpty())
            json(w.op, "operator", "recovery-requests").arr()
            assertTrue("clipboardClearSeconds" in json(w.op, "operator", "policy").obj())

            // A failure: nothing on standard output, the words on standard error, the exit code as without --json.
            val refused = w.run(me, "operator", "accounts", "--json")
            assertEquals(1, refused.code)
            assertEquals("", refused.out)
            assertTrue(refused.err.contains("[$KEY_NOT_THE_OPERATOR]") && refused.err.contains("names another account as the operator"), refused.err)
        }
    }
}
