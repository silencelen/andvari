package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Server text at the command line: a server that puts escape sequences, line breaks, direction overrides and
 * zero-width characters into every string it serves, and shell characters into an address. Nothing of it reaches the
 * terminal as itself (standard output or error, with or without `--json`), no line of the tool's own can be forged,
 * and an address offered for pasting is one shell word.
 */
class ServerTextTest {
    private val esc = Char(0x1b)
    private val bell = Char(7)
    private val rlo = Char(0x202e)
    private val zw = Char(0x200b)
    private val forged = "andvari-cli: done, nothing to worry about"
    private val hostile = "$esc]0;owned$bell$esc[2J${rlo}gpj.exe$zw\n$forged\rX"
    private val shellAddress = "a`id`\$x|y&z@example.org"

    private fun JsonElement.rewriteStrings(keys: Set<String>): JsonElement = when (this) {
        is JsonArray -> JsonArray(map { it.rewriteStrings(keys) })
        is JsonObject -> JsonObject(mapValues { (k, v) -> if (k in keys && v is JsonPrimitive && v.isString) JsonPrimitive(v.content + hostile) else v.rewriteStrings(keys) })
        else -> this
    }

    private fun clean(what: String, r: CliRun) {
        for ((stream, text) in listOf("out" to r.out, "err" to r.err)) {
            assertFalse(text.any { Shown.harmful(it.code) && it != '\n' }, "$what ($stream) holds a character a terminal acts on: ${Shown.text(text)}")
            assertFalse(text.lines().any { it.startsWith(forged) }, "$what ($stream): a server's text made a line of its own: ${Shown.text(text)}")
        }
    }

    @Test fun nothingAServerSendsReachesTheTerminalAsItselfInAnyCommand() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            fun run(home: java.io.File, vararg args: String) = w.run(home, *args, dial = p.address)
            val meId = w.userId("me@example.org")

            p.lie = mapOf(
                WireRoute.ADMIN_ACCOUNTS to { e ->
                    JsonArray(e.jsonArray.map { row ->
                        val o = row.jsonObject
                        val email = if ((o["email"] as JsonPrimitive).content == "me@example.org") JsonPrimitive(shellAddress) else o.getValue("email")
                        JsonObject(o + ("email" to email)).rewriteStrings(setOf("role", "status", "displayName"))
                    })
                },
                WireRoute.ADMIN_ACCOUNT_DEVICES to { it.rewriteStrings(setOf("name", "platform", "how", "clientVersion")) },
                WireRoute.DEVICES to { it.rewriteStrings(setOf("name", "platform", "how", "clientVersion")) },
                WireRoute.ADMIN_AUDIT to { it.rewriteStrings(setOf("type", "meta", "ip")) },
                WireRoute.ADMIN_STATUS to { it.rewriteStrings(setOf("serverVersion", "signupMode", "instanceKind")) },
                WireRoute.ADMIN_ACCOUNT_ENABLE to { buildJsonObject { put("error", JsonPrimitive("not_found$hostile")); put("message", JsonPrimitive(hostile)) } },
            )
            p.anyStatus = setOf(WireRoute.ADMIN_ACCOUNT_ENABLE)

            val accounts = run(w.op, "operator", "accounts")
            assertEquals(0, accounts.code, Shown.text(accounts.out + accounts.err))
            clean("operator accounts", accounts)
            // The address with shell characters is one word to paste, and the hostile role is shown escaped, not obeyed.
            assertTrue(accounts.out.contains("'$shellAddress'"), Shown.text(accounts.out))
            assertTrue(accounts.out.contains("\\u{001B}]0;owned\\u{0007}\\u{001B}[2J\\u{202E}gpj.exe\\u{200B}\\n$forged\\rX"), Shown.text(accounts.out))

            val asJson = run(w.op, "operator", "accounts", "--json")
            assertEquals(0, asJson.code, Shown.text(asJson.err))
            clean("operator accounts --json", asJson)
            // Escaped as JSON, the values are what the server sent: a script reads them unchanged.
            val roles = Json.parseToJsonElement(asJson.out).jsonArray.map { it.jsonObject.getValue("role").jsonPrimitive.content }
            assertTrue(roles.all { it.endsWith(hostile) }, roles.toString())

            for (args in listOf(listOf("operator", "devices", meId), listOf("operator", "audit"), listOf("operator", "status"),
                listOf("operator", "devices", meId, "--json"), listOf("operator", "audit", "--json"), listOf("operator", "status", "--json"))) {
                val r = run(w.op, *args.toTypedArray())
                assertEquals(0, r.code, "$args: ${Shown.text(r.out + r.err)}")
                clean(args.joinToString(" "), r)
            }
            clean("account devices", run(me, "account", "devices"))
            clean("account devices --json", run(me, "account", "devices", "--json"))

            // A refusal's code and message are the server's words too.
            val refused = run(w.op, "operator", "enable", "00000000-0000-4000-8000-000000000000")
            assertEquals(1, refused.code, Shown.text(refused.err))
            clean("a refusal", refused)
            assertTrue(refused.err.contains("not_found\\u{001B}"), Shown.text(refused.err))
        } }
    }
}
