package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The commands of the re-key lies, the ragged cost and the audit filter, run against a test server and the lying proxy,
 * each printed on standard output as a person would see it in a terminal: what was typed, what the tool printed (standard
 * output, then standard error), and the exit code. The assertions are the other tests'; this one keeps the words readable.
 */
class TranscriptTest {
    private val change: (String) -> String? = {
        when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null }
    }

    private fun cost(e: JsonElement, key: String, v: Long): JsonElement {
        val o = e.jsonObject
        return JsonObject(o + ("kdfParams" to JsonObject(o.getValue("kdfParams").jsonObject + (key to JsonPrimitive(v)))))
    }

    private fun shown(what: String, args: List<String>, r: CliRun): CliRun {
        println("### $what")
        println("$ andvari-cli ${args.joinToString(" ")}")
        r.out.lines().filter { it.isNotBlank() }.forEach { println(it) }
        r.err.lines().filter { it.isNotBlank() }.forEach { println(it) }
        println("(exit code ${r.code})")
        println()
        return r
    }

    @Test fun theWordsInATerminal() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                fun run(what: String, home: File, vararg args: String, env: (String) -> String? = { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null }) =
                    shown(what, args.toList(), w.run(home, *args, env = env, dial = p.address))

                val raise = WireRoute.CLIENT_POLICY to { e: JsonElement -> cost(e, "ops", 4) }
                val one = w.account("one@example.org")
                var lies = 1
                p.lie = mapOf(raise)
                p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { _, forward -> if (lies-- > 0) 200 to "{}" else forward().let { it.first to String(it.second) } })
                assertEquals(0, run("policy raised to 4 passes; the re-key answered done and never stored; then a password change in the same run", one,
                    "account", "password", env = change).code)

                val two = w.account("two@example.org")
                lies = 1
                p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { _, forward ->
                    val (status, body) = forward()
                    if (lies-- > 0) 400 to """{"error":"bad_request","message":"refused"}""" else status to String(body)
                })
                assertEquals(0, run("the re-key stored, answered with a refusal; then a password change in the same run", two, "account", "password", env = change).code)

                val three = w.account("three@example.org")
                var reads = 0
                p.lie = mapOf(raise, WireRoute.ACCOUNT_KEYS to { e ->
                    if (reads++ == 0) e else {
                        val wrap = e.jsonObject.getValue("wrappedUvk").jsonPrimitive.content
                        val i = wrap.length / 2
                        JsonObject(e.jsonObject + ("wrappedUvk" to JsonPrimitive(wrap.substring(0, i) + (if (wrap[i] == 'A') 'B' else 'A') + wrap.substring(i + 1))))
                    }
                })
                p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { _, _ -> 200 to "{}" })
                assertEquals(EXIT_KEYS_NOT_KNOWN, run("done never stored, and the keys read again do not open here", three, "account", "password", env = change).code)

                p.lie = emptyMap(); p.answer = emptyMap(); p.wrongProofs = 1
                assertEquals(EXIT_PROOF_REFUSED, run("the server refuses a proof the password made here", three, "account", "password", env = change).code)

                p.lie = mapOf(WireRoute.ACCOUNT_KEYS to { e -> cost(e, "memBytes", 64L * 1024 * 1024 + 1) })
                assertEquals(EXIT_SERVER_ANSWER, run("the saved session's keys served at 64 MiB + 1 byte", three, "item", "list", "personal").code)
                p.lie = mapOf(WireRoute.PRELOGIN to { e -> cost(e, "memBytes", 64L * 1024 * 1024 + 1) })
                assertEquals(EXIT_SERVER_ANSWER, run("a sign-in whose prelogin serves 64 MiB + 1 byte", w.home("new@example.org"),
                    "sign-in", "--email", "three@example.org", "--trust-card", w.card0).code)

                p.lie = emptyMap()
                assertEquals(2, run("an audit kind the server's status does not name", w.op, "operator", "audit", "--type", "no_such_kind").code)
                assertEquals(0, run("an audit kind it names", w.op, "operator", "audit", "--type", "register").code)
            }
        }
    }
}
