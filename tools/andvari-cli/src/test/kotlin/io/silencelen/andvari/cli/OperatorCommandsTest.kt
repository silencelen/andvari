package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The operator's commands the other tests do not run (design §9.2), with no terminal: an account's devices, disable and
 * enable, delete refused before the 30 days with words that say why and done after them, the audit log with its filters
 * (a malformed one refused before sending), and the policy read and written as JSON.
 */
class OperatorCommandsTest {
    @Test fun devicesDisableEnableDeleteAuditAndPolicy() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val bob = File(tmp, "bob")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            val reg = CliRun.run(s, bob, "enrol", Steps.enrolLink(s, "bob@example.org"), "--email", "bob@example.org", "--kit-out", File(tmp, "bob-kit.txt").path, "--trust-card", card0).ok()
            val bobId = Regex("\\(([0-9a-f-]{36})\\)").find(reg)!!.groupValues[1]
            fun bobLine() = CliRun.run(s, op, "operator", "accounts").ok().lines().firstOrNull { it.contains("bob@example.org") }

            assertTrue(CliRun.run(s, op, "operator", "devices", "bob@example.org").ok().isNotBlank(), "bob's device is listed")

            // Disable; delete is refused before the 30 days and says why; enable.
            CliRun.run(s, op, "operator", "disable", "bob@example.org", "--reason", "other").ok()
            assertTrue(bobLine()!!.contains("disabled"), bobLine())
            val early = CliRun.run(s, op, "operator", "delete", "bob@example.org")
            assertEquals(1, early.code, early.err)
            assertTrue(early.err.contains("disabled for at least 30 days") && early.err.contains("Nothing was deleted"), early.err)
            CliRun.run(s, op, "operator", "enable", "bob@example.org").ok()
            assertTrue(bobLine()!!.contains("active"), bobLine())

            // An active account is refused in the same words, saying it is not disabled.
            assertTrue(CliRun.run(s, op, "operator", "delete", bobId).err.contains("is not disabled"))

            // The audit log and its filters; a malformed filter is refused on this device.
            val disables = CliRun.run(s, op, "operator", "audit", "--type", "operator_disable").ok()
            assertTrue(disables.contains("operator_disable") && !disables.contains("operator_enable"), disables)
            // Each line: at, type, the acting account, then the meta.
            assertTrue(CliRun.run(s, op, "operator", "audit", "--user", "bob@example.org").ok().lines().filter { it.isNotBlank() }.all { it.trim().split("  ")[2] == bobId })
            assertEquals(1, CliRun.run(s, op, "operator", "audit", "--type", "Not A Type").code)
            assertEquals(2, CliRun.run(s, op, "operator", "audit", "--since", "yesterday").code)

            // The policy as JSON, edited and written back, then read again.
            val policy = Json.parseToJsonElement(CliRun.run(s, op, "operator", "policy").ok().trim()).jsonObject
            val old = policy.getValue("clipboardClearSeconds").jsonPrimitive.long
            val next = if (old == 30L) 45L else 30L
            val f = File(tmp, "policy.json").apply { writeText(JsonObject(policy + ("clipboardClearSeconds" to JsonPrimitive(next))).toString()) }
            val written = Json.parseToJsonElement(CliRun.run(s, op, "operator", "policy", "set", "--file", f.path).ok().trim()).jsonObject
            assertEquals(next, written.getValue("clipboardClearSeconds").jsonPrimitive.long)
            assertEquals(next, Json.parseToJsonElement(CliRun.run(s, op, "operator", "policy").ok().trim()).jsonObject.getValue("clipboardClearSeconds").jsonPrimitive.long)
            assertEquals(2, CliRun.run(s, op, "operator", "policy", "set", "--file", File(tmp, "op-kit.txt").path).code, "not a policy: nothing sent")

            // Disabled for 30 days: deleted.
            CliRun.run(s, op, "operator", "disable", "bob@example.org", "--reason", "other").ok()
            s.advance(30 * 86_400_000L + 60_000)
            // A month later the operator's own session has expired too: sign in again (the setup pin is no password pin).
            CliRun.run(s, op, "sign-in", "--trust-card", card0).ok()
            assertTrue(CliRun.run(s, op, "operator", "delete", "bob@example.org").ok().contains("deleted at"))
            assertFalse(CliRun.run(s, op, "operator", "accounts").ok().contains("bob@example.org"))
        }
    }

    /**
     * The operator's delete with its one fixed reason (owner policy 2026-11-15, design §9.2): `--under-minimum-age` is a
     * switch (no value, and `--reason` is refused, both before anything is sent); it says what the server will record before
     * the password is asked; an active account is still refused, in words; a disabled one is deleted at once, without the
     * 30 days; and the audit row carries the reason.
     */
    @Test fun deleteUnderTheMinimumAge() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            CliRun.run(s, File(tmp, "kid"), "enrol", Steps.enrolLink(s, "kid@example.org"), "--email", "kid@example.org", "--kit-out", File(tmp, "kid-kit.txt").path, "--trust-card", card0).ok()
            fun kidLine() = CliRun.run(s, op, "operator", "accounts").ok().lines().firstOrNull { it.contains("kid@example.org") }

            // A switch: no other value can be given, and delete takes no --reason. Refused before anything is sent.
            for (bad in listOf(listOf("--under-minimum-age=other"), listOf("--reason", "under_minimum_age"), listOf("--reason=other"))) {
                val r = CliRun.run(s, op, *(listOf("operator", "delete", "kid@example.org") + bad).toTypedArray())
                assertEquals(2, r.code, "$bad: ${r.err}")
                assertTrue(r.err.contains("nothing was sent"), r.err)
            }
            assertTrue(kidLine()!!.contains("active"), kidLine())

            // An active account is still refused, in words.
            val active = CliRun.run(s, op, "operator", "delete", "kid@example.org", "--under-minimum-age")
            assertEquals(1, active.code, active.err)
            assertTrue(active.err.contains("is deleted only once it is disabled") && active.err.contains("run `operator disable` first") &&
                active.err.contains("Nothing was deleted"), active.err)
            assertTrue(kidLine()!!.contains("active"), kidLine())

            // Disabled a minute ago: deleted at once. What the server records is said before the password is asked (here
            // the password comes on standard input after each prompt: once to open the saved session, once for the delete).
            CliRun.run(s, op, "operator", "disable", "kid@example.org", "--reason", "other").ok()
            s.advance(60_000)
            val done = CliRun.run(s, op, "operator", "delete", "kid@example.org", "--under-minimum-age",
                env = { null }, stdin = CliRun.lines(Steps.PASSWORD + "\n" + Steps.PASSWORD))
            assertEquals(0, done.code, done.out + done.err)
            assertTrue(done.out.contains("deleted at") && done.out.contains("reason=under_minimum_age"), done.out)
            val said = done.err.indexOf("reason=under_minimum_age")
            val asked = done.err.lastIndexOf("Master password for")
            assertTrue(said in 0 until asked, "the record is said before the password is asked: ${done.err}")
            assertFalse(CliRun.run(s, op, "operator", "accounts").ok().contains("kid@example.org"))

            // The audit row carries the reason, and no email.
            val rows = CliRun.run(s, op, "operator", "audit", "--type", "operator_delete").ok().lines().filter { it.isNotBlank() }
            assertEquals(1, rows.size, rows.toString())
            assertTrue(rows[0].contains("operator_delete") && rows[0].contains("reason=under_minimum_age") && !rows[0].contains("kid@example.org"), rows[0])
        }
    }
}
