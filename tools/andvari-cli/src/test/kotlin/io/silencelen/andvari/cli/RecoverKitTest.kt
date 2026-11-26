package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A person who lost the master password, with no terminal (design §10, §12.1): `recover kit` with the kit file the tool
 * wrote (a scan: it pins from the kit's card 0) and with the typed groups (through the Trust Gate), each ending in a new
 * password and a new kit; the old kit then stops working. And what is refused without a terminal before anything is sent:
 * a kit that could not be captured, and a Trust Gate without `--trust-card`.
 */
class RecoverKitTest {
    private val pw2 = "second Password for 2 recover"
    private val pw3 = "third Password, after typing 3"

    private fun pw(p: String): (String) -> String? = { if (it == "ANDVARI_PASSWORD") p else null }

    @Test fun recoverWithTheKitFileAndWithTheTypedGroupsAndNothingIsSentWhenTheNewKitCouldNotBeCaptured() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            val kit1 = File(tmp, "kit1.txt")
            CliRun.run(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", kit1.path, "--trust-card", card0).ok()
            CliRun.run(s, me, "item", "put", "personal", "--trust-card", card0, stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}""")).ok()

            // Without a terminal, a kit that could not be captured stops the command before anything is sent: the link
            // is still unused afterwards.
            val x = File(tmp, "x")
            val xLink = Steps.enrolLink(s, "x@example.org")
            val noKit = CliRun.run(s, x, "enrol", xLink, "--email", "x@example.org", "--trust-card", card0)
            assertEquals(2, noKit.code, noKit.err)
            assertTrue(noKit.err.contains("--kit-out FILE") && noKit.err.contains("Nothing was sent"), noKit.err)
            assertTrue(CliRun.run(s, x, "whoami").ok().contains("not pinned on this device"), "not even the link's server was pinned")
            CliRun.run(s, x, "enrol", xLink, "--email", "x@example.org", "--kit-out", File(tmp, "x-kit.txt").path, "--trust-card", card0).ok()

            // Without a terminal, the Trust Gate needs --trust-card; nothing is pinned or sent.
            val stranger = File(tmp, "stranger")
            val noGate = CliRun.run(s, stranger, "sign-in", "--email", "me@example.org")
            assertEquals(1, noGate.code, noGate.err)
            assertTrue(noGate.err.contains("needs --trust-card"), noGate.err)
            assertTrue(CliRun.run(s, stranger, "whoami").ok().contains("not pinned on this device"))

            // A kit is never an argument, and an existing --kit-out is never overwritten (both before anything is sent).
            assertEquals(2, CliRun.run(s, stranger, "recover", "kit", "--kit", "abcd").code)
            assertEquals(2, CliRun.run(s, stranger, "recover", "kit", "--kit-file", kit1.path, "--kit-out", kit1.path, origin = null).code)

            // 0. A recovery stopped after the scan (here: no new password can be read) leaves no pin behind: the scan pinned the
            // server from the kit's card 0, and the stopped flow is cancelled, which drops that pin with the kit's secrets.
            val d0 = File(tmp, "d0")
            val stopped = CliRun.run(s, d0, "recover", "kit", "--kit-file", kit1.path, "--kit-out", File(tmp, "kit0.txt").path, origin = null, env = { null })
            assertEquals(1, stopped.code, stopped.out + stopped.err)
            assertTrue(stopped.err.contains("no password given"), stopped.err)
            assertTrue(CliRun.run(s, d0, "whoami", "--origin", s.origin, origin = null).ok().contains("not pinned on this device"), "the kit's pin was dropped")

            // 1. The kit file `--kit-out` wrote, on a fresh device: a scan, pinned from the kit's card 0 (no --trust-card,
            // no --origin), a new password and a new kit; the items are there under the new password.
            val d1 = File(tmp, "d1")
            val kit2 = File(tmp, "kit2.txt")
            val r1 = CliRun.run(s, d1, "recover", "kit", "--kit-file", kit1.path, "--kit-out", kit2.path, origin = null, env = pw(pw2))
            assertEquals(0, r1.code, r1.out + r1.err)
            assertTrue(r1.out.contains("recovered: me@example.org") && r1.out.contains("on ${s.origin}"), r1.out)
            assertTrue(kit2.readText().startsWith("andvari recovery kit for account"))
            assertTrue(CliRun.run(s, d1, "item", "list", "personal", env = pw(pw2)).ok().contains("GitHub"))
            assertEquals(1, CliRun.run(s, d1, "item", "list", "personal", env = pw(Steps.PASSWORD)).code, "the old password no longer opens the account")

            // 2. The groups of the new kit, typed into a file of their own: --email, --origin and the Trust Gate.
            val d2 = File(tmp, "d2")
            val groups = File(tmp, "groups.txt").apply { writeText(kit2.readLines().filter { Regex("^[0-9]+\\. ").containsMatchIn(it) }.joinToString("\n")) }
            val kit3 = File(tmp, "kit3.txt")
            val noTrust = CliRun.run(s, d2, "recover", "kit", "--kit-file", groups.path, "--email", "me@example.org", "--kit-out", kit3.path, env = pw(pw3))
            assertEquals(1, noTrust.code, "a typed kit carries no card 0: the Trust Gate: ${noTrust.err}")
            assertFalse(kit3.exists())
            val r2 = CliRun.run(s, d2, "recover", "kit", "--kit-file", groups.path, "--email", "me@example.org", "--kit-out", kit3.path, "--trust-card", card0, env = pw(pw3))
            assertEquals(0, r2.code, r2.out + r2.err)
            assertTrue(CliRun.run(s, d2, "item", "list", "personal", env = pw(pw3)).ok().contains("GitHub"))

            // 3. The first kit stopped working with the first recovery: refused in the uniform words, and no new kit file.
            val d3 = File(tmp, "d3")
            val kit4 = File(tmp, "kit4.txt")
            val old = CliRun.run(s, d3, "recover", "kit", "--kit-file", kit1.path, "--kit-out", kit4.path, origin = null, env = pw("fourth Password never used 44"))
            assertEquals(1, old.code, old.out + old.err)
            assertTrue(old.err.contains(Commands.KIT_REJECTED), old.err)
            assertFalse(kit4.exists())
        }
    }
}
