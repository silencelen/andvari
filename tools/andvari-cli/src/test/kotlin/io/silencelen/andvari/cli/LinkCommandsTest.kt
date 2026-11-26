package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The link commands at the command line, against the real server: `link-device show` and `link-device` in their two
 * processes (design §8.2), and `link create`, `link open`, `link answers`, `link code` and `link compare` between two
 * accounts (design §6.7, §6.11).
 */
class LinkCommandsTest {
    /** Waits until [buf] holds a line matching [re], and answers its first group. */
    private fun await(buf: ByteArrayOutputStream, re: Regex, timeoutMs: Long = 120_000): String =
        io.silencelen.andvari.cli.e2e.Await.until("a line matching ${re.pattern} from the other process", timeoutMs, { "its output so far: $buf" }) {
            re.find(buf.toString())?.groupValues?.get(1)
        }

    private class Accounts(val s: TestServer, val tmp: File, val card0: String)

    /** The operator through the setup link, then each of [emails] on its own device through the host's enrol link. */
    private fun accounts(s: TestServer, vararg emails: String): Accounts {
        val tmp = Files.createTempDirectory("andvari-cli").toFile()
        CliRun.run(s, File(tmp, "operator"), "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
        val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, File(tmp, "operator"), "card", "show").ok())!!.groupValues[1]
        for (e in emails) {
            val home = File(tmp, e.substringBefore('@'))
            CliRun.run(s, home, "enrol", Steps.enrolLink(s, e), "--email", e, "--kit-out", File(tmp, "$e-kit.txt").path, "--trust-card", card0).ok()
            // A first password sign-in passes the Trust Gate (an enrol pin is no password pin, design §4.4).
            CliRun.run(s, home, "sign-in", "--trust-card", card0).ok()
        }
        return Accounts(s, tmp, card0)
    }

    @Test fun linkDeviceShowAndLinkDeviceLinkANewDeviceWithNoOrigin() {
        TestServer().use { s ->
            val acc = accounts(s, "me@example.org")
            val me = File(acc.tmp, "me")
            CliRun.run(s, me, "item", "put", "personal", stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}""")).ok()

            val shown = ByteArrayOutputStream()
            val joined = ByteArrayOutputStream()
            // The existing device types the code the new one prints, as the person would read it across.
            val shownEnv: (String) -> String? = { name ->
                when (name) {
                    "ANDVARI_PASSWORD" -> Steps.PASSWORD
                    "ANDVARI_DEVICE_CODE" -> await(joined, Regex("Type this code on your other device: ([0-9 ]+)"))
                    else -> null
                }
            }
            val pool = Executors.newSingleThreadExecutor()
            try {
                val show = pool.submit<CliRun> { CliRun.run(s, me, "link-device", "show", env = shownEnv, out = shown, captureErr = false) }
                val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
                val linkFile = File(acc.tmp, "device-link.txt").also { it.writeText(url) }
                // The new device: a fresh home and no --origin; the link names the origin.
                val newDevice = File(acc.tmp, "new")
                val r = CliRun.run(s, newDevice, "link-device", "--link-file", linkFile.path, "--trust-card", acc.card0, origin = null, out = joined, captureErr = false)
                assertEquals(0, r.code, r.out)
                assertTrue(r.out.contains("linked: this device is"), r.out)
                val shownRun = show.get(3, TimeUnit.MINUTES)
                assertEquals(0, shownRun.code, shownRun.out)
                assertTrue(shownRun.out.contains("approved"), shownRun.out)

                // The new device remembers the origin and the account, and works there with no --origin.
                val who = CliRun.run(s, newDevice, "whoami", origin = null).ok()
                assertTrue(who.contains("origin:  ${s.origin}") && who.contains("account: me@example.org"), who)
                assertTrue(CliRun.run(s, newDevice, "item", "list", "personal", origin = null).ok().contains("GitHub"))
            } finally {
                pool.shutdownNow()
            }
            acc.tmp.deleteRecursively()
        }
    }

    @Test fun linkCreateOpenAnswersCodeAndCompareConnectTwoAccounts() {
        TestServer().use { s ->
            val acc = accounts(s, "me@example.org", "friend@example.org")
            val me = File(acc.tmp, "me")
            val friend = File(acc.tmp, "friend")

            val url = CliRun.run(s, me, "link", "create").ok().lines().last { it.contains("://") }.trim()
            assertTrue(CliRun.run(s, me, "link", "list").ok().contains("connect"))
            val linkFile = File(acc.tmp, "connect-link.txt").also { it.writeText(url) }
            val opened = CliRun.run(s, friend, "link", "open", "--link-file", linkFile.path).ok()
            val meId = Regex("answered: contact ([0-9a-f-]{36})").find(opened)!!.groupValues[1]

            val answers = CliRun.run(s, me, "link", "answers").ok()
            val friendId = Regex("connected: ([0-9a-f-]{36})").find(answers)?.groupValues?.get(1) ?: error(answers)

            val myCode = Regex("Your code: ([0-9 ]+?)\\s{2,}").find(CliRun.run(s, me, "link", "code", friendId).ok())!!.groupValues[1]
            val theirCode = Regex("Your code: ([0-9 ]+?)\\s{2,}").find(CliRun.run(s, friend, "link", "code", meId).ok())!!.groupValues[1]

            // A wrong code is refused in words and changes nothing; the right ones compare both sides.
            val wrong = CliRun.run(s, me, "link", "compare", friendId, "--code", "000000")
            assertEquals(1, wrong.code)
            assertTrue(wrong.err.contains("don't match") && wrong.err.contains("Don't share"), wrong.err)
            assertTrue(CliRun.run(s, me, "link", "compare", friendId, "--code", theirCode).ok().contains("codes match"))
            assertTrue(CliRun.run(s, friend, "link", "compare", meId, "--code", myCode).ok().contains("codes match"))
            assertTrue(CliRun.run(s, me, "contacts").ok().lines().any { it.startsWith(friendId) && it.contains(" compared") })
            assertTrue(CliRun.run(s, friend, "contacts").ok().lines().any { it.startsWith(meId) && it.contains(" compared") })
            acc.tmp.deleteRecursively()
        }
    }
}
