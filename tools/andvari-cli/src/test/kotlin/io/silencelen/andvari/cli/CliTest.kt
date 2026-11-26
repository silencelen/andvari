package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Redirect
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.WireItemTransport
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.client.net.ORIGIN_STOPPED
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.net.originStopped
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.DeviceLinkUrl
import io.silencelen.andvari.core.trust.LinkUrl
import kotlinx.coroutines.runBlocking
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The command line against the real server: the cut-over path (design §14.1) and the demo `seed` / `check` (R11). */
class CliTest {
    private class Run(val code: Int, val out: String)

    /** One run of the tool on the device [home]; [origin] is passed as `--origin` unless null. */
    private fun cli(
        s: TestServer, home: File, vararg args: String, env: Map<String, String> = mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD), stdin: String = "",
        origin: String? = s.origin, dial: String? = null,
    ): Run {
        val buf = ByteArrayOutputStream()
        val lines = stdin.lines().filter { it.isNotEmpty() }.iterator()
        val global = listOf("--home", home.path) + (origin?.let { listOf("--origin", it) } ?: emptyList())
        val http = dial?.let { d -> { Redirect.client(origin ?: s.origin, d) } }
        val code = Cli.runWith(global + args, PrintStream(buf), { env[it] }, { if (lines.hasNext()) lines.next() else null }, s::now, http)
        return Run(code, buf.toString())
    }

    private fun ok(r: Run): String { assertEquals(0, r.code, r.out); return r.out }

    @Test fun theCutOverPathAndTheDemoAccounts() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")

            // The operator through the setup link: card 0 signed here, card0Hash taken from this device (T-R10).
            ok(cli(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path))
            assertTrue(File(tmp, "op-kit.txt").readText().contains("andvari-kit:2:"))
            val show = ok(cli(s, op, "card", "show"))
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(show)!!.groupValues[1]

            // Secrets never on the command line.
            assertEquals(2, cli(s, me, "sign-in", "--password", "x").code)

            // The everyday account through the host's enrol link, with the scripted Trust Gate.
            val link = Steps.enrolLink(s, "me@example.org")
            assertEquals(1, cli(s, me, "enrol", link, "--email", "me@example.org", "--kit-out", File(tmp, "x.txt").path, "--trust-card", "0".repeat(64)).code,
                "a card 0 other than the one given is never trusted")
            ok(cli(s, me, "enrol", link, "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0))

            // Items in and out as JSON.
            ok(cli(s, me, "item", "put", "personal", "--trust-card", card0, stdin = """{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}"""))
            assertTrue(ok(cli(s, me, "item", "list", "personal", "--json")).contains("\"GitHub\""))

            // The operator raises the quota first, then the restore (spec 07 §3).
            assertTrue(ok(cli(s, op, "operator", "accounts")).contains("me@example.org"))
            ok(cli(s, op, "operator", "quota", "me@example.org", "--items", "9000"))
            val backup = File(tmp, "old.andvari").also { it.writeBytes(backupOf(listOf("Bank", "Mail"))) }
            val pass = mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD, "ANDVARI_BACKUP_PASSPHRASE" to "backup pass phrase")
            assertTrue(ok(cli(s, me, "restore", "--backup", backup.path, "--dry-run", env = pass)).contains("2 items"))
            assertTrue(ok(cli(s, me, "restore", "--backup", backup.path, env = pass)).contains("restored 2 items"))
            // A rerun resumes from the plan: every batch is acknowledged, nothing is pushed twice.
            val again = ok(cli(s, me, "restore", "--backup", backup.path, env = pass))
            assertTrue(again.contains("nothing of the chosen vaults was left to restore: nothing was sent"), again)
            val names = ok(cli(s, me, "item", "list", "personal"))
            assertEquals(listOf("Bank", "GitHub", "Mail"), Regex("[0-9a-f-]{36}  (\\S+)").findAll(names).map { it.groupValues[1] }.sorted().toList())

            // The demo account: seed twice adds once, check passes.
            assertTrue(ok(cli(s, me, "seed", "--items", "3")).contains("3 added"))
            assertTrue(ok(cli(s, me, "seed", "--items", "3")).contains("0 added"))
            assertTrue(ok(cli(s, me, "check", "--items", "3")).contains("check ok"))
            assertEquals(1, cli(s, me, "check", "--items", "4").code)

            // Nothing secret reached the device's files in the clear.
            val files = me.listFiles()!!.filter { it.isFile }
            assertFalse(files.any { it.readText().contains(Steps.PASSWORD) })
            tmp.deleteRecursively()
        }
    }

    /**
     * `card show` printed a hash of the raw Ed25519 operator key, a value no Trust Gate ever shows. It now
     * prints the engine's operator short fingerprint (over the X25519 image), the value a new device's gate shows for the
     * same real card.
     */
    @Test fun cardShowPrintsTheOperatorKeyTheTrustGateShows() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            ok(cli(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path))
            val shown = Regex("operatorKey:\\s+(.+?)\\s+\\(as the Trust Gate shows it").find(ok(cli(s, op, "card", "show")))!!.groupValues[1]

            val fresh = Host(MemoryDeviceState(), MemoryDeviceState(), s::now)
            val gate = runBlocking { fresh.trust.beginTrustGate(s.origin, TrustGateWording.TYPED_ADDRESS) }
            assertTrue(gate is FirstPin.NeedsTrustGate, "$gate")
            assertEquals(Fingerprint.groupedShort(gate.operatorShortFp).replace("\n", " "), shown)
            tmp.deleteRecursively()
        }
    }

    /**
     * A link carries its origin, so `operator enrol` and `enrol` need no `--origin`. An `--origin` that
     * disagrees with the link (for `link-device` too) is refused before anything is sent: a listener at the link's origin
     * that only counts connections receives none.
     */
    @Test fun aLinkNamesItsOriginAndAnOriginThatDisagreesIsRefusedBeforeAnythingIsSent() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            assertTrue(ok(cli(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path, origin = null))
                .contains("on ${s.origin}"))
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(ok(cli(s, op, "card", "show", origin = null)))!!.groupValues[1]

            ConnectionCounter().use { counter ->
                val elsewhere = counter.address
                val invite = LinkUrl.compose(elsewhere, ByteArray(32) { 1 }, null)!!
                val deviceLink = DeviceLinkUrl.compose(elsewhere, ByteArray(32) { 2 })!!
                assertEquals(2, cli(s, me, "enrol", invite, "--email", "me@example.org", "--kit-out", File(tmp, "x.txt").path).code)
                assertEquals(2, cli(s, me, "link-device", deviceLink).code)
                assertEquals(0, counter.settled(), "a link for another origin than --origin is sent nothing")
            }

            // The everyday account's enrol link, with no --origin: the account lands on the link's origin, remembered.
            assertTrue(ok(cli(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path,
                "--trust-card", card0, origin = null)).contains("on ${s.origin}"))
            assertTrue(ok(cli(s, me, "whoami", origin = null)).contains("origin:  ${s.origin}"))
            tmp.deleteRecursively()
        }
    }

    /**
     * A link need not be a positional argument (the process list shows those). The operator's setup
     * link comes from standard input (`-`), the everyday account's enrol link from `--link-file`; giving both forms is a
     * usage error, and the help says which to prefer.
     */
    @Test fun aLinkIsReadFromAFileOrStandardInputInsteadOfTheProcessList() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            ok(cli(s, op, "operator", "enrol", "-", "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path, stdin = s.setupLink))
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(ok(cli(s, op, "card", "show")))!!.groupValues[1]

            val linkFile = File(tmp, "link.txt").also { it.writeText("\n  " + Steps.enrolLink(s, "me@example.org") + "\n") }
            assertEquals(2, cli(s, me, "enrol", "https://andvaripass.com/l#v2.x", "--link-file", linkFile.path, "--email", "me@example.org").code,
                "a link given twice is a usage error")
            assertEquals(2, cli(s, me, "enrol", "--link-file", File(tmp, "absent.txt").path, "--email", "me@example.org").code)
            ok(cli(s, me, "enrol", "--link-file", linkFile.path, "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0))
            assertTrue(ok(cli(s, me, "whoami")).contains("account: me@example.org"))

            val help = ByteArrayOutputStream().also { Cli.run(listOf("--help"), PrintStream(it)) }.toString()
            assertTrue(help.contains("--link-file PATH (preferred)"), help)
            tmp.deleteRecursively()
        }
    }

    /**
     * Design §4.4 "a fork stops traffic": every client the tool uses comes from the engine's dialer, so under a fork mark
     * no command sends anything, not even the saved session's refresh or the logout, and the saved session is kept.
     * `forget-server --yes` is the only way on; afterwards the Trust Gate runs again.
     */
    @Test fun aForkStopsEveryCommandAndOnlyForgettingTheServerGoesOn() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            ok(cli(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path))
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(ok(cli(s, op, "card", "show")))!!.groupValues[1]
            ok(cli(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0))
            ok(cli(s, me, "item", "put", "personal", "--trust-card", card0, stdin = """{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}"""))

            val pins = PinStore(CliHome(me).deviceState())
            pins.markForked(pins.get(s.origin)!!)
            // From here every command dials a listener that only counts connections: nothing may reach it.
            ConnectionCounter().use { counter ->
                val dial = counter.address
                for (cmd in listOf(listOf("sync"), listOf("item", "list", "personal"), listOf("vault", "create", "After"), listOf("sign-in"))) {
                    assertEquals(1, cli(s, me, *cmd.toTypedArray(), dial = dial).code, "$cmd is refused under a fork")
                }
                // The host's own clients, the raw-body channel, a token-only client and the saved session's reopening:
                // each answers the guard's stop, and a stop is not the server refusing the session, which is kept.
                val host = Host(CliHome(me).deviceState(), CliHome(me).secureState(), s::now, http = Redirect.client(s.origin, dial))
                val saved = SavedSessions(CliHome(me).secureState())
                runBlocking {
                    assertTrue(host.client(s.origin).call(WireRoute.CLIENT_POLICY, decode = { it }).originStopped)
                    assertTrue(host.withToken(s.origin, "t").call(WireRoute.LOGOUT, decode = { }).originStopped)
                    // The attachment channel the tool's item engine uses (AccountSession: WireItemTransport over the session client).
                    val stopped = WireItemTransport(host.client(s.origin)).downloadAttachment("33333333-3333-4333-8333-333333333333", 10)
                    assertEquals(ORIGIN_STOPPED, (stopped as WireResult.Refused).code)
                    val reopened = runCatching { saved.reopen(host, s.origin, "me@example.org", Steps.PASSWORD.toCharArray()) }
                    assertTrue(reopened.exceptionOrNull()?.message.orEmpty().contains("stopped using"), "$reopened")
                }
                assertEquals(OriginAccess.FORKED, host.access(s.origin))
                assertTrue(saved.has(s.origin, "me@example.org"), "the saved session is kept under a stop")

                // Forgetting is local and asks for --yes.
                assertEquals(2, cli(s, me, "forget-server", dial = dial).code)
                assertTrue(ok(cli(s, me, "forget-server", "--yes", dial = dial)).contains("it was fork"))
                assertEquals(0, counter.settled(), "a forked instance is sent nothing, and forgetting it sends nothing")
            }
            // The pin and the saved session are gone; the next sign-in runs the Trust Gate again.
            assertEquals(PinState.None, PinStore(CliHome(me).deviceState()).state(s.origin))
            assertFalse(SavedSessions(CliHome(me).secureState()).has(s.origin, "me@example.org"))
            assertTrue(ok(cli(s, me, "whoami")).contains("not pinned"))
            assertEquals(1, cli(s, me, "sign-in", "--email", "me@example.org").code, "no silent trust on first use after a forget")
            ok(cli(s, me, "sign-in", "--email", "me@example.org", "--trust-card", card0))
            tmp.deleteRecursively()
        }
    }

    private fun backupOf(names: List<String>): ByteArray {
        val crypto = createCryptoProvider()
        val pv = "11111111-1111-4111-8111-111111111111"
        val payload = BackupPayload(
            exportedAt = 1_760_000_000_000L, origin = "https://old.example",
            vaults = listOf(BackupVault(pv, "personal", "Personal", "owner")),
            items = names.mapIndexed { i, n ->
                BackupItem("22222222-2222-4222-8222-00000000000$i", pv, 1, 1_760_000_000_000L, ItemDoc("login", n, login = LoginData("u$i", "p$i")))
            },
        )
        val parts = ArrayList<ByteArray>()
        Backup.build(crypto, "backup pass phrase", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload, emptyList(), null) { parts += it }
        return parts.fold(ByteArray(0)) { acc, p -> acc + p }
    }
}
