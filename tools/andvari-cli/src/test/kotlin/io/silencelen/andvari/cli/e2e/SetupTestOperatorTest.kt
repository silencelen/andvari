package io.silencelen.andvari.cli.e2e

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `andvari setup --test` to the end (design §9.5 B4, FI-B9), the real thing: the server's own `HostCli.run(setup --test
 * --cli <the installed andvari-cli>)` writes the instance, starts it in memory, runs the INSTALLED tool (the launcher
 * script and the jars `installDist` makes, as a process of its own with no terminal) to enrol the test operator through
 * the setup link, reads card 0 back with `card show`, mints the enrol links and prints one JSON object. This test then
 * serves that instance and checks what setup said against what the tool and the server hold.
 */
class SetupTestOperatorTest {
    private val installed: String = System.getProperty("andvari.cli.installed")!!

    private class Ran(val code: Int, val out: String, val err: String)

    /** The installed tool, as a person or a script runs it: its own process, [stdin] piped in, no terminal. */
    private fun tool(args: List<String>, stdin: String = ""): Ran {
        val dir = Files.createTempDirectory("andvari-cli-setup-run").toFile()
        try {
            val out = File(dir, "out")
            val err = File(dir, "err")
            val p = ProcessBuilder(listOf(installed) + args).redirectOutput(out).redirectError(err).start()
            p.outputStream.use { it.write(stdin.toByteArray()) }
            check(p.waitFor(180, TimeUnit.SECONDS)) { "andvari-cli ${args.take(3)} did not finish" }
            return Ran(p.exitValue(), out.readText(), err.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * The fixture picks no free port by hand, also for a setup that enrols its operator through
     * the tool. Its origin's port is the [Relay]'s, held from construction, and setup routes that relay to its own
     * temporary instance; so neither the fixture class nor its companion opens a server socket of its own.
     */
    @Test fun theFixturePicksNoPortByHand() {
        for (name in listOf("TestServer", "TestServer\$Companion")) {
            val bytes = TestServer::class.java.getResourceAsStream("$name.class")?.use { it.readBytes() } ?: continue
            assertFalse(String(bytes, Charsets.ISO_8859_1).contains("java/net/ServerSocket"), "$name opens a server socket of its own")
        }
        assertTrue(TestServer::class.java.getResource("TestServer.class") != null, "the fixture's class is found")
    }

    @Test fun setupTestEnrolsItsOperatorWithTheInstalledToolAndThenMintsEnrolLinks() {
        assertTrue(File(installed).canExecute(), "the installed tool: $installed")
        TestServer(cli = installed, extraSetup = listOf("--enrol", "2")).use { s ->
            val card0 = s.setup.getValue("card0Hash").jsonPrimitive.content
            val links = s.setup.getValue("enrolLinks").jsonArray.map { it.jsonPrimitive.content }
            assertEquals(2, links.size, "the --enrol 2 links: ${s.setup}")
            assertTrue(Regex("[0-9a-f]{64}").matches(card0), card0)

            // operatorFile: the test operator's credentials, owner-only, and everything in it agrees with the instance.
            val opFile = File(s.setup.getValue("operatorFile").jsonPrimitive.content)
            val ownerOnly = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            assertEquals(ownerOnly, Files.getPosixFilePermissions(opFile.toPath()), "operator.json is owner-only")
            val op = Json.parseToJsonElement(opFile.readText()).jsonObject
            val email = op.getValue("email").jsonPrimitive.content
            val home = File(op.getValue("cliHome").jsonPrimitive.content)
            val password = File(op.getValue("passwordFile").jsonPrimitive.content)
            val kit = File(op.getValue("kitFile").jsonPrimitive.content)
            assertEquals(s.origin, op.getValue("origin").jsonPrimitive.content)
            assertEquals(card0, op.getValue("card0Hash").jsonPrimitive.content)
            assertEquals(ownerOnly, Files.getPosixFilePermissions(kit.toPath()), "the kit is owner-only")
            assertTrue(kit.readText().startsWith("andvari recovery kit for account"), "the kit was captured and confirmed from the file")

            // The tool's device holds the card setup printed, and so does the server; the operator is that account.
            val shown = tool(listOf("--home", home.path, "card", "show"))
            assertEquals(0, shown.code, shown.out + shown.err)
            assertTrue(shown.out.contains("card0Hash:   $card0"), shown.out)
            assertTrue(s.admin("status").contains("card: seq 0, $card0"), s.admin("status"))
            assertTrue(s.admin("operator").contains(email))

            // The operator account works from that device, with the password from the file and no terminal.
            val status = tool(listOf("--home", home.path, "operator", "status", "--password-file", password.path))
            assertEquals(0, status.code, status.out + status.err)
            assertFalse(status.err.contains("SLF4J") || status.err.contains("Exception"), status.err)

            // An everyday account enrols through a link setup minted, with the card 0 setup printed; nothing secret is an argument.
            val me = File(s.dir, "me")
            val args = listOf("--home", me.path, "enrol", "-", "--email", "me@example.org", "--kit-out", File(s.dir, "me-kit.txt").path,
                "--password-file", password.path, "--trust-card", card0)
            assertFalse(args.any { it.contains(links[0]) }, "the link is not an argument")
            val meRun = tool(args, stdin = links[0] + "\n")
            assertEquals(0, meRun.code, meRun.out + meRun.err)
            assertTrue(meRun.out.contains("registered: me@example.org"), meRun.out)
        }
    }
}
