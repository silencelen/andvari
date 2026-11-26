package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.URLProtocol
import io.ktor.server.testing.testApplication
import io.ktor.client.statement.bodyAsText
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `andvari setup --test` to the end (design §9.5, FI-B9; the change the command-line tool needed): without
 * `--stop-at-setup` setup serves the new instance in memory, runs `andvari-cli operator enrol -` with the setup
 * link on standard input, reads card 0 back with `andvari-cli card show`, checks it against the stored card,
 * mints the enrol links and writes `operator.json`. [FakeCli] plays the tool in-process, over real HTTP to the
 * server setup started, doing exactly what the tool does (register through the setup link, sign card 0); the
 * real tool's half is `tools/andvari-cli`'s `SetupTestOperatorTest`. The failure paths run a real child process.
 */
/** [Flow.register] at the real KDF floor, which setup's server keeps (the tool derives with real parameters). */
private suspend fun registerAtTheFloor(http: HttpClient, s: Services, me: Me, auth: RegisterAuth) {
    val body = (WireJson.json.parseToJsonElement(me.register(s, auth)) as JsonObject).toMutableMap()
    body["kdfParams"] = WireJson.json.encodeToJsonElement(KdfParams.serializer(), KdfParams(ops = 3, memBytes = 64L * 1024 * 1024))
    val r = http.call(io.ktor.http.HttpMethod.Post, "/api/v1/auth/register", JsonObject(body).toString())
    assertEquals(200, r.status.value, r.bodyAsText())
    me.session = WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
}

class SetupTestHeadlessTest {
    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun portIsFree(port: Int): Boolean = runCatching { ServerSocket(port, 1, InetAddress.getByName("127.0.0.1")).close() }.isSuccess

    private fun mode(f: File) = PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath()))

    private fun executable(dir: File, name: String, body: String): File =
        File(dir, name).apply { writeText(body); setExecutable(true, true) }

    private class Result(val code: Int, val out: String, val err: String)

    private fun run(argv: List<String>, env: Map<String, String> = emptyMap(), cli: CliRunner = CliRunner.PROCESS, relay: SetupRelay? = null): Result {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val realErr = System.err
        System.setErr(PrintStream(err, true))
        val code = try { HostCli.run(argv, PrintStream(out), cli, relay) { env[it] } } finally { System.setErr(realErr) }
        return Result(code, out.toString(), err.toString())
    }

    /** The tool, in-process: what `operator enrol -` and `card show` do, against the server setup started. */
    private class FakeCli(val envFile: File, val port: Int, val shownHash: (String) -> String = { it }) : CliRunner {
        val calls = ArrayList<Pair<List<String>, String>>()

        override fun run(command: List<String>, stdin: String): CliRunner.Ran {
            calls += command to stdin
            val config = HostCli.configFrom(envFile)
            val s = Services(config, Clock.SYSTEM, Db(config.dbPath), CoreTrust()).also { it.backgroundWorkers = false }
            try {
                return when (command.drop(3).take(2)) {
                    listOf("operator", "enrol") -> runBlocking {
                        // Every request goes to the server setup started (the helpers send relative paths).
                        val http = HttpClient(Java) {
                            install(createClientPlugin("to-setup-server") {
                                onRequest { req, _ -> req.url.protocol = URLProtocol.HTTP; req.url.host = "127.0.0.1"; req.url.port = port }
                            })
                        }
                        val email = command[command.indexOf("--email") + 1]
                        try {
                            val (id, token) = Flow.linkAuth(stdin.trim())
                            val op = Me(email)
                            registerAtTheFloor(http, s, op, RegisterAuth.Setup(id, token))
                            Flow.finishSetupCardOnly(http, s, op)
                        } finally { http.close() }
                        CliRunner.Ran(0, "Instance ready\nregistered: $email\n", "")
                    }
                    listOf("card", "show") -> CliRunner.Ran(0, "card0Hash:  ${shownHash(s.db.read { s.instance.card0Hash(it)!! })}\n", "")
                    else -> CliRunner.Ran(2, "", "unexpected command $command")
                }
            } finally {
                s.close()
            }
        }
    }

    /** The caller's own listener on the origin's port, bound to port 0 and held throughout: it relays to [target]. */
    private class HeldPort : AutoCloseable {
        private val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int = server.localPort
        @Volatile var target = 0
        val routed = java.util.Collections.synchronizedList(ArrayList<Int>())
        val relay = SetupRelay { p -> routed += p; target = p }

        init {
            kotlin.concurrent.thread(isDaemon = true) {
                while (!server.isClosed) {
                    val inbound = try { server.accept() } catch (_: java.io.IOException) { break }
                    kotlin.concurrent.thread(isDaemon = true) {
                        inbound.use { a ->
                            val t = target
                            if (t == 0) return@thread
                            java.net.Socket("127.0.0.1", t).use { b ->
                                val back = kotlin.concurrent.thread(isDaemon = true) { runCatching { b.getInputStream().copyTo(a.getOutputStream()) }; runCatching { a.shutdownOutput() } }
                                runCatching { a.getInputStream().copyTo(b.getOutputStream()) }; runCatching { b.shutdownOutput() }
                                back.join()
                            }
                        }
                    }
                }
            }
        }

        override fun close() = server.close()
    }

    /**
     * Follow-up of 2026-11-16: an in-process caller that holds the origin's port (the CLI's end-to-end fixture) gives setup
     * a [SetupRelay]; setup's temporary server then binds a port of its own (port 0) behind the caller's listener, so no
     * port is picked first and bound later. The held port is never let go, and the origin, the env file and card 0 name it.
     */
    @Test
    fun withARelay_setupServesBehindTheCallersHeldPort_andBindsNoPortPickedBeforehand() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        HeldPort().use { held ->
            val tool = executable(dir, "andvari-cli", "#!/bin/sh\nexit 99\n")
            val fake = FakeCli(env, held.port)
            val r = run(listOf("setup", "--test", "--port", "${held.port}", "--env-file", env.path, "--cli", tool.path), cli = fake, relay = held.relay)
            assertEquals(0, r.code, r.out + r.err)
            val o = WireJson.json.parseToJsonElement(r.out.trim()).jsonObject
            assertEquals("http://127.0.0.1:${held.port}", o["origin"]!!.jsonPrimitive.content)
            assertTrue(env.readText().contains("ANDVARI_PORT=${held.port}\n"))
            // Setup routed the held port to a server of its own on another port, and back to nothing before it stopped.
            assertEquals(2, held.routed.size, "${held.routed}")
            assertTrue(held.routed[0] != 0 && held.routed[0] != held.port, "${held.routed}")
            assertEquals(0, held.routed[1])
            assertTrue(portIsFree(held.routed[0]), "setup stopped its own server")
            // The held port stayed the caller's the whole time (setup never bound it), and card 0 is the one served.
            assertFalse(portIsFree(held.port))
            val config = HostCli.configFrom(env)
            val s = buildServices(config).also { it.backgroundWorkers = false }
            try { assertEquals(o["card0Hash"]!!.jsonPrimitive.content, s.db.read { s.instance.card0Hash(it) }) } finally { s.close() }
        }
    }

    @Test
    fun withoutStopAtSetup_itEnrolsTheTestOperator_checksCard0_andMintsEnrolLinks() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        val data = File(dir, "data")
        val port = freePort()
        val tool = executable(dir, "andvari-cli", "#!/bin/sh\nexit 99\n")
        val fake = FakeCli(env, port)
        val r = run(listOf("setup", "--test", "--port", "$port", "--env-file", env.path, "--cli", tool.path, "--enrol", "2"), cli = fake)
        assertEquals(0, r.code, r.out + r.err)
        assertEquals(1, r.out.trim().lines().size, "stdout is the one JSON object: ${r.out}")
        val o = WireJson.json.parseToJsonElement(r.out.trim()).jsonObject
        assertEquals(
            setOf("origin", "instanceId", "setupLink", "card0Hash", "operatorFile", "enrolLinks", "mailSink", "clockFile", "envFile"),
            o.keys,
        )
        assertTrue(env.readText().contains("ANDVARI_PORT=$port\n"), "the server serves the origin's port")

        // The tool was run as asked: the link on standard input, never as an argument, nor the password.
        val opDir = File(data, HostCli.TEST_OPERATOR_DIR)
        val setupLink = o["setupLink"]!!.jsonPrimitive.content
        val (enrol, enrolIn) = fake.calls[0]
        assertEquals(
            listOf(tool.path, "--home", File(opDir, "home").path, "operator", "enrol", "-", "--email", HostCli.TEST_OPERATOR_EMAIL, "--name", "operator",
                "--kit-out", File(opDir, "kit.txt").path, "--password-file", File(opDir, "password").path),
            enrol,
        )
        assertEquals(setupLink + "\n", enrolIn)
        val password = File(opDir, "password").readText().trim()
        assertFalse(enrol.any { setupLink in it || password in it })
        assertEquals(listOf(tool.path, "--home", File(opDir, "home").path, "card", "show") to "", fake.calls[1])
        assertEquals(2, fake.calls.size)
        assertEquals("rwx------", mode(opDir)); assertEquals("rw-------", mode(File(opDir, "password")))

        // card0Hash is the stored card 0; operator.json (owner-only) names the operator's files.
        val config = HostCli.configFrom(env)
        val card0 = o["card0Hash"]!!.jsonPrimitive.content
        val operatorFile = File(o["operatorFile"]!!.jsonPrimitive.content)
        assertEquals(File(opDir, "operator.json"), operatorFile)
        assertEquals("rw-------", mode(operatorFile))
        val opJson = WireJson.json.parseToJsonElement(operatorFile.readText()) as JsonObject
        assertEquals(
            mapOf(
                "origin" to "http://127.0.0.1:$port", "email" to HostCli.TEST_OPERATOR_EMAIL, "passwordFile" to File(opDir, "password").path,
                "cliHome" to File(opDir, "home").path, "kitFile" to File(opDir, "kit.txt").path, "card0Hash" to card0,
            ),
            opJson.mapValues { it.value.jsonPrimitive.content },
        )
        // The server setup started is stopped again.
        assertTrue(portIsFree(port), "setup stopped its server")

        // The enrol links are real: bound to card 0, open, and an everyday account enrols with one.
        val links = o["enrolLinks"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertEquals(2, links.size)
        val s = buildServices(config).also { it.backgroundWorkers = false }
        try {
            assertEquals(card0, s.db.read { s.instance.card0Hash(it) })
            assertEquals(2L, s.db.read { it.count("SELECT COUNT(*) FROM links WHERE kind='enrol' AND state='open'") })
            assertEquals("operator", s.db.read { it.queryOne("SELECT role FROM users WHERE email=?", HostCli.TEST_OPERATOR_EMAIL) { r -> r.getString(1) } })
            testApplication {
                application { andvariModule(s) }
                val (id, token) = Flow.linkAuth(links[0])
                registerAtTheFloor(client, s, Me("me@example.org"), RegisterAuth.Enrol(id, token))
            }
        } finally {
            s.close()
        }
    }

    @Test
    fun withoutTheTool_setupRefuses_beforeWritingAnything() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        for ((argv, environment) in listOf(
            emptyList<String>() to emptyMap(),
            emptyList<String>() to mapOf("PATH" to dir.path),
            listOf("--cli", File(dir, "missing").path) to emptyMap(),
            listOf("--cli", File(dir, "not-executable").also { it.writeText("x") }.path) to emptyMap(),
            emptyList<String>() to mapOf("ANDVARI_CLI" to File(dir, "missing").path),
        )) {
            val r = run(listOf("setup", "--test", "--env-file", env.path) + argv, environment)
            assertEquals(1, r.code, "$argv $environment")
            assertTrue(r.err.contains("needs andvari-cli to enrol the test operator") && r.err.contains("--stop-at-setup"), r.err)
            assertFalse(env.exists(), "nothing was written")
            assertFalse(File(dir, "data").exists(), "nothing was written")
        }
        // The tool on the PATH is found by name; a bad --enrol is a usage error, still before anything is written.
        executable(dir, "andvari-cli", "#!/bin/sh\nexit 0\n")
        assertEquals(2, run(listOf("setup", "--test", "--env-file", env.path, "--enrol", "0"), mapOf("PATH" to dir.path)).code)
        assertFalse(env.exists())
        // --stop-at-setup needs no tool, and its output carries no card0Hash, operatorFile or enrol links.
        val stop = run(listOf("setup", "--test", "--stop-at-setup", "--env-file", env.path))
        assertEquals(0, stop.code, stop.err)
        val o = WireJson.json.parseToJsonElement(stop.out.trim()).jsonObject
        assertEquals(setOf("origin", "instanceId", "setupLink", "enrolLinks", "mailSink", "clockFile", "envFile"), o.keys)
        assertEquals(0, o["enrolLinks"]!!.jsonArray.size)
    }

    /** A real child process that fails: its standard error is the refusal, and the server is stopped. */
    @Test
    fun aFailingTool_isRefusedWithItsStandardError_andTheServerIsStopped() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        val port = freePort()
        val seen = File(dir, "seen")
        val tool = executable(dir, "fake-cli", "#!/bin/sh\necho \"$@\" > '${seen.path}.args'\ncat > '${seen.path}.stdin'\necho 'enrol: the setup link was already used' >&2\nexit 3\n")
        val r = run(listOf("setup", "--test", "--port", "$port", "--env-file", env.path), mapOf("ANDVARI_CLI" to tool.path))
        assertEquals(1, r.code, r.out + r.err)
        assertTrue(r.err.contains("andvari-cli operator enrol failed (exit 3): enrol: the setup link was already used"), r.err)
        assertTrue(r.err.contains("rebuilt from scratch"), r.err)
        assertEquals("", r.out, "no JSON for a setup that did not finish")
        val setupLink = Regex("https://andvaripass.com/l#v2\\.[^\\s]+").find(File(seen.path + ".stdin").readText())?.value
        assertTrue(setupLink != null && File(seen.path + ".stdin").readText() == setupLink + "\n", "the link came on standard input")
        assertTrue(File(seen.path + ".args").readText().startsWith("--home "), File(seen.path + ".args").readText())
        assertFalse(File(seen.path + ".args").readText().contains(setupLink!!))
        assertTrue(portIsFree(port), "setup stopped its server")
        assertEquals(0L, Db(HostCli.configFrom(env).dbPath).use { db -> db.read { it.count("SELECT COUNT(*) FROM links WHERE kind='enrol'") } })
    }

    /** card 0 as the tool shows it must be the one the server stored; otherwise no enrol link is minted. */
    @Test
    fun aCard0ThatDiffersFromTheStoredOne_isRefused_andNoEnrolLinkIsMinted() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        val port = freePort()
        val tool = executable(dir, "andvari-cli", "#!/bin/sh\nexit 99\n")
        val r = run(listOf("setup", "--test", "--port", "$port", "--env-file", env.path, "--cli", tool.path), cli = FakeCli(env, port) { "0".repeat(64) })
        assertEquals(1, r.code, r.out + r.err)
        assertTrue(r.err.contains("is not the one the server stored"), r.err)
        assertTrue(portIsFree(port))
        assertEquals(0L, Db(HostCli.configFrom(env).dbPath).use { db -> db.read { it.count("SELECT COUNT(*) FROM links WHERE kind='enrol'") } })
        assertFalse(File(File(dir, "data"), "${HostCli.TEST_OPERATOR_DIR}/operator.json").exists())
    }
}
