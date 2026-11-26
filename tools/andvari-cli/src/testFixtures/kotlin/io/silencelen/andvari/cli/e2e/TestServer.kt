package io.silencelen.andvari.cli.e2e

import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.netty.NettyApplicationEngine
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.server.HostCli
import io.silencelen.andvari.server.Services
import io.silencelen.andvari.server.andvariModule
import io.silencelen.andvari.server.buildServices
import io.silencelen.andvari.server.queryOne
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files

/**
 * The real server in its test mode on 127.0.0.1 (design §7.1, §9.5): `andvari setup --test --stop-at-setup` writes the
 * environment file, the database, the mail sink and the test clock, and the server's own module then serves them over
 * real HTTP on a free port. Nothing leaves the loopback interface and no mail is sent.
 *
 * **The proxy seam.** [origin] (`http://127.0.0.1:<originPort>`, the instance's identity: its cards, links and kits) is
 * where the server accepts connections ([listenAddress]), through a [Relay] held from construction. A test stands a
 * proxy in front of the server with [interpose] (the proxy binds port 0 and forwards to [serverAddress]); a device can
 * also be made to dial another address: `device(dial = …)` sends every request there and checks everything against
 * [origin], its `Host` header naming the dial address ([Redirect]).
 */
class TestServer(
    kind: String = "private",
    mode: String? = null,
    extraSetup: List<String> = emptyList(),
    extraEnv: Map<String, String> = emptyMap(),
    /**
     * The tool for `andvari setup --test --cli <cli>` to the end (design §9.5 FI-B9): setup enrols its test operator with
     * it and mints the enrol links, and [setup] then holds `card0Hash`, `operatorFile` and `enrolLinks`. Null: setup
     * stops at the setup link (`--stop-at-setup`), which needs no tool, and the test enrols the operator itself.
     */
    cli: String? = null,
    /**
     * The server's mail transport as this test wants it, given the one its configuration made (the sink): a test of the
     * fixtures' own waiting puts a slow sink here. Applied before the server starts, and again at every [restart].
     */
    private val mailTransport: (io.silencelen.andvari.server.MailTransport?) -> io.silencelen.andvari.server.MailTransport? = { it },
) : AutoCloseable {
    val dir: File = Files.createTempDirectory("andvari-e2e").toFile()

    /**
     * Where the server accepts connections: a [Relay] bound to port 0 here and held until [close], in front of the
     * server's own listener (which binds port 0 too, at every start, [serverPort]). No port of this server is picked first
     * and bound later, so another process on the machine cannot take one in between. With [cli], `andvari setup --test
     * --cli` serves its temporary instance (the one the tool enrols the operator through) on a port of its own that it
     * binds as port 0, and routes this relay to it while it runs ([io.silencelen.andvari.server.SetupRelay]).
     */
    private val listener: Relay = Relay()

    /** The port the server accepts connections on, [origin]'s port: the [listener]'s. */
    val port: Int = listener.port

    /** The port of [origin]: what every card, link and kit names. It is [port]. */
    val originPort: Int get() = port

    /** Where the server accepts connections: [origin]'s own address. */
    val listenAddress: String get() = "http://127.0.0.1:$port"

    /** The port the server's own listener bound at its latest start; [listener] relays to it. */
    @Volatile var serverPort: Int = 0
        private set

    /** The server's own listener, behind [listener] and any [interpose]d proxy: where such a proxy forwards to. */
    val serverAddress: String get() = "http://127.0.0.1:$serverPort"

    /**
     * Put a proxy listening on the loopback port [proxyPort] (bound to port 0 by the test) in front of the server: every
     * connection to [port] goes to it, and it forwards to [serverAddress]. Null puts the server back.
     */
    fun interpose(proxyPort: Int?) {
        listener.target = proxyPort ?: serverPort
        interposed = proxyPort
    }

    @Volatile private var interposed: Int? = null
    val envFile = File(dir, "andvari.env")
    val setup: JsonObject
    val origin: String
    val setupLink: String
    private val clockFile: File

    /** The test clock as this fixture last wrote it; read from its file once, at setup (declared before `init`, which sets it). */
    @Volatile private var clockMs: Long = 0L

    /** The directory the server's mail sink writes each message to, as one JSON file. */
    val mailSinkDir: File
    var services: Services
        private set
    private var engine: EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration>

    init {
        val out = ByteArrayOutputStream()
        val args = listOf("setup", "--test") + (if (cli == null) listOf("--stop-at-setup") else listOf("--cli", cli)) +
            listOf("--port", originPort.toString(), "--env-file", envFile.path, "--kind", kind) + (mode?.let { listOf("--mode", it) } ?: emptyList()) + extraSetup
        val rc = HostCli.run(args, PrintStream(out), io.silencelen.andvari.server.CliRunner.PROCESS, io.silencelen.andvari.server.SetupRelay { listener.target = it }) { null }
        check(rc == 0) { "andvari setup --test exited $rc" }
        setup = Json.parseToJsonElement(out.toString().trim().lines().last()).jsonObject
        origin = setup.getValue("origin").jsonPrimitive.content
        setupLink = setup.getValue("setupLink").jsonPrimitive.content
        clockFile = File(setup.getValue("clockFile").jsonPrimitive.content)
        clockMs = clockFile.readText().trim().toLong()
        mailSinkDir = File(setup.getValue("mailSink").jsonPrimitive.content)
        HostCli.editEnvFile(envFile, mapOf("ANDVARI_PORT" to port.toString()) + extraEnv)
        services = configured(buildServices(HostCli.configFrom(envFile)))
        engine = start(services)
    }

    /**
     * [sv] as this fixture runs it: the mail transport the test asked for ([mailTransport]), and none of the server's own
     * background workers. The fixture is the server's only mail sender ([mailWorker], and [advance]), as the server's own
     * tests drive it: two passes of the outbox at once (the server's worker and a test's) could each send the same message,
     * and a copy that lands late passes for the next one. The janitor and the attachment collector, which start only
     * minutes after boot on wall-clock time, do not run in the middle of a test either.
     */
    private fun configured(sv: Services): Services = sv.also {
        it.mailTransport = mailTransport(it.mailTransport)
        it.backgroundWorkers = false
    }

    /** Held around every pass of the outbox and around the swap of [services] at [restart]: one pass at a time. */
    private val mailLock = Any()
    @Volatile private var closed = false

    /** The last failure of a pass of the outbox, shown by [mailSinkText]; a pass that fails is tried again. */
    @Volatile var mailFailure: Throwable? = null
        private set

    /** One pass of the outbox: what is due goes to the sink, what expired is discarded. */
    private fun drainMail() = synchronized(mailLock) {
        if (!closed) runCatching { services.mail.drain() }.onFailure { mailFailure = it }
    }

    /**
     * The sender worker in the server's place: a pass of the outbox every [MAIL_PASS_MS] (the server's own runs every 15
     * seconds). A mail still comes after the request that queued it, so a test waits for it ([Steps.awaitMail]).
     */
    private val mailWorker = Thread {
        while (!closed) {
            drainMail()
            try { Thread.sleep(MAIL_PASS_MS) } catch (e: InterruptedException) { break }
        }
    }.apply { isDaemon = true; name = "test-server-mail" }

    // After the server is up (the init block above) and the worker is built (the declarations just above).
    init { mailWorker.start() }

    /** Start the server on port 0 and point [listener] at the port it bound (unless a proxy is [interpose]d). */
    private fun start(sv: Services): EmbeddedServer<NettyApplicationEngine, NettyApplicationEngine.Configuration> {
        val e = embeddedServer(Netty, configure = { connector { host = "127.0.0.1"; this.port = 0 } }) { andvariModule(sv) }.also { it.start(wait = false) }
        serverPort = kotlinx.coroutines.runBlocking { e.engine.resolvedConnectors().first().port }
        listener.target = interposed ?: serverPort
        return e
    }

    /** Edit the environment file and restart on the same database and port, as `andvari admin signup …` does. */
    fun restart(env: Map<String, String>) {
        engine.stop(100, 1000)
        synchronized(mailLock) {
            services.close()
            HostCli.editEnvFile(envFile, env)
            services = configured(buildServices(HostCli.configFrom(envFile)))
        }
        engine = start(services)
    }

    /**
     * Run `recovery-cli <args>` in its own JVM, as the operator runs it offline, with [stdin] typed in; its stdout. The
     * recovery seed reaches it only on stdin, never on the command line.
     */
    fun recoveryCli(args: List<String>, stdin: String): String {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val p = ProcessBuilder(listOf(java, "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.recovery.MainKt") + args)
            .redirectErrorStream(false).start()
        p.outputStream.use { it.write(stdin.toByteArray()) }
        val out = p.inputStream.bufferedReader().readText()
        val err = p.errorStream.bufferedReader().readText()
        check(p.waitFor() == 0) { "recovery-cli ${args.firstOrNull()} exited ${p.exitValue()}: $err\n$out" }
        return out
    }

    /** The server's test clock, which the devices share. Read from memory: the file is the server's copy. */
    fun now(): Long = clockMs

    /**
     * Move the test clock on by [ms]. The new value is written to a file beside the clock's and moved over it in one
     * step, so the server (which re-reads the file when its modification time changes) never reads a file half written:
     * a read of an empty or partial clock file falls back to the wall clock there.
     */
    @Synchronized fun advance(ms: Long) {
        val next = clockMs + ms
        val fresh = File(clockFile.parentFile, clockFile.name + ".next")
        fresh.writeText(next.toString())
        // The server re-reads the file when its modification time changes; make sure it does.
        fresh.setLastModified(System.currentTimeMillis() + (++bumps))
        Files.move(fresh.toPath(), clockFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        clockMs = next
        // The sender worker runs on wall-clock time; one pass now discards what the jump expired, so the outbox does
        // not read as stalled (spec 03 §14.5) merely because the test moved time faster than the worker runs. It is a
        // pass of the fixture's own worker, so it never runs beside another.
        drainMail()
    }
    private var bumps = 0L

    /** `andvari admin <args>` against this server's environment file: its stdout, or a failure with its exit code. */
    fun admin(vararg args: String): String {
        // `andvari admin` opens the database on a connection of its own beside the running server's. On a busy machine the
        // server can hold the write lock longer than SQLite's busy timeout (5 s); the command then fails whole, its
        // transaction rolled back, and is run again, within the fixtures' bound. No pass of the outbox runs meanwhile.
        var busy: Throwable? = null
        return Await.until("andvari admin ${args.joinToString(" ")} to find the database free", there = { "the database stayed locked: $busy" }) {
            val out = ByteArrayOutputStream()
            val rc = try {
                synchronized(mailLock) { HostCli.run(listOf("admin") + args + listOf("--env-file", envFile.path), PrintStream(out)) { null } }
            } catch (e: Exception) {
                if (!databaseBusy(e)) throw e
                busy = e
                return@until null
            }
            check(rc == 0) { "andvari admin ${args.joinToString(" ")} exited $rc: $out" }
            out.toString()
        }
    }

    /** True when [e] (or a cause) is SQLite's "database is locked": another connection held the write lock too long. */
    private fun databaseBusy(e: Throwable): Boolean =
        generateSequence(e) { it.cause }.take(10).any { it.message.orEmpty().contains("SQLITE_BUSY") || it.message.orEmpty().contains("database is locked") }

    /** The mail sink's files, oldest first, each read as a message or as null while the server is still writing it. */
    private fun sinkFiles(): List<Pair<File, JsonObject?>> =
        (mailSinkDir.listFiles()?.filter { it.name.endsWith(".json") }?.sortedBy { it.name } ?: emptyList()).map { f ->
            f to runCatching { Json.parseToJsonElement(f.readText()).jsonObject }.getOrNull()
        }

    /**
     * The mail sink's messages, oldest first, as they stand now. The server's sink writes each message to its file in
     * place, so a file it is still writing (empty, or half a message) is not a message yet and is left out; a waiting
     * test finds it on a later look ([Steps.awaitMail]).
     */
    fun mail(): List<JsonObject> = sinkFiles().mapNotNull { it.second }

    /**
     * The mail sink's messages once the server has handed it every message queued so far ([queuedMail] is none): what a
     * test that checks a property of ALL mail sent (none carries the password, say) reads, so that a mail still on its
     * way is not missed. Waits at most [timeoutMs].
     */
    fun settledMail(timeoutMs: Long = Await.DEFAULT_MS): List<JsonObject> {
        Await.until("the server's outbox to hand every queued mail to the sink", timeoutMs, ::mailSinkText) { if (queuedMail() == 0L) Unit else null }
        return mail()
    }

    /** The sink as a failure message shows it: each message's template and recipient, and the files not yet whole. */
    fun mailSinkText(): String {
        val files = sinkFiles()
        val whole = files.mapNotNull { it.second }.map { "${it["template"]?.jsonPrimitive?.content} to ${it["to"]?.jsonPrimitive?.content}" }
        val partial = files.filter { it.second == null }.map { it.first.name }
        return "${whole.size} message(s) in the sink" + (if (whole.isEmpty()) "" else ": " + whole.joinToString(", ")) +
            (if (partial.isEmpty()) "" else "; ${partial.size} file(s) not yet whole: " + partial.joinToString(", ")) +
            "; ${queuedMail()} message(s) still queued in the server's outbox" +
            (mailFailure?.let { "; the last pass of the outbox failed: $it" } ?: "")
    }

    /**
     * The messages the server has queued and not yet handed to its sink ([to] and [template] narrow it). A message is
     * queued in the same transaction as the request that caused it, and leaves the outbox only once the sink has written
     * it whole (or it expired unsent), so none queued here means everything caused so far is in [mail] already.
     */
    fun queuedMail(to: String? = null, template: String? = null): Long = services.db.read { c ->
        c.queryOne(
            "SELECT COUNT(*) FROM mail_outbox WHERE (? IS NULL OR recipient=?) AND (? IS NULL OR template=?)", to, to, template, template,
        ) { it.getLong(1) }
    } ?: 0L

    /** Every exchange of every device, for the failure messages: method, path, status and the start of the body. */
    val trail: MutableList<String> = java.util.Collections.synchronizedList(ArrayList())

    private val trailPlugin = io.ktor.client.plugins.api.createClientPlugin("trail") {
        onResponse { r -> trail += "${r.call.request.method.value} ${r.call.request.url.encodedPath} -> ${r.status.value}" }
    }

    private val clients = HashMap<String, io.ktor.client.HttpClient>()

    /**
     * The HTTP client of devices that send to [dial] (default [listenAddress]). When [dial] is the origin itself the
     * client dials it directly; otherwise every request goes to [dial] ([Redirect], whose `Host` header names [dial]),
     * which is how a proxy on another port sits between the engine and the server.
     */
    fun httpFor(dial: String = listenAddress): io.ktor.client.HttpClient = synchronized(clients) {
        clients.getOrPut(dial) {
            if (dial == origin) {
                io.ktor.client.HttpClient(io.ktor.client.engine.java.Java) {
                    install(io.ktor.client.plugins.HttpTimeout) { requestTimeoutMillis = 60_000 }
                    expectSuccess = false
                    install(trailPlugin)
                }
            } else {
                Redirect.client(origin, dial) { install(trailPlugin) }
            }
        }
    }

    /**
     * A fresh device: its own device state and secure store, the server's clock. [dial] is the address its requests go
     * to (default: where the server listens); every check uses [origin].
     */
    fun device(name: String = "cli", dial: String = listenAddress): Host =
        Host(MemoryDeviceState(), MemoryDeviceState(), ::now, http = httpFor(dial), deviceName = name)

    /** The names of the [switchedDevice]s whose network is gone right now: every request of theirs fails to send. */
    val cut: MutableSet<String> = java.util.Collections.synchronizedSet(HashSet())

    /**
     * A device whose network a test can cut ([cut]), with a durable offline cache in SQLite files under [dir], one per
     * origin and account: what a phone has. A second [io.silencelen.andvari.cli.AccountSession] over the same [Host]
     * finds the cache again, as a restarted app does.
     */
    fun switchedDevice(name: String): Host {
        val http = io.ktor.client.HttpClient(io.ktor.client.engine.java.Java) {
            install(io.ktor.client.plugins.HttpTimeout) { requestTimeoutMillis = 60_000 }
            expectSuccess = false
            install(trailPlugin)
            install(io.ktor.client.plugins.api.createClientPlugin("cut") { onRequest { _, _ -> if (name in cut) throw java.io.IOException("offline") } })
        }
        synchronized(clients) { clients["switched:$name"] = http }
        val host = Host(MemoryDeviceState(), MemoryDeviceState(), ::now, http = http, deviceName = name)
        val caches = File(dir, "cache-$name").apply { mkdirs() }
        host.itemCache = { h ->
            io.silencelen.andvari.core.client.sqliteVaultCache(
                File(caches, io.silencelen.andvari.core.client.items.ItemCacheNames.fileName(host.crypto, h.origin, h.userId)).path, h.userId,
            )
        }
        return host
    }

    fun trailText(): String = synchronized(trail) { trail.takeLast(40).joinToString("\n") }

    /** Run a journey; a failure carries the last exchanges. */
    fun <T> journey(block: suspend TestServer.() -> T): T = kotlinx.coroutines.runBlocking {
        try {
            block()
        } catch (e: Throwable) {
            throw AssertionError("${e.message}\n--- last exchanges:\n${trailText()}", e)
        }
    }

    override fun close() {
        synchronized(mailLock) { closed = true }
        mailWorker.interrupt()
        listener.close()
        engine.stop(100, 1000)
        services.close()
        synchronized(clients) { clients.values.forEach { it.close() } }
        dir.deleteRecursively()
    }

    companion object {
        /** How often the fixture's sender worker passes over the outbox ([mailWorker]). */
        const val MAIL_PASS_MS = 250L
    }
}
