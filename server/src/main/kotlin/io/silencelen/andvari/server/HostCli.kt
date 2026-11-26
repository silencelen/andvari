package io.silencelen.andvari.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceKind
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.WireGrammar
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.io.File
import java.io.PrintStream

/**
 * For an in-process caller of `andvari setup --test` that holds the origin's port itself, bound and listening, and
 * relays what arrives there (the CLI's end-to-end fixture). Setup then serves its temporary instance, the one the tool
 * enrols the operator through, on a port of its own that it binds as port 0, and calls [route] with that port once it
 * is listening and with 0 before it stops. No port is picked first and bound later, so another process cannot take it
 * in between. Without a relay, setup binds the origin's port itself, as a command-line run must: the port is in the
 * origin that card 0 and every link name, so it is chosen before any server runs.
 */
fun interface SetupRelay {
    fun route(port: Int)
}

/** How `andvari setup --test` runs `andvari-cli`: a child process ([PROCESS]); a test substitutes its own. */
fun interface CliRunner {
    class Ran(val code: Int, val out: String, val err: String)

    /** Run [command] with [stdin] on its standard input and nothing else (no terminal), and wait for it. */
    fun run(command: List<String>, stdin: String): Ran

    companion object {
        const val TIMEOUT_MINUTES = 5L

        val PROCESS = CliRunner { command, stdin ->
            val tmp = java.nio.file.Files.createTempDirectory("andvari-setup-cli").toFile()
            try {
                val out = File(tmp, "out")
                val err = File(tmp, "err")
                val p = ProcessBuilder(command).redirectOutput(out).redirectError(err).start()
                // A tool that exits before reading its input closes the pipe; its exit code says why.
                runCatching { p.outputStream.use { it.write(stdin.encodeToByteArray()) } }
                if (!p.waitFor(TIMEOUT_MINUTES, java.util.concurrent.TimeUnit.MINUTES)) {
                    p.destroyForcibly().waitFor()
                    Ran(124, out.readText(), err.readText() + "\n(stopped after $TIMEOUT_MINUTES minutes)")
                } else {
                    Ran(p.exitValue(), out.readText(), err.readText())
                }
            } finally {
                tmp.deleteRecursively()
            }
        }
    }
}

/**
 * `andvari setup` and `andvari admin` (spec 03 §7.4, §17.5; design §9.5): host commands with access to the
 * database and the environment file. They reach no HTTP route and are server-trusted by nature (the host
 * is T1). Both run from the server image (`docker run … andvari setup …`).
 *
 * Exit codes: 0 done; 1 refused (the message says why); 2 usage.
 */
object HostCli {
    class Refused(message: String) : Exception(message)
    class Usage(message: String) : Exception(message)

    /** Parsed `--flag value` / `--switch` arguments. */
    class Args(val argv: List<String>) {
        val flags = HashMap<String, String>()
        val switches = HashSet<String>()
        val positional = ArrayList<String>()

        init {
            var i = 0
            while (i < argv.size) {
                val a = argv[i]
                if (a.startsWith("--")) {
                    val eq = a.indexOf('=')
                    when {
                        eq > 0 -> flags[a.substring(2, eq)] = a.substring(eq + 1)
                        i + 1 < argv.size && !argv[i + 1].startsWith("--") && a.substring(2) !in SWITCHES -> { flags[a.substring(2)] = argv[i + 1]; i++ }
                        else -> switches += a.substring(2)
                    }
                } else positional += a
                i++
            }
        }

        fun opt(name: String): String? = flags[name]
        fun has(name: String): Boolean = name in switches
    }

    private val SWITCHES = setOf("test", "stop-at-setup", "status", "reset-setup", "age-confirm", "qr", "yes", "json", "help")

    /** The mail transport's settings: `--<flag>` on the command line, else `ANDVARI_<FLAG>` from the environment. */
    private val MAIL_FLAGS = listOf("graph-tenant", "graph-client-id", "graph-client-secret", "graph-sender", "smtp-host", "smtp-port", "smtp-user", "smtp-pass", "smtp-from")

    /** Setup's flags whose values it writes into `andvari.env`, as they are or as a path built from them. */
    private val WRITTEN_FLAGS = listOf("origin", "port", "kind", "mode", "name", "cap", "register-links", "recovery-pubkey", "data-dir", "db") + MAIL_FLAGS

    /**
     * Setup writes `ANDVARI_STRICT_ENV=1`, so it never writes a value the strict start would refuse (decided on
     * 22 November 2026): a flag of [WRITTEN_FLAGS] that is blank (a number, a switch or a choice left blank stops the
     * strict start), or that holds a line break (the rest would be a line of its own in the file), is refused before
     * anything is written, and so is a mail setting from the environment that holds a line break (a blank one is not
     * taken). A secret read from a file is its first line only.
     */
    private fun refuseValuesTheFileCannotHold(a: Args, env: (String) -> String?) {
        val nothing = "Nothing was created or changed."
        for (flag in WRITTEN_FLAGS) {
            val v = a.opt(flag) ?: continue
            if (v.isBlank()) throw Refused("--$flag is blank: give it a value, or leave the flag out. $nothing")
            if ('\n' in v || '\r' in v) throw Refused("--$flag holds a line break, which andvari.env cannot hold. $nothing")
        }
        for (k in MAIL_FLAGS) {
            val key = "ANDVARI_" + k.uppercase().replace('-', '_')
            if (a.opt(k) != null || a.opt("$k-file") != null) continue
            val v = env(key)?.takeIf { it.isNotBlank() } ?: continue
            if ('\n' in v || '\r' in v) throw Refused("$key in the environment holds a line break, which andvari.env cannot hold. $nothing")
        }
    }

    /** The two mail secrets, which may also come from a file (`--<flag>-file <path>`, first line). */
    private val MAIL_SECRETS = setOf("graph-client-secret", "smtp-pass")

    val SETUP_HELP = """
        |usage: andvari setup --origin https://your.domain [options]
        |       andvari setup --status | --reset-setup   [--env-file andvari.env]
        |
        |  --origin URL            the instance's https origin (required outside --test)
        |  --kind public|private   default private
        |  --mode open|links|closed  how people join (default links)
        |  --name TEXT             the instance's name (default andvari)
        |  --cap N                 the sign-up cap; --age-confirm to require the age confirmation
        |  --register-links ...    see the self-hosting guide
        |  --recovery-pubkey KEY   operator recovery (private instances with mail only)
        |  --env-file PATH         where to write andvari.env (default ./andvari.env, created mode 0600)
        |  --data-dir DIR, --db PATH
        |  --test [--port N]       a loopback test instance (test mode, mail sink, test clock); it enrols a test
        |                          operator with andvari-cli (--cli PATH or ANDVARI_CLI, else andvari-cli on the
        |                          PATH) and mints --enrol N enrol links (default 1); --stop-at-setup stops after
        |                          the setup link instead
        |
        |Mail (Microsoft Graph or SMTP): --graph-tenant, --graph-client-id, --graph-sender, --smtp-host,
        |--smtp-port, --smtp-user, --smtp-from, and the secrets --graph-client-secret / --smtp-pass.
        |Each may instead come from the environment as ANDVARI_<NAME> (ANDVARI_GRAPH_CLIENT_SECRET,
        |ANDVARI_SMTP_PASS, ...), and the two secrets from a file with --graph-client-secret-file PATH /
        |--smtp-pass-file PATH. Prefer the environment or a file for the secrets: command-line arguments are
        |visible to every other user of this host (ps, /proc) and may land in the shell's history.
        """.trimMargin()

    /**
     * [cli] runs `andvari-cli` for `setup --test` (a child process; tests substitute it). [relay] is for an in-process
     * caller that already holds the origin's port (see [SetupRelay]). [env] stays the last parameter, so a caller's
     * trailing lambda is still the environment.
     */
    fun run(
        argv: List<String>, out: PrintStream = System.out, cli: CliRunner = CliRunner.PROCESS, relay: SetupRelay? = null,
        env: (String) -> String? = System::getenv,
    ): Int = try {
        when (argv.firstOrNull()) {
            "setup" -> { setup(Args(argv.drop(1)), out, env, cli, relay); 0 }
            "admin" -> { admin(Args(argv.drop(1)), out, env); 0 }
            else -> throw Usage("usage: andvari setup [options] | andvari admin <command>   (andvari setup --help lists the options)")
        }
    } catch (e: Refused) {
        System.err.println("andvari: ${e.message}")
        1
    } catch (e: Usage) {
        System.err.println(e.message)
        2
    } catch (e: ConfigError) {
        System.err.println("andvari: ${e.message}")
        1
    }

    // =================================================================================================
    // andvari setup
    // =================================================================================================

    /**
     * Write `andvari.env` (refusing to overwrite one), create the database with the instance id, and mint
     * the setup link (spec 03 §17.5). `--status` reports where an earlier setup stopped; `--reset-setup`
     * mints a new setup link, only while no operator account exists. `--test` is the non-interactive form
     * the test scripts use (design §9.5): loopback origin, test mode, mail sink and test clock, mode `open`,
     * and one JSON object on stdout. Without `--stop-at-setup` it then finishes setup headlessly
     * ([enrolTestOperator]) and the JSON also carries `card0Hash`, `operatorFile` and the enrol links.
     */
    private fun setup(a: Args, out: PrintStream, env: (String) -> String?, cli: CliRunner, relay: SetupRelay?) {
        if (a.has("help")) { out.println(SETUP_HELP); return }
        val envFile = File(a.opt("env-file") ?: env("ANDVARI_ENV_FILE") ?: "andvari.env")
        if (a.has("status")) return setupStatus(envFile, out)
        if (a.has("reset-setup")) return resetSetup(envFile, out)

        if (envFile.exists()) throw Refused("${envFile.path} already exists; setup never overwrites it (use --status or --reset-setup)")
        refuseValuesTheFileCannotHold(a, env)
        val crypto = createCryptoProvider()
        val test = a.has("test")
        val origin = a.opt("origin") ?: if (test) "http://127.0.0.1:${a.opt("port") ?: "8080"}" else throw Usage("--origin https://your.domain is required")
        if (!WireGrammar.isOrigin(origin)) throw Refused("andvari needs an https address with a domain name for this server.")
        val kind = a.opt("kind") ?: InstanceKind.PRIVATE
        if (kind != InstanceKind.PUBLIC && kind != InstanceKind.PRIVATE) throw Usage("--kind public|private")
        val mode = a.opt("mode") ?: if (test) SignupMode.OPEN else SignupMode.LINKS
        if (mode !in setOf(SignupMode.OPEN, SignupMode.LINKS, SignupMode.CLOSED)) throw Usage("--mode open|links|closed")
        val name = a.opt("name") ?: "andvari"
        val nameB64 = Grammar.nameOf(name) ?: throw Refused("the instance name must be 1-64 bytes of plain text")
        val dataDir = File(a.opt("data-dir") ?: if (test) envFile.absoluteFile.parentFile.resolve("data").path else "/data")
        val dbPath = a.opt("db") ?: File(dataDir, "andvari.db").path
        // Never over an existing instance, checked before anything is written: a database that already holds
        // anything is refused with a sentence (it used to fail later, on the instance row, as a stack trace),
        // and a test instance is made only in a new or empty data directory, so it never writes its clock,
        // mail sink or blobs into a live one (or points its blob directory at a live instance's blobs).
        File(dbPath).let { db ->
            if (db.exists() && (!db.isFile || db.length() > 0)) throw Refused("${db.path} already exists; setup never writes over an existing instance")
            // No new database beside the leftover files of another one (a write-ahead file, its `-shm`, a journal), looked
            // for beside the file the path stands for, links followed, as SQLite would: refused before anything is created.
            val real = Db.resolved(db) ?: throw Refused("${db.path} could not be followed to a file (${Db.UNRESOLVED_LINKS}): $SETUP_MAKES_THE_DATABASE")
            val found = RestoredStart.LEFTOVERS.filter { File(real.path + it).exists() }.map { real.name + it }
            if (found.isNotEmpty()) throw Refused(setupBesideLeftovers(real.absoluteFile.parentFile.canonicalPath, found))
            // A link whose target does not exist: setup never creates a file or a folder where a link leads.
            if (java.nio.file.Files.isSymbolicLink(db.toPath()) && !db.exists()) {
                throw Refused("${db.path} is a link to ${real.path}, which does not exist: $SETUP_MAKES_THE_DATABASE")
            }
        }
        if (test && dataDir.exists() && dataDir.list()?.isEmpty() != true) {
            throw Refused("${dataDir.path} is not an empty directory; a test instance is made in a new data directory (pass another --data-dir)")
        }

        val lines = LinkedHashMap<String, String>()
        lines["ANDVARI_CANONICAL_ORIGIN"] = origin
        lines["ANDVARI_INSTANCE_KIND"] = kind
        lines["ANDVARI_INSTANCE_NAME"] = name
        lines["ANDVARI_SIGNUP_MODE"] = mode
        a.opt("cap")?.let { lines["ANDVARI_SIGNUP_CAP"] = it.toLongOrNull()?.toString() ?: throw Usage("--cap <n>") }
        if (a.has("age-confirm") || kind == InstanceKind.PUBLIC) lines["ANDVARI_REQUIRE_AGE_CONFIRM"] = "1"
        a.opt("register-links")?.let { lines["ANDVARI_REGISTER_LINKS"] = it }
        lines["ANDVARI_ENUM_SECRET"] = Bytes.toB64(crypto.randomBytes(32))
        lines["ANDVARI_SIGNUP_SECRET"] = Bytes.toB64(crypto.randomBytes(32))
        lines["ANDVARI_DB"] = dbPath
        lines["ANDVARI_BLOB_DIR"] = File(dataDir, "blobs").path
        if (origin.startsWith("https://")) lines["ANDVARI_FORCE_HSTS"] = "1"
        // A mistyped name in the settings file stops the start instead of leaving that setting at its default
        // (decided on 22 November 2026). Not for a test instance: the test harnesses start servers on its settings file
        // with names of their own.
        if (!test) lines["ANDVARI_STRICT_ENV"] = "1"
        // Step 4 (design §9.5): operator recovery only on a private instance with mail; under variant R
        // never with --kind public. The key itself comes from `recovery-cli keygen` run offline.
        a.opt("recovery-pubkey")?.let { pub ->
            if (kind == InstanceKind.PUBLIC) throw Refused("a public instance has no operator recovery")
            val key = runCatching { Bytes.fromB64(pub) }.getOrNull()?.takeIf { it.size == 32 } ?: throw Refused("--recovery-pubkey must be a 32-byte key in base64url")
            lines["ANDVARI_RECOVERY_PUBKEY"] = pub
            lines["ANDVARI_RECOVERY_FINGERPRINT"] = sha256Hex(key)
        }
        for (k in MAIL_FLAGS) {
            val key = "ANDVARI_" + k.uppercase().replace('-', '_')
            val fromFile = if (k in MAIL_SECRETS) a.opt("$k-file")?.let { path ->
                val f = File(path)
                if (!f.isFile) throw Refused("--$k-file: $path is not a readable file")
                f.readLines().firstOrNull()?.trim()?.takeIf { it.isNotEmpty() } ?: throw Refused("--$k-file: $path is empty")
            } else null
            (a.opt(k) ?: fromFile ?: env(key)?.takeIf { it.isNotBlank() })?.let { lines[key] = it }
        }
        // `--test` without `--stop-at-setup` finishes setup headlessly (design §9.5, FI-B9): everything it needs
        // is checked here, before anything is written, so a missing tool leaves no half-made instance.
        val headless = if (test && !a.has("stop-at-setup")) {
            val spec = a.opt("cli") ?: env("ANDVARI_CLI")?.takeIf { it.isNotBlank() } ?: "andvari-cli"
            val tool = locateCli(spec, env)
                ?: throw Refused("andvari setup --test needs andvari-cli to enrol the test operator: pass --cli PATH or set ANDVARI_CLI, or use --stop-at-setup")
            val count = a.opt("enrol")?.let { n -> n.toIntOrNull()?.takeIf { it in 1..100 } ?: throw Usage("--enrol <n>, 1 to 100") } ?: 1
            if (File(dataDir, TEST_OPERATOR_DIR).exists()) throw Refused("${File(dataDir, TEST_OPERATOR_DIR).path} already exists; a test instance is rebuilt from scratch")
            Headless(tool.path, count, cli, relay)
        } else null
        if (test) lines["ANDVARI_PORT"] = testPort(origin).toString()
        val sinkDir: File? = if (test) File(dataDir, "mail-sink") else null
        val clockFile: File? = if (test) File(dataDir, "clock") else null
        if (test) {
            lines["ANDVARI_TEST_MODE"] = "1"
            lines["ANDVARI_MAIL_SINK"] = sinkDir!!.path
            lines["ANDVARI_TEST_CLOCK"] = clockFile!!.path
        }
        // Every boot rule is checked before anything is written (`--test` with an https origin used to leave a
        // clock and a mail sink behind before it was refused).
        val config = Config.fromEnv { lines[it] }
        if (config.recoveryConfigured && !config.mailConfigured) throw Refused("operator recovery needs mail (the assisted-recovery code is emailed)")

        // Owner-only modes whatever the umask. A data directory setup creates is 0700 and the
        // database it creates 0600 (SQLite gives its -wal and -shm files the database file's mode).
        createPrivateDirs(dataDir)
        if (test) {
            sinkDir!!.mkdirs()
            clockFile!!.writeText(System.currentTimeMillis().toString())
        }
        dataDir.mkdirs()

        val setup = InstanceSetupRow(uuid(), nameB64)
        createPrivateDbFile(File(dbPath))
        val minted = onDatabase(dbPath) {
            Db(dbPath).use { db ->
                db.tx { c ->
                    c.exec("INSERT INTO instance_setup(id,instanceId,name) VALUES(1,?,?)", setup.instanceId, setup.name)
                    HostLinks.mintSetup(c, config, setup, (clockFile?.let { FileClock(it) } ?: Clock.SYSTEM).now())
                }
            }
        }
        envFile.absoluteFile.parentFile?.mkdirs()
        writePrivateFile(envFile, lines.entries.joinToString("\n", postfix = "\n") { "${it.key}=${it.value}" })

        if (test) {
            val finished = headless?.let { h -> enrolTestOperator(h, envFile, dataDir, origin, setup.instanceId, minted.url) }
            val obj = buildJsonObject {
                put("origin", JsonPrimitive(origin))
                put("instanceId", JsonPrimitive(setup.instanceId))
                put("setupLink", JsonPrimitive(minted.url))
                finished?.let { put("card0Hash", JsonPrimitive(it.card0Hash)) }
                finished?.let { put("operatorFile", JsonPrimitive(it.operatorFile.path)) }
                put("enrolLinks", JsonArray(finished?.enrolLinks.orEmpty().map { JsonPrimitive(it) }))
                put("mailSink", JsonPrimitive(sinkDir!!.path))
                put("clockFile", JsonPrimitive(clockFile!!.path))
                put("envFile", JsonPrimitive(envFile.path))
            }
            out.println(obj.toString())
            return
        }
        out.println("Wrote ${envFile.path}. Instance id ${setup.instanceId}.")
        out.println()
        out.println("Setup link (works once, expires in 24 hours):")
        out.println("  ${minted.url}")
        out.println()
        out.println("Open this in the andvari desktop app on the computer that will hold this server's operator account.")
        out.println("Not in an app you use for your everyday account: an app holds one account per server. Whoever uses it")
        out.println("first becomes the operator.")
        out.println()
        out.println("Then start the server, and once card 0 is signed run `andvari admin enrol-link --email <you>` for your everyday account.")
    }

    /** Under the data directory: the test operator's device home, password, kit and `operator.json`. */
    const val TEST_OPERATOR_DIR = "test-operator"
    const val TEST_OPERATOR_EMAIL = "operator@example.org"

    private class Headless(val cli: String, val enrolCount: Int, val runner: CliRunner, val relay: SetupRelay?)

    private class Finished(val card0Hash: String, val operatorFile: File, val enrolLinks: List<String>)

    /** [spec] as a path (it contains a `/`), else the first executable of that name on `PATH`. */
    internal fun locateCli(spec: String, env: (String) -> String?): File? {
        if ('/' in spec) return File(spec).takeIf { it.isFile && it.canExecute() }
        return env("PATH").orEmpty().split(File.pathSeparator).filter { it.isNotEmpty() }
            .map { File(it, spec) }.firstOrNull { it.isFile && it.canExecute() }
    }

    /** The port the test server listens on: the origin's own. */
    private fun testPort(origin: String): Int = java.net.URI(origin).let { u -> u.port.takeIf { it > 0 } ?: if (u.scheme == "https") 443 else 80 }

    /**
     * The headless end of `setup --test` (design §9.5, FI-B9). The server is started in memory on the origin
     * over the files just written; `andvari-cli operator enrol` runs as a child process with the setup link
     * on its standard input and the password in an owner-only file, so neither is in the process list; it
     * registers the test operator and signs card 0. `andvari-cli card show` reads card 0 back, and its hash
     * must equal the one the server stored. Only then are the enrol links minted (FI-B9). `operator.json`
     * (owner-only) names the operator's files. The server is stopped whatever happens; its log lines go to
     * standard error, so standard output stays the one JSON object.
     */
    private fun enrolTestOperator(h: Headless, envFile: File, dataDir: File, origin: String, instanceId: String, setupLink: String): Finished {
        val dir = File(dataDir, TEST_OPERATOR_DIR)
        createPrivateDirs(dir)
        val home = File(dir, "home")
        val kit = File(dir, "kit.txt")
        val passwordFile = File(dir, "password")
        writePrivateFile(passwordFile, Bytes.toB64(createCryptoProvider().randomBytes(32)) + "\n")
        val rebuild = "A test instance is rebuilt from scratch: delete ${envFile.path} and ${dataDir.path}, then run setup again."

        val config = configFrom(envFile)
        val stdout = System.out
        System.setOut(System.err)
        val services = buildServices(config)
        try {
            // With a relay the caller holds the origin's port; this server binds a port of its own (0) behind it.
            val bind = if (h.relay != null) 0 else config.port
            val server = embeddedServer(Netty, configure = { connector { host = "127.0.0.1"; port = bind } }) { andvariModule(services) }
            server.start(wait = false)
            try {
                h.relay?.route(kotlinx.coroutines.runBlocking { server.engine.resolvedConnectors().first().port })
                val enrol = h.runner.run(
                    listOf(h.cli, "--home", home.path, "operator", "enrol", "-", "--email", TEST_OPERATOR_EMAIL, "--name", "operator",
                        "--kit-out", kit.path, "--password-file", passwordFile.path),
                    setupLink + "\n",
                )
                if (enrol.code != 0) throw Refused("andvari-cli operator enrol failed (exit ${enrol.code}): ${enrol.err.trim().ifEmpty { enrol.out.trim() }}\n$rebuild")
                val shown = h.runner.run(listOf(h.cli, "--home", home.path, "card", "show"), "")
                if (shown.code != 0) throw Refused("andvari-cli card show failed (exit ${shown.code}): ${shown.err.trim().ifEmpty { shown.out.trim() }}\n$rebuild")
                val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(shown.out)?.groupValues?.get(1)
                    ?: throw Refused("andvari-cli card show printed no card0Hash.\n$rebuild")
                val links = services.db.tx { c ->
                    val stored = services.instance.card0Hash(c)
                    if (stored != card0) throw Refused("the card 0 andvari-cli shows ($card0) is not the one the server stored (${stored ?: "none"}).\n$rebuild")
                    (1..h.enrolCount).map { HostLinks.mintEnrol(c, config, instanceId, card0, null, 7 * Clock.DAY_MS, services.clock.now()).url }
                        .also { services.audit.on(c, "enrol_link_mint", null, null, null, "count=${h.enrolCount}") }
                }
                val operatorFile = File(dir, "operator.json")
                writePrivateFile(
                    operatorFile,
                    buildJsonObject {
                        put("origin", JsonPrimitive(origin))
                        put("email", JsonPrimitive(TEST_OPERATOR_EMAIL))
                        put("passwordFile", JsonPrimitive(passwordFile.path))
                        put("cliHome", JsonPrimitive(home.path))
                        put("kitFile", JsonPrimitive(kit.path))
                        put("card0Hash", JsonPrimitive(card0))
                    }.toString() + "\n",
                )
                return Finished(card0, operatorFile, links)
            } finally {
                h.relay?.route(0)
                server.stop(100, 1000)
            }
        } finally {
            services.close()
            System.setOut(stdout)
        }
    }

    private fun setupStatus(envFile: File, out: PrintStream) {
        if (!envFile.exists()) { out.println("not started: no ${envFile.path}"); return }
        val config = configFrom(envFile)
        val line = onDatabase(config.dbPath) {
            Db(config.dbPath).use { db ->
                db.read { c ->
                    val operator = c.queryOne("SELECT userId FROM users WHERE role='operator'") { it.getString(1) }
                    val card0 = c.count("SELECT COUNT(*) FROM instance_cards") > 0
                    val openSetup = c.count("SELECT COUNT(*) FROM links WHERE kind='setup' AND state='open'")
                    when {
                        card0 -> "ready: card 0 is signed"
                        operator != null -> "waiting for card 0: the operator account exists; resume from the operator's app"
                        openSetup > 0 -> "waiting for the operator to open the setup link"
                        else -> "no live setup link: run `andvari setup --reset-setup`"
                    }
                }
            }
        }
        out.println(line)
    }

    private fun resetSetup(envFile: File, out: PrintStream) {
        val config = configFrom(envFile)
        val minted = onDatabase(config.dbPath) {
            Db(config.dbPath).use { db ->
                db.tx { c ->
                    if (c.queryOne("SELECT 1 FROM users WHERE role='operator'") { 1 } != null) throw Refused("an operator account exists; a new setup link is minted only while none does")
                    val setup = c.queryOne("SELECT instanceId,name FROM instance_setup WHERE id=1") { InstanceSetupRow(it.getString(1), it.getString(2)) }
                        ?: throw Refused("the database has no instance; run setup first")
                    HostLinks.mintSetup(c, config, setup, clockFor(config).now())
                }
            }
        }
        out.println(minted.url)
    }

    // =================================================================================================
    // andvari admin
    // =================================================================================================

    private fun admin(a: Args, out: PrintStream, env: (String) -> String?) {
        val envFile = File(a.opt("env-file") ?: env("ANDVARI_ENV_FILE") ?: "andvari.env")
        val cmd = a.positional.firstOrNull() ?: throw Usage(
            "usage: andvari admin status|accounts|disable <email>|enable <email>|signup open|links|close|cap <n>|" +
                "quota --account <email> [--bytes N] [--items N] [--vaults N] [--links N]|enrol-link [--email E] [--expires D] [--count N]|" +
                "setup-link|operator|reset-instance-identity|audit|restored|backup [--keep N]",
        )
        // Reads its own settings and opens the database its own way, and says every failure in one line (ServerBackup).
        if (cmd == "backup") return ServerBackup.command(a, envFile)
        val config = configFrom(envFile)
        val clock = clockFor(config)
        // Before anything opens the database: the command must hold it alone (RestoredStart).
        if (cmd == "restored") return RestoredStart.run(config, clock, out)
        onDatabase(config.dbPath) {
            val services = Services(config, clock, Db(config.dbPath), CoreTrust())
            try {
                AdminCommands(services, envFile, out).run(cmd, a)
            } finally {
                services.close()
            }
        }
    }

    /**
     * [block] on the database at [path], with every failure to open or read it said in plain words (exit 1), never as a
     * stack trace: a database this build must not open ([IncompatibleDatabase], a write-ahead file of another database
     * beside it included) with its own message, and SQLite's errors as what they were.
     */
    private fun <T> onDatabase(path: String, block: () -> T): T = try {
        block()
    } catch (e: IncompatibleDatabase) {
        throw Refused(e.message ?: "this build cannot open the database $path")
    } catch (e: java.sql.SQLException) {
        throw Refused(databaseFailed(path, e))
    }

    /** SQLite's error [e] on the database at [path], said as what it was. */
    internal fun databaseFailed(path: String, e: java.sql.SQLException): String = when (e.errorCode and 0xff) {
        5, 6 -> "the database $path is in use by another process (${e.message}): stop it, then run the command again"
        8 -> "the database $path cannot be written (${e.message}): check the file's and its folder's owner and permissions"
        11 -> "the database $path could not be read (${e.message})"
        14 -> cannotOpen(path, e.message ?: "cannot open")
        26 -> "$path is not an SQLite database (${e.message})"
        else -> "the command failed on the database $path (${e.message})"
    }

    /** The database at [path] could not be opened, for the reason [why]: SQLite's own, or what the guard found before it. */
    fun cannotOpen(path: String, why: String): String =
        "could not open the database $path ($why): check that its folder exists and that its owner and permissions let this user open it"

    /**
     * Setup's refusal when the leftover files [found] of another database lie in the data folder [dir] where it would make
     * the new database: setup never makes an instance beside them (SQLite would apply or drop them), and nothing has been
     * written when this is said.
     */
    fun setupBesideLeftovers(dir: String, found: List<String>): String {
        val files = found.joinToString(" and ")
        val them = if (found.size == 1) "it" else "them"
        return "$files ${if (found.size == 1) "lies" else "lie"} in the data folder $dir. Setup makes a new instance only in a folder " +
            "without $them: move $files out of this folder and keep $them, then run setup again. Nothing was created or changed."
    }

    /**
     * Create [f] (which must not exist) readable and writable by its owner only, from the start: on a POSIX
     * file system the file is created with mode 0600 in one step, so the secrets are never readable by other
     * users of the host, whatever the umask. Elsewhere it is created empty, restricted, and only then written.
     */
    fun writePrivateFile(f: File, text: String) {
        val path = f.toPath()
        val posix = runCatching { java.nio.file.Files.getFileStore(path.toAbsolutePath().parent).supportsFileAttributeView("posix") }.getOrDefault(false)
        if (posix) {
            val perms = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")
            java.nio.file.Files.createFile(path, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(perms))
        } else {
            java.nio.file.Files.createFile(path)
            f.setReadable(false, false); f.setReadable(true, true); f.setWritable(false, false); f.setWritable(true, true)
        }
        java.nio.file.Files.write(path, text.encodeToByteArray(), java.nio.file.StandardOpenOption.TRUNCATE_EXISTING)
    }

    private fun posix(p: java.nio.file.Path): Boolean =
        runCatching { java.nio.file.Files.getFileStore(p).supportsFileAttributeView("posix") }.getOrDefault(false)

    /**
     * Creates [dir] and any missing parents, each it creates set to 0700 with an explicit
     * `setPosixFilePermissions` (not left to the umask). A directory that already exists is left as it is.
     */
    internal fun createPrivateDirs(dir: File) {
        val missing = generateSequence(dir.absoluteFile) { it.parentFile }.takeWhile { !it.exists() }.toList().asReversed()
        for (d in missing) {
            if (!d.mkdir() && !d.isDirectory) throw Refused("cannot create ${d.path}")
            if (posix(d.toPath())) java.nio.file.Files.setPosixFilePermissions(d.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        }
    }

    /** Creates the database file [f] empty with mode 0600, set explicitly, unless it exists already. */
    internal fun createPrivateDbFile(f: File) {
        if (f.exists()) return
        f.absoluteFile.parentFile?.let { createPrivateDirs(it) }
        java.nio.file.Files.createFile(f.toPath())
        if (posix(f.toPath())) java.nio.file.Files.setPosixFilePermissions(f.toPath(), java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
    }

    /** The end of setup's refusal of a database path it makes no database at. */
    private const val SETUP_MAKES_THE_DATABASE =
        "setup makes the database only at a path that is not a link (or a link to an existing empty file). Nothing was created or changed."

    /** Read `andvari.env` (KEY=VALUE lines) over the process environment. */
    fun readEnvFile(f: File): Map<String, String> {
        if (!f.isFile) throw Refused("${f.path} not found (run andvari setup, or pass --env-file)")
        return f.readLines().mapNotNull { line ->
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#") || '=' !in t) null else t.substringBefore('=').trim() to t.substringAfter('=').trim()
        }.toMap()
    }

    fun configFrom(f: File): Config = configFrom(f) { System.err.println(it) }

    /** [configFrom] with the settings' warnings given to [warn] instead of standard error. */
    fun configFrom(f: File, warn: (String) -> Unit): Config {
        val vars = readEnvFile(f)
        return Config.fromEnv({ vars[it] ?: System.getenv(it) }, warn)
    }

    /** Rewrite [keys] in the env file, keeping every other line as it was. */
    fun editEnvFile(f: File, keys: Map<String, String>) {
        val lines = f.readLines().toMutableList()
        val left = keys.toMutableMap()
        for (i in lines.indices) {
            val k = lines[i].substringBefore('=').trim()
            left.remove(k)?.let { lines[i] = "$k=$it" }
        }
        for ((k, v) in left) lines += "$k=$v"
        f.writeText(lines.joinToString("\n", postfix = "\n"))
    }
}
