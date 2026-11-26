package io.silencelen.andvari.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import kotlin.system.exitProcess

/**
 * `andvari` (the server image's one program): no arguments or `server` runs the server; `setup` and
 * `admin` are the host commands of spec 03 §7.4 and design §9.5.
 */
fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        null, "server" -> serve()
        "setup", "admin" -> exitProcess(HostCli.run(args.toList()))
        else -> {
            System.err.println("usage: andvari [server] | andvari setup [options] | andvari admin <command>")
            exitProcess(2)
        }
    }
}

/**
 * What the server prints when it starts. Test mode gets a loud line of its own: it is
 * refused off a loopback http origin, but an operator who left it on must still see it in the log.
 */
internal fun startupLines(config: Config): List<String> = buildList {
    if (config.testMode) {
        add("[andvari] ************************************************************************")
        add("[andvari] TEST MODE IS ON (ANDVARI_TEST_MODE=1): for automated tests only, never for real accounts.")
        config.mailSinkDir?.let { add("[andvari] TEST MODE: mail is written to $it, not sent") }
        config.testClockFile?.let { add("[andvari] TEST MODE: the clock is read from $it") }
        add("[andvari] ************************************************************************")
    }
    add("[andvari] ${config.instanceKind} instance at ${config.canonicalOrigin}, listening on ${config.host}:${config.port}")
}

private fun serve() {
    val problems = Config.envLint(System.getenv())
    problems.forEach { System.err.println("[andvari] env WARNING: $it") }
    if (Config.parseBool(System.getenv("ANDVARI_STRICT_ENV")) == true && problems.isNotEmpty()) {
        System.err.println("[andvari] ANDVARI_STRICT_ENV=1: refusing to start with ${problems.size} env problem(s)")
        exitProcess(1)
    }
    val config = try {
        Config.fromEnv()
    } catch (e: ConfigError) {
        System.err.println("[andvari] refusing to start: ${e.message}")
        exitProcess(1)
    }
    // Which file is at the database's path before the database is opened: the line in `server.lock` names a file only
    // where the file there when the line is written is this one (ServerLock).
    val before = ServerLock.keyBeforeOpen(config.dbPath)
    val services = try {
        buildServices(config)
    } catch (e: IncompatibleDatabase) {
        System.err.println("[andvari] refusing to start: ${e.message}")
        exitProcess(1)
    }
    // The database is open, decided, in write-ahead mode and caught up: from here until this process ends, the two parts
    // of the lock on `server.lock` and the line written between them say that a running server holds that database file
    // (`andvari admin backup` keeps a snapshot only then). This is the one place in the server's process that opens that
    // file: the lock belongs to the process, and closing another opening of the same file here would let go of it
    // (ServerLock).
    ServerLock.take(config.dbPath, before)?.let { System.err.println(it) }
    startupLines(config).forEach { System.err.println(it) }
    embeddedServer(
        Netty,
        configure = {
            connector {
                host = config.host
                port = config.port
            }
            requestReadTimeoutSeconds = config.requestReadTimeoutSeconds
            responseWriteTimeoutSeconds = config.responseWriteTimeoutSeconds
        },
    ) {
        andvariModule(services)
    }.start(wait = true)
}
