package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.PlainItem
import io.silencelen.andvari.server.HostCli
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.sql.DriverManager

/**
 * A restore of the server's database from a backup, as the self-hosting guide tells an operator to do it: the nightly
 * snapshot is taken with `VACUUM INTO` while the server runs, beside a copy of the blobs; later the server is stopped,
 * the snapshot is put back as its database (and the copy as its blobs), and the server is started again on them.
 *
 * The test server cannot be stopped without being started again, so the files are put back in a new directory of their
 * own while the server still runs on the old ones, and the server is then restarted on the new ones (for the server this
 * is "put the files back and start": nothing of the old files is read). [restoreFrom]'s step between the two, when one is
 * given, runs on the put-back files while no server has them open: the place of `andvari admin restored`.
 */
class Snapshot(val db: File, val blobs: File)

/** The guide's nightly snapshot of the running server: `VACUUM INTO` through a connection of its own, and the blobs. */
fun World.takeSnapshot(): Snapshot {
    val config = HostCli.configFrom(server.envFile)
    val dir = Files.createTempDirectory(server.dir.toPath(), "snapshot").toFile()
    val db = File(dir, "andvari.db")
    DriverManager.getConnection("jdbc:sqlite:${config.dbPath}").use { c -> c.createStatement().use { it.execute("VACUUM INTO '${db.path}'") } }
    val blobs = File(dir, "blobs").apply { mkdirs() }
    File(config.blobDir).takeIf { it.isDirectory }?.copyRecursively(blobs, overwrite = true)
    return Snapshot(db, blobs)
}

/**
 * The snapshot is put back (a copy of it, in a new directory), [beforeStart] runs with the environment file of the
 * put-back files while no server has them open, and the server starts on them.
 */
fun World.restoreFrom(s: Snapshot, beforeStart: ((File) -> Unit)? = null) {
    val dir = Files.createTempDirectory(server.dir.toPath(), "restored").toFile()
    val db = s.db.copyTo(File(dir, "andvari.db"))
    val blobs = File(dir, "blobs").apply { mkdirs() }
    s.blobs.copyRecursively(blobs, overwrite = true)
    val put = mapOf("ANDVARI_DB" to db.path, "ANDVARI_BLOB_DIR" to blobs.path)
    if (beforeStart != null) {
        val env = File(dir, "andvari.env")
        env.writeText(server.envFile.readText())
        HostCli.editEnvFile(env, put)
        beforeStart(env)
    }
    server.restart(put)
}

/** What one run of `andvari admin restored --env-file [env]` answered: its exit code, what it printed, what it said on stderr. */
class AdminRan(val code: Int, val out: String, val err: String)

fun adminRestored(env: File, vararg more: String): AdminRan = adminCommand(env, "restored", *more)

/** What one run of `andvari admin [command] --env-file [env]` answered, run in this process. */
fun adminCommand(env: File, command: String, vararg more: String): AdminRan =
    hostTool(listOf("admin", command, "--env-file", env.path) + more)

/** What one run of the server's tool (`andvari [argv]`) answered, run in this process. */
fun hostTool(argv: List<String>): AdminRan {
    val out = ByteArrayOutputStream()
    val err = ByteArrayOutputStream()
    val before = System.err
    val code = synchronized(System::class.java) {
        System.setErr(PrintStream(err, true))
        try {
            HostCli.run(argv, PrintStream(out, true)) { null }
        } finally {
            System.setErr(before)
        }
    }
    return AdminRan(code, out.toString(), err.toString())
}

/** The names of [items], as the item documents carry them. */
fun itemNames(items: List<PlainItem>): Set<String> = items.mapTo(HashSet()) { it.doc["name"]!!.jsonPrimitive.content }
