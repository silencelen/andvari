package io.silencelen.andvari.server

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.TimeUnit

/**
 * Fixtures for the tests of `andvari admin backup`. Every data folder is a real one, made by the product's own
 * `andvari setup --test --stop-at-setup` in a new folder under the test task's temporary folder, and every database is
 * read and written through the real SQLite library the server uses. Nothing here removes a file.
 */
internal object BackupFixture {
    /** 2026-11-18 to 2026-11-21, each at 03:17:00 UTC: four nights. */
    const val NIGHT_1 = 1_794_971_820_000L
    const val NIGHT_2 = 1_795_058_220_000L
    const val NIGHT_3 = 1_795_144_620_000L
    const val NIGHT_4 = 1_795_231_020_000L

    private val NOFOLLOW = LinkOption.NOFOLLOW_LINKS

    /** The files of one server's folder, as the guide names them. */
    class Server(val root: File) {
        val env = File(root, "andvari.env")
        val data = File(root, "data")
        val db = File(data, "andvari.db")
        val backup = File(data, ServerBackup.FOLDER)
        val nightly = File(backup, ServerBackup.NIGHTLY)
        val temporary = File(backup, ServerBackup.TEMPORARY)
        val lock = File(backup, ServerBackup.LOCK)
        val serverLock = File(data, ServerLock.NAME)
        fun dated(ms: Long) = File(backup, ServerBackup.datedName(ms))

        /** Sets the server's clock: the test clock file that setup wrote, which the product reads as "now". */
        fun at(ms: Long) = File(data, "clock").writeText(ms.toString())

        /** The connection of [hold] that stands in for the running server's own; null until it is opened and once it is let go ([letGo]). */
        var holder: Connection? = null
    }

    /**
     * Where the seam says that a running server holds the database ([HELD]), the database is held open, as the running
     * server's own connections hold it beside every real run: by a connection of this fixture, which stands in for the
     * connection of the server of the test's story. It is opened for the server folder [s] through the name the story
     * uses at that time (the database's own name, a link in it followed as SQLite follows it), kept open until the test
     * lets it go ([letGo]), and one read is made on it, so that SQLite has its `-wal` and `-shm` beside the database as a
     * running server has them. It is opened only where a running server could hold the database: an ordinary file at the
     * path (links followed, as SQLite follows them), whose header says write-ahead mode, with no rollback journal beside
     * it. Anywhere else nothing is opened, since an open there would change what the test set up (make a database where
     * there is none, or apply a journal).
     */
    fun hold(s: Server) {
        if (s.holder != null) return
        val f = Db.resolved(s.db) ?: return
        if (!f.isFile || File(f.path + "-journal").exists()) return
        if (!runCatching { Db.headerSaysWriteAhead(f) }.getOrDefault(false)) return
        s.holder = connect(s.db).also { c -> c.queryOne("SELECT COUNT(*) FROM sqlite_master") { it.getLong(1) } }
    }

    /**
     * Lets go of the connection of [hold] for the server folder [s], where one is open: closes it and clears
     * [Server.holder]. A test calls it where the server of its story stops while that connection is held, and before the
     * test's own [Db] or a process it starts plays that server, so that the story's server is the last to close the
     * database, as a real one is. A later run under [HELD] holds the database again ([backup]).
     */
    fun letGo(s: Server) {
        s.holder?.close()
        s.holder = null
    }

    fun newFolder(name: String): File = Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")), name).toFile()

    /** A server folder with an instance of this build in it (one row of the fixture's own besides), its clock at [NIGHT_1]. */
    fun server(): Server {
        val s = Server(newFolder("backup"))
        val code = HostCli.run(
            listOf("setup", "--test", "--stop-at-setup", "--env-file", s.env.path, "--data-dir", s.data.path),
            PrintStream(ByteArrayOutputStream()),
        ) { null }
        check(code == 0) { "setup failed" }
        connect(s.db).use { c -> c.exec("INSERT INTO meta(key,value) VALUES('fixture','a row of the fixture')") }
        s.at(NIGHT_1)
        return s
    }

    /**
     * A server folder as [server] makes it, whose database is held open from the start ([hold]): for the tests whose
     * every run takes the seam that tells it a running server holds the database. A test whose story moves the database
     * or names it by a link starts from [server] instead: its first run under the seam holds the database ([backup])
     * after that, through the name the story then uses.
     */
    fun heldServer(): Server = server().also { hold(it) }

    fun connect(f: File): Connection = DriverManager.getConnection("jdbc:sqlite:${f.path}")

    /**
     * The seam of the tests of the steps after the look at `server.lock`, which run in this process: it tells the run that
     * a running server holds the database, and the look is not made. No test of the look takes it; those start the
     * server's real program in a process of its own ([startServer]). Every run here that takes it runs with the database
     * held open ([hold]) by the fixture's connection, which stands for the server of the test's story: where that server
     * is the test's own [Db] or a process the test starts, the fixture holds no connection beside it, and where that
     * server stops, the fixture's connection is let go first ([letGo]).
     */
    val HELD = ServerBackup.Seams(serverHolds = true)

    /**
     * The command as the host's command line runs it, in this process, by default with [HELD]: null when it worked, else
     * its one line. Where the seam tells the run that a server holds the database, it is held open first ([hold]), through
     * the name the test's story uses at that time; a connection already held is kept.
     */
    fun backup(s: Server, vararg extra: String, seams: ServerBackup.Seams = HELD): String? = try {
        if (seams.serverHolds) hold(s)
        ServerBackup.command(HostCli.Args(listOf("backup", "--env-file", s.env.path) + extra), s.env, seams)
        null
    } catch (e: HostCli.Refused) {
        e.message ?: ""
    }

    /**
     * The exit status the host's command line gives for the same run, with [HELD]: 0 for a run that works, 1 for one that
     * fails (`HostCli.run` turns the command's one line into status 1). That the program itself ends so, in a process of
     * its own beside a real server, is held by [ServerBackupProcessTest].
     */
    fun status(s: Server, vararg extra: String): Int = if (backup(s, *extra) == null) 0 else 1

    /** The first 20 bytes of [f]'s header, as SQLite's bytes 18 and 19 (2 and 2: write-ahead mode; 1 and 1: rollback). */
    fun header(f: File): String = f.inputStream().use { it.readNBytes(20) }.let { "header ${it[18]}/${it[19]}" }

    /**
     * What the database [f] holds, read through the real library: the header's journal-mode bytes and the library's
     * journal mode, every definition in `sqlite_master`, every row of every table. Opening it may merge a write-ahead
     * file into it (what it holds stays the same); read a copy ([copyAside]) where that matters.
     */
    fun holds(f: File): List<String> {
        val out = arrayListOf(header(f))
        connect(f).use { c ->
            out += "journal " + c.queryOne("PRAGMA journal_mode") { it.getString(1) }
            out += c.queryAll("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name") { rs -> (1..4).joinToString(" ") { rs.getString(it) ?: "-" } }
            for (t in c.queryAll("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name") { it.getString(1) }) {
                out += c.queryAll("SELECT * FROM \"$t\"") { rs ->
                    "$t: " + (1..rs.metaData.columnCount).joinToString("|") { i ->
                        when (val v = rs.getObject(i)) {
                            null -> "NULL"
                            is ByteArray -> v.joinToString("") { b -> "%02x".format(b) }
                            else -> v.toString()
                        }
                    }
                }.sorted()
            }
        }
        return out
    }

    /** What [f] holds without the journal mode: the rows and definitions alone, to compare a snapshot with its source. */
    fun rows(f: File): List<String> = holds(f).filterNot { it.startsWith("header ") || it.startsWith("journal ") }

    /** The database [f] and every file beside it, copied into a new folder of its own under the same names. */
    fun copyAside(f: File): File {
        val dir = newFolder("aside")
        for (suffix in listOf("", "-wal", "-shm", "-journal")) {
            val src = File(f.path + suffix)
            if (Files.exists(src.toPath(), NOFOLLOW)) Files.copy(src.toPath(), File(dir, f.name + suffix).toPath())
        }
        return File(dir, f.name)
    }

    /** The refusal the server's own start gives for the database [f]: the product's `Db` opened on a copy of it and its files. */
    fun startRefusal(f: File): String? = runCatching { Db(copyAside(f).path).close() }.exceptionOrNull()?.message

    /** The refusal the `restored` command gives in the server folder [s], null when it does not refuse. */
    fun restoredRefusal(s: Server): String? = runCatching {
        val config = HostCli.configFrom(s.env)
        RestoredStart.run(config, clockFor(config), PrintStream(ByteArrayOutputStream()))
    }.exceptionOrNull()?.message

    /**
     * A copy of the database [f] in rollback mode with its own rollback journal beside it, as a writer leaves them that
     * was stopped inside its transaction after it had written changed pages into the file (a page cache of two pages
     * makes it write them before the commit). The file and its journal are copied while that transaction is open, so the
     * journal is a real one that the next open of the file applies; the writer's own copy is then rolled back. Returns the
     * copied file, under [f]'s name in a new folder, with the journal beside it.
     */
    fun stoppedWriter(f: File): File {
        val work = copyAside(f)
        connect(work).use { c -> c.queryOne("PRAGMA journal_mode=DELETE") { it.getString(1) } }
        val stopped = File(newFolder("stopped-writer"), f.name)
        connect(work).use { c ->
            c.createStatement().use { st ->
                st.execute("PRAGMA cache_size=2")
                st.execute("BEGIN IMMEDIATE")
            }
            for (i in 1..400) c.exec("INSERT INTO meta(key,value) VALUES(?,?)", "written in the stopped transaction $i", "x".repeat(2000))
            c.exec("UPDATE meta SET value='changed in the stopped transaction' WHERE key='fixture'")
            Files.copy(work.toPath(), stopped.toPath())
            Files.copy(File(work.path + "-journal").toPath(), File(stopped.path + "-journal").toPath())
            c.createStatement().use { it.execute("ROLLBACK") }
        }
        return stopped
    }

    /**
     * A run of the command in a process of its own, held at the room step (with the lock taken) until it is killed: the
     * main class of [heldRun]. It prints one line once it is held there.
     */
    object HeldRun {
        const val HELD = "held at the room step"

        @JvmStatic
        fun main(args: Array<String>) {
            val env = File(args[0])
            val atRoom = ServerBackup.Seams(
                serverHolds = true,
                atStep = { step ->
                    if (step == ServerBackup.Step.ROOM) {
                        println(HELD)
                        System.out.flush()
                        Thread.sleep(TimeUnit.MINUTES.toMillis(10))
                    }
                },
            )
            ServerBackup.command(HostCli.Args(listOf("backup", "--env-file", env.path)), env, atRoom)
        }
    }

    /**
     * Starts [HeldRun] for the server folder [s] as a process of its own, from this test's own classes and libraries, and
     * returns it once it holds the lock (its line read), with no ANDVARI_ variable from this process's environment. It
     * takes the seam [HELD], so the database is held open first ([hold]).
     */
    fun heldRun(s: Server): Process {
        hold(s)
        val java = File(System.getProperty("java.home"), "bin/java").path
        val pb = ProcessBuilder(
            java, "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"), "-cp", System.getProperty("java.class.path"),
            HeldRun::class.java.name, s.env.path,
        ).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        pb.environment().keys.removeIf { it.startsWith("ANDVARI_") }
        val p = pb.start()
        val said = p.inputStream.bufferedReader().readLine()
        if (said != HeldRun.HELD) {
            p.destroyForcibly().waitFor()
            error("the held run did not reach the room step: $said")
        }
        return p
    }

    /** Every name under [dir], links not followed: a link's target, "folder", or a file's length and bytes' hash. */
    fun tree(dir: File): Map<String, String> {
        val root = dir.toPath()
        if (!Files.exists(root, NOFOLLOW)) return emptyMap()
        if (Files.isSymbolicLink(root)) return mapOf("" to "link to ${Files.readSymbolicLink(root)}")
        return Files.walk(root).use { it.toList() }.associate { p ->
            root.relativize(p).toString() to when {
                Files.isSymbolicLink(p) -> "link to ${Files.readSymbolicLink(p)}"
                Files.isDirectory(p, NOFOLLOW) -> "folder"
                else -> "file ${Files.size(p)} ${p.toFile().readBytes().contentHashCode()}"
            }
        }
    }

    fun inode(f: File): Any = Files.getAttribute(f.toPath(), "unix:ino", NOFOLLOW)

    fun linkCount(f: File): Int = Files.getAttribute(f.toPath(), "unix:nlink", NOFOLLOW) as Int

    fun exists(f: File): Boolean = Files.exists(f.toPath(), NOFOLLOW)

    class Ran(val code: Int, val out: String, val err: String)

    /**
     * What starts a process so that a file's mode binds it as it binds the server's user: for root, `setpriv` without the
     * two capabilities by which root reads and searches past a file's mode (root then reads only what the mode lets the
     * file's owner read); for any other user, nothing.
     */
    fun withoutOverride(): List<String> =
        if (Files.getAttribute(Path.of("/proc/self"), "unix:uid") == 0) {
            listOf("setpriv", "--inh-caps=-dac_override,-dac_read_search", "--bounding-set=-dac_override,-dac_read_search")
        } else {
            emptyList()
        }

    /**
     * The server's program run as a process of its own, as the image runs it (`java … MainKt admin backup …`), from this
     * test's own classes and libraries, with no ANDVARI_ variable from this process's environment and nothing on its input.
     * [before] is a program that starts it ([withoutOverride]).
     */
    fun process(vararg argv: String, before: List<String> = emptyList()): Ran {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val dir = newFolder("process")
        val out = File(dir, "out")
        val err = File(dir, "err")
        val pb = ProcessBuilder(
            before + listOf(java, "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"), "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.server.MainKt") +
                argv,
        ).redirectOutput(out).redirectError(err).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        pb.environment().keys.removeIf { it.startsWith("ANDVARI_") }
        val p = pb.start()
        if (!p.waitFor(3, TimeUnit.MINUTES)) {
            p.destroyForcibly().waitFor()
            error("the process did not end within three minutes")
        }
        return Ran(p.exitValue(), out.readText(), err.readText())
    }

    /** A port that was free a moment ago on 127.0.0.1. */
    fun freePort(): Int = java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }

    /**
     * A server started by [startServer]: its process and every line it printed (standard output and standard error
     * together), read as they come.
     */
    class Started(val process: Process) {
        private val said = java.util.concurrent.CopyOnWriteArrayList<String>()
        private val reader = Thread {
            process.inputStream.bufferedReader().forEachLine { said += it }
        }.also { it.isDaemon = true; it.start() }

        fun lines(): List<String> = ArrayList(said)

        /** Waits up to two minutes for a line that contains [text]: true when one came, false when the process ended first. */
        fun waitFor(text: String): Boolean {
            val end = System.nanoTime() + TimeUnit.MINUTES.toNanos(2)
            while (System.nanoTime() < end) {
                if (said.any { it.contains(text) }) return true
                if (!reader.isAlive) return said.any { it.contains(text) }
                Thread.sleep(20)
            }
            return false
        }

        /** Waits up to a minute for the process to end, then for the last of its lines; its exit status. */
        fun ended(): Int {
            check(process.waitFor(1, TimeUnit.MINUTES)) { "the server did not end within a minute" }
            reader.join(TimeUnit.MINUTES.toMillis(1))
            return process.exitValue()
        }

        /** The real SIGTERM (what `docker compose stop` sends), then its end: its exit status. */
        fun term(): Int {
            process.destroy()
            return ended()
        }

        /** The real SIGKILL, then its end: its exit status. */
        fun kill(): Int {
            process.destroyForcibly()
            return ended()
        }
    }

    /** The line the server's start prints once its database is open, just before it listens. */
    const val LISTENING = ", listening on "

    /**
     * The server's real start (`java … MainKt`, no argument: the program the image runs, the path production takes) in a
     * process of its own, from this test's own classes and libraries, on the server folder [s]. Its environment is the
     * server's settings file, as the container gets it, on a port of its own, with [set] over it, and no other ANDVARI_
     * variable; [before] is a program that starts it ([withoutOverride]). Returns once it printed the line before its
     * listen ([LISTENING]), or once it ended, whichever comes first; with [until], once it printed a line with that text.
     * [dir] is its working folder (this process's own when null).
     */
    fun startServer(s: Server, vararg set: Pair<String, String>, before: List<String> = emptyList(), until: String = LISTENING, dir: File? = null): Started {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val pb = ProcessBuilder(
            before + listOf(java, "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"), "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.server.MainKt"),
        ).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        if (dir != null) pb.directory(dir)
        pb.environment().keys.removeIf { it.startsWith("ANDVARI_") }
        pb.environment().putAll(HostCli.readEnvFile(s.env))
        pb.environment()["ANDVARI_PORT"] = freePort().toString()
        pb.environment().putAll(set)
        val started = Started(pb.start())
        started.waitFor(until)
        return started
    }

    /**
     * The same real start as [startServer], on the server folder [s] with [set] over its settings, returned at once, before
     * the process has printed anything: for a test that watches the start from its first instant.
     */
    fun startServerAtOnce(s: Server, vararg set: Pair<String, String>): Started {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val pb = ProcessBuilder(
            listOf(java, "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"), "-cp", System.getProperty("java.class.path"), "io.silencelen.andvari.server.MainKt"),
        ).redirectErrorStream(true).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null")))
        pb.environment().keys.removeIf { it.startsWith("ANDVARI_") }
        pb.environment().putAll(HostCli.readEnvFile(s.env))
        pb.environment()["ANDVARI_PORT"] = freePort().toString()
        pb.environment().putAll(set)
        return Started(pb.start())
    }
}
