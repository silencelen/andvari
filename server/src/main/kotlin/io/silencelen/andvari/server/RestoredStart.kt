package io.silencelen.andvari.server

import java.io.File
import java.io.PrintStream
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.time.Instant

/**
 * `andvari admin restored` (decided on 2026-11-20): the first start of a server whose database was put back from a
 * backup. The operator runs it once, with the server stopped, after putting the files back and before starting the
 * server. In ONE transaction it:
 *
 * - ends every session of every account, the operator's included (`sessions.revokedAt`, as `/auth/logout` does per
 *   device): every access token and refresh token a device holds is refused from then on, so a device revoked after
 *   the snapshot, which the restored database shows as live again, cannot sync or renew with what it holds;
 * - marks every device that is not revoked as signed out (`devices.signedOutAt`), keeping every row: they are the
 *   accounts' devices lists, and a known row lets the next sign-in reuse it;
 * - closes the links in progress (`links` open or answered become `revoked`) and the device links in progress (their
 *   rows go, as the server's own cancel of a device link removes its row: there is no closed state);
 * - closes the requests for the operator's help in progress, for every account (as a password change cancels them): one
 *   past its mailed code, waiting or already answered, is ended as refused (`vetoed`) with its answer dropped, so that
 *   nobody can finish it; one before its code is marked cancelled; a decoy is left as it was. A restore brings a request
 *   back as the snapshot held it, so one the account refused after the snapshot would be waiting again, and one the
 *   operator had answered would be ready to finish with no further act of anyone;
 * - writes one record into the server's own settings ([RECORD_KEY] in `meta`: the time and the counts), which no route
 *   serves and `andvari admin status` shows.
 *
 * It removes no account, vault, item, log entry, device row, audit row or blob; changes no password, key, policy or
 * quota; writes no row of `changes` (the change counter is as the backup left it) and never moves the retention fence;
 * and writes nothing a device is told about the restore: no flag in any answer, no audit row (the kinds of audit rows are
 * served to the operator's devices), no change to the card chain.
 *
 * **Nothing is opened while a file lies beside the database.** SQLite applies a write-ahead file (`-wal`) or a hot
 * rollback journal (`-journal`) it finds beside a database to it when the file is opened, and nothing in either ties it
 * to that database file: a put-back snapshot with the replaced database's write-ahead file beside it is corrupted for
 * good by its first opening. So the command refuses before it opens anything when a `-wal`, a `-shm` or a `-journal` lies
 * there, names the files it found, and gives one way out that is right whatever left them: move them out of the folder
 * and keep them, copy the backup's file into place again, run the command again. (A journal of a stopped run of this
 * command is the put-back file's own; the same act of moving it out would damage that file, unless the backup's file is
 * copied into place again.) A running server always has its write-ahead file beside the database, so a `-wal` is also
 * the first sign that the server runs. A run that finds the database unreadable says so and to copy the backup's file
 * into place again. The server's start and every other command of the tool refuse a `-wal` beside a database whose header
 * does not say write-ahead mode with the same words ([Db.refuseForeignWriteAhead]).
 *
 * **The put-back file is checked before anything changes it** (decided on 22 November 2026). After those refusals the
 * command runs SQLite's integrity check, the one the snapshot command runs on a new snapshot ([IntegrityCheck]), on the
 * put-back file opened read only and immutable, which leaves its folder byte for byte as it was. A file that is empty, is
 * no database, cannot be read or names a fault is refused with nothing changed and the way back: the backup's file copied
 * into place again, the newest snapshot that passes the check. A sound file whose marker is not this build's (another
 * program's database, or one of another build) is refused in the same opening, with the same way back, before anything
 * opens it for writing. No flag, setting or variable skips the check. Once the
 * exclusive lock below is held, the file must still be the one the check read (the same file, length and time), or the run
 * stops before its first change.
 *
 * **The server must be stopped.** The command opens the database in SQLite's exclusive locking mode with no wait and
 * begins an exclusive transaction: a process holding the file open is refused at once (SQLite's "busy" or "locked"),
 * and only those two are reported as the database being open in another process; any other failure says what it was.
 * "Nothing was changed" is said only where it is so: after a refusal before opening, after an opening failure that left
 * the file and its folder as they were, and after a rollback. It is safe to run twice (the second run finds nothing
 * live), and a run stopped part-way leaves its journal, which the next opening of the database rolls back.
 */
object RestoredStart {
    /** The key of the command's record in `meta`: the time of the last run and its counts. Read by `andvari admin status` only. */
    const val RECORD_KEY = "restoredStart"

    /** What one run did. */
    class Done(
        val sessions: Int, val devices: Int, val links: Int, val deviceLinks: Int,
        /** Requests for the operator's help closed: ended as refused past the mailed code, cancelled before it. */
        val requests: Int,
        val record: String,
        /** What the start-up step did first to a database an earlier development build of this baseline made; empty when nothing. */
        val caughtUp: List<String>,
    )

    const val RUNNING =
        "the database is open in another process: stop the server (and anything else that has the database open), then run " +
            "`andvari admin restored` again. Nothing was changed."

    /**
     * The refusal when the leftover files [found] (of `-wal`, `-shm`, `-journal`) lie beside the database named [name]: one
     * way out, right whatever left them there, so the operator is never asked where a file came from. When the database's
     * path is a link, [link] is (the path, the file it leads to): the refusal says so first, since the files lie beside that
     * file and not beside the path the operator gave.
     */
    fun leftoverBeside(name: String, found: List<String>, link: Pair<String, String>? = null): String {
        val files = found.joinToString(" and ")
        val them = if (found.size == 1) "it" else "them"
        return (link?.let { (path, file) -> "$path is a link to $file: the files named here lie beside that file. " } ?: "") +
            "Left over beside the database: $files. " +
            (if ("$name-wal" in found) "If the server is running, stop the server (and anything else that has the database open) first. " else "") +
            "Whatever left $them there: move $files out of this folder and keep $them; copy the backup's $name into place again " +
            "(copy it, never move it, and keep the backup until the restore has worked); then run `andvari admin restored` again. " +
            "If you no longer have the backup's $name, move nothing and do not start the server" +
            (if ("$name-journal" in found) {
                ": a journal left by a run that was stopped holds the way back for that database, and opening the database once " +
                    "takes that run back (run `andvari admin status` once, then `andvari admin restored` again)"
            } else "") +
            ". Nothing was changed."
    }

    fun run(config: Config, clock: Clock, out: PrintStream) {
        val given = File(config.dbPath)
        val noDatabase = "no database at ${config.dbPath} (put the backup's andvari.db back there first)"
        // The file the path stands for, links followed (also a link whose target does not exist yet): SQLite opens that
        // file and uses the files beside it, so the command looks there, and works on that file from here on.
        val file = Db.resolved(given) ?: throw HostCli.Refused(HostCli.cannotOpen(config.dbPath, Db.UNRESOLVED_LINKS))
        if (file.exists() && !file.isFile) throw HostCli.Refused(noDatabase)
        // Before anything opens the file: SQLite would apply what lies beside it. Said also where the file is missing, so
        // that files left beside a missing database are named before a backup's file is put back beside them.
        val found = LEFTOVERS.filter { File(file.path + it).exists() }.map { file.name + it }
        if (found.isNotEmpty()) throw HostCli.Refused(leftoverBeside(file.name, found, Db.linkOf(given, file)))
        if (!file.isFile) throw HostCli.Refused(noDatabase)
        // SQLite's integrity check, the one the snapshot command runs on a new snapshot, on the put-back file before
        // anything changes it, opened so that nothing in its folder changes; a file that fails is refused as it lies.
        val checked = Identity.of(file)
        checkFailure(file, IntegrityCheck.onFileAsItIs(file))?.let { throw HostCli.Refused(it) }
        betweenCheckAndLock()
        val seen = Seen.of(file)

        val c = try {
            DriverManager.getConnection("jdbc:sqlite:${file.path}")
        } catch (e: SQLException) {
            throw HostCli.Refused(openFailed(e, file, seen))
        }
        val done = try {
            val failure = try {
                // The first statement that reads the file takes its lock in this mode: refused at once when another
                // process has the file open.
                c.createStatement().use { st ->
                    st.execute("PRAGMA busy_timeout=0")
                    st.execute("PRAGMA locking_mode=EXCLUSIVE")
                    st.execute("PRAGMA foreign_keys=ON")
                    st.execute("PRAGMA synchronous=FULL")
                    st.execute("PRAGMA secure_delete=ON")
                    st.execute("BEGIN EXCLUSIVE")
                }
                c.count("SELECT COUNT(*) FROM sqlite_master")
                null
            } catch (e: SQLException) {
                e
            }
            if (failure != null) {
                runCatching { c.close() }
                throw HostCli.Refused(openFailed(failure, file, seen))
            }
            // The lock is held from here to the commit. The file it holds must be the one the check read: the same file,
            // of the same length and time, or the run stops before its first change.
            if (Identity.of(file) != checked) {
                runCatching { c.createStatement().use { it.execute("ROLLBACK") } }
                runCatching { c.close() }
                throw HostCli.Refused(
                    "the database ${file.path} changed between its integrity check and this run (another process wrote to it or " +
                        "replaced it); this run changed nothing in it: run `andvari admin restored` again",
                )
            }
            inTransaction(c, clock.now(), file)
        } finally {
            runCatching { c.close() }
        }

        out.println("Set for the first start after a restore; nothing was removed:")
        if (done.caughtUp.isNotEmpty()) out.println("  ${Db.broughtUp(done.caughtUp)} (as the server's start does)")
        out.println("  sessions ended: ${done.sessions} (of every account, the operator's included)")
        out.println("  devices marked signed out: ${done.devices}")
        out.println("  links in progress closed: ${done.links}")
        out.println("  device links in progress closed: ${done.deviceLinks}")
        out.println("  requests for the operator's help closed: ${done.requests}")
        out.println("Recorded in the server's own settings (`andvari admin status` shows it):")
        out.println(done.record)
        out.println(
            "Start the server. Then, before you tell your members to sign in again, look at every account's devices list and revoke " +
                "again every device revoked after the backup (see the self-hosting guide).",
        )
    }

    /** The whole act in the exclusive transaction begun on [c], committed; rolled back on any failure, and said so. */
    private fun inTransaction(c: Connection, nowMs: Long, file: File): Done {
        try {
            val d = apply(c, nowMs)
            c.createStatement().use { it.execute("COMMIT") }
            return d
        } catch (t: Throwable) {
            val rolledBack = runCatching { c.createStatement().use { it.execute("ROLLBACK") } }
            // A database that cannot be read: said so, and the way back is the backup's file, whatever the rollback did.
            if (unreadable(t)) {
                throw HostCli.Refused("the database ${file.path} could not be read (${t.message}): do not start the server; ${copyBack(file)}")
            }
            // SQLite ends a transaction itself on some failures; then there is nothing left to roll back.
            val back = rolledBack.isSuccess || rolledBack.exceptionOrNull()?.message?.contains("no transaction is active") == true
            if (!back) {
                throw HostCli.Refused(
                    "the run failed (${t.message}) and could not be rolled back (${rolledBack.exceptionOrNull()?.message}): do not start " +
                        "the server; run `andvari admin restored` again and do what it says",
                )
            }
            if (t is HostCli.Refused) throw t
            throw HostCli.Refused("the run failed (${t.message}) and was rolled back: nothing was changed")
        }
    }

    /** The length and time of the database file, and whether anything lies beside it: what "left as it was" compares. */
    private data class Seen(val length: Long, val modified: Long, val beside: Boolean) {
        companion object {
            fun of(f: File) = Seen(f.length(), f.lastModified(), LEFTOVERS.any { File(f.path + it).exists() })
        }
    }

    /**
     * Called once the integrity check has passed and before the opening that takes the lock. Only the tests set it, to
     * change the file in that instant; the server's program never does, and no setting, variable of the environment or
     * option of a command reaches it.
     */
    @Volatile
    internal var betweenCheckAndLock: () -> Unit = {}

    /** Which file the database is (its file key), its length and its time: what the check read and the lock must hold. */
    private data class Identity(val key: Any?, val length: Long, val modified: Long) {
        companion object {
            fun of(f: File): Identity {
                val a = java.nio.file.Files.readAttributes(f.toPath(), java.nio.file.attribute.BasicFileAttributes::class.java)
                return Identity(a.fileKey(), a.size(), a.lastModifiedTime().toMillis())
            }
        }
    }

    /** At most this many characters of what SQLite said go into a refusal's line. */
    private const val SAID_AT_MOST = 300

    private fun cut(s: String): String = if (s.length <= SAID_AT_MOST) s else s.take(SAID_AT_MOST) + "…"

    /**
     * The refusal for a put-back file that did not pass the integrity check ([IntegrityCheck.onFileAsItIs]), null when it
     * passed. Each says what was found, in SQLite's own first words, that nothing was changed, and the way back.
     */
    private fun checkFailure(file: File, result: IntegrityCheck.Result): String? {
        val nothing = "nothing was changed: do not start the server; ${copyBack(file)}"
        val wayBack = "$nothing; the backup to take is the newest snapshot that passes `PRAGMA integrity_check`"
        return when (result) {
            // Read in the check's own opening, before anything opens the file for writing (decided on 22 November 2026).
            // Such a file passes the integrity check, so the way back names a snapshot this refusal would not refuse again. A
            // database with another build's marker has a second way: the version that made it (after a failed update, no
            // snapshot of this build may exist).
            is IntegrityCheck.Result.Passed -> if (result.baseline == Db.BASELINE) null else
                "the database ${file.path} is not a database of this build (baseline ${result.baseline?.let { "'$it'" } ?: "none"}, " +
                    "this build expects '${Db.BASELINE}'); $nothing; the backup to take is the newest snapshot that a server of this " +
                    "build made and that passes `PRAGMA integrity_check`" +
                    (if (result.baseline != null) ", or run the version of andvari that made this database" else "")
            IntegrityCheck.Result.Empty -> "the database ${file.path} is empty (0 bytes), so it is no database to restore; $wayBack"
            is IntegrityCheck.Result.Faults ->
                "the database ${file.path} did not pass SQLite's integrity check, which found faults in it (it answered: " +
                    "${cut(result.answers.joinToString("; "))}); $wayBack"
            is IntegrityCheck.Result.Unreadable -> when (result.code) {
                SQLITE_NOTADB -> "${file.path} is not an SQLite database (${cut(result.message)}); $wayBack"
                SQLITE_CORRUPT ->
                    "the database ${file.path} could not be read: it did not pass SQLite's integrity check (${cut(result.message)}); $wayBack"
                else -> "could not open the database ${file.path} for its integrity check (${cut(result.message)}); nothing was changed"
            }
        }
    }

    /** The files SQLite leaves beside a database: none may lie there when the command begins. */
    internal val LEFTOVERS = listOf("-wal", "-shm", "-journal")

    /** What an opening failure is reported as: busy or locked is another process; anything else says what it was. */
    private fun openFailed(e: SQLException, file: File, seen: Seen): String {
        val code = e.errorCode and 0xff
        if (code == SQLITE_BUSY || code == SQLITE_LOCKED) return "$RUNNING (${e.message})"
        val asItWas = Seen.of(file) == seen
        val changed = if (asItWas) "; nothing was changed" else "; the database file or its folder changed while it was opened: keep this copy apart and put the backup's file back again"
        val copyBack = if (asItWas && (code == SQLITE_NOTADB || code == SQLITE_CORRUPT)) ": ${copyBack(file)}" else ""
        return when (code) {
            SQLITE_NOTADB -> "${file.path} is not an SQLite database (${e.message})$changed$copyBack"
            SQLITE_CORRUPT -> "the database ${file.path} could not be read (${e.message})$changed$copyBack"
            else -> "could not open the database ${file.path} (${e.message})$changed"
        }
    }

    private fun copyBack(file: File) = "copy the backup's ${file.name} into place again, then run `andvari admin restored` again"

    /** The failure of a run that could not read the database: [t] or one of its causes is SQLite's "corrupt" or "not a database". */
    private fun unreadable(t: Throwable): Boolean = generateSequence(t) { it.cause }.filterIsInstance<SQLException>()
        .any { (it.errorCode and 0xff) in setOf(SQLITE_CORRUPT, SQLITE_NOTADB) }

    private const val SQLITE_BUSY = 5
    private const val SQLITE_LOCKED = 6
    private const val SQLITE_CORRUPT = 11
    private const val SQLITE_NOTADB = 26

    /** The whole act, inside the caller's exclusive transaction on [c]. */
    internal fun apply(c: Connection, nowMs: Long): Done {
        // "Baseline none" only for a database with no settings table: one whose settings table cannot be read fails here
        // with SQLite's own error, which the caller says as "could not be read", with the way back.
        val hasMeta = c.count("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='meta'") > 0
        val baseline = if (hasMeta) c.queryOne("SELECT value FROM meta WHERE key='baseline'") { it.getString(1) } else null
        if (baseline != Db.BASELINE) {
            throw HostCli.Refused(
                "this is not a database of this build (baseline ${baseline ?: "none"}, this build expects ${Db.BASELINE}); nothing was changed",
            )
        }
        // A database an earlier development build of this baseline made is brought up to it first, as the server's start does.
        val caughtUp = SessionChains.carryFromRetiredColumn(c) + BaselineCatchUp.run(c) + Assisted.returnOldFormAnswers(c)

        val sessions = c.exec("UPDATE sessions SET revokedAt=? WHERE revokedAt IS NULL", nowMs)
        val devices = c.exec("UPDATE devices SET signedOutAt=? WHERE signedOutAt IS NULL AND revokedAt IS NULL", nowMs)
        val links = c.exec("UPDATE links SET state='revoked', stateChangedAt=? WHERE state IN ('open','answered')", nowMs)
        val deviceLinks = c.exec("DELETE FROM device_links")
        // Requests for the operator's help, as a password change cancels them but for every account, counted once: one past
        // its mailed code (waiting or answered) is ended as refused, its answer dropped, so no commit can succeed; one before
        // it is marked cancelled. A decoy (no account) is left as it was.
        val requests =
            c.exec("UPDATE recovery_requests SET state='vetoed', codeMac=NULL, sealed=NULL, commitHash=NULL WHERE userId IS NOT NULL AND state IN ('verified','fulfilled')") +
                c.exec("UPDATE recovery_requests SET cancelledAt=? WHERE userId IS NOT NULL AND state='unverified' AND cancelledAt IS NULL", nowMs)

        val record = "${Instant.ofEpochMilli(nowMs)} sessions=$sessions devices=$devices links=$links deviceLinks=$deviceLinks requests=$requests"
        c.exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", RECORD_KEY, record)
        return Done(sessions, devices, links, deviceLinks, requests, record, caughtUp)
    }
}
