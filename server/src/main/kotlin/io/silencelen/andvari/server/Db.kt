package io.silencelen.andvari.server

import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Run [action] after the enclosing [Db.tx] commits; outside a transaction, run it now. */
@Suppress("UNUSED_PARAMETER")
fun afterCommit(c: Connection, action: () -> Unit) {
    val db = Db.CURRENT.get()
    if (db != null) db.queueAfterCommit(action) else action()
}

/**
 * Run [action] if the enclosing [Db.tx] rolls back (after the rollback, still under the lock); outside a transaction,
 * nothing. For what a transaction drew outside the database and must give back when nothing it decided was kept: a draw
 * on a limiter's budget made inside the transaction (decided on 2026-11-17: a recovery request whose transaction fails
 * gives its address's draw back).
 */
@Suppress("UNUSED_PARAMETER")
fun onRollback(c: Connection, action: () -> Unit) {
    Db.CURRENT.get()?.queueOnRollback(action)
}

/** A database this build must not open (design §14.3): a pre-cut-over file, or one of an unknown baseline. */
class IncompatibleDatabase(message: String) : Exception(message)

/**
 * Single-connection SQLite (WAL). One writer is all this deployment needs; the lock serialises access
 * so transactions never interleave.
 *
 * **Fresh baseline (design §14.3, spec 02 §5).** The onboarding-and-trust cut-over is a clean break:
 * this build creates [BASELINE] on an EMPTY database and refuses to start on any other — in particular
 * on a database a pre-cut-over build created ("This database is from andvari 0.x; …"). No forward
 * migration from 0.x exists. A database an earlier development build of this baseline made is brought up to
 * it at start by [BaselineCatchUp], or refused (the rule at [SCHEMA]).
 * Every table and plaintext column below is listed in spec 02 §5's zero-knowledge
 * table; adding one means amending that table in the same change.
 *
 * PRAGMAs (kept from the pre-cut-over server, each pinned by DbDurabilityTest):
 *  - `synchronous=FULL` (spec 02 §7.1): a push is answered `applied` only when durable.
 *  - `secure_delete=ON` (since 26 October 2026): freed cells are zeroed, so destroyed key
 *    material (a replaced verifier, a deleted escrow, purged grants) does not survive in free space;
 *    [checkpointTruncate] flushes the WAL after each key-destruction path.
 */
class Db(path: String, durable: Boolean = true) : AutoCloseable {
    // Before anything opens the file: SQLite would apply the write-ahead file it finds beside it.
    init { refuseForeignWriteAhead(path) }

    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    private val lock = ReentrantLock()
    private val afterCommit = ArrayList<() -> Unit>()
    private val keepOnRollback = ArrayList<(Connection) -> Unit>()
    private val onRollback = ArrayList<() -> Unit>()

    /** What the start-up step ([BaselineCatchUp]) added to this database when it was opened; empty when nothing. */
    var addedAtStart: List<String> = emptyList()
        private set

    init {
        try {
            conn.autoCommit = true
            // Settings of this connection only: none of them writes to the file.
            conn.createStatement().use { st ->
                st.execute("PRAGMA foreign_keys=ON")
                st.execute("PRAGMA busy_timeout=5000")
                // [durable] = false is for the route tests only (TestKit): every commit's fsync made them I/O bound,
                // and on a shared build host the test framework's fixed one-minute limit failed correct tests.
                // Production always opens the default, FULL; DbDurabilityTest pins it.
                st.execute(if (durable) "PRAGMA synchronous=FULL" else "PRAGMA synchronous=OFF")
                st.execute("PRAGMA secure_delete=ON")
            }
            // Whether this build may open the file is decided by reading it only, before the journal mode is switched:
            // switching it rewrites the file's header. A refused file in rollback mode (a put-back backup of another
            // build, or one whose settings table cannot be read) is left byte for byte as it was, except where a hot journal
            // of its own lies beside it (its writer stopped in the middle of a transaction): the read that decides rolls that
            // journal back into the file first, as any opening of the file does, so the unfinished transaction is undone,
            // the journal is gone and no commit is lost. A refused file in write-ahead mode with its own write-ahead file beside it has that file merged into it by SQLite when this
            // connection closes, as the last one on it: every commit the write-ahead file held is kept, in the file.
            val empty = decide(conn)
            conn.createStatement().use { st -> st.execute("PRAGMA journal_mode=WAL") }
            if (empty) tx { c -> c.createStatement().use { st -> for (ddl in SCHEMA) st.executeUpdate(ddl) } } else catchUp()
        } catch (t: Throwable) {
            runCatching { conn.close() }
            throw t
        }
    }

    /** Flush the WAL into the main file and truncate it (spec 04 §3: every key-destruction path). */
    fun checkpointTruncate() = lock.withLock {
        conn.createStatement().use { st ->
            st.executeQuery("PRAGMA wal_checkpoint(TRUNCATE)").use { rs ->
                if (rs.next()) {
                    val busy = rs.getInt(1); val log = rs.getInt(2); val done = rs.getInt(3)
                    if (busy != 0 || done != log) System.err.println("[andvari] WARNING: wal_checkpoint(TRUNCATE) incomplete (busy=$busy, frames=$log, checkpointed=$done)")
                }
            }
        }
    }

    /**
     * Serialised read-write transaction. Actions queued with [afterCommit] inside it run once it has
     * committed (socket bells, revocations, file unlinks), outside the lock; a rollback drops them.
     */
    fun <T> tx(block: (Connection) -> T): T {
        val actions: List<() -> Unit>
        val result = lock.withLock {
            conn.autoCommit = false
            afterCommit.clear()
            onRollback.clear()
            CURRENT.set(this)
            try {
                val r = block(conn)
                conn.commit()
                actions = ArrayList(afterCommit)
                r
            } catch (t: Throwable) {
                conn.rollback()
                for (a in ArrayList(onRollback)) runCatching { a() }.onFailure { System.err.println("[andvari] on-rollback action failed: $it") }
                // Writes that must survive the refusal they record (a denied call's audit row)
                // are written again in their own transaction.
                if (keepOnRollback.isNotEmpty()) {
                    val keep = ArrayList(keepOnRollback)
                    keepOnRollback.clear()
                    runCatching { for (w in keep) w(conn); conn.commit() }
                        .onFailure { e -> runCatching { conn.rollback() }; System.err.println("[andvari] keep-on-rollback write failed: $e") }
                }
                throw t
            } finally {
                keepOnRollback.clear()
                onRollback.clear()
                afterCommit.clear()
                CURRENT.remove()
                conn.autoCommit = true
            }
        }
        for (a in actions) runCatching { a() }.onFailure { System.err.println("[andvari] after-commit action failed: $it") }
        return result
    }

    internal fun queueAfterCommit(action: () -> Unit) { afterCommit.add(action) }

    internal fun queueOnRollback(action: () -> Unit) { onRollback.add(action) }

    /** Inside [tx]: if the transaction rolls back, run [write] again in a transaction of its own. */
    internal fun queueKeepOnRollback(write: (Connection) -> Unit) { keepOnRollback.add(write) }

    /** Serialised read. */
    fun <T> read(block: (Connection) -> T): T = lock.withLock { block(conn) }

    override fun close() {
        lock.withLock { conn.close() }
    }

    /**
     * The start-up step (see the rule at [SCHEMA]), then the return of old-form answers ([Assisted.returnOldFormAnswers]):
     * inside the start-up's transaction, and one log line when either did anything.
     */
    private fun catchUp() {
        addedAtStart = tx { c -> SessionChains.carryFromRetiredColumn(c) + BaselineCatchUp.run(c) + Assisted.returnOldFormAnswers(c) }
        if (addedAtStart.isNotEmpty()) System.err.println("[andvari] ${broughtUp(addedAtStart)}")
    }

    companion object {
        internal val CURRENT = ThreadLocal<Db?>()

        /** What the start-up step did to a database, in the words the server's start logs and `andvari admin restored` prints. */
        fun broughtUp(added: List<String>): String = "database brought up to baseline '$BASELINE': ${added.joinToString("; ")}"

        /**
         * The start's decision on the database open on [c]: whether it is empty (true: the start creates the baseline on
         * it) or of this build's baseline (false); any other database is refused with [IncompatibleDatabase]. It only
         * reads, and it is taken before the start switches the journal mode. `andvari admin backup` takes it on a
         * connection of its own, so it refuses what the start refuses, with the same sentence.
         */
        fun decide(c: Connection): Boolean {
            val tables = c.createStatement().use { st ->
                st.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").use { rs ->
                    val out = HashSet<String>()
                    while (rs.next()) out.add(rs.getString(1))
                    out
                }
            }
            if (tables.isEmpty()) return true
            val baseline = if ("meta" in tables) {
                c.createStatement().use { st ->
                    st.executeQuery("SELECT value FROM meta WHERE key='baseline'").use { rs -> if (rs.next()) rs.getString(1) else null }
                }
            } else null
            return when (baseline) {
                BASELINE -> false
                null -> throw IncompatibleDatabase(OLD_DATABASE_MESSAGE)
                in EARLIER_BASELINES -> throw IncompatibleDatabase(olderBuildMessage("baseline '$baseline', this build expects '$BASELINE'"))
                else -> throw IncompatibleDatabase("This database was created by a different andvari build (baseline '$baseline', this build expects '$BASELINE').")
            }
        }

        /**
         * Whether the database file's own header says write-ahead mode: the file begins with SQLite's header string and
         * its write and read version bytes (offsets 18 and 19) are both 2. A file that is missing, shorter than the header
         * or not an SQLite database does not say so.
         */
        fun headerSaysWriteAhead(f: java.io.File): Boolean {
            if (!f.isFile) return false
            val head = ByteArray(20)
            val n = f.inputStream().use { s ->
                var got = 0
                while (got < head.size) {
                    val r = s.read(head, got, head.size - got)
                    if (r < 0) break
                    got += r
                }
                got
            }
            val magic = "SQLite format 3".encodeToByteArray()
            return n == head.size && magic.indices.all { head[it] == magic[it] } && head[magic.size] == 0.toByte() &&
                head[18] == 2.toByte() && head[19] == 2.toByte()
        }

        /**
         * A write-ahead file (`-wal`) beside a database whose header does not say write-ahead mode is refused before
         * anything opens the database, wherever it is opened (the server's start and every command of the tool). The
         * server's database is always in write-ahead mode, so such a file belongs to another database: the replaced one,
         * beside a put-back snapshot (which is in rollback mode). Nothing in a write-ahead file ties it to a database file,
         * and SQLite applies one it finds beside a database when that database is opened. The refusal names the files
         * that lie there and gives the one way out the `restored` command gives ([RestoredStart.leftoverBeside]). A
         * database in write-ahead mode with its own write-ahead file (an unclean stop of the server) opens as before.
         *
         * SQLite follows a symbolic link to the database file and uses the files beside the file it leads to, so the guard
         * reads the header of, and looks for the leftover files beside, that file ([resolved]); the refusal then names the
         * link and the file it leads to. A path that is not a file that can be read (a folder in its place, a file this
         * user may not read) is said as the database that could not be opened, in one plain line; so is a path the system
         * could not look at ([resolved] gives up: a file where one of its folders should be, a folder on the way that this
         * user may not search, a link that cannot be read, more links on the way than the system follows), which is
         * refused before anything is opened.
         */
        fun refuseForeignWriteAhead(path: String) {
            val given = java.io.File(path)
            val f = resolved(given) ?: throw IncompatibleDatabase(HostCli.cannotOpen(path, UNRESOLVED_LINKS))
            if (!java.io.File(f.path + "-wal").exists()) return
            if (f.exists() && !f.isFile) throw IncompatibleDatabase(HostCli.cannotOpen(path, "it is a folder, not a file"))
            val writeAhead = try {
                headerSaysWriteAhead(f)
            } catch (e: java.io.IOException) {
                throw IncompatibleDatabase(HostCli.cannotOpen(path, e.message ?: e.toString()))
            }
            if (writeAhead) return
            val found = RestoredStart.LEFTOVERS.filter { java.io.File(f.path + it).exists() }.map { f.name + it }
            throw IncompatibleDatabase(RestoredStart.leftoverBeside(f.name, found, linkOf(given, f)))
        }

        /**
         * The file [f] stands for: where the path exists, its canonical file, every symbolic link on the way followed, as
         * SQLite follows them when it opens the database and builds the names of the files beside it. Where [f] is a
         * symbolic link whose target does not exist yet, the file it leads to all the same (each link read and taken from
         * the folder it lies in, until the path is no longer a link, in that file's canonical folder): SQLite follows such a
         * link too, creates the database there and builds the names of the files beside it from there. Else [f] itself.
         *
         * Null where this gives up: more links one after another than the system follows (also through folders on the
         * way), a link that cannot be read, or a path the system could not look at for another cause (a file where one of
         * its folders should be, a folder on the way that this user may not search). SQLite follows more links than the
         * system does, so there the file it would open is not known here, and every caller refuses the path
         * ([UNRESOLVED_LINKS]).
         */
        fun resolved(f: java.io.File): java.io.File? {
            if (f.exists()) return try { f.canonicalFile } catch (_: java.io.IOException) { null }
            var p = f.toPath().toAbsolutePath()
            var hops = 0
            while (java.nio.file.Files.isSymbolicLink(p)) {
                if (++hops > MAX_LINKS) return null
                val target = try { java.nio.file.Files.readSymbolicLink(p) } catch (_: java.io.IOException) { return null }
                p = (p.parent ?: return null).resolve(target)
            }
            // Neither there nor missing: the system could not look (a file where one of the folders on the way should be, a
            // folder on the way that this user may not search, or more links through the folders on the way than it follows).
            if (!java.nio.file.Files.notExists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return null
            if (hops == 0) return f
            val folder = p.parent?.toFile() ?: return p.toFile()
            return try { java.io.File(folder.canonicalFile, p.fileName.toString()) } catch (_: java.io.IOException) { null }
        }

        /** How many symbolic links [resolved] follows one after another before it gives up, as the system itself does. */
        private const val MAX_LINKS = 40

        /**
         * Why a database path is refused where [resolved] gives up, in the words every refusal of it uses: one sentence
         * that is true for each cause, since the refusal does not tell them apart.
         */
        const val UNRESOLVED_LINKS =
            "the system could not look at it: a file where one of its folders should be, a folder on the way that this user may not " +
                "search, a symbolic link that cannot be read, or more symbolic links on the way than the system follows"

        /** "[given] is a link to [file]" as (given, file) when the two differ by a link, for the refusal to name; else null. */
        fun linkOf(given: java.io.File, file: java.io.File): Pair<String, String>? =
            if (file.path == given.absoluteFile.normalize().path) null else given.path to file.path

        /** The marker this build writes and accepts (meta key `baseline`). Changing it: see the rule at [SCHEMA]. */
        const val BASELINE = "onboarding-trust-1"

        /** Markers earlier development builds of this design wrote: a database carrying one is refused as older. */
        val EARLIER_BASELINES: Set<String> = emptySet()

        /**
         * Columns the baseline once had under the current marker and no longer has, by table (spec 02 §5.1). The
         * start-up step drops exactly these, by rebuilding the table, and only on a table no other table refers to;
         * any other column the baseline does not have still refuses the start. Each entry is a decision that the
         * column's values are not needed: `recovery_requests.commitAttempts` counted wrong commit values, which are
         * now audited and never counted. `sessions.chainId` (a development build of 2026-11-17)
         * is carried into `session_chains` before the rebuild drops it ([SessionChains.carryFromRetiredColumn]).
         */
        val RETIRED_COLUMNS: Map<String, Set<String>> = mapOf(
            "recovery_requests" to setOf("commitAttempts"),
            "sessions" to setOf("chainId"),
        )

        const val OLD_DATABASE_MESSAGE =
            "This database is from andvari 0.x; restore its export into a new account instead (see the cut-over guide)."

        /** The refusal for a database an older development build made, which this build cannot bring up to its baseline. */
        fun olderBuildMessage(what: String): String =
            "This database was made by an older development build of andvari, and this build cannot bring it up to its baseline ($what). " +
                "Start this build on a new, empty database file (keep the old file aside), or run the build that made it."

        /**
         * The fresh baseline (spec 02 §5). Foreign keys reference `users` so an account deletion
         * (spec 03 §13) must remove every row that names the account before the user row goes.
         *
         * **The rule for changing it, until the server's first release (spec 02 §5.1).** This baseline is edited
         * in place, and databases that development builds made exist (the owner's test server holds one). So
         * every change to it does one of two things in the same commit, never neither:
         *  1. it changes [BASELINE], adds the outgoing marker to [EARLIER_BASELINES], and freezes the outgoing
         *     schema under the tests' `baseline-history/`: an older database is then refused at start with
         *     [olderBuildMessage], which says what to do; or
         *  2. it is a change the start-up step ([BaselineCatchUp]) makes on an older database — a new table, a
         *     column SQLite can add (nullable, or NOT NULL with a default), or a changed column of a table no
         *     other table refers to, or a removed column named in [RETIRED_COLUMNS] of a table no other table refers
         *     to — and it adds the expected effect to `BaselineCatchUpTest`.
         * A NOT NULL column without a default, a removed column not named in [RETIRED_COLUMNS], or a changed table
         * others refer to can only be 1.
         * `BaselineRuleTest` pins a digest of this list beside [BASELINE]: when it fails, choose 1 or 2, then
         * update the digest. After the first release the baseline is frozen and only numbered, tested
         * migrations change a database (spec 07 §3).
         */
        val SCHEMA: List<String> = listOf(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)",
            // ---- accounts ----
            """CREATE TABLE users(
                 userId TEXT PRIMARY KEY,
                 email TEXT UNIQUE NOT NULL,
                 displayName TEXT NOT NULL,
                 kdfSalt TEXT NOT NULL,
                 kdfParams TEXT NOT NULL,
                 verifier TEXT NOT NULL,
                 wrappedUvk TEXT NOT NULL,
                 identityPub TEXT NOT NULL,
                 encryptedIdentitySeed TEXT NOT NULL,
                 genesis TEXT NOT NULL,
                 personalVaultId TEXT NOT NULL,
                 role TEXT NOT NULL CHECK(role IN ('operator','member')),
                 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
                 disabledAt INTEGER,
                 recovery TEXT NOT NULL DEFAULT 'private' CHECK(recovery IN ('private','operator')),
                 requireLink INTEGER NOT NULL DEFAULT 0,
                 recoveryConfirmed INTEGER NOT NULL DEFAULT 0,
                 quotaAccountBytes INTEGER,
                 quotaItems INTEGER,
                 quotaOwnedSharedVaults INTEGER,
                 quotaOpenLinks INTEGER,
                 ageConfirmed INTEGER NOT NULL DEFAULT 0,
                 createdAt INTEGER NOT NULL,
                 registeredVia TEXT NOT NULL CHECK(registeredVia IN ('ticket','link','enrol','setup')),
                 totpSecret TEXT,
                 totpPendingSecret TEXT,
                 totpEnrolledAt INTEGER,
                 totpLastStep INTEGER NOT NULL DEFAULT 0
               )""",
            // Exactly one operator account per instance (spec 03 §7).
            "CREATE UNIQUE INDEX users_one_operator ON users(role) WHERE role='operator'",
            // The daily account maximum (spec 03 §14.4) counts today's `ticket` and `link` registrations.
            "CREATE INDEX idx_users_registered ON users(createdAt, registeredVia)",
            """CREATE TABLE devices(
                 deviceId TEXT PRIMARY KEY,
                 userId TEXT NOT NULL REFERENCES users(userId),
                 platform TEXT NOT NULL,
                 name TEXT NOT NULL,
                 clientVersion TEXT,
                 how TEXT NOT NULL CHECK(how IN ('registered','password','linked','recovered')),
                 linkedFrom TEXT,
                 deviceSecretHash TEXT,
                 createdAt INTEGER NOT NULL,
                 lastSeenAt INTEGER,
                 revokedAt INTEGER,
                 signedOutAt INTEGER
               )""",
            "CREATE INDEX idx_devices_user ON devices(userId)",
            // `clientPlatform` is the X-Andvari-Client platform of the request that minted the session
            // (spec 03 §1: a `web` session is refused by every operator route); `passwordAt` is set when
            // the session was minted by a password login (spec 03 §2: the TOTP first-enrolment window). The refresh chain a
            // session belongs to is kept in `session_chains` below, not here (a server of the version before must start on
            // a database this one has run on, and it refuses a column of this table it does not know).
            """CREATE TABLE sessions(
                 sessionId TEXT PRIMARY KEY,
                 deviceId TEXT NOT NULL REFERENCES devices(deviceId),
                 userId TEXT NOT NULL REFERENCES users(userId),
                 accessHash TEXT UNIQUE NOT NULL,
                 accessExpiresAt INTEGER NOT NULL,
                 refreshHash TEXT UNIQUE NOT NULL,
                 refreshExpiresAt INTEGER NOT NULL,
                 refreshConsumedAt INTEGER,
                 clientPlatform TEXT NOT NULL,
                 passwordAt INTEGER,
                 createdAt INTEGER NOT NULL,
                 revokedAt INTEGER
               )""",
            "CREATE INDEX idx_sessions_user ON sessions(userId)",
            "CREATE INDEX idx_sessions_device ON sessions(deviceId)",
            // The refresh chain a session belongs to (spec 03 §2): one row for each session a refresh made, naming the session
            // a sign-in, registration, recovery commit or pickup minted at the chain's start, so that a sign-in naming the
            // session it replaces by an older token of the chain ends the chain as it stands now. A session with no row is a
            // chain of its own: every chain's first session, and every session made by a server that does not keep this
            // table. A table of its own, with no reference to `sessions`, so that a server of the version before, which
            // ignores tables it does not know, starts on a database this one has run on, and its deletes of sessions are
            // never blocked (decided on 2026-11-17); a row whose session is gone is removed by the janitor.
            """CREATE TABLE session_chains(
                 sessionId TEXT PRIMARY KEY,
                 chainId TEXT NOT NULL
               )""",
            "CREATE INDEX idx_session_chains_chain ON session_chains(chainId)",
            """CREATE TABLE member_recovery(
                 userId TEXT PRIMARY KEY REFERENCES users(userId),
                 recoveryWrappedUvk TEXT NOT NULL,
                 recoveryVerifier TEXT NOT NULL,
                 pieceId TEXT NOT NULL,
                 setupDeviceId TEXT,
                 updatedAt INTEGER NOT NULL
               )""",
            """CREATE TABLE escrow(
                 userId TEXT PRIMARY KEY REFERENCES users(userId),
                 sealed TEXT NOT NULL,
                 fingerprint TEXT NOT NULL,
                 updatedAt INTEGER NOT NULL
               )""",
            """CREATE TABLE account_state(
                 userId TEXT PRIMARY KEY REFERENCES users(userId),
                 sealedState TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 updatedAt INTEGER NOT NULL
               )""",
            """CREATE TABLE personal_wrap(
                 userId TEXT PRIMARY KEY REFERENCES users(userId),
                 vaultId TEXT NOT NULL,
                 wrappedVk TEXT NOT NULL,
                 updatedAt INTEGER NOT NULL
               )""",
            """CREATE TABLE usage_ledger(
                 userId TEXT PRIMARY KEY REFERENCES users(userId),
                 sealedUsage TEXT NOT NULL,
                 updatedAt INTEGER NOT NULL
               )""",
            "CREATE TABLE retired_ids(idHash TEXT PRIMARY KEY)",
            // ---- vaults, the log, items ----
            """CREATE TABLE vaults(
                 vaultId TEXT PRIMARY KEY,
                 type TEXT NOT NULL CHECK(type IN ('personal','shared')),
                 rev INTEGER NOT NULL,
                 metaBlob TEXT NOT NULL,
                 createdAt INTEGER NOT NULL,
                 logSeq INTEGER,
                 logHash TEXT,
                 logAt INTEGER,
                 deletedAt INTEGER,
                 purgeAt INTEGER,
                 purgedAt INTEGER,
                 deletedBy TEXT,
                 deleteId TEXT,
                 finalSeq INTEGER,
                 finalHash TEXT,
                 finalAt INTEGER,
                 pendingOfferId TEXT,
                 pendingOwnerId TEXT,
                 pendingOfferExpiresAt INTEGER,
                 logState TEXT
               )""",
            "CREATE INDEX idx_vaults_purge ON vaults(purgeAt) WHERE purgeAt IS NOT NULL",
            """CREATE TABLE vault_log(
                 vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
                 seq INTEGER NOT NULL,
                 hash TEXT NOT NULL,
                 frame TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 at INTEGER NOT NULL,
                 storedAt INTEGER NOT NULL,
                 PRIMARY KEY(vaultId, seq)
               )""",
            """CREATE TABLE grants(
                 vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
                 userId TEXT NOT NULL REFERENCES users(userId),
                 role TEXT NOT NULL CHECK(role IN ('owner','writer','reader')),
                 addedAt INTEGER NOT NULL,
                 wrappedVk TEXT NOT NULL,
                 signedGrant TEXT,
                 rev INTEGER NOT NULL,
                 revokedAt INTEGER,
                 revokedReason TEXT CHECK(revokedReason IS NULL OR revokedReason IN ('member_remove','member_leave','vault_delete')),
                 PRIMARY KEY(vaultId, userId)
               )""",
            "CREATE INDEX idx_grants_user ON grants(userId)",
            """CREATE TABLE items(
                 itemId TEXT PRIMARY KEY,
                 vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
                 rev INTEGER NOT NULL,
                 createdAt INTEGER NOT NULL,
                 updatedAt INTEGER NOT NULL,
                 deleted INTEGER NOT NULL DEFAULT 0,
                 conflict INTEGER NOT NULL DEFAULT 0,
                 formatVersion INTEGER NOT NULL,
                 attachmentIds TEXT NOT NULL DEFAULT '[]',
                 blob TEXT,
                 blobSize INTEGER NOT NULL DEFAULT 0
               )""",
            "CREATE INDEX idx_items_vault_rev ON items(vaultId, rev)",
            "CREATE INDEX idx_items_deleted_updated ON items(updatedAt) WHERE deleted=1",
            // Covers the use-and-limits sums (Quotas.ownedBytes/ownedItems/vaultBytes/vaultItems, spec 03 §14.4): they read
            // this index alone, never the item rows with their ciphertext (ItemsUseIndexTest).
            "CREATE INDEX idx_items_vault_live_size ON items(vaultId, deleted, blobSize)",
            """CREATE TABLE item_versions(
                 itemId TEXT NOT NULL,
                 rev INTEGER NOT NULL,
                 blob TEXT NOT NULL,
                 formatVersion INTEGER NOT NULL,
                 archivedAt INTEGER NOT NULL,
                 PRIMARY KEY(itemId, rev)
               )""",
            """CREATE TABLE changes(
                 rev INTEGER PRIMARY KEY AUTOINCREMENT,
                 kind TEXT NOT NULL,
                 entityId TEXT NOT NULL,
                 vaultId TEXT,
                 at INTEGER NOT NULL
               )""",
            """CREATE TABLE mutations(
                 deviceId TEXT NOT NULL,
                 mutationId TEXT NOT NULL,
                 resultJson TEXT NOT NULL,
                 createdAt INTEGER NOT NULL,
                 userId TEXT,
                 PRIMARY KEY(deviceId, mutationId)
               )""",
            "CREATE INDEX idx_mutations_user ON mutations(userId)",
            """CREATE TABLE attachments(
                 attachmentId TEXT PRIMARY KEY,
                 itemId TEXT NOT NULL,
                 vaultId TEXT NOT NULL,
                 size INTEGER NOT NULL,
                 sha256 TEXT NOT NULL,
                 header TEXT NOT NULL,
                 createdAt INTEGER NOT NULL
               )""",
            "CREATE INDEX idx_attachments_item ON attachments(itemId)",
            "CREATE INDEX idx_attachments_vault ON attachments(vaultId)",
            // ---- links, device links, connections ----
            """CREATE TABLE connections(
                 a TEXT NOT NULL,
                 b TEXT NOT NULL,
                 createdAt INTEGER NOT NULL,
                 PRIMARY KEY(a, b),
                 CHECK(a < b)
               )""",
            "CREATE INDEX idx_connections_b ON connections(b)",
            """CREATE TABLE links(
                 linkId TEXT PRIMARY KEY,
                 kind TEXT NOT NULL CHECK(kind IN ('connect','register','enrol','setup')),
                 creatorUserId TEXT,
                 createdAt INTEGER NOT NULL,
                 expiresAt INTEGER NOT NULL,
                 offer TEXT NOT NULL,
                 tokenHash TEXT,
                 boundEmailHash TEXT,
                 state TEXT NOT NULL CHECK(state IN ('open','answered','revoked','expired')),
                 stateChangedAt INTEGER,
                 answererUserId TEXT,
                 answer TEXT,
                 answeredAt INTEGER,
                 deliveredAt INTEGER,
                 reveal TEXT
               )""",
            "CREATE INDEX idx_links_creator ON links(creatorUserId)",
            """CREATE TABLE device_links(
                 linkId TEXT PRIMARY KEY,
                 userId TEXT NOT NULL REFERENCES users(userId),
                 deviceId TEXT NOT NULL,
                 state TEXT NOT NULL CHECK(state IN ('open','claimed','revealed','approved')),
                 expiresAt INTEGER NOT NULL,
                 nPub TEXT,
                 claimName TEXT,
                 claimPlatform TEXT,
                 commitN TEXT,
                 claimMac TEXT,
                 nonceE TEXT,
                 nonceN TEXT,
                 proofHash TEXT,
                 outer TEXT,
                 inner TEXT,
                 approveMac TEXT,
                 approvedBy TEXT,
                 createdAt INTEGER NOT NULL,
                 claimedAt INTEGER,
                 revealedAt INTEGER,
                 approvedAt INTEGER
               )""",
            "CREATE INDEX idx_device_links_user ON device_links(userId)",
            "CREATE INDEX idx_device_links_device ON device_links(deviceId)",
            // ---- the instance ----
            // The values `andvari setup` wrote (spec 03 §17.1); one row.
            """CREATE TABLE instance_setup(
                 id INTEGER PRIMARY KEY CHECK(id=1),
                 instanceId TEXT NOT NULL,
                 name TEXT NOT NULL
               )""",
            // `operatorId`, `name` and `recoveryFp` mirror the verified card's fields for the server's own use.
            """CREATE TABLE instance_cards(
                 seq INTEGER PRIMARY KEY,
                 hash TEXT NOT NULL,
                 frame TEXT NOT NULL,
                 operatorId TEXT NOT NULL,
                 name TEXT NOT NULL,
                 recoveryFp TEXT NOT NULL,
                 storedAt INTEGER NOT NULL
               )""",
            """CREATE TABLE recovery_rotations(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 hash TEXT UNIQUE NOT NULL,
                 frame TEXT NOT NULL,
                 fromFp TEXT NOT NULL,
                 toFp TEXT NOT NULL,
                 storedAt INTEGER NOT NULL
               )""",
            // ---- sign-up and assisted recovery ----
            """CREATE TABLE signup_codes(
                 emailHash TEXT PRIMARY KEY,
                 codeMac TEXT NOT NULL,
                 expiresAt INTEGER NOT NULL,
                 attempts INTEGER NOT NULL DEFAULT 0
               )""",
            """CREATE TABLE signup_tickets(
                 ticketHash TEXT PRIMARY KEY,
                 emailHash TEXT NOT NULL,
                 expiresAt INTEGER NOT NULL,
                 usedAt INTEGER
               )""",
            // userId is NULL on a decoy (spec 03 §18.1): a request for an unknown or private-posture address,
            // or one over the per-address cap, stored so that poll, verify and commit answer alike; never verifiable.
            // commitHash is the hash of the newest answer's commit value, uploaded beside it (spec 03 §18.6). Wrong
            // commit values are audited and never counted, so the commitAttempts column an earlier development build
            // had is retired ([RETIRED_COLUMNS]). cancelledAt is when the account's owner cancelled a request that
            // had not passed its mailed code (a password change, the recovery setting switched to private, a recovery):
            // the state stays `unverified`, so its poll answers as before the owner acted, and the cancel is told only
            // at the code step (spec 03 §18.2). Added 2026-11-17, by the start-up step on an older database.
            """CREATE TABLE recovery_requests(
                 requestId TEXT PRIMARY KEY,
                 userId TEXT REFERENCES users(userId),
                 emailHash TEXT NOT NULL,
                 rPub TEXT NOT NULL,
                 pollHash TEXT NOT NULL,
                 platform TEXT NOT NULL,
                 codeMac TEXT,
                 codeExpiresAt INTEGER,
                 attempts INTEGER NOT NULL DEFAULT 0,
                 state TEXT NOT NULL CHECK(state IN ('unverified','verified','vetoed','fulfilled')),
                 createdAt INTEGER NOT NULL,
                 verifiedAt INTEGER,
                 holdEndsAt INTEGER,
                 sealed TEXT,
                 commitHash TEXT,
                 cancelledAt INTEGER
               )""",
            "CREATE INDEX idx_recovery_requests_user ON recovery_requests(userId)",
            // The mailbox values (spec 03 §18.1): every code mail of a recovery request carries one, and a request that
            // names one of its address, unused and unexpired, is taken past the address's daily five. Only the value's
            // hash is kept (keyed, with the address's hash inside it), with the address's hash and the value's expiry
            // (seven days). A row goes when its value is used, when it expires, and with every other row of its address
            // when that address's account is deleted or its recovery completes. Added 2026-11-17, by the start-up step on
            // an older database.
            """CREATE TABLE recovery_mailbox_values(
                 valueHash TEXT PRIMARY KEY,
                 emailHash TEXT NOT NULL,
                 expiresAt INTEGER NOT NULL
               )""",
            "CREATE INDEX idx_recovery_mailbox_values_email ON recovery_mailbox_values(emailHash)",
            // ---- mail, audit, policy ----
            """CREATE TABLE mail_outbox(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 template TEXT NOT NULL,
                 recipient TEXT NOT NULL,
                 subject TEXT NOT NULL,
                 text TEXT NOT NULL,
                 html TEXT NOT NULL,
                 createdAt INTEGER NOT NULL,
                 attempts INTEGER NOT NULL DEFAULT 0,
                 nextAttemptAt INTEGER NOT NULL,
                 lastErrorClass TEXT,
                 discardAt INTEGER NOT NULL
               )""",
            """CREATE TABLE audit(
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 at INTEGER NOT NULL,
                 type TEXT NOT NULL,
                 userId TEXT,
                 deviceId TEXT,
                 ip TEXT,
                 meta TEXT
               )""",
            "CREATE INDEX idx_audit_user ON audit(userId)",
            "CREATE INDEX idx_audit_type_at ON audit(type, at)",
            "CREATE TABLE policies(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL)",
            "INSERT INTO meta(key,value) VALUES('baseline','$BASELINE')",
            "INSERT INTO meta(key,value) VALUES('oldestRetainedRev','0')",
        )
    }
}
