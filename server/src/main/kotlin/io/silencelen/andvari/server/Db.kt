package io.silencelen.andvari.server

import java.sql.Connection
import java.sql.DriverManager
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Single-connection SQLite (WAL). One writer is all this deployment needs; the
 * lock serializes access so transactions never interleave. Route handlers call
 * through Dispatchers.IO. Deliberately plain JDBC — ~14 tables, hand-auditable SQL
 * (the client cache in :core will use SQLDelight; the server does not need codegen).
 */
class Db(path: String) : AutoCloseable {
    private val conn: Connection = DriverManager.getConnection("jdbc:sqlite:$path")
    private val lock = ReentrantLock()

    init {
        conn.autoCommit = true
        conn.createStatement().use { st ->
            st.execute("PRAGMA journal_mode=WAL")
            st.execute("PRAGMA foreign_keys=ON")
            st.execute("PRAGMA busy_timeout=5000")
            st.execute("PRAGMA synchronous=NORMAL")
        }
        migrate()
    }

    /** Serialized read-write transaction. */
    fun <T> tx(block: (Connection) -> T): T = lock.withLock {
        conn.autoCommit = false
        try {
            val result = block(conn)
            conn.commit()
            result
        } catch (t: Throwable) {
            conn.rollback()
            throw t
        } finally {
            conn.autoCommit = true
        }
    }

    /** Serialized read (WAL snapshot semantics are irrelevant under one connection). */
    fun <T> read(block: (Connection) -> T): T = lock.withLock { block(conn) }

    override fun close() {
        lock.withLock { conn.close() }
    }

    private fun migrate() {
        val version = conn.createStatement().use { st ->
            st.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            st.executeQuery("SELECT value FROM meta WHERE key='schemaVersion'").use { rs ->
                if (rs.next()) rs.getString(1).toInt() else 0
            }
        }
        if (version < 1) {
            tx { c ->
                c.createStatement().use { st ->
                    st.executeUpdate(
                        """
                        CREATE TABLE users(
                          userId TEXT PRIMARY KEY,
                          email TEXT UNIQUE NOT NULL,
                          displayName TEXT NOT NULL,
                          kdfSalt TEXT NOT NULL,
                          kdfParams TEXT NOT NULL,
                          verifier TEXT NOT NULL,
                          wrappedUvk TEXT NOT NULL,
                          identityPub TEXT NOT NULL,
                          encryptedIdentitySeed TEXT NOT NULL,
                          isAdmin INTEGER NOT NULL DEFAULT 0,
                          status TEXT NOT NULL DEFAULT 'active',
                          mustChangePassword INTEGER NOT NULL DEFAULT 0,
                          createdAt INTEGER NOT NULL
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE invites(
                          tokenHash TEXT PRIMARY KEY,
                          email TEXT NOT NULL,
                          isAdmin INTEGER NOT NULL DEFAULT 0,
                          createdAt INTEGER NOT NULL,
                          expiresAt INTEGER NOT NULL,
                          usedAt INTEGER
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE devices(
                          deviceId TEXT PRIMARY KEY,
                          userId TEXT NOT NULL REFERENCES users(userId),
                          platform TEXT NOT NULL,
                          name TEXT NOT NULL,
                          clientVersion TEXT,
                          createdAt INTEGER NOT NULL,
                          lastSeenAt INTEGER,
                          revokedAt INTEGER
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE sessions(
                          sessionId TEXT PRIMARY KEY,
                          deviceId TEXT NOT NULL REFERENCES devices(deviceId),
                          userId TEXT NOT NULL,
                          accessHash TEXT UNIQUE NOT NULL,
                          accessExpiresAt INTEGER NOT NULL,
                          refreshHash TEXT UNIQUE NOT NULL,
                          refreshExpiresAt INTEGER NOT NULL,
                          refreshConsumedAt INTEGER,
                          createdAt INTEGER NOT NULL,
                          revokedAt INTEGER
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE vaults(
                          vaultId TEXT PRIMARY KEY,
                          type TEXT NOT NULL,
                          rev INTEGER NOT NULL,
                          metaBlob TEXT NOT NULL,
                          createdAt INTEGER NOT NULL
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE grants(
                          vaultId TEXT NOT NULL REFERENCES vaults(vaultId),
                          userId TEXT NOT NULL REFERENCES users(userId),
                          role TEXT NOT NULL,
                          wrappedVk TEXT NOT NULL,
                          rev INTEGER NOT NULL,
                          revokedAt INTEGER,
                          PRIMARY KEY(vaultId, userId)
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE items(
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
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate("CREATE INDEX idx_items_vault_rev ON items(vaultId, rev)")
                    st.executeUpdate(
                        """
                        CREATE TABLE item_versions(
                          itemId TEXT NOT NULL,
                          rev INTEGER NOT NULL,
                          blob TEXT NOT NULL,
                          formatVersion INTEGER NOT NULL,
                          archivedAt INTEGER NOT NULL,
                          PRIMARY KEY(itemId, rev)
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE changes(
                          rev INTEGER PRIMARY KEY AUTOINCREMENT,
                          kind TEXT NOT NULL,
                          entityId TEXT NOT NULL,
                          vaultId TEXT,
                          at INTEGER NOT NULL
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE mutations(
                          deviceId TEXT NOT NULL,
                          mutationId TEXT NOT NULL,
                          resultJson TEXT NOT NULL,
                          createdAt INTEGER NOT NULL,
                          PRIMARY KEY(deviceId, mutationId)
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE escrow(
                          userId TEXT PRIMARY KEY REFERENCES users(userId),
                          sealed TEXT NOT NULL,
                          fingerprint TEXT NOT NULL,
                          updatedAt INTEGER NOT NULL
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate(
                        """
                        CREATE TABLE audit(
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          at INTEGER NOT NULL,
                          type TEXT NOT NULL,
                          userId TEXT,
                          deviceId TEXT,
                          ip TEXT,
                          meta TEXT
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate("CREATE TABLE policies(id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL)")
                    st.executeUpdate(
                        """
                        CREATE TABLE hibp_cache(
                          prefix TEXT PRIMARY KEY,
                          body TEXT NOT NULL,
                          fetchedAt INTEGER NOT NULL
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate("INSERT INTO meta(key,value) VALUES('oldestRetainedRev','0')")
                    st.executeUpdate("INSERT INTO meta(key,value) VALUES('schemaVersion','1')")
                }
            }
        }
        if (version < 2) {
            tx { c ->
                c.createStatement().use { st ->
                    // Attachments (spec 02 §6): ciphertext chunks live on disk in blobDir;
                    // this row is the server-visible plaintext contract (spec 02 §5).
                    st.executeUpdate(
                        """
                        CREATE TABLE attachments(
                          attachmentId TEXT PRIMARY KEY,
                          itemId TEXT NOT NULL,
                          vaultId TEXT NOT NULL,
                          size INTEGER NOT NULL,
                          sha256 TEXT NOT NULL,
                          header TEXT NOT NULL,
                          createdAt INTEGER NOT NULL
                        )
                        """.trimIndent(),
                    )
                    st.executeUpdate("CREATE INDEX idx_attachments_item ON attachments(itemId)")
                    st.executeUpdate("CREATE INDEX idx_attachments_vault ON attachments(vaultId)")
                    // Server-side TOTP second factor (spec 03 §2, break-glass hardening).
                    // These are server 2FA secrets, NOT vault data — documented in spec 02 §5.
                    st.executeUpdate("ALTER TABLE users ADD COLUMN totpSecret TEXT")
                    st.executeUpdate("ALTER TABLE users ADD COLUMN totpPendingSecret TEXT")
                    st.executeUpdate("ALTER TABLE users ADD COLUMN totpEnrolledAt INTEGER")
                    st.executeUpdate("ALTER TABLE users ADD COLUMN totpLastStep INTEGER NOT NULL DEFAULT 0")
                    st.executeUpdate("UPDATE meta SET value='2' WHERE key='schemaVersion'")
                }
            }
        }
        if (version < 3) {
            tx { c ->
                c.createStatement().use { st ->
                    // Shared vaults (spec 01 §6 / spec 03 §10). Additive + O(1) on the live
                    // v2 DB: ALTER ADD COLUMN with no default rewrite; existing grants read
                    // back sealedVk=NULL → wire null → identical semantics to today. The
                    // member-grant carrier; wrappedVk stays NOT NULL ('' for member grants).
                    st.executeUpdate("ALTER TABLE grants ADD COLUMN sealedVk TEXT")
                    // Join-time (epoch ms). Pre-v3 rows read back NULL → summaries COALESCE to 0.
                    st.executeUpdate("ALTER TABLE grants ADD COLUMN addedAt INTEGER")
                    st.executeUpdate("CREATE INDEX idx_grants_user ON grants(userId)")
                    st.executeUpdate("UPDATE meta SET value='3' WHERE key='schemaVersion'")
                }
            }
        }
        if (version < 4) {
            tx { c ->
                c.createStatement().use { st ->
                    // Shared-vault lifecycle "Skipti" (spec 02 §4/§7, spec 03 §11; design
                    // docs/design/2026-07-07-shared-vault-lifecycle-skipti.md §9). All
                    // additive O(1) ALTERs; pre-v4 rows read back NULL with unchanged
                    // semantics (revokedReason NULL renders as member_remove). No NOT NULL
                    // additions except the constant-default transferSeq. Vault rows are
                    // NEVER hard-deleted post-v4 (vaultId never recycled) — the
                    // vault_mismatch fence and mutation dedup depend on it.
                    // meta.oldestRetainedRev stays '0' — untouched by this feature.
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN deletedAt INTEGER")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN purgeAt INTEGER")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN purgedAt INTEGER")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN deletedBy TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN deleteId TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN deleteProof TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN restoreProof TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN transferSeq INTEGER NOT NULL DEFAULT 0")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN pendingOwnerId TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN pendingOfferId TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN pendingOfferProof TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN pendingOfferExpiresAt INTEGER")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN pendingOfferSetAt INTEGER")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN lastTransferOfferId TEXT")
                    st.executeUpdate("ALTER TABLE vaults ADD COLUMN lastTransferAcceptProof TEXT")
                    st.executeUpdate("ALTER TABLE grants ADD COLUMN revokedReason TEXT")
                    // Removal proof + nonce (spec 03 §3/§5): minted by the removing owner's
                    // client, stored on the victim's revoked grant row, relayed durably via
                    // removedGrantsInfo so a 0.5.0 victim can attribute the removal even
                    // across a server restart (no in-memory relay).
                    st.executeUpdate("ALTER TABLE grants ADD COLUMN removeProof TEXT")
                    st.executeUpdate("ALTER TABLE grants ADD COLUMN removeNonce TEXT")
                    st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_vaults_purge ON vaults(purgeAt) WHERE purgeAt IS NOT NULL")
                    st.executeUpdate("UPDATE meta SET value='4' WHERE key='schemaVersion'")
                }
            }
        }
        if (version < 5) {
            tx { c ->
                c.createStatement().use { st ->
                    // F56 (guided-importers perf pack): tombstone partial index. The F49
                    // janitor retention scan (`deleted=1 AND updatedAt<?`) was a full items
                    // SCAN that grows with vault size forever, while tombstones stay bounded
                    // at 30 days — measured 9 ms → 0.34 ms at 10k items / 200 tombstones
                    // (perf addendum §4). Partial index = O(tombstones) storage, no write
                    // cost on the hot put path (live rows are outside the predicate).
                    // Additive O(n-scan-once) migration; no wire or behavior change.
                    st.executeUpdate("CREATE INDEX IF NOT EXISTS idx_items_deleted_updated ON items(updatedAt) WHERE deleted=1")
                    st.executeUpdate("UPDATE meta SET value='5' WHERE key='schemaVersion'")
                }
            }
        }
    }
}
