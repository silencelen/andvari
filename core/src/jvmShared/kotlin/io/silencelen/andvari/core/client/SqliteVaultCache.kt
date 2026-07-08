package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * Durable client cache (spec 02 §8): item ENVELOPES, grant/vault rows, sync cursor,
 * and the outbound queue at rest — every persisted field is a subset of the spec 02
 * §5 server-visible table, so the client-at-rest surface ⊆ server-at-rest by
 * construction. The decrypted working set stays in an in-memory map exactly like
 * [InMemoryVaultCache]; plaintext never touches disk. One file per account
 * (`vault-<userId>.db`), deleted on sign-out, retained on lock (spec 05 T3).
 *
 * Thread-safe via a ReentrantLock (ViewModel coroutines and the autofill service may
 * interleave); [atomically] additionally wraps a whole pull application in one SQLite
 * transaction so a 410 resync replacement commits all-or-nothing.
 */
class SqliteVaultCache(private val db: SqlBox, private val accountUserId: String) : VaultCache {
    private val lock = ReentrantLock()
    private val items = LinkedHashMap<String, VaultItem>()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val idList = ListSerializer(String.serializer())

    init {
        migrate()
        // Same-file/different-account sanity (defense in depth on top of per-user names):
        // a mismatch wipes EVERYTHING including the queue (it belongs to another account).
        val owner = kv("userId")
        if (owner == null) {
            db.exec("INSERT OR REPLACE INTO kv(key,value) VALUES('userId',?)", accountUserId)
        } else if (owner != accountUserId) {
            db.tx {
                db.exec("DELETE FROM items"); db.exec("DELETE FROM grants"); db.exec("DELETE FROM vaults")
                db.exec("DELETE FROM queue"); db.exec("DELETE FROM kv")
                db.exec("DELETE FROM held"); db.exec("DELETE FROM consumed_delete_ids"); db.exec("DELETE FROM transfer_seq")
                db.exec("INSERT INTO kv(key,value) VALUES('userId',?)", accountUserId)
            }
        }
    }

    private fun migrate() {
        if (db.userVersion == 0) {
            db.tx {
                db.exec("CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                db.exec(
                    """CREATE TABLE IF NOT EXISTS items(itemId TEXT PRIMARY KEY, vaultId TEXT NOT NULL,
                       rev INTEGER NOT NULL, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL,
                       deleted INTEGER NOT NULL, conflict INTEGER NOT NULL, formatVersion INTEGER NOT NULL,
                       attachmentIds TEXT NOT NULL, blob TEXT)""",
                )
                db.exec("CREATE INDEX IF NOT EXISTS items_vault ON items(vaultId)")
                db.exec(
                    """CREATE TABLE IF NOT EXISTS grants(vaultId TEXT PRIMARY KEY, userId TEXT NOT NULL,
                       role TEXT NOT NULL, wrappedVk TEXT NOT NULL, rev INTEGER NOT NULL, sealedVk TEXT)""",
                )
                db.exec(
                    """CREATE TABLE IF NOT EXISTS vaults(vaultId TEXT PRIMARY KEY, type TEXT NOT NULL,
                       rev INTEGER NOT NULL, metaBlob TEXT NOT NULL, createdAt INTEGER NOT NULL)""",
                )
                db.exec(
                    """CREATE TABLE IF NOT EXISTS queue(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                       mutationId TEXT NOT NULL UNIQUE, vaultId TEXT NOT NULL, json TEXT NOT NULL)""",
                )
            }
            db.userVersion = 1
        }
        if (db.userVersion == 1) {
            // v2 (client 0.5.0, spec 03 §11): the durable holding area + replay-protection
            // state, plus the queue's staged-denied flag (a denied mutation awaiting its
            // park-vs-genuine verdict from a fresh pull — must survive process death, F21).
            // `held.json` is a serialized HeldVaultRecord — ciphertext/wire material only
            // (the decrypted name is deliberately not part of the record), so the spec 02
            // §8 at-rest surface is unchanged.
            db.tx {
                db.exec("CREATE TABLE IF NOT EXISTS held(vaultId TEXT PRIMARY KEY, json TEXT NOT NULL, expungeAt INTEGER NOT NULL)")
                db.exec("CREATE TABLE IF NOT EXISTS consumed_delete_ids(deleteId TEXT PRIMARY KEY)")
                db.exec("CREATE TABLE IF NOT EXISTS transfer_seq(vaultId TEXT PRIMARY KEY, seq INTEGER NOT NULL)")
                db.exec("ALTER TABLE queue ADD COLUMN staged INTEGER NOT NULL DEFAULT 0")
            }
            db.userVersion = 2
        }
    }

    private fun kv(key: String): String? =
        db.query("SELECT value FROM kv WHERE key=?", key) { it.string(0) }.firstOrNull()

    override fun cursor(): Long = lock.withLock { kv("cursor")?.toLongOrNull() ?: 0L }

    override fun setCursor(rev: Long): Unit = lock.withLock {
        db.exec("INSERT OR REPLACE INTO kv(key,value) VALUES('cursor',?)", rev.toString())
    }

    override fun upsertItem(wire: WireItem, item: VaultItem?): Unit = lock.withLock {
        db.exec(
            """INSERT OR REPLACE INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,conflict,formatVersion,attachmentIds,blob)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            wire.itemId, wire.vaultId, wire.rev, wire.createdAt, wire.updatedAt,
            if (wire.deleted) 1 else 0, if (wire.conflict) 1 else 0, wire.formatVersion,
            json.encodeToString(idList, wire.attachmentIds), wire.blob,
        )
        if (item != null) items[wire.itemId] = item else items.remove(wire.itemId)
    }

    override fun deleteItem(itemId: String): Unit = lock.withLock {
        items.remove(itemId)
        db.exec("DELETE FROM items WHERE itemId=?", itemId)
    }

    override fun allItems(): List<VaultItem> = lock.withLock { items.values.toList() }
    override fun getItem(itemId: String): VaultItem? = lock.withLock { items[itemId] }

    override fun envelopes(): List<WireItem> = lock.withLock {
        db.query("SELECT itemId,vaultId,rev,createdAt,updatedAt,deleted,conflict,formatVersion,attachmentIds,blob FROM items") { r ->
            WireItem(
                itemId = r.string(0)!!, vaultId = r.string(1)!!, rev = r.long(2),
                createdAt = r.long(3), updatedAt = r.long(4),
                deleted = r.int(5) != 0, conflict = r.int(6) != 0, formatVersion = r.int(7),
                attachmentIds = json.decodeFromString(idList, r.string(8)!!), blob = r.string(9),
            )
        }
    }

    override fun upsertGrant(grant: WireGrant): Unit = lock.withLock {
        db.exec(
            "INSERT OR REPLACE INTO grants(vaultId,userId,role,wrappedVk,rev,sealedVk) VALUES(?,?,?,?,?,?)",
            grant.vaultId, grant.userId, grant.role, grant.wrappedVk, grant.rev, grant.sealedVk,
        )
    }

    override fun grants(): List<WireGrant> = lock.withLock {
        db.query("SELECT vaultId,userId,role,wrappedVk,rev,sealedVk FROM grants") { r ->
            WireGrant(r.string(0)!!, r.string(1)!!, r.string(2)!!, r.string(3)!!, r.long(4), r.string(5))
        }
    }

    override fun upsertVault(vault: WireVault): Unit = lock.withLock {
        db.exec(
            "INSERT OR REPLACE INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)",
            vault.vaultId, vault.type, vault.rev, vault.metaBlob, vault.createdAt,
        )
    }

    override fun vaults(): List<WireVault> = lock.withLock {
        db.query("SELECT vaultId,type,rev,metaBlob,createdAt FROM vaults") { r ->
            WireVault(r.string(0)!!, r.string(1)!!, r.long(2), r.string(3)!!, r.long(4))
        }
    }

    override fun dropVault(vaultId: String): Unit = lock.withLock {
        items.values.filter { it.vaultId == vaultId }.map { it.itemId }.forEach { items.remove(it) }
        db.exec("DELETE FROM items WHERE vaultId=?", vaultId)
        db.exec("DELETE FROM grants WHERE vaultId=?", vaultId)
        db.exec("DELETE FROM vaults WHERE vaultId=?", vaultId)
    }

    override fun clear(): Unit = lock.withLock {
        items.clear()
        db.exec("DELETE FROM items"); db.exec("DELETE FROM grants"); db.exec("DELETE FROM vaults")
        db.exec("INSERT OR REPLACE INTO kv(key,value) VALUES('cursor','0')")
    }

    override fun atomically(block: () -> Unit): Unit = lock.withLock { db.tx(block) }

    override fun evictDecrypted(): Unit = lock.withLock { items.clear() } // durable rows kept

    override fun close(): Unit = lock.withLock { db.close() }

    override fun enqueue(mutation: Mutation): Unit = lock.withLock {
        // INSERT OR REPLACE also resets staged=0: a re-enqueue (reinstate replay) returns
        // the row to the pushable state.
        db.exec(
            "INSERT OR REPLACE INTO queue(mutationId,vaultId,json,staged) VALUES(?,?,?,0)",
            mutation.mutationId, mutation.vaultId, json.encodeToString(Mutation.serializer(), mutation),
        )
    }

    override fun pending(): List<Mutation> = lock.withLock {
        db.query("SELECT json FROM queue WHERE staged=0 ORDER BY seq") { r ->
            json.decodeFromString(Mutation.serializer(), r.string(0)!!)
        }
    }

    override fun dequeue(mutationId: String): Unit = lock.withLock {
        db.exec("DELETE FROM queue WHERE mutationId=?", mutationId)
    }

    override fun dropPending(vaultId: String): Unit = lock.withLock {
        db.exec("DELETE FROM queue WHERE vaultId=?", vaultId)
    }

    override fun markStagedDenied(mutationId: String): Unit = lock.withLock {
        db.exec("UPDATE queue SET staged=1 WHERE mutationId=?", mutationId)
    }

    override fun stagedDenied(): List<Mutation> = lock.withLock {
        db.query("SELECT json FROM queue WHERE staged=1 ORDER BY seq") { r ->
            json.decodeFromString(Mutation.serializer(), r.string(0)!!)
        }
    }

    // ---- vault lifecycle (spec 03 §11) — durable: the holding area's retention promise
    // and the replay floors must survive process restarts. NOT wiped by [clear] (like the
    // queue: safety state a 410 resync must not erase).

    override fun putHeld(held: HeldVaultRecord): Unit = lock.withLock {
        db.exec(
            "INSERT OR REPLACE INTO held(vaultId,json,expungeAt) VALUES(?,?,?)",
            held.vault.vaultId, json.encodeToString(HeldVaultRecord.serializer(), held), held.expungeAt,
        )
    }

    override fun getHeld(vaultId: String): HeldVaultRecord? = lock.withLock {
        db.query("SELECT json FROM held WHERE vaultId=?", vaultId) { r ->
            json.decodeFromString(HeldVaultRecord.serializer(), r.string(0)!!)
        }.firstOrNull()
    }

    override fun heldVaults(): List<HeldVaultRecord> = lock.withLock {
        db.query("SELECT json FROM held") { r ->
            json.decodeFromString(HeldVaultRecord.serializer(), r.string(0)!!)
        }
    }

    override fun removeHeld(vaultId: String): Unit = lock.withLock {
        db.exec("DELETE FROM held WHERE vaultId=?", vaultId)
    }

    override fun addConsumedDeleteId(deleteId: String): Unit = lock.withLock {
        db.exec("INSERT OR REPLACE INTO consumed_delete_ids(deleteId) VALUES(?)", deleteId)
    }

    override fun isConsumedDeleteId(deleteId: String): Boolean = lock.withLock {
        db.query("SELECT deleteId FROM consumed_delete_ids WHERE deleteId=?", deleteId) { it.string(0) }.isNotEmpty()
    }

    override fun lastVerifiedTransferSeq(vaultId: String): Long = lock.withLock {
        db.query("SELECT seq FROM transfer_seq WHERE vaultId=?", vaultId) { it.long(0) }.firstOrNull() ?: 0L
    }

    override fun setLastVerifiedTransferSeq(vaultId: String, seq: Long): Unit = lock.withLock {
        db.exec("INSERT OR REPLACE INTO transfer_seq(vaultId,seq) VALUES(?,?)", vaultId, seq)
    }
}

/** Factory: open (or create) the per-account durable cache at [path]. */
fun sqliteVaultCache(path: String, userId: String): VaultCache = SqliteVaultCache(openSqlBox(path), userId)
