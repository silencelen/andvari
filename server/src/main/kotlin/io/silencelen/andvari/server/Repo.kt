package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.AuditEvent
import io.silencelen.andvari.core.model.DeletedItem
import io.silencelen.andvari.core.model.ItemVersion
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.RemovedGrantInfo
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.ResultSet

val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

private val stringList = ListSerializer(String.serializer())
fun encodeIds(ids: List<String>): String = json.encodeToString(stringList, ids)
fun decodeIds(text: String): List<String> = json.decodeFromString(stringList, text)
fun encodeParams(p: KdfParams): String = json.encodeToString(KdfParams.serializer(), p)
fun decodeParams(text: String): KdfParams = json.decodeFromString(KdfParams.serializer(), text)

fun now(): Long = System.currentTimeMillis()

/** hexLower(sha256(utf8(s))) — the accept-proof wrap binding (spec 03 §11); matches
 *  LifecycleProof.accept's `Bytes.toHexLower(crypto.sha256(wrappedVk.encodeToByteArray()))`. */
fun sha256HexUtf8(s: String): String =
    Bytes.toHexLower(MessageDigest.getInstance("SHA-256").digest(s.encodeToByteArray()))

// ---- tiny JDBC helpers ----

private fun PreparedStatement.bind(vararg args: Any?): PreparedStatement {
    args.forEachIndexed { i, a ->
        when (a) {
            null -> setObject(i + 1, null)
            is String -> setString(i + 1, a)
            is Long -> setLong(i + 1, a)
            is Int -> setInt(i + 1, a)
            is Boolean -> setInt(i + 1, if (a) 1 else 0)
            else -> error("unsupported bind type ${a::class}")
        }
    }
    return this
}

fun Connection.exec(sql: String, vararg args: Any?): Int =
    prepareStatement(sql).use { it.bind(*args).executeUpdate() }

fun <T> Connection.queryOne(sql: String, vararg args: Any?, map: (ResultSet) -> T): T? =
    prepareStatement(sql).use { st ->
        st.bind(*args).executeQuery().use { rs -> if (rs.next()) map(rs) else null }
    }

fun <T> Connection.queryAll(sql: String, vararg args: Any?, map: (ResultSet) -> T): List<T> =
    prepareStatement(sql).use { st ->
        st.bind(*args).executeQuery().use { rs ->
            buildList { while (rs.next()) add(map(rs)) }
        }
    }

fun Connection.lastRowId(): Long =
    queryOne("SELECT last_insert_rowid()") { it.getLong(1) } ?: error("last_insert_rowid failed")

// ---- rows ----

class UserRow(
    val userId: String,
    val email: String,
    val displayName: String,
    val kdfSalt: String,
    val kdfParams: KdfParams,
    val verifier: String,
    val wrappedUvk: String,
    val identityPub: String,
    val encryptedIdentitySeed: String,
    val isAdmin: Boolean,
    val status: String,
    val mustChangePassword: Boolean,
    val createdAt: Long,
    val totpSecret: String?,
    val totpPendingSecret: String?,
    val totpLastStep: Long,
)

/** The per-member self-service recovery row (design 2026-07-12 §F): UVK ciphertext + a one-way
 *  hash of recoveryAuthKey. Held server-side, opaque — the symmetric counterpart to `escrow`. */
class MemberRecoveryRow(
    val userId: String,
    val recoveryWrappedUvk: String,
    val recoveryVerifier: String,
)

private fun memberRecoveryRowOf(rs: ResultSet) = MemberRecoveryRow(
    userId = rs.getString("userId"),
    recoveryWrappedUvk = rs.getString("recoveryWrappedUvk"),
    recoveryVerifier = rs.getString("recoveryVerifier"),
)

fun userRowPublic(rs: ResultSet) = userRow(rs)

private fun userRow(rs: ResultSet) = UserRow(
    userId = rs.getString("userId"),
    email = rs.getString("email"),
    displayName = rs.getString("displayName"),
    kdfSalt = rs.getString("kdfSalt"),
    kdfParams = decodeParams(rs.getString("kdfParams")),
    verifier = rs.getString("verifier"),
    wrappedUvk = rs.getString("wrappedUvk"),
    identityPub = rs.getString("identityPub"),
    encryptedIdentitySeed = rs.getString("encryptedIdentitySeed"),
    isAdmin = rs.getInt("isAdmin") != 0,
    status = rs.getString("status"),
    mustChangePassword = rs.getInt("mustChangePassword") != 0,
    createdAt = rs.getLong("createdAt"),
    totpSecret = rs.getString("totpSecret"),
    totpPendingSecret = rs.getString("totpPendingSecret"),
    totpLastStep = rs.getLong("totpLastStep"),
)

class SessionRow(
    val sessionId: String,
    val deviceId: String,
    val userId: String,
    val accessExpiresAt: Long,
    val refreshExpiresAt: Long,
    val refreshConsumedAt: Long?,
    val revokedAt: Long?,
)

private fun sessionRow(rs: ResultSet) = SessionRow(
    sessionId = rs.getString("sessionId"),
    deviceId = rs.getString("deviceId"),
    userId = rs.getString("userId"),
    accessExpiresAt = rs.getLong("accessExpiresAt"),
    refreshExpiresAt = rs.getLong("refreshExpiresAt"),
    refreshConsumedAt = rs.getLong("refreshConsumedAt").let { if (rs.wasNull()) null else it },
    revokedAt = rs.getLong("revokedAt").let { if (rs.wasNull()) null else it },
)

/** Full vault row incl. the v4 lifecycle/transfer columns (spec 02 §4). */
class VaultRow(
    val vaultId: String,
    val type: String,
    val rev: Long,
    val metaBlob: String,
    val createdAt: Long,
    val deletedAt: Long?,
    val purgeAt: Long?,
    val purgedAt: Long?,
    val deletedBy: String?,
    val deleteId: String?,
    val deleteProof: String?,
    val restoreProof: String?,
    val transferSeq: Long,
    val pendingOwnerId: String?,
    val pendingOfferId: String?,
    val pendingOfferProof: String?,
    val pendingOfferExpiresAt: Long?,
    val pendingOfferSetAt: Long?,
    val lastTransferOfferId: String?,
    val lastTransferAcceptProof: String?,
)

private fun ResultSet.longOrNull(col: String): Long? = getLong(col).let { if (wasNull()) null else it }

fun vaultRow(rs: ResultSet) = VaultRow(
    vaultId = rs.getString("vaultId"),
    type = rs.getString("type"),
    rev = rs.getLong("rev"),
    metaBlob = rs.getString("metaBlob"),
    createdAt = rs.getLong("createdAt"),
    deletedAt = rs.longOrNull("deletedAt"),
    purgeAt = rs.longOrNull("purgeAt"),
    purgedAt = rs.longOrNull("purgedAt"),
    deletedBy = rs.getString("deletedBy"),
    deleteId = rs.getString("deleteId"),
    deleteProof = rs.getString("deleteProof"),
    restoreProof = rs.getString("restoreProof"),
    transferSeq = rs.getLong("transferSeq"),
    pendingOwnerId = rs.getString("pendingOwnerId"),
    pendingOfferId = rs.getString("pendingOfferId"),
    pendingOfferProof = rs.getString("pendingOfferProof"),
    pendingOfferExpiresAt = rs.longOrNull("pendingOfferExpiresAt"),
    pendingOfferSetAt = rs.longOrNull("pendingOfferSetAt"),
    lastTransferOfferId = rs.getString("lastTransferOfferId"),
    lastTransferAcceptProof = rs.getString("lastTransferAcceptProof"),
)

/** A grant row INCLUDING revoked state — the lifecycle guard-order primitive (spec 03 §11):
 *  resolve the caller's grant FIRST so outsiders get a uniform 403 with no existence oracle. */
class GrantRowFull(
    val vaultId: String,
    val userId: String,
    val role: String,
    val wrappedVk: String,
    val sealedVk: String?,
    val rev: Long,
    val revokedAt: Long?,
    val revokedReason: String?,
    val addedAt: Long?,
)

fun grantRowFull(rs: ResultSet) = GrantRowFull(
    vaultId = rs.getString("vaultId"),
    userId = rs.getString("userId"),
    role = rs.getString("role"),
    wrappedVk = rs.getString("wrappedVk"),
    sealedVk = rs.getString("sealedVk"),
    rev = rs.getLong("rev"),
    revokedAt = rs.longOrNull("revokedAt"),
    revokedReason = rs.getString("revokedReason"),
    addedAt = rs.longOrNull("addedAt"),
)

fun itemRow(rs: ResultSet) = WireItem(
    itemId = rs.getString("itemId"),
    vaultId = rs.getString("vaultId"),
    rev = rs.getLong("rev"),
    createdAt = rs.getLong("createdAt"),
    updatedAt = rs.getLong("updatedAt"),
    deleted = rs.getInt("deleted") != 0,
    conflict = rs.getInt("conflict") != 0,
    formatVersion = rs.getInt("formatVersion"),
    attachmentIds = decodeIds(rs.getString("attachmentIds")),
    blob = rs.getString("blob"),
)

// ---- repo ----

class Repo(val db: Db) {

    /** healthz probe: proves the DB is readable/writable. */
    fun currentRevSafe(): Long = db.read { currentRev(it) }

    fun meta(key: String): String? = db.read { it.queryOne("SELECT value FROM meta WHERE key=?", key) { rs -> rs.getString(1) } }
    fun setMeta(key: String, value: String) = db.tx { it.exec("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value) }

    fun nextRev(c: Connection, kind: String, entityId: String, vaultId: String?): Long {
        c.exec("INSERT INTO changes(kind,entityId,vaultId,at) VALUES(?,?,?,?)", kind, entityId, vaultId, now())
        return c.lastRowId()
    }

    fun currentRev(c: Connection): Long =
        c.queryOne("SELECT COALESCE(MAX(rev),0) FROM changes") { it.getLong(1) } ?: 0

    fun oldestRetainedRev(c: Connection): Long =
        c.queryOne("SELECT value FROM meta WHERE key='oldestRetainedRev'") { it.getString(1).toLong() } ?: 0

    // users
    fun userByEmail(email: String): UserRow? =
        db.read { it.queryOne("SELECT * FROM users WHERE email=?", email.lowercase(), map = ::userRow) }

    fun userById(id: String): UserRow? =
        db.read { it.queryOne("SELECT * FROM users WHERE userId=?", id, map = ::userRow) }

    fun escrowFingerprint(userId: String): String? =
        db.read { it.queryOne("SELECT fingerprint FROM escrow WHERE userId=?", userId) { rs -> rs.getString(1) } }

    // member recovery (design 2026-07-12 §F) — the per-member self-service recovery row.
    fun memberRecoveryRow(userId: String): MemberRecoveryRow? =
        db.read { it.queryOne("SELECT userId,recoveryWrappedUvk,recoveryVerifier FROM member_recovery WHERE userId=?", userId, map = ::memberRecoveryRowOf) }

    /** True iff [userId] has a member_recovery row — drives AccountKeys.recoverySetupNeeded (the
     *  migration nudge, §F.2) and AdminUserSummary.recoveryEnrolled (posture reconciliation, §F.4). */
    fun hasMemberRecovery(userId: String): Boolean =
        db.read { it.queryOne("SELECT 1 FROM member_recovery WHERE userId=?", userId) { true } ?: false }

    /** design §F.9: the durable, cross-device capture-confirmation flag on the users row — drives
     *  AccountKeys.recoveryConfirmed. false ⇒ the client forces capture-and-confirm before vault
     *  access (closes the interrupted-reveal / migration silent-total-loss path). A missing user
     *  reads back false (fail-safe: nudge). */
    fun isRecoveryConfirmed(userId: String): Boolean =
        db.read { it.queryOne("SELECT recoveryConfirmed FROM users WHERE userId=?", userId) { rs -> rs.getInt(1) != 0 } ?: false }

    /** design §F.9: flip [userId]'s capture-confirmation flag to 1. Idempotent; takes the caller's
     *  Connection so it commits atomically with the confirm/self-setup audit row (like clearPendingOffer).
     *  Set by POST /recovery/self/confirm (enroll happy-path) and by recoverySelfSetup (explicit capture). */
    fun setRecoveryConfirmed(c: Connection, userId: String) {
        c.exec("UPDATE users SET recoveryConfirmed=1 WHERE userId=?", userId)
    }

    // sessions
    fun sessionByAccessHash(hash: String): SessionRow? = db.read {
        it.queryOne("SELECT * FROM sessions WHERE accessHash=?", hash, map = ::sessionRow)
    }

    fun sessionByRefreshHash(hash: String): SessionRow? = db.read {
        it.queryOne("SELECT * FROM sessions WHERE refreshHash=?", hash, map = ::sessionRow)
    }

    fun deviceRevoked(deviceId: String): Boolean = db.read {
        it.queryOne("SELECT revokedAt FROM devices WHERE deviceId=?", deviceId) { rs ->
            rs.getLong(1).let { v -> !rs.wasNull() && v > 0 }
        } ?: true
    }

    // sync pull (single read transaction for snapshot consistency)
    fun pull(userId: String, since: Long): io.silencelen.andvari.core.model.SyncResponse = db.read { c ->
        val rev = currentRev(c)
        // Backfill (spec 03 §4): deliver a vault/its items when the object's rev OR the
        // caller's grant rev on that vault exceeds `since`. A member added at a high rev
        // whose cursor already passed the vault's/items' own revs still gets them; a role
        // change (bumps grant rev) re-delivers the vault's items (idempotent upsert).
        // currentOwner/currentOwnerWrap feed lastTransfer (spec 03 §11): after an accepted
        // transfer the active owner grant IS the transferee, so no extra column is needed;
        // wrapHash lets EVERY member recompute the accept-proof domain (#3).
        val vaults = c.queryAll(
            """SELECT v.*,
                      (SELECT og.userId    FROM grants og WHERE og.vaultId=v.vaultId AND og.role='owner' AND og.revokedAt IS NULL) AS currentOwner,
                      (SELECT og.wrappedVk FROM grants og WHERE og.vaultId=v.vaultId AND og.role='owner' AND og.revokedAt IS NULL) AS currentOwnerWrap
               FROM vaults v JOIN grants g ON g.vaultId=v.vaultId
               WHERE g.userId=? AND g.revokedAt IS NULL AND (v.rev>? OR g.rev>?)""",
            userId, since, since,
        ) { rs ->
            val transferSeq = rs.getLong("transferSeq")
            val pendingOfferId = rs.getString("pendingOfferId")
            // seq the offer proof binds = transferSeq+1 at offer time; transferSeq only
            // advances at accept, which clears pending — so the invariant holds here.
            val pending = if (pendingOfferId != null) PendingTransfer(
                toUserId = rs.getString("pendingOwnerId"),
                offerId = pendingOfferId,
                proof = rs.getString("pendingOfferProof"),
                expiresAt = rs.getLong("pendingOfferExpiresAt"),
                seq = transferSeq + 1,
            ) else null
            val lastOfferId = rs.getString("lastTransferOfferId")
            val currentOwner = rs.getString("currentOwner")
            val currentOwnerWrap = rs.getString("currentOwnerWrap")
            val last = if (lastOfferId != null && currentOwner != null) TransferRecord(
                offerId = lastOfferId,
                newOwnerUserId = currentOwner,
                acceptProof = rs.getString("lastTransferAcceptProof"),
                seq = transferSeq,
                // hexLower(sha256(utf8(wrappedVk))) — matches LifecycleProof.accept's binding;
                // hashing an opaque ciphertext string is ZK-safe.
                wrapHash = currentOwnerWrap?.takeIf { it.isNotEmpty() }?.let { sha256HexUtf8(it) },
            ) else null
            // Restore consumption marker (#4): only on a LIVE vault that was restored
            // (deletedAt cleared, restoreProof + deleteId retained). Delivered vaults are
            // always live (delete revokes all grants → the vault drops out of this join),
            // so the deletedAt guard below is a belt.
            val isDeleted = rs.getLong("deletedAt").let { !rs.wasNull() }
            val restoreProof = if (!isDeleted) rs.getString("restoreProof") else null
            val consumedDeleteId = if (restoreProof != null) rs.getString("deleteId") else null
            WireVault(
                vaultId = rs.getString("vaultId"), type = rs.getString("type"),
                rev = rs.getLong("rev"), metaBlob = rs.getString("metaBlob"), createdAt = rs.getLong("createdAt"),
                pendingTransfer = pending, lastTransfer = last,
                restoreProof = restoreProof, deleteId = consumedDeleteId,
            )
        }
        val grants = c.queryAll(
            "SELECT * FROM grants WHERE userId=? AND revokedAt IS NULL AND rev>?",
            userId, since,
        ) { rs ->
            WireGrant(
                vaultId = rs.getString("vaultId"), userId = rs.getString("userId"),
                role = rs.getString("role"), wrappedVk = rs.getString("wrappedVk"), rev = rs.getLong("rev"),
                sealedVk = rs.getString("sealedVk"),
            )
        }
        // F56: the natural `(i.rev>? OR g.rev>?)` OR-join defeats idx_items_vault_rev's rev
        // bound (EQP: `SEARCH i (vaultId=?)` — a full per-vault scan on EVERY pull, ~2.7 ms
        // per no-op incremental pull at 10k items). Split into two DISJOINT arms — same rows,
        // both indexed (`vaultId=? AND rev>?` / `rev<=?`): arm 1 = normal delta; arm 2 = the
        // grant-rev backfill (new member / role change) delivering only the items arm 1's rev
        // bound excludes, so UNION ALL needs no dedup pass. Measured: no-op pull 2.7 ms →
        // 0.02 ms; 10-row delta 2.8 ms → 0.07 ms; full since=0 unchanged (perf addendum §2).
        val items = c.queryAll(
            """SELECT i.* FROM items i JOIN grants g ON g.vaultId=i.vaultId
               WHERE g.userId=? AND g.revokedAt IS NULL AND i.rev>?
               UNION ALL
               SELECT i.* FROM items i JOIN grants g ON g.vaultId=i.vaultId
               WHERE g.userId=? AND g.revokedAt IS NULL AND g.rev>? AND i.rev<=?""",
            userId, since, userId, since, since,
        ) { rs -> itemRow(rs) }
        // ONE scan of the caller's revoked grants (#9B): removedGrantsInfo is the detail,
        // removedGrants is derived as its vaultId list — the JOIN to vaults never drops a
        // row (vault rows are never hard-deleted post-v4). Reason derives from the CALLER's
        // own grant's revokedReason (a member removed before a later delete sees 'removed',
        // not 'deleted'; NULL pre-v4 → member_remove); tombstone fields ride only 'deleted',
        // removeProof/nonce only 'removed'/'left'.
        val removedInfo = c.queryAll(
            """SELECT g.vaultId, COALESCE(g.revokedReason,'member_remove') AS rr,
                      g.removeProof, g.removeNonce,
                      v.deletedAt, v.purgeAt, v.deleteId, v.deleteProof
               FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
               WHERE g.userId=? AND g.revokedAt IS NOT NULL AND g.rev>?""",
            userId, since,
        ) { rs ->
            val reason = when (rs.getString("rr")) {
                "vault_delete" -> "deleted"
                "member_leave" -> "left"
                else -> "removed"
            }
            if (reason == "deleted") RemovedGrantInfo(
                vaultId = rs.getString("vaultId"), reason = reason,
                deletedAt = rs.getLong("deletedAt").let { if (rs.wasNull()) null else it },
                purgeAt = rs.getLong("purgeAt").let { if (rs.wasNull()) null else it },
                deleteId = rs.getString("deleteId"), deleteProof = rs.getString("deleteProof"),
            ) else RemovedGrantInfo(
                // 'removed'/'left': relay the durable removal proof so a 0.5.0 victim can
                // attribute the removal even across a server restart (spec 03 §11).
                vaultId = rs.getString("vaultId"), reason = reason,
                removeProof = rs.getString("removeProof"), removeNonce = rs.getString("removeNonce"),
            )
        }
        io.silencelen.andvari.core.model.SyncResponse(
            rev = rev, full = since == 0L,
            vaults = vaults, grants = grants, items = items,
            removedGrants = removedInfo.map { it.vaultId },
            removedGrantsInfo = removedInfo,
        )
    }

    fun grantRole(c: Connection, userId: String, vaultId: String): String? =
        c.queryOne(
            "SELECT role FROM grants WHERE userId=? AND vaultId=? AND revokedAt IS NULL",
            userId, vaultId,
        ) { it.getString(1) }

    /** Caller-grant-FIRST guard primitive (spec 03 §11): the grant row INCLUDING revoked. */
    fun grantRowAny(c: Connection, userId: String, vaultId: String): GrantRowFull? =
        c.queryOne("SELECT * FROM grants WHERE userId=? AND vaultId=?", userId, vaultId, map = ::grantRowFull)

    fun vaultType(c: Connection, vaultId: String): String? =
        c.queryOne("SELECT type FROM vaults WHERE vaultId=?", vaultId) { it.getString(1) }

    fun vaultRowById(c: Connection, vaultId: String): VaultRow? =
        c.queryOne("SELECT * FROM vaults WHERE vaultId=?", vaultId, map = ::vaultRow)

    /** One indexed lookup for the push_denied `deleted:` meta prefix (spec 03 §11). */
    fun vaultDeletedAt(c: Connection, vaultId: String): Long? =
        c.queryOne("SELECT deletedAt FROM vaults WHERE vaultId=?", vaultId) { rs ->
            rs.getLong(1).let { if (rs.wasNull()) null else it }
        }

    /**
     * Clears the pending-transfer fields on a vault; optionally bumps the vault rev so the
     * row re-delivers and every member's stale offer banner clears (spec 03 §11). Shared by
     * Service.clearPendingTransfer (cancel/decline/superseded/target-op) and the janitor's
     * offer-expiry sweep — each caller writes its OWN distinct audit row afterward.
     */
    fun clearPendingOffer(c: Connection, vaultId: String, bumpVaultRev: Boolean) {
        c.exec(
            """UPDATE vaults SET pendingOwnerId=NULL, pendingOfferId=NULL, pendingOfferProof=NULL,
               pendingOfferExpiresAt=NULL, pendingOfferSetAt=NULL WHERE vaultId=?""",
            vaultId,
        )
        if (bumpVaultRev) {
            val vr = nextRev(c, "vault", vaultId, vaultId)
            c.exec("UPDATE vaults SET rev=? WHERE vaultId=?", vr, vaultId)
        }
    }

    fun itemById(c: Connection, itemId: String): WireItem? =
        c.queryOne("SELECT * FROM items WHERE itemId=?", itemId) { itemRow(it) }

    /** Feature: item history — the archived ciphertext versions of an item, newest rev first
     *  (the server keeps the last 10; see [archiveVersion]). Grant-checked at the route. */
    fun itemVersions(c: Connection, itemId: String): List<ItemVersion> =
        c.queryAll(
            // LIMIT 10 is belt-and-suspenders: archiveVersion already prunes to the newest 10, but
            // capping the READ too means a prune regression can never balloon a history response.
            "SELECT rev, blob, formatVersion, archivedAt FROM item_versions WHERE itemId=? ORDER BY rev DESC LIMIT 10",
            itemId,
        ) { rs -> ItemVersion(rs.getLong("rev"), rs.getString("blob"), rs.getInt("formatVersion"), rs.getLong("archivedAt")) }

    /** Item undelete: the user's tombstoned items across every vault they still hold a grant to,
     *  newest-deleted first. Grant-scoped in SQL so it can never surface another tenant's items. */
    fun deletedItemsFor(c: Connection, userId: String): List<DeletedItem> =
        c.queryAll(
            """SELECT itemId, vaultId, updatedAt FROM items
               WHERE deleted=1 AND vaultId IN (SELECT vaultId FROM grants WHERE userId=? AND revokedAt IS NULL)
               ORDER BY updatedAt DESC""",
            userId,
        ) { rs -> DeletedItem(rs.getString("itemId"), rs.getString("vaultId"), rs.getLong("updatedAt")) }

    /** F49 retention: hard-delete a tombstoned item — the row AND its archived versions. Removes it
     *  from the Trash query and frees the ciphertext. (Trade-off: the delete leaves future sync
     *  deltas, so a client offline past retention that never saw the delete could re-add it — rare,
     *  bounded-Trash is the accepted call. Only ever applied to already-tombstoned items.) */
    fun purgeItem(c: Connection, itemId: String) {
        c.exec("DELETE FROM item_versions WHERE itemId=?", itemId)
        c.exec("DELETE FROM items WHERE itemId=?", itemId)
    }

    /** F49 retention: hard-delete every item tombstone deleted before [cutoffMs]. Returns the ids. */
    fun purgeOldTombstones(c: Connection, cutoffMs: Long): List<String> {
        val ids = c.queryAll("SELECT itemId FROM items WHERE deleted=1 AND updatedAt<?", cutoffMs) { rs -> rs.getString("itemId") }
        for (id in ids) purgeItem(c, id)
        return ids
    }

    fun archiveVersion(c: Connection, item: WireItem) {
        if (item.blob == null) return
        c.exec(
            "INSERT OR REPLACE INTO item_versions(itemId,rev,blob,formatVersion,archivedAt) VALUES(?,?,?,?,?)",
            item.itemId, item.rev, item.blob, item.formatVersion, now(),
        )
        c.exec(
            """DELETE FROM item_versions WHERE itemId=? AND rev NOT IN
               (SELECT rev FROM item_versions WHERE itemId=? ORDER BY rev DESC LIMIT 10)""",
            item.itemId, item.itemId,
        )
    }

    // audit — auditOn(c,…) when already inside a tx (avoids nested-tx autocommit corruption);
    // audit(…) opens its own tx for standalone callers.
    fun auditOn(c: Connection, type: String, userId: String?, deviceId: String?, ip: String?, meta: String? = null) {
        c.exec("INSERT INTO audit(at,type,userId,deviceId,ip,meta) VALUES(?,?,?,?,?,?)", now(), type, userId, deviceId, ip, meta)
        AuditLog.log(type, userId, deviceId, ip, meta)
    }

    fun audit(type: String, userId: String?, deviceId: String?, ip: String?, meta: String? = null) {
        db.tx { c -> auditOn(c, type, userId, deviceId, ip, meta) }
    }

    fun auditQuery(sinceId: Long, type: String?, userId: String?, limit: Int): List<AuditEvent> = db.read { c ->
        val where = StringBuilder("id>?")
        val args = mutableListOf<Any?>(sinceId)
        if (type != null) { where.append(" AND type=?"); args.add(type) }
        if (userId != null) { where.append(" AND userId=?"); args.add(userId) }
        args.add(limit.coerceIn(1, 1000))
        c.queryAll("SELECT * FROM audit WHERE $where ORDER BY id DESC LIMIT ?", *args.toTypedArray()) { rs ->
            AuditEvent(
                id = rs.getLong("id"), at = rs.getLong("at"), type = rs.getString("type"),
                userId = rs.getString("userId"), deviceId = rs.getString("deviceId"),
                ip = rs.getString("ip"), meta = rs.getString("meta"),
            )
        }
    }

    // policy
    fun policyJson(): String? = db.read { it.queryOne("SELECT json FROM policies WHERE id=1") { rs -> rs.getString(1) } }
    fun setPolicyJsonOn(c: Connection, value: String) {
        c.exec("INSERT INTO policies(id,json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json", value)
    }

    fun setPolicyJson(value: String) = db.tx { setPolicyJsonOn(it, value) }

    // hibp cache
    fun hibpCached(prefix: String, maxAgeMs: Long): String? = db.read {
        it.queryOne("SELECT body FROM hibp_cache WHERE prefix=? AND fetchedAt>?", prefix, now() - maxAgeMs) { rs -> rs.getString(1) }
    }

    fun hibpStore(prefix: String, body: String) = db.tx {
        it.exec(
            "INSERT INTO hibp_cache(prefix,body,fetchedAt) VALUES(?,?,?) ON CONFLICT(prefix) DO UPDATE SET body=excluded.body, fetchedAt=excluded.fetchedAt",
            prefix, body, now(),
        )
    }
}
