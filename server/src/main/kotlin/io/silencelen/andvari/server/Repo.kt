package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.AuditEvent
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
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
        val vaults = c.queryAll(
            """SELECT v.* FROM vaults v JOIN grants g ON g.vaultId=v.vaultId
               WHERE g.userId=? AND g.revokedAt IS NULL AND v.rev>?""",
            userId, since,
        ) { rs ->
            WireVault(
                vaultId = rs.getString("vaultId"), type = rs.getString("type"),
                rev = rs.getLong("rev"), metaBlob = rs.getString("metaBlob"), createdAt = rs.getLong("createdAt"),
            )
        }
        val grants = c.queryAll(
            "SELECT * FROM grants WHERE userId=? AND revokedAt IS NULL AND rev>?",
            userId, since,
        ) { rs ->
            WireGrant(
                vaultId = rs.getString("vaultId"), userId = rs.getString("userId"),
                role = rs.getString("role"), wrappedVk = rs.getString("wrappedVk"), rev = rs.getLong("rev"),
            )
        }
        val items = c.queryAll(
            """SELECT i.* FROM items i JOIN grants g ON g.vaultId=i.vaultId
               WHERE g.userId=? AND g.revokedAt IS NULL AND i.rev>?""",
            userId, since,
        ) { rs -> itemRow(rs) }
        val removed = c.queryAll(
            "SELECT vaultId FROM grants WHERE userId=? AND revokedAt IS NOT NULL AND rev>?",
            userId, since,
        ) { rs -> rs.getString(1) }
        io.silencelen.andvari.core.model.SyncResponse(
            rev = rev, full = since == 0L,
            vaults = vaults, grants = grants, items = items, removedGrants = removed,
        )
    }

    fun grantRole(c: Connection, userId: String, vaultId: String): String? =
        c.queryOne(
            "SELECT role FROM grants WHERE userId=? AND vaultId=? AND revokedAt IS NULL",
            userId, vaultId,
        ) { it.getString(1) }

    fun itemById(c: Connection, itemId: String): WireItem? =
        c.queryOne("SELECT * FROM items WHERE itemId=?", itemId) { itemRow(it) }

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
    fun setPolicyJson(value: String) = db.tx {
        it.exec("INSERT INTO policies(id,json) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET json=excluded.json", value)
    }

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
