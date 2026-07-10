package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AdminDeviceSummary
import io.silencelen.andvari.core.model.AdminStatus
import io.silencelen.andvari.core.model.AdminUserSummary
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.RecoveryUpload
import java.io.File

/** Admin operations (spec 03 §7). All callers are already checked isAdmin by the route. */
class AdminService(private val repo: Repo) {

    private val inviteTtlMs = 72L * 3600 * 1000

    fun listUsers(): List<AdminUserSummary> = repo.db.read { c ->
        c.queryAll("SELECT * FROM users ORDER BY createdAt") { rs ->
            val userId = rs.getString("userId")
            AdminUserSummary(
                userId = userId,
                email = rs.getString("email"),
                displayName = rs.getString("displayName"),
                isAdmin = rs.getInt("isAdmin") != 0,
                status = rs.getString("status"),
                createdAt = rs.getLong("createdAt"),
                deviceCount = c.queryOne("SELECT COUNT(*) FROM devices WHERE userId=? AND revokedAt IS NULL", userId) { r -> r.getInt(1) } ?: 0,
                escrowFingerprint = c.queryOne("SELECT fingerprint FROM escrow WHERE userId=?", userId) { r -> r.getString(1) },
            )
        }
    }

    /** Create an invite; returns the plaintext token ONCE (only its hash is stored). */
    fun createInvite(email: String, isAdmin: Boolean, byUserId: String, ttlMinutes: Int? = null): Pair<InviteResponse, String> = repo.db.tx { c ->
        if (repo.userByEmail(email) != null) throw BadRequest("email_taken")
        val token = ServerCrypto.newToken()
        val tokenHash = ServerCrypto.hashToken(token)
        // Optional short TTL (S4 QR invites), clamped to [5 min, 72 h]; absent → 72 h unchanged.
        // There is NO invite list/revoke surface, so this clamp is the SOLE containment for a
        // photographed/leaked QR — never honor a client-requested TTL outside these bounds.
        val ttlMs = ttlMinutes?.let { it.coerceIn(5, 72 * 60) * 60_000L } ?: inviteTtlMs
        val expiresAt = now() + ttlMs
        c.exec(
            "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt) VALUES(?,?,?,?,?)",
            tokenHash, email.lowercase(), isAdmin, now(), expiresAt,
        )
        // Meta = token-hash prefix, not the email (INFO-1): the register row logs the same
        // prefix, so create↔redeem stays correlatable with zero PII in Loki.
        repo.auditOn(c, "invite_create", byUserId, null, null, tokenHash.take(12))
        InviteResponse(token, email.lowercase(), expiresAt) to token
    }

    fun disableUser(userId: String, byUserId: String) {
        // The whole decision + audit + mutation happens in ONE tx so (a) two concurrent
        // disables can't both slip past the last-admin count, and (b) EVERY call is
        // audited — success and refusal alike (spec 03 §7: "every call audited"; the
        // refusals are exactly the anomalous attempts the audit log exists to catch).
        // A refusal writes its audit row inside the tx (which commits) and returns a
        // reason; the BadRequest is thrown OUTSIDE, so it can't roll the audit row back.
        val refusal: String? = repo.db.tx { c ->
            val target = c.queryOne("SELECT isAdmin, status FROM users WHERE userId=?", userId) { rs ->
                (rs.getInt("isAdmin") != 0) to rs.getString("status")
            }
            if (target == null) {
                repo.auditOn(c, "user_disable_denied", byUserId, null, null, "$userId/no_such_user")
                return@tx "no_such_user"
            }
            // Lockout guard: refuse to disable the LAST active admin — with no active
            // admin left, nobody can reach the Admin console or re-enable anyone, the
            // disabled admin's own login fails with a misleading "wrong email or
            // password", and the only way back is sqlite surgery on the container.
            if (target.first && target.second == "active") {
                val activeAdmins = c.queryOne("SELECT COUNT(*) FROM users WHERE isAdmin=1 AND status='active'") { it.getInt(1) } ?: 0
                if (activeAdmins <= 1) {
                    repo.auditOn(c, "user_disable_denied", byUserId, null, null, "$userId/last_admin")
                    return@tx "last_admin"
                }
            }
            c.exec("UPDATE users SET status='disabled' WHERE userId=?", userId)
            c.exec("UPDATE sessions SET revokedAt=? WHERE userId=? AND revokedAt IS NULL", now(), userId)
            repo.auditOn(c, "user_disable", byUserId, null, null, userId)
            null
        }
        if (refusal != null) throw BadRequest(refusal)
    }

    fun revokeDevice(deviceId: String, byUserId: String) = repo.db.tx { c ->
        c.exec("UPDATE devices SET revokedAt=? WHERE deviceId=?", now(), deviceId)
        c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now(), deviceId)
        repo.auditOn(c, "device_revoke", byUserId, deviceId, null)
    }

    /** Upload recovery-cli output (spec 04 §4): set temp creds + force change + revoke sessions. */
    fun applyRecovery(req: RecoveryUpload, byUserId: String) = repo.db.tx { c ->
        val exists = c.queryOne("SELECT userId FROM users WHERE userId=?", req.userId) { it.getString(1) }
            ?: throw BadRequest("no_such_user")
        c.exec(
            """UPDATE users SET verifier=?, wrappedUvk=?, kdfSalt=?, kdfParams=?, mustChangePassword=1, status='active' WHERE userId=?""",
            ServerCrypto.hashVerifier(req.tempAuthKey), req.tempWrappedUvk, req.tempKdfSalt, encodeParams(req.tempKdfParams), req.userId,
        )
        c.exec("UPDATE sessions SET revokedAt=? WHERE userId=? AND revokedAt IS NULL", now(), req.userId)
        repo.auditOn(c, "recovery_apply", byUserId, null, null, req.userId)
    }

    fun userSealed(userId: String): String? = repo.db.read {
        it.queryOne("SELECT sealed FROM escrow WHERE userId=?", userId) { rs -> rs.getString(1) }
    }

    fun listDevices(userId: String): List<AdminDeviceSummary> = repo.db.read { c ->
        c.queryAll("SELECT * FROM devices WHERE userId=? ORDER BY createdAt DESC", userId) { rs ->
            AdminDeviceSummary(
                deviceId = rs.getString("deviceId"),
                platform = rs.getString("platform"),
                name = rs.getString("name"),
                clientVersion = rs.getString("clientVersion"),
                createdAt = rs.getLong("createdAt"),
                lastSeenAt = rs.getLong("lastSeenAt").let { v -> if (rs.wasNull()) null else v },
                revokedAt = rs.getLong("revokedAt").let { v -> if (rs.wasNull()) null else v },
            )
        }
    }

    /** spec 03 §7: server version, break-glass state (read-only), storage stats. */
    fun status(config: Config, attachments: AttachmentStore): AdminStatus = repo.db.read { c ->
        val (attCount, attBytes) = attachments.stats(c)
        AdminStatus(
            serverVersion = SERVER_VERSION,
            serverTime = now(),
            escrowConfigured = config.escrowConfigured,
            recoveryFingerprint = config.recoveryFingerprint,
            breakGlassConfigured = config.publicHostname != null,
            lastPublicRequestAt = c.queryOne("SELECT value FROM meta WHERE key='lastPublicRequestAt'") { it.getString(1).toLongOrNull() },
            userCount = c.queryOne("SELECT COUNT(*) FROM users") { it.getInt(1) } ?: 0,
            itemCount = c.queryOne("SELECT COUNT(*) FROM items WHERE deleted=0") { it.getInt(1) } ?: 0,
            attachmentCount = attCount,
            attachmentBytes = attBytes,
            dbBytes = File(config.dbPath).length(),
            totpEnrolledCount = c.queryOne("SELECT COUNT(*) FROM users WHERE totpSecret IS NOT NULL") { it.getInt(1) } ?: 0,
            downloadsManifest = config.downloadsDir?.let { File(it, "manifest.json").isFile } ?: false,
        )
    }
}
