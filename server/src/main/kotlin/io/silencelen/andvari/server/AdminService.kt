package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AdminUserSummary
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.RecoveryUpload

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
    fun createInvite(email: String, isAdmin: Boolean, byUserId: String): Pair<InviteResponse, String> = repo.db.tx { c ->
        if (repo.userByEmail(email) != null) throw BadRequest("email_taken")
        val token = ServerCrypto.newToken()
        val expiresAt = now() + inviteTtlMs
        c.exec(
            "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt) VALUES(?,?,?,?,?)",
            ServerCrypto.hashToken(token), email.lowercase(), isAdmin, now(), expiresAt,
        )
        repo.auditOn(c, "invite_create", byUserId, null, null, email)
        InviteResponse(token, email.lowercase(), expiresAt) to token
    }

    fun disableUser(userId: String, byUserId: String) = repo.db.tx { c ->
        c.exec("UPDATE users SET status='disabled' WHERE userId=?", userId)
        c.exec("UPDATE sessions SET revokedAt=? WHERE userId=? AND revokedAt IS NULL", now(), userId)
        repo.auditOn(c, "user_disable", byUserId, null, null, userId)
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
}
