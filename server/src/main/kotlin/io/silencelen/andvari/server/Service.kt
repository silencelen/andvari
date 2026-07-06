package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.TokenPair
import io.silencelen.andvari.core.crypto.Bytes
import java.sql.Connection

/**
 * Business logic — decoupled from ktor so integration tests drive it directly and
 * routes stay thin. Emits (userIds, rev) sync notifications through [onChange] which
 * the app layer forwards to the [Notifier].
 */
class Service(
    val repo: Repo,
    val config: Config,
    private val onChange: suspend (userIds: Collection<String>, rev: Long) -> Unit = { _, _ -> },
) {
    private val accessTtlMs get() = policy().sessionAccessTtlSeconds * 1000
    private val refreshTtlMs get() = policy().sessionRefreshTtlDays * 24 * 3600 * 1000

    fun policy(): ClientPolicy {
        val stored = repo.policyJson()?.let { json.decodeFromString(ClientPolicy.serializer(), it) } ?: ClientPolicy()
        return stored.copy(recoveryFingerprint = config.recoveryFingerprint, serverTime = now())
    }

    fun setPolicy(p: ClientPolicy) = repo.setPolicyJson(json.encodeToString(ClientPolicy.serializer(), p.copy(serverTime = 0)))

    // ---- prelogin ----
    fun prelogin(email: String): PreloginResponse {
        val user = repo.userByEmail(email)
        return if (user != null) {
            PreloginResponse(user.kdfSalt, user.kdfParams)
        } else {
            PreloginResponse(Bytes.toB64(ServerCrypto.fakeSalt(config.enumSecret, email)), ClientPolicy().kdfParams)
        }
    }

    // ---- register ----
    fun register(req: RegisterRequest, ip: String): SessionResponse = repo.db.tx { c ->
        if (!config.escrowConfigured) throw BadRequest("escrow_not_configured")
        if (req.escrow.fingerprint != config.recoveryFingerprint) throw BadRequest("escrow_fingerprint_mismatch")

        val tokenHash = ServerCrypto.hashToken(req.inviteToken)
        val invite = c.queryOne("SELECT email,isAdmin,expiresAt,usedAt FROM invites WHERE tokenHash=?", tokenHash) { rs ->
            Triple(rs.getString("email"), rs.getInt("isAdmin") != 0, rs.getLong("expiresAt")) to
                (rs.getLong("usedAt").let { if (rs.wasNull()) null else it })
        } ?: throw BadRequest("invalid_invite")
        val (invData, usedAt) = invite
        val (invEmail, invAdmin, expiresAt) = invData
        if (usedAt != null) throw BadRequest("invite_used")
        if (expiresAt < now()) throw BadRequest("invite_expired")
        if (invEmail != BOOTSTRAP_ANY_EMAIL && !invEmail.equals(req.email, ignoreCase = true)) throw BadRequest("invite_email_mismatch")
        if (repo.userByEmail(req.email) != null) throw BadRequest("email_taken")

        val userId = req.userId
        if (!UUID_RE.matches(userId)) throw BadRequest("bad_user_id")
        if (c.queryOne("SELECT userId FROM users WHERE userId=?", userId) { it.getString(1) } != null) throw BadRequest("user_id_taken")
        val t = now()
        c.exec(
            """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,wrappedUvk,identityPub,
               encryptedIdentitySeed,isAdmin,status,mustChangePassword,createdAt)
               VALUES(?,?,?,?,?,?,?,?,?,?, 'active', 0, ?)""",
            userId, req.email.lowercase(), req.displayName, req.kdfSalt, encodeParams(req.kdfParams),
            ServerCrypto.hashVerifier(req.authKey), req.wrappedUvk, req.identityPub,
            req.encryptedIdentitySeed, invAdmin, t,
        )
        c.exec("INSERT INTO escrow(userId,sealed,fingerprint,updatedAt) VALUES(?,?,?,?)", userId, req.escrow.sealed, req.escrow.fingerprint, t)

        val vaultRev = repo.nextRev(c, "vault", req.personalVault.vaultId, req.personalVault.vaultId)
        c.exec(
            "INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?, 'personal', ?, ?, ?)",
            req.personalVault.vaultId, vaultRev, req.personalVault.metaBlob, t,
        )
        val grantRev = repo.nextRev(c, "grant", req.personalVault.vaultId, req.personalVault.vaultId)
        c.exec(
            "INSERT INTO grants(vaultId,userId,role,wrappedVk,rev) VALUES(?,?, 'owner', ?, ?)",
            req.personalVault.vaultId, userId, req.personalVault.wrappedVk, grantRev,
        )
        c.exec("UPDATE invites SET usedAt=? WHERE tokenHash=?", t, tokenHash)

        val session = issueSession(c, userId, req.device.platform, req.device.name)
        repo.auditOn(c, "register", userId, session.deviceId, ip, req.email)
        session.toResponse(user(c, userId), invAdmin, false)
    }

    // ---- login ----
    // Verify OUTSIDE any tx (so a failure's audit persists in its own tx); only the
    // success path opens a write tx to issue the session.
    fun login(req: LoginRequest, ip: String): SessionResponse {
        val user = repo.userByEmail(req.email)
        if (user == null || user.status != "active") {
            ServerCrypto.verify(DUMMY_VERIFIER, req.authKey) // uniform cost
            throw Unauthorized()
        }
        if (!ServerCrypto.verify(user.verifier, req.authKey)) {
            repo.audit("login_fail", user.userId, null, ip)
            throw Unauthorized()
        }
        return repo.db.tx { c ->
            val session = issueSession(c, user.userId, req.device.platform, req.device.name)
            repo.auditOn(c, "login", user.userId, session.deviceId, ip)
            session.toResponse(user, user.isAdmin, user.mustChangePassword)
        }
    }

    // ---- refresh (rotating; reuse of a consumed token revokes the device) ----
    fun refresh(refreshToken: String, ip: String): TokenPair {
        val hash = ServerCrypto.hashToken(refreshToken)
        val s = repo.sessionByRefreshHash(hash) ?: throw Unauthorized("invalid_refresh")
        if (s.revokedAt != null) throw Unauthorized("session_revoked")
        if (s.refreshConsumedAt != null) {
            // Token reuse → theft signal: revoke the whole device session (commit, then fail).
            repo.db.tx { c ->
                c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now(), s.deviceId)
                repo.auditOn(c, "refresh_reuse", s.userId, s.deviceId, ip)
            }
            throw Unauthorized("refresh_reuse")
        }
        if (s.refreshExpiresAt < now()) throw Unauthorized("refresh_expired")

        return repo.db.tx { c ->
            val newAccess = ServerCrypto.newToken()
            val newRefresh = ServerCrypto.newToken()
            // Mark the old refresh CONSUMED only (not revoked): a later replay of it must
            // reach the reuse branch → revoke the whole device chain (spec 03 §2).
            c.exec("UPDATE sessions SET refreshConsumedAt=? WHERE sessionId=?", now(), s.sessionId)
            c.exec(
                """INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,createdAt)
                   VALUES(?,?,?,?,?,?,?,?)""",
                uuid(), s.deviceId, s.userId, ServerCrypto.hashToken(newAccess), now() + accessTtlMs,
                ServerCrypto.hashToken(newRefresh), now() + refreshTtlMs, now(),
            )
            c.exec("UPDATE devices SET lastSeenAt=? WHERE deviceId=?", now(), s.deviceId)
            TokenPair(newAccess, newRefresh)
        }
    }

    fun logout(principal: Principal) = repo.db.tx { c ->
        c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now(), principal.deviceId)
        repo.auditOn(c, "logout", principal.userId, principal.deviceId, null)
    }

    fun accountKeys(userId: String): AccountKeys {
        val u = repo.userById(userId) ?: throw Unauthorized()
        return AccountKeys(u.kdfSalt, u.kdfParams, u.wrappedUvk, u.encryptedIdentitySeed, u.identityPub, config.recoveryFingerprint)
    }

    /** Resolve a Bearer access token → Principal (or null). */
    fun authenticate(accessToken: String): Principal? {
        val hash = ServerCrypto.hashToken(accessToken)
        val s = repo.sessionByAccessHash(hash) ?: return null
        if (s.revokedAt != null || s.accessExpiresAt < now()) return null
        val u = repo.userById(s.userId) ?: return null
        if (u.status != "active") return null
        return Principal(s.userId, s.deviceId, s.sessionId, u.isAdmin)
    }

    // ---- sync ----
    fun pull(userId: String, since: Long): io.silencelen.andvari.core.model.SyncResponse = repo.db.read { c ->
        if (since > 0 && since < repo.oldestRetainedRev(c)) throw ResyncRequired()
        repo.pull(userId, since)
    }

    suspend fun push(principal: Principal, mutations: List<Mutation>, ip: String): PushResponse {
        if (mutations.size > 200) throw BadRequest("batch_too_large")
        val affectedUsers = mutableSetOf<String>()
        val results = repo.db.tx { c ->
            mutations.map { m -> applyMutation(c, principal, m, affectedUsers) }
        }
        val rev = repo.db.read { repo.currentRev(it) }
        if (affectedUsers.isNotEmpty()) onChange(affectedUsers, rev)
        return PushResponse(rev, results)
    }

    private fun applyMutation(c: Connection, principal: Principal, m: Mutation, affected: MutableSet<String>): MutationResult {
        // Idempotency: replay the stored result verbatim.
        c.queryOne("SELECT resultJson FROM mutations WHERE deviceId=? AND mutationId=?", principal.deviceId, m.mutationId) { rs ->
            rs.getString(1)
        }?.let { return json.decodeFromString(MutationResult.serializer(), it) }

        val role = repo.grantRole(c, principal.userId, m.vaultId)
        val result = if (role == null || role == "reader") {
            MutationResult(m.mutationId, "denied")
        } else {
            val existing = repo.itemById(c, m.itemId)
            when (m.op) {
                "put" -> applyPut(c, m, existing, affected)
                "delete" -> applyDelete(c, m, existing, affected)
                else -> throw BadRequest("bad_op")
            }
        }
        c.exec(
            "INSERT INTO mutations(deviceId,mutationId,resultJson,createdAt) VALUES(?,?,?,?)",
            principal.deviceId, m.mutationId, json.encodeToString(MutationResult.serializer(), result), now(),
        )
        return result
    }

    private fun applyPut(c: Connection, m: Mutation, existing: io.silencelen.andvari.core.model.WireItem?, affected: MutableSet<String>): MutationResult {
        val item = m.item ?: throw BadRequest("put_without_item")
        val vaultUsers = vaultMemberIds(c, m.vaultId).also { affected.addAll(it) }
        val t = now()
        if (existing == null) {
            val rev = repo.nextRev(c, "item", m.itemId, m.vaultId)
            c.exec(
                """INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,conflict,formatVersion,attachmentIds,blob,blobSize)
                   VALUES(?,?,?,?,?,0,0,?,?,?,?)""",
                m.itemId, m.vaultId, rev, t, t, item.formatVersion, encodeIds(item.attachmentIds), item.blob, item.blob.length.toLong(),
            )
            return MutationResult(m.mutationId, "applied", rev)
        }
        // Existing item. Conflict iff the client wrote against a stale rev, OR it's edit-over-tombstone.
        val stale = m.baseItemRev < existing.rev
        val conflict = stale || existing.deleted
        if (existing.blob != null) repo.archiveVersion(c, existing)
        val rev = repo.nextRev(c, "item", m.itemId, m.vaultId)
        c.exec(
            """UPDATE items SET rev=?, updatedAt=?, deleted=0, conflict=?, formatVersion=?, attachmentIds=?, blob=?, blobSize=? WHERE itemId=?""",
            rev, t, conflict, item.formatVersion, encodeIds(item.attachmentIds), item.blob, item.blob.length.toLong(), m.itemId,
        )
        return if (conflict) {
            MutationResult(m.mutationId, "conflict", rev, serverItem = existing)
        } else {
            MutationResult(m.mutationId, "applied", rev)
        }
    }

    private fun applyDelete(c: Connection, m: Mutation, existing: io.silencelen.andvari.core.model.WireItem?, affected: MutableSet<String>): MutationResult {
        if (existing == null || existing.deleted) return MutationResult(m.mutationId, "applied") // idempotent
        val vaultUsers = vaultMemberIds(c, m.vaultId).also { affected.addAll(it) }
        // Edit-beats-delete: a delete against a stale rev loses to the newer edit.
        if (m.baseItemRev < existing.rev) {
            return MutationResult(m.mutationId, "conflict", existing.rev, serverItem = existing)
        }
        repo.archiveVersion(c, existing)
        val rev = repo.nextRev(c, "item", m.itemId, m.vaultId)
        c.exec("UPDATE items SET rev=?, updatedAt=?, deleted=1, conflict=0, blob=NULL, blobSize=0 WHERE itemId=?", rev, now(), m.itemId)
        return MutationResult(m.mutationId, "applied", rev)
    }

    private fun vaultMemberIds(c: Connection, vaultId: String): Set<String> =
        c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId) { it.getString(1) }.toSet()

    // ---- helpers ----
    private class IssuedSession(val deviceId: String, val access: String, val refresh: String)

    private fun issueSession(c: Connection, userId: String, platform: String, name: String): IssuedSession {
        val deviceId = uuid()
        c.exec(
            "INSERT INTO devices(deviceId,userId,platform,name,createdAt,lastSeenAt) VALUES(?,?,?,?,?,?)",
            deviceId, userId, platform, name, now(), now(),
        )
        val access = ServerCrypto.newToken()
        val refresh = ServerCrypto.newToken()
        c.exec(
            """INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,createdAt)
               VALUES(?,?,?,?,?,?,?,?)""",
            uuid(), deviceId, userId, ServerCrypto.hashToken(access), now() + accessTtlMs,
            ServerCrypto.hashToken(refresh), now() + refreshTtlMs, now(),
        )
        return IssuedSession(deviceId, access, refresh)
    }

    private fun user(c: Connection, userId: String): UserRow =
        c.queryOne("SELECT * FROM users WHERE userId=?", userId) { rs -> userRowPublic(rs) } ?: error("user vanished")

    private fun IssuedSession.toResponse(u: UserRow, isAdmin: Boolean, mustChange: Boolean) = SessionResponse(
        userId = u.userId, deviceId = deviceId, accessToken = access, refreshToken = refresh,
        accountKeys = AccountKeys(u.kdfSalt, u.kdfParams, u.wrappedUvk, u.encryptedIdentitySeed, u.identityPub, config.recoveryFingerprint),
        isAdmin = isAdmin, mustChangePassword = mustChange,
    )

    companion object {
        // A fixed valid argon2id string so unknown-user logins spend the same CPU (timing).
        val DUMMY_VERIFIER: String = ServerCrypto.hashVerifier("andvari-dummy-authkey")
        private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    }
}
