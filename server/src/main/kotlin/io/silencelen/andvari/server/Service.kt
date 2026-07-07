package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.CreateVaultResponse
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.TokenPair
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.TotpConfig
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.security.MessageDigest
import java.sql.Connection

/**
 * Business logic — decoupled from ktor so integration tests drive it directly and
 * routes stay thin. Emits (userIds, rev) sync notifications through [onChange] which
 * the app layer forwards to the [Notifier].
 */
class Service(
    val repo: Repo,
    val config: Config,
    val attachments: AttachmentStore = AttachmentStore(repo, config.blobDir, config.uploadMaxConcurrentPerUser),
    private val onChange: suspend (userIds: Collection<String>, rev: Long) -> Unit = { _, _ -> },
) {
    private val crypto = createCryptoProvider()
    private val accessTtlMs get() = policy().sessionAccessTtlSeconds * 1000
    private val refreshTtlMs get() = policy().sessionRefreshTtlDays * 24 * 3600 * 1000

    fun policy(): ClientPolicy {
        val stored = repo.policyJson()?.let { json.decodeFromString(ClientPolicy.serializer(), it) } ?: ClientPolicy()
        return stored.copy(recoveryFingerprint = config.recoveryFingerprint, serverTime = now())
    }

    fun setPolicy(p: ClientPolicy, byUserId: String? = null, ip: String? = null) = repo.db.tx { c ->
        // The audit row rides the SAME tx as the policy write (INFO-5): no crash window
        // where the org policy changed with no policy_update row.
        repo.setPolicyJsonOn(c, json.encodeToString(ClientPolicy.serializer(), p.copy(serverTime = 0)))
        repo.auditOn(c, "policy_update", byUserId, null, ip)
    }

    // ---- prelogin ----
    fun prelogin(email: String): PreloginResponse {
        // policy() (a DB read + decode) is computed on BOTH branches so the unknown-email
        // path is not measurably heavier than the known one — an asymmetric cost here would
        // be a timing oracle that partly defeats the fake-salt anti-enumeration (spec 05 T11).
        val defaultParams = policy().kdfParams
        val user = repo.userByEmail(email)
        return if (user != null) {
            PreloginResponse(user.kdfSalt, user.kdfParams)
        } else {
            // Unknown email: fake salt + the CURRENT stored org-default params, not the
            // compile-time default — a policy bump must not mark every unknown email with
            // stale params (INFO-3). Residual per-user divergence oracle: spec 05 R4.
            PreloginResponse(Bytes.toB64(ServerCrypto.fakeSalt(config.enumSecret, email)), defaultParams)
        }
    }

    // ---- register ----
    fun register(req: RegisterRequest, ip: String): SessionResponse = repo.db.tx { c ->
        if (!config.escrowConfigured) throw BadRequest("escrow_not_configured")
        if (req.escrow.fingerprint != config.recoveryFingerprint) throw BadRequest("escrow_fingerprint_mismatch")
        requireEscrowBlob(req.escrow.sealed)
        requireKdfFloor(req.kdfParams)

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
        // Meta = invite token-hash prefix, not the email (INFO-1): joins this row to its
        // invite_create without copying PII into the central log store.
        repo.auditOn(c, "register", userId, session.deviceId, ip, tokenHash.take(12))
        session.toResponse(user(c, userId), invAdmin, false)
    }

    // ---- login ----
    // Verify OUTSIDE any tx (so a failure's audit persists in its own tx); only the
    // success path opens a write tx to issue the session.
    fun login(req: LoginRequest, ip: String, publicOrigin: Boolean = false): SessionResponse {
        val user = repo.userByEmail(req.email)
        if (user == null || user.status != "active") {
            ServerCrypto.verify(DUMMY_VERIFIER, req.authKey) // uniform cost
            throw Unauthorized()
        }
        if (!ServerCrypto.verify(user.verifier, req.authKey)) {
            repo.audit("login_fail", user.userId, null, ip)
            throw Unauthorized()
        }
        // Break-glass hardening (spec 03 §2): via the public origin, server-TOTP is
        // mandatory — an account without it enrolled cannot log in publicly at all.
        if (publicOrigin) {
            val secret = user.totpSecret ?: run {
                repo.audit("login_fail_totp", user.userId, null, ip, "not_enrolled")
                throw Forbidden("public_login_requires_totp")
            }
            val code = req.totp ?: throw Unauthorized("totp_required")
            val step = verifyTotpCode(secret, code, user.totpLastStep)
            if (step == null) {
                repo.audit("login_fail", user.userId, null, ip, "totp")
                throw Unauthorized()
            }
            // Guarded consume: the WHERE clause makes step acceptance atomic, so two
            // concurrent logins replaying one code can't both win (TOCTOU).
            val consumed = repo.db.tx { c ->
                c.exec("UPDATE users SET totpLastStep=? WHERE userId=? AND totpLastStep<?", step, user.userId, step)
            }
            if (consumed != 1) {
                repo.audit("login_fail", user.userId, null, ip, "totp_replay")
                throw Unauthorized()
            }
        }
        return repo.db.tx { c ->
            val session = issueSession(c, user.userId, req.device.platform, req.device.name)
            repo.auditOn(c, "login", user.userId, session.deviceId, ip)
            session.toResponse(user, user.isAdmin, user.mustChangePassword)
        }
    }

    // ---- server TOTP (spec 03 §2; secrets are server 2FA, never vault data) ----
    fun totpStatus(userId: String): TotpStatus {
        val u = repo.userById(userId) ?: throw Unauthorized()
        return TotpStatus(enrolled = u.totpSecret != null, pendingSetup = u.totpPendingSecret != null)
    }

    fun totpSetup(userId: String): TotpSetupResponse {
        val u = repo.userById(userId) ?: throw Unauthorized()
        val secret = Base32.encode(crypto.randomBytes(20))
        repo.db.tx { c -> c.exec("UPDATE users SET totpPendingSecret=? WHERE userId=?", secret, userId) }
        val label = "andvari:${u.email}"
        return TotpSetupResponse(secret, "otpauth://totp/$label?secret=$secret&issuer=andvari&algorithm=SHA1&digits=6&period=30")
    }

    fun totpConfirm(userId: String, code: String, ip: String) {
        val u = repo.userById(userId) ?: throw Unauthorized()
        val pending = u.totpPendingSecret ?: throw BadRequest("no_pending_totp")
        val step = verifyTotpCode(pending, code, 0) ?: throw BadRequest("bad_totp_code")
        repo.db.tx { c ->
            c.exec("UPDATE users SET totpSecret=?, totpPendingSecret=NULL, totpEnrolledAt=?, totpLastStep=? WHERE userId=?", pending, now(), step, userId)
            repo.auditOn(c, "totp_enroll", userId, null, ip)
        }
    }

    fun totpDisable(userId: String, code: String, ip: String) {
        val u = repo.userById(userId) ?: throw Unauthorized()
        val secret = u.totpSecret ?: throw BadRequest("totp_not_enrolled")
        if (verifyTotpCode(secret, code, u.totpLastStep) == null) throw BadRequest("bad_totp_code")
        repo.db.tx { c ->
            c.exec("UPDATE users SET totpSecret=NULL, totpPendingSecret=NULL, totpEnrolledAt=NULL, totpLastStep=0 WHERE userId=?", userId)
            repo.auditOn(c, "totp_disable", userId, null, ip)
        }
    }

    /** RFC 6238 check over steps now-1..now+1; a step at or before the last accepted one is a replay. */
    private fun verifyTotpCode(secretBase32: String, code: String, lastStep: Long): Long? {
        val cfg = TotpConfig(secret = Base32.decode(secretBase32))
        val nowSec = now() / 1000
        val step = nowSec / cfg.periodSeconds
        for (s in longArrayOf(step, step - 1, step + 1)) {
            if (s <= lastStep) continue
            val expect = Totp.code(crypto, cfg, s * cfg.periodSeconds)
            if (MessageDigest.isEqual(expect.encodeToByteArray(), code.trim().encodeToByteArray())) return s
        }
        return null
    }

    /**
     * Reject enrollment/re-key params below the org KDF floor before they are persisted
     * (spec 01 §9 / spec 05 T8). The clients take params from server policy, so this is the
     * authoritative gate against a weak-policy server persisting brute-forceable verifiers.
     * Off (floor 0/0) under the test config; production sets 64 MiB / ops 3 via fromEnv.
     */
    private fun requireKdfFloor(p: KdfParams) {
        if (p.memBytes < config.minKdfMemBytes || p.ops < config.minKdfOps) throw BadRequest("kdf_too_weak")
    }

    // ---- password change (spec 03 §3; also the tail of the recovery flow, spec 04 §4) ----
    fun changePassword(p: Principal, req: PasswordChangeRequest, ip: String) {
        val u = repo.userById(p.userId) ?: throw Unauthorized()
        if (!ServerCrypto.verify(u.verifier, req.currentAuthKey)) {
            repo.audit("password_change_fail", p.userId, p.deviceId, ip)
            throw Unauthorized()
        }
        requireKdfFloor(req.newKdfParams)
        repo.db.tx { c ->
            c.exec(
                "UPDATE users SET verifier=?, kdfSalt=?, kdfParams=?, wrappedUvk=?, mustChangePassword=0 WHERE userId=?",
                ServerCrypto.hashVerifier(req.newAuthKey), req.newKdfSalt, encodeParams(req.newKdfParams), req.newWrappedUvk, p.userId,
            )
            c.exec("UPDATE sessions SET revokedAt=? WHERE userId=? AND sessionId<>? AND revokedAt IS NULL", now(), p.userId, p.sessionId)
            repo.auditOn(c, "password_change", p.userId, p.deviceId, ip)
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
            // Guarded consume (CAS): the reuse check above ran on a snapshot outside this tx,
            // so two concurrent uses of one token could both pass it. Consuming only when
            // still-null and checking the affected-row count makes exactly one winner; a
            // loser means a concurrent consume already happened → treat as reuse (spec 03 §2:
            // reuse revokes the whole device), mirroring the TOTP guarded-step at login.
            val consumed = c.exec(
                "UPDATE sessions SET refreshConsumedAt=? WHERE sessionId=? AND refreshConsumedAt IS NULL",
                now(), s.sessionId,
            )
            if (consumed != 1) {
                c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now(), s.deviceId)
                repo.auditOn(c, "refresh_reuse", s.userId, s.deviceId, ip)
                throw Unauthorized("refresh_reuse")
            }
            val newAccess = ServerCrypto.newToken()
            val newRefresh = ServerCrypto.newToken()
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
        // Attachment blobs of tombstoned items are unlinked ONLY after the batch tx commits.
        // Unlinking mid-tx would orphan the file if a later mutation throws and rolls the tx
        // back (item restored, ciphertext gone). Empty on any rollback (nothing committed).
        val filesToUnlink = mutableListOf<String>()
        val results = repo.db.tx { c ->
            mutations.map { m -> applyMutation(c, principal, m, affectedUsers, filesToUnlink, ip) }
        }
        filesToUnlink.forEach { attachments.file(it).delete() }
        val rev = repo.db.read { repo.currentRev(it) }
        if (affectedUsers.isNotEmpty()) onChange(affectedUsers, rev)
        return PushResponse(rev, results)
    }

    private fun applyMutation(c: Connection, principal: Principal, m: Mutation, affected: MutableSet<String>, filesToUnlink: MutableList<String>, ip: String): MutationResult {
        // Idempotency: replay the stored result verbatim.
        c.queryOne("SELECT resultJson FROM mutations WHERE deviceId=? AND mutationId=?", principal.deviceId, m.mutationId) { rs ->
            rs.getString(1)
        }?.let { return json.decodeFromString(MutationResult.serializer(), it) }

        val role = repo.grantRole(c, principal.userId, m.vaultId)
        val existing = if (role == null || role == "reader") null else repo.itemById(c, m.itemId)
        val result = if (role == null || role == "reader") {
            // spec 03 §5: a denied write is an intrusion event and MUST be audited.
            repo.auditOn(c, "push_denied", principal.userId, principal.deviceId, ip, "${m.vaultId}:${m.itemId}")
            MutationResult(m.mutationId, "denied")
        } else if (existing != null && existing.vaultId != m.vaultId) {
            // An item cannot move vaults (its blob AD binds to (vaultId,itemId), spec 02 §2).
            // Return a per-mutation `denied` — NOT a thrown BadRequest — so a buggy/old client
            // (which re-encrypts a shared item under its personal vault) drops the mutation and
            // keeps syncing instead of wedging its queue forever; other members stay protected.
            repo.auditOn(c, "push_denied", principal.userId, principal.deviceId, ip, "vault_mismatch:${m.vaultId}:${m.itemId}")
            MutationResult(m.mutationId, "denied")
        } else {
            when (m.op) {
                "put" -> applyPut(c, m, existing, affected)
                "delete" -> applyDelete(c, m, existing, affected, filesToUnlink)
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
        validateAttachmentRefs(c, m, item.attachmentIds)
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

    private fun applyDelete(c: Connection, m: Mutation, existing: io.silencelen.andvari.core.model.WireItem?, affected: MutableSet<String>, filesToUnlink: MutableList<String>): MutationResult {
        if (existing == null || existing.deleted) return MutationResult(m.mutationId, "applied") // idempotent
        val vaultUsers = vaultMemberIds(c, m.vaultId).also { affected.addAll(it) }
        // Edit-beats-delete: a delete against a stale rev loses to the newer edit.
        if (m.baseItemRev < existing.rev) {
            return MutationResult(m.mutationId, "conflict", existing.rev, serverItem = existing)
        }
        repo.archiveVersion(c, existing)
        val rev = repo.nextRev(c, "item", m.itemId, m.vaultId)
        c.exec("UPDATE items SET rev=?, updatedAt=?, deleted=1, conflict=0, blob=NULL, blobSize=0, attachmentIds='[]' WHERE itemId=?", rev, now(), m.itemId)
        // Drop the attachment ROWS in-tx (spec 02 §7); defer the file unlink to post-commit.
        filesToUnlink += attachments.deleteRowsForItem(c, m.itemId)
        return MutationResult(m.mutationId, "applied", rev)
    }

    /** Every referenced attachment must exist, be bound to this item+vault, and fit the per-item quota. */
    private fun validateAttachmentRefs(c: Connection, m: Mutation, ids: List<String>) {
        if (ids.isEmpty()) return
        var total = 0L
        for (aid in ids.distinct()) {
            val row = attachments.rowById(c, aid) ?: throw BadRequest("unknown_attachment")
            if (row.itemId != m.itemId || row.vaultId != m.vaultId) throw BadRequest("attachment_mismatch")
            total += row.size
        }
        if (total > attachments.maxCipherBytes(policy().itemAttachmentsMaxBytes)) throw PayloadTooLarge("item_attachment_quota")
    }

    private fun vaultMemberIds(c: Connection, vaultId: String): Set<String> =
        c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId) { it.getString(1) }.toSet()

    // ---- shared vaults (spec 03 §10) ----

    /** base64url ciphertext bound by a byte cap (opaque to the server). ASCII alphabet only. */
    private fun requireB64(value: String, maxBytes: Int, field: String): String {
        val ok = value.isNotEmpty() && value.length <= maxBytes * 4 / 3 + 4 &&
            value.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }
        if (!ok) throw BadRequest("bad_$field")
        return value
    }

    suspend fun createSharedVault(p: Principal, req: CreateVaultRequest, ip: String): CreateVaultResponse {
        if (!UUID_RE.matches(req.vaultId)) throw BadRequest("bad_vault_id")
        requireB64(req.metaBlob, 4096, "meta_blob")
        requireB64(req.wrappedVk, 1024, "wrapped_vk")
        val rev = repo.db.tx { c ->
            if (repo.vaultType(c, req.vaultId) != null) throw BadRequest("vault_id_taken")
            val t = now()
            val vaultRev = repo.nextRev(c, "vault", req.vaultId, req.vaultId)
            c.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?, 'shared', ?, ?, ?)", req.vaultId, vaultRev, req.metaBlob, t)
            val grantRev = repo.nextRev(c, "grant", req.vaultId, req.vaultId)
            c.exec("INSERT INTO grants(vaultId,userId,role,wrappedVk,sealedVk,rev,addedAt) VALUES(?,?, 'owner', ?, NULL, ?, ?)", req.vaultId, p.userId, req.wrappedVk, grantRev, t)
            repo.auditOn(c, "vault_create", p.userId, p.deviceId, ip, req.vaultId)
            repo.currentRev(c)
        }
        onChange(setOf(p.userId), rev)
        return CreateVaultResponse(rev)
    }

    fun lookupUser(p: Principal, email: String, ip: String): UserLookupResponse {
        // Never write the raw target email into audit meta (INFO-1: audit rows ship to the
        // central log store, a different trust boundary). Found → target userId; miss → no meta.
        val u = repo.userByEmail(email)?.takeIf { it.status == "active" } ?: run {
            repo.audit("user_lookup", p.userId, p.deviceId, ip)
            throw NotFound("no_such_user")
        }
        repo.audit("user_lookup", p.userId, p.deviceId, ip, u.userId)
        return UserLookupResponse(u.userId, u.displayName, u.identityPub)
    }

    fun listVaultMembers(p: Principal, vaultId: String): List<VaultMemberSummary> = repo.db.read { c ->
        if (repo.grantRole(c, p.userId, vaultId) == null) throw Forbidden("no_grant") // hidden-as-403
        c.queryAll(
            """SELECT g.userId, g.role, COALESCE(g.addedAt, 0) AS addedAt, u.email, u.displayName, u.identityPub
               FROM grants g JOIN users u ON u.userId=g.userId
               WHERE g.vaultId=? AND g.revokedAt IS NULL ORDER BY g.rev""",
            vaultId,
        ) { rs ->
            VaultMemberSummary(
                userId = rs.getString("userId"), email = rs.getString("email"),
                displayName = rs.getString("displayName"), role = rs.getString("role"),
                identityPub = rs.getString("identityPub"), addedAt = rs.getLong("addedAt"),
            )
        }
    }

    private fun requireOwnerOfShared(c: Connection, p: Principal, vaultId: String) {
        if (repo.grantRole(c, p.userId, vaultId) != "owner") throw Forbidden("not_vault_owner")
        if (repo.vaultType(c, vaultId) != "shared") throw BadRequest("not_shared_vault")
    }

    suspend fun addVaultMember(p: Principal, vaultId: String, req: VaultMemberAdd, ip: String): CreateVaultResponse {
        if (req.role !in setOf("writer", "reader")) throw BadRequest("bad_role")
        if (req.userId == p.userId) throw BadRequest("cannot_target_self")
        requireB64(req.sealedVk, 1024, "sealed_vk")
        val (rev, notify) = repo.db.tx { c ->
            requireOwnerOfShared(c, p, vaultId)
            val target = c.queryOne("SELECT status FROM users WHERE userId=?", req.userId) { it.getString(1) }
                ?: throw NotFound("no_such_user")
            if (target != "active") throw BadRequest("user_inactive")
            if (repo.grantRole(c, req.userId, vaultId) != null) throw BadRequest("already_member")
            val grantRev = repo.nextRev(c, "grant", vaultId, vaultId)
            // Insert, or resurrect a previously-revoked row (PRIMARY KEY(vaultId,userId)).
            c.exec(
                """INSERT INTO grants(vaultId,userId,role,wrappedVk,sealedVk,rev,revokedAt,addedAt) VALUES(?,?,?,'',?,?,NULL,?)
                   ON CONFLICT(vaultId,userId) DO UPDATE SET role=excluded.role, wrappedVk='', sealedVk=excluded.sealedVk, rev=excluded.rev, revokedAt=NULL, addedAt=excluded.addedAt""",
                vaultId, req.userId, req.role, req.sealedVk, grantRev, now(),
            )
            repo.auditOn(c, "vault_member_add", p.userId, p.deviceId, ip, "$vaultId:${req.userId}:${req.role}")
            repo.currentRev(c) to vaultMemberIds(c, vaultId)
        }
        onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    suspend fun setVaultMemberRole(p: Principal, vaultId: String, targetUserId: String, role: String, ip: String): CreateVaultResponse {
        if (role !in setOf("writer", "reader")) throw BadRequest("bad_role")
        if (targetUserId == p.userId) throw BadRequest("cannot_target_self")
        val (rev, notify) = repo.db.tx { c ->
            requireOwnerOfShared(c, p, vaultId)
            if (repo.grantRole(c, targetUserId, vaultId) == null) throw NotFound("not_a_member")
            val grantRev = repo.nextRev(c, "grant", vaultId, vaultId)
            c.exec("UPDATE grants SET role=?, rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL", role, grantRev, vaultId, targetUserId)
            repo.auditOn(c, "vault_member_role", p.userId, p.deviceId, ip, "$vaultId:$targetUserId:$role")
            repo.currentRev(c) to vaultMemberIds(c, vaultId)
        }
        onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    suspend fun removeVaultMember(p: Principal, vaultId: String, targetUserId: String, ip: String): CreateVaultResponse {
        if (targetUserId == p.userId) throw BadRequest("cannot_target_self")
        val (rev, notify) = repo.db.tx { c ->
            requireOwnerOfShared(c, p, vaultId)
            if (repo.grantRole(c, targetUserId, vaultId) == null) throw NotFound("not_a_member")
            val grantRev = repo.nextRev(c, "grant", vaultId, vaultId)
            c.exec("UPDATE grants SET revokedAt=?, rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL", now(), grantRev, vaultId, targetUserId)
            repo.auditOn(c, "vault_member_remove", p.userId, p.deviceId, ip, "$vaultId:$targetUserId")
            // Notify the remaining members AND the victim (so the victim's pull delivers removedGrants).
            repo.currentRev(c) to (vaultMemberIds(c, vaultId) + targetUserId)
        }
        onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

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
        isAdmin = isAdmin, mustChangePassword = mustChange, totpEnrolled = u.totpSecret != null,
    )

    companion object {
        // A fixed valid argon2id string so unknown-user logins spend the same CPU (timing).
        val DUMMY_VERIFIER: String = ServerCrypto.hashVerifier("andvari-dummy-authkey")
        private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    }
}
