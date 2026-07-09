package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.CreateVaultResponse
import io.silencelen.andvari.core.model.DeletedItem
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.ItemUpload
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
import io.silencelen.andvari.core.model.DeletedVaultSummary
import io.silencelen.andvari.core.model.TransferAcceptRequest
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.TransferOfferResponse
import io.silencelen.andvari.core.model.VaultDeleteRequest
import io.silencelen.andvari.core.model.VaultDeleteResponse
import io.silencelen.andvari.core.model.VaultMetaUpdateRequest
import io.silencelen.andvari.core.model.VaultRestoreRequest
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
        return AccountKeys(u.kdfSalt, u.kdfParams, u.wrappedUvk, u.encryptedIdentitySeed, u.identityPub, config.recoveryFingerprint, escrowStale(u.userId))
    }

    /**
     * F57: true when the account has an escrow blob sealed to a SUPERSEDED org recovery key (a
     * re-ceremony rotated the key). Drives the client's re-seal-on-unlock prompt (spec 04 §4).
     * A missing escrow row is NOT stale (nothing to re-seal), and it's never stale when escrow
     * is unconfigured.
     */
    private fun escrowStale(userId: String): Boolean {
        if (!config.escrowConfigured) return false
        val fp = repo.db.read { c -> c.queryOne("SELECT fingerprint FROM escrow WHERE userId=?", userId) { it.getString(1) } }
        return fp != null && fp != config.recoveryFingerprint
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
    fun pull(userId: String, since: Long): io.silencelen.andvari.core.model.SyncResponse =
        repo.db.read { c ->
            if (since > 0 && since < repo.oldestRetainedRev(c)) throw ResyncRequired()
            // Removal proofs are read durably from the grant row inside repo.pull (spec 03 §11).
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

    /** Item undelete (feature): the caller's tombstoned items, grant-scoped in SQL. */
    fun deletedItems(userId: String): List<DeletedItem> = repo.db.read { c -> repo.deletedItemsFor(c, userId) }

    /**
     * Item undelete (feature): un-tombstone [itemId] with the client's re-encrypted content. A
     * DEDICATED restore (deleted=0, conflict=0) rather than a plain put: a put over a tombstone is
     * edit-over-tombstone (conflict=1) and would spawn a spurious conflict copy. Only a writer/owner
     * of the item's vault, and only a currently-deleted item; notifies members like push does.
     * Returns the new global rev.
     */
    suspend fun restoreItem(principal: Principal, itemId: String, upload: ItemUpload, ip: String?): Long {
        var affected: Set<String> = emptySet()
        repo.db.tx { c ->
            val existing = repo.itemById(c, itemId) ?: throw Forbidden("no_grant") // hidden (spec 03 §8)
            val role = repo.grantRole(c, principal.userId, existing.vaultId)
            if (role == null || role == "reader") throw Forbidden("no_grant")
            if (!existing.deleted) throw BadRequest("item_not_deleted")
            affected = vaultMemberIds(c, existing.vaultId)
            val newRev = repo.nextRev(c, "item", itemId, existing.vaultId)
            c.exec(
                "UPDATE items SET rev=?, updatedAt=?, deleted=0, conflict=0, formatVersion=?, attachmentIds=?, blob=?, blobSize=? WHERE itemId=?",
                newRev, now(), upload.formatVersion, encodeIds(upload.attachmentIds), upload.blob, upload.blob.length.toLong(), itemId,
            )
            repo.auditOn(c, "item_restore", principal.userId, principal.deviceId, ip, "${existing.vaultId}:$itemId")
        }
        val rev = repo.db.read { repo.currentRev(it) }
        if (affected.isNotEmpty()) onChange(affected, rev)
        return rev
    }

    /**
     * Item undelete (feature, F49): "Delete forever" — hard-delete a tombstoned item + its versions.
     * Writer/owner only, only on an already-deleted item (a live item must be deleted first). No sync
     * notify needed — Trash is live-queried, and the delete itself already propagated. Audited.
     */
    fun purgeItem(principal: Principal, itemId: String, ip: String?): Long {
        repo.db.tx { c ->
            val existing = repo.itemById(c, itemId) ?: throw Forbidden("no_grant") // hidden (spec 03 §8)
            val role = repo.grantRole(c, principal.userId, existing.vaultId)
            if (role == null || role == "reader") throw Forbidden("no_grant")
            if (!existing.deleted) throw BadRequest("item_not_deleted")
            repo.purgeItem(c, itemId)
            repo.auditOn(c, "item_purge", principal.userId, principal.deviceId, ip, "${existing.vaultId}:$itemId")
        }
        return repo.db.read { repo.currentRev(it) }
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
            // A push against a tombstoned vault gets the `deleted:` meta prefix
            // (spec 03 §11) so intrusion review can exclude routine lifecycle fallout.
            val deletedPrefix = if (role == null && repo.vaultDeletedAt(c, m.vaultId) != null) "deleted:" else ""
            repo.auditOn(c, "push_denied", principal.userId, principal.deviceId, ip, "$deletedPrefix${m.vaultId}:${m.itemId}")
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
        // Dedup cache: NEVER cache a `denied` result (DATA-LOSS #2 / design §4 RESTORE 3).
        // A denied mutation changed no state, so re-evaluating a replay is idempotent-safe.
        // Caching it would freeze a parked edit that was denied during a vault's grace
        // window — after restore the client replays the SAME mutationId and must be allowed
        // to apply against the now-active grant, not served a stale cached `denied` forever.
        if (result.status != "denied") {
            c.exec(
                "INSERT INTO mutations(deviceId,mutationId,resultJson,createdAt) VALUES(?,?,?,?)",
                principal.deviceId, m.mutationId, json.encodeToString(MutationResult.serializer(), result), now(),
            )
        }
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
            """SELECT g.userId, g.role, COALESCE(g.addedAt, 0) AS addedAt, u.email, u.displayName, u.identityPub, u.status
               FROM grants g JOIN users u ON u.userId=g.userId
               WHERE g.vaultId=? AND g.revokedAt IS NULL ORDER BY g.rev""",
            vaultId,
        ) { rs ->
            VaultMemberSummary(
                userId = rs.getString("userId"), email = rs.getString("email"),
                displayName = rs.getString("displayName"), role = rs.getString("role"),
                identityPub = rs.getString("identityPub"), addedAt = rs.getLong("addedAt"),
                // F22 rider (spec 03 §10): disabled badge + transfer target picker input.
                status = rs.getString("status"),
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
                """INSERT INTO grants(vaultId,userId,role,wrappedVk,sealedVk,rev,revokedAt,revokedReason,removeProof,removeNonce,addedAt) VALUES(?,?,?,'',?,?,NULL,NULL,NULL,NULL,?)
                   ON CONFLICT(vaultId,userId) DO UPDATE SET role=excluded.role, wrappedVk='', sealedVk=excluded.sealedVk, rev=excluded.rev, revokedAt=NULL, revokedReason=NULL, removeProof=NULL, removeNonce=NULL, addedAt=excluded.addedAt""",
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
            val v = repo.vaultRowById(c, vaultId) ?: throw NotFound("not_a_member")
            val grantRev = repo.nextRev(c, "grant", vaultId, vaultId)
            c.exec("UPDATE grants SET role=?, rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL", role, grantRev, vaultId, targetUserId)
            // Role-changing the pending transfer target cancels the offer (spec 03 §11).
            if (v.pendingOfferId != null && v.pendingOwnerId == targetUserId) {
                clearPendingTransfer(c, vaultId, "target_role_changed", p, ip, bumpVaultRev = true)
            }
            repo.auditOn(c, "vault_member_role", p.userId, p.deviceId, ip, "$vaultId:$targetUserId:$role")
            repo.currentRev(c) to vaultMemberIds(c, vaultId)
        }
        onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    suspend fun removeVaultMember(
        p: Principal,
        vaultId: String,
        targetUserId: String,
        ip: String,
        // Optional removal proof (spec 03 §10/§11) minted by the removing owner's client;
        // relayed to the victim via removedGrantsInfo so a 0.5.0 client can verify the
        // removal was a real owner action. The server cannot verify it (no VK).
        proof: String? = null,
        nonce: String? = null,
    ): CreateVaultResponse {
        if (targetUserId == p.userId) throw BadRequest("cannot_target_self")
        if (proof != null) requireB64(proof, 64, "proof")
        if (nonce != null && !UUID_RE.matches(nonce)) throw BadRequest("bad_nonce")
        val (rev, notify) = repo.db.tx { c ->
            requireOwnerOfShared(c, p, vaultId)
            if (repo.grantRole(c, targetUserId, vaultId) == null) throw NotFound("not_a_member")
            val v = repo.vaultRowById(c, vaultId) ?: throw NotFound("not_a_member")
            val grantRev = repo.nextRev(c, "grant", vaultId, vaultId)
            // Store the removal proof/nonce ON the revoked grant row (durable relay — spec
            // 03 §3/§5); NULLs when the owner's client sent none (→ victim retain-and-warn).
            c.exec(
                "UPDATE grants SET revokedAt=?, revokedReason='member_remove', removeProof=?, removeNonce=?, rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL",
                now(), proof, nonce, grantRev, vaultId, targetUserId,
            )
            // Removing the pending transfer target cancels the offer (spec 03 §11).
            if (v.pendingOfferId != null && v.pendingOwnerId == targetUserId) {
                clearPendingTransfer(c, vaultId, "target_removed", p, ip, bumpVaultRev = true)
            }
            repo.auditOn(c, "vault_member_remove", p.userId, p.deviceId, ip, "$vaultId:$targetUserId" + if (proof != null) ":proof" else "")
            // Notify the remaining members AND the victim (so the victim's pull delivers removedGrants).
            repo.currentRev(c) to (vaultMemberIds(c, vaultId) + targetUserId)
        }
        onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    // ---- vault lifecycle (spec 03 §11; design 2026-07-07 skipti §4) ----
    //
    // Guard order everywhere: resolve the CALLER's grant row FIRST (including revoked) —
    // an outsider gets a uniform 403 regardless of vault existence (no tombstone
    // existence oracle). Deleted-vault special-case errors go only to grant-holders.
    // The server stores + relays lifecycle proofs; it can never mint or verify them (ZK).


    /** Clears the pending transfer offer. bumpVaultRev re-delivers the vault row so every
     *  member's stale offer banner clears via ordinary row re-delivery. */
    private fun clearPendingTransfer(c: Connection, vaultId: String, tag: String, actor: Principal?, ip: String?, bumpVaultRev: Boolean) {
        repo.clearPendingOffer(c, vaultId, bumpVaultRev)
        repo.auditOn(c, "vault_transfer_cancel", actor?.userId, actor?.deviceId, ip, "$vaultId:$tag")
    }

    /**
     * Soft delete (design §4 DELETE): revoke every active grant (`vault_delete`, key wraps
     * KEPT for restore), stamp the tombstone, start the grace clock. Idempotent by
     * operation identity (deleteId); a mismatched deleteId against an already-deleted
     * vault is a stale retry racing a restore → 409 vault_state_changed, never a fresh delete.
     */
    suspend fun deleteVault(p: Principal, vaultId: String, req: VaultDeleteRequest, ip: String): VaultDeleteResponse {
        if (!UUID_RE.matches(req.deleteId)) throw BadRequest("bad_delete_id")
        requireB64(req.proof, 64, "proof")
        val (rev, purgeAt, notify) = repo.db.tx { c ->
            val g = repo.grantRowAny(c, p.userId, vaultId) ?: throw Forbidden("not_vault_owner")
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("not_vault_owner")
            if (v.deletedAt != null) {
                if (g.role != "owner") throw Forbidden("not_vault_owner")
                if (req.deleteId == v.deleteId) {
                    // Replay of the committed op → idempotent 200, no writes, no bell.
                    return@tx Triple(repo.currentRev(c), v.purgeAt ?: v.deletedAt, emptySet<String>())
                }
                throw Conflict("vault_state_changed")
            }
            requireOwnerOfShared(c, p, vaultId)
            // Consumed-deleteId fence (DATA-LOSS #1 / design Q9): restoreVault RETAINS
            // vaults.deleteId as a consumed marker (alongside restoreProof). A stale delete
            // retry whose deleteId was already consumed by a restore must NOT fall through
            // into a FRESH delete — that would silently undo the restore and re-revoke every
            // member. It gets 409 vault_state_changed. A genuinely new delete carries a fresh
            // deleteId (≠ retained) and proceeds, overwriting deleteId + clearing restoreProof.
            if (req.deleteId == v.deleteId && v.restoreProof != null) throw Conflict("vault_state_changed")
            // Capture the notify set BEFORE any revocation (vaultMemberIds filters revoked —
            // computing after would yield an empty WS bell set).
            val members = vaultMemberIds(c, vaultId)
            if (v.pendingOfferId != null) clearPendingTransfer(c, vaultId, "superseded", p, ip, bumpVaultRev = false)
            val t = now()
            val purgeAt = t + config.vaultGraceDays * DAY_MS
            // Per-member grant rev bumps are what make every member's pull emit
            // removedGrants at ANY cursor age. revokedAt == deletedAt exactly — restore
            // resurrects only vault_delete revocations made at the matching instant.
            for (uid in members) {
                val gr = repo.nextRev(c, "grant", vaultId, vaultId)
                c.exec(
                    "UPDATE grants SET revokedAt=?, revokedReason='vault_delete', rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL",
                    t, gr, vaultId, uid,
                )
            }
            val vr = repo.nextRev(c, "vault", vaultId, vaultId)
            c.exec(
                "UPDATE vaults SET deletedAt=?, purgeAt=?, deletedBy=?, deleteId=?, deleteProof=?, restoreProof=NULL, rev=? WHERE vaultId=?",
                t, purgeAt, p.userId, req.deleteId, req.proof, vr, vaultId,
            )
            repo.auditOn(c, "vault_delete", p.userId, p.deviceId, ip, "$vaultId:members=${members.size}")
            Triple(repo.currentRev(c), purgeAt, members)
        }
        if (notify.isNotEmpty()) onChange(notify, rev)
        return VaultDeleteResponse(rev, purgeAt)
    }

    /**
     * Restore within grace (design §4 RESTORE): un-revoke ONLY grants revoked by THIS
     * delete (`revokedReason='vault_delete' AND revokedAt=deletedAt` — members removed
     * before the delete stay removed), clear the tombstone, store the restoreProof
     * (consumes the deleteId toward clients). Idempotent by deleteId via the stored proof.
     */
    suspend fun restoreVault(p: Principal, vaultId: String, req: VaultRestoreRequest, ip: String): CreateVaultResponse {
        if (!UUID_RE.matches(req.deleteId)) throw BadRequest("bad_delete_id")
        requireB64(req.proof, 64, "proof")
        val (rev, notify) = repo.db.tx { c ->
            val g = repo.grantRowAny(c, p.userId, vaultId) ?: throw Forbidden("not_vault_owner")
            if (g.role != "owner") throw Forbidden("not_vault_owner")
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("not_vault_owner")
            if (v.deletedAt == null) {
                // Live vault: a replay of the restore that already won carries the exact
                // proof we stored (operation identity — the proof binds the deleteId).
                if (v.restoreProof != null && v.restoreProof == req.proof) {
                    return@tx repo.currentRev(c) to emptySet<String>()
                }
                throw Conflict("vault_state_changed")
            }
            if (v.purgedAt != null) throw Gone("vault_gone")
            if (req.deleteId != v.deleteId) throw Conflict("vault_state_changed")
            val resurrect = c.queryAll(
                "SELECT userId FROM grants WHERE vaultId=? AND revokedReason='vault_delete' AND revokedAt=?",
                vaultId, v.deletedAt,
            ) { it.getString(1) }
            for (uid in resurrect) {
                val gr = repo.nextRev(c, "grant", vaultId, vaultId)
                c.exec("UPDATE grants SET revokedAt=NULL, revokedReason=NULL, rev=? WHERE vaultId=? AND userId=?", gr, vaultId, uid)
            }
            val vr = repo.nextRev(c, "vault", vaultId, vaultId)
            // RETAIN deleteId (DATA-LOSS #1): it is the consumed-deleteId marker paired with
            // restoreProof — deleteVault's fence refuses a stale retry bearing it, and the
            // restored vault row carries deleteId+restoreProof so a client re-receiving it can
            // verify restore(VK,vaultId,deleteId)==restoreProof and mark the deleteId consumed.
            // Clear only deletedAt/purgeAt/deleteProof.
            c.exec(
                "UPDATE vaults SET deletedAt=NULL, purgeAt=NULL, deleteProof=NULL, restoreProof=?, rev=? WHERE vaultId=?",
                req.proof, vr, vaultId,
            )
            repo.auditOn(c, "vault_restore", p.userId, p.deviceId, ip, "$vaultId:members=${resurrect.size}")
            repo.currentRev(c) to resurrect.toSet()
        }
        if (notify.isNotEmpty()) onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    /** The caller's own in-grace deleted vaults — ciphertext they already owned (ZK-clean). */
    fun listDeletedVaults(p: Principal): List<DeletedVaultSummary> = repo.db.read { c ->
        c.queryAll(
            """SELECT v.vaultId, v.metaBlob, g.wrappedVk, v.deletedAt, v.purgeAt, v.deleteId
               FROM vaults v JOIN grants g ON g.vaultId=v.vaultId
               WHERE g.userId=? AND g.role='owner' AND v.deletedAt IS NOT NULL AND v.purgedAt IS NULL
               ORDER BY v.deletedAt DESC""",
            p.userId,
        ) { rs ->
            DeletedVaultSummary(
                vaultId = rs.getString(1), metaBlob = rs.getString(2), wrappedVk = rs.getString(3),
                deletedAt = rs.getLong(4), purgeAt = rs.getLong(5), deleteId = rs.getString(6),
            )
        }
    }

    /**
     * Self-removal (design §4 LEAVE): byte-identical revocation to owner removal with
     * `revokedReason='member_leave'`; keys kept so a re-add resurrects. Owner cannot leave.
     * Idempotent by reason.
     */
    suspend fun leaveVault(p: Principal, vaultId: String, ip: String): CreateVaultResponse {
        val (rev, notify, changed) = repo.db.tx { c ->
            val g = repo.grantRowAny(c, p.userId, vaultId) ?: throw Forbidden("no_grant")
            if (g.revokedAt != null) {
                when (g.revokedReason) {
                    "member_leave" -> return@tx Triple(repo.currentRev(c), emptySet<String>(), false) // idempotent retry
                    // Deleted-vault special case only for grant-holders; re-revoking would
                    // clobber revokedAt/revokedReason and break restore matching.
                    "vault_delete" -> throw Conflict("vault_deleted")
                    else -> throw Forbidden("no_grant") // removed member = outsider now
                }
            }
            if (g.role == "owner") throw BadRequest("owner_must_transfer_or_delete")
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("no_grant")
            // Pre-capture: remaining members + the leaver (their own pull delivers removedGrants).
            val members = vaultMemberIds(c, vaultId)
            val gr = repo.nextRev(c, "grant", vaultId, vaultId)
            c.exec(
                "UPDATE grants SET revokedAt=?, revokedReason='member_leave', rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL",
                now(), gr, vaultId, p.userId,
            )
            // Leaving while pending-transfer-target auto-cancels the offer (spec 03 §11).
            if (v.pendingOfferId != null && v.pendingOwnerId == p.userId) {
                clearPendingTransfer(c, vaultId, "target_left", p, ip, bumpVaultRev = true)
            }
            repo.auditOn(c, "vault_member_leave", p.userId, p.deviceId, ip, "$vaultId:${p.userId}")
            Triple(repo.currentRev(c), members, true)
        }
        if (changed) onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    /**
     * Transfer offer (design §4 TRANSFER 1): a proof-bound, inert vault-row annotation.
     * seq = transferSeq+1 (transferSeq advances only at accept). One pending max — an
     * overwrite audits a cancel first.
     */
    suspend fun offerTransfer(p: Principal, vaultId: String, req: TransferOfferRequest, ip: String): TransferOfferResponse {
        if (!UUID_RE.matches(req.offerId)) throw BadRequest("bad_offer_id")
        if (!UUID_RE.matches(req.toUserId)) throw BadRequest("bad_user_id")
        requireB64(req.proof, 64, "proof")
        if (req.toUserId == p.userId) throw BadRequest("cannot_target_self")
        val (rev, notify) = repo.db.tx { c ->
            val g = repo.grantRowAny(c, p.userId, vaultId) ?: throw Forbidden("not_vault_owner")
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("not_vault_owner")
            // Guard order (spec 03 §11 / #6): classify the CALLER's grant FIRST — never the
            // vault's deletedAt — so an ex-member (removed/left before any delete) gets the
            // SAME uniform 403 whether the vault is live or in grace (no state-transition
            // oracle). Only the grant-holder-at-delete owner (vault_delete-revoked) gets the
            // meaningful vault_deleted special case. An active grant implies a live vault
            // (delete revokes every grant), so the deletedAt belt below is unreachable.
            if (g.revokedAt != null) {
                if (g.revokedReason == "vault_delete" && g.role == "owner") throw Conflict("vault_deleted")
                throw Forbidden("not_vault_owner")
            }
            if (g.role != "owner") throw Forbidden("not_vault_owner")
            if (v.deletedAt != null) throw Conflict("vault_deleted") // belt (unreachable for an active grant)
            if (v.type != "shared") throw BadRequest("not_shared_vault")
            val t = now()
            // The proof binds the exact expiresAt, so the server validates rather than
            // rewrites: must be in the future and within the configured TTL (+ slack).
            if (req.expiresAt <= t || req.expiresAt > t + config.transferTtlDays * DAY_MS + 10 * 60_000) throw BadRequest("bad_expiry")
            val target = repo.grantRowAny(c, req.toUserId, vaultId)
            if (target == null || target.revokedAt != null) throw NotFound("not_a_member")
            val status = c.queryOne("SELECT status FROM users WHERE userId=?", req.toUserId) { it.getString(1) }
            if (status != "active") throw BadRequest("user_inactive")
            if (v.pendingOfferId != null) clearPendingTransfer(c, vaultId, "superseded", p, ip, bumpVaultRev = false)
            c.exec(
                """UPDATE vaults SET pendingOwnerId=?, pendingOfferId=?, pendingOfferProof=?,
                   pendingOfferExpiresAt=?, pendingOfferSetAt=? WHERE vaultId=?""",
                req.toUserId, req.offerId, req.proof, req.expiresAt, t, vaultId,
            )
            // Vault rev bump → WireVault.pendingTransfer re-delivers to every member.
            val vr = repo.nextRev(c, "vault", vaultId, vaultId)
            c.exec("UPDATE vaults SET rev=? WHERE vaultId=?", vr, vaultId)
            repo.auditOn(c, "vault_transfer_offer", p.userId, p.deviceId, ip, "$vaultId:${req.toUserId}")
            repo.currentRev(c) to vaultMemberIds(c, vaultId)
        }
        onChange(notify, rev)
        return TransferOfferResponse(rev, req.expiresAt)
    }

    /** Owner cancel or target decline. Idempotent: no pending → 200 for any active member. */
    suspend fun cancelTransfer(p: Principal, vaultId: String, ip: String): CreateVaultResponse {
        val (rev, notify, changed) = repo.db.tx { c ->
            val g = repo.grantRowAny(c, p.userId, vaultId) ?: throw Forbidden("no_grant")
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("no_grant")
            // Guard order (#6): classify the caller's grant FIRST — vault_delete-revoked
            // grant-holder → vault_deleted; any other revoked caller → uniform 403 no_grant
            // regardless of vault state. An active grant implies a live vault.
            if (g.revokedAt != null) {
                if (g.revokedReason == "vault_delete") throw Conflict("vault_deleted")
                throw Forbidden("no_grant")
            }
            if (v.pendingOfferId == null) return@tx Triple(repo.currentRev(c), emptySet<String>(), false)
            val isOwner = g.role == "owner"
            val isTarget = v.pendingOwnerId == p.userId
            if (!isOwner && !isTarget) throw Forbidden("not_transfer_target")
            val members = vaultMemberIds(c, vaultId)
            clearPendingTransfer(c, vaultId, if (isOwner) "owner_cancel" else "target_decline", p, ip, bumpVaultRev = true)
            Triple(repo.currentRev(c), members, true)
        }
        if (changed) onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    /**
     * Transfer accept (design §4 TRANSFER 3-4): the designated pendingOwnerId flips roles
     * atomically — old owner → writer (wrappedVk retained, R7-consistent), new owner →
     * owner with the posted wrappedVk AND their sealedVk RETAINED as fallback key
     * material (spec 01's exactly-one rule is relaxed here; both are wiped together at
     * purge). transferSeq advances to the offer's seq. Idempotent retry / owner-of-record
     * self-heal: the current owner re-posting with offerId == lastTransferOfferId gets its
     * wrappedVk re-stored (fresh-wrap self-heal, design §4 TRANSFER 5).
     */
    suspend fun acceptTransfer(p: Principal, vaultId: String, req: TransferAcceptRequest, ip: String): CreateVaultResponse {
        if (!UUID_RE.matches(req.offerId)) throw BadRequest("bad_offer_id")
        requireB64(req.wrappedVk, 1024, "wrapped_vk")
        requireB64(req.proof, 64, "proof")
        val (rev, notify) = repo.db.tx { c ->
            val g = repo.grantRowAny(c, p.userId, vaultId) ?: throw Forbidden("no_grant")
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("no_grant")
            // Guard order (#6): classify the caller's grant FIRST — never vault.deletedAt.
            // A vault_delete-revoked grant-holder → vault_deleted; any other revoked caller →
            // uniform 403 no_grant regardless of vault state. An active grant implies a live
            // vault (delete revokes all grants), so the self-heal branch below is delete-safe.
            if (g.revokedAt != null) {
                if (g.revokedReason == "vault_delete") throw Conflict("vault_deleted")
                throw Forbidden("no_grant")
            }
            if (g.role == "owner" && v.lastTransferOfferId == req.offerId) {
                // Owner of record for this offer. A pure lost-response retry (identical
                // wrappedVk) is truly READ-ONLY — no rev churn (#8). Only a genuine self-heal
                // (a DIFFERENT wrappedVk, e.g. a cold-start re-wrap that opened via sealedVk)
                // re-stores the wrap + acceptProof and bumps the revs.
                if (g.wrappedVk == req.wrappedVk) {
                    return@tx repo.currentRev(c) to emptySet<String>()
                }
                val gr = repo.nextRev(c, "grant", vaultId, vaultId)
                c.exec("UPDATE grants SET wrappedVk=?, rev=? WHERE vaultId=? AND userId=?", req.wrappedVk, gr, vaultId, p.userId)
                val vr = repo.nextRev(c, "vault", vaultId, vaultId)
                c.exec("UPDATE vaults SET lastTransferAcceptProof=?, rev=? WHERE vaultId=?", req.proof, vr, vaultId)
                repo.auditOn(c, "vault_transfer_accept", p.userId, p.deviceId, ip, "$vaultId:rewrap:${p.userId}")
                return@tx repo.currentRev(c) to vaultMemberIds(c, vaultId)
            }
            // In-tx re-checks (design §4 matrix: accept-vs-cancel/expire/delete).
            if (v.pendingOfferId == null || v.pendingOfferId != req.offerId) throw Conflict("transfer_not_pending")
            if (v.pendingOwnerId != p.userId) throw Forbidden("not_transfer_target")
            if ((v.pendingOfferExpiresAt ?: 0L) <= now()) throw Conflict("transfer_not_pending")
            // (g.revokedAt is already screened at the top — g is active here.)
            // Belt (design §4 TRANSFER 2): a grant re-created AFTER the offer was set must
            // not inherit the offer (remove → re-add → forgotten-banner seizure).
            if ((g.addedAt ?: 0L) > (v.pendingOfferSetAt ?: Long.MAX_VALUE)) throw Conflict("transfer_not_pending")
            val oldOwner = c.queryOne(
                "SELECT userId FROM grants WHERE vaultId=? AND role='owner' AND revokedAt IS NULL", vaultId,
            ) { it.getString(1) } ?: throw Conflict("transfer_not_pending")
            val seq = v.transferSeq + 1
            val gr1 = repo.nextRev(c, "grant", vaultId, vaultId)
            c.exec("UPDATE grants SET role='writer', rev=? WHERE vaultId=? AND userId=?", gr1, vaultId, oldOwner)
            val gr2 = repo.nextRev(c, "grant", vaultId, vaultId)
            // sealedVk deliberately RETAINED on the new owner's grant (keyless-owner fallback).
            c.exec("UPDATE grants SET role='owner', wrappedVk=?, rev=? WHERE vaultId=? AND userId=?", req.wrappedVk, gr2, vaultId, p.userId)
            val vr = repo.nextRev(c, "vault", vaultId, vaultId)
            c.exec(
                """UPDATE vaults SET transferSeq=?, lastTransferOfferId=?, lastTransferAcceptProof=?,
                   pendingOwnerId=NULL, pendingOfferId=NULL, pendingOfferProof=NULL,
                   pendingOfferExpiresAt=NULL, pendingOfferSetAt=NULL, rev=? WHERE vaultId=?""",
                seq, req.offerId, req.proof, vr, vaultId,
            )
            repo.auditOn(c, "vault_transfer_accept", p.userId, p.deviceId, ip, "$vaultId:$oldOwner:${p.userId}")
            repo.currentRev(c) to vaultMemberIds(c, vaultId)
        }
        onChange(notify, rev)
        return CreateVaultResponse(rev)
    }

    /**
     * Rename (design §4 RENAME): the owner's client read-modify-writes the metaBlob
     * (ciphertext — the server audits ids only). Optional baseVaultRev stale-write guard.
     * Active-owner-first guard: rename against a deleted vault hits the revoked grant →
     * 403 (design §4 matrix: rename-vs-delete).
     */
    suspend fun updateVaultMeta(p: Principal, vaultId: String, req: VaultMetaUpdateRequest, ip: String): CreateVaultResponse {
        requireB64(req.metaBlob, 4096, "meta_blob")
        val (rev, notify) = repo.db.tx { c ->
            requireOwnerOfShared(c, p, vaultId)
            val v = repo.vaultRowById(c, vaultId) ?: throw Forbidden("not_vault_owner")
            if (v.deletedAt != null) throw Conflict("vault_deleted") // belt; delete revokes the owner grant
            val base = req.baseVaultRev
            if (base != null && base < v.rev) throw Conflict("stale_meta")
            val vr = repo.nextRev(c, "vault", vaultId, vaultId)
            c.exec("UPDATE vaults SET metaBlob=?, rev=? WHERE vaultId=?", req.metaBlob, vr, vaultId)
            repo.auditOn(c, "vault_rename", p.userId, p.deviceId, ip, vaultId)
            repo.currentRev(c) to vaultMemberIds(c, vaultId)
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
        accountKeys = AccountKeys(u.kdfSalt, u.kdfParams, u.wrappedUvk, u.encryptedIdentitySeed, u.identityPub, config.recoveryFingerprint, escrowStale(u.userId)),
        isAdmin = isAdmin, mustChangePassword = mustChange, totpEnrolled = u.totpSecret != null,
    )

    companion object {
        // A fixed valid argon2id string so unknown-user logins spend the same CPU (timing).
        val DUMMY_VERIFIER: String = ServerCrypto.hashVerifier("andvari-dummy-authkey")
        private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        internal const val DAY_MS = 24L * 3600 * 1000
    }
}
