package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.model.wire.AccountRecoveryPut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.DeviceHow
import io.silencelen.andvari.core.model.wire.EscrowSelfPut
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.NewDevice
import io.silencelen.andvari.core.model.wire.PasswordChangeRequest
import io.silencelen.andvari.core.model.wire.RecoveryCommitRequest
import io.silencelen.andvari.core.model.wire.RecoveryPosture
import io.silencelen.andvari.core.model.wire.RecoverySelfConfirmRequest
import io.silencelen.andvari.core.model.wire.RecoverySelfSetupRequest
import io.silencelen.andvari.core.model.wire.RecoverySelfSetupResponse
import io.silencelen.andvari.core.model.wire.RecoveryVerifyRequest
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.sql.Connection
import java.util.concurrent.ConcurrentHashMap

/** The single-use, user-bound recovery tickets of spec 03 §12, in memory only (5 minutes). */
class RecoveryTickets(private val clock: Clock, private val ttlMs: Long = 5 * 60_000L) {
    private class Entry(val userId: String, val verifier: String, val expiresAt: Long)
    private val map = ConcurrentHashMap<String, Entry>()

    fun mint(userId: String, recoveryVerifier: String): String {
        val t = clock.now()
        map.entries.removeIf { it.value.expiresAt <= t }
        val token = ServerCrypto.newToken()
        map[ServerCrypto.hashToken(token)] = Entry(userId, recoveryVerifier, t + ttlMs)
        return token
    }

    /** Consume [token]: the userId and the recovery verifier it was minted against, or null. */
    fun redeem(token: String): Pair<String, String>? {
        val e = map.remove(ServerCrypto.hashToken(token)) ?: return null
        // Expiry is exclusive (spec 03 §0.1): valid while now < expiresAt.
        return if (clock.now() < e.expiresAt) e.userId to e.verifier else null
    }
}

private val DUMMY_RECOVERY: String by lazy { ServerCrypto.DUMMY_RECOVERY_VERIFIER }

/**
 * The credential reset both recovery commits share (spec 03 §12, §18.5), inside [c]: the new verifier,
 * salt, params and `wrappedUvk`; the member-recovery row REPLACED (new `pieceId`, `recoveryConfirmed = 0`),
 * so the old kit stops working at once; every session revoked; **the `deviceSecret` hash of every earlier
 * device of the account cleared**, deliberately: after a recovery no earlier device is a known device
 * (§16.8), so each must sign in as new (and pass `requireLink` if it is turned on again); every pending
 * assisted-recovery request cancelled; `requireLink` and two-step sign-in cleared; the new device
 * (`how = recovered`) and its session. Emails `recovery_applied`, and `two_step_off` /
 * `require_link_cleared` where they apply. Returns the session answer with the new piece id.
 */
fun commitRecovery(
    s: Services, c: Connection, userId: String, newAuthKey: String, salt: String, params: io.silencelen.andvari.core.crypto.KdfParams,
    wrappedUvk: String, mr: MemberRecoveryBlock, device: NewDevice, secretHash: String, clientPlatform: String, clientVersion: String?,
    how: String,
): SessionResponse {
    val nowMs = s.clock.now()
    // Inside the commit's own transaction: a disable that lands between a route's pre-check and
    // here still refuses the commit, for the kit commit and the assisted commit alike.
    val status = c.queryOne("SELECT status FROM users WHERE userId=?", userId) { it.getString(1) }
    if (status != "active") badRequest(WireErrors.RECOVERY_ACCOUNT_NOT_ACTIVE)
    val (totpWasOn, linkWasOn) = c.queryOne("SELECT totpSecret,requireLink FROM users WHERE userId=?", userId) { (it.getString(1) != null) to it.bool("requireLink") }!!
    c.exec(
        """UPDATE users SET verifier=?, kdfSalt=?, kdfParams=?, wrappedUvk=?, recoveryConfirmed=0, requireLink=0,
             totpSecret=NULL, totpPendingSecret=NULL, totpEnrolledAt=NULL, totpLastStep=0 WHERE userId=?""",
        ServerCrypto.hashVerifier(newAuthKey), salt, encodeParams(params), wrappedUvk, userId,
    )
    s.sessions.revokeAllOf(c, userId)
    // Intended, not an accident: a recovery makes every earlier device unknown (spec 03 §16.8), so a device
    // that was signed in before it must pass "New devices must be linked" and the new_device notice again.
    c.exec("UPDATE devices SET deviceSecretHash=NULL WHERE userId=?", userId)
    // Every request still pending is void after a recovery (and the assisted commit deletes its own after this).
    Assisted.cancelPending(c, userId, nowMs)
    // The recovery completed, so the address's mailbox values have done their work (spec 03 §18.1).
    Assisted.forgetMailboxValuesOf(c, s.config, userId)
    val deviceId = s.sessions.createDevice(c, userId, device.platform, device.name, DeviceHow.RECOVERED, secretHash, clientVersion)
    val pieceId = ServerCrypto.newToken()
    c.exec(
        """INSERT INTO member_recovery(userId,recoveryWrappedUvk,recoveryVerifier,pieceId,setupDeviceId,updatedAt) VALUES(?,?,?,?,?,?)
           ON CONFLICT(userId) DO UPDATE SET recoveryWrappedUvk=excluded.recoveryWrappedUvk, recoveryVerifier=excluded.recoveryVerifier,
             pieceId=excluded.pieceId, setupDeviceId=excluded.setupDeviceId, updatedAt=excluded.updatedAt""",
        userId, mr.recoveryWrappedUvk, ServerCrypto.hashVerifier(mr.recoveryAuthKey), pieceId, deviceId, nowMs,
    )
    val issued = s.sessions.issue(c, userId, deviceId, clientPlatform, passwordLogin = true)
    // The recovering device by the server's own words for it and its name in the narrow form a mail shows (MailDevices).
    notify(s, c, userId, "recovery_applied", MailDevices.of(c, deviceId, isNew = true), mapOf("how" to how))
    // `how` tells the mail rule which commit sent them (MailTemplates.carriesAccountId); neither template prints it.
    if (totpWasOn) notify(s, c, userId, "two_step_off", vars = mapOf("why" to "Your account was recovered, which turns two-step sign-in off.", "how" to how))
    if (linkWasOn) notify(s, c, userId, "require_link_cleared", vars = mapOf("how" to how))
    afterCommit(c) { s.notifier.notifyRevokedUserExcept(userId, deviceId) }
    return sessionResponse(c, s.config, userId, issued, pieceId)
}

/** Shape checks of a credential reset's body (spec 03 §12): KDF floor and shape, salt, the kit block, the device. */
fun checkResetBody(s: Services, newAuthKey: String, salt: String, params: io.silencelen.andvari.core.crypto.KdfParams, wrappedUvk: String, mr: MemberRecoveryBlock?, device: NewDevice): Pair<MemberRecoveryBlock, String> {
    s.policy.requireWrapKdf(params)
    s.policy.requireKdfSalt(salt)
    val kit = requireMemberRecovery(mr)
    Grammar.requireB64(newAuthKey, "newAuthKey", Caps.AUTH_KEY)
    Grammar.requireB64(wrappedUvk, "newWrappedUvk", Caps.KEY_ENVELOPE)
    Grammar.requirePlatform(device.platform)
    Grammar.requireText(device.name, "device")
    val secretHash = deviceSecretHash(device.deviceSecret) ?: badRequest(WireErrors.badField("device"))
    return kit to secretHash
}

fun Route.recoveryRoutes(s: Services) {
    /**
     * `PUT /account/password` (spec 03 §3), session†: the verify-then-write is a compare-and-swap on the
     * credential (`401 credential_changed` when it changed in between); every other session is revoked;
     * `password_changed` is sent. The UVK is unchanged, so the escrow and the kit stay valid.
     */
    api(WireRoute.PASSWORD_CHANGE, s, Bucket.devicePerMinute("password_change", 5)) {
        val req = body<PasswordChangeRequest>()
        val verifier = reauth(req.currentAuthKey, "password_change_fail")
        s.policy.requireWrapKdf(req.newKdfParams)
        s.policy.requireKdfSalt(req.newKdfSalt)
        Grammar.requireB64(req.newAuthKey, "newAuthKey", Caps.AUTH_KEY)
        Grammar.requireB64(req.newWrappedUvk, "newWrappedUvk", Caps.KEY_ENVELOPE)
        val principal = p
        val newVerifier = ServerCrypto.hashVerifier(req.newAuthKey)
        s.raceHook?.invoke("password.afterGate")
        val r = s.db.tx { c ->
            val n = c.exec(
                "UPDATE users SET verifier=?, kdfSalt=?, kdfParams=?, wrappedUvk=? WHERE userId=? AND verifier=? AND status='active'",
                newVerifier, req.newKdfSalt, encodeParams(req.newKdfParams), req.newWrappedUvk, principal.userId, verifier,
            )
            if (n != 1 || !s.sessions.sessionLive(c, principal.sessionId)) return@tx false
            s.sessions.revokeAllOf(c, principal.userId, exceptSessionId = principal.sessionId)
            Assisted.cancelPending(c, principal.userId, now)
            s.audit.on(c, "password_change", principal.userId, principal.deviceId, ip)
            notify(s, c, principal.userId, "password_changed", MailDevices.of(c, principal.deviceId))
            // The notice follows the revocation, session by session: every other session's sockets, on this device too.
            afterCommit(c) { s.notifier.notifyRevokedUserExceptSession(principal.userId, principal.sessionId) }
            true
        }
        if (!r) unauthorized(WireErrors.CREDENTIAL_CHANGED)
        ok()
    }

    /**
     * `PUT /account/recovery` (spec 03 §3.1), session†. Checks, in order: the password proof; the posture
     * (`escrow_not_allowed`, `operator_recovery_unavailable`, `bad_escrow`); the account state's
     * compare-and-set (`409 stale_state`). Then one transaction: the escrow change (`private` deletes it,
     * with secure delete and a WAL truncate), the mirror, and the sealed state. `recovery_changed`; audited.
     */
    api(WireRoute.ACCOUNT_RECOVERY_PUT, s) {
        val req = body<AccountRecoveryPut>()
        checkSealedState(req.accountState.sealedState)
        reauth(req.currentAuthKey)
        val principal = p
        var deleted = false
        val resp: AccountStateResponse = s.db.tx { c ->
            val (old, role, email) = c.queryOne("SELECT recovery,role,email FROM users WHERE userId=?", principal.userId) {
                Triple(it.getString(1), it.getString(2), it.getString(3))
            }!!
            checkPosture(s, c, req.posture, req.escrow, isOperatorAccount = role == "operator", emailNorm = email)
            val st = putAccountState(c, principal.userId, req.accountState, now)
            if (req.posture == RecoveryPosture.PRIVATE) {
                deleted = c.exec("DELETE FROM escrow WHERE userId=?", principal.userId) > 0
                Assisted.cancelPending(c, principal.userId, now)
                // The address's mailbox values open requests the operator can take, and in this posture there are none
                // (spec 03 §18.1): they are forgotten. A password change keeps them (they open nothing but one more request).
                Assisted.forgetMailboxValuesOf(c, s.config, principal.userId)
            } else {
                val e = req.escrow!!
                c.exec(
                    "INSERT INTO escrow(userId,sealed,fingerprint,updatedAt) VALUES(?,?,?,?) ON CONFLICT(userId) DO UPDATE SET sealed=excluded.sealed, fingerprint=excluded.fingerprint, updatedAt=excluded.updatedAt",
                    principal.userId, e.sealed, e.fingerprint, now,
                )
            }
            c.exec("UPDATE users SET recovery=? WHERE userId=?", req.posture, principal.userId)
            s.audit.on(c, "account_recovery_change", principal.userId, principal.deviceId, ip, "posture=${req.posture}")
            notify(s, c, principal.userId, "recovery_changed", MailDevices.of(c, principal.deviceId), mapOf("old" to old, "new" to req.posture))
            st
        }
        if (deleted) s.db.checkpointTruncate()
        respond(resp)
    }

    /**
     * `PUT /escrow/self` (spec 03 §3.2), **R**: a re-seal after rotation statements signed offline by the
     * outgoing recovery seed. The posture mirror is `operator` (`400 escrow_not_allowed`); the blob's shape
     * (`400 bad_escrow`); the chain from the current escrow's fingerprint to the new one (`409 escrow_not_due`,
     * also for an empty list). The new blob replaces the old one. Audited `escrow_self_reseal`.
     */
    api(WireRoute.ESCROW_SELF, s, Bucket.devicePerMinute("escrow_self", 10)) {
        val req = body<EscrowSelfPut>()
        val principal = p
        s.db.tx { c ->
            val (posture, email) = c.queryOne("SELECT recovery,email FROM users WHERE userId=?", principal.userId) { it.getString(1) to it.getString(2) }!!
            if (posture != RecoveryPosture.OPERATOR) badRequest(WireErrors.ESCROW_NOT_ALLOWED)
            val upload = EscrowUpload(req.sealed, req.fingerprint)
            if (!escrowShapeOk(upload)) badRequest(WireErrors.BAD_ESCROW)
            // A re-seal is the new form too, so a new copy is never replaced by an old one (spec 04 §3).
            EscrowCopy.requireCurrentForm(upload, email)
            // Only now the rotations (§3.2's order): more than 64, an empty list, a frame that does not even
            // decode and a chain that does not link are all the same 409.
            if (req.rotations.isEmpty() || req.rotations.size > 64) conflict(WireErrors.ESCROW_NOT_DUE)
            val frames = req.rotations.map { frameBytesOrNull(it) ?: conflict(WireErrors.ESCROW_NOT_DUE) }
            val currentFp = c.queryOne("SELECT fingerprint FROM escrow WHERE userId=?", principal.userId) { it.getString(1) } ?: conflict(WireErrors.ESCROW_NOT_DUE)
            if (!s.trust.verifyRotationChain(frames, s.instance.instanceId(c), currentFp, req.fingerprint)) conflict(WireErrors.ESCROW_NOT_DUE)
            c.exec("UPDATE escrow SET sealed=?, fingerprint=?, updatedAt=? WHERE userId=?", req.sealed, req.fingerprint, now, principal.userId)
            s.audit.on(c, "escrow_self_reseal", principal.userId, principal.deviceId, ip)
        }
        s.db.checkpointTruncate()
        ok()
    }

    /**
     * `POST /recovery/self/verify` (spec 03 §12), phase 1: per-IP only, and NOTHING else (no email backoff:
     * a per-account counter on the last-resort path would lock the victim out). An unknown address, a known
     * one with no kit row, and a wrong key all run a full verify and answer the uniform `401`.
     */
    api(WireRoute.RECOVERY_SELF_VERIFY, s, Bucket.ipPerMinute("recovery_verify", 5)) {
        val req = body<RecoveryVerifyRequest>()
        val email = Grammar.emailOrNull(req.email)
        val row = email?.let { e ->
            s.db.read { c ->
                c.queryOne(
                    """SELECT u.userId,u.encryptedIdentitySeed,u.identityPub,m.recoveryWrappedUvk,m.recoveryVerifier
                       FROM users u JOIN member_recovery m ON m.userId=u.userId WHERE u.email=?""",
                    e,
                ) { listOf(it.getString(1), it.getString(2), it.getString(3), it.getString(4), it.getString(5)) }
            }
        }
        val ok = withContext(Dispatchers.IO) {
            runCatching { ServerCrypto.verify(row?.get(4) ?: DUMMY_RECOVERY, req.recoveryAuthKey) }.getOrDefault(false)
        }
        if (row == null || !ok) {
            s.db.tx { c -> s.audit.on(c, "recovery_self_verify_fail", null, null, ip) }
            unauthorized()
        }
        val ticket = s.recoveryTickets.mint(row[0], row[4])
        respond(RecoveryVerifyResponse(row[0], ticket, row[3], row[1], row[2]))
    }

    /**
     * `POST /recovery/self/commit` (spec 03 §12), phase 2: the ticket (consumed; `401 invalid_ticket`), an
     * active account (`400 recovery_account_not_active`), the KDF and kit checks, then [commitRecovery].
     * Audited `recovery_self_commit`.
     */
    api(WireRoute.RECOVERY_SELF_COMMIT, s, SharedBuckets.RECOVERY_COMMIT) {
        val req = body<RecoveryCommitRequest>()
        val (userId, ticketVerifier) = s.recoveryTickets.redeem(req.recoveryTicket) ?: unauthorized(WireErrors.INVALID_TICKET)
        val active = s.db.read { c -> c.queryOne("SELECT status FROM users WHERE userId=?", userId) { it.getString(1) } } == "active"
        if (!active) badRequest(WireErrors.RECOVERY_ACCOUNT_NOT_ACTIVE)
        val (kit, secretHash) = checkResetBody(s, req.newAuthKey, req.newKdfSalt, req.newKdfParams, req.newWrappedUvk, req.newMemberRecovery, req.device)
        val clientVersion = call.declaredClientVersion()
        val resp = s.db.tx { c ->
            // The kit the ticket was minted against must still be the account's (a concurrent commit replaced it otherwise).
            val still = c.queryOne("SELECT recoveryVerifier FROM member_recovery WHERE userId=?", userId) { it.getString(1) }
            if (still != ticketVerifier) unauthorized(WireErrors.INVALID_TICKET)
            val r = commitRecovery(s, c, userId, req.newAuthKey, req.newKdfSalt, req.newKdfParams, req.newWrappedUvk, kit, req.device, secretHash,
                headerPlatform ?: req.device.platform, clientVersion, "with your recovery kit")
            s.audit.on(c, "recovery_self_commit", userId, r.deviceId, ip)
            r
        }
        respond(SessionResponse.serializer(), resp)
    }

    /**
     * `PUT /recovery/self-setup` (spec 03 §12), session†, bucket `recovery_setup` 5/min per device: rotate the kit. A fresh `pieceId`, the committing
     * device, and `recoveryConfirmed` back to 0. Audited `recovery_self_setup`.
     */
    api(WireRoute.RECOVERY_SELF_SETUP, s, Bucket.devicePerMinute("recovery_setup", 5)) {
        val req = body<RecoverySelfSetupRequest>()
        reauth(req.currentAuthKey, "recovery_self_setup_fail")
        val kit = requireMemberRecovery(req.memberRecovery)
        val principal = p
        val pieceId = ServerCrypto.newToken()
        val recoveryVerifier = ServerCrypto.hashVerifier(kit.recoveryAuthKey)
        s.db.tx { c ->
            c.exec(
                """INSERT INTO member_recovery(userId,recoveryWrappedUvk,recoveryVerifier,pieceId,setupDeviceId,updatedAt) VALUES(?,?,?,?,?,?)
                   ON CONFLICT(userId) DO UPDATE SET recoveryWrappedUvk=excluded.recoveryWrappedUvk, recoveryVerifier=excluded.recoveryVerifier,
                     pieceId=excluded.pieceId, setupDeviceId=excluded.setupDeviceId, updatedAt=excluded.updatedAt""",
                principal.userId, kit.recoveryWrappedUvk, recoveryVerifier, pieceId, principal.deviceId, now,
            )
            c.exec("UPDATE users SET recoveryConfirmed=0 WHERE userId=?", principal.userId)
            s.audit.on(c, "recovery_self_setup", principal.userId, principal.deviceId, ip)
        }
        respond(RecoverySelfSetupResponse(pieceId))
    }

    /**
     * `POST /recovery/self/confirm` (spec 03 §12), bucket `recovery_confirm` 5/min per device: flips `recoveryConfirmed` once the person typed the kit
     * back. With a `pieceId` it must name the CURRENT piece (`409 recovery_piece_stale`); without one, only
     * the device that committed the piece may confirm.
     */
    api(WireRoute.RECOVERY_SELF_CONFIRM, s, Bucket.devicePerMinute("recovery_confirm", 5)) {
        val req = runCatching { body<RecoverySelfConfirmRequest>() }.getOrElse { RecoverySelfConfirmRequest(null) }
        val principal = p
        val r = s.db.tx { c ->
            val (pieceId, setupDevice) = c.queryOne("SELECT pieceId,setupDeviceId FROM member_recovery WHERE userId=?", principal.userId) { it.getString(1) to it.getString(2) }
                ?: (null to null)
            val accepted = if (req.pieceId != null) pieceId != null && req.pieceId == pieceId else setupDevice == principal.deviceId
            if (!accepted) {
                s.audit.on(c, "recovery_self_confirm_stale", principal.userId, principal.deviceId, ip)
                return@tx false
            }
            c.exec("UPDATE users SET recoveryConfirmed=1 WHERE userId=?", principal.userId)
            s.audit.on(c, if (req.pieceId != null) "recovery_self_confirm" else "recovery_self_confirm_unbound", principal.userId, principal.deviceId, ip)
            true
        }
        if (!r) conflict(WireErrors.RECOVERY_PIECE_STALE)
        ok()
    }
}
