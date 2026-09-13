package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AdminStatus
import io.silencelen.andvari.core.model.AdminUserSummary
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.RecoveryUpload
import kotlinx.serialization.Serializable
import java.io.File

/**
 * H25 (audit 2026-09-13): the device row the Admin device list renders — core's
 * `AdminDeviceSummary` (the client-decodable subset) plus the two liveness fields the server
 * derives. A SERVER-side superset in the InviteCreateResponse mould (App.kt): the wire stays
 * additive — every client decodes with ignoreUnknownKeys, so a build that only knows the core
 * shape sees exactly what it saw before — while the server can say what only it knows.
 *   live        — the device still holds access: not revoked, and a session exists that is not
 *                 revoked and whose refresh chain has not lapsed ([AdminService.LIVE_SESSION_FOR_DEVICE_SQL]).
 *                 THE field the console keys the Revoke control on: `!live` renders "signed out"
 *                 (or "revoked" when revokedAt is set), never a Revoke button over nothing.
 *   signedOutAt — when the member's own /auth/logout stamped the row (Service.logout); null for
 *                 a device that was revoked, lapsed, or is still live. Distinct from revokedAt on
 *                 purpose: an admin revoke and a member sign-out are different events.
 */
@Serializable
data class AdminDeviceView(
    val deviceId: String,
    val platform: String,
    val name: String,
    val clientVersion: String?,
    val createdAt: Long,
    val lastSeenAt: Long?,
    val revokedAt: Long?,
    val signedOutAt: Long?,
    val live: Boolean,
)

/** Admin operations (spec 03 §7). All callers are already checked isAdmin by the route. */
class AdminService(private val repo: Repo, private val config: Config) {

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
                // H25 (audit 2026-09-13): the count answers "how many devices still hold access to
                // the household vault", so it is DERIVED from live sessions — not read off the
                // admin-only revokedAt column, which a member's own sign-out never touched. Every
                // login mints a fresh device row, so the old COUNT(*) grew monotonically with
                // sign-ins ("5 devices" for one phone re-enrolled five times) and an admin could
                // not tell a compromised live device from a long-gone one. Same definition of
                // "live" as Service.deviceHasLiveSession (a non-revoked session under a non-revoked
                // device), plus the refresh-chain expiry: a device whose last refresh token lapsed
                // cannot come back without a fresh login, which mints a new row.
                deviceCount = c.queryOne(LIVE_DEVICE_COUNT_SQL, userId, now()) { r -> r.getInt(1) } ?: 0,
                // Posture reconciliation (design §F.4): escrowFingerprint==null ⇒ no admin backstop
                // (waived, intended — or, for a legacy pre-migration account, never escrowed).
                // recoveryEnrolled ⇒ the account holds its self-service piece. The two together let the
                // Admin UI distinguish "waived (intended)" from "no recovery at all (needs setup)" and
                // surface a server-side policy flip on reconciliation.
                escrowFingerprint = c.queryOne("SELECT fingerprint FROM escrow WHERE userId=?", userId) { r -> r.getString(1) },
                recoveryEnrolled = c.queryOne("SELECT 1 FROM member_recovery WHERE userId=?", userId) { true } ?: false,
                // The invite's escrow posture persisted at register (v8): 'required'|'waived'; NULL =
                // pre-v8 account (legacy, posture unknown). Server column only — no client body ever
                // sets it — so reconciliation can tell an intended waiver from a required member whose
                // escrow blob went missing.
                escrowPolicy = rs.getString("escrowPolicy"),
            )
        }
    }

    /** Create an invite; returns the plaintext token ONCE (only its hash is stored). [escrowPolicy]
     *  is the admin's per-invite recovery posture (design §F.4), persisted on the invite row and read
     *  SERVER-SIDE at register — normalized to 'waived'|'required' (anything but the literal 'waived'
     *  ⇒ 'required', fail-safe, matching the register gate). */
    fun createInvite(email: String, isAdmin: Boolean, byUserId: String, ttlMinutes: Int? = null, sendEmail: Boolean = false, escrowPolicy: String = "required"): Pair<InviteResponse, String> = repo.db.tx { c ->
        // B1: validate the address BEFORE it is stored — it's admin-typed free text that can reach
        // SMTP, and a CR/LF/comma is a header-injection primitive. Applies to ALL invites (the
        // bootstrap "*" invite is a raw insert in App.kt, not this path, so it is unaffected).
        if (!EmailAddress.isValid(email)) throw BadRequest("invalid_email")
        if (repo.userByEmail(email) != null) throw BadRequest("email_taken")
        val token = ServerCrypto.newToken()
        val tokenHash = ServerCrypto.hashToken(token)
        // Optional short TTL (S4 QR invites), clamped to [5 min, 72 h]; absent → 72 h unchanged.
        // There is NO invite list/revoke surface, so this clamp is the SOLE containment for a
        // photographed/leaked QR — never honor a client-requested TTL outside these bounds.
        var ttlMs = ttlMinutes?.let { it.coerceIn(5, 72 * 60) * 60_000L } ?: inviteTtlMs
        // A2: an emailed invite is a bearer token that rests in an inbox → clamp the FINAL ttl to
        // ≤60 min (AFTER the null→72h default resolves, so no client can email a 72h token).
        if (sendEmail) ttlMs = minOf(ttlMs, 60L * 60_000L)
        val expiresAt = now() + ttlMs
        val policy = if (escrowPolicy == "waived") "waived" else "required"
        c.exec(
            "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt,escrowPolicy) VALUES(?,?,?,?,?,?)",
            tokenHash, email.lowercase(), isAdmin, now(), expiresAt, policy,
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

    /** Returns the revoked device's owner userId so the route can push {revoked} + close that
     *  device's live WS socket (M8). An UNKNOWN deviceId is a refusal, not a no-op success: the
     *  admin who mistyped/pasted a stale id must not be told "ok" while the compromised device
     *  stays live, and the audit trail must not carry a device_revoke row for a device that never
     *  existed — an incident review reads that as a completed revocation (bug-server--8). Audited
     *  as device_revoke_denied INSIDE the tx and thrown OUTSIDE it, exactly like [disableUser]. */
    fun revokeDevice(deviceId: String, byUserId: String): String {
        val owner: String? = repo.db.tx { c ->
            val found = c.queryOne("SELECT userId FROM devices WHERE deviceId=?", deviceId) { it.getString(1) }
            if (found == null) {
                // meta carries the reason ALONE — unlike user_disable_denied, the audit row has a
                // deviceId column of its own, so restating the id there would just duplicate it.
                repo.auditOn(c, "device_revoke_denied", byUserId, deviceId, null, "no_such_device")
                return@tx null
            }
            c.exec("UPDATE devices SET revokedAt=? WHERE deviceId=?", now(), deviceId)
            c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now(), deviceId)
            repo.auditOn(c, "device_revoke", byUserId, deviceId, null)
            found
        }
        return owner ?: throw NotFound("no_such_device")
    }

    /** Upload recovery-cli output (spec 04 §4): set temp creds + force change + revoke sessions. */
    fun applyRecovery(req: RecoveryUpload, byUserId: String) = repo.db.tx { c ->
        // L1 (spec 05 T1/T8): the admin recovery bundle sets a login verifier + kdfParams exactly like
        // register / change / self-recovery — floor it too, so no password-set path can persist a
        // brute-forceable verifier. recovery-cli emits KdfParams.DEFAULT (at-floor) so this is a no-op
        // for the honest producer; it fails closed only on a hand-edited sub-floor bundle.
        requireKdfFloor(req.tempKdfParams, config)
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

    /**
     * H25: every device row the user ever minted, each with its liveness DERIVED from the sessions
     * join — the same rule [LIVE_DEVICE_COUNT_SQL] counts by, so the list and the count can never
     * disagree. Newest first, dead rows included: the admin's question is "which of these still
     * holds access", and the answer for a signed-out row is `live=false` + `signedOutAt`, rendered
     * as "signed out", not a Revoke button (the janitor ages session-less rows out after 90 d).
     */
    fun listDevices(userId: String): List<AdminDeviceView> = repo.db.read { c ->
        c.queryAll(
            """SELECT d.*, EXISTS($LIVE_SESSION_FOR_DEVICE_SQL) AS live
               FROM devices d WHERE d.userId=? ORDER BY d.createdAt DESC""",
            now(), userId,
        ) { rs ->
            val revokedAt = rs.getLong("revokedAt").let { v -> if (rs.wasNull()) null else v }
            AdminDeviceView(
                deviceId = rs.getString("deviceId"),
                platform = rs.getString("platform"),
                name = rs.getString("name"),
                clientVersion = rs.getString("clientVersion"),
                createdAt = rs.getLong("createdAt"),
                lastSeenAt = rs.getLong("lastSeenAt").let { v -> if (rs.wasNull()) null else v },
                revokedAt = revokedAt,
                signedOutAt = rs.getLong("signedOutAt").let { v -> if (rs.wasNull()) null else v },
                // A revoked device is never live regardless of its session rows (revokeDevice stamps
                // both, but the row's own flag is the authority the M8 socket re-check reads too).
                live = revokedAt == null && rs.getInt("live") != 0,
            )
        }
    }

    companion object {
        /** H25: "this device still holds access" — a session that is not revoked and whose refresh
         *  chain has not lapsed. Parameter 1 = now (ms). Correlated against the outer `d` row. */
        internal const val LIVE_SESSION_FOR_DEVICE_SQL =
            "SELECT 1 FROM sessions s WHERE s.deviceId = d.deviceId AND s.revokedAt IS NULL AND s.refreshExpiresAt > ?"

        /** H25: the user table's device count. Parameters: userId, now (ms). */
        internal const val LIVE_DEVICE_COUNT_SQL =
            """SELECT COUNT(*) FROM devices d WHERE d.userId=? AND d.revokedAt IS NULL AND EXISTS($LIVE_SESSION_FOR_DEVICE_SQL)"""
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
            emailConfigured = config.emailConfigured,
        )
    }
}
