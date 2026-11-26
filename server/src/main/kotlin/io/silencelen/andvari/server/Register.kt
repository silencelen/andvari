package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.model.wire.AccountRole
import io.silencelen.andvari.core.model.wire.DeviceHow
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.LinkKind
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.RecoveryPosture
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.RegisterRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.sql.Connection

/** Caps of spec 03 §14.3 and §0.1, in characters of the encoded string. */
object Caps {
    const val KEY_ENVELOPE = 1024
    const val META_BLOB = 4096
    const val AUTH_KEY = 256
    const val LINK_ENVELOPE = 2732
    /** A sealed 0x02 escrow: `crypto_box_seal` (48 bytes) of one frame (103..1125 bytes). */
    const val ESCROW_SEALED_MIN_BYTES = 48 + 103
    const val ESCROW_SEALED_MAX_BYTES = 48 + 1125
}

/** The member-recovery block (spec 03 §12): present and well-formed, or `400 recovery_required`. */
fun requireMemberRecovery(mr: MemberRecoveryBlock?): MemberRecoveryBlock {
    if (mr == null) badRequest(WireErrors.RECOVERY_REQUIRED)
    val okWrap = Grammar.b64Bytes(mr.recoveryWrappedUvk, 1, Caps.KEY_ENVELOPE) != null && mr.recoveryWrappedUvk.length <= Caps.KEY_ENVELOPE
    val okKey = mr.recoveryAuthKey.length <= Caps.AUTH_KEY && Grammar.b64Bytes(mr.recoveryAuthKey, 16, 192) != null
    if (!okWrap || !okKey) badRequest(WireErrors.RECOVERY_REQUIRED)
    return mr
}

/** The escrow blob's shape and fingerprint (spec 03 §3.1): `400 bad_escrow` on anything malformed. */
fun escrowShapeOk(e: EscrowUpload?): Boolean {
    if (e == null) return false
    val bytes = Grammar.b64Bytes(e.sealed, Caps.ESCROW_SEALED_MIN_BYTES, Caps.ESCROW_SEALED_MAX_BYTES) ?: return false
    return bytes.isNotEmpty() && io.silencelen.andvari.core.model.wire.WireGrammar.isHex64(e.fingerprint)
}

/**
 * The one form of recovery copy the server stores (spec 04 §3, "every seal is version 3"). A version-3 copy names
 * the account's address inside its statement, and every other field of that statement has a fixed length, so the
 * copy has exactly one size for each address: the server cannot open a copy, but it can refuse every copy that is
 * not of that size, which is every copy of the old form (version 2 has no address: 444 bytes, never a version-3
 * size) and every copy sealed for another address length.
 */
object EscrowCopy {
    /**
     * The error of a copy whose size is not the version-3 size for the account's address (`400`): the client sealed
     * the old form, or sealed for another address. Checked after `bad_escrow`, so a malformed copy keeps that answer.
     */
    const val WRONG_FORM = "escrow_wrong_form"

    /**
     * The bytes of a sealed version-3 copy besides the address: the seal 48, the frame's header 101 (magic 4,
     * purpose 1, signer 32, signature 64) and the statement's 306 (its keys and fixed values with a 13-digit
     * `issuedAt`, and `,"email":""` around the address).
     */
    const val SEALED_BYTES_WITHOUT_ADDRESS = 455

    /**
     * The one size of a sealed version-3 copy for an account whose `emailNorm` is [emailNorm]: `455 + E`, with `E`
     * the length of the unpadded base64url of its octets (`ceil(4n / 3)`): 462 bytes at the shortest address
     * (5 octets), 478 for a 17-octet one, 794 at the longest (254 octets).
     */
    fun sealedBytes(emailNorm: String): Int {
        val n = emailNorm.encodeToByteArray().size
        return SEALED_BYTES_WITHOUT_ADDRESS + (4 * n + 2) / 3
    }

    /**
     * `400 escrow_wrong_form` unless [e]'s copy (already through [escrowShapeOk]) is exactly [sealedBytes] for the
     * account's [emailNorm]. Every route that stores a copy calls this before it writes: registration (every kind),
     * `PUT /account/recovery` and `PUT /escrow/self`.
     */
    fun requireCurrentForm(e: EscrowUpload, emailNorm: String) {
        val bytes = Grammar.b64Bytes(e.sealed, Caps.ESCROW_SEALED_MIN_BYTES, Caps.ESCROW_SEALED_MAX_BYTES) ?: badRequest(WireErrors.BAD_ESCROW)
        if (bytes.size != sealedBytes(emailNorm)) badRequest(WRONG_FORM)
    }
}

/**
 * The recovery posture rules (spec 03 §3.1, §14.3 step 8), shared by register and `PUT /account/recovery`:
 * `private` with an escrow is `escrow_not_allowed`; `operator` with no card recovery key (and always
 * before card 0), on a public instance, or for the operator account is `operator_recovery_unavailable`;
 * `operator` with a malformed escrow or a fingerprint other than the newest card's is `bad_escrow`; a copy that is
 * not the version-3 size for the account's address [emailNorm] is `escrow_wrong_form` ([EscrowCopy]).
 */
fun checkPosture(s: Services, c: Connection, posture: String, escrow: EscrowUpload?, isOperatorAccount: Boolean, emailNorm: String) {
    when (posture) {
        RecoveryPosture.PRIVATE -> if (escrow != null) badRequest(WireErrors.ESCROW_NOT_ALLOWED)
        RecoveryPosture.OPERATOR -> {
            val fp = s.instance.recoveryFp(c)
            if (fp == null || fp == "none" || s.config.isPublic || isOperatorAccount) badRequest(WireErrors.OPERATOR_RECOVERY_UNAVAILABLE)
            if (!escrowShapeOk(escrow) || escrow!!.fingerprint != fp) badRequest(WireErrors.BAD_ESCROW)
            EscrowCopy.requireCurrentForm(escrow, emailNorm)
        }
        else -> badRequest(WireErrors.badField("recovery"))
    }
}

/** True when [userId] (or its hash) is retired by an account deletion (spec 03 §13). */
fun isRetiredId(c: Connection, id: String): Boolean =
    c.queryOne("SELECT 1 FROM retired_ids WHERE idHash=?", sha256Hex(id)) { 1 } != null

fun Route.registerRoutes(s: Services) {
    /**
     * `POST /auth/register` (spec 03 §14.3, design §7.3). The checks run in the spec's order; the first
     * failure is the answer:
     *
     * 1. shapes and key-material caps, the KDF floor and shape, the salt bound, `memberRecovery`;
     * 2. the `auth` kind is allowed now: `setup` only while no operator exists (`403 setup_done`, exempt
     *    from the mode); every other kind waits for card 0 (`409 setup_incomplete`), then the effective
     *    mode (`403 signup_closed`);
     * 3. the ticket (`400 bad_ticket`, uniform) or the link row (`404 link_unknown`, `409 kind_mismatch`,
     *    `409 link_used`, `410 link_expired`, `403 email_mismatch`);
     * 4. age confirmation; 5. the cap, counted inside the transaction, and the daily maximum (setup is
     *    exempt from both; an enrol link counts against the cap only); 6. email, userId (live or retired)
     *    and personal vault id unused; 7. the genesis; 8. the recovery posture; 9. the personal vault ids.
     *
     * Then one transaction creates the account, its personal vault, wrap, kit row, escrow, consumes the
     * ticket or moves the link to `answered` (a register link also stores the answer and writes the
     * `connections` row), and creates the first device and its session. Audited `register` with the kind.
     */
    api(WireRoute.REGISTER, s, Bucket.ipPerHour("register", 10)) {
        val req = body<RegisterRequest>()
        // ---- step 1, in body order ----
        when (val a = req.auth) {
            is RegisterAuth.Ticket -> Grammar.requireB64_32(a.signupTicket, "auth")
            is RegisterAuth.Link -> {
                Grammar.requireB64_16(a.linkId, "auth"); Grammar.requireB64_32(a.registerToken, "auth")
                Grammar.requireB64(a.answer, "auth", Caps.LINK_ENVELOPE)
            }
            is RegisterAuth.Enrol -> { Grammar.requireB64_16(a.linkId, "auth"); Grammar.requireB64_32(a.registerToken, "auth") }
            is RegisterAuth.Setup -> { Grammar.requireB64_16(a.linkId, "auth"); Grammar.requireB64_32(a.registerToken, "auth") }
        }
        // Spec 03 §0.3: an address without an emailNorm is `400 invalid_email` wherever one is taken.
        val email = Grammar.requireEmail(req.email)
        val displayName = Grammar.requireText(req.displayName, "displayName")
        val userId = Grammar.requireUuid(req.userId, "userId")
        s.policy.requireKdfSalt(req.kdfSalt)
        s.policy.requireWrapKdf(req.kdfParams)
        Grammar.requireB64(req.authKey, "authKey", Caps.AUTH_KEY)
        Grammar.requireB64(req.wrappedUvk, "wrappedUvk", Caps.KEY_ENVELOPE)
        val identityPub = Grammar.b64Bytes(Grammar.requireB64_32(req.identityPub, "identityPub"), 32, 32)!!
        Grammar.requireB64(req.encryptedIdentitySeed, "encryptedIdentitySeed", Caps.KEY_ENVELOPE)
        val genesisFrame = frameBytes(req.genesis, WireErrors.BAD_GENESIS)
        val pv = req.personalVault
        if (!io.silencelen.andvari.core.model.wire.WireGrammar.isUuid(pv.vaultId) || pv.wrappedVk.length > Caps.KEY_ENVELOPE ||
            Grammar.b64Bytes(pv.wrappedVk, 1, Caps.KEY_ENVELOPE) == null || pv.metaBlob.length > Caps.META_BLOB ||
            Grammar.b64Bytes(pv.metaBlob, 1, Caps.META_BLOB) == null
        ) badRequest(WireErrors.badField("personalVault"))
        val pw = req.personalWrap
        if (!io.silencelen.andvari.core.model.wire.WireGrammar.isUuid(pw.vaultId) || pw.wrappedVk.length > Caps.KEY_ENVELOPE ||
            Grammar.b64Bytes(pw.wrappedVk, 1, Caps.KEY_ENVELOPE) == null
        ) badRequest(WireErrors.badField("personalWrap"))
        val mr = requireMemberRecovery(req.memberRecovery)
        if (req.recovery.posture != RecoveryPosture.PRIVATE && req.recovery.posture != RecoveryPosture.OPERATOR) badRequest(WireErrors.badField("recovery"))
        Grammar.requirePlatform(req.device.platform)
        Grammar.requireText(req.device.name, "device")
        val secretHash = deviceSecretHash(req.device.deviceSecret) ?: badRequest(WireErrors.badField("device"))

        val clientPlatform = headerPlatform ?: req.device.platform
        val clientVersion = call.declaredClientVersion()
        val nowMs = now
        val auth = req.auth
        val isSetup = auth is RegisterAuth.Setup

        /** Steps 2 and 3: the `auth` kind is allowed now, and the ticket or link holds. Reads only. */
        fun checkAuth(c: Connection): LinkRow? {
            // ---- step 2 ----
            if (isSetup) {
                if (c.queryOne("SELECT 1 FROM users WHERE role='operator'") { 1 } != null) forbidden(WireErrors.SETUP_DONE)
            } else {
                if (!s.instance.hasCard(c)) conflict(WireErrors.SETUP_INCOMPLETE)
                val mode = s.policy.effectiveMode()
                val allowed = when (mode) {
                    SignupMode.OPEN -> true
                    SignupMode.LINKS -> auth !is RegisterAuth.Ticket
                    else -> auth is RegisterAuth.Enrol
                }
                if (!allowed) forbidden(WireErrors.SIGNUP_CLOSED)
            }
            // ---- step 3 ----
            return when (auth) {
                is RegisterAuth.Ticket -> {
                    val ok = c.queryOne("SELECT emailHash,expiresAt,usedAt FROM signup_tickets WHERE ticketHash=?", ServerCrypto.hashToken(auth.signupTicket)) {
                        Signup.ticketOk(it.getString(1), it.getLong(2), it.longOrNull("usedAt") != null, s.config.addressHash(email), nowMs)
                    } ?: false
                    if (!ok) badRequest(WireErrors.BAD_TICKET)
                    null
                }
                is RegisterAuth.Link -> checkLink(c, s.config, auth.linkId, auth.registerToken, LinkKind.REGISTER, email, nowMs)
                is RegisterAuth.Enrol -> checkLink(c, s.config, auth.linkId, auth.registerToken, LinkKind.ENROL, email, nowMs)
                is RegisterAuth.Setup -> checkLink(c, s.config, auth.linkId, auth.registerToken, LinkKind.SETUP, email, nowMs)
            }
        }

        // Steps 4 to 6: the age, the instance's sign-up limits, and the address and ids not taken.
        fun beforeTheWrites(c: Connection) {
            // ---- step 4 ----
            if (s.config.requireAgeConfirm && !req.ageConfirmed) badRequest(WireErrors.AGE_CONFIRM_REQUIRED)
            // ---- step 5 ----
            if (!isSetup) {
                if (s.policy.signupFull(c)) forbidden(WireErrors.SIGNUP_FULL)
                if (auth !is RegisterAuth.Enrol) {
                    // Counted from `users.registeredVia` (spec 02 §5), never from audit rows, which the janitor
                    // and an account deletion's pseudonymisation may remove.
                    val today = c.count(
                        "SELECT COUNT(*) FROM users WHERE createdAt>=? AND registeredVia IN ('ticket','link')",
                        Clock.utcDayStart(nowMs),
                    )
                    // The refusal carries its wait (decided on 2026-11-17): the time to the next midnight UTC, when the
                    // count starts again. It tells nothing about any account.
                    if (today >= s.config.signupDailyMax) {
                        val wait = Clock.utcDayStart(nowMs) + Clock.DAY_MS - nowMs
                        throw ApiException(429, WireError(WireErrors.SIGNUP_DAILY_MAX, ApiException.defaultMessage(429)), retryAfterSeconds = ((wait + 999) / 1000).coerceAtLeast(1))
                    }
                }
            }
            // ---- step 6 ----
            if (c.queryOne("SELECT 1 FROM users WHERE email=?", email) { 1 } != null) conflict(WireErrors.EMAIL_TAKEN)
            if (c.queryOne("SELECT 1 FROM users WHERE userId=?", userId) { 1 } != null || isRetiredId(c, userId)) conflict(WireErrors.USER_ID_TAKEN)
            if (c.queryOne("SELECT 1 FROM vaults WHERE vaultId=?", pv.vaultId) { 1 } != null) conflict(WireErrors.VAULT_ID_TAKEN)
        }

        // A read-only pre-check of the mode, the ticket and the link before any Argon2 work, so a
        // refused call costs no hash; and since 2026-11-17 steps 4 to 6 as well, so that a try with an address that
        // is taken (which the holder of a link not bound to an address may make) costs no hash either. The answer is
        // the same, in the same order: the transaction checks them all again. The hashes run off the request thread.
        s.db.read { c -> checkAuth(c); beforeTheWrites(c) }
        val (verifier, recoveryVerifier) = withContext(Dispatchers.IO) {
            ServerCrypto.hashVerifier(req.authKey) to ServerCrypto.hashVerifier(mr.recoveryAuthKey)
        }

        val resp: SessionResponse = s.db.tx { c ->
            val linkRow = checkAuth(c)
            beforeTheWrites(c)
            // ---- step 7 ----
            val genesis = s.trust.verifyGenesis(genesisFrame, identityPub, userId, s.instance.instanceId(c)) ?: badRequest(WireErrors.BAD_GENESIS)
            // ---- step 8 ----
            checkPosture(s, c, req.recovery.posture, req.recovery.escrow, isOperatorAccount = isSetup, emailNorm = email)
            // ---- step 9 ----
            if (pw.vaultId != pv.vaultId || pv.vaultId != genesis.personalVaultId) badRequest(WireErrors.PERSONAL_VAULT_MISMATCH)

            // ---- the transaction's writes ----
            val role = if (isSetup) AccountRole.OPERATOR else AccountRole.MEMBER
            c.exec(
                """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,wrappedUvk,identityPub,encryptedIdentitySeed,
                     genesis,personalVaultId,role,recovery,ageConfirmed,createdAt,registeredVia) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                userId, email, displayName, req.kdfSalt, encodeParams(req.kdfParams), verifier, req.wrappedUvk, req.identityPub,
                req.encryptedIdentitySeed, req.genesis, pv.vaultId, role, req.recovery.posture, req.ageConfirmed, nowMs, registeredVia(auth),
            )
            val rev = nextRev(c, "vault", pv.vaultId, pv.vaultId, nowMs)
            c.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)", pv.vaultId, "personal", rev, pv.metaBlob, nowMs)
            c.exec(
                "INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,rev) VALUES(?,?,'owner',?,?,?)",
                pv.vaultId, userId, nowMs, pv.wrappedVk, rev,
            )
            c.exec("INSERT INTO personal_wrap(userId,vaultId,wrappedVk,updatedAt) VALUES(?,?,?,?)", userId, pw.vaultId, pw.wrappedVk, nowMs)
            if (req.recovery.posture == RecoveryPosture.OPERATOR) {
                val e = req.recovery.escrow!!
                c.exec("INSERT INTO escrow(userId,sealed,fingerprint,updatedAt) VALUES(?,?,?,?)", userId, e.sealed, e.fingerprint, nowMs)
            }
            when (auth) {
                is RegisterAuth.Ticket -> c.exec("UPDATE signup_tickets SET usedAt=? WHERE ticketHash=?", nowMs, ServerCrypto.hashToken(auth.signupTicket))
                else -> {
                    val answer = (auth as? RegisterAuth.Link)?.answer
                    c.exec(
                        "UPDATE links SET state='answered', stateChangedAt=?, answererUserId=?, answeredAt=?, answer=? WHERE linkId=? AND state='open'",
                        nowMs, userId, nowMs, answer, linkRow!!.linkId,
                    )
                    if (auth is RegisterAuth.Link) {
                        val creator = linkRow.creatorUserId ?: error("register link without a creator")
                        writeConnection(c, creator, userId, nowMs)
                        afterCommit(c) { s.notifier.notifyRev(listOf(creator), currentRevSafe(s)) }
                    }
                }
            }
            val deviceId = s.sessions.createDevice(c, userId, req.device.platform, req.device.name, DeviceHow.REGISTERED, secretHash, clientVersion)
            val pieceId = ServerCrypto.newToken()
            c.exec(
                "INSERT INTO member_recovery(userId,recoveryWrappedUvk,recoveryVerifier,pieceId,setupDeviceId,updatedAt) VALUES(?,?,?,?,?,?)",
                userId, mr.recoveryWrappedUvk, recoveryVerifier, pieceId, deviceId, nowMs,
            )
            val issued = s.sessions.issue(c, userId, deviceId, clientPlatform, passwordLogin = true)
            s.audit.on(c, "register", userId, deviceId, ip, "auth=${auth.key}")
            sessionResponse(c, s.config, userId, issued, pieceId)
        }
        respond(SessionResponse.serializer(), resp)
    }
}

/** `users.registeredVia` (spec 02 §5): the `auth` kind an account registered with. */
fun registeredVia(auth: RegisterAuth): String = when (auth) {
    is RegisterAuth.Ticket -> "ticket"
    is RegisterAuth.Link -> "link"
    is RegisterAuth.Enrol -> "enrol"
    is RegisterAuth.Setup -> "setup"
}

/** The link row fields register needs. */
class LinkRow(val linkId: String, val kind: String, val creatorUserId: String?, val state: String, val expiresAt: Long, val boundEmailHash: String?)

/**
 * Step 3 for a link (spec 03 §14.3): known, not revoked, token hash equal (`404 link_unknown`); the kind
 * matches the `auth` key (`409 kind_mismatch`); `open` (`409 link_used`, or `410 link_expired` for a row
 * the janitor expired); unexpired (`410 link_expired`); a bound enrol link's address (`403 email_mismatch`).
 */
private fun checkLink(c: Connection, config: Config, linkId: String, registerToken: String, kind: String, email: String, nowMs: Long): LinkRow {
    val row = c.queryOne("SELECT linkId,kind,creatorUserId,state,expiresAt,boundEmailHash,tokenHash FROM links WHERE linkId=?", linkId) {
        LinkRow(it.getString(1), it.getString(2), it.getString(3), it.getString(4), it.getLong(5), it.getString(6)) to it.getString(7)
    }
    if (row == null || row.first.state == "revoked" || row.second == null ||
        !java.security.MessageDigest.isEqual(row.second!!.encodeToByteArray(), ServerCrypto.hashToken(registerToken).encodeToByteArray())
    ) notFound(WireErrors.LINK_UNKNOWN)
    val link = row.first
    if (link.kind != kind) conflict(WireErrors.KIND_MISMATCH)
    if (link.state == "answered") conflict(WireErrors.LINK_USED)
    if (link.state == "expired" || link.expiresAt <= nowMs) gone(WireErrors.LINK_EXPIRED)
    // The bound address as the link row keeps it: its keyed hash, or for a link minted before 2026-11-18 the plain one,
    // so that a link the operator handed out before still works until it expires.
    if (link.boundEmailHash != null && link.boundEmailHash != config.addressHash(email) && link.boundEmailHash != Grammar.emailHash(email)) {
        forbidden(WireErrors.EMAIL_MISMATCH)
    }
    return link
}

/** `connections(a, b)` with `a < b` (spec 03 §15.8). Idempotent. */
fun writeConnection(c: Connection, x: String, y: String, nowMs: Long) {
    val (a, b) = if (x < y) x to y else y to x
    c.exec("INSERT OR IGNORE INTO connections(a,b,createdAt) VALUES(?,?,?)", a, b, nowMs)
}

fun currentRevSafe(s: Services): Long = s.db.read { currentRev(it) }

