package io.silencelen.andvari.server

import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.route
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.TotpConfig
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.DeviceHow
import io.silencelen.andvari.core.model.wire.LoginRequest
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.TotpCodeRequest
import io.silencelen.andvari.core.model.wire.TotpSetupRequest
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.TotpStatus
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireOk
import io.silencelen.andvari.core.model.wire.WirePlatform
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.sql.Connection

/** Server TOTP (spec 03 §2): RFC 6238 SHA-1/6 digits/30 s, ±1 step, an accepted step is single-use. */
object TotpCheck {
    private val crypto = createCryptoProvider()

    /** The step [code] matches over now-1..now+1 and after [lastStep], or null. */
    fun verify(secretBase32: String, code: String, lastStep: Long, nowMs: Long): Long? {
        if (code.length != 6 || code.any { it !in '0'..'9' }) return null
        val cfg = TotpConfig(secret = Base32.decode(secretBase32))
        val step = nowMs / 1000 / cfg.periodSeconds
        for (st in longArrayOf(step, step - 1, step + 1)) {
            if (st <= lastStep) continue
            if (MessageDigest.isEqual(Totp.code(crypto, cfg, st * cfg.periodSeconds).encodeToByteArray(), code.encodeToByteArray())) return st
        }
        return null
    }

    /** Consume [step] for [userId] (compare-and-set): false when another request took it first (a replay). */
    fun consume(c: Connection, userId: String, step: Long): Boolean =
        c.exec("UPDATE users SET totpLastStep=? WHERE userId=? AND totpLastStep<?", step, userId, step) == 1

    fun newSecret(): String = Base32.encode(crypto.randomBytes(20))
}

/**
 * The login body's optional field that names the session the sign-in replaces (spec 03 §2): the refresh token the client
 * last held for it. Not in core's `LoginRequest` yet, so the route reads it from the body's tree.
 */
internal const val REPLACES_FIELD = "replacesRefreshToken"

/** Index row 93 (spec 03 §2), `POST /auth/end-session`. */
internal const val END_SESSION_PATH = "/api/v1/auth/end-session"

/** Its bucket: `end_session` 30/min per IP. */
internal val END_SESSION_BUCKET = Bucket.ipPerMinute("end_session", 30)

/**
 * `POST /auth/end-session { refreshToken }` (spec 03 §2, index row 93): end exactly the one session that
 * [RefreshRequest.refreshToken] belongs to, and nothing else of the device row. No bearer: the token is the proof.
 *
 * - A live token (not consumed, not revoked, expired or not): its session row is revoked, so the token never
 *   refreshes again (`401 session_revoked`) and the access token minted with it, which lives in the same row, is
 *   refused from now on. Audited `session_end`. Sibling sessions on the row and the device row itself are untouched.
 * - A consumed token (one a refresh already rotated away): treated exactly as `/auth/refresh` treats its reuse, the
 *   theft signal: every session of the device row is revoked, audited `refresh_reuse`, and its sockets are told.
 *   Revoking only the consumed row would instead let a thief who refreshed first disarm that signal for good.
 * - An unknown, already ended or malformed token: nothing.
 *
 * Every case answers `200 ok`; only a body that is not `{refreshToken: string}` is `400 bad_request`.
 *
 * **The bucket is drawn only for a call whose token names no live session**: a body that is
 * not the shape, and a token that is unknown, malformed or already ended. A token that names a live session (one
 * not revoked, consumed or not) is always served, whatever the address has spent. Drawing first let anyone behind
 * the same address, or a page in the same browser, spend the 30 and so refuse every tab's lock; the session then
 * lived on to its refresh expiry, and a consumed token's reuse signal never fired. The live case needs no bucket:
 * each such call revokes the session its token names, so a token is served as live at most once. Telling the two
 * cases apart costs one indexed read by the token's hash, before the bucket.
 *
 * Registered outside [api] only because core's [io.silencelen.andvari.core.model.wire.WireRoute] table does not
 * hold row 93 yet (the spec wins over that table, §0.2). The generic rules of a `none` route are all here: no
 * version check, not refused on a public instance, the per-IP bucket as above.
 */
internal fun Route.endSessionRoute(s: Services) {
    route(END_SESSION_PATH, HttpMethod.Post) {
        handle {
            val ip = call.clientIp(s.config)
            val b = END_SESSION_BUCKET
            fun limit() = s.limiter.retryAfterMs("${b.name}:${rateKeyOf(ip)}", b.limit, b.windowMs)?.let { rateLimited(it) }
            val req = try {
                WireJson.json.decodeFromString(RefreshRequest.serializer(), call.receiveText())
            } catch (_: Throwable) {
                limit()
                badRequest(WireErrors.BAD_REQUEST)
            }
            val token = req.refreshToken
            val hash = token.takeIf { it.isNotEmpty() && it.length <= 128 }?.let { ServerCrypto.hashToken(it) }
            val live = hash != null && s.db.read { c -> c.queryOne("SELECT 1 FROM sessions WHERE refreshHash=? AND revokedAt IS NULL", hash) { 1 } } != null
            if (!live) limit()
            if (hash != null && live) {
                s.db.tx { c ->
                    val now = s.clock.now()
                    val row = c.queryOne(
                        "SELECT sessionId,deviceId,userId,refreshConsumedAt FROM sessions WHERE refreshHash=? AND revokedAt IS NULL", hash,
                    ) { rs -> listOf(rs.getString(1), rs.getString(2), rs.getString(3), rs.longOrNull("refreshConsumedAt")) }
                        ?: return@tx
                    val (sessionId, deviceId, userId) = Triple(row[0] as String, row[1] as String, row[2] as String)
                    if (row[3] != null) {
                        c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now, deviceId)
                        s.audit.on(c, "refresh_reuse", userId, deviceId, ip, "end_session")
                        afterCommit(c) { s.notifier.notifyRevokedDevice(userId, deviceId) }
                    } else if (c.exec("UPDATE sessions SET revokedAt=? WHERE sessionId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL", now, sessionId) == 1) {
                        s.audit.on(c, "session_end", userId, deviceId, ip)
                    }
                }
            }
            call.respondText(WireOk.BODY, ContentType.Text.Plain, HttpStatusCode.OK)
        }
    }
}

/** Row 11's bucket for a token that names no live session: `refresh` 30/min per IP. */
internal val REFRESH_ADDRESS_BUCKET = Bucket.ipPerMinute("refresh", 30)

/** Row 11's bucket for a token that names a live session: `refresh_session` 30/min per device, with its ceiling. */
internal val REFRESH_SESSION_BUCKET = Bucket.devicePerMinute("refresh_session", 30)

/** What one refresh spends (see the refresh route). */
internal sealed interface RefreshDraw {
    data object Address : RefreshDraw
    data object Free : RefreshDraw
    data class Device(val userId: String, val deviceId: String) : RefreshDraw
}

/**
 * The budget a refresh with the token hash [hash] (null: empty or overlong) draws at [now]: the device of the live
 * session it names, nothing for the reuse of a consumed token of a live device, else the caller's address. One indexed
 * read; the refresh's own transaction checks everything again.
 */
internal fun refreshDraw(s: Services, hash: String?, now: Long): RefreshDraw {
    if (hash == null) return RefreshDraw.Address
    return s.db.read { c ->
        val row = c.queryOne(
            "SELECT se.userId,se.deviceId,se.refreshConsumedAt,se.refreshExpiresAt FROM sessions se " +
                "JOIN users u ON u.userId=se.userId JOIN devices d ON d.deviceId=se.deviceId AND d.userId=se.userId " +
                "WHERE se.refreshHash=? AND se.revokedAt IS NULL AND u.status='active' AND d.revokedAt IS NULL",
            hash,
        ) { rs -> listOf(rs.getString(1), rs.getString(2), rs.longOrNull("refreshConsumedAt"), rs.getLong(4)) }
            ?: return@read RefreshDraw.Address
        when {
            // A replaced token the grace would answer ([graceEntry]) draws the caller address's allowance, as on the
            // released line (decided on 2026-11-17): the grace is an answer, not a free door, and without a draw one
            // signed-in person could repeat it without end, each time taking the server's database lock. Drawn per
            // address, a thief spends only their own address's allowance.
            row[2] != null && graceEntry(s, c, hash, row[1] as String) != null -> RefreshDraw.Address
            // Any other replaced token is the reuse, and it draws nothing: drawn on the device, a spent budget would keep
            // the reuse from being served. It ends every session of the device, so it is served once.
            row[2] != null -> RefreshDraw.Free
            now >= (row[3] as Long) -> RefreshDraw.Address
            else -> RefreshDraw.Device(row[0] as String, row[1] as String)
        }
    }
}

/**
 * The grace's entry for the replaced token [hash] when the grace would answer it ([RefreshGrace], spec 03 §2): within the
 * window, the token's own device row [deviceId] is the pair's, and the pair's session is neither ended nor itself
 * refreshed (read on [c]). Null otherwise.
 */
private fun graceEntry(s: Services, c: Connection, hash: String, deviceId: String): RefreshGrace.Entry? {
    val e = s.sessions.refreshGrace.lookup(hash) ?: return null
    if (e.deviceId != deviceId) return null
    val untouched = c.queryOne(
        "SELECT 1 FROM sessions WHERE sessionId=? AND deviceId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL",
        e.successorSessionId, deviceId,
    ) { 1 } != null
    return if (untouched) e else null
}

/**
 * The answer a repeat of the refresh that replaced the token [hash] gets inside the grace ([RefreshGrace], spec 03 §2): the
 * pair that refresh answered, while the window lasts, the token's own device row [deviceId] is the pair's, and the pair's
 * session is neither ended nor itself refreshed (read here, on [c], inside the refresh's transaction). Null otherwise, and
 * the reuse rule applies.
 *
 * Each answer is recorded as `refresh_grace` (the account, the device and the caller's address, nothing else), as on the
 * released line (decided on 2026-11-17): a replaced token presented again and answered is something the operator and the
 * person can see, since the reuse rule would otherwise have treated it as stolen.
 */
internal fun graceAnswer(s: Services, c: Connection, hash: String, userId: String, deviceId: String, ip: String): TokenPair? {
    val e = graceEntry(s, c, hash, deviceId) ?: return null
    s.audit.on(c, "refresh_grace", userId, deviceId, ip)
    return e.pair
}

/** A fixed valid verifier for uniform-cost failures (login of an unknown or inactive address). */
private val DUMMY_VERIFIER: String by lazy { ServerCrypto.hashVerifier("andvari-dummy-login-authkey") }

/** The account fields login and pickup read. */
class LoginUser(val userId: String, val verifier: String, val status: String, val totpSecret: String?, val totpLastStep: Long, val requireLink: Boolean, val identityPub: String)

fun loginUserByEmail(c: Connection, email: String): LoginUser? =
    c.queryOne("SELECT userId,verifier,status,totpSecret,totpLastStep,requireLink,identityPub FROM users WHERE email=?", email) {
        LoginUser(it.getString(1), it.getString(2), it.getString(3), it.getString(4), it.getLong(5), it.bool("requireLink"), it.getString(7))
    }

/**
 * How a back-off's refusals are traced (decided on 2026-11-17): one audit record per key per period, never one per
 * refused request. The back-offs' period is their longest lock (fifteen minutes); a deletion refused over a moved log is
 * traced once per account per hour, the window of the deletion's own limits.
 */
object RefusalTrace {
    const val BACKOFF_PERIOD_MS = 15 * Clock.MINUTE_MS
    const val DELETE_STALE_PERIOD_MS = Clock.HOUR_MS
}

/**
 * A sign-in ([at] `login`) or a device-link pickup (`pickup`) refused by its address's back-off: audited `login_wait`,
 * once per address per [RefusalTrace.BACKOFF_PERIOD_MS] ([Services.refusalTraceDue]). The row names the account when
 * the address has one ([userId], or read here), as `login_fail` does, and keeps of the address only its keyed hash's
 * first 8 characters ([Config.addressHash]). The refused caller is answered exactly as before, record or not.
 */
fun recordLoginWait(s: Services, email: String, userId: String?, ip: String, at: String) {
    if (!s.refusalTraceDue("login_wait", Grammar.emailHash(email), RefusalTrace.BACKOFF_PERIOD_MS)) return
    s.db.tx { c ->
        val account = userId ?: c.queryOne("SELECT userId FROM users WHERE email=?", email) { it.getString(1) }
        s.audit.on(c, "login_wait", account, null, ip, "addr=${s.config.addressHash(email).take(8)} at=$at")
    }
}

/**
 * The password-and-code gate shared by login (spec 03 §2) and device-link pickup (§16.6): the email
 * backoff first, then the verifier (the dummy for an unknown or inactive address, uniform cost and
 * shape), then the TOTP rules. A missing code is `401 totp_required`; a wrong or replayed one the uniform
 * `401 invalid_credentials`; every failure counts against the email backoff (§8). The attempt is reserved
 * (counted) before the verifier runs and cleared once the password and any code verified, so
 * requests sent at the same moment cannot all pass the check. The TOTP step is consumed here. Returns the
 * account on success.
 */
suspend fun passwordGate(s: Services, email: String, authKey: String, totp: String?, ip: String, failAudit: String): LoginUser {
    // A fixed 60 seconds, never the lock's real wait: the caller has proven nothing, and the real wait would tell how many
    // wrong tries were made for this address lately (spec 03 §8; the session back-offs name their real wait).
    if (!s.loginBackoff.reserve(email)) {
        recordLoginWait(s, email, null, ip, if (failAudit == "login_fail") "login" else "pickup")
        rateLimited(60_000)
    }
    val user = s.db.read { c -> loginUserByEmail(c, email) }
    val live = user != null && user.status == "active"
    val ok = withContext(Dispatchers.IO) {
        runCatching { ServerCrypto.verify(if (live) user!!.verifier else DUMMY_VERIFIER, authKey) }.getOrDefault(false)
    }
    if (!live || !ok) {
        s.db.tx { c -> s.audit.on(c, failAudit, user?.userId, null, ip, if (user != null && !live) "inactive" else null) }
        unauthorized()
    }
    val u = user!!
    if (u.totpSecret != null) {
        if (totp == null) unauthorized(WireErrors.TOTP_REQUIRED)
        val step = TotpCheck.verify(u.totpSecret, totp, u.totpLastStep, s.clock.now())
        val consumed = step != null && s.db.tx { c -> TotpCheck.consume(c, u.userId, step) }
        if (!consumed) {
            s.db.tx { c -> s.audit.on(c, failAudit, u.userId, null, ip, "totp") }
            unauthorized()
        }
    }
    s.loginBackoff.success(email)
    return u
}

fun Route.authRoutes(s: Services) {
    /**
     * `POST /auth/prelogin` (spec 03 §2): an account's own salt and params; an unknown address gets a
     * deterministic fake salt and the cost the client policy serves ([PolicyStore.servedKdf]: the policy's, never below
     * the floor), so an address without an account is answered with the cost a new account would be made at. Both
     * branches read the policy, so neither is measurably heavier.
     */
    api(WireRoute.PRELOGIN, s, Bucket.ipPerMinute("prelogin", 10)) {
        val req = body<PreloginRequest>()
        val email = Grammar.requireEmail(req.email)
        val defaults = s.policy.servedKdf()
        val known = s.db.read { c -> c.queryOne("SELECT kdfSalt,kdfParams FROM users WHERE email=?", email) { it.getString(1) to it.getString(2) } }
        respond(
            if (known != null) PreloginResponse(known.first, decodeParams(known.second))
            else PreloginResponse(Bytes.toB64(ServerCrypto.fakeSalt(s.config.enumSecret, email)), defaults),
        )
    }

    /**
     * `POST /auth/login` (spec 03 §2). Check order: the per-IP bucket; the email backoff; the verifier;
     * the TOTP rules; then, only after the password and any code verified, `requireLink` for a login that
     * is not from a known device (`403 link_required`). A **known device** (spec 03 §16.8) is one whose
     * `deviceId` names a device row of the account that is not revoked and whose stored secret hash equals
     * `SHA-256(deviceSecret)`; no live session is needed (a signed-out device, or one whose sessions the
     * janitor pruned, stays known): the session lands on that row, every earlier session of that row ends in the same
     * transaction (a device has one live session; audited `session_end` with `sign_in` when one was live, its sockets
     * told and closed; not on a browser's row, whose tabs each hold a pair on the browser's one row), and no email goes out. Anything else is a new device (`how = password`) with the
     * `new_device` email. The write is a compare-and-swap on the verifier, so a credential changed in
     * between fails the login.
     *
     * **The kind of a row decides, not the caller's word** (decided on 2026-11-17): a row is a browser's when it was made
     * with the platform `web` (`devices.platform`, set when the row is made and never changed). A sign-in that claims
     * another kind than its row's is treated by its row's kind: a caller that says `web` on a row made as an app's ends the
     * row's earlier sessions as any app's sign-in does, and a session minted on a browser's row is a web session whatever
     * the caller says (every operator route refuses it). Before, `X-Andvari-Client` alone decided at each sign-in, so an
     * app's row could be given several live sessions again by a caller that said `web`.
     *
     * **`replacesRefreshToken`** (optional; [REPLACES_FIELD]): the refresh token the client last held for the session this
     * sign-in replaces. Only once the whole sign-in has succeeded, and only on a known device, the session that token
     * belongs to ends in this transaction, as it stands now ([Sessions.endNamed]): when it is a session of this account on
     * this device row, also when the token had been replaced (then the record's meta is `sign_in_named_replaced`, the sign
     * of a lost refresh answer or of someone else's use of the token; else `sign_in_named`). Anything else named (another
     * account's, another row's, an unknown, ended, expired, empty or overlong token) is ignored and changes nothing; a
     * value that is not a string is `400 bad_request`. On an app's or the tool's row every earlier session ends anyway, and
     * the name only adds the record. A sign-in that fails ends nothing, whatever it names.
     */
    api(WireRoute.LOGIN, s, SharedBuckets.login(s.config)) {
        val tree = jsonBody() as? JsonObject ?: badRequest(WireErrors.BAD_REQUEST)
        val replaces = when (val v = tree[REPLACES_FIELD]) {
            null, JsonNull -> null
            is JsonPrimitive -> v.takeIf { it.isString }?.content ?: badRequest(WireErrors.BAD_REQUEST)
            else -> badRequest(WireErrors.BAD_REQUEST)
        }
        val req = try {
            WireJson.json.decodeFromJsonElement(LoginRequest.serializer(), JsonObject(tree - REPLACES_FIELD))
        } catch (_: Throwable) {
            badRequest(WireErrors.BAD_REQUEST)
        }
        val replacesHash = replaces?.takeIf { it.isNotEmpty() && it.length <= 128 }?.let { ServerCrypto.hashToken(it) }
        val email = Grammar.requireEmail(req.email)
        Grammar.requireB64(req.authKey, "authKey", Caps.AUTH_KEY)
        Grammar.requirePlatform(req.device.platform)
        Grammar.requireText(req.device.name, "device")
        val secretHash = deviceSecretHash(req.device.deviceSecret) ?: badRequest(WireErrors.badField("device"))
        req.device.deviceId?.let { Grammar.requireUuid(it, "device") }
        val u = passwordGate(s, email, req.authKey, req.totp, ip, "login_fail")
        val clientVersion = call.declaredClientVersion()
        s.raceHook?.invoke("login.afterGate")
        val clientPlatform = headerPlatform ?: req.device.platform
        val resp = s.db.tx { c ->
            val still = c.queryOne("SELECT verifier,status,requireLink FROM users WHERE userId=?", u.userId) { Triple(it.getString(1), it.getString(2), it.bool("requireLink")) }
            if (still == null || still.second != "active" || still.first != u.verifier) {
                s.audit.on(c, "login_fail", u.userId, null, ip, "credential_changed")
                return@tx Result.failure(ApiException(401, WireErrors.INVALID_CREDENTIALS))
            }
            // The known row and the kind it was made as (`devices.platform`).
            val knownRow = req.device.deviceId?.let { did ->
                // A row whose secret was cleared (a recovery's commit clears every earlier row's) is never known.
                c.queryOne("SELECT deviceSecretHash,platform FROM devices WHERE deviceId=? AND userId=? AND revokedAt IS NULL AND deviceSecretHash IS NOT NULL", did, u.userId) {
                    it.getString(1) to it.getString(2)
                }
                    ?.takeIf { (stored, _) -> MessageDigest.isEqual(stored.encodeToByteArray(), secretHash.encodeToByteArray()) }
                    ?.let { (_, platform) -> did to platform }
            }
            val known = knownRow?.first
            if (known == null && still.third) {
                s.audit.on(c, "login_fail", u.userId, null, ip, "link_required")
                return@tx Result.failure(ApiException(403, WireErrors.LINK_REQUIRED))
            }
            val deviceId = known ?: s.sessions.createDevice(c, u.userId, req.device.platform, req.device.name, DeviceHow.PASSWORD, secretHash, clientVersion)
            // The row's kind decides, not the caller's word: a browser's row is one made as `web`.
            val browserRow = (knownRow?.second ?: req.device.platform) == WirePlatform.WEB
            val sessionPlatform = if (browserRow) WirePlatform.WEB else clientPlatform
            // A device has one live session: a sign-in on a known device ends that device's earlier sessions itself, in
            // this transaction ([Sessions.endEarlierOf]), so the client never has to send an earlier session's token.
            // Not on a browser's row: the web client keeps one device row per account in a browser, and each tab without
            // the offline copy signs in and holds its own pair on that row (spec 03 §2), so a sign-in in one tab must not
            // end the others. There only the session the sign-in names ends ([Sessions.endNamed]).
            if (known != null) c.exec("UPDATE devices SET lastSeenAt=?, signedOutAt=NULL, clientVersion=COALESCE(?,clientVersion) WHERE deviceId=?", now, clientVersion, deviceId)
            val named = if (known != null && replacesHash != null) s.sessions.endNamed(c, u.userId, known, replacesHash) else null
            val namedLive = named?.liveSessionIds.orEmpty()
            val ended = if (known != null && !browserRow) s.sessions.endEarlierOf(c, deviceId) else 0
            val issued = s.sessions.issue(c, u.userId, deviceId, sessionPlatform, passwordLogin = true)
            if (ended > 0 || namedLive.isNotEmpty()) {
                val meta = when {
                    namedLive.isEmpty() -> "sign_in"
                    named!!.replaced -> "sign_in_named_replaced"
                    else -> "sign_in_named"
                }
                s.audit.on(c, "session_end", u.userId, deviceId, ip, meta)
                // The ended sessions' sockets are told and closed, as after a password change; the new session's stay, and
                // on a browser's row so do the other tabs'.
                afterCommit(c) {
                    if (browserRow) s.notifier.notifyRevokedSessions(u.userId, namedLive)
                    else s.notifier.notifyRevokedDeviceExceptSession(u.userId, deviceId, issued.sessionId)
                }
            }
            s.audit.on(c, "login", u.userId, deviceId, ip, if (known != null) "known_device" else "new_device")
            if (known == null) {
                val to = c.queryOne("SELECT email FROM users WHERE userId=?", u.userId) { it.getString(1) }!!
                s.mail.enqueue(
                    c, "new_device", to,
                    // The new device by the server's own words for it and its name in the narrow form a mail shows (MailDevices).
                    Mail.Ctx(
                        Mail.accountId(u.identityPub), now,
                        listOfNotNull(MailDevices.of(c, deviceId, isNew = true)?.let { "device" to it }).toMap() + ("how" to "signed in with your master password"),
                    ),
                )
            }
            Result.success(sessionResponse(c, s.config, u.userId, issued))
        }
        val session = resp.getOrElse { e ->
            if ((e as? ApiException)?.status == 401) s.loginBackoff.fail(email)
            throw e
        }
        s.loginBackoff.success(email)
        respond(SessionResponse.serializer(), session)
    }

    /**
     * `POST /auth/refresh` (spec 03 §2): the rotated pair; the old refresh token is single-use, and reuse
     * of a consumed one revokes the whole device session (`401 refresh_reuse`, audited). The new session
     * keeps the platform it was minted for (a web session stays a web session) and its password time.
     *
     * **The grace for a repeated refresh** ([RefreshGrace], decided on 2026-11-17): a replaced token presented again on
     * its own device row within sixty seconds of its replacement (sixty inclusive), while the pair that replaced it has
     * authenticated nothing and its session is neither ended nor refreshed, is answered with that same pair and is no
     * reuse; each such answer is audited `refresh_grace`. Later, or once the pair was used, the reuse rule stands as it is.
     *
     * **Which budget a refresh spends** ([refreshDraw]) follows what its token names, read by the token's hash before
     * any bucket is drawn:
     * - a live session (not revoked, not consumed, not expired, of an active account and a device not removed): that
     *   session's device, [REFRESH_SESSION_BUCKET], with its ceiling per account, as every session bucket;
     * - a consumed token the grace would answer: the caller's address, [REFRESH_ADDRESS_BUCKET], as on the released line;
     * - any other consumed token of such a session (the reuse signal): nothing, and it is never refused by a bucket. It revokes
     *   every session of its device, so it is served at most once per device; drawn on the device, the holder of the
     *   rotated chain could keep that device's budget spent and so keep the reuse from ever revoking it;
     * - anything else (a body that is not the shape, an empty, overlong or unknown token, a revoked or expired session,
     *   one of an account that is not active or of a removed device): the caller's address, [REFRESH_ADDRESS_BUCKET].
     *
     * Until 2026-11-17 every refresh drew the address's thirty a minute, so the people behind one address (a household,
     * an office, a mobile network's shared address) shared them, and anyone behind it could keep all of them from
     * refreshing with tokens that name nothing. A live token is served once and rotates, so the address protected
     * nothing there.
     */
    api(WireRoute.REFRESH, s, bucket = null) {
        val req = try {
            WireJson.json.decodeFromString(RefreshRequest.serializer(), call.receiveText())
        } catch (_: Throwable) {
            take(REFRESH_ADDRESS_BUCKET)
            badRequest(WireErrors.BAD_REQUEST)
        }
        val hash = req.refreshToken.takeIf { it.isNotEmpty() && it.length <= 128 }?.let { ServerCrypto.hashToken(it) }
        when (val draw = refreshDraw(s, hash, now)) {
            RefreshDraw.Address -> take(REFRESH_ADDRESS_BUCKET)
            RefreshDraw.Free -> {}
            is RefreshDraw.Device -> s.limiter.drawDevice(REFRESH_SESSION_BUCKET, draw.userId, draw.deviceId)?.let { rateLimited(it) }
        }
        if (hash == null) unauthorized(WireErrors.INVALID_REFRESH)
        val clientVersion = call.declaredClientVersion()
        val pair = s.db.tx { c ->
            val row = c.queryOne(
                "SELECT s.sessionId,s.deviceId,s.userId,s.refreshExpiresAt,s.refreshConsumedAt,s.revokedAt,s.clientPlatform,s.passwordAt,${SessionChains.CHAIN_OF_S} " +
                    "FROM sessions s LEFT JOIN session_chains sc ON sc.sessionId=s.sessionId WHERE s.refreshHash=?", hash,
            ) { rs ->
                listOf(rs.getString(1), rs.getString(2), rs.getString(3), rs.getLong(4), rs.longOrNull("refreshConsumedAt"), rs.longOrNull("revokedAt"), rs.getString(7), rs.longOrNull("passwordAt"), rs.getString(9))
            } ?: return@tx Result.failure(ApiException(401, WireErrors.INVALID_REFRESH))
            val (sessionId, deviceId, userId) = Triple(row[0] as String, row[1] as String, row[2] as String)
            if (row[5] != null) return@tx Result.failure(ApiException(401, WireErrors.SESSION_REVOKED))
            // A session of an account that is not active, or of a revoked device, is refused as every
            // session route refuses it, and the token is not consumed.
            val live = c.queryOne(
                "SELECT 1 FROM users u JOIN devices d ON d.userId=u.userId WHERE u.userId=? AND u.status='active' AND d.deviceId=? AND d.revokedAt IS NULL",
                userId, deviceId,
            ) { 1 } != null
            if (!live) return@tx Result.failure(ApiException(401, WireErrors.INVALID_CREDENTIALS))
            fun reuse(): Result<TokenPair> {
                // The grace first ([graceAnswer]): a repeat of the refresh that replaced this very token, on its own
                // device row, within the minute, while the pair it answered is untouched, gets that pair again.
                graceAnswer(s, c, hash, userId, deviceId, ip)?.let { return Result.success(it) }
                c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now, deviceId)
                s.audit.on(c, "refresh_reuse", userId, deviceId, ip)
                // The device's sessions are dead, so its events socket goes too (after the commit).
                afterCommit(c) { s.notifier.notifyRevokedDevice(userId, deviceId) }
                return Result.failure(ApiException(401, WireErrors.REFRESH_REUSE))
            }
            if (row[4] != null) return@tx reuse()
            // Expiry is exclusive (refused AT refreshExpiresAt), and it is checked before the
            // token is consumed, so an expired token is refused without being spent.
            if (now >= (row[3] as Long)) return@tx Result.failure(ApiException(401, WireErrors.REFRESH_EXPIRED))
            if (c.exec("UPDATE sessions SET refreshConsumedAt=? WHERE sessionId=? AND refreshConsumedAt IS NULL AND revokedAt IS NULL", now, sessionId) != 1) return@tx reuse()
            val issued = s.sessions.issue(c, userId, deviceId, row[6] as String, passwordLogin = false, chainId = row[8] as String)
            // Kept for the grace inside the transaction; one that does not commit leaves an entry whose session does not
            // exist, which [graceAnswer] refuses.
            s.sessions.refreshGrace.record(hash, TokenPair(issued.accessToken, issued.refreshToken), issued.sessionId, deviceId)
            (row[7] as Long?)?.let { c.exec("UPDATE sessions SET passwordAt=? WHERE accessHash=?", it, ServerCrypto.hashToken(issued.accessToken)) }
            c.exec("UPDATE devices SET lastSeenAt=?, clientVersion=COALESCE(?,clientVersion) WHERE deviceId=?", now, clientVersion, deviceId)
            // The sockets opened on the rotated-away session belong to the new one from now on.
            afterCommit(c) { s.notifier.sessionRotated(userId, sessionId, issued.sessionId) }
            Result.success(TokenPair(issued.accessToken, issued.refreshToken))
        }
        respond(TokenPair.serializer(), pair.getOrThrow())
    }

    /**
     * `POST /auth/logout` (spec 03 §2): revokes this device's sessions and stamps `signedOutAt`; after the
     * commit the device's events sockets get `revoked` and are closed. The account's other devices keep theirs.
     */
    api(WireRoute.LOGOUT, s) {
        val principal = p
        s.db.tx { c ->
            c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", now, principal.deviceId)
            c.exec("UPDATE devices SET signedOutAt=? WHERE deviceId=? AND signedOutAt IS NULL", now, principal.deviceId)
            s.audit.on(c, "logout", principal.userId, principal.deviceId, ip)
            afterCommit(c) { s.notifier.notifyRevokedDevice(principal.userId, principal.deviceId) }
        }
        ok()
    }

    endSessionRoute(s)

    /**
     * `GET /account/keys` (spec 03 §3). An answered call moves the calling device's `lastSeenAt`, as a sign-in and a
     * refresh do, so a device that only fetches the keys (every unlock under a policy that forbids keeping data) is seen
     * in the account's list of devices; nothing else is recorded (no version, no audit row).
     */
    api(WireRoute.ACCOUNT_KEYS, s) {
        val principal = p
        val keys = s.db.tx { c ->
            c.exec("UPDATE devices SET lastSeenAt=? WHERE deviceId=? AND revokedAt IS NULL", now, principal.deviceId)
            accountKeys(c, principal.userId)
        }
        respond(AccountKeys.serializer(), keys)
    }

    // ---- server TOTP (spec 03 §2) ----

    api(WireRoute.TOTP_STATUS, s) {
        val principal = p
        val st = s.db.read { c ->
            c.queryOne("SELECT totpSecret,totpPendingSecret FROM users WHERE userId=?", principal.userId) { TotpStatus(it.getString(1) != null, it.getString(2) != null) }
        } ?: unauthorized()
        respond(st)
    }

    /**
     * `POST /account/totp/setup` (spec 03 §2). Always the password proof first, on every account and every session
     * (decided on 2026-11-17: before, a session a password login had minted less than ten minutes earlier could set
     * up a first factor without it, so whoever took such a session could add a factor of their own and the owner
     * could then not sign in anew). `currentAuthKey` is checked, on the proofs' back-off, before anything else about
     * the request or the account is looked at: missing (or a body that is not the route's shape) is
     * `403 reauth_required`; wrong is `403 reauth_failed`, audited `totp_setup_reauth_fail`. Then an enrolled account
     * replaces its secret only with its current code too (`400 bad_totp_code`, on the codes' back-off), so a wrong or
     * missing proof never tells whether the code was right; an account without two-step sign-in needs no code.
     */
    api(WireRoute.TOTP_SETUP, s, Bucket.devicePerMinute("totp_setup", 5)) {
        val req = runCatching { body<TotpSetupRequest>() }.getOrElse { TotpSetupRequest() }
        val principal = p
        reauth(req.currentAuthKey ?: forbidden(WireErrors.REAUTH_REQUIRED), "totp_setup_reauth_fail")
        val row = s.db.read { c ->
            c.queryOne("SELECT totpSecret,totpLastStep,email FROM users WHERE userId=?", principal.userId) { Triple(it.getString(1), it.getLong(2), it.getString(3)) }
        } ?: unauthorized()
        if (row.first != null) {
            checkSessionCode("setup") {
                req.code?.let { code -> TotpCheck.verify(row.first!!, code, row.second, now) }
                    ?.takeIf { step -> s.db.tx { c -> TotpCheck.consume(c, principal.userId, step) } }
            }
        }
        val secret = TotpCheck.newSecret()
        s.db.tx { c -> c.exec("UPDATE users SET totpPendingSecret=? WHERE userId=?", secret, principal.userId) }
        respond(TotpSetupResponse(secret, "otpauth://totp/andvari:${row.third}?secret=$secret&issuer=andvari&algorithm=SHA1&digits=6&period=30"))
    }

    /** `POST /account/totp/confirm` (spec 03 §2): the pending secret becomes the factor; the confirming step is consumed. */
    api(WireRoute.TOTP_CONFIRM, s, Bucket.devicePerMinute("totp_confirm", 5)) {
        val req = body<TotpCodeRequest>()
        val principal = p
        val (pending, enrolled) = s.db.read { c ->
            c.queryOne("SELECT totpPendingSecret,totpSecret FROM users WHERE userId=?", principal.userId) { it.getString(1) to (it.getString(2) != null) }
        } ?: unauthorized()
        if (pending == null) badRequest(WireErrors.NO_PENDING_TOTP)
        val step = checkSessionCode("confirm") { TotpCheck.verify(pending, req.code, 0, now) }
        s.db.tx { c ->
            c.exec("UPDATE users SET totpSecret=?, totpPendingSecret=NULL, totpEnrolledAt=?, totpLastStep=? WHERE userId=?", pending, now, step, principal.userId)
            s.audit.on(c, if (enrolled) "totp_rotate" else "totp_enroll", principal.userId, principal.deviceId, ip)
        }
        ok()
    }

    /**
     * `POST /account/totp/disable` (spec 03 §2): needs the password proof and the current code; sends `two_step_off`.
     * After `400 totp_not_enrolled`, the proof first (missing: `403 reauth_required`; wrong: `403 reauth_failed`,
     * audited `reauth_fail`, on the proofs' back-off), and only then the code (`400 bad_totp_code`, on the codes'
     * back-off): a session in the wrong hands can no longer remove the second factor by guessing the code, and a
     * wrong or missing proof never tells whether the code was right.
     */
    api(WireRoute.TOTP_DISABLE, s, SharedBuckets.TOTP_VERIFY) {
        val req = body<TotpDisableBody>()
        val principal = p
        val (secret, last) = s.db.read { c ->
            c.queryOne("SELECT totpSecret,totpLastStep FROM users WHERE userId=?", principal.userId) { it.getString(1) to it.getLong(2) }
        } ?: unauthorized()
        if (secret == null) badRequest(WireErrors.TOTP_NOT_ENROLLED)
        reauth(req.currentAuthKey ?: forbidden(WireErrors.REAUTH_REQUIRED))
        checkSessionCode("disable") {
            TotpCheck.verify(secret, req.code, last, now)?.takeIf { step -> s.db.tx { c -> TotpCheck.consume(c, principal.userId, step) } }
        }
        s.db.tx { c ->
            c.exec("UPDATE users SET totpSecret=NULL, totpPendingSecret=NULL, totpEnrolledAt=NULL, totpLastStep=0 WHERE userId=?", principal.userId)
            s.audit.on(c, "totp_disable", principal.userId, principal.deviceId, ip)
            notify(s, c, principal.userId, "two_step_off", MailDevices.of(c, principal.deviceId))
        }
        ok()
    }
}

/**
 * The body of `POST /account/totp/disable`: `{code, currentAuthKey}`. [currentAuthKey] is optional in the shape only
 * so that a request without it is answered `403 reauth_required`, as every other route that needs the proof answers
 * its absence, rather than `400 bad_request`.
 */
@kotlinx.serialization.Serializable
internal data class TotpDisableBody(val code: String, val currentAuthKey: String? = null)

/** Queue notice [template] to [userId]'s address with its account ID and, when given, the device's words ([MailDevices.of]). */
fun notify(s: Services, c: Connection, userId: String, template: String, device: String? = null, vars: Map<String, String> = emptyMap()) {
    val (email, pub) = c.queryOne("SELECT email,identityPub FROM users WHERE userId=?", userId) { it.getString(1) to it.getString(2) } ?: return
    val all = if (device != null) vars + ("device" to device) else vars
    s.mail.enqueue(c, template, email, Mail.Ctx(Mail.accountId(pub), s.clock.now(), all))
}
