package io.silencelen.andvari.server

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.header
import io.ktor.server.request.receiveText
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.route
import io.silencelen.andvari.core.model.wire.Caller
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireOk
import io.silencelen.andvari.core.model.wire.WirePlatform
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.serializer

/** What a bucket's budget belongs to (spec 03 §0.2). */
enum class BucketKey {
    /** The caller's address (an IPv6 client by its /64): the routes that need no session. */
    IP,

    /**
     * The session's device (`devices.deviceId`, which a refresh keeps), with a second budget per account of
     * [Bucket.ACCOUNT_CEILING_TIMES] times the device's: every route that needs a session.
     */
    DEVICE,

    /** A key the route gives itself (a hash of the typed address), drawn with `take(bucket, keySuffix)`. */
    GIVEN,
}

/**
 * A rate bucket (spec 03 §0.1, §0.2): [limit] calls per [windowMs] under [key]. [name] is the bucket's name in the
 * index; routes that share a name share the budget.
 *
 * A bucket of a route that needs a session is kept per device: a session spends only its own device's budget, so a
 * session in the wrong hands cannot keep the account's owner from a route on any other device. (Until 2026-11-17 these
 * buckets were kept per account, and five requests an hour from a held session kept the owner from deleting the
 * account on every device.) Beside it, every such bucket keeps a ceiling per account, [accountCeiling], because a
 * device is made by every sign-in with the password and the server holds no cap on an account's devices: without it,
 * whoever has the password could multiply any budget, the password checks (Argon2id, four at a time server-wide)
 * among them. The ceiling is drawn only by calls the device's own budget admitted, so a device refused by its own
 * budget spends nothing of the account's, and a call the ceiling refuses is given back to the device. One device can put at most twice its limit into one window of the ceiling
 * (the windows are fixed, and a burst at the end of one device window and the start of the next lands in one ceiling
 * window), so at four times the limit a held session leaves the other devices at least two devices' budgets.
 */
data class Bucket(val name: String, val limit: Int, val windowMs: Long, val key: BucketKey) {
    /** The second budget per account of a [BucketKey.DEVICE] bucket, in the same window; null for the others. */
    val accountCeiling: Int? get() = if (key == BucketKey.DEVICE) limit * ACCOUNT_CEILING_TIMES else null

    companion object {
        /** A device bucket's ceiling per account, as a multiple of its limit per device (see [Bucket]). */
        const val ACCOUNT_CEILING_TIMES = 4

        fun ipPerMinute(name: String, n: Int) = Bucket(name, n, Clock.MINUTE_MS, BucketKey.IP)
        fun ipPerHour(name: String, n: Int) = Bucket(name, n, Clock.HOUR_MS, BucketKey.IP)
        fun ipPerDay(name: String, n: Int) = Bucket(name, n, Clock.DAY_MS, BucketKey.IP)
        fun devicePerMinute(name: String, n: Int) = Bucket(name, n, Clock.MINUTE_MS, BucketKey.DEVICE)
        fun devicePerHour(name: String, n: Int) = Bucket(name, n, Clock.HOUR_MS, BucketKey.DEVICE)
        fun devicePerDay(name: String, n: Int) = Bucket(name, n, Clock.DAY_MS, BucketKey.DEVICE)
        fun givenPerDay(name: String, n: Int) = Bucket(name, n, Clock.DAY_MS, BucketKey.GIVEN)

        /** The limiter key of [b]'s budget for one device, and the one of its ceiling for the device's account. */
        fun deviceKey(b: Bucket, deviceId: String) = "${b.name}:device:$deviceId"
        fun accountKey(b: Bucket, userId: String) = "${b.name}:account:$userId"
    }
}

/**
 * Draw once on the [BucketKey.DEVICE] bucket [b] for [deviceId] of [userId]: the device's own budget first, and the
 * account's ceiling only when the device's admitted the call; when the ceiling refuses it, the device's is given back,
 * so a refused call spends nothing. Null when admitted, else the milliseconds to wait.
 *
 * The wait is never shorter than the real one: when the device's budget refuses while the account's ceiling is full as
 * well and lasts longer (the two windows start at different times), the wait is the ceiling's. Naming the device's alone
 * sent a client back while the ceiling would still refuse it.
 */
fun RateLimiter.drawDevice(b: Bucket, userId: String, deviceId: String): Long? = drawDeviceHeld(b, userId, deviceId).waitMs

/**
 * What one draw on a device bucket did ([drawDeviceHeld]): refused with [waitMs], or admitted in both the device's window
 * and the account's ceiling. [giveBack] returns it to the device's window only, once.
 */
class DeviceDraw internal constructor(
    private val limiter: RateLimiter, val waitMs: Long?,
    private val device: RateLimiter.Admitted?,
) {
    /**
     * The call is given back to the device's budget it was counted in, for a refusal that decided nothing about the caller
     * (an account deletion refused because a vault's log moved on). Good for one use, as [RateLimiter.refund] is.
     *
     * **The account's ceiling keeps the call, whatever the refusal** (decided on 2026-11-17). A refusal that decided nothing
     * can still be one the caller produces at will (a deletion that leaves a leaf out is refused for a moved log), and the
     * work in front of it can be expensive (the password's hash, of which the server runs four at a time). So something
     * that is never given back always stands in front of that work: once the ceiling is spent, the next call is refused
     * before any of it runs. The ceiling is four times the device's budget, so an honest person's retries still pass.
     */
    fun giveBack() {
        device?.let { limiter.refund(it) }
    }
}

/** [drawDevice], keeping the admitted call so that a route can give it back ([DeviceDraw.giveBack]). */
fun RateLimiter.drawDeviceHeld(b: Bucket, userId: String, deviceId: String): DeviceDraw {
    require(b.key == BucketKey.DEVICE) { "bucket ${b.name} is not kept per device" }
    val device = Bucket.deviceKey(b, deviceId)
    val account = Bucket.accountKey(b, userId)
    val drawn = draw(device, b.limit, b.windowMs)
    val admitted = drawn.admitted ?: return DeviceDraw(this, maxOf(drawn.waitMs!!, waitIfFull(account, b.accountCeiling!!) ?: 0L), null)
    val ceiling = draw(account, b.accountCeiling!!, b.windowMs)
    // A call the ceiling refuses goes back to the device window it was counted in, not to whichever is current then.
    if (ceiling.admitted == null) { refund(admitted); return DeviceDraw(this, ceiling.waitMs!!, null) }
    return DeviceDraw(this, null, admitted)
}

/** No bucket at all: the non-API routes (rows 88–92) and the WebSocket upgrade. */
val NO_BUCKET: Bucket? = null

/**
 * One API request in flight. Built by [api], which has already applied every generic rule of spec 03
 * §0.1 that the index marks for the route, in this order:
 *
 *  1. **R** (§18.6): on a public instance the route answers `404 not_found` before anything else.
 *  2. **V** (§1): a caller below `minVersion[platform]` gets `426 upgrade_required`.
 *  3. **Who may call** (§0.1): `401 missing_token` / `401 invalid_credentials`; a restricted session
 *     gets `403 totp_enrollment_required` except on TOTP setup, confirm and logout; an operator route
 *     answers `403 not_operator` to any other account and `403 operator_web_refused` to a web session.
 *  4. **The rate bucket** (§0.2): the route's own, or the default (reads 60/min, writes 60/h, † routes
 *     5/min, all per device and per route, each with its ceiling per account).
 *
 * The † password proof is checked by the handler through [reauth] once it has the body, so the route's
 * own check order stays where the spec puts it.
 */
class Req(val call: ApplicationCall, val s: Services, val route: WireRoute) {
    val ip: String by lazy { call.clientIp(s.config) }
    internal var principalOrNull: Principal? = null

    /** The session's principal; only on session and operator routes. */
    val p: Principal get() = principalOrNull ?: error("route ${route.name} has no session")

    val now: Long get() = s.clock.now()

    /** The platform of `X-Andvari-Client` when it is on the closed list, else null. */
    val headerPlatform: String? get() = call.clientId().platform.takeIf { it in WirePlatform.ALL }

    fun param(name: String): String = call.parameters[name] ?: badRequest(WireErrors.BAD_REQUEST)

    fun query(name: String): String? = call.request.queryParameters[name]

    /**
     * Draw on [b] now (the caller decides where in its check order): by the caller's address, by the session's device
     * and its account's ceiling, or by [keySuffix], which only a [BucketKey.GIVEN] bucket takes and must.
     */
    fun take(b: Bucket, keySuffix: String? = null) {
        require((b.key == BucketKey.GIVEN) == (keySuffix != null)) { "bucket ${b.name}: a key of its own is for given buckets only" }
        val wait = when (b.key) {
            BucketKey.IP -> s.limiter.retryAfterMs("${b.name}:${rateKeyOf(ip)}", b.limit, b.windowMs)
            BucketKey.GIVEN -> s.limiter.retryAfterMs("${b.name}:$keySuffix", b.limit, b.windowMs)
            BucketKey.DEVICE -> p.let { pr -> s.limiter.drawDevice(b, pr.userId, pr.deviceId) }
        }
        wait?.let { rateLimited(it) }
    }

    /**
     * [take] for a [BucketKey.IP] bucket, returning the admitted call so that the route can give it back
     * ([RateLimiter.refund]) when it refuses before anything was sent.
     */
    fun takeHeldAddress(b: Bucket): RateLimiter.Admitted {
        require(b.key == BucketKey.IP) { "bucket ${b.name} is not kept per address" }
        val d = s.limiter.draw("${b.name}:${rateKeyOf(ip)}", b.limit, b.windowMs)
        return d.admitted ?: rateLimited(d.waitMs!!)
    }

    /** [take] for a [BucketKey.DEVICE] bucket, keeping the admitted call so that the route can give it back. */
    fun takeHeld(b: Bucket): DeviceDraw {
        val pr = p
        val d = s.limiter.drawDeviceHeld(b, pr.userId, pr.deviceId)
        d.waitMs?.let { rateLimited(it) }
        return d
    }

    /** The JSON body, decoded leniently (§0.1); anything that is not the route's shape is `400 bad_request`. */
    suspend fun <T> body(ser: KSerializer<T>): T {
        val text = call.receiveText()
        return try {
            WireJson.json.decodeFromString(ser, text)
        } catch (_: Throwable) {
            badRequest(WireErrors.BAD_REQUEST)
        }
    }

    suspend inline fun <reified T> body(): T = body(serializer<T>())

    /** The raw JSON tree of the body (for routes that must tell a missing key from a null). */
    suspend fun jsonBody(): JsonElement {
        val text = call.receiveText()
        return try { WireJson.json.parseToJsonElement(text) } catch (_: Throwable) { badRequest(WireErrors.BAD_REQUEST) }
    }

    /**
     * The † password proof (spec 03 §0.1): [currentAuthKey] verified against the login verifier exactly
     * as `PUT /account/password` verifies it. A wrong key is `403 reauth_failed`, audited as
     * [auditType]. Returns the verifier that matched, for the routes that compare-and-swap on it.
     *
     * The proof has a back-off of its own (spec 03 §8): per device ([Services.deviceCounterKey] of the session's
     * device), with the sign-in back-off's curve, and counted only by proofs made on that device's sessions, so the
     * wrong proofs of one device never refuse another device's right one. Every proof
     * is counted before the verify, so a wrong one stays counted and arms the lock at the sign-in's threshold; while
     * it is locked the proof is refused before any verifier work with `429 rate_limited` and a `Retry-After` that names
     * the lock's real remaining wait (since 2026-11-17; it said 60 seconds while the lock could last 15 minutes): the
     * session learns only how long its own device must wait, which it can count for itself. A right one clears it, as
     * a right sign-in clears the sign-in's. The sign-in back-off is
     * neither read nor counted here, so no number of wrong sign-ins by someone without a session refuses this proof,
     * and no number of wrong proofs refuses a sign-in. The † routes together still give a session no more guesses
     * than a sign-in gets.
     */
    suspend fun reauth(currentAuthKey: String, auditType: String = "reauth_fail", auditMeta: String? = "route=${route.row}"): String {
        val principal = p
        val verifier = s.db.read { c -> c.queryOne("SELECT verifier FROM users WHERE userId=?", principal.userId) { it.getString(1) } }
            ?: unauthorized()
        val counter = s.deviceCounterKey(principal.deviceId)
        s.proofBackoff.reserveOrWait(counter)?.let { wait ->
            // Traced once per device per period, never per refused proof (decided on 2026-11-17).
            if (s.refusalTraceDue("reauth_wait", counter, RefusalTrace.BACKOFF_PERIOD_MS)) {
                s.db.tx { c -> s.audit.on(c, "reauth_wait", principal.userId, principal.deviceId, ip, "route=${route.row}") }
            }
            rateLimited(wait)
        }
        val ok = withContext(Dispatchers.IO) { runCatching { ServerCrypto.verify(verifier, currentAuthKey) }.getOrDefault(false) }
        if (!ok) {
            s.db.tx { c -> s.audit.on(c, auditType, principal.userId, principal.deviceId, ip, auditMeta) }
            forbidden(WireErrors.REAUTH_FAILED)
        }
        s.proofBackoff.success(counter)
        return verifier
    }

    /**
     * One two-step code sent on this session (TOTP setup, confirm and disable; the account deletion's code), checked
     * on the codes' own back-off: per device ([Services.deviceCounterKey]), with the sign-in back-off's curve, counted
     * only by codes checked on that device's sessions. The code is counted before [check] looks at it, so a wrong one stays counted;
     * while the back-off is in force the code is refused before it is looked at with `429 rate_limited` and a
     * `Retry-After` that names the lock's real remaining wait, exactly as a proof is; a right one clears it. A wrong one is audited `totp_verify_fail` with
     * [where] and answered `400 bad_totp_code`. [check] returns the step that verified (and was consumed, where the
     * route consumes it), or null. Neither the sign-in's back-off nor the proofs' is read or counted here, and this
     * one refuses nothing but the checking of a code.
     */
    suspend fun checkSessionCode(where: String, check: suspend () -> Long?): Long {
        val principal = p
        val counter = s.deviceCounterKey(principal.deviceId)
        s.codeBackoff.reserveOrWait(counter)?.let { wait ->
            // Traced once per device per period, never per refused code (decided on 2026-11-17).
            if (s.refusalTraceDue("totp_verify_wait", counter, RefusalTrace.BACKOFF_PERIOD_MS)) {
                s.db.tx { c -> s.audit.on(c, "totp_verify_wait", principal.userId, principal.deviceId, ip, where) }
            }
            rateLimited(wait)
        }
        val step = check() ?: run {
            s.db.tx { c -> s.audit.on(c, "totp_verify_fail", principal.userId, principal.deviceId, ip, where) }
            badRequest(WireErrors.BAD_TOTP_CODE)
        }
        s.codeBackoff.success(counter)
        return step
    }

    suspend fun <T> respond(ser: KSerializer<T>, value: T, status: Int = route.success) {
        call.respondText(WireJson.json.encodeToString(ser, value), ContentType.Application.Json, HttpStatusCode.fromValue(status))
    }

    suspend inline fun <reified T> respond(value: T, status: Int = route.success) = respond(serializer<T>(), value, status)

    suspend fun <T> respondList(ser: KSerializer<T>, values: List<T>) =
        call.respondText(WireJson.json.encodeToString(ListSerializer(ser), values), ContentType.Application.Json, HttpStatusCode.fromValue(route.success))

    suspend fun respondJsonText(text: String, status: Int = route.success) =
        call.respondText(text, ContentType.Application.Json, HttpStatusCode.fromValue(status))

    /** The plain-text `ok` (§0.1). */
    suspend fun ok() = call.respondText(WireOk.BODY, ContentType.Text.Plain, HttpStatusCode.fromValue(route.success))
}

/** Routes a restricted session may still reach (spec 03 §2). */
private val RESTRICTED_ALLOWED = setOf(WireRoute.TOTP_SETUP, WireRoute.TOTP_CONFIRM, WireRoute.LOGOUT)

/** The default bucket of an authenticated route that names none (spec 03 §0.1). */
fun defaultBucket(r: WireRoute): Bucket = when {
    r.reauth -> Bucket.devicePerMinute("reauth_${r.name.lowercase()}", 5)
    r.method == "GET" -> Bucket.devicePerMinute("read_${r.name.lowercase()}", 60)
    else -> Bucket.devicePerHour("write_${r.name.lowercase()}", 60)
}

/**
 * Register [r] with its generic rules (see [Req]). [bucket] is the route's bucket, drawn after the caller
 * is known; null draws nothing here (the handler draws its own, in its own check order, or the route has
 * none). Every API route goes through this, so none can skip a generic rule.
 */
fun Route.api(r: WireRoute, s: Services, bucket: Bucket? = if (r.caller == Caller.NONE) null else defaultBucket(r), handler: suspend Req.() -> Unit) {
    route(r.path, HttpMethod(r.method)) {
        handle {
            val req = Req(call, s, r)
            if (r.refusedOnPublic && s.config.isPublic) notFound(WireErrors.NOT_FOUND)
            if (r.versionChecked) enforceMinVersion(s, call)
            when (r.caller) {
                Caller.SESSION, Caller.SESSION_REAUTH, Caller.OPERATOR, Caller.OPERATOR_REAUTH -> {
                    val token = call.request.header(HttpHeaders.Authorization)?.takeIf { it.startsWith("Bearer ") }?.removePrefix("Bearer ")?.trim()
                        ?.takeIf { it.isNotEmpty() } ?: unauthorized(WireErrors.MISSING_TOKEN)
                    if (token.length > 128) unauthorized()
                    val principal = s.db.read { c -> s.sessions.authenticate(c, token) } ?: unauthorized()
                    if (principal.restricted && r !in RESTRICTED_ALLOWED) forbidden(WireErrors.TOTP_ENROLLMENT_REQUIRED)
                    if (r.caller == Caller.OPERATOR || r.caller == Caller.OPERATOR_REAUTH) {
                        if (!principal.isOperator) forbidden(WireErrors.NOT_OPERATOR)
                        if (principal.webSession) forbidden(WireErrors.OPERATOR_WEB_REFUSED)
                    }
                    req.principalOrNull = principal
                }
                else -> {}
            }
            bucket?.let { req.take(it) }
            req.handler()
        }
    }
}

/** spec 03 §1: `426 upgrade_required` with `message = "min <platform> <minVersion>"`. */
private fun enforceMinVersion(s: Services, call: ApplicationCall) {
    val client = call.clientId()
    val min = s.policy.get().minVersion[client.platform] ?: return
    if (compareVersions(client.version, min) < 0) {
        throw ApiException(426, WireErrors.UPGRADE_REQUIRED, "min ${client.platform} $min")
    }
}
