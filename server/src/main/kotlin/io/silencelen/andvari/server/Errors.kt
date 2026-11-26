package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AccountDeleteBlocker
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors

/**
 * Every refusal the server answers (spec 03 §0.1): `{error, message}` plus, for a few codes, extra
 * top-level fields ([WireError]). Thrown anywhere in a handler; StatusPages turns it into the response.
 *
 * [retryAfterSeconds] rides a `429` as `Retry-After` (spec 03 §0.1). [message] is human text and never
 * carries a secret, a code, a token or an address.
 */
class ApiException(
    val status: Int,
    val body: WireError,
    val retryAfterSeconds: Long? = null,
) : Exception(body.error) {
    constructor(status: Int, code: String, message: String = defaultMessage(status)) : this(status, WireError(code, message))

    companion object {
        fun defaultMessage(status: Int): String = when (status) {
            400 -> "bad request"
            401 -> "authentication failed"
            403 -> "forbidden"
            404 -> "not found"
            409 -> "conflict"
            410 -> "gone"
            413 -> "too large"
            426 -> "upgrade required"
            429 -> "slow down"
            502 -> "upstream failed"
            503 -> "unavailable"
            else -> "error"
        }
    }
}

fun badRequest(code: String): Nothing = throw ApiException(400, code)
fun unauthorized(code: String = WireErrors.INVALID_CREDENTIALS): Nothing = throw ApiException(401, code)
fun forbidden(code: String): Nothing = throw ApiException(403, code)
fun notFound(code: String = WireErrors.NOT_FOUND): Nothing = throw ApiException(404, code)
fun conflict(code: String): Nothing = throw ApiException(409, code)
fun gone(code: String): Nothing = throw ApiException(410, code)
fun unavailable(code: String): Nothing = throw ApiException(503, code)

fun rateLimited(retryAfterMs: Long): Nothing =
    throw ApiException(429, WireError(WireErrors.RATE_LIMITED, "slow down"), retryAfterSeconds = ((retryAfterMs + 999) / 1000).coerceAtLeast(1))

/** `413 quota_exceeded {quota}` (spec 03 §14.4). */
fun quotaExceeded(quota: String): Nothing =
    throw ApiException(413, WireError(WireErrors.QUOTA_EXCEEDED, "this vault's owner is out of space on this server", quota = quota))

/** `409 log_head_moved {seq, hash, at}` (spec 03 §10.3 step 6). */
fun logHeadMoved(seq: Long, hash: String, at: Long): Nothing =
    throw ApiException(409, WireError(WireErrors.LOG_HEAD_MOVED, "the log moved on", seq = seq, hash = hash, at = at))

/** `409 card_head_moved {seq, hash}` (spec 03 §17.2). */
fun cardHeadMoved(seq: Long, hash: String): Nothing =
    throw ApiException(409, WireError(WireErrors.CARD_HEAD_MOVED, "the card chain moved on", seq = seq, hash = hash))

/** `409 account_delete_blocked {blockers}` (spec 03 §13). */
fun accountDeleteBlocked(blockers: List<AccountDeleteBlocker>): Nothing =
    throw ApiException(409, WireError(WireErrors.ACCOUNT_DELETE_BLOCKED, "account deletion is blocked", blockers = blockers))

/** `409 account_delete_log_stale {vaultIds}` (spec 03 §13). */
fun accountDeleteLogStale(vaultIds: List<String>): Nothing =
    throw ApiException(409, WireError(WireErrors.ACCOUNT_DELETE_LOG_STALE, "a vault log moved on", vaultIds = vaultIds))

/** `409 not_disabled_long_enough {disabledAt}` (spec 03 §7.1). */
fun notDisabledLongEnough(disabledAt: Long?): Nothing =
    throw ApiException(409, WireError(WireErrors.NOT_DISABLED_LONG_ENOUGH, "the account has not been disabled for 30 days", disabledAt = disabledAt))
