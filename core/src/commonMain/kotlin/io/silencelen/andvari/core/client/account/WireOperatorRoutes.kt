package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountDeleteBlocker
import io.silencelen.andvari.core.model.wire.AccountDisableRequest
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.DisableReason
import io.silencelen.andvari.core.model.wire.OperatorDeleteReason
import io.silencelen.andvari.core.model.wire.OperatorDeleteRequest
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.model.wire.QuotaPut
import io.silencelen.andvari.core.model.wire.ReauthRequest
import io.silencelen.andvari.core.model.wire.RecoveryFulfilRequest
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer

/**
 * What an operator's account deletion came to (spec 03 §7.1 row 76, design §9.2): the typed refusals of the 30-day rule
 * and of a shared vault with other members, beside the [Reauthed] outcomes every `†` route has.
 */
sealed class OperatorDelete {
    /** Deleted; [deletedAt] is the server's time. */
    data class Deleted(val deletedAt: Long) : OperatorDelete()

    /**
     * `409 not_disabled_long_enough`: the account is active, or was disabled less than 30 days ago. [disabledAt] is when it
     * was disabled as the server says, null when it is active (the two read the same, spec 03 §7.1). Nothing was deleted.
     */
    data class NotDisabledLongEnough(val disabledAt: Long?) : OperatorDelete()

    /** `409 account_delete_blocked`: the account owns a shared vault with other members ([blockers], as served). */
    data class Blocked(val blockers: List<AccountDeleteBlocker>) : OperatorDelete()

    /** Every other outcome: [NoSession][Reauthed.NoSession], a wrong password, another refusal code, or unknown. */
    data class Other(val result: Reauthed<Nothing>) : OperatorDelete()
}

/**
 * [OperatorRoutes] over the wire (spec 03 §7, §18.6; rows 73 to 86; design §9.2), for the operator account's own session at
 * [client]'s origin, so the apps and the command-line tool stop calling the routes by hand. [userId] and [role] are the
 * session's; [trust] gives the pinned card's `kind` (variant R); [reauth] is the session's one re-authentication path.
 *
 * - **Nothing is derived from the password, and nothing sent, while a refusal is certain on this device:** a session that
 *   is not the operator's ([NOT_OPERATOR]), an id that is not of its grammar, the operator's own account as the target of
 *   a disable or a delete ([CANNOT_TARGET_SELF]), a disable reason, quota or KDF shape the server would refuse, an
 *   answer the shared reader read for another request (an upload takes only what that reader made), and on a `public`
 *   card the three recovery routes
 *   ([OPERATOR_RECOVERY_UNAVAILABLE], variant R: spec 03 §18.6).
 * - Every `†` route re-authenticates through [Reauth] ([io.silencelen.andvari.core.client.pin.PasswordGate] purpose
 *   `reauth`), and each `password` handed in is wiped before the call returns, on every path.
 * - Results: a refusal is the route's code ([Reauthed.Refused], [Fetched.Refused]); the constants below name every code the
 *   index lists for these rows. `reauth_failed` is [Reauthed.Refused] with [Reauthed.PROOF_REFUSED] (a password typed wrong here is
 *   [Reauthed.WrongPassword], with nothing sent); a `5xx`, no answer or a reply that does not
 *   decode is [Reauthed.Unknown] or [Fetched.Unreachable]. [deleteChecked] types the delete's two `409`s.
 * - Nothing here shows a recovery request code (T2-R-c): the server sends none, and none is asked for.
 */
class WireOperatorRoutes(
    private val userId: String,
    private val role: String,
    private val client: WireClient,
    private val trust: InstanceTrust,
    private val reauth: Reauth,
) : OperatorRoutes {
    private val operator: Boolean get() = role == OPERATOR_ROLE

    /** A public card (variant R) has no operator recovery: routes 84 to 86 are never called. */
    private fun publicCard(): Boolean = trust.pinFor(client.origin)?.kind == InstanceKind.PUBLIC.literal

    private suspend fun <T> read(route: WireRoute, s: KSerializer<T>, params: Map<String, String> = emptyMap(), query: String? = null): Fetched<T> {
        if (!operator) return Fetched.Refused(NOT_OPERATOR)
        return when (val r = client.call(route, pathParams = params, query = query, decode = { WireJson.json.decodeFromString(s, it) })) {
            is WireResult.Ok -> Fetched.Ok(r.value)
            is WireResult.Refused -> if (r.status >= 500) Fetched.Unreachable else Fetched.Refused(r.code)
            is WireResult.NoAnswer -> Fetched.Unreachable
        }
    }

    /** How a `†` call ended: stopped before anything was sent, or the server's answer. */
    private sealed class Sent<out T> {
        class Stop(val result: Reauthed<Nothing>) : Sent<Nothing>()
        class Answer<T>(val result: WireResult<T>) : Sent<T>()
    }

    /**
     * The one path of every `†` route: [check] (null to go on) before the password is touched, then [Reauth], then the call
     * with the body [body] builds from the key. [password] is wiped on every path.
     */
    private suspend fun <T> send(
        password: CharArray,
        route: WireRoute,
        params: Map<String, String>,
        check: () -> String?,
        body: (String) -> String,
        decode: (String) -> T,
    ): Sent<T> {
        val key = try {
            if (!operator) return Sent.Stop(Reauthed.Refused(NOT_OPERATOR))
            check()?.let { return Sent.Stop(Reauthed.Refused(it)) }
            reauth.currentAuthKey(password)
        } finally {
            password.fill('\u0000')
        }
        val current = when (key) {
            is ReauthKey.Key -> key.currentAuthKey
            ReauthKey.Refused -> return Sent.Stop(Reauthed.NoSession)
            ReauthKey.Unreachable -> return Sent.Stop(Reauthed.Unknown)
            ReauthKey.WrongPassword -> return Sent.Stop(Reauthed.WrongPassword)
        }
        return Sent.Answer(client.call(route, pathParams = params, bodyJson = body(current), decode = decode))
    }

    private suspend fun <T> reauthed(
        password: CharArray,
        route: WireRoute,
        params: Map<String, String>,
        check: () -> String?,
        body: (String) -> String,
        decode: (String) -> T,
        withMessage: Boolean = false,
    ): Reauthed<T> = when (val s = send(password, route, params, check, body, decode)) {
        is Sent.Stop -> s.result
        is Sent.Answer -> when (val r = s.result) {
            is WireResult.Ok -> Reauthed.Done(r.value)
            is WireResult.Refused -> plain(r, withMessage)
            is WireResult.NoAnswer -> Reauthed.Unknown
        }
    }

    /** [r] as a result; with [withMessage] (a refused policy) a refusal for the request carries the server's own words. */
    private fun plain(r: WireResult.Refused, withMessage: Boolean = false): Reauthed<Nothing> = when {
        r.code == REAUTH_FAILED -> Reauthed.Refused(Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
        r.status >= 500 -> Reauthed.Unknown
        else -> Reauthed.Refused(r.code, r.retryAfterSeconds, if (withMessage) Reauthed.serverMessage(r.error.message) else null)
    }

    private fun reauthBody(key: String) = WireJson.json.encodeToString(ReauthRequest.serializer(), ReauthRequest(key))

    private fun user(id: String): String? = if (TrustGrammar.isUuid(id)) null else BAD_USER_ID

    /** A target that is not the operator's own account (spec 03 §7.1 `cannot_target_self`). */
    private fun other(id: String): String? = user(id) ?: if (id == userId) CANNOT_TARGET_SELF else null

    override suspend fun accounts(): Fetched<List<AccountSummary>> = read(WireRoute.ADMIN_ACCOUNTS, ListSerializer(AccountSummary.serializer()))

    /** `POST /admin/accounts/{userId}/disable`†; [reason] is a [DisableReason] value. */
    override suspend fun disable(userId: String, reason: String, password: CharArray): Reauthed<Unit> =
        reauthed(password, WireRoute.ADMIN_ACCOUNT_DISABLE, mapOf("userId" to userId),
            { other(userId) ?: if (reason in DISABLE_REASONS) null else BAD_REASON },
            { WireJson.json.encodeToString(AccountDisableRequest.serializer(), AccountDisableRequest(reason, it)) }, { })

    override suspend fun enable(userId: String, password: CharArray): Reauthed<Unit> =
        reauthed(password, WireRoute.ADMIN_ACCOUNT_ENABLE, mapOf("userId" to userId), { user(userId) }, ::reauthBody, { })

    /** [deleteChecked] as a [Reauthed]: the two `409`s are [Reauthed.Refused] with their codes. */
    override suspend fun deleteAccount(userId: String, password: CharArray): Reauthed<Long> = deleteAccount(userId, password, null)

    /** [deleteChecked] with a [reason] (an [OperatorDeleteReason] value, or null for the 30-day rule), as a [Reauthed]. */
    override suspend fun deleteAccount(userId: String, password: CharArray, reason: String?): Reauthed<Long> = when (val d = deleteChecked(userId, password, reason)) {
        is OperatorDelete.Deleted -> Reauthed.Done(d.deletedAt)
        is OperatorDelete.NotDisabledLongEnough -> Reauthed.Refused(NOT_DISABLED_LONG_ENOUGH)
        is OperatorDelete.Blocked -> Reauthed.Refused(ACCOUNT_DELETE_BLOCKED)
        is OperatorDelete.Other -> d.result
    }

    /**
     * `POST /admin/accounts/{userId}/delete`† (design §9.2, W2): only an account disabled at least 30 days, and not one
     * that owns a shared vault with other members. The server decides both (its clock, its rows); this device does not
     * pre-judge the 30 days with its own clock. The refusals come back typed.
     *
     * [reason] is null (the 30-day rule; the body is then exactly the `{currentAuthKey}` it always was) or
     * [OperatorDeleteReason.UNDER_MINIMUM_AGE], which lifts the 30 days for a disabled account and nothing else. Any
     * other value is [BAD_REASON] here: nothing derived, nothing sent.
     */
    suspend fun deleteChecked(userId: String, password: CharArray, reason: String? = null): OperatorDelete {
        val s = send(password, WireRoute.ADMIN_ACCOUNT_DELETE, mapOf("userId" to userId),
            { other(userId) ?: if (reason == null || reason in DELETE_REASONS) null else BAD_REASON },
            { WireJson.json.encodeToString(OperatorDeleteRequest.serializer(), OperatorDeleteRequest(it, reason)) },
            { WireJson.json.decodeFromString(DeletedAtResponse.serializer(), it).deletedAt })
        val r = when (s) {
            is Sent.Stop -> return OperatorDelete.Other(s.result)
            is Sent.Answer -> s.result
        }
        return when (r) {
            is WireResult.Ok -> OperatorDelete.Deleted(r.value)
            is WireResult.NoAnswer -> OperatorDelete.Other(Reauthed.Unknown)
            is WireResult.Refused -> when {
                r.status == 409 && r.code == NOT_DISABLED_LONG_ENOUGH -> OperatorDelete.NotDisabledLongEnough(r.error.disabledAt)
                r.status == 409 && r.code == ACCOUNT_DELETE_BLOCKED -> OperatorDelete.Blocked(r.error.blockers.orEmpty())
                else -> OperatorDelete.Other(plain(r))
            }
        }
    }

    override suspend fun accountDevices(userId: String): Fetched<List<Device>> {
        user(userId)?.let { return Fetched.Refused(it) }
        if (!operator) return Fetched.Refused(NOT_OPERATOR)
        // Every page ([DevicePages]: the whole list only once its last page arrived).
        return DevicePages.readAll(client, WireRoute.ADMIN_ACCOUNT_DEVICES, mapOf("userId" to userId))
    }

    override suspend fun revokeDevice(deviceId: String, password: CharArray): Reauthed<Unit> =
        reauthed(password, WireRoute.ADMIN_DEVICE_REVOKE, mapOf("deviceId" to deviceId),
            { if (TrustGrammar.isUuid(deviceId)) null else BAD_DEVICE_ID }, ::reauthBody, { })

    /** Each limit null returns it to the instance default (every key is sent, spec 03 §7.1); a negative limit is [BAD_QUOTA]. */
    override suspend fun setQuota(userId: String, accountBytes: Long?, items: Long?, ownedSharedVaults: Long?, openLinks: Long?, password: CharArray): Reauthed<Quota> =
        reauthed(password, WireRoute.ADMIN_QUOTA, mapOf("userId" to userId),
            { user(userId) ?: if (listOfNotNull(accountBytes, items, ownedSharedVaults, openLinks).any { it < 0 }) BAD_QUOTA else null },
            { WireJson.json.encodeToString(QuotaPut.serializer(), QuotaPut(accountBytes, items, ownedSharedVaults, openLinks, it)) },
            { WireJson.json.decodeFromString(Quota.serializer(), it) })

    override suspend fun policy(): Fetched<AdminPolicy> = read(WireRoute.ADMIN_POLICY_GET, AdminPolicy.serializer())

    /**
     * `PUT /admin/policy`†. A `kdfParams.memBytes` that is not a whole number of KiB is refused here
     * ([KDF_MEM_NOT_KIB_MULTIPLE], spec 03 §7.2) before the password is touched; every other bound is the server's.
     */
    override suspend fun setPolicy(policy: AdminPolicy, password: CharArray): Reauthed<AdminPolicy> =
        reauthed(password, WireRoute.ADMIN_POLICY_PUT, emptyMap(),
            { if (policy.kdfParams.memBytes % 1024 != 0L) KDF_MEM_NOT_KIB_MULTIPLE else null },
            { WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(policy, it)) },
            { WireJson.json.decodeFromString(AdminPolicy.serializer(), it) }, withMessage = true)

    override suspend fun audit(): Fetched<List<AuditRow>> = audit(null, null, null)

    /**
     * `GET /admin/audit?since=&type=&userId=` (spec 03 §7.3), each filter only when given. A [type] that is not a
     * lowercase audit type name is [BAD_TYPE] and a [userId] that is not a uuid [BAD_USER_ID]; nothing is sent then.
     */
    suspend fun audit(sinceMs: Long?, type: String?, userId: String?): Fetched<List<AuditRow>> {
        if (type != null && !AUDIT_TYPE.matches(type)) return Fetched.Refused(BAD_TYPE)
        if (userId != null) user(userId)?.let { return Fetched.Refused(it) }
        if (sinceMs != null && sinceMs < 0) return Fetched.Refused(BAD_SINCE)
        val query = listOfNotNull(sinceMs?.let { "since=$it" }, type?.let { "type=$it" }, userId?.let { "userId=$it" })
            .joinToString("&").ifEmpty { null }
        return read(WireRoute.ADMIN_AUDIT, ListSerializer(AuditRow.serializer()), query = query)
    }

    /**
     * One page of `GET /admin/audit` (spec 03 §7.3), newest first, with the filters of [audit] and the page cursor
     * [after] (the `id` of the previous page's last row; null for the first page). The page is checked before it is
     * handed out, the same checks for every host ([AuditPage]): at most [AUDIT_PAGE_ROWS] rows, no row twice, ids
     * strictly falling, every row inside the filters, and on a later page every row older than the cursor. A page that
     * fails one is [AUDIT_PAGE_LIES], never a short list.
     */
    suspend fun auditPage(sinceMs: Long?, type: String?, userId: String?, after: Long? = null): Fetched<AuditPage> {
        if (after != null && after <= 0) return Fetched.Refused(BAD_CURSOR)
        if (type != null && !AUDIT_TYPE.matches(type)) return Fetched.Refused(BAD_TYPE)
        if (userId != null) user(userId)?.let { return Fetched.Refused(it) }
        if (sinceMs != null && sinceMs < 0) return Fetched.Refused(BAD_SINCE)
        val query = listOfNotNull(sinceMs?.let { "since=$it" }, type?.let { "type=$it" }, userId?.let { "userId=$it" }, after?.let { "after=$it" })
            .joinToString("&").ifEmpty { null }
        val rows = when (val r = read(WireRoute.ADMIN_AUDIT, ListSerializer(AuditRow.serializer()), query = query)) {
            is Fetched.Ok -> r.value
            is Fetched.Refused -> return r
            Fetched.Unreachable -> return Fetched.Unreachable
        }
        if (!AuditPage.holds(rows, sinceMs, type, userId, after)) return Fetched.Refused(AUDIT_PAGE_LIES)
        return Fetched.Ok(AuditPage(rows, rows.size == AUDIT_PAGE_ROWS, sinceMs, type, userId))
    }

    /** The page after [page], with the same filters; null when [page] was not full (it was the last one). */
    suspend fun nextAuditPage(page: AuditPage): Fetched<AuditPage>? {
        if (!page.full) return null
        return auditPage(page.sinceMs, page.type, page.userId, page.rows.last().id)
    }

    override suspend fun status(): Fetched<AdminStatus> = read(WireRoute.ADMIN_STATUS, AdminStatus.serializer())

    override suspend fun recoveryRequests(): Fetched<List<AdminRecoveryRequest>> {
        if (operator && publicCard()) return Fetched.Refused(OPERATOR_RECOVERY_UNAVAILABLE)
        return read(WireRoute.ADMIN_RECOVERY_REQUESTS, ListSerializer(AdminRecoveryRequest.serializer()))
    }

    /** `POST /admin/accounts/{userId}/escrow`†. An answer for another account than [userId] is refused ([BAD_RESPONSE]). */
    override suspend fun escrow(userId: String, password: CharArray): Reauthed<AdminEscrowResponse> {
        val r = reauthed(password, WireRoute.ADMIN_ESCROW, mapOf("userId" to userId),
            { user(userId) ?: if (publicCard()) OPERATOR_RECOVERY_UNAVAILABLE else null }, ::reauthBody,
            { WireJson.json.decodeFromString(AdminEscrowResponse.serializer(), it) })
        return if (r is Reauthed.Done && r.value.userId != userId) Reauthed.Refused(BAD_RESPONSE) else r
    }

    /**
     * `POST /admin/recovery-requests/{requestId}/fulfil`†: the three parts of [answer], which only the shared reader of an
     * answer makes ([io.silencelen.andvari.core.trust.AnswerToken.read]), so a bare sealed answer, anything that is not an
     * answer, and an answer for another request or of another size never get here. An [answer] read for another request
     * than [requestId] is [BAD_REQUEST_ID]: nothing derived or sent.
     */
    override suspend fun fulfil(requestId: String, answer: io.silencelen.andvari.core.trust.AnswerRead.Ok, password: CharArray): Reauthed<Unit> =
        reauthed(password, WireRoute.ADMIN_RECOVERY_FULFIL, mapOf("requestId" to requestId),
            {
                when {
                    !TrustGrammar.isB64_16(requestId) || answer.requestId != requestId -> BAD_REQUEST_ID
                    publicCard() -> OPERATOR_RECOVERY_UNAVAILABLE
                    else -> null
                }
            },
            {
                WireJson.json.encodeToString(RecoveryFulfilRequest.serializer(), RecoveryFulfilRequest(answer.sealed, it, answer.requestKey, answer.commitHash))
            }, { })

    companion object {
        const val OPERATOR_ROLE = "operator"

        // ---- refusals the route index lists for rows 73 to 86 (spec 03 §0.2, §7, §18.6) ----
        const val NOT_OPERATOR = "not_operator"
        const val OPERATOR_WEB_REFUSED = "operator_web_refused"
        const val REAUTH_FAILED = "reauth_failed"
        const val NO_SUCH_USER = "no_such_user"
        const val CANNOT_TARGET_SELF = "cannot_target_self"
        const val NOT_DISABLED_LONG_ENOUGH = "not_disabled_long_enough"
        const val ACCOUNT_DELETE_BLOCKED = "account_delete_blocked"
        const val NO_SUCH_DEVICE = "no_such_device"
        const val KDF_TOO_WEAK = "kdf_too_weak"
        const val KDF_MEM_NOT_KIB_MULTIPLE = "kdf_mem_not_kib_multiple"
        const val NOT_TIGHTER = "not_tighter"
        const val NO_ESCROW = "no_escrow"
        const val REQUEST_UNKNOWN = "request_unknown"
        const val REQUEST_STATE = "request_state"
        const val BAD_REQUEST = "bad_request"

        /** Variant R: the public instance answers `404 not_found` on routes 84 to 86. */
        const val NOT_FOUND = "not_found"

        // ---- refused on this device, nothing derived or sent ----
        const val BAD_USER_ID = "bad_user_id"
        const val BAD_DEVICE_ID = "bad_device_id"
        const val BAD_REQUEST_ID = "bad_request_id"
        const val BAD_REASON = "bad_reason"
        const val BAD_QUOTA = "bad_quota"
        const val BAD_TYPE = "bad_type"

        /** An audit page cursor that is not a positive row id: nothing is sent. */
        const val BAD_CURSOR = "bad_cursor"

        /** An audit page that fails the checks every host makes ([AuditPage]): it is not shown as a short list. */
        const val AUDIT_PAGE_LIES = "audit_page_lies"

        /** The rows of one full audit page (the server's `AUDIT_PAGE`, spec 03 §7.3): a page this long has a next one to ask for. */
        const val AUDIT_PAGE_ROWS = 500
        const val BAD_SINCE = "bad_since"
        const val BAD_SEALED = "bad_sealed"

        // ---- the upload's refusals (spec 03 §18.6) ----
        const val BAD_REQUEST_KEY = "bad_request_key"
        const val BAD_COMMIT_HASH = "bad_commit_hash"
        const val REQUEST_KEY_MISMATCH = "request_key_mismatch"

        /** A `public` card (variant R): no operator recovery, so routes 84 to 86 are never called. */
        const val OPERATOR_RECOVERY_UNAVAILABLE = "operator_recovery_unavailable"

        /** The server answered for another account than the one asked. */
        const val BAD_RESPONSE = "bad_response"

        /** A fulfilment statement is at most 1 KiB decoded (spec 03 §18.6). */
        const val SEALED_MAX_BYTES = 1024

        private val DISABLE_REASONS = setOf(DisableReason.ABUSE, DisableReason.REQUEST, DisableReason.OTHER)
        private val DELETE_REASONS = setOf(OperatorDeleteReason.UNDER_MINIMUM_AGE)
        private val AUDIT_TYPE = Regex("^[a-z][a-z0-9_]{0,63}$")
    }
}

/**
 * One checked page of the operator's audit list ([WireOperatorRoutes.auditPage]), newest first. [full]: it holds
 * [WireOperatorRoutes.AUDIT_PAGE_ROWS] rows, so there may be older ones: [WireOperatorRoutes.nextAuditPage] asks for them
 * with the same filters. Joining pages needs no more checks than each page's own: every row of a later page is older than
 * the cursor (the previous page's last row), so no row comes twice across pages and none is out of order.
 */
class AuditPage internal constructor(
    val rows: List<AuditRow>,
    val full: Boolean,
    internal val sinceMs: Long?,
    internal val type: String?,
    internal val userId: String?,
) {
    internal companion object {
        /** The checks every host makes of one page (and so of pages joined in order). */
        fun holds(rows: List<AuditRow>, sinceMs: Long?, type: String?, userId: String?, after: Long?): Boolean {
            if (rows.size > WireOperatorRoutes.AUDIT_PAGE_ROWS) return false
            for (i in rows.indices) {
                val r = rows[i]
                if (r.id <= 0) return false
                // Newest first: ids strictly falling, so no row twice.
                if (i > 0 && r.id >= rows[i - 1].id) return false
                if (after != null && r.id >= after) return false
                if (sinceMs != null && r.at < sinceMs) return false
                if (type != null && r.type != type) return false
                if (userId != null && r.userId != userId) return false
            }
            return true
        }
    }
}
