package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.model.wire.AccountDisableRequest
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminMailStatus
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupStatus
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.DisableReason
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.model.wire.ReauthRequest
import io.silencelen.andvari.core.model.wire.RecoveryFulfilRequest
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.sql.Connection

/**
 * The operator routes (spec 03 §7, §18.6; design §9.2). Every one needs the operator account's session,
 * never a web one (the generic checks of [api]); the † ones a fresh password proof. Through these routes the
 * operator can do exactly what §9.2 lists: account status, devices, quotas, the tighten-only policy, the
 * audit, and — on a private instance — an opted-in account's escrow and the assisted-recovery answer. Every
 * call is audited with ids only.
 */
/**
 * The bounds of `PUT /admin/policy` (spec 03 §7.2), checked in body order so the first failing field names
 * the refusal (§0.1). They are the previous server's, not new ones:
 *
 *  - `kdfParams`: the KDF floor and the KiB-multiple shape (`kdf_too_weak`, `kdf_mem_not_kib_multiple`);
 *    the previous server refused the shape at this write and the floor at every account write; and, since
 *    2026-11-17, the floor's own limits ([KdfLimits.policyProblem]): not above what the clients accept (10 passes,
 *    1 GiB) nor the server's own limit, refused as `kdf_too_weak` with the floor's line as the message;
 *  - `autoLockSeconds` in `1..AUTO_LOCK_MAX_SECONDS` (900) and `clipboardClearSeconds` in
 *    `1..CLIPBOARD_CLEAR_MAX_SECONDS` (300): the ranges every client clamps to (`ClientPolicyClamps`), so a
 *    stored value is the value the clients apply;
 *  - `sessionAccessTtlSeconds` at least 60 and `sessionRefreshTtlDays` at least 1 (the server's own lower
 *    bounds, spec 03 §7.2 "as implemented"). The previous server had no upper bound; the only ceiling here is
 *    arithmetic, so the expiry in milliseconds cannot overflow ([TTL_SECONDS_MAX], [TTL_DAYS_MAX]);
 *  - `attachmentMaxBytes` and `itemAttachmentsMaxBytes` positive and at most `quotaDefaults.accountBytes`;
 *  - `quotaDefaults`: positive account bytes and items, non-negative counts;
 *  - `minVersion` keys on the platform list with `x.y.z` values; `signup.mode` one of the three modes.
 */
object PolicyBounds {
    const val TTL_SECONDS_MAX = Long.MAX_VALUE / 4 / 1000
    const val TTL_DAYS_MAX = Long.MAX_VALUE / 4 / Clock.DAY_MS
    private val SEMVER = Regex("^\\d{1,5}\\.\\d{1,5}\\.\\d{1,5}$")

    fun check(s: Services, req: AdminPolicyPut) {
        req.minVersion.forEach { (k, v) -> if (k !in io.silencelen.andvari.core.model.wire.WirePlatform.ALL || !SEMVER.matches(v)) badRequest(WireErrors.badField("minVersion")) }
        // The floor's limits first, in its own lines ([KdfLimits.policyProblem]): `400 kdf_too_weak`, as the server's own
        // limit was already answered here, with the line as the message.
        KdfLimits.policyProblem(req.kdfParams.ops, req.kdfParams.memBytes)?.let { throw ApiException(400, WireErrors.KDF_TOO_WEAK, it) }
        s.policy.requireKdf(req.kdfParams)
        if (req.autoLockSeconds !in 1..io.silencelen.andvari.core.client.ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS.toLong()) badRequest(WireErrors.badField("autoLockSeconds"))
        if (req.clipboardClearSeconds !in 1..io.silencelen.andvari.core.client.ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS.toLong()) badRequest(WireErrors.badField("clipboardClearSeconds"))
        if (req.sessionAccessTtlSeconds !in 60..TTL_SECONDS_MAX) badRequest(WireErrors.badField("sessionAccessTtlSeconds"))
        if (req.sessionRefreshTtlDays !in 1..TTL_DAYS_MAX) badRequest(WireErrors.badField("sessionRefreshTtlDays"))
        val q = req.quotaDefaults
        if (req.attachmentMaxBytes <= 0 || req.attachmentMaxBytes > q.accountBytes) badRequest(WireErrors.badField("attachmentMaxBytes"))
        if (req.itemAttachmentsMaxBytes <= 0 || req.itemAttachmentsMaxBytes > q.accountBytes) badRequest(WireErrors.badField("itemAttachmentsMaxBytes"))
        if (q.accountBytes <= 0 || q.items <= 0 || q.ownedSharedVaults < 0 || q.openLinks < 0) badRequest(WireErrors.badField("quotaDefaults"))
        req.signup.mode?.let { if (it !in setOf(SignupMode.OPEN, SignupMode.LINKS, SignupMode.CLOSED)) badRequest(WireErrors.badField("signup")) }
    }
}

/**
 * The body of `POST /admin/accounts/{userId}/delete` (spec 03 §7.1): the † proof, and an optional `reason`
 * whose only value is [UNDER_MINIMUM_AGE]. Absent, the 30-day rule applies. A server-side type because
 * core's route table names `ReauthRequest` for this body; a client that sends no `reason` is unchanged.
 */
@kotlinx.serialization.Serializable
data class OperatorDeleteRequest(val currentAuthKey: String, val reason: String? = null) {
    companion object {
        const val UNDER_MINIMUM_AGE = "under_minimum_age"
    }
}

object OperatorRules {
    const val DELETE_AFTER_DISABLED_MS = 30 * Clock.DAY_MS
    const val AUDIT_PAGE = 500

    /** The target account, or `400 no_such_user` (audited [deniedType] without the id); the operator itself is `cannot_target_self`. */
    fun target(s: Services, c: Connection, raw: String, op: Principal, ip: String, deniedType: String?, selfAllowed: Boolean = false): String {
        val id = raw.takeIf { WireGrammar.isUuid(it) }
        if (id == null || c.queryOne("SELECT 1 FROM users WHERE userId=?", id) { 1 } == null) {
            deniedType?.let { s.audit.denied(c, it, op.userId, op.deviceId, ip) }
            badRequest(WireErrors.NO_SUCH_USER)
        }
        if (!selfAllowed && id == op.userId) badRequest(WireErrors.CANNOT_TARGET_SELF)
        return id
    }

    /**
     * Every account's row with its meters (§7.1, §14.4): the meters are [QuotaUses.of], the very function `GET /sync`
     * answers the account itself with, and `usedBytes`/`itemCount` are read from them, so the three never disagree.
     *
     * **One short hold of the database lock per account, not one for the whole list** (the server's
     * cost of the meters). The meters are aggregates over each account's items; measured on this build, one hold for the
     * whole list was about 310 ms for 300 accounts of 300 items and about 850 ms at 1,000 items each, and every other
     * request waited for it. Now the ids are read in one short hold and each row in a hold of its own (a few ms), so a
     * request waits at most one account. Each row is consistent in itself; the list is not one snapshot, and an account
     * deleted while the list is read is left out.
     */
    fun summaries(s: Services, nowMs: Long): List<AccountSummary> {
        val policy = s.policy.get()
        val ids = s.db.read { c -> c.queryAll("SELECT userId FROM users ORDER BY createdAt, userId") { it.getString(1) } }
        return ids.mapNotNull { id ->
            s.raceHook?.invoke("accounts.betweenRows")
            s.db.read { c -> summary(s, c, id, nowMs, policy) }
        }
    }

    /** One account's row, read inside [c]; null when the account no longer exists. */
    private fun summary(s: Services, c: Connection, id: String, nowMs: Long, policy: io.silencelen.andvari.core.model.wire.AdminPolicy): AccountSummary? {
        val r = c.queryOne("SELECT userId,email,displayName,role,status,createdAt,disabledAt,recovery FROM users WHERE userId=?", id) { rs ->
            listOf(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getLong(6), rs.longOrNull("disabledAt"), rs.getString(8))
        } ?: return null
        val quota = QuotaUses.of(s, c, id, nowMs, policy)
        return AccountSummary(
                userId = id, email = r[1] as String, displayName = r[2] as String, role = r[3] as String, status = r[4] as String,
                createdAt = r[5] as Long,
                lastSeenAt = c.queryOne("SELECT MAX(lastSeenAt) FROM devices WHERE userId=?", id) { it.longOrNull("MAX(lastSeenAt)") },
                disabledAt = r[6] as Long?, recovery = r[7] as String,
                usedBytes = quota.accountBytes.used, itemCount = quota.items.used,
                ownedVaultCount = c.count(
                    "SELECT COUNT(*) FROM grants g JOIN vaults v ON v.vaultId=g.vaultId WHERE g.userId=? AND g.role='owner' AND g.revokedAt IS NULL AND v.purgedAt IS NULL", id,
                ),
                liveDeviceCount = deviceList(c, id, nowMs, null).count { it.live }.toLong(),
                quota = quota,
            )
    }
}

/**
 * `GET /admin/status`'s answer with `auditKinds` added (spec 03 §7.3; additive): every kind of audit row this server can
 * write ([AuditKinds.ALL], sorted), so the operator's consoles filter and word the audit list by the server's own list.
 * A constant: it costs the status nothing, and it names no account.
 */
fun statusWithAuditKinds(statusJson: String): String {
    val tree = WireJson.json.parseToJsonElement(statusJson) as JsonObject
    val kinds = kotlinx.serialization.json.JsonArray(AuditKinds.ALL.map { kotlinx.serialization.json.JsonPrimitive(it) })
    return JsonObject(tree + ("auditKinds" to kinds)).toString()
}

/**
 * [row] with the stored copy's recovery-key fingerprint added as its last key [name] (spec 03 §18.6), or as it is when
 * the account has no copy ([fp] null): the key is left out, never sent as null.
 */
fun withEscrowFingerprint(row: JsonObject, name: String, fp: String?): JsonObject =
    if (fp == null) row else JsonObject(row + (name to kotlinx.serialization.json.JsonPrimitive(fp)))

/**
 * The details of an `operator_device_revoke` row (spec 03 §7.1): `target=<the removed device's account>,by=<the
 * operator's own device>`. The row's userId is the operator and its deviceId the removed device; rows written before
 * 2026-11-17 carry `target=` alone and read the same way.
 */
internal fun operatorRevokeMeta(ownerUserId: String, operatorDeviceId: String) = "target=$ownerUserId,by=$operatorDeviceId"

/** The operator's own device in an `operator_device_revoke` row's details, or null for an older row without it. */
internal fun operatorRevokeBy(meta: String?): String? = meta?.let { Regex(",by=([0-9a-f-]{36})(?:,|$)").find(it)?.groupValues?.get(1) }

fun Route.operatorRoutes(s: Services) {
    /** `GET /admin/accounts` (§7.1): each `AccountSummary` with its `quota` added as the row's last key. */
    api(WireRoute.ADMIN_ACCOUNTS, s) {
        val nowMs = now
        val rows = OperatorRules.summaries(s, nowMs)
        respondJsonText(QuotaUses.accountsJson(rows))
    }

    /**
     * `POST /admin/accounts/{userId}/disable` (spec 03 §7.1), operator†: sessions revoked, sockets get
     * `revoked`, `account_disabled` with the reason category. A disabled account changes nothing.
     */
    api(WireRoute.ADMIN_ACCOUNT_DISABLE, s) {
        val req = body<AccountDisableRequest>()
        reauth(req.currentAuthKey)
        if (req.reason !in setOf(DisableReason.ABUSE, DisableReason.REQUEST, DisableReason.OTHER)) badRequest(WireErrors.badField("reason"))
        val op = p
        s.db.tx { c ->
            val id = OperatorRules.target(s, c, param("userId"), op, ip, "operator_disable_denied")
            Accounts(s).disable(c, id, req.reason, op.deviceId, ip)
        }
        ok()
    }

    /** `POST /admin/accounts/{userId}/enable` (spec 03 §7.1), operator†: ignores the cap (design S3-Q7). */
    api(WireRoute.ADMIN_ACCOUNT_ENABLE, s) {
        val req = body<ReauthRequest>()
        reauth(req.currentAuthKey)
        val op = p
        s.db.tx { c ->
            val id = OperatorRules.target(s, c, param("userId"), op, ip, null, selfAllowed = true)
            Accounts(s).enable(c, id, op.deviceId, ip)
        }
        ok()
    }

    /**
     * `POST /admin/accounts/{userId}/delete` (spec 03 §7.1, W2), operator†: only an account disabled for 30
     * days (`409 not_disabled_long_enough {disabledAt}`), not while it owns a shared vault with members. The
     * account-deletion transaction WITHOUT leaves: its grants go server-side and it stays in those logs'
     * members. `account_deleted_by_operator` goes to the address captured in the transaction.
     *
     * The one exception (owner policy 2026-11-15): `reason: "under_minimum_age"` lifts the 30 days, not the
     * disable. The account must still be disabled (the policy's "with an email first" is the disable's
     * notice, and the deletion email names the disable's date), the blockers, the reauth and the buckets stay,
     * and the reason is a closed value: any other value is `400 bad_reason` and unlocks nothing. The
     * operator's `operator_delete` row carries `reason=under_minimum_age`; it is the operator's row, so it
     * outlives the account.
     */
    api(WireRoute.ADMIN_ACCOUNT_DELETE, s) {
        val req = body<OperatorDeleteRequest>()
        val underAge = when (req.reason) {
            null -> false
            OperatorDeleteRequest.UNDER_MINIMUM_AGE -> true
            else -> badRequest(WireErrors.badField("reason"))
        }
        reauth(req.currentAuthKey)
        val op = p
        val nowMs = now
        var target = ""
        val out = s.db.tx { c ->
            val id = OperatorRules.target(s, c, param("userId"), op, ip, "operator_delete_denied")
            target = id
            val (email, disabledAt, pub) = c.queryOne("SELECT email,disabledAt,identityPub FROM users WHERE userId=?", id) {
                Triple(it.getString(1), it.longOrNull("disabledAt"), it.getString(3))
            }!!
            if (disabledAt == null || (!underAge && nowMs - disabledAt < OperatorRules.DELETE_AFTER_DISABLED_MS)) notDisabledLongEnough(disabledAt)
            val blockers = AccountDeletion.blockers(c, id)
            if (blockers.isNotEmpty()) accountDeleteBlocked(blockers)
            val o = AccountDeletion.deleteRows(s, c, id, null, ip, nowMs)
            val meta = if (underAge) "target=${o.pseudonym},reason=${OperatorDeleteRequest.UNDER_MINIMUM_AGE}" else "target=${o.pseudonym}"
            s.audit.on(c, "operator_delete", op.userId, op.deviceId, ip, meta)
            s.mail.enqueue(c, "account_deleted_by_operator", email, Mail.Ctx(Mail.accountId(pub), nowMs, mapOf("disabledSince" to Mail.utc(disabledAt))))
            o
        }
        finishDeletion(s, target, out)
        respond(DeletedAtResponse(nowMs))
    }

    /** `GET /admin/accounts/{userId}/devices[?after=<deviceId>]` (spec 03 §7.1): one page, `live` derived, `current` absent. */
    api(WireRoute.ADMIN_ACCOUNT_DEVICES, s) {
        val op = p
        val after = devicePageAfter()
        val rows = s.db.tx { c ->
            val id = OperatorRules.target(s, c, param("userId"), op, ip, null, selfAllowed = true)
            deviceList(c, id, now, null, DEVICE_PAGE_ROWS, after)
        }
        respondList(Device.serializer(), rows)
    }

    /**
     * `POST /admin/devices/{deviceId}/revoke` (spec 03 §7.1), operator†: sessions revoked, the secret hash
     * cleared, sockets closed, `device_removed` naming the operator. Unknown: `404 no_such_device`, audited
     * `device_revoke_denied` with no deviceId.
     */
    api(WireRoute.ADMIN_DEVICE_REVOKE, s) {
        val req = body<ReauthRequest>()
        reauth(req.currentAuthKey)
        val op = p
        s.db.tx { c ->
            val target = param("deviceId").takeIf { WireGrammar.isUuid(it) }
            val owner = target?.let { t -> c.queryOne("SELECT userId FROM devices WHERE deviceId=?", t) { it.getString(1) } }
            if (owner == null) {
                s.audit.denied(c, "device_revoke_denied", op.userId, null, ip)
                notFound(WireErrors.NO_SUCH_DEVICE)
            }
            s.sessions.revokeDevice(c, target!!)
            // userId = the operator, deviceId = the removed device (as before), meta = the account it belonged to and,
            // since 2026-11-17, the operator's own device, so that every record of a removal says who did it and from
            // which device. Older rows carry `target=` alone.
            s.audit.on(c, "operator_device_revoke", op.userId, target, ip, operatorRevokeMeta(owner, op.deviceId))
            notify(s, c, owner, "device_removed", vars = mapOf("removed" to (MailDevices.of(c, target) ?: "a device"), "by" to "the operator"))
            afterCommit(c) {
                s.forgetDeviceCounters(listOf(target))
                s.notifier.notifyRevokedDevice(owner, target)
            }
        }
        ok()
    }

    /**
     * `PUT /admin/accounts/{userId}/quota` (spec 03 §7.1), operator†: each limit a REQUIRED key whose value is
     * an `int` or `null` (`null` returns it to the default); a missing key is `400 bad_request`.
     */
    api(WireRoute.ADMIN_QUOTA, s) {
        val obj = jsonBody() as? JsonObject ?: badRequest(WireErrors.BAD_REQUEST)
        val keys = listOf("accountBytes", "items", "ownedSharedVaults", "openLinks")
        if (!obj.keys.containsAll(keys + "currentAuthKey")) badRequest(WireErrors.BAD_REQUEST)
        val key = runCatching { obj["currentAuthKey"]!!.jsonPrimitive.content }.getOrNull() ?: badRequest(WireErrors.BAD_REQUEST)
        val values = keys.map { k ->
            val e = obj[k]
            if (e == null || e is JsonNull) null
            else WireGrammar.intOf(e) ?: badRequest(WireErrors.badField(k))
        }
        reauth(key)
        val op = p
        val q = s.db.tx { c ->
            val id = OperatorRules.target(s, c, param("userId"), op, ip, null, selfAllowed = true)
            c.exec(
                "UPDATE users SET quotaAccountBytes=?, quotaItems=?, quotaOwnedSharedVaults=?, quotaOpenLinks=? WHERE userId=?",
                values[0], values[1], values[2], values[3], id,
            )
            s.audit.on(c, "operator_quota", op.userId, op.deviceId, ip, "target=$id")
            s.policy.quotaOf(c, id)
        }
        respond(Quota.serializer(), q)
    }

    /**
     * `GET /admin/policy` (spec 03 §7.2): the stored policy; `signup` values are null when nothing is stored. Its
     * `kdfParams` is the cost in force ([PolicyStore.servedKdf]: the stored one raised to the floor), the one the clients
     * are served, so a console that sends the policy back with one field changed is not refused as `kdf_too_weak` after
     * the floor was raised above the stored cost.
     */
    api(WireRoute.ADMIN_POLICY_GET, s) {
        val stored = s.db.read { c -> s.policy.load(c) }
        respond(AdminPolicy.serializer(), stored.copy(kdfParams = s.policy.servedKdf(stored)))
    }

    /**
     * `PUT /admin/policy` (spec 03 §7.2), operator†. The fields in body order ([PolicyBounds.check]: the
     * first failing field names the `400 bad_<field>`); `signup` can only TIGHTEN against the current
     * effective values (`400 not_tighter`, nothing stored); `null` leaves a stored sign-up value unchanged.
     */
    api(WireRoute.ADMIN_POLICY_PUT, s) {
        val req = body<AdminPolicyPut>()
        reauth(req.currentAuthKey)
        PolicyBounds.check(s, req)
        val op = p
        val stored = s.db.tx { c ->
            val current = s.policy.load(c)
            val mode = req.signup.mode?.also { m -> if (s.policy.stricterMode(m, s.policy.effectiveMode(current)) != m) badRequest(WireErrors.NOT_TIGHTER) } ?: current.signup.mode
            val cap = req.signup.cap?.also { cap -> if (cap < 0 || cap > s.policy.effectiveCap(current)) badRequest(WireErrors.NOT_TIGHTER) } ?: current.signup.cap
            val p = req.policy().copy(signup = AdminSignupPolicy(mode, cap))
            s.policy.storeOn(c, p)
            s.audit.on(c, "operator_policy", op.userId, op.deviceId, ip)
            p
        }
        respond(AdminPolicy.serializer(), stored)
    }

    /** `GET /admin/audit?since=&type=&userId=` (spec 03 §7.3): newest first, ids only. */
    api(WireRoute.ADMIN_AUDIT, s) {
        val since = query("since")?.let { parseInt(it) ?: badRequest(WireErrors.badField("since")) }
        // A malformed type is refused, not ignored (before, it was dropped and every type came back unasked).
        val type = query("type")?.let { t -> t.takeIf { it.isNotEmpty() && it.length <= 64 && it.all { ch -> ch in 'a'..'z' || ch == '_' } } ?: badRequest(WireErrors.badField("type")) }
        val userId = query("userId")?.let { Grammar.requireUuid(it, "userId") }
        // The page cursor (spec 03 §7.3): the `id` of the previous page's last row; the next page is the rows older than it.
        val after = query("after")?.let { a -> parseInt(a)?.takeIf { it > 0 } ?: badRequest(WireErrors.BAD_REQUEST) }
        respondList(AuditRow.serializer(), s.db.read { c -> s.audit.query(c, since, type, userId, OperatorRules.AUDIT_PAGE, after) })
    }

    /** `GET /admin/status` (spec 03 §7.3). */
    api(WireRoute.ADMIN_STATUS, s) {
        val st = s.db.read { c ->
            val p = s.policy.load(c)
            val (attCount, attBytes) = s.attachments.stats(c)
            AdminStatus(
                serverVersion = SERVER_VERSION, serverTime = now, userCount = c.count("SELECT COUNT(*) FROM users"),
                itemCount = c.count("SELECT COUNT(*) FROM items WHERE deleted=0"), attachmentCount = attCount, attachmentBytes = attBytes,
                dbBytes = File(s.config.dbPath).length(), totpEnrolledCount = c.count("SELECT COUNT(*) FROM users WHERE totpSecret IS NOT NULL"),
                downloadsManifest = s.config.downloadsDir?.let { File(it, "manifest.json").isFile } ?: false,
                emailConfigured = s.config.mailConfigured, instanceKind = s.config.instanceKind,
                signup = AdminSignupStatus(s.policy.effectiveMode(p), s.policy.effectiveCap(p), s.policy.activeMembers(c), s.policy.signupFull(c, p)),
                mail = AdminMailStatus(s.mail.stalled(c), s.mail.oldestQueuedAt(c)),
            )
        }
        respondJsonText(statusWithAuditKinds(WireJson.json.encodeToString(AdminStatus.serializer(), st)))
    }

    /**
     * `GET /admin/recovery-requests` (spec 03 §18.6), **R**: verified, live requests. Never the request code. Each row
     * also carries `escrowFingerprint` (additive): the recovery-key fingerprint the account's stored copy names, as
     * the server has it, absent when the account has no copy. It is the server's word: a console uses it only to say
     * that the copy is sealed to an outgoing recovery key, so that both sheets are needed, and never as a key.
     */
    api(WireRoute.ADMIN_RECOVERY_REQUESTS, s) {
        val fps = HashMap<String, String?>()
        val rows = s.db.read { c ->
            // spec 03 §18.6: `ready` (an answer stored, not yet committed) is listed too, so the operator can upload again.
            c.queryAll("SELECT requestId FROM recovery_requests WHERE state IN ('verified','fulfilled') AND userId IS NOT NULL") { it.getString(1) }
                .mapNotNull { Assisted.row(c, it) }
                .filter { Assisted.stateOf(it, now) in setOf(RecoveryRequestState.HOLDING, RecoveryRequestState.AWAITING_OPERATOR, RecoveryRequestState.READY) }
                .map { r ->
                    val (email, pub) = c.queryOne("SELECT email,identityPub FROM users WHERE userId=?", r.account) { it.getString(1) to it.getString(2) }!!
                    fps[r.requestId] = c.queryOne("SELECT fingerprint FROM escrow WHERE userId=?", r.account) { it.getString(1) }
                    AdminRecoveryRequest(r.requestId, r.account, email, Mail.accountId(pub), r.rPub, r.platform, r.createdAt, r.verifiedAt!!, r.holdEndsAt!!,
                        Assisted.stateOf(r, now))
                }
        }
        val list = WireJson.json.encodeToJsonElement(kotlinx.serialization.builtins.ListSerializer(AdminRecoveryRequest.serializer()), rows) as kotlinx.serialization.json.JsonArray
        respondJsonText(kotlinx.serialization.json.JsonArray(list.mapIndexed { i, row -> withEscrowFingerprint(row as JsonObject, "escrowFingerprint", fps[rows[i].requestId]) }).toString())
    }

    /**
     * `POST /admin/accounts/{userId}/escrow` (spec 03 §18.6), operator†, **R**: an operator-posture account's
     * escrow (`404 no_escrow` otherwise). Sends `operator_escrow_read`. Audited. The answer also carries
     * `fingerprint` (additive): the recovery-key fingerprint the copy was stored under, the server's word, as on the
     * request rows.
     */
    api(WireRoute.ADMIN_ESCROW, s) {
        val req = body<ReauthRequest>()
        reauth(req.currentAuthKey)
        val op = p
        val resp = s.db.tx { c ->
            // No row for an account that does not exist: nothing was handed out, so the call is a
            // plain refusal, `400 no_such_user`, like any read. Before, it wrote an `operator_escrow_read` row.
            val id = OperatorRules.target(s, c, param("userId"), op, ip, deniedType = null, selfAllowed = true)
            val (sealed, fp) = c.queryOne("SELECT sealed,fingerprint FROM escrow WHERE userId=?", id) { it.getString(1) to it.getString(2) } ?: notFound(WireErrors.NO_ESCROW)
            val (seed, pub) = c.queryOne("SELECT encryptedIdentitySeed,identityPub FROM users WHERE userId=?", id) { it.getString(1) to it.getString(2) }!!
            s.audit.on(c, "operator_escrow_read", op.userId, op.deviceId, ip, "target=$id")
            notify(s, c, id, "operator_escrow_read")
            AdminEscrowResponse(id, sealed, seed, pub) to fp
        }
        val tree = WireJson.json.encodeToJsonElement(AdminEscrowResponse.serializer(), resp.first) as JsonObject
        respondJsonText(withEscrowFingerprint(tree, "fingerprint", resp.second).toString())
    }

    /**
     * `POST /admin/recovery-requests/{requestId}/fulfil` (spec 03 §18.6), operator†, **R**: the sealed 0x09
     * answer (at most 1 KiB decoded) for a verified request past its hold and not vetoed (`409 request_state`).
     */
    api(WireRoute.ADMIN_RECOVERY_FULFIL, s) {
        // The tree, so that a part that is absent, null or not a string gets that part's own refusal (spec 03 §18.6).
        val tree = jsonBody() as? JsonObject ?: badRequest(WireErrors.BAD_REQUEST)
        fun text(name: String): String? = (tree[name] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
        reauth(text("currentAuthKey") ?: badRequest(WireErrors.BAD_REQUEST))
        // The body's shape, before anything stored is read (spec 03 §18.6, the † rule of §0.2), in this order.
        val sealed = text("sealed") ?: badRequest(WireErrors.badField("sealed"))
        val sealedBytes = Grammar.b64Bytes(sealed, 1, Assisted.SEALED_MAX_BYTES)?.size ?: badRequest(WireErrors.badField("sealed"))
        val requestKey = text("requestKey")?.takeIf { WireGrammar.isB64_32(it) } ?: badRequest(WireErrors.badField("requestKey"))
        val commitHash = text("commitHash")?.takeIf { WireGrammar.isHex64(it) } ?: badRequest(WireErrors.badField("commitHash"))
        val requestId = Assisted.pathId(param("requestId"))
        val op = p
        s.db.tx { c ->
            val r = Assisted.row(c, requestId) ?: notFound(WireErrors.REQUEST_UNKNOWN)
            // Verified and past its hold, or fulfilled and not yet committed (an upload can be repeated).
            val st = Assisted.stateOf(r, now)
            val answerable = r.userId != null && ((r.state == "verified" && st == RecoveryRequestState.AWAITING_OPERATOR) ||
                (r.state == "fulfilled" && st == RecoveryRequestState.READY))
            if (!answerable) conflict(WireErrors.REQUEST_STATE)
            // An answer made for another request's key.
            if (requestKey != r.rPub) badRequest(WireErrors.REQUEST_KEY_MISMATCH)
            // Exactly the one size for this account's address: a cut or over-long answer, or one made for another address.
            val email = c.queryOne("SELECT email FROM users WHERE userId=?", r.account) { it.getString(1) } ?: conflict(WireErrors.REQUEST_STATE)
            if (sealedBytes != Assisted.answerBytes(email)) badRequest(WireErrors.badField("sealed"))
            val replaced = r.state == "fulfilled"
            c.exec("UPDATE recovery_requests SET state='fulfilled', sealed=?, commitHash=? WHERE requestId=?", sealed, commitHash, requestId)
            s.audit.on(c, "operator_recovery_fulfil", op.userId, op.deviceId, ip, "target=${r.userId}" + if (replaced) ";replaced=1" else "")
        }
        ok()
    }
}

