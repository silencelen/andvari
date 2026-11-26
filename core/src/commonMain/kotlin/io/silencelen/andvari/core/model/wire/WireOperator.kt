package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer

// =====================================================================================================
// Operator-assisted recovery (spec 03 §18). Every route here answers `404 not_found` on a public
// instance (variant R); clients never offer it when the pinned card's kind is `public`.
// =====================================================================================================

/** Assisted-recovery request states (spec 03 §18.4). */
object RecoveryRequestState {
    const val UNVERIFIED = "unverified"
    const val HOLDING = "holding"
    const val AWAITING_OPERATOR = "awaiting_operator"
    const val VETOED = "vetoed"
    const val EXPIRED = "expired"
    const val READY = "ready"
}

/**
 * `POST /recovery/requests` (spec 03 §18.1) → `202 {requestId}`. [rPub] `b64_32` (the device's fresh
 * X25519 key), [pollHash] `hex64` SHA-256 of the 32-byte poll secret, [platform] self-reported. [mailboxValue], optional
 * (decided on 2026-11-17): the value a code mail about a request carried, for a person whose own requests are used up by
 * someone else; absent when none was given (the encoder leaves a null out). The answer is the same with or without it.
 */
@Serializable
data class RecoveryRequestCreate(val email: String, val rPub: String, val pollHash: String, val platform: String, val mailboxValue: String? = null)

/** `202 {requestId}` (`b64_16`), uniform for every address. */
@Serializable
data class RecoveryRequestCreated(val requestId: String)

/** `POST /recovery/requests/{requestId}/verify` (spec 03 §18.2): the emailed 6-digit code. */
@Serializable
data class RecoveryRequestVerify(val code: String)

/** `200 {state: "holding", holdEndsAt}`. */
@Serializable
data class RecoveryRequestVerified(val state: String, val holdEndsAt: Long)

/**
 * `GET /account/recovery-requests` (spec 03 §18.3): the account's live requests. [state] is `holding` or
 * `awaiting_operator`; [platform] is self-reported and shown as such.
 */
@Serializable
data class RecoveryRequestSummary(
    val requestId: String,
    val state: String,
    val createdAt: Long,
    val verifiedAt: Long,
    val holdEndsAt: Long,
    val platform: String,
)

/** `POST /recovery/requests/{requestId}/veto` (spec 03 §18.3), with the device's session: [statement] a 0x0A `frame`. */
@Serializable
data class RecoveryVetoRequest(val statement: String)

/** `POST /recovery/requests/{requestId}/poll` (spec 03 §18.4): the secret travels in the body, never the URL. */
@Serializable
data class RecoveryPollRequest(val pollSecret: String)

/**
 * The poll's answer (spec 03 §18.4): before fulfilment `{state, holdEndsAt?}`; once fulfilled
 * `{state: "ready", sealed, encryptedIdentitySeed, identityPub}`.
 *
 * The app opens [sealed] with its request key and requires the 0x09 frame, a signer that maps to the
 * recovery key the PINNED card's `recoveryFp` names, matching `instanceId`/`userId`/`requestId`/
 * `requestKey`, and the identity seed opening under the UVK to [identityPub] (design §9.3 step 4).
 */
@Serializable
data class RecoveryPollResponse(
    val state: String,
    val holdEndsAt: Long? = null,
    /** `sealed` 0x09 statement */
    val sealed: String? = null,
    val encryptedIdentitySeed: String? = null,
    val identityPub: String? = null,
    /**
     * With `ready`: the `hex64` hash of the commit value the stored answer was uploaded with (spec 03 §18.6). A device
     * compares it with the hash of the value inside the answer it opened before it asks the person anything. Absent from
     * a server that does not send it.
     */
    val commitHash: String? = null,
)

/**
 * `POST /recovery/requests/{requestId}/commit` (spec 03 §18.5) → [SessionResponse] with
 * `recoveryPieceId`. [newMemberRecovery] nullable for `400 recovery_required`.
 */
@Serializable
data class RecoveryRequestCommit(
    val pollSecret: String,
    val newAuthKey: String,
    val newKdfSalt: String,
    val newKdfParams: KdfParams,
    val newWrappedUvk: String,
    val newMemberRecovery: MemberRecoveryBlock? = null,
    val device: NewDevice,
    /**
     * The commit value from the version-3 answer this device opened (spec 03 §18.5): a
     * `b64_32`. Nullable only for the precise `400 bad_commit` of a body without it.
     */
    val commit: String? = null,
)

// =====================================================================================================
// Operator (spec 03 §7, §18.6). Operator routes refuse a web-minted session (`operator_web_refused`).
// =====================================================================================================

/** `GET /admin/accounts` (spec 03 §7.1): one per account. */
@Serializable
data class AccountSummary(
    val userId: String,
    val email: String,
    val displayName: String,
    /** [AccountRole] value */
    val role: String,
    /** [AccountStatus] value */
    val status: String,
    val createdAt: Long,
    val lastSeenAt: Long?,
    val disabledAt: Long? = null,
    /** [RecoveryPosture] value: the server's mirror */
    val recovery: String,
    val usedBytes: Long,
    val itemCount: Long,
    val ownedVaultCount: Long,
    val liveDeviceCount: Long,
    /**
     * This account's own meters (spec 03 §7.1, §14.4; added 2026-11-16, additive): the object its own `GET /sync`
     * carries. [usedBytes] and [itemCount] equal `quota.accountBytes.used` and `quota.items.used` on an honest server.
     * Null from an older server, or when the object cannot be one ([QuotaUseOrUnknown]).
     */
    @Serializable(with = QuotaUseOrUnknown::class)
    val quota: QuotaUse? = null,
)

/** Account statuses (spec 03 §7.1). */
object AccountStatus {
    const val ACTIVE = "active"
    const val DISABLED = "disabled"
}

/** `POST /admin/accounts/{userId}/disable` (spec 03 §7.1): [reason] a [DisableReason] value. */
@Serializable
data class AccountDisableRequest(val reason: String, val currentAuthKey: String)

/** `AccountDisableRequest.reason` values. */
object DisableReason {
    const val ABUSE = "abuse"
    const val REQUEST = "request"
    const val OTHER = "other"
}

/**
 * `POST /admin/accounts/{userId}/delete { currentAuthKey, reason? }` (spec 03 §7.1). [reason] is absent (the
 * 30-day rule) or [OperatorDeleteReason.UNDER_MINIMUM_AGE]; any other value is `400 bad_reason`. With no reason
 * the body is byte-for-byte a [ReauthRequest]'s (`encodeDefaults = false` leaves the null out).
 */
@Serializable
data class OperatorDeleteRequest(
    /** `b64`: a fresh master-password proof (spec 03 §0.1). */
    val currentAuthKey: String,
    val reason: String? = null,
)

/** `OperatorDeleteRequest.reason` values: a closed set of one. */
object OperatorDeleteReason {
    /** The account holder is under the minimum age: lifts the 30-day wait for a disabled account, and nothing else. */
    const val UNDER_MINIMUM_AGE = "under_minimum_age"
}

/**
 * `PUT /admin/accounts/{userId}/quota` (spec 03 §7.1): each limit an `int` or `null` (null returns it
 * to the instance default). The keys are always present.
 */
@Serializable
data class QuotaPut(
    val accountBytes: Long?,
    val items: Long?,
    val ownedSharedVaults: Long?,
    val openLinks: Long?,
    val currentAuthKey: String,
)

/** An account's effective quota, and `AdminPolicy.quotaDefaults` (spec 03 §7.1, §14.4). */
@Serializable
data class Quota(val accountBytes: Long, val items: Long, val ownedSharedVaults: Long, val openLinks: Long)

/**
 * `GET /admin/policy`, and the answer of `PUT /admin/policy` (spec 03 §7.2). [signup] holds the
 * operator's STORED tightening; `null` in either field stores nothing (the environment's value rules).
 */
@Serializable
data class AdminPolicy(
    val minVersion: Map<String, String>,
    val kdfParams: KdfParams,
    val autoLockSeconds: Long,
    val clipboardClearSeconds: Long,
    val offlineCacheAllowed: Boolean,
    val sessionAccessTtlSeconds: Long,
    val sessionRefreshTtlDays: Long,
    val attachmentMaxBytes: Long,
    val itemAttachmentsMaxBytes: Long,
    val quotaDefaults: Quota,
    val signup: AdminSignupPolicy,
)

/** `AdminPolicy.signup` (spec 03 §7.2): tighten-only. A value not at least as strict as the current effective one is `400 not_tighter`; `null` on a PUT leaves the stored value unchanged. */
@Serializable
data class AdminSignupPolicy(val mode: String?, val cap: Long?)

/** `PUT /admin/policy` (spec 03 §7.2): an [AdminPolicy] plus `currentAuthKey`, flat in one object. */
@Serializable
data class AdminPolicyPut(
    val minVersion: Map<String, String>,
    val kdfParams: KdfParams,
    val autoLockSeconds: Long,
    val clipboardClearSeconds: Long,
    val offlineCacheAllowed: Boolean,
    val sessionAccessTtlSeconds: Long,
    val sessionRefreshTtlDays: Long,
    val attachmentMaxBytes: Long,
    val itemAttachmentsMaxBytes: Long,
    val quotaDefaults: Quota,
    val signup: AdminSignupPolicy,
    val currentAuthKey: String,
) {
    fun policy(): AdminPolicy = AdminPolicy(
        minVersion, kdfParams, autoLockSeconds, clipboardClearSeconds, offlineCacheAllowed,
        sessionAccessTtlSeconds, sessionRefreshTtlDays, attachmentMaxBytes, itemAttachmentsMaxBytes,
        quotaDefaults, signup,
    )

    companion object {
        fun of(p: AdminPolicy, currentAuthKey: String) = AdminPolicyPut(
            p.minVersion, p.kdfParams, p.autoLockSeconds, p.clipboardClearSeconds, p.offlineCacheAllowed,
            p.sessionAccessTtlSeconds, p.sessionRefreshTtlDays, p.attachmentMaxBytes, p.itemAttachmentsMaxBytes,
            p.quotaDefaults, p.signup, currentAuthKey,
        )
    }
}

/** One audit row (spec 03 §7.3): ids only, never an email. */
@Serializable
data class AuditRow(
    val id: Long,
    val at: Long,
    val type: String,
    val userId: String? = null,
    val deviceId: String? = null,
    val ip: String? = null,
    val meta: String? = null,
)

/** `GET /admin/status` (spec 03 §7.3). */
@Serializable
data class AdminStatus(
    val serverVersion: String,
    val serverTime: Long,
    val userCount: Long,
    val itemCount: Long,
    val attachmentCount: Long,
    val attachmentBytes: Long,
    val dbBytes: Long,
    val totpEnrolledCount: Long,
    val downloadsManifest: Boolean,
    val emailConfigured: Boolean,
    /** [InstanceKind] value */
    val instanceKind: String,
    val signup: AdminSignupStatus,
    val mail: AdminMailStatus,
    /**
     * Every kind of audit row the server can write, sorted (spec 03 §7.3; added 2026-11-16, additive). A console filters
     * and words the audit list by it and keeps no list of its own; a kind it has no words for is shown as served, never
     * dropped. Null when an older server sent none, and when what it sent is not a list of strings ([KindsOrUnknown]):
     * the console then falls back to the kinds it has seen in rows.
     */
    @Serializable(with = KindsOrUnknown::class)
    val auditKinds: List<String>? = null,
)

/**
 * [AdminStatus.auditKinds]'s decoder: a JSON array of strings is the list; anything else (an array holding anything but
 * strings, an object, a string, a number, `null`) is null and never fails the status that carries it.
 */
object KindsOrUnknown : kotlinx.serialization.KSerializer<List<String>?> {
    private val plain = kotlinx.serialization.builtins.ListSerializer(String.serializer()).nullable

    override val descriptor: kotlinx.serialization.descriptors.SerialDescriptor = plain.descriptor

    override fun deserialize(decoder: kotlinx.serialization.encoding.Decoder): List<String>? {
        if (decoder !is kotlinx.serialization.json.JsonDecoder) return decoder.decodeSerializableValue(plain)
        val a = decoder.decodeJsonElement() as? kotlinx.serialization.json.JsonArray ?: return null
        return a.map { e -> (e as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content ?: return null }
    }

    override fun serialize(encoder: kotlinx.serialization.encoding.Encoder, value: List<String>?) {
        encoder.encodeSerializableValue(plain, value)
    }
}

/** `AdminStatus.signup`: the effective values and the number of accounts the cap counts. */
@Serializable
data class AdminSignupStatus(val mode: String, val cap: Long, val active: Long, val full: Boolean)

/** `AdminStatus.mail`: [stalled] drives the operator banner (§14.5). */
@Serializable
data class AdminMailStatus(val stalled: Boolean, val oldestQueuedAt: Long? = null)

/**
 * `GET /admin/recovery-requests` (spec 03 §18.6): verified, live requests. Never carries the request
 * code; [accountId] is the 32-hex short identity fingerprint as the server holds it; [platform] is
 * self-reported.
 */
@Serializable
data class AdminRecoveryRequest(
    val requestId: String,
    val userId: String,
    val email: String,
    val accountId: String,
    val rPub: String,
    val platform: String,
    val createdAt: Long,
    val verifiedAt: Long,
    val holdEndsAt: Long,
    /**
     * `holding`, `awaiting_operator` or `ready` (an answer stored, not yet committed, so it can be replaced; spec 03
     * §18.6). Additive: null from a server that does not send it.
     */
    val state: String? = null,
    /**
     * The `hex64` fingerprint of the recovery key the account's stored copy was stored under, as the server has it; absent
     * when the account has no copy (spec 03 §18.6, additive 2026-11-16). The server's word: used only to choose what a
     * console says, never as a key or a check of the copy. A present value that is not `hex64` fails the row's check.
     */
    val escrowFingerprint: String? = null,
)

/**
 * `POST /admin/accounts/{userId}/escrow` (spec 03 §18.6) → `{userId, sealed, encryptedIdentitySeed, identityPub}`, plus
 * the additive [fingerprint] (2026-11-16): the same value as [AdminRecoveryRequest.escrowFingerprint].
 */
@Serializable
data class AdminEscrowResponse(
    val userId: String,
    val sealed: String,
    val encryptedIdentitySeed: String,
    val identityPub: String,
    val fingerprint: String? = null,
)

/**
 * `POST /admin/recovery-requests/{requestId}/fulfil` (spec 03 §18.6): the three parts of the answer token as the shared
 * reader yields them ([io.silencelen.andvari.core.trust.AnswerToken]): the sealed version-3 0x09 statement, the request
 * key it was sealed to, and the hash of its commit value. The server refuses a [requestKey] that is not the row's and a
 * [sealed] of any other size than the one for the account's address. [requestKey] and [commitHash] are nullable only so
 * that a body without them gets its precise refusal (`400 bad_request_key`, `400 bad_commit_hash`).
 */
@Serializable
data class RecoveryFulfilRequest(val sealed: String, val currentAuthKey: String, val requestKey: String? = null, val commitHash: String? = null)
