package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable

// =====================================================================================================
// Account key material and state (spec 03 §3)
// =====================================================================================================

/**
 * `GET /account/keys`, and `SessionResponse.accountKeys` (spec 03 §3).
 *
 * - [recoveryConfirmed]: false ⇒ the client runs the vault-entry capture gate before vault access.
 * - [personalWrap]: set once at registration (design §5.3). Nullable because a server can withhold it;
 *   a withheld or unopenable wrap leaves "no personal vault" with the anomaly, never a guess.
 * - [genesis]: the 0x05 `frame` (spec 01 §5.4). Clients run its checks at EVERY unlock against the
 *   seed-derived key, the session's `userId`, the pinned card's `instanceId` and [personalWrap]'s
 *   vault (design §5.2). Nullable so that a missing genesis decodes and is refused by the engine as
 *   damaged key material (design §5.2, offline unlock) instead of failing the whole session decode.
 */
@Serializable
data class AccountKeys(
    /** `b64` */
    val kdfSalt: String,
    val kdfParams: KdfParams,
    /** `envelope` */
    val wrappedUvk: String,
    /** `envelope` */
    val encryptedIdentitySeed: String,
    /** `b64_32` (X25519). Never trusted until the seed-derived key equals it (spec 01 §5). */
    val identityPub: String,
    val recoveryConfirmed: Boolean,
    val personalWrap: PersonalWrap? = null,
    val genesis: String? = null,
)

/**
 * `GET /account/state` and the answer of `PUT /account/state` / `PUT /account/recovery` (spec 03 §3):
 * the one UVK-sealed document (`null` when never written) and the server's compare-and-set counter.
 *
 * [seq] is a CAS token only. The authenticated counter is the document's own in-blob `seq` (design §5.4,
 * FI-B14); a client never treats this [seq] as "newer" or "older".
 */
@Serializable
data class AccountStateResponse(
    /** `envelope` or null */
    val sealedState: String?,
    val seq: Long,
)

/** `PUT /account/state` (spec 03 §3): `409 stale_state` unless [baseSeq] equals the stored counter. */
@Serializable
data class AccountStatePut(val sealedState: String, val baseSeq: Long)

/** `PUT /account/password` (spec 03 §3), session†. The UVK is unchanged; only its wrap is replaced. */
@Serializable
data class PasswordChangeRequest(
    val currentAuthKey: String,
    val newAuthKey: String,
    val newKdfSalt: String,
    val newKdfParams: KdfParams,
    val newWrappedUvk: String,
)

/**
 * `PUT /account/recovery` (spec 03 §3.1), session†. [accountState] carries the account-state document
 * with the new `recovery` record, sealed by the client; the server stores it with the escrow change in
 * one transaction. [escrow] is present exactly when [posture] is `operator`.
 */
@Serializable
data class AccountRecoveryPut(
    /** [RecoveryPosture] value. */
    val posture: String,
    val escrow: EscrowUpload? = null,
    val currentAuthKey: String,
    val accountState: AccountStatePut,
)

/**
 * `PUT /escrow/self` (spec 03 §3.2), R. The re-seal after a signed rotation: [rotations] are 0x08
 * `frame`s, oldest first, from the current escrow's fingerprint to [fingerprint].
 */
@Serializable
data class EscrowSelfPut(
    /** `sealed` 0x02 escrow */
    val sealed: String,
    /** `hex64` */
    val fingerprint: String,
    val rotations: List<String>,
)

/** `GET /usage` (spec 03 §3). `null` means never written, never "nothing is used". [updatedAt] is the server clock. */
@Serializable
data class UsageResponse(val sealedUsage: String?, val updatedAt: Long)

/** `PUT /usage` (spec 03 §3). */
@Serializable
data class UsagePut(val sealedUsage: String)

// =====================================================================================================
// Devices (spec 03 §16.7, §16.8, §7.1)
// =====================================================================================================

/**
 * One device (spec 03 §16.7). [how] is a [DeviceHow] value. [current] marks the calling device; the
 * operator's listing (§7.1) does not list it, so it defaults to false. It is encoded also when false
 * (spec 03 §0.1 "Field presence": §16.7 lists it), so the operator's listing carries `current: false`
 * too, a field a client ignores where it does not take it. [live] is derived server-side.
 * [name] is plain text and is rendered only as plain text.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class Device(
    /** `uuid` */
    val deviceId: String,
    val platform: String,
    val name: String,
    val clientVersion: String?,
    val createdAt: Long,
    val lastSeenAt: Long?,
    val live: Boolean,
    val how: String,
    /** `uuid` of the linking device, for `how = linked`. */
    val linkedFrom: String? = null,
    @EncodeDefault val current: Boolean = false,
)

/** `Device.how` values (spec 03 §16.7). */
object DeviceHow {
    const val REGISTERED = "registered"
    const val PASSWORD = "password"
    const val LINKED = "linked"
    const val RECOVERED = "recovered"
}

/** `PUT /account/require-link` (spec 03 §16.8), session†. */
@Serializable
data class RequireLinkPut(val enabled: Boolean, val currentAuthKey: String)

// =====================================================================================================
// Account deletion (spec 03 §13)
// =====================================================================================================

/**
 * One reason the server refuses to delete the account (spec 03 §13). [kind] is a [DeleteBlockerKind]
 * value; a client MUST show a kind it does not know as a blocker it cannot explain and MUST NOT offer
 * to proceed past it.
 */
@Serializable
data class AccountDeleteBlocker(
    val kind: String,
    /** `uuid`, for `shared_vault`. */
    val vaultId: String? = null,
    val others: Int,
)

/** `AccountDeleteBlocker.kind` values (spec 03 §13). */
object DeleteBlockerKind {
    const val SHARED_VAULT = "shared_vault"
    const val OPERATOR = "operator"
}

/**
 * `GET /account/delete/preview` (spec 03 §13). [memberships] lists exactly the vaults that need a
 * leave, each with its stored head. A leave is built at that served head with
 * `at = max(device clock, head.at)`; from an unverified head a device refuses a `head.at` more than one
 * day ahead of its own clock (design §3.11, FS-R7).
 */
@Serializable
data class AccountDeletePreview(
    val blockers: List<AccountDeleteBlocker>,
    /** sorted `uuid`s */
    val deletedVaults: List<String>,
    /** sorted `uuid`s */
    val leftVaults: List<String>,
    val memberships: List<DeleteMembership>,
    val totpRequired: Boolean,
)

/** One vault that needs a leave (spec 03 §13): its id and stored log head `{seq, hash, at}`. */
@Serializable
data class DeleteMembership(val vaultId: String, val head: LogHead)

/** `POST /account/delete` (spec 03 §13). [leaves] are 0x03 `leave` `frame`s, one per preview membership, at most 500. */
@Serializable
data class AccountDeleteRequest(
    val confirmEmail: String,
    val currentAuthKey: String,
    val totp: String? = null,
    val leaves: List<String>,
)

/** `200 {deletedAt}` (`ms`): of self-deletion (§13) and of the operator's deletion (§7.1). */
@Serializable
data class DeletedAtResponse(val deletedAt: Long)

// =====================================================================================================
// Recovery with the kit (spec 03 §12)
// =====================================================================================================

/** `POST /recovery/self/verify` (spec 03 §12). Sent only after pinning the instance from the kit (design §10). */
@Serializable
data class RecoveryVerifyRequest(val email: String, val recoveryAuthKey: String)

/**
 * `POST /recovery/self/verify` → `200` (spec 03 §12). [userId] is what the client opens
 * [recoveryWrappedUvk] with (AD `andvari/v1|recovery-uvk|{userId}`) and runs the identity hard-fail
 * under (`andvari/v1|idkey|{userId}`); a substituted id cannot open the wrap.
 */
@Serializable
data class RecoveryVerifyResponse(
    val userId: String,
    val recoveryTicket: String,
    val recoveryWrappedUvk: String,
    val encryptedIdentitySeed: String,
    val identityPub: String,
)

/**
 * `POST /recovery/self/commit` (spec 03 §12) → [SessionResponse] with `recoveryPieceId`.
 * [newMemberRecovery] is nullable only so the server can answer `400 recovery_required`.
 */
@Serializable
data class RecoveryCommitRequest(
    val recoveryTicket: String,
    val newAuthKey: String,
    val newKdfSalt: String,
    val newKdfParams: KdfParams,
    val newWrappedUvk: String,
    val newMemberRecovery: MemberRecoveryBlock? = null,
    val device: NewDevice,
)

/** `PUT /recovery/self-setup` (spec 03 §12), session†. [memberRecovery] nullable for `400 recovery_required`. */
@Serializable
data class RecoverySelfSetupRequest(val currentAuthKey: String, val memberRecovery: MemberRecoveryBlock? = null)

/** `200 {pieceId}`: the opaque id of the piece this setup committed. */
@Serializable
data class RecoverySelfSetupResponse(val pieceId: String)

/** `POST /recovery/self/confirm` (spec 03 §12). An empty body parses as `pieceId = null`. */
@Serializable
data class RecoverySelfConfirmRequest(val pieceId: String? = null)
