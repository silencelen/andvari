package io.silencelen.andvari.core.model

import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.Serializable

/**
 * spec 03 wire DTOs — shared by the ktor server and the Kotlin clients (the web
 * client implements the same JSON shapes independently in TypeScript).
 * All binary fields are base64url unpadded strings (spec 00).
 */

@Serializable
data class ApiError(val error: String, val message: String)

// ---- auth ----

@Serializable
data class PreloginRequest(val email: String)

@Serializable
data class PreloginResponse(val kdfSalt: String, val kdfParams: KdfParams)

@Serializable
data class DeviceInfo(val platform: String, val name: String)

@Serializable
data class EscrowUpload(val sealed: String, val fingerprint: String)

@Serializable
data class PersonalVaultUpload(val vaultId: String, val wrappedVk: String, val metaBlob: String)

@Serializable
data class RegisterRequest(
    val inviteToken: String,
    val userId: String, // client-chosen UUID: keys are AD-bound to it (spec 02 §2), so the client must fix it at enrollment
    val email: String,
    val displayName: String,
    val kdfSalt: String,
    val kdfParams: KdfParams,
    val authKey: String,
    val wrappedUvk: String,
    val identityPub: String,
    val encryptedIdentitySeed: String,
    val escrow: EscrowUpload,
    val personalVault: PersonalVaultUpload,
    val device: DeviceInfo,
)

@Serializable
data class LoginRequest(
    val email: String,
    val authKey: String,
    val device: DeviceInfo,
    val totp: String? = null,
)

@Serializable
data class AccountKeys(
    val kdfSalt: String,
    val kdfParams: KdfParams,
    val wrappedUvk: String,
    val encryptedIdentitySeed: String,
    val identityPub: String,
    val escrowFingerprint: String,
    // F57: true when this account's escrow blob is sealed to a PRIOR org recovery key (a
    // re-ceremony happened) and must be re-sealed to the current key. `escrowFingerprint` is
    // the CURRENT org fingerprint (the re-seal target + pubkey-verification anchor). Additive,
    // defaulted false so older clients ignore it and a rollback server that omits it is safe.
    val escrowStale: Boolean = false,
)

@Serializable
data class SessionResponse(
    val userId: String,
    val deviceId: String,
    val accessToken: String,
    val refreshToken: String,
    val accountKeys: AccountKeys,
    val isAdmin: Boolean,
    val mustChangePassword: Boolean = false,
    val totpEnrolled: Boolean = false,
)

@Serializable
data class RefreshRequest(val refreshToken: String)

@Serializable
data class TokenPair(val accessToken: String, val refreshToken: String)

@Serializable
data class PasswordChangeRequest(
    val currentAuthKey: String,
    val newAuthKey: String,
    val newKdfSalt: String,
    val newKdfParams: KdfParams,
    val newWrappedUvk: String,
)

// ---- sync ----

@Serializable
data class WireVault(
    val vaultId: String,
    val type: String,
    val rev: Long,
    val metaBlob: String,
    val createdAt: Long,
    // Vault lifecycle (spec 03 §11) — additive; 0.2.x/0.4.0 clients ignore unknown keys.
    // Present while an ownership-transfer offer is pending / after the last completed one.
    val pendingTransfer: PendingTransfer? = null,
    val lastTransfer: TransferRecord? = null,
    // Restore consumption marker (spec 03 §11 / #4): on a live vault that WAS restored,
    // the deleteId that was consumed + the restoreProof over it. A client re-receiving the
    // restored vault verifies restore(VK, vaultId, deleteId) == restoreProof and durably
    // marks the deleteId consumed, so a later replayed old tombstone bearing it is rejected
    // as stale even by a device offline across the whole delete→restore cycle.
    val restoreProof: String? = null,
    val deleteId: String? = null,
)

/**
 * A pending ownership-transfer offer riding the vault row (spec 03 §11). Placing it on
 * the vault means any cancel/expiry/re-designate clears every stale banner via ordinary
 * row re-delivery. `proof` is the VK-derived offer MAC — the target's 0.5.0 client
 * verifies it BEFORE rendering consent; the server only stores and relays it.
 */
@Serializable
data class PendingTransfer(
    val toUserId: String,
    val offerId: String,
    val proof: String,
    val expiresAt: Long,
    val seq: Long,
)

/**
 * The last completed transfer (spec 03 §11): every member verifies the seq-chained
 * acceptProof under its held VK. The accept-proof domain binds hexLower(sha256(utf8(the
 * new owner's wrappedVk))), which other members never receive — so the server relays that
 * hash here (`wrapHash`) as hashing an opaque ciphertext blob is ZK-safe. It stays
 * consistent with acceptProof because the self-heal re-mints both together.
 */
@Serializable
data class TransferRecord(
    val offerId: String,
    val newOwnerUserId: String,
    val acceptProof: String,
    val seq: Long,
    val wrapHash: String? = null,
)

@Serializable
data class WireGrant(
    val vaultId: String,
    val userId: String,
    val role: String,
    val wrappedVk: String,
    val rev: Long,
    // Exactly one of wrappedVk (owner/personal, under UVK) or sealedVk (member,
    // crypto_box_seal to the member identityPub) is set (spec 01 §6). Additive: old
    // clients ignore it (Json ignoreUnknownKeys), and member grants carry wrappedVk="".
    val sealedVk: String? = null,
)

@Serializable
data class WireItem(
    val itemId: String,
    val vaultId: String,
    val rev: Long,
    val createdAt: Long,
    val updatedAt: Long,
    val deleted: Boolean,
    val conflict: Boolean,
    val formatVersion: Int,
    val attachmentIds: List<String>,
    val blob: String?,
)

@Serializable
data class SyncResponse(
    val rev: Long,
    val full: Boolean,
    val vaults: List<WireVault>,
    val grants: List<WireGrant>,
    val items: List<WireItem>,
    val removedGrants: List<String>,
    // Additive companion detail for removedGrants (spec 03 §4/§11). removedGrants stays
    // the sole purge trigger for fielded clients; 0.5.0 clients use this for the
    // proof-verified notice/holding-area flow. Never the trigger itself.
    val removedGrantsInfo: List<RemovedGrantInfo> = emptyList(),
)

/**
 * Why the caller lost a grant (spec 03 §11). `reason` derives from the caller's OWN
 * grant's revokedReason: 'removed' | 'left' | 'deleted'. Tombstone fields ride along only
 * for reason='deleted'; removeProof/removeNonce only for reason='removed' when the removing
 * owner supplied a removal proof. (restoreProof is NOT delivered here — a revoked grant is
 * never live at the same instant a restore populates restoreProof; the consumed-deleteId
 * marker rides WireVault.restoreProof/deleteId on the live restored vault instead — #4.)
 */
@Serializable
data class RemovedGrantInfo(
    val vaultId: String,
    val reason: String,
    val deletedAt: Long? = null,
    val purgeAt: Long? = null,
    val deleteId: String? = null,
    val deleteProof: String? = null,
    val removeProof: String? = null,
    val removeNonce: String? = null,
)

// ---- shared vaults (spec 03 §10) ----

@Serializable
data class CreateVaultRequest(val vaultId: String, val metaBlob: String, val wrappedVk: String)

@Serializable
data class CreateVaultResponse(val rev: Long)

@Serializable
data class UserLookupRequest(val email: String)

@Serializable
data class UserLookupResponse(val userId: String, val displayName: String, val identityPub: String)

@Serializable
data class VaultMemberAdd(val userId: String, val role: String, val sealedVk: String)

@Serializable
data class VaultMemberRole(val role: String)

@Serializable
data class VaultMemberSummary(
    val userId: String,
    val email: String,
    val displayName: String,
    val role: String,
    val identityPub: String,
    val addedAt: Long,
    // F22 rider (spec 03 §10): account status ('active'|'disabled') — additive; feeds the
    // transfer target picker and the disabled-member badge.
    val status: String? = null,
)

// ---- vault lifecycle (spec 03 §11) ----

@Serializable
data class VaultDeleteRequest(val deleteId: String, val proof: String)

@Serializable
data class VaultDeleteResponse(val rev: Long, val purgeAt: Long)

@Serializable
data class VaultRestoreRequest(val deleteId: String, val proof: String)

/** One in-grace deleted vault of the caller's (owner-only; ciphertext they already owned). */
@Serializable
data class DeletedVaultSummary(
    val vaultId: String,
    val metaBlob: String,
    val wrappedVk: String,
    val deletedAt: Long,
    val purgeAt: Long,
    val deleteId: String,
)

@Serializable
data class TransferOfferRequest(val toUserId: String, val offerId: String, val expiresAt: Long, val proof: String)

@Serializable
data class TransferOfferResponse(val rev: Long, val expiresAt: Long)

@Serializable
data class TransferAcceptRequest(val offerId: String, val wrappedVk: String, val proof: String)

@Serializable
data class VaultMetaUpdateRequest(val metaBlob: String, val baseVaultRev: Long? = null)

/** Optional removal-proof body for the existing member-remove route (spec 03 §10). */
@Serializable
data class VaultMemberRemoveRequest(val proof: String? = null, val nonce: String? = null)

@Serializable
data class ItemUpload(
    val formatVersion: Int,
    val attachmentIds: List<String> = emptyList(),
    val blob: String,
)

@Serializable
data class Mutation(
    val mutationId: String,
    val op: String, // put | delete
    val itemId: String,
    val vaultId: String,
    val baseItemRev: Long,
    val item: ItemUpload? = null,
)

@Serializable
data class PushRequest(val mutations: List<Mutation>)

@Serializable
data class MutationResult(
    val mutationId: String,
    val status: String, // applied | conflict | duplicate | denied
    val newItemRev: Long? = null,
    val serverItem: WireItem? = null,
)

@Serializable
data class PushResponse(val rev: Long, val results: List<MutationResult>)

/**
 * One archived ciphertext version of an item (spec 02 §7 / feature: item history & restore). The
 * server keeps the last 10 per item and returns them newest-first from GET /items/{id}/versions.
 * `blob` is sealed under the vault VK with AD bound to (vaultId, itemId, formatVersion) — NOT rev —
 * so the client decrypts old versions with the key it already holds. No vault-identifying field:
 * the client supplies the vaultId (known from the live item) to decrypt.
 */
@Serializable
data class ItemVersion(
    val rev: Long,
    val blob: String,
    val formatVersion: Int,
    val archivedAt: Long,
)

@Serializable
data class ItemVersionsResponse(val itemId: String, val versions: List<ItemVersion>)

/**
 * Item undelete (feature): a tombstoned item the user can restore. A tombstone's blob is null, so
 * the name/preview lives in the item's last archived version (GET /items/{id}/versions). Restore
 * re-encrypts a chosen version and POSTs it to /items/{id}/restore (an ItemUpload body).
 */
@Serializable
data class DeletedItem(val itemId: String, val vaultId: String, val deletedAt: Long)

@Serializable
data class DeletedItemsResponse(val items: List<DeletedItem>)

@Serializable
data class ItemRestoreResponse(val rev: Long)

// ---- attachments (spec 02 §6) ----

/** Server bookkeeping for one encrypted attachment blob; filename + fileKey live inside item ciphertext. */
@Serializable
data class AttachmentMeta(
    val attachmentId: String,
    val itemId: String,
    val vaultId: String,
    val size: Long,
    val sha256: String,
    val createdAt: Long = 0,
)

// ---- server TOTP (spec 03 §2, break-glass hardening) ----

@Serializable
data class TotpSetupResponse(val secretBase32: String, val otpauthUri: String)

@Serializable
data class TotpCodeRequest(val code: String)

@Serializable
data class TotpStatus(val enrolled: Boolean, val pendingSetup: Boolean)

// ---- admin ----

@Serializable
data class AdminUserSummary(
    val userId: String,
    val email: String,
    val displayName: String,
    val isAdmin: Boolean,
    val status: String,
    val createdAt: Long,
    val deviceCount: Int,
    val escrowFingerprint: String?,
)

@Serializable
data class InviteRequest(val email: String, val isAdmin: Boolean = false)

@Serializable
data class InviteResponse(val inviteToken: String, val email: String, val expiresAt: Long)

@Serializable
data class RecoveryUpload(
    val userId: String,
    val tempAuthKey: String,
    val tempWrappedUvk: String,
    val tempKdfSalt: String,
    val tempKdfParams: KdfParams,
)

@Serializable
data class AdminDeviceSummary(
    val deviceId: String,
    val platform: String,
    val name: String,
    val clientVersion: String?,
    val createdAt: Long,
    val lastSeenAt: Long?,
    val revokedAt: Long?,
)

@Serializable
data class AdminStatus(
    val serverVersion: String,
    val serverTime: Long,
    val escrowConfigured: Boolean,
    val recoveryFingerprint: String,
    val breakGlassConfigured: Boolean,
    val lastPublicRequestAt: Long? = null,
    val userCount: Int,
    val itemCount: Int,
    val attachmentCount: Int,
    val attachmentBytes: Long,
    val dbBytes: Long,
    val totpEnrolledCount: Int,
    val downloadsManifest: Boolean,
)

@Serializable
data class AuditEvent(
    val id: Long,
    val at: Long,
    val type: String,
    val userId: String?,
    val deviceId: String?,
    val ip: String?,
    val meta: String?,
)

@Serializable
data class ClientPolicy(
    val minVersion: Map<String, String> = emptyMap(),
    val kdfParams: KdfParams = KdfParams(),
    val autoLockSeconds: Int = 300,
    val clipboardClearSeconds: Int = 30,
    val offlineCacheAllowed: Boolean = true,
    val sessionAccessTtlSeconds: Long = 3600,
    val sessionRefreshTtlDays: Long = 30,
    val recoveryFingerprint: String = "",
    val serverTime: Long = 0,
    // Attachment quotas (spec 02 §6) — plaintext byte limits, enforced server-side on ciphertext with overhead allowance.
    val attachmentMaxBytes: Long = 25L * 1024 * 1024,
    val itemAttachmentsMaxBytes: Long = 100L * 1024 * 1024,
    val userAttachmentsMaxBytes: Long = 1024L * 1024 * 1024,
)

/** Single-use WS auth ticket (spec 03 §6): minted over authenticated REST, ~30 s TTL. */
@Serializable
data class WsTicketResponse(val ticket: String, val expiresInSeconds: Long)
