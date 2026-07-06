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
)

@Serializable
data class WireGrant(
    val vaultId: String,
    val userId: String,
    val role: String,
    val wrappedVk: String,
    val rev: Long,
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
)

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
