package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.PersonalVaultUpload
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Item plaintext document (spec 02 §3) — shared client model. */
@kotlinx.serialization.Serializable
data class LoginData(
    val username: String? = null,
    val password: String? = null,
    val uris: List<String> = emptyList(),
    val totp: String? = null,
    val passwordHistory: List<PasswordHistoryEntry> = emptyList(),
)

@kotlinx.serialization.Serializable
data class PasswordHistoryEntry(val password: String, val retiredAt: Long)

/** Mirrors the plaintext attachment entry (spec 02 §3) — the SECRET half of attachmentIds. */
@kotlinx.serialization.Serializable
data class AttachmentRef(val id: String, val name: String, val size: Long, val fileKey: String)

@kotlinx.serialization.Serializable
data class ItemDoc(
    val type: String, // "login" | "note"
    val name: String,
    val notes: String? = null,
    val favorite: Boolean = false,
    val login: LoginData? = null,
    val attachments: List<AttachmentRef> = emptyList(),
)

/**
 * An unlocked account — the Kotlin sibling of web/src/vault/account.ts. Holds the
 * in-memory UVK + personal vault key and performs item AEAD (AD-bound to
 * userId/vaultId/itemId, spec 02 §2). Nothing here is persisted in the clear.
 * Native clients (Android/desktop) and the JVM tests share this exact logic.
 */
class Account private constructor(
    private val crypto: CryptoProvider,
    val userId: String,
    private val uvk: ByteArray,
    val identityPub: ByteArray,
    private val identityPriv: ByteArray,
    var personalVaultId: String,
    private val vaultKeys: MutableMap<String, ByteArray>,
    private val vaultRoles: MutableMap<String, String> = mutableMapOf(),
) {
    companion object {
        private const val ITEM_FORMAT_VERSION = 1
        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        fun deviceInfo(name: String): DeviceInfo = DeviceInfo("android", name)

        /** Derive the login authKey a fresh device sends after prelogin. */
        fun deriveAuthKey(password: String, kdfSaltB64: String, params: KdfParams, crypto: CryptoProvider = createCryptoProvider()): String {
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(kdfSaltB64), params)
            return Bytes.toB64(Keys.authKey(crypto, mk))
        }

        /** Enrollment: generate all keys, seal escrow, return the one-shot register request. */
        fun enroll(
            inviteToken: String,
            email: String,
            displayName: String,
            password: String,
            params: KdfParams,
            recoveryPublicKey: ByteArray,
            recoveryFingerprint: String,
            deviceName: String,
            crypto: CryptoProvider = createCryptoProvider(),
        ): Pair<RegisterRequest, Account> {
            val userId = uuid(crypto)
            val personalVaultId = uuid(crypto)
            val kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
            val mk = Keys.masterKey(crypto, password, kdfSalt, params)
            val authKey = Keys.authKey(crypto, mk)
            val wrapKey = Keys.wrapKey(crypto, mk)

            val uvk = crypto.randomBytes(32)
            val identitySeed = crypto.randomBytes(32)
            val identity = crypto.boxKeypairFromSeed(identitySeed)
            val vk = crypto.randomBytes(32)

            val computedFp = Escrow.fingerprint(crypto, recoveryPublicKey)
            if (computedFp != recoveryFingerprint) throw CryptoException("recovery public key does not match its fingerprint")

            val req = RegisterRequest(
                inviteToken = inviteToken,
                userId = userId,
                email = email,
                displayName = displayName,
                kdfSalt = Bytes.toB64(kdfSalt),
                kdfParams = params,
                authKey = Bytes.toB64(authKey),
                wrappedUvk = Envelope.sealB64(crypto, wrapKey, uvk, Ad.uvk(userId)),
                identityPub = Bytes.toB64(identity.publicKey),
                encryptedIdentitySeed = Envelope.sealB64(crypto, uvk, identitySeed, Ad.idkey(userId)),
                escrow = EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recoveryPublicKey, userId, uvk)), recoveryFingerprint),
                personalVault = PersonalVaultUpload(
                    vaultId = personalVaultId,
                    wrappedVk = Envelope.sealB64(crypto, uvk, vk, Ad.vk(personalVaultId, userId)),
                    metaBlob = Envelope.sealB64(crypto, vk, """{"name":"Personal"}""".encodeToByteArray(), Ad.vaultMeta(personalVaultId)),
                ),
                device = DeviceInfo("android", deviceName),
            )
            val account = Account(
                crypto, userId, uvk, identity.publicKey, identity.privateKey, personalVaultId,
                mutableMapOf(personalVaultId to vk), mutableMapOf(personalVaultId to "owner"),
            )
            return req to account
        }

        /** Unlock a device holding only the password + the server's account keys. */
        fun unlock(userId: String, password: String, keys: AccountKeys, crypto: CryptoProvider = createCryptoProvider()): Account {
            val mk = Keys.masterKey(crypto, password, Bytes.fromB64(keys.kdfSalt), keys.kdfParams)
            val wrapKey = Keys.wrapKey(crypto, mk)
            val uvk = try {
                Envelope.openB64(crypto, wrapKey, keys.wrappedUvk, Ad.uvk(userId))
            } catch (e: CryptoException) {
                throw CryptoException("wrong master password")
            }
            // The identity keypair is DERIVED from the UVK-sealed seed — which the server
            // cannot forge. Fingerprints and sealed-grant opening must use this derived
            // keypair, never a server-sent value; a mismatching server identityPub is a
            // pubkey-substitution attempt (spec 01 §5) and unlock hard-fails.
            val identitySeed = Envelope.openB64(crypto, uvk, keys.encryptedIdentitySeed, Ad.idkey(userId))
            val identity = crypto.boxKeypairFromSeed(identitySeed)
            if (!identity.publicKey.contentEquals(Bytes.fromB64(keys.identityPub))) {
                throw CryptoException(
                    "identity key mismatch — the server returned an identity public key that " +
                        "your account's sealed seed does not derive; possible server compromise. Do not proceed.",
                )
            }
            return Account(crypto, userId, uvk, identity.publicKey, identity.privateKey, "", mutableMapOf())
        }

        private fun uuid(crypto: CryptoProvider): String {
            // RFC 4122 v4 from 16 random bytes.
            val b = crypto.randomBytes(16)
            b[6] = ((b[6].toInt() and 0x0F) or 0x40).toByte()
            b[8] = ((b[8].toInt() and 0x3F) or 0x80).toByte()
            val h = Bytes.toHexLower(b)
            return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
        }
    }

    /**
     * Apply an incoming grant (spec 01 §6). The ROLE update is unconditional — a role
     * change re-delivers the grant with a bumped rev and must take effect even though the
     * VK is already held; the key itself is opened only when missing. Member grants carry
     * sealedVk (crypto_box_seal to our identity); owner/personal grants carry wrappedVk
     * (under UVK).
     */
    fun addGrant(grant: WireGrant) {
        if (grant.role.isNotEmpty()) vaultRoles[grant.vaultId] = grant.role
        if (vaultKeys.containsKey(grant.vaultId)) return
        val sealed = grant.sealedVk
        val vk = if (!sealed.isNullOrEmpty()) {
            SharedGrant.open(crypto, identityPub, identityPriv, grant.vaultId, Bytes.fromB64(sealed))
        } else {
            Envelope.openB64(crypto, uvk, grant.wrappedVk, Ad.vk(grant.vaultId, userId))
        }
        vaultKeys[grant.vaultId] = vk
    }

    @Deprecated("shared grants exist now — use addGrant", ReplaceWith("addGrant(grant)"))
    fun addPersonalGrant(grant: WireGrant) = addGrant(grant)

    fun setPersonalVault(vaultId: String) {
        if (personalVaultId.isEmpty()) personalVaultId = vaultId
    }

    fun hasVault(vaultId: String): Boolean = vaultKeys.containsKey(vaultId)

    /** Server-declared role for a vault we hold (null when unknown). */
    fun roleFor(vaultId: String): String? = vaultRoles[vaultId]

    /** Drop a vault's key + role (removedGrants purge) so later writes fail fast client-side. */
    fun removeVault(vaultId: String) {
        vaultKeys.remove(vaultId)
        vaultRoles.remove(vaultId)
    }

    // ---- shared vaults (spec 01 §6 / spec 03 §10) ----

    class NewSharedVault(val request: CreateVaultRequest, val vaultId: String)

    /** Create a shared vault locally: fresh VK, meta under VK, owner grant under OUR UVK. */
    fun buildCreateSharedVault(name: String): NewSharedVault {
        val vaultId = uuid(crypto)
        val svk = crypto.randomBytes(32)
        val metaPlain = buildJsonObject { put("name", name) }.toString()
        val req = CreateVaultRequest(
            vaultId = vaultId,
            metaBlob = Envelope.sealB64(crypto, svk, metaPlain.encodeToByteArray(), Ad.vaultMeta(vaultId)),
            wrappedVk = Envelope.sealB64(crypto, uvk, svk, Ad.vk(vaultId, userId)),
        )
        vaultKeys[vaultId] = svk
        vaultRoles[vaultId] = "owner"
        return NewSharedVault(req, vaultId)
    }

    /** Seal a vault's VK to a member's (out-of-band verified!) identity pubkey. */
    fun wrapVkForMember(memberIdentityPub: ByteArray, vaultId: String): String =
        Bytes.toB64(SharedGrant.seal(crypto, memberIdentityPub, vaultId, vk(vaultId)))

    /** Short identity fingerprint over the SEED-DERIVED pubkey (spec 01 §5) — what a
     *  family member reads out when someone shares a vault with them. */
    fun identityFingerprintShort(): String = SharedGrant.shortFingerprint(crypto, identityPub)

    /** Decrypt a vault's display name from its metaBlob (null when the VK is missing). */
    fun decryptVaultName(vaultId: String, metaBlob: String): String? = runCatching {
        val plain = Envelope.openB64(crypto, vk(vaultId), metaBlob, Ad.vaultMeta(vaultId)).decodeToString()
        Json.parseToJsonElement(plain).jsonObject["name"]?.jsonPrimitive?.content
    }.getOrNull()

    private fun vk(vaultId: String): ByteArray =
        vaultKeys[vaultId] ?: throw CryptoException("no key for vault $vaultId")

    fun encryptItem(vaultId: String, itemId: String, doc: ItemDoc): ItemUpload {
        val blob = Envelope.sealB64(crypto, vk(vaultId), json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray(), Ad.item(vaultId, itemId, ITEM_FORMAT_VERSION))
        return ItemUpload(formatVersion = ITEM_FORMAT_VERSION, attachmentIds = doc.attachments.map { it.id }, blob = blob)
    }

    /** Random per-file key (spec 02 §6) — lives only inside item ciphertext. */
    fun newFileKey(): ByteArray = crypto.randomBytes(32)

    fun cryptoProvider(): CryptoProvider = crypto

    fun decryptItem(item: WireItem): ItemDoc {
        val blob = item.blob ?: throw CryptoException("item has no blob (tombstone?)")
        val plain = Envelope.openB64(crypto, vk(item.vaultId), blob, Ad.item(item.vaultId, item.itemId, item.formatVersion))
        return json.decodeFromString(ItemDoc.serializer(), plain.decodeToString())
    }

    fun newItemId(): String = uuid(crypto)
}
