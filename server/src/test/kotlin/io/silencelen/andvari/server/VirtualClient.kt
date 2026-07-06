package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.PersonalVaultUpload
import io.silencelen.andvari.core.model.RegisterRequest

/**
 * A test-only "virtual client" that performs the REAL client-side crypto (spec 01/02)
 * against the server, using the same :core primitives the Android/desktop/web clients
 * will. Proves the server accepts what a conforming client produces and that the
 * zero-knowledge chain round-trips end to end.
 */
class VirtualClient(val email: String, val password: String, fast: Boolean = true) {
    private val crypto = createCryptoProvider()
    val kdfParams = if (fast) KdfParams(ops = 1, memBytes = 8 * 1024 * 1024) else KdfParams.DEFAULT
    val kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES)

    private val mk = Keys.masterKey(crypto, password, kdfSalt, kdfParams)
    val authKey = Bytes.toB64(Keys.authKey(crypto, mk))
    private val wrapKey = Keys.wrapKey(crypto, mk)

    /** What a fresh device computes after prelogin returns the account's salt/params. */
    fun authKeyWith(kdfSaltB64: String, params: KdfParams): String {
        val m = Keys.masterKey(crypto, password, Bytes.fromB64(kdfSaltB64), params)
        return Bytes.toB64(Keys.authKey(crypto, m))
    }

    val uvk = crypto.randomBytes(32)
    private val identitySeed = crypto.randomBytes(32)
    private val identity = crypto.boxKeypairFromSeed(identitySeed)

    var personalVaultId = uuidV4()
    val vk = crypto.randomBytes(32)

    var userId: String = ""
    var accessToken: String = ""
    var refreshToken: String = ""

    private fun uuidV4() = java.util.UUID.randomUUID().toString()

    /**
     * Registration bundle. Because AEAD AD binds to userId (spec 02 §2), the client
     * chooses its own userId (a UUID) and the server honors it — the server never
     * needs to re-encrypt, so client-chosen ids are fine and keep AD stable forever.
     */
    fun buildRegister(inviteToken: String, recoveryPub: ByteArray, fingerprint: String): RegisterRequest {
        userId = uuidV4()
        val wrappedUvk = Envelope.sealB64(crypto, wrapKey, uvk, Ad.uvk(userId))
        val encIdentity = Envelope.sealB64(crypto, uvk, identitySeed, Ad.idkey(userId))
        val wrappedVk = Envelope.sealB64(crypto, uvk, vk, Ad.vk(personalVaultId, userId))
        val metaBlob = Envelope.sealB64(crypto, vk, """{"name":"Personal"}""".encodeToByteArray(), Ad.vaultMeta(personalVaultId))
        val sealed = Bytes.toB64(Escrow.sealUvk(crypto, recoveryPub, userId, uvk))
        return RegisterRequest(
            inviteToken = inviteToken,
            userId = userId,
            email = email,
            displayName = email.substringBefore('@'),
            kdfSalt = Bytes.toB64(kdfSalt),
            kdfParams = kdfParams,
            authKey = authKey,
            wrappedUvk = wrappedUvk,
            identityPub = Bytes.toB64(identity.publicKey),
            encryptedIdentitySeed = encIdentity,
            escrow = EscrowUpload(sealed, fingerprint),
            personalVault = PersonalVaultUpload(personalVaultId, wrappedVk, metaBlob),
            device = DeviceInfo("test", "vc-${email.take(3)}"),
        )
    }

    /**
     * The full zero-knowledge unlock a fresh device performs with ONLY the password:
     * derive MK from the returned salt/params → unwrap UVK → unwrap the personal
     * VK from the grant. Mutates this client's uvk/vk so decItem then works.
     */
    fun unlockFromServer(accountKeys: AccountKeys, wrappedVkFromGrant: String) {
        val recoveredMk = Keys.masterKey(crypto, password, Bytes.fromB64(accountKeys.kdfSalt), accountKeys.kdfParams)
        val wk = Keys.wrapKey(crypto, recoveredMk)
        val recoveredUvk = Envelope.openB64(crypto, wk, accountKeys.wrappedUvk, Ad.uvk(userId))
        recoveredUvk.copyInto(uvk)
        val recoveredVk = Envelope.openB64(crypto, uvk, wrappedVkFromGrant, Ad.vk(personalVaultId, userId))
        recoveredVk.copyInto(vk)
    }

    /**
     * Password change payload (spec 03 §3): fresh salt + authKey derived from the new
     * password, and the SAME UVK re-wrapped under the new wrap key — items must stay
     * decryptable because nothing below the UVK changes. Pure: this client keeps its
     * original password; post-change flows use a fresh VirtualClient(newPassword).
     */
    fun buildPasswordChange(newPassword: String): PasswordChangeRequest {
        val newSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
        val newMk = Keys.masterKey(crypto, newPassword, newSalt, kdfParams)
        return PasswordChangeRequest(
            currentAuthKey = authKey,
            newAuthKey = Bytes.toB64(Keys.authKey(crypto, newMk)),
            newKdfSalt = Bytes.toB64(newSalt),
            newKdfParams = kdfParams,
            newWrappedUvk = Envelope.sealB64(crypto, Keys.wrapKey(crypto, newMk), uvk, Ad.uvk(userId)),
        )
    }

    fun encItem(itemId: String, plaintext: String): ItemUpload {
        val blob = Envelope.sealB64(crypto, vk, plaintext.encodeToByteArray(), Ad.item(personalVaultId, itemId, 1))
        return ItemUpload(formatVersion = 1, blob = blob)
    }

    fun decItem(itemId: String, blobB64: String): String =
        Envelope.openB64(crypto, vk, blobB64, Ad.item(personalVaultId, itemId, 1)).decodeToString()

    fun newItemId() = uuidV4()
}
