package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.CreateVaultRequest
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

    fun encItem(itemId: String, plaintext: String, formatVersion: Int = 1): ItemUpload {
        val blob = Envelope.sealB64(crypto, vk, plaintext.encodeToByteArray(), Ad.item(personalVaultId, itemId, formatVersion))
        return ItemUpload(formatVersion = formatVersion, blob = blob)
    }

    fun decItem(itemId: String, blobB64: String, formatVersion: Int = 1): String =
        Envelope.openB64(crypto, vk, blobB64, Ad.item(personalVaultId, itemId, formatVersion)).decodeToString()

    fun newItemId() = uuidV4()

    // ---- shared vaults (spec 01 §6 / spec 03 §10) ----

    /** The client's X25519 identity keys (server stores identityPub; identitySeed is UVK-sealed). */
    val identityPub: ByteArray get() = identity.publicKey
    val identityPriv: ByteArray get() = identity.privateKey

    class SharedVaultHandle(val vaultId: String, val vk: ByteArray)

    /** Owner creates a shared vault: fresh vaultId+VK, owner grant wrapped under this client's UVK. */
    fun buildCreateSharedVault(): Pair<CreateVaultRequest, SharedVaultHandle> {
        val svId = uuidV4()
        val svk = crypto.randomBytes(32)
        val wrappedVk = Envelope.sealB64(crypto, uvk, svk, Ad.vk(svId, userId))
        val metaBlob = Envelope.sealB64(crypto, svk, """{"name":"Shared"}""".encodeToByteArray(), Ad.vaultMeta(svId))
        return CreateVaultRequest(svId, metaBlob, wrappedVk) to SharedVaultHandle(svId, svk)
    }

    /** Owner re-opens its own shared-vault grant (wrappedVk under UVK) → the VK. */
    fun openOwnGrant(vaultId: String, wrappedVkB64: String): ByteArray =
        Envelope.openB64(crypto, uvk, wrappedVkB64, Ad.vk(vaultId, userId))

    /** Owner seals a shared VK to a member's identity pubkey (base64url sealedVk). */
    fun sealVkFor(memberIdentityPub: ByteArray, vaultId: String, vk: ByteArray): String =
        Bytes.toB64(SharedGrant.seal(crypto, memberIdentityPub, vaultId, vk))

    /** Member opens a sealed grant with its own identity keys → the VK. */
    fun openSharedGrant(vaultId: String, sealedVkB64: String): ByteArray =
        SharedGrant.open(crypto, identity.publicKey, identity.privateKey, vaultId, Bytes.fromB64(sealedVkB64))

    /** The client's seed-derived identity fingerprint (what the sharing UX verifies out-of-band). */
    fun identityShortFingerprint(): String = SharedGrant.shortFingerprint(crypto, identity.publicKey)

    fun encItemIn(vaultId: String, vaultKey: ByteArray, itemId: String, plaintext: String): ItemUpload {
        val blob = Envelope.sealB64(crypto, vaultKey, plaintext.encodeToByteArray(), Ad.item(vaultId, itemId, 1))
        return ItemUpload(formatVersion = 1, blob = blob)
    }

    fun decItemIn(vaultId: String, vaultKey: ByteArray, itemId: String, blobB64: String): String =
        Envelope.openB64(crypto, vaultKey, blobB64, Ad.item(vaultId, itemId, 1)).decodeToString()

    // ---- vault lifecycle (spec 03 §11): the REAL client-side proof mints + re-wrap ----

    private fun lifecycleKey(vaultKey: ByteArray): ByteArray = LifecycleProof.lifecycleKey(crypto, vaultKey)

    fun mintDeleteProof(vaultId: String, vaultKey: ByteArray, deleteId: String): String =
        LifecycleProof.delete(crypto, lifecycleKey(vaultKey), vaultId, deleteId)

    fun mintRestoreProof(vaultId: String, vaultKey: ByteArray, deleteId: String): String =
        LifecycleProof.restore(crypto, lifecycleKey(vaultKey), vaultId, deleteId)

    fun mintOfferProof(vaultId: String, vaultKey: ByteArray, offerId: String, toUserId: String, expiresAt: Long, seq: Long): String =
        LifecycleProof.offer(crypto, lifecycleKey(vaultKey), vaultId, offerId, toUserId, expiresAt, seq)

    fun mintAcceptProof(vaultId: String, vaultKey: ByteArray, offerId: String, newOwnerUserId: String, seq: Long, wrappedVk: String): String =
        LifecycleProof.accept(crypto, lifecycleKey(vaultKey), vaultId, offerId, newOwnerUserId, seq, wrappedVk)

    /**
     * What an OTHER 0.5.0 member does with a delivered lastTransfer (spec 03 §11 / #3): it
     * only ever receives `wrapHash` (never the new owner's wrappedVk), so it recomputes the
     * accept-proof domain from wrapHash + its held VK and compares — detecting a server-side
     * role rewrite or wrap swap. Mirrors LifecycleProof.accept's domain, fed the hash directly.
     */
    fun verifyAcceptProofFromWrapHash(
        vaultId: String, vaultKey: ByteArray, offerId: String, newOwnerUserId: String, seq: Long, wrapHash: String, presented: String,
    ): Boolean {
        val domain = "andvari/v1|lifecycle|transfer-accept|$vaultId|$offerId|$newOwnerUserId|$seq|$wrapHash"
        val expected = Bytes.toB64(crypto.hmacSha256(lifecycleKey(vaultKey), domain.encodeToByteArray()))
        return LifecycleProof.verify(expected, presented)
    }

    fun mintRemoveProof(vaultId: String, vaultKey: ByteArray, targetUserId: String, nonce: String): String =
        LifecycleProof.remove(crypto, lifecycleKey(vaultKey), vaultId, targetUserId, nonce)

    /** What a 0.5.0 member does with a delivered proof: recompute under the held VK and compare. */
    fun verifyDeleteProof(vaultId: String, vaultKey: ByteArray, deleteId: String, presented: String): Boolean =
        LifecycleProof.verify(mintDeleteProof(vaultId, vaultKey, deleteId), presented)

    fun verifyRemoveProof(vaultId: String, vaultKey: ByteArray, targetUserId: String, nonce: String, presented: String): Boolean =
        LifecycleProof.verify(mintRemoveProof(vaultId, vaultKey, targetUserId, nonce), presented)

    /** Transfer-accept re-wrap: the transferee seals the VK under its OWN UVK — the exact
     *  construction vault creation uses (Ad.vk binds vaultId + this user). */
    fun wrapVkUnderOwnUvk(vaultId: String, vaultKey: ByteArray): String =
        Envelope.sealB64(crypto, uvk, vaultKey, Ad.vk(vaultId, userId))

    /** A renamed metaBlob under the same VK/AD (rename, spec 03 §11). */
    fun sealVaultMeta(vaultId: String, vaultKey: ByteArray, plaintextJson: String): String =
        Envelope.sealB64(crypto, vaultKey, plaintextJson.encodeToByteArray(), Ad.vaultMeta(vaultId))

    fun openVaultMeta(vaultId: String, vaultKey: ByteArray, metaBlobB64: String): String =
        Envelope.openB64(crypto, vaultKey, metaBlobB64, Ad.vaultMeta(vaultId)).decodeToString()
}
