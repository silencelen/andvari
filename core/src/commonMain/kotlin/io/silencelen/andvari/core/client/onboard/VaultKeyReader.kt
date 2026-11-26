package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized

/**
 * Opens what [OpenedAccount.sealUnderVaultKey] sealed, holding nothing but the account's id and its vault key (UVK): the
 * iPhone's AutoFill extension, a separate process that holds only those after its own quick unlock and Face ID, reads the
 * fill snapshot the app sealed with it. It opens seals and does nothing else: no identity key, no signing key, no vault
 * keys, no seal of its own.
 *
 * [uvk] is copied: the caller wipes its own at once. [wipe] when done; after it, [openUnderVaultKey] throws
 * [AccountWipedException], as a wiped [OpenedAccount] does, so a lock is never mistaken for a damaged snapshot.
 */
class VaultKeyReader(val userId: String, uvk: ByteArray) {
    private val key: ByteArray

    init {
        require(userId.isNotEmpty()) { "an account id is required" }
        require(uvk.size == VaultKeySeal.UVK_BYTES) { "a vault key is ${VaultKeySeal.UVK_BYTES} bytes" }
        key = uvk.copyOf()
    }

    private val keyLock = SynchronizedObject()
    private var wiped = false

    /**
     * What [OpenedAccount.sealUnderVaultKey] sealed for [purpose] under this account; null for anything else (another
     * account, another purpose, another key, a damaged or forged seal, a purpose outside the label grammar). Throws
     * [AccountWipedException] after [wipe].
     */
    fun openUnderVaultKey(crypto: CryptoProvider, purpose: String, sealed: ByteArray): ByteArray? = synchronized(keyLock) {
        if (wiped) throw AccountWipedException()
        VaultKeySeal.open(crypto, key, userId, purpose, sealed)
    }

    /** Zeroes the held key; every later [openUnderVaultKey] throws [AccountWipedException]. */
    fun wipe() {
        synchronized(keyLock) {
            wiped = true
            key.fill(0)
        }
    }
}

/**
 * The one derivation and associated data of a seal under the account's vault key, used by both [OpenedAccount] and
 * [VaultKeyReader]: an envelope (spec 02 §2) under HKDF-SHA-256(UVK, info `andvari vault-key seal v1|<purpose>`), with
 * associated data `andvari/v2|vault-key-seal|<userId>|<purpose>`. Callers hold their own lock and wiped state.
 */
internal object VaultKeySeal {
    const val UVK_BYTES = 32

    /** The label grammar of a purpose. */
    private val PURPOSE = Regex("^[a-z0-9][a-z0-9.-]{0,63}$")

    fun isPurpose(purpose: String): Boolean = PURPOSE.matches(purpose)

    fun seal(crypto: CryptoProvider, uvk: ByteArray, userId: String, purpose: String, plain: ByteArray): ByteArray {
        require(isPurpose(purpose)) { "not a seal purpose" }
        val key = key(crypto, uvk, purpose)
        try {
            return Envelope.seal(crypto, key, plain, ad(userId, purpose))
        } finally {
            key.fill(0)
        }
    }

    fun open(crypto: CryptoProvider, uvk: ByteArray, userId: String, purpose: String, sealed: ByteArray): ByteArray? {
        if (!isPurpose(purpose)) return null
        val key = key(crypto, uvk, purpose)
        return try {
            Envelope.open(crypto, key, sealed, ad(userId, purpose))
        } catch (e: CryptoException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } finally {
            key.fill(0)
        }
    }

    private fun key(crypto: CryptoProvider, uvk: ByteArray, purpose: String): ByteArray =
        Hkdf.sha256(crypto, uvk, ByteArray(0), "${OpenedAccount.VAULT_KEY_SEAL_INFO}$purpose".encodeToByteArray(), 32)

    private fun ad(userId: String, purpose: String): ByteArray = "andvari/v2|vault-key-seal|$userId|$purpose".encodeToByteArray()
}
