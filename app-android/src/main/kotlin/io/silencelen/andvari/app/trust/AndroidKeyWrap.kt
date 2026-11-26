package io.silencelen.andvari.app.trust

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import io.silencelen.andvari.core.client.session.KeyWrapOpen
import io.silencelen.andvari.core.client.session.KeyWrapPrepare
import io.silencelen.andvari.core.client.session.KeyWrapPrepared
import io.silencelen.andvari.core.client.session.PlatformKeyWrap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume

/**
 * Quick unlock's platform key on Android (spec 01 §8.1, the engine's [PlatformKeyWrap]): one AES-256-GCM key per slot
 * in the Android Keystore, non-exportable, auth-per-use behind `BIOMETRIC_STRONG` only (a device passcode never
 * counts), invalidated when a biometric is added, unusable while the device is locked; StrongBox when the device has
 * it. The Keystore parameters and the prompt bridge are the old app's (`QuickUnlock.kt`), unchanged.
 *
 * Core keeps the sealed bytes and decides every rule (when it may be used, when it goes); this holds the key and shows
 * the prompt, nothing else. The prompt needs the activity on screen: [MainActivity][io.silencelen.andvari.app.MainActivity]
 * [attach]es itself on create and [detach]es on destroy. With no activity attached an enrolment fails and an open is refused
 * (the master password is the way in), and no key is made.
 *
 * The sealed form is `[1, ivLength, iv…, ciphertext‖tag…]`.
 */
internal class AndroidKeyWrap(private val app: Context) : PlatformKeyWrap {
    @Volatile private var activity: WeakReference<FragmentActivity>? = null

    fun attach(a: FragmentActivity) {
        activity = WeakReference(a)
    }

    fun detach(a: FragmentActivity) {
        if (activity?.get() === a) activity = null
    }

    override fun strongBiometric(): Boolean =
        runCatching { BiometricManager.from(app).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS }
            .getOrDefault(false)

    /**
     * Enrolment's consent step: a fresh auth-per-use key, a cipher initialised for encryption
     * under it, and the prompt over that cipher (a `CryptoObject`). The prompt authorises that one cipher for one
     * operation; nothing of the account's key is here while the prompt is up. The core then seals inside its guarded use
     * ([Sealer.seal]). A cancelled or failed prompt leaves no key behind.
     */
    override suspend fun prepare(slot: String, aad: ByteArray): KeyWrapPrepare {
        val a = activity?.get() ?: return KeyWrapPrepare.Failed
        val cipher = try {
            val key = generateKey(slot)
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
        } catch (t: Throwable) {
            destroy(slot)
            return KeyWrapPrepare.Failed
        }
        return when (val auth = authenticate(a, cipher, ENROL_TITLE)) {
            is Auth.Ok -> KeyWrapPrepare.Prepared(Sealer(auth.cipher, aad.copyOf()))
            // A cancelled or failed prompt leaves no key behind.
            Auth.Cancelled -> {
                destroy(slot)
                KeyWrapPrepare.Cancelled
            }
            else -> {
                destroy(slot)
                KeyWrapPrepare.Failed
            }
        }
    }

    /**
     * The authorised cipher of one consented prompt, sealing once and at once. [seal] is lent the guard's own buffer:
     * `doFinal` reads it and neither zeroes nor keeps it, and this keeps nothing of it. The key is auth-per-use (no
     * validity window), so the authorisation belongs to this cipher's one operation rather than to a time: if the
     * Keystore dropped the operation meanwhile, or a new biometric invalidated the key while the prompt was up, `doFinal`
     * throws and [seal] answers null (the core destroys the slot, and enrolment answers "failed").
     */
    internal class Sealer(private var cipher: Cipher?, private val aad: ByteArray) : KeyWrapPrepared {
        override fun seal(secret: ByteArray): ByteArray? {
            val c = cipher ?: return null
            cipher = null
            return try {
                c.updateAAD(aad)
                val ct = c.doFinal(secret)
                val iv = c.iv
                byteArrayOf(VERSION, iv.size.toByte()) + iv + ct
            } catch (t: Throwable) {
                null
            }
        }

        override fun discard() {
            cipher = null
        }
    }

    override suspend fun open(slot: String, sealed: ByteArray, aad: ByteArray): KeyWrapOpen = openUnder(slot, sealed, aad, UNLOCK_TITLE)

    /**
     * A confirmation of the person's presence while the vault is already open (the shared code's
     * `QuickUnlockKeeper.confirmPresence`, for approving a new device, design §8.2 step 6): the same cipher flow as
     * [open], over the same key and the same sealed bytes, under a prompt that says what is approved ([reason]: the
     * device being added), never "Unlock". The shared code compares what this opens with the open account's key.
     */
    override suspend fun openToConfirm(slot: String, sealed: ByteArray, aad: ByteArray, reason: String?): KeyWrapOpen =
        openUnder(slot, sealed, aad, confirmTitle(reason))

    /** [open] and [openToConfirm]: one cipher flow, under the prompt [title]. */
    private suspend fun openUnder(slot: String, sealed: ByteArray, aad: ByteArray, title: String): KeyWrapOpen {
        val parsed = parse(sealed) ?: return KeyWrapOpen.Invalidated
        val key = try {
            loadKey(slot)
        } catch (t: Throwable) {
            null
        } ?: return KeyWrapOpen.Invalidated
        val cipher = Cipher.getInstance(TRANSFORM)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, parsed.first))
        } catch (e: KeyPermanentlyInvalidatedException) {
            return KeyWrapOpen.Invalidated
        } catch (t: Throwable) {
            return KeyWrapOpen.Invalidated
        }
        // No activity on screen: no prompt can be shown. The key is kept; the password is the way in now.
        val a = activity?.get() ?: return KeyWrapOpen.Refused
        return when (val auth = authenticate(a, cipher, title)) {
            is Auth.Ok -> try {
                auth.cipher.updateAAD(aad)
                KeyWrapOpen.Opened(auth.cipher.doFinal(parsed.second))
            } catch (t: Throwable) {
                // The key was invalidated between init and use, or the tag or the AAD does not match: wipe-class.
                KeyWrapOpen.Invalidated
            }
            Auth.Cancelled -> KeyWrapOpen.Cancelled
            // A lockout never ends a valid enrolment (the old app's A8): the key is kept.
            Auth.Lockout, Auth.Error -> KeyWrapOpen.Refused
        }
    }

    override fun destroy(slot: String) {
        runCatching { KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias(slot)) }
    }

    private sealed interface Auth {
        class Ok(val cipher: Cipher) : Auth
        data object Cancelled : Auth
        data object Lockout : Auth
        data object Error : Auth
    }

    /**
     * One BiometricPrompt over [cipher], suspended until it resolves. BIOMETRIC_STRONG only, so the negative button is
     * mandatory; a single rejected read is not terminal (the system prompt stays up).
     */
    private suspend fun authenticate(a: FragmentActivity, cipher: Cipher, title: String): Auth = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { cont ->
            val prompt = BiometricPrompt(
                a,
                a.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(code: Int, msg: CharSequence) {
                        if (cont.isActive) cont.resume(authErrorOf(code))
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!cont.isActive) return
                        val c = result.cryptoObject?.cipher
                        cont.resume(if (c == null) Auth.Error else Auth.Ok(c))
                    }

                    override fun onAuthenticationFailed() { /* one bad read; the prompt remains */ }
                },
            )
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(NEGATIVE)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setConfirmationRequired(false)
                .build()
            runCatching { prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher)) }
                .onFailure { if (cont.isActive) cont.resume(Auth.Error) }
            cont.invokeOnCancellation { runCatching { prompt.cancelAuthentication() } }
        }
    }

    private fun authErrorOf(code: Int): Auth = when (code) {
        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> Auth.Lockout
        BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED -> Auth.Cancelled
        else -> Auth.Error
    }

    private fun generateKey(slot: String): SecretKey {
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        return try {
            gen.init(keySpec(slot, strongBox = true))
            gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            gen.init(keySpec(slot, strongBox = false))
            gen.generateKey()
        }
    }

    private fun keySpec(slot: String, strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias(slot), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            b.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox) b.setIsStrongBoxBacked(true)
        return b.build()
    }

    private fun loadKey(slot: String): SecretKey? =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.getKey(alias(slot), null) as? SecretKey

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val VERSION: Byte = 1

        // The system prompt's words. GAP: the design gives none for the new path; these are the old app's, kept until
        // the owner approves copy (a system dialog cannot show the in-app placeholder style).
        private const val ENROL_TITLE = "Enable quick unlock"
        internal const val UNLOCK_TITLE = "Unlock andvari"
        private const val NEGATIVE = "Use master password"

        /**
         * A confirmation's title when the shared code gives no reason. GAP, as the titles above: no approved words, and
         * a system prompt cannot show the placeholder style. It says that something is approved, never "Unlock".
         */
        internal const val CONFIRM_TITLE = "Approve adding a device"

        /** The title of a confirmation of presence: what the person approves ([reason]), or [CONFIRM_TITLE]. */
        internal fun confirmTitle(reason: String?): String = reason?.trim()?.takeIf { it.isNotEmpty() } ?: CONFIRM_TITLE

        /** The Keystore alias of a core slot: the new path's own prefix, never one of the old app's. */
        internal fun alias(slot: String): String = "andvari.ovh.qk.$slot"

        /** `[1, ivLength, iv…, ciphertext‖tag…]` → (iv, ciphertext‖tag), or null when it is not that shape. */
        internal fun parse(sealed: ByteArray): Pair<ByteArray, ByteArray>? {
            if (sealed.size < 2 || sealed[0] != VERSION) return null
            val ivLen = sealed[1].toInt() and 0xff
            if (ivLen == 0 || sealed.size <= 2 + ivLen + GCM_TAG_BITS / 8 - 1) return null
            return sealed.copyOfRange(2, 2 + ivLen) to sealed.copyOfRange(2 + ivLen, sealed.size)
        }
    }
}
