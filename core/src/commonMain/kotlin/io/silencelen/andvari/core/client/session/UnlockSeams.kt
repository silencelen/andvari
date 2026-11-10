package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.VaultCache

/**
 * The namespace directories (design 2026-07-15 §4.2): where one (origin, user)'s durable files live. Android
 * keeps them under `<noBackup>/ns/<originKey>/<userId>/`.
 */
interface NamespaceStorage {
    /** The durable vault cache of [userId] at [originKey], created if missing. */
    fun openVaultCache(originKey: String, userId: String): VaultCache

    /**
     * The small device state that outlives the cache (root cause A, A5b M-1): the personal wrap this device
     * last authenticated. Purges never remove it.
     */
    fun deviceState(originKey: String, userId: String): DeviceState

    /** Delete the durable vault cache of [userId] at [originKey], its journal files included. Never throws. */
    fun deleteVaultCache(originKey: String, userId: String)
}

/**
 * Whatever the platform's biometric prompt needs in order to show itself: on Android, the activity it rides
 * on. A platform whose prompt needs nothing passes [None].
 */
interface BiometricHost {
    object None : BiometricHost
}

/**
 * The platform's quick-unlock key wrapping (spec 01 §8.1): the UVK, never the password, wrapped under a
 * non-exportable hardware key that only a strong biometric releases. Android: a Keystore AES-GCM key behind
 * BIOMETRIC_STRONG. iOS: a Secure Enclave key created with `biometryCurrentSet`.
 *
 * Fail-to-password invariant: every outcome is a working biometric or the master-password prompt, never
 * neither. Wipe-class failures destroy the wrapped key; a cancel or a lockout never does.
 */
interface QuickUnlockKeys {
    /** A strong biometric is enrolled and usable. A device passcode never counts: it is weaker than the master password. */
    fun hasStrongBiometric(): Boolean

    /** Why [hasStrongBiometric] is false, as a sentence the person can act on; null when it is true or the platform cannot say. */
    fun biometricProblem(): String? = null

    /** A well-formed wrapped UVK exists for [userId] at [originKey]. */
    fun isEnrolled(originKey: String, userId: String): Boolean

    /** Show the prompt over [host] and unwrap the UVK. Every prompt outcome maps to a [QuickRecover]. */
    suspend fun recover(host: BiometricHost, originKey: String, userId: String): QuickRecover

    /**
     * Wrap [account]'s UVK for [userId] at [originKey] under a fresh hardware key, once the prompt over [host] consents
     * (spec 01 §8.1 requires a biometric at enrollment). Replaces an earlier enrollment. The UVK copy is zeroed
     * whatever happens, and an account wiped meanwhile (the vault locked under the prompt) wraps nothing.
     */
    suspend fun enroll(host: BiometricHost, originKey: String, userId: String, account: Account): QuickEnroll

    /** Destroy the wrapped UVK and its key for one namespace. Idempotent; never throws. */
    fun wipe(originKey: String, userId: String)
}

/** What one quick-unlock prompt released. */
sealed interface QuickRecover {
    /** The UVK. The receiver owns it: an account takes it, or the receiver zeroes it (survey gap 7). */
    class Ok(val uvk: ByteArray) : QuickRecover

    /** Cancelled, declined ("Use master password") or locked out: the enrollment is kept (A8). [reason] is what to say, if anything. */
    data class Fallback(val reason: String?) : QuickRecover

    /** A wipe-class failure (enrollment changed, tamper, a corrupt blob): the enrollment is gone. */
    data class Wiped(val reason: String) : QuickRecover
}

/** What one enrollment prompt came to. */
sealed interface QuickEnroll {
    /** The UVK is wrapped. */
    data object Ok : QuickEnroll

    /** The prompt was cancelled: nothing was wrapped. */
    data object Cancelled : QuickEnroll

    /** Nothing was wrapped; [reason] says why, when it can. */
    data class Failed(val reason: String?) : QuickEnroll
}

/** The gate that refuses a quick unlock, in the order they are checked (spec 01 §8.1, A1 to A4). */
enum class QuickGate {
    /** The origin's policy forbids durable key material, or this device has not seen its policy in 7 days (A4). */
    POLICY,

    /** No strong biometric is enrolled and usable. */
    NO_BIOMETRIC,

    /** Nothing is wrapped for this account at this origin. */
    NOT_ENROLLED,

    /** The last full-password unlock is too old, or its age cannot be proven (A1/A2). */
    EXPIRED,
}

/** The quick-unlock gates for one account at the origin the client dials: one view for the UI and the unlock. */
data class QuickStatus(
    /** The policy permits it and a strong biometric is usable: quick unlock can be offered here. */
    val eligible: Boolean,
    /** A wrapped UVK exists for this account at this origin. */
    val enrolled: Boolean,
    /** Enrolled, and within the window of the last full-password unlock. */
    val fresh: Boolean,
    /** The first gate that refuses, or null when a quick unlock may run. */
    val refusal: QuickGate?,
) {
    val usable: Boolean get() = refusal == null
}
