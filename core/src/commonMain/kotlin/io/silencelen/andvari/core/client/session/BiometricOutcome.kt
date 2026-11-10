package io.silencelen.andvari.core.client.session

/**
 * What a biometric prompt's failure means for quick unlock, platform-neutral, so the table is pinned once
 * (spec 01 §8.1; Android's `QuickUnlock` table). Fail-to-password: every outcome is a working biometric or the
 * master-password prompt. A cancel, a fallback and a lockout keep the enrollment (A8: a lockout must never be a
 * way to destroy it); only a key that can never work again is wiped.
 */
enum class BiometricOutcome {
    /** The person cancelled, chose the password, or the system interrupted: silent, the enrollment stays. */
    CANCELLED,

    /** Too many attempts: say so, the enrollment stays. */
    LOCKED_OUT,

    /** The biometric set or the device passcode is gone, so the wrapping key can never be used again: wipe. */
    INVALIDATED,

    /** Anything else (unavailable for now, a failed match, a system error): point at the password, keep the enrollment. */
    DEVICE_ERROR,
}

/** iOS LocalAuthentication: the `LAError` codes, numerically, so the mapping is testable off the platform. */
object LocalAuthenticationCodes {
    fun outcome(code: Long): BiometricOutcome = when (code) {
        -2L, // userCancel
        -3L, // userFallback ("Use master password")
        -4L, // systemCancel
        -9L, // appCancel
        -> BiometricOutcome.CANCELLED
        -8L -> BiometricOutcome.LOCKED_OUT // biometryLockout
        -7L, // biometryNotEnrolled: the set the key was bound to is gone
        -5L, // passcodeNotSet: the system deletes a passcode-bound key
        -> BiometricOutcome.INVALIDATED
        else -> BiometricOutcome.DEVICE_ERROR // authenticationFailed, biometryNotAvailable, invalidContext, notInteractive, …
    }

    /** Why `canEvaluatePolicy` refused, from its error [code], for the biometric the device has ([name]: "Face ID", "Touch ID"). */
    fun unavailable(code: Long?, name: String): String = when (code) {
        -7L -> "Set up $name in the Settings app first." // biometryNotEnrolled
        -6L -> "andvari isn't allowed to use $name. Turn it on in Settings › andvari." // biometryNotAvailable: denied, or no hardware
        -8L -> "$name is locked after too many tries. Lock and unlock your iPhone with its passcode, then try again." // biometryLockout
        -5L -> "Set a passcode on this iPhone first." // passcodeNotSet
        else -> "$name isn't available right now."
    }
}

/** The sentences a quick-unlock outcome says (Android's, where it has them). */
object QuickUnlockCopy {
    const val LOCKOUT_FALLBACK = "Too many attempts — enter your master password."
    const val DEVICE_FALLBACK = "Couldn't unlock with your device — unlock with your master password."
    const val BIOMETRICS_CHANGED = "Your biometrics changed — enter your master password."
    const val SET_UP_AGAIN = "Quick unlock needs to be set up again."
    const val ENROLL_LOCKED_OUT = "Too many attempts — try again later."
    const val NO_SECURE_HARDWARE = "This device can't hold a quick-unlock key."

    /** What a recover attempt that the prompt did not release comes to. */
    fun recoverFailure(outcome: BiometricOutcome): QuickRecover = when (outcome) {
        BiometricOutcome.CANCELLED -> QuickRecover.Fallback(null)
        BiometricOutcome.LOCKED_OUT -> QuickRecover.Fallback(LOCKOUT_FALLBACK)
        BiometricOutcome.INVALIDATED -> QuickRecover.Wiped(BIOMETRICS_CHANGED)
        BiometricOutcome.DEVICE_ERROR -> QuickRecover.Fallback(DEVICE_FALLBACK)
    }

    /** What an enroll attempt that the prompt did not consent to comes to. */
    fun enrollFailure(outcome: BiometricOutcome): QuickEnroll = when (outcome) {
        BiometricOutcome.CANCELLED -> QuickEnroll.Cancelled
        BiometricOutcome.LOCKED_OUT -> QuickEnroll.Failed(ENROLL_LOCKED_OUT)
        BiometricOutcome.INVALIDATED, BiometricOutcome.DEVICE_ERROR -> QuickEnroll.Failed(null)
    }
}
