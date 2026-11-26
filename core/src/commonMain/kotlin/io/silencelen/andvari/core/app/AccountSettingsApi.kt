package io.silencelen.andvari.core.app

/**
 * Settings › Delete account (§3.11, spec 03 §13): what a deletion would do now, and the request itself. A deletion
 * carries one signed `leave` for every shared vault the account is a member of, so each of those vaults' histories
 * shows the account leaving, signed by itself.
 */
class DeletionScreen internal constructor(
    /** This account's address, which the person types to confirm. */
    val email: String,
    /** Null until the server answered. */
    val plan: DeletionPlan?,
    /**
     * The server refused the request because a vault's history moved on while the leaves were being built
     * (`409 account_delete_log_stale`): the app fetched the heads again and is retrying by itself. Nothing was deleted.
     */
    val retrying: Boolean,
    /**
     * The last request got no answer that says what happened: the account may have been deleted. Never report it as
     * done or as failed; [AccountSettingsApi.checkDeletion] finds out.
     */
    val outcomeUnknown: Boolean,
)

/** What deleting the account would do now (the engine's `DeletionPreview`, with the vaults by name). */
class DeletionPlan internal constructor(
    /** The vaults that go with the account: its personal vault and every vault only it holds. By name, where this device can read it. */
    val deletedVaults: List<String>,
    /** The shared vaults it leaves; one `leave` is signed for each. */
    val leftVaults: List<String>,
    /** What stands in the way. The deletion is not offered while there is one. */
    val blockers: List<DeletionBlockerRow>,
    /** The account has two-step sign-in: the deletion needs the current code. */
    val codeNeeded: Boolean,
) {
    val canProceed: Boolean get() = blockers.isEmpty()
}

class DeletionBlockerRow internal constructor(
    val kind: DeletionBlockerKind,
    /** [DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS]: the vault, by name; null otherwise or when it cannot be read. */
    val vaultName: String?,
    /** How many other accounts hold that vault. */
    val others: Int,
)

enum class DeletionBlockerKind {
    /** The account owns a shared vault others hold: delete it or hand it over first. */
    SHARED_VAULT_WITH_OTHERS,

    /** The account is the instance's operator: a signed handover makes another account the operator first (§9.1). */
    OPERATOR_ACCOUNT,

    /** A kind this build does not know: show it as a blocker it cannot explain, and never offer to go past it. */
    NOT_KNOWN,
}

interface AccountSettingsApi {
    /**
     * Change the master password. Every other session of the account ends; the recovery kit and any operator
     * recovery stay valid, because the account's key does not change, so no new kit is due. The current password goes,
     * as a re-authentication, to the session's own server only. Once the server answered, this device's copy opens
     * with the new password only. It needs the vault open and the session live (not signed out by the server).
     */
    suspend fun changeMasterPassword(current: String, replacement: String): PasswordChangeResult

    suspend fun openDeletion(): PlainResult

    fun closeDeletion()

    /**
     * Delete the account: the typed address, the master password, and the code when the plan asks for one. The
     * leaves are built at the heads the server served, and a head dated more than a day ahead of this device's
     * clock stops the deletion before anything is signed ([DeletionResult.FAR_FUTURE]).
     */
    suspend fun deleteAccount(screen: DeletionScreen, typedEmail: String, password: String, code: String?): DeletionResult

    /** After an unknown outcome: ask the server whether the account still exists. */
    suspend fun checkDeletion(screen: DeletionScreen): PlainResult

    // ---- quick unlock (spec 01 §8.1) ----

    /**
     * Turn quick unlock on: the platform's prompt asks for the biometric, and the account's key is sealed under a key
     * only it releases. It needs [QuickUnlockSetting.state] [QuickUnlockState.OFF]. Turning it on does not renew the
     * periodic full password: that stays 30 days from the last time the password was typed here.
     */
    suspend fun turnOnQuickUnlock(setting: QuickUnlockSetting): QuickEnrolResult

    /** Turn it off: the sealed key and the device's key for it are destroyed. */
    fun turnOffQuickUnlock(setting: QuickUnlockSetting)

    /**
     * "Not now" on the offer ([QuickUnlockSetting.offerNow]): it comes back only after three more unlocks with the
     * password, and at most twice (design 2026-08-23 §7.1).
     */
    fun quickUnlockNotNow(setting: QuickUnlockSetting)

    // ---- two-step sign-in (spec 03 rows 13 to 16) ----

    /** Settings › Two-step sign-in: asks the server whether it is on (`GET /account/totp`). */
    suspend fun openTwoStep(): PlainResult

    fun closeTwoStep()

    /**
     * "Turn on two-step sign-in" while it is off: needs the master password, which goes, as a re-authentication, to
     * the session's own server only. On [TwoStepResult.DONE] the screen holds a [TwoStepScreen.enrolment]: show its
     * key ([twoStepKey]) for the authenticator app, then [confirmTwoStep] with a code from it.
     */
    suspend fun startTwoStep(screen: TwoStepScreen, password: String): TwoStepResult

    /**
     * The key for the authenticator app, while [enrolment] is on show. It is read through this call, never carried
     * by a snapshot, as a kit's secret is.
     */
    fun twoStepKey(enrolment: TwoStepEnrolment): TwoStepKey?

    /** The first code from the authenticator app: two-step sign-in is on once it is accepted. */
    suspend fun confirmTwoStep(enrolment: TwoStepEnrolment, code: String): TwoStepResult

    /**
     * Since 2026-11-16 a code alone no longer turns two-step sign-in off: this sends nothing and answers
     * [TwoStepResult.PASSWORD_NEEDED]. Kept so that no app breaks; call [turnOffTwoStepWithPassword].
     */
    suspend fun turnOffTwoStep(screen: TwoStepScreen, code: String): TwoStepResult

    /**
     * Turn two-step sign-in off with a current [code] and the master [password], whose proof goes, as a
     * re-authentication, to the session's own server only. The server checks the password first and looks at the code
     * only after a right one: [TwoStepResult.WRONG_PASSWORD], then [TwoStepResult.TOO_MANY_TRIES] (wrong passwords or
     * wrong codes, with the wait in [AppApi.retryAfterSeconds]), then [TwoStepResult.WRONG_CODE]. The server mails the
     * account that it was turned off.
     */
    suspend fun turnOffTwoStepWithPassword(screen: TwoStepScreen, code: String, password: String): TwoStepResult

    /**
     * A new key for the authenticator app while two-step sign-in is on ([TwoStepScreen.enabled]): a current [code] and
     * the master [password], with the same answers as [turnOffTwoStepWithPassword]. On [TwoStepResult.DONE] the screen
     * holds a [TwoStepScreen.enrolment], as after [startTwoStep]: show its key ([twoStepKey]), then [confirmTwoStep] with
     * a code from it. Until it is confirmed, the old key stays in force.
     */
    suspend fun replaceTwoStepKey(screen: TwoStepScreen, code: String, password: String): TwoStepResult
}

/** Quick unlock on this device, for the account that is open ([AccountSnapshot.quickUnlock]). */
class QuickUnlockSetting internal constructor(
    val state: QuickUnlockState,
    /** Offer it now, as a card: it can be turned on, is not on, and the person has not put it off. */
    val offerNow: Boolean,
)

enum class QuickUnlockState {
    /** This build has no platform key, or the device has no strong biometric enrolled (a passcode does not count). */
    UNAVAILABLE,

    /** The server's policy forbids keys at rest on devices, or this device has not seen its policy for 7 days. */
    NOT_ALLOWED,

    /** It can be turned on. */
    OFF,
    ON,
}

/** What turning quick unlock on came to. */
enum class QuickEnrolResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** The person cancelled the prompt: nothing was sealed. */
    CANCELLED,

    /** No strong biometric, no platform key, or the policy forbids it: [QuickUnlockSetting.state] says which. */
    NOT_AVAILABLE,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/**
 * The client policy the session's server last declared (spec 03 §1.1), as this device applies it: clamped to the
 * client's own bounds, so a server can make a window shorter but never longer (B1-1). Read-only. Until the policy has
 * been read on this device ([known] false) the times are the defaults ([DEFAULT_AUTO_LOCK_SECONDS],
 * [DEFAULT_CLIPBOARD_CLEAR_SECONDS]), not the ceilings, and keys at rest count as forbidden. A policy kept from an earlier
 * session ([known] true) is used until a new one is read: at every opening of the vault.
 */
class ServerPolicy internal constructor(
    /** The policy was read from the server. */
    val known: Boolean,
    /** Lock after this many idle seconds ([AppApi.lock] is the app's to call). */
    val autoLockSeconds: Int,
    /** Clear a copied secret from the clipboard after this many seconds. */
    val clipboardClearSeconds: Int,
    /** The server permits key material at rest on this device (an offline copy, quick unlock). */
    val offlineCacheAllowed: Boolean,
    /** The server's own limit for one attachment, in bytes; 0 when not known. */
    val attachmentMaxBytes: Long,
    /** The server's own limit for all attachments of one item, in bytes; 0 when not known. */
    val itemAttachmentsMaxBytes: Long,
    /**
     * On a phone whose autofill catches logins, while the server's policy forbids keeping data on it: logins andvari
     * catches are kept sealed on the phone until the person answers them (decided on 2026-11-18). Show it with the
     * policy in Settings while it is not null. Additive.
     */
    val capturesKeptLine: CopyLine? = null,
) {
    companion object {
        /** The auto-lock before any policy was read on this device: 5 minutes. */
        const val DEFAULT_AUTO_LOCK_SECONDS: Int = 300

        /** The clipboard clear before any policy was read on this device: 30 seconds. */
        const val DEFAULT_CLIPBOARD_CLEAR_SECONDS: Int = 30
    }
}

/** Settings › Two-step sign-in (`GET /account/totp`). */
class TwoStepScreen internal constructor(
    /** It is on: every sign-in asks for a code. */
    val enabled: Boolean,
    /** A turn-on in progress: the key is shown and the first code is awaited. Null otherwise. */
    val enrolment: TwoStepEnrolment?,
)

/** A two-step enrolment awaiting its first code (`POST /account/totp/setup` answered; pending until confirmed). */
class TwoStepEnrolment internal constructor()

/** The authenticator app's key ([AccountSettingsApi.twoStepKey]): a secret, never in a snapshot. */
class TwoStepKey internal constructor(
    /** The key in base32, for typing by hand. */
    val secret: String,
    /** The `otpauth://` URI, for a QR code. */
    val uri: String,
)

/** Two-step sign-in in Settings (spec 03 rows 14 to 16). */
enum class TwoStepResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE]: never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED]: the server refused a proof this device made; never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /** `403 reauth_failed`: the master password is wrong. Never shown as an expired session (S3-K1). */
    WRONG_PASSWORD,

    /** `400 bad_totp_code`: the code is wrong or was used already; a code is single-use, so wait for the next one. */
    WRONG_CODE,

    /** `400 no_pending_totp` or `400 totp_not_enrolled`: the server's state moved on; the screen now shows what it is. */
    NOT_PENDING,

    /**
     * [AccountSettingsApi.turnOffTwoStep], the call that takes a code alone: turning two-step sign-in off needs the master
     * password as well since 2026-11-16. Nothing was sent. Additive.
     */
    PASSWORD_NEEDED(sentence = CopyKey.TWO_STEP_PASSWORD_NEEDED),

    /**
     * `429` on turning two-step sign-in off or replacing its key: too many wrong passwords, or too many wrong codes, on
     * this account; wait ([AppApi.retryAfterSeconds]) and try again. Nothing was looked at. Additive.
     */
    TOO_MANY_TRIES(sentence = CopyKey.TWO_STEP_TOO_MANY_TRIES),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** `PUT /account/password`. */
enum class PasswordChangeResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE]: never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED]: the server refused a proof this device made; never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /** `403 reauth_failed`: the current password is wrong. Never shown as an expired session (S3-K1). */
    WRONG_PASSWORD,

    /** The new password is below the master-password floor. Nothing was sent. */
    WEAK_PASSWORD,

    /** `401 credential_changed`: a recovery or another device changed it meanwhile. */
    CHANGED_ELSEWHERE,

    /**
     * The new password IS in force at the server (other devices and sign-ins take it), but this device's copy could
     * not be wrapped again under it: HERE the previous password still opens the copy. Say so; never offer "try again"
     * (the current password is the new one now). The lock screen says it too ([LockedScreen.previousPasswordOpensCopy])
     * until a later change, a recovery or a sign-in wraps the copy again.
     */
    CHANGED_PREVIOUS_OPENS_HERE,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** `POST /account/delete` (the engine's `DeletionOutcome`). */
enum class DeletionResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Deleted. This device's state for the account is wiped, and the app is back at the first screen. */
    DONE,

    /** The typed address is not the account's. */
    EMAIL_MISMATCH,
    WRONG_PASSWORD,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE]: never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED]: the server refused a proof this device made; never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /** The account has two-step sign-in and no code was sent: ask for it. */
    CODE_NEEDED,
    WRONG_CODE,

    /** `409 account_delete_blocked`: the plan now lists what stands in the way. */
    BLOCKED,

    /** The vaults' histories kept moving while the leaves were built, and the retries ran out. Nothing was deleted: try again. */
    STILL_CHANGING,

    /** A shared vault's unverified head is dated more than a day ahead: nothing was signed (FS-R7). */
    FAR_FUTURE(sentence = CopyKey.DELETION_FAR_FUTURE),
    CLOCK_AHEAD(sentence = CopyKey.CLOCK_AHEAD),

    /** `401 credential_changed`. */
    CHANGED_ELSEWHERE,

    /** No answer that says what happened: [DeletionScreen.outcomeUnknown]. */
    OUTCOME_UNKNOWN,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
