package io.silencelen.andvari.core.client.deletion

import io.silencelen.andvari.core.model.wire.AccountDeleteBlocker

/**
 * Account deletion with leaves (spec 03 §13, design §3.11). The engine builds one `leave` per preview
 * membership at the SERVED head with `at = max(device clock, head.at)`, refusing a `head.at` more than
 * one day ahead of the device clock from an unverified head (FS-R7), and treats every unclear answer as
 * an unknown outcome.
 */

/** The preview, ready to show before the master password is asked. */
data class DeletionPreview(
    val blockers: List<AccountDeleteBlocker>,
    val deletedVaults: List<String>,
    val leftVaults: List<String>,
    val leavesNeeded: Int,
    val totpRequired: Boolean,
) {
    /** A blocker of a kind this build does not know is shown generically and never passed. */
    val canProceed: Boolean get() = blockers.isEmpty()
}

sealed class DeletionOutcome {
    /** Deleted: the engine wiped this device's state for the account, including the self-identity records. */
    data class Deleted(val deletedAt: Long) : DeletionOutcome()
    data class Blocked(val blockers: List<AccountDeleteBlocker>) : DeletionOutcome()
    /** Some heads moved: refetch the preview and retry. */
    data class LogStale(val vaultIds: List<String>) : DeletionOutcome()
    /** "One of your shared vaults reports a time far in the future. Try again later." Nothing signed. */
    data object FutureHead : DeletionOutcome()
    /** `400 at_ahead`: "Your device's clock is ahead." */
    data object ClockAhead : DeletionOutcome()
    data object TotpNeeded : DeletionOutcome()
    data object BadTotp : DeletionOutcome()
    /**
     * The password typed here did not open this device's own wrap: nothing was sent. The server's `403 reauth_failed` is
     * [Refused] with [io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED].
     */
    data object WrongPassword : DeletionOutcome()
    data object EmailMismatch : DeletionOutcome()
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : DeletionOutcome()
    /** No answer, a 5xx or a non-JSON reply: the deletion may have committed. Offer to check (the preview). */
    data object Unknown : DeletionOutcome()

    /** The preview could not be fetched before anything was signed or sent: nothing happened. */
    data object Unreachable : DeletionOutcome()

    /** The re-authentication gate refused at the entry (no session here, or the origin is forked or damaged): nothing sent. */
    data object ReauthRefused : DeletionOutcome()
}

interface AccountDeletion {
    suspend fun preview(): DeletionPreview?

    /** Delete with the typed address, the master password (fenced reauth) and the code when needed. */
    suspend fun delete(typedEmail: String, password: CharArray, totp: String?): DeletionOutcome
}
