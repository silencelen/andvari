package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AccountDeleteBlockedException
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.ReauthFailedException
import io.silencelen.andvari.core.client.ReauthStaleSessionException
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.session.BoundedOps
import io.silencelen.andvari.core.client.session.runBounded
import io.silencelen.andvari.core.crypto.CryptoUnavailableException
import io.silencelen.andvari.core.model.AccountDeleteBlocker
import io.silencelen.andvari.core.model.AccountDeletePreview
import io.silencelen.andvari.core.model.AccountDeleteRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * What deleting the account says (the web app's sentences, spec 03 §13), the same on every client but for the device's
 * name ([device]: "this iPhone", "this phone", "this computer").
 */
class DeletionCopy(private val device: String) {
    companion object {
        /** The iOS app's words. */
        val IPHONE = DeletionCopy("this iPhone")

        /** The Android app's words. */
        val PHONE = DeletionCopy("this phone")

        /** The desktop app's words. */
        val COMPUTER = DeletionCopy("this computer")
    }

    val UNNAMED_VAULT = "a vault $device can't name"
    val EMAIL_MISMATCH = "That isn't this account's email address."
    val PASSWORD_REQUIRED = "Type your master password."
    val CODE_REQUIRED = "Type the code from your authenticator app."
    val BAD_CODE = "That code is wrong or was already used. Wait for the next one and try again."
    val BLOCKED = "The server didn't delete your account: something below stands in the way. Nothing was deleted."
    val PUBLIC_ORIGIN = "Deleting an account isn't available from this emergency address. Use your household's usual andvari address."
    val TOTP_ENROLL_FIRST = "This server requires two-step sign-in: turn it on first, then delete the account."
    val CREDENTIAL_CHANGED =
        "Your password was changed, or $device was signed out, while deleting: nothing was deleted. Sign in again and try again."
    val SESSION_ENDED = "Your session ended: nothing was deleted. Sign in again and try again."
    val TOO_MANY = "Too many attempts. Wait a while, then try again."
    val FAILED = "Something went wrong, and your account was not deleted. Try again."
    val OUTCOME_UNKNOWN =
        "The server didn't answer in a way that says whether your account was deleted: it may have been. Check below, or sign in again: if your account is gone, the deletion went through."
    val NOT_DELETED_AFTER_CHECK = "Your account is still here: it was not deleted. You can try again."
    /**
     * The session ended after an unknown outcome, by something this device cannot tie to the deletion (a 401 on the check
     * or on a retry): an admin's revocation, disable or recovery and a password change elsewhere end a session too, so the
     * account may still exist, and nothing offers to forget it (spec 03 §13). The web client's words.
     */
    val SESSION_ENDED_OUTCOME_UNKNOWN =
        "Your session ended, so andvari can't tell whether your account was deleted. Sign in to find out: if your account still exists, you can."
    val PREVIEW_FAILED = "Couldn't check what deleting your account would do. Try again."

    // The screen's own words, as the iOS app has them (Settings › Delete account).
    /** Settings' entry and its line. */
    val ENTRY = "Delete account…"
    val ENTRY_ABOUT = "Deletes your account and everything only you hold, on every device. It can't be undone."
    val TITLE = "Delete account"
    val GOES_HEADING = "What goes for good"
    val BLOCKERS_HEADING = "First"
    val BLOCKERS_FOOTER = "The account can't be deleted while any of these stands."
    val CHECK_AGAIN = "Check again"
    val CONFIRM_HEADING = "Confirm it's you"
    val EMAIL_LABEL = "Email address"
    val PASSWORD_LABEL = "Master password"
    val CODE_LABEL = "Code from your authenticator app"
    val DELETE_BUTTON = "Delete account…"
    val CONFIRM_TITLE = "Delete your account for good?"
    val CONFIRM_BODY = "This can't be undone: nobody, an admin of your server included, can bring the account back."
    val CONFIRM_BUTTON = "Delete account"
    val CHECK_OUTCOME = "Check whether it went through"
    val FORGET_BUTTON = "Forget this account"
    val SIGN_IN_TO_CHECK = "Sign in to check"

    fun confirmFooter(email: String): String =
        "Type $email to confirm. Your master password is checked on $device before anything is sent."

    private fun people(n: Int): String = if (n == 1) "1 other person" else "$n other people"

    /** One sentence per blocker; a kind this version does not know is listed as one it cannot explain, never dropped. */
    fun blocker(kind: String, vault: String?, others: Int): String = when (kind) {
        "shared_vault" -> {
            val verb = if (others == 1) "still uses it" else "still use it"
            if (vault != null) "You own “$vault”, and ${people(others)} $verb. Delete it, or make one of them its owner, first (Shared vaults)."
            else "You own a shared vault that ${people(others)} $verb. Delete it, or make one of them its owner, first (Shared vaults)."
        }
        "last_admin" ->
            "You're the only admin of this andvari server, and ${people(others)} ${if (others == 1) "has an account" else "have accounts"} on it. " +
                "andvari can't make an existing account an admin: an account is an admin only if it was invited as one. Invite a new admin first, from the web app's Administration, then come back."
        else -> "The server reports something else that stops this account being deleted, which this version of andvari can't explain. Update andvari, or ask whoever runs your server."
    }

    private fun quoted(names: List<String>): String {
        val q = names.map { "“$it”" }
        return if (q.size <= 1) q.joinToString("") else q.dropLast(1).joinToString(", ") + " and " + q.last()
    }

    /** What goes for good: the account, its personal vault and the vaults only it holds (by name), the recovery paths. */
    fun deletes(personal: Boolean, onlyMine: List<String?>): List<String> {
        val named = onlyMine.filterNotNull()
        val unnamed = onlyMine.size - named.size
        val vaults = buildList {
            if (personal) add("your Personal vault")
            if (named.isNotEmpty()) add((if (named.size == 1) "the vault" else "the vaults") + " only you use, " + quoted(named))
            if (unnamed > 0) add(if (unnamed == 1) "1 other vault only you hold" else "$unnamed other vaults only you hold")
        }
        return buildList {
            add("Your account, and its sign-in on every device.")
            if (vaults.isNotEmpty()) add(joinAnd(vaults).replaceFirstChar { it.uppercase() } + ": every item, file and earlier version in them.")
            add("Your recovery phrase and your household recovery backup: nobody, an admin included, can bring the account back.")
            add("Invites you sent that nobody has used yet.")
        }
    }

    /** The shared vaults the account leaves; what it saved there stays for the people who still use them. */
    fun leaves(vaults: List<String?>): List<String> {
        if (vaults.isEmpty()) return emptyList()
        val named = vaults.filterNotNull()
        val unnamed = vaults.size - named.size
        val what = buildList {
            if (named.isNotEmpty()) add(quoted(named))
            if (unnamed > 0) add(if (unnamed == 1) "1 other shared vault" else "$unnamed other shared vaults")
        }
        return listOf("You'll leave ${joinAnd(what)}. What you saved there stays for the people who still use ${if (vaults.size == 1) "it" else "them"}.")
    }

    private fun joinAnd(parts: List<String>): String =
        if (parts.size <= 1) parts.joinToString("") else parts.dropLast(1).joinToString(", ") + " and " + parts.last()

    fun deleted(email: String): String = "The account $email was deleted, with everything $device kept for it."

    /**
     * The session ended WHILE the deletion was being sent, and its answer never came: that end was most likely the deletion's
     * own. The screen offers to forget the account on this device (the same wipe as after a deletion) or to sign in and check.
     */
    val MOST_LIKELY_DELETED =
        "Your session ended while your account was being deleted, and the server's answer never arrived: the deletion most likely went through. You can make $device forget the account: its sign-in, its offline copy and everything else it kept for it. Or sign in to check: if your account still exists, you can."

    /** After the person chose to forget an account whose deletion's answer was lost. */
    val FORGOTTEN =
        "$device forgot the account. It no longer signed in, so its deletion most likely went through; if it still exists after all, sign in again."
            .replaceFirstChar { it.uppercase() }

    /** A request whose answer says nothing about what happened: no answer, a server error, or a reply not the server's. */
    fun outcomeUnknown(t: Throwable): Boolean = when {
        t is ApiException -> t.status >= 500 || t.code.startsWith("http_")
        else -> t !is ReauthFailedException && t !is ReauthStaleSessionException && t !is KdfPolicyViolationException && t !is CryptoUnavailableException
    }

    fun forPreview(t: Throwable): String = when {
        t is ApiException && t.code == "account_delete_public_disabled" -> PUBLIC_ORIGIN
        t is ApiException && t.code == "totp_enrollment_required" -> TOTP_ENROLL_FIRST
        t is ApiException -> HouseholdCopy.forError(t).takeIf { t.status == 401 || t.status == 429 || t.status == 426 } ?: PREVIEW_FAILED
        else -> HouseholdCopy.forError(t)
    }

    /** One sentence per refusal of the deletion (or of the local password proof before it): nothing was deleted. */
    fun forError(t: Throwable): String = when {
        t is ReauthFailedException -> HouseholdCopy.REAUTH_FAILED
        t is ReauthStaleSessionException -> HouseholdCopy.REAUTH_STALE_SESSION
        t is ApiException -> when (t.code) {
            "reauth_failed" -> HouseholdCopy.REAUTH_FAILED
            "totp_code_required" -> CODE_REQUIRED
            "bad_totp_code" -> BAD_CODE
            "confirm_email_mismatch" -> EMAIL_MISMATCH
            "account_delete_public_disabled" -> PUBLIC_ORIGIN
            "totp_enrollment_required" -> TOTP_ENROLL_FIRST
            "credential_changed" -> CREDENTIAL_CHANGED
            "rate_limited" -> TOO_MANY
            else -> if (t.status == 401) SESSION_ENDED else if (t is UpgradeRequiredException) HouseholdCopy.forError(t) else FAILED
        }
        else -> HouseholdCopy.forError(t)
    }

    /** After an answer that said nothing, a refused session no longer says "nothing was deleted": the account may be gone. */
    fun forErrorAfterUnknown(t: Throwable): String =
        if (t is ApiException && t.status == 401 && t.code != "credential_changed") SESSION_ENDED_OUTCOME_UNKNOWN else forError(t)
}

/** How a deletion request ended (spec 03 §13), for the app that sent it. */
sealed class DeletionOutcome {
    /** The server deleted the account: the app forgets everything this device kept for it, and lands signed out. */
    object Deleted : DeletionOutcome()

    /** Refused for what stands in the way now, in place of the preview's: nothing was deleted. */
    class Blocked(val blockers: List<AccountDeleteBlocker>) : DeletionOutcome()

    /** The answer says nothing about what happened (no answer, a server error, a reply not the server's): it may be done. */
    object Unknown : DeletionOutcome()

    /**
     * Refused, or never sent (the master password did not prove on this device): nothing was deleted. [codeNowRequired]: the
     * account has a two-step code the preview did not ask for, and the field shows now. A 426 ([UpgradeRequiredException])
     * is the app's update screen, not a sentence.
     */
    class Refused(val cause: Throwable, val codeNowRequired: Boolean) : DeletionOutcome()
}

/** What asking again after an unknown outcome found. */
sealed class DeletionCheck {
    /** The server answered this session: the account is still here, and this is what deleting it would do now. */
    class StillHere(val preview: AccountDeletePreview) : DeletionCheck()

    /** The session was refused: a revocation does that too, so the account may still exist. */
    object SessionEnded : DeletionCheck()

    /** No answer again. */
    object Unreachable : DeletionCheck()
}

/**
 * The steps of deleting the account that every app takes the same way (spec 03 §13 client duties; the web client's
 * Settings › Delete account): what the preview says, what is checked before anything is sent, the request with a fresh
 * master-password proof derived through the session's fenced reauth, and what its answer means. Each app keeps its own
 * session and screen, and forgets what its device kept once the server says the account is gone.
 */
class AccountDeletionFlow(val copy: DeletionCopy) {
    /** What the server says deleting would do now. */
    @Throws(CancellationException::class)
    suspend fun preview(api: AndvariApi): AccountDeletePreview = runBounded(BoundedOps.FLAT_MS) { api.accountDeletePreview() }

    /**
     * The preview in words. [personalVaultId] is the account's personal vault; [nameOf] a vault's name as this device knows
     * it (null: one it can't name). At most [LISTED] vaults and blockers each; a blocker of a kind this version does not
     * know is listed as one it can't explain, never dropped. [blockers]: a refusal's, in place of the preview's.
     */
    fun previewView(
        p: AccountDeletePreview,
        personalVaultId: String,
        nameOf: (String) -> String?,
        blockers: List<AccountDeleteBlocker> = p.blockers,
    ): AccountDeletionPreviewView {
        val name = { id: String? -> id?.let(nameOf) }
        return AccountDeletionPreviewView(
            deleted = copy.deletes(p.deletedVaults.contains(personalVaultId), p.deletedVaults.filter { it != personalVaultId }.take(LISTED).map(name)),
            left = copy.leaves(p.leftVaults.take(LISTED).map(name)),
            blockers = blockers.take(LISTED).map { copy.blocker(it.kind, name(it.vaultId), it.others) },
            totpRequired = p.totpRequired,
        )
    }

    /** Why what was typed can't be sent (the address must be the account's), or null when it can. Nothing is sent before. */
    fun refusal(typedEmail: String, accountEmail: String, password: String, code: String, totpRequired: Boolean): String? = when {
        typedEmail.trim().lowercase() != accountEmail.trim().lowercase() -> copy.EMAIL_MISMATCH
        password.isEmpty() -> copy.PASSWORD_REQUIRED
        totpRequired && digits(code).isEmpty() -> copy.CODE_REQUIRED
        else -> null
    }

    /**
     * Delete the account of [account]'s session on [api]. The master [password] is proved first, on this device, against the
     * keys the server serves now (so a wrong one is caught here and never sent); then the request goes with the address as
     * typed and the [code]'s digits. Call [refusal] first.
     */
    @Throws(CancellationException::class)
    suspend fun delete(api: AndvariApi, account: Account, typedEmail: String, password: String, code: String): DeletionOutcome {
        val proof = try {
            val keys = runBounded(BoundedOps.FLAT_MS) { api.accountKeys() }
            withContext(Dispatchers.Default) { account.reauthAuthKey(password, keys) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return DeletionOutcome.Refused(t, codeNowRequired = false)
        }
        val totp = digits(code).ifEmpty { null }
        try {
            runBounded(BoundedOps.FLAT_MS) { api.deleteAccount(AccountDeleteRequest(confirmEmail = typedEmail.trim(), currentAuthKey = proof, totp = totp)) }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            if (t is AccountDeleteBlockedException) return DeletionOutcome.Blocked(t.blockers)
            if (copy.outcomeUnknown(t)) return DeletionOutcome.Unknown
            return DeletionOutcome.Refused(t, codeNowRequired = t is ApiException && t.code == "totp_code_required")
        }
        return DeletionOutcome.Deleted
    }

    /** After an unknown outcome: ask for the preview again. An answer means the account is still here. */
    @Throws(CancellationException::class)
    suspend fun check(api: AndvariApi): DeletionCheck = try {
        DeletionCheck.StillHere(preview(api))
    } catch (t: Throwable) {
        if (t is CancellationException) throw t
        if (t is ApiException && t.status == 401) DeletionCheck.SessionEnded else DeletionCheck.Unreachable
    }

    /** The sentence for a refusal: after an unknown outcome a refused session no longer says "nothing was deleted". */
    fun refusedMessage(t: Throwable, afterUnknown: Boolean): String = if (afterUnknown) copy.forErrorAfterUnknown(t) else copy.forError(t)

    /** The sentence for a check that found no answer, or a refused session. */
    fun checkMessage(c: DeletionCheck): String? = when (c) {
        is DeletionCheck.StillHere -> null
        DeletionCheck.SessionEnded -> copy.SESSION_ENDED_OUTCOME_UNKNOWN
        DeletionCheck.Unreachable -> copy.OUTCOME_UNKNOWN
    }

    private fun digits(code: String): String = code.filter { it.isDigit() }

    companion object {
        /** At most this many of a preview's vaults and blockers are listed. */
        const val LISTED = 50
    }
}

