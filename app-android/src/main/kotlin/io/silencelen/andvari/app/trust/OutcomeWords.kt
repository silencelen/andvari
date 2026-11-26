package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AskOperatorResult
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.VaultUnlockResult

/**
 * What the app says for a result, a trouble or a state that the shared code gives no sentence for. A person never
 * reads a type's name: each outcome without words has a placeholder of its own here, whose gloss says what happened
 * (it is not proposed wording). `OutcomeWordsTest` walks every result type of the shared code, so a new result fails
 * until it has an entry.
 */
internal object OutcomeWords {

    /** A trouble any intent can have. */
    fun trouble(t: Trouble, retryAfterSeconds: Int): UiText = when (t) {
        Trouble.STALE -> UiText.ph(Placeholder.TROUBLE_STALE)
        Trouble.UNREACHABLE -> UiText.ph(Placeholder.TROUBLE_UNREACHABLE)
        Trouble.RATE_LIMITED -> counted(retryAfterSeconds.coerceAtLeast(1).toLong(), Placeholder.TROUBLE_RATE_LIMITED, Placeholder.TROUBLE_RATE_LIMITED_ONE)
        Trouble.UPDATE_REQUIRED -> UiText.ph(Placeholder.TROUBLE_UPDATE_REQUIRED)
        Trouble.FAILED -> UiText.ph(Placeholder.TROUBLE_FAILED)
    }

    /** An intent's own refusal with no sentence of the design's: its placeholder, or null when the table has none. */
    fun refusal(r: IntentResult): UiText? = (r as? Enum<*>)?.let { refusals[it] }?.let { UiText.outcome(it) }

    /** How a link of this device to another ended. */
    /**
     * A sentence of the shared code that may carry the server's wait in its slot ({0}: a link refused as one of too many
     * requests): filled with the wait where the server named one, empty where it did not. [tooMany] false: the sentence
     * as it is. Null where there is no sentence.
     */
    fun tooManyLine(sentence: io.silencelen.andvari.core.app.CopyKey?, tooMany: Boolean, retryAfterSeconds: Int): UiText? = when {
        sentence == null -> null
        tooMany -> UiText.of(sentence, waitLength(retryAfterSeconds).shown())
        else -> UiText.of(sentence)
    }

    /**
     * A wait the server named, in seconds, as a length of time a person reads: seconds under a minute, else whole minutes
     * under an hour, else whole hours, each rounded up so a wait is never said shorter than the server asked; "a while"
     * where it named none (0). The one place a wait in seconds becomes words of time.
     */
    fun waitLength(seconds: Int): UiText = when {
        seconds <= 0 -> UiText.ph(Placeholder.WAIT_A_WHILE)
        seconds < 60 -> counted(seconds.toLong(), Placeholder.WAIT_SECONDS, Placeholder.WAIT_ONE_SECOND)
        seconds < 3600 -> counted(((seconds + 59) / 60).toLong(), Placeholder.WAIT_MINUTES, Placeholder.WAIT_ONE_MINUTE)
        else -> counted(((seconds.toLong() + 3599) / 3600), Placeholder.WAIT_HOURS, Placeholder.WAIT_ONE_HOUR)
    }

    fun linkDeviceEnd(e: LinkDeviceEnd, retryAfterSeconds: Int = 0): UiText = tooManyLine(e.sentence, e == LinkDeviceEnd.TOO_MANY, retryAfterSeconds) ?: UiText.outcome(
        when (e) {
            LinkDeviceEnd.EXPIRED -> "the link ran out of time; nothing was linked; start again from your other device"
            LinkDeviceEnd.ALREADY_CLAIMED -> "another device picked up this link first; nothing was linked; start again from your other device"
            LinkDeviceEnd.DID_NOT_CHECK_OUT -> "a check of the link failed, so it was stopped; nothing was linked; start again from your other device"
            LinkDeviceEnd.NO_ANSWER -> "the server did not answer; nothing was linked; start again from your other device"
            else -> "the link ended; nothing was linked; start again from your other device"
        },
    )

    /**
     * A shared vault's history state: the design's sentence, the owner's approved words, or its own placeholder. The
     * row's own lines ([logStateLine]) come first where the row carries more (who removed, who to confirm).
     */
    fun vaultLogState(s: VaultLogState): UiText? = s.sentence?.let { UiText.of(it) } ?: when (s) {
        VaultLogState.VERIFIED -> null
        VaultLogState.NOT_CHECKED_YET -> UiText.outcome("this vault's history is not checked on this device yet")
        VaultLogState.FROZEN -> UiText.Plain(Approved.VAULT_HISTORY_FORKED)
        VaultLogState.KEY_MISSING -> UiText.Plain(Approved.VAULT_KEY_MISSING)
        VaultLogState.REMOVED -> UiText.ph(Placeholder.VAULT_REMOVED_UNVERIFIED)
        VaultLogState.CONNECT_FIRST -> UiText.outcome("connect with the person who shared it first; nothing of it is opened until then")
        VaultLogState.CONFIRM_FIRST -> UiText.outcome("confirm the person who shared it on this device first")
        else -> UiText.outcome("this vault's history is in a state this build has no words for")
    }

    /** Every refusal with no sentence of the design's, by the result it is. */
    val refusals: Map<Enum<*>, String> = mapOf(
        // ---- quick unlock and its set-up ----
        QuickEnrolResult.CANCELLED to "cancelled; quick unlock was not turned on",
        QuickEnrolResult.NOT_AVAILABLE to "quick unlock cannot be turned on here now",
        QuickUnlockResult.CANCELLED to "cancelled; use your master password",
        QuickUnlockResult.USE_PASSWORD to "enter your master password: quick unlock needs it this time",
        QuickUnlockResult.TURNED_OFF to "quick unlock is off now; turn it on again in Settings",
        QuickUnlockResult.SERVER_BLOCKED to "this device's record of the server is damaged or gone, so the account was not opened",
        QuickUnlockResult.IDENTITY_FAULT to "this device's keys do not match the account's record; nothing was opened, and quick unlock is off",
        VaultUnlockResult.WRONG_PASSWORD to "the master password is wrong",
        VaultUnlockResult.SERVER_BLOCKED to "this device's record of the server is damaged or gone, so the account was not opened",
        VaultUnlockResult.IDENTITY_FAULT to "this device's keys do not match the account's record; nothing was opened",

        // ---- Settings: two-step sign-in, the password, recovery, deletion ----
        TwoStepResult.WRONG_PASSWORD to "the master password is wrong; nothing changed",
        TwoStepResult.WRONG_CODE to "the code is wrong or was used already; wait for the next one",
        TwoStepResult.NOT_PENDING to "two-step sign-in changed meanwhile; the screen now shows where it stands",
        PasswordChangeResult.WRONG_PASSWORD to "the current master password is wrong; nothing changed",
        PasswordChangeResult.WEAK_PASSWORD to "the new master password is too weak; nothing was sent",
        PasswordChangeResult.CHANGED_ELSEWHERE to "the master password was changed on another device or by a recovery meanwhile; nothing changed here",
        PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE to "changed: the new password is in force for your account, but this phone's copy still opens with the previous one",
        RecoveryChangeResult.WRONG_PASSWORD to "the master password is wrong; nothing changed",
        RecoveryChangeResult.NOT_TICKED to "tick the box first; nothing was sent",
        RecoveryChangeResult.OPERATOR_RECOVERY_UNAVAILABLE to "this server offers no recovery by its operator for this account",
        RecoveryChangeResult.CHANGED_ELSEWHERE to "the master password was changed on another device meanwhile; nothing changed",
        DeletionResult.EMAIL_MISMATCH to "that is not this account's email address; nothing was deleted",
        DeletionResult.WRONG_PASSWORD to "the master password is wrong; nothing was deleted",
        DeletionResult.CODE_NEEDED to "this account has two-step sign-in: type the current code; nothing was deleted",
        DeletionResult.WRONG_CODE to "the two-step code is wrong or was used already; nothing was deleted",
        DeletionResult.BLOCKED to "something now stands in the way (listed above); nothing was deleted",
        DeletionResult.STILL_CHANGING to "your shared vaults kept changing while andvari tried; nothing was deleted; try again",
        DeletionResult.CHANGED_ELSEWHERE to "the master password was changed on another device meanwhile; nothing was deleted",
        DeletionResult.OUTCOME_UNKNOWN to "andvari can't tell yet whether the account was deleted: the answer never came",

        // ---- people, devices ----
        ComparisonResult.LINK_FAILED to "the connection could not be checked",
        ProofResult.WRONG_PASSWORD to "the master password is wrong; nothing was approved",
        ProofResult.BIOMETRICS_NOT_USED to "fingerprint or face cannot be used for this now: enter your master password",
        ProofResult.CHANGED_ELSEWHERE to "the master password was changed on another device meanwhile; nothing was approved",
        ProofResult.NOT_POSSIBLE to "that device is gone already, or it is this one",

        // ---- links someone sent ----
        InviteResult.NOT_AN_INVITE to "this is not a link andvari knows",
        InviteResult.EXPIRED to "this link has expired: ask the person who sent it for a new one",
        InviteResult.ALREADY_USED to "someone used this link already: ask the person who sent it for a new one",
        InviteResult.NOT_FOUND to "this link is unknown, or whoever made it took it back",
        InviteResult.OWN_LINK to "this is a link you made yourself",
        InviteResult.DOES_NOT_CHECK_OUT to "this link did not check out; nothing was sent",
        InviteResult.OTHER_ADDRESS to "this link's server names another address than the link; nothing was sent",
        InviteResult.IDENTITY_CONFLICT to "the link's server is not the one this device knows at that address; nothing was sent",
        InviteResult.SERVER_CHANGED to "the link's server changed since this device last saw it",
        InviteResult.SETUP_ALREADY_DONE to "this server is set up already; the set-up link is no longer needed",
        InviteResult.NOT_USABLE_SIGNED_IN to "this link cannot be used while you are signed in to this server",

        // ---- choosing a server ----
        ServerResult.NOT_SET_UP_YET to "this server is not set up yet",
        ServerResult.IDENTITY_CONFLICT to "this server is not the one this device knows at that address",
        ServerResult.CARD_NOT_ACCEPTED to "this server's identity card was not accepted; nothing was sent",
        ServerResult.OTHER_ADDRESS to "this server's identity card names another address",
        ServerResult.NOT_TAKING_ACCOUNTS to "this server takes no new accounts right now",
        ServerResult.NO_OPERATOR_RECOVERY to "this server offers no recovery by its operator",
        ServerResult.SETUP_LINK_NOT_USABLE to "this set-up link expired, was used, or did not check out",
        ServerResult.SETUP_ALREADY_DONE to "this server is set up already",
        ServerResult.WRONG_PASSWORD to "the master password is wrong; nothing was sent",
        ServerResult.SERVER_CHANGED to "this server changed since this device last saw it",

        // ---- sign-up ----
        SignUpStartResult.INVALID_EMAIL to "that is not an email address",
        SignUpStartResult.EMAIL_DOMAIN_NOT_ACCEPTED to "this server takes no addresses of that domain",
        SignUpStartResult.AGE_CONFIRMATION_NEEDED to "confirm that you are 13 or older",
        SignUpStartResult.SIGNUP_CLOSED to "sign-up is closed on this server",
        SignUpStartResult.SIGNUP_FULL to "this server takes no more accounts",
        SignUpStartResult.ANOTHER_ACCOUNT_KEPT to "this phone keeps another account that its server signed out: sign out of it first; nothing was sent",
        CodeResult.WRONG_CODE to "that code is wrong, expired or used up: ask for another",
        CreateAccountResult.WEAK_PASSWORD to "the master password is too weak; nothing was sent",
        CreateAccountResult.INVALID_EMAIL to "that is not an email address",
        CreateAccountResult.EMAIL_TAKEN to "an account with this address exists already: sign in",
        CreateAccountResult.EMAIL_NOT_THE_LINKS to "this link was made for another email address",
        CreateAccountResult.AGE_CONFIRMATION_NEEDED to "confirm that you are 13 or older",
        CreateAccountResult.SIGNUP_CLOSED to "sign-up is closed on this server",
        CreateAccountResult.SIGNUP_FULL to "this server takes no more accounts",
        CreateAccountResult.DAILY_LIMIT to "this server takes no more new accounts today: try again tomorrow",
        CreateAccountResult.VERIFICATION_EXPIRED to "the confirmed address ran out of time: start again",
        CreateAccountResult.LINK_GONE to "the link expired, was used or was taken back meanwhile",
        CreateAccountResult.SERVER_NOT_SET_UP to "this server is not set up yet",
        CreateAccountResult.SETUP_ALREADY_DONE to "this server already has its operator",
        CreateAccountResult.OPERATOR_RECOVERY_UNAVAILABLE to "this server offers no recovery by its operator",
        CreateAccountResult.MAY_EXIST to "the account may exist: sign in",
        CreateAccountResult.ANOTHER_ACCOUNT_KEPT to "this phone keeps another account that its server signed out: sign out of it first; no account was made",

        // ---- sign-in, linking this device ----
        SignInAnswer.CODE_NEEDED to "type the code from your authenticator app",
        SignInAnswer.WRONG to "the email address, the master password or the code is wrong",
        SignInAnswer.LINK_REQUIRED to "this account takes new devices only when one of its devices links them",
        SignInAnswer.OPERATOR_NEEDS_COMPUTER to "the operator account signs in only on a computer",
        SignInAnswer.TRUST_GATE_FIRST to "confirm this server first",
        SignInAnswer.ANOTHER_ACCOUNT_KEPT to "this phone keeps another account that its server signed out: sign out of it first",
        DeviceLinkScanResult.NOT_A_DEVICE_LINK to "this is not a link from your other device",
        DeviceLinkScanResult.IDENTITY_CONFLICT to "the link's server is not the one this device knows at that address",
        DeviceLinkScanResult.SERVER_CHANGED to "the link's server changed since this device last saw it",
        DeviceLinkScanResult.CARD_NOT_ACCEPTED to "the link's server's identity card was not accepted; nothing was sent",
        DeviceLinkScanResult.OTHER_ADDRESS to "the link's server names another address; start again from your other device",
        LinkPasswordResult.CODE_NEEDED to "type the code from your authenticator app",
        LinkPasswordResult.WRONG to "the master password or the code is wrong",
        LinkPasswordResult.ENDED to "the link ended",
        LinkPasswordResult.OPERATOR_NEEDS_COMPUTER to "the operator account signs in only on a computer",
        LinkPasswordResult.ANOTHER_ACCOUNT_KEPT to "this phone keeps another account that its server signed out: sign out of it first",

        // ---- recovery ----
        KitScanResult.NOT_A_KIT to "this is not a recovery kit",
        KitScanResult.INVALID_EMAIL to "that is not an email address; nothing was sent",
        KitScanResult.IDENTITY_CONFLICT to "the kit's server is not the one this device knows at that address",
        KitScanResult.SERVER_CHANGED to "the kit's server changed since this device last saw it",
        KitScanResult.CARD_NOT_ACCEPTED to "the kit's server's identity card was not accepted; nothing was sent",
        KitScanResult.OTHER_ADDRESS to "the kit's server names another address",
        KitRecoverResult.KIT_NOT_ACCEPTED to "this kit was not accepted: it may be another account's, or a newer kit replaced it",
        KitRecoverResult.OPERATOR_NEEDS_COMPUTER to "this is the operator account's kit: recover it on a computer; nothing was changed",
        KitRecoverResult.ANOTHER_ACCOUNT_KEPT to "this phone keeps another account that its server signed out: sign out of it first; nothing was changed",
        ReplacePasswordResult.WEAK_PASSWORD to "the new master password is too weak; nothing was sent",
        ReplacePasswordResult.TOO_LATE to "the recovery ran out of time or was used: start again",
        ReplacePasswordResult.ACCOUNT_DISABLED to "this account is disabled: the operator turns it on again first",
        ReplacePasswordResult.MAY_HAVE_WORKED to "no answer came: the new password may be in force; sign in with it",
        ReplacePasswordResult.OPERATOR_NEEDS_COMPUTER to "the new password is set, but the operator account signs in only on a computer",
        AskOperatorResult.INVALID_EMAIL to "that is not an email address",

        // ---- the server moved; the kit ----
        MoveResult.ALREADY_PINNED_THERE to "this device already knows a server at the new address; nothing moved",
        MoveResult.NOT_FINISHED to "the move stands, but this device's data could not be moved yet: try again",
        MoveResult.MOVED_NOT_VERIFIED to "this device followed the move, but the new address did not check out",
        KitConfirmResult.MISMATCH to "a group does not match your kit",
        KitConfirmResult.REPLACED to "another device made a newer kit meanwhile, so this one no longer works",
        KitConfirmResult.WRONG_PASSWORD to "the master password is wrong; no kit was made",

        // ---- links this account makes, and answering one ----
        LinkCreateResult.NOT_ALLOWED to "this account may not make this link here",
        LinkCreateResult.TOO_MANY_OPEN_LINKS to "you have as many open links as the server allows: take one back first",
        LinkCreateResult.TOO_MANY_CONTACTS to "you are connected with as many people as an account can be",
        LinkCreateResult.BAD_LIFETIME to "a link cannot last that long",
        ConnectResult.ALREADY_USED to "someone answered this link first",
        ConnectResult.EXPIRED to "this link has expired",
        ConnectResult.TOO_MANY_CONTACTS to "you are connected with as many people as an account can be",

        // ---- the operator's panel (the desktop app and the command-line tool; never a phone screen) ----
        OperatorResult.WRONG_PASSWORD to "the master password is wrong",
        OperatorResult.NOT_THE_OPERATOR to "this account is not the server's operator",
        OperatorResult.NO_SUCH_ACCOUNT to "there is no such account",
        OperatorResult.CANNOT_TARGET_SELF to "the operator cannot do this to their own account",
        OperatorResult.NOT_DISABLED_LONG_ENOUGH to "only an account disabled for 30 days can be deleted",
        OperatorResult.BLOCKED_BY_SHARED_VAULT to "the account owns a shared vault that others hold",
        OperatorResult.NO_SUCH_DEVICE to "there is no such device",
        OperatorResult.NOT_TIGHTER to "sign-up can only be made stricter here",
        OperatorResult.BAD_POLICY to "these settings are below what the server allows",
        OperatorResult.NO_ESCROW to "this account did not choose recovery by the operator",
        OperatorResult.REQUEST_NOT_READY to "this request is still waiting, was cancelled, or is gone",
        OperatorResult.ANSWER_EMPTY to "there is no answer in what was pasted",
        OperatorResult.ANSWER_IS_THE_COPY to "this is the recovery copy, not the answer the tool wrote",
        OperatorResult.ANSWER_NOT_AN_ANSWER to "this is not an answer from the recovery tool",
        OperatorResult.ANSWER_BARE to "only part of the answer was pasted: the whole last line is needed",
        OperatorResult.ANSWER_OTHER_REQUEST to "this answer was made for another request",
        OperatorResult.ANSWER_OTHER_REQUEST_KEY to "this answer was made for another request",
        OperatorResult.ANSWER_CUT_SHORT to "part of the answer is missing",
        OperatorResult.ANSWER_TOO_LONG to "the answer is longer than it can be",
        OperatorResult.CARD_MOVED_ON to "another device changed the server's identity card meanwhile: look again and retry",
        OperatorResult.CARD_REFUSED to "the server refused the identity card",
        OperatorResult.ROTATION_REFUSED to "the change of the recovery key did not check out",
        OperatorResult.SETUP_ALREADY_DONE to "there is nothing to finish: the server is set up",

        // ---- shared vaults ----
        VaultActionResult.NEEDS_UNCOMPARED_WARNING to "you have not compared codes with this person yet; nothing was shared",
        VaultActionResult.NOT_OWNER to "only the vault's owner can do this",
        VaultActionResult.NOT_ALLOWED to "the vault's rules do not allow this now; nothing was changed",
        VaultActionResult.READ_ONLY to "this vault is read-only on this device; nothing was changed",
        VaultActionResult.CHANGED_MEANWHILE to "the vault changed meanwhile; nothing was changed: try again",
        VaultActionResult.OFFER_EXPIRED to "the offer has expired",
        VaultActionResult.NOT_CONNECTED to "the server does not know you two as connected",
        VaultActionResult.NOT_A_CONTACT_HERE to "this person is not confirmed on this device",
        VaultActionResult.MEMBER_LIMIT to "this person is in as many shared vaults as an account can be",
    )
}
