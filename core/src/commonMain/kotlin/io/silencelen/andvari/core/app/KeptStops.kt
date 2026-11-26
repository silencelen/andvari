package io.silencelen.andvari.core.app

/**
 * The one way out of a stop for which something kept on this device stands in the way (section "one cause, one way
 * out"): the act a screen offers beside the stop's sentence, wherever that stop is said and wherever its sentence names
 * the act. Each act goes through its usual counts and confirmations.
 */
enum class KeptWayOut {
    /**
     * Another account is kept here: its sign-out ([AppApi.signOut], behind the screen's usual sign-out warning with its
     * count of changes not sent). In the journey it can be called while [AppSnapshot.keptSignedOut] is set.
     */
    SIGN_OUT_KEPT_ACCOUNT,

    /**
     * This device holds its server's operator account: its removal from this device ([EntryScreen.FirstRun.heldAsOperator],
     * [EntryApi.removeHeldOperatorAccount], behind the first screen's own confirmation). Never a sign-out.
     */
    REMOVE_HELD_OPERATOR_ACCOUNT,

    /**
     * What stands in the way is this device's own copy of the SAME account (its keys are not the ones the server gives, or
     * it is damaged): the removal of that copy ([AppApi.signOut] of it, which says first how many changes made here were
     * not sent, or that it cannot tell, and asks a second time). Never "sign out of that account", as if it were another.
     */
    REMOVE_THIS_COPY,
}

/** Which way out a result offers, and the reason line said once a kit shown with a refusal is gone or typed back. */
object KeptStops {
    private val removeCopy: Set<IntentResult> = setOf(
        ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED,
        ReplacePasswordResult.KEPT_COPY_DAMAGED, ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED,
        KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE, KitRecoverResult.KEPT_COPY_DAMAGED,
        SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE, SignInAnswer.KEPT_COPY_DAMAGED,
        LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, LinkPasswordResult.KEPT_COPY_DAMAGED,
    )

    private val signOutKept: Set<IntentResult> = setOf(
        ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED,
        CreateAccountResult.ANOTHER_ACCOUNT_KEPT, CreateAccountResult.ACCOUNT_MADE_NOT_KEPT,
        KitRecoverResult.ANOTHER_ACCOUNT_KEPT, KitScanResult.ANOTHER_ACCOUNT_KEPT,
        SignInAnswer.ANOTHER_ACCOUNT_KEPT, SignUpStartResult.ANOTHER_ACCOUNT_KEPT,
        LinkPasswordResult.ANOTHER_ACCOUNT_KEPT, LinkPasswordResult.ANOTHER_SESSION_KEPT,
    )

    private val removeHeld: Set<IntentResult> = setOf(
        ReplacePasswordResult.OPERATOR_ACCOUNT_HELD, ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED,
        CreateAccountResult.OPERATOR_ACCOUNT_HELD, CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD,
        KitRecoverResult.OPERATOR_ACCOUNT_HELD, KitScanResult.OPERATOR_ACCOUNT_HELD,
        SignInAnswer.OPERATOR_ACCOUNT_HELD, SignUpStartResult.OPERATOR_ACCOUNT_HELD,
        LinkPasswordResult.OPERATOR_ACCOUNT_HELD,
    )

    /** As [wayOut], for how a device link ended on the new device ([EntryScreen.LinkDeviceEnded]). */
    fun linkWayOut(end: LinkDeviceEnd): KeptWayOut? = when (end) {
        LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE, LinkDeviceEnd.KEPT_COPY_DAMAGED -> KeptWayOut.REMOVE_THIS_COPY
        LinkDeviceEnd.ANOTHER_SESSION_KEPT -> KeptWayOut.SIGN_OUT_KEPT_ACCOUNT
        LinkDeviceEnd.OPERATOR_ACCOUNT_HELD -> KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT
        else -> null
    }

    /**
     * The act [result] offers beside its sentence; null where nothing kept here stands in the way (the identity fault, an
     * account that is not the kept one, a reason not known: none of them is a sign-out or a removal).
     */
    fun wayOut(result: IntentResult): KeptWayOut? = when (result) {
        in removeCopy -> KeptWayOut.REMOVE_THIS_COPY
        in signOutKept -> KeptWayOut.SIGN_OUT_KEPT_ACCOUNT
        in removeHeld -> KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT
        else -> null
    }

    /**
     * For a result that came with a kit shown with a refusal ([KitScreen.notKeptLine]): the line said on the first screen
     * once that kit was typed back, in place of the result's own sentence, which tells the person to save the kit. One
     * line per reason, none of them about the kit; null for every other result.
     */
    fun lineWithoutKit(result: IntentResult): CopyKey? =
        if (result in kitResults) whyFromKitLine(KeeperReasons.kitLine(result)) else null

    /** The results of a commit (a recovery's, a registration's) that come with a kit shown with a refusal. */
    private val kitResults: Set<IntentResult> = setOf(
        ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, ReplacePasswordResult.IDENTITY_FAULT_COMMITTED,
        ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED, ReplacePasswordResult.COMMITTED_NOT_KEPT,
        ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED, ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED,
        CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD, CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT,
    )

    /** The reason line for a kit's own refusal line [kitLine]; null for a key that is not one. */
    internal fun whyFromKitLine(kitLine: CopyKey): CopyKey? = when (kitLine) {
        CopyKey.KIT_RECOVERED_NOT_KEPT, CopyKey.KIT_REGISTERED_NOT_KEPT -> CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT
        CopyKey.RECOVERY_COMMITTED_OPERATOR_ACCOUNT_HELD, CopyKey.KIT_REGISTERED_OPERATOR_ACCOUNT_HELD -> CopyKey.KIT_NOT_HERE_WHY_OPERATOR_HELD
        CopyKey.RECOVERY_COMMITTED_IDENTITY_FAULT, CopyKey.KIT_REGISTERED_IDENTITY_FAULT -> CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT
        CopyKey.RECOVERY_COMMITTED_SERVER_KEYS_NOT_KNOWN_HERE -> CopyKey.KIT_NOT_HERE_WHY_SERVER_KEYS
        CopyKey.RECOVERY_COMMITTED_KEPT_COPY_DAMAGED -> CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED
        CopyKey.RECOVERY_COMMITTED_NOT_KEPT, CopyKey.KIT_NOT_KEPT_HERE -> CopyKey.KIT_NOT_HERE_WHY_NOT_OPENED
        else -> null
    }

    /** The way out for a kit's own refusal line [kitLine]. */
    internal fun wayOutFromKitLine(kitLine: CopyKey): KeptWayOut? = when (whyFromKitLine(kitLine)) {
        CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT -> KeptWayOut.SIGN_OUT_KEPT_ACCOUNT
        CopyKey.KIT_NOT_HERE_WHY_OPERATOR_HELD -> KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT
        CopyKey.KIT_NOT_HERE_WHY_SERVER_KEYS, CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED -> KeptWayOut.REMOVE_THIS_COPY
        else -> null
    }
}
