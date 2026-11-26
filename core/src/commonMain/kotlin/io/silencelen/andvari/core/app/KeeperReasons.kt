package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.onboard.AccountOpen
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.session.Establishing

/**
 * The session keeper's own reasons for refusing a session, as the screens say them: one place, read by the engine's
 * entry and by the fake, so that both say each reason as what it is. A reason always comes from the keeper (handed up by
 * the flow that asked it), never from a guess over addresses.
 */
internal object KeeperReasons {
    /**
     * The committed results whose refusal stands only while another account (or its server's operator account) is kept
     * here: once none is kept, this device can take the account (the engine's `KitMark.whileAnotherKept`).
     */
    val WHILE_ANOTHER_KEPT: Set<IntentResult> = setOf(
        ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED,
        CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD,
    )

    /**
     * A recovery's commit the server took, whose session the keeper refused for [reason]: every answer says what is so after
     * a commit (the new master password is in force, the old kit no longer works), and the new kit is on show with it.
     */
    fun committedRecovery(reason: String): ReplacePasswordResult = when (reason) {
        Establishing.ANOTHER_SESSION_KEPT -> ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT
        AccountOpen.SELF_IDENTITY_MISMATCH -> ReplacePasswordResult.IDENTITY_FAULT_COMMITTED
        WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE -> ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED
        Establishing.OPERATOR_ACCOUNT_HELD -> ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED
        Establishing.KEPT_COPY_DAMAGED -> ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED
        else -> ReplacePasswordResult.COMMITTED_NOT_KEPT
    }

    /**
     * A registration the server took (the account exists, with the kit on show), whose session the keeper refused for
     * [reason]. A new account's own user id can be kept here only if the server lied about it, so the keeper's reasons
     * about a kept copy of the SAME account (its keys, a damaged copy) and any reason not known here are said as the
     * identity fault: the safer reading, under which this device uses nothing of the account.
     */
    fun committedRegistration(reason: String): CreateAccountResult = when (reason) {
        Establishing.ANOTHER_SESSION_KEPT -> CreateAccountResult.ACCOUNT_MADE_NOT_KEPT
        Establishing.OPERATOR_ACCOUNT_HELD -> CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD
        else -> CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT
    }

    /**
     * A recovery's commit stopped BEFORE it was sent, for the keeper's reason (or a flow's own check that says the same)
     * [reason]: nothing was committed. Null for a reason that is not the keeper's.
     */
    fun beforeCommit(reason: String): ReplacePasswordResult? = when (reason) {
        Establishing.ANOTHER_SESSION_KEPT -> ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED
        AccountOpen.SELF_IDENTITY_MISMATCH -> ReplacePasswordResult.IDENTITY_FAULT
        WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE -> ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE
        Establishing.OPERATOR_ACCOUNT_HELD -> ReplacePasswordResult.OPERATOR_ACCOUNT_HELD
        Establishing.KEPT_COPY_DAMAGED -> ReplacePasswordResult.KEPT_COPY_DAMAGED
        io.silencelen.andvari.core.client.recovery.WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT -> ReplacePasswordResult.NOT_THE_KEPT_ACCOUNT
        else -> null
    }

    /** The kit screen's line beside a kit shown with the keeper's refusal after a commit that gave [result]. */
    fun kitLine(result: IntentResult): CopyKey = when (result) {
        ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT -> CopyKey.KIT_RECOVERED_NOT_KEPT
        CreateAccountResult.ACCOUNT_MADE_NOT_KEPT -> CopyKey.KIT_REGISTERED_NOT_KEPT
        CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD -> CopyKey.KIT_REGISTERED_OPERATOR_ACCOUNT_HELD
        CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT -> CopyKey.KIT_REGISTERED_IDENTITY_FAULT
        // A recovery's own committed result: its sentence says what is so and the way out.
        is ReplacePasswordResult -> result.sentence ?: CopyKey.KIT_NOT_KEPT_HERE
        else -> CopyKey.KIT_NOT_KEPT_HERE
    }

    /** The sign-in's answer for the keeper's refusal [code] (a sign-in's `Refused` code), or null for any other code. */
    fun signIn(code: String): SignInAnswer? = when (code) {
        WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE -> SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE
        Establishing.ANOTHER_SESSION_KEPT -> SignInAnswer.ANOTHER_ACCOUNT_KEPT
        Establishing.OPERATOR_ACCOUNT_HELD -> SignInAnswer.OPERATOR_ACCOUNT_HELD
        Establishing.KEPT_COPY_DAMAGED -> SignInAnswer.KEPT_COPY_DAMAGED
        else -> null
    }

    /** How a device link that stopped for one of the keeper's reasons ends, or null for another stop. */
    fun linkEnd(stop: io.silencelen.andvari.core.client.devicelink.DeviceLinkStop): LinkDeviceEnd? = when (stop) {
        io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE -> LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE
        io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.ANOTHER_SESSION_KEPT -> LinkDeviceEnd.ANOTHER_SESSION_KEPT
        io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.IDENTITY_MISMATCH -> LinkDeviceEnd.IDENTITY_FAULT
        io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.OPERATOR_ACCOUNT_HELD -> LinkDeviceEnd.OPERATOR_ACCOUNT_HELD
        io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.KEPT_COPY_DAMAGED -> LinkDeviceEnd.KEPT_COPY_DAMAGED
        else -> null
    }

    /** The request's screen's line for a stop that keeps the request, by the keeper's (or the flow's) reason. */
    fun helpLine(reason: String?): CopyKey? = when (reason) {
        Establishing.ANOTHER_SESSION_KEPT -> CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT
        AccountOpen.SELF_IDENTITY_MISMATCH -> CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN
        Establishing.OPERATOR_ACCOUNT_HELD -> CopyKey.OPERATOR_ACCOUNT_HELD_HERE
        Establishing.KEPT_COPY_DAMAGED -> CopyKey.KEPT_COPY_DAMAGED
        io.silencelen.andvari.core.client.recovery.WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT -> CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT
        else -> null
    }
}
