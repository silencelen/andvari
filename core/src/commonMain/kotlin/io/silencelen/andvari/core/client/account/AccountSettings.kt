package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.recovery.EscrowDecision
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.Quota

/**
 * The signed-in account's settings flows and the operator's console, so the app API never calls
 * [io.silencelen.andvari.core.client.net.WireClient] itself (design §4.4 password rule, §4.5, §7.7, §8.6,
 * §8.7, §9.2, §10; spec 03 §3, §7, §16.7, §16.8).
 *
 * **Re-authentication.** Every action that takes a `password` is a `†` route: the engine first runs
 * [io.silencelen.andvari.core.client.pin.PasswordGate] with purpose `reauth` for this session's account and
 * origin, and only on `proceed` derives `currentAuthKey` (prelogin at the session's origin, then the KDF).
 * A refused entry derives and sends nothing ([Reauthed.NoSession]). The engine wipes nothing the caller
 * owns: the caller wipes each `password` array after the call returns.
 */
sealed class Reauthed<out T> {
    data class Done<T>(val value: T) : Reauthed<T>()

    /** The password gate refused at the entry: no session for this account at this origin. Nothing was derived or sent. */
    data object NoSession : Reauthed<Nothing>()

    /**
     * The master password typed here is not this account's: on a session that holds the device's own wrap, it did not
     * open that wrap, and nothing was sent. The server's refusal of a proof this device made is never this: it is
     * [Refused] with [PROOF_REFUSED].
     */
    data object WrongPassword : Reauthed<Nothing>()

    /** A new master password below the local strength floor; nothing sent. */
    data object PasswordTooWeak : Reauthed<Nothing>()

    /**
     * A refusal code of the route's table (spec 03), e.g. `rate_limited`, `stale_state`, `operator_recovery_unavailable`.
     * [message]: on a refused policy only, the server's own words for the refusal (its envelope's `message`), as the server
     * sent them but for control characters and past [MESSAGE_MAX] characters: the server's text, to be shown as the
     * server's, never as the app's verdict. Null on every other route.
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null, val message: String? = null) : Reauthed<Nothing>()

    /** No answer, a `5xx` or a reply that does not decode: the change may have landed. The next read shows which. */
    data object Unknown : Reauthed<Nothing>()

    companion object {
        /**
         * The code of [Refused] when the server refused the password proof this device sent (`403 reauth_failed`): the
         * same code in [io.silencelen.andvari.core.client.deletion.DeletionOutcome.Refused],
         * [CardChangeResult.Refused] and [TwoStepSetup.Refused]. On the engine's session the password was proven on
         * this device first, so a wrong password never reaches the server: this refusal says that the server holds
         * other keys for the account than this device knows (spec 01 §7, a re-key the server lied about), or that the
         * session derives its proof under a salt or cost the server no longer holds. It is told as a wrong password only
         * where the session holds no wrap of its own to prove the password against. Kept as a code of an existing
         * result so that every exhaustive `when` over these results still compiles.
         */
        const val PROOF_REFUSED = "reauth_failed"

        /** The most characters of a server's own message that [Refused.message] carries. */
        const val MESSAGE_MAX = 300

        /** [text] as [Refused.message] carries it: control characters dropped, at most [MESSAGE_MAX] characters; null when empty. */
        fun serverMessage(text: String?): String? =
            text?.filter { it.code >= 32 && it.code != 127 }?.take(MESSAGE_MAX)?.trim()?.ifEmpty { null }
    }
}

/** A read that needs no re-authentication. */
sealed class Fetched<out T> {
    data class Ok<T>(val value: T) : Fetched<T>()
    data class Refused(val code: String) : Fetched<Nothing>()
    data object Unreachable : Fetched<Nothing>()
}

/** The account's recovery posture as this device sees it (design §4.5, §7.7). */
data class RecoveryPostureView(
    /** The merged account-state `recovery` record (the person's consent), or null when none is recorded yet. */
    val record: RecoveryRecord?,
    /** False on a `public` card (variant R) or a card whose `recoveryFp` is `none`: operator recovery is not offered. */
    val operatorOffered: Boolean,
    /** What the escrow rules want now: nothing, a silent re-seal the engine did, the own-mirror question or the takeover warning. */
    val pending: EscrowDecision,
)

/** Recovery settings and the kit (design §4.5, §7.7, §10). */
interface RecoverySettings {
    /** Read the posture: merges account state and runs [io.silencelen.andvari.core.client.recovery.EscrowRules]. */
    suspend fun posture(): Fetched<RecoveryPostureView>

    /**
     * `PUT /account/recovery`†. [choice] `PRIVATE` turns operator recovery off. `OPERATOR` needs the [offer] this device
     * made ([io.silencelen.andvari.core.client.onboard.Onboarding.operatorRecoveryOffer] or [operatorOffer]) and the
     * person's [understood] box: it is re-checked against the pin (`stale_offer`), refused on a `public` card or a card
     * without a `recoveryFp` (`operator_recovery_unavailable`) and without the box (`consent_required`), all before
     * anything is derived. The escrow is sealed to the key the offer checked against the card at full length. The new
     * `recovery` record goes into account state in the same request, and into this device's own mirror on success.
     */
    suspend fun setPosture(choice: RecoveryChoiceKind, offer: io.silencelen.andvari.core.client.onboard.OperatorRecoveryOffer?, understood: Boolean, password: CharArray): Reauthed<RecoveryRecord>

    /** Operator recovery as Settings may offer it now, from the pinned card (null when it is not offered). */
    suspend fun operatorOffer(): io.silencelen.andvari.core.client.onboard.OperatorRecoveryOffer?

    /**
     * The person answered [prompt] ("Keep that?", or the takeover warning): [keep] re-seals to the card's key and
     * refreshes this device's own mirror; otherwise the posture becomes `private`. The prompt is re-derived from
     * this device's own state first; a stale one is refused (`stale_prompt`).
     */
    suspend fun answerEscrowPrompt(prompt: EscrowDecision, keep: Boolean, password: CharArray): Reauthed<RecoveryRecord>

    /**
     * `PUT /recovery/self-setup`† with a fresh recovery secret: the old kit stops working when the server answers.
     * The new kit goes through the capture gate ([io.silencelen.andvari.core.client.onboard.Onboarding.confirmKit]).
     */
    suspend fun rotateKit(password: CharArray): Reauthed<RevealedKit>
}

/** The master password (spec 03 §3 `PUT /account/password`). */
interface PasswordChange {
    /** Re-wraps the UVK under [newPassword]; the UVK and the kit are unchanged. Sessions on other devices stay. */
    suspend fun change(currentPassword: CharArray, newPassword: CharArray): Reauthed<Unit>
}

/** "Your devices" and "New devices must be linked" (design §8.6, §8.7; spec 03 §16.7, §16.8). */
interface DeviceSettings {
    /** `GET /account/devices`. Names and platforms are self-reported, rendered as plain text. */
    suspend fun list(): Fetched<List<Device>>

    /** `POST /account/devices/{deviceId}/revoke`†. Revoking this device signs it out. */
    suspend fun revoke(deviceId: String, password: CharArray): Reauthed<Unit>

    /** `PUT /account/require-link`†. */
    suspend fun setRequireLink(enabled: Boolean, password: CharArray): Reauthed<Boolean>
}

/**
 * The operator's console (design §9.2; spec 03 §7), for the operator account's own session only. Every write
 * re-authenticates. Nothing here shows a recovery request code: the operator gets it only from the person
 * (design §9.3 step 3, T2-R-c).
 */
interface OperatorRoutes {
    suspend fun accounts(): Fetched<List<AccountSummary>>
    suspend fun disable(userId: String, reason: String, password: CharArray): Reauthed<Unit>
    suspend fun enable(userId: String, password: CharArray): Reauthed<Unit>

    /** `POST /admin/accounts/{userId}/delete`†: answers the server's `deletedAt`. */
    suspend fun deleteAccount(userId: String, password: CharArray): Reauthed<Long>

    /**
     * The same with a [reason]: null is the 30-day rule (the two-argument form), and
     * [io.silencelen.andvari.core.model.wire.OperatorDeleteReason.UNDER_MINIMUM_AGE] lifts the 30 days for an account
     * already disabled, and nothing else. Any other value is refused on this device with `bad_reason`.
     */
    suspend fun deleteAccount(userId: String, password: CharArray, reason: String?): Reauthed<Long>
    suspend fun accountDevices(userId: String): Fetched<List<Device>>
    suspend fun revokeDevice(deviceId: String, password: CharArray): Reauthed<Unit>

    /** Each limit null returns it to the instance default. */
    suspend fun setQuota(userId: String, accountBytes: Long?, items: Long?, ownedSharedVaults: Long?, openLinks: Long?, password: CharArray): Reauthed<Quota>
    suspend fun policy(): Fetched<AdminPolicy>
    suspend fun setPolicy(policy: AdminPolicy, password: CharArray): Reauthed<AdminPolicy>
    suspend fun audit(): Fetched<List<AuditRow>>
    suspend fun status(): Fetched<AdminStatus>

    /** Private instances only (design §9.3); the public instance answers `404`. */
    suspend fun recoveryRequests(): Fetched<List<AdminRecoveryRequest>>

    /** `POST /admin/accounts/{userId}/escrow`†: the sealed escrow, for the offline `recovery-cli assist` only. */
    suspend fun escrow(userId: String, password: CharArray): Reauthed<AdminEscrowResponse>

    /**
     * `POST /admin/recovery-requests/{requestId}/fulfil`†: [answer] is what the ONE shared reader made of the token
     * `recovery-cli assist` printed ([io.silencelen.andvari.core.trust.AnswerToken.read], spec 04 §7 step 3), so nothing
     * else can be uploaded. Repeatable until the commit (spec 03 §18.6).
     */
    suspend fun fulfil(requestId: String, answer: io.silencelen.andvari.core.trust.AnswerRead.Ok, password: CharArray): Reauthed<Unit>
}
