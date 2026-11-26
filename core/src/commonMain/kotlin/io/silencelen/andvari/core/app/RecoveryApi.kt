package io.silencelen.andvari.core.app

/**
 * Recovery in Settings (§4.5, §7.7, §10): who can recover the account, a new kit, and the requests for the
 * operator's help that this account's devices can cancel.
 *
 * The person's choice lives with the account, sealed under its key; the app never acts on what the server says the
 * choice is (T-B4). And every sentence about recovery names the instance from its pinned card ([InstanceLabel]):
 * never a name the server reports for an account, such as an operator's display name (§7.7, T2-R-f).
 */
class RecoveryScreen internal constructor(
    val whoCanRecover: WhoCanRecover,
    /**
     * The choice, or null when none is offered here: the card names no recovery key, the instance is public
     * (variant R: whatever its card says), or this is the operator account.
     */
    val question: RecoveryQuestion?,
    /** The warning, while it is being reviewed ([RecoveryApi.reviewOperatorRecovery]). */
    val warning: OperatorRecoveryWarning?,
    /** The account's live requests for the operator's help (§9.3, FI-B7). */
    val requests: List<RecoveryRequestRow>,
    /**
     * How many rows of the server's list this device could not read: each was dropped, never the
     * whole list. Above zero, show [unreadableLine] with [requests], so that a short or empty list is not read as
     * "nobody asked". Additive.
     */
    val unreadableRequests: Int = 0,
    /**
     * The list could not be read at all this opening (no answer, a refusal, a body that is not a list): [requests] is
     * empty for that reason. Show [notReadLine] in its place. Additive.
     */
    val requestsNotRead: Boolean = false,
) {
    /** [unreadableRequests] said; null when every row was read. */
    val unreadableLine: CopyLine?
        get() = if (unreadableRequests > 0) CopyLine.of(CopyKey.RECOVERY_REQUESTS_SOME_UNREADABLE, unreadableRequests.toString()) else null

    /** [requestsNotRead] said; null otherwise. */
    val notReadLine: CopyKey? get() = if (requestsNotRead) CopyKey.RECOVERY_REQUESTS_NOT_READ else null

    /**
     * Shown beside "Make a new recovery kit", before the person starts: the old kit is void
     * from the moment the server takes the new one. A placeholder ([CopyKey.awaitingOwner]) until the owner words it.
     */
    val kitVoidsOldLine: CopyLine get() = CopyLine.of(CopyKey.KIT_NEW_VOIDS_OLD)
}

/** The recovery choice as §7.7 words it, in the public or the private (family) wording of the pinned card's kind. */
class RecoveryQuestion internal constructor(
    val instance: InstanceLabel,
    /**
     * First consent (§4.5, FS-R2, FC-2): walking the card chain from card 0, some change of the recovery key is not
     * covered by a statement the old key signed. Show [takeoverTitle] and [CopyKey.RECOVERY_KEY_CHANGED_BODY] with
     * the choice. "Only me" stays selected, as it always is.
     */
    val unsignedChange: Boolean,
) {
    private val family: Boolean get() = instance.kind == ServerKind.PRIVATE_SERVER

    val question: CopyKey get() = CopyKey.RECOVERY_QUESTION

    /** The first option, selected by default, with [onlyMeDetail]. */
    val onlyMe: CopyKey get() = CopyKey.RECOVERY_ONLY_ME
    val onlyMeDetail: CopyKey get() = CopyKey.RECOVERY_ONLY_ME_DETAIL

    /** The second option, with [meOrOperatorDetail]. */
    val meOrOperator: CopyLine
        get() = CopyLine.of(if (family) CopyKey.FAMILY_RECOVERY_OPERATOR else CopyKey.RECOVERY_OPERATOR, instance.name)
    val meOrOperatorDetail: CopyKey get() = if (family) CopyKey.FAMILY_RECOVERY_OPERATOR_DETAIL else CopyKey.RECOVERY_OPERATOR_DETAIL

    /** The unsigned-change warning's title; null unless [unsignedChange]. */
    val takeoverTitle: CopyLine?
        get() = if (unsignedChange) CopyLine.of(CopyKey.RECOVERY_KEY_CHANGED_TITLE, instance.name, instance.origin) else null
}

/**
 * What is shown before operator recovery is turned on (§7.7), at sign-up and in Settings. **It is the only way to
 * turn it on**: [EntryApi.acceptOperatorRecovery] and [RecoveryApi.turnOnOperatorRecovery] take this object, and
 * both do nothing unless the checkbox is ticked. So no screen can register or set the operator posture without the
 * person having been shown what it means.
 */
class OperatorRecoveryWarning internal constructor(
    val instance: InstanceLabel,
    /** As [RecoveryQuestion.unsignedChange]: the takeover warning belongs on this screen too. */
    val unsignedChange: Boolean,
) {
    private val family: Boolean get() = instance.kind == ServerKind.PRIVATE_SERVER

    val title: CopyLine
        get() = CopyLine.of(if (family) CopyKey.FAMILY_RECOVERY_WARNING_TITLE else CopyKey.RECOVERY_WARNING_TITLE, instance.name, instance.origin)

    /** The body's paragraphs, in order. */
    val paragraphs: List<CopyLine>
        get() = if (family) {
            listOf(CopyLine.of(CopyKey.FAMILY_RECOVERY_WARNING))
        } else {
            listOf(
                CopyLine.of(CopyKey.RECOVERY_WARNING_WHAT, instance.name),
                CopyLine.of(CopyKey.RECOVERY_WARNING_WHO_CAN_ASK),
                CopyLine.of(CopyKey.RECOVERY_WARNING_KIT),
            )
        }

    /** The checkbox. */
    val understand: CopyKey get() = if (family) CopyKey.FAMILY_RECOVERY_UNDERSTAND else CopyKey.RECOVERY_WARNING_UNDERSTAND
    val turnOn: CopyKey get() = CopyKey.RECOVERY_TURN_ON
    val keepPrivate: CopyKey get() = CopyKey.RECOVERY_KEEP_PRIVATE

    /** The unsigned-change warning's title; null unless [unsignedChange]. */
    val takeoverTitle: CopyLine?
        get() = if (unsignedChange) CopyLine.of(CopyKey.RECOVERY_KEY_CHANGED_TITLE, instance.name, instance.origin) else null
}

/** One live request for the operator's help, as the account's own devices see it (the wire's `RecoveryRequestSummary`). */
class RecoveryRequestRow internal constructor(
    val requestId: String,
    /** [OperatorHelpStage.HOLDING] or [OperatorHelpStage.AWAITING_OPERATOR]. */
    val stage: OperatorHelpStage,
    val askedAtMs: Long,
    val verifiedAtMs: Long,
    val holdEndsAtMs: Long,
    /** What the asking device said it is. Nothing vouches for it: say "reported" beside it (S3-Q4). */
    val reportedPlatform: AppPlatform,
    /**
     * The operator has answered it (spec 03 §18.3 `ready`): whoever made it can set a new password now, and only a
     * cancel stops them ([CopyKey.RECOVERY_REQUEST_ANSWERED]). [stage] is then [OperatorHelpStage.AWAITING_OPERATOR].
     * Additive.
     */
    val answered: Boolean = false,
    /**
     * The server lets the wait end early: its [holdEndsAtMs] is less than seven days after [verifiedAtMs], or it says
     * the wait is over before seven days have passed ([CopyKey.RECOVERY_REQUEST_HOLD_CUT_SHORT]). This device cannot
     * stop the operator from acting early; it says so. Additive.
     */
    val holdCutShort: Boolean = false,
    /**
     * A cancel from this device was answered as done, and the server still lists the request
     * ([CopyKey.RECOVERY_REQUEST_CANCEL_NOT_TAKEN]). Additive.
     */
    val cancelNotTaken: Boolean = false,
)

interface RecoveryApi {
    suspend fun openRecovery(): PlainResult

    fun closeRecovery()

    /** Show the warning that comes before operator recovery can be turned on ([RecoveryScreen.warning]). */
    fun reviewOperatorRecovery(screen: RecoveryScreen)

    /**
     * "Turn on operator recovery". It does nothing unless [understood], the warning's checkbox, is ticked
     * ([RecoveryChangeResult.NOT_TICKED]), and it needs the master password.
     */
    suspend fun turnOnOperatorRecovery(warning: OperatorRecoveryWarning, understood: Boolean, password: String): RecoveryChangeResult

    /** "Keep it private": close the warning; nothing changes. */
    fun keepRecoveryPrivate(warning: OperatorRecoveryWarning)

    /** Turn operator recovery off, after showing [CopyKey.RECOVERY_TURN_OFF_NOTE]. */
    suspend fun turnOffOperatorRecovery(screen: RecoveryScreen, password: String): RecoveryChangeResult

    /**
     * "Make a new recovery kit": the old one stops working when the new one is committed. The new kit is shown and
     * confirmed through [AccountSnapshot.kit] and [KitApi].
     */
    suspend fun makeKit(password: String): RecoveryChangeResult

    /**
     * "Cancel it": veto a request for the operator's help, with a statement this account's key signs (§9.3 step 2).
     * [request] is a row of [RecoveryScreen.requests] or of [AccountPrompt.RecoveryRequest] on show. The list is read
     * again afterwards: DONE only when the server no longer lists the request; a cancel answered as done while the
     * request is still listed is FAILED, and its row says so ([RecoveryRequestRow.cancelNotTaken]).
     */
    suspend fun cancelRecoveryRequest(request: RecoveryRequestRow): PlainResult

    /**
     * "This was me" on [prompt]: the person made these requests themselves. The prompt goes and is not raised again
     * for them on this device (a later request is); nothing is sent, and Settings still lists them.
     */
    fun recoveryRequestWasMe(prompt: AccountPrompt.RecoveryRequest)

    /**
     * Answer the unsigned change of the recovery key: [keep] false turns operator recovery off (the default button),
     * true keeps it with the new key. Both need the master password.
     */
    suspend fun answerRecoveryKeyChanged(prompt: AccountPrompt.RecoveryKeyChanged, keep: Boolean, password: String): RecoveryChangeResult

    /** "Later": nothing changes and nothing is sealed; the prompt returns at the next unlock. */
    fun recoveryKeyChangedLater(prompt: AccountPrompt.RecoveryKeyChanged)

    /** Answer "Keep that?": [keep] true keeps operator recovery, false turns it off. Both need the master password. */
    suspend fun answerKeepOperatorRecovery(prompt: AccountPrompt.KeepOperatorRecovery, keep: Boolean, password: String): RecoveryChangeResult

    /** "Not now", the default: nothing is sealed, and it asks again at the next unlock. */
    fun keepOperatorRecoveryNotNow(prompt: AccountPrompt.KeepOperatorRecovery)

    /** "Later" on [AccountSnapshot.kitAfterMove]: it returns at the next unlock, until a new kit is made ([makeKit]). */
    fun kitAfterMoveLater(prompt: KitAfterMovePrompt)
}

/**
 * §4.4, R36: the server moved, this device followed, and the recovery kit made before the move names the old
 * address. The app asks for a new kit: [RecoveryApi.makeKit] (which needs the master password) makes it, and this
 * prompt goes once that answered [RecoveryChangeResult.DONE]; the new kit is then shown and confirmed as any other.
 *
 * GAP (§4.4): the design says "apps ask for a new kit after following a move" and gives no wording.
 */
class KitAfterMovePrompt internal constructor(
    /** The server at its new address. */
    val instance: InstanceLabel,
)

/** A change of the recovery settings (`PUT /account/recovery`, `PUT /recovery/self-setup`). */
enum class RecoveryChangeResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,

    /** `403 reauth_failed`: that password is wrong. Never shown as an expired session (S3-K1). */
    WRONG_PASSWORD,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE]: never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED]: the server refused a proof this device made; never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /** The warning's checkbox was not ticked: nothing was sent. */
    NOT_TICKED,

    /** `400 operator_recovery_unavailable`: this server offers none, or this is the operator account. */
    OPERATOR_RECOVERY_UNAVAILABLE,

    /** The password was changed on another device meanwhile. */
    CHANGED_ELSEWHERE,

    /**
     * `400 escrow_wrong_form`: the server no longer stores the form of recovery copy this app sealed. Nothing was stored
     * and nothing changed; an update of the app seals the form it takes. Additive.
     */
    ESCROW_WRONG_FORM(sentence = CopyKey.ESCROW_WRONG_FORM),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
