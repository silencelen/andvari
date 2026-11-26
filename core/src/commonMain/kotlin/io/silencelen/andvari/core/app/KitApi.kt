package io.silencelen.andvari.core.app

/**
 * The recovery kit (§10) as a screen shows it: revealed once, then confirmed by typing three of its groups. The same
 * steps run after a registration, after either recovery replaced the kit (FS-B1), at a sign-in that found the kit was
 * never saved, and when the person makes a new one in Settings. It is the engine's `RevealedKit` and capture gate.
 *
 * The secret is not here. It is read with [KitApi.kitDocument], and only while [step] is [KitStep.REVEAL].
 */
class KitScreen internal constructor(
    val reason: KitReason,
    val step: KitStep,
    /** The account the kit is for. */
    val email: String,
    val instance: InstanceLabel,
    /**
     * [KitStep.CONFIRM]: the three groups to type, each 1 to 11, in ascending order. Core picks them with the
     * system's random source; empty in every other step.
     */
    val groupsToType: List<Int>,
    /** Wrong entries so far on this confirm; after three the kit is shown again. */
    val failedTries: Int,
    /**
     * The kit came with a refusal: the server holds it (a recovery or a registration was committed), but this device did
     * not keep the account's session ([CopyKey.KIT_RECOVERED_NOT_KEPT], [CopyKey.KIT_REGISTERED_NOT_KEPT],
     * [CopyKey.KIT_NOT_KEPT_HERE]). Show it with the kit on every step. The kit is kept until the person typed its groups
     * on the confirm step (checked on this device: with no session the server is not told), then wiped, and the journey
     * is back at the first screen; the vault does not open. Null for every other kit. Additive.
     */
    val notKeptLine: CopyKey? = null,
    /**
     * The kit screen's idle limit, set for every kit: after this many milliseconds without a touch or a key on the
     * screen, the app calls [AppApi.lock], which wipes the kit (for a kit shown with [notKeptLine] it says so,
     * [AppSnapshot.kitWiped]; for every other kit the next unlock makes a fresh one, [earlierKitVoidLine]).
     * - A kit in the journey ([EntryScreen.Kit]): the lock time of the policy this device keeps for the kit's server, five
     *   minutes where it keeps none. The apps see no policy in the journey; this is it.
     * - A kit shown with [notKeptLine]: the same, but never longer than five minutes (the browser's kit screens' limit),
     *   as no account is open.
     * - A kit in Settings ([AccountSnapshot.kit]): the account's own policy ([AccountSnapshot.policy]), the same figure.
     *
     * [idleWarnBeforeMs] before it, show [idleWarningLine]; a touch or a key starts the count again. The timer is the
     * app's own (each app counts touches and keys where it already does for its auto-lock). The figure is the one when
     * the screen was made: a screen that is made again (a step changes) carries the policy as it is then. Additive.
     */
    val idleLockAfterMs: Long? = null,
    /**
     * With [idleLockAfterMs]: how long before the lock [idleWarningLine] is shown (thirty seconds). Where the limit itself
     * is not longer than that, it equals the limit: the warning is shown from the start of the screen. Set for every kit
     * the engine makes. Additive.
     */
    val idleWarnBeforeMs: Long? = null,
    /**
     * With [idleWarnBeforeMs]: the warning shown that long before the lock: [CopyKey.KIT_IDLE_WARNING], or, where the limit
     * is thirty seconds or less (the warning shows from the start), [CopyKey.KIT_IDLE_WARNING_SHORT], whose slot is the
     * limit: draw [idleWarning], which fills it. Additive.
     */
    val idleWarningLine: CopyKey? = null,
    /**
     * On [KitStep.REVEAL], before anything else: this kit replaces one that was shown on this device and never confirmed
     * at the server (a lock took it, it was left, or another device's newer kit voided it), so whatever the person wrote
     * down or stored of that earlier kit no longer works and must not be kept ([CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID]).
     * Null on every other step and for every other kit, including where this device cannot know: a kit shown on another
     * device, or by a build of the app before this one, or one whose mark this device could not keep. Additive.
     */
    val earlierKitVoidLine: CopyKey? = null,
) {
    /**
     * With [notKeptLine], on every step: how long the kit holds ([CopyKey.KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN]). No session
     * could tell the server that it was typed back, so the next sign-in to the account, on any device, shows a new kit
     * that replaces this one. Null for every other kit. Additive.
     */
    val notKeptHoldsLine: CopyKey?
        get() = if (notKeptLine != null) CopyKey.KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN else null

    /**
     * [idleWarningLine] with its value: for [CopyKey.KIT_IDLE_WARNING_SHORT], the limit in whole seconds (at least one), so
     * that no line names a time that is untrue. Null with [idleWarningLine]. Additive.
     */
    val idleWarning: CopyLine?
        get() = idleWarningLine?.let { key ->
            if (key == CopyKey.KIT_IDLE_WARNING_SHORT) CopyLine.of(key, maxOf(1L, ((idleLockAfterMs ?: 0L) + 999) / 1000).toString())
            else CopyLine.of(key)
        }

    internal companion object {
        /** The browser's kit screens' limit: five minutes without a touch or a key. */
        const val KIT_IDLE_LOCK_MS = 5 * 60_000L

        /** The warning, thirty seconds before. */
        const val KIT_IDLE_WARN_MS = 30_000L

        /**
         * The limit for a kit whose server's policy locks after [policySeconds] (null: this device keeps none, five
         * minutes), at most five minutes for a kit shown with a refusal ([notKept]); and every kit's warning, thirty seconds
         * before the lock, or from the start of the screen where the limit is not longer than that (a person is always told
         * that a touch keeps the kit). The smallest limit a policy gives is one second (the server takes 1..900 s, and this
         * device clamps what it keeps to the same). (limit, warn before, warning line).
         */
        fun idleLimits(policySeconds: Int?, notKept: Boolean): Triple<Long, Long?, CopyKey?> {
            val policyMs = (policySeconds ?: ServerPolicy.DEFAULT_AUTO_LOCK_SECONDS).toLong() * 1000L
            val limit = if (notKept) minOf(policyMs, KIT_IDLE_LOCK_MS) else policyMs
            // Where no thirty seconds of warning are left, a line of its own that names the limit, never "in 30 seconds".
            val warning = if (limit <= KIT_IDLE_WARN_MS) CopyKey.KIT_IDLE_WARNING_SHORT else CopyKey.KIT_IDLE_WARNING
            return Triple(limit, minOf(limit, KIT_IDLE_WARN_MS), warning)
        }
    }

    /** [CopyKey.KIT_TYPE_GROUPS] for [groupsToType]; null outside [KitStep.CONFIRM]. */
    val confirmLine: CopyLine?
        get() = if (step == KitStep.CONFIRM && groupsToType.size == 3) {
            CopyLine.of(CopyKey.KIT_TYPE_GROUPS, groupsToType[0].toString(), groupsToType[1].toString(), groupsToType[2].toString())
        } else {
            null
        }
}

/** Why a kit is being shown. */
enum class KitReason {
    /** A new account's first kit. */
    FIRST_KIT,

    /** A recovery just replaced the old kit, which stopped working with it (§10, §9.3 step 5). */
    AFTER_RECOVERY,

    /** The account never confirmed a kit: an interrupted reveal. The vault stays shut until one is saved. */
    NEVER_SAVED,

    /** "Make a new recovery kit" in Settings. */
    MADE_IN_SETTINGS,

    /** Another device made a newer kit while this one was on screen (`409 recovery_piece_stale`): a fresh one is made with the master password. */
    REPLACED_ELSEWHERE,
}

enum class KitStep {
    /** A fresh kit is being committed to the server. */
    MAKING,

    /** That failed: [KitApi.retryKit]. */
    NOT_MADE,

    /** The kit is on screen. There is no Copy button here or on the confirm step (§10). */
    REVEAL,

    /** "Type groups 2, 7 and 10". */
    CONFIRM,
}

/**
 * The kit document (§10): generated on the device, never uploaded, offered as Print, Save to Files or Save PDF
 * without leaving a temporary copy behind. Not a data class: no `toString` of the secret. Read it, render it, drop it.
 */
class KitDocument internal constructor(
    val email: String,
    val instance: InstanceLabel,
    /** The date printed on it, unix milliseconds. */
    val madeAtMs: Long,
    /** The secret's 11 groups (ten of four characters, one of three), to print large and monospaced. */
    val groups: List<String>,
    /** The kit QR's content (`andvari-kit:2:…`), for a QR in byte mode. Deliberately not a URL. */
    val qrPayload: String,
    /** The account ID: the identity fingerprint's short form, 32 hex. */
    val accountId: String,
) {
    val title: CopyKey get() = CopyKey.KIT_TITLE
    val keepPrivate: CopyKey get() = CopyKey.KIT_KEEP_PRIVATE
    val accountIdLine: CopyLine get() = CopyLine.of(CopyKey.KIT_ACCOUNT_ID, accountId)
    val howToRecover: CopyKey get() = CopyKey.KIT_HOW_TO_RECOVER
}

/** The kit's steps, wherever a [KitScreen] is on show ([EntryScreen.Kit], [AccountSnapshot.kit]). */
interface KitApi {
    /**
     * The kit to show, print or save. **Null unless [screen] is on show and on [KitStep.REVEAL]**: a kit is readable
     * only while it is being revealed, never from the confirm step and never later.
     */
    fun kitDocument(screen: KitScreen): KitDocument?

    /** From the reveal to "Type groups …". */
    fun proceedToConfirm(screen: KitScreen)

    /** From the confirm back to the reveal. */
    fun showKitAgain(screen: KitScreen)

    /**
     * The three groups as typed, in the order of [KitScreen.groupsToType]. They are compared exactly, case and all.
     * Only a match records the kit as saved and lets the vault open.
     */
    suspend fun confirmKit(screen: KitScreen, typedGroups: List<String>): KitConfirmResult

    /**
     * Commit a fresh kit on [KitStep.NOT_MADE]: after a commit that failed, or after [KitConfirmResult.REPLACED]. It is
     * `PUT /recovery/self-setup`, which re-authenticates, so it takes the account's current master [password]
     * ([KitConfirmResult.WRONG_PASSWORD]).
     */
    suspend fun retryKit(screen: KitScreen, password: String): KitConfirmResult
}

enum class KitConfirmResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** Saved. The vault opens, or the Settings screen returns. */
    DONE,

    /** As [ProofResult.KEYS_NOT_KNOWN_HERE]: never a wrong password while the session knows it. Additive. */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /** As [ProofResult.PROOF_REFUSED]: the server refused a proof this device made; never a wrong password. Additive. */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /** A group does not match. After the third wrong entry the kit is shown again ([KitStep.REVEAL]). */
    MISMATCH,

    /**
     * Another device made a newer kit meanwhile (`409 recovery_piece_stale`): this one is void. The screen is now on
     * [KitStep.NOT_MADE] with [KitReason.REPLACED_ELSEWHERE]: [KitApi.retryKit] with the master password makes a fresh one.
     */
    REPLACED,

    /** [KitApi.retryKit]: the master password did not re-authenticate. Nothing was made. */
    WRONG_PASSWORD,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
