package io.silencelen.andvari.core.app

/**
 * The signed-in, unlocked account as IF-3 shows it ([AppPhase.UNLOCKED]): what waits for an answer, the shared
 * vaults with the state of their history, and whichever of its screens are open. A screen is opened and closed by
 * its own intents ([ContactsApi.openContacts], …) and is null while it is closed.
 *
 * **It is the mark of an open vault.** A snapshot carries one exactly while [AppSnapshot.phase] is
 * [AppPhase.UNLOCKED]: the account is [email] (and [accountId]) on the server [AppSnapshot.instance] names. It is
 * gone from the first snapshot after [AppApi.lock], [AppApi.signOut], a session the server ended, or a forgotten
 * server. The vault's content (items, sync, attachments) is not part of this API; inside core it follows the same
 * session through `SessionKeeper.phase`.
 */
class AccountSnapshot internal constructor(
    val email: String,
    /** "Your account ID": the identity fingerprint's short form, 32 hex, as on the kit and in every notice (§10, §11.2). */
    val accountId: String,
    /** This is the instance's operator account, which holds no everyday data (§9.1). */
    val operatorAccount: Boolean,
    /**
     * The server is stopped on this device: its chain forked ([InstanceCardState.Stopped], §4.4). The vault is open
     * from this device's own copy and **nothing can be saved**: nothing is sent to that server, accepted from it or
     * written, and every intent that would need it answers [Trouble.FAILED]. Show [CopyKey.CARD_FORK] with what is
     * readable, and [CopyKey.FORGET_THIS_SERVER], which also deletes this copy ([InstanceApi.forgetServer]).
     */
    val serverStopped: Boolean,
    /** What waits for the person's answer, in the order to show it. */
    val prompts: List<AccountPrompt>,
    /** The shared vaults this account holds or is offered, by name; the personal vault has no history and is not here (§3.10). */
    val vaults: List<SharedVaultRow>,
    val contacts: ContactsScreen?,
    /** A comparison of codes with one contact, while it is open ([ContactsApi.openCompare]). */
    val comparing: CompareScreen?,
    val links: LinksScreen?,
    /** An invite opened while signed in ([LinksApi.openInvite], [AppApi.openAppLink]), until it is answered or dismissed. */
    val opened: OpenedInvite?,
    val members: MembersScreen?,
    /**
     * A share with a contact whose codes were never compared was asked for ([SharedVaultsApi.addMember],
     * [LinksApi.releaseShare]): the warning to show before it can go on. Null otherwise.
     */
    val shareWarning: UncomparedShareWarning?,
    val moving: MoveEverythingScreen?,
    val devices: DevicesScreen?,
    /** Linking a new device from this one, while it runs ([DevicesApi.startDeviceLink]). */
    val deviceLink: DeviceLinkHost?,
    val recovery: RecoveryScreen?,
    /** A new kit made in Settings, until it is confirmed ([RecoveryApi.makeKit]). */
    val kit: KitScreen?,
    val deletion: DeletionScreen?,
    /** Quick unlock on this device: whether it is on, can be, and whether to offer it now (Settings, and the offer card). */
    val quickUnlock: QuickUnlockSetting,
    /** The client policy the server last declared, clamped, read-only (spec 03 §1.1). */
    val policy: ServerPolicy,
    /** Settings › Two-step sign-in, while it is open ([AccountSettingsApi.openTwoStep]). */
    val twoStep: TwoStepScreen?,
    /**
     * The server moved and this device followed (§4.4): the kit made before the move names the old address, so the
     * app asks for a new one ([RecoveryApi.makeKit], R36). Null when none is due, or put off until the next unlock
     * ([RecoveryApi.kitAfterMoveLater]).
     */
    val kitAfterMove: KitAfterMovePrompt?,
    /**
     * The revision of [AppApi.content]'s state ([io.silencelen.andvari.core.app.content.ContentState.revision]) when
     * this snapshot was made: a host that follows only the app's snapshots sees the vault's content change by it.
     * Read the content itself from [AppApi.content].
     */
    val contentRevision: Long,
    /**
     * The server ended this session (design §4.4) and the password opened this device's copy read-only: the same fact
     * the lock screen carried ([LockedScreen.signedOutByServer]), kept while the vault is open. [serverStopped] is true
     * with it. Offer "Sign out", and "Sign in again", which is [AppApi.lock] and then [AppApi.signInAgain] on the lock
     * screen that follows (it carries [LockedScreen.signedOutByServer] too).
     */
    val signedOutByServer: Boolean = false,
    /**
     * With [signedOutByServer]: the session ended because this device could not confirm it with its server in time (no
     * try was left for a refresh whose answer was lost), not because the server ended it ([LockedScreen.sessionNotConfirmed],
     * kept while this copy is open). The ways on are those of [signedOutByServer]. Additive.
     */
    val sessionNotConfirmed: Boolean = false,
    /** With [sessionNotConfirmed]: its line for the open copy, [CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN], in place of the server's end. Null otherwise. */
    val endLine: CopyKey? = null,
    /**
     * Why the link just opened here is not used ([InviteResult.NOT_USABLE_SIGNED_IN]): the whole sentence, filled
     * ([CopyKey.ALREADY_SIGNED_IN_THERE] for a register link, [CopyKey.ALREADY_SIGNED_IN_THERE_ENROL] for an enrol
     * link) with this instance's pinned name and address. Show it in place of the invite; [LinksApi.dismissOpened]
     * puts it away, and opening another link, a lock or the session's end clear it. Null otherwise.
     */
    val inviteNotUsed: CopyLine? = null,
    /**
     * Whether this opening's live updates reach this device (the event bell, spec 03 §6). Show [LiveUpdates.line], when
     * it is not null, as one quiet line; nothing else changes. Additive: [LiveUpdates.NOT_RUNNING] where nothing says.
     */
    val liveUpdates: LiveUpdates = LiveUpdates.NOT_RUNNING,
    /**
     * The moves of everything out of a vault that this device started and did not finish (design §3.13), remembered
     * across a lock and a restart: the first screen after an unlock offers to finish each one. Show [UnfinishedVaultMove.line]
     * with a button that calls [SharedVaultsApi.openMoveEverything] on [UnfinishedVaultMove.vault], and a "Not now" that calls
     * [SharedVaultsApi.unfinishedMoveLater] (it comes back at the next unlock). The vault's own row says the same
     * ([SharedVaultRow.unfinishedMove]). Additive: not a prompt, so no switch over [AccountPrompt] changes.
     */
    val unfinishedMoves: List<UnfinishedVaultMove> = emptyList(),
    /**
     * A move's deletion of its old vault that the server stored outside a run of the move (it held the signed deletion
     * and stored it later): never the person's own quiet departure. Show [MoveStoredNotice.line] as a notice, with a
     * button that calls [SharedVaultsApi.bringLateIntoMove] while [MoveStoredNotice.canCopy], [MoveStoredNotice.copiedLine]
     * once copied, and a dismiss that calls [SharedVaultsApi.dismissMoveStored]. Additive.
     */
    val movesStoredOutside: List<MoveStoredNotice> = emptyList(),
    /**
     * The one line after a sign-in that has something to say about this device's copy (spec 01 §7): today only
     * [CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER], when the copy this device kept was sealed under another master password than
     * the one typed and now follows the server's. Show it once as a notice; [AppApi.dismissSignInNotice] puts it away,
     * and a lock clears it. Null otherwise. Additive.
     */
    val signInNotice: CopyLine? = null,
    /**
     * The vault was opened by a surface that only fills ([UnlockForFilling]) while the account's kit is not confirmed:
     * no kit was made then, and the account has no working kit. When the app itself is opened (brought to the screen by
     * the person) with this set, it calls [AppApi.lock] first: the unlock that follows is with the master password and
     * shows a fresh kit to save before the vault opens. False otherwise, and once a lock or a confirmed kit ends it.
     * Additive.
     */
    val kitDueAtOpening: Boolean = false,
    /**
     * What a "Move everything" run has to tell once it is over or has passed a step, each to show as a notice until the
     * person dismisses it ([MoveNotes.dismissMoveNote]): a half-made vault of an earlier try that was NOT deleted because
     * it holds items the move did not make (it stays a vault of its own), and earlier copies kept beside a newer one. Kept
     * on the device until dismissed, also across a lock and a restart, without any name: the names are those of now (the
     * vault's, a contact's present label). A note whose vault this opening cannot name yet (not read since the opening, or
     * no longer this account's) is not listed until it can. Additive.
     */
    val moveNotes: List<MoveNote> = emptyList(),
    /**
     * What became of changes to shared vaults that this device let go of or sent again (§3.7): each a notice until the
     * person dismisses it ([WaitingChanges.dismissWaitingNotice]), kept across a lock and a restart. With them, a deletion
     * that waits for the person's word and was looked at is asked about on its row ([WaitingChange.asksForWord]). Additive.
     */
    val waitingNotices: List<WaitingNotice> = emptyList(),
)

/**
 * One thing a move says after it ([AccountSnapshot.moveNotes]): about the move of the vault [oldVaultId], concerning the
 * vault [vaultId] (the half-made vault kept, or the move's new vault). Show every line of [lines] in order. [member]: the
 * member the move removes, who still holds that half-made vault and what is in it
 * ([CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS] names them by this, after the vault's name); null otherwise.
 */
class MoveNote internal constructor(
    val oldVaultId: String,
    val vaultId: String?,
    val lines: List<CopyLine>,
    val member: PersonName?,
)

/**
 * Taking a [MoveNote] away: asked for with `as?` on the [AppApi]'s [SharedVaultsApi] (the engine's and the fake's
 * implement it), so no implementer of the interfaces breaks.
 */
interface MoveNotes {
    /** The person dismissed [note]; one no longer on show changes nothing. */
    fun dismissMoveNote(note: MoveNote)
}

/**
 * The deletion of [oldName] by "Move everything" into [intoName] was stored by the server outside a run of the move.
 * [added] items this device holds were added to the old vault after the copies, and [changed] were changed after their
 * copy; [line] says so ([CopyKey.MOVE_STORED_OUTSIDE], or [CopyKey.MOVE_STORED_OUTSIDE_NOTHING_LATE] when both are 0),
 * including that what another member added and this device never received cannot be saved here. The held copy stays in
 * the holding area. [canCopy]: there is something to copy and the new vault takes it. [copiedLine]: after a copy.
 */
class MoveStoredNotice internal constructor(
    val oldVaultId: String,
    val oldName: String,
    val intoVaultId: String?,
    val intoName: String,
    val added: Int,
    val changed: Int,
    val canCopy: Boolean,
    val line: CopyLine,
    val copiedLine: CopyLine? = null,
    /**
     * How many of the person's own deletions, waiting when the old vault closed, the move carried into [intoName] without a
     * question (decided on 2026-11-17): such an item counts neither in [added] nor in [changed], and its earlier copy is in
     * [intoName]'s trash for thirty days. Show [carriedLine] with the notice while it is not null. Additive.
     */
    val deletionsCarried: Int = 0,
    /** [CopyKey.MOVE_STORED_DELETIONS_CARRIED] while [deletionsCarried] is above 0; null otherwise. Additive. */
    val carriedLine: CopyLine? = null,
    /**
     * How many of the person's own waiting deletions were NOT carried into [intoName]. A copy is deleted only at the
     * revision the move made it at, decided against the copy as the server holds it when the deletion is sent, so a copy
     * changed since (elsewhere, or by a change still waiting on this device), one of no known revision, and one whose
     * deletion the server refused are kept. Each copy stays live in [intoName]; such an item counts in none of [added],
     * [changed] and [deletionsCarried]. Show [keptLine] with the notice while it is not null. Additive.
     */
    val deletionsKept: Int = 0,
    /** [CopyKey.MOVE_STORED_DELETIONS_KEPT] while [deletionsKept] is above 0; null otherwise. Additive. */
    val keptLine: CopyLine? = null,
    /**
     * Earlier copies in [intoName] kept beside the newer copy a copy step made: changed there since the move made them,
     * of no known revision, or their deletion refused. Each line counts one reason ([CopyKey.MOVE_KEPT_BESIDE_CHANGED],
     * [CopyKey.MOVE_KEPT_BESIDE_NO_REVISION], [CopyKey.MOVE_KEPT_BESIDE_REFUSED]); empty when none. Additive.
     */
    val keptBesideLines: List<CopyLine> = emptyList(),
    /**
     * Items not copied again because their copy was deleted in [intoName] since (by anyone with that vault): never counted
     * as copied. [CopyKey.MOVE_STORED_DELETED_THERE] while above 0, in [deletedThereLine]. Additive.
     */
    val deletedThere: Int = 0,
    val deletedThereLine: CopyLine? = null,
)

/**
 * A "Move everything" this device started and did not finish (design §3.13), for the first screen after an unlock.
 * [deleteWaiting]: the old vault's deletion is signed and waiting for the server and cannot be taken back, so the move
 * must be finished ([CopyKey.MOVE_DELETE_WAITING]); otherwise everything is still in the old vault
 * ([CopyKey.MOVE_UNFINISHED]).
 */
class UnfinishedVaultMove internal constructor(
    /** The old vault's row: [SharedVaultsApi.openMoveEverything] with it finishes the move. */
    val vault: SharedVaultRow,
    val deleteWaiting: Boolean,
    val line: CopyLine,
)

/**
 * Live updates of the open vault (the event bell, spec 03 §6): changes made on the account's other
 * devices arrive at once while a socket is open. Without one the vault still syncs at every opening, every return to
 * the foreground and after every change made here, so only changes made elsewhere arrive later. Nothing is asked of
 * the person and nothing is lost: show [line], when it is not null, as ONE quiet line (never a dialog, an error or a
 * badge that asks for action). It clears itself the moment a socket opens.
 */
class LiveUpdates internal constructor(
    /**
     * This opening dials live updates at all. False while the vault is locked, for a copy the server signed out, a
     * server stopped on this device ([AccountSnapshot.serverStopped] says that), a server that wants a newer build, or a
     * host whose transport has no bell.
     */
    val running: Boolean,
    /** A socket is open now. */
    val connected: Boolean,
    /** Why no socket is open, once an attempt failed; null while [connected], before the first attempt, and when not [running]. */
    val trouble: LiveUpdatesTrouble?,
) {
    /**
     * The one quiet line ([CopyKey.LIVE_UPDATES_NOT_CONNECTED]) while [running], not [connected] and an attempt failed;
     * null otherwise, and null for [LiveUpdatesTrouble.SERVER_STOPPED], which the server-stopped notice already says.
     */
    val line: CopyLine?
        get() = if (running && !connected && trouble != null && trouble != LiveUpdatesTrouble.SERVER_STOPPED) CopyLine.of(CopyKey.LIVE_UPDATES_NOT_CONNECTED) else null

    override fun equals(other: Any?): Boolean =
        other is LiveUpdates && other.running == running && other.connected == connected && other.trouble == trouble

    override fun hashCode(): Int = (if (running) 1 else 0) + (if (connected) 2 else 0) + 4 * (trouble?.ordinal?.plus(1) ?: 0)

    override fun toString(): String = "LiveUpdates(running=$running, connected=$connected, trouble=$trouble)"

    companion object {
        /** No live updates this opening (see [running]). */
        val NOT_RUNNING: LiveUpdates = LiveUpdates(running = false, connected = false, trouble = null)
    }
}

/** Why live updates are not connected (the dialer's `BellFailure.Kind`). For a diagnostic line or a log, never shown as wording of its own. */
enum class LiveUpdatesTrouble {
    /** This device dials nothing to the server now (its pin is forked, damaged, moving or gone). */
    SERVER_STOPPED,

    /** The socket did not open: no network, TLS, or the server refused or did not answer the upgrade. */
    NOT_OPENED,

    /** The server sent a message larger than live updates allow, and the socket was ended. */
    TOO_LARGE,

    /** An open socket failed. */
    BROKEN,
}

/**
 * Something the account must be asked. Each prompt is answered through the intent that takes it, so an answer is
 * always an answer to what was shown.
 */
sealed class AccountPrompt {
    /**
     * §3.6: someone this account is connected with wants to share a vault. It is never adopted unasked, even from a
     * current contact, and again after a re-add (FS-R6, FC-7, FN-2). The log verified, this account is a member and
     * the key matches the log's commitment; only then was the name decrypted. (The engine's `Adoption.AskAccept`.)
     *
     * **The prompt is bound to the `add` it answers.** [SharedVaultsApi.acceptIncoming] and
     * [SharedVaultsApi.declineIncoming] take this object, and the answer is recorded for that `add` alone: a later
     * `add` of this account raises a new prompt.
     */
    class IncomingVault internal constructor(
        val vaultId: String,
        /** The owner's label: a contact current on this device whose key signed the `add`. */
        val from: String,
        /** The vault's name, plain text. */
        val vaultName: String,
        internal val addSeq: Long,
    ) : AccountPrompt() {
        val line: CopyLine get() = CopyLine.of(CopyKey.INCOMING_VAULT, from, vaultName)
    }

    /**
     * §6.8 step 6: a contact answered or made a link with another key than the pinned one, or another device's
     * record names another key (§5.4). Nothing is replaced: the old key stays pinned and the new one is untrusted
     * until [ContactsApi.openCompare] ends in a match (R34).
     */
    class KeyChanged internal constructor(
        val userId: String,
        /** The label of the contact as pinned. */
        val label: String,
    ) : AccountPrompt() {
        val line: CopyLine get() = CopyLine.of(CopyKey.CONTACT_KEY_CHANGED, label)
    }

    /**
     * §6.9: a contact made on another device, not yet used on this one. One tap ([ContactsApi.useOnThisDevice])
     * makes it current here. The web never makes contacts, so a name the person does not recognise is a warning
     * sign (T-R6). (The engine's `ContactPrompt`.)
     *
     * The other answer is [ContactsApi.dontUseOnThisDevice]: the contact stays in the account, is not used on this
     * device, and this prompt does not return for it. It can still be confirmed later from the list
     * ([ContactsApi.confirmOnThisDevice]), or removed there.
     *
     * GAP (§6.9): the design gives "one tap each" and names no second button.
     */
    class NewPerson internal constructor(
        val userId: String,
        val label: String,
        /**
         * The device that made the contact: the name the person gave that device, as the account's device list has
         * it, shown as plain text. Empty when the account's record names a device this app cannot name (it is gone
         * from the list, or the list could not be read): [line] then says "another of your devices". The record
         * itself holds only a device id, which a hostile web page could forge (R24); the name the person recognises
         * on the contact is the real check.
         */
        val madeOn: String,
    ) : AccountPrompt() {
        val line: CopyLine
            get() = if (madeOn.isEmpty()) CopyLine.of(CopyKey.PERSON_FROM_ANOTHER_DEVICE, label) else CopyLine.of(CopyKey.PERSON_FROM_OTHER_DEVICE, madeOn, label)
    }

    /**
     * §8.5: this device signed in with only the password, so none of the account's contacts is current here. The
     * list is shown once, every row ticked, under [CopyKey.PEOPLE_TITLE] and [body]; the person unticks anyone they
     * do not recognise (R23).
     *
     * - [ContactsApi.usePeople] answers it: the ticked people are used on this device. The unticked stay in the
     *   account as "confirm on this device" and raise no prompt of their own afterwards.
     * - [ContactsApi.peopleLater] puts it off: nothing is used here, and the list does **not** come back at every
     *   unlock. It comes back when it matters, that is when someone on it shares a vault with this account, and
     *   whenever the person asks for it ([ContactsScreen.peopleNotReviewed], [ContactsApi.reviewPeople]).
     *
     * GAP (§8.5): the design does not say when the list returns after "Later"; the rule above is this API's.
     */
    class PeopleList internal constructor(
        val people: List<ContactRow>,
        /** The account's recovery record says operator: the body names the operator too. */
        val operatorClause: Boolean,
        /**
         * Whether this device could read the account's recovery record this opening.
         * False: [operatorClause] is not known (false here), and [body] says the operator may be among those who could
         * ([CopyKey.PEOPLE_BODY_OPERATOR_UNKNOWN], a placeholder), rather than dropping the clause.
         */
        val operatorClauseKnown: Boolean = true,
    ) : AccountPrompt() {
        val body: CopyKey get() = when {
            !operatorClauseKnown -> CopyKey.PEOPLE_BODY_OPERATOR_UNKNOWN
            operatorClause -> CopyKey.PEOPLE_BODY_OPERATOR
            else -> CopyKey.PEOPLE_BODY
        }
    }

    /**
     * §9.3 step 2: someone asked the operator to reset this account, and the request is in its hold. Shown on every
     * signed-in device at its next unlock, with [CopyKey.RECOVERY_REQUEST_ALERT]. Cancelling is
     * [RecoveryApi.cancelRecoveryRequest], signed by this account's key.
     */
    class RecoveryRequest internal constructor(
        val requests: List<RecoveryRequestRow>,
        /**
         * The server says there is a request (the sync's count) but its list could not be read, or does not show it:
         * [requests] may be empty. Say [CopyKey.RECOVERY_REQUEST_UNREADABLE] with the alert, and offer Settings' recovery
         * screen. Additive.
         */
        val unreadable: Boolean = false,
    ) : AccountPrompt() {
        /** The alert's line (approved wording). */
        val line: CopyKey get() = CopyKey.RECOVERY_REQUEST_ALERT

        /**
         * Under each row: when it was made ({0}), the kind of device it came from as the server says it ({1}), when the
         * wait ends ({2}), and that the operator will then be asked to help whoever made it set a new password. The
         * values are the row's own fields; the app formats the dates.
         */
        val rowLine: CopyKey get() = CopyKey.RECOVERY_REQUEST_DETAILS

        /** The second button: [RecoveryApi.recoveryRequestWasMe]. */
        val wasMe: CopyKey get() = CopyKey.RECOVERY_REQUEST_WAS_ME
    }

    /**
     * §4.5: the instance's recovery key changed and no statement signed by the old key covers the change. Nothing
     * is sealed to the new key unasked. The buttons are [CopyKey.RECOVERY_KEY_CHANGED_TURN_OFF] (the default),
     * [CopyKey.RECOVERY_KEY_CHANGED_KEEP] and [CopyKey.RECOVERY_KEY_CHANGED_LATER]; turning off and keeping both
     * need the master password. (The engine's `EscrowDecision.UnsignedChange`.)
     */
    class RecoveryKeyChanged internal constructor(val instance: InstanceLabel) : AccountPrompt() {
        val title: CopyLine get() = CopyLine.of(CopyKey.RECOVERY_KEY_CHANGED_TITLE, instance.name, instance.origin)
        val body: CopyKey get() = CopyKey.RECOVERY_KEY_CHANGED_BODY
    }

    /**
     * §4.5 (T2-R-e): the account's record says the operator may restore it, and this device has no record of its
     * own that the person chose that here (it signed in with the password, or was linked). So it seals nothing by
     * itself and asks. The buttons are [CopyKey.KEEP_OPERATOR_NOT_NOW] (the default: nothing is sealed, and it asks
     * again at the next unlock), [CopyKey.KEEP_OPERATOR_KEEP] and [CopyKey.KEEP_OPERATOR_TURN_OFF]; both changes need
     * the master password. (The engine's `EscrowDecision.AskOwnMirror`.)
     */
    class KeepOperatorRecovery internal constructor(val instance: InstanceLabel) : AccountPrompt() {
        val question: CopyLine get() = CopyLine.of(CopyKey.KEEP_OPERATOR_QUESTION, instance.name, instance.origin)
    }

    /**
     * §6.7 "Connect, recipient has no account": this account was created to connect with [from], and the answer to
     * their link could not be posted after the registration succeeded. The account exists; the connection does
     * not. (The engine's `RecipientStep.Stopped` from the `confirm` that follows a registration.)
     *
     * - [canRetry]: the server did not answer, and the link's flow is still held:
     *   [LinksApi.retryConnection] posts the same answer again.
     * - Otherwise the link is spent (someone answered first, it expired, or it failed a check): only a new link
     *   from them helps. [LinksApi.dropConnection] closes the prompt in both cases.
     *
     * GAP (§6.7): the design gives no wording for it.
     */
    class ConnectionNotMade internal constructor(
        /** The link's creator, as they call themselves. */
        val from: String,
        /** Why the answer was not posted. */
        val why: ConnectResult,
        val canRetry: Boolean,
    ) : AccountPrompt()

    /**
     * §6.7 Resume (R10): this is the instance's operator account, and the instance serves no identity card, because
     * its setup stopped between registering the operator and signing card 0. Shown at every unlock until the card
     * exists, with [CopyKey.FINISH_SERVER_SETUP]; until then the server refuses every other registration.
     * [OperatorApi.finishServerSetup] answers it. **Only a [DesktopAppApi] raises it** (the engine's
     * `SetupResume.due`): a phone app cannot sign a card (§9.5) and shows nothing.
     */
    class FinishServerSetup internal constructor(
        /** The server's address. It has no card yet, so there is no card name to show with it. */
        val origin: String,
    ) : AccountPrompt() {
        val label: CopyKey get() = CopyKey.FINISH_SERVER_SETUP
    }
}
