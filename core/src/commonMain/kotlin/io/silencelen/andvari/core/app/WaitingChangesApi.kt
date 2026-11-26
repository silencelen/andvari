package io.silencelen.andvari.core.app

/*
 * A change to a shared vault that waits to be sent (design §3.7): what a screen draws for it, the acts on it, and the
 * notices about changes this device let go of or sent again. The words of every act come from the act's own result,
 * never from what was drawn before the tap. Nothing here sends a vault's deletion by itself, and nothing says "not made"
 * from a waiting change merely disappearing: only a notice ([WaitingNotice]) says what became of one.
 */

/** What a waiting change is ([WaitingChange.kind]). */
enum class WaitingKind {
    /** A member added ([WaitingChange.names], with [WaitingChange.role]). */
    ADD,

    /** A member removed ([WaitingChange.names]). */
    REMOVE,

    /** A member's role changed ([WaitingChange.names], to [WaitingChange.role]). */
    ROLE,

    /** Ownership offered to a member ([WaitingChange.names]). */
    OFFER,

    /** The vault's deletion, asked for by the person. */
    DELETION,

    /** Any other entry (a rename, a restore, a leave, an answer to an offer): it waits and is sent again; it is not withdrawn. */
    OTHER,
}

/** What this device knows of a waiting change ([WaitingChange.known]). */
enum class WaitingKnown {
    /** The server answered that it took it; the vault's log as read here does not show it yet. It cannot be withdrawn. */
    SERVER_SAYS_STORED,

    /** Known not made: every send so far was answered "slow down", which the server says before it looks at the change. */
    NOT_STORED,

    /** Cannot tell: a send had no answer that settles it, or one is out now. It may already be made. */
    CANNOT_TELL,
}

/**
 * The change this device signed for one shared vault and keeps to send again ([SharedVaultRow.waiting]), settled against
 * what this device has read of the vault's log before it is drawn. A move's own steps are not here: the move's row and
 * screen say them ([SharedVaultRow.unfinishedMove]).
 *
 * It names the very change it was drawn for, in the opening of the account it was drawn in: an act on it
 * ([WaitingChanges.withdrawWaiting], [WaitingChanges.deleteWaitingNow]) acts only where that change is still the one held
 * for the vault, in that same opening, and answers [WaitingResult.STALE] otherwise, sending and withdrawing nothing. A
 * screen hands back the object it drew, never one it made or kept from an earlier snapshot to stand for another.
 */
class WaitingChange internal constructor(
    val vaultId: String,
    val kind: WaitingKind,
    /**
     * The member the change names ([WaitingKind.ADD], [WaitingKind.REMOVE], [WaitingKind.ROLE], [WaitingKind.OFFER]); null
     * otherwise. Named only by the key the change itself names them by: where no contact current here has that key, the
     * name is [PersonName.Unverified], never a contact's label.
     */
    val names: PersonName?,
    /** The role an addition or a change of role gives; null otherwise. */
    val role: RoleInVault?,
    /** Since when this device holds it, unix milliseconds. */
    val sinceMs: Long,
    val known: WaitingKnown,
    /** A request of it is out now: show that it is being sent. */
    val sending: Boolean,
    /** [WaitingChanges.withdrawWaiting] is offered: "Withdraw" for a member's change, "Keep the vault" for a deletion. */
    val canWithdraw: Boolean,
    /**
     * A deletion of the vault that waits for the person's word, which a look in the vault's log (nothing sent) found still
     * waiting, less than a day old: ask [CopyKey.WAITING_DELETE_ASK] with "Delete it now" ([WaitingChanges.deleteWaitingNow],
     * [CopyKey.WAITING_DELETE_NOW]) and "Keep the vault" ([WaitingChanges.withdrawWaiting], [CopyKey.WAITING_KEEP_VAULT]).
     * False for a deletion not looked at yet: it is drawn as waiting, and nothing is asked.
     */
    val asksForWord: Boolean,
    /** The vault's name as the row has it, or null where this device cannot name it. */
    private val vaultName: String?,
    /** The account id of the member [names] names; null where the change names none. */
    val memberId: String?,
    /**
     * For [WaitingKind.ROLE]: the role the member holds in the vault's log as verified here, which they keep if the change
     * is withdrawn; null for the other kinds, or where the log does not list them.
     */
    val roleBack: RoleInVault?,
    /** The hash of the held change's signed entry this was drawn for. */
    internal val heldHash: String,
    /** The account's opening this was drawn in (a new one at every unlock and every sign-in). */
    internal val opening: Any,
) {
    /** [CopyKey.WAITING_DELETE_ASK] while [asksForWord], naming the vault (or [CopyKey.WAITING_UNNAMED_VAULT]); null otherwise. */
    val askLine: CopyLine?
        get() = if (!asksForWord) null else CopyLine.of(CopyKey.WAITING_DELETE_ASK, vaultName ?: CopyKey.WAITING_UNNAMED_VAULT.english)

    /**
     * The waiting line for the vault's row and panel, by [kind] and [known]; the member is drawn from [names] beside it. A
     * change the server says it stored offers no act, and its line promises none.
     */
    val line: CopyLine
        get() = CopyLine.of(
            when {
                kind == WaitingKind.DELETION && known == WaitingKnown.SERVER_SAYS_STORED -> CopyKey.WAITING_DELETE_SERVER_SAYS_STORED
                kind == WaitingKind.DELETION -> CopyKey.WAITING_DELETE
                known == WaitingKnown.SERVER_SAYS_STORED -> CopyKey.WAITING_SERVER_SAYS_STORED
                known == WaitingKnown.NOT_STORED -> CopyKey.WAITING_NOT_MADE_YET
                else -> CopyKey.WAITING_MAY_BE_MADE
            },
        )

    /** [CopyKey.WAITING_SENDING] while [sending]; null otherwise. */
    val sendingLine: CopyLine? get() = if (sending) CopyLine.of(CopyKey.WAITING_SENDING) else null

    /** The button for [WaitingChanges.withdrawWaiting] while [canWithdraw]: "Keep the vault" for a deletion, "Withdraw" otherwise. */
    val withdrawLabel: CopyKey? get() = if (!canWithdraw) null else if (kind == WaitingKind.DELETION) CopyKey.WAITING_KEEP_VAULT else CopyKey.WAITING_WITHDRAW
}

/** What a waiting change's act came to ([WaitingChanges]). Every outcome but a trouble has its own line, also where [done]. */
enum class WaitingResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null, private val did: Boolean = false) : IntentResult {
    /** Withdrawn where it was known not made: it was not made and will not be. */
    WITHDRAWN_NOT_MADE(sentence = CopyKey.WAITING_WITHDRAWN_NOT_MADE, did = true),

    /** Withdrawn where it may already be made: this device will not send it again; the log is read and a notice follows. */
    WITHDRAWN_MAY_BE_MADE(sentence = CopyKey.WAITING_WITHDRAWN_MAY_BE_MADE, did = true),

    /** "Keep the vault" where the deletion was known not made: the vault stays. */
    KEPT_NOT_DELETED(sentence = CopyKey.WAITING_KEPT_NOT_DELETED, did = true),

    /** "Keep the vault" where the deletion may already be made: not sent again; a notice follows. */
    KEPT_MAY_BE_DELETED(sentence = CopyKey.WAITING_KEPT_MAY_BE_DELETED, did = true),

    /** "Delete it now": the vault's log holds the deletion; it can be restored while its grace lasts. */
    DELETED(sentence = CopyKey.WAITING_DELETED, did = true),

    /** "Delete it now" was sent and no answer settled it: it still waits, and is asked about again later. */
    DELETE_STILL_WAITING(sentence = CopyKey.WAITING_DELETE_STILL_WAITING),

    /** "Delete it now": another change took the deletion's place, so it did not happen. */
    DELETE_DID_NOT_HAPPEN(sentence = CopyKey.WAITING_DELETE_DID_NOT_HAPPEN),

    /** "Delete it now": the server refused it; the vault was not deleted. */
    DELETE_REFUSED(sentence = CopyKey.WAITING_DELETE_REFUSED),

    /**
     * "Delete it now": the server refused this send, but an earlier send of the deletion got no answer that settles it, so
     * whether the vault was deleted cannot be told; this device stopped sending it, and a notice says what a later read finds.
     */
    DELETE_REFUSED_CANNOT_TELL(sentence = CopyKey.WAITING_DELETE_REFUSED_CANNOT_TELL),

    /** "Delete it now" while a move of the same vault runs, or while the move's own deletion of it waits: nothing was sent. */
    MOVE_IN_PROGRESS(sentence = CopyKey.WAITING_MOVE_IN_PROGRESS),

    /** The deletion waited more than a day between the question and the tap: nothing was sent, and it was given up. */
    DELETE_GIVEN_UP(sentence = CopyKey.WAITING_DELETE_GIVEN_UP),

    /** Its first request is still out: it can be withdrawn once that request has ended. */
    STILL_SENDING(sentence = CopyKey.WAITING_STILL_SENDING),

    /** The server's own answer said it took it: withdrawing cannot undo it; the act that undoes it can, once it is read back. */
    SERVER_SAYS_STORED(sentence = CopyKey.WAITING_SERVER_HAS_IT),

    /** Nothing waits for the vault any more (settled meanwhile): redraw; what became of it is a notice's. */
    NOTHING_WAITING(sentence = CopyKey.WAITING_NOTHING_WAITS),

    /** Not a change that is withdrawn, or not a deletion asked about. */
    NOT_OFFERED(sentence = CopyKey.WAITING_NOT_OFFERED),

    /** This device cannot read its record of the vault now: nothing was done and nothing is said either way. */
    RECORD_UNREADABLE(sentence = CopyKey.WAITING_RECORD_UNREADABLE),

    /**
     * The vault is frozen on this device (its server's record of it contradicts itself): andvari has stopped changing it
     * here for good, and nothing was sent.
     */
    FROZEN(sentence = CopyKey.WAITING_VAULT_FROZEN),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = did
}

/** The act that undoes a change found made after all ([WaitingNotice.undo]): each is the ordinary act, from its own screen. */
enum class WaitingUndo {
    /** An addition was made: remove the member again ([SharedVaultsApi.removeMember]). */
    REMOVE_MEMBER,

    /** A removal was made: share the vault with them again ([SharedVaultsApi.addMember]). */
    ADD_MEMBER,

    /** A change of role was made: change it back to [WaitingNotice.roleBack] ([SharedVaultsApi.changeRole]). */
    CHANGE_ROLE_BACK,

    /** An ownership offer was made: cancel it ([SharedVaultsApi.cancelOffer]). */
    CANCEL_OFFER,

    /** The vault was deleted: restore it while its grace lasts ([SharedVaultsApi.restoreVault]). */
    RESTORE_VAULT,
}

/**
 * What became of a change this device let go of or sent again, kept on the device until the person dismisses it
 * ([WaitingChanges.dismissWaitingNotice]), across locks and restarts. [line] names the vault ({0}: its name now, or
 * [CopyKey.WAITING_UNNAMED_VAULT] where this device cannot name it); the member is drawn from [names].
 */
class WaitingNotice internal constructor(
    /** Unique among the notices on show. */
    val noticeId: String,
    val vaultId: String,
    val kind: WaitingKind,
    /** The member the change named, by the key it named them by (as [WaitingChange.names]); null where it named none. */
    val names: PersonName?,
    val line: CopyLine,
    /**
     * The act that undoes a change found made after all; null for every other notice, and for a deletion of a vault that
     * no longer reads deleted here (the line then says so).
     */
    val undo: WaitingUndo?,
    /** The account id of the member [names] names, for the undo to act on; null where the change named none. */
    val memberId: String?,
    /**
     * For [WaitingUndo.CHANGE_ROLE_BACK]: the role to change it back to (the one the member held when this device let go of
     * the change); null otherwise. Where it is not known, no undo is offered.
     */
    val roleBack: RoleInVault?,
)

/**
 * The acts on a waiting change, asked for with `as?` on the [AppApi]'s [SharedVaultsApi] (the engine's and the stand-in's
 * implement it), so no implementer of the interfaces breaks. Each runs only from the person's own tap.
 */
interface WaitingChanges {
    /**
     * "Withdraw" ([WaitingChange.canWithdraw]), and "Keep the vault" for a deletion that waits. The words come from the
     * result, never from [change] as it was drawn. Acts only on the very change [change] was drawn for, in the opening it
     * was drawn in: [WaitingResult.STALE] otherwise (another change waits now, or the account was locked, signed out or
     * switched since), and nothing is withdrawn; redraw from the snapshot.
     */
    suspend fun withdrawWaiting(change: WaitingChange): WaitingResult

    /**
     * "Delete it now", only for a deletion that [WaitingChange.asksForWord]: sends the deletion as it was signed. Acts only
     * on the very deletion [change] was drawn for, in the opening it was drawn in, and only after this opening's own look
     * at that deletion: [WaitingResult.STALE] otherwise, and nothing is sent.
     */
    suspend fun deleteWaitingNow(change: WaitingChange): WaitingResult

    /** The person saw or dismissed [notice]: it is forgotten. One no longer on show changes nothing. */
    fun dismissWaitingNotice(notice: WaitingNotice)

    /**
     * Close a move that stopped because its old vault froze ([SharedVaultRow.frozenMoveClose], the line that says what
     * this does): this device's record of the unfinished move and its mark of a waiting deletion go. Nothing is sent, and
     * nothing changes in either vault: the copied items stay in the new vault, the old vault stays at its server with what
     * it held and stays frozen and read-only here. DONE; STALE where no such move is on show.
     */
    fun closeFrozenMove(vault: SharedVaultRow): VaultActionResult
}
