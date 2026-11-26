package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.WaitingChange
import io.silencelen.andvari.core.app.WaitingChanges
import io.silencelen.andvari.core.app.WaitingKind
import io.silencelen.andvari.core.app.WaitingNotice
import io.silencelen.andvari.core.app.WaitingResult
import io.silencelen.andvari.core.app.WaitingUndo
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.Job

/*
 * A change to a shared vault that waits to be sent (design §3.7), as the vault's row and page draw it, and what became of
 * one ([WaitingNotice]). Every line that says how a change stands is the shared code's; the phone adds only what the
 * shared code hands no line for (which change it is, the buttons it names none for). Every act hands back the very object
 * the screen drew from the snapshot on show, and its answer is said in the result's own sentence; STALE ("another change
 * waits now, or the account was locked or switched since") says nothing: the row is simply drawn again from the snapshot.
 */

/** The acts on a waiting change. */
internal enum class WaitingAct { WITHDRAW, DELETE_NOW }

/** The shared vaults' acts on a waiting change, where this API has them; null otherwise (and then no act is drawn). */
internal fun waitingActsOf(api: AppApi): WaitingChanges? = api.vaults as? WaitingChanges

/**
 * The buttons a waiting change's row offers, each only where the row itself offers it: for a deletion, its question's
 * two ("Delete it now" and "Keep the vault"), and only once the row says it asks ([WaitingChange.asksForWord]); for any
 * other change, "Withdraw" while [WaitingChange.canWithdraw] ([WaitingChange.withdrawLabel]).
 */
internal fun waitingActs(w: WaitingChange): List<WaitingAct> = when {
    w.kind == WaitingKind.DELETION -> if (!w.asksForWord) emptyList() else listOfNotNull(WaitingAct.DELETE_NOW, WaitingAct.WITHDRAW.takeIf { w.withdrawLabel != null })
    else -> listOfNotNull(WaitingAct.WITHDRAW.takeIf { w.withdrawLabel != null })
}

/** A button's words: the shared code's key for each. */
internal fun waitingActLabel(w: WaitingChange, act: WaitingAct): UiText = when (act) {
    WaitingAct.DELETE_NOW -> UiText.of(CopyKey.WAITING_DELETE_NOW)
    WaitingAct.WITHDRAW -> UiText.of(requireNotNull(w.withdrawLabel) { "withdraw is drawn only where the row offers it" })
}

/**
 * What a waiting change's row says, in order: which change it is (the member it names, by the key the change names them
 * by, and the role it gives; the phone's own line, since the shared code hands none), the shared code's line of how it
 * stands, "being sent" while it is, and the deletion's question once the row asks it.
 */
internal fun waitingLines(w: WaitingChange): List<UiText> = listOfNotNull(
    waitingKindLine(w),
    UiText.of(w.line),
    w.sendingLine?.let { UiText.of(it) },
    w.askLine?.let { UiText.of(it) },
)

/** Which change waits, naming the member and the role; null for a deletion and any other entry, whose line says it. */
internal fun waitingKindLine(w: WaitingChange): UiText? {
    val who = w.names?.let { personLine(it).shown() } ?: return null
    return when (w.kind) {
        WaitingKind.ADD -> w.role?.let { UiText.ph(Placeholder.WAITING_KIND_ADD, who, roleWord(it)) }
        WaitingKind.REMOVE -> UiText.ph(Placeholder.WAITING_KIND_REMOVE, who)
        WaitingKind.ROLE -> w.role?.let { to ->
            w.roleBack?.let { UiText.ph(Placeholder.WAITING_KIND_ROLE, who, roleWord(it), roleWord(to)) } ?: UiText.ph(Placeholder.WAITING_KIND_ROLE_TO, who, roleWord(to))
        }
        WaitingKind.OFFER -> UiText.ph(Placeholder.WAITING_KIND_OFFER, who)
        WaitingKind.DELETION, WaitingKind.OTHER -> null
    }
}

/**
 * What an act on a waiting change answered, said in place: the result's own sentence, also for the results that mean
 * done; a trouble's words; and nothing for STALE, which only means that the row is drawn again.
 */
internal fun waitingResultWords(r: WaitingResult, retryAfterSeconds: Int): UiText? =
    if (r == WaitingResult.STALE) null else r.sentence?.let { UiText.of(it) } ?: r.trouble?.let { OutcomeWords.trouble(it, retryAfterSeconds) }

/** "Withdraw", or "Keep the vault" for a deletion: on [change], the very object the row on show was drawn from. */
internal fun withdrawWaiting(model: TrustModel, change: WaitingChange): Job =
    model.runSaying({ waitingOf(this).withdrawWaiting(change) }, { waitingResultWords(it, model.api.retryAfterSeconds()) })

/** "Delete it now": on [change], the very object the row on show was drawn from. */
internal fun deleteWaitingNow(model: TrustModel, change: WaitingChange): Job =
    model.runSaying({ waitingOf(this).deleteWaitingNow(change) }, { waitingResultWords(it, model.api.retryAfterSeconds()) })

private fun waitingOf(api: AppApi): WaitingChanges = requireNotNull(waitingActsOf(api)) { "no act on a waiting change is drawn without them" }

/**
 * A shared vault's waiting change, on its row and on its page: its lines, then the buttons its row offers. Each button
 * acts on `w`, read from the row of the snapshot being drawn.
 */
@Composable
internal fun WaitingChangeView(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    val w = v.waiting ?: return
    for (line in waitingLines(w)) Say(line)
    if (waitingActsOf(model.api) == null) return
    ButtonRow {
        for (act in waitingActs(w)) {
            Quieter(waitingActLabel(w, act), enabled = !s.busy) {
                when (act) {
                    WaitingAct.WITHDRAW -> withdrawWaiting(model, w)
                    WaitingAct.DELETE_NOW -> deleteWaitingNow(model, w)
                }
            }
        }
    }
}

/** What "Close this move" answered: nothing where it was done (the line goes) and nothing for STALE (drawn again). */
internal fun frozenMoveCloseWords(r: VaultActionResult, retryAfterSeconds: Int): UiText? =
    if (r == VaultActionResult.DONE || r == VaultActionResult.STALE) null else UiText.forResult(r, retryAfterSeconds)

/** "Close this move" on [row], the very row on show. */
internal fun closeFrozenMove(model: TrustModel, row: SharedVaultRow): Job =
    model.runSaying({ waitingOf(this).closeFrozenMove(row) }, { frozenMoveCloseWords(it, model.api.retryAfterSeconds()) })

/** A move stopped on a frozen old vault: the shared code's line of what closing it does, and "Close this move". */
@Composable
internal fun FrozenMoveCloseView(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    val line = v.frozenMoveClose ?: return
    Say(UiText.of(line))
    if (waitingActsOf(model.api) == null) return
    Quieter(UiText.ph(Placeholder.MOVE_FROZEN_CLOSE_BUTTON), enabled = !s.busy) { closeFrozenMove(model, v) }
}

// ---- what became of a change: the notices ----

/** A notice's lines: the shared code's line, then the member it names, by the key the change named them by. */
internal fun waitingNoticeLines(n: WaitingNotice): List<UiText> = listOfNotNull(UiText.of(n.line), n.names?.let { personLine(it) })

/**
 * The undo a notice offers, by the values the act needs: the vault's id, the member's account id, and for a role the role
 * to change it back to. [who] only names the member in the question; the member is found by [memberId], never by a name.
 */
internal class WaitingUndoAsk internal constructor(
    val vaultId: String,
    val undo: WaitingUndo,
    val memberId: String?,
    val roleBack: MemberRole?,
    val who: PersonName?,
) {
    /** The ordinary act asks first (a removal's warning, a role change's question); the others act on the tap, as they do. */
    val asks: Boolean get() = undo == WaitingUndo.REMOVE_MEMBER || undo == WaitingUndo.CHANGE_ROLE_BACK
}

/**
 * The undo [n] offers, or null where it offers none, or where it names no member for an act on a member, or no role a
 * member can be given back: then there is nothing this phone could act on, and no button is drawn.
 */
internal fun waitingUndoOf(n: WaitingNotice): WaitingUndoAsk? {
    val undo = n.undo ?: return null
    return when (undo) {
        WaitingUndo.RESTORE_VAULT, WaitingUndo.CANCEL_OFFER -> WaitingUndoAsk(n.vaultId, undo, null, null, n.names)
        WaitingUndo.REMOVE_MEMBER, WaitingUndo.ADD_MEMBER -> n.memberId?.let { WaitingUndoAsk(n.vaultId, undo, it, null, n.names) }
        WaitingUndo.CHANGE_ROLE_BACK -> {
            val back = when (n.roleBack) {
                RoleInVault.WRITER -> MemberRole.WRITER
                RoleInVault.READER -> MemberRole.READER
                RoleInVault.OWNER, null -> return null
            }
            n.memberId?.let { WaitingUndoAsk(n.vaultId, undo, it, back, n.names) }
        }
    }
}

/** The undo's button: the ordinary act's own button words. */
internal fun waitingUndoLabel(u: WaitingUndoAsk): UiText = when (u.undo) {
    WaitingUndo.REMOVE_MEMBER -> UiText.ph(Placeholder.VAULT_REMOVE_MEMBER)
    WaitingUndo.ADD_MEMBER -> UiText.ph(Placeholder.VAULT_ADD_THIS_PERSON, undoWho(u))
    WaitingUndo.CHANGE_ROLE_BACK -> UiText.ph(Placeholder.ROLE_CHANGE_CONFIRM)
    WaitingUndo.CANCEL_OFFER -> UiText.ph(Placeholder.VAULT_CANCEL_OFFER)
    WaitingUndo.RESTORE_VAULT -> UiText.ph(Placeholder.VAULT_RESTORE)
}

private fun undoWho(u: WaitingUndoAsk): String = u.who?.let { personLine(it).shown() } ?: CopyKey.MEMBER_UNVERIFIED.english

/** The question an undo that asks puts first: the ordinary act's own (the removal's warning, the role change's question). */
internal fun waitingUndoQuestion(u: WaitingUndoAsk): List<UiText> = when (u.undo) {
    WaitingUndo.REMOVE_MEMBER -> listOf(UiText.of(CopyKey.REMOVE_MEMBER_WARNING))
    WaitingUndo.CHANGE_ROLE_BACK -> {
        val to = requireNotNull(u.roleBack)
        listOf(UiText.ph(Placeholder.ROLE_CHANGE_ASK, undoWho(u), roleWord(to)), UiText.ph(if (to == MemberRole.WRITER) Placeholder.ROLE_WRITER_ALLOWS else Placeholder.ROLE_READER_ALLOWS))
    }
    else -> emptyList()
}

/** Where an undo found nothing to act on: nothing was sent. The phone's own lines, as the shared code hands none. */
internal enum class UndoNotThere(val placeholder: Placeholder) : IntentResult {
    MEMBER_NOT_LISTED(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED),
    CONTACT_NOT_HERE(Placeholder.WAITING_UNDO_CONTACT_NOT_HERE),
    VAULT_GONE(Placeholder.WAITING_UNDO_VAULT_GONE),
    ;

    override val done: Boolean get() = false
    override val trouble: Trouble? get() = null
    override val sentence: CopyKey? get() = null
}

/**
 * The undo [u] as the ordinary act: on the vault's row on show now, and on the member listed with the account id the
 * notice names (an addition made after all is removed, a removal is undone by adding that contact again as a reader, as
 * the members screen adds, a role is changed back to the role the notice names). The members screen and the contacts are
 * opened for it where they were not, and closed again after (but for a share that waits for the uncompared warning,
 * which stays up). Nothing is done where the vault, the member or the contact is not there: [UndoNotThere].
 */
internal suspend fun AppApi.undoWaiting(u: WaitingUndoAsk): IntentResult {
    val row = snapshot.account?.vaults?.firstOrNull { it.vaultId == u.vaultId } ?: return UndoNotThere.VAULT_GONE
    when (u.undo) {
        WaitingUndo.RESTORE_VAULT -> return vaults.restoreVault(row)
        WaitingUndo.CANCEL_OFFER -> return vaults.cancelOffer(row)
        else -> Unit
    }
    val before = snapshot.account?.members
    val opened = before?.vault?.vaultId != u.vaultId
    if (opened) {
        val r = vaults.openMembers(row)
        if (!r.done) return r
    }
    var keepOpen = false
    try {
        val screen = snapshot.account?.members?.takeIf { it.vault.vaultId == u.vaultId } ?: return UndoNotThere.MEMBER_NOT_LISTED
        val member = screen.members.firstOrNull { it.userId == u.memberId }
        return when (u.undo) {
            WaitingUndo.REMOVE_MEMBER -> member?.let { vaults.removeMember(it) } ?: UndoNotThere.MEMBER_NOT_LISTED
            WaitingUndo.CHANGE_ROLE_BACK -> member?.let { vaults.changeRole(it, requireNotNull(u.roleBack)) } ?: UndoNotThere.MEMBER_NOT_LISTED
            else -> {
                val contactsOpened = snapshot.account?.contacts == null
                if (contactsOpened) contacts.openContacts()
                val contact = snapshot.account?.contacts?.contacts?.firstOrNull { it.userId == u.memberId }
                val r = if (contact == null) UndoNotThere.CONTACT_NOT_HERE else vaults.addMember(screen, contact, MemberRole.READER)
                if (contactsOpened && snapshot.account?.contacts != null) contacts.closeContacts()
                keepOpen = r == VaultActionResult.NEEDS_UNCOMPARED_WARNING
                r
            }
        }
    } finally {
        if (opened && !keepOpen && snapshot.account?.members != null) vaults.closeMembers()
    }
}

/** The undo's words: where nothing was there to act on, the phone's own line; otherwise as every vault act is said. */
internal fun undoWords(model: TrustModel, r: IntentResult): UiText? = (r as? UndoNotThere)?.let { UiText.ph(it.placeholder) } ?: model.wordsFor(r)

/** Runs the undo [u] (after its question, where it asks one). */
internal fun undoWaiting(model: TrustModel, u: WaitingUndoAsk): Job = model.runSaying({ undoWaiting(u) }, { undoWords(model, it) })

/** "Dismiss" on [n], the very notice on show. */
internal fun dismissWaitingNotice(model: TrustModel, n: WaitingNotice) {
    model.act { waitingActsOf(this)?.dismissWaitingNotice(n) }
}

/**
 * What became of a change this device let go of or sent again: the notice's lines, its undo where it offers one, and its
 * dismiss, the only thing that takes it away (the shared code keeps it across a lock and a restart).
 */
@Composable
internal fun WaitingNoticeView(model: TrustModel, s: AppSnapshot, n: WaitingNotice) {
    for (line in waitingNoticeLines(n)) Say(line)
    if (waitingActsOf(model.api) == null) return
    val undo = waitingUndoOf(n)
    var asking by remember(n.noticeId) { mutableStateOf(false) }
    ButtonRow {
        undo?.let { u -> Quieter(waitingUndoLabel(u), enabled = !s.busy) { if (u.asks) asking = true else undoWaiting(model, u) } }
        Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { dismissWaitingNotice(model, n) }
    }
    if (asking && undo != null) {
        AlertDialog(
            onDismissRequest = { asking = false },
            text = { Column { for (line in waitingUndoQuestion(undo)) Say(line) } },
            confirmButton = { TextButton(onClick = { asking = false; undoWaiting(model, undo) }) { Say(waitingUndoLabel(undo)) } },
            dismissButton = { TextButton(onClick = { asking = false }) { Say(CopyKey.CANCEL) } },
        )
    }
}
