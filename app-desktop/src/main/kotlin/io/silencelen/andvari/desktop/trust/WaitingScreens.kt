package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.WaitingChange
import io.silencelen.andvari.core.app.WaitingKind
import io.silencelen.andvari.core.app.WaitingNotice
import io.silencelen.andvari.core.app.WaitingResult
import io.silencelen.andvari.core.app.WaitingUndo
import io.silencelen.andvari.core.trust.MemberRole

/*
 * A change to a shared vault that waits to be sent (design §3.7), as the shared code hands it: on the vault's row its line,
 * the member it names, "being sent", and only the acts the row offers; a deletion of the vault asked about only once the
 * row says it asks; each act's answer in the result's own sentence; the notices of what became of a change, kept until the
 * person dismisses them; and closing a move that stopped on a frozen old vault. Every act is handed the very object the
 * screen drew from the snapshot on show, never one kept from an earlier snapshot or made here.
 */

/** The acts a waiting change's row can offer. */
internal enum class WaitingAct {
    /** "Withdraw" for a member's change, "Keep the vault" for a deletion ([WaitingChange.withdrawLabel]). */
    WITHDRAW,

    /** "Delete it now", only while the row asks about the deletion ([WaitingChange.asksForWord]). */
    DELETE_NOW,
}

/** One button of a waiting change's row: its act and its label, which is the shared code's. */
internal class WaitingButton(val act: WaitingAct, val label: UiText)

/** What the vault's row draws for its waiting change: its lines, the question about a deletion, and the buttons it offers. */
internal class WaitingDrawn(val lines: List<UiText>, val ask: UiText?, val buttons: List<WaitingButton>)

/**
 * What the row draws for [w]: the shared code's waiting line ([WaitingChange.line]); the member it names beside it, with
 * the role it gives; "being sent" while it is ([WaitingChange.sendingLine]). A deletion's question
 * ([WaitingChange.askLine]) and its two buttons only while the row asks ([WaitingChange.asksForWord]), the way out
 * ("Keep the vault") first; before that a deletion is drawn as waiting and nothing is asked. Any other change has
 * "Withdraw" only where the row offers it ([WaitingChange.withdrawLabel]).
 */
internal fun waitingDrawn(w: WaitingChange): WaitingDrawn {
    val lines = ArrayList<UiText>()
    lines += UiText.of(w.line)
    w.names?.let { lines += memberWithRole(it, w.role) }
    w.sendingLine?.let { lines += UiText.of(it) }
    val buttons = ArrayList<WaitingButton>()
    if (w.kind == WaitingKind.DELETION) {
        if (w.asksForWord) {
            w.withdrawLabel?.let { buttons += WaitingButton(WaitingAct.WITHDRAW, UiText.of(it)) }
            buttons += WaitingButton(WaitingAct.DELETE_NOW, UiText.of(CopyKey.WAITING_DELETE_NOW))
        }
    } else {
        w.withdrawLabel?.let { buttons += WaitingButton(WaitingAct.WITHDRAW, UiText.of(it)) }
    }
    return WaitingDrawn(lines, w.askLine?.let { UiText.of(it) }, buttons)
}

/** A member as the members list draws them, with the role a change gives where it gives one. */
private fun memberWithRole(who: PersonName, role: RoleInVault?): UiText =
    UiText.Plain(personLine(who).shown() + (role?.let { "  ·  " + it.name.lowercase() } ?: ""))

/**
 * What a waiting change's act answered, in place: the result's own sentence, also for the results that mean done; a
 * trouble's line where the result has no sentence; and nothing at all for [WaitingResult.STALE], which means that nothing
 * happened and the row is drawn again from the snapshot on show.
 */
internal fun waitingAnswer(r: WaitingResult, retryAfterSeconds: Int): UiText? {
    if (r == WaitingResult.STALE) return null
    r.sentence?.let { return UiText.of(it) }
    return UiText.forResult(r, retryAfterSeconds)
}

/** What a notice says, in order: the shared code's line, then the member it names, as the shared code names them. */
internal fun waitingNoticeLines(n: WaitingNotice): List<UiText> = listOfNotNull(UiText.of(n.line), n.names?.let(::personLine))

/** The trust layer's role for [role], where an owner can give it (writer or reader); null for the owner. */
internal fun givenRole(role: RoleInVault?): MemberRole? = when (role) {
    RoleInVault.WRITER -> MemberRole.WRITER
    RoleInVault.READER -> MemberRole.READER
    RoleInVault.OWNER, null -> null
}

/**
 * The undo a notice offers ([WaitingNotice.undo]), with the label of the ordinary act it is; null where it offers none,
 * and where an undo on a member names no member ([WaitingNotice.memberId]) or no role an owner can give back.
 */
internal fun undoLabel(n: WaitingNotice): UiText? = when (n.undo) {
    null -> null
    WaitingUndo.RESTORE_VAULT -> UiText.ph(Placeholder.VAULT_RESTORE)
    WaitingUndo.CANCEL_OFFER -> UiText.ph(Placeholder.VAULT_CANCEL_OFFER)
    WaitingUndo.REMOVE_MEMBER -> n.memberId?.let { UiText.ph(Placeholder.VAULT_REMOVE_MEMBER) }
    WaitingUndo.ADD_MEMBER -> n.memberId?.let { UiText.ph(Placeholder.VAULT_ADD_THIS_PERSON, personLine(n.names ?: return@let null).shown()) }
    WaitingUndo.CHANGE_ROLE_BACK -> if (n.memberId == null) null else givenRole(n.roleBack)?.let { UiText.ph(Placeholder.WAITING_UNDO_ROLE_BACK, it.literal) }
}

/** What an undo from a notice came to: the ordinary act's own answer, or why the desktop did not call it. */
internal sealed class WaitingUndoAnswer : IntentResult {
    /** The ordinary act was called; [result] is its answer. */
    class Acted(val result: IntentResult) : WaitingUndoAnswer() {
        override val done: Boolean get() = result.done
        override val trouble: Trouble? get() = result.trouble
        override val sentence: CopyKey? get() = result.sentence
    }

    /** Nothing was called: the vault or the member the notice names is not where the act needs them ([why] says which). */
    class NotCalled(val why: Placeholder) : WaitingUndoAnswer() {
        override val done: Boolean get() = false
        override val trouble: Trouble? get() = null
        override val sentence: CopyKey? get() = null
    }
}

/** The line for [a]: the ordinary act's own, or the desktop's line for an act it did not call. */
internal fun undoWords(a: WaitingUndoAnswer, retryAfterSeconds: Int): UiText? = when (a) {
    is WaitingUndoAnswer.Acted -> UiText.forResult(a.result, retryAfterSeconds)
    is WaitingUndoAnswer.NotCalled -> UiText.ph(a.why)
}

/**
 * The undo of [n], the ordinary act on the vault and the member the notice names: the restore and the cancelled offer on
 * the vault's row as listed now; the others on the member whose account id is [WaitingNotice.memberId] in the vault's
 * member list (opened for it), never on a member found by a name. "Change it back" gives [WaitingNotice.roleBack];
 * sharing the vault again goes to the contact with that account id, as a reader (the notice names no role for it).
 * [moveInstead]: in place of removing the member, the remove dialog's other way, "Move everything", for that member.
 */
internal suspend fun DesktopAppApi.undoNoticeAct(n: WaitingNotice, moveInstead: Boolean = false): WaitingUndoAnswer {
    val undo = checkNotNull(n.undo) { "a notice without an undo has no undo button" }
    val row = snapshot.account?.vaults?.firstOrNull { it.vaultId == n.vaultId }
        ?: return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_VAULT_NOT_LISTED)
    when (undo) {
        WaitingUndo.RESTORE_VAULT -> return WaitingUndoAnswer.Acted(vaults.restoreVault(row))
        WaitingUndo.CANCEL_OFFER -> return WaitingUndoAnswer.Acted(vaults.cancelOffer(row))
        else -> {}
    }
    val id = n.memberId ?: return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED)
    val opened = vaults.openMembers(row)
    if (!opened.done) return WaitingUndoAnswer.Acted(opened)
    val screen = snapshot.account?.members?.takeIf { it.vault.vaultId == n.vaultId }
        ?: return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED)
    val listed = screen.members.firstOrNull { it.userId == id }
    return when (undo) {
        WaitingUndo.REMOVE_MEMBER -> listed?.let { WaitingUndoAnswer.Acted(if (moveInstead) vaults.openMoveEverythingRemoving(it) else vaults.removeMember(it)) }
            ?: WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED)
        WaitingUndo.CHANGE_ROLE_BACK -> {
            val role = givenRole(n.roleBack) ?: return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED)
            listed?.let { WaitingUndoAnswer.Acted(vaults.changeRole(it, role)) } ?: WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED)
        }
        WaitingUndo.ADD_MEMBER -> {
            if (listed != null) return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_ALREADY_MEMBER)
            if (snapshot.account?.contacts == null) {
                val c = contacts.openContacts()
                if (!c.done) return WaitingUndoAnswer.Acted(c)
            }
            val contact = snapshot.account?.contacts?.contacts?.firstOrNull { it.userId == id }
                ?: return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_NOT_A_CONTACT)
            val now = snapshot.account?.members?.takeIf { it.vault.vaultId == n.vaultId }
                ?: return WaitingUndoAnswer.NotCalled(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED)
            WaitingUndoAnswer.Acted(vaults.addMember(now, contact, MemberRole.READER))
        }
        WaitingUndo.RESTORE_VAULT, WaitingUndo.CANCEL_OFFER -> error("handled above")
    }
}

/**
 * Told each time the Sharing page draws a waiting change, a notice or a move to close, with the very tap its buttons
 * call. Nothing listens in the app; a test listens, to see what is drawn and to tap it as a person would.
 */
internal interface WaitingTaps {
    fun row(v: SharedVaultRow, drawn: WaitingDrawn, tap: (WaitingAct) -> Unit) {}

    fun notice(n: WaitingNotice, lines: List<UiText>, undo: UiText?, act: () -> Unit, dismiss: () -> Unit) {}

    fun frozenMove(v: SharedVaultRow, line: UiText, close: () -> Unit) {}
}

internal val LocalWaitingTaps = staticCompositionLocalOf<WaitingTaps> { object : WaitingTaps {} }

/** The waiting change on a shared vault's row ([SharedVaultRow.waiting]), as [waitingDrawn] has it; nothing when none waits. */
@Composable
internal fun WaitingOnRow(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    val w = v.waiting ?: return
    val drawn = waitingDrawn(w)
    for (line in drawn.lines) Quiet(line)
    drawn.ask?.let { Say(it) }
    // The object drawn here, from the snapshot on show, is the one each act is handed.
    val tap: (WaitingAct) -> Unit = { act -> model.actOnWaiting(w, act) }
    if (drawn.buttons.isNotEmpty() && model.waitingActs() != null) {
        Actions { for (b in drawn.buttons) Quieter(b.label, enabled = !s.busy) { tap(b.act) } }
    }
    val taps = LocalWaitingTaps.current
    SideEffect { taps.row(v, drawn, tap) }
}

/** A move out of [v] that stopped on its frozen old vault: the shared code's line of what closing does, and "Close this move". */
@Composable
internal fun FrozenMoveClose(model: TrustModel, s: AppSnapshot, v: SharedVaultRow, line: CopyLine) {
    val text = UiText.of(line)
    Say(text)
    val close = { model.closeFrozenMove(v) }
    if (model.waitingActs() != null) Quieter(UiText.ph(Placeholder.MOVE_FROZEN_CLOSE_BUTTON), enabled = !s.busy) { close() }
    val taps = LocalWaitingTaps.current
    SideEffect { taps.frozenMove(v, text, close) }
}

/**
 * What became of a change this device let go of or sent again ([io.silencelen.andvari.core.app.AccountSnapshot.waitingNotices]):
 * its lines, its undo where it offers one, and the dismiss, the one way it goes. Removing a member again asks first, with
 * the remove dialog's own words and its other way ("Move everything").
 */
@Composable
internal fun WaitingNoticeCard(model: TrustModel, s: AppSnapshot, notice: WaitingNotice) {
    var askingRemove by remember(notice.noticeId) { mutableStateOf(false) }
    val lines = waitingNoticeLines(notice)
    val undo = undoLabel(notice)
    val act = { model.undoWaiting(notice); Unit }
    val dismiss = { model.dismissWaitingNotice(notice) }
    Column(Modifier.padding(vertical = 8.dp)) {
        for (line in lines) Say(line)
        Actions {
            undo?.let { label ->
                Quieter(label, enabled = !s.busy) { if (notice.undo == WaitingUndo.REMOVE_MEMBER) askingRemove = true else act() }
            }
            if (model.waitingActs() != null) Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { dismiss() }
        }
    }
    if (askingRemove) {
        AlertDialog(
            onDismissRequest = { askingRemove = false },
            text = { Say(CopyKey.REMOVE_MEMBER_WARNING) },
            // The way out comes first and is the dialog's dismiss; the design's own alternative sits beside it.
            dismissButton = {
                Row {
                    DialogButton(UiText.of(CopyKey.CANCEL)) { askingRemove = false }
                    DialogButton(UiText.of(CopyKey.MOVE_EVERYTHING)) { askingRemove = false; model.undoWaiting(notice, moveInstead = true) }
                }
            },
            confirmButton = { DialogButton(UiText.ph(Placeholder.VAULT_REMOVE_MEMBER)) { askingRemove = false; act() } },
        )
    }
    val taps = LocalWaitingTaps.current
    SideEffect { taps.notice(notice, lines, undo, act, dismiss) }
}
