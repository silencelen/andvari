package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.OwnershipOfferRow
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MembersScreen
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveKept
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.MoveStop
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.trust.MemberRole
import java.text.DateFormat
import java.util.Date

/** A person as the design names them: a contact's label only where the key is the pinned one, else the server's word marked as such. */
internal fun personLine(p: PersonName): UiText = when (p) {
    is PersonName.Contact -> UiText.Plain(p.label)
    is PersonName.Unverified -> UiText.Plain(CopyKey.MEMBER_UNVERIFIED.english + (p.serverName?.let { ": $it" } ?: ""))
    is PersonName.You -> UiText.ph(Placeholder.VAULT_YOU)
}

/** Each log state's line: the design's sentence where it gives one, otherwise a placeholder naming the state. */
internal fun logStateLine(row: SharedVaultRow): UiText? = when (row.log) {
    VaultLogState.VERIFIED -> null
    VaultLogState.CONNECT_FIRST -> row.connectFirstLine?.let { UiText.of(it) }
    VaultLogState.REMOVED -> UiText.ph(if (row.removedByOwner) Placeholder.VAULT_REMOVED_BY_OWNER else Placeholder.VAULT_REMOVED_UNVERIFIED)
    // Approved entries 22, 23 and 20.
    VaultLogState.FROZEN -> UiText.approved("VAULT_HISTORY_FORKED.body")
    VaultLogState.KEY_MISSING -> UiText.approved("VAULT_KEY_MISSING.body")
    VaultLogState.CONFIRM_FIRST -> row.senderToConfirm?.let { UiText.approved("INCOMING_CONFIRM_FIRST.body", it.label) }
        ?: UiText.ph(Placeholder.VAULT_LOG_STATE, row.log.name)
    else -> row.log.sentence?.let { UiText.of(it) } ?: UiText.ph(Placeholder.VAULT_LOG_STATE, row.log.name)
}

/** A shared vault row's second line: this account's role in it, as the current app's "shared vault · reader". */
internal fun roleLine(role: RoleInVault): UiText = UiText.ph(
    when (role) {
        RoleInVault.OWNER -> Placeholder.VAULT_ROLE_OWNER
        RoleInVault.WRITER -> Placeholder.VAULT_ROLE_WRITER
        RoleInVault.READER -> Placeholder.VAULT_ROLE_READER
    },
)

/** A row's name; a vault no key opens has none, and the approved title stands in for it (entry 23). */
internal fun vaultRowName(row: SharedVaultRow): String =
    row.name ?: if (row.log == VaultLogState.KEY_MISSING) ApprovedCopy.words("VAULT_KEY_MISSING.title") else vaultSlot(null).text

/**
 * The note on a vault while an ownership offer is open: the approved line (entry 26) where this account made it;
 * where it is offered to this account the design gives no words yet.
 */
internal fun offerLine(row: SharedVaultRow, o: OwnershipOfferRow, date: DateFormat): UiText =
    if (o.toMe) {
        UiText.ph(Placeholder.VAULT_OFFER, personLine(o.to).shown())
    } else {
        UiText.Plain(ApprovedCopy.lineWith("OWNERSHIP_OFFER.body", 1, said(personLine(o.to).shown()), vaultSlot(row.name), said(date.format(Date(o.expiresAtMs)))))
    }

/** A frozen, failed or withheld vault, or one in the holding area: what is copied out may have been changed. */
internal fun mustWarnBeforeCopy(row: SharedVaultRow): Boolean =
    row.log == VaultLogState.FROZEN || row.log == VaultLogState.FAILED || row.log == VaultLogState.WITHHELD || row.heldUntilMs > 0

/**
 * Shared vaults (map §3.12 to §3.14), ported from the Android app: create; each vault with its name, role, owner,
 * every log state, the history hint, the owner out of space, deletion in grace, a pending ownership offer; the actions
 * its role allows. Members ([MembersView]) and "Move everything to a new vault" ([MoveEverythingView]) open above the
 * list. Most of the API behind it is still a stand-in on the engine; the screens are tested over the fake.
 */
@Composable
internal fun SharedVaultsSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {
    SectionTitle(Placeholder.SHARED_VAULTS)
    account.members?.let { MembersView(model, s, account, it) }
    account.moving?.let { MoveEverythingView(model, s, it) }
    val date = DateFormat.getDateInstance(DateFormat.MEDIUM)
    for (v in account.vaults) {
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            // A vault is a row with its letter, as the current app's Vaults card draws it; the role is its second line.
            // The role in words of its own, as the current app's "shared vault · reader", never the enum's name (found in the run).
            LetterHead(vaultRowName(v), v.role?.let { roleLine(it) })
            v.owner?.let { Quiet(UiText.ph(Placeholder.VAULT_OWNER, personLine(it).shown())) }
            logStateLine(v)?.let { Say(it, color = if (v.log == VaultLogState.FAILED || v.log == VaultLogState.KEY_REFUSED) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface) }
            if (v.historyHint) Quiet(UiText.of(CopyKey.VAULT_HISTORY_HINT))
            if (v.ownerOutOfSpace) {
                Quiet(UiText.of(CopyKey.OWNER_OUT_OF_SPACE))
                // Approved entries 27 and 28: whose space it is (core picks by the row's role).
                v.outOfSpaceLine?.let { Quiet(UiText.of(it)) }
            }
            deletedVaultLine(v, date)?.let { line ->
                Quiet(line)
                val drawn = LocalDeletedVaultDrawn.current
                androidx.compose.runtime.SideEffect { drawn(v, line) }
            }
            if (v.heldUntilMs > 0) Quiet(UiText.ph(Placeholder.VAULT_HELD_UNTIL, date.format(Date(v.heldUntilMs))))
            // The change that waits, as the shared code hands it ([WaitingOnRow]); approved entry 24's second line, the row's
            // mark until the server confirms, only where it hands none (a move's own step, say).
            if (v.waiting != null) WaitingOnRow(model, s, v) else if (v.changeWaiting) Quiet(UiText.approvedLine("VAULT_CHANGE_WAITING.body", 1))
            v.frozenMoveClose?.let { FrozenMoveClose(model, s, v, it) }
            v.senderToConfirm?.let { c -> Second(UiText.of(CopyKey.CONFIRM_ON_THIS_DEVICE), enabled = !s.busy) { model.run({ contacts.confirmOnThisDevice(c) }) } }
            v.offer?.let { o ->
                Quiet(offerLine(v, o, date))
                if (o.toMe) {
                    Second(UiText.ph(Placeholder.VAULT_ACCEPT_OWNERSHIP), enabled = !s.busy) { model.run({ vaults.acceptOwnership(v) }) }
                } else if (v.role == RoleInVault.OWNER) {
                    Quieter(UiText.ph(Placeholder.VAULT_CANCEL_OFFER), enabled = !s.busy) { model.run({ vaults.cancelOffer(v) }) }
                }
            }
            VaultActions(model, s, v)
        }
        HorizontalDivider()
    }
    var name by remember { mutableStateOf("") }
    Field(UiText.ph(Placeholder.VAULT_NAME_FIELD), name) { name = it }
    Second(UiText.ph(Placeholder.VAULT_CREATE), enabled = name.isNotBlank() && !s.busy) {
        val n = name.trim()
        model.run({ vaults.createVault(n) }) { if (it.done) name = "" }
    }
}

/**
 * Told each time a deleted shared vault's line is drawn on the Sharing page, with its row. Nothing listens in the app; a
 * test listens, to see what the page draws for a vault whose day the server did not serve.
 */
internal val LocalDeletedVaultDrawn = androidx.compose.runtime.staticCompositionLocalOf<(SharedVaultRow, UiText) -> Unit> { { _, _ -> } }

/**
 * A deleted shared vault's line ([SharedVaultRow.deleted]): restorable until its day where the server served one, else
 * the shared code's line that names no day ([SharedVaultRow.deletedNoDayLine]), as handed. Null for a vault not deleted.
 */
internal fun deletedVaultLine(v: SharedVaultRow, date: DateFormat): UiText? = when {
    !v.deleted -> null
    v.purgeAtMs > 0 -> UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, date.format(Date(v.purgeAtMs)))
    else -> v.deletedNoDayLine?.let { UiText.of(it) }
}

@Composable
private fun VaultActions(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    var confirmCopy by remember(v.vaultId) { mutableStateOf(false) }
    val owner = v.role == RoleInVault.OWNER
    Actions {
        if (v.role != null && v.log != VaultLogState.PURGED) {
            Quieter(UiText.ph(Placeholder.VAULT_MEMBERS), enabled = !s.busy) { model.run({ vaults.openMembers(v) }) }
        }
        // A deleted vault is read from its own field, never from the day (a server may serve none).
        if (owner && v.deleted) {
            Quieter(UiText.ph(Placeholder.VAULT_RESTORE), enabled = !s.busy) { model.run({ vaults.restoreVault(v) }) }
        } else if (owner && v.writable) {
            Quieter(UiText.ph(Placeholder.VAULT_DELETE), enabled = !s.busy) { model.run({ vaults.deleteVault(v) }) }
            Quieter(UiText.of(CopyKey.MOVE_EVERYTHING), enabled = !s.busy) { model.run({ vaults.openMoveEverything(v) }) }
        } else if (v.role != null && !owner && v.log != VaultLogState.REMOVED && v.log != VaultLogState.PURGED) {
            Quieter(UiText.ph(Placeholder.VAULT_LEAVE), enabled = !s.busy) { model.run({ vaults.leaveVault(v) }) }
        }
    }
    if (owner && !v.deleted && v.writable) RenameVaultControl(model, s, v)
    Actions {
        if (v.canSaveElsewhere) {
            Quieter(UiText.ph(Placeholder.VAULT_SAVE_ELSEWHERE), enabled = !s.busy) {
                if (mustWarnBeforeCopy(v)) confirmCopy = true else model.run({ vaults.saveItemsElsewhere(v, null) })
            }
        }
        if (v.canRemoveFromDevice) Quieter(UiText.of(CopyKey.REMOVE_FROM_THIS_DEVICE), enabled = !s.busy) { model.act { vaults.removeFromThisDevice(v) } }
    }
    if (confirmCopy) {
        AlertDialog(
            onDismissRequest = { confirmCopy = false },
            text = { Say(CopyKey.CHECK_WHAT_YOU_COPY) },
            // The way out comes first and is the dialog's dismiss.
            dismissButton = { TextButton(onClick = { confirmCopy = false }) { Say(CopyKey.CANCEL) } },
            confirmButton = { TextButton(onClick = { confirmCopy = false; model.run({ vaults.saveItemsElsewhere(v, null) }) }) { Say(Placeholder.VAULT_SAVE_ELSEWHERE) } },
        )
    }
}

/**
 * Rename a shared vault this account owns, while it is writable. The call is the vault content's
 * ([io.silencelen.andvari.core.app.content.VaultContent.renameSharedVault]: the name is encrypted and syncs to every
 * member), because the app API's `renameVault` is not bound to the engine yet (as on Android). The content
 * checks the name, the role and the vault itself; what it refuses is said in its own words. Offered only while the
 * vault is open (a content instance exists).
 */
@Composable
private fun RenameVaultControl(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    val content by model.content.collectAsState()
    val c = content ?: return
    val scope = rememberWorkScope()
    var editing by remember(v.vaultId) { mutableStateOf(false) }
    var name by remember(v.vaultId) { mutableStateOf(v.name ?: "") }
    var said by remember(v.vaultId) { mutableStateOf<String?>(null) }
    var busy by remember(v.vaultId) { mutableStateOf(false) }
    if (!editing) {
        Quieter(UiText.ph(Placeholder.VAULT_RENAME), enabled = !s.busy) {
            name = v.name ?: ""
            said = null
            editing = true
        }
        return
    }
    val save = {
        if (!busy && !s.busy && name.isNotBlank()) {
            busy = true
            scope.launch(vaultRowName(v)) {
                val r = try {
                    c.renameSharedVault(v.vaultId, name)
                } finally {
                    busy = false
                }
                said = renameSentence(r)
                if (said == null) editing = false
            }
        }
    }
    Field(UiText.ph(Placeholder.VAULT_NAME_FIELD), name, onEnter = { save() }) { name = it }
    said?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Quieter(UiText.of(CopyKey.CANCEL), enabled = !busy) { editing = false }
        Quieter(UiText.ph(Placeholder.VAULT_RENAME_SAVE), enabled = !busy && !s.busy && name.isNotBlank()) { save() }
    }
}

/** What a rename answered, in the content's words; null when it was done. */
internal fun renameSentence(r: ActionResult): String? = when (r) {
    is ActionResult.Failed -> r.message
    is ActionResult.NotDone -> r.message ?: UiText.ph(Placeholder.VAULT_RENAME_NOT_DONE).shown()
    else -> null
}

/**
 * Members (§3.13): each member as the design names them; "may be incomplete"; an account the operator deleted, with
 * "Remove from the list"; for the owner, role changes, remove (behind the warning, which offers "Move everything to a
 * new vault"), offer ownership, and adding a contact with a role.
 */
@Composable
private fun MembersView(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, screen: MembersScreen) {
    var removing by remember(screen.vault.vaultId) { mutableStateOf<MemberRow?>(null) }
    var offering by remember(screen.vault.vaultId) { mutableStateOf<MemberRow?>(null) }
    Say(UiText.phWith(Placeholder.VAULT_MEMBERS_OF, vaultSlot(screen.vault.name)), style = MaterialTheme.typography.titleSmall)
    // Approved entry 25: core's MEMBERS_MAY_BE_INCOMPLETE in brackets after the heading, the new line under the list.
    if (screen.mayBeIncomplete) Quiet(UiText.Plain("(" + CopyKey.MEMBERS_MAY_BE_INCOMPLETE.english + ")"))
    for (m in screen.members) {
        Text(personLine(m.who).shown() + "  ·  " + m.role.name.lowercase())
        m.deletedLine?.let { line ->
            Say(line)
            Quieter(UiText.of(CopyKey.REMOVE_FROM_THE_LIST), enabled = !s.busy) { model.run({ vaults.removeMember(m) }) }
        }
        if (screen.canManage && m.who !is PersonName.You && !m.deletedByOperator) {
            Actions {
                val next = if (m.role == RoleInVault.READER) MemberRole.WRITER else MemberRole.READER
                Quieter(UiText.ph(Placeholder.LINK_ROLE_SWITCH), enabled = !s.busy && m.role != RoleInVault.OWNER) { model.run({ vaults.changeRole(m, next) }) }
                Quieter(UiText.ph(Placeholder.VAULT_REMOVE_MEMBER), enabled = !s.busy) { removing = m }
                Quieter(UiText.ph(Placeholder.VAULT_OFFER_OWNERSHIP), enabled = !s.busy && m.role != RoleInVault.OWNER) { offering = m }
            }
        }
    }
    if (screen.mayBeIncomplete) Quiet(UiText.approved("MEMBERS_MAY_BE_INCOMPLETE_WHY.body"))
    if (screen.canManage) {
        val inVault = screen.members.map { it.userId }.toSet()
        val contacts = account.contacts?.contacts
        if (contacts == null) {
            Quieter(UiText.ph(Placeholder.VAULT_ADD_MEMBER), enabled = !s.busy) { model.run({ this.contacts.openContacts() }) }
        } else {
            for (c in contacts.filter { it.userId !in inVault }) {
                Quieter(UiText.ph(Placeholder.VAULT_ADD_THIS_PERSON, c.label), enabled = !s.busy) { model.run({ vaults.addMember(screen, c, MemberRole.READER) }) }
            }
        }
    }
    // Approved entry 26: the dialog before an ownership offer (fixed at 14 days); Cancel is the way out.
    offering?.let { m ->
        val who = personLine(m.who).shown()
        val name = vaultSlot(screen.vault.name)
        AlertDialog(
            onDismissRequest = { offering = null },
            title = { Say(UiText.Plain(ApprovedCopy.wordsWith("OWNERSHIP_OFFER.title", said(who), name))) },
            text = { Say(UiText.Plain(ApprovedCopy.lineWith("OWNERSHIP_OFFER.body", 0, said(who), name))) },
            dismissButton = { TextButton(onClick = { offering = null }) { Say(UiText.approved("OWNERSHIP_OFFER.button1")) } },
            confirmButton = { TextButton(onClick = { offering = null; model.run({ vaults.offerOwnership(m) }) }) { Say(UiText.approved("OWNERSHIP_OFFER.button0", who)) } },
        )
    }
    removing?.let { m ->
        AlertDialog(
            onDismissRequest = { removing = null },
            text = { Say(CopyKey.REMOVE_MEMBER_WARNING) },
            // The way out comes first and is the dialog's dismiss; the design's own alternative sits beside it.
            dismissButton = {
                Row {
                    TextButton(onClick = { removing = null }) { Say(CopyKey.CANCEL) }
                    // §3.13: the move names the member being removed, so it signs their `remove` first and never adds them.
                    TextButton(onClick = { removing = null; model.run({ vaults.openMoveEverythingRemoving(m) }) }) { Say(CopyKey.MOVE_EVERYTHING) }
                }
            },
            confirmButton = { TextButton(onClick = { removing = null; model.run({ vaults.removeMember(m) }) }) { Say(Placeholder.VAULT_REMOVE_MEMBER) } },
        )
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { vaults.closeMembers() } }
    HorizontalDivider()
}

/** A shared-code line ([CopyKey], perhaps awaiting the owner) with its `{0}`, `{1}`, … filled, styled as core marks it. */
internal fun keyLine(key: CopyKey, vararg values: String): UiText = when {
    key.reserved -> UiText.ph(Placeholder.RESERVED_COPY, key.name, *values)
    key.awaitingOwner -> UiText.Awaiting(fillCopy(key, *values))
    else -> UiText.Plain(fillCopy(key, *values))
}

/** As [keyLine], where some slots may hold the plain words for a name not known ([Slot]): the sentence does not quote those. */
internal fun keyLineWith(key: CopyKey, vararg slots: Slot): UiText = when {
    key.reserved -> UiText.ph(Placeholder.RESERVED_COPY, key.name, *slots.map { it.text }.toTypedArray())
    key.awaitingOwner -> UiText.Awaiting(fillTemplate(key.english, slots.map { it.text }, unnamedOf(slots)))
    else -> UiText.Plain(fillTemplate(key.english, slots.map { it.text }, unnamedOf(slots)))
}

/**
 * A note a "Move everything" left ([io.silencelen.andvari.core.app.AccountSnapshot.moveNotes]): its lines as the shared
 * code hands them ([moveNoteLines]) and its dismiss, the one way it goes (the shared code keeps it, across a lock and a
 * restart, until then).
 */
@Composable
internal fun MoveNoteCard(model: TrustModel, s: AppSnapshot, note: io.silencelen.andvari.core.app.MoveNote) {
    Column(Modifier.padding(vertical = 8.dp)) {
        for (line in moveNoteLines(note)) Say(line)
        Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) {
            model.quietly { (model.api.vaults as? io.silencelen.andvari.core.app.MoveNotes)?.dismissMoveNote(note) }
        }
    }
}

/**
 * What a move's note says, in order: each of its lines; after the line that the member the move removes still holds the
 * half-made vault, kept ([CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS]) or frozen ([CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS]),
 * that member, as the shared code names them ([personLine]).
 */
internal fun moveNoteLines(note: io.silencelen.andvari.core.app.MoveNote): List<UiText> = note.lines.flatMap { line ->
    listOf(UiText.of(line)) +
        if (line.key in MEMBER_HOLDS_LINES) listOfNotNull(note.member?.let(::personLine)) else emptyList()
}

/** The note lines after which the member who still holds the half-made vault is named. */
private val MEMBER_HOLDS_LINES = setOf(CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS, CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS)

/**
 * A move's deletion of its old vault that the server stored outside the move ([io.silencelen.andvari.core.app.AccountSnapshot.movesStoredOutside]):
 * the shared code's lines ([moveStoredLines]); the copy of what came late while it can be made, once; and the dismiss.
 */
@Composable
internal fun MoveStoredCard(model: TrustModel, s: AppSnapshot, notice: io.silencelen.andvari.core.app.MoveStoredNotice) {
    Column(Modifier.padding(vertical = 8.dp)) {
        for (line in moveStoredLines(notice)) Say(line)
        if (notice.canCopy && notice.copiedLine == null) {
            Second(UiText.ph(Placeholder.MOVE_STORED_COPY), enabled = !s.busy) { model.run({ vaults.bringLateIntoMove(notice) }) }
        }
        Quieter(UiText.ph(Placeholder.DISMISS), enabled = !s.busy) { model.quietly { model.api.vaults.dismissMoveStored(notice) } }
    }
}

/**
 * A "Move everything" this computer started and did not finish ([io.silencelen.andvari.core.app.AccountSnapshot.unfinishedMoves],
 * design §3.13), offered on the first screen after an unlock: the shared code's line, the way to finish it (the move's
 * screen opened again on the old vault, where it carries on) and "Not now", which puts it off until the next unlock.
 * The move's screen is drawn on the Sharing page only, and the offer goes while the move is open: so "Finish" also goes
 * to that page ([openMovePage]), where the move's screen takes the offer's place.
 */
@Composable
internal fun UnfinishedMoveOffer(model: TrustModel, s: AppSnapshot, move: io.silencelen.andvari.core.app.UnfinishedVaultMove, openMovePage: () -> Unit) {
    Column(Modifier.padding(vertical = 8.dp)) {
        Say(UiText.of(move.line), color = if (move.deleteWaiting) MaterialTheme.colorScheme.error else androidx.compose.ui.graphics.Color.Unspecified)
        Actions {
            Second(UiText.ph(Placeholder.MOVE_FINISH), enabled = !s.busy) {
                openMovePage()
                model.run({ vaults.openMoveEverything(move.vault) })
            }
            Quieter(UiText.ph(Placeholder.NOT_NOW), enabled = !s.busy) { model.act { vaults.unfinishedMoveLater(move) } }
        }
    }
}

/**
 * What [MoveStoredCard] says, in order: what the server did ([io.silencelen.andvari.core.app.MoveStoredNotice.line]); the
 * person's own waiting deletions the move carried ([io.silencelen.andvari.core.app.MoveStoredNotice.carriedLine]) and
 * those it kept, now the usual outcome ([io.silencelen.andvari.core.app.MoveStoredNotice.keptLine]); then how many were
 * copied, after a copy.
 */
internal fun moveStoredLines(notice: io.silencelen.andvari.core.app.MoveStoredNotice): List<UiText> =
    listOfNotNull(notice.line, notice.carriedLine, notice.keptLine, notice.copiedLine).map { UiText.of(it) }

/** The member the remove dialog named, as the move shows them: being removed, never added (§3.13). Null for a move on its own. */
internal fun moveRemovingLine(screen: MoveEverythingScreen): UiText? =
    screen.removing?.let { UiText.ph(Placeholder.MOVE_REMOVING, personLine(it.who).shown()) }

/**
 * Said before the person starts (§3.13): what moves, then, when the old vault will be kept, every reason that holds:
 * a frozen or failed vault stays where it is; the remaining members this computer cannot add, named; the items it
 * cannot read, counted. Core's [MoveEverythingScreen.oldVaultKept] is the first reason; the others are said as well.
 */
internal fun moveBeforeLines(screen: MoveEverythingScreen): List<UiText> {
    val lines = ArrayList<UiText>()
    lines += UiText.of(screen.whatMoves)
    if (screen.sourceStays) lines += keyLine(CopyKey.MOVE_KEPT_SOURCE_STAYS)
    val cannot = screen.members.filter { !it.canBeAdded }
    if (!screen.sourceStays && cannot.isNotEmpty()) {
        lines += keyLine(CopyKey.MOVE_KEPT_NOT_ADDED)
        for (m in cannot) lines += UiText.Plain("·  " + personLine(m.who).shown())
    }
    if (screen.unreadable > 0) lines += keyLine(CopyKey.MOVE_KEPT_UNREADABLE, screen.unreadable.toString())
    // The vault made last time holds someone who is not to be added now, so a
    // fresh new vault is made; said before the start.
    screen.startsFresh?.let { lines += keyLine(it) }
    return lines
}

/**
 * A stop (§3.13): at which step, the shared line (in which new vault, how many of how many, that moving again carries on,
 * or what stopped it, such as an old vault frozen here), and the step's own answer under it. Only the answer that the
 * shared line says itself is not drawn ([saidByTheStopLine]); every other answer is drawn, with its sentence, its
 * trouble, or, where it has neither, the line without wording that names it, so that an answer the shared code adds
 * later without words is seen, never dropped.
 */
internal fun moveStopLines(screen: MoveEverythingScreen, retryAfterSeconds: Int): List<UiText> {
    val stop = screen.stopped ?: return emptyList()
    val at = when (stop.stage) {
        MoveStage.REMOVE_MEMBER -> Placeholder.MOVE_STOPPED_REMOVING
        MoveStage.CREATE_VAULT -> Placeholder.MOVE_STOPPED_CREATING
        MoveStage.TRANSFER_ITEMS -> Placeholder.MOVE_STOPPED_COPYING
        MoveStage.ADD_MEMBERS -> Placeholder.MOVE_STOPPED_ADDING
        MoveStage.DELETE_OLD_VAULT -> Placeholder.MOVE_STOPPED_DELETING
    }
    return listOfNotNull(
        UiText.ph(at),
        keyLineWith(stop.line, vaultSlot(stop.toVaultName), vaultSlot(screen.vault.name), said(stop.copied.toString()), said(stop.total.toString())),
        if (saidByTheStopLine(stop)) null else UiText.forResult(stop.result, retryAfterSeconds),
    )
}

/**
 * The one answer at a move's stop that the stop's shared line says itself, so that nothing is drawn under it: READ_ONLY
 * under the line that the old vault is frozen on this device ([CopyKey.MOVE_OLD_VAULT_FROZEN]). READ_ONLY under any
 * other line is drawn like every other answer.
 */
internal fun saidByTheStopLine(stop: MoveStop): Boolean =
    stop.result == VaultActionResult.READ_ONLY && stop.line == CopyKey.MOVE_OLD_VAULT_FROZEN

/** The shared code's line for the last run's check for space ([MoveEverythingScreen.space]); null when it found room or made none. */
internal fun moveSpaceLine(screen: MoveEverythingScreen): UiText? = screen.space?.line?.let { UiText.of(it) }

/** A finished move that kept the old vault: where the items went, the shared line saying why it was kept, and who was not added. */
internal fun moveFinishedLines(screen: MoveEverythingScreen): List<UiText> {
    val f = screen.finished ?: return emptyList()
    val lines = ArrayList<UiText>()
    lines += UiText.ph(Placeholder.MOVE_FINISHED, f.copied.toString(), f.toVaultName)
    lines += if (f.oldKept == MoveKept.UNREADABLE_ITEMS) keyLine(f.line, screen.unreadable.toString()) else keyLine(f.line)
    for (p in f.notAdded) lines += UiText.Plain("·  " + personLine(p).shown())
    return lines
}

/**
 * Move everything to a new vault (§3.13), as the shared code decided it on 2026-11-16: the member the remove dialog
 * named, shown as being removed; what moves and why the old vault would be kept, before the start; the new vault's name
 * (not after a stop: the run carries on into the vault it made); the remaining members, ticked only where core offers
 * ticks (a frozen or failed vault, none ticked, with the warning), else a plain list, all added again; progress; a stop
 * and where; a finished move that kept the old vault, with its line and Close.
 */
@Composable
private fun MoveEverythingView(model: TrustModel, s: AppSnapshot, screen: MoveEverythingScreen) {
    var name by remember(screen.vault.vaultId) { mutableStateOf("") }
    Say(CopyKey.MOVE_EVERYTHING, style = MaterialTheme.typography.titleSmall)
    Text(vaultSlot(screen.vault.name).text, style = MaterialTheme.typography.bodyLarge)
    moveRemovingLine(screen)?.let { Say(it) }
    val finished = screen.finished
    if (finished != null) {
        for (line in moveFinishedLines(screen)) Say(line)
        Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { vaults.closeMoveEverything() } }
        HorizontalDivider()
        return
    }
    if (screen.sourceStays) Say(CopyKey.CHECK_WHAT_YOU_COPY, color = MaterialTheme.colorScheme.error)
    for (line in moveBeforeLines(screen)) Quiet(line)
    val space = moveSpaceLine(screen)
    if (screen.shortOfSpace && screen.stopped == null && space == null) Say(UiText.ph(Placeholder.MOVE_SHORT_OF_SPACE))
    // The last run's check for space, before anything was signed or sent: which limit, and by how much.
    space?.let { Say(it, color = if (screen.space?.started == false) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface) }
    // After a stop the run carries on into the vault it made, unless a fresh one is to be made, which takes a name.
    val carriesOn = screen.stopped != null && screen.startsFresh == null
    if (!carriesOn) Field(UiText.ph(Placeholder.VAULT_NAME_FIELD), name) { name = it }
    if (screen.ticksOffered) {
        Quiet(UiText.ph(Placeholder.MOVE_TICK_WHO))
        for (m in screen.members) {
            Tick(UiText.Plain(personLine(m.who).shown() + "  ·  " + m.role.literal), m.ticked, enabled = m.canBeAdded && !screen.running) {
                model.act { vaults.tickMember(screen, m, it) }
            }
            if (!m.canBeAdded) Quiet(UiText.ph(Placeholder.MOVE_CONNECT_FIRST))
        }
    } else if (screen.members.isNotEmpty()) {
        Quiet(UiText.ph(Placeholder.MOVE_ADDED_AGAIN))
        for (m in screen.members) Text(personLine(m.who).shown() + "  ·  " + m.role.literal)
    }
    if (screen.running) Quiet(UiText.ph(Placeholder.MOVE_PROGRESS, screen.copied.toString(), screen.total.toString()))
    for (line in moveStopLines(screen, model.api.retryAfterSeconds())) Say(line, color = MaterialTheme.colorScheme.error)
    // The way out first, then the move: after a stop the move is the first control the focus would reach otherwise
    // (there is no name field then), and the move deletes the old vault in the end (the keyboard walk).
    WayOutThenMain(
        UiText.ph(Placeholder.CLOSE), !screen.running && !s.busy, { model.act { vaults.closeMoveEverything() } },
        UiText.of(CopyKey.MOVE_EVERYTHING), enabled = (carriesOn || name.isNotBlank()) && !screen.running && !s.busy, busy = screen.running,
    ) {
        val n = name.trim()
        model.run({ vaults.moveEverything(screen, n) })
    }
    HorizontalDivider()
}
