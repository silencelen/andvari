package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.app.launchOvertakable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import io.silencelen.andvari.core.app.AccountSnapshot
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MembersScreen
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveKept
import io.silencelen.andvari.core.app.MoveStage
import kotlinx.coroutines.Job
import io.silencelen.andvari.core.app.OwnershipOfferRow
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
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

/**
 * Each log state's line: the design's sentence where it gives one, the owner's approved words where the design gave
 * none (a fork, a key that could not be opened, a sender to confirm here), otherwise a placeholder naming the state.
 */
internal fun logStateLine(row: SharedVaultRow): UiText? = when (row.log) {
    VaultLogState.VERIFIED -> null
    VaultLogState.CONNECT_FIRST -> row.connectFirstLine?.let { UiText.of(it) }
    VaultLogState.CONFIRM_FIRST -> UiText.approved(Approved.INCOMING_CONFIRM_FIRST, row.sharedBy?.serverName.orEmpty())
    VaultLogState.FROZEN -> UiText.Plain(Approved.VAULT_HISTORY_FORKED)
    VaultLogState.KEY_MISSING -> UiText.Plain(Approved.VAULT_KEY_MISSING)
    VaultLogState.REMOVED -> UiText.ph(if (row.removedByOwner) Placeholder.VAULT_REMOVED_BY_OWNER else Placeholder.VAULT_REMOVED_UNVERIFIED)
    else -> OutcomeWords.vaultLogState(row.log)
}

/**
 * The row's name: the vault's, or for a key that could not be opened (nothing decrypted) the approved title in its
 * place; any other row without a name (an offer not accepted yet, a key that was refused) says, as its name, that this
 * device doesn't know it. Never a sentence in the name's place.
 */
/**
 * The mark at the head of a shared vault's row: its name's first letter, or a neutral mark where this phone does not
 * know the name (never the first letter of the words that stand in for it).
 */
internal fun vaultRowMark(row: SharedVaultRow): String =
    row.name?.trim()?.firstOrNull()?.uppercase() ?: NAMELESS_VAULT_MARK

/** The neutral mark of a vault whose name this phone does not know. */
internal const val NAMELESS_VAULT_MARK = "•"

internal fun vaultRowName(row: SharedVaultRow): String =
    row.name ?: if (row.log == VaultLogState.KEY_MISSING) Approved.VAULT_KEY_MISSING_TITLE else UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN_TITLE).shown()

/**
 * "You'll see this vault's name once you accept it.", only under a shared vault this account has not accepted yet (it
 * must connect with the sender, or confirm them on this device, first): there the name comes once it is accepted. Not
 * for a vault already accepted whose key was refused or is missing, where accepting will not show it.
 */
internal fun nameOnceAcceptedLine(row: SharedVaultRow): UiText? =
    if (row.name == null && (row.log == VaultLogState.CONNECT_FIRST || row.log == VaultLogState.CONFIRM_FIRST)) UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN) else null

/**
 * Under [CopyKey.OWNER_OUT_OF_SPACE]: whose space it is, the shared code's line ([SharedVaultRow.outOfSpaceLine]:
 * approved entry 27 when this account owns the vault, 28 otherwise); null when the owner is not out of space.
 */
internal fun outOfSpaceLine(row: SharedVaultRow): UiText? = row.outOfSpaceLine?.let { UiText.of(it) }

/**
 * The note on a vault while an ownership offer is open, by who reads it: the person offered gets their own line; the
 * owner who made it the approved note (copy page, entry 26: {0} the member, {1} the vault, {2} the day it ends); any
 * other member the line that names the person offered. Only the owner ever reads the owner's note.
 */
internal fun offerLine(row: SharedVaultRow, offer: OwnershipOfferRow, endsOn: String): UiText = when {
    offer.toMe -> UiText.ph(Placeholder.VAULT_OFFER_TO_YOU)
    row.role == RoleInVault.OWNER ->
        UiText.approvedNamed(Approved.OWNERSHIP_OFFER_NOTE, NameSlot.said(personLine(offer.to).shown()), vaultSlot(row.name), NameSlot.said(endsOn))
    else -> UiText.ph(Placeholder.VAULT_OFFER, personLine(offer.to).shown())
}

/**
 * A vault's name in a sentence that quotes it, or, where this phone does not know it, the words that say so, which are
 * not a name and so stand without the sentence's quotes (never a dash in quotes).
 */
internal fun vaultSlot(name: String?): NameSlot = NameSlot.of(name, UiText.ph(Placeholder.VAULT_NAME_IN_LINE_NOT_KNOWN))

/** The question before an ownership offer (copy page, entry 26): its title, its body and its confirm button. */
internal class OwnershipOfferQuestion(val title: UiText, val body: UiText, val ask: UiText)

/**
 * Entry 26's dialog for [member] and [vault]: the approved title and "Ask {0} to take over" (Cancel is the existing
 * [CopyKey.CANCEL]); the body is [ownershipOfferBody].
 */
internal fun ownershipOfferQuestion(member: String, vault: String?): OwnershipOfferQuestion = OwnershipOfferQuestion(
    UiText.approvedNamed(Approved.OWNERSHIP_OFFER_TITLE, NameSlot.said(member), vaultSlot(vault)),
    ownershipOfferBody(),
    UiText.approved(Approved.OWNERSHIP_OFFER_ASK, member),
)

/**
 * The approved body says "They have 14 days", and core's offer now lasts exactly that (`OwnershipOffer.DAYS`), so the
 * dialog shows the approved words.
 */
internal fun ownershipOfferBody(): UiText = UiText.Plain(Approved.OWNERSHIP_OFFER_BODY)

/** A frozen, failed or withheld vault, or one in the holding area: what is copied out may have been changed. */
internal fun mustWarnBeforeCopy(row: SharedVaultRow): Boolean =
    row.log == VaultLogState.FROZEN || row.log == VaultLogState.FAILED || row.log == VaultLogState.WITHHELD || row.heldUntilMs > 0

/**
 * Shared vaults (map §3.12 to §3.14, slice 15) as the current app's Sharing has them: a list of rows, each with its
 * name, role and a settings button that opens the vault's own page ([SharedVaultSettings]); under each row what it says
 * (owner, every log state, the history hint, the owner out of space, deletion in grace, a pending ownership offer) and
 * what waits for this person's answer; the actions its role allows are on the vault's page. Create stays under the
 * list. Members ([MembersView]) and "Move everything to a new vault" ([MoveEverythingView]) open above the list.
 */
@Composable
internal fun SharedVaultsSection(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, onOpen: (String) -> Unit) {
    SectionDivider()
    Say(UiText.ph(Placeholder.SHARED_VAULTS), style = sectionTitleStyle())
    account.members?.let { MembersView(model, s, account, it) }
    account.moving?.let { MoveEverythingView(model, s, it) }
    for (v in account.vaults) {
        SharedVaultRowHead(v) { onOpen(v.vaultId) }
        VaultStateLines(v)
        VaultAnswers(model, s, v)
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
 * The vault Sharing's page is open on, by its id: null when none is, or when the vault is gone from the list (deleted,
 * left or revoked on another device), so the page falls back to the list instead of showing a vault that is not there.
 */
internal fun sharingVaultShown(account: AccountSnapshot, vaultId: String?): SharedVaultRow? =
    vaultId?.let { id -> account.vaults.firstOrNull { it.vaultId == id } }

/**
 * A shared vault's own page, the current app's vault settings: the name as the card's title with Rename beside it (an
 * owner, while the vault is writable), the role line, what the vault's row says, what waits for this person's answer,
 * then the actions the role allows (members, restore or delete for the owner, leave for anyone else, move everything,
 * save its items elsewhere, remove it from this device). Members and "Move everything" open at its top.
 */
@Composable
internal fun SharedVaultSettings(model: TrustModel, s: AppSnapshot, account: AccountSnapshot, v: SharedVaultRow) {
    account.members?.let { MembersView(model, s, account, it) }
    account.moving?.let { MoveEverythingView(model, s, it) }
    VaultSettingsHead(model, s, v)
    Text(sharedVaultRoleLine(v), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    // A move out of this vault that is not finished is said once on its page: by the offer at the top while it stands,
    // with its two answers; by the page itself once the offer was put off.
    VaultStateLines(v, moveOfferedAbove = unfinishedMoveOfferedAbove(account, v))
    VaultAnswers(model, s, v)
    VaultActions(model, s, v)
}

/** What a shared vault's row says: its owner, its log state, the history hint, space, deletion, the holding area, a change waiting, an offer. */
internal fun unfinishedMoveOfferedAbove(account: AccountSnapshot, v: SharedVaultRow): Boolean =
    account.unfinishedMoves.any { it.vault.vaultId == v.vaultId }

@Composable
private fun VaultStateLines(v: SharedVaultRow, moveOfferedAbove: Boolean = false) {
    v.owner?.let { Quiet(UiText.ph(Placeholder.VAULT_OWNER, personLine(it).shown())) }
    nameOnceAcceptedLine(v)?.let { Quiet(it) }
    logStateLine(v)?.let { Say(it, color = if (v.log == VaultLogState.FAILED || v.log == VaultLogState.KEY_REFUSED) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface) }
    if (v.historyHint) Quiet(UiText.of(CopyKey.VAULT_HISTORY_HINT))
    if (v.ownerOutOfSpace) {
        Quiet(UiText.of(CopyKey.OWNER_OUT_OF_SPACE))
        outOfSpaceLine(v)?.let { Quiet(it) }
    }
    // A deleted vault: the day its grace ends only where the server served one, else the shared code's line with no day.
    deletedLine(v)?.let { Quiet(it) }
    if (v.heldUntilMs > 0) Quiet(UiText.ph(Placeholder.VAULT_HELD_UNTIL, Dates.date(v.heldUntilMs)))
    // The plain mark only where the shared code hands no line of the change that waits (a move's own steps): a change it
    // draws ([SharedVaultRow.waiting]) is said by its own lines ([WaitingChangeView]).
    if (v.changeWaiting && v.waiting == null) Quiet(UiText.Plain(Approved.VAULT_CHANGE_WAITING_MARK))
    // Read-only here while its deletion by "Move everything" is signed and waiting: the shared code's line, as information.
    v.readOnlyLine?.let { Say(UiText.of(it)) }
    v.offer?.let { o -> Quiet(offerLine(v, o, Dates.date(o.expiresAtMs))) }
    // A move out of this vault that is not finished (kept across a lock and a restart): the shared code's line.
    if (!moveOfferedAbove) v.unfinishedMove?.let { Say(UiText.of(it), color = MaterialTheme.colorScheme.error) }
}

/**
 * What waits for this person's answer on a shared vault, on its row as on its page (the current app put an incoming
 * offer where it is seen at once): a change of theirs that waits to be sent, with the acts its row offers; a move stopped
 * on a frozen old vault, with "close this move"; confirm the sender on this device, accept an ownership offered to this
 * account.
 */
@Composable
private fun VaultAnswers(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    WaitingChangeView(model, s, v)
    FrozenMoveCloseView(model, s, v)
    v.senderToConfirm?.let { c -> Second(UiText.of(CopyKey.CONFIRM_ON_THIS_DEVICE), enabled = !s.busy) { model.run({ contacts.confirmOnThisDevice(c) }) } }
    if (v.offer?.toMe == true) {
        Second(UiText.ph(Placeholder.VAULT_ACCEPT_OWNERSHIP), enabled = !s.busy) { model.run({ vaults.acceptOwnership(v) }) }
    }
}

/**
 * A shared vault's line as the current app's vault row: the name's first letter, the name, then "shared vault · role",
 * and the settings button that opens the vault's page.
 */
@Composable
private fun SharedVaultRowHead(v: SharedVaultRow, onOpenSettings: () -> Unit) {
    val name = vaultRowName(v)
    androidx.compose.foundation.layout.Row(Modifier.padding(vertical = 6.dp), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
        Text(
            vaultRowMark(v), color = MaterialTheme.colorScheme.primary,
            fontFamily = androidx.compose.ui.text.font.FontFamily.Serif,
            modifier = Modifier.clearAndSetSemantics {},
        )
        androidx.compose.foundation.layout.Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 2, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis)
            Text(
                sharedVaultRoleLine(v), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        androidx.compose.material3.IconButton(onClick = onOpenSettings) {
            androidx.compose.material3.Icon(
                androidx.compose.material.icons.Icons.Default.Settings,
                UiText.ph(Placeholder.VAULT_SETTINGS, name).shown(),
            )
        }
    }
}

/** The row's second line: "shared vault", and the account's role in it where it has one (the role's own name). */
internal fun sharedVaultRoleLine(v: SharedVaultRow): String =
    listOfNotNull(UiText.ph(Placeholder.LIST_SHARED_VAULT).shown(), v.role?.let { roleWord(it) }).joinToString(" · ")

@Composable
private fun VaultActions(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    var confirmCopy by remember(v.vaultId) { mutableStateOf(false) }
    val owner = v.role == RoleInVault.OWNER
    if (v.role != null && v.log != VaultLogState.PURGED) {
        Quieter(UiText.ph(Placeholder.VAULT_MEMBERS), enabled = !s.busy) { model.run({ vaults.openMembers(v) }) }
    }
    v.offer?.let { o ->
        if (!o.toMe && owner) Quieter(UiText.ph(Placeholder.VAULT_CANCEL_OFFER), enabled = !s.busy) { model.run({ vaults.cancelOffer(v) }) }
    }
    if (owner && v.deleted) {
        Quieter(UiText.ph(Placeholder.VAULT_RESTORE), enabled = !s.busy) { model.run({ vaults.restoreVault(v) }) }
    }
    if (moveEverythingOffered(v)) Quieter(UiText.of(CopyKey.MOVE_EVERYTHING), enabled = !s.busy) { model.run({ vaults.openMoveEverything(v) }) }
    if (v.canSaveElsewhere) {
        Quieter(UiText.ph(Placeholder.VAULT_SAVE_ELSEWHERE), enabled = !s.busy) {
            if (mustWarnBeforeCopy(v)) confirmCopy = true else model.run({ vaults.saveItemsElsewhere(v, null) })
        }
    }
    if (v.canRemoveFromDevice) Quieter(UiText.of(CopyKey.REMOVE_FROM_THIS_DEVICE), enabled = !s.busy) { model.act { vaults.removeFromThisDevice(v) } }
    // The way out of the vault last, at the end of the row, as the current app's "Delete vault…" and "Leave".
    if (owner && !v.deleted && v.writable) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = androidx.compose.foundation.layout.Arrangement.End) {
            Quieter(UiText.ph(Placeholder.VAULT_DELETE), enabled = !s.busy) { model.run({ vaults.deleteVault(v) }) }
        }
    } else if (v.role != null && !owner && v.log != VaultLogState.REMOVED && v.log != VaultLogState.PURGED) {
        Quieter(UiText.ph(Placeholder.VAULT_LEAVE), enabled = !s.busy) { model.run({ vaults.leaveVault(v) }) }
    }
    if (confirmCopy) {
        AlertDialog(
            onDismissRequest = { confirmCopy = false },
            text = { Say(CopyKey.CHECK_WHAT_YOU_COPY) },
            confirmButton = { TextButton(onClick = { confirmCopy = false; model.run({ vaults.saveItemsElsewhere(v, null) }) }) { Say(Placeholder.VAULT_SAVE_ELSEWHERE) } },
            dismissButton = { TextButton(onClick = { confirmCopy = false }) { Say(CopyKey.CANCEL) } },
        )
    }
}

/**
 * The vault page's head, as the current app's: the vault's name as the card's title, with Rename beside it for a shared
 * vault this account owns, while it is writable and open. The call is the vault content's
 * ([VaultContent.renameSharedVault]: the name is encrypted and syncs to every member), the canonical call (the vault
 * content's, since 2026-11-15); the app API's `renameVault` is not used. The content checks the name, the role and the vault itself; what it
 * refuses is said in its own words. Offered only while the vault is open (a content instance exists).
 */
@Composable
private fun VaultSettingsHead(model: TrustModel, s: AppSnapshot, v: SharedVaultRow) {
    val content by model.content.collectAsState()
    val c = content
    val scope = rememberCoroutineScope()
    var editing by remember(v.vaultId) { mutableStateOf(false) }
    var name by remember(v.vaultId) { mutableStateOf(v.name ?: "") }
    var said by remember(v.vaultId) { mutableStateOf<String?>(null) }
    var busy by remember(v.vaultId) { mutableStateOf(false) }
    val canRename = c != null && v.role == RoleInVault.OWNER && v.writable && !v.deleted
    if (!editing || c == null || !canRename) {
        val rename: @Composable () -> Unit = {
            if (canRename) {
                Quieter(UiText.ph(Placeholder.VAULT_RENAME), enabled = !s.busy) {
                    name = v.name ?: ""
                    said = null
                    editing = true
                }
            }
        }
        // At the largest font Rename goes under the name: beside it, it squeezed the name to a few letters a line.
        if (largeFont()) {
            Text(vaultRowName(v), style = MaterialTheme.typography.titleLarge)
            rename()
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(vaultRowName(v), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
                rename()
            }
        }
        return
    }
    Field(UiText.ph(Placeholder.VAULT_NAME_FIELD), name) { name = it }
    said?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Quieter(UiText.of(CopyKey.CANCEL), enabled = !busy) { editing = false }
        Quieter(UiText.ph(Placeholder.VAULT_RENAME_SAVE), enabled = !busy && !s.busy && name.isNotBlank()) {
            busy = true
            scope.launchOvertakable {
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
    var changingRole by remember(screen.vault.vaultId) { mutableStateOf<Pair<MemberRow, MemberRole>?>(null) }
    changingRole?.let { (m, next) ->
        val q = roleChangeQuestion(m, next)
        AlertDialog(
            onDismissRequest = { changingRole = null },
            text = { androidx.compose.foundation.layout.Column { Say(q.first); Quiet(q.second) } },
            confirmButton = { TextButton(onClick = { changingRole = null; confirmRoleChange(model, m, next) }) { Say(Placeholder.ROLE_CHANGE_CONFIRM) } },
            dismissButton = { TextButton(onClick = { changingRole = null }) { Say(CopyKey.CANCEL) } },
        )
    }
    offering?.let { m ->
        val q = ownershipOfferQuestion(personLine(m.who).shown(), screen.vault.name)
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { offering = null },
            title = { Say(q.title) },
            text = { Say(q.body) },
            confirmButton = { androidx.compose.material3.TextButton(onClick = { offering = null; model.run({ vaults.offerOwnership(m) }) }) { Say(q.ask) } },
            dismissButton = { androidx.compose.material3.TextButton(onClick = { offering = null }) { Say(CopyKey.CANCEL) } },
        )
    }
    // While the list may be incomplete, the design's "may be incomplete" goes in brackets after the heading and the
    // approved line under the list (copy page, entry 25).
    Row(verticalAlignment = Alignment.CenterVertically) {
        Say(UiText.phNamed(Placeholder.VAULT_MEMBERS_OF, vaultSlot(screen.vault.name)), style = MaterialTheme.typography.titleSmall)
        if (screen.mayBeIncomplete) Say(UiText.Plain(" (" + CopyKey.MEMBERS_MAY_BE_INCOMPLETE.english + ")"), style = MaterialTheme.typography.titleSmall)
    }
    for (m in screen.members) {
        Text(personLine(m.who).shown() + "  ·  " + roleWord(m.role))
        m.deletedLine?.let { line ->
            Say(line)
            Quieter(UiText.of(CopyKey.REMOVE_FROM_THE_LIST), enabled = !s.busy) { model.run({ vaults.removeMember(m) }) }
        }
        if (screen.canManage && m.who !is PersonName.You && !m.deletedByOperator) {
            ButtonRow {
                val next = if (m.role == RoleInVault.READER) MemberRole.WRITER else MemberRole.READER
                // A role change is asked first (as the web's walk of 2026-11-16): the button only opens the question.
                Quieter(UiText.ph(Placeholder.LINK_ROLE_SWITCH), enabled = !s.busy && m.role != RoleInVault.OWNER) { changingRole = m to next }
                Quieter(UiText.ph(Placeholder.VAULT_REMOVE_MEMBER), enabled = !s.busy) { removing = m }
                // The offer is asked first (copy page, entry 26): the button only opens the question.
                Quieter(UiText.ph(Placeholder.VAULT_OFFER_OWNERSHIP), enabled = !s.busy && m.role != RoleInVault.OWNER) { offering = m }
            }
        }
    }
    if (screen.mayBeIncomplete) Quiet(UiText.Plain(Approved.MEMBERS_MAY_BE_INCOMPLETE_WHY))
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
    removing?.let { m ->
        AlertDialog(
            onDismissRequest = { removing = null },
            text = { Say(CopyKey.REMOVE_MEMBER_WARNING) },
            confirmButton = { TextButton(onClick = { removing = null; model.run({ vaults.removeMember(m) }) }) { Say(Placeholder.VAULT_REMOVE_MEMBER) } },
            dismissButton = {
                ButtonRow {
                    TextButton(onClick = { removing = null; moveEverythingRemoving(model, m) }) { Say(CopyKey.MOVE_EVERYTHING) }
                    TextButton(onClick = { removing = null }) { Say(CopyKey.CANCEL) }
                }
            },
        )
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { vaults.closeMembers() } }
    HorizontalDivider()
}

/**
 * A role change's question (no approved words: placeholders): who, the role they would hold, and what that role
 * allows. Nothing is signed until [confirmRoleChange].
 */
internal fun roleChangeQuestion(member: MemberRow, next: MemberRole): Pair<UiText, UiText> =
    UiText.ph(Placeholder.ROLE_CHANGE_ASK, personLine(member.who).shown(), roleWord(next)) to
        UiText.ph(if (next == MemberRole.WRITER) Placeholder.ROLE_WRITER_ALLOWS else Placeholder.ROLE_READER_ALLOWS)

/**
 * A role as every screen names it: the current app's words ("shared vault · writer", a member's "· reader"), from this
 * one place, so no screen shows a role by the word the server's records use for it.
 */
internal fun roleWord(role: RoleInVault): String = when (role) {
    RoleInVault.OWNER -> "owner"
    RoleInVault.WRITER -> "writer"
    RoleInVault.READER -> "reader"
}

/** [roleWord] for a role a person can be given (a writer or a reader). */
internal fun roleWord(role: MemberRole): String = roleWord(if (role == MemberRole.WRITER) RoleInVault.WRITER else RoleInVault.READER)

/** The confirmed role change: the one place the members screen signs a `role` entry. */
internal fun confirmRoleChange(model: TrustModel, member: MemberRow, next: MemberRole): Job =
    model.run({ vaults.changeRole(member, next) })

/**
 * A deleted vault's line ([SharedVaultRow.deleted], never read from the day): the day its grace ends where the server
 * served one ([SharedVaultRow.purgeAtMs]), else the shared code's line that names no day, as handed. Null for a vault
 * that is not deleted.
 */
internal fun deletedLine(v: SharedVaultRow): UiText? = when {
    !v.deleted -> null
    v.purgeAtMs > 0 -> UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, Dates.date(v.purgeAtMs))
    else -> v.deletedNoDayLine?.let { UiText.of(it) }
}

/**
 * "Move everything" is offered on this row (§3.13, the rules of 2026-11-16): to the vault's owner, on a vault whose
 * history is verified, frozen or failed, that is not deleted, and whose key this device holds (never on a withheld one).
 * On a frozen or failed vault it is the way out (T2-R-k), so it is offered although the vault is not writable.
 */
internal fun moveEverythingOffered(v: SharedVaultRow): Boolean =
    v.role == RoleInVault.OWNER && !v.deleted && v.canSaveElsewhere &&
        (v.log == VaultLogState.VERIFIED || v.log == VaultLogState.FROZEN || v.log == VaultLogState.FAILED)

/**
 * The remove dialog's "Move everything" for [member] (§3.13): the move removes them on the old log first and never adds
 * them to the new vault ([MoveEverythingScreen.removing]).
 */
internal fun moveEverythingRemoving(model: TrustModel, member: MemberRow): Job =
    model.run({ vaults.openMoveEverythingRemoving(member) })

/**
 * Start the move, or after a stop carry on into the new vault it made (under the name it was made with). A stop is said
 * by the screen's own lines ([moveStopLines], which carry its result), so it is not said a second time at the top.
 */
internal fun startMove(model: TrustModel, screen: MoveEverythingScreen, typed: String): Job =
    model.runSaying({ vaults.moveEverything(screen, screen.stopped?.toVaultName ?: typed.trim()) }, { r ->
        if (model.api.snapshot.account?.moving?.stopped != null) null else model.wordsFor(r)
    })

/**
 * Said before the person starts (§3.13): what moves (only the items in the vault now), and, when the old vault will be
 * kept, why: a frozen or failed vault stays; the remaining members who cannot be added from this phone, named; the
 * items this phone cannot read, counted. Each reason that holds is said, not only the one core leads with.
 */
internal fun moveBeforeStartLines(screen: MoveEverythingScreen): List<UiText> {
    val out = ArrayList<UiText>()
    out += UiText.of(screen.whatMoves)
    if (screen.sourceStays || screen.oldVaultKept == MoveKept.SOURCE_STAYS) out += UiText.of(CopyKey.MOVE_KEPT_SOURCE_STAYS)
    // With ticks (a frozen or failed vault) a member who cannot be added has their own mark in the list.
    val cannot = if (screen.ticksOffered) emptyList() else screen.members.filter { !it.canBeAdded }
    if (cannot.isNotEmpty() || screen.oldVaultKept == MoveKept.MEMBER_CANNOT_BE_ADDED) {
        out += UiText.of(CopyKey.MOVE_KEPT_NOT_ADDED)
        cannot.forEach { out += personLine(it.who) }
    }
    if (screen.unreadable > 0 || screen.oldVaultKept == MoveKept.UNREADABLE_ITEMS) out += UiText.of(CopyKey.MOVE_KEPT_UNREADABLE, screen.unreadable.toString())
    // A stopped run whose half-made vault holds someone this plan does not add starts fresh: the
    // shared code's own sentence.
    screen.startsFresh?.let { out += UiText.of(it) }
    return out
}

/**
 * Where a move stopped, as a sentence of its own per step (the design names the steps; no approved words exist for
 * them yet), so each can be given its words without a phrase of the code inside another sentence.
 */
internal fun moveStoppedAt(stage: MoveStage): Placeholder = when (stage) {
    MoveStage.REMOVE_MEMBER -> Placeholder.MOVE_STOPPED_REMOVING_MEMBER
    MoveStage.CREATE_VAULT -> Placeholder.MOVE_STOPPED_MAKING_VAULT
    MoveStage.TRANSFER_ITEMS -> Placeholder.MOVE_STOPPED_COPYING
    MoveStage.ADD_MEMBERS -> Placeholder.MOVE_STOPPED_ADDING_MEMBERS
    MoveStage.DELETE_OLD_VAULT -> Placeholder.MOVE_STOPPED_DELETING_OLD
}

/**
 * A move that stopped part-way (§3.13, "a stop says where"): at which step, the shared code's line ({0} the new vault,
 * {1} the old one, {2} of {3} items copied, and that moving again carries on from there), and what the step came to.
 */
internal fun moveStopLines(screen: MoveEverythingScreen, retryAfterSeconds: Int = 0): List<UiText> {
    val st = screen.stopped ?: return emptyList()
    return listOfNotNull(
        UiText.ph(moveStoppedAt(st.stage)),
        UiText.ofNamed(st.line, vaultSlot(st.toVaultName), vaultSlot(screen.vault.name), NameSlot.said(st.copied.toString()), NameSlot.said(st.total.toString())),
        UiText.forResult(st.result, retryAfterSeconds),
    )
}

/**
 * The space check's own line for the move (which limit, by how much), while the check says the copies do not fit, or
 * fit only by the sizes their files state; null when it fits, or when no check could be made.
 */
internal fun moveSpaceLine(screen: MoveEverythingScreen): UiText? {
    val space = screen.space ?: return null
    if (space.verdict != io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH &&
        space.verdict != io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES
    ) {
        return null
    }
    return space.line?.let { UiText.of(it) }
}

/**
 * The first screen's offer after an unlock for a "Move everything" that is not finished: the shared code's line (the
 * deletion signed and waiting, or a move that stopped part-way), "finish the move", which opens the move's screen on
 * that vault, and "later", which puts the offer off until the next unlock.
 */
@Composable
internal fun UnfinishedMoveOffer(model: TrustModel, s: AppSnapshot, move: io.silencelen.andvari.core.app.UnfinishedVaultMove) {
    Say(UiText.of(move.line), color = MaterialTheme.colorScheme.error)
    Second(UiText.ph(Placeholder.MOVE_FINISH), enabled = !s.busy) { model.run({ vaults.openMoveEverything(move.vault) }) }
    Quieter(UiText.ph(Placeholder.LATER), enabled = !s.busy) { model.act { vaults.unfinishedMoveLater(move) } }
}

/** A finished move that kept the old vault: into which new vault, how many items, the shared code's line why, and who was not added. */
internal fun moveFinishedLines(screen: MoveEverythingScreen): List<UiText> {
    val f = screen.finished ?: return emptyList()
    return listOf(counted(f.copied.toLong(), Placeholder.MOVE_FINISHED_INTO, Placeholder.MOVE_FINISHED_INTO_ONE, f.toVaultName), UiText.of(f.line, screen.unreadable.toString())) +
        f.notAdded.map(::personLine)
}

/**
 * Move everything to a new vault (§3.13): who is being removed; before the start, what moves and why the old vault will
 * be kept; the new name (after a stop, the stop's line instead: it carries on into the vault it made); the remaining
 * members, as a plain list on a vault in good standing (all of them are added again) and with tick boxes, none ticked,
 * only where core offers ticks (a frozen or failed vault, with the warning); progress; a finished move that kept the old
 * vault, with its line and a Close.
 */
@Composable
private fun MoveEverythingView(model: TrustModel, s: AppSnapshot, screen: MoveEverythingScreen) {
    var name by remember(screen.vault.vaultId) { mutableStateOf("") }
    Say(CopyKey.MOVE_EVERYTHING, style = MaterialTheme.typography.titleSmall)
    screen.removing?.let { r -> Say(UiText.ph(Placeholder.MOVE_REMOVING, personLine(r.who).shown())) }
    if (screen.finished != null) {
        for (line in moveFinishedLines(screen)) Say(line)
        Quieter(UiText.ph(Placeholder.CLOSE), enabled = !s.busy) { model.act { vaults.closeMoveEverything() } }
        HorizontalDivider()
        return
    }
    if (screen.sourceStays) {
        Say(CopyKey.CHECK_WHAT_YOU_COPY, color = MaterialTheme.colorScheme.error)
    }
    for (line in moveBeforeStartLines(screen)) Quiet(line)
    val stop = screen.stopped
    for (line in moveStopLines(screen, model.api.retryAfterSeconds())) Say(line, color = MaterialTheme.colorScheme.error)
    moveSpaceLine(screen)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
    if (stop == null && screen.shortOfSpace) Quiet(UiText.of(CopyKey.OWNER_OUT_OF_SPACE))
    if (stop == null) Field(UiText.ph(Placeholder.VAULT_NAME_FIELD), name) { name = it }
    if (screen.ticksOffered) {
        for (m in screen.members) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = m.ticked, enabled = m.canBeAdded && !screen.running, onCheckedChange = { model.act { vaults.tickMember(screen, m, it) } })
                Text(personLine(m.who).shown() + "  ·  " + roleWord(m.role))
            }
            if (!m.canBeAdded) Quiet(UiText.ph(Placeholder.MOVE_CONNECT_FIRST))
        }
    } else {
        for (m in screen.members) Text(personLine(m.who).shown() + "  ·  " + roleWord(m.role))
    }
    if (screen.running) Quiet(UiText.ph(Placeholder.MOVE_PROGRESS, screen.copied.toString(), screen.total.toString()))
    Main(UiText.of(CopyKey.MOVE_EVERYTHING), enabled = (stop != null || name.isNotBlank()) && !screen.running && !s.busy, busy = screen.running) {
        startMove(model, screen, name)
    }
    Quieter(UiText.ph(Placeholder.CLOSE), enabled = !screen.running && !s.busy) { model.act { vaults.closeMoveEverything() } }
    HorizontalDivider()
}
