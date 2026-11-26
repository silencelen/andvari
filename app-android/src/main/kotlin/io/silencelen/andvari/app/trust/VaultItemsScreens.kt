package io.silencelen.andvari.app.trust

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.copyToClipboard
import io.silencelen.andvari.core.app.ItemDetail
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.OneTimeCode
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.emptyLine
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.content.VaultSyncState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.graphics.Color
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.TRASH_EXPLANATION
import io.silencelen.andvari.core.app.TrashItemView
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.AttachmentView
import io.silencelen.andvari.app.ExternalExcursion
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.DisposableEffect
import androidx.compose.material3.RadioButton
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.runtime.rememberUpdatedState
// The first-run screens' master password field (masked, with its show control), named apart from core's SecretField.
import io.silencelen.andvari.app.SecretField as MaskedField
import io.silencelen.andvari.core.app.AttachmentDraftView
import io.silencelen.andvari.core.app.AttachmentRules
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import io.silencelen.andvari.app.launchOvertakable
import kotlinx.coroutines.withContext
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.TextButton

/**
 * The open vault's items, read from [TrustModel.content] (a new [VaultContent] at every unlock, none while locked).
 * Every sentence here is the content's own ([ContentState.notice], [ContentState.error]); the labels the content does
 * not carry are placeholders. The list with its search, the sync and failure states, and an item's detail with reveal,
 * copy (cleared after the policy's window) and one-time codes. The editors are not here yet.
 */
@Composable
internal fun VaultItemsSection(model: TrustModel, header: @Composable () -> Unit, go: (SignedInPage) -> Unit) {
    val content by model.content.collectAsState()
    val c = content
    if (c == null) {
        // No content (it opens with the unlock): the page's own lines, under the vault's top bar.
        PageScaffold(UiText.ph(Placeholder.VAULT_ITEMS), onBack = {}) { header() }
        return
    }
    val state by c.states.collectAsState()
    // Keyed by the opening, not the instance ([GuardedContent.opening]): a new unlock starts on the list, and nothing
    // opened under the last one survives it; but where the shared code composes the same account's vault again while it
    // is open (after the policy's wipe of its copy), the screen on show and what was typed stay, bound to the new content.
    val opening = (c as? GuardedContent)?.opening ?: c
    val first = LocalFirstVaultView.current
    var open by remember(opening) { mutableStateOf(first?.open) }
    // The editor: null = closed; else which kind, and the item being edited (null for a new one).
    var editing by remember(opening) { mutableStateOf(first?.editKind?.let { Editing(it, first.editItem) }) }
    val detail = open?.let { c.itemDetail(it) }
    val e = editing
    val trash = state.trash
    val deleted = state.deletedVaults
    val history = state.history
    val importing = state.csvImport
    val exporting = state.exporting
    val health = state.health
    // Back walks the vault's own screens first, as in the current app: an item's detail goes back to the list.
    ActiveBackHandler(model, enabled = e == null && detail != null) { open = null }
    var barAnswer by remember(c) { mutableStateOf<String?>(null) }
    // The list's sort and filters: kept while an item or another vault screen is open, fresh at each unlock.
    var controls by remember(opening) { mutableStateOf(first?.controls ?: ListControls()) }
    val (bar, transfer) = rememberVaultBarActions(c, state, go) { barAnswer = it }
    // The export and the import are dialogs over whichever screen they were asked from, as the current app's
    // ([ExportPanel], [ImportDialog]).
    val onList = health == null && deleted == null && trash == null &&
        history == null && e == null && detail == null
    // The current app's Trash and Vault health are pages of their own, with their title and the way back in the top bar
    // (and the system Back): so are they here.
    val page = subPage(state)
    val closePage: () -> Unit = {
        when (page) {
            VaultSubPage.HEALTH -> c.closeHealth()
            VaultSubPage.TRASH -> c.closeTrash()
            null -> {}
        }
    }
    ActiveBackHandler(model, enabled = page != null) { closePage() }
    // The current app's structure: one top bar over every vault screen, the floating Add button over the list only.
    Scaffold(
        topBar = { if (page != null) PageTopBar(subPageTitle(page), closePage) else VaultTopBar(bar, working = state.busy) },
        floatingActionButton = { if (onList && canSave(state)) AddButton(EDITOR_KINDS) { editing = Editing(it, null) } },
        contentWindowInsets = WindowInsets(0),
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            // What the page says above whichever vault screen is on show: the account's lines, then the content's notice
            // (a write whose screen left while it was on the wire answers here), then what the bar answered.
            val above: @Composable () -> Unit = {
                header()
                VaultNotice(c, state)
                (barAnswer ?: transfer.answer)?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
            }
            if (onList) {
                VaultList(c, state, controls, { controls = it }, header = { above(); VaultListLines(c, state) }, footer = {
                    RecentlyRemovedSection(c, state)
                    AutofillSavesSection(c, state)
                }) { open = it }
            } else {
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
                    above()
                    when {
                        // The bad-password offer opens the item: its detail, or its editor with a new password, unsaved, on show.
                        health != null -> HealthPanel(model, c, state, health) { itemId, generate ->
                            c.closeHealth()
                            if (generate) editing = Editing("login", itemId, generate = true) else open = itemId
                        }
                        deleted != null -> DeletedVaultsView(model, c, state, deleted)
                        trash != null -> TrashView(c, state, trash)
                        // An item's history is part of its detail, as the current app's "Version history"; one opened
                        // without its item on show is drawn on its own.
                        history != null && (detail == null || detail.itemId != history.itemId) -> HistoryView(model, c, state, history)
                        e != null -> ItemEditor(model, c, opening, state, e.kind, e.itemId, e.itemId?.let { c.itemDetail(it) }, e.generate) { editing = null }
                        detail != null -> ItemDetailView(model, c, state, detail, history, onEdit = { editing = Editing(detail.type, detail.itemId) }) { open = null }
                    }
                }
            }
            importing?.let { ImportDialog(c, state, it) }
            exporting?.let { ExportPanel(c, it) }
        }
    }
}

/** The vault's screens that are pages of their own, with their title and the way back in the top bar. */
internal enum class VaultSubPage { HEALTH, TRASH }

/**
 * The page on show, in the order the vault's screens take precedence; null for the list and the screens under the
 * vault's bar. The import and the export are dialogs over the screen they were asked from, not pages.
 */
internal fun subPage(state: ContentState): VaultSubPage? = when {
    state.health != null -> VaultSubPage.HEALTH
    state.exporting != null || state.deletedVaults != null -> null
    state.trash != null -> VaultSubPage.TRASH
    else -> null
}

/** A page's title in its top bar, as the current app's "Trash" and "Vault health". */
internal fun subPageTitle(page: VaultSubPage): UiText = UiText.ph(
    when (page) {
        VaultSubPage.HEALTH -> Placeholder.HEALTH
        VaultSubPage.TRASH -> Placeholder.TRASH
    },
)

/**
 * What [VaultNotice] says: the content's notice; for what a lock cut short (kind LOCK), each thing on its own line, in
 * the shared code's sentence with its name and counts ([ContentState.lockCut]); empty with no notice.
 */
internal fun noticeLines(state: ContentState): List<UiText> {
    val notice = state.notice ?: return emptyList()
    if (state.noticeKind == io.silencelen.andvari.core.app.content.ContentNoticeKind.LOCK && state.lockCut.isNotEmpty()) {
        return state.lockCut.map { UiText.Plain(it.line) }
    }
    return listOf(UiText.Plain(notice))
}

/**
 * A notice is drawn as information when it says something went well, waits, or is in the trash again after a later
 * deletion elsewhere. A notice is drawn as a warning when it says something did not happen: what a lock cut short, a restore or delete for
 * good the server answered as done and did not perform, a refusal whose screen had gone, or what this device keeps for
 * later that could not be read. Never as a success. A notice of no known kind is a warning too (the safer reading).
 */
internal fun noticeWarns(kind: io.silencelen.andvari.core.app.content.ContentNoticeKind?): Boolean = when (kind) {
    io.silencelen.andvari.core.app.content.ContentNoticeKind.DONE,
    io.silencelen.andvari.core.app.content.ContentNoticeKind.QUEUED,
    io.silencelen.andvari.core.app.content.ContentNoticeKind.KEPT_SAVE,
    // An item in the trash again after a later deletion elsewhere: what is so, said plainly; no warning about the server.
    io.silencelen.andvari.core.app.content.ContentNoticeKind.IN_TRASH_AGAIN -> false
    else -> true
}

/**
 * [ContentState.notice] with its Close: once, above every vault screen, as the current app's bars. A notice that
 * [noticeWarns] is its error bar (the error container, announced at once); any other is its notice bar.
 */
@Composable
internal fun VaultNotice(c: VaultContent, state: ContentState) {
    val lines = noticeLines(state)
    if (lines.isEmpty()) return
    val warn = noticeWarns(state.noticeKind)
    val colors = if (warn) {
        androidx.compose.material3.CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)
    } else {
        androidx.compose.material3.CardDefaults.cardColors()
    }
    val text = if (warn) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.secondary
    val region = if (warn) LiveRegionMode.Assertive else LiveRegionMode.Polite
    androidx.compose.material3.Card(Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = region }, colors = colors) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                for (line in lines) Say(line, style = MaterialTheme.typography.bodySmall, color = text)
            }
            TextButton(
                onClick = { c.dismissNotice() },
                colors = ButtonDefaults.textButtonColors(contentColor = if (warn) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurfaceVariant),
            ) { Say(UiText.ph(Placeholder.CLOSE)) }
        }
    }
}

/**
 * The vault view a drawn screen opens on, for the screen images (ScreenImagesTest) only: an item's detail ([open]) or
 * its editor ([editKind], with [editItem] null for a new item). Nothing in the app provides it, so on a phone the vault
 * opens on its list.
 */
internal class FirstVaultView(
    val open: String? = null,
    val editKind: String? = null,
    val editItem: String? = null,
    val discard: Boolean = false,
    val controls: ListControls? = null,
    /** Vault health's tab on show, for the screen images only; null: Passwords, as on a phone. */
    val healthTab: HealthTab? = null,
    /** The history's question before a restore, open for its newest earlier version, for the screen images only. */
    val restoreAsked: Boolean = false,
    /** The import's sheet open before the file picker, for the screen images only. */
    val importAsked: Boolean = false,
)

internal val LocalFirstVaultView = androidx.compose.runtime.staticCompositionLocalOf<FirstVaultView?> { null }

/** [generate]: the editor opens with a freshly generated password in its field, shown and not saved. */
private class Editing(val kind: String, val itemId: String?, val generate: Boolean = false)

/**
 * An item's files on its detail: each by name and size, saved on request to a place the person picks (the picker is
 * another app's screen, so the excursion is armed). The decrypted bytes live only for the write and are zeroed after.
 */
@Composable
private fun AttachmentsOnDetail(c: VaultContent, d: ItemDetail) {
    if (d.attachments.isEmpty()) return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var pending by remember(c, d.itemId) { mutableStateOf<AttachmentView?>(null) }
    var answer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val a = pending
        pending = null
        if (uri != null && a != null) {
            scope.launchOvertakable {
                val got = c.readAttachment(d.itemId, a.id)
                val bytes = got.bytes
                answer = if (bytes == null) {
                    got.error
                } else {
                    try {
                        writeTruncated(context, uri, bytes)
                        null
                    } catch (e: Exception) {
                        // The platform's own words would not help here; the file was not written.
                        UiText.ph(Placeholder.ATTACHMENT_NOT_WRITTEN).shown()
                    } finally {
                        bytes.fill(0)
                    }
                }
            }
        }
    }
    Say(Placeholder.ATTACHMENTS, style = MaterialTheme.typography.labelMedium)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    d.attachments.forEach { a ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(a.name + "  ·  " + sizeText(a.size), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            Quieter(UiText.ph(Placeholder.ATTACHMENT_SAVE)) {
                pending = a
                ExternalExcursion.begin()
                saver.launch(a.name)
            }
        }
    }
}

/**
 * The open editor's files ([ContentState.attachmentDraft]): the kept and the added, each removable, and Add, which reads
 * a file the person picks and hands it to the content (it encrypts and zeroes the bytes). The draft is opened with the
 * editor and closed when the editor leaves the screen.
 */
@Composable
private fun AttachmentsInEditor(c: VaultContent, state: ContentState, itemId: String?, key: String) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var answer by remember(c, key) { mutableStateOf<String?>(null) }
    DisposableEffect(c, key) {
        c.openAttachmentDraft(itemId)
        onDispose { c.closeAttachmentDraft() }
    }
    val currentDraft by rememberUpdatedState(state.attachmentDraft)
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val d = currentDraft
        if (uri != null && d != null) {
            scope.launchOvertakable {
                // Never more than the draft lets this file be: its own limit and what the item still has room for.
                val room = attachmentRoom(d)
                val picked = withContext(Dispatchers.IO) { PickedFiles.read(context, uri, room) }
                answer = when (picked) {
                    is PickedFiles.Picked.Read -> sentence(c.addAttachment(picked.name, picked.bytes))
                    is PickedFiles.Picked.TooLarge -> attachmentTooLarge(picked.size, d)
                    PickedFiles.Picked.NotRead -> UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()
                }
            }
        }
    }
    val draft = state.attachmentDraft ?: return
    Say(Placeholder.ATTACHMENTS, style = MaterialTheme.typography.labelMedium)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    (draft.kept + draft.added).forEach { a ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(a.name + "  ·  " + sizeText(a.size), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            Quieter(UiText.ph(Placeholder.ATTACHMENT_REMOVE), enabled = !state.busy) { c.removeAttachment(a.id) }
        }
    }
    Say(Placeholder.ATTACHMENT_LIMITS, sizeText(draft.totalBytes), sizeText(draft.limits.perFileBytes), sizeText(draft.limits.perItemBytes), style = MaterialTheme.typography.bodySmall)
    state.upload?.let { Say(Placeholder.ATTACHMENT_UPLOADING, it.done.toString(), it.total.toString()) }
    Quieter(UiText.ph(Placeholder.ATTACHMENT_ADD), enabled = !state.busy && canSave(state)) {
        ExternalExcursion.begin()
        picker.launch(arrayOf("*/*"))
    }
}

/** A size for people: bytes, KB or MB. */
internal fun sizeText(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${(bytes + 1023) / 1024} KB"
    else -> String.format(java.util.Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
}

/** Open [uri] for writing, truncated ("wt"): plain "w" leaves stale bytes when a longer file is overwritten. */
private fun writeTruncated(context: Context, uri: Uri, bytes: ByteArray) {
    val out = runCatching { context.contentResolver.openOutputStream(uri, "wt") }.getOrNull()
        ?: context.contentResolver.openOutputStream(uri)
        ?: throw IllegalStateException("could not open the chosen destination")
    out.use { it.write(bytes) }
}

/** The most a picked file is read to for [draft]: the per-file limit, or the room the item has left if that is less. */
internal fun attachmentRoom(draft: AttachmentDraftView): Long =
    minOf(draft.limits.perFileBytes, draft.limits.perItemBytes - draft.totalBytes).coerceAtLeast(0)

/** The content's own sentence for a file of [size] bytes the draft cannot take. */
internal fun attachmentTooLarge(size: Long, draft: AttachmentDraftView): String =
    AttachmentRules.refusal(size, draft.totalBytes, draft.limits) ?: UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()

/** What an intent answered, as the sentence to show in place; null for done. */
private fun sentence(r: ActionResult): String? = when (r) {
    is ActionResult.Failed -> r.message
    is ActionResult.NotDone -> r.message
    else -> null
}

/**
 * "Recently removed" (spec 02 §10.6): vaults this account no longer has, whose copy this device keeps for a while. A
 * readable one can be copied into the personal vault, behind the check-what-you-copy warning; any can be removed from
 * this device, behind a confirmation whose way out comes first.
 */
@Composable
private fun RecentlyRemovedSection(c: VaultContent, state: ContentState) {
    if (state.held.isEmpty()) return
    val scope = rememberCoroutineScope()
    var asking by remember(c) { mutableStateOf<Pair<String, Boolean>?>(null) } // vault id, true = copy, false = remove
    var answer by remember(c) { mutableStateOf<String?>(null) }
    Gap()
    Say(Placeholder.RECENTLY_REMOVED, style = MaterialTheme.typography.titleSmall)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    state.copying?.let { Say(Placeholder.COPYING, it.done.toString(), it.total.toString()) }
    state.held.forEach { h ->
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            Text(h.name.ifEmpty { "—" }, style = MaterialTheme.typography.bodyLarge)
            Say(UiText.Plain(h.line), style = MaterialTheme.typography.bodySmall)
            Say(Placeholder.HELD_ITEM_COUNT, h.itemCount.toString(), style = MaterialTheme.typography.bodySmall)
            val ask = asking
            if (ask != null && ask.first == h.vaultId) {
                if (ask.second) Say(CopyKey.CHECK_WHAT_YOU_COPY) else Say(Placeholder.HELD_REMOVE_CONFIRM)
                ButtonRow {
                    Quieter(UiText.ph(Placeholder.ITEM_BACK)) { asking = null }
                    if (ask.second) {
                        Quieter(UiText.ph(Placeholder.HELD_COPY_TO_PERSONAL), enabled = canSave(state) && !state.busy) {
                            asking = null
                            scope.launchOvertakable { answer = sentence(c.saveVaultItemsToPersonal(h.vaultId)) }
                        }
                    } else {
                        Quieter(UiText.of(CopyKey.REMOVE_FROM_THIS_DEVICE)) {
                            asking = null
                            answer = sentence(c.removeFromDevice(h.vaultId))
                        }
                    }
                }
            } else {
                ButtonRow {
                    if (h.readable && canSave(state)) Quieter(UiText.ph(Placeholder.HELD_COPY_TO_PERSONAL), enabled = !state.busy) { asking = h.vaultId to true }
                    Quieter(UiText.of(CopyKey.REMOVE_FROM_THIS_DEVICE), enabled = !state.busy) { asking = h.vaultId to false }
                }
            }
        }
    }
}

/**
 * Move or copy one item into another vault ([VaultContent.moveTargets]); move only where [VaultContent.canMoveOut]
 * allows it. Back cancels, so an unfinished try is not kept.
 */
@Composable
private fun MoveOrCopy(c: VaultContent, state: ContentState, d: ItemDetail, onMoved: () -> Unit) {
    val scope = rememberCoroutineScope()
    var open by remember(c, d.itemId) { mutableStateOf(false) }
    var answer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    if (!open) {
        if (canSave(state)) Quieter(UiText.ph(Placeholder.MOVE_OR_COPY)) { open = true }
        return
    }
    val targets = c.moveTargets(d.itemId)
    val canMove = c.canMoveOut(d.itemId)
    Quieter(UiText.ph(Placeholder.ITEM_BACK)) { c.cancelMove(d.itemId); open = false; answer = null }
    if (targets.isEmpty()) Say(Placeholder.MOVE_NO_TARGETS)
    targets.forEach { t ->
        Text(t.name, style = MaterialTheme.typography.bodyLarge)
        if (!t.personal) Say(Placeholder.ITEM_SHARED_VAULT_SEES)
        ButtonRow {
            Quieter(UiText.ph(Placeholder.COPY_TO_VAULT), enabled = !state.busy) {
                scope.launchOvertakable {
                    val r = c.moveOrCopyItem(d.itemId, t.vaultId, move = false)
                    answer = sentence(r)
                    if (r is ActionResult.Ok) open = false
                }
            }
            if (canMove) {
                Quieter(UiText.ph(Placeholder.MOVE_TO_VAULT), enabled = !state.busy) {
                    scope.launchOvertakable {
                        val r = c.moveOrCopyItem(d.itemId, t.vaultId, move = true)
                        answer = sentence(r)
                        if (r is ActionResult.Ok) onMoved()
                    }
                }
            }
        }
    }
}

/**
 * An item's earlier versions, newest first, while the content has them open ([ContentState.history]). On the item's
 * detail ([inline]) it is the current app's "Version history": a quiet heading, one row per version with its date first
 * and the password hidden until shown, and the way to hide it again under the list. Opened without its item on show,
 * it has its own way back.
 */
@Composable
private fun HistoryView(model: TrustModel, c: VaultContent, state: ContentState, h: ItemHistoryView, inline: Boolean = false) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var answer by remember(c, h.itemId) { mutableStateOf<String?>(null) }
    val shown = remember(c, h.itemId) { mutableStateMapOf<Long, String>() }
    // The version the person asked to restore (its rev and when it was archived), until they confirm or cancel.
    // A drawn screen may open on the question for the newest earlier version (FirstVaultView.restoreAsked).
    val drawnRestore = LocalFirstVaultView.current?.restoreAsked == true
    var restoring by remember(c, h.itemId) { mutableStateOf(if (drawnRestore) h.versions.firstOrNull()?.let { it.rev to it.archivedAtMs } else null) }
    restoring?.let { (rev, archivedAt) ->
        AlertDialog(
            onDismissRequest = { restoring = null },
            title = { Say(UiText.ph(Placeholder.HISTORY_RESTORE_CONFIRM)) },
            text = { Say(UiText.ph(Placeholder.HISTORY_RESTORE_CONFIRM_BODY, Dates.date(archivedAt))) },
            confirmButton = {
                TextButton(enabled = canSave(state) && !state.busy, onClick = {
                    restoring = null
                    scope.launchOvertakable {
                        answer = when (val r = c.restoreItemVersion(h.itemId, rev)) {
                            is ActionResult.Failed -> r.message
                            is ActionResult.NotDone -> r.message
                            else -> null
                        }
                    }
                }) { Say(UiText.ph(Placeholder.TRASH_RESTORE)) }
            },
            dismissButton = { TextButton(onClick = { restoring = null }) { Say(CopyKey.CANCEL) } },
        )
    }
    if (!inline) Quieter(UiText.ph(Placeholder.ITEM_BACK)) { c.closeItemHistory() }
    Say(UiText.ph(Placeholder.HISTORY), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    // An item with no earlier versions: the shared code's own line, never the empty vault's "Nothing here yet.".
    h.emptyLine?.let { Quiet(UiText.of(it)) }
    // At the largest font the date stands on its own line above the version: in its column it broke a word a line.
    val stacked = largeFont()
    h.versions.forEach { v ->
        if (stacked) {
            Text(
                Dates.dateTime(v.archivedAtMs), Modifier.padding(top = 4.dp),
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
            if (!stacked) {
                Text(
                    Dates.dateTime(v.archivedAtMs), Modifier.width(96.dp).padding(top = 2.dp),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
          Column(Modifier.weight(1f)) {
            Text(v.name, style = MaterialTheme.typography.bodyMedium)
            v.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            if (v.hasPassword) Text(shown[v.rev] ?: MASK,style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
            ButtonRow {
                if (v.hasPassword) {
                    if (shown[v.rev] == null) {
                        Quieter(UiText.ph(Placeholder.ITEM_REVEAL)) { c.historyPassword(h.itemId, v.rev)?.let { shown[v.rev] = it } }
                    } else {
                        Quieter(UiText.ph(Placeholder.ITEM_HIDE)) { shown.remove(v.rev) }
                    }
                    Quieter(UiText.ph(Placeholder.ITEM_COPY)) {
                        c.historyPassword(h.itemId, v.rev)?.let { copyToClipboard(context, "password", it, maxOf(1, (model.clipboardClearMs() / 1000).toInt())) }
                    }
                }
                if (h.canRestore) {
                    // The current app asks first ("Restore this version?"): a restore replaces the current version.
                    Quieter(UiText.ph(Placeholder.TRASH_RESTORE), enabled = canSave(state) && !state.busy) { restoring = v.rev to v.archivedAtMs }
                }
            }
          }
        }
    }
    if (inline) Quieter(UiText.ph(Placeholder.HISTORY_HIDE)) { c.closeItemHistory() }
}

/**
 * The trash, while the content has it open ([ContentState.trash]): the content's own explanation, each deleted item
 * with restore and delete forever where the content allows them, the latter behind a confirmation.
 */
@Composable
private fun TrashView(c: VaultContent, state: ContentState, rows: List<TrashItemView>) {
    val scope = rememberCoroutineScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    var purging by remember(c) { mutableStateOf<String?>(null) }
    fun said(r: ActionResult) {
        answer = when (r) {
            is ActionResult.Failed -> r.message
            is ActionResult.NotDone -> r.message
            else -> null
        }
    }
    // The current app's trash: the title and the way back are in the top bar; the explanation is its quiet line.
    Text(TRASH_EXPLANATION, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Spacer(Modifier.height(12.dp))
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    if (rows.isEmpty()) Say(Placeholder.VAULT_EMPTY)
    rows.forEach { t ->
        // The current app's trash row: the name (or what stands in for it) over one quiet line, the actions at its end.
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Column(Modifier.weight(1f)) {
                val name = trashRowName(t)
                if (name.isPlaceholder) Say(name, style = MaterialTheme.typography.bodyLarge) else Text(name.shown(), style = MaterialTheme.typography.bodyLarge)
                Text(trashRowLine(t), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            val canWrite = canSave(state) && !state.busy
            Column(horizontalAlignment = Alignment.End) {
                if (t.canRestore) Quieter(UiText.ph(Placeholder.TRASH_RESTORE), enabled = canWrite) { scope.launchOvertakable { said(c.restoreFromTrash(t.itemId)) } }
                if (t.canPurge) {
                    if (purging == t.itemId) {
                        Quieter(UiText.ph(Placeholder.ITEM_BACK)) { purging = null }
                        Quieter(UiText.ph(Placeholder.TRASH_PURGE_CONFIRM), enabled = canWrite) {
                            purging = null
                            scope.launchOvertakable { said(c.purgeFromTrash(t.itemId)) }
                        }
                    } else {
                        TextButton(enabled = canWrite, onClick = { purging = t.itemId }) {
                            Say(UiText.ph(Placeholder.TRASH_PURGE), color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }
    }
}

/**
 * A trash row's name: the item's own; for a row this device has not read yet, that it is not read yet (it can still be
 * restored: the restore reads it first); for one with no readable version, that it can only be deleted forever.
 */
internal fun trashRowName(t: TrashItemView): UiText = t.name?.let { UiText.Plain(it) } ?: when {
    t.notReadYet -> UiText.ph(Placeholder.TRASH_NOT_READ_YET)
    else -> UiText.ph(Placeholder.TRASH_UNREADABLE)
}

/**
 * A trash row's quiet line, as the current app's "deleted 2026-11-17 · view only": its detail and vault where they are
 * known, the day it was deleted (as the phone's language writes a date, not a machine's timestamp), and "view only" in a vault this account only reads (it offers neither action there).
 */
internal fun trashRowLine(t: TrashItemView): String =
    (listOfNotNull(t.detail, t.vault) +
        UiText.ph(Placeholder.TRASH_DELETED_ON, Dates.date(t.deletedAtMs)).shown() +
        listOfNotNull(UiText.ph(Placeholder.ITEM_VIEW_ONLY).shown().takeIf { !t.canPurge })).joinToString(" · ")

/** What a content action's answer says, or null when it was done. */
internal fun actionAnswer(r: ActionResult): String? = when (r) {
    is ActionResult.Failed -> r.message
    is ActionResult.NotDone -> r.message
    else -> null
}

/**
 * "Recently deleted" ([ContentState.deletedVaults]): the shared vaults this account deleted, still in their grace, as
 * this device's verified log shows them. Restore brings one back for everyone ([io.silencelen.andvari.core.app.SharedVaultsApi.restoreDeletedVault]);
 * its answer is said above, where every intent's is. Not offered while the server is stopped on this device.
 */
@Composable
internal fun DeletedVaultsView(model: TrustModel, c: VaultContent, state: ContentState, rows: List<io.silencelen.andvari.core.app.DeletedVaultView>) {
    Quieter(UiText.ph(Placeholder.ITEM_BACK)) { c.closeDeletedVaults() }
    Say(Placeholder.RECENTLY_DELETED, style = MaterialTheme.typography.titleSmall)
    if (rows.isEmpty()) Say(Placeholder.RECENTLY_DELETED_NONE)
    rows.forEach { v ->
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            Text(v.name, style = MaterialTheme.typography.bodyLarge)
            deletedVaultListLine(v)?.let { Quiet(it) }
            Quieter(UiText.ph(Placeholder.VAULT_RESTORE), enabled = canSave(state) && !state.busy) {
                model.run({ vaults.restoreDeletedVault(v) })
            }
        }
    }
}

/**
 * A row of "Recently deleted", as the vault's own row on Sharing says it ([deletedLine]): the state read from
 * [io.silencelen.andvari.core.app.DeletedVaultView.deleted], never from the day; the day its grace ends only where the
 * server served one; else the shared code's line that names no day, as handed. Never a date made of an empty day.
 */
internal fun deletedVaultListLine(v: io.silencelen.andvari.core.app.DeletedVaultView): UiText? = when {
    !v.deleted -> null
    v.purgeAtMs > 0 -> UiText.ph(Placeholder.VAULT_DELETED_IN_GRACE, Dates.date(v.purgeAtMs))
    else -> v.deletedNoDayLine?.let { UiText.of(it) }
}

/** The kinds the editors make, as [ItemSummary.type] names them. */
internal val EDITOR_KINDS = listOf("login", "card", "note")

/** Anything can be saved at all: the server is not stopped on this device. */
internal fun canSave(state: ContentState): Boolean = !state.serverStopped && state.sync != VaultSyncState.STOPPED

/**
 * Adds or edits a login, a card or a note. An edit is bound to the vault the editor opened on (the content refuses an
 * item that changed vaults meanwhile); a new item goes to the vault picked here, the personal vault first.
 */
@Composable
private fun ItemEditor(
    model: TrustModel, c: VaultContent, opening: Any, state: ContentState, kind: String, itemId: String?, found: ItemDetail?,
    generate: Boolean, onDone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val key = kind + ":" + (itemId ?: "")
    // What is typed is the editor's own, kept per opening ([GuardedContent.opening]): when the shared code composes the
    // account's vault again while it is open (the policy's wipe of the copy), it stays on the screen, and Save goes to the
    // new content. The item as last read here stands in while the new content does not hold it yet (before its sync).
    val lastRead = remember(opening, key) { arrayOfNulls<ItemDetail>(1) }
    if (found != null) lastRead[0] = found
    val d = found ?: lastRead[0]
    fun secret(f: SecretField, has: Boolean) = d?.takeIf { has }?.let { c.revealSecret(it.itemId, f) } ?: ""
    var name by remember(opening, key) { mutableStateOf(d?.name ?: "") }
    var username by remember(opening, key) { mutableStateOf(d?.username ?: "") }
    var password by remember(opening, key) {
        mutableStateOf(if (generate) c.generatePassword(GeneratorSettings.standard) else secret(SecretField.PASSWORD, d?.hasPassword == true))
    }
    val passwordShown = remember(opening, key) { mutableStateOf(generate) }
    var uri by remember(opening, key) { mutableStateOf(d?.uris?.firstOrNull() ?: "") }
    var notes by remember(opening, key) { mutableStateOf(secret(SecretField.NOTES, d?.hasNotes == true)) }
    var totp by remember(opening, key) { mutableStateOf(secret(SecretField.TOTP_SECRET, d?.hasTotp == true)) }
    var holder by remember(opening, key) { mutableStateOf(d?.card?.cardholder ?: "") }
    var number by remember(opening, key) { mutableStateOf(secret(SecretField.CARD_NUMBER, d?.card?.hasNumber == true)) }
    var expMonth by remember(opening, key) { mutableStateOf(d?.card?.expMonth ?: "") }
    var expYear by remember(opening, key) { mutableStateOf(d?.card?.expYear ?: "") }
    var code by remember(opening, key) { mutableStateOf(secret(SecretField.CARD_CODE, d?.card?.hasCode == true)) }
    var postal by remember(opening, key) { mutableStateOf(d?.card?.postalCode ?: "") }
    // Read from the content on show, again when it changes or the copy's removal begins or ends: none is offered while
    // the copy is being removed (the screen then says the removal's line), and they come back with the new content.
    val choices = remember(c, key, state.removingLine) { if (itemId == null) c.vaultsForNewItems() else emptyList() }
    var vaultId by remember(opening, key) { mutableStateOf(d?.vaultId ?: choices.firstOrNull { it.personal }?.vaultId ?: choices.firstOrNull()?.vaultId) }
    var answer by remember(opening, key) { mutableStateOf<String?>(null) }
    val drawnAsking = LocalFirstVaultView.current?.discard == true
    var confirmDiscard by remember(opening, key) { mutableStateOf(drawnAsking) }
    // Generate over a password already typed asks first, as the current app does: one more tap replaces it.
    var confirmGenerate by remember(opening, key) { mutableStateOf(false) }

    // The current app's editor: Cancel at the top and Back both ask before typed work is thrown away.
    ActiveBackHandler(model) { confirmDiscard = true }
    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Say(Placeholder.ITEM_DISCARD_TITLE, style = MaterialTheme.typography.headlineSmall) },
            text = { Say(Placeholder.ITEM_DISCARD_BODY) },
            confirmButton = { TextButton(onClick = { confirmDiscard = false; onDone() }) { Say(Placeholder.ITEM_DISCARD) } },
            dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Say(Placeholder.ITEM_KEEP_EDITING) } },
        )
    }
    // Then the title large, the vault a new item goes to, the fields, and Save as the main button.
    TextButton(onClick = { confirmDiscard = true }) { Text(UiText.ph(Placeholder.ITEM_CANCEL).shown()) }
    Say(UiText.ph(if (itemId == null) Placeholder.ITEM_NEW else Placeholder.ITEM_EDIT, kindWords(kind).shown()), style = MaterialTheme.typography.headlineMedium)
    Spacer(Modifier.height(8.dp))
    // No vault is offered for a new item while the copy is being removed: "New" stays, and the removal's line says why
    // (a save meanwhile is refused, and its answer says so).
    if (itemId == null && choices.isEmpty()) state.removingLine?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.onSurfaceVariant) }
    if (itemId == null && choices.size > 1) {
        Say(Placeholder.ITEM_VAULT, style = MaterialTheme.typography.labelMedium)
        choices.forEach { v ->
            Row(Modifier.fillMaxWidth().clickable { vaultId = v.vaultId }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = vaultId == v.vaultId, onClick = { vaultId = v.vaultId })
                Text(v.name)
            }
        }
        // Everyone in a shared vault sees what is put there.
        choices.firstOrNull { it.vaultId == vaultId && !it.personal }?.let { Say(Placeholder.ITEM_SHARED_VAULT_SEES) }
    }
    Field(UiText.ph(Placeholder.ITEM_NAME), name) { name = it }
    when (kind) {
        "login" -> {
            Field(UiText.ph(Placeholder.ITEM_USERNAME), username) { username = it }
            // Masked like the master password, with its show control; Generate shows what will be saved.
            MaskedField(UiText.ph(Placeholder.ITEM_PASSWORD).shown(), password, revealed = passwordShown) { password = it; confirmGenerate = false }
            TextButton(onClick = {
                if (password.isNotEmpty() && !confirmGenerate) {
                    confirmGenerate = true
                } else {
                    password = c.generatePassword(GeneratorSettings.standard)
                    passwordShown.value = true
                    confirmGenerate = false
                }
            }) {
                Icon(Icons.Default.Refresh, null)
                Text(" " + UiText.ph(if (confirmGenerate) Placeholder.ITEM_GENERATE_REPLACE else Placeholder.ITEM_GENERATE).shown())
            }
            if (confirmGenerate) {
                Text(
                    UiText.ph(Placeholder.ITEM_GENERATE_REPLACE_NOTE).shown(),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            Field(UiText.ph(Placeholder.ITEM_ADDRESS), uri, KeyboardType.Uri) { uri = it }
            MaskedField(UiText.ph(Placeholder.ITEM_TOTP).shown(), totp) { totp = it }
        }
        "card" -> {
            Field(UiText.ph(Placeholder.ITEM_CARDHOLDER), holder) { holder = it }
            // The current app's label: "Card number · Visa" once the typed digits name a brand.
            MaskedField(cardNumberLabel(c, number), number, digits = true) { number = it }
            c.cardNumberWarning(number)?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
            Field(UiText.ph(Placeholder.ITEM_EXP_MONTH), expMonth, KeyboardType.Number) { expMonth = it }
            Field(UiText.ph(Placeholder.ITEM_EXP_YEAR), expYear, KeyboardType.Number) { expYear = it }
            MaskedField(UiText.ph(Placeholder.ITEM_CARD_CODE).shown(), code, digits = true) { code = it }
            Field(UiText.ph(Placeholder.ITEM_POSTAL_CODE), postal) { postal = it }
        }
    }
    // Notes hold secrets too, so the keyboard is asked not to learn them (a password input
    // type, which keyboards keep out of their dictionaries and suggestions; nothing is masked). It holds lines.
    LinesField(UiText.ph(Placeholder.ITEM_NOTES), notes) { notes = it }
    AttachmentsInEditor(c, state, itemId, key)
    Spacer(Modifier.height(16.dp))
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    Main(UiText.ph(Placeholder.ITEM_SAVE), enabled = canSave(state) && !state.busy && name.isNotBlank(), busy = state.busy) {
        val fav = d?.favorite ?: false
        // The vault chosen, or (where none could be offered when the editor opened) the content's own default now.
        val into = vaultId ?: choices.firstOrNull { it.personal }?.vaultId ?: choices.firstOrNull()?.vaultId
        scope.launchOvertakable {
            val r = when (kind) {
                // Only the first web address is editable here; the others the login has are kept as they are.
                "login" -> c.saveLogin(itemId, LoginInput(name, username, password, listOf(uri) + (d?.uris?.drop(1) ?: emptyList()), notes, totp, fav), into)
                "card" -> c.saveCard(itemId, CardInput(name, holder, number, expMonth, expYear, code, postal, notes, fav), into)
                else -> c.saveNote(itemId, NoteInput(name, notes, fav), into)
            }
            when (r) {
                is ActionResult.Ok -> onDone()
                is ActionResult.Failed -> answer = r.message
                is ActionResult.NotDone -> answer = r.message
                else -> answer = null
            }
        }
    }
}

/** The line for how the last sync went, or null when there is nothing to say (synced, nothing waiting). */
internal fun syncLine(state: ContentState): UiText? = when {
    // The copy is being removed for the server's policy: the shared code's line, where a stopped server's would be. It is
    // not a stopped server, so Save and the other writes stay offered (each is refused meanwhile with the shared code's
    // line for a change not made).
    state.removingLine != null -> UiText.Plain(state.removingLine!!)
    state.serverStopped || state.sync == VaultSyncState.STOPPED -> UiText.ph(Placeholder.SYNC_STOPPED)
    state.sync == VaultSyncState.ROLLBACK -> UiText.ph(Placeholder.SYNC_ROLLBACK)
    state.sync == VaultSyncState.REFUSED -> UiText.ph(Placeholder.SYNC_REFUSED)
    state.sync == VaultSyncState.OFFLINE -> UiText.ph(Placeholder.SYNC_OFFLINE, state.queued.toString())
    state.queued > 0 -> UiText.ph(Placeholder.SYNC_QUEUED, state.queued.toString())
    state.sync == VaultSyncState.NOT_YET -> UiText.ph(Placeholder.SYNC_NOT_YET)
    else -> null
}

/**
 * The lines above the vault's search field: how the last sync went, the content's error, and its notices about
 * vaults. The actions that stood here as a row of buttons are in the top bar, its menu and the Add button now, as in
 * the current app.
 */
@Composable
private fun VaultListLines(c: VaultContent, state: ContentState) {
    syncLine(state)?.let { Say(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    state.error?.let {
        Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error)
        Quieter(UiText.ph(Placeholder.CLOSE)) { c.dismissError() }
    }
    // A copy that went on although, by the sizes its files state, it may not fit: said once, for information.
    declaredSpaceLine(state)?.let { Say(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    state.vaultNotices.forEach { n ->
        Say(UiText.Plain(n.text), color = if (n.warning) MaterialTheme.colorScheme.error else Color.Unspecified)
        Quieter(UiText.ph(Placeholder.CLOSE)) { c.dismissVaultNotice(n.id) }
    }
}

/**
 * What autofill captured (the content's save queue, [ContentState.pendingSaves] and [ContentState.appliedSaves]): what
 * core saved by itself, each with an undo until the list is dismissed, and what waits for the person, each with its
 * reason, its password on request, Save and Discard. Every answer is the content's own sentence.
 */
@Composable
private fun AutofillSavesSection(c: VaultContent, state: ContentState) {
    if (state.pendingSaves.isEmpty() && state.appliedSaves.isEmpty()) return
    val scope = rememberCoroutineScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    val shown = remember(c) { mutableStateMapOf<String, String>() }
    // A shown password goes when the vault locks (a new content) or the row leaves.
    DisposableEffect(c) { onDispose { shown.clear() } }
    fun act(block: suspend () -> ActionResult) {
        scope.launchOvertakable { answer = actionAnswer(block()) }
    }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    if (state.appliedSaves.isNotEmpty()) {
        Say(Placeholder.APPLIED_SAVES, style = MaterialTheme.typography.titleSmall)
        state.appliedSaves.forEach { a ->
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Text(a.host + (if (a.username.isEmpty()) "" else "  ·  " + a.username), style = MaterialTheme.typography.bodyLarge)
                a.replaced?.let { Quiet(UiText.ph(Placeholder.APPLIED_SAVE_REPLACED, it)) }
                if (a.plainHttp) Quiet(UiText.ph(Placeholder.PENDING_SAVE_HTTP))
                Quieter(UiText.ph(Placeholder.APPLIED_SAVE_UNDO), enabled = !state.busy) { act { c.undoAppliedSave(a.id) } }
            }
        }
        ButtonRow {
            Quieter(UiText.ph(Placeholder.APPLIED_SAVES_UNDO_ALL), enabled = !state.busy) { act { c.undoAllAppliedSaves() } }
            Quieter(UiText.ph(Placeholder.APPLIED_SAVES_DISMISS), enabled = !state.busy) { act { c.dismissAppliedSaves() } }
        }
    }
    if (state.pendingSaves.isNotEmpty()) {
        Say(Placeholder.PENDING_SAVES, style = MaterialTheme.typography.titleSmall)
        state.pendingSaves.forEach { p ->
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Text(p.host + (if (p.username.isEmpty()) "" else "  ·  " + p.username), style = MaterialTheme.typography.bodyLarge)
                Text(p.detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                p.replaces?.let { Quiet(UiText.ph(Placeholder.PENDING_SAVE_REPLACES, it)) }
                if (p.plainHttp) Say(UiText.ph(Placeholder.PENDING_SAVE_HTTP), color = MaterialTheme.colorScheme.error)
                p.reason?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.onSurfaceVariant) }
                shown[p.id]?.let { Text(it, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)) }
                ButtonRow {
                    if (shown[p.id] == null) Quieter(UiText.ph(Placeholder.PENDING_SAVE_SHOW)) { c.pendingSavePassword(p.id)?.let { shown[p.id] = it } }
                    Quieter(UiText.ph(Placeholder.PENDING_SAVE_SAVE), enabled = canSave(state) && !state.busy) { shown.remove(p.id); act { c.confirmPendingSave(p.id) } }
                    Quieter(UiText.ph(Placeholder.PENDING_SAVE_DISCARD), enabled = !state.busy) { shown.remove(p.id); act { c.discardPendingSave(p.id) } }
                }
            }
        }
    }
}

@Composable
private fun ItemDetailView(model: TrustModel, c: VaultContent, state: ContentState, d: ItemDetail, history: ItemHistoryView?, onEdit: () -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    // What was revealed lives only while this detail is on show.
    val shown = remember(c, d.itemId) { mutableStateMapOf<SecretField, String>() }
    val clearSeconds = maxOf(1, (model.clipboardClearMs() / 1000).toInt())
    fun copy(label: String, value: String) = copyToClipboard(context, label, value, clearSeconds)

    // The current app's detail: the way back, the name large, a line with its kind and vault, then one row per field
    // with its label above, its value, and Show and Copy beside it; a copy says so under its row for a moment.
    TextButton(onClick = onBack) {
        Icon(Icons.AutoMirrored.Filled.ArrowBack, null)
        Text(" " + UiText.ph(Placeholder.ITEM_BACK).shown())
    }
    Text(d.name, style = MaterialTheme.typography.headlineMedium)
    Text(
        (listOfNotNull(kindWords(d.type).shown(), d.card?.summary, c.vaultName(d.vaultId)) +
            listOfNotNull(UiText.ph(Placeholder.ITEM_VIEW_ONLY).shown().takeIf { !d.editable })).joinToString(" · "),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    // The current app's per-item health line, under the kind line of a login with a password.
    if (d.type == "login") LoginHealthLine(c, state, d.itemId)
    Spacer(Modifier.height(16.dp))
    d.username?.let { u -> PlainCopyRow(Placeholder.ITEM_USERNAME, u, clearSeconds) { copy("username", u) } }
    if (d.hasPassword) SecretRow(Placeholder.ITEM_PASSWORD, SecretField.PASSWORD, c, d, shown, clearSeconds, ::copy)
    if (d.hasTotp) OneTimeCodeRow(c, d.itemId, clearSeconds, ::copy)
    d.uris.forEach { LabelledValue(Placeholder.ITEM_ADDRESS, it) }
    d.card?.let { card ->
        card.cardholder?.let { h -> PlainCopyRow(Placeholder.ITEM_CARDHOLDER, h, clearSeconds) { copy("cardholder", h) } }
        if (card.hasNumber) SecretRow(Placeholder.ITEM_CARD_NUMBER, SecretField.CARD_NUMBER, c, d, shown, clearSeconds, ::copy)
        // The current app's ExpiryRow: the expiry, "expired" once its month is over, and Copy of the short form.
        val expiry = remember(state, d.itemId) { c.cardExpiry(d.itemId) }
        if (expiry != null) ExpiryRow(expiry, clearSeconds) { copy("expiry", it) }
        else card.expiry?.let { LabelledValue(Placeholder.ITEM_EXPIRY, it, mono = true) }
        if (card.hasCode) SecretRow(Placeholder.ITEM_CARD_CODE, SecretField.CARD_CODE, c, d, shown, clearSeconds, ::copy)
        // The billing postal code, after the security code, as the current app's card shows it.
        card.postalCode?.takeIf { it.isNotBlank() }?.let { p -> PlainCopyRow(Placeholder.ITEM_POSTAL_CODE, p, clearSeconds) { copy("postal code", p) } }
    }
    if (d.hasNotes) SecretRow(Placeholder.ITEM_NOTES, SecretField.NOTES, c, d, shown, clearSeconds, ::copy)
    AttachmentsOnDetail(c, d)
    Spacer(Modifier.height(16.dp))
    val scope = rememberCoroutineScope()
    var historyAnswer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    // The current app's "Version history": opened in place on the detail, under the fields.
    if (history != null && history.itemId == d.itemId) HistoryView(model, c, state, history, inline = true)
    else Quieter(UiText.ph(Placeholder.HISTORY), enabled = !c.state.busy) {
        scope.launchOvertakable {
            historyAnswer = when (val r = c.openItemHistory(d.itemId)) {
                is ActionResult.Failed -> r.message
                is ActionResult.NotDone -> r.message
                else -> null
            }
        }
    }
    historyAnswer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    Spacer(Modifier.height(24.dp))
    // Edit, the main action, and Delete beside it in the error tone, as the current app's detail ends.
    if (canDelete(d, c.state)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (d.type in EDITOR_KINDS) {
                Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text(UiText.ph(Placeholder.ITEM_EDIT, kindWords(d.type).shown()).shown()) }
                Spacer(Modifier.width(12.dp))
            }
            DeleteItem(c, d, onBack)
        }
    }
    Spacer(Modifier.height(8.dp))
    MoveOrCopy(c, c.state, d, onBack)
}

/**
 * A login's health as the current app's ItemHealthLine says it: its strength (in the error tone when weak), how many
 * other logins reuse it and, once checked, its breaches, on one line; when it was last used under it. From the
 * shared code's [VaultContent.itemHealth], asked once per state. A login with no password has none.
 */
@Composable
private fun LoginHealthLine(c: VaultContent, state: ContentState, itemId: String) {
    val line = remember(state, itemId) { c.itemHealth()[itemId] }
    if (line == null) {
        // A login with no password has no health line, but it has an age and a last use ([VaultContent.loginAges]),
        // as the current app's staleness list shows it: said here too.
        val age = remember(state, itemId) { c.loginAges()[itemId] } ?: return
        Spacer(Modifier.height(8.dp))
        Say(lastUsedLine(age), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    Spacer(Modifier.height(8.dp))
    Column {
        // Wraps at the largest font instead of squeezing a mark to a letter a line.
        ButtonRow(spacing = 10) {
            for ((text, bad) in healthMarks(line)) {
                Say(text, style = MaterialTheme.typography.bodySmall, color = if (bad) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Say(lastUsedLine(line), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** The marks of a login's health line, in the current app's order, each with whether it is bad. */
internal fun healthMarks(line: io.silencelen.andvari.core.app.content.ItemHealthLine): List<Pair<UiText, Boolean>> = listOfNotNull(
    UiText.ph(Placeholder.ITEM_HEALTH_STRENGTH, line.strength) to line.weak,
    // [reused] counts the OTHER logins with this exact password.
    (counted(line.reused.toLong(), Placeholder.HEALTH_REUSED, Placeholder.HEALTH_REUSED_ONE) to true).takeIf { line.reused > 0 },
    line.breaches?.takeIf { it > 0 }?.let { counted(it.toLong(), Placeholder.HEALTH_BREACHED, Placeholder.HEALTH_BREACHED_ONE) to true },
)

/** When the login was last used, as this account's devices recorded it; "no use recorded" is not "never used". */
internal fun lastUsedLine(line: io.silencelen.andvari.core.app.content.ItemHealthLine): UiText = lastUsedLine(line.lastUsedAt)

/** The same line for a login with no password, from its age ([VaultContent.loginAges]). */
internal fun lastUsedLine(age: io.silencelen.andvari.core.app.content.LoginAgeLine): UiText = lastUsedLine(age.lastUsedAt)

private fun lastUsedLine(lastUsedAt: Long?): UiText =
    lastUsedAt?.let { UiText.ph(Placeholder.ITEM_HEALTH_LAST_USED, Dates.date(it)) } ?: UiText.ph(Placeholder.ITEM_HEALTH_NO_USE_RECORD)

/** The card editor's number label, with the brand the typed digits name ([VaultContent.cardBrandOf]), as the current app's. */
internal fun cardNumberLabel(c: VaultContent, typed: String): String =
    UiText.ph(Placeholder.ITEM_CARD_NUMBER).shown() + (c.cardBrandOf(typed)?.let { " · $it" } ?: "")

/**
 * The current app's ExpiryRow: the label above, the expiry, "expired" beside it in the error tone once its month is
 * over, and Copy of the short form a checkout takes ("07/31") where both halves are there.
 */
@Composable
private fun ExpiryRow(expiry: io.silencelen.andvari.core.app.content.CardExpiryView, clearSeconds: Int, copy: (String) -> Unit) {
    var copied by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Say(UiText.ph(Placeholder.ITEM_EXPIRY), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(expiry.label, fontFamily = FontFamily.Monospace)
            if (expiry.expired) {
                Spacer(Modifier.width(8.dp))
                Say(UiText.ph(Placeholder.ITEM_EXPIRED), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
            }
            expiry.shortExpiry?.let { short ->
                Spacer(Modifier.weight(1f))
                CopyButton(copied) { copy(short); copied = true }
            }
        }
        if (copied) CopiedLine(clearSeconds) { copied = false }
    }
}

/** A field's label above its value, read only (the current app's ReadOnlyRow). */
@Composable
private fun LabelledValue(label: Placeholder, value: String, mono: Boolean = false) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Say(UiText.ph(label), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontFamily = if (mono) FontFamily.Monospace else null)
    }
}

/** A field that is not secret, with Copy beside it (the current app's CopyRow). */
@Composable
private fun PlainCopyRow(label: Placeholder, value: String, clearSeconds: Int, copy: () -> Unit) {
    var copied by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Say(UiText.ph(label), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            CopyButton(copied) { copy(); copied = true }
        }
        if (copied) CopiedLine(clearSeconds) { copied = false }
    }
}

/** The current app's Copy: it reads "copied" once used, until the line under the row goes. */
@Composable
private fun CopyButton(copied: Boolean, onClick: () -> Unit) {
    TextButton(onClick = onClick) { Text(UiText.ph(if (copied) Placeholder.ITEM_COPIED else Placeholder.ITEM_COPY).shown()) }
}

/**
 * The current app's note after a copy, for about three and a half seconds and read out politely: that it was copied,
 * that andvari clears it after [clearSeconds] while it is open, and that the device hides it from other apps.
 */
@Composable
private fun CopiedLine(clearSeconds: Int, onGone: () -> Unit) {
    Text(
        counted(clearSeconds.toLong(), Placeholder.ITEM_COPIED_NOTE, Placeholder.ITEM_COPIED_NOTE_ONE).shown(),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
    LaunchedEffect(Unit) { delay(COPIED_LINE_MS); onGone() }
}

internal const val COPIED_LINE_MS = 3500L

/** Delete is offered only on an item this account may change, while something can be saved at all. */
internal fun canDelete(d: ItemDetail, state: ContentState): Boolean =
    d.editable && !state.serverStopped && state.sync != VaultSyncState.STOPPED

@Composable
private fun DeleteItem(c: VaultContent, d: ItemDetail, onGone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var asking by remember(c, d.itemId) { mutableStateOf(false) }
    var answer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    Column {
        OutlinedButton(onClick = { asking = true }, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) {
            Text(UiText.ph(Placeholder.ITEM_DELETE).shown())
        }
        answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    }
    if (!asking) return
    // The current app asks in a dialog; the way out is the dismiss button.
    AlertDialog(
        onDismissRequest = { asking = false },
        title = { Text(d.name) },
        text = { Say(UiText.ph(Placeholder.ITEM_DELETE_CONFIRM)) },
        confirmButton = {
            TextButton(enabled = !c.state.busy, onClick = {
                scope.launchOvertakable {
                    when (val r = c.deleteItem(d.itemId)) {
                        is ActionResult.Ok -> onGone()
                        is ActionResult.Failed -> { answer = r.message; asking = false }
                        is ActionResult.NotDone -> { answer = r.message; asking = false }
                        else -> { answer = null; asking = false }
                    }
                }
            }) { Text(UiText.ph(Placeholder.ITEM_DELETE).shown()) }
        },
        dismissButton = { TextButton(onClick = { asking = false }) { Text(UiText.ph(Placeholder.ITEM_KEEP).shown()) } },
    )
}

@Composable
private fun SecretRow(
    label: Placeholder,
    field: SecretField,
    c: VaultContent,
    d: ItemDetail,
    shown: MutableMap<SecretField, String>,
    clearSeconds: Int,
    copy: (String, String) -> Unit,
) {
    // The current app's SecretCopyRow: the label above, the value masked, the eye to show or hide it, Copy beside.
    val value = shown[field]
    var copied by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Say(UiText.ph(label), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            // The mask stays on one line: at the largest font it broke into a second line of one dot.
            if (value == null) {
                Text(MASK, Modifier.weight(1f), fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Clip)
            } else {
                Text(value, Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            }
            IconButton(onClick = {
                if (value == null) c.revealSecret(d.itemId, field)?.let { shown[field] = it } else shown.remove(field)
            }) {
                Icon(
                    if (value == null) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                    UiText.ph(if (value == null) Placeholder.ITEM_REVEAL else Placeholder.ITEM_HIDE).shown(),
                )
            }
            // A copy reads the value afresh and keeps nothing on screen.
            CopyButton(copied) { c.revealSecret(d.itemId, field)?.let { copy(field.name.lowercase(), it); copied = true } }
        }
        if (copied) CopiedLine(clearSeconds) { copied = false }
    }
}

/** What a hidden value shows in its place. */
internal const val MASK = "••••••••••"

/** A one-time code as the current app shows it: in groups of three, large, and copied with a tap on the code itself. */
internal fun groupedCode(code: String): String = code.chunked(3).joinToString(" ")

@Composable
private fun OneTimeCodeRow(c: VaultContent, itemId: String, clearSeconds: Int, copy: (String, String) -> Unit) {
    var code by remember(c, itemId) { mutableStateOf<OneTimeCode?>(c.oneTimeCode(itemId)) }
    var copied by remember { mutableStateOf(false) }
    LaunchedEffect(c, itemId) {
        while (true) {
            code = c.oneTimeCode(itemId)
            delay(1000)
        }
    }
    Column(Modifier.padding(vertical = 8.dp)) {
        Say(UiText.ph(Placeholder.ITEM_CODE), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        code?.let { otp ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                val tapToCopy = UiText.ph(Placeholder.ITEM_CODE_TAP_TO_COPY).shown()
                TextButton(
                    onClick = { c.oneTimeCode(itemId)?.let { copy("one-time code", it.code); copied = true } },
                    modifier = Modifier.semantics { contentDescription = tapToCopy },
                ) {
                    Text(groupedCode(otp.code), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.secondary)
                }
                // Counted every second; not read out at every tick.
                Text("${otp.secondsRemaining}s", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.clearAndSetSemantics {})
            }
        }
        if (copied) CopiedLine(clearSeconds) { copied = false }
    }
}
