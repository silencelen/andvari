package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TextButton
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import io.silencelen.andvari.desktop.BrandRune
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentDraftView
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.AttachmentView
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.desktop.SAVE_OUTSIDE_FOLDER
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.io.File
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.GeneratorSettings
import io.silencelen.andvari.core.app.ItemDetail
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.OneTimeCode
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.app.TRASH_EXPLANATION
import io.silencelen.andvari.core.app.TrashItemView
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import io.silencelen.andvari.core.app.content.CardExpiryView
import io.silencelen.andvari.core.app.content.ItemHealthLine
import io.silencelen.andvari.core.app.content.ContentNoticeKind
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.ContentVault
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.CardDisplay
import androidx.compose.foundation.layout.widthIn
import io.silencelen.andvari.core.app.content.VaultSyncState
import io.silencelen.andvari.desktop.CLIPBOARD_COPY_FAILED
import io.silencelen.andvari.desktop.copyWithAutoClear
import kotlinx.coroutines.delay

/**
 * The open vault's items, read from [TrustModel.content] (a new [VaultContent] at every unlock, none while locked),
 * ported from the Android app. Every sentence here is the content's own ([ContentState.notice],
 * [ContentState.error], an [ActionResult]'s message); the labels the content does not carry are placeholders.
 *
 * The list with its search, the sync and failure states, the vault notices and "Recently removed"; an item's detail
 * with reveal, copy (through the desktop's sensitive clipboard, cleared after the policy's window), one-time codes,
 * its files (saved through the system's Save dialog), its earlier versions, and move or copy to another vault; the
 * editors for a login, a card and a note, with the generator, the vault picker and the item's files; delete; the
 * trash; CSV import, backup and CSV export ([TransferButtons]); vault health ([HealthPanel]).
 */
@Composable
internal fun VaultItemsSection(model: TrustModel, header: @Composable () -> Unit = {}) {
    val content by model.content.collectAsState()
    val unlocks by model.unlocks.collectAsState()
    // Keyed by the unlock, and held above the content: a new unlock starts on the list, and nothing opened under the last
    // one survives it; a content the shared code composes again while the vault stays open (the removal of this
    // computer's copy for the server's policy) keeps the item or the editor on show, and what was typed in it.
    var open by remember(unlocks) { mutableStateOf<String?>(null) }
    var editing by remember(unlocks) { mutableStateOf<Editing?>(null) }
    // The moment between the unlock and the content's first state is named, never a blank page under the toolbar.
    val c = content ?: return Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        header()
        VaultOpening()
    }
    val state by c.states.collectAsState()
    // A read the shared code makes throw is said ("something went wrong") and the list stays.
    val detail = open?.let { id -> guardedRead(null, null) { c.itemDetail(id) } }
    val e = editing
    val trash = state.trash
    val history = state.history
    val importing = state.csvImport
    val exporting = state.exporting
    val health = state.health
    // The list is the only one that scrolls by itself (a lazy list, as the current app's); every other view is a
    // column that scrolls under the toolbar, with what needs the person at its top.
    if (health == null && importing == null && exporting == null && trash == null && history == null && e == null && detail == null) {
        return VaultItemsList(model, c, state, header, onNew = { editing = Editing(it, null) }) { open = it }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 12.dp)) {
        header()
        when {
            // The bad-password offer opens the item: its detail, or its editor with a new password, unsaved, on show.
            health != null -> HealthPanel(model, c, state, health) { itemId, generate ->
                c.closeHealth()
                if (generate) editing = Editing("login", itemId, generate = true) else open = itemId
            }
            importing != null -> ImportView(c, state, importing)
            exporting != null -> ExportPanel(model, c, exporting)
            trash != null -> TrashView(c, state, trash)
            history != null -> HistoryView(model, c, state, history)
            e != null -> ItemEditor(model, c, state, e, e.itemId?.let { id -> guardedRead(null, null) { c.itemDetail(id) } }) { editing = null }
            detail != null -> ItemDetailView(model, c, state, detail, onEdit = { editing = Editing(detail.type, detail.itemId) }) { open = null }
        }
    }
}

/**
 * The vault is being opened: the current app's loading page (its brand mark, 16 dp, its small spinner), with the line
 * under it, where the list's empty state stands.
 */
@Composable
internal fun VaultOpening() {
    Column(Modifier.fillMaxWidth().padding(top = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        BrandRune()
        Gap(16)
        OpeningSpinner(UiText.ph(Placeholder.VAULT_OPENING))
        Say(UiText.ph(Placeholder.VAULT_OPENING), Modifier.padding(top = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/**
 * The current app's loading spinner (18 dp, a 2 dp stroke), drawn over a faint full ring: the turning arc alone is caught
 * as a dot by any still frame at the short end of its sweep (seen on the virtual display), and a ring always reads as
 * "working". [named]: what a screen reader says for it (none where, as at the start, the current app said nothing).
 */
@Composable
internal fun OpeningSpinner(named: UiText? = null) {
    CircularProgressIndicator(
        Modifier.size(18.dp).let { m -> if (named == null) m else m.semantics { contentDescription = named.shown() } },
        strokeWidth = 2.dp,
        trackColor = MaterialTheme.colorScheme.outlineVariant,
    )
}

/**
 * The name of vault [vaultId] as the content's state lists it (data already drawn, never a call into the shared
 * code): what a fault in work on that vault names.
 */
internal fun vaultNamed(state: ContentState, vaultId: String?): String? = state.vaults.firstOrNull { it.vaultId == vaultId }?.name

/** [generate]: the editor opens with a freshly generated password in its field, shown and not saved. */
private class Editing(val kind: String, val itemId: String?, val generate: Boolean = false) {
    /** What was typed in this editor, held by the window from its first drawing on ([ItemEditor]). */
    var draft: EditorDraft? = null
}

/**
 * An editor's fields as typed, held by the window and not by the content: a content the shared code composes again while
 * the vault stays open (the removal of this computer's copy for the server's policy) neither closes the editor nor
 * empties it. A lock or a new unlock does ([VaultItemsSection]). [moreUris] and [favorite] are kept as the item had them.
 */
internal class EditorDraft(
    name: String, username: String, password: String, passwordShown: Boolean, uri: String, val moreUris: List<String>, notes: String,
    totp: String, holder: String, number: String, expMonth: String, expYear: String, code: String, postal: String,
    vaultId: String?, val favorite: Boolean,
) {
    var name by mutableStateOf(name)
    var username by mutableStateOf(username)
    var password by mutableStateOf(password)
    val passwordShown = mutableStateOf(passwordShown)
    var uri by mutableStateOf(uri)
    var notes by mutableStateOf(notes)
    var totp by mutableStateOf(totp)
    var holder by mutableStateOf(holder)
    var number by mutableStateOf(number)
    var expMonth by mutableStateOf(expMonth)
    var expYear by mutableStateOf(expYear)
    var code by mutableStateOf(code)
    var postal by mutableStateOf(postal)

    /** The vault a new item goes to, as picked; an edit's own vault. */
    var vaultId by mutableStateOf(vaultId)
}

/** Told each time an editor is drawn, with what is typed in it. Nothing listens in the app; a test does. */
internal val LocalEditorShown = staticCompositionLocalOf<(EditorDraft) -> Unit> { {} }

/**
 * The content's check for space (design §3.13), as a line: for the import's plan ([informational] false), the
 * "short" of an import, with the limit and the amount; for the vault ([informational] true), the line that a copy or a
 * move went on although it looked short only on sizes a co-member declared. A copy's or a move's own "short" is the
 * full sentence of its refusal, said where it was asked. Null otherwise.
 */
internal fun spaceLine(state: ContentState, informational: Boolean): io.silencelen.andvari.core.app.CopyLine? {
    val space = state.space ?: return null
    return if (informational) {
        space.line.takeIf { space.verdict == io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES && space.forWhat != io.silencelen.andvari.core.app.content.SpaceFor.CSV_IMPORT }
    } else {
        space.line.takeIf {
            space.forWhat == io.silencelen.andvari.core.app.content.SpaceFor.CSV_IMPORT &&
                (space.verdict == io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH || space.verdict == io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES)
        }
    }
}

/** What an intent answered, as the sentence to show in place; null for done. */
internal fun sentence(r: ActionResult): String? = when (r) {
    is ActionResult.Failed -> r.message
    is ActionResult.NotDone -> r.message
    else -> null
}

/** The kinds the editors make, as [ItemSummary.type] names them. */
internal val EDITOR_KINDS = listOf("login", "card", "note")

/** Anything can be saved at all, as the content says: the server is not stopped on this computer (a fork stops traffic, not reading). */
internal fun canSaveState(state: ContentState): Boolean = !state.serverStopped && state.sync != VaultSyncState.STOPPED

/**
 * The app holds saves on this screen for a reason the content does not know: the session's server answered that this
 * build is too old. The vault stays open and readable, as under a session the server
 * ended, with the notice in view. Provided by [AccountShell].
 */
internal val LocalSavesHeld = staticCompositionLocalOf { false }

/** Anything can be saved here: [canSaveState], and the app holds no saves ([LocalSavesHeld]). */
@Composable
@ReadOnlyComposable
internal fun canSave(state: ContentState): Boolean = canSaveState(state) && !LocalSavesHeld.current

/** Delete and edit are offered only on an item this account may change, while something can be saved at all. */
internal fun canDeleteState(d: ItemDetail, state: ContentState): Boolean = d.editable && canSaveState(state)

@Composable
@ReadOnlyComposable
internal fun canDelete(d: ItemDetail, state: ContentState): Boolean = d.editable && canSave(state)

/** The line for how the last sync went, or null when there is nothing to say (synced, nothing waiting). */
internal fun syncLine(state: ContentState): UiText? = when {
    // This computer's copy is being removed for the server's policy: the shared code's line, never "stopped" (Save stays).
    state.removingLine != null -> UiText.Plain(state.removingLine!!)
    state.serverStopped || state.sync == VaultSyncState.STOPPED -> UiText.ph(Placeholder.SYNC_STOPPED)
    state.sync == VaultSyncState.ROLLBACK -> UiText.ph(Placeholder.SYNC_ROLLBACK)
    state.sync == VaultSyncState.REFUSED -> UiText.ph(Placeholder.SYNC_REFUSED)
    state.sync == VaultSyncState.OFFLINE -> UiText.ph(Placeholder.SYNC_OFFLINE, state.queued.toString())
    state.queued > 0 -> UiText.ph(Placeholder.SYNC_QUEUED, state.queued.toString())
    state.sync == VaultSyncState.NOT_YET -> UiText.ph(Placeholder.SYNC_NOT_YET)
    else -> null
}

/** ux-error--6: what a stored one-time-code key that will not parse says instead of a code (the old desktop's words,
 *  moved here from `Ui.kt`). Pinned by [io.silencelen.andvari.desktop.TotpRowTest]. */
internal const val TOTP_URI_UNREADABLE = "This one-time code isn't set up right — edit the item and add it again."

/** The clipboard window in whole seconds, never under one. */
internal fun clipboardSeconds(model: TrustModel): Int = maxOf(1, (model.clipboardClearMs() / 1000).toInt())

/** The type filter's choices, as the current app's dropdown: all, or one kind. */
internal val TYPE_FILTERS: List<Pair<String?, Placeholder>> =
    listOf(null to Placeholder.TYPE_ALL, "login" to Placeholder.TYPE_LOGINS, "note" to Placeholder.TYPE_NOTES, "card" to Placeholder.TYPE_CARDS)

/** The rows the type filter lets through, in the content's order (null: all). */
internal fun itemsOfType(items: List<ItemSummary>, type: String?): List<ItemSummary> = if (type == null) items else items.filter { it.type == type }

/** Under this width the add buttons go on a line of their own under the search box, so the box is never squeezed. */
internal val SEARCH_ROW_MIN_WIDTH = 600.dp

/**
 * The vault's list, as the current app's: what needs the person at the top; then, held at the top once scrolled to, the
 * search box with Add, Add note and Add card beside it and the type filter under it; the content's lines; a card per
 * item; and "Recently removed". A lazy list, so a large vault draws only what is in view.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun VaultItemsList(model: TrustModel, c: VaultContent, state: ContentState, header: @Composable () -> Unit, onNew: (String) -> Unit, onOpen: (String) -> Unit) {
    // As the current app's: fresh at each unlock (a filter that outlived a session would read as missing items).
    var typeFilter by remember(c) { mutableStateOf<String?>(null) }
    var vaultFilter by remember(c) { mutableStateOf<String?>(null) }
    var sort by remember(c) { mutableStateOf(ListSort.NAME) }
    val shown = listRows(state, typeFilter, vaultFilter, sort)
    // Every login's health in one pass, kept by the shared code until the items, their uses or the verdicts change.
    val health = guardedRead(null, emptyMap()) { c.itemHealth() }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp)) {
        item(key = "attention") { Column(Modifier.fillMaxWidth()) { header() } }
        stickyHeader(key = "search") {
            // The page's own colour (the window's surface), so the held search box hides the rows scrolling under it.
            Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(bottom = 8.dp)) {
                SearchAndAdd(c, state, onNew)
                // The current app's row under the search box: the sort, the type, and the vault when there is a choice.
                Actions {
                    SortChoice(sort) { sort = it }
                    TypeFilter(typeFilter) { typeFilter = it }
                    VaultFilter(state, vaultFilter) { vaultFilter = it }
                }
            }
        }
        item(key = "lines") {
            Column(Modifier.fillMaxWidth()) {
                ImportRequests(model, c, state)
                syncLine(state)?.let { Say(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                // A vault this computer holds closed for writing says why, above its items (the shared code's line).
                for (line in closedVaultLines(state, vaultFilter)) Say(UiText.Plain(line), color = MaterialTheme.colorScheme.error)
                // The content's error and its notice, in the current app's error bar and notice bar; core's notice, among
                // them what a lock cut short, by kind and with counts (noticeKind LOCK).
                ContentSaid(c, state)
                // A copy or a move that went on although it looked short of space, on sizes a co-member declared: the server decides.
                spaceLine(state, informational = true)?.let { Quiet(UiText.of(it)) }
                // Whatever the content reports is shown; nothing is invented.
                state.vaultNotices.forEach { n ->
                    Say(UiText.Plain(n.text), color = if (n.warning) MaterialTheme.colorScheme.error else Color.Unspecified)
                    Quieter(UiText.ph(Placeholder.DISMISS)) { c.dismissVaultNotice(n.id) }
                }
            }
        }
        if (shown.isEmpty()) {
            item(key = "empty") {
                Column(Modifier.fillMaxWidth().padding(top = 48.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    BrandRune(36.dp)
                    Gap(8)
                    Say(UiText.ph(if (state.items.isEmpty() && state.query.isEmpty()) Placeholder.VAULT_EMPTY else Placeholder.VAULT_NO_MATCH), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        } else {
            items(shown, key = { it.itemId }) { item ->
                ItemRow(item, sharedMark(item), health[item.itemId]) { onOpen(item.itemId) }
                Spacer(Modifier.height(8.dp))
            }
        }
        item(key = "removed") { Column(Modifier.fillMaxWidth()) { RecentlyRemovedSection(c, state) } }
    }
}

/** The search box with its magnifier, and the three add buttons (beside it, or under it in a narrow window). */
@Composable
private fun SearchAndAdd(c: VaultContent, state: ContentState, onNew: (String) -> Unit) {
    val search = @Composable { m: Modifier ->
        OutlinedTextField(
            state.query, guardedChange(onChange = { q: String -> c.setQuery(q) }), m,
            label = { Say(UiText.ph(Placeholder.VAULT_SEARCH)) }, singleLine = true,
            leadingIcon = { Icon(Icons.Default.Search, null) },
        )
    }
    val adds = @Composable {
        if (canSave(state)) {
            // Each with the focus mark every control of the path has.
            for ((kind, words) in listOf("login" to Placeholder.ITEM_ADD, "note" to Placeholder.ITEM_ADD_NOTE, "card" to Placeholder.ITEM_ADD_CARD)) {
                val (source, mark) = focusMark(UiText.ph(words).shown())
                Button(onClick = guarded(onClick = { onNew(kind) }), modifier = mark, interactionSource = source) { ButtonWords(UiText.ph(words)) }
            }
        }
    }
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        if (maxWidth >= SEARCH_ROW_MIN_WIDTH) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                search(Modifier.weight(1f))
                adds()
            }
        } else {
            Column(Modifier.fillMaxWidth()) {
                search(Modifier.fillMaxWidth())
                Box(Modifier.fillMaxWidth().padding(top = 8.dp)) { Actions { adds() } }
            }
        }
    }
}

/** A filled button's words: a placeholder keeps its brackets and italics in the button's own tone. */
@Composable
private fun ButtonWords(text: UiText) {
    if (text.isPlaceholder) Text(text.shown(), style = MaterialTheme.typography.labelLarge.copy(fontStyle = FontStyle.Italic), color = LocalContentColor.current)
    else Text(text.shown())
}

/** One of the current app's dropdown chips under the search box: what is chosen, and the choices in a menu. */
@Composable
private fun <T> ChoiceChip(chosen: UiText, choices: List<Pair<T, UiText>>, onPick: (T) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box(Modifier.padding(top = 8.dp)) {
        OutlinedButton(onClick = { open = true }) {
            Say(chosen, Modifier.widthIn(max = 200.dp))
            Icon(Icons.Default.ArrowDropDown, null)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            choices.forEach { (value, label) ->
                DropdownMenuItem(text = { Say(label) }, onClick = { open = false; onPick(value) })
            }
        }
    }
}

/** The type filter, as the current app's dropdown chip under the search box. */
@Composable
private fun TypeFilter(type: String?, onPick: (String?) -> Unit) =
    ChoiceChip(UiText.ph(TYPE_FILTERS.first { it.first == type }.second), TYPE_FILTERS.map { (t, label) -> t to UiText.ph(label) }, onPick)

/** The sort, as the current app's chip: by name, or recently updated. */
@Composable
private fun SortChoice(sort: ListSort, onPick: (ListSort) -> Unit) =
    ChoiceChip(UiText.ph(sort.label), ListSort.entries.map { it to UiText.ph(it.choice) }, onPick)

/**
 * The vault filter, as the current app's chip: offered only when there is more than one vault to choose from, its
 * choices the content's own list of vaults (each by the name this device knows it by).
 */
@Composable
private fun VaultFilter(state: ContentState, wanted: String?, onPick: (String?) -> Unit) {
    val vaults = vaultChoices(state)
    if (vaults.size < 2) return
    val chosen = effectiveVaultFilter(state, wanted)
    val all: Pair<String?, UiText> = null to UiText.ph(Placeholder.VAULTS_ALL)
    ChoiceChip(vaults.firstOrNull { it.vaultId == chosen }?.let { UiText.Plain(it.name) } ?: all.second, listOf(all) + vaults.map { it.vaultId to UiText.Plain(it.name) }, onPick)
}

/** The list's order, as the current app's sort chip has it. */
internal enum class ListSort(
    /** What the chip says while this order is chosen: the word "sort" is on the chip, once. */
    val label: Placeholder,
    /** This order's line in the chip's menu, as the current app's menu names it ("Name", "Recently updated"). */
    val choice: Placeholder,
) {
    /** The content's own order (by name). */
    NAME(Placeholder.SORT_NAME, Placeholder.SORT_CHOICE_NAME),

    /**
     * The last change first. The time is the server's bookkeeping ([ItemSummary.updatedAt]), used for this order and
     * for nothing else.
     */
    RECENT(Placeholder.SORT_RECENT, Placeholder.SORT_CHOICE_RECENT),
}

/**
 * Why vaults are closed for writing here ([ContentVault.closedLine]): the filtered vault's line when the list is
 * filtered to one vault, every closed vault's line otherwise. Empty when none is closed.
 */
internal fun closedVaultLines(state: ContentState, wanted: String?): List<String> {
    val inVault = effectiveVaultFilter(state, wanted)
    return state.vaults.filter { inVault == null || it.vaultId == inVault }.mapNotNull { it.closedLine }
}

/** The line of [vaultId] while it is closed for writing; null otherwise. */
internal fun closedLineOf(state: ContentState, vaultId: String?): String? = state.vaults.firstOrNull { it.vaultId == vaultId }?.closedLine

/** The vaults the filter offers: the content's own list. */
internal fun vaultChoices(state: ContentState): List<ContentVault> = state.vaults

/** The filter's vault, or all (null) when it names no vault the content lists now (one left mid-session, say). */
internal fun effectiveVaultFilter(state: ContentState, wanted: String?): String? =
    wanted?.takeIf { w -> state.vaults.any { it.vaultId == w } }

/** The list's rows: the content's (already searched) rows of the type and the vault chosen, in the order chosen. */
internal fun listRows(state: ContentState, type: String?, vault: String?, sort: ListSort): List<ItemSummary> {
    val inVault = effectiveVaultFilter(state, vault)
    val rows = itemsOfType(state.items, type).let { r -> if (inVault == null) r else r.filter { it.vaultId == inVault } }
    return when (sort) {
        ListSort.NAME -> rows
        ListSort.RECENT -> rows.sortedByDescending { it.updatedAt }
    }
}

/** The mark of a row in a shared vault: that vault's name, as the current app's gold tag; null for the personal vault. */
internal fun sharedMark(item: ItemSummary): UiText? = when {
    !item.sharedVault -> null
    item.vaultName.isNullOrBlank() -> UiText.ph(Placeholder.ROW_SHARED_VAULT)
    else -> UiText.Plain(item.vaultName!!)
}

/**
 * The content's error, in the current app's error bar, and its notice: in the notice bar, or in the error bar when it
 * is not a success ([noticeIsWarning]), so "the server did not do it" never reads as done.
 */
@Composable
internal fun ContentSaid(c: VaultContent, state: ContentState) {
    state.error?.let { ErrorBar(UiText.Plain(it)) { c.dismissError() } }
    state.notice?.let {
        if (noticeIsWarning(state.noticeKind)) ErrorBar(UiText.Plain(it)) { c.dismissNotice() }
        else NoticeBar(UiText.Plain(it)) { c.dismissNotice() }
    }
}

/**
 * A notice that is not a success: everything but a done or a queued change. The safer reading for a kind added later,
 * and for what a lock cut short or a save cut short, is the warning; a notice of no kind stays a notice.
 */
internal fun noticeIsWarning(kind: ContentNoticeKind?): Boolean = when (kind) {
    // An item in the trash again (deleted again elsewhere after this device's change) is plain information: it blames
    // nobody, and never reads as a warning about the server.
    null, ContentNoticeKind.DONE, ContentNoticeKind.QUEUED, ContentNoticeKind.IN_TRASH_AGAIN -> false
    else -> true
}

/**
 * "Recently removed" (spec 02 §10.6): vaults this account no longer has, whose copy this computer keeps for a while. A
 * readable one can be copied into the personal vault, behind the check-what-you-copy warning; any can be removed from
 * this computer, behind a confirmation whose way out comes first.
 */
@Composable
private fun RecentlyRemovedSection(c: VaultContent, state: ContentState) {
    if (state.held.isEmpty()) return
    val scope = rememberWorkScope()
    var asking by remember(c) { mutableStateOf<Pair<String, Boolean>?>(null) } // vault id, true = copy, false = remove
    var answer by remember(c) { mutableStateOf<String?>(null) }
    Gap()
    Say(Placeholder.RECENTLY_REMOVED, style = MaterialTheme.typography.titleSmall)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    state.copying?.let { Say(Placeholder.COPYING, it.done.toString(), it.total.toString()) }
    state.held.forEach { h ->
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            Text(vaultSlot(h.name).text, style = MaterialTheme.typography.bodyLarge)
            Say(UiText.Plain(h.line), style = MaterialTheme.typography.bodySmall)
            Say(UiText.ph(Placeholder.HELD_ITEM_COUNT, h.itemCount.toString()), style = MaterialTheme.typography.bodySmall)
            val ask = asking
            if (ask != null && ask.first == h.vaultId) {
                if (ask.second) Say(CopyKey.CHECK_WHAT_YOU_COPY) else Say(Placeholder.HELD_REMOVE_CONFIRM)
                Actions {
                    // The way out comes first.
                    Quieter(UiText.ph(Placeholder.BACK)) { asking = null }
                    if (ask.second) {
                        Quieter(UiText.ph(Placeholder.HELD_COPY_TO_PERSONAL), enabled = canSave(state) && !state.busy) {
                            asking = null
                            scope.launch(h.name) { answer = sentence(c.saveVaultItemsToPersonal(h.vaultId)) }
                        }
                    } else {
                        Quieter(UiText.of(CopyKey.REMOVE_FROM_THIS_DEVICE)) {
                            asking = null
                            answer = sentence(c.removeFromDevice(h.vaultId))
                        }
                    }
                }
            } else {
                Actions {
                    if (h.readable && canSave(state)) Quieter(UiText.ph(Placeholder.HELD_COPY_TO_PERSONAL), enabled = !state.busy) { asking = h.vaultId to true }
                    Quieter(UiText.of(CopyKey.REMOVE_FROM_THIS_DEVICE), enabled = !state.busy) { asking = h.vaultId to false }
                }
            }
        }
    }
}

/**
 * An item's files on its detail: each by name and size, saved on request through the system's Save dialog (a bare safe
 * name, only inside the folder it showed, a file already there replaced only on a second yes). The decrypted bytes
 * live only for the write and are zeroed after.
 */
@Composable
private fun AttachmentsOnDetail(model: TrustModel, c: VaultContent, d: ItemDetail) {
    if (d.attachments.isEmpty()) return
    val scope = rememberWorkScope()
    val overwrite = remember(c, d.itemId) { OverwriteGate() }
    val risky = remember(c, d.itemId) { RiskyTypeGate() }
    var answer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    fun saveTo(a: AttachmentView, dest: File) {
        answer = null
        scope.launch {
            val got = c.readAttachment(d.itemId, a.id)
            val bytes = got.bytes
            answer = if (bytes == null) {
                got.error
            } else {
                val written = withContext(NonCancellable + Dispatchers.IO) {
                    try {
                        writeVerified(dest, bytes)
                    } finally {
                        bytes.fill(0)
                    }
                }
                when {
                    written.keptAs != null -> UiText.ph(Placeholder.FILE_KEPT_ASIDE, written.keptAs).shown()
                    written.result != ExportWrite.SAVED -> UiText.ph(Placeholder.ATTACHMENT_NOT_WRITTEN).shown()
                    else -> null
                }
            }
        }
    }
    RiskyTypeDialog(risky)
    ReplaceFileDialog(overwrite)
    Say(Placeholder.ATTACHMENTS, style = MaterialTheme.typography.labelMedium)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    d.attachments.forEach { a ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            // The name is whoever wrote the item's text: shown as every app shows it (round-10 review 1).
            Text(AttachmentRules.safeFileName(a.name) + "  ·  " + sizeText(a.size), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            Quieter(UiText.ph(Placeholder.ATTACHMENT_SAVE)) {
                when (val pick = FilePicker.save(UiText.ph(Placeholder.ATTACHMENT_SAVE).shown(), a.name)) {
                    FilePicker.SavePick.Cancelled -> {}
                    FilePicker.SavePick.Outside -> answer = SAVE_OUTSIDE_FOLDER
                    // Note N3: a name that ends like a program asks first, naming the type; then a file already there.
                    is FilePicker.SavePick.At -> if (stillOpen(model, c)) risky.request(pick.file) { overwrite.request(pick.file) { saveTo(a, pick.file) } }
                }
            }
        }
    }
}

/**
 * The open editor's files ([ContentState.attachmentDraft]): the kept and the added, each removable, and Add, which reads
 * a file the person picks (its size asked first, the read stopped at the limit, off the UI thread) and hands it to the
 * content (it encrypts and zeroes the bytes). The draft is opened with the editor and closed when the editor goes.
 */
@Composable
private fun AttachmentsInEditor(model: TrustModel, c: VaultContent, state: ContentState, itemId: String?, key: String) {
    val scope = rememberWorkScope()
    var answer by remember(c, key) { mutableStateOf<String?>(null) }
    val fault = LocalFault.current
    DisposableEffect(c, key) {
        Overtaken.read(fault, null, Unit) { c.openAttachmentDraft(itemId) }
        onDispose { Overtaken.read(fault, null, Unit) { c.closeAttachmentDraft() } }
    }
    val draft = state.attachmentDraft ?: return
    Say(Placeholder.ATTACHMENTS, style = MaterialTheme.typography.labelMedium)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    (draft.kept + draft.added).forEach { a ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(AttachmentRules.safeFileName(a.name) + "  ·  " + sizeText(a.size), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
            Quieter(UiText.ph(Placeholder.ATTACHMENT_REMOVE), enabled = !state.busy) { c.removeAttachment(a.id) }
        }
    }
    Say(Placeholder.ATTACHMENT_LIMITS, sizeText(draft.totalBytes), sizeText(draft.limits.perFileBytes), sizeText(draft.limits.perItemBytes), style = MaterialTheme.typography.bodySmall)
    state.upload?.let { Say(Placeholder.ATTACHMENT_UPLOADING, it.done.toString(), it.total.toString()) }
    Quieter(UiText.ph(Placeholder.ATTACHMENT_ADD), enabled = !state.busy && canSave(state)) {
        val file = FilePicker.open(UiText.ph(Placeholder.ATTACHMENT_ADD).shown())
        if (file != null && stillOpen(model, c)) scope.launch { answer = addPicked(c, file) }
    }
}

/**
 * Reads a picked file for the open editor's draft, never more than the draft lets it be (its own limit and what the
 * item still has room for), off the UI thread, and hands it to the content; the sentence to show, or null when added.
 */
internal suspend fun addPicked(c: VaultContent, file: File): String? {
    val d = c.state.attachmentDraft ?: return null
    return when (val picked = withContext(Dispatchers.IO) { PickedFiles.read(file, attachmentRoom(d)) }) {
        is PickedFiles.Picked.Read -> sentence(c.addAttachment(picked.name, picked.bytes))
        is PickedFiles.Picked.TooLarge -> attachmentTooLarge(picked.size, d)
        PickedFiles.Picked.NotRead -> UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()
    }
}

/** The most a picked file is read to for [draft]: the per-file limit, or the room the item has left if that is less. */
internal fun attachmentRoom(draft: AttachmentDraftView): Long =
    minOf(draft.limits.perFileBytes, draft.limits.perItemBytes - draft.totalBytes).coerceAtLeast(0)

/** The content's own sentence for a file of [size] bytes the draft cannot take. */
internal fun attachmentTooLarge(size: Long, draft: AttachmentDraftView): String =
    AttachmentRules.refusal(size, draft.totalBytes, draft.limits) ?: UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()

/**
 * Whether [d] can be moved out of its vault, not only copied: never an item that may only be viewed, and only where
 * the content allows it ([VaultContent.canMoveOut]).
 */
internal fun canMoveItem(c: VaultContent, d: ItemDetail): Boolean = d.editable && c.canMoveOut(d.itemId)

/** The button that opens the choice: "move or copy" where a move is possible, otherwise only "copy to another vault". */
internal fun moveOrCopyLabel(canMove: Boolean): Placeholder = if (canMove) Placeholder.MOVE_OR_COPY else Placeholder.COPY_TO_ANOTHER_VAULT

/**
 * Move or copy one item into another vault ([VaultContent.moveTargets]); move only where [canMoveItem] allows it, and
 * an item that may only be viewed is offered the copy alone, in its button too. Back cancels, so an unfinished try is
 * not kept.
 */
@Composable
private fun MoveOrCopy(c: VaultContent, state: ContentState, d: ItemDetail, onMoved: () -> Unit) {
    val scope = rememberWorkScope()
    var open by remember(c, d.itemId) { mutableStateOf(false) }
    var answer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    val vault = vaultNamed(state, d.vaultId)
    val canMove = guardedRead(vault, false) { canMoveItem(c, d) }
    if (!open) {
        if (canSave(state)) Quieter(UiText.ph(moveOrCopyLabel(canMove))) { open = true }
        return
    }
    val targets = guardedRead(vault, emptyList()) { c.moveTargets(d.itemId) }
    Quieter(UiText.ph(Placeholder.BACK)) { c.cancelMove(d.itemId); open = false; answer = null }
    if (targets.isEmpty()) Say(Placeholder.MOVE_NO_TARGETS)
    targets.forEach { t ->
        Text(t.name, style = MaterialTheme.typography.bodyLarge)
        if (!t.personal) Say(Placeholder.ITEM_SHARED_VAULT_SEES)
        Actions {
            Quieter(UiText.ph(Placeholder.COPY_TO_VAULT), enabled = !state.busy) {
                scope.launch(vault) {
                    val r = c.moveOrCopyItem(d.itemId, t.vaultId, move = false)
                    answer = sentence(r)
                    if (r is ActionResult.Ok) open = false
                }
            }
            if (canMove) {
                Quieter(UiText.ph(Placeholder.MOVE_TO_VAULT), enabled = !state.busy) {
                    scope.launch(vault) {
                        val r = c.moveOrCopyItem(d.itemId, t.vaultId, move = true)
                        answer = sentence(r)
                        if (r is ActionResult.Ok) onMoved()
                    }
                }
            }
        }
    }
}

/** An item's earlier versions, newest first, while the content has them open ([ContentState.history]). */
@Composable
private fun HistoryView(model: TrustModel, c: VaultContent, state: ContentState, h: ItemHistoryView) {
    val scope = rememberWorkScope()
    var answer by remember(c, h.itemId) { mutableStateOf<String?>(null) }
    val shown = remember(c, h.itemId) { mutableStateMapOf<Long, String>() }
    PageHeader(UiText.ph(Placeholder.HISTORY)) { c.closeItemHistory() }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    if (h.versions.isEmpty()) Say(Placeholder.VAULT_EMPTY)
    h.versions.forEach { v ->
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            Text(v.name, style = MaterialTheme.typography.bodyLarge)
            Text(listOfNotNull(v.detail, java.text.DateFormat.getDateTimeInstance().format(java.util.Date(v.archivedAtMs))).joinToString(" · "), style = MaterialTheme.typography.bodySmall)
            shown[v.rev]?.let { Text(it, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)) }
            Actions {
                if (v.hasPassword) {
                    if (shown[v.rev] == null) {
                        Quieter(UiText.ph(Placeholder.ITEM_REVEAL)) { c.historyPassword(h.itemId, v.rev)?.let { shown[v.rev] = it } }
                    } else {
                        Quieter(UiText.ph(Placeholder.ITEM_HIDE)) { shown.remove(v.rev) }
                    }
                    Quieter(UiText.ph(Placeholder.ITEM_COPY)) {
                        c.historyPassword(h.itemId, v.rev)?.let {
                            answer = if (copyWithAutoClear(it, clipboardSeconds(model))) null else CLIPBOARD_COPY_FAILED
                        }
                    }
                }
                if (h.canRestore) {
                    Quieter(UiText.ph(Placeholder.TRASH_RESTORE), enabled = canSave(state) && !state.busy) {
                        scope.launch { answer = sentence(c.restoreItemVersion(h.itemId, v.rev)) }
                    }
                }
            }
        }
    }
}

/** The words for a kind of item ([ItemSummary.type]), as the current app's tag at a row's right. */
internal fun kindWord(type: String): Placeholder = when (type) {
    "login" -> Placeholder.KIND_LOGIN
    "card" -> Placeholder.KIND_CARD
    else -> Placeholder.KIND_NOTE
}

/**
 * A row's second line, as the current app's: a login's user name (or, without one, its site), a note's "secure note".
 * A card's brand and last four digits are not in the row the shared code gives ([ItemSummary]), so a card has none yet.
 */
internal fun rowSecondLine(item: ItemSummary): UiText? = when (item.type) {
    "login" -> (item.username?.takeIf { it.isNotBlank() } ?: item.host)?.let { UiText.Plain(it) }
    "note" -> UiText.ph(Placeholder.ROW_NOTE)
    // The shared code's card words, as an item's view says them (CardDisplay.subtitle): "Visa ••4242", "Card ••9123"
    // for a brand it does not know, "card" for a card with no number.
    "card" -> UiText.Plain(item.cardLastFour?.let { "${item.cardBrand ?: "Card"} ${CardDisplay.maskedLast4(it)}" } ?: "card")
    else -> null
}

/**
 * A login's health, as the current phone app's line under a login's name (the current desktop app has none): its
 * strength, in the error tone when it is weak; how many other logins have the same password and the breaches it was
 * seen in, both in the error tone; when it was last used. The values are the shared code's ([VaultContent.itemHealth]),
 * the ones the Health page shows; nothing is checked or sent for them. A login without a password has no line.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun HealthLine(h: ItemHealthLine) {
    val quiet = MaterialTheme.colorScheme.onSurfaceVariant
    val warn = MaterialTheme.colorScheme.error
    val small = MaterialTheme.typography.bodySmall
    FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Say(UiText.ph(Placeholder.HEALTH_STRENGTH, h.strength), style = small, color = if (h.weak) warn else quiet)
        if (h.reused > 0) Say(reusedLine(h.reused), style = small, color = warn)
        h.breaches?.takeIf { it > 0 }?.let { Say(UiText.ph(Placeholder.HEALTH_BREACHED, it.toString()), style = small, color = warn) }
        h.lastUsedAt?.let { Say(UiText.ph(Placeholder.HEALTH_LAST_USED, healthDay(it)), style = small, color = quiet) }
    }
}

/** A day as the health line names it: the date, in this computer's medium form. */
internal fun healthDay(ms: Long): String = java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(ms))

/**
 * An item in the list, as the current app's: a card with the name's first letter in the brand colour, the name and its
 * second line, a login's health line under them ([HealthLine]), "not on the server yet" while it waits, and the kind at
 * the right.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ItemRow(item: ItemSummary, shared: UiText?, health: ItemHealthLine?, onClick: () -> Unit) {
    Card(onClick = guarded(onClick = onClick), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text((item.name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif, modifier = Modifier.padding(end = 12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                rowSecondLine(item)?.let { Say(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                if (item.type == "login") health?.let { HealthLine(it) }
            }
            if (item.pendingSync) Say(UiText.ph(Placeholder.ITEM_WAITING), Modifier.padding(end = 8.dp), MaterialTheme.typography.labelSmall)
            // A shared vault's name in the brand gold, as the current app's tag, capped so the name keeps its room.
            shared?.let {
                if (it.isPlaceholder) Say(it, Modifier.widthIn(max = 140.dp).padding(end = 8.dp), MaterialTheme.typography.labelSmall)
                else Text(it.shown(), Modifier.widthIn(max = 140.dp).padding(end = 8.dp), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Say(UiText.ph(kindWord(item.type)), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * An item's view, as the current app's: "back" with its arrow, the name as a large heading, the kind (a card's summary)
 * and its vault, then a row per field (its label above; the value; the eye and Copy at the right), the files, the
 * earlier versions and move or copy, then Edit beside Delete, and Delete asks in a dialog.
 */
@Composable
private fun ItemDetailView(model: TrustModel, c: VaultContent, state: ContentState, d: ItemDetail, onEdit: () -> Unit, onBack: () -> Unit) {
    // What was revealed lives only while this detail is on show.
    val shown = remember(c, d.itemId) { mutableStateMapOf<SecretField, String>() }
    var copyFailed by remember(c, d.itemId) { mutableStateOf(false) }
    fun copy(value: String) {
        copyFailed = !copyWithAutoClear(value, clipboardSeconds(model))
    }

    TextButton(onClick = guarded(onClick = onBack)) {
        Icon(Icons.AutoMirrored.Filled.ArrowBack, null)
        Say(UiText.ph(Placeholder.BACK), Modifier.padding(start = 4.dp))
    }
    Text(d.name, style = MaterialTheme.typography.headlineMedium)
    // The kind, or a card's own summary (its brand and last four), as the current app's line under the name.
    // An item that may only be viewed says so beside it, as the current app's " · view only" (and offers no Edit, below).
    Row(verticalAlignment = Alignment.CenterVertically) {
        Say(d.card?.summary?.let { UiText.Plain(it) } ?: UiText.ph(kindWord(d.type)), color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (!d.editable) Say(UiText.ph(Placeholder.VIEW_ONLY), Modifier.padding(start = 8.dp))
    }
    guardedRead(vaultNamed(state, d.vaultId), null) { c.vaultName(d.vaultId) }?.let {
        Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 2.dp))
    }
    // Its vault is closed for writing here: why, beside the vault's name.
    closedLineOf(state, d.vaultId)?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    // A login's health under its kind, as the current phone app's item view has it.
    if (d.type == "login") {
        guardedRead(vaultNamed(state, d.vaultId), null) { c.itemHealth()[d.itemId] }?.let { h ->
            Gap(8)
            HealthLine(h)
        }
    }
    if (copyFailed) Say(UiText.Plain(CLIPBOARD_COPY_FAILED), color = MaterialTheme.colorScheme.error)
    Gap(16)
    d.username?.let { u -> ValueRow(UiText.ph(Placeholder.ITEM_USERNAME), u, mono = true) { copy(u) } }
    if (d.hasPassword) SecretRow(Placeholder.ITEM_PASSWORD, SecretField.PASSWORD, c, d, shown, ::copy)
    if (d.hasTotp) OneTimeCodeRow(c, d.itemId, ::copy)
    d.uris.forEach { ValueRow(UiText.ph(Placeholder.ITEM_ADDRESS), it, mono = false, copy = null) }
    d.card?.let { card ->
        card.cardholder?.let { h -> ValueRow(UiText.ph(Placeholder.ITEM_CARDHOLDER), h, mono = false) { copy(h) } }
        if (card.hasNumber) SecretRow(Placeholder.ITEM_CARD_NUMBER, SecretField.CARD_NUMBER, c, d, shown, ::copy)
        val expiry = guardedRead(vaultNamed(state, d.vaultId), null) { c.cardExpiry(d.itemId) }
        if (expiry != null) ExpiryRow(expiry, ::copy) else card.expiry?.let { ValueRow(UiText.ph(Placeholder.ITEM_EXPIRY), it, mono = true, copy = null) }
        if (card.hasCode) SecretRow(Placeholder.ITEM_CARD_CODE, SecretField.CARD_CODE, c, d, shown, ::copy)
    }
    if (d.hasNotes) SecretRow(Placeholder.ITEM_NOTES, SecretField.NOTES, c, d, shown, ::copy)
    AttachmentsOnDetail(model, c, d)
    Gap(16)
    val scope = rememberWorkScope()
    var historyAnswer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    Quieter(UiText.ph(Placeholder.HISTORY), enabled = !state.busy) { scope.launch { historyAnswer = sentence(c.openItemHistory(d.itemId)) } }
    historyAnswer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    MoveOrCopy(c, state, d, onBack)
    Gap(24)
    val canEdit = canDelete(d, state) && d.type in EDITOR_KINDS
    if (canEdit || canDelete(d, state)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            if (canEdit) Button(onClick = guarded(onClick = onEdit), modifier = Modifier.weight(1f)) { ButtonWords(UiText.ph(Placeholder.ITEM_EDIT_BUTTON)) }
            else Spacer(Modifier.weight(1f))
            if (canDelete(d, state)) {
                Spacer(Modifier.width(12.dp))
                DeleteItem(c, state, d, onBack)
            }
        }
    }
}

/**
 * Delete, as the current app's: an outlined button in the error tone that asks in a dialog. In the dialog the way out
 * comes first (Keep, then Delete), and Escape or a click outside keeps the item.
 */
@Composable
private fun DeleteItem(c: VaultContent, state: ContentState, d: ItemDetail, onGone: () -> Unit) {
    val scope = rememberWorkScope()
    var asking by remember(c, d.itemId) { mutableStateOf(false) }
    var answer by remember(c, d.itemId) { mutableStateOf<String?>(null) }
    Column {
        OutlinedButton(onClick = { asking = true }, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Say(UiText.ph(Placeholder.ITEM_DELETE)) }
        answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    }
    if (!asking) return
    AlertDialog(
        onDismissRequest = { asking = false },
        title = { Say(UiText.ph(Placeholder.ITEM_DELETE_TITLE), style = MaterialTheme.typography.titleLarge) },
        text = { Say(Placeholder.ITEM_DELETE_CONFIRM) },
        // The way out comes first.
        dismissButton = { TextButton(onClick = { asking = false }) { Say(UiText.ph(Placeholder.ITEM_KEEP)) } },
        confirmButton = {
            TextButton(enabled = !state.busy, onClick = guarded(onClick = {
                asking = false
                scope.launch(vaultNamed(state, d.vaultId)) {
                    val r = c.deleteItem(d.itemId)
                    if (r is ActionResult.Ok) onGone() else answer = sentence(r)
                }
            })) { Say(UiText.ph(Placeholder.ITEM_DELETE)) }
        },
    )
}

/**
 * A card's expiry, as the current app's row: its label above; the expiry; "expired" beside it in the error tone when its
 * month is over; and Copy at the right, which copies the short form a checkout's combined box takes ("07/31"), through
 * the clipboard that clears itself. Without a short form (a half is missing) the row is read only.
 */
@Composable
internal fun ExpiryRow(e: CardExpiryView, copy: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Say(UiText.ph(Placeholder.ITEM_EXPIRY), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(e.label, fontFamily = FontFamily.Monospace)
            if (e.expired) {
                Spacer(Modifier.width(8.dp))
                Say(UiText.ph(Placeholder.ITEM_EXPIRED), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
            }
            Spacer(Modifier.weight(1f))
            e.shortExpiry?.let { short -> TextButton(onClick = guarded(onClick = { copy(short) })) { Say(UiText.ph(Placeholder.ITEM_COPY)) } }
        }
    }
}

/** A field of an item's view, as the current app's row: its label above, the value, and Copy at the right. */
@Composable
private fun ValueRow(label: UiText, value: String, mono: Boolean, copy: (() -> Unit)?) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Say(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(value, Modifier.weight(1f), fontFamily = if (mono) FontFamily.Monospace else null)
            copy?.let { TextButton(onClick = guarded(onClick = it)) { Say(UiText.ph(Placeholder.ITEM_COPY)) } }
        }
    }
}

/**
 * A secret field of an item's view: hidden until its eye shows it (read afresh, kept only while this view is on show),
 * and Copy, which reads the value afresh and keeps nothing on screen.
 */
@Composable
private fun SecretRow(
    label: Placeholder,
    field: SecretField,
    c: VaultContent,
    d: ItemDetail,
    shown: MutableMap<SecretField, String>,
    copy: (String) -> Unit,
) {
    val value = shown[field]
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Say(UiText.ph(label), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(value ?: "••••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            IconButton(onClick = guarded(onClick = {
                if (value == null) c.revealSecret(d.itemId, field)?.let { shown[field] = it } else shown.remove(field)
            })) {
                Icon(
                    if (value == null) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                    eyeButtonName(shown = value != null, UiText.ph(label)).shown(),
                )
            }
            TextButton(onClick = guarded(onClick = { c.revealSecret(d.itemId, field)?.let(copy) })) { Say(UiText.ph(Placeholder.ITEM_COPY)) }
        }
    }
}

@Composable
private fun OneTimeCodeRow(c: VaultContent, itemId: String, copy: (String) -> Unit) {
    val fault = LocalFault.current
    var code by remember(c, itemId) { mutableStateOf<OneTimeCode?>(Overtaken.read(fault, null, null) { c.oneTimeCode(itemId) }) }
    // The code is read again each second while the item is on show; a lock overtaking a read ends the loop (the screen
    // goes with the lock), never as a crash. A read the shared code makes throw ends it too, said as a fault.
    val overtook = LocalLockOvertook.current
    LaunchedEffect(c, itemId) {
        try {
            Overtaken.orLocked(overtook) {
                while (true) {
                    code = c.oneTimeCode(itemId)
                    delay(1000)
                }
            }
        } catch (t: Throwable) {
            Overtaken.handle(t, overtook, fault, null)
        }
    }
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Say(UiText.ph(Placeholder.ITEM_CODE), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        // A stored key that does not make a code says so, with the repair, instead of showing nothing (ux-error--6).
        if (code == null) Text(TOTP_URI_UNREADABLE, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        code?.let { otp ->
            // As the current app's: the code large in the brand colour, in two groups, with its seconds beside it.
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    otp.code.chunked(3).joinToString(" "),
                    style = MaterialTheme.typography.headlineSmall.copy(fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold),
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(start = 12.dp, end = 12.dp),
                )
                Text("${otp.secondsRemaining}s", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TextButton(onClick = guarded(onClick = { c.oneTimeCode(itemId)?.let { copy(it.code) } })) { Say(UiText.ph(Placeholder.ITEM_COPY)) }
            }
        }
    }
}

/**
 * Adds or edits a login, a card or a note. An edit is bound to the vault the editor opened on (the content refuses an
 * item that changed vaults meanwhile); a new item goes to the vault picked here, the personal vault first.
 */
@Composable
private fun ItemEditor(model: TrustModel, c: VaultContent, state: ContentState, e: Editing, d: ItemDetail?, onDone: () -> Unit) {
    val scope = rememberWorkScope()
    val kind = e.kind
    val key = kind + ":" + (e.itemId ?: "")
    val fault = LocalFault.current
    // Reads the shared code makes throw leave the field empty and are said, naming the item's vault.
    fun secret(f: SecretField, has: Boolean) =
        d?.takeIf { has }?.let { Overtaken.read(fault, vaultNamed(state, it.vaultId), null) { c.revealSecret(it.itemId, f) } } ?: ""
    // What is typed is the window's own ([Editing.draft]), filled once from the item: a content the shared code composes
    // again under the editor (its removal of this computer's copy for the server's policy) keeps it, and the editor goes
    // on over the new content. An edit whose item could not be read when it opened has nothing to fill it with: closed.
    val draft = e.draft ?: if (e.itemId != null && d == null) null else EditorDraft(
        name = d?.name ?: "", username = d?.username ?: "",
        password = if (e.generate) c.generatePassword(GeneratorSettings.standard) else secret(SecretField.PASSWORD, d?.hasPassword == true),
        passwordShown = e.generate, uri = d?.uris?.firstOrNull() ?: "", moreUris = d?.uris?.drop(1) ?: emptyList(),
        notes = secret(SecretField.NOTES, d?.hasNotes == true), totp = secret(SecretField.TOTP_SECRET, d?.hasTotp == true),
        holder = d?.card?.cardholder ?: "", number = secret(SecretField.CARD_NUMBER, d?.card?.hasNumber == true),
        expMonth = d?.card?.expMonth ?: "", expYear = d?.card?.expYear ?: "", code = secret(SecretField.CARD_CODE, d?.card?.hasCode == true),
        postal = d?.card?.postalCode ?: "", vaultId = d?.vaultId, favorite = d?.favorite ?: false,
    ).also { e.draft = it }
    if (draft == null) {
        LaunchedEffect(e) { onDone() }
        return
    }
    val shown = LocalEditorShown.current
    androidx.compose.runtime.SideEffect { shown(draft) }
    val editedVault = if (e.itemId != null) vaultNamed(state, draft.vaultId) else null
    var name by draft::name
    var username by draft::username
    var password by draft::password
    // Generate shows what will be saved; otherwise the password stays masked until its own toggle.
    val passwordShown = draft.passwordShown
    var uri by draft::uri
    var notes by draft::notes
    var totp by draft::totp
    var holder by draft::holder
    var number by draft::number
    var expMonth by draft::expMonth
    var expYear by draft::expYear
    var code by draft::code
    var postal by draft::postal
    // Read again over each content: empty while this computer's copy is being removed for the server's policy.
    val choices = remember(c, key) { if (e.itemId == null) Overtaken.read(fault, null, emptyList()) { c.vaultsForNewItems() } else emptyList() }
    // An edit stays bound to its item's vault; a new item goes to the vault picked, while it is offered, else the first.
    val vaultId = if (e.itemId != null) draft.vaultId else draft.vaultId?.takeIf { id -> choices.any { it.vaultId == id } }
        ?: choices.firstOrNull { it.personal }?.vaultId ?: choices.firstOrNull()?.vaultId
    var answer by remember(key) { mutableStateOf<String?>(null) }

    // As the current app's: "cancel" asks before anything typed is dropped (the way out of the question, keep editing,
    // comes first), then the kind as a large heading and, for a new item with a choice to make, the vault under it.
    var discard by remember(key) { mutableStateOf(false) }
    TextButton(onClick = { discard = true }, enabled = !state.busy) { Say(UiText.ph(Placeholder.EDITOR_CANCEL)) }
    if (discard) {
        AlertDialog(
            onDismissRequest = { discard = false },
            title = { Say(UiText.ph(Placeholder.EDITOR_DISCARD_TITLE), style = MaterialTheme.typography.titleLarge) },
            text = { Say(Placeholder.EDITOR_DISCARD_BODY) },
            dismissButton = { TextButton(onClick = { discard = false }) { Say(UiText.ph(Placeholder.EDITOR_KEEP_EDITING)) } },
            confirmButton = { TextButton(onClick = { discard = false; onDone() }) { Say(UiText.ph(Placeholder.EDITOR_DISCARD)) } },
        )
    }
    Say(UiText.ph(if (e.itemId == null) Placeholder.ITEM_NEW else Placeholder.ITEM_EDIT, kind), style = MaterialTheme.typography.headlineMedium)
    // While the copy is being removed no vault is offered for a new item: the removal's line, and Save stays offered (the
    // shared code refuses it with the same line); what was typed stays.
    if (e.itemId == null && choices.isEmpty()) state.removingLine?.let { Say(UiText.Plain(it)) }
    if (e.itemId == null && choices.size > 1) {
        VaultChoice(choices, vaultId) { draft.vaultId = it }
        // Everyone in a shared vault sees what is put there.
        choices.firstOrNull { it.vaultId == vaultId && !it.personal }?.let { Say(Placeholder.ITEM_SHARED_VAULT_SEES) }
    }
    Field(UiText.ph(Placeholder.ITEM_NAME), name) { name = it }
    when (kind) {
        "login" -> {
            Field(UiText.ph(Placeholder.ITEM_USERNAME), username, mono = true) { username = it }
            SecretField(UiText.ph(Placeholder.ITEM_PASSWORD), password, revealed = passwordShown) { password = it }
            TextButton(onClick = guarded(onClick = {
                password = c.generatePassword(GeneratorSettings.standard)
                passwordShown.value = true
            })) {
                Icon(Icons.Default.Refresh, null)
                Say(UiText.ph(Placeholder.ITEM_GENERATE), Modifier.padding(start = 4.dp))
            }
            Field(UiText.ph(Placeholder.ITEM_ADDRESS), uri, mono = true) { uri = it }
            SecretField(UiText.ph(Placeholder.ITEM_TOTP), totp) { totp = it }
        }
        "card" -> {
            Field(UiText.ph(Placeholder.ITEM_CARDHOLDER), holder) { holder = it }
            // As the current app's label: the brand beside "card number" while the number is typed, once it is known.
            val brand = guardedRead(editedVault, null) { c.cardBrandOf(number) }
            SecretField(cardNumberLabel(brand), number) { number = it }
            // In a slot of a fixed height: the warning comes and goes while the number is typed, and must not move the
            // fields under it (the card's code is one).
            FixedSlot(CARD_WARNING_SLOT) {
                guardedRead(editedVault, null) { c.cardNumberWarning(number) }?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
            }
            // Month and year side by side, as the current app's.
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Field(UiText.ph(Placeholder.ITEM_EXP_MONTH), expMonth, modifier = Modifier.weight(1f)) { expMonth = it }
                Field(UiText.ph(Placeholder.ITEM_EXP_YEAR), expYear, modifier = Modifier.weight(1f)) { expYear = it }
            }
            SecretField(UiText.ph(Placeholder.ITEM_CARD_CODE), code) { code = it }
            Field(UiText.ph(Placeholder.ITEM_POSTAL_CODE), postal) { postal = it }
        }
    }
    // Notes take more than one line: Enter is a new line here (the first run found a one-line field that dropped it).
    Field(UiText.ph(Placeholder.ITEM_NOTES), notes, lines = NOTES_LINES) { notes = it }
    AttachmentsInEditor(model, c, state, e.itemId, key)
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    Main(UiText.ph(Placeholder.ITEM_SAVE), enabled = canSave(state) && !state.busy && name.isNotBlank(), busy = state.busy) {
        val fav = draft.favorite
        scope.launch(vaultNamed(state, vaultId)) {
            val r = when (kind) {
                // Only the first web address is editable here; the others the login has are kept as they are.
                "login" -> c.saveLogin(e.itemId, LoginInput(name, username, password, listOf(uri) + draft.moreUris, notes, totp, fav), vaultId)
                "card" -> c.saveCard(e.itemId, CardInput(name, holder, number, expMonth, expYear, code, postal, notes, fav), vaultId)
                else -> c.saveNote(e.itemId, NoteInput(name, notes, fav), vaultId)
            }
            if (r is ActionResult.Ok) onDone() else answer = sentence(r)
        }
    }
}

/** The card number's label in the editor: with the brand beside it once the shared code knows it ([VaultContent.cardBrandOf]). */
internal fun cardNumberLabel(brand: String?): UiText =
    if (brand == null) UiText.ph(Placeholder.ITEM_CARD_NUMBER) else UiText.ph(Placeholder.ITEM_CARD_NUMBER_BRAND, brand)

/** The vault a new item goes to, as the current app's dropdown under the editor's heading. */
@Composable
private fun VaultChoice(choices: List<io.silencelen.andvari.core.app.VaultChoiceView>, selected: String?, onPick: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    Say(UiText.ph(Placeholder.ITEM_VAULT), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Box {
        OutlinedButton(onClick = { open = true }) {
            Text(choices.firstOrNull { it.vaultId == selected }?.name ?: "")
            Icon(Icons.Default.ArrowDropDown, null)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            choices.forEach { v -> DropdownMenuItem(text = { Text(v.name) }, onClick = { open = false; onPick(v.vaultId) }) }
        }
    }
}

/**
 * A trash row's name: the item's own; for a row this device has not read yet ([TrashItemView.notReadYet]) a line that
 * says so (its Restore still stands: it reads the item first); for one no version of which could be read, the plain
 * words that say so, never a dash.
 */
internal fun trashRowName(t: TrashItemView): UiText = when {
    t.name != null -> UiText.Plain(t.name!!)
    t.notReadYet -> UiText.ph(Placeholder.TRASH_NOT_READ)
    else -> UiText.ph(Placeholder.TRASH_NAME_UNREADABLE)
}

/**
 * The trash, while the content has it open ([ContentState.trash]): the content's own explanation, each deleted item
 * with restore and delete forever where the content allows them, the latter behind a confirmation.
 */
@Composable
private fun TrashView(c: VaultContent, state: ContentState, rows: List<TrashItemView>) {
    val scope = rememberWorkScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    var purging by remember(c) { mutableStateOf<String?>(null) }
    PageHeader(UiText.ph(Placeholder.TRASH)) { c.closeTrash() }
    Say(UiText.Plain(TRASH_EXPLANATION))
    answer?.let { ErrorBar(UiText.Plain(it)) { answer = null } }
    // A restore or a delete for good the server answered as done and did not perform is said here, where the next
    // read of the trash finds it, as a warning (NOT_DONE_ON_SERVER), never as a success.
    ContentSaid(c, state)
    if (rows.isEmpty()) Say(Placeholder.VAULT_EMPTY)
    rows.forEach { t ->
        Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            trashRowName(t).let { if (it.isPlaceholder) Say(it, style = MaterialTheme.typography.bodyLarge) else Text(it.shown(), style = MaterialTheme.typography.bodyLarge) }
            listOfNotNull(t.detail, t.vault).takeIf { it.isNotEmpty() }?.let { Text(it.joinToString(" · "), style = MaterialTheme.typography.bodySmall) }
            Actions {
                val canWrite = canSave(state) && !state.busy
                if (t.canRestore) Quieter(UiText.ph(Placeholder.TRASH_RESTORE), enabled = canWrite) { scope.launch { answer = sentence(c.restoreFromTrash(t.itemId)) } }
                if (t.canPurge) {
                    if (purging == t.itemId) {
                        Quieter(UiText.ph(Placeholder.BACK)) { purging = null }
                        Quieter(UiText.ph(Placeholder.TRASH_PURGE_CONFIRM), enabled = canWrite) {
                            purging = null
                            scope.launch { answer = sentence(c.purgeFromTrash(t.itemId)) }
                        }
                    } else {
                        Quieter(UiText.ph(Placeholder.TRASH_PURGE), enabled = canWrite) { purging = t.itemId }
                    }
                }
            }
        }
    }
}
