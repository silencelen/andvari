package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Favorite
import androidx.compose.material.icons.filled.FileUpload
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.EmptySigil
import io.silencelen.andvari.app.SigilMark
import io.silencelen.andvari.app.launchOvertakable
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.ContentVault
import androidx.compose.material3.TextButton
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.content.VaultContent

/*
 * The vault's screens in the current app's structure (the 0.30.0 Android app is the reference since 2026-11-16): a top
 * bar on every page, the vault's list as a lazy list of cards under a search field, a floating Add button with its
 * choices, and the other actions in the top bar and its menu. What the screens do and say is the new app's: every
 * label the content does not carry is still a placeholder.
 */

/** The top bar of a page reached from the vault: the way back (the mirrored back arrow) and the page's title. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun PageTopBar(title: UiText, onBack: () -> Unit) {
    TopAppBar(
        // One line, as the current app's titles are: a long title in two lines ran under the bar at the largest font.
        title = { Text(title.shown(), style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        navigationIcon = {
            IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, UiText.ph(Placeholder.BACK_TO_VAULT).shown()) }
        },
        windowInsets = WindowInsets(0),
    )
}

/** A page with a top bar and a scrolling body, as Sharing and Settings are in the current app. */
@Composable
internal fun PageScaffold(title: UiText, onBack: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Scaffold(topBar = { PageTopBar(title, onBack) }, contentWindowInsets = WindowInsets(0)) { pad ->
        Box(Modifier.padding(pad).fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = PAGE_MAX_WIDTH).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), content = content)
        }
    }
}

internal val PAGE_MAX_WIDTH = 760.dp

/**
 * What the vault's top bar offers, exactly as the current app's does: import, health, sharing, the trash, settings, and
 * no menu. The backups are in Settings and the recently deleted shared vaults in Sharing, where the current app has them.
 */
internal class VaultBarActions(
    val importCsv: (() -> Unit)?,
    val health: () -> Unit,
    val sharing: () -> Unit,
    val trash: () -> Unit,
    val settings: () -> Unit,
    val enabled: Boolean,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun VaultTopBar(a: VaultBarActions, working: Boolean) {
    Column {
        TopAppBar(
            // One line: at the largest font the five icons leave the name little room, and a name broken into
            // two lines pushed the bar's text off its edge.
            title = { Text("andvari", style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            actions = {
                a.importCsv?.let { IconButton(onClick = it, enabled = a.enabled) { Icon(Icons.Default.FileUpload, UiText.ph(Placeholder.IMPORT_CSV).shown()) } }
                IconButton(onClick = a.health, enabled = a.enabled) { Icon(Icons.Default.Favorite, UiText.ph(Placeholder.HEALTH).shown()) }
                IconButton(onClick = a.sharing) { Icon(Icons.Default.Group, UiText.ph(Placeholder.SHARING).shown()) }
                IconButton(onClick = a.trash, enabled = a.enabled) { Icon(Icons.Default.Delete, UiText.ph(Placeholder.TRASH).shown()) }
                IconButton(onClick = a.settings) { Icon(Icons.Default.Settings, UiText.ph(Placeholder.SETTINGS).shown()) }
            },
            windowInsets = WindowInsets(0),
        )
        // One thin line under the bar while something runs, as the current app shows a sync.
        if (working) LinearProgressIndicator(Modifier.fillMaxWidth())
    }
}

/** The floating Add button with its choices (a login, a card, a note), as the current app's. */
@Composable
internal fun AddButton(kinds: List<String>, onNew: (String) -> Unit) {
    var menu by remember { mutableStateOf(false) }
    Box {
        ExtendedFloatingActionButton(
            onClick = { menu = true },
            text = { Say(UiText.ph(Placeholder.ITEM_ADD)) },
            icon = { Icon(Icons.Default.Add, null) },
        )
        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
            kinds.forEach { kind ->
                DropdownMenuItem(text = { Say(kindWords(kind)) }, onClick = { menu = false; onNew(kind) })
            }
        }
    }
}

/** An item's kind in words: a login, a card, a secure note. */
internal fun kindWords(type: String): UiText = when (type) {
    "login" -> UiText.ph(Placeholder.KIND_LOGIN)
    "card" -> UiText.ph(Placeholder.KIND_CARD)
    "note" -> UiText.ph(Placeholder.KIND_NOTE)
    else -> UiText.ph(Placeholder.KIND_OTHER)
}

/**
 * The vault's list: a lazy list whose first rows are what the page must say above it (the account's lines, the
 * content's notices, the sync line) and the search field, then one card per item, then what waits below the list.
 * Pulled down, it syncs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun VaultList(
    c: VaultContent,
    state: ContentState,
    controls: ListControls,
    onControls: (ListControls) -> Unit,
    header: @Composable () -> Unit,
    footer: @Composable () -> Unit,
    onOpen: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val shown = remember(state.items, state.vaults, controls) { listView(state.items, controls, state.vaults) }
    PullToRefreshBox(isRefreshing = state.busy, onRefresh = { scope.launchOvertakable { c.refresh() } }) {
        LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp)) {
            item(key = "header") {
                Column {
                    header()
                    OutlinedTextField(
                        state.query, { c.setQuery(it) }, Modifier.fillMaxWidth(),
                        label = { Text(UiText.ph(Placeholder.VAULT_SEARCH).shown()) },
                        singleLine = true,
                        leadingIcon = { Icon(Icons.Default.Search, null) },
                    )
                    ListControlsRow(state, controls, onControls)
                    // Filtered to a vault closed for writing: why, above its items (the rows keep what they show).
                    closedFilterLine(controls, state.vaults)?.let { Quiet(UiText.Plain(it)) }
                    Spacer(Modifier.height(8.dp))
                }
            }
            if (shown.isEmpty()) {
                item(key = "empty") {
                    Column(Modifier.fillMaxWidth().padding(top = 60.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        SigilMark(EmptySigil, 40.dp)
                        Spacer(Modifier.height(8.dp))
                        // As the current app: an empty vault, or a search that found nothing, each said as what it is.
                        Say(UiText.ph(emptyListWords(state, controls)), color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            } else {
                items(shown, key = { it.itemId }) { item ->
                    ItemCard(item) { onOpen(item.itemId) }
                    Spacer(Modifier.height(8.dp))
                }
            }
            // Room under the last card for the floating button.
            item(key = "footer") { Column(Modifier.padding(bottom = 72.dp)) { footer() } }
        }
    }
}

/** What an empty list says: nothing matches a search or a filter, or the vault holds nothing yet. */
internal fun emptyListWords(state: ContentState, controls: ListControls = ListControls()): Placeholder =
    if (state.query.isNotBlank() || (state.items.isNotEmpty() && controls.filtering)) Placeholder.VAULT_NO_MATCH else Placeholder.VAULT_EMPTY

/**
 * The list's sort and filters, as the current app's row of three under the search field: by name (the content's own
 * order) or by the last change, every type or one, every vault or one. [ALL] is every type or every vault. Fresh at each
 * unlock, as in the current app.
 */
internal data class ListControls(val recent: Boolean = false, val type: String = ALL, val vaultId: String = ALL) {
    val filtering: Boolean get() = type != ALL || vaultId != ALL

    companion object {
        const val ALL = "all"
        /** The types the filter offers, in the current app's order. */
        val TYPES = listOf("login", "note", "card")
    }
}

/**
 * The rows on show: the content's list (already searched and in name order), cut to one type and one vault, then by
 * the last change when asked (stable, so rows changed at the same time keep their name order). A filter naming a vault
 * the content no longer lists is every vault, as in the current app, never a silent empty list.
 */
internal fun listView(items: List<ItemSummary>, controls: ListControls, vaults: List<ContentVault>): List<ItemSummary> {
    var out = items
    if (controls.type != ListControls.ALL) out = out.filter { it.type == controls.type }
    val vault = effectiveVault(controls, vaults)
    if (vault != ListControls.ALL) out = out.filter { it.vaultId == vault }
    if (controls.recent) out = out.sortedByDescending { it.updatedAt }
    return out
}

/** The vault filter in force: [ListControls.ALL] when it names a vault the content does not list. */
internal fun effectiveVault(controls: ListControls, vaults: List<ContentVault>): String =
    if (controls.vaultId != ListControls.ALL && vaults.none { it.vaultId == controls.vaultId }) ListControls.ALL else controls.vaultId

internal fun sortWords(recent: Boolean): UiText = UiText.ph(if (recent) Placeholder.LIST_SORT_RECENT else Placeholder.LIST_SORT_NAME)

internal fun typeFilterWords(type: String): UiText = UiText.ph(
    when (type) {
        "login" -> Placeholder.LIST_LOGINS
        "note" -> Placeholder.LIST_NOTES
        "card" -> Placeholder.LIST_CARDS
        else -> Placeholder.LIST_ALL_TYPES
    },
)

/**
 * Why the vault the filter names is closed for writing on this device ([ContentVault.closedLine], the same sentence a
 * change into it is refused with), said above its items; null when the filter shows every vault or an open one.
 */
internal fun closedFilterLine(controls: ListControls, vaults: List<ContentVault>): String? {
    val v = effectiveVault(controls, vaults)
    return vaults.firstOrNull { it.vaultId == v }?.closedLine
}

/** The vault filter's words: a vault's own name (data, as the content gives it), or every vault. */
internal fun vaultFilterWords(controls: ListControls, vaults: List<ContentVault>): UiText {
    val v = effectiveVault(controls, vaults)
    return vaults.firstOrNull { it.vaultId == v }?.let { UiText.Plain(it.name) } ?: UiText.ph(Placeholder.LIST_ALL_VAULTS)
}

/** The current app's row of three text buttons with their menus; the vault filter only when there is more than one vault. */
@Composable
private fun ListControlsRow(state: ContentState, controls: ListControls, onControls: (ListControls) -> Unit) {
    // The current app's row; it wraps where it does not fit (the largest font), so no choice runs off the screen.
    ButtonRow(spacing = 0) {
        var sortMenu by remember { mutableStateOf(false) }
        Box {
            TextButton(onClick = { sortMenu = true }) { Say(sortWords(controls.recent)) }
            DropdownMenu(expanded = sortMenu, onDismissRequest = { sortMenu = false }) {
                DropdownMenuItem(text = { Say(UiText.ph(Placeholder.LIST_BY_NAME)) }, onClick = { sortMenu = false; onControls(controls.copy(recent = false)) })
                DropdownMenuItem(text = { Say(UiText.ph(Placeholder.LIST_BY_RECENT)) }, onClick = { sortMenu = false; onControls(controls.copy(recent = true)) })
            }
        }
        var typeMenu by remember { mutableStateOf(false) }
        Box {
            TextButton(onClick = { typeMenu = true }) { Say(typeFilterWords(controls.type)) }
            DropdownMenu(expanded = typeMenu, onDismissRequest = { typeMenu = false }) {
                (listOf(ListControls.ALL) + ListControls.TYPES).forEach { t ->
                    DropdownMenuItem(text = { Say(typeFilterWords(t)) }, onClick = { typeMenu = false; onControls(controls.copy(type = t)) })
                }
            }
        }
        if (state.vaults.size > 1) {
            var vaultMenu by remember { mutableStateOf(false) }
            Box {
                TextButton(onClick = { vaultMenu = true }) { Say(vaultFilterWords(controls, state.vaults)) }
                DropdownMenu(expanded = vaultMenu, onDismissRequest = { vaultMenu = false }) {
                    DropdownMenuItem(text = { Say(UiText.ph(Placeholder.LIST_ALL_VAULTS)) }, onClick = { vaultMenu = false; onControls(controls.copy(vaultId = ListControls.ALL)) })
                    state.vaults.forEach { v ->
                        // A vault closed for writing says why under its name in the filter.
                        DropdownMenuItem(text = {
                            Column {
                                Text(v.name)
                                v.closedLine?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                            }
                        }, onClick = { vaultMenu = false; onControls(controls.copy(vaultId = v.vaultId)) })
                    }
                }
            }
        }
    }
}

/**
 * A row's second line, as the current app's: a login's user name (else its address, else its kind), a card's brand and
 * last four digits ("Visa ••4242"; an unknown brand is the kind's word; a card with no number is its kind), and a
 * note's kind. No more of a card's number than the last four.
 */
internal fun rowSecondLine(item: ItemSummary): String = when (item.type) {
    "login" -> item.username?.takeIf { it.isNotBlank() } ?: item.host?.takeIf { it.isNotBlank() } ?: kindWords("login").shown()
    "card" -> item.cardLastFour?.takeIf { it.isNotEmpty() }?.let { last -> (item.cardBrand ?: kindWords("card").shown()) + " ••" + last }
        ?: kindWords("card").shown()
    else -> kindWords(item.type).shown()
}

/** The row's shared-vault mark: the shared vault's name (a placeholder where this device holds no name); none for the personal vault. */
internal fun sharedVaultMark(item: ItemSummary): String? =
    if (!item.sharedVault) null else item.vaultName?.takeIf { it.isNotBlank() } ?: UiText.ph(Placeholder.LIST_SHARED_VAULT).shown()

/** One item, as the current app's row: a card with the name's first letter, the name, a second line, and its kind. */
@Composable
internal fun ItemCard(item: ItemSummary, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(38.dp), contentAlignment = Alignment.Center) {
                // Decoration: the name's first letter is read with the name itself.
                Text(
                    (item.name.firstOrNull() ?: '?').uppercase(),
                    color = MaterialTheme.colorScheme.primary,
                    fontFamily = FontFamily.Serif,
                    modifier = Modifier.clearAndSetSemantics {},
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    rowSecondLine(item), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            if (item.pendingSync) {
                Text(UiText.ph(Placeholder.ITEM_WAITING).shown(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary, maxLines = 1)
                Spacer(Modifier.width(8.dp))
            }
            // The shared vault's mark, as the current app's (its gold, width-capped so a long name leaves the item's name room).
            sharedVaultMark(item)?.let {
                Text(
                    it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary, maxLines = 1,
                    overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 140.dp),
                )
                Spacer(Modifier.width(8.dp))
            }
            Text(kindWords(item.type).shown(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
        }
    }
}

/**
 * Settings' "vault backup", where the current app has it: the encrypted backup as the main button, the CSV for another
 * password manager under it, and the export itself in place once opened. Nothing while the vault is locked.
 */
@Composable
internal fun VaultBackupSection(model: TrustModel) {
    val content by model.content.collectAsState()
    val c = content ?: return
    val state by c.states.collectAsState()
    val t = rememberTransferActions(c)
    // A card of its own, as in the current app's Settings (nothing at all while the vault is locked).
    SettingsCard {
        Say(Placeholder.VAULT_BACKUP, style = sectionTitleStyle())
        t.answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
        Main(UiText.ph(Placeholder.EXPORT_BACKUP), enabled = !state.busy && state.exporting == null, busy = false) { t.export(ExportKind.BACKUP) }
        Second(UiText.ph(Placeholder.EXPORT_CSV), enabled = !state.busy && state.exporting == null) { t.export(ExportKind.CSV) }
        // The export opens as a dialog over Settings, as the current app's.
        state.exporting?.let { exporting -> ExportPanel(c, exporting) }
    }
}

/**
 * Settings' storage line: the account's four meters on this server (what it stores, its items, the shared vaults it
 * owns, its open links), each as used of its limit with a bar, as the freshest sync served them. Nothing at all when
 * the server gave none, and nothing while the vault is locked.
 */
@Composable
internal fun StorageSection(model: TrustModel) {
    val content by model.content.collectAsState()
    val c = content ?: return
    val state by c.states.collectAsState()
    val rows = storageRows(state.storage ?: return)
    // A card of its own, drawn as the current app's Settings cards (nothing at all when the server gave no meters).
    SettingsCard {
        Say(Placeholder.STORAGE, style = sectionTitleStyle())
        rows.forEach { (label, meter) ->
            Say(UiText.ph(label, meterText(label, meter.used), meterText(label, meter.limit)), style = MaterialTheme.typography.bodySmall)
            LinearProgressIndicator(
                progress = { if (meter.limit > 0) (meter.used.toFloat() / meter.limit).coerceIn(0f, 1f) else 0f },
                modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
            )
        }
    }
}

/** The four meters, in the order Settings shows them. */
internal fun storageRows(s: io.silencelen.andvari.core.app.content.AccountStorage): List<Pair<Placeholder, io.silencelen.andvari.core.app.content.StorageMeter>> =
    listOf(
        Placeholder.STORAGE_BYTES to s.accountBytes,
        Placeholder.STORAGE_ITEMS to s.items,
        Placeholder.STORAGE_SHARED_VAULTS to s.ownedSharedVaults,
        Placeholder.STORAGE_LINKS to s.openLinks,
    )

/** A meter's number: a size for the bytes, a count for the rest. */
internal fun meterText(label: Placeholder, n: Long): String =
    if (label == Placeholder.STORAGE_BYTES) sizeText(n) else n.toString()

/**
 * Sharing's "recently deleted shared vaults", where the current app has them: opened on request (the content reads
 * them from this device's verified log), then listed in place with Restore.
 */
@Composable
internal fun RecentlyDeletedVaultsSection(model: TrustModel) {
    val content by model.content.collectAsState()
    val c = content ?: return
    val state by c.states.collectAsState()
    val scope = rememberCoroutineScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    // A card of its own at the foot of Sharing, as the current app's "Recently deleted vaults".
    SettingsCard {
        val rows = state.deletedVaults
        if (rows != null) {
            DeletedVaultsView(model, c, state, rows)
        } else {
            Quieter(UiText.ph(Placeholder.RECENTLY_DELETED), enabled = !state.busy) {
                scope.launchOvertakable { answer = actionAnswer(c.openDeletedVaults()) }
            }
            answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
        }
    }
}

/** The actions of the vault's top bar over [c], with the trash answering in [said]. */
@Composable
internal fun rememberVaultBarActions(
    c: VaultContent,
    state: ContentState,
    go: (SignedInPage) -> Unit,
    said: (String?) -> Unit,
): Pair<VaultBarActions, TransferActions> {
    val scope = rememberCoroutineScope()
    val t = rememberTransferActions(c)
    val a = VaultBarActions(
        importCsv = if (canSave(state)) t.importCsv else null,
        health = { c.openHealth() },
        sharing = { go(SignedInPage.SHARING) },
        trash = { scope.launchOvertakable { said(actionAnswer(c.openTrash())) } },
        settings = { go(SignedInPage.SETTINGS) },
        enabled = !state.busy,
    )
    return a to t
}
