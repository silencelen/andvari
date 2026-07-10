package io.silencelen.andvari.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

class MainActivity : ComponentActivity() {
    private val vm: AndvariViewModel by viewModels {
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T =
                // Cache DBs live in no_backup/ — the platform keeps that dir out of Auto
                // Backup AND device-to-device transfer on every API level (backup rules
                // can't glob the per-user vault-<userId>.db names, so location does the job).
                AndvariViewModel(SessionStore(applicationContext), applicationContext.noBackupFilesDir) as T
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // If the previous run crashed, show the captured trace using a PLAIN Android view
        // (no Compose/theme), so even a crash in the Compose layer itself is still visible
        // to screenshot. Skips the (possibly still-crashing) normal startup path.
        val crashFile = java.io.File(filesDir, AndvariApplication.CRASH_FILE)
        if (crashFile.exists()) {
            val trace = runCatching { crashFile.readText() }.getOrDefault("(crash file unreadable)")
            showCrash(trace) { crashFile.delete(); recreate() }
            return
        }
        // Block Recents thumbnails / screen recording / casting from capturing revealed
        // secrets (set AFTER the crash-screen early-return above — crash traces must stay
        // screenshot-able). The Autofill Status screen is exempted below: the owner's Fold
        // debugging protocol depends on screenshotting it, and it renders no vault values.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        lifecycleScope.launch {
            vm.ui.map { it.screen is Screen.AutofillStatus }.distinctUntilChanged().collect { exempt ->
                if (exempt) window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                else window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
        // One-time: bump an old LAN-default server URL to the tailnet HTTPS default.
        SessionStore(applicationContext).migrateDefaultOnce()
        vm.start()
        // Foreground sync cadence (spec 03 §6): sync immediately on EVERY ON_RESUME
        // (onForeground also enforces the idle auto-lock first — a backgrounded app must
        // lock on return if the window passed while it slept), then every 5 min while
        // resumed and unlocked. repeatOnLifecycle cancels the loop off-RESUMED; no
        // WorkManager, no schedule outlives the foreground.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    vm.onForeground()
                    delay(FOREGROUND_SYNC_MS)
                }
            }
        }
        setContent { AndvariTheme { AndvariApp(vm) } }
    }

    // Any user interaction resets the inactivity auto-lock window (spec 01 §8: activity =
    // pointer/key/touch, nothing else). Dispatch overrides see every event before Compose.
    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        VaultSession.touch()
        return super.dispatchTouchEvent(ev)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        VaultSession.touch()
        return super.dispatchKeyEvent(event)
    }

    override fun dispatchGenericMotionEvent(ev: MotionEvent?): Boolean {
        VaultSession.touch() // mouse wheel / rotary / hover-scroll on tablets & ChromeOS
        return super.dispatchGenericMotionEvent(ev)
    }

    private companion object {
        const val FOREGROUND_SYNC_MS = 5L * 60 * 1000 // spec 03 §6 poll interval
    }

    /** Deliberately uses only android.widget — no Compose — so a Compose crash still renders. */
    private fun showCrash(trace: String, onClear: () -> Unit) {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setBackgroundColor(0xFF14120E.toInt())
            setPadding(pad, pad, pad, pad)
        }
        root.addView(android.widget.TextView(this).apply {
            text = "andvari hit an error — screenshot this and send it"
            setTextColor(0xFFCF6B5A.toInt())
            textSize = 15f
        })
        val scroll = android.widget.ScrollView(this).apply {
            layoutParams = android.widget.LinearLayout.LayoutParams(-1, 0, 1f)
        }
        scroll.addView(android.widget.TextView(this).apply {
            text = trace
            setTextColor(0xFFEDE4D0.toInt())
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
            setPadding(0, pad, 0, pad)
        })
        root.addView(scroll)
        root.addView(android.widget.Button(this).apply {
            text = "Clear & retry"
            setOnClickListener { onClear() }
        })
        setContentView(root)
    }
}

@Composable
fun AndvariApp(vm: AndvariViewModel) {
    val ui by vm.ui.collectAsStateWithLifecycle()
    Surface(Modifier.fillMaxSize()) {
        when (val screen = ui.screen) {
            is Screen.Loading -> Centered { Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary) }
            is Screen.Welcome -> WelcomeScreen(vm, ui)
            is Screen.Unlock -> UnlockScreen(vm, ui, screen.email)
            is Screen.Vault -> VaultScreen(vm, ui)
            is Screen.Sharing -> SharingScreen(vm, ui)
            is Screen.Settings -> SettingsScreen(vm, ui)
            is Screen.Trash -> TrashScreen(vm, ui)
            is Screen.AutofillStatus -> AutofillStatusScreen(vm, ui)
        }
    }
}

@Composable
private fun Centered(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally, content = content)
}

@Composable
private fun Sigil() {
    Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
    Text("andvari", style = MaterialTheme.typography.titleLarge)
    Text("the keeper of the hoard", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
internal fun ErrorBar(msg: String?, onDismiss: () -> Unit) {
    if (msg != null) {
        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(msg, Modifier.weight(1f), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = onDismiss) { Text("dismiss") }
            }
        }
    }
}

@Composable
internal fun NoticeBar(msg: String?, onDismiss: () -> Unit) {
    if (msg != null) {
        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(msg, Modifier.weight(1f), color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = onDismiss) { Text("dismiss") }
            }
        }
    }
}

// ---- auth ----

@Composable
fun WelcomeScreen(vm: AndvariViewModel, ui: UiState) {
    var tab by rememberSaveable { mutableStateOf(0) }
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(40.dp))
        Sigil()
        Spacer(Modifier.height(24.dp))
        TabRow(selectedTabIndex = tab) {
            Tab(tab == 0, { tab = 0 }, text = { Text("Sign in") })
            Tab(tab == 1, { tab = 1 }, text = { Text("Enroll") })
        }
        Spacer(Modifier.height(20.dp))
        ErrorBar(ui.error, vm::clearError)
        if (tab == 0) SignInForm(vm, ui) else EnrollForm(vm, ui)
        Spacer(Modifier.height(24.dp))
        ServerField(ui.baseUrl, vm::setBaseUrl)
    }
}

@Composable
private fun SignInForm(vm: AndvariViewModel, ui: UiState) {
    // rememberSaveable: rotation / fold-posture change must not wipe a half-typed form.
    var email by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var totp by rememberSaveable { mutableStateOf("") }
    Column(Modifier.fillMaxWidth()) {
        Field("Email", email, { email = it }, keyboard = KeyboardType.Email)
        SecretField("Master password", password) { password = it }
        if (ui.loginTotpRequired) {
            Field("One-time code", totp, { totp = it.filter { c -> c.isDigit() }.take(6) }, mono = true, keyboard = KeyboardType.Number)
        }
        Spacer(Modifier.height(12.dp))
        val ready = email.isNotBlank() && password.isNotBlank() && (!ui.loginTotpRequired || totp.length == 6)
        PrimaryButton("Sign in", enabled = ready && !ui.busy, busy = ui.busy) { vm.signIn(email.trim(), password, totp.ifBlank { null }) }
    }
}

@Composable
private fun EnrollForm(vm: AndvariViewModel, ui: UiState) {
    // rememberSaveable: enrollment is the longest form in the app — losing it to a fold
    // unfold (Activity recreation) was silent data loss.
    var invite by rememberSaveable { mutableStateOf("") }
    var email by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var password by rememberSaveable { mutableStateOf("") }
    var confirm by rememberSaveable { mutableStateOf("") }
    var fpOk by rememberSaveable { mutableStateOf(false) }
    val fp = ui.policy?.recoveryFingerprint ?: ""
    val ready = invite.isNotBlank() && email.isNotBlank() && password.length >= 8 && password == confirm && fpOk && fp.isNotEmpty()
    Column(Modifier.fillMaxWidth()) {
        Field("Invite token", invite, { invite = it }, mono = true)
        Field("Email", email, { email = it }, keyboard = KeyboardType.Email)
        Field("Name (optional)", name, { name = it })
        SecretField("Master password", password) { password = it }
        SecretField("Confirm password", confirm) { confirm = it }
        if (fp.isEmpty()) {
            Text("This server has no recovery key configured yet — enrollment is disabled until the escrow ceremony is done.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 8.dp))
        } else {
            Spacer(Modifier.height(8.dp))
            Text("Recovery fingerprint", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(groupHex(fp), fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall)
            Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(fpOk, { fpOk = it })
                Text("Matches my printed recovery sheet. My master password can only be reset with that offline key.", style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(12.dp))
        PrimaryButton("Create vault", enabled = ready && !ui.busy, busy = ui.busy) { vm.enroll(invite.trim(), email.trim(), name.trim(), password) }
    }
}

/**
 * F57: after a recovery-key re-ceremony this account's escrow is sealed to the DEAD key. Offer to
 * re-seal to the current key — but only after the user TYPES the new recovery fingerprint from
 * their PRINTED sheet (spec 04 §2(3): we deliberately do NOT display it, so a compromised server
 * can't win a lazy eyeball-match). The ViewModel binds the fetched pubkey to that verified
 * fingerprint and refuses on mismatch. Non-blocking: "Later" leaves it for the next unlock.
 */
@Composable
private fun ReSealCard(vm: AndvariViewModel, ui: UiState) {
    var open by rememberSaveable { mutableStateOf(false) }
    var entry by rememberSaveable { mutableStateOf("") }
    val ok = Escrow.shortFormMatches(entry, ui.escrowFingerprint)
    Card(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
    ) {
        Column(Modifier.padding(12.dp)) {
            if (!open) {
                Text(
                    "Your household's recovery key changed — re-protect this account so it stays recoverable.",
                    style = MaterialTheme.typography.bodySmall,
                )
                TextButton(onClick = { open = true }) { Text("Re-protect →") }
            } else {
                Text("Re-protect account", style = MaterialTheme.typography.titleSmall)
                Text(
                    "Confirm the NEW recovery fingerprint from your printed recovery sheet, then re-protect. " +
                        "Your master key never leaves this device except sealed to the recovery key you verify.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 6.dp),
                )
                Field("First 16 characters from your printed recovery sheet", entry, { entry = it }, mono = true)
                Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    PrimaryButton("Re-protect account", enabled = ok && !ui.busy, busy = ui.busy) { vm.resealEscrow(entry) }
                    TextButton(onClick = { open = false }) { Text("Later") }
                }
            }
        }
    }
}

@Composable
fun UnlockScreen(vm: AndvariViewModel, ui: UiState, email: String) {
    var password by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Sigil()
        Spacer(Modifier.height(8.dp))
        Text(email, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(24.dp))
        ErrorBar(ui.error, vm::clearError)
        SecretField("Master password", password) { password = it }
        Spacer(Modifier.height(12.dp))
        PrimaryButton("Unlock", enabled = password.isNotBlank() && !ui.busy, busy = ui.busy) { vm.unlock(email, password) }
        TextButton(onClick = vm::signOut) { Text("Sign out / use a different account") }
    }
}

// ---- vault ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(vm: AndvariViewModel, ui: UiState) {
    // rememberSaveable: rotation / fold-posture change recreates the Activity, and plain
    // `remember` state (search, open detail) silently reset — typed work lost. (With the
    // manifest configChanges those events no longer even recreate; this is defense-in-depth.)
    var query by rememberSaveable { mutableStateOf("") }
    var detailId by rememberSaveable { mutableStateOf<String?>(null) }
    val ctx = LocalContextCompat()
    val scope = rememberCoroutineScope()

    // The editor session (open flag + target itemId) lives in the ViewModel — see
    // AndvariViewModel.openEditor/closeEditor. Local snapshot for smart-casts.
    val editorItemId = vm.editorItemId
    // Snapshot the initial doc per editor session (remember, not derived live): edits build
    // on initial.copy(), and the base must not shift under the user mid-session. null with
    // a non-null id = the target item no longer exists.
    val editorInitial = if (!vm.editorOpen) null else remember(editorItemId, vm.editorNewType) {
        when {
            editorItemId != null -> vm.item(editorItemId)?.doc
            vm.editorNewType == "card" -> ItemDoc(type = "card", name = "", card = CardData())
            else -> ItemDoc(type = "login", name = "", login = LoginData(uris = listOf("")))
        }
    }
    if (vm.editorOpen && editorItemId != null && editorInitial == null) {
        // Deleted on another device (tombstone synced) — never rebase a blank doc onto the
        // existing id; the ViewModel closes the session and explains.
        LaunchedEffect(editorItemId) { vm.editorTargetVanished() }
    }
    // System back walks the in-app hierarchy instead of backgrounding the app: detail →
    // list here; editor → discard-confirm (handled inside ItemEditor, which registers its
    // own BackHandler while composed and therefore wins while the editor is open).
    BackHandler(enabled = editorInitial == null && detailId != null) { detailId = null }

    // CSV import: OpenDocument → BOUNDED read (never buffer a multi-GB file) → parse on-device.
    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    ctx.contentResolver.openInputStream(uri)?.use { readBounded(it, CsvImport.MAX_BYTES) }
                        ?: throw IllegalStateException("could not read the selected file")
                }
            }
            result.onSuccess { bytes ->
                if (bytes == null) vm.importReject("That file is larger than 10 MiB — far bigger than any real browser password export.")
                else vm.importParse(bytes)
            }.onFailure { vm.importReject(it.message ?: "could not read the selected file") }
        }
    }

    val filtered = ui.items.filter {
        val q = query.trim().lowercase()
        // F79 parity with web/desktop: name + username + EVERY uri + notes + card brand/••last4.
        val d = it.doc
        q.isEmpty() ||
            d.name.lowercase().contains(q) ||
            (d.notes ?: "").lowercase().contains(q) ||
            (d.login?.username ?: "").lowercase().contains(q) ||
            (d.login?.uris ?: emptyList()).any { u -> u.lowercase().contains(q) } ||
            (d.type == "card" && CardDisplay.subtitle(d).lowercase().contains(q))
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("andvari", style = MaterialTheme.typography.titleLarge) },
                actions = {
                    // Guided importers (design 2026-07-09): source picker first, THEN the file picker.
                    IconButton(onClick = { vm.importBegin() }) { Icon(Icons.Default.FileUpload, "import CSV") }
                    IconButton(onClick = { vm.refresh() }) { Icon(Icons.Default.Refresh, "sync") }
                    IconButton(onClick = { vm.openSharing() }) { Icon(Icons.Default.Group, "sharing") }
                    IconButton(onClick = { vm.openTrash() }) { Icon(Icons.Default.Delete, "trash") }
                    IconButton(onClick = { vm.openSettings() }) { Icon(Icons.Default.Settings, "settings") }
                    IconButton(onClick = { vm.lock() }) { Icon(Icons.Default.Lock, "lock") }
                },
            )
        },
        floatingActionButton = {
            if (editorInitial == null && detailId == null) {
                // Option A rollout gate (design 2026-07-09): card CREATION stays dark until the
                // fielded 0.2.x desktop MSI is retired — the gate const lives in core beside the
                // display helpers. Everything downstream for EXISTING cards renders regardless.
                if (!CardDisplay.CREATE_ENABLED) {
                    ExtendedFloatingActionButton(onClick = { vm.openEditor(null) }, text = { Text("Add") }, icon = { Icon(Icons.Default.Add, null) })
                } else {
                    var addMenu by remember { mutableStateOf(false) }
                    Box {
                        ExtendedFloatingActionButton(onClick = { addMenu = true }, text = { Text("Add") }, icon = { Icon(Icons.Default.Add, null) })
                        DropdownMenu(expanded = addMenu, onDismissRequest = { addMenu = false }) {
                            DropdownMenuItem(text = { Text("Login") }, onClick = { addMenu = false; vm.openEditor(null) })
                            DropdownMenuItem(text = { Text("Card") }, onClick = { addMenu = false; vm.openEditor(null, newType = "card") })
                        }
                    }
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            val current = detailId?.let { vm.item(it) }
            when {
                // Completion callbacks capture the STABLE vm, never composition state: a
                // save finishing across an Activity recreation still closes the editor.
                editorInitial != null -> ItemEditor(vm, ui, editorItemId, editorInitial, onSave = { doc, uploads -> vm.saveItem(editorItemId, doc, uploads) { vm.closeEditor() } }, onCancel = { vm.closeEditor() })
                current != null -> ItemDetail(vm, ui, current, onEdit = { vm.openEditor(current.itemId) }, onDelete = { vm.deleteItem(current.itemId); detailId = null }, onBack = { detailId = null })
                else -> Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState())) {
                    OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search vault…") }, singleLine = true, leadingIcon = { Icon(Icons.Default.Search, null) })
                    ErrorBar(ui.error, vm::clearError)
                    NoticeBar(ui.notice, vm::clearNotice)
                    // Lifecycle notices + verified ownership offers (spec 03 §11) land where the
                    // user actually looks — the main list — not only on the Sharing screen.
                    LifecycleNoticesBanner(ui.lifecycleNotices, vm::dismissNotice)
                    IncomingTransferCards(vm, ui)
                    if (ui.escrowStale && ui.escrowFingerprint.isNotEmpty()) ReSealCard(vm, ui)
                    if (ui.needsUpdateCount > 0) {
                        Text(needsUpdateLine(ui.needsUpdateCount), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 4.dp))
                    }
                    Spacer(Modifier.height(8.dp))
                    if (filtered.isEmpty()) {
                        Centered { Spacer(Modifier.height(60.dp)); Text("ᛝ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary); Text(if (ui.items.isEmpty()) "Your hoard is empty." else "Nothing matches.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    } else {
                        filtered.forEach { item -> VaultRow(item) { detailId = item.itemId }; Spacer(Modifier.height(8.dp)) }
                    }
                }
            }
            ImportSourceDialog(vm, ui) { importPicker.launch(arrayOf("*/*")) }
            ImportDialogs(vm, ui)
        }
    }
}

/**
 * Guided source picker (design 2026-07-09): the 8 named sources, each a short export
 * instruction block + the file input, in this file's dialog idiom. Selection tailors the
 * instructions and the post-parse mismatch hint ONLY — header detection stays
 * authoritative, so any supported export imports fine under any source.
 */
@Composable
private fun ImportSourceDialog(vm: AndvariViewModel, ui: UiState, onChooseFile: () -> Unit) {
    if (!ui.importSourceSheet) return
    val source = ui.importSource
    AlertDialog(
        onDismissRequest = vm::importSheetDismiss,
        confirmButton = {
            if (source != null) {
                TextButton(onClick = { vm.importChooseFile(); onChooseFile() }) { Text("Choose file") }
            }
        },
        dismissButton = { TextButton(onClick = vm::importSheetDismiss) { Text("Cancel") } },
        title = { Text(if (source == null) "Import passwords from…" else "Import from ${source.label}") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (source == null) {
                    Text(
                        "Where is your export from? This only tailors the steps — the file itself decides how it's read.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(4.dp))
                    ImportSource.values().forEach { s ->
                        TextButton(onClick = { vm.importSourcePick(s) }, modifier = Modifier.fillMaxWidth()) {
                            Text(s.label, Modifier.fillMaxWidth())
                        }
                    }
                } else {
                    source.steps.forEachIndexed { i, step ->
                        Text("${i + 1}. $step", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 3.dp))
                    }
                    Spacer(Modifier.height(6.dp))
                    TextButton(onClick = vm::importSourceBack) { Text("My file is from somewhere else") }
                }
            }
        },
    )
}

/** The three CSV-import dialogs (parse error → preview/confirm+progress+retry → done). */
@Composable
private fun ImportDialogs(vm: AndvariViewModel, ui: UiState) {
    if (ui.importError != null && ui.importPlan == null && !ui.importDone) {
        AlertDialog(
            onDismissRequest = vm::importDismiss,
            confirmButton = { TextButton(onClick = vm::importDismiss) { Text("OK") } },
            title = { Text("Couldn’t import") },
            text = { Text(ui.importError) },
        )
    }
    ui.importPlan?.let { plan ->
        if (!ui.importDone) {
            val report = plan.report
            AlertDialog(
                onDismissRequest = { if (!ui.importBusy) vm.importDismiss() },
                confirmButton = {
                    if (ui.importError != null) {
                        TextButton(onClick = vm::importConfirm, enabled = !ui.importBusy) { Text("Retry") }
                    } else {
                        TextButton(onClick = vm::importConfirm, enabled = !ui.importBusy && report.imported > 0) { Text("Import ${report.imported}") }
                    }
                },
                dismissButton = { TextButton(onClick = vm::importDismiss, enabled = !ui.importBusy) { Text("Cancel") } },
                title = { Text("Import passwords?") },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Text(
                            "⚠ This file holds every secret in plaintext. Nothing is uploaded — each item is encrypted on this device. Afterwards, delete the CSV and empty the trash.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("From ${ui.importFormat?.let { importFormatLabel(it) } ?: "browser"} export:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        // Post-parse info lines (calm): source-vs-detected mismatch + A10 mangle.
                        ui.importFormatNote?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 2.dp)) }
                        ui.importMangleNote?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 2.dp)) }
                        Text("• ${report.imported} to import", style = MaterialTheme.typography.bodySmall)
                        if (report.collapsed > 0) Text("• ${report.collapsed} exact duplicates in the file merged", style = MaterialTheme.typography.bodySmall)
                        if (report.skippedEmpty > 0) Text("• ${report.skippedEmpty} empty rows skipped", style = MaterialTheme.typography.bodySmall)
                        // Every bucket enumerates BY NAME (house rule), collapsed when long.
                        ImportBucket("imported as secure notes:", report.noteItems)
                        ImportBucket("already in your vault — skipped:", report.alreadyInVault)
                        ImportBucket("same site + username but a different password — imported separately; review which password is current:", report.passwordDiffers)
                        ImportBucket("same site + username but a different 2FA secret — imported separately; review which is current:", report.totpDiffers)
                        ImportBucket("renamed — the name was already taken:", report.flagged)
                        ImportBucket("archived in the export — not imported:", report.archivedSkipped)
                        ImportBucket("of a type this import doesn’t understand — skipped:", report.unknownTypeSkipped)
                        ImportBucket("with an unsupported one-time-code secret — kept as text in the item’s notes:", report.totpUnsupported)
                        if (report.errors.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            Text("${report.errors.size} row(s) couldn’t be read:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            report.errors.forEach { err ->
                                // A9: lead with the data-row ordinal — a multi-line quoted
                                // note makes the physical line unmatchable to the row a
                                // spreadsheet shows (core's rowOrdinalsByLine, same reader).
                                val where = ui.importRowOrdinals[err.line]?.let { "row $it (file line ${err.line})" } ?: "file line ${err.line}"
                                Text("• $where: ${importRowErrorLabel(err.code)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            }
                        }
                        ui.importProgress?.let { (done, total) ->
                            Spacer(Modifier.height(10.dp))
                            LinearProgressIndicator(progress = { if (total > 0) done.toFloat() / total else 0f }, modifier = Modifier.fillMaxWidth())
                            Text("Importing $done / $total", style = MaterialTheme.typography.bodySmall)
                        }
                        ui.importError?.let { Spacer(Modifier.height(8.dp)); Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    }
                },
            )
        }
    }
    if (ui.importDone) {
        AlertDialog(
            onDismissRequest = vm::importDismiss,
            confirmButton = { TextButton(onClick = vm::importDismiss) { Text("Done") } },
            title = { Text("Imported") },
            text = { Text("Added ${ui.importReport?.imported ?: 0} item(s) to your vault. Now delete the CSV file and empty your trash.") },
        )
    }
}

/** Import-report bucket: title (with count) + names, collapsed past [collapseAt] — the
 *  house rule is enumerate-by-name, never a bare count, but a 500-name list must not
 *  swallow the dialog. Empty → renders nothing. */
@Composable
private fun ImportBucket(title: String, names: List<String>, collapseAt: Int = 5) {
    if (names.isEmpty()) return
    var expanded by remember(names) { mutableStateOf(false) }
    Spacer(Modifier.height(6.dp))
    Text("${names.size} $title", style = MaterialTheme.typography.bodySmall)
    val shown = if (expanded || names.size <= collapseAt) names else names.take(collapseAt)
    shown.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    if (names.size > collapseAt) {
        TextButton(onClick = { expanded = !expanded }) { Text(if (expanded) "Show fewer" else "…and ${names.size - collapseAt} more") }
    }
}

private fun importRowErrorLabel(code: String): String = when (code) {
    "wrong_field_count" -> "wrong number of fields"
    "bad_quote" -> "broken quoting"
    else -> code
}

/**
 * Read at most [limit] bytes from [input]; return null if the source is larger (so a
 * multi-GB pick is rejected without ever being buffered in memory). Mirrors CsvImport's
 * own size cap so a file that fits here also passes parse().
 */
private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray? {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val r = input.read(buf)
        if (r < 0) break
        total += r
        if (total > limit) return null
        out.write(buf, 0, r)
    }
    return out.toByteArray()
}

@Composable
private fun VaultRow(item: VaultItem, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(38.dp), contentAlignment = Alignment.Center) {
                Text((item.doc.name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.doc.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                Text(
                    when (item.doc.type) {
                        "login" -> item.doc.login?.username?.ifBlank { "login" } ?: "login"
                        // Brand + ••last4 (mirrors web) — enough to pick the right card, never the PAN.
                        "card" -> CardDisplay.subtitle(item.doc)
                        else -> "secure note"
                    },
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                )
            }
            Text(item.doc.type, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * Item history & restore (feature: "the fat-finger seatbelt"). Loads the archived versions the
 * server keeps (up to the last 10), decrypts each under the held VK, and offers per-version reveal
 * + Restore (a plain put over the live item). Readers view but can't restore. "up to the last 10
 * saves" — never "nothing is ever lost" (spec 02 §7). Mirrors the deployed web panel.
 */
@Composable
private fun ItemHistorySection(vm: AndvariViewModel, ui: UiState, item: VaultItem, readOnly: Boolean, onRestored: () -> Unit) {
    var open by rememberSaveable(item.itemId) { mutableStateOf(false) }
    if (!open) {
        TextButton(onClick = { open = true; vm.loadItemVersions(item.itemId, item.vaultId) }) { Text("Version history") }
        return
    }
    Text("Version history · up to the last 10 saves", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    val versions = ui.itemVersions
    when {
        versions == null -> Text(if (ui.busy) "Loading…" else "", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        versions.isEmpty() -> Text("No earlier versions yet — history starts from the next change.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        else -> versions.forEach { v ->
            var revealed by remember(v.rev) { mutableStateOf(false) }
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
                Text(java.time.Instant.ofEpochMilli(v.archivedAt).toString().take(10), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(90.dp))
                val pw = v.doc.login?.password
                Text(
                    when {
                        // Card versions identify by brand + ••last4 (mirrors web) — never the PAN.
                        v.doc.type == "card" -> CardDisplay.subtitle(v.doc)
                        pw == null && v.doc.type == "login" -> "(no password)"
                        pw == null -> "note"
                        revealed -> pw
                        else -> "••••••••"
                    },
                    modifier = Modifier.weight(1f),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
                if (pw != null) TextButton(onClick = { revealed = !revealed }) { Text(if (revealed) "Hide" else "Show") }
                if (!readOnly) TextButton(onClick = { vm.saveItem(item.itemId, v.doc) { onRestored() } }) { Text("Restore") }
            }
        }
    }
    TextButton(onClick = { open = false; vm.clearItemVersions() }) { Text("Hide history") }
}

@Composable
private fun ItemDetail(vm: AndvariViewModel, ui: UiState, item: VaultItem, onEdit: () -> Unit, onDelete: () -> Unit, onBack: () -> Unit) {
    val ctx = LocalContextCompat()
    val doc = item.doc
    // Reader-role members get no Edit/Delete affordances (mirrors web): the push would be
    // denied server-side and the denied mutation's typed work destroyed.
    val readOnly = vm.roleFor(item.vaultId) == "reader"
    var pendingDownload by remember { mutableStateOf<AttachmentRef?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val ref = pendingDownload
        pendingDownload = null
        if (uri != null && ref != null) {
            // "wt": same truncate-on-open contract as the export writes — plain "w"
            // leaves stale trailing bytes when overwriting a longer existing file.
            vm.saveAttachmentTo(ref) { bytes -> openTruncated(ctx, uri).use { it.write(bytes) } }
        }
    }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        ErrorBar(ui.error, vm::clearError)
        NoticeBar(ui.notice, vm::clearNotice)
        Text(doc.name, style = MaterialTheme.typography.headlineMedium)
        // Cards identify themselves by brand + ••last4 (design contract, mirrors web) — the one
        // line that lets the user confirm the right card without revealing the full PAN.
        Text(
            when {
                doc.type == "login" -> "Login"
                doc.type == "card" -> if (doc.card?.number.isNullOrEmpty()) "Card" else CardDisplay.subtitle(doc)
                else -> "Secure note"
            } + (if (readOnly) " · view only" else ""),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        // Vault-secret copies clear after the org policy window, clamped to >=1 s exactly
        // like web's useCopy (Math.max(1, n)): a policy of 0 still clears — never "keep
        // forever" for secrets. 30 s fallback while the policy hasn't loaded (matches web).
        val clipClear = maxOf(1, ui.policy?.clipboardClearSeconds ?: 30)
        doc.login?.let { login ->
            login.username?.takeIf { it.isNotBlank() }?.let { CopyRow("Username", it, ctx, clipClear) }
            login.password?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Password", it, ctx, clipClear) }
            login.totp?.takeIf { it.isNotBlank() }?.let { TotpRow(it, ctx, clipClear) }
            login.uris.firstOrNull()?.takeIf { it.isNotBlank() }?.let { ReadOnlyRow("Website", it) }
        }
        if (doc.type == "card") doc.card?.let { card ->
            card.cardholderName?.takeIf { it.isNotBlank() }?.let { CopyRow("Cardholder", it, ctx, clipClear) }
            // Reveal shows the grouped form; Copy carries the BARE stored digits (what a
            // checkout field wants) through the same policy-cleared clipboard as passwords.
            card.number?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Card number", it, ctx, clipClear, display = CardDisplay.groupNumber(it)) }
            CardDisplay.expiryLabel(card)?.let { label ->
                val today = java.time.LocalDate.now()
                ExpiryRow(label, CardDisplay.isExpired(card.expMonth, card.expYear, today.year, today.monthValue))
            }
            card.securityCode?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Security code", it, ctx, clipClear) }
        }
        doc.notes?.takeIf { it.isNotBlank() }?.let { ReadOnlyRow("Notes", it) }
        if (doc.attachments.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(4.dp))
            doc.attachments.forEach { ref ->
                AttachmentRow(ref, enabled = !ui.busy) { pendingDownload = ref; saver.launch(ref.name) }
                Spacer(Modifier.height(8.dp))
            }
        }
        Spacer(Modifier.height(16.dp))
        ItemHistorySection(vm, ui, item, readOnly, onRestored = onBack)
        Spacer(Modifier.height(24.dp))
        if (!readOnly) {
            var confirmDelete by remember { mutableStateOf(false) }
            Row {
                Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text("Edit") }
                Spacer(Modifier.width(12.dp))
                OutlinedButton(onClick = { confirmDelete = true }, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Delete") }
            }
            if (confirmDelete) {
                AlertDialog(
                    onDismissRequest = { confirmDelete = false },
                    title = { Text("Delete \"${doc.name}\"?") },
                    text = { Text("This removes the item from every device and every family member who can see it.") },
                    confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Delete") } },
                    dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Keep") } },
                )
            }
            // F19 (design §8): move/copy into another writable vault. Mirrors web — only for
            // writers/owners of the SOURCE (a reader's delete leg would be denied anyway).
            val moveTargets = vm.vaultInfos().filter {
                (it.type == "personal" || it.role == "owner" || it.role == "writer") && it.vaultId != item.vaultId
            }
            if (moveTargets.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                MoveCopyControl(vm, ui, item, moveTargets)
            }
        }
    }
}

@Composable
private fun AttachmentRow(ref: AttachmentRef, enabled: Boolean, onClick: () -> Unit) {
    Card(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.AttachFile, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(ref.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                Text(humanSize(ref.size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(Icons.Default.FileDownload, "download", tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ItemEditor(vm: AndvariViewModel, ui: UiState, itemId: String?, initial: ItemDoc, onSave: (ItemDoc, List<PendingUpload>) -> Unit, onCancel: () -> Unit) {
    val ctx = LocalContextCompat()
    val isLogin = initial.type == "login"
    val isCard = initial.type == "card"
    // rememberSaveable: every typed field survives Activity recreation (rotation / fold
    // posture change) — plain `remember` silently wiped them all.
    var name by rememberSaveable { mutableStateOf(initial.name) }
    var username by rememberSaveable { mutableStateOf(initial.login?.username ?: "") }
    var password by rememberSaveable { mutableStateOf(initial.login?.password ?: "") }
    var website by rememberSaveable { mutableStateOf(initial.login?.uris?.firstOrNull() ?: "") }
    var totp by rememberSaveable { mutableStateOf(initial.login?.totp ?: "") }
    // Card fields load VERBATIM (no normalization): merely opening the editor on an old card
    // must never change what a later Save writes back — normalization happens once, inside
    // builtDoc (the TOTP idiom).
    var cardholder by rememberSaveable { mutableStateOf(initial.card?.cardholderName ?: "") }
    var cardNumber by rememberSaveable { mutableStateOf(initial.card?.number ?: "") }
    var cardExpMonth by rememberSaveable { mutableStateOf(initial.card?.expMonth ?: "") }
    var cardExpYear by rememberSaveable { mutableStateOf(initial.card?.expYear ?: "") }
    var cardSecurityCode by rememberSaveable { mutableStateOf(initial.card?.securityCode ?: "") }
    var notes by rememberSaveable { mutableStateOf(initial.notes ?: "") }
    var attachments by rememberSaveable(stateSaver = attachmentListSaver) { mutableStateOf(initial.attachments) }
    // Pending pick BYTES live in the ViewModel (they can't go in SavedState) — see
    // AndvariViewModel.editorPendingUploads.
    val pendingUploads = vm.editorPendingUploads
    var attachError by remember { mutableStateOf<String?>(null) }
    var totpError by remember { mutableStateOf<String?>(null) }
    var confirmDiscard by remember { mutableStateOf(false) }
    val crypto = remember { createCryptoProvider() }
    val scope = rememberCoroutineScope()

    // Process death (not rotation) loses the ViewModel's pending bytes while the saved
    // attachment refs restore: drop any NEW ref whose bytes we no longer hold — saving it
    // would write a dangling attachment pointer.
    LaunchedEffect(Unit) {
        val held = pendingUploads.mapTo(HashSet()) { it.ref.id }
        val preExisting = initial.attachments.mapTo(HashSet()) { it.id }
        attachments = attachments.filter { it.id in preExisting || it.id in held }
    }

    // System back asks before throwing typed work away (it used to background the app).
    BackHandler { confirmDiscard = true }
    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text("Discard changes?") },
            text = { Text("Anything typed in this editor will be lost.") },
            confirmButton = { TextButton(onClick = { confirmDiscard = false; onCancel() }) { Text("Discard") } },
            dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") } },
        )
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            attachError = null
            val cap = ui.policy?.attachmentMaxBytes ?: DEFAULT_ATTACHMENT_MAX_BYTES
            runCatching {
                withContext(Dispatchers.IO) {
                    val fileName = displayName(ctx, uri)
                    val stream = ctx.contentResolver.openInputStream(uri)
                        ?: throw IllegalStateException("could not read the selected file")
                    // BOUNDED read, mirroring the CSV import path: the cap must be enforced
                    // DURING the read — buffering first (readBytes) OOMed on a mispicked
                    // multi-GB file before the size check ever ran. null = over the cap.
                    val bytes = stream.use { readBounded(it, cap.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()) }
                    val overCapSize = if (bytes == null) documentSize(ctx, uri) else -1L
                    Triple(fileName, bytes, overCapSize)
                }
            }.onSuccess { (fileName, bytes, overCapSize) ->
                when {
                    bytes == null -> attachError =
                        if (overCapSize > 0) "“$fileName” is ${humanSize(overCapSize)} — over the ${humanSize(cap)} limit."
                        else "“$fileName” is over the ${humanSize(cap)} limit."
                    bytes.isEmpty() -> attachError = "“$fileName” is empty — nothing to attach."
                    else -> when (val ref = vm.newAttachmentRef(fileName, bytes.size.toLong())) {
                        null -> attachError = "vault is locked"
                        else -> {
                            pendingUploads += PendingUpload(ref, bytes)
                            attachments = attachments + ref
                        }
                    }
                }
            }.onFailure { attachError = it.message ?: "could not read the selected file" }
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onCancel) { Text("cancel") }
        Text(if (itemId != null) "Edit" else if (isLogin) "New login" else if (isCard) "New card" else "New note", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        ErrorBar(ui.error, vm::clearError)
        Field("Name", name, { name = it })
        if (isLogin) {
            Field("Username", username, { username = it }, mono = true)
            Column {
                SecretField("Password", password) { password = it }
                TextButton(onClick = { password = PasswordGenerator.generate(crypto, GeneratorOptions(length = 20)) }) { Icon(Icons.Default.Refresh, null); Text(" Generate") }
            }
            Field("Website", website, { website = it })
            // RAW text while typing — normalizeTotp per keystroke rewrote the field to an
            // otpauth:// URI on the first character, making hand-typing a secret impossible.
            // Normalization + validation happen once, on Save.
            Field("TOTP (otpauth:// or base32)", totp, { totp = it; totpError = null }, mono = true)
            InlineError(totpError)
        }
        if (isCard) {
            Field("Cardholder name", cardholder, { cardholder = it })
            // RAW text while typing (separators and all) — digits-only ONCE, on Save, exactly
            // like the TOTP field above. The label badge + warn line read the live digits; the
            // Luhn check WARNS, never blocks: an odd-but-real card must still be savable.
            val cardDigits = CardNormalize.digitsOnly(cardNumber)
            Field(
                "Card number" + (CardDisplay.brandLabel(CardNormalize.brand(cardDigits))?.let { " · $it" } ?: ""),
                cardNumber, { cardNumber = it }, mono = true, keyboard = KeyboardType.Number,
            )
            if (cardDigits.length >= 12 && !CardNormalize.luhnValid(cardDigits)) {
                Text("this number doesn’t pass the usual check — you can still save it", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
            }
            // Free-text expiry (this file has no select idiom) — padMonth/yearTo4 normalize on
            // Save, so "1"/"27" store as "01"/"2027". Every card field is optional. A half that
            // doesn't parse is stored ABSENT (overwriting any stored value), so warn — never
            // block — while it can't be read (desktop Ui.kt parity; web's selects make bad
            // input impossible).
            Field("Expiry month (MM)", cardExpMonth, { cardExpMonth = it }, mono = true, keyboard = KeyboardType.Number)
            Field("Expiry year (YYYY)", cardExpYear, { cardExpYear = it }, mono = true, keyboard = KeyboardType.Number)
            if ((cardExpMonth.isNotBlank() && CardNormalize.padMonth(cardExpMonth) == null) ||
                (cardExpYear.isNotBlank() && CardNormalize.yearTo4(cardExpYear) == null)
            ) {
                Text("expiry wants a month 1–12 and a 2- or 4-digit year — a part that can’t be read won’t be saved", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
            }
            // Masked-with-reveal: a CVV is glanceable-short and worth shielding from shoulders
            // by default. Digits-only is applied once, on Save, beside the other normalizations.
            SecretField("Security code", cardSecurityCode) { cardSecurityCode = it }
            Text("Optional — stored encrypted like everything else.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
        }
        Field("Notes", notes, { notes = it }, singleLine = false)
        Spacer(Modifier.height(12.dp))
        Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        attachments.forEach { ref ->
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.AttachFile, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(ref.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                    Text(humanSize(ref.size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                TextButton(
                    onClick = {
                        attachments = attachments.filterNot { it.id == ref.id }
                        pendingUploads.removeAll { it.ref.id == ref.id }
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Remove") }
            }
        }
        attachError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        TextButton(onClick = { picker.launch(arrayOf("*/*")) }) { Icon(Icons.Default.AttachFile, null); Text(" Attach file") }
        Spacer(Modifier.height(16.dp))
        // copy()-based edit, never a field-by-field rebuild: carries favorite, passwordHistory,
        // extra URIs beyond the first, and unknown-field extras (spec 02 §3) through the save.
        fun builtDoc(totpValue: String) = initial.copy(
            name = name.trim(), notes = notes.ifBlank { null },
            login = if (isLogin) (initial.login ?: LoginData()).copy(
                username = username, password = password,
                uris = buildList { if (website.isNotBlank()) add(website); addAll(initial.login?.uris.orEmpty().drop(1)) },
                totp = totpValue.ifBlank { null },
            ) else null,
            // Cards normalize ONCE here (mirrors the web submit): .copy() on the EXISTING
            // CardData so unknown-field extras survive; blanks → null; brand is ALWAYS
            // recomputed from the number — the stored field is display-only, never stale.
            card = if (isCard) (initial.card ?: CardData()).copy(
                cardholderName = cardholder.trim().ifBlank { null },
                number = CardNormalize.digitsOnly(cardNumber).ifBlank { null },
                expMonth = CardNormalize.padMonth(cardExpMonth),
                expYear = CardNormalize.yearTo4(cardExpYear),
                securityCode = CardNormalize.digitsOnly(cardSecurityCode).ifBlank { null },
                brand = CardNormalize.brand(cardNumber),
            ) else initial.card,
            attachments = attachments,
        )
        PrimaryButton("Save", enabled = name.isNotBlank() && !ui.busy, busy = ui.busy) {
            // A5: ONE shared TOTP normalize — core Totp.normalize (the private copy this
            // file carried is deleted). Blank stays blank: normalize is only for values.
            val normalizedTotp = if (isLogin && totp.isNotBlank()) Totp.normalize(totp) else ""
            if (isLogin && totp.isNotBlank() && runCatching { Totp.parseUri(normalizedTotp) }.isFailure) {
                totpError = "TOTP secret isn't valid base32 or an otpauth:// link"
            } else {
                onSave(builtDoc(normalizedTotp), pendingUploads.toList())
            }
        }
    }
}

// ---- TOTP live row ----
@Composable
private fun TotpRow(uri: String, ctx: Context, clearSeconds: Int) {
    val crypto = remember { createCryptoProvider() }
    var code by remember { mutableStateOf("······") }
    var remaining by remember { mutableStateOf(30) }
    LaunchedEffect(uri) {
        val cfg = runCatching { Totp.parseUri(uri) }.getOrNull()
        if (cfg == null) { code = "invalid"; return@LaunchedEffect }
        while (true) {
            val now = System.currentTimeMillis() / 1000
            code = Totp.code(crypto, cfg, now)
            remaining = Totp.secondsRemaining(cfg, now)
            delay(1000)
        }
    }
    Column(Modifier.padding(vertical = 8.dp)) {
        Text("One-time code", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { copyToClipboard(ctx, "code", code, clearSeconds) }) {
                Text(code.chunked(3).joinToString(" "), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.secondary)
            }
            Text("${remaining}s", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ---- settings / server TOTP ----

/**
 * Item undelete (feature): "Recently deleted" — the tombstoned items the user can recover. Each is
 * named from its last archived version (a tombstone's own blob is null); Restore re-creates it live
 * via the dedicated route (clean un-tombstone). Attachments are not restored (blobs gone at delete).
 * Mirrors the web Trash view.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(vm: AndvariViewModel, ui: UiState) {
    BackHandler(onBack = vm::closeTrash)
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Recently deleted", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeTrash) { Icon(Icons.Default.ArrowBack, "back") } },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
            ErrorBar(ui.error, vm::clearError)
            NoticeBar(ui.notice, vm::clearNotice)
            var confirmPurgeId by remember { mutableStateOf<String?>(null) }
            Text(
                "Deleted items are kept for 30 days, then removed automatically. Restore brings one back to its vault on every device; \"Delete forever\" removes it now.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            confirmPurgeId?.let { id ->
                AlertDialog(
                    onDismissRequest = { confirmPurgeId = null },
                    title = { Text("Delete forever?") },
                    text = { Text("This permanently removes the item and its history from every device. It can't be undone.") },
                    confirmButton = { TextButton(onClick = { vm.purgeDeleted(id); confirmPurgeId = null }) { Text("Delete forever", color = MaterialTheme.colorScheme.error) } },
                    dismissButton = { TextButton(onClick = { confirmPurgeId = null }) { Text("Keep") } },
                )
            }
            val deleted = ui.deletedItems
            when {
                deleted == null -> Text(if (ui.busy) "Loading…" else "", color = MaterialTheme.colorScheme.onSurfaceVariant)
                deleted.isEmpty() -> Text("Nothing here — deleted items you can recover will show up in this list.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                else -> deleted.forEach { d ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                d.doc?.name ?: "(unrecoverable — no readable version)",
                                style = MaterialTheme.typography.bodyLarge,
                                color = if (d.doc != null) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                "deleted ${java.time.Instant.ofEpochMilli(d.deletedAt).toString().take(10)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        val docToRestore = d.doc
                        if (docToRestore != null) {
                            TextButton(enabled = !ui.busy, onClick = { vm.restoreDeleted(d.itemId, d.vaultId, docToRestore) }) { Text("Restore") }
                        }
                        TextButton(enabled = !ui.busy, onClick = { confirmPurgeId = d.itemId }) {
                            Text("Delete forever", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContextCompat()
    var code by remember { mutableStateOf("") }
    BackHandler(onBack = vm::closeSettings) // back = the top-bar arrow, not "background the app"
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeSettings) { Icon(Icons.Default.ArrowBack, "back") } },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
            vm.identityCode()?.let { idCode ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("My identity code", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Someone sharing a vault with you will ask you to read this out (in person or by phone) before they send you the key.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(8.dp))
                        SelectionContainer {
                            Text(
                                idCode.chunked(4).joinToString(" "),
                                style = MaterialTheme.typography.titleMedium, fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Vault backup", style = MaterialTheme.typography.titleLarge)
                    Text(lastBackupLine(ui.lastExportAt), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (backupNudge(ui.lastExportAt)) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            if (ui.lastExportAt <= 0) {
                                "You've never backed up this vault — an offline backup is the only copy that survives losing the server and its backups."
                            } else {
                                "It's been over 90 days — consider taking a fresh backup."
                            },
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = vm::backupBegin, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Back up vault…") }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = vm::csvBegin, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Export for another password manager…") }
                }
            }
            Spacer(Modifier.height(16.dp))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Autofill", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Is autofill working? See what the last fill request looked like and why it did (or didn't) offer anything — screenshot-friendly.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = vm::openAutofillStatus, modifier = Modifier.fillMaxWidth()) { Text("Autofill status") }
                }
            }
            Spacer(Modifier.height(16.dp))
            ErrorBar(ui.error, vm::clearError)
            NoticeBar(ui.notice, vm::clearNotice)
            ExportDialogs(vm, ui)
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Server TOTP", style = MaterialTheme.typography.titleLarge)
                    Text("A second factor the server checks — protects break-glass/public logins.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(12.dp))
                    val status = ui.totpStatus
                    val setup = ui.totpSetup
                    when {
                        status == null -> {
                            if (ui.totpMessage != null) {
                                InlineError(ui.totpMessage)
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                    Spacer(Modifier.width(10.dp))
                                    Text("Checking status…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                        setup != null -> {
                            Text("Add this secret to your authenticator app, then confirm with a code.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            SelectableCopyRow("Setup URI (otpauth)", setup.otpauthUri, ctx)
                            SelectableCopyRow("Secret (base32)", setup.secretBase32, ctx)
                            Spacer(Modifier.height(4.dp))
                            Field("6-digit code", code, { code = it.filter { c -> c.isDigit() }.take(6) }, mono = true, keyboard = KeyboardType.Number)
                            InlineError(ui.totpMessage)
                            Spacer(Modifier.height(8.dp))
                            PrimaryButton("Confirm", enabled = code.length == 6 && !ui.busy, busy = ui.busy) { vm.totpConfirm(code); code = "" }
                        }
                        status.enrolled -> {
                            Text("Enrolled — one-time codes are active for this account.", style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.height(8.dp))
                            Field("6-digit code", code, { code = it.filter { c -> c.isDigit() }.take(6) }, mono = true, keyboard = KeyboardType.Number)
                            InlineError(ui.totpMessage)
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(
                                onClick = { vm.totpDisable(code); code = "" },
                                enabled = code.length == 6 && !ui.busy,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                            ) { Text("Disable") }
                        }
                        else -> {
                            Text(
                                if (status.pendingSetup) "A previous setup was never confirmed — enable to restart it." else "Not enrolled.",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            InlineError(ui.totpMessage)
                            Spacer(Modifier.height(8.dp))
                            PrimaryButton("Enable", enabled = !ui.busy, busy = ui.busy) { vm.totpBegin() }
                        }
                    }
                }
            }
        }
    }
}

// ---- export & backup (spec 07) ----

/** The spec 07 export dialogs + their SAF launchers (backup preflight → CreateDocument →
 *  build/verify/write/verify-on-disk; CSV preflight → CreateDocument → write/verify;
 *  backup success summary). The pending [BackupRequest] is stashed in the ViewModel —
 *  NOT `remember` — so a Fold unfold / rotation / split-screen resize while the SAF
 *  picker is foreground doesn't drop it (a `remember` came back null and the result
 *  no-op'd, leaving a silent empty file). */
@Composable
internal fun ExportDialogs(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContextCompat()

    // ---- backup (.andvari) ----
    val backupSaver = rememberLauncherForActivityResult(
        // MIME octet-stream is deliberate (spec 07 §2.6): a JSON MIME makes SAF mangle the
        // .andvari extension. Restore sniffs the magic bytes, never the extension.
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        // uri == null → picker cancelled; the request is dropped (take() below) and the
        // preflight dialog stays open for another go (re-confirming re-stashes it).
        val req = vm.backupRequestTake()
        when {
            uri == null -> {}
            req == null ->
                // Process death while the picker was foreground (ViewModel gone; the
                // passphrase is never persisted, so the flow cannot resume), or a
                // lock/sign-out cleared the stash: remove the created doc (empty-only)
                // and explain — never a silent 0-byte file.
                vm.backupRequestMissing { discardExportDoc(ctx, uri, writeBegan = false) }
            else -> vm.backupRun(
                req.vaults, req.includeAttachments, req.passphrase,
                write = { bytes -> openTruncated(ctx, uri).use { it.write(bytes) } },
                // On-disk verification read (spec 07 §2.6): bounded by the §2.2 256 MiB
                // open() cap — larger (a provider that kept a giant stale tail) reads
                // back null, which the ViewModel treats as verification failure.
                readBack = { ctx.contentResolver.openInputStream(uri)?.use { readBounded(it, EXPORT_READBACK_LIMIT) } },
                discard = { writeBegan -> discardExportDoc(ctx, uri, writeBegan) },
            )
        }
    }
    ui.backupPreflight?.let { pre ->
        BackupPreflightDialog(vm, ui, pre) { selected, includeAttachments, passphrase ->
            vm.backupRequestStash(BackupRequest(selected, includeAttachments, passphrase))
            backupSaver.launch("andvari-backup-${exportDateSuffix()}.andvari")
        }
    }
    ui.backupResult?.let { BackupResultDialog(it, vm::backupResultDismiss) }

    // ---- CSV ----
    val csvSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        if (uri != null) {
            vm.csvRun(
                write = { bytes -> openTruncated(ctx, uri).use { it.write(bytes) } },
                readBack = { ctx.contentResolver.openInputStream(uri)?.use { readBounded(it, EXPORT_READBACK_LIMIT) } },
                discard = { writeBegan -> discardExportDoc(ctx, uri, writeBegan) },
            )
        }
    }
    ui.csvPreflight?.let { pre ->
        CsvPreflightDialog(vm, ui, pre) { csvSaver.launch("andvari-export-${exportDateSuffix()}.csv") }
    }
}

/** Bound for the post-export verification read-back = the spec 07 §2.2 total-file cap.
 *  Anything larger on disk is by definition not the file we wrote. */
private const val EXPORT_READBACK_LIMIT = 256 * 1024 * 1024

/**
 * Open [uri] for writing with TRUNCATION ("wt"). Plain "w" ([android.content.ContentResolver.openOutputStream]'s
 * default) does NOT truncate on many DocumentsProviders, so overwriting a longer
 * pre-existing file would leave stale trailing bytes — a corrupt export. "wt" is the
 * documented truncate-on-open contract; SAF offers no channel-level truncate to force
 * the issue on a provider that rejects the mode, so those fall back to "w" and the
 * export paths rely on their on-disk read-back verification to refuse any
 * non-truncated result.
 */
private fun openTruncated(ctx: Context, uri: Uri): java.io.OutputStream =
    runCatching { ctx.contentResolver.openOutputStream(uri, "wt") }.getOrNull()
        ?: ctx.contentResolver.openOutputStream(uri)
        ?: throw IllegalStateException("could not open the chosen destination")

/**
 * Best-effort discard of an export destination — deleting ONLY bytes this run may own.
 * [writeBegan] = the write lambda ran (the destination was opened with truncation): its
 * content is now partial/corrupt, so deleting satisfies spec 07 §2.6 (never leave a
 * partial file). When the failure happened BEFORE any write, delete only if the doc is
 * still EMPTY: CreateDocument usually mints a fresh 0-byte doc (delete = clean abort),
 * but a user confirming an overwrite gets the PRE-EXISTING document back — deleting
 * that on a build/verify failure would turn one good backup into zero. Unknown size
 * (provider won't say) → leave it alone: a stray empty file beats a destroyed backup.
 */
private fun discardExportDoc(ctx: Context, uri: Uri, writeBegan: Boolean) {
    runCatching {
        if (writeBegan || documentSize(ctx, uri) == 0L) {
            DocumentsContract.deleteDocument(ctx.contentResolver, uri)
        }
    }
}

/** SIZE column of a document, or -1 when the provider won't report it. */
private fun documentSize(ctx: Context, uri: Uri): Long {
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            val i = c.getColumnIndex(OpenableColumns.SIZE)
            if (i >= 0 && !c.isNull(i)) return c.getLong(i)
        }
    }
    return -1L
}

@Composable
private fun BackupPreflightDialog(
    vm: AndvariViewModel,
    ui: UiState,
    pre: BackupPreflight,
    onChooseDestination: (Set<String>, Boolean, String) -> Unit,
) {
    var selected by remember(pre) { mutableStateOf(pre.vaults.map { it.vaultId }.toSet()) }
    var includeAttachments by remember(pre) { mutableStateOf(false) }
    var passphrase by remember(pre) { mutableStateOf("") }
    var confirm by remember(pre) { mutableStateOf("") }
    val plan = remember(pre, selected) { vm.attachmentPlan(selected) }
    val score = Strength.estimateStrength(passphrase)
    val ready = selected.isNotEmpty() && passphrase.isNotEmpty() && passphrase == confirm &&
        score >= Strength.BACKUP_FLOOR && !ui.busy
    AlertDialog(
        onDismissRequest = { if (!ui.busy) vm.backupDismiss() },
        confirmButton = {
            TextButton(onClick = { onChooseDestination(selected, includeAttachments, passphrase) }, enabled = ready) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = vm::backupDismiss, enabled = !ui.busy) { Text("Cancel") } },
        title = { Text("Back up vault") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                pre.offlineNote?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    "Exporting is private — other members and the server are not notified.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                pre.vaults.forEach { v ->
                    if (v.type == "personal") {
                        Text("• ${v.name} — ${v.itemCount} item(s), personal", style = MaterialTheme.typography.bodySmall)
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(v.vaultId in selected, { on -> selected = if (on) selected + v.vaultId else selected - v.vaultId })
                            Text("${v.name} — ${v.itemCount} item(s), shared (${v.role})", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(includeAttachments, { includeAttachments = it })
                    Text("Include attachments (${humanSize(plan.totalBytes)})", style = MaterialTheme.typography.bodySmall)
                }
                if (includeAttachments && plan.overCap.isNotEmpty()) {
                    Text("Skipped — over the 64 MiB total cap:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    plan.overCap.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                }
                Spacer(Modifier.height(8.dp))
                SecretField("Backup passphrase", passphrase) { passphrase = it }
                SecretField("Confirm passphrase", confirm) { confirm = it }
                if (passphrase.isNotEmpty()) {
                    val ok = score >= Strength.BACKUP_FLOOR
                    Text(
                        "Strength: ${Strength.label(score)}" + if (ok) "" else " — needs at least “good”",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (ok) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
                    )
                }
                if (confirm.isNotEmpty() && confirm != passphrase) {
                    Text("Passphrases don't match.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                if (passphrase.any { it.code > 127 }) {
                    Text(
                        "Heads-up: non-ASCII characters are used exactly as typed — you must type them identically to restore.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    "Tip: your master password is a fine choice — the backup is then exactly as protected as your vault. A different passphrase belongs on your printed recovery sheet.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

@Composable
private fun BackupResultDialog(r: BackupResult, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        confirmButton = { TextButton(onClick = onDone) { Text("Done") } },
        title = { Text("Backup saved") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Backed up ${r.items} item(s) across ${r.vaults} vault(s)" +
                        (if (r.attachments > 0) " with ${r.attachments} attachment(s)." else "."),
                    style = MaterialTheme.typography.bodySmall,
                )
                NamedSkips("Skipped (over the 64 MiB attachment cap):", r.attachmentsOverCap)
                NamedSkips("Skipped (download failed twice):", r.attachmentFetchFailed)
                Spacer(Modifier.height(8.dp))
                Text(
                    "If you change your master password later, this file still opens with the passphrase you just set.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Restore is for total server loss only — via the offline backup-cli today, in-app in a future release.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

@Composable
private fun CsvPreflightDialog(vm: AndvariViewModel, ui: UiState, pre: CsvPreflight, onChooseDestination: () -> Unit) {
    AlertDialog(
        onDismissRequest = { if (!ui.busy) vm.csvDismiss() },
        confirmButton = {
            TextButton(onClick = onChooseDestination, enabled = !ui.busy && pre.loginCount > 0) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = vm::csvDismiss, enabled = !ui.busy) { Text("Cancel") } },
        title = { Text("Export for another password manager?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                pre.offlineNote?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    "⚠ The CSV holds every password in PLAINTEXT. Anyone who reads the file reads your vault — and your Downloads folder may auto-sync to cloud storage. Delete it (and empty the trash) as soon as the other manager has imported it.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                )
                Spacer(Modifier.height(8.dp))
                Text("${pre.loginCount} login(s) will be written.", style = MaterialTheme.typography.bodySmall)
                NamedSkips("Not exported (secure notes):", pre.warnings.noteItems)
                NamedSkips("Cards can't go in a CSV — back up the vault to include them:", pre.warnings.cardItems)
                NamedSkips("Attachments can't be represented in CSV:", pre.warnings.withAttachments)
                NamedSkips("Only the first website is kept:", pre.warnings.extraUris)
                NamedSkips("Written, but a reimport would skip them (no username or password):", pre.warnings.emptyUsernameAndPassword)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Reimporting a CSV collapses exact duplicates.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

/** Named enumeration (spec 07 §1: by item name, never by count). Empty → renders nothing. */
@Composable
private fun NamedSkips(title: String, names: List<String>) {
    if (names.isEmpty()) return
    Spacer(Modifier.height(6.dp))
    Text(title, style = MaterialTheme.typography.bodySmall)
    names.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
}

private fun exportDateSuffix(): String =
    java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.ROOT).format(java.util.Date())

private fun lastBackupLine(lastExportAt: Long): String {
    if (lastExportAt <= 0) return "Last backup: never"
    return when (val days = ((System.currentTimeMillis() - lastExportAt) / 86_400_000L).toInt()) {
        0 -> "Last backup: today"
        1 -> "Last backup: yesterday"
        else -> "Last backup: $days days ago"
    }
}

private fun backupNudge(lastExportAt: Long): Boolean =
    lastExportAt <= 0 || System.currentTimeMillis() - lastExportAt > 90L * 86_400_000L

@Composable
private fun InlineError(msg: String?) {
    if (msg != null) Text(msg, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
}

/** Copy row for setup material (not vault secrets): selectable text, copy WITHOUT auto-clear. */
@Composable
private fun SelectableCopyRow(label: String, value: String, ctx: Context) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            SelectionContainer(Modifier.weight(1f)) {
                Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = { copyToClipboard(ctx, label, value, 0) }) { Text("Copy") }
        }
    }
}

// ---- small building blocks ----

@Composable private fun LocalContextCompat(): Context = androidx.compose.ui.platform.LocalContext.current

@Composable
private fun Field(label: String, value: String, onChange: (String) -> Unit, mono: Boolean = false, singleLine: Boolean = true, keyboard: KeyboardType = KeyboardType.Text) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = singleLine,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard),
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium)
}

@Composable
private fun SecretField(label: String, value: String, onChange: (String) -> Unit) {
    var show by remember { mutableStateOf(false) }
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = { IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) } })
}

@Composable
private fun CopyRow(label: String, value: String, ctx: Context, clearSeconds: Int) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            TextButton(onClick = { copyToClipboard(ctx, label, value, clearSeconds) }) { Text("Copy") }
        }
    }
}

/** [display] lets the reveal show a formatted view (e.g. a grouped card number) while Copy
 *  still carries the bare stored [value]. */
@Composable
private fun SecretCopyRow(label: String, value: String, ctx: Context, clearSeconds: Int, display: String = value) {
    var show by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (show) display else "••••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) }
            TextButton(onClick = { copyToClipboard(ctx, label, value, clearSeconds) }) { Text("Copy") }
        }
    }
}

/** Read-only expiry line with the "expired" marker — flagged strictly AFTER the last moment
 *  of the printed month (a card is good THROUGH it); absent/garbled halves never flag. */
@Composable
private fun ExpiryRow(label: String, expired: Boolean) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text("Expiry", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, fontFamily = FontFamily.Monospace)
            if (expired) {
                Spacer(Modifier.width(8.dp))
                Text("expired", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
private fun ReadOnlyRow(label: String, value: String) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value)
    }
}

@Composable
private fun ServerField(baseUrl: String, onSet: (String) -> Unit) {
    var url by remember(baseUrl) { mutableStateOf(baseUrl) }
    Column(Modifier.fillMaxWidth()) {
        OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("Server") }, singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            trailingIcon = { if (url != baseUrl) TextButton(onClick = { onSet(url) }) { Text("Set") } })
    }
}

@Composable
private fun PrimaryButton(text: String, enabled: Boolean, busy: Boolean, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) {
        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary) else Text(text)
    }
}

// ---- non-composable helpers ----

private const val DEFAULT_ATTACHMENT_MAX_BYTES = 25L * 1024 * 1024

private val attachmentJson = Json { ignoreUnknownKeys = true }

/** SavedState Saver for the editor's attachment list — JSON via the spec serializer so
 *  unknown-field extras survive the recreation round-trip too. Restore failures fall
 *  back to re-initialization (null) rather than crashing the restore. */
private val attachmentListSaver = listSaver<List<AttachmentRef>, String>(
    save = { list -> list.map { attachmentJson.encodeToString(AttachmentRef.serializer(), it) } },
    restore = { list -> runCatching { list.map { attachmentJson.decodeFromString(AttachmentRef.serializer(), it) } }.getOrNull() },
)

private fun needsUpdateLine(n: Int): String =
    if (n == 1) "1 item needs an app update to display." else "$n items need an app update to display."

private fun groupHex(hex: String): String = hex.chunked(4).joinToString(" ")

private fun humanSize(bytes: Long): String = when {
    bytes >= 1024L * 1024 * 1024 -> "%.1f GB".format(bytes / (1024.0 * 1024 * 1024))
    bytes >= 1024L * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024))
    bytes >= 1024L -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

private fun displayName(ctx: Context, uri: Uri): String {
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (i >= 0) c.getString(i)?.let { return it }
        }
    }
    return uri.lastPathSegment ?: "file"
}

private fun copyToClipboard(ctx: Context, label: String, value: String, clearSeconds: Int) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    // <=0 is reserved for NON-secret setup material (e.g. the TOTP setup URI) — no auto-clear.
    // Vault-secret call sites always pass max(1, policy.clipboardClearSeconds), mirroring web.
    if (clearSeconds <= 0) {
        cm.setPrimaryClip(ClipData.newPlainText(label, value))
        return
    }
    // Secret copy: EXTRA_IS_SENSITIVE keeps the value out of the Android 13+ clipboard
    // preview overlay (and tells sync'd clipboards to leave it alone).
    val clip = ClipData.newPlainText(label, value)
    clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    cm.setPrimaryClip(clip)
    // Auto-clear after the policy window — ONLY when we can confirm the clipboard still
    // holds OUR secret. On API 29+ a backgrounded read returns null (and a non-text clip
    // reads null even in foreground), so a null read means "can't verify ownership" — NOT
    // "still ours". Clearing on null would silently wipe whatever the user copied from
    // another app after pasting (a URL, a 2FA code, an image). For the background case the
    // real mitigation is EXTRA_IS_SENSITIVE (set above), which lets the OS auto-expire and
    // hide the value on Android 13+; on older versions the secret may linger until
    // overwritten — a platform limitation we cannot fix without clobbering user data.
    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
        val cur = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (cur == value) runCatching { cm.clearPrimaryClip() }
    }, clearSeconds * 1000L)
}
