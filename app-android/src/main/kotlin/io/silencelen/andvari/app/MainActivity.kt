package io.silencelen.andvari.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val vm: AndvariViewModel by viewModels {
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T =
                AndvariViewModel(SessionStore(applicationContext)) as T
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // If the previous run crashed, show the captured trace instead of re-running the
        // (possibly still-crashing) startup path, so it can be screenshotted.
        val crashFile = java.io.File(filesDir, AndvariApplication.CRASH_FILE)
        if (crashFile.exists()) {
            val text = runCatching { crashFile.readText() }.getOrDefault("(crash file unreadable)")
            setContent { AndvariTheme { CrashScreen(text) { crashFile.delete(); recreate() } } }
            return
        }
        vm.start()
        setContent { AndvariTheme { AndvariApp(vm) } }
    }
}

@Composable
private fun CrashScreen(text: String, onClear: () -> Unit) {
    Surface(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            Text("andvari hit an error", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
            Text("Screenshot the text below and send it, then tap Clear & retry.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(12.dp))
            SelectionContainer(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                Text(text, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
            Spacer(Modifier.height(12.dp))
            Button(onClick = onClear, modifier = Modifier.fillMaxWidth()) { Text("Clear & retry") }
        }
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
            is Screen.Settings -> SettingsScreen(vm, ui)
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
private fun ErrorBar(msg: String?, onDismiss: () -> Unit) {
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
private fun NoticeBar(msg: String?, onDismiss: () -> Unit) {
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
    var tab by remember { mutableStateOf(0) }
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
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var totp by remember { mutableStateOf("") }
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
    var invite by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var fpOk by remember { mutableStateOf(false) }
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
    var query by remember { mutableStateOf("") }
    var editing by remember { mutableStateOf<Pair<String?, ItemDoc>?>(null) }
    var detailId by remember { mutableStateOf<String?>(null) }

    val filtered = ui.items.filter {
        val q = query.trim().lowercase()
        q.isEmpty() || it.doc.name.lowercase().contains(q) || (it.doc.login?.username ?: "").lowercase().contains(q)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("andvari", style = MaterialTheme.typography.titleLarge) },
                actions = {
                    IconButton(onClick = { vm.refresh() }) { Icon(Icons.Default.Refresh, "sync") }
                    IconButton(onClick = { vm.openSettings() }) { Icon(Icons.Default.Settings, "settings") }
                    IconButton(onClick = { vm.lock() }) { Icon(Icons.Default.Lock, "lock") }
                },
            )
        },
        floatingActionButton = {
            if (editing == null && detailId == null) {
                ExtendedFloatingActionButton(onClick = { editing = null to ItemDoc(type = "login", name = "", login = LoginData(uris = listOf(""))) }, text = { Text("Add") }, icon = { Icon(Icons.Default.Add, null) })
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            val current = detailId?.let { vm.item(it) }
            when {
                editing != null -> ItemEditor(vm, ui, editing!!.first, editing!!.second, onSave = { doc, uploads -> vm.saveItem(editing!!.first, doc, uploads) { editing = null } }, onCancel = { editing = null })
                current != null -> ItemDetail(vm, ui, current, onEdit = { editing = current.itemId to current.doc }, onDelete = { vm.deleteItem(current.itemId); detailId = null }, onBack = { detailId = null })
                else -> Column(Modifier.padding(16.dp)) {
                    OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search vault…") }, singleLine = true, leadingIcon = { Icon(Icons.Default.Search, null) })
                    ErrorBar(ui.error, vm::clearError)
                    Spacer(Modifier.height(8.dp))
                    if (filtered.isEmpty()) {
                        Centered { Spacer(Modifier.height(60.dp)); Text("ᛝ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary); Text(if (ui.items.isEmpty()) "Your hoard is empty." else "Nothing matches.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    } else {
                        filtered.forEach { item -> VaultRow(item) { detailId = item.itemId }; Spacer(Modifier.height(8.dp)) }
                    }
                }
            }
        }
    }
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
                Text(if (item.doc.type == "login") item.doc.login?.username?.ifBlank { "login" } ?: "login" else "secure note", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
            }
            Text(item.doc.type, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ItemDetail(vm: AndvariViewModel, ui: UiState, item: VaultItem, onEdit: () -> Unit, onDelete: () -> Unit, onBack: () -> Unit) {
    val ctx = LocalContextCompat()
    val doc = item.doc
    var pendingDownload by remember { mutableStateOf<AttachmentRef?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val ref = pendingDownload
        pendingDownload = null
        if (uri != null && ref != null) {
            vm.saveAttachmentTo(ref) { bytes ->
                ctx.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
                    ?: throw IllegalStateException("could not open the chosen destination")
            }
        }
    }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        ErrorBar(ui.error, vm::clearError)
        NoticeBar(ui.notice, vm::clearNotice)
        Text(doc.name, style = MaterialTheme.typography.headlineMedium)
        Text(if (doc.type == "login") "Login" else "Secure note", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(16.dp))
        doc.login?.let { login ->
            login.username?.takeIf { it.isNotBlank() }?.let { CopyRow("Username", it, ctx) }
            login.password?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Password", it, ctx) }
            login.totp?.takeIf { it.isNotBlank() }?.let { TotpRow(it, ctx) }
            login.uris.firstOrNull()?.takeIf { it.isNotBlank() }?.let { ReadOnlyRow("Website", it) }
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
        Spacer(Modifier.height(24.dp))
        Row {
            Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text("Edit") }
            Spacer(Modifier.width(12.dp))
            OutlinedButton(onClick = onDelete, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Delete") }
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
    var name by remember { mutableStateOf(initial.name) }
    var username by remember { mutableStateOf(initial.login?.username ?: "") }
    var password by remember { mutableStateOf(initial.login?.password ?: "") }
    var website by remember { mutableStateOf(initial.login?.uris?.firstOrNull() ?: "") }
    var totp by remember { mutableStateOf(initial.login?.totp ?: "") }
    var notes by remember { mutableStateOf(initial.notes ?: "") }
    var attachments by remember { mutableStateOf(initial.attachments) }
    val pendingUploads = remember { mutableStateListOf<PendingUpload>() }
    var attachError by remember { mutableStateOf<String?>(null) }
    val crypto = remember { createCryptoProvider() }
    val scope = rememberCoroutineScope()

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            attachError = null
            val cap = ui.policy?.attachmentMaxBytes ?: DEFAULT_ATTACHMENT_MAX_BYTES
            runCatching {
                withContext(Dispatchers.IO) {
                    val fileName = displayName(ctx, uri)
                    val bytes = ctx.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("could not read the selected file")
                    fileName to bytes
                }
            }.onSuccess { (fileName, bytes) ->
                when {
                    bytes.isEmpty() -> attachError = "“$fileName” is empty — nothing to attach."
                    bytes.size > cap -> attachError = "“$fileName” is ${humanSize(bytes.size.toLong())} — over the ${humanSize(cap)} limit."
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
        Text(if (itemId != null) "Edit" else if (isLogin) "New login" else "New note", style = MaterialTheme.typography.headlineMedium)
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
            Field("TOTP (otpauth:// or base32)", totp, { totp = normalizeTotp(it) }, mono = true)
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
        val doc = ItemDoc(
            type = initial.type, name = name.trim(), notes = notes.ifBlank { null },
            login = if (isLogin) LoginData(username = username, password = password, uris = listOf(website), totp = totp.ifBlank { null }) else null,
            attachments = attachments,
        )
        PrimaryButton("Save", enabled = name.isNotBlank() && !ui.busy, busy = ui.busy) { onSave(doc, pendingUploads.toList()) }
    }
}

// ---- TOTP live row ----
@Composable
private fun TotpRow(uri: String, ctx: Context) {
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
            TextButton(onClick = { copyToClipboard(ctx, "code", code, 30) }) {
                Text(code.chunked(3).joinToString(" "), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.secondary)
            }
            Text("${remaining}s", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ---- settings / server TOTP ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContextCompat()
    var code by remember { mutableStateOf("") }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeSettings) { Icon(Icons.Default.ArrowBack, "back") } },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
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
private fun CopyRow(label: String, value: String, ctx: Context) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            TextButton(onClick = { copyToClipboard(ctx, label, value, 30) }) { Text("Copy") }
        }
    }
}

@Composable
private fun SecretCopyRow(label: String, value: String, ctx: Context) {
    var show by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (show) value else "••••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) }
            TextButton(onClick = { copyToClipboard(ctx, label, value, 30) }) { Text("Copy") }
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

private fun normalizeTotp(input: String): String {
    val t = input.trim()
    if (t.isEmpty()) return ""
    if (t.startsWith("otpauth://", ignoreCase = true)) return t
    return runCatching { io.silencelen.andvari.core.crypto.Base32.decode(t); "otpauth://totp/andvari?secret=${t.replace(" ", "")}" }.getOrDefault(t)
}

private fun copyToClipboard(ctx: Context, label: String, value: String, clearSeconds: Int) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText(label, value))
    if (clearSeconds <= 0) return // non-secret material (e.g. TOTP setup URI) — no auto-clear
    // Best-effort auto-clear after the policy window.
    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
        val cur = cm.primaryClip?.getItemAt(0)?.text?.toString()
        if (cur == value) cm.setPrimaryClip(ClipData.newPlainText("", ""))
    }, clearSeconds * 1000L)
}
