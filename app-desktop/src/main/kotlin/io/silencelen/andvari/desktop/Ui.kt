package io.silencelen.andvari.desktop

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.TotpSetupResponse
import kotlinx.coroutines.delay
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.util.Locale

/** Fallback attachment cap when the server policy hasn't loaded (matches ClientPolicy's default). */
private const val DEFAULT_ATTACHMENT_MAX_BYTES = 25L * 1024 * 1024

@Composable
fun DesktopApp(state: DesktopState) {
    when (val s = state.screen) {
        is DesktopScreen.Loading -> Center { Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary) }
        is DesktopScreen.Welcome -> Welcome(state)
        is DesktopScreen.Unlock -> Unlock(state, s.email)
        is DesktopScreen.Vault -> Vault(state)
        is DesktopScreen.Settings -> SettingsScreen(state)
    }
}

@Composable
private fun Center(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally, content = content)

@Composable
private fun Sigil() {
    Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
    Text("andvari", style = MaterialTheme.typography.titleLarge)
    Text("the keeper of the hoard", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun ErrorBar(msg: String?, onDismiss: () -> Unit) {
    if (msg != null) Card(Modifier.fillMaxWidth().padding(vertical = 8.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(msg, Modifier.weight(1f), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onDismiss) { Text("dismiss") }
        }
    }
}

@Composable
private fun NoticeBar(msg: String?, onDismiss: () -> Unit) {
    if (msg != null) Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(msg, Modifier.weight(1f), color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall)
            TextButton(onClick = onDismiss) { Text("dismiss") }
        }
    }
}

@Composable
private fun Welcome(state: DesktopState) {
    var tab by remember { mutableStateOf(0) }
    Column(Modifier.fillMaxSize().padding(28.dp).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(24.dp)); Sigil(); Spacer(Modifier.height(20.dp))
        state.updateAvailable?.let { Text("Update available: $it", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall) }
        TabRow(selectedTabIndex = tab) {
            Tab(tab == 0, { tab = 0 }, text = { Text("Sign in") })
            Tab(tab == 1, { tab = 1 }, text = { Text("Enroll") })
        }
        Spacer(Modifier.height(16.dp))
        ErrorBar(state.error, state::clearError)
        if (tab == 0) SignIn(state) else Enroll(state)
        Spacer(Modifier.height(20.dp))
        ServerField(state.baseUrl, state::updateServer)
    }
}

@Composable
private fun SignIn(state: DesktopState) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var code by remember { mutableStateOf("") }
    Column(Modifier.fillMaxWidth()) {
        Field("Email", email, { email = it })
        Secret("Master password", password) { password = it }
        if (state.signInTotpRequired) {
            Field("One-time code", code, { code = it }, mono = true)
            Text("This account has server-TOTP enabled — enter a code from your authenticator.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(12.dp))
        val ready = email.isNotBlank() && password.isNotBlank() && (!state.signInTotpRequired || code.isNotBlank())
        Primary("Sign in", ready && !state.busy, state.busy) { state.signIn(email.trim(), password, code.trim().ifBlank { null }) }
    }
}

@Composable
private fun Enroll(state: DesktopState) {
    var invite by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var fpOk by remember { mutableStateOf(false) }
    val fp = state.policy?.recoveryFingerprint ?: ""
    val ready = invite.isNotBlank() && email.isNotBlank() && password.length >= 8 && password == confirm && fpOk && fp.isNotEmpty()
    Column(Modifier.fillMaxWidth()) {
        Field("Invite token", invite, { invite = it }, mono = true)
        Field("Email", email, { email = it })
        Field("Name (optional)", name, { name = it })
        Secret("Master password", password) { password = it }
        Secret("Confirm password", confirm) { confirm = it }
        if (fp.isEmpty()) {
            Text("This server has no recovery key configured yet — enrollment is disabled until the escrow ceremony is done.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 8.dp))
        } else {
            Spacer(Modifier.height(8.dp))
            Text("Recovery fingerprint", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(fp.chunked(4).joinToString(" "), fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall)
            Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                Checkbox(fpOk, { fpOk = it })
                Text("Matches my printed recovery sheet.", style = MaterialTheme.typography.bodySmall)
            }
        }
        Spacer(Modifier.height(12.dp))
        Primary("Create vault", ready && !state.busy, state.busy) { state.enroll(invite.trim(), email.trim(), name.trim(), password) }
    }
}

@Composable
private fun Unlock(state: DesktopState, email: String) {
    var password by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(28.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Sigil(); Spacer(Modifier.height(8.dp))
        Text(email, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(20.dp))
        ErrorBar(state.error, state::clearError)
        Secret("Master password", password) { password = it }
        Spacer(Modifier.height(12.dp))
        Primary("Unlock", password.isNotBlank() && !state.busy, state.busy) { state.unlock(email, password) }
        TextButton(onClick = state::signOut) { Text("Sign out / use a different account") }
    }
}

@Composable
private fun Vault(state: DesktopState) {
    var query by remember { mutableStateOf("") }
    var editing by remember { mutableStateOf<Pair<String?, ItemDoc>?>(null) }
    var detailId by remember { mutableStateOf<String?>(null) }
    val filtered = state.items.filter {
        val q = query.trim().lowercase()
        q.isEmpty() || it.doc.name.lowercase().contains(q) || (it.doc.login?.username ?: "").lowercase().contains(q)
    }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("andvari", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            IconButton(onClick = {
                val dialog = FileDialog(null as Frame?, "Import passwords CSV", FileDialog.LOAD)
                dialog.isVisible = true
                val dir = dialog.directory; val picked = dialog.file
                if (dir != null && picked != null) state.importFromFile(File(dir, picked))
            }) { Icon(Icons.Default.FileUpload, "import CSV") }
            IconButton(onClick = { state.openSettings() }) { Icon(Icons.Default.Settings, "settings") }
            IconButton(onClick = { state.refresh() }) { Icon(Icons.Default.Refresh, "sync") }
            IconButton(onClick = { state.lock() }) { Icon(Icons.Default.Lock, "lock") }
        }
        Divider()
        ImportDialogs(state)
        val current = detailId?.let { state.item(it) }
        when {
            editing != null -> Editor(
                itemId = editing!!.first, initial = editing!!.second, busy = state.busy,
                maxAttachmentBytes = state.policy?.attachmentMaxBytes ?: DEFAULT_ATTACHMENT_MAX_BYTES,
                newRef = state::newAttachmentRef,
                onSave = { doc, uploads -> state.saveItem(editing!!.first, doc, uploads); editing = null },
                onCancel = { editing = null },
            )
            current != null -> Detail(state, current, { editing = current.itemId to current.doc }, { state.deleteItem(current.itemId); detailId = null }, { detailId = null })
            else -> Column(Modifier.fillMaxSize().padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(query, { query = it }, Modifier.weight(1f), placeholder = { Text("Search vault…") }, singleLine = true, leadingIcon = { Icon(Icons.Default.Search, null) })
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { editing = null to ItemDoc(type = "login", name = "", login = LoginData(uris = listOf(""))) }) { Text("Add") }
                }
                ErrorBar(state.error, state::clearError)
                NoticeBar(state.notice, state::clearNotice)
                Spacer(Modifier.height(8.dp))
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    if (filtered.isEmpty()) {
                        Center { Spacer(Modifier.height(48.dp)); Text("ᛝ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary); Text(if (state.items.isEmpty()) "Your hoard is empty." else "Nothing matches.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    } else filtered.forEach { item -> Row(item) { detailId = item.itemId }; Spacer(Modifier.height(8.dp)) }
                }
            }
        }
    }
}

/** The three CSV-import dialogs (parse error → preview/confirm+progress+retry → done). */
@Composable
private fun ImportDialogs(state: DesktopState) {
    if (state.importError != null && state.importPlan == null && !state.importDone) {
        AlertDialog(
            onDismissRequest = { state.importDismiss() },
            confirmButton = { TextButton(onClick = { state.importDismiss() }) { Text("OK") } },
            title = { Text("Couldn’t import") },
            text = { Text(state.importError!!) },
        )
    }
    state.importPlan?.let { plan ->
        if (!state.importDone) {
            val report = plan.report
            AlertDialog(
                onDismissRequest = { if (!state.importBusy) state.importDismiss() },
                confirmButton = {
                    if (state.importError != null) {
                        TextButton(onClick = { state.importConfirm() }, enabled = !state.importBusy) { Text("Retry") }
                    } else {
                        TextButton(onClick = { state.importConfirm() }, enabled = !state.importBusy && report.imported > 0) { Text("Import ${report.imported}") }
                    }
                },
                dismissButton = { TextButton(onClick = { state.importDismiss() }, enabled = !state.importBusy) { Text("Cancel") } },
                title = { Text("Import passwords?") },
                text = {
                    Column {
                        Text(
                            "⚠ This file holds every password in plaintext. Nothing is uploaded — each login is encrypted on this device. Afterwards, delete the CSV and empty the trash. Re-importing the same file makes duplicates.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("From ${state.importFormat?.name?.lowercase() ?: "browser"} export:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("• ${report.imported} to import", style = MaterialTheme.typography.bodySmall)
                        if (report.collapsed > 0) Text("• ${report.collapsed} exact duplicates merged", style = MaterialTheme.typography.bodySmall)
                        if (report.flagged.isNotEmpty()) Text("• ${report.flagged.size} renamed (same site, different password)", style = MaterialTheme.typography.bodySmall)
                        if (report.skippedEmpty > 0) Text("• ${report.skippedEmpty} empty rows skipped", style = MaterialTheme.typography.bodySmall)
                        if (report.errors.isNotEmpty()) Text("• ${report.errors.size} rows skipped (parse errors)", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                        state.importProgress?.let { (done, total) ->
                            Spacer(Modifier.height(10.dp))
                            LinearProgressIndicator(progress = { if (total > 0) done.toFloat() / total else 0f }, modifier = Modifier.fillMaxWidth())
                            Text("Importing $done / $total", style = MaterialTheme.typography.bodySmall)
                        }
                        state.importError?.let { Spacer(Modifier.height(8.dp)); Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    }
                },
            )
        }
    }
    if (state.importDone) {
        AlertDialog(
            onDismissRequest = { state.importDismiss() },
            confirmButton = { TextButton(onClick = { state.importDismiss() }) { Text("Done") } },
            title = { Text("Imported") },
            text = { Text("Added ${state.importReport?.imported ?: 0} logins to your vault. Now delete the CSV file and empty your trash.") },
        )
    }
}

@Composable
private fun Row(item: VaultItem, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        androidx.compose.foundation.layout.Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text((item.doc.name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif, modifier = Modifier.padding(end = 12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.doc.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                Text(if (item.doc.type == "login") item.doc.login?.username?.ifBlank { "login" } ?: "login" else "secure note", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1)
            }
            Text(item.doc.type, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun Detail(state: DesktopState, item: VaultItem, onEdit: () -> Unit, onDelete: () -> Unit, onBack: () -> Unit) {
    val doc = item.doc
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        Text(doc.name, style = MaterialTheme.typography.headlineMedium)
        Text(if (doc.type == "login") "Login" else "Secure note", color = MaterialTheme.colorScheme.onSurfaceVariant)
        ErrorBar(state.error, state::clearError)
        NoticeBar(state.notice, state::clearNotice)
        Spacer(Modifier.height(16.dp))
        doc.login?.let { login ->
            login.username?.takeIf { it.isNotBlank() }?.let { CopyRow("Username", it, secret = false) }
            login.password?.takeIf { it.isNotBlank() }?.let { CopyRow("Password", it, secret = true) }
            login.totp?.takeIf { it.isNotBlank() }?.let { TotpRow(it) }
            login.uris.firstOrNull()?.takeIf { it.isNotBlank() }?.let { ReadOnly("Website", it) }
        }
        doc.notes?.takeIf { it.isNotBlank() }?.let { ReadOnly("Notes", it) }
        if (doc.attachments.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            doc.attachments.forEach { ref ->
                AttachmentLine(ref) {
                    TextButton(enabled = !state.busy, onClick = {
                        val dialog = FileDialog(null as Frame?, "Save attachment", FileDialog.SAVE)
                        dialog.file = ref.name
                        dialog.isVisible = true
                        val dir = dialog.directory; val file = dialog.file
                        if (dir != null && file != null) state.saveAttachmentTo(ref, File(dir, file))
                    }) { Text("Save") }
                }
            }
        }
        Spacer(Modifier.height(24.dp))
        androidx.compose.foundation.layout.Row {
            Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text("Edit") }
            Spacer(Modifier.width(12.dp))
            OutlinedButton(onClick = onDelete, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Delete") }
        }
    }
}

@Composable
private fun Editor(
    itemId: String?,
    initial: ItemDoc,
    busy: Boolean,
    maxAttachmentBytes: Long,
    newRef: (String, Long) -> AttachmentRef,
    onSave: (ItemDoc, List<PendingUpload>) -> Unit,
    onCancel: () -> Unit,
) {
    val isLogin = initial.type == "login"
    var name by remember { mutableStateOf(initial.name) }
    var username by remember { mutableStateOf(initial.login?.username ?: "") }
    var password by remember { mutableStateOf(initial.login?.password ?: "") }
    var website by remember { mutableStateOf(initial.login?.uris?.firstOrNull() ?: "") }
    var totp by remember { mutableStateOf(initial.login?.totp ?: "") }
    var notes by remember { mutableStateOf(initial.notes ?: "") }
    var attachments by remember { mutableStateOf(initial.attachments) }
    var pending by remember { mutableStateOf(listOf<PendingUpload>()) }
    var attachError by remember { mutableStateOf<String?>(null) }
    val crypto = remember { createCryptoProvider() }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onCancel) { Text("cancel") }
        Text(if (itemId != null) "Edit" else if (isLogin) "New login" else "New note", style = MaterialTheme.typography.headlineMedium)
        Field("Name", name, { name = it })
        if (isLogin) {
            Field("Username", username, { username = it }, mono = true)
            Secret("Password", password) { password = it }
            TextButton(onClick = { password = PasswordGenerator.generate(crypto, GeneratorOptions(length = 20)) }) { Icon(Icons.Default.Refresh, null); Text(" Generate") }
            Field("Website", website, { website = it })
            Field("TOTP (otpauth:// or base32)", totp, { totp = normalizeTotp(it) }, mono = true)
        }
        Field("Notes", notes, { notes = it }, singleLine = false)
        Spacer(Modifier.height(8.dp))
        Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        attachments.forEach { ref ->
            AttachmentLine(ref) {
                TextButton(onClick = {
                    attachments = attachments.filterNot { it.id == ref.id }
                    pending = pending.filterNot { it.ref.id == ref.id }
                }) { Text("Remove", color = MaterialTheme.colorScheme.error) }
            }
        }
        attachError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        TextButton(onClick = {
            attachError = null
            val dialog = FileDialog(null as Frame?, "Attach file", FileDialog.LOAD)
            dialog.isVisible = true
            val dir = dialog.directory; val picked = dialog.file
            if (dir != null && picked != null) {
                val bytes = runCatching { File(dir, picked).readBytes() }.getOrElse { attachError = "Couldn't read $picked: ${it.message}"; return@TextButton }
                when {
                    bytes.isEmpty() -> attachError = "$picked is empty — nothing to attach."
                    bytes.size > maxAttachmentBytes -> attachError = "$picked is ${humanSize(bytes.size.toLong())} — over the ${humanSize(maxAttachmentBytes)} attachment limit."
                    else -> {
                        val ref = newRef(picked, bytes.size.toLong())
                        pending = pending + PendingUpload(ref, bytes)
                        attachments = attachments + ref
                    }
                }
            }
        }) { Icon(Icons.Default.AttachFile, null); Text(" Attach file") }
        Spacer(Modifier.height(16.dp))
        val doc = ItemDoc(type = initial.type, name = name.trim(), notes = notes.ifBlank { null }, favorite = initial.favorite,
            login = if (isLogin) LoginData(username = username, password = password, uris = listOf(website), totp = totp.ifBlank { null }) else null,
            attachments = attachments)
        Primary("Save", name.isNotBlank() && !busy, busy) { onSave(doc, pending) }
    }
}

/** One attachment row: name + human size on the left, an action slot on the right. */
@Composable
private fun AttachmentLine(ref: AttachmentRef, action: @Composable () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Default.AttachFile, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(8.dp))
        Column(Modifier.weight(1f)) {
            Text(ref.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
            Text(humanSize(ref.size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        action()
    }
}

@Composable
private fun TotpRow(uri: String) {
    val crypto = remember { createCryptoProvider() }
    var code by remember { mutableStateOf("······") }
    var remaining by remember { mutableStateOf(30) }
    LaunchedEffect(uri) {
        val cfg = runCatching { Totp.parseUri(uri) }.getOrNull()
        if (cfg == null) { code = "invalid"; return@LaunchedEffect }
        while (true) {
            val now = System.currentTimeMillis() / 1000
            code = Totp.code(crypto, cfg, now); remaining = Totp.secondsRemaining(cfg, now)
            delay(1000)
        }
    }
    Column(Modifier.padding(vertical = 8.dp)) {
        Text("One-time code", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { copyWithAutoClear(code) }) { Text(code.chunked(3).joinToString(" "), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.secondary) }
            Text("${remaining}s", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ---- settings / server TOTP ----

@Composable
private fun SettingsScreen(state: DesktopState) {
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = state::closeSettings) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        Text("Settings", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(16.dp))
        state.identityCode()?.let { idCode ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("My identity code", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Someone sharing a vault with you will ask you to read this out (in person or by phone) before they send you the key.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    SelectionContainer {
                        Text(idCode.chunked(4).joinToString(" "), style = MaterialTheme.typography.titleMedium, fontFamily = FontFamily.Monospace)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
        }
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text("Server TOTP", style = MaterialTheme.typography.titleLarge)
                Text("A second factor the server checks at sign-in — protects break-glass/public logins.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(12.dp))
                val status = state.totpStatus
                val setup = state.totpSetupInfo
                when {
                    setup != null -> TotpSetupBlock(state, setup)
                    status == null -> Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Checking…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        state.totpError?.let { Spacer(Modifier.width(8.dp)); Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    }
                    status.enrolled -> TotpEnrolledBlock(state)
                    else -> {
                        Text("Not enrolled.", style = MaterialTheme.typography.bodyMedium)
                        if (status.pendingSetup) Text("A setup was started but never confirmed — Enable starts fresh.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        state.totpError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                        Spacer(Modifier.height(8.dp))
                        Button(onClick = state::beginTotpSetup, enabled = !state.busy) { Text("Enable") }
                    }
                }
            }
        }
    }
}

@Composable
private fun TotpSetupBlock(state: DesktopState, setup: TotpSetupResponse) {
    var code by remember { mutableStateOf("") }
    Column {
        Text("Add it to your authenticator (URI or secret), then confirm with a code.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        CopyPlainRow("otpauth URI", setup.otpauthUri)
        CopyPlainRow("Secret (base32)", setup.secretBase32)
        Field("One-time code", code, { code = it }, mono = true)
        state.totpError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.height(8.dp))
        Primary("Confirm", code.isNotBlank() && !state.busy, state.busy) { state.confirmTotp(code) }
    }
}

@Composable
private fun TotpEnrolledBlock(state: DesktopState) {
    var code by remember { mutableStateOf("") }
    Column {
        Text("Enrolled.", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodyMedium)
        Text("To turn it off, enter a current code from your authenticator.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Field("One-time code", code, { code = it }, mono = true)
        state.totpError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = { state.disableTotp(code); code = "" }, enabled = code.isNotBlank() && !state.busy,
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Disable") }
    }
}

/** Selectable value + plain copy (no auto-clear — this is setup material, not a vault secret). */
@Composable
private fun CopyPlainRow(label: String, value: String) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            SelectionContainer(Modifier.weight(1f)) {
                Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = { copyPlain(value) }) { Text("Copy") }
        }
    }
}

// ---- building blocks ----
@Composable
private fun Field(label: String, value: String, onChange: (String) -> Unit, mono: Boolean = false, singleLine: Boolean = true) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = singleLine,
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium)
}

@Composable
private fun Secret(label: String, value: String, onChange: (String) -> Unit) {
    var show by remember { mutableStateOf(false) }
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = { IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) } })
}

@Composable
private fun CopyRow(label: String, value: String, secret: Boolean) {
    var show by remember { mutableStateOf(!secret) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (show) value else "••••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            if (secret) IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) }
            TextButton(onClick = { copyWithAutoClear(value) }) { Text("Copy") }
        }
    }
}

@Composable
private fun ReadOnly(label: String, value: String) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value)
    }
}

@Composable
private fun ServerField(baseUrl: String, onSet: (String) -> Unit) {
    var url by remember(baseUrl) { mutableStateOf(baseUrl) }
    OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("Server") }, singleLine = true,
        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = { if (url != baseUrl) TextButton(onClick = { onSet(url) }) { Text("Set") } })
}

@Composable
private fun Primary(text: String, enabled: Boolean, busy: Boolean, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) {
        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary) else Text(text)
    }
}

private fun humanSize(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var v = bytes.toDouble()
    var i = -1
    while (v >= 1024 && i < units.lastIndex) { v /= 1024; i++ }
    return String.format(Locale.ROOT, "%.1f %s", v, units[i])
}

private fun normalizeTotp(input: String): String {
    val t = input.trim()
    if (t.isEmpty()) return ""
    if (t.startsWith("otpauth://", ignoreCase = true)) return t
    return runCatching { Base32.decode(t); "otpauth://totp/andvari?secret=${t.replace(" ", "")}" }.getOrDefault(t)
}
