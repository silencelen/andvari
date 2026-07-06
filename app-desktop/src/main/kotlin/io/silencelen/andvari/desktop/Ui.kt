package io.silencelen.andvari.desktop

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
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
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Base32
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.delay

@Composable
fun DesktopApp(state: DesktopState) {
    when (val s = state.screen) {
        is DesktopScreen.Loading -> Center { Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary) }
        is DesktopScreen.Welcome -> Welcome(state)
        is DesktopScreen.Unlock -> Unlock(state, s.email)
        is DesktopScreen.Vault -> Vault(state)
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
    Column(Modifier.fillMaxWidth()) {
        Field("Email", email, { email = it })
        Secret("Master password", password) { password = it }
        Spacer(Modifier.height(12.dp))
        Primary("Sign in", email.isNotBlank() && password.isNotBlank() && !state.busy, state.busy) { state.signIn(email.trim(), password) }
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
            IconButton(onClick = { state.refresh() }) { Icon(Icons.Default.Refresh, "sync") }
            IconButton(onClick = { state.lock() }) { Icon(Icons.Default.Lock, "lock") }
        }
        Divider()
        val current = detailId?.let { state.item(it) }
        when {
            editing != null -> Editor(editing!!.first, editing!!.second, state.busy, { state.saveItem(editing!!.first, it); editing = null }, { editing = null })
            current != null -> Detail(current, { editing = current.itemId to current.doc }, { state.deleteItem(current.itemId); detailId = null }, { detailId = null })
            else -> Column(Modifier.fillMaxSize().padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(query, { query = it }, Modifier.weight(1f), placeholder = { Text("Search vault…") }, singleLine = true, leadingIcon = { Icon(Icons.Default.Search, null) })
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { editing = null to ItemDoc(type = "login", name = "", login = LoginData(uris = listOf(""))) }) { Text("Add") }
                }
                ErrorBar(state.error, state::clearError)
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
private fun Detail(item: VaultItem, onEdit: () -> Unit, onDelete: () -> Unit, onBack: () -> Unit) {
    val doc = item.doc
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        Text(doc.name, style = MaterialTheme.typography.headlineMedium)
        Text(if (doc.type == "login") "Login" else "Secure note", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(16.dp))
        doc.login?.let { login ->
            login.username?.takeIf { it.isNotBlank() }?.let { CopyRow("Username", it, secret = false) }
            login.password?.takeIf { it.isNotBlank() }?.let { CopyRow("Password", it, secret = true) }
            login.totp?.takeIf { it.isNotBlank() }?.let { TotpRow(it) }
            login.uris.firstOrNull()?.takeIf { it.isNotBlank() }?.let { ReadOnly("Website", it) }
        }
        doc.notes?.takeIf { it.isNotBlank() }?.let { ReadOnly("Notes", it) }
        Spacer(Modifier.height(24.dp))
        androidx.compose.foundation.layout.Row {
            Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text("Edit") }
            Spacer(Modifier.width(12.dp))
            OutlinedButton(onClick = onDelete, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Delete") }
        }
    }
}

@Composable
private fun Editor(itemId: String?, initial: ItemDoc, busy: Boolean, onSave: (ItemDoc) -> Unit, onCancel: () -> Unit) {
    val isLogin = initial.type == "login"
    var name by remember { mutableStateOf(initial.name) }
    var username by remember { mutableStateOf(initial.login?.username ?: "") }
    var password by remember { mutableStateOf(initial.login?.password ?: "") }
    var website by remember { mutableStateOf(initial.login?.uris?.firstOrNull() ?: "") }
    var totp by remember { mutableStateOf(initial.login?.totp ?: "") }
    var notes by remember { mutableStateOf(initial.notes ?: "") }
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
        Spacer(Modifier.height(16.dp))
        val doc = ItemDoc(type = initial.type, name = name.trim(), notes = notes.ifBlank { null },
            login = if (isLogin) LoginData(username = username, password = password, uris = listOf(website), totp = totp.ifBlank { null }) else null)
        Primary("Save", name.isNotBlank() && !busy, busy) { onSave(doc) }
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

private fun normalizeTotp(input: String): String {
    val t = input.trim()
    if (t.isEmpty()) return ""
    if (t.startsWith("otpauth://", ignoreCase = true)) return t
    return runCatching { Base32.decode(t); "otpauth://totp/andvari?secret=${t.replace(" ", "")}" }.getOrDefault(t)
}
