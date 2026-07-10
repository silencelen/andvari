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
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.BackupPreflight
import io.silencelen.andvari.core.client.BackupResult
import io.silencelen.andvari.core.client.CsvPreflight
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.crypto.Escrow
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
    // A 426 blocks everything: this build is too old for the server's minVersion pin.
    state.upgradeRequired?.let { msg ->
        Center {
            Sigil()
            Spacer(Modifier.height(16.dp))
            Text("Update required", style = MaterialTheme.typography.titleMedium)
            Text(msg, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center, modifier = Modifier.widthIn(max = 380.dp).padding(top = 8.dp))
            Text(downloadsUrl(state.baseUrl), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 8.dp))
        }
        return
    }
    Column(Modifier.fillMaxSize()) {
        // A found update is a soft nudge — a thin bar above whatever screen is showing, so
        // a signed-in user (who never sees the Welcome screen) actually learns about it.
        state.updateAvailable?.let { v ->
            Surface(color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.fillMaxWidth()) {
                Text(
                    "Version $v is available — download from ${downloadsUrl(state.baseUrl)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                )
            }
        }
        // F58: an admin recovery left a TEMPORARY master password live on this account.
        // Deliberately non-dismissable (the web mustChange banner idiom) and rendered at the
        // root, above every screen, so no view change escapes it. Desktop can't change the
        // password yet (native screen deferred) — direct to the web app, which can.
        if (state.mustChangePassword) {
            Surface(color = MaterialTheme.colorScheme.errorContainer, modifier = Modifier.fillMaxWidth()) {
                Text(
                    "Recovery sign-in — set a new master password now. This app can't change it yet: open ${state.baseUrl} in your browser and use Settings → Change master password.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                )
            }
        }
        Box(Modifier.weight(1f)) {
            when (val s = state.screen) {
                is DesktopScreen.Loading -> Center { Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary) }
                is DesktopScreen.Welcome -> Welcome(state)
                is DesktopScreen.Unlock -> Unlock(state, s.email)
                is DesktopScreen.Vault -> Vault(state)
                is DesktopScreen.Settings -> SettingsScreen(state)
                is DesktopScreen.Trash -> TrashScreen(state)
            }
        }
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

/**
 * F57: after a recovery-key re-ceremony this account's escrow is sealed to the DEAD key. Offer to
 * re-seal to the current key — but only after the user TYPES the new recovery fingerprint from their
 * PRINTED sheet (spec 04 §2(3): the fingerprint is deliberately NOT displayed, so a compromised
 * server can't win a lazy eyeball-match). DesktopState.resealEscrow binds the fetched pubkey to that
 * verified fingerprint and refuses on mismatch. Non-blocking: "Later" leaves it for the next unlock.
 */
@Composable
private fun ReSealCard(state: DesktopState) {
    var open by remember { mutableStateOf(false) }
    var entry by remember { mutableStateOf("") }
    val ok = Escrow.shortFormMatches(entry, state.escrowFingerprint)
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
                    Primary("Re-protect account", ok && !state.busy, state.busy) { state.resealEscrow(entry) }
                    Spacer(Modifier.width(8.dp))
                    TextButton(onClick = { open = false }) { Text("Later") }
                }
            }
        }
    }
}

@Composable
private fun Welcome(state: DesktopState) {
    var tab by remember { mutableStateOf(0) }
    Column(Modifier.fillMaxSize().padding(28.dp).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(24.dp)); Sigil(); Spacer(Modifier.height(20.dp))
        // (update banner now renders once at the app root, above every screen)
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
    val ready = email.isNotBlank() && password.isNotBlank() && (!state.signInTotpRequired || code.isNotBlank())
    // F72: THE submit path — button and every field's Enter land here; the gate makes a
    // held/double Enter (or Enter while incomplete) a no-op.
    val submit = { if (ready && !state.busy) state.signIn(email.trim(), password, code.trim().ifBlank { null }) }
    Column(Modifier.fillMaxWidth()) {
        Field("Email", email, { email = it }, onEnter = submit)
        Secret("Master password", password, onEnter = submit) { password = it }
        if (state.signInTotpRequired) {
            Field("One-time code", code, { code = it }, mono = true, onEnter = submit)
            Text("This account has server-TOTP enabled — enter a code from your authenticator.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(12.dp))
        Primary("Sign in", ready && !state.busy, state.busy, submit)
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
    // F72: single gated submit — Enter can't create a vault before the fingerprint box is ticked.
    val submit = { if (ready && !state.busy) state.enroll(invite.trim(), email.trim(), name.trim(), password) }
    Column(Modifier.fillMaxWidth()) {
        Field("Invite token", invite, { invite = it }, mono = true, onEnter = submit)
        Field("Email", email, { email = it }, onEnter = submit)
        Field("Name (optional)", name, { name = it }, onEnter = submit)
        Secret("Master password", password, onEnter = submit) { password = it }
        Secret("Confirm password", confirm, onEnter = submit) { confirm = it }
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
        Primary("Create vault", ready && !state.busy, state.busy, submit)
    }
}

@Composable
private fun Unlock(state: DesktopState, email: String) {
    var password by remember { mutableStateOf("") }
    // F72: Enter in the password field = Unlock (the most-repeated interaction in the app).
    // The handler lives on the FIELD, so Tab→Enter on "Sign out" below still signs out.
    val submit = { if (password.isNotBlank() && !state.busy) state.unlock(email, password) }
    Column(Modifier.fillMaxSize().padding(28.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Sigil(); Spacer(Modifier.height(8.dp))
        Text(email, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(20.dp))
        ErrorBar(state.error, state::clearError)
        Secret("Master password", password, onEnter = submit) { password = it }
        Spacer(Modifier.height(12.dp))
        Primary("Unlock", password.isNotBlank() && !state.busy, state.busy, submit)
        TextButton(onClick = state::signOut) { Text("Sign out / use a different account") }
    }
}

@Composable
private fun Vault(state: DesktopState) {
    var query by remember { mutableStateOf("") }
    var editing by remember { mutableStateOf<Pair<String?, ItemDoc>?>(null) }
    var detailId by remember { mutableStateOf<String?>(null) }
    var importFlow by remember { mutableStateOf(false) } // the guided source-picker steps
    val filtered = state.items.filter {
        val q = query.trim().lowercase()
        // F79: name + username + EVERY uri + notes + a card's brand/••last4 (never secrets),
        // matching the web predicate — so a 2nd-website login, a note's body, and a card by
        // "visa" all match, not just name+username.
        val d = it.doc
        q.isEmpty() ||
            d.name.lowercase().contains(q) ||
            (d.notes ?: "").lowercase().contains(q) ||
            (d.login?.username ?: "").lowercase().contains(q) ||
            (d.login?.uris ?: emptyList()).any { u -> u.lowercase().contains(q) } ||
            (d.type == "card" && CardDisplay.subtitle(d).lowercase().contains(q))
    }
    // F81: decrypted names for held vaults OTHER than the personal one — the gold badge on
    // rows/detail. Each lookup decrypts vault metaBlobs, so build the map once per items-change
    // (sync/refresh replace `items`), never per row recomposition (search keystrokes recompose).
    val vaultBadges = remember(state.items) { state.sharedVaultNames() }
    // F18: the new-item picker's writable-vault choices (personal + owner/writer shared). Each
    // choice decrypts vault metadata, so — like vaultBadges — recompute only when the item set
    // changes (sync/refresh replace `items`), never per search keystroke.
    val newItemVaultChoices = remember(state.items) { state.newItemVaultChoices() }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("andvari", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            IconButton(onClick = { importFlow = true }) { Icon(Icons.Default.FileUpload, "import passwords") }
            IconButton(onClick = { state.openTrash() }) { Icon(Icons.Default.Delete, "trash") }
            IconButton(onClick = { state.openSettings() }) { Icon(Icons.Default.Settings, "settings") }
            IconButton(onClick = { state.refresh() }) { Icon(Icons.Default.Refresh, "sync") }
            IconButton(onClick = { state.lock() }) { Icon(Icons.Default.Lock, "lock") }
        }
        Divider()
        if (importFlow) {
            ImportSourceFlow(onDismiss = { importFlow = false }) { file, src ->
                importFlow = false
                state.importFromFile(file, src)
            }
        }
        ImportDialogs(state)
        val current = detailId?.let { state.item(it) }
        when {
            editing != null -> Editor(
                itemId = editing!!.first, initial = editing!!.second, busy = state.busy,
                // F71: the editor renders the save error INLINE and shows upload progress —
                // it must stay open (typed fields + picked attachments intact) until the
                // save actually resolves.
                error = state.saveError,
                onErrorDismiss = state::clearSaveError,
                saveProgress = state.saveProgress,
                maxAttachmentBytes = state.policy?.attachmentMaxBytes ?: DEFAULT_ATTACHMENT_MAX_BYTES,
                newRef = state::newAttachmentRef,
                // F18: offer the vault picker ONLY for a NEW item (existing items never move
                // vaults) and ONLY when a writable SHARED vault exists — a personal-only user
                // never sees it (mirrors web's `selected === null && hasWritableShared`). Read
                // once per editor open (each choice decrypts vault metadata).
                vaultChoices = if (editing!!.first == null)
                    newItemVaultChoices.takeIf { c -> c.any { it.type != "personal" } }
                else null,
                // F71: close ONLY via saveItem's success callback (the Android op{}+onSaved
                // contract) — the old `saveItem(...); editing = null` closed optimistically
                // and a failed save/upload discarded everything typed.
                onSave = { doc, uploads, vaultId -> state.saveItem(editing!!.first, doc, uploads, vaultId) { state.endEditorSession(); editing = null } },
                onCancel = { state.endEditorSession(); editing = null },
            )
            current != null -> Detail(state, current, vaultBadges[current.vaultId], { editing = current.itemId to current.doc }, { state.deleteItem(current.itemId); detailId = null }, { detailId = null })
            else -> Column(Modifier.fillMaxSize().padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(query, { query = it }, Modifier.weight(1f), placeholder = { Text("Search vault…") }, singleLine = true, leadingIcon = { Icon(Icons.Default.Search, null) })
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { editing = null to ItemDoc(type = "login", name = "", login = LoginData(uris = listOf(""))) }) { Text("Add") }
                    // F81: notes are mintable on desktop too — the same blank ItemDoc mint as
                    // web's startNew("note"); the Editor already branches on doc.type ("New
                    // note": name + notes + attachments only) and builtDoc copies from it.
                    Spacer(Modifier.width(8.dp))
                    Button(onClick = { editing = null to ItemDoc(type = "note", name = "", notes = null) }) { Text("Add note") }
                    // Card creation stays dark until the Option A gate clears (the fielded 0.2.x
                    // MSI is retired) — the flip list lives in the cards design doc. Everything
                    // downstream (row/detail/editor/history for EXISTING cards) renders regardless.
                    if (CardDisplay.CREATE_ENABLED) {
                        Spacer(Modifier.width(8.dp))
                        Button(onClick = { editing = null to ItemDoc(type = "card", name = "", card = CardData()) }) { Text("Add card") }
                    }
                }
                ErrorBar(state.error, state::clearError)
                NoticeBar(state.notice, state::clearNotice)
                if (state.escrowStale && state.escrowFingerprint.isNotEmpty()) ReSealCard(state)
                if (state.needsUpdateCount > 0) {
                    Text(needsUpdateLine(state.needsUpdateCount), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 4.dp))
                }
                Spacer(Modifier.height(8.dp))
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    if (filtered.isEmpty()) {
                        Center { Spacer(Modifier.height(48.dp)); Text("ᛝ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary); Text(if (state.items.isEmpty()) "Your hoard is empty." else "Nothing matches.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    } else filtered.forEach { item -> Row(item, vaultBadges[item.vaultId]) { detailId = item.itemId }; Spacer(Modifier.height(8.dp)) }
                }
            }
        }
    }
}

/**
 * Guided import, steps 1–2 (design 2026-07-09): pick the source → 2–4 numbered export
 * steps → the AWT file dialog (the house file-pick mechanism — same family as the
 * attachment/backup pickers). The pick informs instructions and the preview's mismatch
 * hint ONLY — header detection stays authoritative, so a Bitwarden file picked under
 * "Chrome" still imports as Bitwarden (with a calm note). Keyboard-first: every entry is
 * a focusable button, so Tab/Enter walks the whole flow.
 */
@Composable
private fun ImportSourceFlow(onDismiss: () -> Unit, onFile: (File, ImportSource) -> Unit) {
    var source by remember { mutableStateOf<ImportSource?>(null) }
    val s = source
    if (s == null) {
        AlertDialog(
            onDismissRequest = onDismiss,
            confirmButton = {},
            dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
            title = { Text("Import passwords") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text("Where is your export from?", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(4.dp))
                    ImportSource.entries.forEach { src ->
                        TextButton(onClick = { source = src }, modifier = Modifier.fillMaxWidth()) {
                            Text(src.label, Modifier.fillMaxWidth())
                        }
                    }
                    Text(
                        "Picked wrong? No harm — the file itself decides how it’s read.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
        )
    } else {
        AlertDialog(
            onDismissRequest = onDismiss,
            confirmButton = {
                TextButton(onClick = {
                    val dialog = FileDialog(null as Frame?, "Import passwords CSV", FileDialog.LOAD)
                    dialog.isVisible = true
                    val dir = dialog.directory; val picked = dialog.file
                    // Cancelled picker → the instructions stay open for another go.
                    if (dir != null && picked != null) onFile(File(dir, picked), s)
                }) { Text("Choose file…") }
            },
            dismissButton = {
                androidx.compose.foundation.layout.Row {
                    TextButton(onClick = { source = null }) { Text("My file is from somewhere else") }
                    TextButton(onClick = onDismiss) { Text("Cancel") }
                }
            },
            title = { Text("Export from ${s.label}") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    s.steps.forEachIndexed { i, step ->
                        Text("${i + 1}. $step", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                    }
                }
            },
        )
    }
}

/** The three import dialogs (refusal/parse error → preview/confirm+progress+retry → done). */
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
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Text(
                            "⚠ This file holds every password in plaintext. Nothing is uploaded — each item is encrypted on this device. Afterwards, delete the CSV and empty the trash.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                        )
                        val fmt = state.importFormat
                        val src = state.importSource
                        // Calm mismatch hint: the pick was only a guide — the header decided.
                        if (fmt != null && src != null && fmt.name !in src.expectedFormats) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "This file looks like a ${formatLabel(fmt)} export, not ${src.label} — importing it as ${formatLabel(fmt)}.",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary,
                            )
                        }
                        // A10: HTML-entity mangle hint (in-page LastPass exports) — never auto-decoded.
                        if (state.importMangled) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "Several values look HTML-mangled (things like &amp; instead of &) — re-export choosing the file download (LastPass: Advanced Options → Export). Importing as-is keeps the mangled text.",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary,
                            )
                        }
                        // S2: destination picker — the F18 choice rule (personal + owner/writer
                        // shared, never reader) via newItemVaultChoices, shown only when there's
                        // >1 choice. Selecting RE-PLANS against that vault: every count/bucket
                        // below re-derives, so the picker AND Confirm are importBusy-disabled
                        // until the fresh plan lands. Read once per preview open (each choice
                        // decrypts vault metadata; the list must not shift under the dialog).
                        val vaultChoices = remember { state.newItemVaultChoices() }
                        if (vaultChoices.size > 1) {
                            Spacer(Modifier.height(8.dp))
                            VaultPicker("Import into", vaultChoices, state.importVaultId, enabled = !state.importBusy) { state.importSetVault(it) }
                        }
                        Spacer(Modifier.height(8.dp))
                        Text("From ${fmt?.let { formatLabel(it) } ?: "password"} export:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Text("• ${report.imported} to import", style = MaterialTheme.typography.bodySmall)
                        if (report.collapsed > 0) Text("• ${report.collapsed} exact duplicates in the file merged", style = MaterialTheme.typography.bodySmall)
                        // Kind-neutral (A1): skippedEmpty also counts empty NOTE rows, which never had credentials.
                        if (report.skippedEmpty > 0) Text("• ${report.skippedEmpty} empty row${if (report.skippedEmpty == 1) "" else "s"} skipped", style = MaterialTheme.typography.bodySmall)
                        ImportBucket("Imported as secure notes", report.noteItems)
                        ImportBucket("Already in your vault — skipped", report.alreadyInVault)
                        // A9: rule-2 copy splits password-differs from 2FA-differs.
                        ImportBucket("Password differs from your vault — imported separately; review which is current", report.passwordDiffers)
                        ImportBucket("2FA secret differs from your vault — imported separately", report.totpDiffers)
                        ImportBucket("Renamed — the name was already taken", report.flagged)
                        ImportBucket("Archived in the export — not imported", report.archivedSkipped)
                        ImportBucket("Unsupported item type — skipped", report.unknownTypeSkipped)
                        ImportBucket("2FA secret not usable — kept as text in the item’s notes", report.totpUnsupported)
                        ImportBucket("Rows that couldn’t be read", report.errors.map { rowErrorLine(it, state.importRowOrdinals) }, error = true)
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
        val report = state.importReport
        val notes = report?.noteItems?.size ?: 0
        // S2: the summary names the DESTINATION vault — "your vault" hid which vault the
        // rows landed in. Resolved once (decrypts metadata); fallback keeps the old copy.
        val destName = remember(state.importVaultId) {
            state.newItemVaultChoices().find { it.vaultId == state.importVaultId }?.let { vaultChoiceLabel(it) }
        }
        AlertDialog(
            onDismissRequest = { state.importDismiss() },
            confirmButton = { TextButton(onClick = { state.importDismiss() }) { Text("Done") } },
            title = { Text("Imported") },
            text = {
                Text(
                    "Added ${report?.imported ?: 0} item(s) to ${destName ?: "your vault"}" +
                        (if (notes > 0) " ($notes as secure notes)" else "") +
                        ". Now delete the CSV file and empty your trash.",
                )
            },
        )
    }
}

/** One named report bucket: "$title (n):" + the names — enumerate BY NAME, never bare
 *  counts (house rule) — collapsed past six with a keyboard-reachable "Show all". */
@Composable
private fun ImportBucket(title: String, names: List<String>, error: Boolean = false) {
    if (names.isEmpty()) return
    var expanded by remember(names) { mutableStateOf(false) }
    val tint = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant
    Spacer(Modifier.height(6.dp))
    Text("$title (${names.size}):", style = MaterialTheme.typography.bodySmall, color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
    // "Show all" is capped: this Column is non-lazy, and a mass-mangled import can put
    // thousands of rows in the error bucket — composing them all in one frame is a freeze.
    val shown = when {
        names.size <= 6 -> names
        expanded -> names.take(BUCKET_EXPAND_CAP)
        else -> names.take(5)
    }
    shown.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = tint) }
    if (!expanded && names.size > 6) TextButton(onClick = { expanded = true }) { Text("Show all ${names.size}") }
    if (expanded && names.size > BUCKET_EXPAND_CAP) {
        Text("(showing the first $BUCKET_EXPAND_CAP of ${names.size})", style = MaterialTheme.typography.bodySmall, color = tint)
    }
}

/** Non-lazy dialog enumerations stop here — past this, composition itself is the bottleneck. */
private const val BUCKET_EXPAND_CAP = 100

/**
 * Display names keyed on ImportFormat.name STRINGS — the three new core constants land in
 * a parallel workstream and "1password" can't be a Kotlin identifier, so this file doesn't
 * hard-reference a guessed spelling (an unknown constant degrades to its lowercase name).
 */
private fun formatLabel(f: CsvImport.ImportFormat): String = when (f.name) {
    "CHROME" -> "Chrome/Chromium"
    "FIREFOX" -> "Firefox"
    "BITWARDEN" -> "Bitwarden"
    "ONEPASSWORD", "ONE_PASSWORD" -> "1Password"
    "LASTPASS" -> "LastPass"
    else -> f.name.lowercase()
}

/** A9: "row N (file line M)" — a multi-line quoted note makes the physical line unmatchable
 *  to the row a spreadsheet shows, so lead with the data-row ordinal (core's
 *  [CsvImport.rowOrdinalsByLine], the same reader parse uses). Falls back to the file line
 *  alone if an error line somehow isn't in the map. */
private fun rowErrorLine(e: CsvImport.RowError, ordinals: Map<Int, Int>): String {
    val where = ordinals[e.line]?.let { "row $it (file line ${e.line})" } ?: "file line ${e.line}"
    return "$where — " + when (e.code) {
        "wrong_field_count" -> "wrong number of columns"
        "bad_quote" -> "unclosed quote"
        else -> e.code
    }
}

@Composable
private fun Row(item: VaultItem, vaultBadge: String? = null, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        androidx.compose.foundation.layout.Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text((item.doc.name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif, modifier = Modifier.padding(end = 12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.doc.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                Text(
                    when (item.doc.type) {
                        "login" -> item.doc.login?.username?.ifBlank { "login" } ?: "login"
                        // "Visa ••4242" — brand + last4 identify the card, never the full PAN.
                        "card" -> CardDisplay.subtitle(item.doc)
                        else -> "secure note"
                    },
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                )
            }
            // F81: shared-vault badge — the decrypted vault name in gold (primary = treasury
            // gold), the same labelSmall tag style as the type tag beside it. Personal = none.
            // Width-capped so a long vault name can't squeeze out the item name column.
            if (vaultBadge != null) {
                Text(vaultBadge, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary,
                    maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 140.dp).padding(end = 8.dp))
            }
            Text(item.doc.type, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * Item undelete (feature): "Recently deleted" — the tombstoned items the user can recover. Each is
 * named from its last archived version (a tombstone's own blob is null); Restore re-creates it live
 * via the dedicated route (clean un-tombstone). Attachments are not restored (blobs gone at delete).
 * Mirrors the web Trash view.
 */
@Composable
private fun TrashScreen(state: DesktopState) {
    var confirmPurgeId by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = { state.closeTrash() }) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        Text("Recently deleted", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Deleted items are kept for 30 days, then removed automatically. Restore brings one back to its vault on every device; \"Delete forever\" removes it now.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        ErrorBar(state.error, state::clearError)
        NoticeBar(state.notice, state::clearNotice)
        Spacer(Modifier.height(12.dp))
        val deleted = state.deletedItems
        when {
            deleted == null -> Text(if (state.busy) "Loading…" else "", color = MaterialTheme.colorScheme.onSurfaceVariant)
            deleted.isEmpty() -> Text("Nothing here — deleted items you can recover will show up in this list.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            else -> deleted.forEach { d ->
                androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            d.doc?.name ?: "(unrecoverable — no readable version)",
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
                        TextButton(enabled = !state.busy, onClick = { state.restoreDeleted(d.itemId, d.vaultId, docToRestore) }) { Text("Restore") }
                    }
                    TextButton(enabled = !state.busy, onClick = { confirmPurgeId = d.itemId }) {
                        Text("Delete forever", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
    confirmPurgeId?.let { id ->
        AlertDialog(
            onDismissRequest = { confirmPurgeId = null },
            title = { Text("Delete forever?") },
            text = { Text("This permanently removes the item and its history from every device. It can't be undone.") },
            confirmButton = { TextButton(onClick = { state.purgeDeleted(id); confirmPurgeId = null }) { Text("Delete forever", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmPurgeId = null }) { Text("Keep") } },
        )
    }
}

/**
 * Item history & restore (feature: "the fat-finger seatbelt"). Loads the archived versions the
 * server keeps (up to the last 10), decrypts each under the held VK, and offers per-version reveal
 * + Restore (a plain put over the live item). Readers view but can't restore. "up to the last 10
 * saves" — never "nothing is ever lost" (spec 02 §7). Mirrors the deployed web panel.
 */
@Composable
private fun ItemHistorySection(state: DesktopState, item: VaultItem, readOnly: Boolean, onRestored: () -> Unit) {
    var open by remember(item.itemId) { mutableStateOf(false) }
    if (!open) {
        TextButton(onClick = { open = true; state.loadItemVersions(item.itemId, item.vaultId) }) { Text("Version history") }
        return
    }
    Text("Version history · up to the last 10 saves", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    val versions = state.itemVersions
    when {
        versions == null -> Text(if (state.busy) "Loading…" else "", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        versions.isEmpty() -> Text("No earlier versions yet — history starts from the next change.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        else -> versions.forEach { v ->
            var revealed by remember(v.rev) { mutableStateOf(false) }
            androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
                Text(java.time.Instant.ofEpochMilli(v.archivedAt).toString().take(10), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(96.dp))
                val pw = v.doc.login?.password
                Text(
                    when {
                        // Card versions identify by brand + ••last4 (no reveal here — web parity);
                        // Restore below works on them like any other doc.
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
                if (!readOnly) TextButton(onClick = { state.saveItem(item.itemId, v.doc) { onRestored() } }) { Text("Restore") }
            }
        }
    }
    TextButton(onClick = { open = false; state.clearItemVersions() }) { Text("Hide history") }
}

@Composable
private fun Detail(state: DesktopState, item: VaultItem, vaultBadge: String?, onEdit: () -> Unit, onDelete: () -> Unit, onBack: () -> Unit) {
    val doc = item.doc
    // Reader-role members get no Edit/Delete affordances (mirrors web): the push would be
    // denied server-side and the denied mutation's typed work destroyed.
    val readOnly = state.roleFor(item.vaultId) == "reader"
    // Vault-secret copies clear after the org policy window, clamped to >=1 s exactly like
    // web's useCopy (Math.max(1, n)): a policy of 0 still clears — never "keep forever" for
    // secrets. 30 s fallback while the policy hasn't loaded (matches web).
    val clipClear = maxOf(1, state.policy?.clipboardClearSeconds ?: 30)
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        Text(doc.name, style = MaterialTheme.typography.headlineMedium)
        // Cards identify themselves by brand + ••last4 (design contract) — the one line that
        // lets the user pick the right card without revealing the full PAN.
        val kindLine = when {
            doc.type == "login" -> "Login"
            doc.type == "card" -> if (doc.card?.number.isNullOrEmpty()) "Card" else CardDisplay.subtitle(doc)
            else -> "Secure note"
        }
        Text(kindLine + (if (readOnly) " · view only" else ""), color = MaterialTheme.colorScheme.onSurfaceVariant)
        // F81: which SHARED vault this item lives in — gold, mirroring the row badge (personal
        // items get no line; "yours" is the default that needs no label).
        if (vaultBadge != null) {
            Text(vaultBadge, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 2.dp))
        }
        ErrorBar(state.error, state::clearError)
        NoticeBar(state.notice, state::clearNotice)
        Spacer(Modifier.height(16.dp))
        doc.login?.let { login ->
            login.username?.takeIf { it.isNotBlank() }?.let { CopyRow("Username", it, secret = false, clearSeconds = clipClear) }
            login.password?.takeIf { it.isNotBlank() }?.let { CopyRow("Password", it, secret = true, clearSeconds = clipClear) }
            login.totp?.takeIf { it.isNotBlank() }?.let { TotpRow(it, clearSeconds = clipClear) }
            login.uris.firstOrNull()?.takeIf { it.isNotBlank() }?.let { ReadOnly("Website", it) }
        }
        if (doc.type == "card") doc.card?.let { card ->
            card.cardholderName?.takeIf { it.isNotBlank() }?.let { CopyRow("Cardholder", it, secret = false, clearSeconds = clipClear) }
            // Reveal shows the grouped form; Copy hands checkout forms the bare digits (web parity).
            card.number?.takeIf { it.isNotBlank() }?.let { CopyRow("Card number", it, secret = true, clearSeconds = clipClear, display = CardDisplay.groupNumber(it)) }
            CardDisplay.expiryLabel(card)?.let { exp ->
                Column(Modifier.padding(vertical = 6.dp)) {
                    Text("Expiry", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(exp, fontFamily = FontFamily.Monospace)
                        val today = java.time.LocalDate.now()
                        if (CardDisplay.isExpired(card.expMonth, card.expYear, today.year, today.monthValue)) {
                            Spacer(Modifier.width(8.dp))
                            Text("expired", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
            card.securityCode?.takeIf { it.isNotBlank() }?.let { CopyRow("Security code", it, secret = true, clearSeconds = clipClear) }
        }
        doc.notes?.takeIf { it.isNotBlank() }?.let { ReadOnly("Notes", it) }
        if (doc.attachments.isNotEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val overwrite = remember { OverwriteGate() } // F71: XAWT SAVE never asks before replacing
            OverwriteConfirmDialog(overwrite)
            doc.attachments.forEach { ref ->
                AttachmentLine(ref) {
                    TextButton(enabled = !state.busy, onClick = {
                        val dialog = FileDialog(null as Frame?, "Save attachment", FileDialog.SAVE)
                        dialog.file = ref.name
                        dialog.isVisible = true
                        val dir = dialog.directory; val file = dialog.file
                        if (dir != null && file != null) {
                            val dest = File(dir, file)
                            overwrite.request(dest) { state.saveAttachmentTo(ref, dest) }
                        }
                    }) { Text("Save") }
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        ItemHistorySection(state, item, readOnly, onRestored = onBack)
        Spacer(Modifier.height(24.dp))
        if (!readOnly) {
            var confirmDelete by remember { mutableStateOf(false) }
            androidx.compose.foundation.layout.Row {
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
            // F19: move/copy into another writable vault (mirrors web + Android). Only for a
            // writer/owner of the SOURCE — a reader's delete leg would be denied anyway, and
            // this whole block is already gated on !readOnly. Each choice decrypts vault meta,
            // so read once per item shown.
            val writable = remember(item.itemId) { state.newItemVaultChoices() }
            val moveTargets = writable.filter { it.vaultId != item.vaultId }
            if (moveTargets.isNotEmpty()) {
                val sourceName = writable.find { it.vaultId == item.vaultId }?.name ?: "this vault"
                MoveCopyControl(state, item, moveTargets, sourceName, onMoved = onBack)
            }
        }
    }
}

/**
 * F19 (design §8): move or copy this item into another vault. All gesture safety lives in core
 * [SyncEngine.runGesture] via [DesktopState.moveOrCopyItem] (copy-leg-first, confirmed before any
 * delete; a retry reuses the SAME gesture so server dedup converges — never duplicates; a denied
 * copy or a changed source aborts with the source untouched). This composable is only the picker:
 * mode → target dropdown → Move/Copy, with the inline error + Retry from [DesktopState.moveError].
 * Escape cancels (F72 idiom). onMoved (→ back to the list) fires only on success.
 */
@Composable
private fun MoveCopyControl(state: DesktopState, item: VaultItem, targets: List<VaultInfo>, sourceName: String, onMoved: () -> Unit) {
    var mode by remember(item.itemId) { mutableStateOf<String?>(null) } // "move" | "copy" | null
    var target by remember(item.itemId) { mutableStateOf(targets.firstOrNull()?.vaultId ?: "") }
    if (mode == null) {
        androidx.compose.foundation.layout.Row(Modifier.padding(top = 6.dp)) {
            // Entering a mode discards any stale inline error/gesture from the other mode.
            TextButton(onClick = { state.clearMoveState(item.itemId); mode = "move" }) { Text("Move to vault…") }
            Spacer(Modifier.width(8.dp))
            TextButton(onClick = { state.clearMoveState(item.itemId); mode = "copy" }) { Text("Copy to vault…") }
        }
        return
    }
    val cancel = { state.clearMoveState(item.itemId); mode = null }
    val moveError = state.moveError
    val progress = state.moveProgress
    Column(Modifier.fillMaxWidth().padding(top = 12.dp).dismissOnEscape(cancel)) {
        Text(if (mode == "move") "Move to another vault" else "Copy to another vault", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        moveError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        if (mode == "move") {
            Text("Members of “$sourceName” may still have copies from before the move.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(bottom = 4.dp))
        }
        androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
            VaultPicker(null, targets, target, enabled = !state.busy) { target = it }
            Spacer(Modifier.width(8.dp))
            Button(enabled = !state.busy && target.isNotEmpty(), onClick = {
                // onMoved leaves the detail on success only; a failure sets moveError + (for a
                // transient one) keeps the gesture so this same button reads "Retry".
                state.moveOrCopyItem(item.itemId, target, move = mode == "move") { mode = null; onMoved() }
            }) {
                Text(when {
                    state.busy && progress != null && progress.second > 0 -> "Copying… ${progress.first}/${progress.second}"
                    state.busy -> "Working…"
                    moveError != null -> "Retry"
                    mode == "move" -> "Move"
                    else -> "Copy"
                })
            }
            Spacer(Modifier.width(8.dp))
            TextButton(enabled = !state.busy, onClick = cancel) { Text("Cancel") }
        }
    }
}

/**
 * A held-vault dropdown (F18 new-item picker + F19 move/copy target). [label] shows a small
 * caption above (null = inline, no caption). Compose's [DropdownMenu] handles Escape/outside-
 * click dismissal itself, so it's keyboard-reachable and dismissable out of the box.
 */
@Composable
private fun VaultPicker(label: String?, choices: List<VaultInfo>, selected: String?, enabled: Boolean = true, onSelect: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val current = choices.find { it.vaultId == selected } ?: choices.firstOrNull()
    Column(Modifier.padding(vertical = 4.dp)) {
        if (label != null) Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Box {
            OutlinedButton(onClick = { open = true }, enabled = enabled) {
                Text(current?.let { vaultChoiceLabel(it) } ?: "Choose a vault")
                Icon(Icons.Default.ArrowDropDown, null)
            }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                choices.forEach { v ->
                    DropdownMenuItem(text = { Text(vaultChoiceLabel(v)) }, onClick = { onSelect(v.vaultId); open = false })
                }
            }
        }
    }
}

/** "Name" for personal, "Name (shared)" otherwise — matches the web picker/option copy. */
private fun vaultChoiceLabel(v: VaultInfo): String = v.name + if (v.type == "personal") "" else " (shared)"

@Composable
private fun Editor(
    itemId: String?,
    initial: ItemDoc,
    busy: Boolean,
    error: String?,
    onErrorDismiss: () -> Unit,
    saveProgress: Pair<Int, Int>?,
    maxAttachmentBytes: Long,
    newRef: (String, Long) -> AttachmentRef,
    vaultChoices: List<VaultInfo>? = null,
    onSave: (ItemDoc, List<PendingUpload>, String?) -> Unit,
    onCancel: () -> Unit,
) {
    // F18: which vault a NEW item is created in. Non-null only for new items with a writable
    // shared vault (see the call site); default = the first choice, which is personal
    // (vaultInfos is personal-first). Threaded into onSave → saveItem's vaultId.
    var vaultId by remember { mutableStateOf(vaultChoices?.firstOrNull()?.vaultId) }
    val isLogin = initial.type == "login"
    val isCard = initial.type == "card"
    var name by remember { mutableStateOf(initial.name) }
    var username by remember { mutableStateOf(initial.login?.username ?: "") }
    var password by remember { mutableStateOf(initial.login?.password ?: "") }
    var website by remember { mutableStateOf(initial.login?.uris?.firstOrNull() ?: "") }
    var totp by remember { mutableStateOf(initial.login?.totp ?: "") }
    var cardholder by remember { mutableStateOf(initial.card?.cardholderName ?: "") }
    var cardNumber by remember { mutableStateOf(initial.card?.number ?: "") }
    var expMonth by remember { mutableStateOf(initial.card?.expMonth ?: "") }
    var expYear by remember { mutableStateOf(initial.card?.expYear ?: "") }
    var securityCode by remember { mutableStateOf(initial.card?.securityCode ?: "") }
    var notes by remember { mutableStateOf(initial.notes ?: "") }
    var attachments by remember { mutableStateOf(initial.attachments) }
    var pending by remember { mutableStateOf(listOf<PendingUpload>()) }
    var attachError by remember { mutableStateOf<String?>(null) }
    var totpError by remember { mutableStateOf<String?>(null) }
    val crypto = remember { createCryptoProvider() }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        // Busy-gated like every other dialog's Cancel here: a mid-save click would unmount
        // the editor and destroy the very draft F71 keeps alive for the retry.
        TextButton(onClick = onCancel, enabled = !busy) { Text("cancel") }
        Text(if (itemId != null) "Edit" else if (isLogin) "New login" else if (isCard) "New card" else "New note", style = MaterialTheme.typography.headlineMedium)
        // F18: shown only when there's a choice to make (>1 writable vault). A single-vault
        // user's new item lands in Personal exactly as before — no picker.
        if (vaultChoices != null && vaultChoices.size > 1) {
            VaultPicker("Vault", vaultChoices, vaultId) { vaultId = it }
        }
        Field("Name", name, { name = it })
        if (isLogin) {
            Field("Username", username, { username = it }, mono = true)
            Secret("Password", password) { password = it }
            TextButton(onClick = { password = PasswordGenerator.generate(crypto, GeneratorOptions(length = 20)) }) { Icon(Icons.Default.Refresh, null); Text(" Generate") }
            Field("Website", website, { website = it })
            // RAW text while typing — normalizeTotp per keystroke rewrote the field to an
            // otpauth:// URI on the first character and the clamped cursor then garbled all
            // further typing. Normalization + validation happen once, on Save.
            Field("TOTP (otpauth:// or base32)", totp, { totp = it; totpError = null }, mono = true)
            totpError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        }
        if (isCard) {
            // Live signals off the RAW typed number (separators and all — digits-only happens
            // once, in builtDoc, the TOTP idiom): decisive-prefix brand label in the field
            // label, and a Luhn line that WARNS once a plausible PAN length is present but
            // never blocks Save — storing what the user typed beats rejecting an odd-but-real
            // number.
            val cardDigits = CardNormalize.digitsOnly(cardNumber)
            val cardBrand = CardDisplay.brandLabel(CardNormalize.brand(cardDigits))
            Field("Cardholder name", cardholder, { cardholder = it })
            Field(if (cardBrand != null) "Card number · $cardBrand" else "Card number", cardNumber, { cardNumber = it }, mono = true)
            if (cardDigits.length >= 12 && !CardNormalize.luhnValid(cardDigits)) {
                Text("this number doesn’t pass the usual check — you can still save it", color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
            }
            // Free-typed expiry (keyboard-first, unlike web's selects): padMonth/yearTo4 accept
            // "1" and "27" and normalize at save; a half that can't be read is stored absent,
            // so warn (never block) while it doesn't parse.
            androidx.compose.foundation.layout.Row(Modifier.fillMaxWidth()) {
                OutlinedTextField(expMonth, { expMonth = it }, Modifier.weight(1f).padding(vertical = 4.dp), label = { Text("Expiry month (MM)") }, singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
                Spacer(Modifier.width(8.dp))
                OutlinedTextField(expYear, { expYear = it }, Modifier.weight(1f).padding(vertical = 4.dp), label = { Text("Expiry year (YYYY)") }, singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
            }
            if ((expMonth.isNotBlank() && CardNormalize.padMonth(expMonth) == null) || (expYear.isNotBlank() && CardNormalize.yearTo4(expYear) == null)) {
                Text("expiry wants a month 1–12 and a 2- or 4-digit year — a part that can’t be read won’t be saved", color = MaterialTheme.colorScheme.tertiary, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
            }
            // Masked-with-reveal (unlike the login password's plain field): a CVV is glanceable-
            // short and worth shielding from shoulders by default. Digits-only at save.
            Secret("Security code (optional — stored encrypted like everything else)", securityCode) { securityCode = it }
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
        // copy()-based edit, never a field-by-field rebuild: carries favorite, passwordHistory,
        // extra URIs beyond the first, and unknown-field extras (spec 02 §3) through the save.
        // Card values normalize ONCE here (web submit parity): digits-only number/CVV, padded
        // month, 4-digit year (a half that doesn't parse is stored absent), and brand ALWAYS
        // recomputed from the number — display-only, never authored, so it can never go stale.
        // CardData.copy preserves its @Transient extras (the house rule vs the 0.2.x rebuild bug).
        fun builtDoc(totpValue: String) = initial.copy(name = name.trim(), notes = notes.ifBlank { null },
            login = if (isLogin) (initial.login ?: LoginData()).copy(
                username = username, password = password,
                uris = buildList { if (website.isNotBlank()) add(website); addAll(initial.login?.uris.orEmpty().drop(1)) },
                totp = totpValue.ifBlank { null },
            ) else null,
            card = if (isCard) (initial.card ?: CardData()).copy(
                cardholderName = cardholder.trim().ifEmpty { null },
                number = CardNormalize.digitsOnly(cardNumber).ifEmpty { null },
                expMonth = CardNormalize.padMonth(expMonth),
                expYear = CardNormalize.yearTo4(expYear),
                securityCode = CardNormalize.digitsOnly(securityCode).ifEmpty { null },
                brand = CardNormalize.brand(cardNumber),
            ) else initial.card,
            attachments = attachments)
        // F71: a failed save lands its error HERE, beside the Save it belongs to — the
        // editor stays open with everything typed still editable; per-upload progress
        // shows while `busy` disables Save.
        ErrorBar(error, onErrorDismiss)
        saveProgress?.let { (done, total) ->
            Text("Uploading attachment $done of $total…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 4.dp))
        }
        Primary("Save", name.isNotBlank() && !busy, busy) {
            // A5: ONE shared byte-exact TOTP normalize — core Totp.normalize (the private
            // copy this file carried is deleted). Blank stays blank (stored null by builtDoc).
            val normalizedTotp = if (isLogin && totp.isNotBlank()) Totp.normalize(totp) else ""
            if (isLogin && totp.isNotBlank() && runCatching { Totp.parseUri(normalizedTotp) }.isFailure) {
                totpError = "TOTP secret isn't valid base32 or an otpauth:// link"
            } else {
                onSave(builtDoc(normalizedTotp), pending, vaultId)
            }
        }
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
private fun TotpRow(uri: String, clearSeconds: Int) {
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
            TextButton(onClick = { copyWithAutoClear(code, clearSeconds) }) { Text(code.chunked(3).joinToString(" "), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.secondary) }
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
                Text("Vault backup", style = MaterialTheme.typography.titleLarge)
                Text(lastBackupLine(state.lastExportAt), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (backupNudge(state.lastExportAt)) {
                    Spacer(Modifier.height(4.dp))
                    Text(
                        if (state.lastExportAt <= 0) {
                            "You've never backed up this vault — an offline backup is the only copy that survives losing the server and its backups."
                        } else {
                            "It's been over 90 days — consider taking a fresh backup."
                        },
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(12.dp))
                Button(onClick = state::backupBegin, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) { Text("Back up vault…") }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = state::csvBegin, enabled = !state.busy, modifier = Modifier.fillMaxWidth()) { Text("Export for another password manager…") }
            }
        }
        Spacer(Modifier.height(16.dp))
        ErrorBar(state.error, state::clearError)
        NoticeBar(state.notice, state::clearNotice)
        ExportDialogs(state)
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
                    // F74 tri-state: a FAILED status fetch stops the spinner and offers Retry —
                    // the old shape (spinner + error side by side, status forever null) spun
                    // eternally beside its own stale message.
                    state.totpLoad == TotpLoad.Failed -> {
                        Text(state.totpError ?: "couldn't load TOTP status", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                        Spacer(Modifier.height(8.dp))
                        OutlinedButton(onClick = state::loadTotpStatus) { Text("Retry") }
                    }
                    status == null -> Row(verticalAlignment = Alignment.CenterVertically) { // Pending
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                        Text("Checking…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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

/**
 * F71: java.awt.FileDialog(SAVE) on Linux (XAWT) has NO overwrite prompt — picking an
 * existing name replaces the file silently. Every SAVE-dialog destination routes through
 * [request]: a fresh path runs the action immediately; an existing file waits for an
 * explicit "Replace" in [OverwriteConfirmDialog] (Cancel returns to whatever dialog the
 * picker came from). Windows' native dialog asks by itself — a second ask there is the
 * price of one consistent code path.
 */
private class OverwriteGate {
    var pending by mutableStateOf<Pair<File, () -> Unit>?>(null)
        private set

    fun request(dest: File, action: () -> Unit) {
        if (dest.exists()) pending = dest to action else action()
    }

    fun cancel() { pending = null }
    fun confirm() { pending?.second?.invoke(); pending = null }
}

@Composable
private fun OverwriteConfirmDialog(gate: OverwriteGate) {
    val file = gate.pending?.first ?: return
    AlertDialog(
        onDismissRequest = gate::cancel,
        title = { Text("Replace \"${file.name}\"?") },
        text = { Text("A file with that name already exists there. Replacing it can't be undone.") },
        confirmButton = { TextButton(onClick = gate::confirm) { Text("Replace") } },
        dismissButton = { TextButton(onClick = gate::cancel) { Text("Cancel") } },
    )
}

// ---- export & backup (spec 07) ----

/** The spec 07 export dialogs. Destinations come from java.awt.FileDialog(SAVE) — the
 *  same pattern as the attachment "Save" button — invoked from the confirm buttons,
 *  each gated on [OverwriteGate] (F71: XAWT never asks before replacing). */
@Composable
private fun ExportDialogs(state: DesktopState) {
    val overwrite = remember { OverwriteGate() }
    OverwriteConfirmDialog(overwrite)
    state.backupPreflight?.let { pre ->
        BackupPreflightDialog(state, pre) { selected, includeAttachments, passphrase ->
            val dialog = FileDialog(null as Frame?, "Save vault backup", FileDialog.SAVE)
            dialog.file = "andvari-backup-${exportDateSuffix()}.andvari"
            dialog.isVisible = true
            val dir = dialog.directory; val file = dialog.file
            // Cancelled picker (or a declined overwrite) → the preflight stays open for another go.
            if (dir != null && file != null) {
                val dest = File(dir, file)
                overwrite.request(dest) { state.backupRun(selected, includeAttachments, passphrase, dest) }
            }
        }
    }
    state.backupResult?.let { BackupResultDialog(it, state::backupResultDismiss) }
    state.csvPreflight?.let { pre ->
        CsvPreflightDialog(state, pre) {
            val dialog = FileDialog(null as Frame?, "Save CSV export", FileDialog.SAVE)
            dialog.file = "andvari-export-${exportDateSuffix()}.csv"
            dialog.isVisible = true
            val dir = dialog.directory; val file = dialog.file
            if (dir != null && file != null) {
                val dest = File(dir, file)
                overwrite.request(dest) { state.csvRun(dest) }
            }
        }
    }
}

@Composable
private fun BackupPreflightDialog(
    state: DesktopState,
    pre: BackupPreflight,
    onChooseDestination: (Set<String>, Boolean, String) -> Unit,
) {
    var selected by remember(pre) { mutableStateOf(pre.vaults.map { it.vaultId }.toSet()) }
    var includeAttachments by remember(pre) { mutableStateOf(false) }
    var passphrase by remember(pre) { mutableStateOf("") }
    var confirm by remember(pre) { mutableStateOf("") }
    val plan = remember(pre, selected) { state.attachmentPlan(selected) }
    val score = Strength.estimateStrength(passphrase)
    val ready = selected.isNotEmpty() && passphrase.isNotEmpty() && passphrase == confirm &&
        score >= Strength.BACKUP_FLOOR && !state.busy
    // F72: Enter in either passphrase field = the confirm button (the AWT save dialog it opens
    // is modal, so key autorepeat dies there); Escape = Cancel, same busy gate as the scrim.
    // `ready` is captured at composition, so re-read state.busy live like the other forms.
    val submit = { if (ready && !state.busy) onChooseDestination(selected, includeAttachments, passphrase) }
    val dismiss = { if (!state.busy) state.backupDismiss() }
    AlertDialog(
        onDismissRequest = dismiss,
        confirmButton = {
            TextButton(onClick = submit, enabled = ready) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = state::backupDismiss, enabled = !state.busy) { Text("Cancel") } },
        title = { Text("Back up vault") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).dismissOnEscape(dismiss)) {
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
                Secret("Backup passphrase", passphrase, onEnter = submit) { passphrase = it }
                Secret("Confirm passphrase", confirm, onEnter = submit) { confirm = it }
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
            Column(Modifier.verticalScroll(rememberScrollState()).dismissOnEscape(onDone)) { // F72
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
private fun CsvPreflightDialog(state: DesktopState, pre: CsvPreflight, onChooseDestination: () -> Unit) {
    val dismiss = { if (!state.busy) state.csvDismiss() } // F72: Escape = Cancel (no fields → no Enter path)
    AlertDialog(
        onDismissRequest = dismiss,
        confirmButton = {
            TextButton(onClick = onChooseDestination, enabled = !state.busy && pre.loginCount > 0) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = state::csvDismiss, enabled = !state.busy) { Text("Cancel") } },
        title = { Text("Export for another password manager?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()).dismissOnEscape(dismiss)) {
                pre.offlineNote?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    "⚠ The CSV holds every password in PLAINTEXT. Anyone who reads the file reads your vault. Delete it (and empty the trash) as soon as the other manager has imported it.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                )
                Spacer(Modifier.height(8.dp))
                Text("${pre.loginCount} login(s) will be written.", style = MaterialTheme.typography.bodySmall)
                NamedSkips("Not exported (secure notes):", pre.warnings.noteItems)
                NamedSkips("Not exported (cards — a vault backup includes them):", pre.warnings.cardItems)
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
    java.text.SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(java.util.Date())

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
private fun TotpSetupBlock(state: DesktopState, setup: TotpSetupResponse) {
    var code by remember { mutableStateOf("") }
    val submit = { if (code.isNotBlank() && !state.busy) state.confirmTotp(code) } // F72
    Column {
        Text("Add it to your authenticator (URI or secret), then confirm with a code.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        CopyPlainRow("otpauth URI", setup.otpauthUri)
        CopyPlainRow("Secret (base32)", setup.secretBase32)
        Field("One-time code", code, { code = it }, mono = true, onEnter = submit)
        state.totpError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.height(8.dp))
        Primary("Confirm", code.isNotBlank() && !state.busy, state.busy, submit)
    }
}

@Composable
private fun TotpEnrolledBlock(state: DesktopState) {
    var code by remember { mutableStateOf("") }
    // F72: Enter in the code field = Disable — unambiguous (typing a code INTO the disable
    // field is the whole intent of this block), same gate as the button.
    val submit = { if (code.isNotBlank() && !state.busy) { state.disableTotp(code); code = "" } }
    Column {
        Text("Enrolled.", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodyMedium)
        Text("To turn it off, enter a current code from your authenticator.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Field("One-time code", code, { code = it }, mono = true, onEnter = submit)
        state.totpError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = submit, enabled = code.isNotBlank() && !state.busy,
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

// F72: desktop keyboard affordances. Enter-to-submit attaches to a form's single-line text
// FIELDS (the canonical compose-desktop per-field preview pattern) — never to a whole form
// container, where a preview handler would steal Enter from focused buttons (Tab→Enter must
// keep activating them; that's also why Escape, which no widget here claims, MAY wrap whole
// dialog contents). Every submit lambda is the form's ONE submit path — button and Enter both
// call it — and carries its own ready/busy gate, so a held key's repeats and Enter-while-busy
// are no-ops rather than queued double submits.

/** Enter/NumPad-Enter (key-down, preview phase) fires [submit] and consumes the key — repeats
 *  included, so autorepeat can't outrun the gate INSIDE the call site's submit function. Null
 *  [submit] = plain passthrough: Field passes null for multi-line fields, where Enter must
 *  stay a newline. */
private fun Modifier.submitOnEnter(submit: (() -> Unit)?): Modifier =
    if (submit == null) this else onPreviewKeyEvent { e ->
        if (e.type == KeyEventType.KeyDown && (e.key == Key.Enter || e.key == Key.NumPadEnter)) { submit(); true } else false
    }

/** Escape (key-down) anywhere in the wrapped subtree fires [dismiss] — the keyboard twin of a
 *  dialog's onDismissRequest; call sites pass the SAME busy-gated lambda so Escape can never
 *  cancel more than a click on the scrim/Cancel could. */
private fun Modifier.dismissOnEscape(dismiss: () -> Unit): Modifier =
    onPreviewKeyEvent { e ->
        if (e.type == KeyEventType.KeyDown && e.key == Key.Escape) { dismiss(); true } else false
    }

@Composable
private fun Field(label: String, value: String, onChange: (String) -> Unit, mono: Boolean = false, singleLine: Boolean = true, onEnter: (() -> Unit)? = null) {
    // F72 multi-line guard: onEnter is dropped (not just unused) when singleLine=false.
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp).submitOnEnter(onEnter.takeIf { singleLine }), label = { Text(label) }, singleLine = singleLine,
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium)
}

@Composable
private fun Secret(label: String, value: String, onEnter: (() -> Unit)? = null, onChange: (String) -> Unit) {
    var show by remember { mutableStateOf(false) }
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp).submitOnEnter(onEnter), label = { Text(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = { IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) } })
}

/** [display] is what a reveal shows (e.g. a grouped card number); Copy always hands over the raw [value]. */
@Composable
private fun CopyRow(label: String, value: String, secret: Boolean, clearSeconds: Int, display: String = value) {
    var show by remember { mutableStateOf(!secret) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        androidx.compose.foundation.layout.Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (show) display else "••••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            if (secret) IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, null) }
            TextButton(onClick = { copyWithAutoClear(value, clearSeconds) }) { Text("Copy") }
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

private fun needsUpdateLine(n: Int): String =
    if (n == 1) "1 item needs an app update to display." else "$n items need an app update to display."
