package io.silencelen.andvari.app

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.HeldVaultInfo
import io.silencelen.andvari.core.client.LifecycleNotice
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.VaultItem

/** "July 14"-style day (spec 03 §11 copy). Falls back gracefully for a missing time. */
internal fun fmtDay(ms: Long?): String {
    if (ms == null || ms <= 0) return "soon"
    return java.text.SimpleDateFormat("MMMM d", java.util.Locale.getDefault()).format(java.util.Date(ms))
}

/** §11 notice copy — attribution ("by its owner") is EARNED by a verified proof; the
 *  anomaly wordings render in the danger tone. Mirrors web Vault.tsx noticeBody. */
private fun noticeBody(n: LifecycleNotice): Pair<String, Boolean> {
    val name = n.vaultName.ifBlank { "a vault" }
    return when (n.kind) {
        "deleted" -> Pair(
            "“$name” was deleted by its owner. Its items were moved off this device" +
                (n.purgeAt?.let { " (kept sealed until ${fmtDay(it)}, then removed)." } ?: ".") +
                (n.parkedCount?.let { " $it of your edits hadn’t synced — they’ll be recovered if the vault is restored this week." } ?: ""),
            false,
        )
        "removed" -> Pair("Your access to “$name” was removed.", false)
        "left" -> Pair("You left “$name”.", false)
        "restored" -> Pair("“$name” was restored.", false)
        "transfer-complete" -> Pair(
            if (n.becameMine) "You are now the owner of “$name”." else "“$name” now has a new owner.",
            false,
        )
        "transfer-anomaly" -> Pair(
            "The server says “$name” changed owners, but this couldn’t be verified with the vault’s own key. " +
                "If nobody in your household did this, tell your admin — the server may be misbehaving.",
            true,
        )
        "replay-denied" -> {
            val c = n.parkedCount ?: 0
            Pair(
                "$c recovered ${if (c == 1) "edit" else "edits"} couldn't be applied to “$name” — your role may have changed.",
                false,
            )
        }
        else -> Pair( // "anomaly"
            "The server says you lost access to “$name”, but this couldn’t be verified as a real owner action. " +
                "A sealed copy of its data is kept on this device for 30 days (Sharing → Recently removed). " +
                "If nobody in your household did this, tell your admin — the server may be misbehaving.",
            true,
        )
    }
}

/** The lifecycle notices banner (spec 03 §11) — each notice individually dismissable. */
@Composable
internal fun LifecycleNoticesBanner(notices: List<LifecycleNotice>, onDismiss: (String) -> Unit) {
    notices.forEach { n ->
        val (body, warn) = noticeBody(n)
        Card(
            Modifier.fillMaxWidth().padding(vertical = 4.dp),
            colors = if (warn) CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer) else CardDefaults.cardColors(),
        ) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    body, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
                    color = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.secondary,
                )
                TextButton(onClick = { onDismiss(n.id) }) { Text("Dismiss") }
            }
        }
    }
}

/** Incoming ownership offers (spec 03 §11): renders ONLY entries the engine already
 *  verified under the held VK. The in-person confirm is an ADVISORY, not proof. */
@Composable
internal fun IncomingTransferCards(vm: AndvariViewModel, ui: UiState) {
    ui.incomingTransfers.forEach { t ->
        val owner = ui.transferOwnerNames[t.vaultId] ?: "the current owner"
        Card(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
            Column(Modifier.padding(16.dp)) {
                Text("Become the owner of “${t.vaultName}”?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(4.dp))
                Text("$owner wants to make you the owner of “${t.vaultName}”.", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(6.dp))
                Text(
                    "✓ This offer was verified with the vault's own key. To be sure it really came from $owner — " +
                        "and not a compromised server — confirm with them in person or by phone. As owner you'd manage " +
                        "members and be the only one who can rename, transfer, or delete it.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(10.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    androidx.compose.material3.Button(onClick = { vm.acceptTransfer(t.vaultId) }, enabled = !ui.busy, modifier = Modifier.weight(1f)) {
                        Text("Become the owner")
                    }
                    OutlinedButton(onClick = { vm.cancelTransfer(t.vaultId) }, enabled = !ui.busy) { Text("Decline") }
                }
            }
        }
    }
}

/** Sharing screen (spec 03 §10/§11): vaults + the full lifecycle — delete, restore, leave,
 *  transfer, rename — plus Recently deleted (restore) and Recently removed (holding area).
 *  Member management (add/role/remove) stays a web surface for now; this screen carries the
 *  lifecycle slice the natives need for 0.5.0 parity.
 *
 *  DN-1 (per-vault Settings reveal): the lifecycle panels no longer stack under the vault
 *  list — each SHARED vault's row carries a Settings affordance that opens that one vault's
 *  settings view in place of the list ([UiState.sharingSettingsVaultId], rotation-safe VM
 *  state). Banners (error/notice, lifecycle notices, incoming offers) and the A4 copy
 *  status line compose ABOVE the branch — always visible from either side (A6/A7). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SharingScreen(vm: AndvariViewModel, ui: UiState) {
    BackHandler(onBack = vm::closeSharing)
    val vaults = vm.vaultInfos()
    // DN-1: resolve the open settings id against the CURRENT vaults every composition — a
    // vault vanishing mid-view (deleted/revoked on another device) degrades to the list,
    // never a crash. A2 actively clears the stale id in the VM's refresh path; this
    // null-safe lookup covers the same-frame gap.
    val settingsVault = ui.sharingSettingsVaultId?.let { id -> vaults.find { it.vaultId == id } }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(settingsVault?.name ?: "Sharing", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = {
                    IconButton(onClick = if (settingsVault != null) vm::closeVaultSettings else vm::closeSharing) {
                        Icon(Icons.Default.ArrowBack, "back")
                    }
                },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
            // A6/A7 branch boundary: bars, lifecycle notices, incoming ownership offers and
            // the copy status line stay ABOVE the list/settings branch — an op failure
            // inside settings is never silent, and an arriving offer shows immediately.
            ErrorBar(ui.error, vm::clearError)
            NoticeBar(ui.notice, vm::clearNotice)
            LifecycleNoticesBanner(ui.lifecycleNotices, vm::dismissNotice)
            IncomingTransferCards(vm, ui)
            CopyStatusLine(ui, vaults)

            if (settingsVault != null) {
                // A11: this BackHandler composes INSIDE the settings branch — last-composed
                // wins, so system Back closes the settings layer before the screen (the
                // panels' AlertDialog confirms keep their own window back-dispatch).
                BackHandler(onBack = vm::closeVaultSettings)
                if (settingsVault.type == "shared" && settingsVault.role == "owner") {
                    OwnerVaultPanel(vm, ui, settingsVault)
                } else {
                    MemberVaultPanel(vm, ui, settingsVault)
                }
            } else {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("Vaults", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Every item lives in exactly one vault. Shared vaults are visible to everyone you add; only the vault owner manages members.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(8.dp))
                        vaults.forEach { v ->
                            VaultListRow(v, onOpenSettings = if (v.type == "shared") ({ vm.openVaultSettings(v.vaultId) }) else null)
                        }
                    }
                }

                RecentlyDeletedSection(vm, ui)
                RecentlyRemovedSection(ui.heldVaults)
            }
            Spacer(Modifier.height(24.dp))
            ExportDialogs(vm, ui) // "Back up first…" opens the spec 07 backup preflight here
        }
    }
}

/** One Vaults-card row — the pure extraction of the old inline row (DN-1). SHARED vaults
 *  (owner or member alike) get the Settings affordance; personal vaults get none (no
 *  lifecycle ops — rename/delete/leave/transfer are all shared-vault verbs, and an empty
 *  settings page is worse than no button). Leave moved into the settings view; the row
 *  keeps its role tag. */
@Composable
private fun VaultListRow(v: VaultInfo, onOpenSettings: (() -> Unit)?) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text((v.name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif)
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(v.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
            Text(
                if (v.type == "personal") "personal vault" else "shared vault · ${v.role ?: "member"}",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (onOpenSettings != null) {
            IconButton(onClick = onOpenSettings) { Icon(Icons.Default.Settings, "vault settings") }
        }
    }
}

/** DN-1 settings view for a shared vault this account is a MEMBER of: a role line + the
 *  relocated [LeaveControl] (Leave moved off the list row into settings). */
@Composable
private fun MemberVaultPanel(vm: AndvariViewModel, ui: UiState, v: VaultInfo) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(
                "shared vault · ${v.role ?: "member"}",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))
            LeaveControl(vm, ui, v)
        }
    }
}

/** A4 (DN-1): the ONE authoritative bulk-copy progress/note line — screen-level, visible
 *  from either branch, naming the SOURCE vault via [UiState.copyVaultId]. A mid-copy
 *  navigation clears the id (openVaultSettings/closeVaultSettings convention) while the
 *  op's next tick republishes the progress — fall back to "a vault" honestly rather than
 *  hide a live op. */
@Composable
private fun CopyStatusLine(ui: UiState, vaults: List<VaultInfo>) {
    if (ui.copyProgress == null && ui.copiedNote == null) return
    val label = ui.copyVaultId?.let { id -> vaults.find { it.vaultId == id }?.name }?.let { "“$it”" } ?: "a vault"
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            val progress = ui.copyProgress
            if (progress != null) {
                val (done, total) = progress
                Text("Copying items from $label to your Personal vault… $done/$total", style = MaterialTheme.typography.bodySmall)
                if (total > 0) LinearProgressIndicator(progress = { done.toFloat() / total }, modifier = Modifier.fillMaxWidth().padding(top = 4.dp))
            } else {
                ui.copiedNote?.let {
                    Text("From $label: $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
                }
            }
        }
    }
}

// ---- leave (self-removal, spec 03 §11) ----

@Composable
private fun LeaveControl(vm: AndvariViewModel, ui: UiState, v: VaultInfo) {
    var confirming by remember(v.vaultId) { mutableStateOf(false) }
    TextButton(
        onClick = { confirming = true },
        colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
    ) { Text("Leave") }
    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("Leave “${v.name}”?") },
            text = {
                Text(
                    "You'll lose access on all your devices, and any edits you haven't synced will be discarded. " +
                        "The items stay with the owner and other members; only the owner can add you back. " +
                        "(Leaving doesn't erase what this device already knew.)",
                )
            },
            confirmButton = {
                TextButton(onClick = { confirming = false; vm.leaveVault(v.vaultId) }, enabled = !ui.busy) {
                    Text("Leave vault", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirming = false }) { Text("Cancel") } },
        )
    }
}

// ---- owner panel: rename / transfer / delete (spec 03 §11) ----

@Composable
private fun OwnerVaultPanel(vm: AndvariViewModel, ui: UiState, v: VaultInfo) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            RenameHeader(vm, ui, v)
            Text(
                "You own this vault. Writers can add and edit items; readers can only view.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(10.dp))
            TransferControl(vm, ui, v)
            Spacer(Modifier.height(10.dp))
            DeleteVaultControl(vm, ui, v)
        }
    }
}

@Composable
private fun RenameHeader(vm: AndvariViewModel, ui: UiState, v: VaultInfo) {
    var editing by rememberSaveable(v.vaultId) { mutableStateOf(false) }
    var name by rememberSaveable(v.vaultId) { mutableStateOf(v.name) }
    if (!editing) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("“${v.name}”", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(onClick = { name = v.name; editing = true }) { Text("Rename") }
        }
    } else {
        Column {
            OutlinedTextField(
                name, { name = it }, Modifier.fillMaxWidth(), label = { Text("Rename vault") },
                singleLine = true, enabled = !ui.busy,
            )
            Text(
                "Encrypted — readable only with this vault's key. Syncs to every member.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(
                    onClick = {
                        val next = name.trim()
                        if (next.isNotEmpty() && next != v.name) vm.renameVault(v.vaultId, next)
                        editing = false
                    },
                    enabled = !ui.busy && name.trim().isNotEmpty(),
                ) { Text("Save") }
                TextButton(onClick = { editing = false }, enabled = !ui.busy) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun TransferControl(vm: AndvariViewModel, ui: UiState, v: VaultInfo) {
    val pending = vm.pendingTransferFor(v.vaultId)
    val members = ui.sharingMembers[v.vaultId]
    if (pending != null) {
        val pendingName = members?.find { it.userId == pending.toUserId }?.displayName ?: "a member"
        Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    "Ownership offer to $pendingName — expires ${fmtDay(pending.expiresAt)}",
                    Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
                )
                TextButton(onClick = { vm.cancelTransfer(v.vaultId) }, enabled = !ui.busy) { Text("Cancel offer") }
            }
        }
        return
    }
    // Transfer targets: active members who are not the owner and not disabled (F22 badge).
    val targets = (members ?: emptyList()).filter { it.role != "owner" && (it.status ?: "active") == "active" }
    if (targets.isEmpty()) return
    var confirming by remember(v.vaultId) { mutableStateOf<String?>(null) } // userId pending confirm
    Column {
        Text("Make someone else the owner", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        targets.forEach { m ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("${m.displayName} (${m.email})", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, maxLines = 1)
                TextButton(onClick = { confirming = m.userId }, enabled = !ui.busy) { Text("Transfer ownership…") }
            }
        }
    }
    confirming?.let { userId ->
        val m = targets.find { it.userId == userId } ?: return
        AlertDialog(
            onDismissRequest = { confirming = null },
            title = { Text("Make ${m.displayName} the owner of “${v.name}”?") },
            text = {
                Text(
                    "Nothing changes until they accept in their app (they have 14 days; you can cancel anytime). " +
                        "Afterwards they manage members and only they can rename, transfer, or delete it — " +
                        "you'll stay in it as a writer.",
                )
            },
            confirmButton = {
                TextButton(onClick = { confirming = null; vm.offerTransfer(v.vaultId, m.userId) }, enabled = !ui.busy) {
                    Text("Ask ${m.displayName} to take over")
                }
            },
            dismissButton = { TextButton(onClick = { confirming = null }) { Text("Cancel") } },
        )
    }
}

// ---- delete vault (owner side, spec 03 §11 + F19 rescue) ----

@Composable
private fun DeleteVaultControl(vm: AndvariViewModel, ui: UiState, v: VaultInfo) {
    var open by rememberSaveable(v.vaultId) { mutableStateOf(false) }
    var typed by rememberSaveable(v.vaultId) { mutableStateOf("") }
    if (!open) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
            TextButton(
                onClick = { open = true; typed = "" },
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) { Text("Delete vault…") }
        }
        return
    }
    val items = ui.items.filter { it.vaultId == v.vaultId }
    val attachmentCount = items.sumOf { it.doc.attachments.size }
    val eraseDay = fmtDay(System.currentTimeMillis() + 7L * 86_400_000)
    Column {
        Text("Delete “${v.name}”?", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(4.dp))
        Text(
            "This removes the vault from everyone's andvari now. The server keeps its ${items.size} " +
                (if (items.size == 1) "item" else "items") +
                (if (attachmentCount > 0) " and $attachmentCount ${if (attachmentCount == 1) "attachment" else "attachments"}" else "") +
                " for 7 days (until $eraseDay) in case you change your mind — then erases them for good. " +
                "Want to keep some of these?",
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { vm.copyItemsToPersonal(v.vaultId) }, enabled = !ui.busy) {
                // A4: the inline copy display is gated to ITS vault — another vault's
                // in-flight copy must not relabel this button.
                Text(ui.copyProgress?.takeIf { ui.copyVaultId == v.vaultId }?.let { (d, t) -> "Copying… $d/$t" } ?: "Copy items to my Personal vault first…")
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = vm::backupBegin, enabled = !ui.busy) { Text("Back up first…") }
        }
        // A4: progress bar + note kept in-panel but gated to ITS vault (copyVaultId) —
        // the screen-level CopyStatusLine is the cross-branch authoritative display.
        if (ui.copyVaultId == v.vaultId) ui.copyProgress?.let { (done, total) ->
            if (total > 0) LinearProgressIndicator(progress = { done.toFloat() / total }, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp))
        }
        if (ui.copyVaultId == v.vaultId) ui.copiedNote?.let {
            Spacer(Modifier.height(4.dp))
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary)
        }
        Spacer(Modifier.height(8.dp))
        Text(
            "Deleting can't take back what people already saw: anyone who had access may have kept copies of items " +
                "or the vault key, and encrypted server backups age out on their own schedule (about a month). " +
                "If a password really matters, change it at the website too.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            typed, { typed = it }, Modifier.fillMaxWidth(),
            label = { Text("Type the vault's name to delete it") }, placeholder = { Text(v.name) },
            singleLine = true, enabled = !ui.busy,
        )
        Row(Modifier.fillMaxWidth().padding(top = 6.dp), horizontalArrangement = Arrangement.End) {
            TextButton(onClick = { open = false; typed = ""; vm.clearCopiedNote() }, enabled = !ui.busy) { Text("Cancel") }
            Spacer(Modifier.width(8.dp))
            TextButton(
                onClick = { open = false; typed = ""; vm.clearCopiedNote(); vm.deleteVault(v.vaultId, v.name) },
                enabled = !ui.busy && typed == v.name,
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) { Text("Delete vault") }
        }
    }
}

// ---- recently deleted (restore, spec 03 §11) ----

@Composable
private fun RecentlyDeletedSection(vm: AndvariViewModel, ui: UiState) {
    if (ui.deletedVaults.isEmpty()) return
    var restoring by remember { mutableStateOf<String?>(null) } // vaultId pending confirm
    Spacer(Modifier.height(16.dp))
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Recently deleted", style = MaterialTheme.typography.titleLarge)
            Text(
                "Deleted vaults you can still restore. Restoring brings a vault back for every member with everything that was in it.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(6.dp))
            ui.deletedVaults.forEach { d ->
                Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("“${d.name}”", style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                        Text(
                            "deleted ${fmtDay(d.deletedAt)} · erased for good ${fmtDay(d.purgeAt)}",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    TextButton(onClick = { restoring = d.vaultId }, enabled = !ui.busy) { Text("Restore") }
                }
            }
        }
    }
    restoring?.let { vaultId ->
        val d = ui.deletedVaults.find { it.vaultId == vaultId } ?: return
        AlertDialog(
            onDismissRequest = { restoring = null },
            title = { Text("Restore “${d.name}”?") },
            text = {
                Text(
                    "It comes back for every member with everything that was in it. Devices running the latest app " +
                        "also recover edits members hadn't synced; older devices may have discarded theirs.",
                )
            },
            confirmButton = {
                TextButton(onClick = { restoring = null; vm.restoreVault(d.vaultId, d.deleteId) }, enabled = !ui.busy) { Text("Restore vault") }
            },
            dismissButton = { TextButton(onClick = { restoring = null }) { Text("Cancel") } },
        )
    }
}

// ---- recently removed (the holding area, spec 03 §11 / design §6) ----

@Composable
private fun RecentlyRemovedSection(held: List<HeldVaultInfo>) {
    if (held.isEmpty()) return
    Spacer(Modifier.height(16.dp))
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Recently removed", style = MaterialTheme.typography.titleLarge)
            Text(
                "Vaults this account lost access to. A sealed copy is kept on this device for a while in case of a mistake — if the vault is restored or you're re-added, everything (including unsynced edits) comes back.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(6.dp))
            held.forEach { h ->
                Column(Modifier.padding(vertical = 4.dp)) {
                    Text("“${h.name}”", style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                    val line = when {
                        h.reason == "deleted" && h.verified -> "deleted by its owner · kept sealed until ${fmtDay(h.purgeAt ?: h.expungeAt)}"
                        h.reason == "left" -> "you left · kept until ${fmtDay(h.expungeAt)}"
                        h.verified -> "access removed · kept until ${fmtDay(h.expungeAt)}"
                        else -> "unverified removal · kept until ${fmtDay(h.expungeAt)}"
                    }
                    Text(
                        line, style = MaterialTheme.typography.bodySmall,
                        color = if (h.verified || h.reason == "left") MaterialTheme.colorScheme.onSurfaceVariant else MaterialTheme.colorScheme.error,
                    )
                }
            }
        }
    }
}

// ---- F19: move / copy an item into another vault (Detail screen, design §8) ----

/** Move or copy this item into another vault. The picker SESSION (open flag + mode) lives
 *  in the ViewModel — completion across an Activity recreation must close the picker the
 *  user actually sees (#7, same convention as the editor). A transient failure keeps the
 *  SAME gesture in the ViewModel so Retry converges (never duplicates); a denied copy or a
 *  changed source aborts with an honest message (source untouched). */
@Composable
internal fun MoveCopyControl(vm: AndvariViewModel, ui: UiState, item: VaultItem, targets: List<VaultInfo>) {
    val mode = if (vm.movePickerItemId == item.itemId) vm.movePickerMode else null
    var target by rememberSaveable(item.itemId) { mutableStateOf(targets.firstOrNull()?.vaultId ?: "") }
    if (mode == null) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TextButton(onClick = { vm.openMovePicker(item.itemId, "move") }) { Text("Move to vault…") }
            TextButton(onClick = { vm.openMovePicker(item.itemId, "copy") }) { Text("Copy to vault…") }
        }
        return
    }
    Column(Modifier.padding(top = 8.dp)) {
        Text(
            if (mode == "move") "Move to another vault" else "Copy to another vault",
            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (mode == "move") {
            val srcName = vm.vaultInfos().find { it.vaultId == item.vaultId }?.name ?: "this vault"
            Text(
                "Members of “$srcName” may still have copies from before the move.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        targets.forEach { t ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(selected = target == t.vaultId, onClick = { target = t.vaultId }, enabled = !ui.busy)
                Text(t.name + if (t.type == "personal") "" else " (shared)", style = MaterialTheme.typography.bodyMedium)
            }
        }
        ui.moveProgress?.let { (done, total) ->
            if (total > 0) {
                LinearProgressIndicator(progress = { done.toFloat() / total }, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp))
                Text("Copying attachments $done / $total", style = MaterialTheme.typography.bodySmall)
            }
        }
        Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            androidx.compose.material3.Button(
                onClick = { vm.moveOrCopyItem(item.itemId, target, mode == "move") },
                enabled = !ui.busy && target.isNotEmpty(),
            ) { Text(if (ui.busy) "Working…" else if (ui.error != null) "Retry" else if (mode == "move") "Move" else "Copy") }
            TextButton(onClick = { vm.closeMovePicker() }, enabled = !ui.busy) { Text("Cancel") }
        }
    }
}
