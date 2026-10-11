package io.silencelen.andvari.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AccountStateSync
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.model.UserLookupResponse
import kotlinx.coroutines.launch

/*
 * Household verification and the personal vault (security review 2026-10, root cause A §4, §7.2; A5).
 * The decisions live in core (SyncEngine / ContactPin / PersonalVaultMigration); these screens only collect
 * human input. A contact is pinned only when the member TYPES the other person's 32 hex as read from THAT
 * person's screen; nothing is pinned from a lookup. (No QR here: the app ships no QR encoder or scanner; the
 * web client scans and shows QRs, and the typed path is complete on every client.)
 */

@Composable
fun HouseholdCard(vm: AndvariViewModel) {
    val scope = rememberCoroutineScope()
    var tick by remember { mutableIntStateOf(0) }
    var verifying by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(tick) { vm.refreshHousehold() }
    val contacts = remember(tick) { vm.householdContacts() }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Household members you've verified", style = MaterialTheme.typography.titleLarge)
            Text(
                "Each person does this once with each other person, not once per vault. andvari never trusts a key just because the server sent it.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            when (vm.householdAnomaly()) {
                AccountStateSync.Anomaly.ROLLBACK -> Text("The server sent an older copy of your verified-members list. Your newer copy was kept. If this keeps happening, tell your admin.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                AccountStateSync.Anomaly.UNREADABLE -> Text("The server sent a verified-members list this account did not write. It was ignored. Tell your admin.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                null -> {}
            }
            err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(8.dp))
            if (contacts.isEmpty()) Text("Nobody yet.", style = MaterialTheme.typography.bodySmall)
            for (c in contacts) {
                Text("${c.label} · ${methodLabel(c.method)}", style = MaterialTheme.typography.bodyMedium)
                TextButton(onClick = {
                    scope.launch {
                        err = runCatching { vm.unpinHouseholdMember(c.userId) }.exceptionOrNull()?.let { "Couldn't remove it. Try again." }
                        tick++
                    }
                }) { Text("Remove") }
            }
            OutlinedButton(onClick = { verifying = true }) { Text("Verify a household member") }
        }
    }
    if (verifying) VerifyMemberDialog(vm) { verifying = false; tick++ }
}

private fun methodLabel(m: String) = when (m) {
    "qr" -> "QR scan"
    "typed" -> "typed code"
    "enrol" -> "in-person enrolment"
    else -> m
}

@Composable
private fun VerifyMemberDialog(vm: AndvariViewModel, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var email by remember { mutableStateOf("") }
    var served by remember { mutableStateOf<UserLookupResponse?>(null) }
    var typed by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("Verify a household member") },
        text = {
            Column {
                err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                val s = served
                if (s == null) {
                    OutlinedTextField(email, { email = it }, Modifier.fillMaxWidth(), label = { Text("Their email") }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email))
                } else {
                    Text("Verifying ${s.displayName}. Do this together, in person or on a call you trust.", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Text("Your code (read it to them):", style = MaterialTheme.typography.labelSmall)
                    SelectionContainer {
                        Text(vm.identityCode()?.let { Fingerprint.groupedShort(it) } ?: "…", fontFamily = FontFamily.Monospace)
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        typed, { typed = it }, Modifier.fillMaxWidth(),
                        label = { Text("${s.displayName}'s code, from THEIR screen (32 characters)") },
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                scope.launch {
                    busy = true
                    err = null
                    val s = served
                    if (s == null) {
                        runCatching { vm.lookupHouseholdMember(email.trim()) }
                            .onSuccess { r -> served = r }
                            .onFailure { err = "No active account has that email, or the server is unreachable." }
                    } else {
                        val c = runCatching { vm.verifyHouseholdMember(s, typed) }.getOrNull()
                        if (c != null) onDone()
                        else err = "That code doesn't match the key this server holds for them. If they read it correctly from their own screen, STOP: do not share with this account until your admin checks it."
                    }
                    busy = false
                }
            }) { Text(if (served == null) "Next" else "Verify") }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}

/** Settings: which vault is personal, and the Q9 re-designation with a master-password reauth. */
@Composable
fun PersonalVaultCard(vm: AndvariViewModel) {
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var choice by remember { mutableStateOf<String?>(null) }
    var password by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val choices = vm.personalRedesignationChoices()
    val current = choices.firstOrNull { it.type == "personal" }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Personal vault", style = MaterialTheme.typography.titleLarge)
            Text(
                current?.let { "Your personal vault is ${it.name}. New items, imports and usage history go here." } ?: "Your personal vault isn't confirmed yet.",
                style = MaterialTheme.typography.bodySmall,
            )
            msg?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = { open = true }) { Text("Change which vault is personal…") }
        }
    }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text("This is my personal vault") },
            text = {
                Column {
                    for (v in choices) {
                        androidx.compose.foundation.layout.Row(
                            Modifier.fillMaxWidth().selectable(selected = choice == v.vaultId, onClick = { choice = v.vaultId }, role = Role.RadioButton),
                        ) {
                            RadioButton(selected = choice == v.vaultId, onClick = null)
                            Text(v.name, Modifier.padding(start = 8.dp))
                        }
                    }
                    OutlinedTextField(
                        password, { password = it }, Modifier.fillMaxWidth(), label = { Text("Master password (required)") },
                        singleLine = true, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    )
                }
            },
            confirmButton = {
                TextButton(enabled = !busy && choice != null && password.isNotEmpty(), onClick = {
                    scope.launch {
                        busy = true
                        msg = runCatching { vm.redesignatePersonalVault(choice!!, password) }.fold(
                            { "Saved. New items now go to this vault by default." },
                            { "Couldn't change it: wrong master password, or the server refused." },
                        )
                        password = ""
                        busy = false
                        open = false
                    }
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { open = false }) { Text("Cancel") } },
        )
    }
}

/**
 * Vault banner while no personal vault is confirmed (§4.3): no default destination, usage paused. With no wrap
 * anywhere it asks "Which vault is your Personal vault?", offering every vault on this account's own UVK wrap
 * (the server label neither filters nor orders them; only the answer mints the wrap, A5 review H-1). A
 * withheld wrap is reported as an anomaly instead.
 */
@Composable
fun PersonalVaultBanner(vm: AndvariViewModel, onChanged: () -> Unit) {
    val status = vm.personalStatus() ?: return
    if (status == Account.PersonalStatus.CONFIRMED) return
    val scope = rememberCoroutineScope()
    var err by remember { mutableStateOf<String?>(null) }
    if (status == Account.PersonalStatus.WITHHELD) {
        // A5 review H-1: an anomaly, not "unmigrated": the device keeps the wrap it already authenticated.
        Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            Column(Modifier.padding(12.dp)) {
                Text("The server didn't send your personal-vault record this time.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.titleSmall)
                Text("This device kept the one it already had, so nothing changed. If this keeps happening, tell your admin.", style = MaterialTheme.typography.bodySmall)
            }
        }
        return
    }
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text("Your personal vault isn't confirmed yet.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.titleSmall)
            Text("Until it is, pick a vault every time you save or import, and usage history is paused.", style = MaterialTheme.typography.bodySmall)
            if (status == Account.PersonalStatus.UNREADABLE) {
                Text("The server sent a personal-vault record this account can't read. Choose your personal vault in Settings (it asks for your master password), and tell your admin.", style = MaterialTheme.typography.bodySmall)
            }
            val choices = vm.personalVaultChoices().orEmpty()
            if (status == Account.PersonalStatus.ABSENT && choices.isNotEmpty()) {
                Text("Which vault is your Personal vault?", style = MaterialTheme.typography.bodySmall)
                for (c in choices) {
                    OutlinedButton(onClick = {
                        scope.launch {
                            err = runCatching { vm.designatePersonalVault(c.vaultId) }.exceptionOrNull()?.let { "Couldn't save that. If another device already chose, change it in Settings." }
                            onChanged()
                        }
                    }) { Text("${c.name ?: "(unnamed)"} · ${c.itemCount} items") }
                }
            }
            err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
