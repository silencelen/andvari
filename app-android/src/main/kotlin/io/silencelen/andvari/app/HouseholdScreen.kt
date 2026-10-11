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
import androidx.compose.runtime.key
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
import io.silencelen.andvari.core.client.PersonalChoiceInfo
import io.silencelen.andvari.core.client.PersonalVaultProposal
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
                val here = if (vm.householdContactConfirmedHere(c)) "" else " · verify again on this device"
                Text("${c.label} · ${methodLabel(c.method)}$here", style = MaterialTheme.typography.bodyMedium)
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

/**
 * One line under each personal-vault option (A5b, M-2): who else holds it and where it came from, so the
 * wrong vault is hard to pick. What the server reports; it informs the human and decides nothing.
 */
internal fun personalChoiceDetail(info: PersonalChoiceInfo?): String {
    if (info == null) return ""
    // A5b review LOW-2 (closed in A6): the origin and the co-holders are what the SERVER reports; say so.
    val origin = when (info.origin) {
        PersonalChoiceInfo.Origin.CREATED -> "created by this account"
        PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER -> "received from someone else by transfer"
    }
    val holders = info.coHolders.let { h ->
        when {
            h == null -> "couldn't check who else holds it"
            h.isEmpty() -> "nobody else holds it"
            else -> "also held by " + h.joinToString(", ") { "${it.displayName} (${it.role})" }
        }
    }
    val device = if (info.onThisDevice) " · this device's personal vault" else ""
    return "As reported by the server: $origin · $holders$device"
}

/** The confirmation every designation goes through (A5b, M-2): it names the vault and everyone else on it. */
@Composable
private fun ConfirmPersonalText(p: PersonalVaultProposal) {
    Column {
        Text("New items, imports and usage history will go to ${p.name ?: "this vault"} by default.", style = MaterialTheme.typography.bodySmall)
        Spacer(Modifier.height(6.dp))
        if (p.coHolders.isEmpty()) {
            Text("The server reports nobody else on this vault.", style = MaterialTheme.typography.bodySmall)
        } else {
            Text(
                "The server reports that these people can also read everything in it: " + p.coHolders.joinToString(", ") { "${it.displayName} (${it.email})" } +
                    ". Choose it only if that is what you want.",
                color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall,
            )
        }
        if (p.origin == PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER) {
            Text("The server reports that someone else created this vault and transferred it to you.", style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** Settings: which vault is personal, and the Q9 re-designation (confirmed, with a master-password reauth). */
@Composable
fun PersonalVaultCard(vm: AndvariViewModel) {
    val scope = rememberCoroutineScope()
    var open by remember { mutableStateOf(false) }
    var choice by remember { mutableStateOf<String?>(null) }
    var proposal by remember { mutableStateOf<PersonalVaultProposal?>(null) }
    var password by remember { mutableStateOf("") }
    var msg by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var tick by remember { mutableIntStateOf(0) }
    val choices = remember(tick, open) { vm.personalRedesignationChoices() }
    val current = choices.firstOrNull { it.type == "personal" }
    LaunchedEffect(open) { if (open) { vm.refreshPersonalChoiceDetails(choices.map { it.vaultId }); tick++ } }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Personal vault", style = MaterialTheme.typography.titleLarge)
            Text(
                current?.let { "Your personal vault is ${it.name}. New items, imports and usage history go here." } ?: "Your personal vault isn't confirmed yet.",
                style = MaterialTheme.typography.bodySmall,
            )
            msg?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            TextButton(onClick = { open = true; choice = null; proposal = null }) { Text("Change which vault is personal…") }
        }
    }
    if (open) {
        val p = proposal
        AlertDialog(
            onDismissRequest = { vm.cancelPersonalProposal(); open = false },
            title = { Text(if (p == null) "This is my personal vault" else "Make ${p.name ?: "this vault"} your personal vault?") },
            text = {
                Column {
                    if (p == null) {
                        for (v in choices) {
                            androidx.compose.foundation.layout.Row(
                                Modifier.fillMaxWidth().selectable(selected = choice == v.vaultId, onClick = { choice = v.vaultId }, role = Role.RadioButton),
                            ) {
                                RadioButton(selected = choice == v.vaultId, onClick = null)
                                Column(Modifier.padding(start = 8.dp)) {
                                    Text(v.name)
                                    Text(personalChoiceDetail(vm.personalChoiceInfo(v.vaultId)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                    } else {
                        ConfirmPersonalText(p)
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            password, { password = it }, Modifier.fillMaxWidth(), label = { Text("Master password (required)") },
                            singleLine = true, visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        )
                    }
                    msg?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                }
            },
            confirmButton = {
                if (p == null) {
                    TextButton(enabled = !busy && choice != null, onClick = {
                        scope.launch {
                            busy = true
                            msg = null
                            runCatching { vm.proposePersonalVault(choice!!) }
                                .onSuccess { proposal = it }
                                .onFailure { msg = "Couldn't check who else holds that vault. Try again when you're connected." }
                            busy = false
                        }
                    }) { Text("Next") }
                } else {
                    TextButton(enabled = !busy && password.isNotEmpty(), onClick = {
                        scope.launch {
                            busy = true
                            msg = runCatching { vm.redesignatePersonalVault(p, password) }.fold(
                                { "Saved. New items now go to this vault by default." },
                                { "Couldn't change it: wrong master password, or the server refused." },
                            )
                            password = ""
                            busy = false
                            open = false
                            proposal = null
                        }
                    }) { Text("Yes, this is my personal vault") }
                }
            },
            dismissButton = { TextButton(onClick = { vm.cancelPersonalProposal(); open = false; proposal = null }) { Text("Cancel") } },
        )
    }
}

/**
 * Vault banner while the personal vault needs attention (§4.3; A5 review H-1; A5b). With no wrap anywhere it
 * asks "Which vault is your Personal vault?", offering every vault on this account's own UVK wrap with who else
 * holds it and where it came from; a choice goes through a confirmation naming the vault and its co-holders
 * before anything is minted. A withheld or unreadable wrap with a good local copy is an anomaly, and a served
 * wrap naming another vault than this device's is a change the human confirms, never a silent switch.
 */
@Composable
fun PersonalVaultBanner(vm: AndvariViewModel, onChanged: () -> Unit) {
    val status = vm.personalStatus() ?: return
    if (status == Account.PersonalStatus.CONFIRMED) return
    val scope = rememberCoroutineScope()
    var err by remember { mutableStateOf<String?>(null) }
    var proposal by remember { mutableStateOf<PersonalVaultProposal?>(null) }
    var busy by remember { mutableStateOf(false) }
    var tick by remember { mutableIntStateOf(0) }
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
    if (status == Account.PersonalStatus.UNREADABLE_CACHED) {
        // A5 re-review L-1: junk from the server never discards the valid local copy.
        val name = vm.personalChoiceInfo(vm.personalVaultId())?.name ?: "your personal vault"
        Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            Column(Modifier.padding(12.dp)) {
                Text("The server sent a personal-vault record this account can't read.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.titleSmall)
                Text("This device kept the one it already had ($name), so nothing changed. To repair the server's copy, choose $name again in Settings (it asks for your master password), and tell your admin.", style = MaterialTheme.typography.bodySmall)
            }
        }
        return
    }
    if (status == Account.PersonalStatus.CHANGED) {
        // A5 re-review M-2 / L-2: never a silent switch. A5b review LOW-1 (closed in A6): keeping the current vault
        // comes FIRST, and "Use new" is offered only after the new vault's co-holders loaded (core enforces it too).
        val change = vm.personalChange() ?: return
        var details by remember(change.servedVaultId) { mutableStateOf<io.silencelen.andvari.core.client.PersonalChangeDetails?>(null) }
        var lookupFailed by remember(change.servedVaultId) { mutableStateOf(false) }
        LaunchedEffect(change.servedVaultId, tick) {
            runCatching { vm.describePersonalChange() }.onSuccess { details = it; lookupFailed = false }.onFailure { lookupFailed = true }
        }
        val newName = details?.servedName ?: vm.vaultDisplayName(change.servedVaultId)
        val oldName = details?.currentName ?: vm.vaultDisplayName(change.currentVaultId)
        Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
            Column(Modifier.padding(12.dp)) {
                Text("Your personal vault was changed from $oldName to $newName.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.titleSmall)
                Text("Another of your devices changed it, or the server sent an older record. This device still uses $oldName until you decide.", style = MaterialTheme.typography.bodySmall)
                OutlinedButton(enabled = !busy, onClick = {
                    scope.launch {
                        busy = true
                        err = null
                        runCatching { vm.proposePersonalVault(change.currentVaultId) }
                            .onSuccess { proposal = it }
                            .onFailure { err = "Couldn't check who else holds $oldName. Try again when you're connected." }
                        busy = false
                    }
                }) { Text("Keep $oldName") }
                val d = details
                if (d != null) {
                    val holders = if (d.servedCoHolders.isEmpty()) "nobody else" else d.servedCoHolders.joinToString(", ") { "${it.displayName} (${it.role})" }
                    val origin = if (d.servedOrigin == PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER) "received by transfer" else "created by this account"
                    Text("$newName, as reported by the server: $origin · also held by $holders.", style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = {
                        err = runCatching { vm.acceptPersonalChange() }.exceptionOrNull()?.let { "Couldn't switch. Try again." }
                        onChanged()
                    }) { Text("Use $newName") }
                } else if (lookupFailed) {
                    Text("Couldn't check who else holds $newName, so switching to it isn't offered yet.", style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { tick++ }) { Text("Try again") }
                }
                Text("If you didn't change it, keep $oldName (it asks for your master password) and tell your admin.", style = MaterialTheme.typography.bodySmall)
                err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        }
        val p = proposal
        if (p != null) KeepCurrentDialog(vm, p, onDone = { proposal = null; onChanged() })
        return
    }
    val choices = vm.personalVaultChoices().orEmpty()
    LaunchedEffect(choices.map { it.vaultId }) { if (choices.isNotEmpty()) { vm.refreshPersonalChoiceDetails(choices.map { it.vaultId }); tick++ } }
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text("Your personal vault isn't confirmed yet.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.titleSmall)
            Text("Until it is, pick a vault every time you save or import, and usage history is paused.", style = MaterialTheme.typography.bodySmall)
            if (status == Account.PersonalStatus.UNREADABLE) {
                Text("The server sent a personal-vault record this account can't read. Choose your personal vault in Settings (it asks for your master password), and tell your admin.", style = MaterialTheme.typography.bodySmall)
            }
            if (status == Account.PersonalStatus.ABSENT && choices.isNotEmpty()) {
                Text("Which vault is your Personal vault?", style = MaterialTheme.typography.bodySmall)
                key(tick) {
                    for (c in choices) {
                        OutlinedButton(enabled = !busy, onClick = {
                            scope.launch {
                                busy = true
                                err = null
                                runCatching { vm.proposePersonalVault(c.vaultId) }
                                    .onSuccess { proposal = it }
                                    .onFailure { err = "Couldn't check who else holds that vault. Try again when you're connected." }
                                busy = false
                            }
                        }) { Text("${c.name ?: "(unnamed)"} · ${c.itemCount} items") }
                        Text(personalChoiceDetail(vm.personalChoiceInfo(c.vaultId)), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        }
    }
    val p = proposal
    if (p != null) {
        AlertDialog(
            onDismissRequest = { vm.cancelPersonalProposal(); proposal = null },
            title = { Text("Make ${p.name ?: "this vault"} your personal vault?") },
            text = { ConfirmPersonalText(p) },
            confirmButton = {
                TextButton(enabled = !busy, onClick = {
                    scope.launch {
                        busy = true
                        err = runCatching { vm.confirmPersonalVault(p) }.exceptionOrNull()?.let { "Couldn't save that. If another device already chose, change it in Settings." }
                        busy = false
                        proposal = null
                        onChanged()
                    }
                }) { Text("Yes, this is my personal vault") }
            },
            dismissButton = { TextButton(onClick = { vm.cancelPersonalProposal(); proposal = null }) { Text("Cancel") } },
        )
    }
}

/** "Keep <current>" over a personal-vault change (A5b review LOW-1): a re-designation of the current vault, which
 *  replaces the server's copy and needs a fresh master-password reauth (Q9). */
@Composable
private fun KeepCurrentDialog(vm: AndvariViewModel, p: PersonalVaultProposal, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { vm.cancelPersonalProposal(); onDone() },
        title = { Text("Keep ${p.name ?: "this vault"} as your personal vault?") },
        text = {
            Column {
                ConfirmPersonalText(p)
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    password, { password = it }, Modifier.fillMaxWidth(), label = { Text("Master password (required)") },
                    singleLine = true, visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                )
                err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy && password.isNotEmpty(), onClick = {
                scope.launch {
                    busy = true
                    val failed = runCatching { vm.redesignatePersonalVault(p, password) }.isFailure
                    password = ""
                    busy = false
                    if (failed) err = "Couldn't keep it: wrong master password, or the server refused." else onDone()
                }
            }) { Text("Keep it") }
        },
        dismissButton = { TextButton(onClick = { vm.cancelPersonalProposal(); onDone() }) { Text("Cancel") } },
    )
}
