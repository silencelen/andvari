package io.silencelen.andvari.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.CoHolder
import io.silencelen.andvari.core.client.LegacyGrantRow
import io.silencelen.andvari.core.client.OwnershipClaim
import io.silencelen.andvari.core.client.OwnershipTransferAckRequiredException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.ReauthFailedException
import io.silencelen.andvari.core.client.ReauthStaleSessionException
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.VaultInfo
import kotlinx.coroutines.launch

// Grant re-issue authority (security review 2026-10, root cause A, branch A6b). The two owner-side surfaces that let
// a human, and only a human, authorize what the server's labels used to: "You own <vault>?" (a password reauth that
// records this account's own ownership evidence) and the "Legacy grants" list (a per-row "Re-share <vault> with
// <member>?"). Kept identical between the Android and desktop apps except for the state holder's type.

/**
 * "You own <vault>?" (review MEDIUM-1): the server reports this account as the owner, but this device has no record
 * that the account created the vault or that its owner transferred it here. Like A5b's personal-vault choice, the
 * dialog first loads and shows what the SERVER reports (its owner, its last transfer, the co-holders), then asks for
 * a fresh master password (checked on this device). A vault this device first received as a MEMBER also needs the
 * explicit "This vault's owner transferred it to me".
 */
@Composable
internal fun OwnershipConfirmCard(vm: AndvariViewModel, v: VaultInfo, onConfirmed: () -> Unit) {
    val scope = rememberCoroutineScope()
    var claim by remember(v.vaultId) { mutableStateOf<OwnershipClaim?>(null) }
    var password by remember(v.vaultId) { mutableStateOf("") }
    var ack by remember(v.vaultId) { mutableStateOf(false) }
    var busy by remember(v.vaultId) { mutableStateOf(false) }
    var err by remember(v.vaultId) { mutableStateOf<String?>(null) }
    val who = { c: CoHolder -> if (c.displayName.isNotEmpty()) "${c.displayName} (${c.email})" else "someone this device can't name" }
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(12.dp)) {
            Text("You own “${v.name}”?", style = MaterialTheme.typography.titleSmall)
            Text(
                "The server reports you as its owner, but this device has no record that you created this vault or that its " +
                    "owner transferred it to you. Only confirm if you created this vault, or its owner transferred it to you. " +
                    "Otherwise, don't confirm: tell your admin.",
                style = MaterialTheme.typography.bodySmall,
            )
            err?.takeIf { claim == null }?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(6.dp))
            OutlinedButton(enabled = !busy, onClick = {
                scope.launch {
                    busy = true
                    err = null
                    claim = runCatching { vm.describeVaultOwnership(v.vaultId) }
                        .onFailure { err = "Couldn't load who holds this vault, or its key did not come from your own account." }.getOrNull()
                    busy = false
                }
            }) { Text("Confirm I own “${v.name}”…") }
        }
    }
    claim?.let { c ->
        val close = { vm.cancelOwnershipClaim(); claim = null; password = ""; ack = false; err = null }
        AlertDialog(
            onDismissRequest = close,
            title = { Text("You own “${c.vaultName ?: v.name}”?") },
            text = {
                Column {
                    Text("Only confirm if you created this vault, or its owner transferred it to you.")
                    Spacer(Modifier.height(6.dp))
                    Text(
                        (c.lastTransferTo?.let { "Last ownership transfer: to ${who(it)}, transfer #${c.lastTransferSeq}" }
                            ?: "Created by ${c.reportedOwner?.let(who) ?: "an unknown owner"}; no transfer on record") + " (as reported by the server)",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Text(
                        "Also holding this vault: " + (if (c.coHolders.isEmpty()) "no one else" else c.coHolders.joinToString("; ") { "${who(it)}, ${it.role}" }) +
                            " (as reported by the server)",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (c.receivedAsMember) {
                        Spacer(Modifier.height(6.dp))
                        Text("This device first received this vault as a member.", style = MaterialTheme.typography.bodySmall)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(checked = ack, onCheckedChange = { ack = it })
                            Text("This vault's owner transferred it to me", style = MaterialTheme.typography.bodySmall)
                        }
                    }
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
                TextButton(enabled = !busy && password.isNotEmpty() && (!c.receivedAsMember || ack), onClick = {
                    scope.launch {
                        busy = true
                        val failure = runCatching { vm.confirmVaultOwnership(c, password, ack) }.exceptionOrNull()
                        password = ""
                        busy = false
                        if (failure == null) {
                            claim = null
                            err = null
                            onConfirmed()
                        } else {
                            err = when (failure) {
                                is ReauthFailedException -> HouseholdCopy.REAUTH_FAILED
                                // A1b (A6b carry-forward): a session salt that is stale since a password change / KDF upgrade.
                                is ReauthStaleSessionException -> HouseholdCopy.REAUTH_STALE_SESSION
                                is OwnershipTransferAckRequiredException -> "Tick “This vault's owner transferred it to me” only if that is true."
                                else -> "Couldn't confirm it. Try again."
                            }
                        }
                    }
                }) { Text("Confirm") }
            },
            dismissButton = { TextButton(onClick = close) { Text("Cancel") } },
        )
    }
}

/**
 * §8.2 step 4, "Legacy grants": the members the SERVER lists as still on the older grant format. Nothing is re-shared
 * on its own: the owner confirms each row, which names the vault and the member as this device verified them. (A pair
 * this account already re-shared, for the same identity key, is renewed without a prompt when the list loads.)
 */
@Composable
internal fun LegacyGrantsCard(vm: AndvariViewModel, v: VaultInfo) {
    val scope = rememberCoroutineScope()
    var rows by remember(v.vaultId) { mutableStateOf<List<LegacyGrantRow>>(emptyList()) }
    var confirming by remember(v.vaultId) { mutableStateOf<LegacyGrantRow?>(null) }
    var busy by remember(v.vaultId) { mutableStateOf(false) }
    var err by remember(v.vaultId) { mutableStateOf<String?>(null) }
    LaunchedEffect(v.vaultId) {
        rows = runCatching { vm.loadLegacyGrants(v.vaultId) }.getOrDefault(emptyList())
    }
    if (rows.isEmpty()) return
    val nameOf = { r: LegacyGrantRow -> r.vaultName ?: v.name }
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.padding(12.dp)) {
            Text("Legacy grants", style = MaterialTheme.typography.titleSmall)
            Text(
                "The server lists these members as still on the old sharing format. Only confirm people you shared this vault with.",
                style = MaterialTheme.typography.bodySmall,
            )
            err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            rows.forEach { r ->
                Spacer(Modifier.height(6.dp))
                when {
                    r.pinState == SyncEngine.MemberPinState.PINNED && r.verifiedLabel != null ->
                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text(
                                "${r.verifiedLabel} (verified; the server calls them ${r.displayName}, ${r.email})",
                                Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
                            )
                            TextButton(onClick = { confirming = r }, enabled = !busy) { Text("Re-share…") }
                        }
                    r.pinState == SyncEngine.MemberPinState.KEY_CHANGED ->
                        Text(
                            "${r.displayName}: the server holds a different identity key than the one you verified. Don't re-share; " +
                                "check their code in person again.",
                            color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall,
                        )
                    else ->
                        Text(
                            "Verify ${r.displayName} (${r.email}) first (Settings → Household members), then re-share “${nameOf(r)}” with them here.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                }
            }
        }
    }
    confirming?.let { r ->
        AlertDialog(
            onDismissRequest = { confirming = null },
            title = { Text("Re-share “${nameOf(r)}” with ${r.verifiedLabel}?") },
            text = {
                Text(
                    "${r.verifiedLabel} gets a new-format key to “${nameOf(r)}”, signed by you. Only confirm if you shared this " +
                        "vault with them: the list itself comes from the server.",
                )
            },
            confirmButton = {
                TextButton(enabled = !busy, onClick = {
                    scope.launch {
                        busy = true
                        err = runCatching { vm.confirmReissue(r) }.exceptionOrNull()?.let { "Couldn't re-share. Verify them again and retry." }
                        rows = vm.legacyGrantRows(v.vaultId)
                        busy = false
                        confirming = null
                    }
                }) { Text("Re-share") }
            },
            dismissButton = { TextButton(onClick = { confirming = null }) { Text("Cancel") } },
        )
    }
}
