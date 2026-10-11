package io.silencelen.andvari.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.client.CoHolder
import io.silencelen.andvari.core.client.PendingInvitation
import io.silencelen.andvari.core.crypto.Fingerprint
import kotlinx.coroutines.launch

/*
 * Signed vault grants on Android (security review 2026-10, root cause A §1.6, §8.2; branch A6). Every decision is
 * core's (SyncEngine): these cards only collect human input.
 *  - A pending invitation comes from someone this device has not verified. The vault's name is NOT shown (it would
 *    decrypt under a key nobody authenticated); accepting means comparing codes with the sender, then core re-runs
 *    the grant check.
 *  - "Review your shared vaults" lists vaults readable only through a legacy grant nobody vouched for: readable,
 *    never written to, until the member accepts (trust on first use, said plainly) or leaves.
 */

/** True when either card has something to show (the attention area counts it). */
fun signedGrantNeedsAttention(vm: AndvariViewModel): Boolean =
    vm.pendingInvitations().isNotEmpty() || vm.legacyReviewVaults().isNotEmpty()

@Composable
fun SignedGrantCards(vm: AndvariViewModel, onChanged: () -> Unit) {
    var tick by remember { mutableIntStateOf(0) }
    val invitations = remember(tick) { vm.pendingInvitations() }
    val legacy = remember(tick) { vm.legacyReviewVaults() }
    for (inv in invitations) InvitationCard(vm, inv) { tick++; onChanged() }
    if (legacy.isNotEmpty()) LegacyReviewCard(vm, legacy) { tick++; onChanged() }
}

@Composable
private fun InvitationCard(vm: AndvariViewModel, inv: PendingInvitation, onChanged: () -> Unit) {
    var sender by remember(inv.grantIdB64) { mutableStateOf<io.silencelen.andvari.core.model.UserLookupResponse?>(null) }
    var verifying by remember { mutableStateOf(false) }
    LaunchedEffect(inv.grantIdB64) { sender = runCatching { vm.invitationSender(inv) }.getOrNull() }
    val who = sender?.displayName?.let { "$it (as the server names them)" } ?: "Someone"
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text("$who wants to share a vault with you.", style = MaterialTheme.typography.titleSmall)
            Text(
                "Verify them to accept: compare identity codes in person or on a call you trust. Until then the vault stays closed.",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = sender != null, onClick = { verifying = true }) { Text("Verify and accept") }
                TextButton(onClick = { vm.declineInvitation(inv); onChanged() }) { Text("Decline") }
            }
        }
    }
    val s = sender
    if (verifying && s != null) VerifySenderDialog(vm, inv, s.displayName) { done -> verifying = false; if (done) onChanged() }
}

@Composable
private fun VerifySenderDialog(vm: AndvariViewModel, inv: PendingInvitation, name: String, onDone: (Boolean) -> Unit) {
    val scope = rememberCoroutineScope()
    var typed by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { onDone(false) },
        title = { Text("Verify $name") },
        text = {
            Column {
                Text("Do this together, in person or on a call you trust.", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Text("Your code (read it to them):", style = MaterialTheme.typography.labelSmall)
                SelectionContainer { Text(vm.identityCode()?.let { Fingerprint.groupedShort(it) } ?: "…", fontFamily = FontFamily.Monospace) }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    typed, { typed = it }, Modifier.fillMaxWidth(),
                    label = { Text("$name's code, from THEIR screen (32 characters)") }, singleLine = true,
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
                err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(enabled = !busy && typed.isNotBlank(), onClick = {
                scope.launch {
                    busy = true
                    err = null
                    val ok = runCatching { vm.acceptInvitation(inv, typed) }.getOrDefault(false)
                    busy = false
                    if (ok) onDone(true)
                    else err = "That code doesn't match, or the invitation didn't verify. If they read it correctly from their own screen, STOP and tell your admin."
                }
            }) { Text("Verify") }
        },
        dismissButton = { TextButton(onClick = { onDone(false) }) { Text("Cancel") } },
    )
}

@Composable
private fun LegacyReviewCard(vm: AndvariViewModel, vaults: List<io.silencelen.andvari.core.client.LegacyVaultReview>, onChanged: () -> Unit) {
    val scope = rememberCoroutineScope()
    var owners by remember { mutableStateOf<Map<String, CoHolder?>>(emptyMap()) }
    var err by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(vaults.map { it.vaultId }) { owners = vaults.associate { it.vaultId to vm.reportedOwner(it.vaultId) } }
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text("Review your shared vaults", style = MaterialTheme.typography.titleSmall)
            Text(
                "These vaults were shared in a way andvari can't check: it can't confirm who sent them. You can read them, but nothing is saved into them until you accept. Accept only a vault you expected to be in; that is trust on first use. If you don't recognise one, leave it and tell your admin.",
                style = MaterialTheme.typography.bodySmall,
            )
            for (v in vaults) {
                Spacer(Modifier.height(6.dp))
                val owner = owners[v.vaultId]?.let { "owner ${it.displayName} (as reported by the server)" } ?: "owner unknown"
                Text("${v.name ?: "(unnamed)"} · not yet verified · ${v.itemCount} items · $owner", style = MaterialTheme.typography.bodyMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(enabled = !busy, onClick = {
                        scope.launch {
                            busy = true
                            err = runCatching { vm.acceptLegacyVault(v.vaultId) }.exceptionOrNull()?.let { "Couldn't accept it. Try again." }
                            busy = false
                            onChanged()
                        }
                    }) { Text("Accept") }
                    TextButton(enabled = !busy, onClick = { vm.leaveVault(v.vaultId); onChanged() }) { Text("Leave") }
                }
            }
            err?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
        }
    }
}
