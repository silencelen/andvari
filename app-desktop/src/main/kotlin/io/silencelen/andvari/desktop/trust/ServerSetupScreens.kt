package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Alignment
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceDetails
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ServerSetupStep

/**
 * §6.7 setup link, step 3, on the desktop: the first operator's computer signs card 0, uploads it and
 * pins it. Three states: signing; FINISHED, with what "Instance details" shows (the operator key to compare with what
 * the server's setup printed, the card's number, card 0's hash for the store builds) and the way on to the recovery
 * kit, which is held behind this screen; NOT_UPLOADED, with the retry, whose master password is asked in a step of its
 * own, as every operator action's is ([SetupPasswordStep]).
 */
@Composable
internal fun ServerSetupScreen(model: TrustModel, s: AppSnapshot, screen: EntryScreen.ServerSetup) {
    var retrying by remember(screen) { mutableStateOf(false) }
    AuthColumn {
        // A window that stands alone: the brand head with the setup's title, and the server's address quietly under it.
        WindowHead(UiText.ph(Placeholder.SETUP_TITLE, plainName(screen.instance.name)))
        Text(
            screen.instance.origin, Modifier.fillMaxWidth().padding(bottom = 12.dp), color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, textAlign = TextAlign.Center),
        )
        when (screen.step) {
            // The current app's wait: its small spinner beside the line.
            ServerSetupStep.SIGNING -> Row(verticalAlignment = Alignment.CenterVertically) {
                OpeningSpinner()
                Say(UiText.ph(Placeholder.SETUP_SIGNING), Modifier.padding(start = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            ServerSetupStep.FINISHED -> {
                Say(UiText.ph(Placeholder.SETUP_FINISHED))
                // What to compare with the server's setup, in the current app's card for something to check by hand.
                screen.details?.let { CodeCard { SetupDetails(it) } }
                Gap()
                // The kit comes after the setup: card 0 is signed inside the registration and the kit names it.
                Main(UiText.ph(Placeholder.SETUP_TO_KIT), enabled = !s.busy, busy = false) { model.act { entry.finishServerSetup(screen) } }
            }
            ServerSetupStep.NOT_UPLOADED -> {
                Say(UiText.ph(Placeholder.SETUP_NOT_UPLOADED), color = MaterialTheme.colorScheme.error)
                Main(UiText.ph(Placeholder.SETUP_RETRY), enabled = !s.busy, busy = s.busy) { retrying = true }
            }
        }
        SaidHere(model, s)
    }
    if (retrying && screen.step == ServerSetupStep.NOT_UPLOADED) {
        SetupPasswordStep(model, s, plainName(screen.instance.name), screen.instance.origin, null, onCancel = { retrying = false }) { pw, closed ->
            model.runSaying({ entry.retryServerSetup(screen, pw) }, ::setupRetryWords) { r -> if (r != ServerResult.WRONG_PASSWORD) closed() }
        }
    }
}

/** What a retry answered: a wrong password in the step's words; the rest as every result is said. */
internal fun setupRetryWords(r: ServerResult): UiText? = when (r) {
    ServerResult.DONE -> null
    ServerResult.WRONG_PASSWORD -> UiText.ph(Placeholder.OP_WRONG_PASSWORD)
    else -> UiText.forResult(r, 0)
}

/** "Instance details" after the setup: the operator key (to compare), the card's number, card 0's hash. */
@Composable
private fun SetupDetails(d: InstanceDetails) {
    Say(Placeholder.OPERATOR_KEY, style = MaterialTheme.typography.labelSmall)
    Text(d.operatorKeyShort.chunked(4).joinToString(" "), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
    Quiet(UiText.ph(Placeholder.SETUP_COMPARE_KEY))
    Text("#${d.cardSeq}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    if (d.card0Hash.isNotEmpty()) {
        Say(Placeholder.SETUP_CARD0_HASH, style = MaterialTheme.typography.labelSmall)
        OneLine(d.card0Hash, MaterialTheme.typography.bodySmall, mono = true)
    }
}

/**
 * The open vault's prompt while the operator's server has no card pinned (§6.7 Resume): what it is, the server's
 * address, and "Finish setting up this server", whose master password is asked in a step of its own.
 */
@Composable
internal fun FinishServerSetupPrompt(model: TrustModel, s: AppSnapshot, p: AccountPrompt.FinishServerSetup) {
    var open by remember(p.origin) { mutableStateOf(false) }
    Say(UiText.ph(Placeholder.SETUP_UNFINISHED))
    Origin(p.origin)
    Second(UiText.of(p.label), enabled = !s.busy) { open = true }
    if (open) {
        SetupPasswordStep(model, s, null, p.origin, masterPasswordFor(s), onCancel = { open = false }) { pw, closed ->
            // Through the operator model, the one place that calls the operator interface.
            model.operator.finishServerSetup(pw) { r -> if (r != OperatorResult.WRONG_PASSWORD) closed() }
        }
    }
}

/**
 * The step that takes the master password for the setup's upload: a dialog of a fixed layout (nothing above the field
 * can change while it is open), Cancel first and Escape's, Enter sending from the field. A wrong password keeps it open
 * and empties the field; any other answer closes it. Nothing is focused by itself (§12.1).
 */
@Composable
private fun SetupPasswordStep(
    model: TrustModel,
    s: AppSnapshot,
    server: String?,
    origin: String,
    passwordFor: UiText?,
    onCancel: () -> Unit,
    send: (String, closed: () -> Unit) -> Unit,
) {
    var password by remember { mutableStateOf("") }
    val go = {
        if (password.isNotEmpty() && !s.busy) {
            val pw = password
            password = ""
            send(pw, onCancel)
        }
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Say(UiText.of(CopyKey.FINISH_SERVER_SETUP), style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(Modifier.widthIn(min = 320.dp, max = 560.dp).verticalScroll(rememberScrollState())) {
                Say(UiText.ph(Placeholder.SETUP_STEP_WHAT))
                Gap(8)
                server?.let {
                    Say(UiText.ph(Placeholder.OP_STEP_SERVER), style = MaterialTheme.typography.labelSmall)
                    OneLine(it, mono = true)
                }
                Say(UiText.ph(Placeholder.OP_STEP_SERVER_ADDRESS), style = MaterialTheme.typography.labelSmall)
                OneLine(origin, mono = true)
                Gap(8)
                passwordFor?.let { Say(it, style = MaterialTheme.typography.bodySmall) }
                SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), password, onEnter = go) { password = it }
                // What the step answered, in a slot of a fixed height: nothing above moves when it comes.
                Box(Modifier.fillMaxWidth().height(56.dp).verticalScroll(rememberScrollState())) { SaidHere(model, s) }
            }
        },
        dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = onCancel) },
        confirmButton = { DialogButton(UiText.ph(Placeholder.SETUP_SEND), enabled = password.isNotEmpty() && !s.busy, onClick = go) },
    )
}
