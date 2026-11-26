package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.Backup
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The file dialog of "Restore a backup" (it shows `.andvari` files), then the file read off the UI thread, never past the
 * largest backup there can be (its size asked before a byte is read). What was picked is used only if [c] is still the
 * open vault. Null when the restore's page opened, or the dialog was cancelled; otherwise what to say in the card.
 */
internal suspend fun pickBackup(model: TrustModel, c: VaultContent): String? {
    val file = FilePicker.open(UiText.ph(Placeholder.RESTORE_ENTRY).shown(), "andvari") ?: return null
    if (!stillOpen(model, c)) return null
    return readBackup(model, c, file)
}

/** The picked [file] read off the UI thread for the restore over [c] (opened as its page), or what the card says instead. */
internal suspend fun readBackup(model: TrustModel, c: VaultContent, file: java.io.File): String? =
    when (val picked = withContext(Dispatchers.IO) { PickedFiles.read(file, Backup.MAX_FILE_BYTES) }) {
        is PickedFiles.Picked.Read -> {
            model.openRestore(c, picked.name, picked.bytes)
            null
        }
        // Larger than any andvari backup can be: its own line, not "not a backup".
        is PickedFiles.Picked.TooLarge -> UiText.ph(Placeholder.RESTORE_TOO_LARGE).shown()
        PickedFiles.Picked.NotRead -> UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()
    }

/**
 * "Restore a backup", in the place of the backup card while it is open: the page [RestoreFlow.page] makes, drawn row by
 * row. Every string, every box with its tick, and the button with whether it can be pressed come made; this draws them
 * and hands a press to the call the row carries, and decides nothing.
 */
@Composable
internal fun RestorePage(model: TrustModel, flow: RestoreFlow) {
    val v by flow.views.collectAsState()
    // Where the restore's record lives is asked again whenever the app's state (a policy read) or the switch changes.
    val snapshot by model.snapshots.collectAsState()
    val keep by model.keepSignIn.collectAsState()
    LaunchedEffect(flow, snapshot, keep) { flow.recheck() }
    val scope = rememberWorkScope()
    val page = flow.page(v)
    PageHeader(page.title, enabled = page.backEnabled) { model.closeRestore() }
    // Keyed by the flow, so that a field's typed text never outlives the file it was typed for.
    key(flow) { for (row in page.rows) RestoreRowDrawn(row, scope) }
}

@Composable
private fun RestoreRowDrawn(row: RestoreRow, scope: WorkScope) {
    when (row) {
        is RestoreRow.Line -> when (row.tone) {
            RestoreRow.Tone.PLAIN -> Say(row.text)
            RestoreRow.Tone.SMALL -> Say(row.text, style = MaterialTheme.typography.bodySmall)
            RestoreRow.Tone.ERROR -> Say(row.text, color = MaterialTheme.colorScheme.error)
        }
        is RestoreRow.Box -> Tick(row.text, row.ticked, enabled = row.enabled, onChange = row.onTick)
        is RestoreRow.Button -> Main(row.text, enabled = row.enabled, busy = row.busy) { scope.launch { row.onPress() } }
        is RestoreRow.Passphrase -> {
            var passphrase by remember { mutableStateOf("") }
            // Taken as characters and the field emptied: the flow zeroes them once the file is opened.
            fun open() {
                if (passphrase.isEmpty() || row.busy) return
                val chars = passphrase.toCharArray()
                passphrase = ""
                scope.launch { row.onOpen(chars) }
            }
            SecretField(row.label, passphrase, onEnter = { open() }) { passphrase = it }
            row.said?.let { Say(it, color = MaterialTheme.colorScheme.error) }
            row.working?.let { Say(it) }
            Main(row.button, enabled = passphrase.isNotEmpty() && !row.busy, busy = row.busy) { open() }
        }
    }
}
