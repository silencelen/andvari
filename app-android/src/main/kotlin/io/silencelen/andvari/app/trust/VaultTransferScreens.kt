package io.silencelen.andvari.app.trust

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import io.silencelen.andvari.core.app.CopyKey
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.ExternalExcursion
import io.silencelen.andvari.app.SecretField
import io.silencelen.andvari.core.app.CsvImportView
import io.silencelen.andvari.core.app.ExportCopy
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.ExportView
import io.silencelen.andvari.core.app.ImportBucketView
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.CsvImport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import io.silencelen.andvari.app.launchOvertakable
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.OutputStream

/**
 * Import a CSV and export a backup or a CSV, over the content (spec 06, spec 07). Every sentence is the content's own
 * ([CsvImportView], [ExportView]); the labels it does not carry are placeholders.
 */
@Composable
internal fun TransferButtons(c: VaultContent, state: ContentState) {
    val t = rememberTransferActions(c)
    t.answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    ButtonRow {
        if (canSave(state)) Quieter(UiText.ph(Placeholder.IMPORT_CSV), enabled = !state.busy) { t.importCsv() }
        Quieter(UiText.ph(Placeholder.EXPORT_BACKUP), enabled = !state.busy) { t.export(ExportKind.BACKUP) }
        Quieter(UiText.ph(Placeholder.EXPORT_CSV), enabled = !state.busy) { t.export(ExportKind.CSV) }
    }
}

/** Import and export as actions, for the vault's top bar and its menu; [answer] is what the last one said. */
internal class TransferActions(val importCsv: () -> Unit, val export: (ExportKind) -> Unit, private val said: androidx.compose.runtime.State<String?>) {
    val answer: String? get() = said.value
}

@Composable
internal fun rememberTransferActions(c: VaultContent): TransferActions {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val answer = remember(c) { mutableStateOf<String?>(null) }
    // The current app's import starts with its sheet: what the file may come from, the warning that it holds every
    // secret in plain text, and how to export from each source; only its "choose file" opens the picker.
    val drawnAsking = LocalFirstVaultView.current?.importAsked == true
    val asking = remember(c) { mutableStateOf(drawnAsking) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launchOvertakable {
                // Never read past the content's own cap for a CSV (CsvImport.MAX_BYTES).
                val picked = withContext(Dispatchers.IO) { PickedFiles.read(context, uri, CsvImport.MAX_BYTES.toLong()) }
                answer.value = when (picked) {
                    // The content zeroes the bytes once read.
                    is PickedFiles.Picked.Read -> transferSentence(c.importCsv(picked.bytes))
                    is PickedFiles.Picked.TooLarge -> csvTooLarge()
                    PickedFiles.Picked.NotRead -> UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()
                }
            }
        }
    }
    if (asking.value) {
        ImportSourceDialog(
            onChoose = {
                asking.value = false
                ExternalExcursion.begin()
                picker.launch(arrayOf("text/csv", "text/comma-separated-values", "text/plain", "application/octet-stream"))
            },
            onCancel = { asking.value = false },
        )
    }
    return remember(c, picker) {
        TransferActions(
            importCsv = { asking.value = true },
            export = { kind -> scope.launchOvertakable { answer.value = transferSentence(c.openExport(kind)) } },
            said = answer,
        )
    }
}

/**
 * The current app's import sheet ("Import passwords (CSV)"), before the file picker: the sources a file may come from,
 * the warning about plain text in error colour, "How do I export from…?" (the shared export steps, closed each time it
 * opens), and "Choose file…" with Cancel.
 */
@Composable
internal fun ImportSourceDialog(onChoose: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        confirmButton = { TextButton(onClick = onChoose) { Say(UiText.ph(Placeholder.IMPORT_CHOOSE_FILE)) } },
        dismissButton = { TextButton(onClick = onCancel) { Say(CopyKey.CANCEL) } },
        title = { Say(UiText.ph(Placeholder.IMPORT_CSV)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Say(UiText.ph(Placeholder.IMPORT_SOURCES), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Gap(8)
                Say(UiText.ph(Placeholder.IMPORT_PLAIN_TEXT), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                var helpOpen by remember { mutableStateOf(false) }
                TextButton(onClick = { helpOpen = !helpOpen }) { Say(UiText.ph(if (helpOpen) Placeholder.IMPORT_HELP_HIDE else Placeholder.IMPORT_HELP)) }
                if (helpOpen) {
                    io.silencelen.andvari.core.client.ImportHelp.SOURCES.forEach { s ->
                        Text(s.label, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
                        s.steps.forEachIndexed { i, step -> Text("${i + 1}. $step", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp)) }
                        s.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 2.dp)) }
                    }
                }
            }
        },
    )
}

/** The import's own space line: shown while the content's check for a CSV import says it does not fit. */
internal fun importSpaceLine(state: ContentState): UiText? {
    val s = state.space ?: return null
    return if (s.forWhat == io.silencelen.andvari.core.app.content.SpaceFor.CSV_IMPORT && s.verdict == io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH) {
        s.line?.let { UiText.of(it) }
    } else {
        null
    }
}

/**
 * The line for a copy that goes on although, by the sizes its files state, it may not fit: informational, whichever
 * copy it is for (an import, a copy into a vault, a move).
 */
internal fun declaredSpaceLine(state: ContentState): UiText? {
    val s = state.space ?: return null
    return if (s.verdict == io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES) s.line?.let { UiText.of(it) } else null
}

/**
 * What a CSV over the content's cap says. The content's own sentence for it (`ImportCopy.TOO_LARGE`) is internal to
 * core, so this is a placeholder naming the cap until the content exposes it.
 */
internal fun csvTooLarge(): String = UiText.ph(Placeholder.IMPORT_TOO_LARGE, sizeText(CsvImport.MAX_BYTES.toLong())).shown()

private fun transferSentence(r: io.silencelen.andvari.core.app.ActionResult): String? = when (r) {
    is io.silencelen.andvari.core.app.ActionResult.Failed -> r.message
    is io.silencelen.andvari.core.app.ActionResult.NotDone -> r.message
    else -> null
}

@Composable
private fun Buckets(buckets: List<ImportBucketView>) {
    buckets.forEach { b ->
        Text(b.title + " (" + b.count + ")", style = MaterialTheme.typography.bodyMedium)
        if (b.names.isNotEmpty()) Text(b.names.joinToString(", "), style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * The import's plan and its run, while the content holds it open ([ContentState.csvImport]), as the current app's
 * import dialog over the vault: its title, the plan (which scrolls), the import (or Try again) and Cancel. Neither
 * Cancel nor Back closes it while the import runs; once it is done, Close.
 */
@Composable
internal fun ImportDialog(c: VaultContent, state: ContentState, v: CsvImportView) {
    val scope = rememberCoroutineScope()
    val canRun = importCanRun(v)
    androidx.compose.material3.AlertDialog(
        onDismissRequest = { if (!v.busy) c.closeImport() },
        title = { Say(UiText.ph(Placeholder.IMPORT_CSV)) },
        text = { Column(Modifier.verticalScroll(rememberScrollState())) { ImportView(c, state, v) } },
        confirmButton = {
            if (canRun) {
                TextButton(onClick = { scope.launchOvertakable { c.confirmImport() } }, enabled = !v.busy && canSave(state) && v.toImport > 0) { Say(UiText.ph(importRunLabel(v))) }
            } else {
                TextButton(onClick = { c.closeImport() }) { Say(UiText.ph(Placeholder.CLOSE)) }
            }
        },
        dismissButton = if (canRun) ({ TextButton(onClick = { c.closeImport() }, enabled = !v.busy) { Say(CopyKey.CANCEL) } }) else null,
    )
}

/**
 * The import can be run from the dialog: before its first run, and again after a stop the content says a retry can
 * finish without duplicates. Not once it is done, and not after a stop that is not retryable (a refusal, or an import
 * kept on this device to be sent later): running it again there could add the same items twice.
 */
internal fun importCanRun(v: CsvImportView): Boolean = v.done == null && !v.kept && (v.error == null || v.retryable)

/**
 * The import's stop is a failure only where it is not [CsvImportView.kept]: an import kept on this device to be sent
 * later is said in the plain colour (section AX, sixth point), and no second run is offered ([importCanRun]).
 */
internal fun importStopIsFailure(v: CsvImportView): Boolean = !v.kept

/** "Try again" only after a stop; "Import" before the first run. */
internal fun importRunLabel(v: CsvImportView): Placeholder = if (v.error != null) Placeholder.TRY_AGAIN else Placeholder.IMPORT_CONFIRM

/** The plan and its run, inside [ImportDialog]: what is read, into which vault, the counts, and how the run went. */
@Composable
internal fun ImportView(c: VaultContent, state: ContentState, v: CsvImportView) {
    val scope = rememberCoroutineScope()
    Text(v.source, style = MaterialTheme.typography.bodyMedium)
    v.note?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    v.vaultChoices.forEach { choice ->
        Row(Modifier.fillMaxWidth().clickable(enabled = !v.busy) { scope.launchOvertakable { c.setImportVault(choice.vaultId) } }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = v.vaultId == choice.vaultId, onClick = { scope.launchOvertakable { c.setImportVault(choice.vaultId) } }, enabled = !v.busy)
            Text(choice.name)
        }
    }
    if (v.vaultChoices.isEmpty()) Text(v.vaultName, style = MaterialTheme.typography.bodyMedium)
    Say(Placeholder.IMPORT_COUNT, v.toImport.toString())
    v.counts.forEach { Say(UiText.Plain(it)) }
    Buckets(v.buckets)
    // Short of space for this import (the content's early check on what this device last heard): its line, under the plan.
    importSpaceLine(state)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
    v.errors.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    v.progress?.let { Say(Placeholder.IMPORT_PROGRESS, it.done.toString(), it.total.toString()) }
    v.error?.let { Say(UiText.Plain(it), color = if (importStopIsFailure(v)) MaterialTheme.colorScheme.error else androidx.compose.ui.graphics.Color.Unspecified) }
    v.done?.let { Say(UiText.Plain(it)) }
}

/**
 * The export screen, while the content holds it open ([ContentState.exporting]). The file is made only after the
 * person picked where it goes, written there once, read back and compared, and its bytes zeroed; a file that did not
 * read back the same is removed.
 */
@Composable
internal fun ExportPanel(c: VaultContent, v: ExportView) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var ack by remember(c, v.kind) { mutableStateOf(false) }
    var passphrase by remember(c, v.kind) { mutableStateOf("") }
    var confirm by remember(c, v.kind) { mutableStateOf("") }
    var writing by remember(c, v.kind) { mutableStateOf(false) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri == null) {
            c.exportNotSaved(false)
            return@rememberLauncherForActivityResult
        }
        writing = true
        scope.launchOvertakable {
            try {
                // The content is made on the content's own thread, as every content call is; a backup's heavy work
                // (key derivation, encryption, its own check) already runs on the content's Default dispatcher.
                // The backup passphrase goes as two CharArrays, which the content zeroes on every path; the fields are
                // emptied once it has them, so the screen holds no copy past the file being made.
                val file = if (v.kind == ExportKind.CSV) {
                    c.csvFile(ack)
                } else {
                    val p = passphrase.toCharArray()
                    val k = confirm.toCharArray()
                    passphrase = ""
                    confirm = ""
                    c.backupFileChars(p, k)
                }
                if (file == null) {
                    // Nothing to write (the screen says why); the empty document the picker made goes.
                    withContext(Dispatchers.IO) { runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) } }
                    return@launchOvertakable
                }
                // Written once, read back and compared, removed if it differs, and its bytes zeroed: off the main
                // thread, and finished even if the screen goes meanwhile, so a bad copy is never left behind.
                val (outcome, name) = withContext(NonCancellable + Dispatchers.IO) {
                    try {
                        val o = writeAndCheck(
                            open = { runCatching { context.contentResolver.openOutputStream(uri, "wt") }.getOrNull() ?: context.contentResolver.openOutputStream(uri) },
                            readBack = { context.contentResolver.openInputStream(uri) },
                            delete = { runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) } },
                            bytes = file.bytes,
                        )
                        o to (if (o == ExportWrite.SAVED) PickedFiles.queriedName(context, uri) else null)
                    } finally {
                        file.bytes.fill(0)
                    }
                }
                when (outcome) {
                    // The picker does not say which folder it was; the content's sentence names the file only.
                    ExportWrite.SAVED -> c.exportSaved(name ?: file.fileName, "")
                    ExportWrite.NOT_OPENED, ExportWrite.NOT_WRITTEN -> c.exportNotSaved(false)
                    ExportWrite.DIFFERS -> c.exportNotSaved(true)
                }
            } finally {
                writing = false
            }
        }
    }
    // The current app's export is a dialog over the screen it was asked from: its title, what goes into the file, the
    // way out, and the main action, which picks where the file goes. While a file is being made, the way out waits.
    val idle = !v.busy && !writing
    AlertDialog(
        onDismissRequest = { if (idle) c.closeExport() },
        title = { Say(UiText.ph(if (v.kind == ExportKind.CSV) Placeholder.EXPORT_CSV else Placeholder.EXPORT_BACKUP)) },
        text = { Column(Modifier.verticalScroll(rememberScrollState())) { ExportBody(c, v, ack, { ack = it }, passphrase, { passphrase = it }, confirm, { confirm = it }, writing) } },
        confirmButton = {
            TextButton(enabled = idle, onClick = {
                ExternalExcursion.begin()
                saver.launch(if (v.kind == ExportKind.CSV) "andvari-export.csv" else "andvari-backup.andvari")
            }) { Say(UiText.ph(Placeholder.EXPORT_CHOOSE_PLACE)) }
        },
        dismissButton = { TextButton(enabled = idle, onClick = { c.closeExport() }) { Say(CopyKey.CANCEL) } },
    )
}

/** What the export dialog shows: the vaults and their counts, the warnings, and the CSV's or the backup's own fields. */
@Composable
private fun ExportBody(
    c: VaultContent,
    v: ExportView,
    ack: Boolean,
    onAck: (Boolean) -> Unit,
    passphrase: String,
    onPassphrase: (String) -> Unit,
    confirm: String,
    onConfirm: (String) -> Unit,
    writing: Boolean,
) {
    v.offlineNote?.let { Say(UiText.Plain(it)) }
    v.vaults.forEach { vault ->
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = vault.included, onCheckedChange = { c.setExportVault(vault.vaultId, it) }, enabled = !vault.personal && !v.busy)
            Text(vault.name + " (" + vault.itemCount + ")")
        }
    }
    Say(Placeholder.EXPORT_COUNT, v.count.toString())
    Buckets(v.warnings)
    if (v.kind == ExportKind.CSV && v.formulaCells.isNotEmpty()) {
        v.formulaCells.forEach { Text(it, style = MaterialTheme.typography.bodySmall) }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = ack, onCheckedChange = onAck)
            Text(ExportCopy.FORMULA_ACK)
        }
    }
    if (v.kind == ExportKind.BACKUP) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = v.includeAttachments, onCheckedChange = { c.setExportAttachments(it) }, enabled = !v.busy)
            Say(Placeholder.EXPORT_FILES, sizeText(v.attachmentBytes))
        }
        if (v.attachmentsLeftOut.isNotEmpty()) Text(v.attachmentsLeftOut.joinToString(", "), style = MaterialTheme.typography.bodySmall)
        SecretField(UiText.ph(Placeholder.EXPORT_PASSPHRASE).shown(), passphrase) { onPassphrase(it) }
        SecretField(UiText.ph(Placeholder.EXPORT_PASSPHRASE_AGAIN).shown(), confirm) { onConfirm(it) }
    }
    v.error?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    v.done?.let { Say(UiText.Plain(it)) }
    if (v.busy || writing) Say(Placeholder.WORKING)
}

/** What writing an export file came to. */
internal enum class ExportWrite {
    /** The place could not be opened for writing; nothing was written. */
    NOT_OPENED,

    /** The write failed; what was there is removed. */
    NOT_WRITTEN,

    /** It was written but did not read back the same (or could not be read back); it is removed. */
    DIFFERS,

    /** Written once and read back the same. */
    SAVED,
}

/**
 * Write [bytes] once through [open], read them back through [readBack] (never more than their own length plus one)
 * and compare; [delete] removes a file that failed the write or the comparison. Blocking: call it off the main thread.
 * The read-back copy is zeroed; [bytes] are the caller's to zero.
 */
internal fun writeAndCheck(open: () -> OutputStream?, readBack: () -> InputStream?, delete: () -> Unit, bytes: ByteArray): ExportWrite {
    val out = runCatching { open() }.getOrNull() ?: return ExportWrite.NOT_OPENED
    if (runCatching { out.use { it.write(bytes) } }.isFailure) {
        delete()
        return ExportWrite.NOT_WRITTEN
    }
    val back = runCatching { readBack()?.use { PickedFiles.readAtMost(it, bytes.size) } }.getOrNull()
    val same = back != null && back.contentEquals(bytes)
    back?.fill(0)
    if (!same) {
        delete()
        return ExportWrite.DIFFERS
    }
    return ExportWrite.SAVED
}
