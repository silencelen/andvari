package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CsvImportView
import io.silencelen.andvari.core.app.ExportCopy
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.ExportView
import io.silencelen.andvari.core.app.ImportBucketView
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.desktop.SAVE_OUTSIDE_FOLDER
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.io.File
import java.time.LocalDate

/**
 * Import a CSV and export a backup or a CSV, over the content (spec 06, spec 07), ported from the Android app with
 * the desktop's own file dialogs. Every sentence is the content's own ([CsvImportView], [ExportView]); the labels it
 * does not carry are placeholders.
 */
@Composable
internal fun ImportRequests(model: TrustModel, c: VaultContent, state: ContentState) {
    var answer by remember(c) { mutableStateOf<String?>(null) }
    // The toolbar's import and the menu's Import: one file dialog per request, and only where a save is possible.
    val wanted by model.importRequested.collectAsState()
    val savable = canSave(state)
    LaunchedEffect(wanted, c) {
        if (wanted) {
            model.importTaken()
            if (savable && !state.busy) {
                val file = FilePicker.open(UiText.ph(Placeholder.IMPORT_CSV).shown())
                // As the work scope's launches: the lock, or a fault said in place, never a crash.
                if (file != null && stillOpen(model, c)) {
                    try {
                        answer = importPicked(c, file)
                    } catch (t: Throwable) {
                        Overtaken.handle(t, model::lockOvertook, model.fault, null)
                    }
                }
            }
        }
    }
    answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
}

/**
 * The backup and the export, as the current app's "Vault backup" card in Settings. Either opens its panel over the
 * vault ([ExportPanel]), and the signed-in shell goes to the vault page to show it.
 */
@Composable
internal fun BackupSection(model: TrustModel) {
    val content by model.content.collectAsState()
    val c = content ?: return
    val state by c.states.collectAsState()
    val scope = rememberWorkScope()
    var answer by remember(c) { mutableStateOf<String?>(null) }
    // "Restore a backup" takes the card's place while it is open, over this unlock's vault only.
    val restoring by model.restoring.collectAsState()
    restoring?.takeIf { it.content === c }?.let { flow ->
        SectionCard { RestorePage(model, flow) }
        return
    }
    SectionCard {
        SectionTitle(Placeholder.BACKUP_TITLE)
        answer?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
        Main(UiText.ph(Placeholder.EXPORT_BACKUP), enabled = !state.busy, busy = false) { scope.launch { answer = sentence(c.openExport(ExportKind.BACKUP)) } }
        Second(UiText.ph(Placeholder.EXPORT_CSV), enabled = !state.busy) { scope.launch { answer = sentence(c.openExport(ExportKind.CSV)) } }
        // The third entry (decided on 21 November 2026): a restore writes, so only where a save is possible.
        Second(UiText.ph(Placeholder.RESTORE_ENTRY), enabled = !state.busy && canSave(state)) { scope.launch { answer = pickBackup(model, c) } }
    }
}

/**
 * A file dialog returned: the person was here all along, so the idle clock starts again, and what was picked is used
 * only if the vault it was picked for is still the open one (the dialog blocks the window, not the idle lock).
 */
internal fun stillOpen(model: TrustModel, c: VaultContent): Boolean {
    model.dialogReturned()
    return model.content.value === c
}

/** Reads a picked CSV, never past the content's own cap ([CsvImport.MAX_BYTES]), off the UI thread, and plans it. */
internal suspend fun importPicked(c: VaultContent, file: File): String? =
    when (val picked = withContext(Dispatchers.IO) { PickedFiles.read(file, CsvImport.MAX_BYTES.toLong()) }) {
        // The content zeroes the bytes once read.
        is PickedFiles.Picked.Read -> sentence(c.importCsv(picked.bytes))
        is PickedFiles.Picked.TooLarge -> csvTooLarge()
        PickedFiles.Picked.NotRead -> UiText.ph(Placeholder.ATTACHMENT_NOT_READ).shown()
    }

/**
 * What a CSV over the content's cap says. The content's own sentence for it (`ImportCopy.TOO_LARGE`) is internal to
 * core, so this is a placeholder naming the cap until the content exposes it.
 */
/**
 * The import's button: "try again" only after an import stopped with a reason that a retry can mend ([CsvImportView.error]
 * with [CsvImportView.retryable], which core sets true before any attempt); "import" before the first (a fresh import had
 * offered "try again").
 */
internal fun importButton(v: CsvImportView): Placeholder =
    if (v.error != null && v.retryable) Placeholder.TRY_AGAIN else Placeholder.IMPORT_CONFIRM

internal fun csvTooLarge(): String = UiText.ph(Placeholder.IMPORT_TOO_LARGE, sizeText(CsvImport.MAX_BYTES.toLong())).shown()

@Composable
private fun Buckets(buckets: List<ImportBucketView>) {
    buckets.forEach { b ->
        Text(b.title + " (" + b.count + ")", style = MaterialTheme.typography.bodyMedium)
        if (b.names.isNotEmpty()) Text(b.names.joinToString(", "), style = MaterialTheme.typography.bodySmall)
    }
}

/** The import's plan and its run, while the content holds it open ([ContentState.csvImport]). */
@Composable
internal fun ImportView(c: VaultContent, state: ContentState, v: CsvImportView) {
    val scope = rememberWorkScope()
    PageHeader(UiText.ph(Placeholder.IMPORT_CSV), enabled = !v.busy) { c.closeImport() }
    Text(v.source, style = MaterialTheme.typography.bodyMedium)
    v.note?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    v.vaultChoices.forEach { choice ->
        Row(Modifier.fillMaxWidth().clickable(enabled = !v.busy) { scope.launch { c.setImportVault(choice.vaultId) } }.padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            RadioButton(selected = v.vaultId == choice.vaultId, onClick = { scope.launch { c.setImportVault(choice.vaultId) } }, enabled = !v.busy)
            Text(choice.name)
        }
    }
    if (v.vaultChoices.isEmpty()) Text(v.vaultName, style = MaterialTheme.typography.bodyMedium)
    Say(Placeholder.IMPORT_COUNT, v.toImport.toString())
    v.counts.forEach { Say(UiText.Plain(it)) }
    Buckets(v.buckets)
    v.errors.forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
    // Before the import: short of space, with the limit and the amount (the content's own check of the plan).
    // After a confirm the import's error holds the full sentence, so the line is not said twice.
    if (v.error == null) spaceLine(state, informational = false)?.let { Say(it, color = MaterialTheme.colorScheme.error) }
    v.progress?.let { Say(Placeholder.IMPORT_PROGRESS, it.done.toString(), it.total.toString()) }
    v.error?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
    v.done?.let { Say(UiText.Plain(it)) }
    if (v.done == null) {
        val label = importButton(v)
        Main(UiText.ph(label), enabled = !v.busy && canSave(state) && v.toImport > 0, busy = v.busy) { scope.launch { c.confirmImport() } }
    }
}

/**
 * Audit F31, carried over from the old backup dialog: the passphrase's strength, and the pattern sentence when it is
 * weaker than it looks. The content refuses a passphrase under "good" on the same pattern-aware score, so without this
 * line its refusal could not be explained. It never gates by itself.
 */
@Composable
internal fun PassphraseStrength(passphrase: String) {
    // In a slot of a fixed height: the second field does not move while the first is typed in.
    FixedSlot(STRENGTH_SLOT) {
        if (passphrase.isNotEmpty()) {
            val pattern = Strength.patternWarning(passphrase)
            Text("strength: ${Strength.label(Strength.estimateStrength(passphrase))}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            pattern?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary) }
        }
    }
}

/** The slot for what the export screen says above its button. */
private val EXPORT_SAID_SLOT = 64.dp

/** The name the Save dialog suggests for an export: the old desktop's, dated. */
internal fun exportFileName(kind: ExportKind, today: LocalDate = LocalDate.now()): String =
    if (kind == ExportKind.CSV) "andvari-export-$today.csv" else "andvari-backup-$today.andvari"

/**
 * The export screen, while the content holds it open ([ContentState.exporting]). The file is made only after the
 * person picked where it goes (and agreed to replace a file already there), written there once off the UI thread,
 * read back and compared, and its bytes zeroed; a file that did not read back the same is removed ([writeVerified]).
 * The backup's passphrase reaches the content as characters ([VaultContent.backupFileChars]), which it zeroes.
 */
@Composable
internal fun ExportPanel(model: TrustModel, c: VaultContent, v: ExportView) {
    val scope = rememberWorkScope()
    val overwrite = remember(c, v.kind) { OverwriteGate() }
    var ack by remember(c, v.kind) { mutableStateOf(false) }
    var passphrase by remember(c, v.kind) { mutableStateOf("") }
    var confirm by remember(c, v.kind) { mutableStateOf("") }
    var writing by remember(c, v.kind) { mutableStateOf(false) }
    var said by remember(c, v.kind) { mutableStateOf<String?>(null) }

    fun writeTo(dest: File) {
        writing = true
        said = null
        // Taken now, as characters, and the fields emptied: the content zeroes the arrays.
        val pass = passphrase.toCharArray()
        val again = confirm.toCharArray()
        if (v.kind == ExportKind.BACKUP) {
            passphrase = ""
            confirm = ""
        }
        scope.launch {
            try {
                // Made on the content's own thread, as every content call is; a backup's heavy work (key derivation,
                // encryption, its own check) already runs on the content's Default dispatcher.
                val file = if (v.kind == ExportKind.CSV) c.csvFile(ack) else c.backupFileChars(pass, again)
                // Nothing to write: the screen says why.
                file ?: return@launch
                // Written once, read back and compared, removed if it differs, and its bytes zeroed: off the UI thread,
                // and finished even if the screen goes meanwhile, so a bad copy is never left behind.
                val written = withContext(NonCancellable + Dispatchers.IO) {
                    try {
                        writeVerified(dest, file.bytes)
                    } finally {
                        file.bytes.fill(0)
                    }
                }
                when (written.result) {
                    ExportWrite.SAVED -> c.exportSaved(dest.name, dest.absoluteFile.parent ?: "")
                    ExportWrite.NOT_OPENED, ExportWrite.NOT_WRITTEN -> c.exportNotSaved(false)
                    ExportWrite.DIFFERS -> c.exportNotSaved(true)
                }
                written.keptAs?.let { said = UiText.ph(Placeholder.FILE_KEPT_ASIDE, it).shown() }
            } finally {
                pass.fill('\u0000')
                again.fill('\u0000')
                writing = false
            }
        }
    }

    ReplaceFileDialog(overwrite)
    PageHeader(UiText.ph(if (v.kind == ExportKind.CSV) Placeholder.EXPORT_CSV else Placeholder.EXPORT_BACKUP), enabled = !v.busy && !writing) { c.closeExport() }
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
        Tick(UiText.Plain(ExportCopy.FORMULA_ACK), ack) { ack = it }
    }
    if (v.kind == ExportKind.BACKUP) {
        Tick(UiText.ph(Placeholder.EXPORT_FILES, sizeText(v.attachmentBytes)), v.includeAttachments, enabled = !v.busy) { c.setExportAttachments(it) }
        if (v.attachmentsLeftOut.isNotEmpty()) Text(v.attachmentsLeftOut.joinToString(", "), style = MaterialTheme.typography.bodySmall)
        SecretField(UiText.ph(Placeholder.EXPORT_PASSPHRASE), passphrase) { passphrase = it }
        PassphraseStrength(passphrase)
        SecretField(UiText.ph(Placeholder.EXPORT_PASSPHRASE_AGAIN), confirm) { confirm = it }
    }
    // What the export said, in a slot of a fixed height: the button under it does not move when a line comes.
    FixedSlot(EXPORT_SAID_SLOT) {
        v.error?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
        v.done?.let { Say(UiText.Plain(it)) }
        said?.let { Say(UiText.Plain(it), color = MaterialTheme.colorScheme.error) }
        if (v.busy || writing) Say(Placeholder.WORKING)
    }
    Main(UiText.ph(Placeholder.EXPORT_CHOOSE_PLACE), enabled = !v.busy && !writing, busy = v.busy || writing) {
        when (val pick = FilePicker.save(UiText.ph(Placeholder.EXPORT_CHOOSE_PLACE).shown(), exportFileName(v.kind))) {
            // A cancelled dialog leaves the screen as it was, for another go.
            FilePicker.SavePick.Cancelled -> {}
            FilePicker.SavePick.Outside -> said = SAVE_OUTSIDE_FOLDER
            is FilePicker.SavePick.At -> if (stillOpen(model, c)) overwrite.request(pick.file) { writeTo(pick.file) }
        }
    }
}
