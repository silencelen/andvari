package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.AttachmentPlan
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.ExportVault
import io.silencelen.andvari.core.client.TerminalText

/** What the export screen makes (spec 07; the Android and desktop apps' flows on core's Export). */
enum class ExportKind {
    /** A `.andvari` backup: every item of the vaults chosen, encrypted under a passphrase set here; files optional. */
    BACKUP,

    /** A CSV for another password manager: the logins of the vaults chosen, in plain text. */
    CSV,
}

/**
 * The export screen: what the export would hold, by vault, before the person picks a folder for it. Nothing is written
 * anywhere but that folder: the file is made in memory and written there once, then read back and compared.
 */
data class ExportView(
    val kind: ExportKind,
    /** Every vault this device holds the key of, in export order; the personal vault is always in. */
    val vaults: List<ExportVaultView>,
    /** The sync before the export did not reach the server: the export holds the vault as of the last sync. */
    val offlineNote: String?,
    /** CSV: the logins written. Backup: the items of the vaults chosen. */
    val count: Int,
    /** CSV: what the file leaves out or changes, by the items' names (capped; [ImportBucketView.count] is the total). */
    val warnings: List<ImportBucketView>,
    /** CSV: the cells a spreadsheet would run as formulas ("Password of “GitHub”"); writing waits for [ExportCopy.FORMULA_ACK]. */
    val formulaCells: List<String>,
    /** Backup: whether the files attached to items go in, how much they hold, and the files left out by name. */
    val includeAttachments: Boolean,
    val attachmentBytes: Long,
    val attachmentsLeftOut: List<String>,
    val busy: Boolean,
    /** Why nothing was written, or why the screen came back. */
    val error: String?,
    /** Saved: what was written, and where. */
    val done: String?,
)

data class ExportVaultView(
    val vaultId: String,
    val name: String,
    val personal: Boolean,
    val itemCount: Int,
    val included: Boolean,
)

/** The file an export made, in memory, for the folder the person chose. [bytes] are the caller's to zero once written. */
class ExportFile(val fileName: String, val bytes: ByteArray)

/** What a made file holds, for the line that says it was saved. */
internal class ExportMade(val logins: Int, val items: Int, val vaults: Int, val files: Int, val skipped: List<String>)

/** The export screen while it is open. Holds no plaintext: the CSV is made when the folder is chosen. */
internal class ExportSession(val kind: ExportKind, val lines: List<ExportVault>, val personalId: String) {
    var included: Set<String> = lines.map { it.vaultId }.toSet()
    var includeAttachments = false
    var offlineNote: String? = null
    /** CSV: the formula cells the screen showed last, which a tick acknowledges (re-checked against what is written). */
    var shownCells: List<ExportCsv.FormulaCell> = emptyList()
    var busy = false
    var error: String? = null
    var done: String? = null
    /** The file handed over last, until the platform says it was saved ([SessionController.exportSaved]). */
    var made: ExportMade? = null

    /** The vaults in the export, in export order; the personal vault always. */
    fun order(): List<String> = lines.map { it.vaultId }.filter { it in included || it == personalId }
}

internal fun exportView(s: ExportSession, csv: ExportCsv.Warnings?, logins: Int, items: Int, plan: AttachmentPlan?): ExportView {
    fun bucket(title: String, names: List<String>) = ImportBucketView(title, names.size, names.take(ExportCopy.NAMES_SHOWN).map(ExportCopy::safeName))
    return ExportView(
        kind = s.kind,
        vaults = s.lines.map { ExportVaultView(it.vaultId, it.name, it.vaultId == s.personalId, it.itemCount, it.vaultId in s.included || it.vaultId == s.personalId) },
        offlineNote = s.offlineNote,
        count = if (s.kind == ExportKind.CSV) logins else items,
        warnings = if (csv == null) emptyList() else listOf(
            bucket(ExportCopy.NOTES_LEFT_OUT, csv.noteItems),
            bucket(ExportCopy.CARDS_LEFT_OUT, csv.cardItems),
            bucket(ExportCopy.FILES_LEFT_OUT, csv.withAttachments),
            bucket(ExportCopy.FIRST_WEBSITE_ONLY, csv.extraUris),
            bucket(ExportCopy.EMPTY_LOGINS, csv.emptyUsernameAndPassword),
        ).filter { it.count > 0 },
        formulaCells = s.shownCells.map(ExportCsv::formulaCellLabel),
        includeAttachments = s.includeAttachments,
        attachmentBytes = plan?.totalBytes ?: 0L,
        attachmentsLeftOut = if (s.includeAttachments) plan?.overCap.orEmpty().take(ExportCopy.NAMES_SHOWN) else emptyList(),
        busy = s.busy,
        error = s.error,
        done = s.done,
    )
}

/** What the export screen says (the Android and desktop apps' words, where they have them). */
object ExportCopy {
    const val NAMES_SHOWN = 20

    const val PRIVATE = "Exporting is private: other members and the server are not told."
    const val CSV_PLAINTEXT =
        "The CSV holds every password in plain text. Anyone who reads the file reads your vault, and a synced folder copies it to the cloud. Save it only where you mean to, and delete it once the other manager has imported it."
    const val NOTES_LEFT_OUT = "Notes, not exported"
    const val CARDS_LEFT_OUT = "Cards, not exported (only a backup keeps them)"
    const val FILES_LEFT_OUT = "Files attached to these logins, not exported"
    const val FIRST_WEBSITE_ONLY = "Only the first website is kept"
    const val EMPTY_LOGINS = "No username or password: written, but a reimport skips them"
    const val FORMULA_WARNING = ExportCsv.FORMULA_WARNING
    const val FORMULA_ACK = ExportCsv.FORMULA_ACK
    const val FORMULA_ACK_NEEDED = "Tick the acknowledgement first: a spreadsheet would run the cells listed as formulas."
    const val VAULT_CHANGED =
        "Your vault changed while you were choosing where to save, so nothing was written. Check the cells listed and tick the acknowledgement again."
    const val NOTHING_TO_EXPORT = "There is nothing to export in the vaults chosen."

    const val BACKUP_ABOUT =
        "The backup holds every item of the vaults chosen, encrypted under the passphrase you set here: without it the file can't be opened. If you change your master password later, the file still opens with this passphrase."
    const val PASSPHRASE_TIP =
        "Your master password is a fine choice: the backup is then exactly as protected as your vault. A different passphrase belongs on your printed recovery sheet."
    const val PASSPHRASE_REQUIRED = "Set a passphrase for the backup."
    const val PASSPHRASES_DIFFER = "The passphrases don't match."
    const val PASSPHRASE_WEAK = "That passphrase is too easy to guess for a backup: it needs at least “good”."
    const val NON_ASCII =
        "Characters other than plain letters, digits and punctuation are used exactly as typed: type them the same way to open the backup."
    const val VERIFY_FAILED = "The backup did not open again as made, so nothing was written. Try again."
    const val LOCKED = "The vault locked while the export was being made, so nothing was written."

    const val NOT_SAVED = "Nothing was saved."
    const val WRITE_FAILED = "That folder couldn't be written to, so nothing was saved there. Choose another folder."
    const val READ_BACK_FAILED = "The saved file did not read back as written, so it was removed. Choose another folder."

    fun offline(lastSync: String?): String =
        "This device couldn't reach your server: the export holds your vault as of the last sync" + (lastSync?.let { ", $it." } ?: ".")

    fun csvSaved(fileName: String, folder: String, logins: Int): String =
        "Saved “$fileName” to $folder: " + (if (logins == 1) "1 login" else "$logins logins") +
            ". It holds every password in plain text: delete it once the other manager has imported it."

    fun backupSaved(fileName: String, folder: String, items: Int, vaults: Int, files: Int): String =
        "Saved “$fileName” to $folder: " + (if (items == 1) "1 item" else "$items items") + " from " +
            (if (vaults == 1) "1 vault" else "$vaults vaults") + (if (files > 0) (if (files == 1) ", with 1 file." else ", with $files files.") else ".")

    fun filesSkipped(names: List<String>): String =
        "Files not in the backup (too large together, or they would not download): " + names.joinToString(", ") { "“${safeName(it)}”" } + "."

    /** A name someone else may have chosen, on one line: control characters escaped, as every app shows one. */
    fun safeName(name: String): String = TerminalText.escape(name)
}
