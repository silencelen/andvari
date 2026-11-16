package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.CsvImport

/**
 * A CSV export being imported ([SessionController.importCsv]), the Android app's flow on core's universal importer
 * (spec 06, design 2026-07-11): what the file holds and what the import would add, against the items already in the
 * chosen vault, before anything is sent. Each item is encrypted on this device like any other save.
 */
data class CsvImportView(
    /** The app the file was exported from, as its columns tell ("Chrome or another Chromium browser"). */
    val source: String,
    /** The vault the items go into. */
    val vaultId: String,
    val vaultName: String,
    /** The vaults that can be chosen instead (the plan is made again for the one chosen); empty once importing began. */
    val vaultChoices: List<VaultChoiceView>,
    /** How many items the import adds. */
    val toImport: Int,
    /** What else was found, a sentence each: duplicates in the file merged, empty rows skipped. */
    val counts: List<String>,
    /** The rows named by what happens to them (already in the vault, renamed, skipped…), each list capped. */
    val buckets: List<ImportBucketView>,
    /** Rows that could not be read, each with where it is in the file (capped). */
    val errors: List<String>,
    /** The file looks like it was copied out of a web page, which mangles characters; said, never undone. */
    val note: String?,
    /** Importing: items sent, of how many. */
    val progress: ScanProgressView?,
    val busy: Boolean,
    /** Why the import stopped; with [retryable], Retry sends the same items again without making duplicates. */
    val error: String?,
    val retryable: Boolean,
    /** The import landed: what to do with the file now. */
    val done: String?,
)

data class ImportBucketView(
    /** What happened to these rows, as a sentence start ("Already in the vault, not imported"). */
    val title: String,
    /** How many there are. */
    val count: Int,
    /** Their names, at most [ImportCopy.NAMES_SHOWN]; [count] says if there are more. */
    val names: List<String>,
)

/** What the import screen holds while it is open: the parsed file (plaintext, so only while it is open) and the plan. */
internal class CsvSession(val parsed: CsvImport.Parsed, val rowOrdinals: Map<Int, Int>, val mangled: Boolean) {
    var vaultId = ""
    var plan: CsvImport.ImportPlan? = null
    var progress: ScanProgressView? = null
    var busy = false
    var error: String? = null
    var retryable = true
    var done = false
}

internal fun csvImportView(s: CsvSession, vaultName: (String) -> String, choices: List<VaultChoiceView>): CsvImportView {
    val report = s.plan?.report
    val locked = s.busy || s.error != null || s.done
    return CsvImportView(
        source = ImportCopy.source(s.parsed.format),
        vaultId = s.vaultId,
        vaultName = vaultName(s.vaultId),
        vaultChoices = if (locked || choices.size < 2) emptyList() else choices,
        toImport = report?.imported ?: 0,
        counts = buildList {
            if (report == null) return@buildList
            if (report.collapsed > 0) add(ImportCopy.collapsed(report.collapsed))
            if (report.skippedEmpty > 0) add(ImportCopy.empty(report.skippedEmpty))
        },
        buckets = if (report == null) emptyList() else listOf(
            ImportCopy.NOTES to report.noteItems,
            ImportCopy.ALREADY to report.alreadyInVault,
            ImportCopy.PASSWORD_DIFFERS to report.passwordDiffers,
            ImportCopy.TOTP_DIFFERS to report.totpDiffers,
            ImportCopy.RENAMED to report.flagged,
            ImportCopy.ARCHIVED to report.archivedSkipped,
            ImportCopy.UNKNOWN_TYPE to report.unknownTypeSkipped,
            ImportCopy.TOTP_UNSUPPORTED to report.totpUnsupported,
        ).filter { it.second.isNotEmpty() }.map { (title, names) -> ImportBucketView(title, names.size, names.take(ImportCopy.NAMES_SHOWN)) },
        errors = report?.errors.orEmpty().let { errors ->
            errors.take(ImportCopy.ERRORS_SHOWN).map { e ->
                val where = s.rowOrdinals[e.line]?.let { "Row $it (line ${e.line} of the file)" } ?: "Line ${e.line} of the file"
                "$where: " + ImportCopy.rowError(e.code)
            } + if (errors.size > ImportCopy.ERRORS_SHOWN) listOf(ImportCopy.moreErrors(errors.size - ImportCopy.ERRORS_SHOWN)) else emptyList()
        },
        note = if (s.mangled) ImportCopy.MANGLED else null,
        progress = s.progress,
        busy = s.busy,
        error = s.error,
        retryable = s.retryable,
        done = if (s.done) ImportCopy.done(report?.imported ?: 0, vaultName(s.vaultId)) else null,
    )
}

/** What the import says (the Android app's sentences, in this app's words). */
internal object ImportCopy {
    const val NAMES_SHOWN = 20
    const val ERRORS_SHOWN = 20
    const val NO_VAULT = "Couldn't check your vault for items you already have. Sync, then import the file again."
    const val VAULT_GONE = "That vault isn't here any more. Sync, then import the file again."
    const val TOO_LARGE = "That file is larger than 10 MiB, far bigger than any real password export."
    const val TOO_MANY_ROWS = "That file has more than 10,000 rows. Split it into smaller files and import each."
    const val UNRECOGNIZED =
        "This file isn't a password export andvari recognizes. andvari reads CSV exports from Chrome and other Chromium browsers, Firefox, Bitwarden, 1Password 8 or newer, LastPass and Safari. Make sure you exported a CSV file, not JSON or a zip."
    const val INTERRUPTED = "The import was interrupted. Retry finishes it without making duplicates."
    const val PARKED =
        "The vault was removed while importing. The items are held and land only if it is restored, so keep the CSV file."
    const val MANGLED = "This file looks like it was copied out of a web page, which changes characters like “&”. Export it again as a file download."
    const val NOTES = "Imported as notes"
    const val ALREADY = "Already in the vault, not imported"
    const val PASSWORD_DIFFERS = "Same site and username as a login in the vault but a different password: imported as well, so check which password is current"
    const val TOTP_DIFFERS = "Same site and username but a different two-step key: imported as well, so check which is current"
    const val RENAMED = "Renamed, as the name was taken"
    const val ARCHIVED = "Archived in the export, not imported"
    const val UNKNOWN_TYPE = "Of a kind this import doesn't read, not imported"
    const val TOTP_UNSUPPORTED = "With a two-step key andvari can't use, kept as text in the item's notes"

    fun source(format: CsvImport.ImportFormat): String = when (format) {
        CsvImport.ImportFormat.CHROME -> "Chrome or another Chromium browser"
        CsvImport.ImportFormat.FIREFOX -> "Firefox"
        CsvImport.ImportFormat.BITWARDEN -> "Bitwarden"
        CsvImport.ImportFormat.LASTPASS -> "LastPass"
        CsvImport.ImportFormat.ONE_PASSWORD -> "1Password"
    }

    fun forCode(code: String): String = when (code) {
        "too_large" -> TOO_LARGE
        "too_many_rows" -> TOO_MANY_ROWS
        "unrecognized_header" -> UNRECOGNIZED
        else -> "That file could not be read."
    }

    fun rowError(code: String): String = when (code) {
        "wrong_field_count" -> "the wrong number of fields"
        "bad_quote" -> "broken quoting"
        else -> "unreadable"
    }

    fun moreErrors(n: Int): String = "And $n more. Fix the export and choose the file again to check it."

    fun collapsed(n: Int): String = if (n == 1) "1 exact duplicate in the file was merged." else "$n exact duplicates in the file were merged."

    fun empty(n: Int): String = if (n == 1) "1 empty row was skipped." else "$n empty rows were skipped."

    fun done(n: Int, vault: String): String =
        (if (n == 1) "Added 1 item" else "Added $n items") + " to “$vault”. Now delete the CSV file: it holds your passwords in plain text."
}
