package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ImportCopy
import io.silencelen.andvari.core.client.CsvImport

/**
 * What a screen checks BEFORE it reads a file the person picked, with the sentence it shows, so a file far too large is
 * never read into memory only to be refused by [VaultContent.importCsv]. The sentences are the ones the content itself
 * answers.
 */
object ContentLimits {
    /** The largest CSV file an import reads (10 MiB). */
    const val CSV_IMPORT_MAX_BYTES: Long = CsvImport.MAX_BYTES.toLong()

    /** The sentence for a CSV file over [CSV_IMPORT_MAX_BYTES]: the one [VaultContent.importCsv] answers for it. */
    const val CSV_IMPORT_TOO_LARGE: String = ImportCopy.TOO_LARGE

    /** [CSV_IMPORT_TOO_LARGE] when a picked file of [sizeBytes] is over the limit, null when it may be read. */
    fun csvImportTooLarge(sizeBytes: Long): String? = if (sizeBytes > CSV_IMPORT_MAX_BYTES) CSV_IMPORT_TOO_LARGE else null
}
