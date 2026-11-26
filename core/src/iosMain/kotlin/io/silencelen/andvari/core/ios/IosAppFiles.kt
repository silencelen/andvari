package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.ScanPdf
import io.silencelen.andvari.core.app.content.VaultContent
import platform.Foundation.NSData
import kotlin.coroutines.cancellation.CancellationException

/**
 * The vault content's calls that take or give bytes, as Swift can use them (Swift sees a Kotlin `ByteArray` as
 * `KotlinByteArray`, element by element): `NSData` in, and `NSData` or a wipeable `NSMutableData` out. The old path's
 * `IosSessionController` wrappers, call for call, over the new path's [VaultContent].
 *
 * The content is read from [api] at EVERY call ([AppApi.content] is a new instance per unlock, and one kept past a lock
 * answers `NotDone`), so a Swift screen may keep this object for the life of the process. While locked: a call that
 * answers an [ActionResult] answers [ActionResult.NotDone]; one that answers a file answers null; [openAttachment]
 * answers neither bytes nor an error (the content's own "it was closed meanwhile").
 *
 * What is wiped (the old path's rule, kept): core's copy of every plaintext it hands over is zeroed once copied into
 * the `NSData`; what Swift holds (the `Data` it read, the `NSData` a preview gets, the image made from it) is released
 * but cannot be wiped by Kotlin. An export is handed over as `NSMutableData` so that Swift zeroes it once written
 * (`resetBytes(in:)`); a CSV is plaintext.
 */
class IosAppFiles internal constructor(private val api: AppApi) {
    private val content: VaultContent? get() = api.content

    /** One file of an item, decrypted, for a preview or to save to Files: in memory only, which the app writes nowhere. */
    @Throws(CancellationException::class)
    suspend fun openAttachment(itemId: String, attachmentId: String): AttachmentFile {
        val c = content ?: return AttachmentFile("", null, null)
        val got = c.readAttachment(itemId, attachmentId)
        val bytes = got.bytes ?: return AttachmentFile(got.name, null, got.error)
        return try {
            AttachmentFile(got.name, bytes.toNSData(), null)
        } finally {
            bytes.fill(0)
        }
    }

    /** Add [data], called [name], to the open editor's item: read whole by the app, within the limits. Core zeroes its copy. */
    @Throws(CancellationException::class)
    suspend fun addAttachmentData(name: String, data: NSData): ActionResult =
        content?.addAttachment(name, data.toByteArray()) ?: ActionResult.NotDone(null)

    /** A scan's pages (each a JPEG, in order) as one PDF, made in memory ([ScanPdf]); null when a page is not a JPEG it can carry. */
    fun scannedPdf(pages: List<NSData>): NSData? {
        val raw = pages.map { it.toByteArray() }
        return try {
            ScanPdf.build(raw)?.let { pdf ->
                try {
                    pdf.toNSData()
                } finally {
                    pdf.fill(0)
                }
            }
        } finally {
            raw.forEach { it.fill(0) }
        }
    }

    /** A CSV export the person chose, read whole by the app: parsed and planned, nothing sent yet. Core zeroes its copy. */
    @Throws(CancellationException::class)
    suspend fun importCsvData(data: NSData): ActionResult = content?.importCsv(data.toByteArray()) ?: ActionResult.NotDone(null)

    /** The CSV for the folder the person chose, as the bytes the app writes there once; core's copy is zeroed. Null: nothing to write. */
    fun exportCsvData(acknowledged: Boolean): ExportData? = content?.csvFile(acknowledged)?.let(::exportData)

    /**
     * The backup for the folder the person chose, made, opened again and checked; core's copy is zeroed. The passphrase
     * comes as character arrays that are zeroed before this returns, whatever happens (core's `backupFileChars` zeroes
     * them, and this does again): Swift builds them from what was typed (`KotlinCharArray(size:)`, one UTF-16 unit per
     * index) and keeps no `String` of it longer than it must.
     */
    @Throws(CancellationException::class)
    suspend fun exportBackupData(passphrase: CharArray, confirm: CharArray): ExportData? = try {
        content?.backupFileChars(passphrase, confirm)?.let(::exportData)
    } finally {
        passphrase.fill('\u0000')
        confirm.fill('\u0000')
    }

    private fun exportData(file: ExportFile): ExportData = try {
        ExportData(file.fileName, file.bytes.toNSMutableData())
    } finally {
        file.bytes.fill(0)
    }
}

/**
 * The app API of the new path as the Swift app reaches it: built once per process by [AndvariBridgeApp.app], on the
 * main thread, in the app (never in an extension). The fake for previews and UI tests stays
 * [io.silencelen.andvari.core.bridge.AndvariBridge.fakeApp].
 */
object AndvariBridgeApp {
    private var built: IosAppSeam? = null
    private var builtFiles: IosAppFiles? = null

    /**
     * The seam, built and started at the first call that can build it; the same one afterwards. Null when it cannot be
     * built yet: the first start of an install found something an earlier install left in the Keychain that it could
     * not delete now (the protected data cannot be read: a launch iOS prewarmed before the first unlock). Swift then
     * calls again on `protectedDataDidBecomeAvailableNotification` or at the next foreground. Also null in an app
     * extension (an `.appex` bundle), which never holds the session: the extensions have their own read-only objects.
     *
     * Quick unlock is passed no key wrap: it shows as unavailable until the iPhone's Face ID key wrap is written.
     *
     * Must be called on the main thread (the engine publishes there); off it, this throws.
     */
    fun app(): IosAppSeam? {
        check(platform.Foundation.NSThread.isMainThread) { "AndvariBridgeApp.app() is called on the main thread" }
        built?.let { return it }
        if (platform.Foundation.NSBundle.mainBundle.bundlePath.endsWith(".appex")) return null
        val seam = IosAppSeam.build(
            layout = IosAppLayout.shipping(),
            keyWrap = NO_KEY_WRAP_YET,
            oldStores = IosOldStores(IosOldLayout.shipping()),
            bakedSpec = IosAppSeam.bundledSpec(),
        ) ?: return null
        built = seam
        builtFiles = IosAppFiles(seam.api)
        return seam
    }

    /** The bytes-in, bytes-out calls over [app]'s content; null until [app] has built it. */
    fun files(): IosAppFiles? {
        check(platform.Foundation.NSThread.isMainThread) { "AndvariBridgeApp.files() is called on the main thread" }
        return builtFiles
    }

    /** No Face ID key wrap exists on the iPhone yet: core then reports quick unlock as unavailable. */
    private val NO_KEY_WRAP_YET: io.silencelen.andvari.core.client.session.PlatformKeyWrap? = null
}
