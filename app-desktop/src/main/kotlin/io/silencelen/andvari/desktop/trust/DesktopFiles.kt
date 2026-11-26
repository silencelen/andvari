package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.desktop.SaveTarget
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions

/**
 * Reading a file the person picked, never past a limit (the Android app's `PickedFiles`, on a [File]). A pick could
 * be any size, and reading it whole before its size is known would take the app down on a very large one. So the
 * file's size is asked first ([File.length]); because a file can grow between the ask and the read, the read itself
 * also stops one byte past the limit. Every buffer the read let go of is zeroed: a picked file can be a secret.
 */
internal object PickedFiles {
    /** What reading a pick came to. */
    sealed class Picked {
        /** The whole file, at most the limit. The caller owns [bytes] and zeroes them. */
        class Read(val name: String, val bytes: ByteArray) : Picked()

        /** Larger than the limit: [size] is the file's length, or the limit plus one when it said less. */
        class TooLarge(val size: Long) : Picked()

        /** It could not be opened or read. */
        data object NotRead : Picked()
    }

    /** The first buffer when the size is not known; it grows by doubling, up to the limit plus one. */
    private const val FIRST_BUFFER = 64 * 1024

    /**
     * The whole of [input] when it is at most [limit] bytes, or null when there is more ([limit] + 1 bytes are read at
     * most). [sizeHint] only sizes the first buffer. Nothing that is let go is left unzeroed.
     */
    fun readAtMost(input: InputStream, limit: Int, sizeHint: Long? = null): ByteArray? {
        require(limit >= 0)
        val cap = if (limit == Int.MAX_VALUE) limit else limit + 1
        val first = (sizeHint?.takeIf { it in 0..cap.toLong() }?.toInt()?.let { it + 1 } ?: FIRST_BUFFER).coerceIn(1, cap.coerceAtLeast(1))
        var buf = ByteArray(first)
        var n = 0
        try {
            while (n < cap) {
                if (n == buf.size) {
                    val grown = buf.copyOf(minOf(cap, if (buf.size > cap / 2) cap else buf.size * 2))
                    buf.fill(0)
                    buf = grown
                }
                val got = input.read(buf, n, buf.size - n)
                if (got < 0) break
                n += got
            }
            if (n > limit) return null
            return buf.copyOf(n)
        } finally {
            buf.fill(0)
        }
    }

    /** Reads [file] when it is at most [limit] bytes. Blocking: call it off the UI thread. */
    fun read(file: File, limit: Long): Picked {
        val max = limit.coerceIn(0, Int.MAX_VALUE.toLong() - 1).toInt()
        if (!runCatching { file.isFile }.getOrDefault(false)) return Picked.NotRead
        val declared = runCatching { file.length() }.getOrNull()?.takeIf { it >= 0 }
        if (declared != null && declared > max) return Picked.TooLarge(declared)
        return try {
            FileInputStream(file).use { readAtMost(it, max, declared) }?.let { Picked.Read(file.name, it) } ?: Picked.TooLarge(max.toLong() + 1)
        } catch (e: Exception) {
            Picked.NotRead
        }
    }
}

/** A size for people: bytes, KB or MB (the Android app's). */
internal fun sizeText(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${(bytes + 1023) / 1024} KB"
    else -> String.format(java.util.Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
}

/**
 * The system's file dialogs (`java.awt.FileDialog`, as the old desktop used them). Each blocks the window until it is
 * closed; the vault may lock meanwhile (the idle clock keeps running), so a caller checks its content is still the open
 * one before it uses what was picked.
 */
internal object FilePicker {
    /**
     * A file to read, or null when the dialog was cancelled. With [extension] ("andvari") the dialog shows files of that
     * kind (a filter where the system's dialog takes one, the name pattern where it takes that instead).
     */
    fun open(title: String, extension: String? = null): File? {
        val d = FileDialog(null as Frame?, title, FileDialog.LOAD)
        if (extension != null) {
            d.setFilenameFilter { _, name -> name.endsWith(".$extension", ignoreCase = true) }
            d.file = "*.$extension"
        }
        d.isVisible = true
        val dir = d.directory
        val name = d.file
        return if (dir != null && name != null) File(dir, name) else null
    }

    /** Where a Save dialog pointed. */
    sealed class SavePick {
        data object Cancelled : SavePick()

        /** The name the dialog gave back would land outside the folder it showed ([SaveTarget.resolve]). */
        data object Outside : SavePick()

        class At(val file: File) : SavePick()
    }

    /**
     * A place to write to: the dialog is pre-filled with a bare safe name ([SaveTarget.defaultName]; an attachment's name
     * is whoever wrote the item's text), and only a file directly inside the folder the dialog showed is accepted.
     */
    fun save(title: String, suggestedName: String): SavePick {
        val d = FileDialog(null as Frame?, title, FileDialog.SAVE)
        d.file = SaveTarget.defaultName(suggestedName)
        d.isVisible = true
        val dir = d.directory
        val name = d.file
        if (dir == null || name == null) return SavePick.Cancelled
        return SaveTarget.resolve(dir, name)?.let { SavePick.At(it) } ?: SavePick.Outside
    }
}

/**
 * `FileDialog(SAVE)` on Linux (XAWT) does not ask before replacing a file. Every place a Save
 * dialog gave goes through [request]: a new name runs at once; an existing file waits for an explicit Replace
 * ([ReplaceFileDialog]). Windows' own dialog asks too; a second ask there is the price of one path.
 */
internal class OverwriteGate {
    var pending by mutableStateOf<Pair<File, () -> Unit>?>(null)
        private set

    fun request(dest: File, action: () -> Unit) {
        if (dest.exists()) pending = dest to action else action()
    }

    fun cancel() {
        pending = null
    }

    fun confirm() {
        val p = pending
        pending = null
        p?.second?.invoke()
    }
}

/**
 * A file saved from a vault came from whoever wrote the item, so on Windows it carries the
 * mark of the web (the `Zone.Identifier` stream, zone 3, as a browser's download does) and Windows warns before running
 * it; and a name that ends like a program, a shortcut or a script is saved only after the person has been asked,
 * with the type named ([RiskyTypeGate]).
 */
internal object SavedFileMarks {
    const val ZONE_STREAM = ":Zone.Identifier"
    const val ZONE_CONTENT = "[ZoneTransfer]\r\nZoneId=3\r\n"

    fun isWindows(os: String = System.getProperty("os.name").orEmpty()): Boolean = os.lowercase().contains("win")

    /**
     * Writes the mark beside [dest] on Windows; elsewhere there is none to write. True when marked or nothing to mark.
     * [write] is the test seam (a stream is written as `<path>:Zone.Identifier` on NTFS).
     */
    fun mark(
        dest: File,
        windows: Boolean = isWindows(),
        write: (File, ByteArray) -> Unit = { f, b -> FileOutputStream(f).use { it.write(b) } },
    ): Boolean {
        if (!windows) return true
        return runCatching { write(File(dest.path + ZONE_STREAM), ZONE_CONTENT.toByteArray(Charsets.US_ASCII)) }.isSuccess
    }

    /**
     * The kinds of file Windows or a Linux desktop runs, opens as a shortcut or reads as settings when opened, by the
     * name's last extension (`.exe`, `.lnk`, `.ps1`, `.desktop` …), and the two names Explorer reads as settings.
     */
    private val RISKY = setOf(
        // programs and installers
        "exe", "com", "scr", "pif", "cpl", "msi", "msp", "mst", "msix", "msixbundle", "appx", "appxbundle", "appref-ms",
        "application", "gadget", "dll", "sys", "ocx", "drv", "jar", "appimage", "run", "bin", "deb", "rpm",
        // scripts
        "bat", "cmd", "ps1", "psm1", "psd1", "ps1xml", "vbs", "vbe", "js", "jse", "wsf", "wsh", "wsc", "hta", "msc",
        "sh", "bash", "zsh", "csh", "ksh", "py", "pyw", "pl", "rb", "php", "command",
        // shortcuts, links and settings files
        "lnk", "url", "scf", "website", "library-ms", "searchconnector-ms", "settingcontent-ms", "desktop", "inf", "reg",
        "chm", "xll", "xlam", "ppam", "docm", "xlsm", "pptm", "iso", "img", "vhd", "vhdx",
    )
    private val RISKY_NAMES = setOf("desktop.ini", "autorun.inf")

    /** The type to name in the question (`exe`, `desktop.ini` …), or null for an ordinary file. */
    fun riskyType(name: String): String? {
        // Windows ignores trailing dots and spaces, so `x.exe.` and `x.exe ` are programs too.
        val n = name.trim().trimEnd('.', ' ').lowercase()
        if (n in RISKY_NAMES) return n
        val dot = n.lastIndexOf('.')
        if (dot < 0 || dot == n.length - 1) return null
        return n.substring(dot + 1).takeIf { it in RISKY }
    }
}

/** Note N3: a save whose name ends like a program waits for an explicit yes that names the type ([RiskyTypeDialog]). */
internal class RiskyTypeGate {
    var pending by mutableStateOf<Triple<File, String, () -> Unit>?>(null)
        private set

    fun request(dest: File, action: () -> Unit) {
        val type = SavedFileMarks.riskyType(dest.name)
        if (type != null) pending = Triple(dest, type, action) else action()
    }

    fun cancel() {
        pending = null
    }

    fun confirm() {
        val p = pending
        pending = null
        p?.third?.invoke()
    }
}

@Composable
internal fun RiskyTypeDialog(gate: RiskyTypeGate) {
    val (file, type, _) = gate.pending ?: return
    AlertDialog(
        onDismissRequest = gate::cancel,
        title = { Say(UiText.ph(Placeholder.FILE_RISKY_TYPE, file.name, type)) },
        // The way out comes first and is the dialog's dismiss.
        dismissButton = { TextButton(onClick = gate::cancel) { Say(CopyKey.CANCEL) } },
        confirmButton = { TextButton(onClick = gate::confirm) { Say(Placeholder.FILE_RISKY_SAVE) } },
    )
}

@Composable
internal fun ReplaceFileDialog(gate: OverwriteGate) {
    val file = gate.pending?.first ?: return
    AlertDialog(
        onDismissRequest = gate::cancel,
        title = { Say(UiText.ph(Placeholder.FILE_REPLACE_CONFIRM, file.name)) },
        // The way out comes first and is the dialog's dismiss.
        dismissButton = { TextButton(onClick = gate::cancel) { Say(CopyKey.CANCEL) } },
        confirmButton = { TextButton(onClick = gate::confirm) { Say(Placeholder.FILE_REPLACE) } },
    )
}

/** What writing a file came to. */
internal enum class ExportWrite {
    /** The place could not be opened for writing; nothing was written. */
    NOT_OPENED,

    /** The write failed; what was written is removed. */
    NOT_WRITTEN,

    /** It was written but did not read back the same (or could not be read back); it is removed. */
    DIFFERS,

    /** Written once and read back the same. */
    SAVED,
}

/**
 * Write [bytes] once through [open], read them back through [readBack] (never more than their own length plus one)
 * and compare; [delete] removes a file that failed the write or the comparison (the Android app's, unchanged).
 * Blocking: call it off the UI thread. The read-back copy is zeroed; [bytes] are the caller's to zero.
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

/** What [writeVerified] came to; [keptAs] names the checked copy left beside [ExportWrite.NOT_WRITTEN]'s target. */
internal class FileWritten(val result: ExportWrite, val keptAs: String? = null)

/**
 * The desktop's write to a file the person picked ([dest]), the old app's discipline (spec 07 §2.6): the bytes go once
 * into an owner-only file beside [dest] ([writeAndCheck]: read back and compared, removed if they differ), and only a
 * checked copy is moved over [dest], atomically where the file system can. A file already at [dest] is therefore never
 * touched until a checked replacement exists. If the move itself fails, the checked copy is kept beside it under a name
 * of its own ([FileWritten.keptAs]): on the non-atomic fallback [dest] may already be gone, and it can be the only copy.
 * Blocking: call it off the UI thread. [bytes] are the caller's to zero.
 */
internal fun writeVerified(
    dest: File,
    bytes: ByteArray,
    survivorOf: (File) -> File = { File(it.absoluteFile.parentFile, "${it.name}.recovered-${System.currentTimeMillis()}") },
): FileWritten {
    val dir = dest.absoluteFile.parentFile ?: return FileWritten(ExportWrite.NOT_OPENED)
    val tmp = runCatching {
        val attrs = if (posixDir(dir)) arrayOf(PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))) else emptyArray()
        Files.createTempFile(dir.toPath(), "andvari-", ".tmp", *attrs).toFile()
    }.getOrNull() ?: return FileWritten(ExportWrite.NOT_OPENED)
    // Removed at exit unless kept below: a list of the app's own, from which a kept copy can be taken back (deleteOnExit's
    // cannot: the check of 2026-11-18 found a "left beside it as" line naming a file that went at the app's end).
    TempsDeletedAtExit.add(tmp)
    val r = writeAndCheck({ FileOutputStream(tmp) }, { FileInputStream(tmp) }, { tmp.delete() }, bytes)
    if (r != ExportWrite.SAVED) {
        tmp.delete()
        TempsDeletedAtExit.forget(tmp)
        return FileWritten(if (r == ExportWrite.NOT_OPENED) ExportWrite.NOT_WRITTEN else r)
    }
    return try {
        try {
            Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } catch (e: AtomicMoveNotSupportedException) {
            Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
        // Note N3: the saved file carries the mark of the web on Windows. A file system without streams (FAT, a
        // network share) cannot carry it; that is logged, and the file stays saved.
        TempsDeletedAtExit.forget(tmp)
        if (!SavedFileMarks.mark(dest)) io.silencelen.andvari.desktop.DesktopDiagnostics.log("a saved file could not be marked as from the web (Zone.Identifier)")
        FileWritten(ExportWrite.SAVED)
    } catch (e: Exception) {
        // The checked copy is kept under a name of its own; where even that rename fails, under its temporary name. Either
        // way it is taken off the exit's list, so the file the line names is still there after the app ends.
        val survivor = survivorOf(dest)
        val kept = runCatching { Files.move(tmp.toPath(), survivor.toPath()); survivor }.getOrDefault(tmp)
        TempsDeletedAtExit.forget(tmp)
        FileWritten(ExportWrite.NOT_WRITTEN, kept.name)
    }
}

/**
 * The temporary files of [writeVerified] that the app removes when it ends (a shutdown hook, as `deleteOnExit` would),
 * unless [forget] took one off the list: a checked copy kept beside a file it could not replace stays.
 */
internal object TempsDeletedAtExit {
    private val files: MutableSet<File> = java.util.concurrent.ConcurrentHashMap.newKeySet()

    init {
        Runtime.getRuntime().addShutdownHook(Thread({ for (f in files) runCatching { f.delete() } }, "andvari-temp-files"))
    }

    fun add(f: File) {
        files += f.absoluteFile
    }

    fun forget(f: File) {
        files -= f.absoluteFile
    }

    /** [f] is on the list, so it goes when the app ends. */
    fun has(f: File): Boolean = f.absoluteFile in files
}

private fun posixDir(dir: File): Boolean = runCatching { Files.getFileStore(dir.toPath()).supportsFileAttributeView("posix") }.getOrDefault(false)
