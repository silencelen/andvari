package io.silencelen.andvari.desktop

import java.awt.datatransfer.ClipboardOwner
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.SystemFlavorMap
import java.awt.datatransfer.Transferable
import java.awt.datatransfer.UnsupportedFlavorException
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Security review 2026-10, A14 (F9): clipboard managers keep what a plain StringSelection puts on
 * the clipboard — Windows clipboard history and cloud clipboard, KDE's Klipper (which keeps history
 * across sessions by default) — and the auto-clear only adds a new, empty entry, it removes nothing.
 * A secret copy therefore also offers the formats those managers honour, as KeePassXC does (and the
 * desktop twin of Android's EXTRA_IS_SENSITIVE):
 *
 *  - Windows: `ExcludeClipboardContentFromMonitorProcessing` (any data; empty here) keeps the entry
 *    out of history and sync altogether; `CanIncludeInClipboardHistory` and
 *    `CanUploadToCloudClipboard` as DWORD 0 (4 bytes, little-endian) say the same per feature.
 *  - Linux/X11: `x-kde-passwordManagerHint` = `secret`, which Klipper skips.
 *
 * AWT exposes a non-text native format through a [DataFlavor] whose data is raw bytes, mapped to the
 * native name in the [SystemFlavorMap] (both directions). The hint flavors use InputStream as their
 * representation class so AWT copies the bytes verbatim rather than serializing an object.
 * Non-secret copies ([copyPlain]) stay plain StringSelections.
 */
internal object SensitiveClipboard {
    class Hint(val native: String, val bytes: ByteArray, val windows: Boolean) {
        val flavor: DataFlavor = DataFlavor("application/x-andvari-clip-$native; class=java.io.InputStream", native)
    }

    fun dwordLe(v: Int): ByteArray = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()

    val hints: List<Hint> = listOf(
        Hint("ExcludeClipboardContentFromMonitorProcessing", ByteArray(0), windows = true),
        Hint("CanIncludeInClipboardHistory", dwordLe(0), windows = true),
        Hint("CanUploadToCloudClipboard", dwordLe(0), windows = true),
        Hint("x-kde-passwordManagerHint", "secret".toByteArray(Charsets.US_ASCII), windows = false),
    )

    /** The natives this platform's clipboard understands: the Windows trio there, the KDE hint elsewhere. */
    fun hintsFor(osName: String): List<Hint> {
        val win = osName.lowercase().contains("win")
        return hints.filter { it.windows == win }
    }

    /** Map this platform's hint flavors to their native names in [map] (idempotent). */
    fun install(map: SystemFlavorMap, osName: String) {
        for (h in hintsFor(osName)) {
            map.addUnencodedNativeForFlavor(h.flavor, h.native)
            map.addFlavorForUnencodedNative(h.native, h.flavor)
        }
    }

    private val installed: Unit by lazy {
        runCatching { install(SystemFlavorMap.getDefaultFlavorMap() as SystemFlavorMap, System.getProperty("os.name").orEmpty()) }
        Unit
    }

    /** The Transferable a secret copy puts on the clipboard (the flavor map is set up on first use). */
    fun selectionFor(text: String): SensitiveTextSelection {
        installed
        return SensitiveTextSelection(text)
    }
}

/** A secret's clipboard contents: the text itself, plus every [SensitiveClipboard.hints] format.
 *  A flavor with no native on this platform is simply not published by AWT. */
internal class SensitiveTextSelection(private val text: String) : Transferable, ClipboardOwner {
    private val flavors: Array<DataFlavor> = arrayOf(DataFlavor.stringFlavor) + SensitiveClipboard.hints.map { it.flavor }

    override fun getTransferDataFlavors(): Array<DataFlavor> = flavors.clone()

    override fun isDataFlavorSupported(flavor: DataFlavor?): Boolean = flavor != null && flavors.any { it.equals(flavor) }

    override fun getTransferData(flavor: DataFlavor?): Any {
        if (flavor != null && flavor.equals(DataFlavor.stringFlavor)) return text
        val hint = SensitiveClipboard.hints.firstOrNull { flavor != null && it.flavor.equals(flavor) } ?: throw UnsupportedFlavorException(flavor)
        return ByteArrayInputStream(hint.bytes.copyOf())
    }

    override fun lostOwnership(clipboard: java.awt.datatransfer.Clipboard?, contents: Transferable?) = Unit
}
