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
 *  - Windows: `ExcludeClipboardContentFromMonitorProcessing` (any data; a DWORD 0 here, never empty:
 *    AWT publishes an empty payload as GlobalAlloc(GMEM_MOVEABLE, 0), which may hand the clipboard a
 *    discarded handle — A14 review N8) keeps the entry out of history and sync altogether;
 *    `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` as DWORD 0 (4 bytes, little-endian)
 *    say the same per feature.
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
        Hint("ExcludeClipboardContentFromMonitorProcessing", dwordLe(0), windows = true),
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
internal class SensitiveTextSelection(internal val text: String) : Transferable, ClipboardOwner {
    private val flavors: Array<DataFlavor> = arrayOf(DataFlavor.stringFlavor) + SensitiveClipboard.hints.map { it.flavor }

    override fun getTransferDataFlavors(): Array<DataFlavor> = flavors.clone()

    override fun isDataFlavorSupported(flavor: DataFlavor?): Boolean = flavor != null && flavors.any { it.equals(flavor) }

    override fun getTransferData(flavor: DataFlavor?): Any {
        if (flavor != null && flavor.equals(DataFlavor.stringFlavor)) return text
        val hint = SensitiveClipboard.hints.firstOrNull { flavor != null && it.flavor.equals(flavor) } ?: throw UnsupportedFlavorException(flavor)
        return ByteArrayInputStream(hint.bytes.copyOf())
    }

    /** Something else is on the clipboard now (another program's copy, a newer copy of ours, or our clear). */
    @Volatile
    var lost: Boolean = false
        private set

    override fun lostOwnership(clipboard: java.awt.datatransfer.Clipboard?, contents: Transferable?) {
        lost = true
    }
}

/** The clipboard as [SecretClipboard] needs it. Each call throws when the clipboard cannot be opened. */
internal interface ClipboardPort {
    /** Put [selection] on the clipboard, [selection] being its owner (told when it loses the clipboard). */
    fun put(selection: SensitiveTextSelection)

    /** Put nothing of ours on the clipboard (an empty text). */
    fun clear()

    /** The clipboard's text now, or null when it holds none. */
    fun text(): String?
}

/**
 * The one secret this app has on the clipboard, and its clear.
 *
 * - **By ownership.** The copy is put there with itself as the owner; the clipboard's owner is told when anything else
 *   replaces it. A due clear empties the clipboard only while it is still ours, and never needs to read it first (a
 *   read is what failed on a busy Windows clipboard).
 * - **With retries.** A clear that fails (the clipboard is held by another program) stays due: it is tried again at
 *   the next tick, at a lock and at exit. The secret is forgotten only after a clear worked, or once the clipboard is
 *   seen to hold something else.
 * - **A lost ownership is looked at**. A clipboard manager that keeps the clipboard alive takes
 *   it over with the same text, so a loss is not taken for "something else is there": the clipboard is read once. Still
 *   the secret: the clear stays due, at its time, at a lock and at exit; before that clear, the text is read again, so
 *   a copy the person made since is never emptied. Something else: the secret is forgotten. A read that fails is tried
 *   at the next tick.
 * - **On two clocks** ([TwoClockMark]): time asleep counts toward the window.
 * - **One at a time.** A newer copy replaces the older one, and with it the older one's clear (ux-parity--5).
 */
internal class SecretClipboard(
    private val port: () -> ClipboardPort?,
    private val monotonicMs: () -> Long,
    private val wallMs: () -> Long,
) {
    private class Held(val selection: SensitiveTextSelection, val windowMs: Long, val since: io.silencelen.andvari.desktop.trust.TwoClockMark) {
        /** A lock or the exit asked for the clear: it is due now, whatever the window says. */
        var asked = false

        /** The ownership was lost and a look found the secret still there: a clipboard manager took it over. */
        var taken = false
    }

    private var held: Held? = null

    /** A secret of ours is on the clipboard, or its clear has not worked yet. */
    @get:Synchronized
    val holding: Boolean get() = held != null

    /** Copy [value]; false when nothing landed on the clipboard (no clear is due then, and an older one stays). */
    @Synchronized
    fun copy(value: String, clearSeconds: Int): Boolean {
        val p = port() ?: return false
        val selection = SensitiveClipboard.selectionFor(value)
        if (runCatching { p.put(selection) }.isFailure) return false
        held = Held(selection, maxOf(1, clearSeconds) * 1000L, io.silencelen.andvari.desktop.trust.TwoClockMark(monotonicMs, wallMs))
        return true
    }

    /** About once a second: a secret whose window passed is cleared; one the clipboard no longer holds is forgotten. */
    @Synchronized
    fun tick() {
        val h = held ?: return
        if (h.selection.lost && !h.taken) look(h)
        if (held != null && (h.asked || h.since.elapsedMs() >= h.windowMs)) clear(h)
    }

    /**
     * The clipboard's ownership was lost: one look. The secret still there (a clipboard manager took it over) keeps the
     * clear due; anything else forgets it; a read that fails is tried at the next tick.
     */
    private fun look(h: Held) {
        val p = port() ?: return
        val now = runCatching { p.text() }.getOrElse { return }
        if (now == h.selection.text) h.taken = true else held = null
    }

    /** A lock, a sign-out, the exit: clear now. A clear that fails stays due for the next tick. */
    @Synchronized
    fun clearNow() {
        held?.let {
            it.asked = true
            clear(it)
        }
    }

    private fun clear(h: Held) {
        if (h.selection.lost) {
            if (!h.taken) look(h)
            if (held == null || !h.taken) return
            // Taken over by a manager: no longer ours, so read again before emptying it; a newer copy is never touched.
            val p = port() ?: return
            val now = runCatching { p.text() }.getOrElse { return }
            if (now != h.selection.text) {
                held = null
                return
            }
            if (runCatching { p.clear() }.isSuccess) held = null
            return
        }
        val p = port() ?: return
        if (runCatching { p.clear() }.isSuccess) held = null
    }
}
