package io.silencelen.andvari.desktop

import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.SystemFlavorMap
import java.awt.datatransfer.UnsupportedFlavorException
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Security review 2026-10, A14 (F9): a vault secret copied on the desktop was a plain
 * StringSelection, so Windows clipboard history / cloud clipboard and KDE's Klipper kept it after
 * the auto-clear (which only adds a new, empty entry). Secret copies now carry the formats those
 * managers honour — the KeePassXC set, and the desktop twin of Android's EXTRA_IS_SENSITIVE.
 *
 * What a headless JVM can prove: the Transferable's flavors, its exact bytes, the unchanged text,
 * and the flavor-to-native mapping. Whether Win+V and Klipper then skip the entry is an owner
 * device check on a real desktop.
 */
class SensitiveClipboardTest {
    private val secret = "hunter2 é 🔑"

    private fun bytesOf(t: SensitiveTextSelection, f: DataFlavor): ByteArray = (t.getTransferData(f) as InputStream).use { it.readBytes() }

    @Test
    fun theTextIsUnchangedAndEveryHintFlavorIsOffered() {
        val t = SensitiveTextSelection(secret)
        assertEquals(secret, t.getTransferData(DataFlavor.stringFlavor), "the pasted text is exactly the secret")
        val offered = t.transferDataFlavors.toList()
        assertTrue(DataFlavor.stringFlavor in offered)
        for (h in SensitiveClipboard.hints) {
            assertTrue(h.flavor in offered, "missing ${h.native}")
            assertTrue(t.isDataFlavorSupported(h.flavor))
        }
        assertEquals(1 + SensitiveClipboard.hints.size, offered.size, "nothing else rides along")
    }

    @Test
    fun theHintBytesAreExact() {
        val t = SensitiveTextSelection(secret)
        val byNative = SensitiveClipboard.hints.associateBy { it.native }
        // A14 review N8: never EMPTY. Windows takes any data for this format, but AWT publishes an empty payload as
        // GlobalAlloc(GMEM_MOVEABLE, 0), which may hand the clipboard a discarded handle; a DWORD 0 is a real block.
        val exclude = bytesOf(t, byNative.getValue("ExcludeClipboardContentFromMonitorProcessing").flavor)
        assertContentEquals(byteArrayOf(0, 0, 0, 0), exclude, "a DWORD 0, 4 bytes")
        assertTrue(exclude.isNotEmpty())
        // DWORD 0, 4 bytes little-endian: "do not keep in history" / "do not sync".
        assertContentEquals(byteArrayOf(0, 0, 0, 0), bytesOf(t, byNative.getValue("CanIncludeInClipboardHistory").flavor))
        assertContentEquals(byteArrayOf(0, 0, 0, 0), bytesOf(t, byNative.getValue("CanUploadToCloudClipboard").flavor))
        assertContentEquals("secret".toByteArray(Charsets.US_ASCII), bytesOf(t, byNative.getValue("x-kde-passwordManagerHint").flavor))
        assertEquals(4, SensitiveClipboard.hints.size)
    }

    @Test
    fun aDwordIsFourBytesLittleEndian() {
        assertContentEquals(byteArrayOf(1, 0, 0, 0), SensitiveClipboard.dwordLe(1))
        assertContentEquals(byteArrayOf(0x78, 0x56, 0x34, 0x12), SensitiveClipboard.dwordLe(0x12345678))
    }

    @Test
    fun anUnknownFlavorIsRefused() {
        assertFailsWith<UnsupportedFlavorException> { SensitiveTextSelection(secret).getTransferData(DataFlavor.imageFlavor) }
    }

    @Test
    fun eachPlatformMapsItsOwnNatives() {
        assertEquals(
            setOf("ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"),
            SensitiveClipboard.hintsFor("Windows 11").map { it.native }.toSet(),
        )
        assertEquals(setOf("x-kde-passwordManagerHint"), SensitiveClipboard.hintsFor("Linux").map { it.native }.toSet())

        val map = SystemFlavorMap.getDefaultFlavorMap() as SystemFlavorMap
        SensitiveClipboard.install(map, "Linux")
        val kde = SensitiveClipboard.hints.single { it.native == "x-kde-passwordManagerHint" }
        assertTrue("x-kde-passwordManagerHint" in map.getNativesForFlavor(kde.flavor), "flavor → native")
        assertTrue(kde.flavor in map.getFlavorsForNative("x-kde-passwordManagerHint"), "native → flavor")
    }
}
