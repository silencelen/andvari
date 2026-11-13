package io.silencelen.andvari.core.app

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A scan's pages made into one PDF in memory ([ScanPdf]): the JPEGs carried as they are, in a file any reader opens. */
class ScanPdfTest {
    /** A JPEG's headers (no image data a decoder would need): an APP0 segment, then the frame. */
    private fun jpeg(width: Int, height: Int, components: Int = 3, sof: Int = 0xC0, fill: Boolean = false, tail: Int = 40): ByteArray {
        val out = ArrayList<Byte>()
        fun put(vararg b: Int) = b.forEach { out += it.toByte() }
        put(0xFF, 0xD8)
        put(0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00)
        if (fill) put(0xFF)
        put(0xFF, sof, 0x00, 8 + 3 * components, 0x08, height shr 8, height and 0xFF, width shr 8, width and 0xFF, components)
        repeat(components) { put(it + 1, 0x11, 0x00) }
        put(0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00)
        repeat(tail) { put((it * 7) and 0x7F) }
        put(0xFF, 0xD9)
        return out.toByteArray()
    }

    private fun ByteArray.indexOf(text: String, from: Int = 0): Int {
        val needle = text.encodeToByteArray()
        outer@ for (i in from..size - needle.size) {
            for (j in needle.indices) if (this[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    private fun ByteArray.ascii(from: Int, to: Int) = copyOfRange(from, to).decodeToString()

    @Test
    fun theFrameHeaderGivesTheSizeAndTheColours() {
        val f = assertNotNull(ScanPdf.jpegFrame(jpeg(1700, 2200)))
        assertEquals(listOf(1700, 2200, 3), listOf(f.width, f.height, f.components))
        val grey = assertNotNull(ScanPdf.jpegFrame(jpeg(800, 600, components = 1, sof = 0xC2, fill = true)), "progressive, after a fill byte")
        assertEquals(listOf(800, 600, 1), listOf(grey.width, grey.height, grey.components))
        assertNull(ScanPdf.jpegFrame(jpeg(10, 10, components = 4)), "CMYK is not carried")
        assertNull(ScanPdf.jpegFrame("%PDF-1.4".encodeToByteArray()))
        assertNull(ScanPdf.jpegFrame(jpeg(10, 10).copyOfRange(0, 22)), "a frame cut short")
        assertNull(ScanPdf.jpegFrame(byteArrayOf()))
    }

    @Test
    fun thePagesBecomeOnePdfWithEveryOffsetRight() {
        val pages = listOf(jpeg(1700, 2200), jpeg(2200, 1700, tail = 300), jpeg(850, 1100, components = 1))
        val pdf = assertNotNull(ScanPdf.build(pages))
        assertTrue(pdf.ascii(0, 9) == "%PDF-1.4\n")
        assertTrue(pdf.ascii(pdf.size - 6, pdf.size) == "%%EOF\n")
        // The cross-reference table: every object where it says, and startxref at the table.
        val startxref = pdf.indexOf("startxref\n")
        val xref = pdf.ascii(startxref + 10, pdf.size).substringBefore('\n').toInt()
        assertEquals("xref\n", pdf.ascii(xref, xref + 5))
        val table = pdf.ascii(xref, startxref).lines()
        assertEquals("0 12", table[1], "the catalog, the page tree and three objects a page")
        assertEquals("0000000000 65535 f ", table[2])
        for (number in 1 until 12) {
            val entry = table[2 + number]
            assertEquals(20, entry.length + 1, "each entry is 20 bytes with its line end")
            val at = entry.substring(0, 10).toInt()
            assertEquals("$number 0 obj\n", pdf.ascii(at, at + "$number 0 obj\n".length), "object $number")
        }
        assertTrue(pdf.indexOf("/Count 3") > 0)
        assertTrue(pdf.indexOf("/Kids [3 0 R 6 0 R 9 0 R]") > 0)
        assertTrue(pdf.indexOf("/MediaBox [0 0 612 792]") > 0, "1700 by 2200 pixels at 200 dpi: letter")
        assertTrue(pdf.indexOf("/MediaBox [0 0 792 612]") > 0)
        assertTrue(pdf.indexOf("/MediaBox [0 0 306 396]") > 0)
        assertTrue(pdf.indexOf("/ColorSpace /DeviceGray") > 0)
        // Each image is the JPEG itself, its length exact.
        var from = 0
        for (page in pages) {
            val dict = pdf.indexOf("/Filter /DCTDecode /Length ${page.size} >>\nstream\n", from)
            assertTrue(dict > 0)
            val start = pdf.indexOf("stream\n", dict) + 7
            assertContentEquals(page, pdf.copyOfRange(start, start + page.size))
            assertEquals("\nendstream", pdf.ascii(start + page.size, start + page.size + 10))
            from = start + page.size
        }
        val draw = "q 612 0 0 792 0 0 cm /Im0 Do Q"
        assertTrue(pdf.indexOf("<< /Length ${draw.length} >>\nstream\n$draw\nendstream") > 0, "each page draws its image across the page")
    }

    @Test
    fun nothingIsMadeOfNoPagesOrOfAPageThatIsNotAJpeg() {
        assertNull(ScanPdf.build(emptyList()))
        assertNull(ScanPdf.build(listOf(jpeg(100, 100), "not a jpeg".encodeToByteArray())))
        val odd = assertNotNull(ScanPdf.build(listOf(jpeg(1001, 333))))
        assertTrue(odd.indexOf("/MediaBox [0 0 360.36 119.88]") > 0, "points to two decimals")
    }
}
