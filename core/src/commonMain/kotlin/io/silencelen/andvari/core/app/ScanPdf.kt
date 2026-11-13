package io.silencelen.andvari.core.app

import kotlin.math.roundToLong

/**
 * A scanned document as one PDF, made in memory from its pages (owner decision 2026-11-12). Each page is a JPEG image,
 * carried as it is (DCTDecode, nothing decoded or re-encoded), on a page sized for [DPI] dots per inch. Nothing is
 * written anywhere: the PDF goes straight into the item as a file of it.
 */
object ScanPdf {
    /** The resolution a page is laid out at: a page of 1700 by 2200 pixels comes out letter size. */
    const val DPI = 200

    /** What the frame header of a JPEG says: its size in pixels and its colour components (1 grey, 3 colour). */
    class JpegFrame(val width: Int, val height: Int, val components: Int)

    /** The frame of a JPEG with one or three components; null if [jpeg] is not one. */
    fun jpegFrame(jpeg: ByteArray): JpegFrame? {
        fun u8(i: Int) = jpeg[i].toInt() and 0xFF
        if (jpeg.size < 4 || u8(0) != 0xFF || u8(1) != 0xD8) return null
        var i = 2
        while (i + 3 < jpeg.size) {
            if (u8(i) != 0xFF) return null
            val marker = u8(i + 1)
            when {
                marker == 0xFF -> i += 1 // a fill byte before a marker
                marker == 0x01 || marker in 0xD0..0xD7 -> i += 2 // markers without a length
                marker == 0xD9 || marker == 0xDA -> return null // the end, or the image data, before any frame
                else -> {
                    val length = (u8(i + 2) shl 8) or u8(i + 3)
                    if (length < 2) return null
                    if (marker in 0xC0..0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
                        if (i + 9 >= jpeg.size) return null
                        val height = (u8(i + 5) shl 8) or u8(i + 6)
                        val width = (u8(i + 7) shl 8) or u8(i + 8)
                        val components = u8(i + 9)
                        return if (width > 0 && height > 0 && (components == 1 || components == 3)) JpegFrame(width, height, components) else null
                    }
                    i += 2 + length
                }
            }
        }
        return null
    }

    /** The pages, in order, as one PDF; null when there are none, or one is not a JPEG this can carry. */
    fun build(pages: List<ByteArray>): ByteArray? {
        if (pages.isEmpty()) return null
        val frames = pages.map { jpegFrame(it) ?: return null }
        val out = Out()
        out.bytes(byteArrayOf(0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34, 0x0A)) // %PDF-1.4
        out.bytes(byteArrayOf(0x25, 0xE2.toByte(), 0xE3.toByte(), 0xCF.toByte(), 0xD3.toByte(), 0x0A)) // marks the file binary
        // Objects: 1 the catalog, 2 the page tree, then three for each page: the page, its image, its contents.
        val count = 3 + 3 * pages.size // with object 0, the head of the free list
        val offsets = LongArray(count)

        fun obj(number: Int, body: () -> Unit) {
            offsets[number] = out.size
            out.ascii("$number 0 obj\n")
            body()
            out.ascii("\nendobj\n")
        }

        obj(1) { out.ascii("<< /Type /Catalog /Pages 2 0 R >>") }
        obj(2) { out.ascii("<< /Type /Pages /Kids [${pages.indices.joinToString(" ") { "${3 + 3 * it} 0 R" }}] /Count ${pages.size} >>") }
        for ((k, jpeg) in pages.withIndex()) {
            val frame = frames[k]
            val width = points(frame.width)
            val height = points(frame.height)
            val page = 3 + 3 * k
            obj(page) {
                out.ascii("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 $width $height] /Resources << /XObject << /Im0 ${page + 1} 0 R >> >> /Contents ${page + 2} 0 R >>")
            }
            obj(page + 1) {
                val space = if (frame.components == 1) "DeviceGray" else "DeviceRGB"
                out.ascii("<< /Type /XObject /Subtype /Image /Width ${frame.width} /Height ${frame.height} /ColorSpace /$space /BitsPerComponent 8 /Filter /DCTDecode /Length ${jpeg.size} >>\nstream\n")
                out.bytes(jpeg)
                out.ascii("\nendstream")
            }
            obj(page + 2) {
                val draw = "q $width 0 0 $height 0 0 cm /Im0 Do Q"
                out.ascii("<< /Length ${draw.length} >>\nstream\n$draw\nendstream")
            }
        }
        val xref = out.size
        out.ascii("xref\n0 $count\n0000000000 65535 f \n")
        for (number in 1 until count) out.ascii(offsets[number].toString().padStart(10, '0') + " 00000 n \n")
        out.ascii("trailer\n<< /Size $count /Root 1 0 R >>\nstartxref\n$xref\n%%EOF\n")
        return out.toByteArray()
    }

    /** [pixels] at [DPI], in points, with two decimals at most. */
    private fun points(pixels: Int): String {
        val hundredths = (pixels * 72.0 / DPI * 100).roundToLong()
        val whole = hundredths / 100
        val rest = hundredths % 100
        return if (rest == 0L) "$whole" else "$whole." + rest.toString().padStart(2, '0').trimEnd('0')
    }

    private class Out {
        private val parts = ArrayList<ByteArray>()
        var size = 0L
            private set

        fun ascii(text: String) = bytes(text.encodeToByteArray())

        fun bytes(b: ByteArray) {
            parts += b
            size += b.size
        }

        fun toByteArray(): ByteArray {
            val all = ByteArray(size.toInt())
            var at = 0
            for (p in parts) {
                p.copyInto(all, at)
                at += p.size
            }
            return all
        }
    }
}
