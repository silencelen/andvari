package io.silencelen.andvari.core.crypto

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Spec 00 conventions: binary ⇄ text is base64url without padding, everywhere;
 * hex only for printed fingerprints.
 */
@OptIn(ExperimentalEncodingApi::class)
object Bytes {
    private val b64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    fun toB64(bytes: ByteArray): String = b64.encode(bytes)

    fun fromB64(text: String): ByteArray = try {
        b64.decode(text)
    } catch (e: IllegalArgumentException) {
        throw CryptoException("invalid base64url", e)
    }

    /**
     * STRICT base64url (design 2026-11-15 §2.2, "strict decoding everywhere"): [text] must use only the
     * unpadded base64url alphabet and re-encode to itself, so padding, the standard alphabet, white space
     * and non-zero trailing bits are all refused. Total: null instead of a throw. Every decoder of a value
     * that another party supplied uses this, never [fromB64], which tolerates padding.
     */
    fun fromB64Canonical(text: String): ByteArray? {
        for (c in text) {
            val ok = c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '_'
            if (!ok) return null
        }
        val bytes = try {
            b64.decode(text)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return if (b64.encode(bytes) == text) bytes else null
    }

    /** [fromB64Canonical], and the decoded value must be exactly [length] bytes. Null otherwise. */
    fun fromB64Exact(text: String, length: Int): ByteArray? = fromB64Canonical(text)?.takeIf { it.size == length }

    /**
     * Unpadded base64url of [bytes] as ASCII BYTES, for a value that must never become a `String`: a key
     * that is written into a statement. A `String` cannot be wiped; this array can, and the caller wipes
     * it. Each character is computed, not looked up, so no table is indexed by key material.
     */
    fun toB64Bytes(bytes: ByteArray): ByteArray {
        val tail = bytes.size % 3
        val out = ByteArray(bytes.size / 3 * 4 + if (tail == 0) 0 else tail + 1)
        var o = 0
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            out[o++] = b64Char(b0 shr 2)
            out[o++] = b64Char(((b0 and 3) shl 4) or (b1 shr 4))
            if (i + 1 < bytes.size) out[o++] = b64Char(((b1 and 15) shl 2) or (b2 shr 6))
            if (i + 2 < bytes.size) out[o++] = b64Char(b2 and 63)
            i += 3
        }
        return out
    }

    /**
     * STRICT unpadded base64url straight from the ASCII bytes `text[start, end)` to bytes, or null: only
     * the base64url alphabet, never a length of 1 mod 4, and the unused trailing bits zero, so the text
     * is the one canonical encoding of the result ([fromB64Canonical] accepts exactly the same texts).
     * No `String` is made of the text or of the value, which is the point: this reads a key out of a
     * statement. The caller wipes the result.
     */
    fun fromB64Bytes(text: ByteArray, start: Int = 0, end: Int = text.size): ByteArray? {
        val n = end - start
        if (start < 0 || end > text.size || n < 0 || n % 4 == 1) return null
        val tail = n % 4
        val out = ByteArray(n / 4 * 3 + if (tail == 0) 0 else tail - 1)
        var acc = 0
        var bits = 0
        var o = 0
        var bad = 0
        for (i in start until end) {
            val v = b64Value(text[i].toInt() and 0xFF)
            bad = bad or v // negative for a byte outside the alphabet
            acc = ((acc shl 6) or (v and 63)) and 0xFFFF
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (acc shr bits).toByte()
            }
        }
        if (bad < 0 || (acc and ((1 shl bits) - 1)) != 0) {
            out.fill(0)
            return null
        }
        return out
    }

    /** The base64url character for a 6-bit value, by arithmetic: `A–Z a–z 0–9 - _`. */
    private fun b64Char(x: Int): Byte {
        var c = x + 65
        c += ((25 - x) shr 8) and 6 // above 25: 'a' is 6 past 'Z' + 1
        c -= ((51 - x) shr 8) and 75 // above 51: back to '0'
        c -= ((61 - x) shr 8) and 13 // 62: '-'
        c += ((62 - x) shr 8) and 49 // 63: '_'
        return c.toByte()
    }

    /** The 6-bit value of a base64url character (0..255), or -1, by arithmetic: each range test is all ones or zero. */
    private fun b64Value(c: Int): Int {
        var v = -1
        v += (((64 - c) and (c - 91)) shr 8) and (c - 64) // 'A'..'Z' -> 0..25
        v += (((96 - c) and (c - 123)) shr 8) and (c - 70) // 'a'..'z' -> 26..51
        v += (((47 - c) and (c - 58)) shr 8) and (c + 5) // '0'..'9' -> 52..61
        v += (((44 - c) and (c - 46)) shr 8) and 63 // '-' -> 62
        v += (((94 - c) and (c - 96)) shr 8) and 64 // '_' -> 63
        return v
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun toHexLower(bytes: ByteArray): String = bytes.toHexString()

    /** Lowercase hex to bytes: an even number of `[0-9a-f]` characters and nothing else. Null otherwise. */
    fun fromHexLower(text: String): ByteArray? {
        if (text.length % 2 != 0) return null
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val hi = hexValue(text[2 * i])
            val lo = hexValue(text[2 * i + 1])
            if (hi < 0 || lo < 0) return null
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return out
    }

    private fun hexValue(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        else -> -1
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun toHexUpper(bytes: ByteArray): String = bytes.toHexString(HexFormat.UpperCase)

    /** Constant-time comparison for MAC-like values. */
    fun ctEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var acc = 0
        for (i in a.indices) acc = acc or (a[i].toInt() xor b[i].toInt())
        return acc == 0
    }

    /**
     * Shape (the first) 16 bytes into an RFC 4122 v4-format UUID string (version nibble
     * forced to 4, variant to 10) — the ONE shared implementation behind random ids
     * (Account.uuid), deterministic conflict-copy ids (ConflictCopy, vector-pinned), and
     * F19 gesture mutationIds (SyncEngine), byte-identical to web's uuidFromLabel shaping.
     * A drift between copies silently breaks server-dedup convergence, so everything
     * derives from this.
     */
    fun uuidV4FromBytes(bytes: ByteArray): String {
        require(bytes.size >= 16) { "need at least 16 bytes for a UUID" }
        val h = bytes.copyOf(16)
        h[6] = ((h[6].toInt() and 0x0F) or 0x40).toByte() // version nibble 4
        h[8] = ((h[8].toInt() and 0x3F) or 0x80).toByte() // variant 10
        val hex = toHexLower(h)
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
    }
}
