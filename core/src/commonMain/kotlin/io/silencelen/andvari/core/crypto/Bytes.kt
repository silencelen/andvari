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

    @OptIn(ExperimentalStdlibApi::class)
    fun toHexLower(bytes: ByteArray): String = bytes.toHexString()

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
