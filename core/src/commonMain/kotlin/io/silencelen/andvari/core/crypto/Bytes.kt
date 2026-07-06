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
}
