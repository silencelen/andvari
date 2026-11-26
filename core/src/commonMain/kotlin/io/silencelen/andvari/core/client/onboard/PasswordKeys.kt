package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys

/**
 * The master password's two keys (spec 01 §§1–2), derived from a [CharArray] without ever making a `String`
 * of it: the UTF-8 bytes are written by hand and wiped once Argon2id has read them. [authKey] is what goes to
 * the server; [wrapKey] wraps the UVK and never leaves the device. Both are owned by this object: [wipe] them.
 */
class PasswordKeys private constructor(val salt: ByteArray, val params: KdfParams, private val auth: ByteArray, private val wrap: ByteArray) {
    /** The `authKey` (or `currentAuthKey`) as the wire carries it. */
    val authKeyB64: String get() = Bytes.toB64(auth)

    internal val wrapKey: ByteArray get() = wrap

    fun wipe() {
        auth.fill(0)
        wrap.fill(0)
    }

    companion object {
        /**
         * Derive under [salt] and [params]. [served] params (a prelogin answer) pass the KDF fence first
         * ([KdfUpgrade.requireServerKdfParams], spec 05 T1); a refusal is `null` with nothing derived. The
         * [password] array is wiped here, whatever happens.
         */
        fun derive(crypto: CryptoProvider, password: CharArray, salt: ByteArray, params: KdfParams, served: Boolean): PasswordKeys? {
            try {
                if (salt.size != KdfParams.SALT_BYTES) return null
                if (served) {
                    try {
                        KdfUpgrade.requireServerKdfParams(params)
                    } catch (e: KdfPolicyViolationException) {
                        return null
                    }
                }
                val utf8 = utf8(password)
                val mk = try {
                    crypto.argon2id(utf8, salt, Keys.KEY_BYTES, params.ops, params.memBytes)
                } finally {
                    utf8.fill(0)
                }
                try {
                    return PasswordKeys(salt.copyOf(), params, Keys.authKey(crypto, mk), Keys.wrapKey(crypto, mk))
                } finally {
                    mk.fill(0)
                }
            } finally {
                password.fill('\u0000')
            }
        }

        /**
         * UTF-8 of [chars] as Kotlin's `String.encodeToByteArray` writes it (an unpaired surrogate becomes
         * U+FFFD), so a password derives the same key here as through the old `String` path.
         */
        internal fun utf8(chars: CharArray): ByteArray {
            var n = 0
            var i = 0
            while (i < chars.size) {
                val c = chars[i]
                n += when {
                    c.code < 0x80 -> 1
                    c.code < 0x800 -> 2
                    c.isHighSurrogate() && i + 1 < chars.size && chars[i + 1].isLowSurrogate() -> { i++; 4 }
                    else -> 3
                }
                i++
            }
            val out = ByteArray(n)
            var o = 0
            i = 0
            while (i < chars.size) {
                val c = chars[i]
                val cp: Int = when {
                    c.isHighSurrogate() && i + 1 < chars.size && chars[i + 1].isLowSurrogate() -> {
                        val lo = chars[i + 1]
                        i++
                        0x10000 + ((c.code - 0xD800) shl 10) + (lo.code - 0xDC00)
                    }
                    c.isSurrogate() -> 0xFFFD
                    else -> c.code
                }
                when {
                    cp < 0x80 -> out[o++] = cp.toByte()
                    cp < 0x800 -> {
                        out[o++] = (0xC0 or (cp shr 6)).toByte()
                        out[o++] = (0x80 or (cp and 0x3F)).toByte()
                    }
                    cp < 0x10000 -> {
                        out[o++] = (0xE0 or (cp shr 12)).toByte()
                        out[o++] = (0x80 or ((cp shr 6) and 0x3F)).toByte()
                        out[o++] = (0x80 or (cp and 0x3F)).toByte()
                    }
                    else -> {
                        out[o++] = (0xF0 or (cp shr 18)).toByte()
                        out[o++] = (0x80 or ((cp shr 12) and 0x3F)).toByte()
                        out[o++] = (0x80 or ((cp shr 6) and 0x3F)).toByte()
                        out[o++] = (0x80 or (cp and 0x3F)).toByte()
                    }
                }
                i++
            }
            return out
        }
    }
}
