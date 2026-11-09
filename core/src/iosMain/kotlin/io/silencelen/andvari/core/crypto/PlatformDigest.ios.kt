@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.crypto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_SHA256
import platform.CoreCrypto.CC_SHA256_DIGEST_LENGTH

internal actual fun platformSha256(data: ByteArray): ByteArray {
    val out = ByteArray(CC_SHA256_DIGEST_LENGTH)
    out.usePinned { o ->
        (if (data.isEmpty()) ByteArray(1) else data).usePinned { d ->
            CC_SHA256(d.addressOf(0), data.size.toUInt(), o.addressOf(0).reinterpret())
        }
    }
    return out
}
