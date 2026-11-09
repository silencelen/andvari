package io.silencelen.andvari.core.crypto

import java.security.MessageDigest

internal actual fun platformSha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
