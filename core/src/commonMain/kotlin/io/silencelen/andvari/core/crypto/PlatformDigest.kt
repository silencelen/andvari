package io.silencelen.andvari.core.crypto

/**
 * SHA-256 from the platform, for callers that must work where libsodium cannot load (the origin
 * namespace is computed before any unlock, and Android's host-side unit tests pin it).
 */
internal expect fun platformSha256(data: ByteArray): ByteArray
