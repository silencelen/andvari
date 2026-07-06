package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AttachmentsTest {
    private val crypto = createCryptoProvider()

    private fun roundtrip(size: Int) {
        val key = crypto.randomBytes(32)
        val plain = ByteArray(size) { (it * 31 + size).toByte() }
        val enc = Attachments.encrypt(crypto, key, plain)
        assertEquals(Attachments.HEADER_BYTES, enc.header.size)
        val expectedChunks = (size + Attachments.CHUNK - 1) / Attachments.CHUNK
        assertEquals(expectedChunks * Attachments.STREAM_ABYTES + size, enc.ciphertext.size)
        assertContentEquals(plain, Attachments.decrypt(crypto, key, enc.header, enc.ciphertext))
    }

    @Test
    fun roundtrip_sub_chunk() = roundtrip(5_000)

    @Test
    fun roundtrip_exact_chunk_boundary() = roundtrip(Attachments.CHUNK)

    @Test
    fun roundtrip_multi_chunk() = roundtrip(Attachments.CHUNK * 2 + 12_345)

    @Test
    fun roundtrip_exact_multiple() = roundtrip(Attachments.CHUNK * 3)

    @Test
    fun empty_plaintext_rejected() {
        assertFailsWith<CryptoException> { Attachments.encrypt(crypto, crypto.randomBytes(32), ByteArray(0)) }
    }

    @Test
    fun corrupt_byte_fails_hard() {
        val key = crypto.randomBytes(32)
        val enc = Attachments.encrypt(crypto, key, ByteArray(Attachments.CHUNK + 100) { 7 })
        val corrupted = enc.ciphertext.copyOf().also { it[Attachments.CIPHER_CHUNK + 5] = (it[Attachments.CIPHER_CHUNK + 5] + 1).toByte() }
        assertFailsWith<CryptoException> { Attachments.decrypt(crypto, key, enc.header, corrupted) }
    }

    @Test
    fun truncation_fails_hard() {
        val key = crypto.randomBytes(32)
        val enc = Attachments.encrypt(crypto, key, ByteArray(Attachments.CHUNK * 2) { 3 })
        // Dropping the whole final chunk means the last remaining chunk lacks TAG_FINAL.
        val truncated = enc.ciphertext.copyOfRange(0, Attachments.CIPHER_CHUNK)
        assertFailsWith<CryptoException> { Attachments.decrypt(crypto, key, enc.header, truncated) }
    }

    @Test
    fun wrong_key_fails_hard() {
        val enc = Attachments.encrypt(crypto, crypto.randomBytes(32), ByteArray(64) { 1 })
        assertFailsWith<CryptoException> { Attachments.decrypt(crypto, crypto.randomBytes(32), enc.header, enc.ciphertext) }
    }
}
