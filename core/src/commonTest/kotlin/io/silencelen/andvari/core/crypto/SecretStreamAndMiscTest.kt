package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SecretStreamAndMiscTest {
    private val crypto = createCryptoProvider()

    @Test
    fun secretstreamRoundTrip() {
        val key = crypto.randomBytes(32)
        val chunks = listOf(
            crypto.randomBytes(64 * 1024),
            crypto.randomBytes(64 * 1024),
            crypto.randomBytes(1234),
        )
        val enc = crypto.secretstreamEncrypt(key, chunks)
        val dec = crypto.secretstreamDecrypt(key, enc.header, enc.chunks)
        assertEquals(chunks.size, dec.size)
        for (i in chunks.indices) assertContentEquals(chunks[i], dec[i])
    }

    @Test
    fun secretstreamTruncationFails() {
        val key = crypto.randomBytes(32)
        val enc = crypto.secretstreamEncrypt(key, listOf(crypto.randomBytes(100), crypto.randomBytes(100)))
        assertFailsWith<CryptoException> {
            crypto.secretstreamDecrypt(key, enc.header, enc.chunks.dropLast(1))
        }
    }

    @Test
    fun secretstreamCorruptChunkFails() {
        val key = crypto.randomBytes(32)
        val enc = crypto.secretstreamEncrypt(key, listOf(crypto.randomBytes(100), crypto.randomBytes(100)))
        val corrupt = enc.chunks.mapIndexed { i, c ->
            if (i == 0) c.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() } else c
        }
        assertFailsWith<CryptoException> { crypto.secretstreamDecrypt(key, enc.header, corrupt) }
    }

    @Test
    fun hibpParsing() {
        val hash = Hibp.sha1UpperHex(crypto, "password123")
        assertEquals(40, hash.length)
        assertEquals(hash.take(5), Hibp.prefix(hash))
        val response = "AAAAA111111111111111111111111111111:3\r\n${Hibp.suffix(hash)}:12345\r\nBBBBB:9"
        assertEquals(12345L, Hibp.countInRange(response, hash))
        assertEquals(0L, Hibp.countInRange("CCCC1111111111111111111111111111111:5", hash))
    }

    @Test
    fun passwordGeneratorRespectsClassesAndLength() {
        repeat(20) {
            val pw = PasswordGenerator.generate(crypto, GeneratorOptions(length = 20))
            assertEquals(20, pw.length)
            assertTrue(pw.any { it.isLowerCase() }, pw)
            assertTrue(pw.any { it.isUpperCase() }, pw)
            assertTrue(pw.any { it.isDigit() }, pw)
            assertTrue(pw.any { !it.isLetterOrDigit() }, pw)
            assertTrue(pw.none { it in "lIO01" }, pw)
        }
        val digitsOnly = PasswordGenerator.generate(crypto, GeneratorOptions(length = 12, lower = false, upper = false, symbols = false, avoidAmbiguous = false))
        assertTrue(digitsOnly.all { it.isDigit() })
    }

    @Test
    fun base64UrlUnpadded() {
        assertEquals("_wA", Bytes.toB64(byteArrayOf(0xFF.toByte(), 0x00)))
        assertContentEquals(byteArrayOf(0xFF.toByte(), 0x00), Bytes.fromB64("_wA"))
        assertFailsWith<CryptoException> { Bytes.fromB64("!!!") }
    }

    @Test
    fun ctEquals() {
        assertTrue(Bytes.ctEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 3)))
        kotlin.test.assertFalse(Bytes.ctEquals(byteArrayOf(1, 2, 3), byteArrayOf(1, 2, 4)))
        kotlin.test.assertFalse(Bytes.ctEquals(byteArrayOf(1, 2), byteArrayOf(1, 2, 3)))
    }
}
