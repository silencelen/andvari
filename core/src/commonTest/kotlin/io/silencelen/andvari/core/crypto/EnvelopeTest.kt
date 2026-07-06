package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class EnvelopeTest {
    private val crypto = createCryptoProvider()
    private val key = crypto.randomBytes(32)
    private val ad = Ad.item("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 1)

    @Test
    fun roundTrip() {
        val plaintext = "correct horse battery staple".encodeToByteArray()
        val env = Envelope.seal(crypto, key, plaintext, ad)
        assertEquals(Envelope.VERSION, env[0])
        assertEquals(Envelope.ALG_XCHACHA20POLY1305_IETF, env[1])
        assertContentEquals(plaintext, Envelope.open(crypto, key, env, ad))
    }

    @Test
    fun adMismatchFails() {
        val env = Envelope.seal(crypto, key, "x".encodeToByteArray(), ad)
        val otherAd = Ad.item("11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333", 1)
        assertFailsWith<CryptoException> { Envelope.open(crypto, key, env, otherAd) }
    }

    @Test
    fun corruptByteFails() {
        val env = Envelope.seal(crypto, key, "payload".encodeToByteArray(), ad)
        for (index in intArrayOf(2, 20, env.size - 1)) {
            val bad = env.copyOf()
            bad[index] = (bad[index].toInt() xor 0x01).toByte()
            assertFailsWith<CryptoException>("index $index") { Envelope.open(crypto, key, bad, ad) }
        }
    }

    @Test
    fun wrongVersionOrAlgOrLengthRejected() {
        val env = Envelope.seal(crypto, key, "p".encodeToByteArray(), ad)
        assertFailsWith<CryptoException> { Envelope.open(crypto, key, env.copyOf().also { it[0] = 0x02 }, ad) }
        assertFailsWith<CryptoException> { Envelope.open(crypto, key, env.copyOf().also { it[1] = 0x07 }, ad) }
        assertFailsWith<CryptoException> { Envelope.open(crypto, key, env.copyOfRange(0, Envelope.MIN_BYTES - 1), ad) }
    }

    @Test
    fun adBytesAreExact() {
        assertContentEquals(
            "andvari/v1|item|a|b|1".encodeToByteArray(),
            Ad.item("a", "b", 1),
        )
        assertContentEquals("andvari/v1|uvk|u1".encodeToByteArray(), Ad.uvk("u1"))
        assertContentEquals("andvari/v1|vk|v1|u1".encodeToByteArray(), Ad.vk("v1", "u1"))
        assertContentEquals("andvari/v1|vaultmeta|v1".encodeToByteArray(), Ad.vaultMeta("v1"))
        assertFailsWith<IllegalArgumentException> { Ad.uvk("bad|component") }
    }
}
