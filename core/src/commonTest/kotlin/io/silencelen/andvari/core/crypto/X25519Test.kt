package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * [X25519.isUsablePublicKey] against the provider it stands in front of.
 * The list of low-order points is written out in common code; libsodium has its
 * own. This test holds the two together from both sides: every key the helper refuses is one the
 * provider will not seal to, and the keys right next to those are ordinary keys for both.
 */
class X25519Test {
    private val crypto = createCryptoProvider()

    private fun hex(text: String): ByteArray = assertNotNull(Bytes.fromHexLower(text))

    /** [key] with the top bit of its last byte set: the same X25519 key, since that bit is ignored (RFC 7748 §5). */
    private fun withTopBit(key: ByteArray): ByteArray = key.copyOf().also { it[31] = (it[31].toInt() or 0x80).toByte() }

    private val lowOrder: List<ByteArray> = listOf(
        "00".repeat(32),
        "01" + "00".repeat(31),
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ec" + "ff".repeat(30) + "7f",
        "ed" + "ff".repeat(30) + "7f",
        "ee" + "ff".repeat(30) + "7f",
    ).map(::hex)

    /** The provider seals to [key]: what [X25519.isUsablePublicKey] must agree with. */
    private fun providerSeals(key: ByteArray): Boolean = try {
        crypto.sealTo(key, ByteArray(8))
        true
    } catch (e: CryptoException) {
        false
    }

    @Test
    fun everyLowOrderPoint_inEitherSpelling_isRefusedHereAndByTheProvider() {
        assertEquals(7, lowOrder.size)
        for (point in lowOrder) {
            for (key in listOf(point, withTopBit(point))) {
                val name = Bytes.toHexLower(key)
                assertFalse(X25519.isUsablePublicKey(key), name)
                assertFalse(providerSeals(key), "the provider seals to $name")
            }
        }
    }

    @Test
    fun theKeysNextToThem_areOrdinaryKeys_forBoth() {
        val neighbours = listOf(
            "02" + "00".repeat(31), // 2
            "09" + "00".repeat(31), // the base point
            "eb" + "ff".repeat(30) + "7f", // p - 2
            "ef" + "ff".repeat(30) + "7f", // p + 2, which reads as 2
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b801", // one bit from a point of order 8
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1156",
            "00".repeat(31) + "01", // 2^248
            "01" + "00".repeat(30) + "40",
        ).map(::hex)
        for (key in neighbours.flatMap { listOf(it, withTopBit(it)) }) {
            val name = Bytes.toHexLower(key)
            assertTrue(X25519.isUsablePublicKey(key), name)
            assertTrue(providerSeals(key), "the provider seals to $name")
        }
        // Every key a device makes for itself, and every one bit away from a listed point in its first byte.
        for (seed in 0 until 64) {
            val pair = crypto.boxKeypairFromSeed(ByteArray(32) { (seed * 7 + it).toByte() })
            assertTrue(X25519.isUsablePublicKey(pair.publicKey))
        }
        for (point in lowOrder) {
            for (bit in 0 until 8) {
                val near = point.copyOf().also { it[0] = (it[0].toInt() xor (1 shl bit)).toByte() }
                val name = Bytes.toHexLower(near)
                assertEquals(providerSeals(near), X25519.isUsablePublicKey(near), name)
            }
        }
    }

    @Test
    fun anythingThatIsNot32Bytes_isNotAKey() {
        for (size in listOf(0, 1, 16, 31, 33, 64)) {
            assertFalse(X25519.isUsablePublicKey(ByteArray(size) { 9 }), "$size bytes")
        }
        assertTrue(X25519.isUsablePublicKey(ByteArray(32) { 9 }))
    }
}
