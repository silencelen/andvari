package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

@OptIn(ExperimentalStdlibApi::class)
class HkdfTest {
    private val crypto = createCryptoProvider()

    @Test
    fun rfc5869_case1() {
        val okm = Hkdf.sha256(
            crypto,
            ikm = "0b".repeat(22).hexToByteArray(),
            salt = "000102030405060708090a0b0c".hexToByteArray(),
            info = "f0f1f2f3f4f5f6f7f8f9".hexToByteArray(),
            length = 42,
        )
        assertContentEquals(
            ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865").hexToByteArray(),
            okm,
        )
    }

    @Test
    fun rfc5869_case2_longInputs() {
        val ikm = (0x00..0x4f).map { it.toByte() }.toByteArray()
        val salt = (0x60..0xaf).map { it.toByte() }.toByteArray()
        val info = (0xb0..0xff).map { it.toByte() }.toByteArray()
        val okm = Hkdf.sha256(crypto, ikm, salt, info, 82)
        assertContentEquals(
            ("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db7" +
                "1cc30c58179ec3e87c14c01d5c1f3434f1d87").hexToByteArray(),
            okm,
        )
    }

    @Test
    fun rfc5869_case3_emptySaltAndInfo() {
        val okm = Hkdf.sha256(
            crypto,
            ikm = "0b".repeat(22).hexToByteArray(),
            salt = ByteArray(0),
            info = ByteArray(0),
            length = 42,
        )
        assertContentEquals(
            ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d" +
                "9d201395faa4b61a96c8").hexToByteArray(),
            okm,
        )
    }
}
