package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TotpTest {
    private val crypto = createCryptoProvider()

    private val sha1Secret = "12345678901234567890".encodeToByteArray()
    private val sha256Secret = "12345678901234567890123456789012".encodeToByteArray()
    private val sha512Secret = ("1234567890123456789012345678901234567890" +
        "123456789012345678901234").encodeToByteArray()

    private fun cfg(alg: TotpAlgorithm, secret: ByteArray) =
        TotpConfig(secret = secret, algorithm = alg, digits = 8, periodSeconds = 30)

    @Test
    fun rfc6238_appendixB() {
        val cases = listOf(
            Triple(59L, TotpAlgorithm.SHA1, "94287082"),
            Triple(59L, TotpAlgorithm.SHA256, "46119246"),
            Triple(59L, TotpAlgorithm.SHA512, "90693936"),
            Triple(1111111109L, TotpAlgorithm.SHA1, "07081804"),
            Triple(1111111109L, TotpAlgorithm.SHA256, "68084774"),
            Triple(1111111109L, TotpAlgorithm.SHA512, "25091201"),
            Triple(1111111111L, TotpAlgorithm.SHA1, "14050471"),
            Triple(1111111111L, TotpAlgorithm.SHA256, "67062674"),
            Triple(1111111111L, TotpAlgorithm.SHA512, "99943326"),
            Triple(1234567890L, TotpAlgorithm.SHA1, "89005924"),
            Triple(1234567890L, TotpAlgorithm.SHA256, "91819424"),
            Triple(1234567890L, TotpAlgorithm.SHA512, "93441116"),
            Triple(2000000000L, TotpAlgorithm.SHA1, "69279037"),
            Triple(2000000000L, TotpAlgorithm.SHA256, "90698825"),
            Triple(2000000000L, TotpAlgorithm.SHA512, "38618901"),
            Triple(20000000000L, TotpAlgorithm.SHA1, "65353130"),
            Triple(20000000000L, TotpAlgorithm.SHA256, "77737706"),
            Triple(20000000000L, TotpAlgorithm.SHA512, "47863826"),
        )
        for ((time, alg, expected) in cases) {
            val secret = when (alg) {
                TotpAlgorithm.SHA1 -> sha1Secret
                TotpAlgorithm.SHA256 -> sha256Secret
                TotpAlgorithm.SHA512 -> sha512Secret
            }
            assertEquals(expected, Totp.code(crypto, cfg(alg, secret), time), "T=$time $alg")
        }
    }

    @Test
    fun sixDigitDefault() {
        val config = TotpConfig(secret = sha1Secret)
        assertEquals(6, Totp.code(crypto, config, 59).length)
        assertEquals("287082", Totp.code(crypto, config, 59)) // last 6 of the RFC 8-digit value
    }

    @Test
    fun base32RoundTrip() {
        val bytes = byteArrayOf(0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        assertEquals("JBSWY3DPEHPK3PXP", Base32.encode(bytes))
        kotlin.test.assertContentEquals(bytes, Base32.decode("JBSWY3DPEHPK3PXP"))
        kotlin.test.assertContentEquals(bytes, Base32.decode("jbswy3dpehpk3pxp"))
        kotlin.test.assertContentEquals(bytes, Base32.decode("JBSW Y3DP EHPK 3PXP="))
    }

    @Test
    fun otpauthUriParsing() {
        val c = Totp.parseUri(
            "otpauth://totp/GitHub:jacob%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60",
        )
        assertEquals("GitHub:jacob@example.com", c.label)
        assertEquals("GitHub", c.issuer)
        assertEquals(TotpAlgorithm.SHA256, c.algorithm)
        assertEquals(8, c.digits)
        assertEquals(60, c.periodSeconds)
        assertEquals("JBSWY3DPEHPK3PXP", Base32.encode(c.secret))
    }

    @Test
    fun otpauthDefaults() {
        val c = Totp.parseUri("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
        assertEquals(TotpAlgorithm.SHA1, c.algorithm)
        assertEquals(6, c.digits)
        assertEquals(30, c.periodSeconds)
    }

    @Test
    fun rejectsNonTotpUri() {
        assertFailsWith<CryptoException> { Totp.parseUri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP") }
        assertFailsWith<CryptoException> { Totp.parseUri("otpauth://totp/x?digits=6") }
    }
}
