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
        // A5 reject-don't-corrupt (2026-07-09 review [1]): an EMPTY secret param must fail —
        // Kotlin once accepted it (empty HMAC key → SecretKeySpec crash at render) while the
        // web twin rejected it, so the same CSV built different vault content per client.
        assertFailsWith<CryptoException> { Totp.parseUri("otpauth://totp/Site?secret=") }
        assertFailsWith<CryptoException> { Totp.parseUri("otpauth://totp/Site?secret=&issuer=X") }
    }

    // ---- Totp.normalize (spec 06 §9.2, A5) — the ONE shared normalize ----

    @Test
    fun normalize_bareBase32_wrapsPreservingOriginalCase() {
        assertEquals("otpauth://totp/andvari?secret=JBSWY3DPEHPK3PXP", Totp.normalize("JBSWY3DPEHPK3PXP"))
        assertEquals("otpauth://totp/andvari?secret=jbswy3dpehpk3pxp", Totp.normalize("jbswy3dpehpk3pxp"))
        assertEquals("otpauth://totp/andvari?secret=JBSWY3DP====", Totp.normalize("JBSWY3DP====")) // padding-tolerant
    }

    @Test
    fun normalize_stripsAllAsciiWhitespace() {
        assertEquals("otpauth://totp/andvari?secret=JBSWY3DPEHPK3PXP", Totp.normalize(" JBSW Y3DP\tEHPK\n3PXP\r"))
        // Inside an otpauth URI too — ALL ASCII whitespace goes, label included (pinned).
        assertEquals(
            "otpauth://totp/MySite?secret=JBSWY3DPEHPK3PXP",
            Totp.normalize("otpauth://totp/My Site?secret=JBSWY3DPEHPK3PXP"),
        )
    }

    @Test
    fun normalize_otpauthPrefixPassesThrough_caseInsensitive() {
        assertEquals("OTPAUTH://totp/X?secret=AAAA", Totp.normalize("OTPAUTH://totp/X?secret=AAAA"))
        // Passing through does NOT mean valid: hotp still fails parseUri afterwards.
        val hotp = Totp.normalize("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP")
        assertEquals("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", hotp)
        assertFailsWith<CryptoException> { Totp.parseUri(hotp) }
    }

    @Test
    fun normalize_nonBase32_returnedUnchanged() {
        assertEquals("steam://ABCD1234", Totp.normalize("steam://ABCD1234"))
        assertEquals("notasecret!", Totp.normalize("not a secret!")) // spaces stripped, then unchanged
        assertEquals("", Totp.normalize("   "))
    }
}
