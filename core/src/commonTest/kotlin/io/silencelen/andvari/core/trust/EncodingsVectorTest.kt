package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The encodings of design 2026-11-15 §2.2 and §2.3, graded off `encodings.json`, which comes from the
 * independent oracle (no andvari code): `emailNorm`, the `platform` enum, the proof-of-work string and
 * bit order, the `name` type and the `origin` grammar. Every row must give exactly its verdict.
 */
class EncodingsVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("encodings.json")

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(v, "_about", "emailNorm", "platform", "powLeadingZeroBits", "powInput", "name", "origin")
    }

    @Test
    fun emailNorm_everyRow() {
        gradeEvery("encodings.emailNorm", v.rows("emailNorm")) { r ->
            assertInputsKnown(r, setOf("why", "input", "expect"), "emailNorm ${r.s("why")}")
            val expect = r.o("expect")
            val got = TrustGrammar.emailNorm(r.s("input"))
            when (expect.s("verdict")) {
                "ok" -> {
                    assertExpectGraded(expect, setOf("verdict", "emailNorm"), "emailNorm ${r.s("why")}")
                    assertEquals(expect.s("emailNorm"), got, r.s("why"))
                }
                "invalid_email" -> {
                    assertExpectGraded(expect, setOf("verdict"), "emailNorm ${r.s("why")}")
                    assertNull(got, r.s("why"))
                }
                else -> error("unknown verdict in ${r.s("why")}")
            }
            // What emailNorm returns is a fixed point, and so is an `email_b64n` value (VR-7).
            if (got != null) {
                assertEquals(got, TrustGrammar.emailNorm(got), r.s("why"))
                val field = TrustGrammar.encodeEmail(got)!!
                assertEquals(got, TrustGrammar.decodeEmail(field)?.orNull, r.s("why"))
            }
        }
    }

    @Test
    fun platform_closedEnum() {
        gradeEvery("encodings.platform", v.rows("platform")) { r ->
            assertEquals(r.bool("valid"), TrustGrammar.isPlatform(r.s("value")), r.s("value"))
        }
    }

    @Test
    fun proofOfWork_bitOrderAndHashedString() {
        gradeEvery("encodings.powLeadingZeroBits", v.rows("powLeadingZeroBits")) { r ->
            assertEquals(r.l("leadingZeroBits").toInt(), SignupPow.leadingZeroBits(hexBytes(r.s("digestHex"))), r.s("why"))
        }
        gradeEvery("encodings.powInput", v.rows("powInput")) { r ->
            val email = r.s("emailNorm")
            val date = r.s("utcDate")
            val nonce = r.l("nonce")
            assertEquals(r.s("inputUtf8"), SignupPow.input(email, date, nonce), r.s("why"))
            val digest = SignupPow.digest(crypto, email, date, nonce)
            assertEquals(r.s("digestHex"), Bytes.toHexLower(digest), r.s("why"))
            val bits = r.l("leadingZeroBits").toInt()
            assertEquals(bits, SignupPow.leadingZeroBits(digest), r.s("why"))
            assertTrue(SignupPow.accepts(crypto, email, date, nonce, bits), r.s("why"))
            assertTrue(!SignupPow.accepts(crypto, email, date, nonce, bits + 1), r.s("why"))
        }
    }

    @Test
    fun proofOfWork_searchFindsTheFirstSolution() {
        val nonce = SignupPow.search(crypto, "alice@example.com", "2026-11-15", powBits = 8, from = 0, tries = 100_000)!!
        assertTrue(SignupPow.accepts(crypto, "alice@example.com", "2026-11-15", nonce, 8))
        for (n in 0 until nonce) assertTrue(!SignupPow.accepts(crypto, "alice@example.com", "2026-11-15", n, 8))
        assertNull(SignupPow.search(crypto, "alice@example.com", "2026-11-15", powBits = 250, from = 0, tries = 50))
        assertFailsWith<IllegalArgumentException> { SignupPow.input("Alice@example.com", "2026-11-15", 0) }
        assertFailsWith<IllegalArgumentException> { SignupPow.input("alice@example.com", "2026-11-5", 0) }
        assertFailsWith<IllegalArgumentException> { SignupPow.input("alice@example.com", "2026-11-15", -1) }
    }

    @Test
    fun name_everyRow() {
        gradeEvery("encodings.name", v.rows("name")) { r ->
            val b64 = r.s("name")
            val text = TrustGrammar.decodeName(b64)
            assertEquals(r.bool("valid"), text != null, r.s("why"))
            assertEquals(r.bool("valid"), TrustGrammar.isName(b64), r.s("why"))
            if (text != null) {
                // No normalisation: the decoded text is exactly the bytes, and it encodes back to the same field.
                assertContentEquals(hexBytes(r.s("textHex")), text.encodeToByteArray(), r.s("why"))
                assertEquals(b64, TrustGrammar.encodeName(text), r.s("why"))
            }
        }
    }

    @Test
    fun origin_everyRow() {
        gradeEvery("encodings.origin", v.rows("origin")) { r ->
            assertEquals(r.bool("valid"), TrustGrammar.isOrigin(r.s("origin")), "${r.s("why")}: ${r.s("origin")}")
        }
    }
}
