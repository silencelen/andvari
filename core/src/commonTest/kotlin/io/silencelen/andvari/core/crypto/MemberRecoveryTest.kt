package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * MemberRecovery (design 2026-07-12 §F.6) — the per-member self-service recovery piece. Proves the
 * generate → open round-trip, the severed HKDF split, fail-closed on a wrong secret / wrong userId
 * (AD) / tampered blob, the CONFIRMATION-only [MemberRecovery.confirmMatches], and the display-form
 * round-trip. Cross-platform (commonTest) so the JVM and Android crypto backends agree.
 */
class MemberRecoveryTest {
    private val crypto = createCryptoProvider()
    private val userId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"

    @Test
    fun generateThenOpenRoundTrips() {
        val uvk = crypto.randomBytes(32)
        val piece = MemberRecovery.generate(crypto, userId, uvk)
        assertEquals(MemberRecovery.SECRET_BYTES, piece.recoverySecret.size, "256-bit generated secret")
        val opened = MemberRecovery.openUvk(crypto, piece.recoverySecret, piece.recoveryWrappedUvk, userId)
        assertTrue(opened.contentEquals(uvk), "openUvk recovers the exact UVK")
    }

    @Test
    fun deriveAuthKeyMatchesGenerate() {
        val piece = MemberRecovery.generate(crypto, userId, crypto.randomBytes(32))
        assertEquals(piece.recoveryAuthKey, MemberRecovery.deriveAuthKey(crypto, piece.recoverySecret), "recovery-path authKey == enroll authKey")
    }

    @Test
    fun wrapAndAuthKeysAreSevered() {
        // HKDF with distinct infos ⇒ the value the server verifies can never open the wrapped UVK.
        val secret = crypto.randomBytes(32)
        assertFalse(
            MemberRecovery.wrapKey(crypto, secret).contentEquals(MemberRecovery.authKey(crypto, secret)),
            "recovery-wrap and recovery-auth must differ",
        )
    }

    @Test
    fun wrongSecretFailsClosed() {
        val uvk = crypto.randomBytes(32)
        val piece = MemberRecovery.generate(crypto, userId, uvk)
        assertFailsWith<CryptoException>("a different secret must fail the AEAD tag") {
            MemberRecovery.openUvk(crypto, crypto.randomBytes(32), piece.recoveryWrappedUvk, userId)
        }
    }

    @Test
    fun wrongUserIdFailsClosed() {
        // The AD binds userId (Ad.recovery), so a blob can't be opened under a different user's slot.
        val piece = MemberRecovery.generate(crypto, userId, crypto.randomBytes(32))
        assertFailsWith<CryptoException>("AD mismatch on userId must fail closed") {
            MemberRecovery.openUvk(crypto, piece.recoverySecret, piece.recoveryWrappedUvk, "ffffffff-ffff-4fff-8fff-ffffffffffff")
        }
    }

    @Test
    fun tamperedBlobFailsClosed() {
        val piece = MemberRecovery.generate(crypto, userId, crypto.randomBytes(32))
        // Flip the last base64url char of the wrapped blob (mangles the tag) → fail closed.
        val body = piece.recoveryWrappedUvk
        val tampered = body.dropLast(1) + if (body.last() == 'A') 'B' else 'A'
        assertFailsWith<CryptoException>("a tampered blob must fail closed") {
            MemberRecovery.openUvk(crypto, piece.recoverySecret, tampered, userId)
        }
    }

    @Test
    fun adRecoveryIsDistinctFromUvk() {
        // recovery-uvk vs uvk — the cross-slot substitution guard.
        assertNotEquals(Ad.recovery(userId).decodeToString(), Ad.uvk(userId).decodeToString())
        assertEquals("andvari/v1|recovery-uvk|$userId", Ad.recovery(userId).decodeToString())
    }

    @Test
    fun displayFormRoundTripsThroughParseSecret() {
        val secret = crypto.randomBytes(32)
        val printed = MemberRecovery.displayForm(secret)
        assertTrue(MemberRecovery.parseSecret(printed)!!.contentEquals(secret), "printed form decodes back to the secret")
        // A space-grouped re-entry (the only safe separator for base64url) still round-trips.
        val grouped = printed.chunked(8).joinToString(" ")
        assertTrue(MemberRecovery.parseSecret(grouped)!!.contentEquals(secret), "space-grouped re-entry decodes back")
        assertNull(MemberRecovery.parseSecret("not valid base64url !!!"), "malformed → null, never throws")
    }

    @Test
    fun confirmMatchesIsConfirmationOnly() {
        val secret = crypto.randomBytes(32)
        val printed = MemberRecovery.displayForm(secret)
        // True on the exact phrase and on a whitespace-grouped copy of it.
        assertTrue(MemberRecovery.confirmMatches(secret, printed), "exact confirm passes")
        assertTrue(MemberRecovery.confirmMatches(secret, printed.chunked(8).joinToString("\n")), "hard-wrapped confirm passes")
        // False on a one-character mistype and on garbage (a mistype must fail the confirm, never mis-key).
        val mistyped = printed.dropLast(1) + if (printed.last() == 'A') 'B' else 'A'
        assertFalse(MemberRecovery.confirmMatches(secret, mistyped), "a mistype must fail the confirm")
        assertFalse(MemberRecovery.confirmMatches(secret, "garbage"), "garbage fails the confirm")
        assertFalse(MemberRecovery.confirmMatches(secret, ""), "empty fails the confirm")
    }
}
