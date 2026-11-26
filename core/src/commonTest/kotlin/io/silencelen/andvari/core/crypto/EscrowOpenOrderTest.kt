package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Comparison V4-K1: the shared openers check in the text's order (spec 04 §4). Every input of step 0 comes
 * first (`--user`, the anchor, the identity file, the address, the identity file's key); the unanchored acknowledgment is
 * step 2. The web's twin copies this order.
 */
class EscrowOpenOrderTest {
    private val crypto = createCryptoProvider()
    private val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val orgFp = Escrow.fingerprint(crypto, org.publicKey)
    private val userId = "11111111-1111-4111-8111-111111111111"
    private val email = "ann@family.example"
    private val idSeed = crypto.randomBytes(32)
    private val identityPub = crypto.boxKeypairFromSeed(idSeed).publicKey
    private val uvk = crypto.randomBytes(32)
    private val sealed = Escrow.sealUvkV3(crypto, org.publicKey, orgFp, userId, email, identityPub, crypto.signKeypairFromSeed(idSeed), uvk, 1_791_590_400_000L)
    private val check = IdentityCheck(Envelope.sealB64(crypto, uvk, idSeed, Ad.idkey(userId)), Bytes.toB64(identityPub))

    /** The verdict of [Escrow.openForAssist] and of [Escrow.open] for the same inputs, unanchored and without the acknowledgment unless given. */
    private fun both(identityCheck: IdentityCheck?, ack: String? = null, typed: String = email, prefix: String? = null): Pair<EscrowVerdict, EscrowVerdict> =
        assertFailsWith<EscrowOpenException> { Escrow.openForAssist(crypto, org, sealed, userId, typed, prefix, identityCheck, ack) }.verdict to
            assertFailsWith<EscrowOpenException> { Escrow.open(crypto, org, sealed, userId, prefix, identityCheck, ack) }.verdict

    @Test
    fun anAbsentIdentityFile_isStep0_beforeTheAcknowledgmentOfStep2() {
        assertEquals(EscrowVerdict.IDENTITY_CHECK_REQUIRED to EscrowVerdict.IDENTITY_CHECK_REQUIRED, both(null))
    }

    @Test
    fun theRestOfStep0_alsoComesBeforeTheAcknowledgment() {
        val shortKey = IdentityCheck(check.encryptedIdentitySeedB64, Bytes.toB64(identityPub.copyOf(31)))
        assertEquals(EscrowVerdict.IDENTITY_CHECK_FAILED to EscrowVerdict.IDENTITY_CHECK_FAILED, both(shortKey))
        assertEquals(
            EscrowVerdict.BAD_EMAIL,
            assertFailsWith<EscrowOpenException> { Escrow.openForAssist(crypto, org, sealed, userId, "not an address", null, check, null) }.verdict,
        )
        // Step 0's own order is unchanged: the anchor before the identity file.
        assertEquals(EscrowVerdict.BAD_ANCHOR to EscrowVerdict.BAD_ANCHOR, both(null, prefix = "AB".repeat(16)))
    }

    @Test
    fun withEveryInputGiven_theAcknowledgmentStillDecides() {
        assertEquals(EscrowVerdict.UNANCHORED_NOT_ACKNOWLEDGED to EscrowVerdict.UNANCHORED_NOT_ACKNOWLEDGED, both(check))
        assertEquals(email, Escrow.openForAssist(crypto, org, sealed, userId, email, null, check, Escrow.UNANCHORED_ACK).also { it.wipe() }.email)
    }
}
