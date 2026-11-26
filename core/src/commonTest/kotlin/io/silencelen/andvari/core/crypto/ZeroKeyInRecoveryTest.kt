package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.trust.RecoveryVerdict
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * A key taken out of a signed and sealed structure is checked before it is used: a recovery copy, or an answer signed by
 * the recovery key, that holds an all-zero account key holds no account's key. It is refused where it is taken out, by the
 * verdict the specification gives a copy or an answer whose key does not open the account's identity (spec 04 §4 step 6:
 * `identity_check_failed`; §7 step 4: `identity_mismatch`), and nothing is opened under it.
 */
class ZeroKeyInRecoveryTest {
    private val crypto = createCryptoProvider()
    private val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val orgFp = Escrow.fingerprint(crypto, org.publicKey)
    private val userId = "11111111-1111-4111-8111-111111111111"
    private val email = "ann@family.example"
    private val idSeed = crypto.randomBytes(32)
    private val identityPub = crypto.boxKeypairFromSeed(idSeed).publicKey
    private val uvk = crypto.randomBytes(32)
    private val check = IdentityCheck(Envelope.sealB64(crypto, uvk, idSeed, Ad.idkey(userId)), Bytes.toB64(identityPub))

    /** [block], with every refusal of the key floor heard (and still passed on): nothing may be attempted under the key. */
    private fun <T> floorSilent(block: () -> T): T {
        val heard = ArrayList<String>()
        val before = KeyFloor.onRefusal
        KeyFloor.onRefusal = { heard += it; before?.invoke(it) }
        try {
            return block().also { assertEquals(emptyList<String>(), heard, "nothing is opened under an all-zero key") }
        } finally {
            KeyFloor.onRefusal = before
        }
    }

    /**
     * The hostile holder of the recovery key: an answer it signed and sealed to the request, whatever key [fields] hold.
     * Sealing a frame that holds an all-zero key is what the zero-key tripwire counts at the provider, and this function
     * is the one place it lists as expected for this class. Everything the device does with the answer happens outside
     * it, so a line from the code under test still fails the run.
     */
    private fun sealedByTheRecoveryKey(recipientPublicKey: ByteArray, signer: KeyPairBytes, fields: AssistedRecoveryFields): ByteArray =
        AssistedRecovery.seal(crypto, recipientPublicKey, AssistedRecovery.sign(crypto, signer, fields))

    @Test
    fun aCopyHoldingAnAllZeroKey_isIdentityCheckFailed_fromEveryOpener() {
        for (v3 in listOf(true, false)) {
            // Signed by the account, sealed to the recovery key: everything about it is right except the key it holds.
            val frame = SignedStatement.build(
                crypto, crypto.signKeypairFromSeed(idSeed),
                Statement.EscrowUvk(userId, identityPub, orgFp, 1_791_590_400_000L, ByteArray(32), if (v3) email else null),
            )
            val sealed = crypto.sealTo(org.publicKey, frame)
            floorSilent {
                assertEquals(EscrowVerdict.IDENTITY_CHECK_FAILED, assertFailsWith<EscrowOpenException> { Escrow.open(crypto, org, sealed, userId, null, check, Escrow.UNANCHORED_ACK) }.verdict)
                assertEquals(EscrowVerdict.IDENTITY_CHECK_FAILED, assertFailsWith<EscrowOpenException> { Escrow.openForFleet(crypto, org, sealed, userId, check) }.verdict)
                assertEquals(
                    EscrowVerdict.IDENTITY_CHECK_FAILED,
                    assertFailsWith<EscrowOpenException> { Escrow.openForAssist(crypto, org, sealed, userId, email, Escrow.fingerprint(crypto, identityPub), check) }.verdict,
                )
            }
        }
    }

    @Test
    fun anAnswerHoldingAnAllZeroKey_isIdentityMismatch_inBothVersions() {
        val instanceId = "12345678-1234-4234-8234-123456789abc"
        val requestId = Bytes.toB64(crypto.randomBytes(16))
        val request = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        // The recovery key that signs: its seed's X25519 key is the one the pinned card names.
        val recoverySeed = crypto.randomBytes(32)
        val recoveryFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(recoverySeed).publicKey)
        val recoverySigner = crypto.signKeypairFromSeed(recoverySeed)
        val v3 = AssistedRecoveryFields(instanceId, userId, requestId, Bytes.toB64(request.publicKey), ByteArray(32), 1_800_000_000_000L, email = email, commit = crypto.randomBytes(32))
        val sealedV3 = sealedByTheRecoveryKey(request.publicKey, recoverySigner, v3)
        assertEquals(
            RecoveryVerdict.IDENTITY_MISMATCH,
            floorSilent { AssistedRecovery.openV3(crypto, request.publicKey, request.privateKey, sealedV3, recoveryFp, instanceId, requestId, email, check, null).verdictOrNull() },
        )
        val v2 = AssistedRecoveryFields(instanceId, userId, requestId, Bytes.toB64(request.publicKey), ByteArray(32), 1_800_000_000_000L)
        val sealedV2 = sealedByTheRecoveryKey(request.publicKey, recoverySigner, v2)
        assertEquals(
            RecoveryVerdict.IDENTITY_MISMATCH,
            floorSilent { AssistedRecovery.open(crypto, request.publicKey, request.privateKey, sealedV2, recoveryFp, instanceId, requestId, check, null).verdictOrNull() },
        )
    }
}
