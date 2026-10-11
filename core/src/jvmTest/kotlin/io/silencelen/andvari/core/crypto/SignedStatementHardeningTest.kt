package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs

/**
 * The A3-review hardening that A4 (the first caller of the codec) had to land (security review 2026-10):
 * 1. escrow statement fields are bound to the OUT-OF-BAND anchor, not to themselves;
 * 2. unverified parse output is a distinct type, not assignable where a verified value is required;
 * 3. verified data is read-only.
 */
class SignedStatementHardeningTest {
    private val crypto = createCryptoProvider()
    private val userId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    private val orgFp = "14f1bf4220e132f39314cabd75e7fa8d88348a699154a7965e64e76321b54f49"

    private fun member(): Pair<KeyPairBytes, ByteArray> {
        val seed = crypto.randomBytes(32)
        return crypto.signKeypairFromSeed(seed) to crypto.boxKeypairFromSeed(seed).publicKey
    }

    private fun escrow(identityKey: ByteArray, user: String = userId, fp: String = orgFp) =
        Statement.EscrowUvk(user, identityKey, fp, 1_791_590_400_000L, crypto.randomBytes(32))

    @Test
    fun escrowStatement_whoseEmbeddedIdentityDiffersFromTheAnchor_isRejectedDespiteAValidSignature() {
        val (signer, identityPub) = member()
        val (_, otherIdentity) = member()
        // The member really signs it (signature valid, signer maps to the anchor), but the statement
        // names ANOTHER identity key. Reading the identity from the statement and pinning to it would
        // have accepted this; binding the field to the anchor refuses it.
        val frame = SignedStatement.build(crypto, signer, escrow(otherIdentity))
        val e = assertFailsWith<SignedStatementException> {
            SignedStatement.verifyEscrow(crypto, frame, userId, identityPub, orgFp)
        }
        assertEquals(StatementVerdict.IDENTITY_MISMATCH, e.verdict)
        // The same frame with the statement's OWN identity as the "anchor" would be self-pinning; it
        // fails too, because the signer does not map to that key.
        val self = assertFailsWith<SignedStatementException> {
            SignedStatement.verifyEscrow(crypto, frame, userId, otherIdentity, orgFp)
        }
        assertEquals(StatementVerdict.SIGNER_NOT_PINNED_KEY, self.verdict)
    }

    @Test
    fun escrowStatement_boundToTheExpectedUserAndRecoveryKey() {
        val (signer, identityPub) = member()
        val frame = SignedStatement.build(crypto, signer, escrow(identityPub))
        assertEquals(
            StatementVerdict.USER_MISMATCH,
            assertFailsWith<SignedStatementException> {
                SignedStatement.verifyEscrow(crypto, frame, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", identityPub, orgFp)
            }.verdict,
        )
        assertEquals(
            StatementVerdict.RECOVERY_FP_MISMATCH,
            assertFailsWith<SignedStatementException> {
                SignedStatement.verifyEscrow(crypto, frame, userId, identityPub, "0".repeat(64))
            }.verdict,
        )
        val ok = SignedStatement.verifyEscrow(crypto, frame, userId, identityPub, orgFp)
        assertIs<Statement.EscrowUvk>(ok.statement)
    }

    @Test
    fun genericVerify_refusesEscrowStatements_soTheAnchorCannotBeSkipped() {
        val (signer, identityPub) = member()
        val frame = SignedStatement.build(crypto, signer, escrow(identityPub))
        assertFailsWith<IllegalArgumentException> {
            SignedStatement.verify(crypto, frame, StatementPurpose.ESCROW_UVK, identityPub)
        }
    }

    @Test
    fun unverifiedParseOutput_isADistinctType_notAssignableWhereAVerifiedValueIsRequired() {
        // Compile-time property, pinned at runtime: the parse result type is neither a Statement nor a
        // VerifiedStatement (so `val s: Statement = parseStatement(...)` does not compile); the
        // VerifiedStatement constructor is `internal` to core, so only the verify helpers mint one.
        assertFalse(Statement::class.java.isAssignableFrom(UnverifiedStatement::class.java))
        assertFalse(VerifiedStatement::class.java.isAssignableFrom(UnverifiedStatement::class.java))
        // And it exposes routing fields only — no key material.
        val (signer, identityPub) = member()
        val frame = SignedStatement.build(crypto, signer, escrow(identityPub))
        val parsed = SignedStatement.parseStatement(2, frame.copyOfRange(SignedStatement.STATEMENT_OFFSET, frame.size))
        val e = assertIs<UnverifiedStatement.EscrowUvk>(parsed)
        assertEquals(userId, e.userId)
        assertEquals(orgFp, e.recoveryFp)
        val publicGetters = UnverifiedStatement.EscrowUvk::class.java.methods.map { it.name }.toSet()
        for (secret in listOf("getKey", "getIdentityKey", "getVk", "getToKey")) {
            assertFalse(secret in publicGetters, "unverified statement must not expose $secret")
        }
    }

    @Test
    fun verifiedData_isReadOnly() {
        val (signer, identityPub) = member()
        val key = crypto.randomBytes(32)
        val st = Statement.EscrowUvk(userId, identityPub, orgFp, 1_791_590_400_000L, key)
        key.fill(0) // the caller mutating its input array after building cannot change the statement
        assertFalse(st.key.contentEquals(ByteArray(32)))
        val verified = SignedStatement.verifyEscrow(crypto, SignedStatement.build(crypto, signer, st), userId, identityPub, orgFp)
        val held = (verified.statement as Statement.EscrowUvk).key
        (verified.statement as Statement.EscrowUvk).key.fill(0)
        (verified.statement as Statement.EscrowUvk).identityKey.fill(0)
        verified.signerPub.fill(0)
        assertContentEquals(held, (verified.statement as Statement.EscrowUvk).key, "key hands out a copy")
        assertContentEquals(identityPub, (verified.statement as Statement.EscrowUvk).identityKey, "identityKey hands out a copy")
        assertContentEquals(signer.publicKey, verified.signerPub, "signerPub hands out a copy")
    }
}
