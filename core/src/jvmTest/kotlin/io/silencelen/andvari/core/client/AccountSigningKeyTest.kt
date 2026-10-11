package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.SignedStatementException
import io.silencelen.andvari.core.crypto.Statement
import io.silencelen.andvari.core.crypto.StatementPurpose
import io.silencelen.andvari.core.crypto.StatementVerdict
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/**
 * The joint Ed25519 signing key (security review 2026-10, root cause A §1.1, owner decision: joint key):
 * derived at enrol AND at unlock from the UVK-sealed identity seed, mapping to the account's existing
 * X25519 identityPub, so no fingerprint changes. A3 has no product caller; this pins the derivation and
 * that a statement the account signs verifies under its own pinned identity key and no other.
 */
class AccountSigningKeyTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"

    @Test
    fun signPub_isDerivedAtEnrolAndUnlock_andMapsToIdentityPub() {
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", crypto)
        val enrolled = r.account
        assertContentEquals(enrolled.identityPub, crypto.ed25519PkToCurve25519(enrolled.signPub))

        val keys = AccountKeys(
            kdfSalt = r.request.kdfSalt,
            kdfParams = r.request.kdfParams,
            wrappedUvk = r.request.wrappedUvk,
            encryptedIdentitySeed = r.request.encryptedIdentitySeed,
            identityPub = r.request.identityPub,
            escrowFingerprint = "",
        )
        val unlocked = Account.unlock(r.request.userId, password, keys, crypto)
        assertContentEquals(enrolled.signPub, unlocked.signPub, "unlock re-derives the same signing key")
        assertContentEquals(unlocked.identityPub, crypto.ed25519PkToCurve25519(unlocked.signPub))
    }

    @Test
    fun signStatement_verifiesOnlyUnderTheAccountsOwnPin() {
        val alice = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", crypto).account
        val bob = Account.enroll("inv", "b@x.com", "b", password, kdf, null, null, "dev", crypto).account
        val st = Statement.VaultGrant(
            from = alice.userId, to = bob.userId, toKey = bob.identityPub, vaultId = alice.personalVaultId,
            grantId = crypto.randomBytes(16), issuedAt = 1_791_590_400_000L, vk = crypto.randomBytes(32),
        )
        val frame = alice.signStatement(st)
        val verified = SignedStatement.verify(crypto, frame, StatementPurpose.VAULT_GRANT, alice.identityPub)
        assertIs<Statement.VaultGrant>(verified.statement)
        assertContentEquals(alice.signPub, verified.signerPub)

        val e = assertFailsWith<SignedStatementException> {
            SignedStatement.verify(crypto, frame, StatementPurpose.VAULT_GRANT, bob.identityPub)
        }
        assertEquals(StatementVerdict.SIGNER_NOT_PINNED_KEY, e.verdict)
    }
}
