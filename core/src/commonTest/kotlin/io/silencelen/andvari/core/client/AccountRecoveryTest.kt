package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Account per-member recovery + opt-out (design 2026-07-12 §F.4/§F.3/§F.8). Proves: enroll ALWAYS
 * mints a member-recovery piece; org escrow is CONDITIONAL on the org key (required vs waived);
 * recover() opens the SAME UVK, fires the identity-pubkey hard-fail, and re-wraps the invariant UVK;
 * and setupMemberRecovery() produces a usable piece over the in-memory UVK.
 */
class AccountRecoveryTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id
    private val password = "correct horse battery staple"

    private fun orgKey() = crypto.boxKeypairFromSeed(crypto.randomBytes(32))

    @Test
    fun requiredInviteSealsEscrowAndMemberRecovery() {
        val org = orgKey()
        val fp = Escrow.fingerprint(crypto, org.publicKey)
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, org.publicKey, fp, "dev", crypto)

        // Org escrow present (required) + member-recovery piece present (mandatory).
        val escrow = r.request.escrow
        assertNotNull(escrow, "required invite must seal org escrow")
        assertEquals(fp, escrow.fingerprint)
        val recovery = r.request.memberRecovery
        assertNotNull(recovery, "member-recovery is mandatory")

        // Both blobs open to the SAME UVK (the double-wrap-consistency invariant, §F.8).
        val uvkFromEscrow = Bytes.fromB64(Escrow.open(crypto, org.publicKey, org.privateKey, Bytes.fromB64(escrow.sealed)).key)
        val uvkFromPiece = MemberRecovery.openUvk(crypto, r.recoverySecret, recovery.recoveryWrappedUvk, r.request.userId)
        assertTrue(uvkFromEscrow.contentEquals(uvkFromPiece), "escrow and member-recovery wrap the same UVK")
        assertTrue(uvkFromPiece.contentEquals(r.account.uvkCopyForPlatformWrap()), "…which is the live account UVK")
    }

    @Test
    fun waivedInviteOmitsEscrowButKeepsMemberRecovery() {
        val r = Account.enroll("inv", "b@x.com", "b", password, kdf, null, null, "dev", crypto)
        assertNull(r.request.escrow, "waived invite must NOT seal org escrow")
        val recovery = r.request.memberRecovery
        assertNotNull(recovery, "member-recovery is mandatory even when escrow is waived")
        val uvk = MemberRecovery.openUvk(crypto, r.recoverySecret, recovery.recoveryWrappedUvk, r.request.userId)
        assertTrue(uvk.contentEquals(r.account.uvkCopyForPlatformWrap()))
    }

    /** Build the verify-response the server would return, from an enroll request. */
    private fun verifyResponseFor(r: EnrollResult) = RecoveryVerifyResponse(
        userId = r.request.userId,
        recoveryTicket = "opaque-ticket",
        recoveryWrappedUvk = r.request.memberRecovery!!.recoveryWrappedUvk,
        encryptedIdentitySeed = r.request.encryptedIdentitySeed,
        identityPub = r.request.identityPub,
    )

    @Test
    fun recoverReWrapsTheSameUvkUnderTheNewPassword() {
        val r = Account.enroll("inv", "c@x.com", "c", password, kdf, null, null, "dev", crypto)
        val originalUvk = r.account.uvkCopyForPlatformWrap()

        val commit = Account.recover(r.recoverySecret, verifyResponseFor(r), "a brand new strong passphrase", kdf, crypto)
        assertEquals("opaque-ticket", commit.recoveryTicket, "ticket carried through to the commit")

        // The commit re-wraps the SAME UVK under the new password material (invariant, §F.8).
        val mk = Keys.masterKey(crypto, "a brand new strong passphrase", Bytes.fromB64(commit.newKdfSalt), commit.newKdfParams)
        val recoveredUvk = Envelope.openB64(crypto, Keys.wrapKey(crypto, mk), commit.newWrappedUvk, Ad.uvk(r.request.userId))
        assertTrue(recoveredUvk.contentEquals(originalUvk), "recover must NOT regenerate the UVK")
        // The new authKey is the login proof derived from the same MK.
        assertEquals(Bytes.toB64(Keys.authKey(crypto, mk)), commit.newAuthKey)
    }

    @Test
    fun recoverFiresIdentityPubkeyHardFail() {
        val r = Account.enroll("inv", "d@x.com", "d", password, kdf, null, null, "dev", crypto)
        // A hostile server substitutes an identity pubkey it controls; the sealed seed is unchanged.
        val attacker = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val tampered = verifyResponseFor(r).copy(identityPub = Bytes.toB64(attacker.publicKey))
        val ex = assertFailsWith<CryptoException> {
            Account.recover(r.recoverySecret, tampered, "another strong passphrase", kdf, crypto)
        }
        assertTrue(ex.message?.contains("identity key mismatch") == true, "the §5 hard-fail must fire during recover()")
    }

    @Test
    fun recoverFailsClosedOnWrongSecret() {
        val r = Account.enroll("inv", "e@x.com", "e", password, kdf, null, null, "dev", crypto)
        assertFailsWith<CryptoException>("wrong recovery secret must fail closed before commit") {
            Account.recover(crypto.randomBytes(32), verifyResponseFor(r), "yet another passphrase", kdf, crypto)
        }
    }

    @Test
    fun setupMemberRecoveryProducesUsablePieceOverLiveUvk() {
        // Simulate a migration: an unlocked account (e.g. legacy jacob) mints a fresh piece.
        val r = Account.enroll("inv", "f@x.com", "f", password, kdf, null, null, "dev", crypto)
        val currentAuthKey = Account.deriveAuthKey(password, r.request.kdfSalt, kdf, crypto)

        val setup = r.account.setupMemberRecovery(currentAuthKey)
        assertEquals(currentAuthKey, setup.request.currentAuthKey, "currentAuthKey carried for server reauth")
        val piece = setup.request.memberRecovery
        val uvk = MemberRecovery.openUvk(crypto, setup.recoverySecret, piece.recoveryWrappedUvk, r.request.userId)
        assertTrue(uvk.contentEquals(r.account.uvkCopyForPlatformWrap()), "the setup piece wraps the live UVK")
    }
}
