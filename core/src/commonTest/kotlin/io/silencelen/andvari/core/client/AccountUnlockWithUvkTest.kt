package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Account.unlockWithUvk (spec 01 §8.1, design 2026-07-10 §1) — the quick-unlock core path.
 * Proves the shared tail with [unlock]: same seed-derived identityPub hard-fail, same vault-key
 * capability, and validation-by-consequence on a wrong/stale UVK (a plain CryptoException, never
 * "wrong master password", never the identity-mismatch security fault).
 */
class AccountUnlockWithUvkTest {
    private val crypto = createCryptoProvider()
    // Minimum-cost argon2id — unlockWithUvk never derives MK, and unlock() only needs to round-
    // trip its own enrollment, so cheap KDF params keep the gate fast.
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String = "quick@example.com"): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        val keys = AccountKeys(
            kdfSalt = reg.kdfSalt,
            kdfParams = reg.kdfParams,
            wrappedUvk = reg.wrappedUvk,
            encryptedIdentitySeed = reg.encryptedIdentitySeed,
            identityPub = reg.identityPub,
            escrowFingerprint = reg.escrow!!.fingerprint,
        )
        return Enrolled(reg, account, keys)
    }

    /** The personal-vault owner grant the sync path would deliver — wrappedVk under the UVK. */
    private fun personalGrant(e: Enrolled) = WireGrant(
        vaultId = e.reg.personalVault.vaultId,
        userId = e.reg.userId,
        role = "owner",
        wrappedVk = e.reg.personalVault.wrappedVk,
        rev = 1,
    )

    @Test
    fun malformedServerIdentityPubIsTampering() {
        // spec 01 §5 (web account.ts parity): garbage where the identity pubkey belongs IS the
        // tampering signal — a malformed identityPub must raise the "possible server compromise"
        // CryptoException, never a bare base64 decode error the caller can't distinguish.
        val e = enroll()
        val tampered = e.keys.copy(identityPub = "!!!not-valid-base64!!!")
        val ex = assertFailsWith<CryptoException> { Account.unlock(e.reg.userId, password, tampered, crypto) }
        assertTrue(ex.message!!.contains("possible server compromise"))
    }

    @Test
    fun happyPathUnlocksAndOpensPersonalVault() {
        val e = enroll()
        val uvk = e.account.uvkCopyForPlatformWrap()
        val unlocked = Account.unlockWithUvk(e.reg.userId, uvk, e.keys, crypto)

        assertEquals(e.reg.userId, unlocked.userId)
        assertTrue(unlocked.identityPub.contentEquals(e.account.identityPub), "seed-derived identityPub matches enrollment")

        // Vault keys hydrate through the SAME addGrant path as unlock(): the personal wrappedVk
        // opens under the UVK we now hold, and the account can seal/open items in it.
        unlocked.addGrant(personalGrant(e))
        unlocked.setPersonalVault(e.reg.personalVault.vaultId)
        val doc = ItemDoc(type = "login", name = "secret", login = LoginData(username = "u", password = "p"))
        val upload = unlocked.encryptItem(e.reg.personalVault.vaultId, "item-1", doc)
        val roundTrip = unlocked.decryptItem(
            WireItem("item-1", e.reg.personalVault.vaultId, 1, 0, 0, false, false, upload.formatVersion, upload.attachmentIds, upload.blob),
        )
        assertEquals(doc, roundTrip)
    }

    @Test
    fun unlockAndUnlockWithUvkProduceEquivalentAccounts() {
        val e = enroll()
        val viaPassword = Account.unlock(e.reg.userId, password, e.keys, crypto)
        val viaUvk = Account.unlockWithUvk(e.reg.userId, e.account.uvkCopyForPlatformWrap(), e.keys, crypto)

        assertEquals(viaPassword.userId, viaUvk.userId)
        assertTrue(viaPassword.identityPub.contentEquals(viaUvk.identityPub), "same identity pubkey on both paths")

        // Same personal vault key behaviour: an item sealed by the password-unlocked account
        // decrypts under the UVK-unlocked account, so both hold the identical VK.
        viaPassword.addGrant(personalGrant(e))
        viaUvk.addGrant(personalGrant(e))
        val doc = ItemDoc(type = "note", name = "shared", notes = "same VK both ways")
        val upload = viaPassword.encryptItem(e.reg.personalVault.vaultId, "item-x", doc)
        val decoded = viaUvk.decryptItem(
            WireItem("item-x", e.reg.personalVault.vaultId, 1, 0, 0, false, false, upload.formatVersion, upload.attachmentIds, upload.blob),
        )
        assertEquals(doc, decoded)
    }

    @Test
    fun wrongUvkFailsTheIdentitySeedOpen() {
        val e = enroll()
        val ex = assertFailsWith<CryptoException> {
            Account.unlockWithUvk(e.reg.userId, crypto.randomBytes(32), e.keys, crypto)
        }
        // Validation by consequence: a plain AEAD-open failure, NOT the softened password
        // message and NOT the identity-mismatch security fault.
        assertNotEquals("wrong master password", ex.message)
        assertTrue(ex.message?.contains("identity key mismatch") != true, "wrong UVK is a bad secret, not a pubkey-substitution fault")
    }

    @Test
    fun emptyAndTruncatedUvkFail() {
        val e = enroll()
        assertFailsWith<CryptoException> { Account.unlockWithUvk(e.reg.userId, ByteArray(0), e.keys, crypto) }
        val truncated = e.account.uvkCopyForPlatformWrap().copyOf(16)
        assertFailsWith<CryptoException> { Account.unlockWithUvk(e.reg.userId, truncated, e.keys, crypto) }
    }

    @Test
    fun tamperedIdentityPubHardFails() {
        val e = enroll()
        // A hostile server substitutes an identity pubkey it controls while the sealed seed (and
        // thus the real derived pubkey) is unchanged.
        val attacker = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val tampered = AccountKeys(
            kdfSalt = e.keys.kdfSalt,
            kdfParams = e.keys.kdfParams,
            wrappedUvk = e.keys.wrappedUvk,
            encryptedIdentitySeed = e.keys.encryptedIdentitySeed,
            identityPub = Bytes.toB64(attacker.publicKey),
            escrowFingerprint = e.keys.escrowFingerprint,
        )
        val ex = assertFailsWith<CryptoException> {
            Account.unlockWithUvk(e.reg.userId, e.account.uvkCopyForPlatformWrap(), tampered, crypto)
        }
        // The §5 hard-fail — the SAME message the password path raises, distinct from a wrong-UVK
        // AEAD failure and never softened to "wrong master password".
        assertTrue(ex.message?.contains("identity key mismatch") == true, "identity-mismatch security fault")
        assertNotEquals("wrong master password", ex.message)
    }

    @Test
    fun uvkCopyForPlatformWrapReturnsIndependentCopy() {
        val e = enroll()
        val a = e.account.uvkCopyForPlatformWrap()
        val b = e.account.uvkCopyForPlatformWrap()
        assertEquals(32, a.size)
        assertTrue(a.contentEquals(b), "same UVK value each call")
        // Zeroing the returned copy must not corrupt the live session UVK: a fresh copy still
        // unlocks, proving the accessor handed out a COPY, not the internal reference.
        a.fill(0)
        val unlocked = Account.unlockWithUvk(e.reg.userId, e.account.uvkCopyForPlatformWrap(), e.keys, crypto)
        assertEquals(e.reg.userId, unlocked.userId)
    }
}
