package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
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

    /**
     * Audit H67 — the structural/secret split on the password path. A `wrappedUvk` the server
     * hands back that is not a well-formed envelope (undecodable base64url, too short, an
     * envelope version or AEAD alg this build does not know) is refused from its PUBLIC header
     * alone, before the wrap key is applied — so no password could ever have made it pass, and
     * calling it "wrong master password" (which this code did until H67) sends a member with a
     * half-restored account row to reset a password that works and then to spend their recovery
     * secret. Each refusal must raise the distinct, terminal [VaultKeyDamagedException]; a
     * genuinely wrong password — the ONE ambiguous outcome, an AEAD tag failure — must still
     * raise the plain "wrong master password" [CryptoException]. Reverting either half fails here.
     */
    @Test
    fun structurallyDamagedWrappedUvkIsNotAWrongPassword() {
        val e = enroll("damaged@example.com")
        val good = Bytes.fromB64(e.keys.wrappedUvk)

        // 1. not base64url at all (a truncated/garbled DB column).
        assertFailsWith<VaultKeyDamagedException> {
            Account.unlock(e.reg.userId, password, e.keys.copy(wrappedUvk = "!!! not base64 !!!"), crypto)
        }
        // 2. too short to even be an envelope.
        assertFailsWith<VaultKeyDamagedException> {
            Account.unlock(e.reg.userId, password, e.keys.copy(wrappedUvk = Bytes.toB64(good.copyOf(8))), crypto)
        }
        // 3. an envelope version this build does not know (a newer server, an older client).
        val futureVersion = good.copyOf().also { it[0] = 0x02 }
        assertFailsWith<VaultKeyDamagedException> {
            Account.unlock(e.reg.userId, password, e.keys.copy(wrappedUvk = Bytes.toB64(futureVersion)), crypto)
        }
        // 4. an AEAD alg this build does not know.
        val futureAlg = good.copyOf().also { it[1] = 0x02 }
        assertFailsWith<VaultKeyDamagedException> {
            Account.unlock(e.reg.userId, password, e.keys.copy(wrappedUvk = Bytes.toB64(futureAlg)), crypto)
        }

        // …and the split's other half: a WRONG PASSWORD against an intact blob still fails the
        // AEAD tag and still says so. (VaultKeyDamagedException is not a CryptoException, so this
        // assertion also proves the two verdicts can never be confused by type.)
        val ex = assertFailsWith<CryptoException> {
            Account.unlock(e.reg.userId, "not the password", e.keys, crypto)
        }
        assertEquals("wrong master password", ex.message)

        // The honest, terminal sentence — not the credentials one — on both native ladders.
        val damaged = assertFailsWith<VaultKeyDamagedException> {
            Account.unlock(e.reg.userId, password, e.keys.copy(wrappedUvk = Bytes.toB64(futureVersion)), crypto)
        }
        assertEquals(HouseholdCopy.ACCOUNT_KEYS_DAMAGED, HouseholdCopy.forSignInError(damaged))
        assertEquals(HouseholdCopy.ACCOUNT_KEYS_DAMAGED, HouseholdCopy.forUnlockError(damaged))
        assertNotEquals(HouseholdCopy.WRONG_EMAIL_OR_PASSWORD, HouseholdCopy.forSignInError(damaged))
        assertNotEquals(HouseholdCopy.WRONG_MASTER_PASSWORD, HouseholdCopy.forUnlockError(damaged))
    }

    /**
     * R38 — H67's missing leg: the SIBLING account-key blob. `encryptedIdentitySeed` sits in the
     * same account row as `wrappedUvk` and is damaged by the same events (a partial DB restore, a
     * newer server serving an envelope version this build does not implement), but its open in
     * the shared tail was left un-caught — so on the PASSWORD path a structurally broken seed
     * collapsed into "Wrong master password" one line after the fix above stopped saying exactly
     * that, about the same damaged row.
     *
     * The quick-unlock (UVK) path keeps its "validation by consequence" signal, and that is the
     * reason the gate is safe in the shared tail: a wrong or stale UVK can only ever fail the
     * AEAD TAG, never the public header, so it still raises the plain CryptoException the callers
     * wipe the quick-unlock blob on. Asserted here, in both directions.
     */
    @Test
    fun structurallyDamagedIdentitySeedIsNotAWrongPassword() {
        val e = enroll("damagedseed@example.com")
        val good = Bytes.fromB64(e.keys.encryptedIdentitySeed)
        val futureVersion = good.copyOf().also { it[0] = 0x02 }

        for (broken in listOf(
            "!!! not base64 !!!",
            Bytes.toB64(good.copyOf(8)),
            Bytes.toB64(futureVersion),
            Bytes.toB64(good.copyOf().also { it[1] = 0x02 }),
        )) {
            assertFailsWith<VaultKeyDamagedException>("seed blob $broken must be the damaged terminal") {
                Account.unlock(e.reg.userId, password, e.keys.copy(encryptedIdentitySeed = broken), crypto)
            }
        }

        // Same on the quick-unlock path — the tail is shared, so the verdict must be too.
        assertFailsWith<VaultKeyDamagedException> {
            Account.unlockWithUvk(
                e.reg.userId,
                e.account.uvkCopyForPlatformWrap(),
                e.keys.copy(encryptedIdentitySeed = Bytes.toB64(futureVersion)),
                crypto,
            )
        }

        // …and the signal the UVK path relies on is UNCHANGED: a wrong UVK against an INTACT seed
        // still fails the AEAD tag as a plain CryptoException (never the damaged terminal), which
        // is what tells the caller to wipe the quick-unlock blob rather than declare the account
        // unreadable.
        // VaultKeyDamagedException is NOT a CryptoException, so assertFailsWith<CryptoException>
        // alone proves the verdict is the bad-secret one and not the damaged terminal — the two
        // types are disjoint by design, which is the property that makes them unconfusable.
        val wrongUvk = ByteArray(32) { 0x11 }
        assertFailsWith<CryptoException> { Account.unlockWithUvk(e.reg.userId, wrongUvk, e.keys, crypto) }

        val damagedSeed = assertFailsWith<VaultKeyDamagedException> {
            Account.unlock(e.reg.userId, password, e.keys.copy(encryptedIdentitySeed = Bytes.toB64(futureVersion)), crypto)
        }
        assertEquals(HouseholdCopy.ACCOUNT_KEYS_DAMAGED, HouseholdCopy.forSignInError(damagedSeed))
        assertEquals(HouseholdCopy.ACCOUNT_KEYS_DAMAGED, HouseholdCopy.forUnlockError(damagedSeed))
    }

    /**
     * Audit F32: [Account.addGrant]'s two branches disagreed about what a vault key is.
     * `SharedGrant.open` has always asserted 32 bytes; the wrappedVk branch installed whatever
     * length the envelope produced, so a wrong-length VK entered the key map and only surfaced
     * later, at the next envelope operation, as an IllegalArgumentException from deep inside the
     * crypto provider — a different exception CLASS for the same broken grant depending on which
     * branch delivered it, which SyncEngine's runCatching paths then classify differently. Both
     * branches now refuse at the door, as a [CryptoException].
     */
    @Test
    fun addGrantRefusesAWrongLengthWrappedVaultKey() {
        val e = enroll("grantlen@example.com")
        val uvk = e.account.uvkCopyForPlatformWrap()
        val vaultId = "66666666-6666-4666-8666-666666666666"
        val shortVk = Envelope.sealB64(crypto, uvk, ByteArray(16), Ad.vk(vaultId, e.reg.userId))
        assertFailsWith<CryptoException> {
            e.account.addGrant(WireGrant(vaultId = vaultId, userId = e.reg.userId, role = "owner", wrappedVk = shortVk, rev = 2))
        }
        // A well-formed grant on the same branch is unaffected.
        val goodVk = Envelope.sealB64(crypto, uvk, crypto.randomBytes(32), Ad.vk(vaultId, e.reg.userId))
        e.account.addGrant(WireGrant(vaultId = vaultId, userId = e.reg.userId, role = "owner", wrappedVk = goodVk, rev = 3))
        assertTrue(e.account.hasVault(vaultId))
    }
}
