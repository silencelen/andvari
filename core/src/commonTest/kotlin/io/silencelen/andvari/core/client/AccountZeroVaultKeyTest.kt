package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.PersonalWrap
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The old account line takes no key of 32 zero bytes out of anything (spec 01, "Keys in memory and the lock", rule 4):
 * not from a v1 grant seal (which the server can make), not from a vault key wrapped under the account's own key, and
 * not from the personal wrap. Each is refused where the key is taken out, as what it is: a grant row that carries no
 * key, or a personal wrap that does not open. Before, each was held, and every later open under it was refused by the
 * key floor as though the account were locked. A key with a single non-zero byte is still held on every path.
 */
class AccountZeroVaultKeyTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "made-up test password 23"
    private val vaultId = "66666666-6666-4666-8666-666666666666"

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        val keys = AccountKeys(
            kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
            encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
            escrowFingerprint = reg.escrow!!.fingerprint,
        )
        return Enrolled(reg, account, keys)
    }

    private val nearZero = ByteArray(32).also { it[31] = 1 }

    /** The test plays the hostile server: a v1 grant seal to the member whose `vk` is 32 zero bytes. */
    private fun v1SealOfZeros(memberPub: ByteArray): String =
        Bytes.toB64(SharedGrant.seal(crypto, memberPub, vaultId, ByteArray(32)))

    /**
     * The test plays a faulty writer that holds the account's key: an envelope under [uvk] whose plaintext is 32 zero
     * bytes, built at the provider because the shared envelope refuses to wrap a wiped key.
     */
    private fun wrapOfZeros(uvk: ByteArray, ad: ByteArray): String {
        val nonce = crypto.randomBytes(Envelope.NONCE_BYTES)
        val ct = crypto.aeadEncrypt(uvk, nonce, ByteArray(32), ad)
        return Bytes.toB64(byteArrayOf(Envelope.VERSION, Envelope.ALG_XCHACHA20POLY1305_IETF) + nonce + ct)
    }

    private fun memberRow(userId: String, sealed: String) =
        WireGrant(vaultId = vaultId, userId = userId, role = "writer", wrappedVk = "", rev = 2, sealedVk = sealed)

    private fun ownRow(userId: String, wrapped: String) =
        WireGrant(vaultId = vaultId, userId = userId, role = "owner", wrappedVk = wrapped, rev = 2)

    // Building the hostile input puts an all-zero key through the provider (a sealed box of a frame holding one, a wrap
    // of one), which the zero-key tripwire counts: [v1SealOfZeros] and [wrapOfZeros] are the two places it lists as
    // expected for this class. The account's own opens happen outside them and record nothing. Each of the three tests
    // fails on the code before the check (the zero key was held).

    @Test fun aV1SealCarryingAZeroVaultKeyIsNeverHeld() {
        val e = enroll("zero-seal@example.com")
        val row = memberRow(e.reg.userId, v1SealOfZeros(e.account.identityPub))
        assertFailsWith<CryptoException> { e.account.addGrant(row) }
        assertFalse(e.account.hasVault(vaultId))
        assertNull(e.account.keySource(vaultId))
        assertNull(e.account.peekVaultName(row, "x"), "the holding area's peek takes no key either")
    }

    @Test fun aVaultKeyOfZerosWrappedUnderTheAccountsKeyIsNeverHeld() {
        val e = enroll("zero-wrap@example.com")
        val uvk = e.account.uvkCopyForPlatformWrap()
        val row = ownRow(e.reg.userId, wrapOfZeros(uvk, Ad.vk(vaultId, e.reg.userId)))
        uvk.fill(0)
        assertFailsWith<CryptoException> { e.account.addGrant(row) }
        assertFalse(e.account.hasVault(vaultId))
        assertNull(e.account.keySource(vaultId))
    }

    @Test fun aPersonalWrapOfAZeroVaultKeyDoesNotOpen() {
        val e = enroll("zero-personal@example.com")
        val uvk = e.account.uvkCopyForPlatformWrap()
        val wrap = PersonalWrap(vaultId, wrapOfZeros(uvk, Ad.vkPersonal(vaultId, e.reg.userId)))
        val opened = Account.unlockWithUvk(e.reg.userId, uvk, e.keys.copy(personalWrap = wrap), crypto)
        assertEquals(Account.PersonalStatus.UNREADABLE, opened.personalStatus)
        assertEquals("", opened.personalVaultId)
        assertFalse(opened.hasVault(vaultId))
        opened.wipe()
    }

    @Test fun aKeyWithOneNonZeroByteIsStillHeldOnEveryPath() {
        val a = enroll("near-zero-seal@example.com")
        a.account.addGrant(memberRow(a.reg.userId, Bytes.toB64(SharedGrant.seal(crypto, a.account.identityPub, vaultId, nearZero))))
        assertTrue(a.account.hasVault(vaultId))
        assertEquals(Account.KeySource.LEGACY_SEAL, a.account.keySource(vaultId))

        val b = enroll("near-zero-wrap@example.com")
        val uvkB = b.account.uvkCopyForPlatformWrap()
        b.account.addGrant(ownRow(b.reg.userId, Envelope.sealB64(crypto, uvkB, nearZero, Ad.vk(vaultId, b.reg.userId))))
        uvkB.fill(0)
        assertTrue(b.account.hasVault(vaultId))
        assertEquals(Account.KeySource.UVK_WRAP, b.account.keySource(vaultId))

        val c = enroll("near-zero-personal@example.com")
        val uvkC = c.account.uvkCopyForPlatformWrap()
        val wrap = PersonalWrap(vaultId, Envelope.sealB64(crypto, uvkC, nearZero, Ad.vkPersonal(vaultId, c.reg.userId)))
        val opened = Account.unlockWithUvk(c.reg.userId, uvkC, c.keys.copy(personalWrap = wrap), crypto)
        assertEquals(Account.PersonalStatus.CONFIRMED, opened.personalStatus)
        assertEquals(vaultId, opened.personalVaultId)
        assertTrue(opened.hasVault(vaultId))
        opened.wipe()
    }
}
