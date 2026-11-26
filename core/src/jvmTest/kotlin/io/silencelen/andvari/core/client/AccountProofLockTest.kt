package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The old account line's password proof compares with the UVK inside its guarded use, after
 * its slow step, so a lock (another thread's wipe) during the argon2 pass answers "locked" (`AccountWipedException`),
 * never a verdict on the password. Before, a right password read as wrong, and a
 * password a hostile server chose (serving a wrap of 32 zero bytes under it) read as right.
 */
class AccountProofLockTest {
    private val base = createCryptoProvider()
    private val recovery = base.boxKeypairFromSeed(base.randomBytes(32))

    /** The provider, with a step that runs on ANOTHER thread, and is waited for, right after the argon2 pass. */
    private class DuringKdf(private val inner: CryptoProvider) : CryptoProvider by inner {
        @Volatile var then: (() -> Unit)? = null

        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            val out = inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
            then?.let { step ->
                then = null
                val other = Thread { step() }
                other.start()
                other.join()
            }
            return out
        }
    }

    private class Open(val account: Account, val keys: AccountKeys, val crypto: DuringKdf)

    private fun open(): Open {
        val crypto = DuringKdf(base)
        val e = Account.enroll("inv", "w@example.com", "w", RIGHT, KdfParams.DEFAULT, recovery.publicKey, Escrow.fingerprint(base, recovery.publicKey), "dev", crypto)
        val keys = AccountKeys(
            kdfSalt = e.request.kdfSalt, kdfParams = e.request.kdfParams, wrappedUvk = e.request.wrappedUvk,
            encryptedIdentitySeed = e.request.encryptedIdentitySeed, identityPub = e.request.identityPub,
            escrowFingerprint = e.request.escrow!!.fingerprint,
        )
        return Open(e.account, keys, crypto)
    }

    @Test fun aRightPasswordIsNeverReadAsWrongAcrossALock() {
        val o = open()
        assertTrue(o.account.verifyPassword(RIGHT, o.keys), "while open, the right password proves")
        o.crypto.then = { o.account.wipe() }
        assertFailsWith<AccountWipedException>("a lock during the KDF is a lock") { o.account.verifyPassword(RIGHT, o.keys) }

        val p = open()
        p.crypto.then = { p.account.wipe() }
        assertFailsWith<AccountWipedException>("and for the re-authentication's proof") { p.account.reauthAuthKey(RIGHT, p.keys) }
    }

    /**
     * A hostile server serves, under the session's salt, a wrap of 32 zero bytes under a password of its choosing: what
     * the wiped UVK looks like. The wrap is built here at the provider on purpose, so the tripwire's line for it is an
     * expected one (`ZeroKeyTripwire.EXPECTED`).
     */
    @Test fun aChosenPasswordIsNeverReadAsRightAcrossALock() {
        val o = open()
        val mk = Keys.masterKey(base, CHOSEN, Bytes.fromB64(o.keys.kdfSalt), o.keys.kdfParams)
        val wrapKey = Keys.wrapKey(base, mk)
        mk.fill(0)
        val header = Envelope.seal(base, wrapKey, byteArrayOf(1), Ad.uvk(o.account.userId)).copyOfRange(0, 2)
        val nonce = base.randomBytes(24)
        val zeros = header + nonce + base.aeadEncrypt(wrapKey, nonce, ByteArray(32), Ad.uvk(o.account.userId))
        wrapKey.fill(0)
        val forged = o.keys.copy(wrappedUvk = Bytes.toB64(zeros))
        assertFalse(o.account.verifyPassword(CHOSEN, forged), "while open, the chosen password proves nothing")
        o.crypto.then = { o.account.wipe() }
        assertFailsWith<AccountWipedException>("a lock during the KDF is never a verdict") { o.account.verifyPassword(CHOSEN, forged) }
    }

    private companion object {
        const val RIGHT = "correct horse Battery 9 staple"
        const val CHOSEN = "the server's own choice"
    }
}
