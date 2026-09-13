package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit H80: MK, authKey, wrapKey and the identity seed are dead the moment their consumers
 * return, and [Account] now `fill(0)`s them (spec 01 §2 "MK never leaves the KDF step"; the
 * discipline spec 07 §2.3 already mandates for MKx/exportKey on the backup path). Zeroization
 * of a LOCAL is invisible from outside — so this test records the LIVE array references as
 * they pass through the [CryptoProvider] (the MK is `argon2id`'s own output array, the wrapKey
 * is the `key` handed to the UVK-envelope seal/open, the identity seed is `boxKeypairFromSeed`'s
 * input, the recovered UVK is the recovery-envelope open's output) plus a snapshot of their
 * bytes at that moment, and asserts afterwards that the live array is all zeros while the
 * snapshot proves it once was not. The UVK the returned [Account] keeps for the session is
 * asserted NOT wiped, so the wipe is proven targeted rather than blanket.
 */
class AccountZeroizationTest {
    private val real = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id
    private val password = "correct horse battery staple"

    private class Seen(val live: ByteArray, val at: ByteArray)

    /** Delegates every primitive to the real provider; captures references, never copies. */
    private class Recording(private val d: CryptoProvider) : CryptoProvider by d {
        val argon = ArrayList<Seen>()                              // MK outputs
        val seeds = ArrayList<Seen>()                              // identity seeds (keypair input)
        val aeadKeys = ArrayList<Pair<ByteArray, Seen>>()          // (ad, key) per seal/open
        val opened = ArrayList<Pair<ByteArray, Seen>>()            // (ad, plaintext) per open

        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray =
            d.argon2id(password, salt, outLen, opsLimit, memLimitBytes).also { argon += Seen(it, it.copyOf()) }

        override fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes =
            d.boxKeypairFromSeed(seed).also { seeds += Seen(seed, seed.copyOf()) }

        override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray {
            aeadKeys += ad.copyOf() to Seen(key, key.copyOf())
            return d.aeadEncrypt(key, nonce, plaintext, ad)
        }

        override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray {
            aeadKeys += ad.copyOf() to Seen(key, key.copyOf())
            return d.aeadDecrypt(key, nonce, ciphertext, ad).also { opened += ad.copyOf() to Seen(it, it.copyOf()) }
        }

        fun keyFor(ad: ByteArray): Seen = aeadKeys.single { it.first.contentEquals(ad) }.second
        fun openedFor(ad: ByteArray): Seen = opened.single { it.first.contentEquals(ad) }.second
    }

    private fun assertWiped(s: Seen, what: String) {
        assertTrue(s.at.any { it != 0.toByte() }, "$what was already all-zero when captured — nothing to prove")
        assertTrue(s.live.all { it == 0.toByte() }, "$what was not zeroed after use")
    }

    private fun assertKept(s: Seen, what: String) {
        assertTrue(s.live.contentEquals(s.at), "$what must survive — the session owns it")
        assertFalse(s.live.all { it == 0.toByte() }, "$what is unexpectedly zero")
    }

    private fun keysOf(r: EnrollResult) = AccountKeys(
        kdfSalt = r.request.kdfSalt,
        kdfParams = r.request.kdfParams,
        wrappedUvk = r.request.wrappedUvk,
        encryptedIdentitySeed = r.request.encryptedIdentitySeed,
        identityPub = r.request.identityPub,
        escrowFingerprint = "",
    )

    @Test
    fun enroll_wipesMkWrapKeyAndIdentitySeed_keepsTheUvk() {
        val rec = Recording(real)
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", rec)
        val userId = r.request.userId

        assertEquals(1, rec.argon.size, "enroll derives exactly one MK")
        assertWiped(rec.argon.single(), "MK")
        assertWiped(rec.keyFor(Ad.uvk(userId)), "wrapKey (the UVK-envelope key)")
        assertWiped(rec.seeds.single(), "identity seed")
        // The UVK is the key that sealed the identity seed — the Account owns it; NOT wiped.
        assertKept(rec.keyFor(Ad.idkey(userId)), "UVK")
    }

    @Test
    fun unlock_wipesMkWrapKeyAndIdentitySeed_keepsTheUvk() {
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", real)
        val rec = Recording(real)
        Account.unlock(r.request.userId, password, keysOf(r), rec)

        assertEquals(1, rec.argon.size, "unlock derives exactly one MK")
        assertWiped(rec.argon.single(), "MK")
        assertWiped(rec.keyFor(Ad.uvk(r.request.userId)), "wrapKey")
        assertWiped(rec.seeds.single(), "identity seed")
        // The UVK came out of the wrappedUvk open and now belongs to the Account — kept.
        assertKept(rec.openedFor(Ad.uvk(r.request.userId)), "UVK")
    }

    @Test
    fun unlock_wrongPassword_stillWipesMkAndWrapKey() {
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", real)
        val rec = Recording(real)
        runCatching { Account.unlock(r.request.userId, "not the password", keysOf(r), rec) }
            .onSuccess { throw AssertionError("wrong password must not unlock") }
        assertWiped(rec.argon.single(), "MK (failed unlock)")
        assertWiped(rec.keyFor(Ad.uvk(r.request.userId)), "wrapKey (failed unlock)")
    }

    @Test
    fun deriveAuthKey_wipesTheMk() {
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", real)
        val rec = Recording(real)
        val b64 = Account.deriveAuthKey(password, r.request.kdfSalt, r.request.kdfParams, rec)
        assertEquals(r.request.authKey, b64) // the encoded credential is intact…
        assertWiped(rec.argon.single(), "MK") // …and the MK that produced it is gone.
    }

    @Test
    fun recover_wipesNewMkNewWrapKeyIdentitySeedAndTheRecoveredUvk() {
        val r = Account.enroll("inv", "a@x.com", "a", password, kdf, null, null, "dev", real)
        val userId = r.request.userId
        val verify = RecoveryVerifyResponse(
            userId = userId,
            recoveryTicket = "opaque-ticket",
            recoveryWrappedUvk = r.request.memberRecovery!!.recoveryWrappedUvk,
            encryptedIdentitySeed = r.request.encryptedIdentitySeed,
            identityPub = r.request.identityPub,
        )
        val rec = Recording(real)
        val commit = Account.recover(r.recoverySecret, verify, "a brand new master password", kdf, rec)
        assertTrue(commit.newWrappedUvk.isNotEmpty()) // the body is built before anything is wiped

        assertEquals(1, rec.argon.size, "recover derives exactly one (new) MK")
        assertWiped(rec.argon.single(), "new MK")
        assertWiped(rec.keyFor(Ad.uvk(userId)), "new wrapKey")
        assertWiped(rec.seeds.single(), "identity seed (hard-fail probe)")
        // recover() returns a commit body, not a session: the recovered UVK is dead too.
        assertWiped(rec.openedFor(Ad.recovery(userId)), "recovered UVK")
    }
}
