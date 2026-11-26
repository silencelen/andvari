package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The last line of defence of the shared crypto path: what a lock leaves in a held key array is zeros,
 * and nothing is sealed, wrapped, signed, derived or opened with it. The refusal is [KeysGoneException], never a
 * [CryptoException] (which its callers read as "wrong password" or "not ours").
 */
class KeyFloorTest {
    private val crypto = createCryptoProvider()
    private val zeros = ByteArray(32)
    private val key = ByteArray(32) { (it + 1).toByte() }

    @Test fun nothingIsSealedOrOpenedUnderAKeyOfZeros() {
        assertFailsWith<KeysGoneException> { Envelope.seal(crypto, zeros, "item".encodeToByteArray(), byteArrayOf(1)) }
        assertFailsWith<KeysGoneException> { Envelope.sealB64(crypto, zeros, "item".encodeToByteArray(), byteArrayOf(1)) }
        val sealed = Envelope.seal(crypto, key, "item".encodeToByteArray(), byteArrayOf(1))
        assertFailsWith<KeysGoneException> { Envelope.open(crypto, zeros, sealed, byteArrayOf(1)) }
        // A wrong (non-zero) key is still the AEAD's refusal.
        assertFailsWith<CryptoException> { Envelope.open(crypto, ByteArray(32) { 9 }, sealed, byteArrayOf(1)) }
    }

    @Test fun noWipedKeyIsWrapped() {
        assertFailsWith<KeysGoneException> { Envelope.seal(crypto, key, ByteArray(32), byteArrayOf(1)) }
        assertFailsWith<KeysGoneException> { Envelope.seal(crypto, key, ByteArray(64), byteArrayOf(1)) }
        assertFailsWith<KeysGoneException> { MemberRecovery.generate(crypto, "u", ByteArray(32)) }
        assertFailsWith<KeysGoneException> { Escrow.sealUvkV1(crypto, crypto.boxKeypairFromSeed(key).publicKey, "u", ByteArray(32)) }
        // Zeros that are not a key's length are ordinary plaintext.
        Envelope.seal(crypto, key, ByteArray(31), byteArrayOf(1))
    }

    @Test fun nothingIsDerivedFromOrSignedWithAKeyOfZeros() {
        assertFailsWith<KeysGoneException> { Hkdf.sha256(crypto, zeros, ByteArray(0), "info".encodeToByteArray(), 32) }
        // HKDF's default salt (zeros) over a real key is RFC 5869 itself.
        Hkdf.sha256(crypto, key, ByteArray(0), "info".encodeToByteArray(), 32)
        val pair = crypto.signKeypairFromSeed(key)
        val fields = CardFields("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", 0, TrustGrammar.ZERO_HASH, "https://h.example", "Home", InstanceKind.PRIVATE,
            "99999999-9999-4999-8999-999999999999", Bytes.toB64(pair.publicKey), null, 1_794_744_000_000L)
        InstanceCard.sign(crypto, pair, fields)
        pair.privateKey.fill(0)
        assertFailsWith<KeysGoneException> { InstanceCard.sign(crypto, pair, fields) }
        assertFailsWith<KeysGoneException> { Attachments.encrypt(crypto, zeros, byteArrayOf(1)) }
    }

    /** Wiped device-link keys MAC nothing and verify nothing. */
    @Test fun wipedDeviceLinkKeysMacNothing() {
        val keys = io.silencelen.andvari.core.trust.DeviceLink.deriveKeys(crypto, key)
        io.silencelen.andvari.core.trust.DeviceLink.approveMac(crypto, keys, byteArrayOf(1, 2, 3))
        keys.wipe()
        assertFailsWith<KeysGoneException> { io.silencelen.andvari.core.trust.DeviceLink.approveMac(crypto, keys, byteArrayOf(1, 2, 3)) }
        assertFailsWith<KeysGoneException> { io.silencelen.andvari.core.trust.DeviceLink.pickupProof(crypto, keys, Bytes.toB64(key)) }
    }

    /** A grant of a wiped vault key is never signed. */
    @Test fun noWipedVaultKeyIsGranted() {
        val signer = crypto.signKeypairFromSeed(key)
        val fields = io.silencelen.andvari.core.trust.GrantFields(
            "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", Bytes.toB64(crypto.boxKeypairFromSeed(key).publicKey),
            "33333333-3333-4333-8333-333333333333", Bytes.toB64(ByteArray(16) { 4 }), 1_794_744_000_000L, ByteArray(32),
        )
        assertFailsWith<KeysGoneException> { io.silencelen.andvari.core.trust.VaultGrant.sign(crypto, signer, fields) }
    }

    /**
     * A phrase whose secret is all zeros is not a phrase, never "locked". The kit's own parse
     * still answers it (the normative vectors grade that row); the kit recovery refuses it as a bad kit
     * (`KitRecoveryTest`).
     */
    @Test fun aPhraseOfZerosIsNotAPhrase() {
        kotlin.test.assertNull(MemberRecovery.parseSecret(Bytes.toB64(ByteArray(32))))
        kotlin.test.assertNotNull(MemberRecovery.parseSecret(Bytes.toB64(key)))
    }

    @Test fun theRefusalIsALockNeverAWrongKey() {
        val e = assertFailsWith<KeysGoneException> { Envelope.seal(crypto, zeros, byteArrayOf(1), byteArrayOf(1)) }
        assertFalse((e as Throwable) is CryptoException)
        // The account's own refusal after a wipe is one of them, so one handler tells every lock apart.
        assertIs<KeysGoneException>(AccountWipedException())
        assertTrue(KeyFloor.allZero(ByteArray(64)) && !KeyFloor.allZero(ByteArray(0)) && !KeyFloor.allZero(byteArrayOf(0, 1)))
    }
}
