package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs

/**
 * The account genesis of design 2026-11-15 §5.2, with one verdict per check in §2.4's order (VR-13),
 * built from the design's rules. `accountgenesis.json` grades the same verifier once its vector
 * file lands.
 */
class AccountGenesisTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)
    private val personalVault = Ids.OTHER_VAULT

    private fun fields(userId: String = Ids.ALICE, key: String = alice.key, instanceId: String = Ids.INSTANCE, vault: String = personalVault) =
        GenesisFields(userId, key, instanceId, vault, Ids.T0)

    private fun verdict(
        frame: ByteArray,
        signPub: ByteArray = alice.sign.publicKey,
        identityPub: ByteArray = alice.box.publicKey,
        userId: String = Ids.ALICE,
        instanceId: String = Ids.INSTANCE,
        vault: String? = personalVault,
    ) = AccountGenesis.verify(crypto, frame, signPub, identityPub, userId, instanceId, vault).verdictOrNull()

    @Test
    fun aGenesisVerifiesForTheAccountItNames() {
        val frame = AccountGenesis.sign(crypto, alice.sign, fields())
        val ok = assertIs<Checked.Ok<VerifiedGenesis>>(
            AccountGenesis.verify(crypto, frame, alice.sign.publicKey, alice.box.publicKey, Ids.ALICE, Ids.INSTANCE, personalVault),
        ).value
        assertEquals(fields(), ok.fields)
        assertEquals(SignedFrame.hash(crypto, frame), ok.hash)
        // No personal wrap is served: that one check is skipped, the others stand.
        assertIs<Checked.Ok<VerifiedGenesis>>(AccountGenesis.verify(crypto, frame, alice.sign.publicKey, alice.box.publicKey, Ids.ALICE, Ids.INSTANCE, null))
        // The server's form, at registration, accepts the same genesis.
        assertIs<Checked.Ok<VerifiedGenesis>>(AccountGenesis.verifyAtRegistration(crypto, frame, alice.box.publicKey, Ids.ALICE, Ids.INSTANCE, personalVault))
    }

    /**
     * §2.4, the Signer binding row 0x05: a genesis VALIDLY signed under the negated Ed25519 key (−A, whose
     * X25519 image is the account's identity key) is refused by every client as `signer_not_pinned_key`,
     * and still passes the server's image binding (it registers, then no device of the account opens it).
     * The frame is the `valid` row of `accountgenesis.json` re-signed with the scalar L − s, built outside
     * andvari (no `CryptoProvider` can make it); the seed is that file's `account.seedB64`.
     */
    @Test
    fun aGenesisSignedUnderTheNegatedKey_isRefusedByEveryClient() {
        val seed = Bytes.fromB64("DRQbIikwNz5FTFNaYWhvdn2Ei5KZoKeutbzDytHY3-Y")
        val signPub = crypto.signKeypairFromSeed(seed).publicKey
        val identityPub = crypto.boxKeypairFromSeed(seed).publicKey
        val frame = Bytes.fromB64(NEGATED_KEY_GENESIS)
        val parts = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value
        // The frame's signer is not the account's key, yet maps to the same identity key, and its signature is valid.
        assertFalse(Bytes.ctEquals(parts.signerPub, signPub))
        assertContentEquals(identityPub, crypto.ed25519PkToCurve25519(parts.signerPub))
        assertIs<Checked.Ok<VerifiedGenesis>>(
            AccountGenesis.verifyAtRegistration(crypto, frame, identityPub, Ids.ALICE, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", null),
        )
        assertEquals(
            GenesisVerdict.SIGNER_NOT_PINNED_KEY,
            AccountGenesis.verify(crypto, frame, signPub, identityPub, Ids.ALICE, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", null).verdictOrNull(),
        )
    }

    @Test
    fun eachCheckHasItsVerdict_inOrder() {
        val frame = AccountGenesis.sign(crypto, alice.sign, fields())
        // The parse.
        assertEquals(GenesisVerdict.BAD_FRAME, verdict(ByteArray(3)))
        assertEquals(GenesisVerdict.UNKNOWN_FORMAT, verdict("{\"v\":2}".encodeToByteArray()))
        val statement = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value.statement.decodeToString()
        fun signedRaw(text: String) = SignedFrame.sign(crypto, alice.sign, TrustPurpose.ACCOUNT_GENESIS, text.encodeToByteArray())
        assertEquals(GenesisVerdict.NON_CANONICAL, verdict(signedRaw(statement.replace("\"v\":2", "\"v\":02"))))
        assertEquals(GenesisVerdict.BAD_STATEMENT, verdict(signedRaw(statement.replace("\"v\":2", "\"v\":1"))))
        // A card frame where a genesis is expected.
        assertEquals(GenesisVerdict.BAD_FRAME, verdict(SignedFrame.sign(crypto, alice.sign, TrustPurpose.RECOVERY_VETO, statement.encodeToByteArray())))

        // The helper is handed the seed-derived Ed25519 key: another account's key does not bind, nor the
        // account's own X25519 key in its place.
        assertEquals(GenesisVerdict.SIGNER_NOT_PINNED_KEY, verdict(frame, signPub = bob.sign.publicKey))
        assertEquals(GenesisVerdict.SIGNER_NOT_PINNED_KEY, verdict(frame, signPub = alice.box.publicKey))
        assertEquals(GenesisVerdict.SIGNER_NOT_PINNED_KEY, verdict(frame, signPub = ByteArray(31)))
        // The X25519 key is the identityKey comparison, not the signer's.
        assertEquals(GenesisVerdict.IDENTITY_MISMATCH, verdict(frame, identityPub = bob.box.publicKey))
        // The signature.
        val flipped = frame.copyOf().also { it[60] = (it[60].toInt() xor 4).toByte() }
        assertEquals(GenesisVerdict.BAD_SIGNATURE, verdict(flipped))

        // The fields, one verdict each. alice signs each of these herself, so only the field differs.
        assertEquals(GenesisVerdict.IDENTITY_MISMATCH, verdict(signedRaw(statement.replace(alice.key, bob.key))))
        assertEquals(GenesisVerdict.USER_MISMATCH, verdict(frame, userId = Ids.BOB))
        assertEquals(GenesisVerdict.INSTANCE_MISMATCH, verdict(frame, instanceId = Ids.OTHER_INSTANCE))
        assertEquals(GenesisVerdict.PERSONAL_VAULT_MISMATCH, verdict(frame, vault = Ids.VAULT))

        // Order: the signer before the fields, and the fields in the listed order.
        assertEquals(GenesisVerdict.SIGNER_NOT_PINNED_KEY, verdict(frame, signPub = bob.sign.publicKey, identityPub = bob.box.publicKey, userId = Ids.BOB, instanceId = Ids.OTHER_INSTANCE))
        assertEquals(GenesisVerdict.BAD_SIGNATURE, verdict(flipped, userId = Ids.BOB))
        assertEquals(GenesisVerdict.IDENTITY_MISMATCH, verdict(signedRaw(statement.replace(alice.key, bob.key)), userId = Ids.BOB))
        assertEquals(GenesisVerdict.USER_MISMATCH, verdict(frame, userId = Ids.BOB, instanceId = Ids.OTHER_INSTANCE, vault = Ids.VAULT))
        assertEquals(GenesisVerdict.INSTANCE_MISMATCH, verdict(frame, instanceId = Ids.OTHER_INSTANCE, vault = Ids.VAULT))
    }

    @Test
    fun sign_refusesAGenesisForAnotherKey() {
        // No client can sign a genesis that names a key it does not hold.
        assertFailsWith<IllegalArgumentException> { AccountGenesis.sign(crypto, bob.sign, fields()) }
        assertFailsWith<IllegalArgumentException> { AccountGenesis.sign(crypto, alice.sign, fields(userId = "nope")) }
    }

    private companion object {
        /** `/tmp/l1-handover/negsig.json` `frameB64`; byte-equal to `accountgenesis.json` row `genesis-signed-under-the-negated-key`. */
        const val NEGATED_KEY_GENESIS =
            "YXZzAgWcerokfUuai3m1bqsYJXTl-M2VQCiaH4laBp4AW1izSqGs-9Ewb-VVNZ7WZRKWT1n0zgzaVUdIdIP6ZJpsZZP4MyLLo71GPbP4wCLMmrfKLlQlJKcV5yw9mev3hXAjAwx7InYiOjIsInB1cnBvc2UiOiJhY2NvdW50LWdlbmVzaXMiLCJ1c2VySWQiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJpZGVudGl0eUtleSI6ImRtbjVUSTEtanRFUmRSVk1ab1dHNVFGcjNMWFBHcmVWSmNIRGF5TW5HaW8iLCJpbnN0YW5jZUlkIjoiZWVlZWVlZWUtZWVlZS00ZWVlLThlZWUtZWVlZWVlZWVlZWVlIiwicGVyc29uYWxWYXVsdElkIjoiY2NjY2NjY2MtY2NjYy00Y2NjLThjY2MtY2NjY2NjY2NjY2NjIiwiY3JlYXRlZEF0IjoxNzYzMTY0ODAwMDAwfQ"
    }
}
