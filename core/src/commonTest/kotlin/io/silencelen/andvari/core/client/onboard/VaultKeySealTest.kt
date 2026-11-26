package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * The seal under the account's vault key ([OpenedAccount.sealUnderVaultKey]), for the iPhone's fill snapshot: it opens
 * for the same account and purpose only, the associated data is the engine's, and the key is never the UVK itself.
 */
class VaultKeySealTest {
    private val crypto = createCryptoProvider()

    private fun account(userId: String = "u1", uvkByte: Int = 1): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(userId, Bytes.toB64(identity.publicKey), "instance", "v-personal", 0), "00".repeat(32))
        return OpenedAccount(userId, ByteArray(32) { uvkByte.toByte() }, identity, crypto.signKeypairFromSeed(seed), genesis, null, null)
    }

    private val snapshot = """{"logins":[{"host":"bank.example","user":"p"}]}""".encodeToByteArray()

    @Test fun aSnapshotOpensForItsAccountAndPurposeOnly() {
        val sealed = account().sealUnderVaultKey(crypto, "fill-snapshot", snapshot)
        assertContentEquals(snapshot, account().openUnderVaultKey(crypto, "fill-snapshot", sealed), "the same account, a new session")
        assertNull(account().openUnderVaultKey(crypto, "fill-snapshot.v2", sealed), "another purpose")
        assertNull(account(userId = "u2").openUnderVaultKey(crypto, "fill-snapshot", sealed), "another account with the same key bytes")
        assertNull(account(uvkByte = 9).openUnderVaultKey(crypto, "fill-snapshot", sealed), "another vault key")
        val tampered = sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertNull(account().openUnderVaultKey(crypto, "fill-snapshot", tampered), "a changed seal")
        assertNull(account().openUnderVaultKey(crypto, "fill-snapshot", ByteArray(3)), "not a seal")
    }

    @Test fun theKeyIsDerivedForThePurposeAndTheAdIsTheEngines() {
        val uvk = ByteArray(32) { 1 }
        val ad = "andvari/v2|vault-key-seal|u1|fill-snapshot".encodeToByteArray()
        val sealed = account().sealUnderVaultKey(crypto, "fill-snapshot", snapshot)
        val key = Hkdf.sha256(crypto, uvk, ByteArray(0), "andvari vault-key seal v1|fill-snapshot".encodeToByteArray(), 32)
        assertContentEquals(snapshot, Envelope.open(crypto, key, sealed, ad))
        // An envelope under the UVK itself, with this AD or one of the UVK's own, is not a seal of this kind.
        assertNull(account().openUnderVaultKey(crypto, "fill-snapshot", Envelope.seal(crypto, uvk, snapshot, ad)))
        assertNull(account().openUnderVaultKey(crypto, "fill-snapshot", Envelope.seal(crypto, uvk, snapshot, Ad.accountState("u1"))))
        // And a seal of this kind does not open as the account's own state.
        assertFailsWith<Exception> { Envelope.open(crypto, uvk, sealed, Ad.accountState("u1")) }
    }

    @Test fun aPurposeIsALabelAndAWipedAccountSealsAndOpensNothing() {
        val me = account()
        for (bad in listOf("", "Fill", "fill|snapshot", "-x", "x".repeat(65), "fill snapshot")) {
            assertFailsWith<IllegalArgumentException>(bad) { me.sealUnderVaultKey(crypto, bad, snapshot) }
            assertNull(me.openUnderVaultKey(crypto, bad, ByteArray(64)), bad)
        }
        val sealed = me.sealUnderVaultKey(crypto, "fill-snapshot", snapshot)
        me.wipe()
        assertFailsWith<AccountWipedException> { me.sealUnderVaultKey(crypto, "fill-snapshot", snapshot) }
        assertFailsWith<AccountWipedException> { me.openUnderVaultKey(crypto, "fill-snapshot", sealed) }
    }
}
