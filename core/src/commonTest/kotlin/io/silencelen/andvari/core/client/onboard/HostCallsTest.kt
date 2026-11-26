package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.TrustGateTicket
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The narrow public calls a host (the command-line tool) uses in place of the engine's internals: the card 0 hash of a
 * Trust Gate, and an instance card signed by the account without its key leaving the engine.
 */
class HostCallsTest {
    private val crypto = createCryptoProvider()
    private val me = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
    private val seed = ByteArray(32) { 4 }

    private fun account(): OpenedAccount {
        val identity = crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(me, Bytes.toB64(identity.publicKey), "instance", "v-personal", 0), "00".repeat(32))
        return OpenedAccount(me, ByteArray(32) { 1 }, identity, crypto.signKeypairFromSeed(seed), genesis, null, null)
    }

    private fun fields(operator: String = me, key: String = Bytes.toB64(crypto.signKeypairFromSeed(seed).publicKey)) =
        CardFields("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", 3, "a".repeat(64), "https://h.example", "Home", InstanceKind.PRIVATE, operator, key, null, 1_794_744_000_000L)

    @Test fun theAccountSignsItsOwnNextCardAndNothingElse() {
        val a = account()
        val frame = a.signInstanceCard(crypto, fields())
        assertContentEquals(InstanceCard.sign(crypto, crypto.signKeypairFromSeed(seed), fields()), frame, "the card the operator's key signs")
        assertFailsWith<IllegalArgumentException> { a.signInstanceCard(crypto, fields(operator = "1c7f4d3f-5e6b-4c8d-9eaf-1a2b3c4d5e6f")) }
        assertFailsWith<IllegalArgumentException> { a.signInstanceCard(crypto, fields(key = Bytes.toB64(ByteArray(32) { 9 }))) }
        a.wipe()
        assertFailsWith<AccountWipedException> { a.signInstanceCard(crypto, fields()) }
    }

    @Test fun aTrustGateNamesTheCard0HashOfTheChainItShows() {
        val c0 = "c".repeat(64)
        val pin = CardPin("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", 3, "b".repeat(64), "https://h.example", "Home", "private", me,
            Bytes.toB64(ByteArray(32) { 2 }), "none", PinRoot.TRUST_GATE, null, c0)
        assertEquals(c0, TrustGateTicket("https://h.example", TrustGateWording.TYPED_ADDRESS, pin).card0Hash)
    }
}
