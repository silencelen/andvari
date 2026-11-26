package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Card rules of design 2026-11-15 §4 that `instancecard.json` does not carry because they are about
 * this API: the builder's refusals, the server's own instance id, a chain that stops verifying after
 * the pin, the operator's X25519 image and the full-length recovery-key check of §4.5.
 */
class InstanceCardRulesTest {
    private val crypto = createCryptoProvider()
    private val operator = Party(crypto, "99999999-9999-4999-8999-999999999999", 9)
    private val other = Party(crypto, "88888888-8888-4888-8888-888888888888", 8)
    private val origin = "https://vault.example.org"

    private fun card0(name: String = "Example", recoveryFp: String? = null, instanceId: String = Ids.INSTANCE) = CardFields(
        instanceId, 0, TrustGrammar.ZERO_HASH, origin, name, InstanceKind.PRIVATE, operator.userId,
        Bytes.toB64(operator.sign.publicKey), recoveryFp, Ids.T0,
    )

    private fun next(prior: VerifiedCard, change: (CardFields) -> CardFields = { it }): CardFields =
        change(prior.fields.copy(seq = prior.fields.seq + 1, prev = prior.hash, issuedAt = prior.fields.issuedAt + 1))

    private fun verified(prior: CardHead?, frame: ByteArray): VerifiedCard =
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, prior, frame)).value

    @Test
    fun sign_buildsAChainThatVerifies_andANameIsDecodedText() {
        val c0 = verified(null, InstanceCard.sign(crypto, operator.sign, card0(name = "Fjölskylda ✓")))
        assertEquals("Fjölskylda ✓", c0.fields.name)
        assertEquals(c0.hash, c0.card0Hash)
        val c1 = verified(c0.head, InstanceCard.sign(crypto, operator.sign, next(c0) { it.copy(origin = "https://vault2.example.org:8443") }))
        assertEquals(c0.hash, c1.card0Hash, "card0Hash follows the chain")
        assertEquals(CardHead(Ids.INSTANCE, c0.hash, 1, c1.hash, c1.fields.operatorSignKey), c1.head)
    }

    @Test
    fun sign_refusesWhatTheVerifierWouldRefuse() {
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0(name = "")) }
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0(name = " padded")) }
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0(name = "a\u200Bb")) } // U+200B is on the list
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0(name = "x".repeat(65))) }
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0(recoveryFp = "none")) } // null is none
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0(recoveryFp = "AB".repeat(32))) }
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0().copy(origin = "http://192.168.1.9:8080")) }
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, operator.sign, card0().copy(prev = "ab".repeat(32))) }
        // Card 0 is signed by the key it names.
        assertFailsWith<IllegalArgumentException> { InstanceCard.sign(crypto, other.sign, card0()) }
    }

    @Test
    fun theServerChecksItsOwnInstanceId_onCardZeroAndAfter() {
        val frame0 = InstanceCard.sign(crypto, operator.sign, card0())
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, null, frame0, expectedInstanceId = Ids.INSTANCE))
        assertEquals(CardVerdict.INSTANCE_MISMATCH, InstanceCard.verify(crypto, null, frame0, expectedInstanceId = Ids.OTHER_INSTANCE).verdictOrNull())
        // A client passes no expectation into the chain check: card 0 of any instance verifies on its own.
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, null, InstanceCard.sign(crypto, operator.sign, card0(instanceId = Ids.OTHER_INSTANCE))))
    }

    @Test
    fun follow_stopsAtACardThatDoesNotVerify_andKeepsWhatDid() {
        val c0 = verified(null, InstanceCard.sign(crypto, operator.sign, card0()))
        val f1 = InstanceCard.sign(crypto, operator.sign, next(c0))
        val c1 = verified(c0.head, f1)
        val f2 = InstanceCard.sign(crypto, operator.sign, next(c1))
        val c2 = verified(c1.head, f2)
        // Card 3 is signed by a key the chain never named.
        val f3 = InstanceCard.sign(crypto, other.sign, next(c2))

        val follow = InstanceCard.follow(crypto, c0.head, listOf(c0.frame, f1, f2, f3))
        assertNull(follow.pin, "the pin is contained")
        assertEquals(listOf(c1.head, c2.head), follow.newer.map { it.head })
        assertEquals(CardVerdict.NOT_AUTHORIZED, follow.verdict)

        // Nothing below the pin is verified again: garbage there does not matter once the pinned hash matches.
        val garbageBelow = InstanceCard.follow(crypto, c1.head, listOf(c0.frame, f1, f2))
        assertNull(garbageBelow.pin)
        assertEquals(listOf(c2.head), garbageBelow.newer.map { it.head })
        // The same pin against a chain whose card 0 was replaced: a fork, although the pinned position matches.
        val otherCard0 = InstanceCard.sign(crypto, operator.sign, card0(name = "Another"))
        assertEquals(PinVerdict.FORK, InstanceCard.follow(crypto, c1.head, listOf(otherCard0, f1, f2)).pin)
        assertEquals(PinVerdict.WITHHELD, InstanceCard.follow(crypto, c2.head, listOf(c0.frame, f1)).pin)
        assertEquals(PinVerdict.WITHHELD, InstanceCard.follow(crypto, c2.head, emptyList()).pin)
    }

    @Test
    fun everyRootChecksTheDialedOriginFirst() {
        val f0 = InstanceCard.sign(crypto, operator.sign, card0())
        val c0 = verified(null, f0)
        val f1 = InstanceCard.sign(crypto, operator.sign, next(c0))
        val c1 = verified(c0.head, f1)
        val chain = InstanceCard.verifyChain(crypto, listOf(f0, f1)).chain
        val lookalike = "https://vau1t.example.org"
        val unknown = "ab".repeat(32)

        // The genuine chain, served by the address it names, passes every root.
        assertNull(InstanceCard.checkBakedRoot(chain, origin, c0.hash, Ids.INSTANCE))
        assertNull(InstanceCard.checkKitRoot(chain, origin, c0.hash))
        assertNull(InstanceCard.checkOfferRoot(chain, origin, c1.hash, Ids.INSTANCE))
        assertNull(InstanceCard.checkTypedRoot(chain, origin))
        // The same genuine chain served by a look-alike address. Cards are public: anyone can serve them.
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkBakedRoot(chain, lookalike, c0.hash, Ids.INSTANCE))
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkKitRoot(chain, lookalike, c0.hash))
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkOfferRoot(chain, lookalike, c1.hash, Ids.INSTANCE))
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkTypedRoot(chain, lookalike))
        // It comes first: before card0_mismatch, instance_mismatch and card_not_in_chain.
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkBakedRoot(chain, lookalike, unknown, Ids.OTHER_INSTANCE))
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkKitRoot(chain, lookalike, unknown))
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkOfferRoot(chain, lookalike, unknown, Ids.OTHER_INSTANCE))
        // With the dialed origin right, the later verdicts are what they were.
        assertEquals(PinVerdict.CARD0_MISMATCH, InstanceCard.checkBakedRoot(chain, origin, unknown, Ids.OTHER_INSTANCE))
        assertEquals(PinVerdict.INSTANCE_MISMATCH, InstanceCard.checkBakedRoot(chain, origin, c0.hash, Ids.OTHER_INSTANCE))
        assertEquals(PinVerdict.CARD0_MISMATCH, InstanceCard.checkKitRoot(chain, origin, unknown))
        assertEquals(PinVerdict.CARD_NOT_IN_CHAIN, InstanceCard.checkOfferRoot(chain, origin, unknown, Ids.INSTANCE))
        assertEquals(PinVerdict.INSTANCE_MISMATCH, InstanceCard.checkOfferRoot(chain, origin, c1.hash, Ids.OTHER_INSTANCE))
        // An empty chain has no card to compare: it is withheld for every root.
        val empty = InstanceCard.verifyChain(crypto, emptyList()).chain
        assertEquals(PinVerdict.WITHHELD, InstanceCard.checkBakedRoot(empty, lookalike, c0.hash, Ids.INSTANCE))
        assertEquals(PinVerdict.WITHHELD, InstanceCard.checkKitRoot(empty, lookalike, c0.hash))
        assertEquals(PinVerdict.WITHHELD, InstanceCard.checkOfferRoot(empty, lookalike, c0.hash, Ids.INSTANCE))
        assertEquals(PinVerdict.WITHHELD, InstanceCard.checkTypedRoot(empty, lookalike))

        // The NEWEST card's origin counts: after a signed move only the new address passes a root.
        val newOrigin = "https://vault2.example.org"
        val f2 = InstanceCard.sign(crypto, operator.sign, next(c1) { it.copy(origin = newOrigin) })
        val moved = InstanceCard.verifyChain(crypto, listOf(f0, f1, f2)).chain
        assertEquals(PinVerdict.ORIGIN_MISMATCH, InstanceCard.checkTypedRoot(moved, origin))
        assertNull(InstanceCard.checkTypedRoot(moved, newOrigin))
        assertNull(InstanceCard.checkOfferRoot(moved, newOrigin, c1.hash, Ids.INSTANCE), "an offer may name an older card of the chain")
        // Under an EXISTING pin a changed origin is a move, never this verdict: follow reports the newer card.
        val follow = InstanceCard.follow(crypto, c1.head, listOf(f0, f1, f2))
        assertNull(follow.pin)
        assertEquals(newOrigin, follow.newer.single().fields.origin)
    }

    @Test
    fun operatorIdentityKey_isTheX25519ImageOfTheSigningKey() {
        assertContentEquals(operator.box.publicKey, InstanceCard.operatorIdentityKey(crypto, Bytes.toB64(operator.sign.publicKey)))
        assertNull(InstanceCard.operatorIdentityKey(crypto, Bytes.toB64(ByteArray(32)))) // no image
        assertNull(InstanceCard.operatorIdentityKey(crypto, "not base64url"))
        assertNull(InstanceCard.operatorIdentityKey(crypto, Bytes.toB64(ByteArray(31))))
    }

    /** `-A`: the same y, with the sign bit of x flipped (the top bit of the last byte). */
    private fun negated(ed25519Pub: ByteArray): ByteArray = ed25519Pub.copyOf().also { it[31] = (it[31].toInt() xor 0x80).toByte() }

    @Test
    fun aHandoverThatNamesTheNegatedKey_isRefusedWhereTheRealKeyIsKnown() {
        // §4.1: a key and its negation are two different Ed25519 keys with ONE X25519 image.
        val minusA = negated(other.sign.publicKey)
        assertTrue(!minusA.contentEquals(other.sign.publicKey))
        assertContentEquals(other.box.publicKey, crypto.ed25519PkToCurve25519(minusA), "the image cannot tell them apart")
        assertContentEquals(other.box.publicKey, InstanceCard.operatorIdentityKey(crypto, Bytes.toB64(minusA)))

        val c0 = verified(null, InstanceCard.sign(crypto, operator.sign, card0()))
        fun handoverNaming(key: ByteArray) =
            InstanceCard.sign(crypto, operator.sign, next(c0) { it.copy(operator = other.userId, operatorSignKey = Bytes.toB64(key)) })
        val handover = handoverNaming(minusA)

        // The incoming operator's own device, and the server (which holds the key that signed that account's genesis).
        val incoming = OperatorKeys { userId -> other.sign.publicKey.takeIf { userId == other.userId } }
        assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, InstanceCard.verify(crypto, c0.head, handover, operatorKeys = incoming).verdictOrNull())
        assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, InstanceCard.verify(crypto, c0.head, handover, Ids.INSTANCE, incoming).verdictOrNull())
        val chain = InstanceCard.verifyChain(crypto, listOf(c0.frame, handover), operatorKeys = incoming)
        assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, chain.verdict)
        assertEquals(1, chain.failedAt)
        assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, InstanceCard.follow(crypto, c0.head, listOf(c0.frame, handover), incoming).verdict)

        // What the check prevents. Every other client accepts the card (the outgoing operator did sign it),
        // and under the negated key the real key can sign no later card: the instance is locked.
        val accepted = verified(c0.head, handover)
        val byTheRealKey = InstanceCard.sign(crypto, other.sign, next(accepted) { it.copy(operatorSignKey = Bytes.toB64(other.sign.publicKey)) })
        assertEquals(CardVerdict.NOT_AUTHORIZED, InstanceCard.verify(crypto, accepted.head, byTheRealKey).verdictOrNull())

        // An honest handover passes, and the new operator's later cards do too.
        val honest = assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, c0.head, handoverNaming(other.sign.publicKey), operatorKeys = incoming)).value
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, honest.head, InstanceCard.sign(crypto, other.sign, next(honest)), operatorKeys = incoming))
    }

    @Test
    fun theOperatorCheck_takesTheEd25519Key_notTheIdentityKey() {
        val frame0 = InstanceCard.sign(crypto, operator.sign, card0())
        // The right key: the Ed25519 key the device derives from its own seed.
        val own = OperatorKeys { userId -> operator.sign.publicKey.takeIf { userId == operator.userId } }
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, null, frame0, operatorKeys = own))
        // The X25519 identity key in its place matches no card: the mistake fails closed.
        val identityKey = OperatorKeys { userId -> operator.box.publicKey.takeIf { userId == operator.userId } }
        assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, InstanceCard.verify(crypto, null, frame0, operatorKeys = identityKey).verdictOrNull())
        // So do a key of the wrong length and another account's key.
        for (wrong in listOf(ByteArray(0), ByteArray(31), operator.sign.publicKey + byteArrayOf(0), other.sign.publicKey, negated(operator.sign.publicKey))) {
            val keys = OperatorKeys { userId -> wrong.takeIf { userId == operator.userId } }
            assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, InstanceCard.verify(crypto, null, frame0, operatorKeys = keys).verdictOrNull())
        }
        // A verifier that holds no key for the named account does not check.
        val anotherAccount = OperatorKeys { userId -> other.sign.publicKey.takeIf { userId == other.userId } }
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, null, frame0, operatorKeys = anotherAccount))
        // The signature comes first: a card with a broken signature is bad_signature, whatever key is held.
        val broken = frame0.copyOf().also { it[50] = (it[50].toInt() xor 1).toByte() }
        assertEquals(CardVerdict.BAD_SIGNATURE, InstanceCard.verify(crypto, null, broken, operatorKeys = identityKey).verdictOrNull())
    }

    @Test
    fun theServerHandsTheKeyThatSignedTheGenesis() {
        // The server keeps each account's genesis frame; its signerPub is the account's Ed25519 signing key (§4.1).
        fun genesisOf(party: Party) =
            AccountGenesis.sign(crypto, party.sign, GenesisFields(party.userId, party.key, Ids.INSTANCE, Ids.OTHER_VAULT, Ids.T0))
        val stored = mapOf(operator.userId to genesisOf(operator), other.userId to genesisOf(other))
        assertContentEquals(operator.sign.publicKey, AccountGenesis.signerOf(stored.getValue(operator.userId)))
        val server = OperatorKeys { userId -> stored[userId]?.let(AccountGenesis::signerOf) }

        val c0 = assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, null, InstanceCard.sign(crypto, operator.sign, card0()), Ids.INSTANCE, server)).value
        val honest = InstanceCard.sign(crypto, operator.sign, next(c0) { it.copy(operator = other.userId, operatorSignKey = Bytes.toB64(other.sign.publicKey)) })
        assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, c0.head, honest, Ids.INSTANCE, server))
        val negatedKey = InstanceCard.sign(crypto, operator.sign, next(c0) { it.copy(operator = other.userId, operatorSignKey = Bytes.toB64(negated(other.sign.publicKey))) })
        assertEquals(CardVerdict.OPERATOR_KEY_MISMATCH, InstanceCard.verify(crypto, c0.head, negatedKey, Ids.INSTANCE, server).verdictOrNull())

        // signerOf reads a genesis frame and nothing else.
        assertNull(AccountGenesis.signerOf(c0.frame), "a card is not a genesis")
        assertNull(AccountGenesis.signerOf(ByteArray(0)))
        assertNull(AccountGenesis.signerOf(ByteArray(200)))
    }

    @Test
    fun recoveryKeyMatches_comparesTheWholeFingerprint() {
        val recovery = Party(crypto, Ids.DAVE, 5).box.publicKey
        val fp = Bytes.toHexLower(crypto.sha256(recovery))
        assertTrue(InstanceCard.recoveryKeyMatches(crypto, fp, recovery))
        assertTrue(!InstanceCard.recoveryKeyMatches(crypto, null, recovery), "none: no operator recovery")
        assertTrue(!InstanceCard.recoveryKeyMatches(crypto, fp, operator.box.publicKey))
        assertTrue(!InstanceCard.recoveryKeyMatches(crypto, fp.take(32), recovery), "a prefix is never enough")
        assertTrue(!InstanceCard.recoveryKeyMatches(crypto, fp.uppercase(), recovery))
        assertTrue(!InstanceCard.recoveryKeyMatches(crypto, fp, recovery.copyOf(31)))
    }

    @Test
    fun verify_isTotalOnGarbage() {
        for (bytes in listOf(ByteArray(0), ByteArray(3), ByteArray(300), "{}".encodeToByteArray())) {
            assertIs<Checked.Refused<CardVerdict>>(InstanceCard.verify(crypto, null, bytes))
        }
        assertTrue(InstanceCard.verifyChain(crypto, emptyList()).complete)
        assertNull(InstanceCard.verifyChain(crypto, emptyList()).chain.newest)
    }
}
