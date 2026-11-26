package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowOpenException
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.SignedStatementException
import io.silencelen.andvari.core.crypto.StatementVerdict
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design 2026-11-15 §2.2: a statement with nesting is refused "BEFORE handing the text to any general
 * JSON parser (a parser that recurses once per level can be made to overflow its stack by a statement
 * of a thousand brackets, and that is a crash, not a verdict)".
 *
 * A frame carries up to 1,024 statement bytes, so 1,024 `[` fit. Before the flat-object check, every
 * call below threw `StackOverflowError` on a 128 KB stack, and `VaultLog.verify` did so on stacks up
 * to 512 KB (an iOS worker thread has 512 KB, and Kotlin/Native cannot recover from an overflow at
 * all). Each reader of untrusted text in `core/trust` and `core/crypto` is therefore run here on a
 * thread with a 128 KB stack and must answer with its ordinary verdict.
 *
 * JVM only: a thread's stack size cannot be chosen in common code.
 */
class StatementNestingStackTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)

    /** The deepest statement a frame can carry: 1,024 open arrays. */
    private val brackets = ByteArray(SignedFrame.MAX_STATEMENT_BYTES) { '['.code.toByte() }

    /** As deep as OBJECTS go in 1,024 bytes: `{"a":` 204 times. */
    private val objects = ("{\"a\":".repeat(204) + "1").encodeToByteArray()

    private fun frameOf(purpose: TrustPurpose, statement: ByteArray): ByteArray =
        SignedFrame.MAGIC + byteArrayOf(purpose.code.toByte()) + ByteArray(32) + ByteArray(64) + statement

    /**
     * Runs [body] on a thread created with a 128 KB stack and returns its result. Anything it throws,
     * a `StackOverflowError` included, fails the test. [body] runs once on the calling thread first, so
     * that class loading and initialisation, which nest deeply on their own, are not what is measured.
     */
    private fun <T> onSmallStack(body: () -> T): T {
        body()
        var outcome: Result<T>? = null
        val thread = Thread(null, { outcome = runCatching(body) }, "stack-128k", SMALL_STACK_BYTES)
        thread.start()
        thread.join()
        return outcome!!.getOrElse { throw AssertionError("on a ${SMALL_STACK_BYTES / 1024} KB stack: $it", it) }
    }

    @Test
    fun everyFramedPurpose_answersNonCanonical_forTheDeepestStatements() {
        for (deepest in listOf(brackets, objects)) {
            for (purpose in TrustPurpose.entries) {
                val verdict = onSmallStack { StatementCodec.parseFrame(frameOf(purpose, deepest), purpose).verdictOrNull() }
                // 0x02 has no template in this package (crypto.Escrow verifies those): the frame is refused first.
                assertEquals(if (purpose == TrustPurpose.ESCROW_UVK) FrameVerdict.BAD_FRAME else FrameVerdict.NON_CANONICAL, verdict, purpose.literal)
            }
        }
    }

    @Test
    fun theVerifiersThatTakeAFrameInTheClear_answerNonCanonical() {
        val log = frameOf(TrustPurpose.VAULT_LOG, brackets)
        assertEquals(VaultLogVerdict.NON_CANONICAL, onSmallStack { VaultLog.parse(crypto, log).verdictOrNull() })
        assertEquals(VaultLogVerdict.NON_CANONICAL, onSmallStack { VaultLog.verify(crypto, Ids.VAULT, null, log, KnownHashes.NONE_HELD).verdictOrNull() })
        val replay = onSmallStack { VaultLog.replay(crypto, Ids.VAULT, listOf(log), from = null, known = KnownHashes.NONE_HELD) }
        assertEquals(VaultLogVerdict.NON_CANONICAL, replay.verdict)
        assertNull(replay.state)

        val card = frameOf(TrustPurpose.INSTANCE_CARD, brackets)
        assertEquals(CardVerdict.NON_CANONICAL, onSmallStack { InstanceCard.parse(crypto, card).verdictOrNull() })
        assertEquals(CardVerdict.NON_CANONICAL, onSmallStack { InstanceCard.verify(crypto, null, card).verdictOrNull() })
        assertEquals(CardVerdict.NON_CANONICAL, onSmallStack { InstanceCard.verifyChain(crypto, listOf(card)).verdict })

        val genesis = frameOf(TrustPurpose.ACCOUNT_GENESIS, brackets)
        assertEquals(
            GenesisVerdict.NON_CANONICAL,
            onSmallStack { AccountGenesis.verify(crypto, genesis, alice.sign.publicKey, alice.box.publicKey, Ids.ALICE, Ids.INSTANCE, null).verdictOrNull() },
        )

        val rotation = frameOf(TrustPurpose.RECOVERY_ROTATION, brackets)
        val fp = "ab".repeat(32)
        assertEquals(RecoveryVerdict.NON_CANONICAL, onSmallStack { RecoveryRotation.verify(crypto, rotation, Ids.INSTANCE, fp).verdictOrNull() })
        assertNull(onSmallStack { RecoveryRotation.chain(crypto, listOf(rotation), Ids.INSTANCE, fp, "cd".repeat(32)) })

        val veto = frameOf(TrustPurpose.RECOVERY_VETO, brackets)
        assertEquals(
            RecoveryVerdict.NON_CANONICAL,
            onSmallStack { RecoveryVeto.verify(crypto, veto, alice.box.publicKey, Ids.ALICE, Ids.id16(1)).verdictOrNull() },
        )
    }

    @Test
    fun theVerifiersThatOpenASealOrAnEnvelopeFirst_answerNonCanonical() {
        // A grant: anyone who knows the member's public key can seal one.
        val grant = crypto.sealTo(bob.box.publicKey, frameOf(TrustPurpose.VAULT_GRANT, brackets))
        assertEquals(
            VaultGrantVerdict.NON_CANONICAL,
            onSmallStack { VaultGrant.open(crypto, Ids.BOB, bob.box.publicKey, bob.box.privateKey, Ids.VAULT, grant, null).verdictOrNull() },
        )

        // An assisted-recovery payload: the server holds the request key and can seal one.
        val request = crypto.boxKeypairFromSeed(ByteArray(32) { 0x33 })
        val assisted = crypto.sealTo(request.publicKey, frameOf(TrustPurpose.ASSISTED_RECOVERY, brackets))
        val identity = IdentityCheck("AAAA", Bytes.toB64(alice.box.publicKey))
        assertEquals(
            RecoveryVerdict.NON_CANONICAL,
            onSmallStack {
                AssistedRecovery.open(crypto, request.publicKey, request.privateKey, assisted, "ab".repeat(32), Ids.INSTANCE, Ids.id16(1), identity, null).verdictOrNull()
            },
        )

        // A link offer and a link answer: whoever holds the link secret can seal either.
        val secret = ByteArray(32) { 0x44 }
        val keys = Links.deriveKeys(crypto, secret)
        val link = LinkUrl.parse(LinkUrl.compose("https://vault.example.org", secret, LinkUrl.creatorFingerprint(crypto, alice.box.publicKey))!!)!!
        val offer = Envelope.seal(crypto, keys.offerKey, frameOf(TrustPurpose.LINK_OFFER, brackets), Ad.linkOffer(keys.linkId))
        val served = ServedLink("connect", Ids.ALICE, alice.key)
        assertEquals(LinkVerdict.NON_CANONICAL, onSmallStack { LinkOffer.open(crypto, link, offer, served, Ids.T0).verdictOrNull() })
        val answer = Envelope.seal(crypto, keys.answerKey, frameOf(TrustPurpose.LINK_ANSWER, brackets), Ad.linkAnswer(keys.linkId))
        assertEquals(
            LinkVerdict.NON_CANONICAL,
            onSmallStack { LinkAnswer.open(crypto, secret, "ab".repeat(32), Ids.ALICE, alice.box.publicKey, answer, Ids.BOB).verdictOrNull() },
        )
    }

    @Test
    fun theSpec01Codec_andTheEscrowOpener_answerNonCanonical() {
        for (code in listOf(0x01, 0x02)) {
            for (deepest in listOf(brackets, objects)) {
                val verdict = onSmallStack { runCatching { SignedStatement.parseStatement(code, deepest) }.exceptionOrNull() }
                assertEquals(StatementVerdict.NON_CANONICAL, (verdict as? SignedStatementException)?.verdict, "0x0$code")
            }
        }
        // The offline recovery tool opens whatever was sealed to the recovery key, and anyone can seal to a public key.
        val recovery = crypto.boxKeypairFromSeed(ByteArray(32) { 0x55 })
        val frame = SignedStatement.MAGIC + byteArrayOf(0x02) + ByteArray(32) + ByteArray(64) + brackets
        val sealed = crypto.sealTo(recovery.publicKey, frame)
        val identity = IdentityCheck("AAAA", Bytes.toB64(alice.box.publicKey))
        val refusal = onSmallStack {
            runCatching { Escrow.open(crypto, recovery, sealed, Ids.ALICE, null, identity, Escrow.UNANCHORED_ACK) }.exceptionOrNull()
        }
        assertEquals(EscrowVerdict.NON_CANONICAL, (refusal as? EscrowOpenException)?.verdict)
    }

    @Test
    fun theReadersOfOtherJson_areBoundedToo() {
        val deepArrays = ByteArray(60_000) { '['.code.toByte() }
        val deepObjects = "{\"a\":".repeat(12_000).encodeToByteArray()
        val closedArrays = ("[".repeat(30_000) + "]".repeat(30_000)).encodeToByteArray()

        // The host-offer reader and the device-link decoders use StrictJson, which bounds its own recursion.
        for (deep in listOf(deepArrays, deepObjects, closedArrays)) {
            assertEquals(FrameVerdict.NON_CANONICAL, onSmallStack { StatementCodec.parseHostOffer(deep).verdictOrNull() })
            assertEquals(FrameVerdict.NON_CANONICAL, onSmallStack { StatementCodec.hostOfferPurpose(deep).verdictOrNull() })
            assertNull(onSmallStack { DeviceLink.decodeBundle(deep) })
            assertNull(onSmallStack { DeviceLink.decodeOuter(deep) })
            assertNull(onSmallStack { StrictJson.parse(deep.decodeToString()) })
        }
        val nestedOffer = ("{\"purpose\":\"setup-offer\",\"x\":" + "[".repeat(900)).encodeToByteArray()
        assertEquals(FrameVerdict.NON_CANONICAL, onSmallStack { StatementCodec.parseHostOffer(nestedOffer).verdictOrNull() })

        // An enveloped host offer, and a sealed bundle, as they arrive.
        val secret = ByteArray(32) { 0x66 }
        val keys = Links.deriveKeys(crypto, secret)
        val link = LinkUrl.parse(LinkUrl.compose("https://vault.example.org", secret, null)!!)!!
        val offer = Envelope.seal(crypto, keys.offerKey, nestedOffer, Ad.linkOffer(keys.linkId))
        assertEquals(LinkVerdict.NON_CANONICAL, onSmallStack { LinkOffer.open(crypto, link, offer, ServedLink("setup", null, null), Ids.T0).verdictOrNull() })
        val uvk = ByteArray(32) { 0x77 }
        val linkId = DeviceLink.deriveKeys(crypto, secret).linkId
        val bundleKey = DeviceLink.bundleKey(crypto, uvk, linkId)
        val inner = Envelope.seal(crypto, bundleKey, deepArrays, Ad.deviceLinkBundle(linkId))
        assertEquals(DeviceLinkVerdict.BAD_BUNDLE, onSmallStack { DeviceLink.openBundle(crypto, uvk, linkId, inner).verdictOrNull() })

        // A stored state is this device's own text, but its decoder is total on anything.
        for (deep in listOf(deepArrays, deepObjects, closedArrays)) assertNull(onSmallStack { VaultState.decode(deep.decodeToString()) })

        // The v1 payloads are decoded into a fixed shape; a member that is not part of it is skipped, however deep.
        val deepMember = ("{\"v\":1,\"x\":" + "[".repeat(30_000) + "]".repeat(30_000) + "}").encodeToByteArray()
        for (deep in listOf(deepArrays, deepObjects, deepMember)) {
            val v1 = onSmallStack { runCatching { Escrow.parseV1(crypto, deep) }.exceptionOrNull() }
            assertEquals(EscrowVerdict.V1_MALFORMED, (v1 as? EscrowOpenException)?.verdict)
            val sealedGrant = crypto.sealTo(bob.box.publicKey, deep)
            val shared = onSmallStack { runCatching { SharedGrant.open(crypto, bob.box.publicKey, bob.box.privateKey, Ids.VAULT, sealedGrant) }.exceptionOrNull() }
            assertTrue(shared is Exception, "a refusal, not an Error: $shared")
        }
    }

    private companion object {
        const val SMALL_STACK_BYTES = 128L * 1024
    }
}
