package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Recovery rules of design 2026-11-15 §4.5 and §9.3 that `recovery.json` does not carry: what the
 * builders refuse, an empty chain, consent that follows rotations served in any order, a card that
 * jumps over a key the rotations passed through, the typed request code, the cases §2.4 names that the
 * file leaves ungraded (an identity seed that does not open; a fresh install that holds no `userId`),
 * and that no served value makes a verifier throw. Built with real statements from fixed seeds.
 */
class RecoveryRulesTest {
    private val crypto = createCryptoProvider()

    /** An instance recovery seed: its Ed25519 signing pair, its X25519 public key and the fingerprint a card carries for it. */
    private inner class RecoverySeed(n: Int) {
        private val seed = ByteArray(32) { (0x80 + n * 5 + it).toByte() }
        val sign: KeyPairBytes = crypto.signKeypairFromSeed(seed)
        val pub: ByteArray = crypto.boxKeypairFromSeed(seed).publicKey
        val fp: String = Bytes.toHexLower(crypto.sha256(pub))
    }

    private val a = RecoverySeed(1)
    private val b = RecoverySeed(2)
    private val c = RecoverySeed(3)
    private val d = RecoverySeed(4)
    private val operator = Party(crypto, "99999999-9999-4999-8999-999999999999", 9)
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)

    private fun statementOf(frame: ByteArray): String = assertIs<Checked.Ok<FrameParts>>(SignedFrame.split(frame)).value.statement.decodeToString()

    /** A frame over [text] as it stands: for statements a builder would refuse to sign. */
    private fun signedRaw(signer: KeyPairBytes, purpose: TrustPurpose, text: String): ByteArray =
        SignedFrame.sign(crypto, signer, purpose, text.encodeToByteArray())

    private fun flipSignatureBit(frame: ByteArray): ByteArray = frame.copyOf().also { it[50] = (it[50].toInt() xor 0x10).toByte() }

    // ---- §4.5 rotation ---------------------------------------------------------------------------------

    /** The rotation [from] to [to], signed offline by the outgoing seed. */
    private fun rotation(from: RecoverySeed, to: RecoverySeed, instanceId: String = Ids.INSTANCE): ByteArray =
        RecoveryRotation.sign(crypto, from.sign, RotationFields(instanceId, from.fp, to.fp, Ids.T0))

    /** A canonical rotation statement signed by whoever: the builder refuses a signer that is not the outgoing key. */
    private fun rotationSignedBy(signer: KeyPairBytes, fromFp: String, toFp: String, instanceId: String = Ids.INSTANCE): ByteArray {
        val statement = StatementCodec.encode(
            TrustPurpose.RECOVERY_ROTATION,
            mapOf("instanceId" to instanceId, "fromFp" to fromFp, "toFp" to toFp, "issuedAt" to Ids.T0.toString()),
        )
        return SignedFrame.sign(crypto, signer, TrustPurpose.RECOVERY_ROTATION, statement)
    }

    private fun rotationVerdict(frame: ByteArray, instanceId: String = Ids.INSTANCE, currentFp: String = a.fp): RecoveryVerdict? =
        RecoveryRotation.verify(crypto, frame, instanceId, currentFp).verdictOrNull()

    @Test
    fun rotation_theOutgoingSeedMovesAVerifierFromOneKeyToTheNext() {
        val frame = rotation(a, b)
        val verified = assertIs<Checked.Ok<VerifiedRotation>>(RecoveryRotation.verify(crypto, frame, Ids.INSTANCE, a.fp)).value
        assertEquals(RotationFields(Ids.INSTANCE, a.fp, b.fp, Ids.T0), verified.fields)
        assertEquals(SignedFrame.hash(crypto, frame), verified.hash)
        assertEquals(
            "{\"v\":2,\"purpose\":\"recovery-rotation\",\"instanceId\":\"${Ids.INSTANCE}\",\"fromFp\":\"${a.fp}\",\"toFp\":\"${b.fp}\",\"issuedAt\":${Ids.T0}}",
            statementOf(frame),
        )
    }

    @Test
    fun rotation_eachCheckHasItsVerdict_inOrder() {
        val good = rotation(a, b)
        val statement = statementOf(good)
        val veto = RecoveryVeto.sign(crypto, alice.sign, VetoFields(Ids.id16(3), Ids.ALICE, Ids.T0))

        // The parse.
        assertEquals(RecoveryVerdict.BAD_FRAME, rotationVerdict(ByteArray(0)))
        assertEquals(RecoveryVerdict.BAD_FRAME, rotationVerdict(ByteArray(3)), "shorter than the magic")
        assertEquals(RecoveryVerdict.UNKNOWN_FORMAT, rotationVerdict(statement.encodeToByteArray()), "the bare statement, not a frame")
        assertEquals(RecoveryVerdict.BAD_FRAME, rotationVerdict(good.copyOf(50)), "truncated")
        assertEquals(RecoveryVerdict.BAD_FRAME, rotationVerdict(veto), "a 0x0A frame")
        assertEquals(RecoveryVerdict.NON_CANONICAL, rotationVerdict(signedRaw(a.sign, TrustPurpose.RECOVERY_ROTATION, statement.replace("\"v\":2", "\"v\": 2"))))
        assertEquals(RecoveryVerdict.NON_CANONICAL, rotationVerdict(signedRaw(a.sign, TrustPurpose.RECOVERY_ROTATION, statement.replace(b.fp, "none"))), "no rotation names none")
        assertEquals(RecoveryVerdict.BAD_STATEMENT, rotationVerdict(signedRaw(a.sign, TrustPurpose.RECOVERY_ROTATION, statement.replace("\"v\":2", "\"v\":3"))))

        // fp_mismatch: the verifier stands at another fingerprint. A card's `none` equals no fromFp.
        assertEquals(RecoveryVerdict.FP_MISMATCH, rotationVerdict(good, currentFp = b.fp))
        assertEquals(RecoveryVerdict.FP_MISMATCH, rotationVerdict(good, currentFp = TrustGrammar.NONE))
        assertEquals(RecoveryVerdict.FP_MISMATCH, rotationVerdict(good, currentFp = a.fp.uppercase()))
        assertEquals(RecoveryVerdict.FP_MISMATCH, rotationVerdict(good, currentFp = a.fp.take(32)), "the 32-hex short form is not the fingerprint")
        assertEquals(RecoveryVerdict.FP_MISMATCH, rotationVerdict(good, currentFp = ""))

        // signer_not_pinned_key: the incoming key, an account key, a key with no curve image.
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, rotationVerdict(rotationSignedBy(b.sign, a.fp, b.fp)), "the new key signs its own promotion")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, rotationVerdict(rotationSignedBy(operator.sign, a.fp, b.fp)), "the operator account's key")
        val noImage = good.copyOf().also { it.fill(0, SignedFrame.HEADER_BYTES, SignedFrame.HEADER_BYTES + SignedFrame.SIGNER_BYTES) }
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, rotationVerdict(noImage), "a signer key with no X25519 image")

        // bad_signature, then instance_mismatch last.
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, rotationVerdict(flipSignatureBit(good)))
        assertEquals(RecoveryVerdict.INSTANCE_MISMATCH, rotationVerdict(good, instanceId = Ids.OTHER_INSTANCE))
        assertEquals(RecoveryVerdict.INSTANCE_MISMATCH, rotationVerdict(rotation(a, b, Ids.OTHER_INSTANCE)))

        // The first failing check decides.
        val otherFpNotCanonical = signedRaw(c.sign, TrustPurpose.RECOVERY_ROTATION, statementOf(rotation(b, c)).replace("\"v\":2", "\"v\": 2"))
        assertEquals(RecoveryVerdict.NON_CANONICAL, rotationVerdict(otherFpNotCanonical), "the parse before the fingerprint")
        assertEquals(RecoveryVerdict.FP_MISMATCH, rotationVerdict(rotationSignedBy(c.sign, b.fp, c.fp)), "the fingerprint before the signer")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, rotationVerdict(flipSignatureBit(rotationSignedBy(b.sign, a.fp, b.fp))), "the signer before the signature")
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, rotationVerdict(flipSignatureBit(rotation(a, b, Ids.OTHER_INSTANCE))), "the signature before the instance")
    }

    @Test
    fun rotation_signRefusesWhatTheVerifierWouldRefuse() {
        fun sign(signer: KeyPairBytes, fields: RotationFields) = RecoveryRotation.sign(crypto, signer, fields)
        // Outside the grammar. Both fingerprints are hex64: a rotation cannot turn operator recovery on or off.
        assertFailsWith<IllegalArgumentException> { sign(a.sign, RotationFields(Ids.INSTANCE.uppercase(), a.fp, b.fp, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(a.sign, RotationFields(Ids.INSTANCE, a.fp, TrustGrammar.NONE, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(a.sign, RotationFields(Ids.INSTANCE, TrustGrammar.NONE, b.fp, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(a.sign, RotationFields(Ids.INSTANCE, a.fp, b.fp.uppercase(), Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(a.sign, RotationFields(Ids.INSTANCE, a.fp, b.fp.take(32), Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(a.sign, RotationFields(Ids.INSTANCE, a.fp, b.fp, 0)) }
        // Signed by the key fromFp names, and by no other: not the incoming seed, not an account key, not a key with no image.
        assertFailsWith<IllegalArgumentException> { sign(b.sign, RotationFields(Ids.INSTANCE, a.fp, b.fp, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(operator.sign, RotationFields(Ids.INSTANCE, a.fp, b.fp, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(KeyPairBytes(ByteArray(32), a.sign.privateKey), RotationFields(Ids.INSTANCE, a.fp, b.fp, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { sign(KeyPairBytes(ByteArray(31), a.sign.privateKey), RotationFields(Ids.INSTANCE, a.fp, b.fp, Ids.T0)) }
    }

    @Test
    fun verifyChain_everyLinkInOrder_andTheLastOneEndsAtTheExpectedKey() {
        val ab = rotation(a, b)
        val bc = rotation(b, c)
        fun verdictOf(frames: List<ByteArray>, from: RecoverySeed, to: RecoverySeed) = RecoveryRotation.verifyChain(crypto, frames, Ids.INSTANCE, from.fp, to.fp)

        assertNull(verdictOf(listOf(ab), a, b))
        assertNull(verdictOf(listOf(ab, bc), a, c))
        // An empty chain holds only when nothing has to move.
        assertNull(verdictOf(emptyList(), a, a))
        assertEquals(RecoveryVerdict.FP_MISMATCH, verdictOf(emptyList(), a, b))
        // Every link verifies, and the chain ends short of, or past, the expected key.
        assertEquals(RecoveryVerdict.FP_MISMATCH, verdictOf(listOf(ab), a, c))
        assertEquals(RecoveryVerdict.FP_MISMATCH, verdictOf(listOf(ab, bc), a, b))
        // Oldest first: the same links newest first do not start from the current key.
        assertEquals(RecoveryVerdict.FP_MISMATCH, verdictOf(listOf(bc, ab), a, c))
        // The first link that fails decides, and nothing after it is looked at.
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, verdictOf(listOf(ab, rotationSignedBy(a.sign, b.fp, c.fp), ByteArray(3)), a, c))
        assertEquals(RecoveryVerdict.BAD_FRAME, verdictOf(listOf(ab, ByteArray(3), bc), a, c))
        assertEquals(RecoveryVerdict.INSTANCE_MISMATCH, verdictOf(listOf(rotation(a, b, Ids.OTHER_INSTANCE), bc), a, c))
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, verdictOf(listOf(ab, flipSignatureBit(bc)), a, c))
    }

    @Test
    fun follows_consentFollowsAChainOfRotationsServedInAnyOrder_andNothingElse() {
        val ab = rotation(a, b)
        val bc = rotation(b, c)
        val cd = rotation(c, d)
        fun follows(rotations: List<ByteArray>, from: RecoverySeed, to: RecoverySeed, instanceId: String = Ids.INSTANCE) =
            RecoveryRotation.follows(crypto, rotations, instanceId, from.fp, to.fp)

        // §4.5 condition 2: the card's key equals the consented one, or follows from it.
        assertTrue(follows(emptyList(), a, a))
        assertFalse(follows(emptyList(), a, b))
        assertTrue(follows(listOf(ab), a, b))
        assertTrue(follows(listOf(cd, bc, ab), a, d), "served in any order")
        assertTrue(follows(listOf(cd, bc, ab), b, d))
        assertFalse(follows(listOf(cd, bc, ab), d, a), "a rotation leads one way")
        assertFalse(follows(listOf(cd, ab), a, d), "a gap in the chain")
        // A chain that does not start at the verifier's own key moves nothing, however well it is signed further on.
        assertFalse(follows(listOf(bc, cd), a, d))

        // Statements that do not verify are ignored: the incoming key's own signature, another instance, another purpose, noise.
        val selfPromoted = rotationSignedBy(b.sign, a.fp, b.fp)
        val elsewhere = rotation(a, b, Ids.OTHER_INSTANCE)
        val veto = RecoveryVeto.sign(crypto, alice.sign, VetoFields(Ids.id16(3), Ids.ALICE, Ids.T0))
        assertFalse(follows(listOf(selfPromoted, bc), a, c))
        assertFalse(follows(listOf(elsewhere, bc), a, c))
        assertFalse(follows(listOf(flipSignatureBit(ab), bc), a, c))
        assertTrue(follows(listOf(ByteArray(0), ByteArray(200), veto, selfPromoted, elsewhere, bc, ab), a, c))
        assertFalse(follows(listOf(ab), a, b, instanceId = Ids.OTHER_INSTANCE), "nothing follows on another instance")

        // A rotation back to an earlier key is a rotation like any other, and the search ends.
        val ba = rotation(b, a)
        assertTrue(follows(listOf(ab, ba), a, b))
        assertTrue(follows(listOf(ab, ba), b, a))
        assertFalse(follows(listOf(ab, ba), a, c))
        assertTrue(follows(listOf(ba, ab, bc), a, c))
        // An attacker's own keys rotate among themselves; none of it starts at the consented key.
        assertFalse(follows(listOf(rotation(c, d), rotation(d, b)), a, b))
    }

    /** Counts the signature checks a verifier makes. */
    private class CountingCrypto(private val inner: CryptoProvider) : CryptoProvider by inner {
        var signatureChecks = 0

        override fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean {
            signatureChecks++
            return inner.signVerifyDetached(publicKey, signature, message)
        }
    }

    @Test
    fun chain_theFramesOfTheShortestPath_oldestFirst_outOfAnUnorderedServedList() {
        val ab = rotation(a, b)
        val bc = rotation(b, c)
        val cd = rotation(c, d)
        val noise = ByteArray(200)
        val elsewhere = rotation(a, d, Ids.OTHER_INSTANCE)
        val selfPromoted = rotationSignedBy(d.sign, a.fp, d.fp)
        fun chain(rotations: List<ByteArray>, from: RecoverySeed, to: RecoverySeed) = RecoveryRotation.chain(crypto, rotations, Ids.INSTANCE, from.fp, to.fp)
        fun assertFrames(expected: List<ByteArray>, actual: List<ByteArray>?) {
            assertEquals(expected.map { SignedFrame.hash(crypto, it) }, actual?.map { SignedFrame.hash(crypto, it) })
        }

        // Served newest first, with other statements between: the path is neither contiguous nor in order there.
        val served = listOf(cd, noise, elsewhere, ab, selfPromoted, bc)
        assertFrames(listOf(ab, bc, cd), chain(served, a, d))
        assertFrames(listOf(bc, cd), chain(served, b, d))
        assertFrames(listOf(ab), chain(served, a, b))
        // What it returns is what PUT /escrow/self checks, and it exists exactly when consent follows.
        for ((from, to) in listOf(a to b, a to c, a to d, b to d, c to d, d to a, b to a, a to a)) {
            val frames = chain(served, from, to)
            assertEquals(RecoveryRotation.follows(crypto, served, Ids.INSTANCE, from.fp, to.fp), frames != null)
            if (frames != null) assertNull(RecoveryRotation.verifyChain(crypto, frames, Ids.INSTANCE, from.fp, to.fp))
        }
        // Nothing to move: an empty chain, whatever is served. No path: null.
        assertEquals(emptyList<ByteArray>(), chain(served, a, a))
        assertEquals(emptyList<ByteArray>(), chain(emptyList(), a, a))
        assertNull(chain(emptyList(), a, b))
        assertNull(chain(served, d, a))
        assertNull(chain(listOf(cd, ab), a, d), "a gap")
        assertNull(chain(listOf(elsewhere, selfPromoted, noise), a, d))
        assertNull(RecoveryRotation.chain(crypto, served, Ids.OTHER_INSTANCE, a.fp, b.fp))

        // The shortest path: a rotation straight from A to C beats the two steps, wherever it is served.
        val ac = rotation(a, c)
        assertFrames(listOf(ac), chain(listOf(ab, bc, ac), a, c))
        assertFrames(listOf(ac), chain(listOf(ac, bc, ab), a, c))
        assertFrames(listOf(ac, cd), chain(listOf(ab, bc, cd, ac), a, d))
        // Two paths of the same length: the one whose first step is served first.
        val bd = rotation(b, d)
        assertFrames(listOf(ab, bd), chain(listOf(ab, ac, cd, bd), a, d))
        assertFrames(listOf(ac, cd), chain(listOf(ac, ab, bd, cd), a, d))
        // Two statements for the same step: the one served first.
        val abAgain = RecoveryRotation.sign(crypto, a.sign, RotationFields(Ids.INSTANCE, a.fp, b.fp, Ids.T0 + 1))
        assertFrames(listOf(abAgain), chain(listOf(abAgain, ab), a, b))
        assertFrames(listOf(ab), chain(listOf(ab, abAgain), a, b))
        // A rotation back to an earlier key does not trap the search, and is not part of a shortest path.
        val ba = rotation(b, a)
        assertFrames(listOf(ab, bc), chain(listOf(ba, ab, bc), a, c))
        assertFrames(listOf(ba), chain(listOf(ba, ab, bc), b, a))
        assertNull(chain(listOf(ba, ab), a, c))
        // The frames handed back are the served ones.
        assertTrue(chain(served, a, d)!!.zip(listOf(ab, bc, cd)).all { (got, sent) -> got === sent })
    }

    @Test
    fun chain_aStatementIsVerifiedOnce_andOnlyWhenItsStartIsReached() {
        val ab = rotation(a, b)
        val bc = rotation(b, c)
        val cd = rotation(c, d)
        // What a server without the recovery seed can serve: its own keys rotating among themselves, statements
        // that claim the consented key under another signer, and the same again and again.
        val x = RecoverySeed(11)
        val y = RecoverySeed(12)
        val hostile = ArrayList<ByteArray>()
        repeat(40) {
            hostile += rotation(x, y)
            hostile += rotation(y, x)
            hostile += rotationSignedBy(x.sign, a.fp, x.fp)
            hostile += rotationSignedBy(y.sign, b.fp, d.fp)
        }

        // None of it starts at the consented key under that key's signer: nothing reaches a signature check.
        val counting = CountingCrypto(crypto)
        assertNull(RecoveryRotation.chain(counting, hostile, Ids.INSTANCE, a.fp, d.fp))
        assertFalse(RecoveryRotation.follows(counting, hostile, Ids.INSTANCE, a.fp, y.fp))
        assertEquals(0, counting.signatureChecks)

        // The signer key is public, so a server can copy it onto statements it cannot sign. Each of those
        // costs one signature check, which fails, and no more: the bound is one check per served frame.
        val forged = (0 until 5).map { k -> ab.copyOf().also { it[60 + k] = (it[60 + k].toInt() xor 0x01).toByte() } }
        val forging = CountingCrypto(crypto)
        assertNull(RecoveryRotation.chain(forging, forged + hostile, Ids.INSTANCE, a.fp, b.fp))
        assertEquals(5, forging.signatureChecks)

        // With the real chain among them: one check per step of the path, and none for the rest.
        val served = hostile.take(80) + cd + hostile.drop(80) + ab + bc
        assertEquals(3, RecoveryRotation.chain(counting, served, Ids.INSTANCE, a.fp, d.fp)?.size)
        assertEquals(3, counting.signatureChecks)

        // The first-consent walk asks about every change and still checks each statement once.
        val walking = CountingCrypto(crypto)
        val ba = rotation(b, a)
        val cards = cardChain(a.fp, b.fp, a.fp, b.fp, a.fp, b.fp, a.fp)
        assertEquals(emptyList<FpChange>(), RecoveryRotation.unsignedChanges(walking, cards, hostile + ab + ba))
        assertEquals(2, walking.signatureChecks)
    }

    // ---- §4.5 first consent ----------------------------------------------------------------------------

    /** The fields of a real, verified card chain whose cards carry [fps] as `recoveryFp` (null: `none`), card 0 first. */
    private fun cardChain(vararg fps: String?): List<CardFields> {
        val frames = ArrayList<ByteArray>()
        var prior: VerifiedCard? = null
        for ((i, fp) in fps.withIndex()) {
            val fields = CardFields(
                Ids.INSTANCE, i.toLong(), prior?.hash ?: TrustGrammar.ZERO_HASH, "https://vault.example.org", "Example", InstanceKind.PRIVATE,
                operator.userId, Bytes.toB64(operator.sign.publicKey), fp, Ids.T0 + i,
            )
            val frame = InstanceCard.sign(crypto, operator.sign, fields)
            prior = assertIs<Checked.Ok<VerifiedCard>>(InstanceCard.verify(crypto, prior?.head, frame)).value
            frames += frame
        }
        val served = InstanceCard.verifyChain(crypto, frames)
        assertTrue(served.complete)
        return served.chain.cards.map { it.fields }
    }

    private fun unsigned(cards: List<CardFields>, vararg rotations: ByteArray): List<FpChange> =
        RecoveryRotation.unsignedChanges(crypto, cards, rotations.toList())

    @Test
    fun firstConsent_everyChangeAlongTheChainNeedsRotationsFromTheOldKeyToTheNew() {
        val ab = rotation(a, b)
        val bc = rotation(b, c)
        val ba = rotation(b, a)
        val covered = emptyList<FpChange>()

        // Nothing to cover: no card, one card, a key that never changed, an instance with no operator recovery.
        assertEquals(covered, unsigned(emptyList(), ab))
        assertEquals(covered, unsigned(cardChain(a.fp)))
        assertEquals(covered, unsigned(cardChain(a.fp, a.fp, a.fp)))
        assertEquals(covered, unsigned(cardChain(null, null), ab))

        // One change and its rotation; the same change without it.
        assertEquals(covered, unsigned(cardChain(a.fp, a.fp, b.fp), ab))
        assertEquals(listOf(FpChange(2, a.fp, b.fp)), unsigned(cardChain(a.fp, a.fp, b.fp)))

        // A card may jump from A to C while the served rotations go A to B and B to C: the chain of them covers it.
        assertEquals(covered, unsigned(cardChain(a.fp, c.fp), bc, ab))
        assertEquals(listOf(FpChange(1, a.fp, c.fp)), unsigned(cardChain(a.fp, c.fp), ab), "the rotations stop at B")
        assertEquals(listOf(FpChange(1, a.fp, c.fp)), unsigned(cardChain(a.fp, c.fp), bc), "nothing leads away from A")

        // Each change is judged alone: a rotation for a later change does not cover an earlier unsigned one.
        assertEquals(listOf(FpChange(1, a.fp, b.fp)), unsigned(cardChain(a.fp, b.fp, c.fp), bc))
        // A key rotated away and back: two changes, each with its own rotation.
        assertEquals(covered, unsigned(cardChain(a.fp, b.fp, a.fp), ab, ba))
        assertEquals(listOf(FpChange(2, b.fp, a.fp)), unsigned(cardChain(a.fp, b.fp, a.fp), ab))

        // A change from or to `none` has no rotation that could cover it: a rotation names two keys.
        assertEquals(listOf(FpChange(1, null, a.fp)), unsigned(cardChain(null, a.fp), ab))
        assertEquals(listOf(FpChange(1, a.fp, null)), unsigned(cardChain(a.fp, null), ab))
        assertEquals(listOf(FpChange(1, a.fp, null), FpChange(2, null, b.fp)), unsigned(cardChain(a.fp, null, b.fp), ab))

        // What does not verify covers nothing: the incoming key's own signature, a rotation for another instance.
        assertEquals(listOf(FpChange(1, a.fp, b.fp)), unsigned(cardChain(a.fp, b.fp), rotationSignedBy(b.sign, a.fp, b.fp), rotation(a, b, Ids.OTHER_INSTANCE)))
    }

    // ---- §2.3, §9.3 the request code -------------------------------------------------------------------

    @Test
    fun requestCode_theTypedCodeIsComparedAfterSpacesDashesAndCaseAreIgnored() {
        val rPub = crypto.boxKeypairFromSeed(ByteArray(32) { (0x60 + it).toByte() }).publicKey
        val code = AssistedRecovery.requestCode(crypto, rPub)
        assertEquals(24, code.length)
        assertTrue(code.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals(Bytes.toHexLower(crypto.sha256(("andvari/v2|recovery-request|code|" + Bytes.toB64(rPub)).encodeToByteArray())).take(24), code)
        val grouped = AssistedRecovery.groupedRequestCode(code)
        assertEquals(code.chunked(4), grouped.split(' '))
        fun matches(typed: String) = AssistedRecovery.requestCodeMatches(crypto, typed, rPub)

        assertTrue(matches(code))
        assertTrue(matches(grouped))
        assertTrue(matches(grouped.uppercase()))
        assertTrue(matches(code.chunked(4).joinToString("-")))
        assertTrue(matches("  " + code.chunked(6).joinToString("\t") + " \t"))
        assertTrue(matches(code.uppercase().chunked(4).joinToString("-")))
        // Spaces, tabs and dashes only; a line break or another white space is no match.
        assertFalse(matches(code + "\n"))
        assertFalse(matches(code + "\r"))
        assertFalse(matches(code.chunked(12).joinToString("\r\n")))
        assertFalse(matches(code + Char(0x0B)))
        // Not the code: a digit short or long, another digit, another character, nothing.
        assertFalse(matches(code.dropLast(1)))
        assertFalse(matches(code + "0"))
        assertFalse(matches(code.dropLast(1) + if (code.last() == '0') '1' else '0'))
        assertFalse(matches(code.chunked(4).joinToString(":")))
        assertFalse(matches(code.dropLast(1) + "g"))
        assertFalse(matches(code + Char(0xA0)), "a no-break space is not ignored")
        assertFalse(matches(""))
        assertFalse(matches("    "))
        // Another request key has another code, and a key of another length has none.
        assertFalse(AssistedRecovery.requestCodeMatches(crypto, grouped, alice.box.publicKey))
        assertFalse(AssistedRecovery.requestCodeMatches(crypto, grouped, rPub.copyOf(31)))
        assertFailsWith<IllegalArgumentException> { AssistedRecovery.requestCode(crypto, rPub.copyOf(31)) }
        assertFailsWith<IllegalArgumentException> { AssistedRecovery.groupedRequestCode(grouped) }
        assertFailsWith<IllegalArgumentException> { AssistedRecovery.groupedRequestCode("ABCDEF".repeat(4)) }
        assertFailsWith<IllegalArgumentException> { AssistedRecovery.groupedRequestCode(code.dropLast(1)) }
    }

    // ---- §9.3 step 4: the assisted-recovery payload ----------------------------------------------------

    private val uvk = ByteArray(32) { (0xA0 + it).toByte() }
    private val requestId = Ids.id16(3)

    /** The requesting device's one-time pair `(rPub, rSec)`. */
    private val request = crypto.boxKeypairFromSeed(ByteArray(32) { (0x60 + it).toByte() })
    private val requestKey = Bytes.toB64(request.publicKey)

    /** What the poll serves beside the seal: [party]'s identity seed under [key] with [userId] in its AD, and its identity key. */
    private fun served(party: Party, key: ByteArray = uvk, userId: String = party.userId): IdentityCheck =
        IdentityCheck(Envelope.sealB64(crypto, key, party.seed, Ad.idkey(userId)), party.key)

    private fun payload(
        userId: String = Ids.ALICE,
        instanceId: String = Ids.INSTANCE,
        id: String = requestId,
        key: String = requestKey,
        delivered: ByteArray = uvk,
    ) = AssistedRecoveryFields(instanceId, userId, id, key, delivered, Ids.T0 + 9)

    private fun sealed(frame: ByteArray): ByteArray = AssistedRecovery.seal(crypto, request.publicKey, frame)

    // A request key that is a low-order point used to reach the provider,
    // whose CryptoException is no refusal a caller can show. Now the key is refused up front: by
    // [AssistedRecovery.requestKeyUsable], which recovery-cli checks when it reads --request-key, and by seal itself,
    // as the caller's contract (IllegalArgumentException, never CryptoException).
    @Test
    fun aLowOrderRequestKey_isRefusedBeforeTheProvider() {
        assertTrue(AssistedRecovery.requestKeyUsable(request.publicKey))
        val frame = AssistedRecovery.sign(crypto, a.sign, payload())
        val points = listOf(
            "00".repeat(32),
            "01" + "00".repeat(31),
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ec" + "ff".repeat(30) + "7f",
            "ed" + "ff".repeat(30) + "7f",
            "ee" + "ff".repeat(30) + "7f",
        ).map { assertNotNull(Bytes.fromHexLower(it)) }
        // Each point as listed, and with the top bit set, which X25519 ignores.
        for (key in points.flatMap { listOf(it, it.copyOf().also { k -> k[31] = (k[31].toInt() or 0x80).toByte() }) }) {
            val hex = Bytes.toHexLower(key)
            assertFalse(AssistedRecovery.requestKeyUsable(key), hex)
            val thrown = assertFails(hex) { AssistedRecovery.seal(crypto, key, frame) }
            assertIs<IllegalArgumentException>(thrown, "$hex: the caller's contract, not the provider's ${thrown::class.simpleName}")
        }
    }

    private fun open(
        sealed: ByteArray,
        recoveryFp: String = a.fp,
        instanceId: String = Ids.INSTANCE,
        id: String = requestId,
        identity: IdentityCheck = served(alice),
        userId: String? = null,
    ) = AssistedRecovery.open(crypto, request.publicKey, request.privateKey, sealed, recoveryFp, instanceId, id, identity, userId)

    @Test
    fun assisted_thePayloadTheRecoveryKeySignedOpensToTheUvk() {
        val frame = AssistedRecovery.sign(crypto, a.sign, payload())
        assertEquals(
            "{\"v\":2,\"purpose\":\"assisted-recovery\",\"instanceId\":\"${Ids.INSTANCE}\",\"userId\":\"${Ids.ALICE}\",\"requestId\":\"$requestId\"," +
                "\"requestKey\":\"$requestKey\",\"uvk\":\"${Bytes.toB64(uvk)}\",\"issuedAt\":${Ids.T0 + 9}}",
            statementOf(frame),
        )
        // A fresh install holds no userId; a device that holds one compares it too.
        val opened = assertIs<Checked.Ok<OpenedAssistedRecovery>>(open(sealed(frame))).value
        assertContentEquals(uvk, opened.uvk)
        assertEquals(Ids.ALICE, opened.userId)
        assertEquals(Ids.T0 + 9, opened.issuedAt)
        assertIs<Checked.Ok<OpenedAssistedRecovery>>(open(sealed(frame), userId = Ids.ALICE))
        // The key handed out is a copy; wipe clears the held one.
        opened.uvk.fill(0)
        assertContentEquals(uvk, opened.uvk)
        opened.wipe()
        assertContentEquals(ByteArray(32), opened.uvk)
    }

    @Test
    fun assisted_eachCheckHasItsVerdict() {
        val good = AssistedRecovery.sign(crypto, a.sign, payload())
        val statement = statementOf(good)
        val other = crypto.boxKeypairFromSeed(ByteArray(32) { 5 })
        fun signed(fields: AssistedRecoveryFields, signer: KeyPairBytes = a.sign) = sealed(AssistedRecovery.sign(crypto, signer, fields))

        // 1. The seal does not open: sealed to another key, or not a sealed box at all.
        assertEquals(RecoveryVerdict.UNOPENABLE, open(AssistedRecovery.seal(crypto, other.publicKey, good)).verdictOrNull())
        assertEquals(RecoveryVerdict.UNOPENABLE, open(ByteArray(0)).verdictOrNull())
        assertEquals(RecoveryVerdict.UNOPENABLE, open(ByteArray(10)).verdictOrNull())
        assertEquals(RecoveryVerdict.UNOPENABLE, open(ByteArray(200)).verdictOrNull())
        assertEquals(RecoveryVerdict.UNOPENABLE, open(good).verdictOrNull(), "the frame itself, never sealed")

        // 2. Not a frame of purpose 0x09, and the strict parse.
        assertEquals(RecoveryVerdict.BAD_FRAME, open(sealed(rotation(a, b))).verdictOrNull(), "a 0x08 frame")
        assertEquals(RecoveryVerdict.BAD_FRAME, open(sealed(good.copyOf(50))).verdictOrNull(), "truncated")
        assertEquals(RecoveryVerdict.BAD_FRAME, open(sealed(ByteArray(2))).verdictOrNull(), "shorter than the magic")
        assertEquals(RecoveryVerdict.UNKNOWN_FORMAT, open(sealed(statement.encodeToByteArray())).verdictOrNull(), "the bare statement")
        fun raw(text: String) = sealed(signedRaw(a.sign, TrustPurpose.ASSISTED_RECOVERY, text))
        assertEquals(RecoveryVerdict.NON_CANONICAL, open(raw(statement.replace("\"v\":2", "\"v\": 2"))).verdictOrNull())
        assertEquals(RecoveryVerdict.NON_CANONICAL, open(raw(statement.replace(requestId, requestKey))).verdictOrNull(), "requestId is a b64_16")
        assertEquals(RecoveryVerdict.BAD_STATEMENT, open(raw(statement.replace("\"v\":2", "\"v\":3"))).verdictOrNull())

        // 3. Signed by anything but the recovery key the pinned card names. A card with `none` names no key.
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(signed(payload(), alice.sign)).verdictOrNull(), "the account's own key")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(signed(payload(), operator.sign)).verdictOrNull(), "the operator account's key")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(signed(payload(), b.sign)).verdictOrNull(), "another recovery seed")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(sealed(good), recoveryFp = b.fp).verdictOrNull(), "the pinned card names another key")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(sealed(good), recoveryFp = TrustGrammar.NONE).verdictOrNull())
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(sealed(good), recoveryFp = a.fp.take(32)).verdictOrNull(), "the short form names nothing")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(sealed(good), recoveryFp = a.fp.uppercase()).verdictOrNull())

        // 4. The signature.
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, open(sealed(flipSignatureBit(good))).verdictOrNull())

        // 5. For another instance, request or request key; for another account only where the device holds one.
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(signed(payload(instanceId = Ids.OTHER_INSTANCE))).verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(signed(payload(id = Ids.id16(4)))).verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(signed(payload(key = Bytes.toB64(other.publicKey)))).verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(sealed(good), instanceId = Ids.OTHER_INSTANCE).verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(sealed(good), id = Ids.id16(4)).verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(sealed(good), userId = Ids.BOB).verdictOrNull())

        // 6. The identity seed does not open under the delivered key, or its key is not the served identityPub.
        val seedEnvelope = served(alice).encryptedIdentitySeedB64
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, open(signed(payload(delivered = ByteArray(32) { 9 }))).verdictOrNull(), "another key delivered")
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, open(sealed(good), identity = served(alice, userId = Ids.BOB)).verdictOrNull(), "a seed bound to another account")
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, open(sealed(good), identity = IdentityCheck(seedEnvelope, bob.key)).verdictOrNull(), "another identityPub served")
        val anotherSeed = Envelope.sealB64(crypto, uvk, bob.seed, Ad.idkey(Ids.ALICE))
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, open(sealed(good), identity = IdentityCheck(anotherSeed, alice.key)).verdictOrNull(), "the seed is another identity")
    }

    @Test
    fun assisted_aFreshInstallIsBoundToTheAccountByTheSeedsAd() {
        // The recovery key really signed bob's UVK for this request key (an opted-in member working with the server).
        val bobUvk = ByteArray(32) { (0x50 + it).toByte() }
        val forBob = sealed(AssistedRecovery.sign(crypto, a.sign, payload(userId = Ids.BOB, delivered = bobUvk)))
        // A device that holds alice's userId refuses it at the request checks.
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(forBob, identity = served(alice), userId = Ids.ALICE).verdictOrNull())
        // A fresh install skips that comparison. Served alice's identity, the seed does not open: its AD names alice, the key is bob's.
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, open(forBob, identity = served(alice)).verdictOrNull())
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, open(forBob, identity = served(alice, key = bobUvk)).verdictOrNull(), "alice's seed re-sealed under bob's key keeps alice's AD")
        // Served bob's own identity it opens, as bob's account: which is why the app shows the delivered account ID before any new password.
        val opened = assertIs<Checked.Ok<OpenedAssistedRecovery>>(open(forBob, identity = served(bob, key = bobUvk))).value
        assertEquals(Ids.BOB, opened.userId)
        assertContentEquals(bobUvk, opened.uvk)
    }

    @Test
    fun assisted_theFirstFailingCheckDecides() {
        val other = crypto.boxKeypairFromSeed(ByteArray(32) { 5 })
        val wrongIdentity = IdentityCheck(served(alice).encryptedIdentitySeedB64, bob.key)
        // The parse before the signer: not canonical AND signed by an account key.
        val notCanonical = statementOf(AssistedRecovery.sign(crypto, a.sign, payload())).replace("\"v\":2", "\"v\": 2")
        assertEquals(RecoveryVerdict.NON_CANONICAL, open(sealed(signedRaw(alice.sign, TrustPurpose.ASSISTED_RECOVERY, notCanonical))).verdictOrNull())
        // The signer before the signature: an account key AND a flipped bit.
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, open(sealed(flipSignatureBit(AssistedRecovery.sign(crypto, alice.sign, payload())))).verdictOrNull())
        // The signature before the request: another request key AND a flipped bit.
        val otherKey = AssistedRecovery.sign(crypto, a.sign, payload(key = Bytes.toB64(other.publicKey)))
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, open(sealed(flipSignatureBit(otherKey))).verdictOrNull())
        // The request before the identity: another request id AND another served identityPub.
        val otherId = AssistedRecovery.sign(crypto, a.sign, payload(id = Ids.id16(4)))
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(sealed(otherId), identity = wrongIdentity).verdictOrNull())
    }

    @Test
    fun assisted_noServedValueMakesTheOpenerThrow() {
        val good = sealed(AssistedRecovery.sign(crypto, a.sign, payload()))
        val seedEnvelope = served(alice).encryptedIdentitySeedB64
        fun identityVerdict(identity: IdentityCheck) = open(good, identity = identity).verdictOrNull()

        // Served values that are not canonical base64url, or not of their length.
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck("not base64 !!", alice.key)))
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck("", alice.key)))
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck(seedEnvelope.dropLast(30), alice.key)))
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck("$seedEnvelope=", alice.key)), "a padded envelope")
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck(seedEnvelope, alice.key + "=")), "a padded key")
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck(seedEnvelope, "")))
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck(seedEnvelope, Bytes.toB64(ByteArray(31)))))
        assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck(seedEnvelope, Bytes.toB64(ByteArray(33)))))
        // An envelope that opens under the delivered key and AD to something that is not a 32-byte seed.
        for (length in listOf(0, 31, 33, 64)) {
            val notASeed = Envelope.sealB64(crypto, uvk, ByteArray(length) { 1 }, Ad.idkey(Ids.ALICE))
            assertEquals(RecoveryVerdict.IDENTITY_MISMATCH, identityVerdict(IdentityCheck(notASeed, alice.key)), "a seed of $length bytes")
        }
        // A request key pair of the wrong size opens nothing.
        val identity = served(alice)
        assertEquals(
            RecoveryVerdict.UNOPENABLE,
            AssistedRecovery.open(crypto, request.publicKey.copyOf(31), request.privateKey, good, a.fp, Ids.INSTANCE, requestId, identity, null).verdictOrNull(),
        )
        assertEquals(
            RecoveryVerdict.UNOPENABLE,
            AssistedRecovery.open(crypto, request.publicKey, ByteArray(0), good, a.fp, Ids.INSTANCE, requestId, identity, null).verdictOrNull(),
        )
        // Expectations that are not even of their type are a mismatch like any other.
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(good, instanceId = "").verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(good, id = "").verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, open(good, userId = "").verdictOrNull())
    }

    @Test
    fun assisted_signAndSealRefuseWhatTheOpenerWouldRefuse() {
        fun sign(fields: AssistedRecoveryFields) = AssistedRecovery.sign(crypto, a.sign, fields)
        assertFailsWith<IllegalArgumentException> { sign(payload(delivered = ByteArray(31))) }
        assertFailsWith<IllegalArgumentException> { sign(payload(delivered = ByteArray(0))) }
        assertFailsWith<IllegalArgumentException> { sign(payload(id = requestKey)) } // a 32-byte value where a b64_16 belongs (FI-B13)
        assertFailsWith<IllegalArgumentException> { sign(payload(key = requestId)) }
        assertFailsWith<IllegalArgumentException> { sign(payload(key = "$requestKey=")) }
        assertFailsWith<IllegalArgumentException> { sign(payload(userId = Ids.INSTANCE.uppercase())) }
        assertFailsWith<IllegalArgumentException> { sign(payload(instanceId = "")) }
        assertFailsWith<IllegalArgumentException> { sign(AssistedRecoveryFields(Ids.INSTANCE, Ids.ALICE, requestId, requestKey, uvk, 0)) }
        assertFailsWith<IllegalArgumentException> { AssistedRecovery.seal(crypto, ByteArray(31), sign(payload())) }
        assertFalse(AssistedRecovery.requestKeyUsable(ByteArray(31)))
        // The fields hold their own copy of the key.
        val key = uvk.copyOf()
        val fields = payload(delivered = key)
        key.fill(0)
        assertContentEquals(uvk, fields.uvk)
    }

    // ---- §9.3 step 2: the veto -------------------------------------------------------------------------

    @Test
    fun veto_theAccountsKeyCancelsARequest_andEachCheckHasItsVerdict() {
        val fields = VetoFields(requestId, Ids.ALICE, Ids.T0 + 3)
        val good = RecoveryVeto.sign(crypto, alice.sign, fields)
        assertEquals("{\"v\":2,\"purpose\":\"recovery-veto\",\"requestId\":\"$requestId\",\"userId\":\"${Ids.ALICE}\",\"issuedAt\":${Ids.T0 + 3}}", statementOf(good))
        fun verify(frame: ByteArray, identityPub: ByteArray = alice.box.publicKey, userId: String = Ids.ALICE, id: String = requestId) =
            RecoveryVeto.verify(crypto, frame, identityPub, userId, id)
        assertEquals(fields, assertIs<Checked.Ok<VetoFields>>(verify(good)).value)

        val statement = statementOf(good)
        assertEquals(RecoveryVerdict.BAD_FRAME, verify(ByteArray(3)).verdictOrNull())
        assertEquals(RecoveryVerdict.UNKNOWN_FORMAT, verify(statement.encodeToByteArray()).verdictOrNull())
        assertEquals(RecoveryVerdict.BAD_FRAME, verify(rotation(a, b)).verdictOrNull(), "a 0x08 frame")
        assertEquals(RecoveryVerdict.NON_CANONICAL, verify(signedRaw(alice.sign, TrustPurpose.RECOVERY_VETO, statement.replace("\"v\":2", "\"v\": 2"))).verdictOrNull())
        assertEquals(RecoveryVerdict.BAD_STATEMENT, verify(signedRaw(alice.sign, TrustPurpose.RECOVERY_VETO, statement.replace("\"v\":2", "\"v\":3"))).verdictOrNull())
        // The signer maps to the identity key the server stores for the session's account.
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, verify(RecoveryVeto.sign(crypto, bob.sign, fields)).verdictOrNull())
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, verify(good, identityPub = bob.box.publicKey).verdictOrNull())
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, verify(good, identityPub = alice.sign.publicKey).verdictOrNull(), "the Ed25519 form is not the stored key")
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, verify(good, identityPub = ByteArray(31)).verdictOrNull())
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, verify(good, identityPub = ByteArray(0)).verdictOrNull())
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, verify(flipSignatureBit(good)).verdictOrNull())
        // Then the account, then the request.
        assertEquals(RecoveryVerdict.USER_MISMATCH, verify(good, userId = Ids.BOB).verdictOrNull())
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, verify(good, id = Ids.id16(4)).verdictOrNull())
        assertEquals(RecoveryVerdict.USER_MISMATCH, verify(good, userId = Ids.BOB, id = Ids.id16(4)).verdictOrNull(), "the account before the request")
        assertEquals(RecoveryVerdict.BAD_SIGNATURE, verify(flipSignatureBit(good), userId = Ids.BOB).verdictOrNull(), "the signature before the account")

        // The builder refuses what the parse would refuse.
        assertFailsWith<IllegalArgumentException> { RecoveryVeto.sign(crypto, alice.sign, VetoFields(requestKey, Ids.ALICE, Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { RecoveryVeto.sign(crypto, alice.sign, VetoFields(requestId, Ids.INSTANCE.uppercase(), Ids.T0)) }
        assertFailsWith<IllegalArgumentException> { RecoveryVeto.sign(crypto, alice.sign, VetoFields(requestId, Ids.ALICE, 0)) }
    }

    // ---- total on noise --------------------------------------------------------------------------------

    @Test
    fun noBytesMakeAVerifierThrow() {
        val rotationFrame = rotation(a, b)
        val identity = served(alice)
        // Every prefix of a real frame, and the same with one byte changed at each position of the header and the statement's start.
        val inputs = ArrayList<ByteArray>()
        for (n in 0..rotationFrame.size) inputs += rotationFrame.copyOf(n)
        for (i in 0 until 140) inputs += rotationFrame.copyOf().also { it[i] = (it[i].toInt() xor 0x41).toByte() }
        inputs += rotationFrame + ByteArray(SignedFrame.MAX_FRAME_BYTES + 1 - rotationFrame.size) { 0x20 }
        for (bytes in inputs) {
            assertFalse(RecoveryRotation.verify(crypto, bytes, Ids.INSTANCE, a.fp).isOk && !bytes.contentEquals(rotationFrame))
            assertFalse(RecoveryVeto.verify(crypto, bytes, alice.box.publicKey, Ids.ALICE, requestId).isOk)
            assertFalse(open(sealed(bytes), identity = identity).isOk)
            assertFalse(open(bytes, identity = identity).isOk)
            RecoveryRotation.follows(crypto, listOf(bytes), Ids.INSTANCE, a.fp, c.fp)
            RecoveryRotation.verifyChain(crypto, listOf(bytes, bytes), Ids.INSTANCE, a.fp, c.fp)
        }
    }
}
