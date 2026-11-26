package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.RecoveryVerdict
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * spec 04 §5, "A copy sealed to an outgoing key": after a signed rotation, an account that has not sealed a new copy has
 * one sealed to the outgoing key, while every device takes only an answer signed by the current one. `assist` opens that
 * copy with the outgoing sheet and signs with the current one, and says so before it asks for any seed. Every seed here
 * is a made-up test seed.
 */
class AssistOutgoingKeyTest {
    private val r = AssistRun()
    private val crypto = r.crypto
    private val current = r.seed
    private val outgoing = crypto.randomBytes(32)
    private val currentFp = Escrow.fingerprint(crypto, r.org.publicKey)
    private val outgoingFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(outgoing).publicKey)

    /** Ann sealed her copy before the rotation and has not unlocked since: it is sealed to the outgoing key. */
    private val ann = Member(crypto, crypto.boxKeypairFromSeed(outgoing).publicKey, "ann@family.example")

    private val t0 = 1_790_000_000_000L
    private val rotatedAt = 1_793_000_000_000L
    private val cardAt = 1_793_000_060_000L

    /** Card 0 names the outgoing key; the rotation is stored, then card 1 names the current key. */
    private fun rotated() = ServedInstance(crypto, r.instanceId).card(outgoing, t0).rotate(outgoing, current, rotatedAt).card(current, cardAt)

    private fun args(m: Member = ann, card0Hash: String? = null) = r.args(
        "--email" to m.email, "--user" to m.userId, "--identity-fp" to m.identityFp.take(32),
        *(if (card0Hash != null) arrayOf("--instance-file" to "instance.json", "--card0-hash" to card0Hash) else emptyArray<Pair<String, String>>()),
    )

    /**
     * The hash of the first card of the server each test builds, as the operator holds it (here taken from that test's own
     * server, which is the genuine one in these tests; `InstanceAnchorTest` is about a file that is not).
     */
    private fun card0Of(instance: ByteArray): String = runCatching {
        val first = (kotlinx.serialization.json.Json.parseToJsonElement(instance.decodeToString()) as kotlinx.serialization.json.JsonObject)["cards"]
            .let { it as kotlinx.serialization.json.JsonArray }.first().let { (it as kotlinx.serialization.json.JsonPrimitive).content }
        io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, Bytes.fromB64(first))
    }.getOrDefault("ab".repeat(32))

    private fun runWith(instance: ByteArray?, seeds: List<ByteArray>, m: Member = ann): AssistRun.Seen {
        r.download = m.download
        instance?.let { r.files["instance.json"] = it }
        r.seedLines = seeds.map { Bytes.toB64(it) }
        return r.run(args(m, instance?.let { card0Of(it) }), typed = listOf("RECOVER ${m.userId.take(8)}"))
    }

    private fun answerOf(seen: AssistRun.Seen, m: Member = ann): ByteArray =
        Bytes.fromB64(assertIs<AnswerRead.Ok>(AnswerToken.read(seen.out.toString(), r.requestId, r.rPub, m.email), seen.toString()).sealed)

    /** A device pinned to the card that names [fp] opens the answer, or says why not. */
    private fun device(sealed: ByteArray, fp: String, m: Member = ann) =
        AssistedRecovery.openV3(crypto, r.request.publicKey, r.request.privateKey, sealed, fp, r.instanceId, r.requestId, m.email, m.check, null)

    private fun nothingAskedOrProduced(seen: AssistRun.Seen, name: String) {
        assertEquals(1, seen.status, seen.toString())
        assertTrue(seen.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED ($name)"), seen.toString())
        assertEquals(0, seen.secretsAsked, "no seed is asked for after a refusal of the file: $seen")
        assertEquals(0, seen.linesAsked, seen.toString())
        assertEquals("Request code matches the request key.\n", seen.out.toString(), seen.toString())
    }

    @Test
    fun withoutTheFile_theCurrentSheetCannotOpenTheCopy_andTheOutgoingSheetsAnswerIsRefusedByEveryDevice() {
        // What the tool did before, and still does without --instance-file.
        val one = runWith(null, listOf(current))
        assertEquals(1, one.status, one.toString())
        val refusal = one.err.lines().last { it.isNotEmpty() }
        assertTrue(refusal.startsWith("REFUSED (unopenable)"), refusal)
        assertTrue("--instance-file" in refusal && "both the current and the outgoing sheet" in refusal, "it now says what to do: $refusal")
        // The file is read only against the server's first card (or unchecked), so the hint names both things to give.
        assertTrue("--card0-hash" in refusal, "it names the card 0 hash the file is checked against: $refusal")
        val other = runWith(null, listOf(outgoing))
        assertEquals(0, other.status, other.toString())
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, device(answerOf(other), currentFp).verdictOrNull())
    }

    @Test
    fun aCopyOnTheOutgoingKey_isOpenedWithTheOutgoingSheet_signedWithTheCurrentOne_andTheDeviceTakesIt() {
        val seen = runWith(rotated().json(), listOf(current, outgoing))
        assertEquals(0, seen.status, seen.toString())
        assertEquals(2, seen.secretsAsked, seen.toString())
        // Said before anything is asked: which sheet signs, which one opens, each by its fingerprint, and since when.
        val firstAsk = seen.events.indexOfFirst { it.startsWith("ask: ") }
        val before = seen.events.take(firstAsk).joinToString("\n")
        assertTrue("CURRENT sheet:  ${KeyHistory.short(currentFp)}, since ${KeyHistory.date(cardAt)}" in before, before)
        assertTrue("OUTGOING sheet: ${KeyHistory.short(outgoingFp)}, outgoing since ${KeyHistory.date(cardAt)}" in before, before)
        // Each seed is asked for by its sheet's name.
        assertTrue(seen.prompts[0].contains("CURRENT sheet (${KeyHistory.short(currentFp)})"), seen.prompts[0])
        assertTrue(seen.prompts[1].contains("OUTGOING sheet (${KeyHistory.short(outgoingFp)}, outgoing since"), seen.prompts[1])
        assertTrue(seen.err.contains("the answer is signed with the CURRENT sheet"), seen.toString())
        // The device pinned to the current card takes it; one pinned to the old card does not.
        val sealed = answerOf(seen)
        val opened = device(sealed, currentFp).valueOrNull()
        assertContentEquals(ann.uvk, opened!!.uvk, seen.toString())
        assertEquals(RecoveryVerdict.SIGNER_NOT_PINNED_KEY, device(sealed, outgoingFp).verdictOrNull())
        for (s in listOf(current, outgoing)) assertTrue(Bytes.toB64(s) !in seen.err && Bytes.toB64(s) !in seen.out, "no seed is printed")
    }

    @Test
    fun aCopyOnTheCurrentKey_needsOneSeed_evenWithTheFile() {
        val seen = runWith(rotated().json(), listOf(current), m = r.member)
        assertEquals(0, seen.status, seen.toString())
        assertEquals(1, seen.secretsAsked, "the outgoing sheet is never asked for: $seen")
        assertTrue(seen.err.contains("The outgoing sheet is not needed."), seen.toString())
        assertContentEquals(r.member.uvk, device(answerOf(seen, r.member), currentFp, r.member).valueOrNull()!!.uvk)
    }

    @Test
    fun anUnchangedKey_isOneSheet_andTheSheetMustBeIt() {
        val once = ServedInstance(crypto, r.instanceId).card(current, t0)
        val ok = runWith(once.json(), listOf(current), m = r.member)
        assertEquals(0, ok.status, ok.toString())
        assertTrue(ok.err.contains("it has not changed (by --instance-file, checked here from its first card, whose hash you gave). You need that one sheet."), ok.toString())
        val wrong = runWith(once.json(), listOf(outgoing), m = r.member)
        assertEquals(1, wrong.status)
        assertTrue(wrong.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED (wrong_sheet)"), wrong.toString())
    }

    @Test
    fun theWrongSheet_atEitherPrompt_isRefused_andNothingElseIsAsked() {
        val atCurrent = runWith(rotated().json(), listOf(outgoing, outgoing))
        assertEquals(1, atCurrent.status)
        assertTrue(atCurrent.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED (wrong_sheet): the seed you pasted is the sheet ${KeyHistory.short(outgoingFp)}, not the CURRENT sheet"), atCurrent.toString())
        assertEquals(1, atCurrent.secretsAsked)
        assertEquals(0, atCurrent.linesAsked)
        val atOutgoing = runWith(rotated().json(), listOf(current, current))
        assertEquals(1, atOutgoing.status)
        assertTrue(atOutgoing.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED (wrong_sheet)"), atOutgoing.toString())
        assertEquals(2, atOutgoing.secretsAsked)
        assertEquals(0, atOutgoing.linesAsked)
        for (s in listOf(atCurrent, atOutgoing)) assertEquals("Request code matches the request key.\n", s.out.toString())
    }

    @Test
    fun aCopySealedToAKeyTheHistoryDoesNotShow_isUnopenable_afterBothSheets() {
        val stranger = Member(crypto, crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey, "ann@family.example")
        val seen = runWith(rotated().json(), listOf(current, outgoing), m = stranger)
        assertEquals(1, seen.status)
        assertTrue(seen.err.lines().last { it.isNotEmpty() }.startsWith("REFUSED (unopenable): this copy opens with neither the current sheet nor any outgoing sheet"), seen.toString())
        assertEquals(0, seen.linesAsked)
    }

    @Test
    fun theFile_isCheckedBeforeAnySeed_eachRefusalByItsName() {
        val other = "22345678-1234-4234-8234-123456789abc"
        val stray = crypto.randomBytes(32)
        val badSignature = rotated().also { val f = it.rotations[0]; f[40] = (f[40] + 1).toByte() }
        val cases = listOf(
            "bad_instance_file" to "not json".encodeToByteArray(),
            "bad_instance_file" to byteArrayOf(0x7B, 0xFF.toByte(), 0x7D),
            "bad_instance_file" to """{"cards":[]}""".encodeToByteArray(),
            "bad_instance_file" to """{"cards":["a b"],"rotations":[]}""".encodeToByteArray(),
            "bad_card_chain" to """{"cards":[],"rotations":[]}""".encodeToByteArray(),
            "bad_card_chain" to rotated().also { it.cards.removeAt(0) }.json(),
            "instance_mismatch" to ServedInstance(crypto, other).card(outgoing, t0).json(),
            "no_recovery_key" to ServedInstance(crypto, r.instanceId).card(outgoing, t0).card(null, cardAt).json(),
            // A rotation for another server, a link that does not verify (its signer, its signature), a chain that does not connect.
            "instance_mismatch" to ServedInstance(crypto, r.instanceId).card(outgoing, t0).rotate(outgoing, current, rotatedAt, forInstance = other).card(current, cardAt).json(),
            "rotation_not_verified" to ServedInstance(crypto, r.instanceId).card(outgoing, t0).rotate(outgoing, current, rotatedAt, signer = stray).card(current, cardAt).json(),
            "rotation_not_verified" to badSignature.json(),
            "rotation_chain_broken" to ServedInstance(crypto, r.instanceId).card(outgoing, t0).card(current, cardAt).json(),
            "rotation_chain_broken" to rotated().rotate(stray, current, rotatedAt).json(),
        )
        for ((name, file) in cases) nothingAskedOrProduced(runWith(file, listOf(current, outgoing)), name)
        // Other fields beside the two lists are ignored, as the server's own may grow.
        assertEquals(0, runWith(rotated().json(""","setup":null,"x":1"""), listOf(current, outgoing)).status)
    }

    @Test
    fun aStoredRotationWithNoCardYet_isSaid_andTheOldKeyIsStillTheOneThatSigns() {
        // The rotation is stored but the card not signed yet: devices still take only the outgoing key, which is current here.
        val half = ServedInstance(crypto, r.instanceId).card(outgoing, t0).rotate(outgoing, current, rotatedAt)
        val seen = runWith(half.json(), listOf(outgoing))
        assertEquals(0, seen.status, seen.toString())
        assertTrue(seen.err.contains("A rotation to ${KeyHistory.short(currentFp)} is stored, but no card names that key yet"), seen.toString())
        assertContentEquals(ann.uvk, device(answerOf(seen), outgoingFp).valueOrNull()!!.uvk)
    }
}
