package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.OperatorApi
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Assisted recovery through the console, walked against a local server with this tree's builds.
 * `recovery-cli assist` prints its answer after four lines of its own; its help suggests `assist … > answer.txt`, and
 * `andvari-cli operator fulfil --sealed-file` reads the last line of that file. The console sent the whole file (trimmed),
 * which the shared code then refused as "the request is in its hold, cancelled or gone". And the server stores whatever
 * base64 it is given, once: an answer cut short or not for this request was stored, and the person's device stopped the
 * request as unopenable after the hold. The console now checks the answer and sends only the answer.
 */
class AssistAnswerTest {
    private val crypto = createCryptoProvider()
    private val requestId = "x_e_no79jN8HmxjZMG_TjQ"
    private val email = "bo@family.example"
    private val requestKey = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
    private val row = AdminRecoveryRequest(requestId, UUID.randomUUID().toString(), email, "0".repeat(32), Bytes.toB64(requestKey), "android", 1, 1, 1)

    /** A real version-3 answer of the shared code's own making, signed by a recovery key and sealed to [key], as its token. */
    private fun realToken(issuedAt: Long = 1_794_858_966_854L, request: String = requestId, key: ByteArray = requestKey, address: String = email): String {
        val signer = crypto.signKeypairFromSeed(crypto.randomBytes(32))
        val commit = crypto.randomBytes(32)
        val fields = AssistedRecoveryFields(UUID.randomUUID().toString(), UUID.randomUUID().toString(), request, Bytes.toB64(key), crypto.randomBytes(32), issuedAt,
            email = address, commit = commit)
        return AnswerToken.format(request, Bytes.toB64(key), AssistedRecovery.commitHash(crypto, commit), AssistedRecovery.seal(crypto, key, AssistedRecovery.sign(crypto, signer, fields)))
    }

    /** What `recovery-cli assist` writes to standard output: lines of its own, then the token as the last line. */
    private fun toolOutput(token: String, request: String = requestId) = "\n" +
        "ANSWER for request $request (account 55e39bb3-ab15-4441-a07a-c016ca964e9d, address $email):\n" +
        "It is signed by the recovery key and sealed to the person's device; only that device can open it, and only\n" +
        "that device can then finish: the server takes the new password only with the value inside the answer.\n" +
        "Give the console, or andvari-cli operator fulfil, the whole last line below (the console also takes this whole output):\n\n" +
        token + "\n"

    private fun sealedOf(token: String) = token.substringAfterLast(':')

    private fun refused(text: String): AssistAnswer.Refused = assertIs<AssistAnswer.Refused>(AssistAnswer.read(text, row), text.take(60))

    @Test
    fun theSizeOfAnAnswerIsTheSharedCodesOwnForTheRequestsAddress() {
        for (at in listOf(1_000_000_000_000L, 1_794_858_966_854L, 9_999_999_999_999L)) {
            assertEquals(AnswerToken.sealedBytes(email), Bytes.fromB64(sealedOf(realToken(at))).size)
        }
        assertEquals(525 + 23, AnswerToken.sealedBytes(email), "17 octets: 23 characters of base64url")
        assertEquals(525 + 26, Bytes.fromB64(sealedOf(realToken(address = "bobb@family.example"))).size, "19 octets: 26 characters")
    }

    @Test
    fun theToolsWholeOutputAndTheTokenAloneAreAccepted_andTheTokenIsWhatIsKept() {
        val token = realToken()
        val fromFile = assertIs<AssistAnswer.Ok>(AssistAnswer.read(toolOutput(token), row))
        assertEquals(token, fromFile.sealed)
        assertEquals(toolOutput(token).trim().lines().last(), fromFile.sealed, "what andvari-cli operator fulfil sends")
        // Windows line ends and a byte-order mark change nothing.
        assertEquals(token, assertIs<AssistAnswer.Ok>(AssistAnswer.read("\uFEFF" + toolOutput(token).replace("\n", "\r\n"), row)).sealed)
        // Pasted alone, with the white space a terminal copy brings; or wrapped by a terminal after its prefix.
        assertEquals(token, assertIs<AssistAnswer.Ok>(AssistAnswer.read("  $token \n", row)).sealed)
        // An 80-column terminal breaks the token inside its head (the request key, the commit hash) as well as its sealed part.
        val wrapped = token.chunked(80).joinToString("\n")
        assertEquals(token, assertIs<AssistAnswer.Ok>(AssistAnswer.read(wrapped, row)).sealed)
    }

    @Test
    fun whatIsNotThisRequestsAnswerIsRefusedWithWhatIsWrong() {
        val token = realToken()
        val sealed = sealedOf(token)
        val head = token.removeSuffix(sealed)
        assertEquals(Placeholder.OP_FULFIL_EMPTY, refused("").why)
        assertEquals(Placeholder.OP_FULFIL_EMPTY, refused(" \n\r\n ").why)
        val copy = """{"userId":"55e39bb3-ab15-4441-a07a-c016ca964e9d","sealed":"abc","encryptedIdentitySeed":"def","identityPub":"ghi"}"""
        assertEquals(Placeholder.OP_ANSWER_IS_THE_COPY, refused(copy).why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused("""{"something":"else"}""").why)
        // A bare sealed answer (the old tool's last line, or the token's tail) is refused, with its own sentence.
        assertEquals(Placeholder.OP_ANSWER_BARE, refused(sealed).why)
        assertEquals(Placeholder.OP_ANSWER_BARE, refused("  $sealed \n").why)
        // Another request's token, and a token for this request's id with another request key: each its own sentence.
        val other = refused(toolOutput(realToken(request = "LKA7FFt_fU7u4CUTCDCTMA"), "LKA7FFt_fU7u4CUTCDCTMA"))
        assertEquals(Placeholder.OP_ANSWER_OTHER_REQUEST, other.why)
        assertEquals("LKA7FFt_fU7u4CUTCDCTMA", other.request)
        val otherKey = refused(realToken(key = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey))
        assertEquals(Placeholder.OP_ANSWER_OTHER_KEY, otherKey.why)
        assertNull(otherKey.request)
        // Cut: the token alone, the file cut inside the sealed part, and the file cut before the token.
        assertEquals(Placeholder.OP_ANSWER_CUT_SHORT, refused(head + sealed.take(sealed.length / 2)).why)
        assertEquals(Placeholder.OP_ANSWER_CUT_SHORT, refused(toolOutput(token).let { it.take(it.length - sealed.length / 2) }).why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused(toolOutput(token).substringBefore("andvari-answer:")).why)
        // A token made for another address has another size; longer: two sealed parts run together, a password typed after it.
        assertEquals(Placeholder.OP_ANSWER_TOO_LONG, refused(realToken(address = "bobby@family.example")).why)
        assertEquals(Placeholder.OP_ANSWER_TOO_LONG, refused(token + sealedOf(realToken())).why)
        assertEquals(Placeholder.OP_ANSWER_TOO_LONG, refused(token + "x79M5XarZolWcidPZfvMiW5dAYOIunyBSn_8JuX4TU0").why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused("$token correct horse battery").why)
        // One character off the alphabet, padding, a seventh part, two tokens: not an answer.
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused(token.dropLast(1) + "+").why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused("$token=").why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused("$token:AAAA").why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused(token.replace("andvari-answer:3:", "andvari-answer:2:")).why)
        assertEquals(Placeholder.OP_ANSWER_NOT_ONE, refused(toolOutput(token) + toolOutput(token)).why)
    }

    // ---- the console: only a checked answer is sent, and only the answer ----

    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    /** The fake, with what the console hands the shared code to upload recorded. */
    private class Recording(val fake: FakeDesktopAppApi) : DesktopAppApi by fake {
        val sent = ArrayList<String>()

        /** When set, what core answers every upload (after recording it), in place of the fake's own answer. */
        var answer: OperatorResult? = null
        override val operatorApi: OperatorApi = object : OperatorApi by fake.operatorApi {
            override suspend fun fulfilRecovery(requestId: String, sealedAnswer: String, password: String): OperatorResult {
                sent += sealedAnswer
                return answer ?: fake.operatorApi.fulfilRecovery(requestId, sealedAnswer, password)
            }
        }
    }

    @Test
    fun theConsoleSendsOnlyTheAnswerFromTheToolsOutputAndNothingForAWrongOne() {
        val api = Recording(FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE))
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        val op = m.operator
        val request = assertNotNull(api.fake.script.someoneAsksOperator(AppPlatform.ANDROID))
        request.stage = OperatorHelpStage.AWAITING_OPERATOR
        op.refresh()
        val listed = assertNotNull(api.operatorApi.console).recoveryRequests.single()
        val id = listed.requestId
        // The console never opens the seal: a token for the listed request, its key and its address.
        val answer = realToken(request = id, key = Bytes.fromB64(listed.rPub), address = listed.email)
        val sealed = sealedOf(answer)

        // Every wrong answer: said beside the request, nothing sent, the request still on the list.
        val wrong = mapOf(
            "" to Placeholder.OP_FULFIL_EMPTY,
            answer.removeSuffix(sealed) + sealed.take(sealed.length / 2) to Placeholder.OP_ANSWER_CUT_SHORT,
            sealed to Placeholder.OP_ANSWER_BARE,
            toolOutput(realToken(request = "LKA7FFt_fU7u4CUTCDCTMA"), "LKA7FFt_fU7u4CUTCDCTMA") to Placeholder.OP_ANSWER_OTHER_REQUEST,
            """{"userId":"u","encryptedIdentitySeed":"s"}""" to Placeholder.OP_ANSWER_IS_THE_COPY,
            "B".repeat(60_000) to Placeholder.OP_ANSWER_BARE,
            "copy this" to Placeholder.OP_ANSWER_NOT_ONE,
        )
        for ((text, why) in wrong) {
            assertNull(op.fulfil(id, text, pw), text.take(40))
            val said = assertIs<UiText.Ph>(assertNotNull(op.answerAt(OperatorModel.Area.REQUESTS, id)).text)
            assertEquals(why, said.placeholder, text.take(40))
        }
        assertTrue(api.sent.isEmpty(), "nothing was sent")
        assertFalse(request.fulfilled)
        assertEquals(id, assertNotNull(api.operatorApi.console).recoveryRequests.single().requestId)

        // The tool's whole output, as read from its file: only its token goes, as andvari-cli operator fulfil sends it.
        op.fulfil(id, toolOutput(answer, id), pw)
        assertEquals(listOf(answer), api.sent)
        assertTrue(request.fulfilled)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun thePasswordHasItsOwnStepAfterTheAnswerIsCheckedAndTheAnswerFieldDoesNotGrow() {
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        val step = screens.substringAfter("private fun FulfilStep(").substringBefore("\n}\n")
        val answerStep = step.substringAfter("if (ok == null) {").substringBefore("} else {")
        val passwordStep = step.substringAfter("} else {")
        assertTrue(answerStep.contains("maxLines = 3"), "the answer's field keeps its height")
        assertFalse(answerStep.contains("MasterPasswordField"), "no password while the answer is being given")
        assertTrue(answerStep.contains("op.checkAnswer("))
        assertTrue(passwordStep.contains("MasterPasswordField"))
        assertFalse(passwordStep.contains("Field(UiText.ph(Placeholder.OP_FULFIL_ANSWER)"), "the answer is not editable beside the password")
        // A file is never trimmed into the answer by the screen: the model's check decides what is sent.
        assertFalse(step.contains(".trim()"))
    }

    /** Found in a walk: a file too large to read left the earlier answer in the field under "this is longer". */
    @Test
    fun aFileThatIsNotReadLeavesNoEarlierAnswerOnShow() {
        val step = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun FulfilStep(").substringBefore("\n}\n")
        for (branch in listOf("is PickedFiles.Picked.TooLarge ->", "else -> {")) {
            val body = step.substringAfter(branch).substringBefore("\n")
            assertTrue(body.contains("answer = \"\""), branch)
        }
    }

    // ---- the console after the assisted-recovery change ----

    /** A console on the fake with one request past its hold, as listed; [result] stands in for what core answers an upload. */
    private fun waitingRequest(result: OperatorResult? = null): Triple<Recording, TrustModel, AdminRecoveryRequest> {
        val fake = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val api = Recording(fake).also { it.answer = result }
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        assertNotNull(fake.script.someoneAsksOperator(AppPlatform.ANDROID)).stage = OperatorHelpStage.AWAITING_OPERATOR
        m.operator.refresh()
        return Triple(api, m, assertNotNull(api.operatorApi.console).recoveryRequests.single())
    }

    private fun saidAt(m: TrustModel, id: String): Placeholder =
        assertIs<UiText.Ph>(assertNotNull(m.operator.answerAt(OperatorModel.Area.REQUESTS, id)).text).placeholder

    /** Each of the shared reader's eight refusals has its own sentence, here and for core's result of the same refusal. */
    @Test
    fun eachOfTheEightRefusalsHasItsOwnSentence() {
        val refusals = io.silencelen.andvari.core.trust.AnswerRefusal.entries
        assertEquals(8, refusals.size)
        val sentences = refusals.map { AssistAnswer.words(it) }
        assertEquals(8, sentences.toSet().size, "$sentences")
        for (r in refusals) {
            val result = OperatorResult.of(r)
            assertEquals(AssistAnswer.words(r), AssistAnswer.words(result))
            // Core reads the answer again before it sends: its result is said in the same words, never as "trouble".
            assertEquals(AssistAnswer.words(r), assertIs<UiText.Ph>(assertNotNull(operatorWords(result, 0))).placeholder, "$r")
        }
        // The sentences asked for: the whole last line, copy only the last line, and
        // both possibilities for a wrong size.
        assertTrue(Placeholder.OP_ANSWER_BARE.gloss.contains("whole last line"))
        assertTrue(Placeholder.OP_ANSWER_NOT_ONE.gloss.contains("only the last line"))
        for (p in listOf(Placeholder.OP_ANSWER_CUT_SHORT, Placeholder.OP_ANSWER_TOO_LONG)) {
            assertTrue(p.gloss.contains("damaged") && p.gloss.contains("made for another address"), p.name)
        }
        assertTrue(Placeholder.OP_ANSWER_CUT_SHORT.gloss.contains("cut"))
        // Each one reached by the reader through the console's caller, from text a person might give.
        val token = realToken()
        val sealed = sealedOf(token)
        val reached = mapOf(
            " " to AnswerRefusalWords.EMPTY,
            """{"userId":"u","sealed":"a","encryptedIdentitySeed":"s","identityPub":"p"}""" to AnswerRefusalWords.IS_THE_COPY,
            "copy this" to AnswerRefusalWords.NOT_AN_ANSWER,
            sealed to AnswerRefusalWords.BARE,
            realToken(request = "LKA7FFt_fU7u4CUTCDCTMA") to AnswerRefusalWords.OTHER_REQUEST,
            realToken(key = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey) to AnswerRefusalWords.OTHER_REQUEST_KEY,
            token.removeSuffix(sealed) + sealed.take(sealed.length - 8) to AnswerRefusalWords.CUT_SHORT,
            realToken(address = "bobby@family.example") to AnswerRefusalWords.TOO_LONG,
        )
        for ((text, which) in reached) assertEquals(which.words, refused(text).why, text.take(40))
        assertEquals(refusals.toSet(), reached.values.map { it.refusal }.toSet(), "all eight reached")
    }

    private enum class AnswerRefusalWords(val refusal: io.silencelen.andvari.core.trust.AnswerRefusal) {
        EMPTY(io.silencelen.andvari.core.trust.AnswerRefusal.EMPTY), IS_THE_COPY(io.silencelen.andvari.core.trust.AnswerRefusal.IS_THE_COPY),
        NOT_AN_ANSWER(io.silencelen.andvari.core.trust.AnswerRefusal.NOT_AN_ANSWER), BARE(io.silencelen.andvari.core.trust.AnswerRefusal.BARE),
        OTHER_REQUEST(io.silencelen.andvari.core.trust.AnswerRefusal.OTHER_REQUEST), OTHER_REQUEST_KEY(io.silencelen.andvari.core.trust.AnswerRefusal.OTHER_REQUEST_KEY),
        CUT_SHORT(io.silencelen.andvari.core.trust.AnswerRefusal.CUT_SHORT), TOO_LONG(io.silencelen.andvari.core.trust.AnswerRefusal.TOO_LONG);

        val words: Placeholder get() = AssistAnswer.words(refusal)
    }

    /** The server's `request_key_mismatch` (core's ANSWER_OTHER_REQUEST_KEY) is said beside the request in the reader's own sentence. */
    @Test
    fun anUploadCoreRefusesAsAnAnswerForAnotherKeyIsSaidInThatSentence() {
        val (api, m, listed) = waitingRequest(OperatorResult.ANSWER_OTHER_REQUEST_KEY)
        val answer = realToken(request = listed.requestId, key = Bytes.fromB64(listed.rPub), address = listed.email)
        m.operator.fulfil(listed.requestId, answer, pw)
        assertEquals(listOf(answer), api.sent)
        assertEquals(Placeholder.OP_ANSWER_OTHER_KEY, saidAt(m, listed.requestId))
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    /**
     * A file is read by the shared reader's own file function, strictly. Bytes that are not UTF-8 are
     * refused even where the reader would pass over that line (before the token), which a lenient decode let through; the
     * bytes are wiped; and what passes goes to the password step without its content on screen.
     */
    @Test
    fun aFileIsReadStrictlyItsBytesAreWipedAndItsContentIsNeverShown() {
        val (api, m, listed) = waitingRequest()
        val op = m.operator
        val answer = realToken(request = listed.requestId, key = Bytes.fromB64(listed.rPub), address = listed.email)
        val chosen = assertNotNull(op.chooseFulfil(listed.requestId))

        val notText = byteArrayOf(0xC3.toByte(), 0x28, '\n'.code.toByte()) + answer.encodeToByteArray()
        assertIs<AssistAnswer.Ok>(AssistAnswer.read(String(notText, Charsets.UTF_8), listed), "a lenient decode passes it")
        assertNull(op.checkAnswerFile(listed.requestId, notText))
        // Said in a sentence for a file, not the paste's (found in the run).
        assertEquals(Placeholder.OP_ANSWER_FILE_NOT_TEXT, saidAt(m, listed.requestId))
        assertTrue(notText.all { it == 0.toByte() }, "the file's bytes are wiped")

        val file = toolOutput(answer, listed.requestId).encodeToByteArray()
        val ok = assertNotNull(op.checkAnswerFile(listed.requestId, file))
        assertTrue(file.all { it == 0.toByte() })
        val step = assertNotNull(op.fulfilStep(chosen, ok.sealed, ok, fromFile = true))
        val lines = step.lines.map { assertIs<UiText.Ph>(it.text).placeholder }
        assertEquals(listOf(Placeholder.OP_FULFIL_FILE_READ, Placeholder.OP_FULFIL_CHECKED), lines)
        val onShow = (step.lines.map { it.text.shown() } + step.values.map { it.value.shown() }).joinToString("\n")
        assertFalse(onShow.contains(sealedOf(answer).take(20)), "nothing of the file is on show")
        assertNotNull(op.confirm(step, pw))
        assertEquals(listOf(answer), api.sent)
        assertTrue(crashes.isEmpty(), "$crashes")

        // The screen: the picked file goes to the model's check as bytes, never into the field, never decoded there.
        val screen = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun FulfilStep(").substringBefore("\n}\n")
        val picked = screen.substringAfter("is PickedFiles.Picked.Read -> {").substringBefore("\n                        }")
        assertTrue(picked.contains("op.checkAnswerFile(requestId, read.bytes)"), picked)
        assertTrue(picked.contains("answer = \"\""))
        for (decode in listOf("toString(", "decodeToString", "String(")) assertFalse(picked.contains(decode), decode)
    }

    /** The console claims only what it checked, offers nothing of the server's to check a person against, and says whose word the address is. */
    @Test
    fun theConsoleClaimsOnlyWhatItCheckedAndOffersNothingOfTheServerToCheckAgainst() {
        for (p in Placeholder.entries.filter { it.name.startsWith("OP_") }) {
            val g = p.gloss.lowercase()
            assertFalse(g.contains("assist made") || g.contains("made this answer") || g.contains("from recovery-cli assist"), "${p.name}: $g")
            if (g.contains("account id")) assertFalse(g.contains("copy") || g.contains("paste") || g.contains("type "), "${p.name}: $g")
        }
        assertFalse(Placeholder.entries.any { it.name == "OP_FULFIL_CHECKED_NAMED" })
        assertEquals(listOf(requestId, row.rPub), requestValues(row).map { it.second }, "only the request's id and key are offered to copy")
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        val section = screens.substringAfter("private fun RequestRows(").substringBefore("\n}\n")
        assertFalse(section.contains("accountId") || section.contains("userId"), "nothing of the account's identity is drawn")
        // Beside the address on show: whose word it is, and that the tool asks for the person's address.
        assertTrue(section.substringAfter("OneLine(r.email").substringBefore("requestState(r)").contains("Placeholder.OP_REQUEST_ADDRESS_SAID"))
        val step = screens.substringAfter("private fun FulfilStep(").substringBefore("\n}\n").substringBefore("} else {")
        assertTrue(step.substringAfter("StepValues(chosen.values)").substringBefore("Field(").contains("Placeholder.OP_REQUEST_ADDRESS_SAID"))
        assertTrue(Placeholder.OP_REQUEST_ADDRESS_SAID.gloss.contains("the server says") && Placeholder.OP_REQUEST_ADDRESS_SAID.gloss.contains("own knowledge"))
    }

    /**
     * A request's row says whether it was answered, from the closed list of states only; an answered one can be answered
     * again, says that the newer upload replaces the older, and its step says so too. (The fake lists no state yet: the
     * mapping and the drawing are pinned here; asked of core.)
     */
    @Test
    fun aRowSaysWhetherItWasAnsweredAndAnAnsweredOneCanBeAnsweredAgain() {
        fun at(state: String?) = requestState(row.copy(state = state))
        assertEquals(RequestState.HOLDING, at("holding"))
        assertEquals(RequestState.WAITING, at("awaiting_operator"))
        assertEquals(RequestState.ANSWERED, at("ready"))
        for (other in listOf(null, "", "READY", "ready ", "vetoed", "\u202Eready")) assertEquals(RequestState.NOT_GIVEN, at(other), "$other")
        assertEquals(4, RequestState.entries.map { it.words }.toSet().size)
        assertTrue(Placeholder.OP_REQUEST_STATE_READY.gloss.contains("newer upload replaces the older"))
        assertTrue(Placeholder.OP_FULFIL_AGAIN.gloss.contains("replaces"))

        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        val section = screens.substringAfter("private fun RequestRows(").substringBefore("\n}\n")
        assertTrue(section.contains("Say(state.words"))
        assertTrue(section.contains("again = state == RequestState.ANSWERED"))
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText()
        assertTrue(model.substringAfter("fun chooseFulfil(").substringBefore("\n    }\n").contains("answered = requestState(r) == RequestState.ANSWERED"))
        assertTrue(model.substringAfter("internal fun fulfilStep(").substringBefore("\n    }\n").contains("if (chosen.answered) listOf(StepLine(UiText.ph(Placeholder.OP_FULFIL_REPLACES)"))

        // Answered once, the request is answered again through the same step (the server replaces the older answer).
        val (api, m, listed) = waitingRequest()
        val first = realToken(request = listed.requestId, key = Bytes.fromB64(listed.rPub), address = listed.email)
        m.operator.fulfil(listed.requestId, first, pw)
        assertEquals(Placeholder.OP_FULFILLED, assertIs<UiText.Ph>(assertNotNull(m.operator.answerAt(OperatorModel.Area.REQUESTS)).text).placeholder)
        val again = assertNotNull(assertNotNull(api.operatorApi.console).recoveryRequests.singleOrNull { it.requestId == listed.requestId }, "still listed")
        val second = realToken(request = again.requestId, key = Bytes.fromB64(again.rPub), address = again.email)
        val chosen = assertNotNull(m.operator.chooseFulfil(again.requestId))
        assertNotNull(m.operator.checkFulfil(chosen, second))
        assertTrue(crashes.isEmpty(), "$crashes")
    }
}
