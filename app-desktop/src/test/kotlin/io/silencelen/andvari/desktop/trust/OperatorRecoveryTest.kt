package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Requests for the operator's help, fulfilled for a request on show; the recovery copy, handed over once. */
class OperatorRecoveryTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    private fun console(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun ph(a: OperatorModel.Answer?): Placeholder = assertIs<UiText.Ph>(assertNotNull(a).text).placeholder

    @Test
    fun aRequestOnShowIsFulfilledWithTheAnswerAndTheRightPasswordAfterItsHold() {
        val (api, m) = console()
        val op = m.operator
        val request = assertNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID))
        op.refresh()
        val row = assertNotNull(api.operatorApi.console).recoveryRequests.single()
        // The fake lists its request under an id of the wire's grammar (b64_16) derived from its own.
        assertEquals(request.email, row.email)

        assertNull(op.fulfil("not-on-show", "answer", pw), "a request not on show sends nothing")
        assertNull(op.fulfil(row.requestId, "   ", pw), "no answer: nothing sent")
        assertEquals(Placeholder.OP_FULFIL_EMPTY, ph(op.answerAt(OperatorModel.Area.REQUESTS, row.requestId)))

        // Still in its hold: the server refuses. (An answer of an answer's shape; AssistAnswerTest has the check.)
        // The tool's token for this request (its id, key and address), as AssistAnswerTest makes a real one.
        val sealedAnswer = io.silencelen.andvari.core.trust.AnswerToken.format(row.requestId, row.rPub, "ab".repeat(32),
            ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(row.email)) { it.toByte() })
        op.fulfil(row.requestId, sealedAnswer, pw)
        assertEquals(OperatorResult.REQUEST_NOT_READY, op.answerAt(OperatorModel.Area.REQUESTS, row.requestId)?.result)
        assertEquals(Placeholder.OP_REQUEST_NOT_READY, ph(op.answerAt(OperatorModel.Area.REQUESTS, row.requestId)))

        request.stage = OperatorHelpStage.AWAITING_OPERATOR
        op.fulfil(row.requestId, sealedAnswer, "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(op.answerAt(OperatorModel.Area.REQUESTS, row.requestId)))
        assertFalse(request.fulfilled)
        op.fulfil(row.requestId, sealedAnswer, pw)
        assertTrue(request.fulfilled)
        assertEquals(Placeholder.OP_FULFILLED, ph(op.answerAt(OperatorModel.Area.REQUESTS)))
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun thereIsNoRefuseOnlyWhatTheOperatorCanDoInstead() {
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        val section = screens.substringAfter("private fun RecoverySection(").substringBefore("\n}\n") +
            screens.substringAfter("private fun RequestRows(").substringBefore("\n}\n")
        assertTrue(section.contains("Placeholder.OP_NO_REFUSE"))
        assertTrue(section.contains("OperatorDesignWords.REQUEST_ENDS"))
        assertTrue(section.contains("OperatorDesignWords.FULFIL_OPERATOR") && section.contains("OperatorDesignWords.FULFIL_PERSON"))
        // No control and no intent to refuse, veto or decline a request exists on the operator's side.
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText()
        for (word in listOf("refuse(", "veto", "decline", "reject")) {
            assertFalse(model.lowercase().contains("fun $word") || model.contains("fun ${word.replaceFirstChar { it.uppercase() }}"), word)
        }
        assertTrue(Placeholder.entries.none { it.name.startsWith("OP_") && (it.name.contains("REFUSE_REQUEST") || it.name.contains("VETO")) })
        assertFalse(Regex("OP_(REFUSE|DECLINE|REJECT)").containsMatchIn(screens))
    }

    @Test
    fun theRecoveryCopyIsHandedOverOnceAndAskedAgainTheScreenSaysSo() {
        val (api, m) = console()
        val op = m.operator
        val accounts = assertNotNull(api.operatorApi.console).accounts
        val bo = accounts.first { it.email == "bo@family.example" }
        val cy = accounts.first { it.email == "cy@family.example" }
        assertEquals("operator", bo.recovery)

        op.downloadEscrow(bo.userId, "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(op.answerAt(OperatorModel.Area.ACCOUNT, bo.userId)))
        assertNull(op.escrowFor.value)
        op.downloadEscrow(bo.userId, pw)
        assertEquals(bo.userId, op.escrowFor.value)
        assertEquals(Placeholder.OP_ESCROW_READY, ph(op.answerAt(OperatorModel.Area.ACCOUNT, bo.userId)))

        val file = assertNotNull(op.takeEscrowFile(bo.userId))
        val text = file.toString(Charsets.UTF_8)
        for (key in listOf("\"userId\"", "\"sealed\"", "\"encryptedIdentitySeed\"", "\"identityPub\"")) assertTrue(text.contains(key), key)
        assertTrue(text.contains(bo.userId))
        assertNull(op.escrowFor.value)

        assertNull(op.takeEscrowFile(bo.userId), "handed over once")
        assertEquals(Placeholder.OP_ESCROW_TAKEN, ph(op.answerAt(OperatorModel.Area.ACCOUNT, bo.userId)))

        // An account that chose private recovery has none.
        op.downloadEscrow(cy.userId, pw)
        assertEquals(Placeholder.OP_NO_ESCROW, ph(op.answerAt(OperatorModel.Area.ACCOUNT, cy.userId)))
        assertTrue(crashes.isEmpty(), "$crashes")
    }
}
