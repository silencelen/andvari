package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeServer
import io.silencelen.andvari.core.model.wire.AccountStatus
import io.silencelen.andvari.core.model.wire.AccountSummary
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
import kotlin.test.assertSame
import kotlin.test.assertTrue
import io.silencelen.andvari.desktop.trust.OperatorModel.Action as A

/**
 * Every console action that asks for the master password has one shape. It is chosen (its inputs
 * entered and checked first); a step of its own shows what will be done and to what, as it was when chosen, and takes
 * the password; the result is said beside the control that was pressed, in words that name what was done. Each action
 * is chosen, the list is read again with another account in it, and the step still names, and acts on, what was chosen.
 */
class OperatorStepsTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    private fun console(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun family(api: FakeDesktopAppApi): FakeServer = assertNotNull(api.script.server(FakeScenes.FAMILY_ORIGIN))
    private fun row(api: FakeDesktopAppApi, email: String): AccountSummary = assertNotNull(api.operatorApi.console).accounts.first { it.email == email }

    /**
     * The list is read again, now with an account it did not have, listed before the others. The console reads nothing
     * under an open step, so this is the shared code reading it, as it does after another action of this account.
     */
    private fun readAgainWithAnother(api: FakeDesktopAppApi, @Suppress("UNUSED_PARAMETER") m: TrustModel) {
        family(api).addAccount("aa@family.example", pw)
        kotlinx.coroutines.runBlocking { api.operatorApi.refreshConsole() }
        assertTrue(assertNotNull(api.operatorApi.console).accounts.any { it.email == "aa@family.example" }, "the list was read again")
    }

    private fun shown(step: OperatorModel.Step): List<Pair<Placeholder?, String>> =
        step.values.map { (it.label as? UiText.Ph)?.placeholder to it.value.shown() }

    private fun assertNames(step: OperatorModel.Step, email: String, id: String) {
        val values = shown(step)
        assertTrue((Placeholder.OP_STEP_ACCOUNT to email) in values, "$values")
        assertTrue((Placeholder.OP_STEP_ACCOUNT_ID to id) in values, "$values")
    }

    private fun said(m: TrustModel, area: OperatorModel.Area, key: String?, action: OperatorModel.Action, about: String? = null): UiText.Ph =
        assertIs<UiText.Ph>(assertNotNull(m.operator.answerFor(area, key, action, about), "said beside $action").text)

    /** A wrong password is said in the step, which stays open; nothing else. Then the right one sends it and closes it. */
    private fun sendWithAWrongPasswordFirst(m: TrustModel, step: OperatorModel.Step) {
        m.operator.confirm(step, "not the password")
        assertSame(step, m.operator.step.value, "a wrong password keeps the step open")
        assertEquals(OperatorResult.WRONG_PASSWORD, m.operator.answerFor(step.chosen.area, step.chosen.key, step.action, step.chosen.about)?.result)
        assertNotNull(m.operator.confirm(step, pw))
        assertNull(m.operator.step.value, "the step closes on its answer")
    }

    private fun lastAuditUser(api: FakeDesktopAppApi, m: TrustModel, type: String): String? {
        m.operator.loadAudit(0L, null, null)
        return assertNotNull(api.operatorApi.console).audit.lastOrNull { it.type == type }?.userId
    }

    @Test
    fun disableNamesTheAccountItWasChosenForAndActsOnItAfterTheListWasReadAgain() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        val chosen = assertNotNull(m.operator.chooseFor(A.DISABLE, bo))
        assertSame(chosen, m.operator.chosen.value, "a reason is asked first")
        assertNull(m.operator.step.value, "no password before the reason")
        readAgainWithAnother(api, m)
        val step = assertNotNull(m.operator.checkDisable(chosen, DisableWhy.ABUSE))
        assertNames(step, "bo@family.example", bo.userId)
        sendWithAWrongPasswordFirst(m, step)
        assertEquals(AccountStatus.DISABLED, row(api, "bo@family.example").status)
        assertEquals(AccountStatus.ACTIVE, row(api, "aa@family.example").status)
        val done = said(m, OperatorModel.Area.ACCOUNT, bo.userId, A.DISABLE)
        assertEquals(Placeholder.OP_DONE_DISABLED, done.placeholder)
        assertEquals(listOf("bo@family.example"), done.args)
        assertNull(m.operator.answerFor(OperatorModel.Area.ACCOUNT, bo.userId, A.QUOTA), "said beside the action pressed only")
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun enableGoesStraightToItsStepAndNamesTheAccount() {
        val (api, m) = console()
        val cy = row(api, "cy@family.example")
        m.operator.chooseFor(A.ENABLE, cy)
        val step = assertNotNull(m.operator.step.value, "no inputs: the password step at once")
        readAgainWithAnother(api, m)
        assertNames(step, "cy@family.example", cy.userId)
        sendWithAWrongPasswordFirst(m, step)
        assertEquals(AccountStatus.ACTIVE, row(api, "cy@family.example").status)
        assertEquals(Placeholder.OP_DONE_ENABLED, said(m, OperatorModel.Area.ACCOUNT, cy.userId, A.ENABLE).placeholder)
    }

    @Test
    fun aQuotaIsCheckedBeforeItsStepAndSentForTheAccountChosen() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        val chosen = assertNotNull(m.operator.chooseFor(A.QUOTA, bo))
        assertNull(m.operator.checkQuota(chosen, QuotaTyped("ten", "", "", "")))
        assertEquals(Placeholder.OP_NOT_A_WHOLE_NUMBER, said(m, OperatorModel.Area.ACCOUNT, bo.userId, A.QUOTA).placeholder)
        assertSame(chosen, m.operator.chosen.value, "the inputs stay open to be corrected")
        val step = assertNotNull(m.operator.checkQuota(chosen, QuotaTyped("1048576", "", "3", "")))
        assertTrue((Placeholder.OP_QUOTA_BYTES to "1048576") in shown(step))
        assertTrue((Placeholder.OP_QUOTA_ITEMS to UiText.ph(Placeholder.OP_STEP_DEFAULT).shown()) in shown(step))
        readAgainWithAnother(api, m)
        assertNames(step, "bo@family.example", bo.userId)
        sendWithAWrongPasswordFirst(m, step)
        assertEquals(Placeholder.OP_DONE_QUOTA, said(m, OperatorModel.Area.ACCOUNT, bo.userId, A.QUOTA).placeholder)
        assertEquals(bo.userId, lastAuditUser(api, m, "operator_quota"))
    }

    @Test
    fun revokeNamesTheDeviceAndItsAccountAndSaysItBesideThatDevice() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        m.operator.openDevices(bo.userId)
        val device = assertNotNull(m.operator.devicesShown(api.operatorApi.console, bo.userId)).first()
        m.operator.chooseFor(A.REVOKE, bo, device)
        val step = assertNotNull(m.operator.step.value)
        readAgainWithAnother(api, m)
        assertNames(step, "bo@family.example", bo.userId)
        assertTrue((Placeholder.OP_STEP_DEVICE_ID to device.deviceId) in shown(step))
        sendWithAWrongPasswordFirst(m, step)
        val done = said(m, OperatorModel.Area.DEVICES, bo.userId, A.REVOKE, device.deviceId)
        assertEquals(Placeholder.OP_DONE_REVOKED, done.placeholder)
        assertEquals(listOf(device.name, "bo@family.example"), done.args)
        assertEquals(bo.userId, lastAuditUser(api, m, "operator_device_revoke"))
    }

    @Test
    fun aRevokeWhoseDeviceIsNoLongerOnShowSendsNothingAndSaysSo() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        m.operator.openDevices(bo.userId)
        val device = assertNotNull(m.operator.devicesShown(api.operatorApi.console, bo.userId)).first()
        m.operator.chooseFor(A.REVOKE, bo, device)
        val step = assertNotNull(m.operator.step.value)
        m.operator.closeDevices()
        assertNull(m.operator.confirm(step, pw))
        assertNull(m.operator.step.value)
        assertEquals(Placeholder.OP_STEP_GONE, assertIs<UiText.Ph>(assertNotNull(m.operator.answerAt(OperatorModel.Area.CONSOLE)).text).placeholder)
        assertNull(lastAuditUser(api, m, "operator_device_revoke"), "nothing was sent")
    }

    @Test
    fun theRecoveryCopyIsDownloadedForTheAccountChosen() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        m.operator.chooseFor(A.ESCROW, bo)
        val step = assertNotNull(m.operator.step.value)
        readAgainWithAnother(api, m)
        assertNames(step, "bo@family.example", bo.userId)
        sendWithAWrongPasswordFirst(m, step)
        assertEquals(bo.userId, m.operator.escrowFor.value)
        val done = said(m, OperatorModel.Area.ACCOUNT, bo.userId, A.ESCROW)
        assertEquals(Placeholder.OP_ESCROW_READY, done.placeholder)
        assertEquals(listOf("bo@family.example"), done.args)
    }

    @Test
    fun deleteSaysWhatTheServerWillRecordInItsStepBeforeThePassword() {
        val (api, m) = console()
        val cy = row(api, "cy@family.example")
        val chosen = assertNotNull(m.operator.chooseFor(A.DELETE, cy))
        val step = assertNotNull(m.operator.checkDelete(chosen, OperatorDeleteWhy.DISABLED_30_DAYS))
        assertEquals(deleteRecordLine(OperatorDeleteWhy.DISABLED_30_DAYS).shown(), step.lines.last().text.shown())
        assertTrue(step.lines.last().warn)
        assertEquals(UiText.Plain(OperatorDesignWords.DELETE_RULE).shown(), step.lines.first().text.shown())
        readAgainWithAnother(api, m)
        assertNames(step, "cy@family.example", cy.userId)
        sendWithAWrongPasswordFirst(m, step)
        assertTrue(assertNotNull(api.operatorApi.console).accounts.none { it.userId == cy.userId }, "deleted")
        assertTrue(assertNotNull(api.operatorApi.console).accounts.any { it.email == "aa@family.example" })
        val done = assertIs<UiText.Ph>(assertNotNull(m.operator.answerAt(OperatorModel.Area.CONSOLE)).text)
        assertEquals(Placeholder.OP_DELETED, done.placeholder)
        assertEquals(listOf("cy@family.example"), done.args)
    }

    @Test
    fun answeringARequestChecksTheAnswerFirstAndItsStepNamesTheRequest() {
        val (api, m) = console()
        val request = assertNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID))
        m.operator.refresh()
        val r = assertNotNull(api.operatorApi.console).recoveryRequests.single()
        val chosen = assertNotNull(m.operator.chooseFulfil(r.requestId))
        assertNull(m.operator.checkFulfil(chosen, "not an answer"), "a refused answer opens no step")
        assertSame(chosen, m.operator.chosen.value)
        // The tool's token for this request (its id, key and address).
        val sealed = io.silencelen.andvari.core.trust.AnswerToken.format(r.requestId, r.rPub, "ab".repeat(32),
            ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(r.email)) { it.toByte() })
        val step = assertNotNull(m.operator.checkFulfil(chosen, sealed))
        assertTrue((Placeholder.OP_STEP_REQUEST to r.requestId) in shown(step))
        request.stage = OperatorHelpStage.AWAITING_OPERATOR
        readAgainWithAnother(api, m)
        assertTrue((Placeholder.OP_STEP_ACCOUNT to r.email) in shown(step))
        // Nothing of the server's account identity is offered as something to check against.
        assertTrue(shown(step).none { it.second == r.userId || it.second == r.accountId }, "${shown(step)}")
        sendWithAWrongPasswordFirst(m, step)
        assertTrue(request.fulfilled)
        assertEquals(Placeholder.OP_FULFILLED, assertIs<UiText.Ph>(assertNotNull(m.operator.answerAt(OperatorModel.Area.REQUESTS)).text).placeholder)
    }

    @Test
    fun thePolicyStepListsWhatChangesOnTheServerChosen() {
        val (api, m) = console()
        val c = assertNotNull(api.operatorApi.console)
        val read = assertNotNull(c.policy)
        val chosen = assertNotNull(m.operator.chooseForServer(A.POLICY))
        assertTrue(read.autoLockSeconds != 120L)
        val typed = PolicyTyped.of(read.copy(autoLockSeconds = 120))
        val step = assertNotNull(m.operator.checkPolicy(chosen, read, typed))
        assertEquals(listOf(changeLine(Placeholder.OP_POLICY_AUTO_LOCK, read.autoLockSeconds.toString(), "120").shown()), step.lines.map { it.text.shown() })
        readAgainWithAnother(api, m)
        assertTrue((Placeholder.OP_STEP_SERVER_ADDRESS to c.instance.origin) in shown(step))
        sendWithAWrongPasswordFirst(m, step)
        assertEquals(120L, assertNotNull(api.operatorApi.console?.policy).autoLockSeconds)
        assertEquals(Placeholder.OP_DONE_POLICY, said(m, OperatorModel.Area.POLICY, null, A.POLICY).placeholder)
    }

    @Test
    fun theCardsActionsCheckTheirInputsAndTheirStepsNameTheServerAsItWas() {
        val (api, m) = console()
        val before = assertNotNull(api.operatorApi.console).instance
        val server = family(api)
        val op = m.operator

        val rename = assertNotNull(op.chooseForServer(A.RENAME))
        assertNull(op.checkRename(rename, "   "))
        assertEquals(Placeholder.OP_CARD_NAME_EMPTY, said(m, OperatorModel.Area.CARD, OperatorModel.CARD_RENAME, A.RENAME).placeholder)
        val renamed = assertNotNull(op.checkRename(rename, "  The Family  "))
        readAgainWithAnother(api, m)
        assertTrue((Placeholder.OP_STEP_SERVER to before.name) in shown(renamed) && (Placeholder.OP_STEP_NEW_NAME to "The Family") in shown(renamed))
        sendWithAWrongPasswordFirst(m, renamed)
        assertEquals("The Family", assertNotNull(api.operatorApi.console).instance.name)
        assertEquals(listOf("The Family"), said(m, OperatorModel.Area.CARD, OperatorModel.CARD_RENAME, A.RENAME).args)

        val set = assertNotNull(op.chooseForServer(A.RECOVERY_SET))
        assertNull(op.checkRecoverySet(set, "abc", ""))
        assertEquals(Placeholder.OP_FINGERPRINT_SHAPE, said(m, OperatorModel.Area.CARD, OperatorModel.CARD_RECOVERY, A.RECOVERY_SET).placeholder)
        val fp = "ab".repeat(32)
        val setStep = assertNotNull(op.checkRecoverySet(set, fp.uppercase(), ""))
        assertTrue(setStep.lines.single().warn, "an unsigned change is said in its step")
        sendWithAWrongPasswordFirst(m, setStep)
        assertEquals(listOf(fp), said(m, OperatorModel.Area.CARD, OperatorModel.CARD_RECOVERY, A.RECOVERY_SET).args)

        val removing = assertNotNull(op.chooseForServer(A.RECOVERY_REMOVE))
        val remove = assertNotNull(op.checkRecoveryRemove(removing, before.origin))
        sendWithAWrongPasswordFirst(m, remove)
        assertFalse(server.recoveryKey)
        assertEquals(Placeholder.OP_DONE_RECOVERY_REMOVED, said(m, OperatorModel.Area.CARD, OperatorModel.CARD_RECOVERY, A.RECOVERY_REMOVE).placeholder)

        val move = assertNotNull(op.chooseForServer(A.MOVE))
        assertNull(op.checkMove(move, "not an address"))
        val moveStep = assertNotNull(op.checkMove(move, "https://vault.newplace.example/"))
        assertTrue((Placeholder.OP_STEP_NEW_ADDRESS to "https://vault.newplace.example") in shown(moveStep))
        assertTrue((Placeholder.OP_STEP_SERVER_ADDRESS to before.origin) in shown(moveStep))
        assertNotNull(op.confirm(moveStep, pw))
        assertEquals("https://vault.newplace.example", server.origin)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    /**
     * Stopping operator recovery was one unconfirmed click under the shared password field. Now it
     * is chosen, says what it does, takes a typed confirmation (the server's address as on show), and only then opens
     * a password step of its own that says it again.
     */
    @Test
    fun stoppingOperatorRecoveryTakesATypedConfirmationAndItsOwnPasswordStep() {
        val (api, m) = console()
        val server = family(api)
        assertTrue(server.recoveryKey)
        val origin = assertNotNull(api.operatorApi.console).instance.origin
        val chosen = assertNotNull(m.operator.chooseForServer(A.RECOVERY_REMOVE))
        assertNull(m.operator.step.value, "no password before the confirmation")
        assertSame(chosen, m.operator.chosen.value)
        for (wrong in listOf("", "yes", "stop", origin + "x", "https://vault.other.example")) {
            assertNull(m.operator.checkRecoveryRemove(chosen, wrong), wrong)
            assertEquals(Placeholder.OP_REMOVE_TYPED_WRONG, said(m, OperatorModel.Area.CARD, OperatorModel.CARD_RECOVERY, A.RECOVERY_REMOVE).placeholder)
        }
        assertTrue(server.recoveryKey, "nothing was signed")
        val step = assertNotNull(m.operator.checkRecoveryRemove(chosen, "  $origin/ "))
        assertEquals(listOf(Placeholder.OP_REMOVE_WHAT_CARD, Placeholder.OP_REMOVE_WHAT_LATER, Placeholder.OP_REMOVE_REQUESTS_STOP), step.lines.map { (it.text as UiText.Ph).placeholder })
        assertTrue(step.lines.all { it.warn })
        assertTrue(Placeholder.OP_REMOVE_WHAT_LATER.gloss.contains("cannot be undone by a rotation"))
        sendWithAWrongPasswordFirst(m, step)
        assertFalse(server.recoveryKey)
        // On the page it stands apart from setting a key, and the screen says what it cannot show of the card.
        val card = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun CardSection(").substringBefore("\n}\n")
        assertTrue(card.contains("Gap(16)\n        // Its own step"))
        // The step names the server's id and the recovery key its pinned card names, from this computer's pin
        // (the fake's pin gives neither, so each is said as not held).
        val values = shown(step)
        assertTrue((Placeholder.OP_STEP_INSTANCE_ID to UiText.ph(Placeholder.OP_PIN_HOLDS_NONE).shown()) in values, "$values")
        assertTrue((Placeholder.OP_STEP_RECOVERY_FP to UiText.ph(Placeholder.OP_CARD_NAMES_NO_RECOVERY_KEY).shown()) in values, "$values")
        assertTrue(card.contains("pinnedCardValues(c.pinnedRecoveryFp, c.pinnedInstanceId"))
    }

    /** While a step is open no list is read again; a typed password is cleared once sent; no typed audit type; no field on the card. */
    @Test
    fun nothingIsReadAgainUnderAnOpenStepAndNoFieldTakesWhatAPasswordStepShould() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        m.operator.enable(row(api, "cy@family.example").userId, pw)
        m.operator.loadAudit(0L, null, null)
        val type = m.operator.auditTypes.value.first()
        m.operator.chooseFor(A.ENABLE, row(api, "cy@family.example"))
        assertNotNull(m.operator.step.value)
        assertNull(m.operator.refresh(), "the console is not read again under the step")
        assertNull(m.operator.loadAudit(0L, type, null), "nor the audit")
        assertNull(m.operator.openDevices(bo.userId), "nor a device list")
        m.operator.cancelStep()
        assertNotNull(m.operator.refresh(), "once it is closed, it is")
        m.operator.chooseFor(A.DISABLE, bo)
        assertNull(m.operator.refresh(), "nor under an action's inputs")
        m.operator.cancelStep()

        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        // The field is emptied whenever the password is sent, so a failed action leaves nothing typed in it.
        for (name in listOf("private fun PasswordStepDialog(", "private fun FulfilStep(")) {
            assertTrue(screens.substringAfter(name).substringBefore("\n}\n").contains("val send = { if (sendStep(op, s, "), name)
        }
        assertTrue(screens.contains("val send = { if (sendStep(op, s, step, password)) password = \"\" }"))
        val card = screens.substringAfter("private fun CardSection(").substringBefore("\n}\n")
        assertFalse(Regex("\\bField\\(").containsMatchIn(card), "the card's name is entered in its own step, under no password field")
        val audit = screens.substringAfter("private fun AuditSection(").substringBefore("\n}\n")
        assertFalse(Regex("\\bField\\(").containsMatchIn(audit), "the audit's type is chosen, never typed")
        assertTrue(audit.contains("AuditTypeChooser(types, type, !s.busy)"))
    }

    /**
     * Names from the server are drawn plainly (a direction override, a zero-width or line
     * separator, a control character is shown escaped, never obeyed); every control names its target; the recovery
     * copy is saved under a name that says whose it is, asks before replacing a file, and says where it is and to delete it.
     */
    @Test
    fun serverNamesAreDrawnPlainlyEveryControlNamesItsTargetAndTheRecoveryCopySaysWhoseItIs() {
        assertEquals("Phone⟨U+202E⟩gnp.exe", plainName("Phone\u202Egnp.exe"))
        assertEquals("a⟨U+200B⟩b⟨U+2028⟩c⟨U+000A⟩d⟨U+0007⟩", plainName("a\u200Bb\u2028c\nd\u0007"))
        assertEquals("Bo's iPhone · Ünïcødé 名前", plainName("Bo's iPhone · Ünïcødé 名前"))

        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        val fakeBo = assertNotNull(family(api).accounts["bo@family.example"])
        fakeBo.addDevice("Phone\u202Egnp.exe", AppPlatform.ANDROID, io.silencelen.andvari.core.app.HowDeviceJoined.REGISTERED)
        m.operator.openDevices(bo.userId)
        val device = assertNotNull(m.operator.devicesShown(api.operatorApi.console, bo.userId)).first { it.name.contains('\u202E') }
        m.operator.chooseFor(A.REVOKE, bo, device)
        val step = assertNotNull(m.operator.step.value)
        assertTrue(step.title.shown().contains("Phone⟨U+202E⟩gnp.exe") && !step.title.shown().contains('\u202E'))
        m.operator.confirm(step, pw)
        assertFalse(said(m, OperatorModel.Area.DEVICES, bo.userId, A.REVOKE, device.deviceId).shown().contains('\u202E'))

        // Every control and step title of an action names its target: none of these placeholders is drawn without one.
        val src = listOf("OperatorScreens.kt", "OperatorModel.kt").joinToString("\n") { File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$it").readText() }
        val unnamed = Regex("UiText\\.ph\\(Placeholder\\.OP_(DISABLE|ENABLE|QUOTA|QUOTA_SAVE|ESCROW_DOWNLOAD|ESCROW_SAVE|POLICY_EDIT|POLICY_SAVE|CARD_RENAME|CARD_MOVE|RECOVERY_SET|RECOVERY_REMOVE|REVOKE_DEVICE|DELETE|DELETE_CONFIRM|FULFIL)\\)")
        assertNull(unnamed.find(src)?.value)
        for (p in listOf(Placeholder.OP_DISABLE, Placeholder.OP_ENABLE, Placeholder.OP_QUOTA, Placeholder.OP_ESCROW_DOWNLOAD)) assertTrue(p.gloss.contains("(account)"), p.name)
        for (p in listOf(Placeholder.OP_POLICY_EDIT, Placeholder.OP_CARD_RENAME, Placeholder.OP_CARD_MOVE, Placeholder.OP_RECOVERY_SET, Placeholder.OP_RECOVERY_REMOVE)) assertTrue(p.gloss.contains("(server)"), p.name)

        // The recovery copy's file: whose it is, a name a file system takes, and the overwrite question.
        assertEquals("recovery-copy-bo@run.example.json", escrowFileName("Bo@Run.example"))
        assertEquals("recovery-copy-.._x_y@z.json", escrowFileName("../x/y@z"))
        val escrow = src.substringAfter("private fun EscrowControls(").substringBefore("\n}\n")
        assertTrue(escrow.contains("escrowFileName(a.email)") && escrow.contains("overwrite.request(pick.file)") && escrow.contains("ReplaceFileDialog(overwrite)"))
        assertFalse(escrow.contains("escrow-download.json"))
        assertTrue(Placeholder.OP_ESCROW_SAVED.gloss.contains("(file)") && Placeholder.OP_ESCROW_SAVED.gloss.contains("delete it"))
        // The server's id and the card's recovery key come from this computer's pin, never from a guess.
        val card = src.substringAfter("private fun CardSection(").substringBefore("\n}\n")
        assertTrue(card.contains("pinnedCardValues(c.pinnedRecoveryFp, c.pinnedInstanceId, c.status?.instanceKind == \"public\")"))
    }

    @Test
    fun cancelLeavesTheStepAndSendsNothing() {
        val (api, m) = console()
        val bo = row(api, "bo@family.example")
        val chosen = assertNotNull(m.operator.chooseFor(A.DISABLE, bo))
        val step = assertNotNull(m.operator.checkDisable(chosen, DisableWhy.OTHER))
        m.operator.cancelStep()
        assertNull(m.operator.confirm(step, pw), "a step no longer open sends nothing")
        assertEquals(AccountStatus.ACTIVE, row(api, "bo@family.example").status)
        assertNull(m.operator.checkDisable(chosen, DisableWhy.OTHER), "nor do inputs no longer open")
    }

    /** The layout: one password field in the console, in the step; no field that grows; the step's line in a slot of fixed height. */
    @Test
    fun theOnlyPasswordFieldIsTheStepsAndNothingAboveItCanMove() {
        val screens = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
        // Two password fields: the steps', and answering a request's, which keeps both of its steps together.
        assertEquals(2, Regex("MasterPasswordField\\(").findAll(screens).count())
        val fulfil = screens.substringAfter("private fun FulfilStep(").substringBefore("\n}\n").substringAfter("} else {")
        for (dialog in listOf(screens.substringAfter("private fun PasswordStepDialog(").substringBefore("\n}\n"), fulfil)) {
            assertTrue(dialog.contains("MasterPasswordField(s, password, onEnter = send)"))
            val field = dialog.indexOf("MasterPasswordField(")
            assertTrue(dialog.indexOf("StepIntro(") in 0 until field, "what it is for comes before the password")
            assertTrue(dialog.indexOf("StepSaid(") > field, "what the step says goes below the field")
        }
        val intro = screens.substringAfter("private fun StepIntro(").substringBefore("\n}\n")
        assertTrue(intro.indexOf("step.lines") < intro.indexOf("StepValues(step.values)"))
        // Every multi-line field of the console has a fixed number of lines.
        for (m in Regex("lines = (\\d+)([^)]*)\\)").findAll(screens)) assertTrue(m.value.contains("maxLines = ${m.groupValues[1]}"), m.value)
        val slot = screens.substringAfter("private fun StepSaid(").substringBefore("\n}\n")
        assertTrue(slot.contains(".height(STEP_SAID_HEIGHT).verticalScroll("))
        // Every action's own line, beside its control; no shared "done".
        assertFalse(screens.contains("Placeholder.OP_DONE)") || File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText().contains("Placeholder.OP_DONE)"))
        val frame = screens.substringAfter("private fun StepFrame(").substringBefore("\n}\n")
        assertTrue(frame.contains("onDismissRequest = onCancel") && frame.contains("dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = onCancel) }"), "Cancel is the way out")
        // Names from the server sit on one line that scrolls; it is no Tab stop without a focus mark (keyboard walk).
        val accounts = screens.substringAfter("private fun AccountRows(").substringBefore("\n}\n")
        assertTrue(accounts.contains("OneLine(a.email") && accounts.contains("OneLine(a.displayName"))
        assertFalse(screens.substringAfter("internal fun OneLine(").substringBefore("\n}\n").contains("SelectionContainer"))
        // A disable that was done turns its control into Enable: its line is said beside that one (found in the run).
        val panel = screens.substringAfter("private fun AccountPanel(").substringBefore("\n}\n")
        val enableBranch = panel.substringAfter("if (a.status == AccountStatus.DISABLED) {").substringBefore("} else {")
        assertTrue(enableBranch.contains("OperatorSaid(op, area, a.userId, OperatorModel.Action.DISABLE)"))
    }
}
