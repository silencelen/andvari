package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** An account's devices (shown whole, revoked one on show), the audit with its filters, the policy. */
class OperatorViewsTest {
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val pw = FakeScenes.PASSWORD

    private fun console(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun idOf(api: FakeDesktopAppApi, email: String): String = assertNotNull(api.operatorApi.console).accounts.first { it.email == email }.userId

    private fun ph(a: OperatorModel.Answer?): Placeholder = assertIs<UiText.Ph>(assertNotNull(a).text).placeholder

    @Test
    fun anAccountsDevicesShowOnlyWholeAndOnlyADeviceOnShowCanBeRevoked() {
        val (api, m) = console()
        val op = m.operator
        val bo = idOf(api, "bo@family.example")
        api.script.holdNext()
        op.openDevices(bo)
        assertNull(op.devicesShown(api.operatorApi.console, bo), "nothing shows while the list is read")
        api.script.releaseHold()
        val devices = assertNotNull(op.devicesShown(api.operatorApi.console, bo))
        assertEquals(listOf("Bo's iPhone"), devices.map { it.name })
        val phone = devices.single()
        assertTrue(phone.live)

        assertNull(op.revokeDevice("not-on-show", pw), "a device not on show sends nothing")
        op.revokeDevice(phone.deviceId, "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(op.answerAt(OperatorModel.Area.DEVICES, bo)))
        assertTrue(assertNotNull(op.devicesShown(api.operatorApi.console, bo)).single().live, "nothing was done")
        op.revokeDevice(phone.deviceId, pw)
        assertEquals(OperatorResult.DONE, op.answerAt(OperatorModel.Area.DEVICES, bo)?.result)
        assertFalse(assertNotNull(op.devicesShown(api.operatorApi.console, bo)).single().live)

        op.closeDevices()
        assertNull(op.devicesShown(api.operatorApi.console, bo))
        assertNull(op.revokeDevice(phone.deviceId, pw), "closed: nothing on show")
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    /** The screen said the server sends every row and the filters work here; neither is true. */
    @Test
    fun theAuditSaysTheServerAnswersOnePageAndWhenItIsFull() {
        assertFalse(auditPageFull(0) || auditPageFull(499))
        assertTrue(auditPageFull(500))
        assertEquals(500, AUDIT_PAGE_ROWS)
        val words = Placeholder.OP_AUDIT_FILTERED_HERE.gloss
        assertTrue(words.contains("sent to the server") && words.contains("newest 500"))
        assertFalse(words.contains("every row") || words.contains("this computer"))
        assertTrue(Placeholder.OP_AUDIT_PAGE_FULL.gloss.contains("older rows"))
        val audit = java.io.File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorScreens.kt").readText()
            .substringAfter("private fun AuditSection(").substringBefore("\n}\n")
        assertTrue(audit.contains("if (auditPageFull(c.audit.size)) Say(UiText.ph(Placeholder.OP_AUDIT_PAGE_FULL)"))
    }

    @Test
    fun theAuditReadsWithItsFiltersAndARefusedReadKeepsTheRowsShown() {
        val (api, m) = console()
        val op = m.operator
        val bo = idOf(api, "bo@family.example")
        val cy = idOf(api, "cy@family.example")
        op.disable(bo, DisableWhy.ABUSE, pw)
        op.enable(cy, pw)

        op.loadAudit(0L, null, null)
        assertEquals(listOf("operator_disable", "operator_enable"), assertNotNull(api.operatorApi.console).audit.map { it.type })
        // A type is chosen from those the server has sent, never typed; anything
        // else (a typed value, a passphrase typed in the wrong place) reads nothing and goes into no address.
        assertEquals(listOf("operator_disable", "operator_enable"), op.auditTypes.value)
        for (typed in listOf("  operator_enable ", "", "correct horse battery staple", "correcthorsebatterystaple")) {
            assertNull(op.loadAudit(0L, typed, null), typed)
        }
        assertNull(op.auditFilter.value?.type)
        op.loadAudit(0L, "operator_enable", null)
        assertEquals(listOf(cy), assertNotNull(api.operatorApi.console).audit.map { it.userId })
        assertEquals("operator_enable", op.auditFilter.value?.type)
        op.loadAudit(0L, null, bo)
        assertEquals(listOf("operator_disable"), assertNotNull(api.operatorApi.console).audit.map { it.type })
        assertNull(op.auditFilter.value?.type, "no type is no filter")
        assertEquals(listOf("operator_disable", "operator_enable"), op.auditTypes.value, "a narrowed read forgets no type")

        api.script.failNext(Trouble.UNREACHABLE)
        op.loadAudit(0L, null, null)
        assertEquals(listOf("operator_disable"), assertNotNull(api.operatorApi.console).audit.map { it.type }, "the rows shown stay")
        assertTrue(assertNotNull(op.answerAt(OperatorModel.Area.AUDIT)).previousKept)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun thePolicySavesAndARefusedValueIsSaidInASentenceWithNothingStored() {
        val (api, m) = console()
        val op = m.operator
        val read = assertNotNull(assertNotNull(api.operatorApi.console).policy)
        val typed = PolicyTyped.of(read)
        assertEquals(read, typed.over(read), "the fields as read are the policy as read")

        // Not a number: said before anything is sent.
        api.script.holdNext()
        assertNull(op.savePolicy(read, PolicyTyped.of(read.copy()).let { PolicyTyped(it.autoLockSeconds, "soon", it.offlineCacheAllowed, it.sessionAccessTtlSeconds, it.sessionRefreshTtlDays, it.attachmentMaxBytes, it.itemAttachmentsMaxBytes, it.quotaBytes, it.quotaItems, it.quotaVaults, it.quotaLinks, it.kdfOps, it.kdfMemBytes, it.signupMode, it.signupCap) }, pw))
        assertFalse(api.script.holding)
        assertEquals(Placeholder.OP_POLICY_NOT_A_WHOLE_NUMBER, ph(op.answerAt(OperatorModel.Area.POLICY)), "the policy's own line: an empty field is refused there")

        // A memory that is not a whole number of KiB: this computer's own refusal, said as that, and nothing is sent.
        assertNull(op.savePolicy(read, PolicyTyped.of(read.copy(kdfParams = read.kdfParams.copy(memBytes = 1000))), pw))
        assertFalse(api.script.holding)
        assertEquals(Placeholder.OP_POLICY_KDF_MEM_NOT_KIB, ph(op.answerAt(OperatorModel.Area.POLICY)))

        // The server refuses a value: one sentence, nothing stored. (The hold armed above takes this one.)
        val badMem = PolicyTyped.of(read.copy(kdfParams = read.kdfParams.copy(memBytes = 4096)))
        op.savePolicy(read, badMem, pw)
        assertTrue(api.script.holding)
        api.script.releaseHold()
        assertEquals(OperatorResult.BAD_POLICY, op.answerAt(OperatorModel.Area.POLICY)?.result)
        assertEquals(Placeholder.OP_BAD_POLICY, ph(op.answerAt(OperatorModel.Area.POLICY)))
        assertEquals(read, assertNotNull(api.operatorApi.console).policy)

        // Sign-up can only be tightened here.
        val looser = PolicyTyped.of(read.copy(signup = read.signup.copy(mode = "open")))
        op.savePolicy(read, looser, pw)
        assertEquals(Placeholder.OP_NOT_TIGHTER, ph(op.answerAt(OperatorModel.Area.POLICY)))

        op.savePolicy(read, PolicyTyped.of(read.copy(autoLockSeconds = 120)), "not the password")
        assertEquals(Placeholder.OP_WRONG_PASSWORD, ph(op.answerAt(OperatorModel.Area.POLICY)))
        op.savePolicy(read, PolicyTyped.of(read.copy(autoLockSeconds = 120)), pw)
        assertEquals(OperatorResult.DONE, op.answerAt(OperatorModel.Area.POLICY)?.result)
        assertEquals(120L, assertNotNull(api.operatorApi.console).policy?.autoLockSeconds)
        assertTrue(crashes.isEmpty(), "$crashes")
    }
}
