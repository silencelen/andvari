package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The desktop on the key fix. A lock landing during each kind of work the desktop launches: the
 * screen on show (the lock screen) says it as the lock, in a sentence; never a crash, never a wrong password; and a
 * "keys gone" throw is the lock, while any other failure is not swallowed. The idle lock, the lock on sleep and the
 * manual lock are the same lock; one test drives each.
 */
class LockOvertakesWorkTest {
    /** What reached the scope uncaught: on the desktop, the window's failure card. */
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })

    /** Both of the model's clocks, which a test moves. */
    private var clock = 0L

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, scope, { clock }, SignInKeeping.Never, { clock }, faultLog = {})
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** The shared code's answer within a bound: work that never answers fails, saying which. */
    private fun <T> bounded(what: String, block: suspend () -> T): T = runBlocking {
        try {
            kotlinx.coroutines.withTimeout(20_000) { block() }
        } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
            throw AssertionError("the test waited 20 s for $what, which never came")
        }
    }

    /** Signed in with the vault open and its content read. */
    private fun open(scene: FakeScene = FakeScene.LOCKED): Pair<FakeDesktopAppApi, TrustModel> {
        val (api, m) = at(scene)
        if (api.snapshot.phase == AppPhase.LOCKED) unlockAgain(api, m)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun unlockAgain(api: FakeDesktopAppApi, m: TrustModel) {
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
    }

    private fun overtookSaid(api: FakeDesktopAppApi, m: TrustModel): Placeholder {
        val said = assertNotNull(m.saidOn(api.snapshot), "the screen on show says it")
        return assertIs<UiText.Ph>(said.text).placeholder
    }

    /** A held intent of the fake, with [lock] landing while it waits, then let go. */
    private fun lockDuring(api: FakeDesktopAppApi, m: TrustModel, lock: () -> Unit = { m.lockNow() }, start: () -> Unit) {
        api.script.holdNext()
        start()
        assertTrue(api.script.holding, "the intent is under way")
        lock()
        api.script.releaseHold()
        m.onSnapshot(api.snapshot)
        assertTrue(crashes.isEmpty(), "nothing crashed: $crashes")
    }

    private fun assertOvertook(api: FakeDesktopAppApi, m: TrustModel, what: String = "", line: Placeholder = Placeholder.LOCK_OVERTOOK) {
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, what)
        assertEquals(line, overtookSaid(api, m), what)
    }

    @Test
    fun anIntentThatThrowsTheKeysAreGoneIsTheLockNotACrashAndNothingElseIsSwallowed() {
        val (api, m) = open()
        var after = false
        m.run<PlainResult>({ throw KeysGoneException() }) { after = true }
        assertTrue(crashes.isEmpty(), "the keys being gone is not a crash: $crashes")
        assertOvertook(api, m)
        assertFalse(after, "nothing after it runs: a screen still there keeps what was typed")

        // Wrapped, it is the same lock.
        unlockAgain(api, m)
        assertNull(m.saidOn(api.snapshot), "the unlock clears it")
        m.run<PlainResult>({ throw IllegalStateException("outer", KeysGoneException()) })
        assertTrue(crashes.isEmpty())
        assertOvertook(api, m)

        // A plain intent that finds the keys gone is the lock too.
        unlockAgain(api, m)
        m.act { throw KeysGoneException() }
        assertOvertook(api, m)

        // Any other failure is not swallowed: it is said in place as "something went wrong",
        // never a crash, and is not taken for a lock.
        unlockAgain(api, m)
        m.run<PlainResult>({ throw IllegalStateException("something else") })
        assertTrue(crashes.isEmpty(), "$crashes")
        assertEquals(Placeholder.SOMETHING_WENT_WRONG, overtookSaid(api, m))
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "and is not taken for a lock")
    }

    /** The three ways the lock comes: Ctrl+L or the menu, the idle window, and a computer that slept. */
    private fun lockWays(m: TrustModel): List<Pair<String, () -> Unit>> = listOf(
        "manual" to { m.lockNow() },
        "idle" to {
            // A tick each second, none of them late, until the idle window is over.
            repeat((m.autoLockMs() / 1000).toInt()) {
                clock += 1000
                m.tick()
            }
        },
        "sleep" to {
            // The person was here a moment ago, but the ticks stopped for longer than a tick can be late: it slept.
            clock += TrustModel.LATE_TICK_MS + 5_000
            m.touched()
            m.tick()
        },
    )

    @Test
    fun aPasswordChangeOvertakenByEachKindOfLockIsSaidOnTheLockScreenNeverAsAWrongPassword() {
        for (way in listOf("manual", "idle", "sleep")) {
            clock = 0L
            val (api, m) = open()
            val lock = lockWays(m).first { it.first == way }.second
            var after: Any? = null
            lockDuring(api, m, lock) {
                m.runSaying({ settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeLine(it) }) { after = it }
            }
            assertOvertook(api, m, way)
            assertNotEquals(Placeholder.PASSWORD_CHANGE_WRONG, overtookSaid(api, m), way)
            assertNotNull(after, "$way: the screen sees the answer (STALE), so nothing claims it was done")
            // Not done: the old password still opens the vault, and the unlock clears the line.
            unlockAgain(api, m)
            assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, way)
            assertNull(m.saidOn(api.snapshot), way)
        }
    }

    /**
     * Found in the run: a password change that went through just as the lock came said nothing, because its screen had
     * gone, and the old password then read as wrong. The lock screen now says it was changed.
     */
    @Test
    fun aPasswordChangeDoneAsTheLockCameIsSaidOnTheLockScreen() {
        val (api, m) = open()
        val newPassword = "a much longer master password, 2026!"
        m.runSaying({ settings.changeMasterPassword(FakeScenes.PASSWORD, newPassword).also { lock() } }, { passwordChangeLine(it) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertEquals(Placeholder.PASSWORD_CHANGED, overtookSaid(api, m), "which password opens this computer's copy now")
        assertTrue(crashes.isEmpty())
        // Anything else done as the lock came is said as done.
        m.run({ unlock(assertNotNull(snapshot.locked), newPassword) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.run({ vaults.createVault("Trips").also { lock() } })
        assertEquals(Placeholder.LOCK_AFTER_DONE, overtookSaid(api, m))
        assertEquals(Placeholder.PASSWORD_CHANGED_PREVIOUS_OPENS_HERE, (doneUnderLockWords(io.silencelen.andvari.core.app.PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE) as UiText.Ph).placeholder)
    }

    @Test
    fun aDeletionALockOvertookDeletesNothingAndSaysSo() {
        val (api, m) = open()
        m.run({ settings.openDeletion() })
        m.onSnapshot(api.snapshot)
        val screen = assertNotNull(api.snapshot.account?.deletion)
        lockDuring(api, m) { m.deleteAccount(screen, FakeScenes.EMAIL, FakeScenes.PASSWORD, null) }
        assertOvertook(api, m)
        assertNull(m.accountDeletedNotice(), "the account is still here, locked")
    }

    @Test
    fun aDeviceLinkApprovalALockOvertookApprovesNothingAndIsNeverAWrongPassword() {
        val (api, m) = open(FakeScene.VAULTS)
        m.run({ devices.startDeviceLink() })
        api.script.joiningDeviceClaims("Pixel", AppPlatform.ANDROID)
        api.script.joiningDeviceReveals(true)
        val type = assertIs<DeviceLinkHost.TypeDigits>(api.snapshot.account?.deviceLink)
        m.run({ devices.submitDeviceDigits(type, api.script.joiningDeviceCode) })
        val approvable = assertIs<DeviceLinkHost.Approvable>(api.snapshot.account?.deviceLink)
        lockDuring(api, m) {
            m.runSaying({ devices.approveWithPassword(approvable, FakeScenes.PASSWORD) }, { deviceLinkApproveLine(it) })
        }
        assertOvertook(api, m)
        assertNotEquals(Placeholder.DEVICE_LINK_WRONG_PASSWORD, overtookSaid(api, m))
    }

    @Test
    fun aKitConfirmALockOvertookIsSaidOnTheLockScreen() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        val reveal = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        m.act { kit.proceedToConfirm(reveal) }
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        lockDuring(api, m) { m.run({ kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) }) }
        assertOvertook(api, m)
    }

    @Test
    fun aSharedVaultActionALinkAndARecoverySettingALockOvertookAreSaidAsTheLock() {
        val kinds: List<Pair<String, (TrustModel) -> Unit>> = listOf(
            "shared vault" to { m -> m.run({ vaults.createVault("Trips") }) },
            "link" to { m -> m.run({ links.createConnectLink(emptyList(), LinkLifetimes.IN_PERSON_MINUTES) }) },
            "recovery" to { m -> m.run({ recovery.makeKit(FakeScenes.PASSWORD) }) },
        )
        for ((kind, work) in kinds) {
            val (api, m) = open(FakeScene.VAULTS)
            lockDuring(api, m) { work(m) }
            assertOvertook(api, m, kind)
        }
    }

    /** A content write that a lock overtakes once it is under way (the content says busy). */
    private fun lockWhenBusy(api: FakeDesktopAppApi, c: VaultContent) {
        var fired = false
        c.observe { s -> if (s.busy && !fired) { fired = true; api.lock() } }
    }

    @Test
    fun aSaveADeletionAMoveAFileAndAnExportALockOvertookAreNotDoneAndTheLockScreenSaysSo() {
        val kinds: List<Pair<String, suspend (VaultContent, String, String) -> ActionResult>> = listOf(
            "save" to { c, _, _ -> c.saveLogin(null, LoginInput("New", "me", "pw", listOf("https://new.example"), "", "", false), null) },
            "delete" to { c, id, _ -> c.deleteItem(id) },
            "move" to { c, id, shared -> c.moveOrCopyItem(id, shared, move = true) },
            "copy" to { c, id, shared -> c.moveOrCopyItem(id, shared, move = false) },
            "file" to { c, id, _ -> c.openAttachmentDraft(id); c.addAttachment("a.txt", "hello".toByteArray()) },
            "export" to { c, _, _ -> c.openExport(ExportKind.BACKUP) },
        )
        for ((kind, work) in kinds) {
            val (api, m) = open()
            val fake = assertNotNull(api.fakeContent)
            val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
            fake.addSharedVault("v-shared", "Trips", "owner", VaultStanding.VERIFIED)
            val c = assertNotNull(m.content.value)
            lockWhenBusy(api, c)
            val r = bounded("the $kind to answer after the lock") { work(c, id, "v-shared") }
            assertEquals(ActionResult.NotDone(null), r, "$kind: not done, and never a failure")
            m.onSnapshot(api.snapshot)
            assertNull(m.content.value)
            // The content closed while the change ran: whether it went through is not known in general, so the lock
            // screen says to check, never "do it again".
            assertOvertook(api, m, kind, Placeholder.CHANGE_CUT_BY_LOCK)
            assertTrue(crashes.isEmpty(), "$kind: $crashes")
        }
    }

    @Test
    fun anImportALockOvertookIsSaidOnTheLockScreen() {
        val (api, m) = open()
        val c = assertNotNull(m.content.value)
        val rows = (1..10).joinToString("") { "Site $it,https://s$it.example,me,pw$it\n" }
        assertEquals(ActionResult.Ok, bounded("the CSV to be read") { c.importCsv(("name,url,username,password\n" + rows).toByteArray()) })
        var fired = false
        c.observe { s -> if (s.csvImport?.progress?.done == 4 && !fired) { fired = true; api.lock() } }
        bounded("the import to answer after the lock") { c.confirmImport() }
        m.onSnapshot(api.snapshot)
        // Four of the ten went in before the lock: to check, never "do it again".
        assertOvertook(api, m, line = Placeholder.CHANGE_CUT_BY_LOCK)
        assertTrue(crashes.isEmpty(), "$crashes")
    }

    @Test
    fun aLockWithNothingRunningSaysNothing() {
        val (api, m) = open()
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.saidOn(api.snapshot))
    }

    @Test
    fun workOnTheOpenVaultThatThrowsTheKeysAreGoneEndsQuietlyAndAnythingElseStillFails() {
        var locked = false
        val faults = ArrayList<Throwable>()
        val sink = FaultSink { t, _ -> faults += t }
        scope.launchOvertakable({ locked = true }, sink) { throw KeysGoneException() }
        assertTrue(locked)
        assertTrue(crashes.isEmpty())
        WorkScope(scope, { locked = false }, sink).launch { throw IllegalStateException("wrapped", KeysGoneException()) }
        assertFalse(locked, "the work scope's launches are overtakable")
        assertTrue(faults.isEmpty(), "a lock is not a fault")
        // Anything else is a fault, never a crash and never a lock.
        scope.launchOvertakable({ locked = true }, sink) { throw IllegalArgumentException("not a lock") }
        assertEquals(1, faults.size)
        assertFalse(locked)
        assertTrue(crashes.isEmpty())
        assertEquals(7, Overtaken.orLocked({ 7 }) { throw KeysGoneException() })
        // Every place the vault screens launch work goes through the work scope; no other scope is held there.
        for (f in listOf("VaultItemsScreens.kt", "VaultScreens.kt", "VaultTransferScreens.kt", "VaultHealthScreens.kt")) {
            val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$f").readText()
            assertFalse(src.contains("rememberCoroutineScope"), "$f holds a scope whose work a lock could crash")
            assertFalse(src.contains("import kotlinx.coroutines.launch"), f)
            assertTrue(src.contains("rememberWorkScope()"), f)
        }
        // The model's own launches are overtakable too, and so is the one-time code's loop.
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustModel.kt").readText()
        assertEquals(1, Regex("scope\\.launch \\{").findAll(model).count(), "only launchIntent launches plainly, and it catches the lock itself")
        val items = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()
        val otp = items.substringAfter("private fun OneTimeCodeRow(").substringBefore("\n}\n")
        assertTrue(otp.contains("Overtaken.orLocked(overtook)") && otp.contains("Overtaken.handle(t, overtook, fault, null)"))
        // Said on a screen already drawn (the lock screen, once a lock overtook work) shows at once: the place that says it
        // reads the state itself, so a screen whose own inputs did not change is not skipped (found in a run against a local server).
        val ui = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustUi.kt").readText()
        assertTrue(ui.substringAfter("internal fun SaidHere(").substringBefore("\n}\n").contains("model.said.collectAsState().value"))
        // Nothing of it is logged.
        val overtaken = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/Overtaken.kt").readText()
        assertFalse(overtaken.contains("log") && overtaken.contains("DesktopDiagnostics."), "nothing is logged")
    }
}
