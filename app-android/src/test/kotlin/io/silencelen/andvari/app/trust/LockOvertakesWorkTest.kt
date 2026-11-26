package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.Overtaken
import io.silencelen.andvari.app.autofill.ContentFill
import io.silencelen.andvari.app.launchOvertakable
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FillCard
import io.silencelen.andvari.core.app.FillCredential
import io.silencelen.andvari.core.app.FillLogin
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.content.ContentNoticeKind
import io.silencelen.andvari.core.app.content.ContentState
import io.silencelen.andvari.core.app.content.LockCutKind
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.autofill.FillTarget
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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
 * The app on the shared code's fix for keys used after a lock. A lock landing during each kind of work the app launches:
 * the screen on show says it as the lock, in a sentence; never a crash, never a wrong password; a screen still there
 * keeps what was typed; and the open vault says, once it is open again, what the lock cut short.
 */
class LockOvertakesWorkTest {
    /** What reached the scope uncaught: on the phone, a crash. */
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, scope, BuildConstants.JOIN_BASE, { 0L })
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
    private fun open(): Pair<FakeAppApi, TrustModel> {
        val (api, m) = at(FakeScene.LOCKED)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun overtookSaid(api: FakeAppApi, m: TrustModel): UiText.Ph {
        val said = assertNotNull(m.saidOn(api.snapshot), "the screen on show says it")
        return assertIs<UiText.Ph>(said.text)
    }

    /** A held intent of the fake, with a lock landing while it waits, then let go. */
    private fun <R> lockDuring(api: FakeAppApi, m: TrustModel, start: () -> R) {
        api.script.holdNext()
        start()
        assertTrue(api.script.holding, "the intent is under way")
        m.act { lock() }
        api.script.releaseHold()
        m.onSnapshot(api.snapshot)
        assertTrue(crashes.isEmpty(), "nothing crashed: $crashes")
    }

    @Test
    fun anIntentThatThrowsTheKeysAreGoneIsTheLockNotACrashAndNothingElseIsSwallowed() {
        val (api, m) = open()
        var after = false
        m.run<PlainResult>({ throw KeysGoneException() }) { after = true }
        assertTrue(crashes.isEmpty(), "the keys being gone is not a crash: $crashes")
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the app shows the lock it is")
        assertEquals(Placeholder.LOCK_OVERTOOK, overtookSaid(api, m).placeholder)
        assertFalse(after, "nothing after it runs: a screen still there keeps what was typed")

        // Wrapped, it is the same lock.
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.run<PlainResult>({ throw IllegalStateException("outer", KeysGoneException()) })
        assertTrue(crashes.isEmpty())
        assertEquals(Placeholder.LOCK_OVERTOOK, overtookSaid(api, m).placeholder)

        // Any other failure is not swallowed, and not a crash either: it is said in place, as a
        // fault the app contained, never as the lock.
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.run<PlainResult>({ throw IllegalStateException("something else") })
        assertTrue(crashes.isEmpty(), "contained: $crashes")
        // An intent is the account's and names no vault: the general line (copy page, PQ16).
        assertEquals(Placeholder.WENT_WRONG, overtookSaid(api, m).placeholder)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "not the lock: the vault stays open")
    }

    @Test
    fun aPasswordChangeALockOvertookIsSaidOnTheLockScreenNeverAsAWrongPassword() {
        val (api, m) = at(FakeScene.VAULTS)
        lockDuring(api, m) {
            m.runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeWords(it, 0) })
        }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        val ph = overtookSaid(api, m)
        assertEquals(Placeholder.LOCK_OVERTOOK, ph.placeholder)
        assertNotEquals(Placeholder.PASSWORD_CHANGE_WRONG, ph.placeholder)
        // Not done: the old password still opens the vault.
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(m.saidOn(api.snapshot), "the unlock clears it")
    }

    @Test
    fun aDeletionALockOvertookDeletesNothingAndSaysSo() {
        val (api, m) = at(FakeScene.DELETION)
        val screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        lockDuring(api, m) {
            m.runIn(DELETION_SECTION, { settings.deleteAccount(screen, screen.email, FakeScenes.PASSWORD, null) }, { deletionWords(it, 0) }) { m.deletionAnswered(it) }
        }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the account is still here, locked")
        assertEquals(Placeholder.LOCK_OVERTOOK, overtookSaid(api, m).placeholder)
        assertNull((api.snapshot.entry as? io.silencelen.andvari.core.app.EntryScreen.FirstRun)?.accountDeleted, "nothing was deleted")
        assertFalse(m.deletionCannotTell())
    }

    @Test
    fun aDeviceLinkApprovalALockOvertookApprovesNothing() {
        val (api, m) = at(FakeScene.HOST_LINK_TYPE_DIGITS)
        val typing = assertIs<DeviceLinkHost.TypeDigits>(assertNotNull(api.snapshot.account).deviceLink)
        m.runIn(DEVICE_LINK_SECTION, { devices.submitDeviceDigits(typing, api.script.joiningDeviceCode) }, { deviceDigitsWords(it, 0) })
        val approvable = assertIs<DeviceLinkHost.Approvable>(assertNotNull(api.snapshot.account).deviceLink)
        lockDuring(api, m) {
            m.runIn(DEVICE_LINK_SECTION, { devices.approveWithPassword(approvable, FakeScenes.PASSWORD) }, { deviceLinkProofWords(it, 0) })
        }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        val ph = overtookSaid(api, m)
        assertEquals(Placeholder.LOCK_OVERTOOK, ph.placeholder)
        assertNotEquals(Placeholder.DEVICE_LINK_WRONG_PASSWORD, ph.placeholder)
    }

    @Test
    fun aKitConfirmALockOvertookIsSaidOnTheLockScreen() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        val reveal = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        m.act { kit.proceedToConfirm(reveal) }
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        lockDuring(api, m) {
            m.run({ kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertEquals(Placeholder.LOCK_OVERTOOK, overtookSaid(api, m).placeholder)
    }

    @Test
    fun aSharedVaultActionALockOvertookIsSaidAsTheLock() {
        val (api, m) = at(FakeScene.VAULTS)
        lockDuring(api, m) { m.run({ vaults.createVault("Trips") }) }
        assertEquals(Placeholder.LOCK_OVERTOOK, overtookSaid(api, m).placeholder)
    }

    /** A content write that a lock overtakes once it is under way (the content says busy), as on the phone. */
    private fun lockWhenBusy(api: FakeAppApi, c: VaultContent) {
        var fired = false
        c.observe { s -> if (s.busy && !fired) { fired = true; api.lock() } }
    }

    @Test
    fun aSaveAMoveADeletionAndAFileALockOvertookAreNotDoneAndTheOpenVaultSaysSoNextTime() {
        val kinds: List<Pair<String, suspend (VaultContent, String, String) -> ActionResult>> = listOf(
            "save" to { c, _, _ -> c.saveLogin(null, LoginInput("New", "me", "pw", listOf("https://new.example"), "", "", false), null) },
            "delete" to { c, id, _ -> c.deleteItem(id) },
            "move" to { c, id, shared -> c.moveOrCopyItem(id, shared, move = true) },
            "file" to { c, id, _ -> c.openAttachmentDraft(id); c.addAttachment("a.txt", "hello".toByteArray()) },
        )
        for ((kind, work) in kinds) {
            val (api, m) = open()
            val fake = assertNotNull(api.fakeContent)
            val personal = assertNotNull(m.content.value).vaultsForNewItems().first { it.personal }.vaultId
            val id = fake.seedLogin(personal, "Bank", "me", "pw", "https://bank.example")
            fake.addSharedVault("v-shared", "Trips", "owner", VaultStanding.VERIFIED)
            val c = assertNotNull(m.content.value)
            lockWhenBusy(api, c)
            val r = bounded("the $kind to answer after the lock") { work(c, id, "v-shared") }
            assertEquals(ActionResult.NotDone(null), r, "$kind: not done, and never a failure")
            assertEquals(AppPhase.LOCKED, api.snapshot.phase)
            m.onSnapshot(api.snapshot)
            assertNull(m.content.value)
            // Unlocked again: what the lock cut short is the reopened content's to say; the app adds no line of its own.
            m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
            m.onSnapshot(api.snapshot)
            val again = assertNotNull(m.content.value).state
            if (again.noticeKind != ContentNoticeKind.LOCK) assertTrue(noticeLines(again).none { it.isPlaceholder }, kind)
            assertTrue(crashes.isEmpty(), "$kind: $crashes")
        }
    }

    @Test
    fun anImportALockOvertookSaysHowFarItGotOnceTheVaultIsOpenAgain() {
        val (api, m) = open()
        val c = assertNotNull(m.content.value)
        val rows = (1..10).joinToString("") { "Site $it,https://s$it.example,me,pw$it\n" }
        assertEquals(ActionResult.Ok, bounded("the CSV to be read") { c.importCsv(("name,url,username,password\n" + rows).toByteArray()) })
        assertEquals(10, assertNotNull(c.state.csvImport).toImport)
        var fired = false
        c.observe { s -> if (s.csvImport?.progress?.done == 4 && !fired) { fired = true; api.lock() } }
        bounded("the import to answer after the lock") { c.confirmImport() }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        assertNull(m.content.value, "said in the open vault, not over the lock screen")
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        // An import is the shared code's to tell (the content's notice, saved and not saved): the app says nothing of its own.
        assertTrue(noticeLines(assertNotNull(m.content.value).state).none { it.isPlaceholder })
    }

    @Test
    fun whatALockCutShortIsSaidByTheReopenedContentOneLineEachWithItsCounts() {
        val (api, m) = open()
        val fake = assertNotNull(api.fakeContent)
        // Two things the lock cut short on the content it closed; the next unlock's content says them.
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        fake.raiseLockCut(LockCutKind.VAULT_COPY, "Family", "Personal", 3, 9)
        fake.raiseLockCut(LockCutKind.ITEM_DELETE, "Bank", "", 0, 0)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        val st = assertNotNull(m.content.value).state
        assertEquals(ContentNoticeKind.LOCK, st.noticeKind)
        assertEquals(2, st.lockCut.size)
        val lines = noticeLines(st).map { it.shown() }
        assertEquals(st.lockCut.map { it.line }, lines, "each thing on its own line, in the shared code's sentence")
        assertTrue(lines[0].contains("3") && lines[0].contains("9") && lines[0].contains("Family"), lines[0])
        assertTrue(noticeLines(io.silencelen.andvari.core.app.content.FakeVaultContent().state).isEmpty(), "no notice, no line")
        // The app's own lock line and its two placeholders are gone; the line at the moment of the lock stays.
        val model = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustModel.kt").readText()
        assertFalse(model.contains("overtookNotice") || model.contains("lockOvertookWords") || model.contains("overtookYields"))
        assertTrue(Placeholder.entries.none { it.name == "LOCK_OVERTOOK_COPY" || it.name == "LOCK_OVERTOOK_CHANGE" })
        assertTrue(Placeholder.entries.any { it.name == "LOCK_OVERTOOK" })
    }

    @Test
    fun workOnTheOpenVaultThatThrowsTheKeysAreGoneEndsQuietlyAndAnythingElseIsContained() {
        var locked = false
        var faults = 0
        scope.launchOvertakable(onLock = { locked = true }, onFault = { faults++ }) { throw KeysGoneException() }
        assertTrue(locked)
        assertEquals(0, faults, "the lock is not a fault")
        assertTrue(crashes.isEmpty())
        // Anything else is a fault the app contains and says, never a crash, and never the lock.
        locked = false
        scope.launchOvertakable(onLock = { locked = true }, onFault = { faults++ }) { throw IllegalArgumentException("not a lock") }
        assertEquals(1, faults)
        assertFalse(locked)
        assertTrue(crashes.isEmpty(), "contained: $crashes")
        // A cancellation is how work ends: it is neither.
        scope.launchOvertakable(onLock = { locked = true }, onFault = { faults++ }) { throw kotlinx.coroutines.CancellationException("ended") }
        assertEquals(1, faults)
        assertFalse(locked)
        assertEquals(7, Overtaken.orLocked({ 7 }) { throw KeysGoneException() })
        // Every place the vault screens launch work goes through it.
        for (f in listOf("VaultItemsScreens.kt", "VaultScreens.kt", "VaultTransferScreens.kt", "VaultHealthScreens.kt")) {
            val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/$f").readText()
            assertFalse(Regex("scope\\.launch\\s*\\{").containsMatchIn(src), "$f launches work outside launchOvertakable")
            assertTrue(src.contains("scope.launchOvertakable"), f)
        }
    }

    /** A content whose fill reads find the keys gone, as a lock landing between the fill's reads would. */
    private class KeysGoneContent(inner: VaultContent) : VaultContent by inner {
        override fun fillLogins(hosts: List<String>): List<FillLogin> = throw KeysGoneException()
        override fun fillCards(): List<FillCard> = throw KeysGoneException()
        override fun fillCredential(itemId: String): FillCredential? = throw KeysGoneException()
        override fun fillCardField(itemId: String, field: String): String? = throw KeysGoneException()
        override fun fillCredentialUnrecorded(itemId: String): FillCredential? = throw KeysGoneException()
        override fun fillCardFieldUnrecorded(itemId: String, field: String): String? = throw KeysGoneException()
        override fun recordFillPicked(itemId: String): Boolean = throw KeysGoneException()
        override fun recordFillPickedAt(itemId: String, pickedAtMs: Long): Boolean = throw KeysGoneException()
    }

    @Test
    fun theFillCallsALockOvertookOfferNothingAndReleaseNothing() {
        val (api, m) = open()
        val fake = assertNotNull(api.fakeContent)
        val personal = assertNotNull(m.content.value).vaultsForNewItems().first { it.personal }.vaultId
        val id = fake.seedLogin(personal, "Bank", "me", "pw", "https://bank.example")
        val c = KeysGoneContent(assertNotNull(m.content.value))
        val target = listOf(FillTarget(webHost = "bank.example", packageName = "com.android.chrome"))
        assertTrue(ContentFill.offersFor(c, target, listOf("bank.example"), cards = true).isEmpty())
        assertNull(ContentFill.release(c, id))
        assertNull(ContentFill.loginById(c, id))
        assertNull(ContentFill.cardById(c, id))
        assertTrue(ContentFill.cardLines(c).isEmpty())
        // A lock overtaking the record of a pick, with and without the offer's time: nothing recorded, nothing thrown.
        ContentFill.recordPicked(c, listOf(id), offeredAtMs = 0L)
        ContentFill.recordPicked(c, listOf(id), offeredAtMs = 1_700_000_000_000L)
        assertTrue(fake.recordedUses.isEmpty())
        // The same reads on the content itself find the login: the lock, not the vault, emptied them.
        assertNotNull(ContentFill.loginById(assertNotNull(m.content.value), id))
        assertTrue(crashes.isEmpty())
    }

    @Suppress("unused")
    private fun state(c: VaultContent): ContentState = c.state
}
