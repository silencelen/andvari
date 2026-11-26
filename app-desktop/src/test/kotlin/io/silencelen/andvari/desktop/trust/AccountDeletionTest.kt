package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Settings › Delete account: the plan, the blockers, the typed address, retrying, and every end, unknown included. */
class AccountDeletionTest {
    private fun unlocked(keeping: SignInKeeping = SignInKeeping.Never, before: (FakeDesktopAppApi) -> Unit = {}): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        before(api)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, keeping)
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun opened(api: FakeDesktopAppApi, m: TrustModel): DeletionScreen {
        m.run({ settings.openDeletion() })
        m.onSnapshot(api.snapshot)
        val screen = assertNotNull(api.snapshot.account?.deletion)
        assertNotNull(screen.plan, "the plan is in")
        return screen
    }

    private fun said(api: FakeDesktopAppApi, m: TrustModel): Placeholder? = (m.saidOn(api.snapshot)?.text as? UiText.Ph)?.placeholder

    @Test
    fun theButtonWaitsForTheAccountsOwnAddressThePasswordAndNoBlocker() {
        val (api, m) = unlocked()
        val screen = opened(api, m)
        assertTrue(assertNotNull(screen.plan).canProceed)
        assertFalse(deletionReady(screen, "someone@else.example", "pw", ""), "another address")
        assertFalse(deletionReady(screen, FakeScenes.EMAIL, "", ""), "no password")
        assertTrue(deletionReady(screen, "  " + FakeScenes.EMAIL.uppercase() + " ", "pw", ""), "trimmed and case-folded, as the server compares")
        assertFalse(deletionReady(screen, FakeScenes.EMAIL, "pw", "", codeAsked = true), "the code once the server asked for it")
        assertTrue(deletionReady(screen, FakeScenes.EMAIL, "pw", "123456", codeAsked = true))
    }

    @Test
    fun everyEndHasItsOwnLineAndNoneSaysDeleted() {
        val (api, m) = unlocked()
        var screen = opened(api, m)
        m.deleteAccount(screen, "other@example.com", FakeScenes.PASSWORD, null)
        assertEquals(Placeholder.DELETION_EMAIL_MISMATCH, said(api, m))
        screen = assertNotNull(api.snapshot.account?.deletion)
        m.deleteAccount(screen, FakeScenes.EMAIL, "wrong", null)
        assertEquals(Placeholder.DELETION_WRONG_PASSWORD, said(api, m))

        api.script.deletionStaleRounds = 3
        m.deleteAccount(assertNotNull(api.snapshot.account?.deletion), FakeScenes.EMAIL, FakeScenes.PASSWORD, null)
        assertEquals(Placeholder.DELETION_STILL_CHANGING, said(api, m))
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "nothing was deleted")

        api.script.deletionFarFutureHead = true
        m.deleteAccount(assertNotNull(api.snapshot.account?.deletion), FakeScenes.EMAIL, FakeScenes.PASSWORD, null)
        assertEquals(DeletionResult.FAR_FUTURE, m.saidOn(api.snapshot)?.result)
        assertFalse(assertNotNull(m.saidOn(api.snapshot)).text.isPlaceholder, "the design's own sentence")
        api.script.deletionFarFutureHead = false

        val ends = DeletionResult.entries.filter { it != DeletionResult.DONE }.associateWith { deletionLine(it) }
        assertTrue(ends.values.all { it != null }, "every end but done says something")
        assertNull(deletionLine(DeletionResult.DONE))
        // Whatever the words are, in any case: no end but done says the account was deleted. "Nothing was deleted",
        // "nothing has been deleted", "may have been deleted" and "whether ... was deleted" do not say that.
        val claim = Regex("""\b(?:was|is|has been|have been) deleted\b""")
        fun saysDeleted(s: String): Boolean = !s.contains("whether") &&
            claim.findAll(s).any { m -> s.substring(0, m.range.first).let { !it.endsWith("nothing ") && !it.endsWith("may ") } }
        assertTrue(ends.values.none { saysDeleted(it!!.shown().lowercase()) }, "no end but done says deleted: " + ends.values.map { it!!.shown() }.filter { saysDeleted(it.lowercase()) })
        assertTrue(saysDeleted("your account was deleted.") && !saysDeleted("nothing was deleted.") && !saysDeleted("it may have been deleted."))
        val own = listOf(DeletionResult.EMAIL_MISMATCH, DeletionResult.WRONG_PASSWORD, DeletionResult.CODE_NEEDED, DeletionResult.WRONG_CODE, DeletionResult.BLOCKED, DeletionResult.STILL_CHANGING, DeletionResult.CHANGED_ELSEWHERE, DeletionResult.OUTCOME_UNKNOWN)
        assertEquals(own.size, own.map { (deletionLine(it) as UiText.Ph).placeholder }.toSet().size, "one line each")
    }

    /**
     * While a vault's history moves on, core retries by itself and the screen says so; nothing else is offered then.
     * (The fake retries within one call, so the in-between snapshot is not caught here: the section's source is pinned.)
     */
    @Test
    fun theRetryingStateIsShownWhileItRetries() {
        val (api, m) = unlocked()
        val screen = opened(api, m)
        api.script.deletionStaleRounds = 1
        m.deleteAccount(screen, FakeScenes.EMAIL, FakeScenes.PASSWORD, null)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "a retry that succeeds goes through")
        val section = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText().substringAfter("internal fun DeleteAccountSection(").substringBefore("\n}\n")
        assertTrue(section.contains("if (screen.retrying) Quiet(UiText.ph(Placeholder.DELETION_RETRYING))"))
    }

    @Test
    fun anUnknownOutcomeSaysItCannotTellOffersTheCheckAndTheCheckFindsTheAccountThere() {
        val (api, m) = unlocked()
        val screen = opened(api, m)
        api.script.deletionAnswerLost = true
        m.deleteAccount(screen, FakeScenes.EMAIL, FakeScenes.PASSWORD, null)
        assertEquals(Placeholder.DELETION_OUTCOME_UNKNOWN, said(api, m))
        val unknown = assertNotNull(api.snapshot.account?.deletion)
        assertTrue(unknown.outcomeUnknown)
        assertFalse(deletionReady(unknown, FakeScenes.EMAIL, FakeScenes.PASSWORD, ""), "nothing else is offered meanwhile")
        assertNull(m.accountDeletedNotice())
        m.checkDeletion(unknown)
        assertEquals(Placeholder.DELETION_STILL_THERE, said(api, m))
    }

    @Test
    fun aCheckAnsweredByTheSessionsEndSaysItCannotTellOnTheLockScreenAndKeepsTheCopy() {
        val root = Files.createTempDirectory("andvari-delete").toFile().also { it.deleteOnExit() }
        val store = TestKeyStore()
        val home = DesktopHome(root, store, log = {})
        val (api, m) = unlocked(HomeSignInKeeping(home))
        m.setKeepSignIn(true)
        home.secureFile.replace("""{"session":"kept"}""")
        val screen = opened(api, m)
        api.script.deletionAnswerLost = true
        api.script.deletionHappenedAnyway = true
        m.deleteAccount(screen, FakeScenes.EMAIL, FakeScenes.PASSWORD, null)
        m.checkDeletion(assertNotNull(api.snapshot.account?.deletion))
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertTrue(assertNotNull(api.snapshot.locked).signedOutByServer)
        // Core's own record says it (the desktop's flag is gone): the lock screen cannot tell.
        assertTrue(assertNotNull(api.snapshot.locked).deletionOutcomeUnknown, "the lock screen says it cannot tell")
        assertNull(m.accountDeletedNotice(), "never 'deleted'")
        assertTrue(File(root, "v2/secure-state.json").exists(), "the copy and its sign-in stay")
        assertEquals(1, store.keys.size)
        val lock = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText().substringAfter("internal fun LockScreen(").substringBefore("\n}\n")
        assertTrue(lock.contains("if (locked.deletionOutcomeUnknown) Say(UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN_LOCKED)"))
        assertFalse(lock.contains("cantTell"))
        // The first screen shows core's notice (AppInterfaceOffersTest drives it through the fake).
        val entry = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/EntryScreens.kt").readText().substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        assertTrue(entry.contains("screen.deletionOutcomeUnknown?.let { unknown ->") && entry.contains("Say(UiText.of(unknown.line))"))
    }

    /** After a deletion that is done, nothing of the account is left here: the kept session, its key-store item, the copy. */
    @Test
    fun aDoneDeletionLeavesNothingOfTheAccountOnThisComputer() {
        val root = Files.createTempDirectory("andvari-delete").toFile().also { it.deleteOnExit() }
        val store = TestKeyStore()
        val home = DesktopHome(root, store, log = {})
        val (api, m) = unlocked(HomeSignInKeeping(home))
        m.setKeepSignIn(true)
        // What a kept sign-in leaves on disk: the wrapped session (with its key-store item), the cache, the content.
        home.secureFile.replace("""{"session":"kept"}""")
        val cache = File(home.cacheDir, "vault-abc.db").apply { parentFile.mkdirs(); writeText("rows") }
        File(home.cacheDir, "vault-abc.db-wal").writeText("wal")
        assertTrue(home.content.storage.record("kept-abc").write(byteArrayOf(1)))
        assertTrue(File(root, "v2/secure-state.json").exists())
        assertEquals(1, store.keys.size)

        m.deleteAccount(opened(api, m), FakeScenes.EMAIL, FakeScenes.PASSWORD, null)
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val notice = assertNotNull(m.accountDeletedNotice(), "the first screen says it was deleted: core's notice")
        assertEquals(FakeScenes.EMAIL, notice.email)
        assertFalse(File(root, "v2/secure-state.json").exists(), "the kept session")
        assertTrue(store.keys.isEmpty(), "its key-store item")
        assertFalse(cache.exists(), "the copy")
        assertTrue(home.cacheDir.listFiles().orEmpty().isEmpty(), "and its journal")
        assertFalse(File(root, "v2/content/kept-abc").exists(), "and what a lock cut short")
        assertFalse(home.keepsAtRest(), "the switch is off: nothing is kept for an account that is gone")
        m.act { entry.dismissNotice(assertIs<EntryScreen.FirstRun>(snapshot.entry)) }
        assertNull(m.accountDeletedNotice())
        val first = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/EntryScreens.kt").readText().substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        assertTrue(first.contains("screen.accountDeleted?.let"), "core's notice, in place of the desktop's own flag")
        assertTrue(first.contains("Say(UiText.of(deleted.line))"))
    }

    @Test
    fun theCheckSaysTheAccountIsThereOnlyWhenTheServerSaysSo() {
        assertEquals(Placeholder.DELETION_STILL_THERE, (deletionCheckLine(PlainResult.DONE) as UiText.Ph).placeholder)
        assertNull(deletionCheckLine(PlainResult.STALE), "the lock screen says it")
        assertEquals(UiText.ph(Placeholder.VAULT_NAME_UNREADABLE).shown(), vaultNameOrUnreadable(""))
        assertEquals("Family", vaultNameOrUnreadable("Family"))
    }
}
