package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Settings › Change master password: a line of its own for each outcome, what follows a change, and a kept sign-in after it. */
class PasswordChangeTest {
    private val newPassword = "a brand new master password"

    private class Kept(override var on: Boolean, override var keptFor: String?) : SignInKeeping {
        override fun set(on: Boolean, account: String?) {
            this.on = on
            keptFor = account
        }
    }

    private fun unlocked(keeping: SignInKeeping = SignInKeeping.Never): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, keeping)
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun change(m: TrustModel, current: String, replacement: String) =
        m.runSaying({ settings.changeMasterPassword(current, replacement) }, { passwordChangeLine(it) })

    private fun saidPlaceholder(api: FakeDesktopAppApi, m: TrustModel): Placeholder? =
        (m.saidOn(api.snapshot)?.text as? UiText.Ph)?.placeholder

    @Test
    fun eachOutcomeHasItsOwnLine() {
        val (api, m) = unlocked()
        change(m, "not the password", newPassword)
        assertEquals(Placeholder.PASSWORD_CHANGE_WRONG, saidPlaceholder(api, m))
        change(m, FakeScenes.PASSWORD, "short")
        assertEquals(Placeholder.PASSWORD_CHANGE_WEAK, saidPlaceholder(api, m), "too weak, and nothing sent")
        api.script.forceNext(PasswordChangeResult.CHANGED_ELSEWHERE)
        change(m, FakeScenes.PASSWORD, newPassword)
        assertEquals(Placeholder.PASSWORD_CHANGE_ELSEWHERE, saidPlaceholder(api, m))
        api.script.failNext(Trouble.UNREACHABLE)
        change(m, FakeScenes.PASSWORD, newPassword)
        assertEquals(Placeholder.PASSWORD_CHANGE_NO_ANSWER, saidPlaceholder(api, m), "the server not answering is never read as 'not changed'")
        // Four outcomes, four different lines; done says nothing in place.
        val lines = listOf(PasswordChangeResult.WRONG_PASSWORD, PasswordChangeResult.WEAK_PASSWORD, PasswordChangeResult.CHANGED_ELSEWHERE, PasswordChangeResult.UNREACHABLE)
            .map { (passwordChangeLine(it) as UiText.Ph).placeholder }
        assertEquals(4, lines.toSet().size)
        assertNull(passwordChangeLine(PasswordChangeResult.DONE))
        assertTrue(passwordChangeLine(PasswordChangeResult.RATE_LIMITED, 7)!!.shown().contains("7"), "other troubles as any intent's")
    }

    @Test
    fun afterTheChangeTheNewPasswordOpensThisComputersCopyAndTheOldOneDoesNot() {
        val kept = Kept(on = true, keptFor = null)
        val (api, m) = unlocked(kept)
        val account = assertNotNull(api.snapshot.account).accountId
        assertEquals(account, kept.keptFor)
        change(m, FakeScenes.PASSWORD, newPassword)
        assertNull(m.saidOn(api.snapshot), "done: nothing said in place")
        m.onSnapshot(api.snapshot)
        assertTrue(kept.on, "keep me signed in stays on through a change")
        assertEquals(account, kept.keptFor)

        m.lockNow()
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result, "the old password no longer opens it")
        m.run({ unlock(assertNotNull(snapshot.locked), newPassword) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the kept session opens with the new one")
        assertTrue(kept.on)
    }

    /**
     * The desktop's side of a kept sign-in through a change: core writes the rewrapped session through the home's
     * secure file (`persist()` after `passwordChanged`); the write is wrapped with the same key-store key, and a restart
     * of the app opens the rewritten one, not the one from before the change.
     */
    @Test
    fun theKeptFileFollowsTheRewriteAndARestartOpensTheRewrittenSession() {
        val root = Files.createTempDirectory("andvari-change").toFile().also { it.deleteOnExit() }
        val store = TestKeyStore()
        val home = DesktopHome(root, store, log = {}).also { it.setKeepSignIn(true, "acct-1") }
        home.secureFile.replace("""{"wrappedUvk":"under-the-old-password"}""")
        home.secureFile.replace("""{"wrappedUvk":"under-the-new-password"}""")
        assertEquals(1, store.keys.size, "one key-store item, reused")
        val restarted = DesktopHome(root, store, log = {})
        assertEquals(Keep.ON, restarted.keepAtStart)
        assertEquals("""{"wrappedUvk":"under-the-new-password"}""", restarted.secureFile.read())
        assertEquals(KeptForm.WRAPPED, restarted.secureFile.form)
    }

    @Test
    fun theSectionSaysEachOutcomeInItsOwnWordsAndWhatFollowsAChange() {
        val section = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/SettingsScreens.kt").readText()
            .substringAfter("internal fun ChangePasswordSection(").substringBefore("\n}\n")
        assertTrue(section.contains("runSaying({ settings.changeMasterPassword(c, r) }, { passwordChangeLine(it, model.api.retryAfterSeconds()) })"))
        assertTrue(section.contains("for (p in if (previousOpensHere) PASSWORD_CHANGED_PREVIOUS_OPENS_LINES else PASSWORD_CHANGED_LINES) Say(p)") && section.contains("changed = true"))
        assertTrue(section.contains("CopyKey.MASTER_PASSWORD_FOR"), "the account and the instance are named")
    }
}
