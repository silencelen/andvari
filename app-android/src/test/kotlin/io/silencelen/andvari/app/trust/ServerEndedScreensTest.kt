package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.fillUnlockNotice
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeletedVaultView
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The shared code's new states on Android's screens.
 * A session the server ended, unlock's STALE, an entry call's UNREACHABLE, "Recently deleted" and autofill under a
 * copy the server signed out.
 */
class ServerEndedScreensTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    /** A signed-in account with its vault open. */
    private fun unlocked(): Pair<FakeAppApi, TrustModel> {
        val (api, m) = at(FakeScene.LOCKED)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    @Test
    fun theLockScreenOfASessionTheServerEndedOpensTheCopyReadOnlyWithTheNoticeInView() {
        val (api, m) = unlocked()
        api.script.sessionEndedByServer()
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        // The password opens the copy read-only, and the open vault says it is a server-ended copy, not a fork.
        m.run({ unlock(locked, FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val account = assertNotNull(api.snapshot.account)
        assertTrue(account.serverStopped)
        assertTrue(m.openedSignedOutByServer())
        val line = assertIs<UiText.Ph>(stoppedLine(m, api.snapshot, account))
        assertEquals(Placeholder.SIGNED_OUT_BY_SERVER_OPEN, line.placeholder)
        // Locked again, "Sign in again" opens the journey with its notice; the mark goes with it.
        m.act { lock() }
        val again = assertNotNull(api.snapshot.locked)
        assertTrue(again.signedOutByServer)
        m.act { signInAgain(again) }
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertFalse(m.openedSignedOutByServer())

        val lock = src("trust/AccountScreens.kt").substringAfter("internal fun LockScreen(").substringBefore("internal fun lockTitle(")
        // The server's end is said through lockEndLine, which says this phone's own end in its place where it is that.
        assertTrue(lock.contains("lockEndLine(locked, signOutWayOutStands(s))?.let { Say(it, color = MaterialTheme.colorScheme.error) }"))
        assertEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), assertNotNull(lockEndLine(again)).shown())
        assertTrue(lock.contains("model.act { signInAgain(locked) }"))
        assertTrue(lock.contains("SignOutButton(model, s)"))
    }

    /**
     * The fact is the account snapshot's own ([AccountSnapshot.signedOutByServer]), so a model
     * that never saw the lock screen (a fill process, a recreated screen) still tells. The old inference from the
     * last lock screen answered false here.
     */
    @Test
    fun aModelThatNeverSawTheLockScreenStillTellsTheServerEndedCopy() {
        val (api, m) = unlocked()
        api.script.sessionEndedByServer()
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertTrue(assertNotNull(api.snapshot.account).signedOutByServer)
        val fresh = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        assertTrue(fresh.openedSignedOutByServer())
        assertIs<UiText.Ph>(stoppedLine(fresh, api.snapshot, assertNotNull(api.snapshot.account)))
        assertFalse(io.silencelen.andvari.app.autofill.AutofillSave.sessionTakesSaves(api.snapshot))
        assertFalse(src("trust/TrustModel.kt").contains("lockedByServer"), "nothing inferred from the last lock screen")
    }

    @Test
    fun anOrdinaryStopIsStillAForkLine() {
        val (api, m) = unlocked()
        val account = assertNotNull(api.snapshot.account)
        assertNull(stoppedLine(m, api.snapshot, account), "a running session says nothing")
        assertFalse(m.openedSignedOutByServer())
        // The old line was pinned to CARD_FORK for every stop; it is the fallback now.
        assertTrue(src("trust/AccountScreens.kt").contains("else -> UiText.of(CopyKey.CARD_FORK)"))
        assertEquals(CopyKey.CARD_FORK.english, (UiText.of(CopyKey.CARD_FORK) as UiText.Plain).text)
    }

    @Test
    fun unlockStaleAndEntryUnreachableAreSaidInPlace() {
        val stale = assertIs<UiText.Ph>(unlockWords(VaultUnlockResult.STALE, 0))
        assertEquals(Placeholder.UNLOCK_STALE, stale.placeholder)
        assertNull(unlockWords(VaultUnlockResult.DONE, 0))
        assertNotNull(unlockWords(VaultUnlockResult.WRONG_PASSWORD, 0))
        assertTrue(src("trust/AccountScreens.kt").contains("model.runSaying({ unlock(locked, password) }, { unlockWords(it, model.api.retryAfterSeconds()) })"))
        // An entry call that ran out its time answers UNREACHABLE: a visible line, never silence.
        val unreachable = assertIs<UiText.Ph>(UiText.forResult(SignInAnswer.UNREACHABLE, 0))
        assertEquals(Placeholder.TROUBLE_UNREACHABLE, unreachable.placeholder)
    }

    @Test
    fun recentlyDeletedListsTheOwnersVaultsAndRestoreGoesThroughTheApi() {
        val (api, m) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        fake.seedDeletedVault("Holiday", daysAgo = 2)
        assertEquals(ActionResult.Ok, runBlocking { c.openDeletedVaults() })
        val rows = assertNotNull(c.state.deletedVaults)
        assertEquals(listOf("Holiday"), rows.map { it.name })
        // A row not on show is STALE, said in place.
        val r = runBlocking { api.vaults.restoreDeletedVault(DeletedVaultView("x", "x", 0L, 0L)) }
        assertEquals(VaultActionResult.STALE, r)
        c.closeDeletedVaults()
        assertNull(c.state.deletedVaults)
        val screens = src("trust/VaultItemsScreens.kt")
        assertTrue(screens.contains("deleted != null -> DeletedVaultsView(model, c, state, deleted)"))
        assertTrue(screens.contains("model.run({ vaults.restoreDeletedVault(v) })"))
        // Reached from the vault's top-bar menu, as in the current app.
        assertTrue(src("trust/VaultHome.kt").contains("c.openDeletedVaults()"))
    }

    @Test
    fun autofillUnderASignedOutCopySaysItFillsFromTheCopyAndSavesNothing() {
        val (api, _) = unlocked()
        api.lock()
        assertNull(fillUnlockNotice(assertNotNull(api.snapshot.locked)))
        api.script.sessionEndedByServer()
        val notice = assertIs<UiText.Ph>(fillUnlockNotice(assertNotNull(api.snapshot.locked)))
        assertEquals(Placeholder.FILL_FROM_COPY, notice.placeholder)
        assertTrue(src("autofill/AutofillUnlockActivity.kt").contains("notice = fillUnlockNoticeText(locked),"))
        assertEquals(notice.shown(), io.silencelen.andvari.app.autofill.fillUnlockNoticeText(assertNotNull(api.snapshot.locked)), "the card says that notice alone")
        // Nothing is saved from autofill under that copy: the session takes no saves (AutofillSaveTest has the rest).
        assertFalse(io.silencelen.andvari.app.autofill.AutofillSave.sessionTakesSaves(api.snapshot))
    }
}
