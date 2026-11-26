package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.overlayUnlock
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.VaultUnlockResult
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
 * An unlock from the autofill window makes no recovery kit: no window of it can show one. For an account whose kit was
 * never confirmed, the window's unlock opens the vault for filling and the server's kit stays; when andvari itself is
 * then opened, it locks first, and the next unlock (with the master password: quick unlock stays off until a kit is
 * confirmed) shows the fresh kit. The device step of the earlier check (an autofill unlock of a never-saved account) is
 * this test's sequence, over the shared code's fake.
 */
class AutofillUnlockMakesNoKitTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    @Test
    fun theAutofillWindowsUnlockOfANeverSavedAccountOpensForFillingAndAndvariShowsTheKitAtItsNextUnlock() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val account = fake.script.publicInstance.accounts.values.first()
        account.kitSaved = false
        val serial = account.kitSerial
        val m = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)
        val locked = assertNotNull(fake.snapshot.locked)
        // The window's quick unlock: the shared code keeps it off while the kit is not confirmed, so it opens nothing and
        // makes no kit; the password is the way in.
        assertEquals(io.silencelen.andvari.core.app.QuickUnlockResult.USE_PASSWORD, runBlocking { fake.quickUnlock(locked) })
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)

        // The autofill window: the person types the master password.
        assertEquals(VaultUnlockResult.DONE, runBlocking { overlayUnlock(fake, assertNotNull(fake.snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(fake.snapshot)
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase, "open for filling")
        assertFalse(fake.snapshot.entry is EntryScreen.Kit, "no kit made where no window can show it")
        assertNull(fake.snapshot.account?.kit)
        assertEquals(serial, account.kitSerial, "the server's kit stays: nothing was sent about one")
        assertTrue(assertNotNull(fake.snapshot.account).kitDueAtOpening, "the kit is left to andvari's next opening")

        // andvari itself is opened: it locks first.
        m.openedAsTheApp()
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase, "locked before anything of the vault is shown")
        val again = assertNotNull(fake.snapshot.locked)
        assertEquals(io.silencelen.andvari.core.app.QuickUnlockResult.USE_PASSWORD, runBlocking { fake.quickUnlock(again) }, "the next unlock is with the master password")

        // The next unlock shows the fresh kit before the vault opens.
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val kit = assertIs<EntryScreen.Kit>(fake.snapshot.entry, "the kit, at andvari's own unlock").kit
        assertEquals(KitReason.NEVER_SAVED, kit.reason)
        assertEquals(KitStep.REVEAL, kit.step)
        assertEquals(serial + 1, account.kitSerial, "the server's kit is replaced only now, where it is shown")
    }

    @Test
    fun andvariOpenedWithNoKitDueLeavesTheVaultOpen() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)
        assertEquals(VaultUnlockResult.DONE, runBlocking { overlayUnlock(fake, assertNotNull(fake.snapshot.locked), FakeScenes.PASSWORD) })
        assertFalse(assertNotNull(fake.snapshot.account).kitDueAtOpening)
        m.openedAsTheApp()
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase, "a kit already confirmed: the vault the window opened stays open")
    }

    @Test
    fun theWindowAsksForTheUnlockForFillingAndOnlyAndvarisOwnWindowLocksForTheKit() {
        val overlay = main("autofill/AutofillUnlockActivity.kt").substringAfter("internal suspend fun overlayUnlock(").substringBefore("\n\n")
        assertTrue(overlay.indexOf("(api as? UnlockForFilling)?.unlockForFilling(locked, password)") in 0 until overlay.indexOf("FastUnlock"), "the unlock for filling first")
        val unlockAndFinish = main("autofill/AutofillUnlockActivity.kt").substringAfter("private fun unlockAndFinish(").substringBefore("\n    }\n")
        assertTrue("overlayUnlock(model.api, locked, password)" in unlockAndFinish, "the window's password unlock goes through it")
        // The lock for the kit is the activity's own start (TrustApp is MainActivity's), not the process's, which the
        // autofill window shares: the window's own start never locks what it just opened.
        val app = main("trust/TrustApp.kt").substringAfter("fun TrustApp(").substringBefore("\n}\n")
        assertTrue("androidx.lifecycle.compose.LocalLifecycleOwner.current" in app)
        assertTrue("if (event == Lifecycle.Event.ON_START) model.openedAsTheApp()" in app)
        val callers = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { f -> f.readLines().any { "openedAsTheApp()" in it.substringBefore("//") && "fun openedAsTheApp" !in it } }.map { it.name }.toSet()
        assertEquals(setOf("TrustApp.kt"), callers, "nothing else calls it")
        assertTrue("io.silencelen.andvari.app.trust.TrustApp(model)" in main("MainActivity.kt"))
    }
}
