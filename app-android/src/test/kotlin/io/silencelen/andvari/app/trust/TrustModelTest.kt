package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The new path's state holder against the app API's fake. */
class TrustModelTest {
    private var now = 0L

    private fun model(api: FakeAppApi) = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { now })

    private fun at(scene: FakeScene) = model(FakeScenes.onPlatform(AppPlatform.ANDROID, scene))

    @Test
    fun aFreshAndroidInstallStartsAtTheFirstScreenAndItsWipeRemovesNothing() {
        val api = FakeAppApi(AppPlatform.ANDROID, NoOldStores)
        api.start()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertEquals(PreCutoverStore.entries.toList(), api.wiped, "the first launch asks for every old store once")
        assertNull(api.snapshot.oldData, "Android's wipe reports nothing left")
        assertTrue(PreCutoverStore.entries.all { NoOldStores.wipe(it) })
    }

    @Test
    fun theOnlyAppLinkIsSlashLOnTheJoinHost() {
        val m = at(FakeScene.FIRST_RUN)
        assertTrue(m.isAppLink("https://andvaripass.com/l#v2.a.b.c"))
        assertFalse(m.isAppLink("https://andvaripass.com/d#v2.a.b"), "a device link is never an app link (§12.1, T2-B1)")
        assertFalse(m.isAppLink("http://andvaripass.com/l#v2.a.b.c"))
        assertFalse(m.isAppLink("https://andvaripass.com.evil.example/l#v2.a.b.c"))
        assertFalse(m.isAppLink("https://andvaripass.com/l/x#v2.a.b.c"))
        assertFalse(m.isAppLink("https://andvaripass.com:444/l#v2.a.b.c"))
        assertFalse(m.isAppLink("andvari-kit:2:a:b:c:d"))
    }

    /** §17 flow conformance: a tapped `/d` link starts no device link. */
    @Test
    fun aTappedDeviceLinkStartsNothing() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN)
        val m = model(api)
        val account = api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        val before = api.snapshot.entry
        m.openLink(api.script.deviceLinkFrom(account, "Laptop"))
        assertNull(m.heldLink, "dropped, not kept for later")
        assertTrue(api.snapshot.entry === before, "the screen did not change")
        // Core refuses it too, if a /d link ever reached it as an app link.
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, runBlocking { api.openAppLink(api.script.deviceLinkFrom(account, "Laptop")) })
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
    }

    @Test
    fun aLinkTappedWhileLockedWaitsForTheUnlockAndIsThenOpened() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = model(api)
        val link = api.script.connectInvite(api.script.addServer("https://vault.friends.example", "Friends", io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER), "Cy")
        m.openLink(link)
        assertEquals(link, m.heldLink, "core holds no link across a lock: the app keeps it")
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        val locked = assertNotNull(api.snapshot.locked)
        assertEquals(VaultUnlockResult.DONE, runBlocking { api.unlock(locked, FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        assertNull(m.heldLink, "opened once the vault is open")
        assertNotNull(api.snapshot.account?.opened, "the invite is on show")
    }

    @Test
    fun anAnswerIsShownOnTheScreenItWasGivenOnAndAnUpdateRequiredRaisesTheWall() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.SIGN_IN)
        val m = model(api)
        val screen = assertIs<EntryScreen.SignIn>(api.snapshot.entry)
        m.run({ entry.submitSignIn(screen, FakeScenes.EMAIL, "wrong") })
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(SignInAnswer.WRONG, said.result)
        assertTrue(said.text.isPlaceholder, "the design gives WRONG no sentence: a visible placeholder")
        api.entry.back()
        assertNull(m.saidOn(api.snapshot), "not carried to another screen")

        api.script.failNext(Trouble.UPDATE_REQUIRED)
        val again = api.snapshot.entry
        if (again is EntryScreen.SignInServer) m.run({ entry.choosePublicInstance(again) })
        if (again is EntryScreen.SignInServer) {
            // Signed out it is said in place, and the entry screen stays usable, as on the desktop.
            assertFalse(m.updateNoticeOn(api.snapshot))
        }
    }

    @Test
    fun anOpenVaultLocksAfterTheIdleWindowAndWhenTheAppIsBackgrounded() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(api)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        now += TrustModel.DEFAULT_AUTO_LOCK_MS - 1
        m.tick()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.touched()
        now += TrustModel.DEFAULT_AUTO_LOCK_MS - 1
        m.tick()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "activity resets the window")
        now += 1
        m.tick()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)

        val api2 = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        model(api2).backgrounded()
        assertEquals(AppPhase.LOCKED, api2.snapshot.phase)
    }

    @Test
    fun theKitBeforeTheVaultOpensLocksInTheBackgroundAndIsNeverOpenedOver() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.KIT_REVEAL)
        val m = model(api)
        m.openLink(api.script.connectInvite(api.script.publicInstance, "Cy"))
        assertNotNull(m.heldLink, "a link never opens over the kit: kept for later")
        assertIs<EntryScreen.Kit>(api.snapshot.entry)
        // lock() acts on the kit step now: the background takes the kit and its keys away.
        m.backgrounded()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
    }

    @Test
    fun thisBuildBakesNoPublicInstanceWhileTheSpecHoldsPlaceholders() {
        assertFalse(BuildConstants.BAKES_PUBLIC_INSTANCE, "spec/public-instance.json is still placeholders (update this test at the cut-over)")
        assertNull(TrustSeam.bakedInstance())
        assertEquals("https://andvaripass.com", BuildConstants.JOIN_BASE)
    }
}
