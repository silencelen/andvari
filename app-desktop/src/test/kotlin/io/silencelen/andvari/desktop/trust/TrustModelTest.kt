package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.ServerPolicy
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The desktop's new state holder against the app API's fake. */
class TrustModelTest {
    /** The monotonic clock (stops while a Linux computer sleeps). */
    private var now = 0L

    /** The wall clock (counts through sleep; can be set back). */
    private var wall = 1_700_000_000_000L

    private fun model(api: FakeDesktopAppApi, keeping: SignInKeeping = SignInKeeping.Never) =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now }, keeping, wallMs = { wall })

    /** [ms] pass with the app running: both clocks move and the window ticks once a second. */
    private fun run(m: TrustModel, ms: Long) {
        var left = ms
        while (left > 0) {
            val step = minOf(1000L, left)
            now += step
            wall += step
            left -= step
            m.tick()
        }
    }

    private fun at(scene: FakeScene) = FakeScenes.desktopAt(scene).let { it to model(it) }

    @Test
    fun aFreshDesktopInstallStartsAtTheFirstScreenAndAsksTheWipeForEveryOldStore() {
        val asked = ArrayList<PreCutoverStore>()
        val api = FakeDesktopAppApi(stores { asked += it; true })
        api.start()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertEquals(PreCutoverStore.entries.toList(), asked)
        assertNull(api.snapshot.oldData)
    }

    private fun stores(answer: (PreCutoverStore) -> Boolean) = object : PreCutoverStores {
        override fun wipe(store: PreCutoverStore): Boolean = answer(store)
    }

    @Test
    fun aStoreTheWipeCouldNotRemoveIsReported() {
        val api = FakeDesktopAppApi(stores { it != PreCutoverStore.OFFLINE_CACHE })
        api.start()
        val left = assertNotNull(api.snapshot.oldData)
        assertEquals(listOf(PreCutoverStore.OFFLINE_CACHE), left.stores)
        assertTrue(left.tellNow)
    }

    @Test
    fun anAnswerIsShownOnTheScreenItWasGivenOn() {
        val (api, m) = at(FakeScene.SIGN_IN)
        val screen = assertIs<EntryScreen.SignIn>(api.snapshot.entry)
        m.run({ entry.submitSignIn(screen, FakeScenes.EMAIL, "wrong") })
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(SignInAnswer.WRONG, said.result)
        assertTrue(said.text.isPlaceholder, "the design gives WRONG no sentence: a visible placeholder")
        api.entry.back()
        assertNull(m.saidOn(api.snapshot), "not carried to another screen")
    }

    /** A hostile link's server answers "update required" while signed out. */
    @Test
    fun signedOutAnUpdateRequiredIsSaidInPlaceAndTheScreenStaysUsable() {
        val (api, m) = at(FakeScene.SIGN_IN)
        api.entry.back()
        val server = api.snapshot.entry
        assertIs<EntryScreen.SignInServer>(server)
        api.script.failNext(Trouble.UPDATE_REQUIRED)
        m.run({ entry.choosePublicInstance(server) })
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the screen it was answered on")
        assertEquals(Placeholder.UPDATE_REQUIRED, (said.text as UiText.Ph).placeholder)
        assertFalse(m.updateRequiredOn(api.snapshot), "no notice: no session's server answered")
        api.entry.back()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertFalse(api.snapshot.entry is EntryScreen.SignInServer, "Back still works")
    }

    /**
     * The person's own server, signed in. The notice is core's per-server state
     * ([io.silencelen.andvari.core.app.InstanceSnapshot.updateRequired]), no longer a record of the desktop's own.
     */
    @Test
    fun signedInAnUpdateRequiredIsANoticeAboveAVaultThatStaysOpenAndItClears() {
        val (api, m) = at(FakeScene.VAULTS)
        m.onSnapshot(api.snapshot)
        assertFalse(m.updateRequiredOn(api.snapshot))
        val server = assertNotNull(api.script.server(assertNotNull(api.snapshot.instance).label.origin))
        server.tooNewForThisBuild = true
        m.run({ vaults.createVault("Trips") })
        assertTrue(assertNotNull(api.snapshot.instance).updateRequired, "core's state for the session's server")
        assertTrue(m.updateRequiredOn(api.snapshot))
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the vault stays open")
        assertNotNull(m.content.value, "and readable from the copy")

        // A later answer from that server that is not "update required" clears it (core decides which answers count).
        server.tooNewForThisBuild = false
        m.run({ vaults.createVault("Trips 3") })
        assertFalse(m.updateRequiredOn(api.snapshot), "cleared with core's state")

        // Signed out, there is no notice.
        server.tooNewForThisBuild = true
        m.run({ vaults.createVault("Trips 4") })
        assertTrue(m.updateRequiredOn(api.snapshot))
        m.run({ signOut() })
        assertFalse(m.updateRequiredOn(api.snapshot), "signing out drops it")

        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustModel.kt").readText()
        assertFalse(model.contains("updateFlow"), "the desktop keeps no record of its own")
    }

    @Test
    fun theUpdateNoticeIsNoWallAndOffersNoSignOut() {
        val app = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustApp.kt").readText()
        assertFalse(app.contains("UpdateWall"), "no wall over the app")
        val notice = app.substringAfter("internal fun UpdateNotice(").substringBefore("\n}\n")
        assertFalse(notice.contains("SignOutButton"))
        assertTrue(notice.contains("ForgetServerButton"))
        val shell = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText()
        assertTrue(shell.contains("CompositionLocalProvider(LocalSavesHeld provides model.updateRequiredOn(s))"), "nothing offers a save meanwhile")
        assertTrue(shell.substringAfter("internal fun LockScreen(").substringBefore("\n}\n").contains("UpdateNotice(model, s)"))
        assertTrue(shell.substringAfter("private fun AttentionArea(").substringBefore("\n}\n").contains("UpdateNotice(model, s)"))
    }

    @Test
    fun anOpenVaultLocksAfterTheIdleWindowAndOnCtrlL() {
        val (api, m) = at(FakeScene.VAULTS)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        run(m, m.autoLockMs() - 1)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.touched()
        run(m, m.autoLockMs() - 1)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "activity resets the window")
        run(m, 1)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)

        val (api2, m2) = at(FakeScene.VAULTS)
        m2.lockNow()
        assertEquals(AppPhase.LOCKED, api2.snapshot.phase)
    }

    /** On Linux the monotonic clock stops while the lid is shut; the wall clock does not. */
    @Test
    fun timeAsleepCountsTowardTheIdleLock() {
        val (api, m) = at(FakeScene.VAULTS)
        run(m, 60_000)
        // The lid is shut for three hours: the monotonic clock stands still, the wall clock moves.
        wall += 3L * 60 * 60 * 1000
        now += 2
        m.tick()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the first tick after waking locks")
    }

    @Test
    fun aTickThatComesSecondsLateLocksWhateverTheClocksSayOfTheActivity() {
        val (api, m) = at(FakeScene.VAULTS)
        run(m, 3000)
        m.touched()
        // The process was stopped for a quarter of a minute (both clocks moved; nothing ticked).
        now += TrustModel.LATE_TICK_MS
        wall += TrustModel.LATE_TICK_MS
        m.tick()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)

        val (api2, m2) = at(FakeScene.VAULTS)
        run(m2, 5000)
        now += TrustModel.LATE_TICK_MS - 1000
        wall += TrustModel.LATE_TICK_MS - 1000
        m2.tick()
        assertEquals(AppPhase.UNLOCKED, api2.snapshot.phase, "a tick a few seconds late but under the limit does not")

        // A system file dialog that held the window's ticks and returned with the person's answer is not a late tick.
        val (api3, m3) = at(FakeScene.VAULTS)
        run(m3, 2000)
        now += 40_000
        wall += 40_000
        m3.dialogReturned()
        m3.tick()
        assertEquals(AppPhase.UNLOCKED, api3.snapshot.phase)
    }

    @Test
    fun aWallClockSetBackNeverLengthensTheWindow() {
        val (api, m) = at(FakeScene.VAULTS)
        m.touched()
        wall -= 24L * 60 * 60 * 1000
        var left = m.autoLockMs()
        while (left > 0) {
            now += 1000
            wall += 1000
            left -= 1000
            m.tick()
        }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the monotonic clock still counts the window")
    }

    /** Design point 9: before the policy is read, core reports its defaults (not its ceilings), and they are used as they come. */
    @Test
    fun beforeThePolicyIsReadTheWindowsAreTheSharedCodesDefaults() {
        val (_, signedOut) = at(FakeScene.FIRST_RUN)
        assertEquals(ServerPolicy.DEFAULT_AUTO_LOCK_SECONDS * 1000L, signedOut.autoLockMs(), "no account: core's default")
        assertEquals(ServerPolicy.DEFAULT_CLIPBOARD_CLEAR_SECONDS * 1000L, signedOut.clipboardClearMs())
        val (api, m) = at(FakeScene.VAULTS)
        val policy = assertNotNull(api.snapshot.account?.policy)
        assertEquals(policy.autoLockSeconds * 1000L, m.autoLockMs(), "the policy as core reports it")
        assertEquals(policy.clipboardClearSeconds * 1000L, m.clipboardClearMs())
        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustModel.kt").readText()
        assertFalse(model.contains("policyWindowMs") || model.contains("DEFAULT_AUTO_LOCK_MS"), "the desktop's own workaround is gone")
    }

    /** The kit step locks too (replaces the pin that said the kit step could not be locked). */
    @Test
    fun theKitOnShowLocksOnCtrlLAndAfterTheIdleWindow() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        assertIs<EntryScreen.Kit>(api.snapshot.entry)
        assertTrue(m.lockable())
        m.lockNow()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "Ctrl+L and the menu's Lock: the kit and the keys go")

        // The kit's own limit (every kit carries one), counted from the first tick it is on show.
        val (api2, m2) = at(FakeScene.KIT_REVEAL)
        val limit = assertNotNull(kitIdleLimitOf(api2.snapshot)?.idleLockAfterMs)
        run(m2, limit)
        assertIs<EntryScreen.Kit>(api2.snapshot.entry)
        run(m2, 1000)
        assertEquals(AppPhase.LOCKED, api2.snapshot.phase, "the idle timer")

        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        assertTrue(main.contains("Item(\"Lock\", shortcut = KeyShortcut(Key.L, ctrl = true), enabled = snapshot != null && model?.lockable(snapshot) == true)"))
    }

    @Test
    fun nothingElseOfTheJourneyIsLockable() {
        val (api, m) = at(FakeScene.SIGN_IN)
        assertFalse(m.lockable())
        m.lockNow()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
    }

    @Test
    fun theContentIsReadAgainAtEveryUnlockAndDroppedAtALock() {
        val (api, m) = at(FakeScene.VAULTS)
        m.onSnapshot(api.snapshot)
        val first = assertNotNull(m.content.value)
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertNull(m.content.value)
    }

    @Test
    fun keepingTheSignInFollowsTheSwitch() {
        var kept = false
        val keeping = object : SignInKeeping {
            override val on: Boolean get() = kept
            override fun set(on: Boolean, account: String?) { kept = on }
        }
        val (api, _) = at(FakeScene.SIGN_IN)
        val m = model(api, keeping)
        assertFalse(m.keepSignIn.value, "off by default")
        m.setKeepSignIn(true)
        assertTrue(kept && m.keepSignIn.value)
        m.setKeepSignIn(false)
        assertFalse(kept || m.keepSignIn.value)
    }

    @Test
    fun thisBuildBakesNoPublicInstanceWhileTheSpecHoldsPlaceholders() {
        assertFalse(BuildConstants.BAKES_PUBLIC_INSTANCE, "spec/public-instance.json is still placeholders (update this test at the cut-over)")
        assertNull(TrustSeam.bakedInstance())
        assertEquals("https://vault.andvaripass.com", BuildConstants.PUBLIC_ORIGIN)
    }

    @Test
    fun thePlatformIsWindowsOrLinux() {
        assertEquals(AppPlatform.WINDOWS, TrustSeam.desktopPlatform("Windows 11"))
        assertEquals(AppPlatform.LINUX, TrustSeam.desktopPlatform("Linux"))
    }

    /** §17 flow conformance on desktop: no link handler, so nothing of the new path opens an app link. */
    @Test
    fun nothingOpensAnAppLinkAndTheBuildRegistersNoUrlHandler() {
        val sources = File("src/main/kotlin").walk().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue(sources.isNotEmpty())
        for (f in sources) assertFalse(f.readText().contains("openAppLink("), "${f.name} calls openAppLink")
        val build = File("build.gradle.kts").readText()
        for (needle in listOf("x-scheme-handler", "MimeType", "protocol", "fileAssociation")) {
            assertFalse(build.contains(needle), "the build registers no handler ($needle)")
        }
    }

    @Test
    fun noInstallerIsMadeWhileTheSpecHoldsPlaceholders() {
        val build = File("build.gradle.kts").readText()
        assertTrue(build.contains("val checkStoreConstants = tasks.register(\"checkStoreConstants\")"))
        assertTrue(build.contains("""tasks.matching { it.name.startsWith("package") || it.name.contains("Distributable") }.configureEach { dependsOn(checkStoreConstants) }"""))
    }
}
