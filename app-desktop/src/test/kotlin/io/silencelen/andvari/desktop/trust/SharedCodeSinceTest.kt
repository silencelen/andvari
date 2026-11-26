package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DevicesApi
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** What the shared code bound since the desktop last took it, on the desktop's screens. */
class SharedCodeSinceTest {
    private fun model(api: DesktopAppApi) = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }

    /** A link to create an account where this computer is signed in: the approved sentence in place, nothing else said. */
    @Test
    fun theAlreadySignedInRefusalShowsTheApprovedSentence() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        m.runSaying({ links.openInvite(api.script.invitation(api.script.publicInstance, "Bo"), PayloadSource.PASTED) }, { openInviteLine(it) })
        assertNull(m.said.value, "no generic refusal beside it")
        val line = assertNotNull(api.snapshot.account?.inviteNotUsed)
        assertEquals(CopyKey.ALREADY_SIGNED_IN_THERE, line.key)
        val here = assertNotNull(api.snapshot.instance).label
        val shown = UiText.of(line).shown()
        assertTrue(shown.contains("You're already signed in there") && shown.contains(here.origin), shown)
        m.act { links.dismissOpened() }
        assertNull(api.snapshot.account?.inviteNotUsed)
        assertNotNull(openInviteLine(InviteResult.FAILED), "every other answer is still said")
        val links = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/LinksScreens.kt").readText()
        assertTrue(links.contains("account.inviteNotUsed?.let"))
    }

    @Test
    fun aChangeThisCopyCouldNotFollowIsSaidAsInForceNeverAsTryAgain() {
        assertNull(passwordChangeLine(PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE))
        assertEquals(Placeholder.PASSWORD_CHANGED_PREVIOUS_OPENS_HERE, PASSWORD_CHANGED_PREVIOUS_OPENS_LINES.first())
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        api.script.deviceCannotFollowPassword = true
        val m = model(api)
        m.runSaying({ settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer new master password 42!") }, { passwordChangeLine(it) })
        assertNull(m.said.value)
        m.lockNow()
        assertTrue(assertNotNull(api.snapshot.locked).previousPasswordOpensCopy)
        val lock = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText()
        assertTrue(lock.contains("locked.previousPasswordOpensCopy") && lock.contains("LOCKED_PREVIOUS_PASSWORD_OPENS"))
    }

    /** The devices list on show is read again once a link this computer showed is approved. */
    @Test
    fun theDevicesListIsReadAgainWhenALinkIsApproved() {
        val fake = FakeScenes.desktopAt(FakeScene.VAULTS)
        val api = Counting(fake)
        val m = model(api)
        m.run({ devices.openDevices() })
        m.run({ devices.startDeviceLink() })
        m.onSnapshot(api.snapshot)
        fake.script.joiningDeviceClaims("Pixel", AppPlatform.ANDROID)
        fake.script.joiningDeviceReveals(true)
        m.run({ devices.submitDeviceDigits(assertIs(api.snapshot.account?.deviceLink), fake.script.joiningDeviceCode) })
        m.onSnapshot(api.snapshot)
        assertEquals(1, api.opens)
        m.run({ devices.approveWithPassword(assertIs(api.snapshot.account?.deviceLink), FakeScenes.PASSWORD) })
        assertIs<DeviceLinkHost.Approved>(api.snapshot.account?.deviceLink)
        m.onSnapshot(api.snapshot)
        assertEquals(2, api.opens, "read again once approved")
        m.onSnapshot(api.snapshot)
        assertEquals(2, api.opens, "once")
    }

    @Test
    fun theLinesAwaitingTheOwnersWordingAreShownWhereNamed() {
        val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
        assertTrue(File(dir + "SettingsScreens.kt").readText().contains("UiText.of(screen.revokeLine)"))
        assertTrue(File(dir + "AccountEntryScreens.kt").readText().contains("Say(screen.codeLine)"))
        assertTrue(File(dir + "LinkAndRecoveryScreens.kt").readText().contains("Say(screen.setsPasswordLine)"))
        val seam = File(dir + "TrustSeam.kt").readText()
        assertTrue(seam.contains("requestStore = JsonDeviceState(home.requestFile)"), "assisted recovery's requests outlive a restart")
    }

    /** Assisted recovery's requests are kept whatever the switch says, wrapped; never unwrapped without a key store. */
    @Test
    fun theRequestStoreIsKeptWrappedWhateverTheSwitchSays() {
        val root = java.nio.file.Files.createTempDirectory("andvari-req").toFile().also { it.deleteOnExit() }
        val store = TestKeyStore()
        val h = DesktopHome(root, store, log = {}, keyStorePause = {})
        assertEquals(Keep.OFF, h.prefs.keep())
        h.requestFile.replace("""{"assist":"request"}""")
        val f = File(root, "v2/assist-requests.json")
        assertTrue(SessionWrap.isWrapped(f.readText()))
        assertEquals("""{"assist":"request"}""", DesktopHome(root, store, log = {}, keyStorePause = {}).requestFile.read())
        val none = java.nio.file.Files.createTempDirectory("andvari-req").toFile().also { it.deleteOnExit() }
        DesktopHome(none, NoKeyStore, log = {}).requestFile.replace("""{"assist":"request"}""")
        assertTrue(!File(none, "v2/assist-requests.json").exists(), "no key store: held in memory only")
    }

    private class Counting(val inner: FakeDesktopAppApi) : DesktopAppApi by inner {
        var opens = 0
        override val devices: DevicesApi = object : DevicesApi by inner.devices {
            override suspend fun openDevices(): PlainResult {
                opens++
                return inner.devices.openDevices()
            }
        }
    }
}
