package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Linking this device and recovering with the kit on the new path, with §17's flow-conformance demands for both entries. */
class LinkAndRecoveryTest {
    private var now = 0L

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { now })
    }

    private val code = File("src/main/kotlin/io/silencelen/andvari/app/trust/LinkAndRecoveryScreens.kt").readText()

    private fun body(fn: String) = code.substringAfter("fun $fn(").substringBefore("\n@Composable")

    /** §17: a recovery kit (or an invite) scanned or pasted on "Link from your other device" starts nothing. */
    @Test
    fun linkFromYourOtherDeviceTakesDeviceLinksOnly() {
        val (api, m) = at(FakeScene.LINK_DEVICE_ENTRY)
        val account = api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        val screen = assertIs<EntryScreen.LinkDeviceEntry>(api.snapshot.entry)
        for (payload in listOf(api.script.kitOf(account), api.script.connectInvite(api.script.publicInstance, "Cy"))) {
            m.run({ entry.submitDeviceLink(screen, payload, PayloadSource.PASTED) })
            assertEquals(DeviceLinkScanResult.NOT_A_DEVICE_LINK, m.saidOn(api.snapshot)?.result)
            assertTrue(api.snapshot.entry === screen, "nothing started")
        }
        val entry = body("LinkDeviceEntryScreen")
        assertTrue(entry.contains("entry.submitDeviceLink("))
        assertFalse(entry.contains("submitInvite") || entry.contains("submitKit") || entry.contains("submitTypedKit"), "nothing forwarded to another entry")
    }

    /** §17: the new device shows its digits and has no control that confirms them; they are typed on the other device. */
    @Test
    fun theNewDeviceShowsItsDigitsAndNothingThatConfirmsThem() {
        val (api, _) = at(FakeScene.LINK_DEVICE_CODE)
        val screen = assertIs<EntryScreen.LinkDeviceCode>(api.snapshot.entry)
        assertEquals(6, screen.code.count { it.isDigit() })
        val shown = body("LinkDeviceCodeScreen")
        assertFalse(shown.contains("Main(") || shown.contains("Second("), "no confirm, no 'they match'")
        assertFalse(api.entry.back(), "a claimed link has no Back")
    }

    /** §17: an invite or a device link on "Scan your recovery kit" starts no recovery; only a kit does. */
    @Test
    fun scanYourRecoveryKitTakesKitsOnly() {
        val (api, m) = at(FakeScene.KIT_ENTRY)
        val account = api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        val screen = assertIs<EntryScreen.KitEntry>(api.snapshot.entry)
        for (payload in listOf(api.script.deviceLinkFrom(account, "Laptop"), api.script.connectInvite(api.script.publicInstance, "Cy"))) {
            m.run({ entry.submitKit(screen, payload, PayloadSource.PASTED) })
            assertEquals(KitScanResult.NOT_A_KIT, m.saidOn(api.snapshot)?.result)
            assertTrue(api.snapshot.entry === screen)
        }
        m.run({ entry.submitKit(screen, api.script.kitOf(account), PayloadSource.PASTED) })
        val recover = assertIs<EntryScreen.KitRecover>(api.snapshot.entry)
        assertEquals("Recover bo@example.com on ${recover.instance.name} (${recover.instance.origin})", UiText.of(recover.title).shown())
        val entry = body("KitEntryScreen")
        assertTrue(entry.contains("entry.submitKit(") && entry.contains("entry.submitTypedKit("))
        assertFalse(entry.contains("submitInvite") || entry.contains("submitDeviceLink"))
    }

    @Test
    fun aKitRecoveryEndsWithANewPasswordAndANewKit() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD)
        val screen = assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        m.run({ entry.chooseReplacementPassword(screen, "short") })
        assertEquals(ReplacePasswordResult.WEAK_PASSWORD, m.saidOn(api.snapshot)?.result)
        m.run({ entry.chooseReplacementPassword(screen, "a much longer master password, 2026!") })
        assertEquals(KitReason.AFTER_RECOVERY, assertIs<EntryScreen.Kit>(api.snapshot.entry).kit.reason)
    }

    @Test
    fun aVerifiedRecoveryLeftAloneIsDroppedAfterFiveMinutesOrInTheBackground() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD)
        now += TrustModel.RECOVERY_IDLE_MS - 1
        m.tick()
        assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        now += 1
        m.tick()
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "startOver dropped what the recovery opened")
        assertEquals(Placeholder.RECOVERY_IDLE_DROPPED, assertIs<UiText.Ph>(m.saidOn(api.snapshot)?.text).placeholder, "it says why, by its key")

        val (api2, m2) = at(FakeScene.REPLACE_PASSWORD)
        m2.backgrounded()
        assertIs<EntryScreen.FirstRun>(api2.snapshot.entry)
    }
}
