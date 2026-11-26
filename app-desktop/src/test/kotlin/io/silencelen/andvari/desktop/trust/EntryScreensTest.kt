package io.silencelen.andvari.desktop.trust

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.awt.image.BufferedImage
import java.awt.print.PageFormat
import java.awt.print.Printable
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The desktop's signed-out screens, the kit and the lock screen, at state level against the fake. The
 * module has no Compose test runtime, so a screen's choices are built as data
 * ([firstRunChoices], [trustGateConfirmLabel]) and tested here, and the composables are pinned by source where the rule
 * is about their shape.
 */
class EntryScreensTest {
    private var now = 0L

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { now })
    }

    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private val entrySource = File(dir + "EntryScreens.kt").readText()
    private val linkSource = File(dir + "LinkAndRecoveryScreens.kt").readText()
    private val kitSource = File(dir + "KitScreens.kt").readText()

    private fun body(source: String, fn: String) = source.substringAfter("fun $fn(").substringBefore("\n@Composable")

    @Test
    fun theFirstScreenHasThreeEqualChoicesThePasteOneFirstAndTheSignInLine() {
        val (api, _) = at(FakeScene.FIRST_RUN)
        val screen = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertTrue(screen.takesSetupLinks, "the desktop takes a server's setup link")
        val choices = firstRunChoices(screen)
        assertEquals(
            listOf(CopyKey.FIRST_PASTE_INVITE_LINK.english, CopyKey.FIRST_CREATE_ACCOUNT.english, CopyKey.FIRST_OWN_SERVER.english),
            choices.map { it.label.shown() },
        )
        assertTrue(choices.all { it.enabled })
        assertEquals(CopyKey.FIRST_CREATE_ACCOUNT_LINE.english, choices[1].line?.shown())
        val first = body(entrySource, "FirstRunScreen")
        assertTrue(first.contains("EqualChoice(choice.label") && first.contains("CopyKey.FIRST_SIGN_IN"))
        // The one exception: a kit's idle warning line takes the focus where the window has it, so that a screen reader
        // reads it (the toolkit announces no line that appears). Nowhere else, and never a control.
        val warningLine = File(dir + "TrustUi.kt").readText().substringAfter("internal fun KitIdleWarningLine(").substringBefore("\n}\n")
        assertTrue(warningLine.contains("requester.requestFocus()"))
        val all = File(dir).listFiles()!!.joinToString("\n") { it.readText() }.replace(warningLine, "")
            .lines().filterNot { it.startsWith("import ") }.joinToString("\n")
        assertFalse(all.contains("FocusRequester") || all.contains("requestFocus"), "nothing is focused by itself")
    }

    @Test
    fun withoutABakedInstanceThereIsNoCreateAccountButtonAndAFullOneIsDisabled() {
        val none = firstRunChoices(assertIs(at(FakeScene.FIRST_RUN_NO_PUBLIC_INSTANCE).first.snapshot.entry))
        assertEquals(listOf(CopyKey.FIRST_PASTE_INVITE_LINK.english, CopyKey.FIRST_OWN_SERVER.english), none.map { it.label.shown() })
        val full = firstRunChoices(assertIs(at(FakeScene.FIRST_RUN_SIGNUP_FULL).first.snapshot.entry))[1]
        assertEquals(CopyKey.FIRST_SIGNUP_FULL.english, full.label.shown())
        assertFalse(full.enabled)
        val unknown = firstRunChoices(assertIs(at(FakeScene.FIRST_RUN_SIGNUP_NOT_KNOWN).first.snapshot.entry))[1]
        assertTrue(unknown.enabled, "a mode not known is never shown as closed")
    }

    @Test
    fun theChoicesLeadWhereTheDesignSays() {
        val (api, model) = at(FakeScene.FIRST_RUN)
        val choices = firstRunChoices(assertIs(api.snapshot.entry))
        choices[0].go(model, assertIs(api.snapshot.entry))
        assertIs<EntryScreen.InviteEntry>(api.snapshot.entry)
        api.entry.back()
        choices[2].go(model, assertIs(api.snapshot.entry))
        assertIs<EntryScreen.OwnServer>(api.snapshot.entry)
        api.entry.back()
        choices[1].go(model, assertIs(api.snapshot.entry))
        assertIs<EntryScreen.SignUpEmail>(api.snapshot.entry)
    }

    /** §17: a kit or a device link pasted on "Paste an invite link" starts nothing, says only the API's sentence, and is forwarded nowhere. */
    @Test
    fun aKitOrADeviceLinkOnPasteAnInviteLinkStartsNothing() {
        val (api, model) = at(FakeScene.INVITE_ENTRY)
        val account = api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        val screen = assertIs<EntryScreen.InviteEntry>(api.snapshot.entry)

        model.run({ entry.submitInvite(screen, api.script.kitOf(account), PayloadSource.PASTED) })
        assertTrue(api.snapshot.entry === screen, "the screen stays as it was")
        val kitSaid = assertNotNull(model.saidOn(api.snapshot))
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, kitSaid.result)
        assertEquals(CopyKey.KIT_NOT_AN_INVITE.english, kitSaid.text.shown(), "the sentence alone, no directions (FC-9)")

        model.run({ entry.submitInvite(screen, api.script.deviceLinkFrom(account, "Laptop"), PayloadSource.PASTED) })
        assertTrue(api.snapshot.entry === screen)
        val linkSaid = assertNotNull(model.saidOn(api.snapshot))
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, linkSaid.result)
        assertEquals(CopyKey.DEVICE_LINK_GOES_ELSEWHERE.english, linkSaid.text.shown())

        val invite = body(entrySource, "InviteEntryScreen")
        assertTrue(invite.contains("entry.submitInvite("))
        assertFalse(invite.contains("submitDeviceLink") || invite.contains("submitKit") || invite.contains("submitTypedKit"))
    }

    /** §17: a kit or an invite on "Link from your other device" starts nothing; it takes device links only. */
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
        val entry = body(linkSource, "LinkDeviceEntryScreen")
        assertTrue(entry.contains("entry.submitDeviceLink("))
        assertFalse(entry.contains("submitInvite") || entry.contains("submitKit") || entry.contains("submitTypedKit"), "nothing forwarded to another entry")
    }

    /** §17: the new device shows its digits and has no control that confirms them; they are typed on the other device. */
    @Test
    fun theNewDeviceShowsItsDigitsAndNothingThatConfirmsThem() {
        val (api, _) = at(FakeScene.LINK_DEVICE_CODE)
        val screen = assertIs<EntryScreen.LinkDeviceCode>(api.snapshot.entry)
        assertEquals(6, screen.code.count { it.isDigit() })
        val shown = body(linkSource, "LinkDeviceCodeScreen")
        assertFalse(shown.contains("Main(") || shown.contains("Second("), "no confirm, no 'they match'")
    }

    /** §17: an invite or a device link on the kit entry starts no recovery; only a kit does, and nothing is forwarded. */
    @Test
    fun theKitEntryTakesKitsOnly() {
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
        val entry = body(linkSource, "KitEntryScreen")
        assertTrue(entry.contains("entry.submitKit(") && entry.contains("entry.submitTypedKit("))
        assertFalse(entry.contains("submitInvite") || entry.contains("submitDeviceLink"))
    }

    @Test
    fun aVerifiedRecoveryLeftAloneIsDroppedAfterFiveMinutes() {
        val (api, m) = at(FakeScene.REPLACE_PASSWORD)
        now += TrustModel.RECOVERY_IDLE_MS - 1
        m.tick()
        assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        now += 1
        m.tick()
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "startOver dropped what the recovery opened")
        assertEquals(Placeholder.RECOVERY_IDLE_DROPPED, assertIs<UiText.Ph>(m.saidOn(api.snapshot)?.text).placeholder, "it says why, by its key")
    }

    @Test
    fun anAddressTheGrammarRefusesIsSaidInPlaceAndAGoodOneRaisesTheGate() {
        val (api, model) = at(FakeScene.OWN_SERVER)
        val screen = assertIs<EntryScreen.OwnServer>(api.snapshot.entry)
        model.run({ entry.submitServerAddress(screen, "http://10.0.0.5") })
        val said = assertNotNull(model.saidOn(api.snapshot))
        assertEquals(ServerResult.NOT_AN_ADDRESS, said.result)
        assertEquals(CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN.english, said.text.shown())

        api.script.addServer("https://vault.friends.example", "Friends", ServerKind.PRIVATE_SERVER)
        model.run({ entry.submitServerAddress(screen, "https://vault.friends.example") })
        val gate = assertIs<EntryScreen.TrustGate>(api.snapshot.entry)
        assertEquals(TrustGateWording.TYPED_ADDRESS, gate.prompt.wording)
        assertEquals(CopyKey.GATE_TITLE_CONNECT.english, trustGateTitle(gate.prompt).shown())
        assertEquals(Placeholder.TRUST_GATE_CONNECT, assertIs<UiText.Ph>(trustGateConfirmLabel(gate.prompt)).placeholder, "the design names no confirm button for this wording: the app's own line, by its key")
        model.act { entry.declineTrustGate(gate) }
        assertFalse(api.snapshot.entry is EntryScreen.TrustGate, "Cancel leaves the gate, nothing pinned")
        // Cancel comes first and nothing confirms on Enter.
        val gateBody = body(entrySource, "TrustGateScreen")
        assertTrue(gateBody.indexOf("CopyKey.CANCEL") < gateBody.indexOf("confirmTrustGate"))
        assertFalse(gateBody.contains("onEnter"))
    }

    @Test
    fun theDeviceLinkGateSaysItsTheSameAndAStoppedServerOffersForgettingThatDeletesTheCopy() {
        val device = assertIs<EntryScreen.TrustGate>(at(FakeScene.GATE_DEVICE_LINK).first.snapshot.entry)
        assertEquals(CopyKey.GATE_ITS_THE_SAME.english, trustGateConfirmLabel(device.prompt).shown())
        val (stopped, _) = at(FakeScene.SERVER_STOPPED)
        val changed = assertIs<EntryScreen.ServerChanged>(stopped.snapshot.entry)
        assertIs<InstanceCardState.Stopped>(changed.instance.card)
        val card = entrySource.substringAfter("is InstanceCardState.Stopped ->").substringBefore("is InstanceCardState.Damaged")
        assertTrue(card.contains("CopyKey.CARD_FORK") && card.contains("ForgetServerButton"))
        assertTrue(body(entrySource, "ForgetServerButton").contains("Placeholder.FORGET_DELETES_COPY"), "the sentence says it deletes this copy")
    }

    @Test
    fun signingUpOnAServerEndsInTheKitAndTheKitConfirmsOnlyWithTypedGroups() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.REVEAL, kit.step)
        val doc = assertNotNull(api.kit.kitDocument(kit))
        assertEquals(11, doc.groups.size)
        m.act { this.kit.proceedToConfirm(kit) }
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        m.run({ this.kit.confirmKit(confirm, confirm.groupsToType.map { "zzzz" }) })
        assertNotNull(m.saidOn(api.snapshot), "a wrong group is said in place")
        val right = confirm.groupsToType.map { doc.groups[it - 1] }
        m.run({ this.kit.confirmKit(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit, right) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the vault opens once the kit is confirmed")
    }

    /** Printed through the system dialog only; no Copy, no Save PDF, nothing selectable. */
    @Test
    fun theKitHasNoCopyNoSaveOfItsOwnAndNothingSelectable() {
        val reveal = body(kitSource, "KitReveal")
        assertTrue(reveal.contains("printKit(model.holdForPrint(doc),"))
        for (needle in listOf("clipboard", "Clipboard", "SelectionContainer", "FileDialog", "JFileChooser", "writeBytes", "FileOutputStream")) {
            assertFalse(kitSource.contains(needle), "KitScreens.kt holds $needle")
        }
        assertTrue(kitSource.contains("PrinterJob.getPrinterJob()") && kitSource.contains("job.printDialog()"))
    }

    @Test
    fun theKitQrDecodesBackToItsPayloadAndThePageDraws() {
        val (api, _) = at(FakeScene.KIT_REVEAL)
        val doc = assertNotNull(api.kit.kitDocument(assertIs<EntryScreen.Kit>(api.snapshot.entry).kit))
        val img = qrImage(doc.qrPayload)
        val px = IntArray(img.width * img.height).also { img.getRGB(0, 0, img.width, img.height, it, 0, img.width) }
        // One pixel per module is too small for the reader's sampling: scale by 4 first.
        val big = BufferedImage(img.width * 4, img.height * 4, BufferedImage.TYPE_INT_RGB).also { b ->
            for (y in 0 until b.height) for (x in 0 until b.width) b.setRGB(x, y, px[(y / 4) * img.width + x / 4])
        }
        val bigPx = IntArray(big.width * big.height).also { big.getRGB(0, 0, big.width, big.height, it, 0, big.width) }
        val decoded = QRCodeReader().decode(
            BinaryBitmap(HybridBinarizer(RGBLuminanceSource(big.width, big.height, bigPx))),
            mapOf(DecodeHintType.PURE_BARCODE to true),
        )
        assertEquals(doc.qrPayload, decoded.text)

        val page = BufferedImage(612, 792, BufferedImage.TYPE_INT_RGB)
        val g = page.createGraphics()
        assertEquals(Printable.PAGE_EXISTS, KitPrintable(KitPrintHold(doc)).print(g, PageFormat(), 0))
        assertEquals(Printable.NO_SUCH_PAGE, KitPrintable(KitPrintHold(doc)).print(g, PageFormat(), 1))
        g.dispose()
    }

    @Test
    fun theLockScreenNamesTheAccountAndAWrongPasswordIsSaidInPlace() {
        val (api, m) = at(FakeScene.LOCKED)
        val locked = assertNotNull(api.snapshot.locked)
        val title = lockTitle(locked).shown()
        assertTrue(title.contains(locked.prompt.instance.origin), "the origin is named (§4.4): $title")
        m.run({ unlock(locked, "wrong") })
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNotNull(m.saidOn(api.snapshot))
        m.run({ unlock(assertNotNull(api.snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    @Test
    fun theSignInTitleNamesTheTypedAccountAndTheInstance() {
        val (api, _) = at(FakeScene.SIGN_IN)
        val screen = assertIs<EntryScreen.SignIn>(api.snapshot.entry)
        assertNull(signInTitle(screen, "  "), "before an address is typed the server's name and origin name it")
        val named = assertNotNull(signInTitle(screen, "bo@example.com")).shown()
        assertTrue(named.contains("bo@example.com") && named.contains(screen.prompt.instance.origin), named)
    }

    /** The gate's cautions are the old desktop's (§12.3 "the existing cautions"), with audit H68's loopback split. */
    @Test
    fun plainHttpIsCalledLocalOnlyWhereItNeverLeavesThisComputer() {
        for (o in listOf("http://127.0.0.1:8080", "http://127.0.1.1", "http://localhost:3000", "http://[::1]:8080")) assertTrue(httpCautionIsLoopback(o), o)
        for (o in listOf("http://10.0.0.5", "http://127.0.0.1.evil.example", "http://localhost.example")) assertFalse(httpCautionIsLoopback(o), o)
        // Word for word the old gate's sentences (the old DesktopState.kt's TRUST_GATE_HTTP_LOOPBACK and TRUST_GATE_HTTP_LAN,
        // pinned by value now that the file is gone).
        assertEquals("This is an unencrypted http:// address on this computer. Traffic to it never leaves the machine, so it isn't exposed to the network.", HTTP_LOOPBACK_CAUTION)
        assertEquals("This is an unencrypted http:// connection — traffic to this server can be read on the network. Only continue on a network you trust.", HTTP_LAN_CAUTION)
    }

    @Test
    fun fillCopyFillsOncePerPlace() {
        assertEquals("Recover {1} on x (y)", fillCopy(CopyKey.KIT_RECOVER, "{1}", "x", "y"))
    }
}
