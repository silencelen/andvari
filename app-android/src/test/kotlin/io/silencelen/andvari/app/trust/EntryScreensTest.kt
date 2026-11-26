package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The signed-out screens of the new path, at state level against the fake (slices 3 and 4): what each screen offers,
 * where its intents lead, and §17's flow-conformance demands for "Scan an invite". The module has no Compose test
 * runtime offline, so a screen's choices are built as data ([firstRunChoices], [trustGateConfirmLabel]) and tested
 * here, and the composables are pinned by source where the rule is about their shape.
 */
class EntryScreensTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private val entrySource = File("src/main/kotlin/io/silencelen/andvari/app/trust/EntryScreens.kt").readText()

    @Test
    fun theFirstScreenHasThreeEqualChoicesInTheDesignsOrderAndTheSignInLine() {
        val (api, _) = at(FakeScene.FIRST_RUN)
        val screen = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val choices = firstRunChoices(screen)
        assertEquals(
            listOf(CopyKey.FIRST_SCAN_INVITE.english, CopyKey.FIRST_CREATE_ACCOUNT.english, CopyKey.FIRST_OWN_SERVER.english),
            choices.map { it.label.shown() },
        )
        assertTrue(choices.all { it.enabled })
        assertEquals(CopyKey.FIRST_CREATE_ACCOUNT_LINE.english, choices[1].line?.shown())
        // Equal size and style, none preselected or focused (§12.1): one composable for all three, no focus request.
        val body = entrySource.substringAfter("fun FirstRunScreen(").substringBefore("internal class FirstRunChoice")
        assertTrue(body.contains("EqualChoice(choice.label"))
        assertFalse(entrySource.contains("FocusRequester") || entrySource.contains("requestFocus"), "nothing is focused")
        assertTrue(body.contains("CopyKey.FIRST_SIGN_IN"))
    }

    @Test
    fun withoutABakedInstanceThereIsNoCreateAccountButton() {
        val (api, _) = at(FakeScene.FIRST_RUN_NO_PUBLIC_INSTANCE)
        val choices = firstRunChoices(assertIs(api.snapshot.entry))
        assertEquals(listOf(CopyKey.FIRST_SCAN_INVITE.english, CopyKey.FIRST_OWN_SERVER.english), choices.map { it.label.shown() })
    }

    @Test
    fun aFullPublicInstanceDisablesItsButtonAndAnUnknownModeNeverReadsAsClosed() {
        val full = firstRunChoices(assertIs(at(FakeScene.FIRST_RUN_SIGNUP_FULL).first.snapshot.entry))[1]
        assertEquals(CopyKey.FIRST_SIGNUP_FULL.english, full.label.shown())
        assertFalse(full.enabled)
        val unknown = firstRunChoices(assertIs(at(FakeScene.FIRST_RUN_SIGNUP_NOT_KNOWN).first.snapshot.entry))[1]
        assertEquals(CopyKey.FIRST_CREATE_ACCOUNT.english, unknown.label.shown())
        assertTrue(unknown.enabled)
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

    /** §17: a kit or a device link pasted on "Scan an invite" starts nothing, says only the API's sentence, and is forwarded nowhere. */
    @Test
    fun aKitOrADeviceLinkOnScanAnInviteStartsNothing() {
        val (api, model) = at(FakeScene.INVITE_ENTRY)
        val account = api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        val screen = assertIs<EntryScreen.InviteEntry>(api.snapshot.entry)

        model.run({ entry.submitInvite(screen, api.script.kitOf(account), PayloadSource.PASTED) })
        assertTrue(api.snapshot.entry === screen, "the screen stays as it was")
        val kitSaid = assertNotNull(model.saidOn(api.snapshot))
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, kitSaid.result)
        assertEquals("This is a recovery kit, not an invite.", kitSaid.text.shown(), "the sentence alone, no directions (FC-9)")

        model.run({ entry.submitInvite(screen, api.script.deviceLinkFrom(account, "Laptop"), PayloadSource.PASTED) })
        assertTrue(api.snapshot.entry === screen)
        val linkSaid = assertNotNull(model.saidOn(api.snapshot))
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, linkSaid.result)
        assertEquals(CopyKey.DEVICE_LINK_GOES_ELSEWHERE.english, linkSaid.text.shown())

        // No screen of the new path hands a payload to another entry: the invite screen calls submitInvite only.
        val invite = entrySource.substringAfter("fun InviteEntryScreen(").substringBefore("// ---- \"Use your own server\"")
        assertTrue(invite.contains("entry.submitInvite("))
        assertFalse(invite.contains("submitDeviceLink") || invite.contains("submitKit") || invite.contains("submitTypedKit"))
    }

    @Test
    fun anAddressTheGrammarRefusesIsSaidInPlaceAndAGoodOneRaisesTheGate() {
        val (api, model) = at(FakeScene.OWN_SERVER)
        val screen = assertIs<EntryScreen.OwnServer>(api.snapshot.entry)
        model.run({ entry.submitServerAddress(screen, "http://10.0.0.5") })
        val said = assertNotNull(model.saidOn(api.snapshot))
        assertEquals(ServerResult.NOT_AN_ADDRESS, said.result)
        assertEquals(CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN.english, said.text.shown())

        api.script.addServer("https://vault.friends.example", "Friends", io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER)
        model.run({ entry.submitServerAddress(screen, "https://vault.friends.example") })
        val gate = assertIs<EntryScreen.TrustGate>(api.snapshot.entry)
        assertEquals(TrustGateWording.TYPED_ADDRESS, gate.prompt.wording)
        assertEquals(CopyKey.GATE_TITLE_CONNECT.english, trustGateTitle(gate.prompt).shown())
        assertEquals(Placeholder.TRUST_GATE_CONNECT, assertIs<UiText.Ph>(trustGateConfirmLabel(gate.prompt)).placeholder, "the design names no confirm button for this wording: the app's own line, by its key")
        model.act { entry.declineTrustGate(gate) }
        assertFalse(api.snapshot.entry is EntryScreen.TrustGate, "Cancel leaves the gate, nothing pinned")
    }

    @Test
    fun theGateConfirmsTheTypedServerAndTheDeviceLinkWordingSaysItsTheSame() {
        val (api, model) = at(FakeScene.GATE_TYPED_ADDRESS)
        val gate = assertIs<EntryScreen.TrustGate>(api.snapshot.entry)
        assertEquals(32, gate.prompt.operatorKeyShort.length)
        model.run({ entry.confirmTrustGate(gate) })
        val server = assertIs<EntryScreen.Server>(api.snapshot.entry)
        assertEquals("Create an account here", UiText.of(server.createAccountLabel).shown(), "a reserved key shows the owner's approved words")
        assertEquals("Sign in", UiText.of(server.signInLabel).shown())

        val device = assertIs<EntryScreen.TrustGate>(at(FakeScene.GATE_DEVICE_LINK).first.snapshot.entry)
        assertEquals(CopyKey.GATE_ITS_THE_SAME.english, trustGateConfirmLabel(device.prompt).shown())
        assertEquals(CopyKey.GATE_TITLE_DEVICE_LINK.english, trustGateTitle(device.prompt).shown())
    }

    @Test
    fun aKindChangeGateHasTheApprovedTitleAndButtonsAndAStoppedServerOffersOnlyForgetting() {
        val (api, _) = at(FakeScene.CARD_KIND_CHANGED)
        val card = assertIs<InstanceCardState.KindChanged>(assertNotNull(api.snapshot.instance).card)
        assertEquals("This server says it changed", trustGateTitle(card.gate).shown())
        assertEquals("Continue", trustGateConfirmLabel(card.gate).shown())
        assertTrue(entrySource.contains("is InstanceCardState.KindChanged -> KindChangeGate(model, s, card)"))
        val kind = entrySource.substringAfter("internal fun KindChangeGate(").substringBefore("\n}\n")
        assertTrue(kind.contains("Second(UiText.Plain(Approved.GATE_KIND_CHANGE_NOT_NOW)") && kind.contains("kindChangeNotNow(card)"))
        assertEquals("Not now", Approved.GATE_KIND_CHANGE_NOT_NOW)
        val (stopped, _) = at(FakeScene.SERVER_STOPPED)
        val changed = assertIs<EntryScreen.ServerChanged>(stopped.snapshot.entry)
        assertIs<InstanceCardState.Stopped>(changed.instance.card)
        val card2 = entrySource.substringAfter("is InstanceCardState.Stopped ->").substringBefore("is InstanceCardState.Damaged")
        assertTrue(card2.contains("CopyKey.CARD_FORK") && card2.contains("ForgetServerButton"))
    }

    @Test
    fun plainHttpIsCalledLoopbackOnlyWhereAndroidPermitsIt() {
        assertTrue(httpCautionIsLoopback("http://127.0.0.1:8080"))
        isDebugBuild = false
        assertFalse(httpCautionIsLoopback("http://localhost:8080"), "the shipped config does not list localhost")
        isDebugBuild = true
        assertTrue(httpCautionIsLoopback("http://localhost:8080"))
        isDebugBuild = false
    }
}
