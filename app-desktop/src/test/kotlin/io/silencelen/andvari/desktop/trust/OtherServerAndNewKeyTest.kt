package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The two flows the shared code made real: an invite for another server opened while signed in (§6.7), with its Trust
 * Gate when that server is new to this computer, and the prompt that a contact answered under a new key, on the
 * creator's side (§6.8 step 6). Also what the instance's details and the console's request rows show for them.
 */
class OtherServerAndNewKeyTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    @Test
    fun anInviteForAnotherServerIsAWindowThatNamesBothAndPutsTheWayOutFirst() {
        val (api, _) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account?.opened))
        // Both servers, as the shared code gives them: its line names the invite's server and this one, and the line
        // beside the switch names the server it signs out of, with its address.
        assertEquals(CopyKey.OTHER_INSTANCE, opened.line.key)
        assertTrue(opened.line.values.containsAll(listOf(opened.inviteInstance.name, opened.inviteInstance.origin, opened.signedInTo.name)))
        // Which of its three lines depends on what the shared code knows of linked devices (SignOutOverUnsentTest).
        assertTrue(opened.signOutLine.key in setOf(CopyKey.OTHER_INSTANCE_SIGNS_OUT, CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_REQUIRED, CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN))
        assertEquals(listOf(opened.signedInTo.name, opened.signedInTo.origin), opened.signOutLine.values)
        assertNotEquals(opened.inviteInstance.origin, opened.signedInTo.origin)

        val links = src("LinksScreens.kt")
        val view = body(links, "internal fun OpenedInviteView(")
        assertTrue(view.contains("is OpenedInvite.OtherInstance -> return OtherInstanceWindow(model, s, opened)"), view)
        assertTrue(view.contains("is OpenedInvite.TrustGate -> return OpenedGateWindow(model, s, opened)"), view)
        val window = body(links, "internal fun OtherInstanceWindow(")
        // The current app's window for another server: a dialog, its line, the server it goes to with its address, the
        // sign-out line, then the way out laid out before the switch (so the focus reaches it first) and Escape's.
        assertTrue(window.contains("AlertDialog(") && window.contains("onDismissRequest = cancel"), window)
        for (part in listOf("Say(opened.line)", "InstanceName(opened.inviteInstance)", "Say(opened.signOutLine", "SaidHere(model, s)")) assertTrue(window.contains(part), part)
        assertTrue(window.indexOf("Say(opened.line)") < window.indexOf("Say(opened.signOutLine"))
        // The way out first, in the one row of buttons (SignOutOverUnsentTest pins the row's order), and Escape's.
        assertTrue(window.contains("ConfirmationButtons(UiText.of(CopyKey.CANCEL), cancel, ask, s, UiText.of(opened.switchLabel))"), window)
        assertTrue(window.contains("links.dismissOpened()"))
        // The switch goes through the sign-out's check (SignOutOverUnsentTest).
        assertTrue(window.contains("ask.proceed()"))
    }

    @Test
    fun cancellingTheOtherServersWindowKeepsThisSession() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val email = api.snapshot.account!!.email
        m.act { links.dismissOpened() }
        assertNull(api.snapshot.account?.opened, "the window is put away")
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertEquals(email, api.snapshot.account?.email, "still signed in here")
    }

    @Test
    fun theSwitchSignsOutHereAndTheEntryWindowsFollowOnTheOtherServer() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(api.snapshot.account?.opened)
        val other = opened.inviteInstance.origin
        m.run({ links.switchInstance(opened) })
        assertNull(m.saidOn(api.snapshot), "the switch said nothing went wrong")
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "signed out on this computer")
        assertNull(api.snapshot.account)
        assertNotNull(api.snapshot.entry, "the entry windows")
        assertEquals(other, api.snapshot.instance?.label?.origin, "on the server the invite is for")
    }

    @Test
    fun aServerNewToThisComputerShowsItsTrustGateFirstThenTheSwitch() {
        val (api, m) = at(FakeScene.OPENED_TRUST_GATE)
        val gate = assertIs<OpenedInvite.TrustGate>(api.snapshot.account?.opened)
        val window = body(src("LinksScreens.kt"), "internal fun OpenedGateWindow(")
        assertTrue(window.contains("AlertDialog(") && window.contains("TrustGateBody(opened.gate, titled = false)") && window.contains("trustGateTitle(opened.gate)"), window)
        assertTrue(window.indexOf("dismissButton") < window.indexOf("confirmButton"), "Cancel first")
        assertTrue(window.contains("links.confirmOpenedGate(opened)") && window.contains("links.dismissOpened()"))
        m.run({ links.confirmOpenedGate(gate) })
        assertNull(m.saidOn(api.snapshot))
        val opened = assertIs<OpenedInvite.OtherInstance>(api.snapshot.account?.opened, "after the gate, the window for the other server")
        m.run({ links.switchInstance(opened) })
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertNotNull(api.snapshot.entry)
    }

    @Test
    fun declinedGateSendsNothingAndKeepsTheSession() {
        val (api, m) = at(FakeScene.OPENED_TRUST_GATE)
        m.act { links.dismissOpened() }
        assertNull(api.snapshot.account?.opened)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    /** §6.8 step 6, creator's side: the prompt's line and its one action, and it stays until a match replaces the key. */
    @Test
    fun aContactAnsweringUnderANewKeyIsPromptedUntilTheComparisonReplacesTheKey() {
        val (api, m) = at(FakeScene.VAULTS)
        val dana = assertNotNull(api.script.unnamedDeviceAddsContact("Dana"))
        m.run({ links.createConnectLink(emptyList(), 60) })
        val link = api.snapshot.account!!.links!!.links.single()
        assertTrue(api.script.contactAnswersUnderNewKey(link, dana))
        val prompt = assertIs<AccountPrompt.KeyChanged>(api.snapshot.account!!.prompts.single { it is AccountPrompt.KeyChanged })
        assertEquals(CopyKey.CONTACT_KEY_CHANGED, prompt.line.key)
        assertEquals(UiText.of(prompt.line).shown(), promptLine(prompt).shown(), "its line is the shared code's")
        // Its one action opens the comparison, on the Sharing page where the comparison stands.
        val view = body(src("PeopleScreens.kt"), "private fun PromptView(")
        val keyChanged = view.substringAfter("is AccountPrompt.KeyChanged ->").substringBefore("is AccountPrompt.NewPerson")
        assertEquals(1, Regex("Second\\(|Main\\(|Quieter\\(").findAll(keyChanged).count(), "one action")
        assertTrue(keyChanged.contains("UiText.of(CopyKey.COMPARE_CODES)") && keyChanged.contains("contacts.openCompareForNewKey(p)") && keyChanged.contains("openSharing()"), keyChanged)
        assertTrue(src("AccountScreens.kt").contains("PromptsSection(model, s, account.prompts, openSharing = { go(SignedInPage.SHARING) })"))
        assertTrue(body(src("PeopleScreens.kt"), "internal fun PeopleSection(").startsWith("model: TrustModel, s: AppSnapshot, account: AccountSnapshot) {\n    account.comparing?.let { CompareView(model, s, it) }"))

        m.run({ contacts.openCompareForNewKey(prompt) })
        val ready = assertIs<CompareScreen.Ready>(api.snapshot.account!!.comparing)
        assertTrue(ready.replacesKey)
        assertTrue(api.snapshot.account!!.prompts.any { it is AccountPrompt.KeyChanged }, "the prompt stays while the codes are compared")
        // A wrong code replaces nothing: the prompt stays.
        val theirs = assertNotNull(api.script.codeTheyReadOut(ready.userId))
        val wrong = if (theirs == "000000") "111111" else "000000"
        m.run({ contacts.submitComparison(ready, wrong) })
        assertTrue(api.snapshot.account!!.prompts.any { it is AccountPrompt.KeyChanged }, "a wrong code keeps the prompt")
        val again = assertIs<CompareScreen.Ready>(api.snapshot.account!!.comparing)
        m.run({ contacts.submitComparison(again, theirs) })
        assertTrue(api.snapshot.account!!.prompts.none { it is AccountPrompt.KeyChanged }, "the matched comparison replaced the key")
    }

    @Test
    fun theInstanceDetailsShowTheFirstCardsHashThisComputerPinnedWithItsLabel() {
        val (api, _) = at(FakeScene.VAULTS)
        val details = assertNotNull(api.snapshot.instance).details
        assertTrue(details.pinnedCard0Hash.isNotEmpty(), "the fake pins a first card")
        assertEquals(CopyKey.INSTANCE_CARD0_PINNED, details.pinnedCard0Label)
        val shown = body(src("AccountScreens.kt"), "internal fun PinnedCard0Hash(")
        assertTrue(shown.contains("if (details.pinnedCard0Hash.isEmpty()) return"))
        assertTrue(shown.indexOf("Say(details.pinnedCard0Label") < shown.indexOf("details.pinnedCard0Hash.chunked(4)"), "the label, then the hash")
        // Settings' server card and the console's card section both show it.
        assertTrue(body(src("AccountScreens.kt"), "private fun ServerSection(").contains("PinnedCard0Hash(instance.details)"))
        assertTrue(body(src("OperatorScreens.kt"), "private fun CardSection(").contains("PinnedCard0Hash(c.details)"))
    }

    /** The fake has no switch for a copy on an outgoing key: the row is pinned to the shared code's line by its source. */
    @Test
    fun aRequestWhoseCopyIsOnAnOutgoingKeySaysSoInItsRow() {
        val rows = body(src("OperatorScreens.kt"), "private fun RequestRows(")
        assertTrue(rows.contains("c.outgoingKeyLine(r)?.let { Say(it"), rows)
        assertTrue(rows.indexOf("Say(state.words") < rows.indexOf("c.outgoingKeyLine(r)") && rows.indexOf("c.outgoingKeyLine(r)") < rows.indexOf("FulfilControl("))
    }
}
