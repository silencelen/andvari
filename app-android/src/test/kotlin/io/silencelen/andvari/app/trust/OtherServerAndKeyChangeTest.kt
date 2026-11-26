package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.fake.FakeAppApi
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Two flows the shared code made real (design §7, §3.6): an invitation for another server opened while signed in, with
 * the switch that signs out here, and the prompt that a contact answered one of this account's links under a new key,
 * which stays until this phone's own comparison replaces the key. Also the instance details' pinned first-card hash.
 */
class OtherServerAndKeyChangeTest {
    /** The switch's line, by what the shared code knows of "New devices must be linked" (off, on, not known). */
    private val SWITCH_LINES = setOf(CopyKey.OTHER_INSTANCE_SIGNS_OUT, CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_REQUIRED, CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN)

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    @Test
    fun anInviteForAnotherServerNamesBothAndCancelKeepsThisSession() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened)
        assertNotEquals(opened.inviteInstance.origin, opened.signedInTo.origin, "two servers")
        assertEquals(CopyKey.OTHER_INSTANCE, opened.line.key)
        assertTrue(opened.inviteInstance.origin in opened.line.values, "the invite's server is named with its address")
        assertTrue(opened.signedInTo.name in opened.line.values, "and the one this phone is signed in to")
        assertTrue(opened.signOutLine.key in SWITCH_LINES, "the line says what the shared code knows of linking: ${opened.signOutLine.key}")
        assertTrue(opened.signedInTo.origin in opened.signOutLine.values)

        val email = assertNotNull(api.snapshot.account).email
        m.act { links.dismissOpened() }
        val account = assertNotNull(api.snapshot.account, "Cancel signs nothing out")
        assertEquals(email, account.email)
        assertNull(account.opened)
    }

    @Test
    fun theSwitchSignsOutHereAndShowsTheEntryScreensOfTheOtherServer() {
        val (api, m) = at(FakeScene.OPENED_OTHER_INSTANCE)
        val opened = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened)
        m.run({ links.switchInstance(opened) })
        assertNull(api.snapshot.account, "switching signed out on this phone")
        assertNotNull(api.snapshot.entry, "the entry screens follow, for the invite's server: ${m.said.value?.text?.shown()}")
    }

    @Test
    fun anEnrolLinkForAServerNewToThisPhoneShowsTheTrustGateFirstThenTheSwitch() {
        val (api, m) = at(FakeScene.OPENED_TRUST_GATE)
        val gate = assertIs<OpenedInvite.TrustGate>(assertNotNull(api.snapshot.account).opened)
        m.run({ links.confirmOpenedGate(gate) })
        val other = assertIs<OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened, "said: ${m.said.value?.text?.shown()}")
        assertTrue(other.signOutLine.key in SWITCH_LINES)
    }

    @Test
    fun theOtherServerScreenSaysTheSignOutLineBeforeItsSwitchAndCancelLast() {
        val body = src("LinksScreens.kt").substringAfter("is OpenedInvite.OtherInstance ->").substringBefore("is OpenedInvite.TrustGate ->")
        assertTrue("Say(opened.line)" in body)
        assertTrue("InstanceName(opened.inviteInstance" in body, "the invite's server, as pinned")
        val signOut = body.indexOf("UiText.of(opened.signOutLine)")
        val switch = body.indexOf("UiText.of(opened.switchLabel)")
        assertTrue(signOut >= 0 && signOut < switch, "the sign-out line is read before the switch")
        assertTrue(body.indexOf("UnsentLines(ask, s)") in signOut..switch, "and the lines about changes not sent")
        assertTrue("model.switchAsk(opened)" in body && "links.switchInstance" !in body, "the switch goes only through its confirmation")
        assertTrue("Main(" !in body, "switching is never the default")
        val gate = src("LinksScreens.kt").substringAfter("is OpenedInvite.TrustGate ->").substringBefore("is OpenedInvite.ServerChanged ->")
        assertTrue("TrustGateBody(opened.gate)" in gate && "links.confirmOpenedGate(opened)" in gate)
    }

    /** Ada made a link; Dana, a contact already, answers it under another key. */
    private fun danaAnswersUnderANewKey(): Triple<FakeAppApi, TrustModel, String> {
        val (api, m) = at(FakeScene.VAULTS)
        val dana = assertNotNull(api.script.unnamedDeviceAddsContact("Dana"))
        m.run({ links.createConnectLink(emptyList(), 60) })
        val link = assertNotNull(assertNotNull(api.snapshot.account).links).links.single()
        assertTrue(api.script.contactAnswersUnderNewKey(link, dana))
        m.onSnapshot(api.snapshot)
        return Triple(api, m, dana.userId)
    }

    private fun keyPrompt(api: FakeAppApi): AccountPrompt.KeyChanged? =
        assertNotNull(api.snapshot.account).prompts.filterIsInstance<AccountPrompt.KeyChanged>().singleOrNull()

    @Test
    fun aContactsNewKeyIsPromptedUntilTheComparisonReplacesIt() {
        val (api, m, userId) = danaAnswersUnderANewKey()
        val prompt = assertNotNull(keyPrompt(api))
        assertEquals("Dana", prompt.label)
        assertEquals(CopyKey.CONTACT_KEY_CHANGED, prompt.line.key)

        // Its one action opens the comparison, which says a match replaces the key.
        m.run({ contacts.openCompareForNewKey(prompt) })
        var ready = assertIs<CompareScreen.Ready>(assertNotNull(api.snapshot.account).comparing)
        assertTrue(ready.replacesKey)

        // Closing the comparison, or a wrong code, leaves the prompt where it is.
        m.act { contacts.closeCompare() }
        assertSame(prompt, keyPrompt(api), "the prompt stays")
        m.run({ contacts.openCompareForNewKey(prompt) })
        ready = assertIs(assertNotNull(api.snapshot.account).comparing)
        val theirs = assertNotNull(api.script.codeTheyReadOut(userId))
        val wrong = ((theirs.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
        m.run({ contacts.submitComparison(ready, wrong) })
        assertSame(prompt, keyPrompt(api), "a wrong code replaces nothing")

        // Dana's own code replaces the key: the prompt is gone.
        ready = assertIs(assertNotNull(api.snapshot.account).comparing)
        m.run({ contacts.submitComparison(ready, theirs) })
        assertNull(keyPrompt(api), "said: ${m.said.value?.text?.shown()}")
    }

    @Test
    fun thePromptHasOneActionAndTheComparisonSaysWhyItIsAsked() {
        val people = src("PeopleScreens.kt")
        val branch = people.substringAfter("is AccountPrompt.KeyChanged ->").substringBefore("is AccountPrompt.NewPerson ->")
        assertEquals(1, Regex("model\\.(run|act)\\(").findAll(branch).count(), "one action")
        assertTrue("contacts.openCompareForNewKey(p)" in branch)
        assertTrue("UiText.of(CopyKey.COMPARE_CODES)" in branch)
        val compare = people.substringAfter("is CompareScreen.Ready ->").substringBefore("is CompareScreen.LinkFailed ->")
        assertTrue("if (c.replacesKey) Say(UiText.of(CopyKey.CONTACT_KEY_CHANGED, c.label))" in compare)
    }

    @Test
    fun theInstanceDetailsShowTheFirstCardsHashThisPhonePinnedWithItsLabel() {
        val (api, _) = at(FakeScene.VAULTS)
        val details = assertNotNull(api.snapshot.instance).details
        assertTrue(details.pinnedCard0Hash.isNotEmpty(), "the fake pins a first card")
        assertEquals(CopyKey.INSTANCE_CARD0_PINNED, details.pinnedCard0Label)
        val account = src("AccountScreens.kt")
        val server = account.substringAfter("private fun ServerSection(").substringBefore("\n}\n")
        assertTrue("PinnedCard0Hash(instance.details)" in server)
        val shown = account.substringAfter("internal fun PinnedCard0Hash(").substringBefore("\n}\n")
        assertTrue("Say(details.pinnedCard0Label" in shown && "hash.chunked(4)" in shown)
        assertTrue("if (hash.isEmpty()) return" in shown, "nothing while no pin is held")
    }
}
