package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.TwoStepResult
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
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Each of an entry's lines stands where it belongs: the line beside a live two-step key is not the one for a key that
 * ran out; the button that turns "New devices must be linked" on is not its explanation; a match of codes is not a
 * match that was not recorded; the line after a password change says that it was changed; the name field's label is
 * not the line under it; a move whose data has not arrived is not a move whose new address did not check out. Lines
 * are named by their constants (the two sentences of the comparison by the owner's words, which that test is about),
 * and a state that had no line of its own shows its own and no placeholder.
 */
class WordingPlacesTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun shown(p: Placeholder, vararg args: String) = UiText.ph(p, *args).shown()

    private fun approved(p: Placeholder) = assertFalse(UiText.ph(p).isPlaceholder, "$p has its line")

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    // ---- two-step sign-in: the line beside the live key, and the key that ran out ----

    @Test
    fun theLineBesideALiveTwoStepKeyIsTheTypedKeysAndAKeyThatRanOutSaysSo() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ settings.openTwoStep() })
        var r: TwoStepResult? = null
        m.run({ settings.startTwoStep(assertNotNull(api.snapshot.account?.twoStep), FakeScenes.PASSWORD) }) { r = it }
        assertEquals(TwoStepResult.DONE, r)
        val enrolment = assertNotNull(assertNotNull(api.snapshot.account?.twoStep).enrolment)
        val key = assertNotNull(api.settings.twoStepKey(enrolment), "the key is live")
        assertEquals(listOf(Placeholder.TWO_STEP_SCAN, Placeholder.TWO_STEP_TYPE_KEY), twoStepKeyLines(key))
        assertNotEquals(shown(Placeholder.TWO_STEP_KEY_GONE), shown(Placeholder.TWO_STEP_TYPE_KEY), "the live key is not said to have run out")

        // The fake's key never runs out, so the state is named by what the shared code gives: no key.
        assertEquals(listOf(Placeholder.TWO_STEP_KEY_GONE), twoStepKeyLines(null))
        approved(Placeholder.TWO_STEP_KEY_GONE)
        approved(Placeholder.TWO_STEP_TYPE_KEY)
        val section = src("SettingsScreens.kt").substringAfter("internal fun TwoStepSection(").substringBefore("\n}\n")
        assertTrue(section.contains("for (line in twoStepKeyLines(shown))") && section.contains("delay(TWO_STEP_KEY_REREAD_MS)"), section)
        assertTrue(section.indexOf("if (shown != null) {") < section.indexOf("settings.confirmTwoStep("), "no code is asked for a key that ran out")
    }

    // ---- "New devices must be linked" ----

    @Test
    fun newDevicesMustBeLinkedHasItsNameItsExplanationItsStateAndButtonsThatSayTheAct() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ devices.openDevices() })
        val unknown = assertNotNull(api.snapshot.account?.devices)
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_NOT_KNOWN, requireLinkState(unknown))
        m.run({ devices.setRequireLink(true, FakeScenes.PASSWORD) })
        val on = assertNotNull(api.snapshot.account?.devices)
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_IS_ON, requireLinkState(on))
        assertEquals(listOf(false), requireLinkChoices(on))
        m.run({ devices.setRequireLink(false, FakeScenes.PASSWORD) })
        val off = assertNotNull(api.snapshot.account?.devices)
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_IS_OFF, requireLinkState(off))
        for (p in listOf(
            Placeholder.DEVICE_REQUIRE_LINK_TITLE, Placeholder.DEVICE_REQUIRE_LINK_BODY, Placeholder.DEVICE_REQUIRE_LINK_IS_ON,
            Placeholder.DEVICE_REQUIRE_LINK_IS_OFF, Placeholder.DEVICE_REQUIRE_LINK_NOT_KNOWN, Placeholder.DEVICE_REQUIRE_LINK_ON,
            Placeholder.DEVICE_REQUIRE_LINK_OFF,
        )) approved(p)
        assertNotEquals(shown(Placeholder.DEVICE_REQUIRE_LINK_BODY), shown(Placeholder.DEVICE_REQUIRE_LINK_ON), "the button is not the explanation")
        val section = src("SettingsScreens.kt").substringAfter("internal fun DevicesSection(").substringBefore("\n}\n")
        val title = section.indexOf("Say(Placeholder.DEVICE_REQUIRE_LINK_TITLE")
        val body = section.indexOf("Quiet(UiText.ph(Placeholder.DEVICE_REQUIRE_LINK_BODY))")
        val state = section.indexOf("Say(requireLinkState(screen))")
        val button = section.indexOf("if (next) Placeholder.DEVICE_REQUIRE_LINK_ON else Placeholder.DEVICE_REQUIRE_LINK_OFF")
        assertTrue(title in 0 until body && body < state && state < button, section)
    }

    // ---- comparing codes ----

    private val matched = "The codes match."
    private val notSaved = "The codes match, but your account couldn't be updated, so your other devices still show this person as not compared. Try again."

    /** What the comparison shows: its screen's line for a match, and what the last entry answered. */
    private fun compareShows(api: FakeDesktopAppApi, m: TrustModel): List<String> =
        listOfNotNull(
            (assertNotNull(api.snapshot.account).comparing as? CompareScreen.Matched)?.let { shown(Placeholder.COMPARE_MATCHED) },
            m.saidOn(api.snapshot)?.text?.shown(),
        )

    private fun ready(api: FakeDesktopAppApi) = assertIs<CompareScreen.Ready>(assertNotNull(api.snapshot.account).comparing)

    @Test
    fun aMatchSaysTheCodesMatchAndNothingElse() {
        val (api, m) = at(FakeScene.COMPARE_READY)
        val c = ready(api)
        var r: ComparisonResult? = null
        m.run({ contacts.submitComparison(c, assertNotNull(api.script.codeTheyReadOut(c.userId))) }) { r = it }
        assertEquals(ComparisonResult.DONE, r)
        assertEquals(listOf(matched), compareShows(api, m))
    }

    @Test
    fun aMatchTheAccountCouldNotRecordSaysSoThenTypingAgainRecordsIt() {
        val (api, m) = at(FakeScene.COMPARE_READY)
        val c = ready(api)
        val theirs = assertNotNull(api.script.codeTheyReadOut(c.userId))
        api.script.comparisonNotSaved = true
        var r: ComparisonResult? = null
        m.run({ contacts.submitComparison(c, theirs) }) { r = it }
        assertEquals(ComparisonResult.NOT_SAVED, r)
        assertEquals(listOf(notSaved), compareShows(api, m))
        m.run({ contacts.submitComparison(ready(api), theirs) }) { r = it }
        assertEquals(ComparisonResult.DONE, r)
        assertEquals(listOf(matched), compareShows(api, m))
    }

    @Test
    fun aWrongCodeSaysNeitherMatch() {
        val (api, m) = at(FakeScene.COMPARE_READY)
        val c = ready(api)
        val theirs = assertNotNull(api.script.codeTheyReadOut(c.userId))
        var r: ComparisonResult? = null
        m.run({ contacts.submitComparison(c, if (theirs == "000000") "111111" else "000000") }) { r = it }
        assertEquals(ComparisonResult.MISMATCH, r)
        assertEquals(listOf(UiText.of(CopyKey.CODES_DO_NOT_MATCH).shown()), compareShows(api, m))
    }

    // ---- after a password change ----

    @Test
    fun aDonePasswordChangeSaysFirstThatThePasswordIsChanged() {
        val (api, m) = at(FakeScene.VAULTS)
        var r: PasswordChangeResult? = null
        m.runSaying({ settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeLine(it) }) { r = it }
        assertEquals(PasswordChangeResult.DONE, r)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertEquals(Placeholder.PASSWORD_CHANGED, PASSWORD_CHANGED_LINES.first())
        // The owner's two lines together, the change itself first, then what opens this computer's copy now.
        assertEquals(
            "Your master password is changed. andvari on this device opens with the new master password from now on. The old one no longer opens it.",
            shown(Placeholder.PASSWORD_CHANGED),
        )
        for (p in PASSWORD_CHANGED_LINES) approved(p)
    }

    // ---- the name field ----

    @Test
    fun theNameFieldIsLabelledAsTheNameAndItsLineStandsUnderIt() {
        val (api, _) = at(FakeScene.CREATE_ACCOUNT)
        assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        approved(Placeholder.DISPLAY_NAME_FIELD)
        approved(Placeholder.DISPLAY_NAME_HINT)
        assertNotEquals(shown(Placeholder.DISPLAY_NAME_HINT), shown(Placeholder.DISPLAY_NAME_FIELD), "the label is not the line under the field")
        val form = src("AccountEntryScreens.kt").substringAfter("internal fun CreateAccountScreen(").substringBefore("\n}\n")
        val field = form.indexOf("Field(UiText.ph(Placeholder.DISPLAY_NAME_FIELD), name)")
        val hint = form.indexOf("Quiet(UiText.ph(Placeholder.DISPLAY_NAME_HINT))")
        val next = form.indexOf("SecretField(UiText.ph(Placeholder.NEW_PASSWORD_FIELD)")
        assertTrue(field in 0 until hint && hint < next, "the line stands right under the field")
    }

    // ---- a move that did not finish, and one whose new address did not check out ----

    @Test
    fun aMoveWhoseDataHasNotArrivedNamesBothAddressesAndIsNotTheFailedCheck() {
        val (api, m) = at(FakeScene.CARD_MOVED)
        api.script.namespaceMoveFails = true
        api.script.storeBuild = false
        val from = assertNotNull(api.snapshot.instance).label.origin
        val to = "https://vault.newhome.example"
        val moved = assertIs<InstanceCardState.Moved>(assertNotNull(api.snapshot.instance).card)
        var r: MoveResult? = null
        m.run({ instance.followMove(moved) }) { r = it }
        assertEquals(MoveResult.NOT_FINISHED, r)
        val instance = assertNotNull(api.snapshot.instance)
        val move = assertNotNull(instance.unfinishedMove)
        val line = assertIs<UiText.Ph>(unfinishedMoveLine(instance, move))
        assertEquals(Placeholder.MOVE_UNFINISHED, line.placeholder)
        assertEquals(listOf(from, to), line.args)
        assertNotEquals(from, to)
        approved(Placeholder.MOVE_UNFINISHED)
        assertTrue(line.shown().contains(from) && line.shown().contains(to), line.shown())
        assertNotEquals(shown(Placeholder.MOVE_NOT_VERIFIED), line.shown())
        assertTrue(src("EntryScreens.kt").substringAfter("internal fun UnfinishedMoveCard(").substringBefore("\n}\n").contains("Say(unfinishedMoveLine(instance, move)"))
    }

    @Test
    fun aMoveFollowedToAnAddressThatDidNotCheckOutSaysSoInItsOwnLine() {
        val (api, m) = at(FakeScene.CARD_MOVED)
        api.script.storeBuild = false
        val moved = assertIs<InstanceCardState.Moved>(assertNotNull(api.snapshot.instance).card)
        api.script.forceNext(MoveResult.MOVED_NOT_VERIFIED)
        var r: MoveResult? = null
        m.run({ instance.followMove(moved) }) { r = it }
        assertEquals(MoveResult.MOVED_NOT_VERIFIED, r)
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(Placeholder.MOVE_NOT_VERIFIED, assertIs<UiText.Ph>(said.text).placeholder)
        approved(Placeholder.MOVE_NOT_VERIFIED)
        assertNull(UiText.forResult(MoveResult.DONE, 0))
    }
}
