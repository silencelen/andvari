package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.MoveResult
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
import kotlin.test.assertTrue

/**
 * Lines that stood untrue where the desktop showed them (the readings of the wording page, 17 November): each place now
 * says what is so, on a key of its own where the earlier words cannot be kept.
 */
class UntrueLinesTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun src(name: String) = File(dir + name).readText()
    private fun body(file: String, head: String) = src(file).substringAfter(head).substringBefore("\n}\n")

    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** An open link's time left is the countdown (m:ss), never bare seconds ("Time left: 272"). */
    @Test
    fun anOpenLinksTimeLeftIsTheCountdown() {
        val links = src("LinksScreens.kt")
        assertTrue(links.contains("UiText.ph(Placeholder.DEVICE_LINK_TIME_LEFT, countdown(left))"))
        assertFalse(links.contains("(left / 1000).toString()"))
        assertEquals("4:32", countdown(272_000L))
    }

    /** The eye button beside a secret keeps the field's name in what a screen reader says, on keys of their own. */
    @Test
    fun theEyeButtonsNameKeepsTheFieldsName() {
        val field = UiText.Plain("Master password")
        val show = assertIs<UiText.Ph>(eyeButtonName(false, field))
        val hide = assertIs<UiText.Ph>(eyeButtonName(true, field))
        assertEquals(Placeholder.SHOW_FIELD_NAMED, show.placeholder)
        assertEquals(Placeholder.HIDE_FIELD_NAMED, hide.placeholder)
        assertEquals(listOf("Master password"), show.args)
        assertTrue(show.shown().contains("Master password") && hide.shown().contains("Master password"))
        assertTrue(body("TrustUi.kt", "internal fun SecretField(").contains("eyeButtonName(show, label).shown()"))
        assertTrue(src("VaultItemsScreens.kt").contains("eyeButtonName(shown = value != null, UiText.ph(label)).shown()"))
    }

    /**
     * Removing operator recovery: requests made before are stopped at the person's device's next look, during the wait
     * too (the earlier line said the device says so only after the wait). A refused rotation: one line true of both
     * causes the shared code answers it for.
     */
    @Test
    fun theOperatorsLinesSayWhatTheSharedCodeDoes() {
        assertEquals(Placeholder.OP_REMOVE_REQUESTS_STOP, recoveryRemoveLines(true).map { (it.text as UiText.Ph).placeholder }.last())
        assertTrue(Placeholder.entries.none { it.name == "OP_REMOVE_WHAT_REQUESTS" || it.name == "OP_ROTATION_REFUSED" })
        assertTrue(src("OperatorModel.kt").contains("OperatorResult.ROTATION_REFUSED -> UiText.ph(Placeholder.OP_ROTATION_REFUSED_EITHER)"))
    }

    /**
     * Under a server move that is not finished, nothing of this computer's copy is read: "Forget this server" does not
     * say that the copy stays readable there, on its card or in its question.
     */
    @Test
    fun forgettingUnderAnUnfinishedMoveDoesNotSayTheCopyStaysReadable() {
        val (api, m) = at(FakeScene.CARD_MOVED)
        assertEquals(Placeholder.FORGET_DELETES_COPY, (forgetDeletesLine(assertNotNull(api.snapshot.instance)) as UiText.Ph).placeholder)
        api.script.namespaceMoveFails = true
        api.script.storeBuild = false
        val moved = assertIs<InstanceCardState.Moved>(assertNotNull(api.snapshot.instance).card)
        var r: MoveResult? = null
        m.run({ instance.followMove(moved) }) { r = it }
        assertEquals(MoveResult.NOT_FINISHED, r)
        val instance = assertNotNull(api.snapshot.instance)
        assertNotNull(instance.unfinishedMove)
        assertEquals(Placeholder.FORGET_DELETES_COPY_MOVE_UNFINISHED, (forgetDeletesLine(instance) as UiText.Ph).placeholder)
        assertTrue(body("EntryScreens.kt", "internal fun ForgetServerButton(").contains("Quiet(forgetDeletesLine(instance))"))
        assertTrue(src("EntryScreens.kt").contains("line = forgetDeletesLine(instance)"))
        // The move's own result is said as itself, never as "result without wording".
        assertEquals(Placeholder.MOVE_NOT_FINISHED_AGAIN, (UiText.forResult(MoveResult.NOT_FINISHED, 0) as UiText.Ph).placeholder)
    }

    /** "Invited by" holds its words from the wording page (entry F17, its third line), with the inviter's name. */
    @Test
    fun invitedByHoldsItsWords() {
        assertEquals("Invited by Bo (as they call themselves)", UiText.ph(Placeholder.INVITED_BY, "Bo").shown())
        assertEquals("Two-step sign-in is on.", UiText.ph(Placeholder.TWO_STEP_ON).shown())
    }
}
