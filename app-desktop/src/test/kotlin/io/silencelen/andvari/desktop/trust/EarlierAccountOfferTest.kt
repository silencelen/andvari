package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EarlierAccountKnown
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.SignInAnswer
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17), as the desktop draws it: the refusal with both
 * possibilities, the offer, the second step with every line the confirmation carries, the call only from the person's own
 * click on that step, a call that throws leaving the second step for the next click and never tried again by the app, the
 * results' lines, and the notice at the next account taken under the address. Walked on the shared code's fake, which plays
 * the engine's answers; the keyboard walk runs in a headless scene.
 */
class EarlierAccountOfferTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")
    private val EVE = "eve@example.com"

    /** Eve's sign-in, refused because this computer remembers an earlier account under her address: the offer stands. */
    private fun refused(copy: (FakeDesktopAppApi) -> Unit = {}): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.SIGN_IN)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
        api.script.publicInstance.addAccount(EVE, FakeScenes.PASSWORD)
        api.script.earlierAccountKnown = true
        api.script.identityFault = true
        copy(api)
        m.run({ entry.submitSignIn(assertIs<EntryScreen.SignIn>(api.snapshot.entry), EVE, FakeScenes.PASSWORD) })
        val said = assertNotNull(m.saidOn(api.snapshot), "the refusal is said")
        assertSame(SignInAnswer.IDENTITY_FAULT, said.result)
        assertNotNull(api.snapshot.earlierAccount, "the shared code offers the forgetting on this screen")
        return api to m
    }

    private fun offer(api: FakeDesktopAppApi): EarlierAccountKnown = assertNotNull(api.snapshot.earlierAccount)

    private fun keys(lines: List<UiText>): List<String> = lines.map { it.shown() }

    /** The window's entry screens, redrawn from the snapshot as it changes, with the focus walk written to [log]. */
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    private class Walk(api: FakeDesktopAppApi, m: TrustModel) {
        val log = ArrayList<String>()
        private var t = 0L
        private val scene = ImageComposeScene(600, 3000, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log) {
                MaterialTheme {
                    Surface {
                        val s: AppSnapshot by api.snapshots.collectAsState()
                        m.said.collectAsState().value
                        s.entry?.let { EntryScreens(m, s, it) }
                    }
                }
            }
        }

        init {
            scene.render(t)
        }

        private fun press(key: Key) {
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyUp))
            repeat(2) {
                t += 50_000_000L
                scene.render(t)
            }
        }

        fun tabUntil(words: String, most: Int = 60) {
            repeat(most) {
                if (log.lastOrNull() == words) return
                press(Key.Tab)
            }
            assertEquals(words, log.lastOrNull(), log.toString())
        }

        fun enter() = press(Key.Enter)

        fun close() = scene.close()
    }

    // ---- the first step ----

    @Test
    fun theRefusalSaysBothPossibilitiesAsSentencesOfTheirOwnAndOffersTheForgettingBesideCancel() {
        val (api, m) = refused()
        val o = offer(api)
        assertFalse(o.confirming)
        // Each a line of its own, in the shared code's order, by key: what was refused, both possibilities, how to tell.
        assertEquals(
            keys(listOf(UiText.of(CopyKey.REMADE_ACCOUNT_TITLE), UiText.of(o.refusal), UiText.of(CopyKey.REMADE_ACCOUNT_IF_REMADE), UiText.of(CopyKey.REMADE_ACCOUNT_IF_SERVER), UiText.of(CopyKey.REMADE_ACCOUNT_HOW_TO_TELL))),
            keys(earlierOfferLines(o)),
        )
        assertEquals(CopyKey.REMADE_ACCOUNT_REFUSAL, o.refusal.key)
        assertTrue(earlierConfirmLines(o).isEmpty(), "nothing of the second step yet")
        // Drawn under the refused answer's line, wherever that line is said, and with both buttons alike: neither is the
        // screen's main button, neither is focused, preselected or bound to a key.
        val said = body("TrustUi.kt", "internal fun SaidHere(")
        assertTrue(said.indexOf("ErrorBar(said.text)") in 0 until said.indexOf("EarlierAccountOffer(model, s)"))
        val drawn = body("EarlierAccountOffer.kt", "internal fun EarlierAccountOffer(")
        val first = drawn.substringAfter("if (!offer.confirming) {").substringBefore("return@Column")
        assertTrue(first.contains("Second(UiText.of(offer.forgetLabel)") && first.contains("Second(cancel"), first)
        assertFalse(Regex("""\bMain\(|FocusRequester|requestFocus|onKeyEvent|onPreviewKeyEvent|remember""").containsMatchIn(drawn), "nothing preselected, focused, bound to a key, or kept by the window")
        // "Forget" only asks for the second step; the first step's Cancel takes the offer away and forgets nothing.
        m.quietly { m.api.entry.keepEarlierAccount(o) }
        assertNull(api.snapshot.earlierAccount)
        assertTrue(api.script.earlierAccountKnown, "nothing forgotten")
    }

    // ---- the second step ----

    @Test
    fun theSecondStepCarriesEveryLineOfTheConfirmationWithWhatCannotBeToldOfACopy() {
        for ((setUp, copyLine) in listOf<Pair<(FakeDesktopAppApi) -> Unit, CopyKey?>>(
            { _: FakeDesktopAppApi -> } to null,
            { a: FakeDesktopAppApi -> a.script.earlierCopyKept = true; a.script.earlierCopyUnsent = 0 } to CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_ALL_SENT,
            { a: FakeDesktopAppApi -> a.script.earlierCopyKept = true } to CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL,
            { a: FakeDesktopAppApi -> a.script.earlierCopyHeld = true } to CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL,
        )) {
            val (api, m) = refused(setUp)
            m.quietly { m.api.entry.askToForgetEarlierAccount(offer(api)) }
            val o = offer(api)
            assertTrue(o.confirming)
            val want = listOfNotNull(CopyKey.REMADE_ACCOUNT_CONFIRM_TITLE, CopyKey.REMADE_ACCOUNT_CONFIRM, copyLine, CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS)
            val lines = earlierConfirmLines(o)
            assertEquals(want.size, lines.size, "$copyLine")
            assertEquals(listOf(CopyKey.REMADE_ACCOUNT_CONFIRM_TITLE) + o.confirmLines.map { it.key }, want, "$copyLine")
            assertEquals(keys(listOf(UiText.of(CopyKey.REMADE_ACCOUNT_CONFIRM_TITLE)) + o.confirmLines.map { UiText.of(it) }), keys(lines))
            // The first step's sentences stay above it.
            assertEquals(5, earlierOfferLines(o).size)
            assertTrue(api.script.earlierAccountKnown, "nothing forgotten by the second step's showing")
        }
    }

    /**
     * The keyboard reaches every control, neither step is a default button, and Enter on the first step never passes the
     * second: Enter on "Forget" shows the second step, and further Enters forget nothing until the focus is taken to the
     * second step's own button and Enter is pressed there.
     */
    @Test
    fun theKeyboardReachesBothStepsAndEnterOnTheFirstNeverPassesTheSecond() {
        val (api, m) = refused()
        val o = offer(api)
        val forget = UiText.of(o.forgetLabel).shown()
        val walk = Walk(api, m)
        try {
            walk.tabUntil(forget)
            walk.enter()
            assertTrue(offer(api).confirming, "Enter on Forget shows the second step")
            walk.enter()
            walk.enter()
            assertTrue(offer(api).confirming, "Enter again forgets nothing")
            assertTrue(api.script.earlierAccountKnown)
            val confirm = UiText.of(assertNotNull(offer(api).confirmLabel)).shown()
            walk.tabUntil(confirm)
            walk.enter()
            assertNull(api.snapshot.earlierAccount, "forgotten by the person's own press on the second step")
            assertFalse(api.script.earlierAccountKnown)
            assertEquals(UiText.of(o.lineFor(ForgetEarlierResult.FORGOTTEN)!!).shown(), assertNotNull(m.saidOn(api.snapshot)).text.shown())
            assertIs<EntryScreen.SignIn>(api.snapshot.entry, "the refused screen stays, for the person to sign in again")
        } finally {
            walk.close()
        }
    }

    // ---- a call that throws ----

    @Test
    fun aForgettingThatThrowsLeavesTheSecondStepForTheNextClickAndIsNeverTriedAgainByTheApp() {
        val (api, m) = refused { it.script.forgetFailsOnce = true }
        m.quietly { m.api.entry.askToForgetEarlierAccount(offer(api)) }
        val walk = Walk(api, m)
        try {
            val confirm = UiText.of(assertNotNull(offer(api).confirmLabel)).shown()
            walk.tabUntil(confirm)
            walk.enter()
            // Said as a fault, in place; the second step is still on show.
            assertEquals(Placeholder.SOMETHING_WENT_WRONG, assertIs<UiText.Ph>(assertNotNull(m.saidOn(api.snapshot)).text).placeholder)
            assertTrue(offer(api).confirming, "the second step stays on show")
            // Time passes and the window ticks: nothing tries it again.
            repeat(5) { m.tick() }
            val still = offer(api)
            assertTrue(still.confirming, "never tried again by the app")
            assertEquals(Placeholder.SOMETHING_WENT_WRONG, assertIs<UiText.Ph>(assertNotNull(m.saidOn(api.snapshot)).text).placeholder)
            // The person's next press (the focus is still on the button) finishes it.
            walk.tabUntil(confirm)
            walk.enter()
            assertNull(api.snapshot.earlierAccount)
            assertEquals(assertNotNull(earlierResultLine(still, ForgetEarlierResult.FORGOTTEN)).shown(), assertNotNull(m.saidOn(api.snapshot)).text.shown())
        } finally {
            walk.close()
        }
        // The only call of the forgetting is the second step's button, through the one place that runs an intent.
        val src = File(dir).listFiles()!!.filter { it.name.endsWith(".kt") }.joinToString("\n") { it.readText() }
        assertEquals(1, Regex("""forgetEarlierAccount\(""").findAll(src).count(), "one call in the whole window")
        assertEquals(1, Regex("""askToForgetEarlierAccount\(""").findAll(src).count(), "the second step is asked only by the first step's button")
    }

    // ---- the results ----

    @Test
    fun eachResultSaysItsLineAndTheOfferStandsOnlyWhereTheSharedCodeKeepsIt() {
        for (r in listOf(
            ForgetEarlierResult.FORGOTTEN, ForgetEarlierResult.NOTHING_TO_FORGET, ForgetEarlierResult.UNDER_WAY,
            ForgetEarlierResult.REQUEST_KEPT, ForgetEarlierResult.ACCOUNT_OPEN,
        )) {
            val (api, m) = refused { it.script.forgetAnswer = r }
            m.quietly { m.api.entry.askToForgetEarlierAccount(offer(api)) }
            val o = offer(api)
            val walk = Walk(api, m)
            try {
                walk.tabUntil(UiText.of(assertNotNull(o.confirmLabel)).shown())
                walk.enter()
            } finally {
                walk.close()
            }
            assertEquals(assertNotNull(earlierResultLine(o, r)).shown(), assertNotNull(m.saidOn(api.snapshot), "$r").text.shown(), "$r")
            val after = api.snapshot.earlierAccount
            if (r == ForgetEarlierResult.UNDER_WAY || r == ForgetEarlierResult.REQUEST_KEPT) {
                assertFalse(assertNotNull(after, "$r: the offer stays").confirming, "$r: at its first step")
            } else {
                assertNull(after, "$r")
            }
        }
        // STALE has no line of its own: nothing is said, and the snapshot shows what holds.
        val (api, _) = refused()
        assertNull(earlierResultLine(offer(api), ForgetEarlierResult.STALE))
    }

    // ---- never across a lock ----

    @Test
    fun aLockBetweenTheTwoStepsTakesTheConfirmationBackAndTheWindowKeepsNoneOfItsOwn() {
        val (api, m) = refused()
        m.quietly { m.api.entry.askToForgetEarlierAccount(offer(api)) }
        assertTrue(offer(api).confirming)
        api.lock()
        m.onSnapshot(api.snapshot)
        val o = offer(api)
        assertFalse(o.confirming, "the shared code took the confirmation back")
        assertTrue(earlierConfirmLines(o).isEmpty(), "the window draws only the first step now")
        // The button that forgets reads the offer on show, nothing kept: with the confirmation gone, a call would be refused.
        val r = kotlinx.coroutines.runBlocking { api.entry.forgetEarlierAccount(o) }
        assertEquals(ForgetEarlierResult.NOT_CONFIRMED, r)
        assertTrue(api.script.earlierAccountKnown)
    }

    // ---- the notice at the next account taken under the address ----

    @Test
    fun theNextAccountTakenUnderTheAddressIsSaidOnceAboveTheScreenUntilDismissed() {
        val (api, m) = refused()
        m.quietly { m.api.entry.askToForgetEarlierAccount(offer(api)) }
        val o = offer(api)
        kotlinx.coroutines.runBlocking { api.entry.forgetEarlierAccount(o) }
        assertNull(api.snapshot.rememberedNewAccount, "not before an account is taken")
        m.run({ entry.submitSignIn(assertIs<EntryScreen.SignIn>(api.snapshot.entry), EVE, FakeScenes.PASSWORD) })
        val notice = assertNotNull(api.snapshot.rememberedNewAccount, "said once the new account is taken")
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, notice.line.key)
        // Drawn above whatever is on show, beside the other notices, with its dismiss.
        val column = body("TrustApp.kt", "fun TrustApp(").substringAfter("Column(Modifier.fillMaxSize()) {")
        assertTrue(column.indexOf("NewAccountRememberedBar(model, s)") in 0 until column.indexOf("when (s.phase)"))
        val scene = ImageComposeScene(480, 1400, Density(1f)) { MaterialTheme { TrustApp(m, null, "log") } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
        m.quietly { m.api.dismissNewAccountRemembered(notice) }
        assertNull(api.snapshot.rememberedNewAccount)
        assertTrue(body("EarlierAccountOffer.kt", "internal fun NewAccountRememberedBar(").contains("model.api.dismissNewAccountRemembered(notice)"))
    }
}
