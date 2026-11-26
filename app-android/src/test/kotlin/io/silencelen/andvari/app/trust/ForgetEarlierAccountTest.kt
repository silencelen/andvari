package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EarlierAccountKnown
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.SignInAnswer
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
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17), drawn as the shared code hands it: the refusal
 * with both possibilities as sentences of their own and neither preferred; the offer; the second step with every line
 * the confirmation carries; the call only from the person's own tap; a call that throws leaves the second step on show
 * and is never tried again by the app; the results' lines; the notice at the next sign-in under the address. Over the
 * shared code's fake, which plays the engine's answers.
 */
class ForgetEarlierAccountTest {
    private val email = "ada@example.com"

    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    /** The fake, the app's model over it, and how many times the app called the forgetting. */
    private class Walk(val fake: FakeAppApi, val api: EngineLike, val m: TrustModel) {
        var calls = 0
    }

    /** A sign-in refused because this phone remembers an earlier account under the address, which it keeps a copy of. */
    private fun refusedSignIn(): Walk {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.SIGN_IN)
        fake.script.publicInstance.addAccount(email, FakeScenes.PASSWORD)
        val api = EngineLike(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        val walk = Walk(fake, api, m)
        val inner = fake.entry
        api.entryOverride = object : EntryApi by inner {
            override suspend fun forgetEarlierAccount(confirmation: EarlierAccountKnown): ForgetEarlierResult {
                walk.calls++
                return inner.forgetEarlierAccount(confirmation)
            }
        }
        m.onSnapshot(api.snapshot)
        fake.script.earlierAccountKnown = true
        fake.script.earlierCopyKept = true
        fake.script.identityFault = true
        m.run({ entry.submitSignIn(assertIs(snapshot.entry), email, FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(SignInAnswer.IDENTITY_FAULT, assertNotNull(m.saidOn(api.snapshot)).result, "the refused result's line, said on the screen")
        return walk
    }

    private fun shown(offer: EarlierAccountKnown) = earlierAccountLines(offer).map { it.shown() }

    @Test
    fun theRefusalSaysBothPossibilitiesThenTheSecondStepSaysEverythingItsConfirmationCarries() {
        val w = refusedSignIn()
        val offer = assertNotNull(w.api.snapshot.earlierAccount, "offered on the refused screen")
        assertFalse(offer.confirming)
        assertEquals(
            listOf(
                UiText.of(CopyKey.REMADE_ACCOUNT_TITLE).shown(),
                UiText.of(offer.refusal).shown(),
                UiText.of(CopyKey.REMADE_ACCOUNT_IF_REMADE).shown(),
                UiText.of(CopyKey.REMADE_ACCOUNT_IF_SERVER).shown(),
                UiText.of(CopyKey.REMADE_ACCOUNT_HOW_TO_TELL).shown(),
            ),
            shown(offer),
            "the heading, the refusal, both possibilities and how to tell, each a sentence of its own",
        )
        assertEquals(CopyKey.REMADE_ACCOUNT_REFUSAL, offer.refusal.key)

        // Its first step: nothing is forgotten, and nothing is called.
        w.m.askToForgetEarlierAccount()
        val confirm = assertNotNull(w.api.snapshot.earlierAccount)
        assertTrue(confirm.confirming)
        assertEquals(0, w.calls, "the second step is shown; the forgetting is not called with it")
        assertTrue(w.fake.script.earlierAccountKnown, "nothing forgotten yet")
        // Every line the confirmation carries, in order: what goes, the copy that goes (what cannot be told of its
        // changes), and that it cannot be undone.
        assertEquals(
            listOf(CopyKey.REMADE_ACCOUNT_CONFIRM, CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL, CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS),
            confirm.confirmLines.map { it.key },
        )
        assertEquals(
            listOf(UiText.of(CopyKey.REMADE_ACCOUNT_CONFIRM_TITLE).shown()) + confirm.confirmLines.map { UiText.of(it).shown() },
            shown(confirm),
        )

        // Cancel: back to the offer; Cancel again: the offer goes.
        w.m.keepEarlierAccount()
        assertFalse(assertNotNull(w.api.snapshot.earlierAccount).confirming)
        w.m.keepEarlierAccount()
        assertNull(w.api.snapshot.earlierAccount)
        assertEquals(0, w.calls)
    }

    @Test
    fun aConfirmationIsNeverCarriedAcrossALockAndATapWithoutTheSecondStepCallsNothing() {
        val w = refusedSignIn()
        // The confirm button's own call, with no second step on show: nothing.
        w.m.forgetEarlierAccount()
        assertEquals(0, w.calls, "the second step is never offered by itself, nor skipped")
        w.m.askToForgetEarlierAccount()
        assertTrue(assertNotNull(w.api.snapshot.earlierAccount).confirming)
        w.m.act { lock() }
        assertFalse(assertNotNull(w.api.snapshot.earlierAccount).confirming, "the lock took the confirmation back")
        w.m.forgetEarlierAccount()
        assertEquals(0, w.calls, "the app holds no confirmation of its own to carry across the lock")
        assertTrue(w.fake.script.earlierAccountKnown)
    }

    @Test
    fun aForgettingThatThrowsLeavesTheSecondStepForTheNextTapAndIsNeverTriedAgainByTheApp() {
        val w = refusedSignIn()
        w.fake.script.forgetFailsOnce = true
        w.m.askToForgetEarlierAccount()
        w.m.forgetEarlierAccount()
        assertEquals(1, w.calls)
        val said = assertNotNull(w.m.saidOn(w.api.snapshot), "the fault is said in place")
        assertNull(said.result)
        assertEquals(Placeholder.WENT_WRONG, assertIs<UiText.Ph>(said.text).placeholder)
        assertTrue(assertNotNull(w.api.snapshot.earlierAccount, "the second step stays on show").confirming)
        // Nothing the app does by itself calls it again.
        w.m.tick()
        w.m.onSnapshot(w.api.snapshot)
        w.m.returnedToForeground()
        assertEquals(1, w.calls, "never retried by the app")

        // The person's next tap finishes it.
        w.m.forgetEarlierAccount()
        assertEquals(2, w.calls)
        assertNull(w.api.snapshot.earlierAccount)
        assertIs<EntryScreen.SignIn>(w.api.snapshot.entry, "the refused screen stays for the person to submit again")
        val forgotten = assertNotNull(w.m.saidOn(w.api.snapshot))
        assertEquals(ForgetEarlierResult.FORGOTTEN, forgotten.result)
        assertEquals(UiText.of(CopyKey.REMADE_ACCOUNT_FORGOTTEN, email).shown(), forgotten.text.shown())

        // The next sign-in under the address: this phone now remembers the new account, said once above the screen.
        w.m.run({ entry.submitSignIn(assertIs(snapshot.entry), email, FakeScenes.PASSWORD) })
        val notice = assertNotNull(w.api.snapshot.rememberedNewAccount)
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, notice.line.key)
        w.m.dismissNewAccountRemembered(notice)
        assertNull(w.api.snapshot.rememberedNewAccount)
    }

    @Test
    fun eachAnswerIsSaidInItsOwnLine() {
        for (answer in listOf(ForgetEarlierResult.UNDER_WAY, ForgetEarlierResult.REQUEST_KEPT, ForgetEarlierResult.ACCOUNT_OPEN, ForgetEarlierResult.NOTHING_TO_FORGET)) {
            val w = refusedSignIn()
            w.fake.script.forgetAnswer = answer
            w.m.askToForgetEarlierAccount()
            w.m.forgetEarlierAccount()
            val said = assertNotNull(w.m.saidOn(w.api.snapshot), "$answer")
            assertEquals(answer, said.result)
            assertEquals(UiText.of(assertNotNull(answer.sentence), email).shown(), said.text.shown(), "$answer")
            assertEquals(1, w.calls)
        }
    }

    @Test
    fun theOfferIsDrawnOnlyUnderTheRefusedLineWithTwoButtonsOfTheSameWeightAndTheNoticeAboveEveryScreen() {
        val offer = main("trust/EarlierAccountScreens.kt").substringAfter("internal fun EarlierAccountOffer(").substringBefore("\n}\n")
        assertEquals(3, Regex("Second\\(").findAll(offer).count(), "the step's button and Cancel, of one weight")
        for (never in listOf("Main(", "FocusRequester", "requestFocus", "BackHandler", "onKeyEvent", "onPreviewKeyEvent", "ImeAction", "LaunchedEffect")) {
            assertFalse(never in offer, "neither default, focused nor bound to a key: $never")
        }
        assertTrue("model.forgetEarlierAccount()" in offer && "model.askToForgetEarlierAccount()" in offer && "model.keepEarlierAccount()" in offer)
        // Drawn where the refused result's line is, and nowhere else.
        val here = main("trust/TrustUi.kt").substringAfter("internal fun SaidHere(").substringBefore("\n}\n")
        assertTrue("s.earlierAccount?.let { EarlierAccountOffer(model, s, it) }" in here)
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        fun usersOf(token: String) = sources.filter { f -> f.readLines().any { token in it.substringBefore("//") } }.map { it.name }.toSet()
        // And on the screen of a device link that ended, where the shared code raises it for a refused link.
        assertEquals(setOf("TrustUi.kt", "EarlierAccountScreens.kt", "LinkAndRecoveryScreens.kt"), usersOf("EarlierAccountOffer("))
        val ended = main("trust/LinkAndRecoveryScreens.kt").substringAfter("internal fun LinkDeviceEndedScreen(").substringBefore("\n}\n")
        assertTrue("s.earlierAccount?.let { EarlierAccountOffer(model, s, it) }" in ended)
        assertEquals(setOf("TrustModel.kt"), usersOf("entry.forgetEarlierAccount("), "one call, in the model")
        assertEquals(setOf("TrustModel.kt"), usersOf("entry.askToForgetEarlierAccount("))
        assertEquals(setOf("TrustUi.kt", "TrustModel.kt", "LinkAndRecoveryScreens.kt"), usersOf(".earlierAccount"), "read from the snapshot, never kept")
        // The model reads the offer on show at the tap, and keeps none.
        val model = main("trust/TrustModel.kt")
        assertFalse(Regex("(val|var) \\w+: (io\\.silencelen\\.andvari\\.core\\.app\\.)?EarlierAccountKnown").containsMatchIn(model), "no confirmation kept")
        val call = model.substringAfter("fun forgetEarlierAccount() {").substringBefore("\n    }\n")
        assertTrue("api.snapshot.earlierAccount?.takeIf { it.confirming } ?: return" in call)
        // The notice is drawn above whatever screen is on show, with its dismiss.
        val root = main("trust/TrustApp.kt").substringAfter("fun TrustApp(").substringBefore("\n}\n")
        val notice = root.indexOf("s.rememberedNewAccount?.let { NewAccountRememberedView(model, it) }")
        assertTrue(notice > 0 && notice < root.indexOf("when (s.phase)"))
    }
}
