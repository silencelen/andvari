package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A second account while one its server signed out is kept on this phone. The refusal names the
 * kept account, offers to sign it out behind a warning, and the sign-out lands on the first screen.
 */
class KeptAccountRefusalTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private inline fun <reified S : EntryScreen> FakeAppApi.on(): S = assertIs<S>(snapshot.entry)

    @Test
    fun aSecondSignInNamesTheKeptAccountAndItsSignOutLandsOnTheFirstScreen() {
        val (api, m) = at(FakeScene.VAULTS)
        val bea = api.script.publicInstance.addAccount("bea@example.com", FakeScenes.PASSWORD)
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        val kept = assertNotNull(api.snapshot.keptSignedOut)
        api.entry.openSignIn(api.on())
        api.entry.openPasswordSignIn(api.on())
        assertEquals(ServerResult.DONE, runBlocking { api.entry.choosePublicInstance(api.on()) })

        val screen = api.on<EntryScreen.SignIn>()
        m.run({ entry.submitSignIn(screen, bea.email, FakeScenes.PASSWORD) })
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the sign-in screen")
        assertEquals(SignInAnswer.ANOTHER_ACCOUNT_KEPT, said.result)
        val ph = assertIs<UiText.Ph>(said.text)
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, ph.placeholder)
        assertEquals(listOf(FakeScenes.EMAIL, kept.instance.name, kept.instance.origin), ph.args, "it names the kept account and its server")
        assertTrue(offersKeptSignOut(api.snapshot, said.result))
        val warning = keptSignOutWarning(kept)
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_WARNING, (warning as UiText.Ph).placeholder)
        assertTrue(Placeholder.KEPT_ACCOUNT_SIGN_OUT_WARNING.gloss.contains("cannot be undone"))
        assertTrue(Placeholder.KEPT_ACCOUNT_SIGN_OUT_WARNING.gloss.contains("deletes this phone's copy"))

        // Its copy is not open, so this phone cannot count what was not sent: the confirmation says so and asks twice.
        val ask = m.signOutAsk()
        ask.open()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, assertNotNull(ask.check?.line).key)
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step)
        assertNotNull(api.snapshot.keptSignedOut, "the first confirmation deletes nothing")
        ask.confirm()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "back at the first screen")
        assertNull(api.snapshot.keptSignedOut)
        assertNull(m.saidOn(api.snapshot), "the sign-out says nothing on the first screen")

        // Now the other account signs in.
        api.entry.openSignIn(api.on())
        api.entry.openPasswordSignIn(api.on())
        assertEquals(ServerResult.DONE, runBlocking { api.entry.choosePublicInstance(api.on()) })
        m.run({ entry.submitSignIn(api.on(), bea.email, FakeScenes.PASSWORD) })
        assertTrue(api.snapshot.phase == AppPhase.UNLOCKED || api.snapshot.entry is EntryScreen.Kit)
    }

    @Test
    fun everyKeptRefusalIsRecognisedAndAReplacedPasswordSaysItIsInForce() {
        for (r in listOf(SignInAnswer.ANOTHER_ACCOUNT_KEPT, CreateAccountResult.ANOTHER_ACCOUNT_KEPT, LinkPasswordResult.ANOTHER_ACCOUNT_KEPT, KitRecoverResult.ANOTHER_ACCOUNT_KEPT)) {
            assertEquals(KeptRefusal.SIGN_OUT_FIRST, keptRefusal(r), r.toString())
            assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, (keptAccountWords(r, null) as UiText.Ph).placeholder)
        }
        assertEquals(KeptRefusal.PASSWORD_IN_FORCE, keptRefusal(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT))
        val inForce = keptAccountWords(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, null) as UiText.Ph
        assertEquals(Placeholder.KEPT_ACCOUNT_PASSWORD_IN_FORCE, inForce.placeholder)
        assertTrue(inForce.placeholder.gloss.contains("new master password is in force"))
        for (r in listOf(SignInAnswer.WRONG, SignInAnswer.STALE, ReplacePasswordResult.DONE, PlainResult.DONE, null)) {
            assertNull(keptRefusal(r))
            assertNull(keptAccountWords(r, null))
        }
    }

    @Test
    fun aRegistrationWhileAnAccountIsKeptIsRefusedWithTheSameOffer() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        assertNotNull(api.snapshot.keptSignedOut)
        // Every screen that runs the intent through the model words the answer this way.
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, (m.wordsFor(CreateAccountResult.ANOTHER_ACCOUNT_KEPT) as UiText.Ph).placeholder)
        assertEquals(FakeScenes.EMAIL, (m.wordsFor(CreateAccountResult.ANOTHER_ACCOUNT_KEPT) as UiText.Ph).args.first())
    }

    @Test
    fun theSignOutOfferIsUnderEveryAnswerShownInPlace() {
        val ui = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustUi.kt").readText()
            .substringAfter("internal fun SaidHere(").substringBefore("\n}\n")
        assertTrue(ui.contains("WayOutOffer(model, s, wayOutFor(said.result))"))
        val way = File("src/main/kotlin/io/silencelen/andvari/app/trust/KeptAccountScreens.kt").readText().substringAfter("internal fun WayOutOffer(").substringBefore("\n}\n")
        assertTrue(way.contains("WayOut.KEPT_SIGN_OUT -> s.keptSignedOut?.let { KeptAccountSignOut(model, s, it) }"))
        val kept = File("src/main/kotlin/io/silencelen/andvari/app/trust/KeptAccountScreens.kt").readText()
        assertTrue(kept.contains("model.signOutAsk()") && kept.contains("SignOutConfirm(ask, s,"), "only the confirmation signs out")
        assertTrue(kept.contains("warning = if (removal) copyRemovalWarning(kept) else keptSignOutWarning(kept)"))
    }
}
