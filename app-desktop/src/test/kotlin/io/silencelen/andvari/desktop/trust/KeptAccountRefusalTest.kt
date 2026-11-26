package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
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
import kotlin.test.assertTrue

/**
 * A second account while a server-ended account is kept: every entry that can answer ANOTHER_ACCOUNT_KEPT names the
 * kept account and offers to sign it out, behind the usual warning, and the sign-out returns to the first screen.
 */
class KeptAccountRefusalTest {
    private val pw = FakeScenes.PASSWORD

    /** Ada signed in, her server ended the session, and "Sign in again" opened the journey: she is kept, signed out. */
    private fun keptAda(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        api.script.sessionEndedByServer()
        m.signInAgain()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertEquals(FakeScenes.EMAIL, assertNotNull(api.snapshot.keptSignedOut).email)
        return api to m
    }

    private inline fun <reified T : EntryScreen> on(api: FakeDesktopAppApi): T = assertIs<T>(api.snapshot.entry)

    /** The refusal as the screen shows it, then the sign-out of the kept account, which lands on the first screen. */
    private fun refusedThenSignedOut(api: FakeDesktopAppApi, m: TrustModel, expected: IntentResult) {
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the screen it was asked on")
        assertEquals<IntentResult?>(expected, said.result)
        val lines = assertNotNull(keptAccountLines(said.result, api.snapshot))
        val first = lines.first().shown()
        val kept = assertNotNull(api.snapshot.keptSignedOut)
        assertTrue(first.contains(FakeScenes.EMAIL) && first.contains(kept.instance.name) && first.contains(kept.instance.origin), first)
        // Named by their keys, so this holds whatever their words are.
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, assertIs<UiText.Ph>(lines.first()).placeholder)
        // A recovery's commit that went through says the shared code's sentence for it, nothing of the desktop's own.
        val committed = UiText.of(assertNotNull(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT.sentence)).shown()
        assertTrue(lines.drop(1).all { it.shown() == committed })

        // Its copy cannot be counted from the journey: the sign-out confirmation says so, and only its second
        // confirmation signs out (the rule of 2026-11-17).
        val ask = SignOutAsk(m, SignOutAct.SignOut) {}
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGN_OUT_UNSENT_UNKNOWN, ask.check?.line?.key)
        ask.proceed()
        assertTrue(ask.second)
        assertNotNull(api.snapshot.keptSignedOut, "the first confirmation deletes nothing")
        ask.confirmLoss()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertNull(api.snapshot.keptSignedOut, "the kept account and its copy are gone")
    }

    @Test
    fun aSignInToAnotherAccountNamesTheKeptOneAndItsSignOutReturnsToTheFirstScreen() {
        val (api, m) = keptAda()
        val bea = api.script.publicInstance.addAccount("bea@example.com", pw)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openPasswordSignIn(on(api)) }
        m.run({ entry.choosePublicInstance(on(api)) })
        m.run({ entry.submitSignIn(on(api), bea.email, pw) })
        refusedThenSignedOut(api, m, SignInAnswer.ANOTHER_ACCOUNT_KEPT)

        // Afterwards the other account signs in.
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openPasswordSignIn(on(api)) }
        m.run({ entry.choosePublicInstance(on(api)) })
        m.run({ entry.submitSignIn(on(api), bea.email, pw) })
        assertNull(m.said.value, "the sign-in went through: nothing was refused")
        assertFalse(api.snapshot.entry is EntryScreen.SignIn)
    }

    @Test
    fun aRegistrationIsRefusedTheSameWay() {
        val (api, m) = keptAda()
        m.run({ entry.createAccountOnAndvari(on(api)) })
        // The shared code now refuses at the first step of sign-up: a new account is never the one kept
        // here, so no address and no code is sent. The email step shows the same refusal "Create account" did.
        val emailStep = on<EntryScreen.SignUpEmail>(api)
        m.run({ entry.startSignUp(emailStep, "cy@example.com", true) })
        assertIs<EntryScreen.SignUpEmail>(api.snapshot.entry, "nothing was sent: no code step")
        assertEquals(FakeScenes.EMAIL, assertNotNull(api.snapshot.keptSignedOut).email, "the kept account stays as it was")
        refusedThenSignedOut(api, m, SignUpStartResult.ANOTHER_ACCOUNT_KEPT)
        // The email step shows what was said through the place that shows the kept-account refusal.
        val screen = java.io.File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountEntryScreens.kt").readText()
            .substringAfter("internal fun SignUpEmailScreen(").substringBefore("\n}\n")
        assertTrue(screen.contains("SaidHere(model, s)"))
    }

    @Test
    fun aKitRecoveryOfAnotherAccountIsRefusedTheSameWay() {
        val (api, m) = keptAda()
        val dee = api.script.publicInstance.addAccount("dee@example.com", pw)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openForgot(on(api)) }
        m.act { entry.openKitEntry(on(api)) }
        m.run({ entry.submitKit(on(api), api.script.kitOf(dee), PayloadSource.PASTED) })
        m.run({ entry.confirmKitRecovery(on(api)) })
        refusedThenSignedOut(api, m, KitRecoverResult.ANOTHER_ACCOUNT_KEPT)
    }

    @Test
    fun aDeviceLinkPickupForAnotherAccountIsRefusedTheSameWay() {
        val (api, m) = keptAda()
        val eve = api.script.publicInstance.addAccount("eve@example.com", pw)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openLinkDevice(on(api)) }
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(eve, "MacBook"), PayloadSource.PASTED) })
        api.script.otherDeviceAnswers()
        api.script.otherDeviceApproves()
        m.run({ entry.submitLinkPassword(on(api), pw) })
        refusedThenSignedOut(api, m, LinkPasswordResult.ANOTHER_ACCOUNT_KEPT)
    }

    /**
     * Each of the five answers is recognised; after a kit's commit the screen also says the shared code's sentence for a
     * recovery committed beside a kept account (the new master password is set), in place of a line of the desktop's own.
     */
    @Test
    fun allFiveAnswersAreRecognisedAndTheCommittedKitSaysTheNewPasswordHolds() {
        val (api, _) = keptAda()
        val s: AppSnapshot = api.snapshot
        for (r in listOf(SignInAnswer.ANOTHER_ACCOUNT_KEPT, SignUpStartResult.ANOTHER_ACCOUNT_KEPT, CreateAccountResult.ANOTHER_ACCOUNT_KEPT, LinkPasswordResult.ANOTHER_ACCOUNT_KEPT, KitRecoverResult.ANOTHER_ACCOUNT_KEPT)) {
            assertEquals(1, assertNotNull(keptAccountLines(r, s), r.toString()).size)
        }
        val replaced = assertNotNull(keptAccountLines(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, s))
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, assertIs<UiText.Ph>(replaced.first()).placeholder)
        assertEquals(
            listOf(UiText.of(assertNotNull(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT.sentence)).shown()), replaced.drop(1).map { it.shown() },
            "the shared code's sentence for the commit",
        )
        assertTrue(Placeholder.entries.none { it.name == "KEPT_ACCOUNT_NEW_PASSWORD_IN_FORCE" }, "the desktop's own line is gone")
        assertNull(keptAccountLines(SignInAnswer.WRONG, s))
        // No account kept: the result's own words are shown, not a refusal naming nobody.
        val fresh = FakeScenes.desktopAt(FakeScene.SIGN_IN).snapshot
        assertNull(keptAccountLines(SignInAnswer.ANOTHER_ACCOUNT_KEPT, fresh))
    }

    /** Every screen of the five intents shows what was said through SaidHere, which carries the refusal and the warning. */
    @Test
    fun theRefusalIsShownWhereverOneOfTheFiveIntentsIsAskedAndTheSignOutWarnsFirst() {
        val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
        val said = File(dir + "TrustUi.kt").readText().substringAfter("internal fun SaidHere(").substringBefore("\n}\n")
        assertTrue(said.contains("val way = wayOutOf(said.result, said.text, s)") && said.contains("KeptAccountRefusal(model, s, way, offered = !showsNotKeptKit(s))"))
        val refusal = File(dir + "KeptAccountRefusal.kt").readText()
        val view = refusal.substringAfter("internal fun KeptAccountRefusal(").substringBefore("\n}\n")
        assertTrue(view.contains("asking = true") && view.contains("SignOutQuestion(model, way.kept, s)"), "the sign-out asks first")
        assertTrue(refusal.substringAfter("internal fun SignOutQuestion(").contains("Placeholder.KEPT_ACCOUNT_SIGN_OUT_DELETES"))
        val screens = File(dir + "AccountEntryScreens.kt").readText() + File(dir + "LinkAndRecoveryScreens.kt").readText()
        for ((intent, screen) in listOf(
            "entry.submitSignIn(" to "SignInScreen", "entry.submitSignInCode(" to "SignInScreen", "entry.startSignUp(" to "SignUpEmailScreen",
            "entry.createAccount(" to "CreateAccountScreen",
            "entry.submitLinkPassword(" to "LinkDevicePasswordScreen", "entry.confirmKitRecovery(" to "KitRecoverScreen",
            "entry.chooseReplacementPassword(" to "ReplacePasswordScreen",
        )) {
            val body = screens.substringAfter("internal fun $screen(").substringBefore("\n}\n")
            assertTrue(body.contains(intent) && body.contains("SaidHere(model, s)"), screen)
        }
    }
}
