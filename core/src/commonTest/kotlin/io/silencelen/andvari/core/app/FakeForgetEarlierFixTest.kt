package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The fake plays the forgetting's answers as the engine gives them, so that the apps' walks meet only real answers. */
class FakeForgetEarlierFixTest {
    private val strong = "correct horse Battery 9 staple"

    @Test fun aHeldCopyIsSaidAsDeletedWithItsChangesNotToldAndAKeptCopyNotHeldCountsNone() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        app.script.earlierAccountKnown = true
        app.script.earlierCopyHeld = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        val offer = assertNotNull(app.snapshot.earlierAccount)
        assertTrue(offer.keptCopy)
        assertNull(offer.unsentChanges)
        app.entry.keepEarlierAccount(offer)
        app.script.earlierCopyHeld = false
        app.script.earlierCopyKept = true
        app.script.earlierCopyUnsent = 0
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertEquals(0, assertNotNull(app.snapshot.earlierAccount).unsentChanges)
    }

    @Test fun aRegistrationIsOfferedTheForgettingOnlyForTheKeepersRefusalNotTheServersFault() {
        val faulty = FakeScenes.at(FakeScene.CREATE_ACCOUNT)
        // The server's answer does not carry back the identity: its own fault, no offer.
        faulty.script.earlierAccountKnown = true
        faulty.script.identityFault = true
        assertEquals(CreateAccountResult.IDENTITY_FAULT, await { faulty.entry.createAccount(faulty.on(), NewAccountInput("", "Ada", strong, true)) })
        assertNull(faulty.snapshot.earlierAccount)
        // The keeper's refusal of an address known here under an earlier account: offered, and after it the registration goes on.
        val reg = FakeScenes.at(FakeScene.CREATE_ACCOUNT)
        reg.script.earlierAccountKnown = true
        assertEquals(CreateAccountResult.IDENTITY_FAULT, await { reg.entry.createAccount(reg.on(), NewAccountInput("", "Ada", strong, true)) })
        val offer = assertNotNull(reg.snapshot.earlierAccount)
        assertTrue(reg.entry.askToForgetEarlierAccount(offer))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { reg.entry.forgetEarlierAccount(assertNotNull(reg.snapshot.earlierAccount)) })
        assertEquals(CreateAccountResult.DONE, await { reg.entry.createAccount(reg.on(), NewAccountInput("", "Ada", strong, true)) })
    }

    @Test fun nothingToForgetIsNotOfferedAgain() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        app.script.earlierAccountKnown = true
        app.script.forgetAnswer = ForgetEarlierResult.NOTHING_TO_FORGET
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.NOTHING_TO_FORGET, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertNull(app.snapshot.earlierAccount)
    }

    @Test fun aForgettingThatFailsPartWayIsFinishedByTheNextTap() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        app.script.earlierAccountKnown = true
        app.script.forgetFailsOnce = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        val confirm = assertNotNull(app.snapshot.earlierAccount)
        assertIs<IllegalStateException>(runCatching { await { app.entry.forgetEarlierAccount(confirm) } }.exceptionOrNull())
        assertTrue(assertNotNull(app.snapshot.earlierAccount).confirming, "the second step stays on show")
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(confirm) })
        assertNull(app.snapshot.earlierAccount)
    }

    @Test fun afterForgottenATwoStepSignInStandsAtItsPasswordStepAndTheNoticeNamesTheServer() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW).twoStepCode = "123456"
        app.script.earlierAccountKnown = true
        assertEquals(SignInAnswer.CODE_NEEDED, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignInCode(app.on(), "123456") })
        // As the engine: the code step was used, so the screen is back at the password at once, with the offer on it.
        assertFalse(app.on<EntryScreen.SignIn>().codeNeeded)
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        assertFalse(app.on<EntryScreen.SignIn>().codeNeeded, "back at the password step")
        assertEquals(SignInAnswer.CODE_NEEDED, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignInCode(app.on(), "123456") })
        assertNotNull(app.snapshot.rememberedNewAccount)
    }

    /** As the engine: the notice that the new account is remembered stays until dismissed, also across a restart. */
    @Test fun theRememberedNoticeStaysUntilDismissedAcrossARestart() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        app.script.earlierAccountKnown = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertNotNull(app.snapshot.rememberedNewAccount)
        app.script.restart()
        assertEquals(AppPhase.LOCKED, app.snapshot.phase)
        val notice = assertNotNull(app.snapshot.rememberedNewAccount, "said again after a restart")
        app.dismissNewAccountRemembered(notice)
        assertNull(app.snapshot.rememberedNewAccount)
        app.script.restart()
        assertNull(app.snapshot.rememberedNewAccount, "dismissed: not said again")
    }
}
