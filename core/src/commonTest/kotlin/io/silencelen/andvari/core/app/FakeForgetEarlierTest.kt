package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The fake plays "Forget the earlier account on this device" as the engine does, so that the apps' walks can. */
class FakeForgetEarlierTest {
    @Test
    fun theFakeOffersTheForgettingOnlyForAnEarlierAccountAndPlaysItsTwoStepsAndEveryAnswer() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        val screen = app.on<EntryScreen.SignIn>()
        // An identity fault that is not about an earlier account offers nothing.
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertNull(app.snapshot.earlierAccount)

        // An earlier account kept here as a copy whose data is held: as the engine, its changes not sent cannot be told
        // (no other number is ever given for an account that is not open).
        app.script.earlierAccountKnown = true
        app.script.earlierCopyKept = true
        app.script.earlierCopyUnsent = 3
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(screen, ADA, PW) })
        val offer = assertNotNull(app.snapshot.earlierAccount)
        assertTrue(offer.keptCopy)
        assertNull(offer.unsentChanges)
        assertEquals(ForgetEarlierResult.NOT_CONFIRMED, await { app.entry.forgetEarlierAccount(offer) })
        assertTrue(app.entry.askToForgetEarlierAccount(offer))
        val confirm = assertNotNull(app.snapshot.earlierAccount)
        assertEquals(
            listOf(CopyKey.REMADE_ACCOUNT_CONFIRM, CopyKey.REMADE_ACCOUNT_CONFIRM_COPY_CANNOT_TELL, CopyKey.REMADE_ACCOUNT_CONFIRM_ALWAYS),
            confirm.confirmLines.map { it.key },
        )
        // A lock between the steps takes the confirmation back.
        app.lock()
        assertFalse(assertNotNull(app.snapshot.earlierAccount).confirming)
        assertEquals(ForgetEarlierResult.STALE, await { app.entry.forgetEarlierAccount(confirm) })

        // Each answer the engine can give.
        for (answer in listOf(ForgetEarlierResult.UNDER_WAY, ForgetEarlierResult.REQUEST_KEPT)) {
            app.script.forgetAnswer = answer
            assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
            assertEquals(answer, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
            assertFalse(assertNotNull(app.snapshot.earlierAccount, "the offer stays").confirming)
        }
        app.script.forgetAnswer = ForgetEarlierResult.ACCOUNT_OPEN
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.ACCOUNT_OPEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        assertNull(app.snapshot.earlierAccount)
        // As the engine: no offer for the account kept here; once it is no longer kept, the earlier account is offered again.
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertNull(app.snapshot.earlierAccount)
        app.script.earlierAccountKnown = true

        app.script.forgetAnswer = ForgetEarlierResult.FORGOTTEN
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        assertNull(app.snapshot.earlierAccount)
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(screen, ADA, PW) })
        val notice = assertNotNull(app.snapshot.rememberedNewAccount)
        assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, notice.line.key)
        app.dismissNewAccountRemembered(notice)
        assertNull(app.snapshot.rememberedNewAccount)
    }
}
