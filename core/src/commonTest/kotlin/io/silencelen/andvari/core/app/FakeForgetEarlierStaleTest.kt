package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeScript
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The fake plays the two cases of "Forget the earlier account on this device" that the engine's tests walk beside it
 * (`EngineForgetEarlierCauseTest.aConfirmationIsNotTakenOnceTheAddressIsTiedToTheServedAccount` and
 * `EngineForgetEarlierCauseTest.theEarlierAccountBackUnderItsOwnKeyIsOfferedToForgetTheNewOne`): an offer and a confirmation
 * that no longer hold once the address is tied to the account served ([FakeScript.addressTiedToServed]), and the earlier
 * account served again under its own key after the next one was taken, which gets the offer to forget that new account
 * ([FakeScript.earlierBackUnderOwnKey]).
 */
class FakeForgetEarlierStaleTest {

    /** Refused at the sign-in with the offer on show. */
    private fun offered(): io.silencelen.andvari.core.app.fake.FakeAppApi {
        // FakeScenes.at gives the fake app interface.
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        app.script.earlierAccountKnown = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertNotNull(app.snapshot.earlierAccount)
        return app
    }

    @Test fun anOfferAndAConfirmationNoLongerHoldOnceTheAddressIsTiedToTheServedAccount() {
        // The first step.
        val first = offered()
        first.script.addressTiedToServed = true
        assertFalse(first.entry.askToForgetEarlierAccount(assertNotNull(first.snapshot.earlierAccount)))
        assertNull(first.snapshot.earlierAccount, "no offer stands")

        // The second step: refused, nothing forgotten, no offer left.
        val second = offered()
        assertTrue(second.entry.askToForgetEarlierAccount(assertNotNull(second.snapshot.earlierAccount)))
        val confirmation = assertNotNull(second.snapshot.earlierAccount)
        assertTrue(confirmation.confirming)
        second.script.addressTiedToServed = true
        assertEquals(ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT, await { second.entry.forgetEarlierAccount(confirmation) })
        assertNull(second.snapshot.earlierAccount, "no offer stands")
        assertTrue(second.script.earlierAccountKnown, "nothing was forgotten")
    }

    @Test fun theEarlierAccountBackUnderItsOwnKeyIsOfferedToForgetTheNewOne() {
        val app = offered()
        val forgotten = assertNotNull(app.snapshot.earlierAccount)
        assertTrue(app.entry.askToForgetEarlierAccount(forgotten))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        // The next account was taken under the address; then the server serves the earlier account again, under its own key.
        app.script.earlierBackUnderOwnKey = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        val back = assertNotNull(app.snapshot.earlierAccount, "offered: someone who forgot by mistake finds the way back")
        assertNotEquals(forgotten.earlierUserId, back.earlierUserId, "the account offered is the new one")
        assertEquals(forgotten.earlierUserId, back.servedUserId, "the account served is the earlier one")
        assertTrue(app.entry.askToForgetEarlierAccount(back))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        assertFalse(app.script.earlierBackUnderOwnKey)
    }
}
