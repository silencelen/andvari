package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeScript
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The fake plays both causes of the identity fault as the engine does (decided on 2026-11-19): "Forget the earlier account on
 * this device" only where the server serves ANOTHER account than the one the address is tied to, never where it serves the
 * same account under another key ([FakeScript.sameAccountOtherKey]); and after a forgetting, the earlier account under
 * another key is refused with no offer (the engine keeps its key).
 */
class FakeForgetEarlierCauseTest {
    private val strong = "correct horse Battery 9 staple"

    @Test fun aSignInOrAKitCheckServingTheSameAccountUnderAnotherKeyOffersNothing() {
        for (same in listOf(true, false)) {
            val app = FakeScenes.at(FakeScene.SIGN_IN)
            app.script.publicInstance.addAccount(ADA, PW)
            app.script.earlierAccountKnown = true
            app.script.sameAccountOtherKey = same
            app.script.identityFault = true
            assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
            assertEquals(!same, app.snapshot.earlierAccount != null, "the same account under another key: $same")

            val kit = FakeScenes.at(FakeScene.KIT_RECOVER)
            kit.script.earlierAccountKnown = true
            kit.script.sameAccountOtherKey = same
            kit.script.identityFault = true
            assertEquals(KitRecoverResult.IDENTITY_FAULT, await { kit.entry.confirmKitRecovery(kit.on()) })
            assertEquals(!same, kit.snapshot.earlierAccount != null, "kit check, the same account under another key: $same")
        }
    }

    @Test fun aCommitOrAnOperatorsAnswerServingTheSameAccountUnderAnotherKeyOffersNothing() {
        for (same in listOf(true, false)) {
            val commit = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
            commit.script.earlierAccountKnown = true
            commit.script.sameAccountOtherKey = same
            commit.script.keeperIdentityFault = true
            assertEquals(ReplacePasswordResult.IDENTITY_FAULT, await { commit.entry.chooseReplacementPassword(commit.on(), "a whole new Passphrase 42 here") })
            assertEquals(!same, commit.snapshot.earlierAccount != null, "commit, the same account under another key: $same")

            val help = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
            help.script.earlierAccountKnown = true
            help.script.sameAccountOtherKey = same
            help.script.advance(7 * FakeScript.DAY)
            assertTrue(help.script.operatorAnswers(forged = false))
            assertNotNull(help.helpRequest).boundElsewhere = true
            assertEquals(ServerResult.DONE, await { help.entry.refreshOperatorHelp(help.on()) })
            assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, help.on<EntryScreen.OperatorHelp>().identityFault)
            assertEquals(!same, help.snapshot.earlierAccount != null, "operator's answer, the same account under another key: $same")
        }
    }

    /** A registration's account is always new, never the earlier one under another key: offered as before. */
    @Test fun aRegistrationIsOfferedAsBefore() {
        val reg = FakeScenes.at(FakeScene.CREATE_ACCOUNT)
        reg.script.earlierAccountKnown = true
        reg.script.sameAccountOtherKey = true
        assertEquals(CreateAccountResult.IDENTITY_FAULT, await { reg.entry.createAccount(reg.on(), NewAccountInput("", "Ada", strong, true)) })
        assertNotNull(reg.snapshot.earlierAccount)
    }

    /** After FORGOTTEN, the earlier account served under another key is refused with no offer, as the engine with its kept key. */
    @Test fun afterAForgettingTheEarlierAccountUnderAnotherKeyIsRefusedWithNoOffer() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        app.script.earlierAccountKnown = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertTrue(app.entry.askToForgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, await { app.entry.forgetEarlierAccount(assertNotNull(app.snapshot.earlierAccount)) })
        app.script.sameAccountOtherKey = true
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertNull(app.snapshot.earlierAccount)
    }
}
