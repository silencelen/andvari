package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The fake keeps the engine's rule: no sign-out, and no switch, over unsent changes without the person's second confirmation. */
class FakeSignOutUnsentTest {
    private fun FakeAppApi.offlineSave(name: String) {
        val c = assertNotNull(fakeContent)
        c.setOffline(true)
        assertEquals(ActionResult.Ok, await { c.saveLogin(null, LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false), null) })
    }

    @Test
    fun aSignOutOverUnsentChangesAsksAgainSendsFirstAndGoesOnlyWhenConfirmed() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        assertEquals(0, assertNotNull(app.signOutCheck()).unsentChanges)
        app.offlineSave("Bank")
        val check = assertNotNull(app.signOutCheck())
        assertEquals(1, check.unsentChanges)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, check.line?.key)
        assertTrue(check.canSendFirst)
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, await { app.signOut() })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)

        // Sending first while still offline: not sent, still asked.
        assertEquals(SendFirstResult.NOT_ALL_SENT, await { app.sendBeforeSignOut(check) })
        assertEquals(1, assertNotNull(app.signOutCheck()).unsentChanges)

        // The switch is held behind the same confirmation.
        val other = assertIs<OpenedInvite.OtherInstance>(app.account.opened)
        assertEquals(ServerResult.UNSENT_NOT_CONFIRMED, await { app.links.switchInstance(other) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)

        // Back online, sending first empties the queue; then nothing more is asked.
        assertNotNull(app.fakeContent).setOffline(false)
        assertEquals(SendFirstResult.DONE, await { app.sendBeforeSignOut(assertNotNull(app.signOutCheck())) })
        assertFalse(assertNotNull(app.signOutCheck()).needsConfirmation)
        assertEquals(ServerResult.DONE, await { app.links.switchInstance(other) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
    }

    @Test
    fun theConfirmedSwitchAndTheConfirmedSignOutGoOverUnsentChanges() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        app.offlineSave("Bank")
        val other = assertIs<OpenedInvite.OtherInstance>(app.account.opened)
        assertEquals(ServerResult.DONE, await { app.links.switchInstanceConfirmed(other, assertNotNull(app.signOutCheck())) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)

        val again = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        again.offlineSave("Shop")
        val check = assertNotNull(again.signOutCheck())
        again.offlineSave("Mail")
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, await { again.signOutConfirmed(check) }, "a check that no longer holds")
        assertEquals(PlainResult.DONE, await { again.signOutConfirmed(assertNotNull(again.signOutCheck())) })
        assertNull(again.signOutCheck())
    }

    @Test
    fun lockedAfterTheVaultWasOpenTheFakeCannotTellEither() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        app.lock()
        val check = assertNotNull(app.signOutCheck())
        assertNull(check.unsentChanges)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, check.line?.key)
        assertFalse(check.canSendFirst)
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, await { app.signOut() })
        assertEquals(PlainResult.DONE, await { app.signOutConfirmed(check) })
    }

    @Test
    fun theFakesSwitchLineFollowsWhatThisDeviceSetForLinking() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        val other = assertIs<OpenedInvite.OtherInstance>(app.account.opened)
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN, other.signOutLine.key)
    }
}
