package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.content.ContentCopy
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame

/** The fake plays the policy's wipe as the engine does, so that the apps' tests can walk the notice and the refusal. */
class FakePolicyWipeTest {
    @Test
    fun theFakePlaysTheRefusalWhileTheCopyIsRemovedAndTheNoticeUntilItIsDismissed() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        val c = assertNotNull(app.fakeContent)
        c.removingForPolicy()
        // As the engine: the content's state says the copy is being removed, with its own line (not a save's refusal), and
        // is not a stopped server.
        assertEquals(ContentCopy.REMOVING_LINE, c.state.removingLine)
        assertEquals(CopyKey.POLICY_COPY_BEING_REMOVED.english, c.state.removingLine)
        assertEquals(false, c.state.serverStopped)
        val r = await { c.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.test"), "", "", false), null) }
        assertEquals(ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED), r)
        c.removingForPolicy(false)
        assertNull(c.state.removingLine)

        app.script.policyCopyRemoved(notSent = 2, unsure = 1, serverName = "Home")
        val notice = assertNotNull(app.snapshot.policyWipe)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE_ONE), notice.lines.map { it.key })
        assertEquals(listOf("2", "Home", "1"), notice.lines[0].values)
        app.lock()
        assertSame(notice, app.snapshot.policyWipe, "on the lock screen too")
        app.dismissPolicyWipe(notice)
        assertNull(app.snapshot.policyWipe)
    }

    /**
     * As the engine, the notice belongs to its account: another account's session neither reads it nor puts it away;
     * it is shown where no session is kept.
     */
    @Test
    fun theFakesNoticeBelongsToItsAccount() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        app.script.policyCopyRemoved(notSent = 4, userId = "someone-else")
        assertNull(app.snapshot.policyWipe, "another account's notice is not read inside this one")
        assertEquals(PlainResult.DONE, await { app.signOutConfirmed(assertNotNull(app.signOutCheck())) })
        val shown = assertNotNull(app.snapshot.policyWipe, "no session is kept: it is shown")
        assertEquals(4, shown.notSent)
    }

    /** By default the notice is the account's on show, and it is shown there. */
    @Test
    fun theFakesNoticeIsTheOpenAccountsByDefault() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        app.script.policyCopyRemoved(notSent = 1)
        assertEquals(1, assertNotNull(app.snapshot.policyWipe).notSent)
    }

    /** While the copy is being removed, every change to a shared vault is refused with the removal's line. */
    @Test
    fun theFakeRefusesSharedVaultChangesWhileTheCopyIsRemoved() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        val c = assertNotNull(app.fakeContent)
        c.removingForPolicy()
        val r = await { app.vaults.createVault("Family") }
        assertEquals(VaultActionResult.REMOVING_COPY, r)
        assertEquals(CopyKey.SAVE_COPY_BEING_REMOVED, r.sentence)
        c.removingForPolicy(false)
        assertEquals(VaultActionResult.DONE, await { app.vaults.createVault("Family") })
    }

    /**
     * After the policy's wipe the account goes on from the server, its copy in memory only: what waits there is counted
     * (the number an app asks with before it ends).
     */
    @Test
    fun theFakeCountsWhatWaitsInMemoryAfterThePolicysWipe() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        val c = assertNotNull(app.fakeContent)
        assertEquals(0, app.waitingInMemory(), "a copy kept at rest: nothing waits in memory only")
        app.script.policyCopyRemoved(notSent = 0)
        c.setOffline(true)
        assertEquals(ActionResult.Ok, await { c.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.test"), "", "", false), null) })
        assertEquals(1, app.waitingInMemory())
    }

    /** The mark that the copy goes on in memory is the account's whose copy it was: another account signed in is counted as usual. */
    @Test
    fun theFakesCopyInMemoryEndsWhenAnotherAccountSignsIn() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        // An earlier account's copy went on in memory after the policy's wipe (as policyCopyRemoved leaves it).
        app.copyInMemory = true
        app.script.waitingInMemory = 7
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on<EntryScreen.SignIn>(), ADA, PW) })
        assertEquals(7, app.waitingInMemory(), "this account's copy is kept as usual: the script's number, not the earlier copy's")
    }
}
