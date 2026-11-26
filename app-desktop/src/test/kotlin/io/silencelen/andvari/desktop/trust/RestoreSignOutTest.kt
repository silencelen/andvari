package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A sign-out and "Forget this server" delete the restore's record with everything else this computer holds of the
 * account. While a restore of the account has not finished here, the question before that act says so (decided on
 * 23 November 2026, as built until the person who decides says otherwise).
 */
internal class RestoreSignOutTest : RestoreTestKit() {
    private val line get() = ph(Placeholder.RESTORE_UNFINISHED_AT_SIGN_OUT)

    private fun signOutQuestion(w: World): List<String> = drawn { SignOutQuestion(w.m, null, w.api.snapshot) {} }

    private fun forgetQuestion(w: World): List<String> = drawn { ForgetServerQuestion(w.m, assertNotNull(w.api.snapshot.instance)) {} }

    @Test
    fun aSignOutAfterAStopSaysTheRestoreHasNotFinishedAndTheSameFileThenStoresTwice() {
        val w = world("sign-out-unfinished")
        keepOn(w)
        val bytes = backup(401)
        stopAfter(w, bytes, taken = 1)
        val asked = signOutQuestion(w)
        val forget = forgetQuestion(w)
        println("SIGNOUT|question=$asked forget=$forget")
        has(asked, line)
        has(forget, line)
        // The person signs out all the same: the record goes, and the same file stores again what was stored.
        signOut(w)
        runBlocking { signIn(w.api, w.instance) }
        w.m.onSnapshot(w.api.snapshot)
        val again = flow(w, bytes)
        open(again)
        runBlocking { again.confirm() }
        println("SIGNOUT|after signing in again: items=${personalItems(w)}")
        assertEquals(601, personalItems(w), "what the line says: stored a second time")
    }

    @Test
    fun noLineWithoutARestoreOrAfterOneThatFinishedWithASharedVaultLeftUnticked() {
        val w = world("sign-out-finished")
        assertFalse(line in signOutQuestion(w), "no restore at all")
        val f = flow(w, backup(3, familyItems = 2))
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        val asked = signOutQuestion(w)
        assertTrue(asked.isNotEmpty(), "the question is drawn")
        assertFalse(line in asked, "a vault left unticked is not an unfinished restore: $asked")
        assertFalse(line in forgetQuestion(w))
    }

    @Test
    fun itemsTheServerRefusedAreAnUnfinishedRestore() {
        val w = world("sign-out-refused")
        w.server.rejectFirst = true
        val f = flow(w, backup(3))
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        has(signOutQuestion(w), line)
    }
}
