package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KeptWayOut
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A session this phone could not confirm with its server in time, walked over the stand-in's own way to play it
 * ([io.silencelen.andvari.core.app.fake.FakeScript.sessionNotConfirmed]): said as that end on the lock screen and on the
 * first screen after "Sign in again", never as the server's; and, where a way out that signs that kept account OUT
 * stands on the same screen (the notice that a kit was wiped names it), the shared code's line for that end without
 * "sign in again" ([CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST]), so the person is never told two opposite things.
 */
class SessionNotConfirmedOnPhoneTest {
    private fun lockedNotConfirmed(): FakeAppApi = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED).also { it.script.sessionNotConfirmed() }

    @Test
    fun aSessionThePhoneCouldNotConfirmIsSaidAsThatEndNeverAsTheServers() {
        val fake = lockedNotConfirmed()
        val locked = assertNotNull(fake.snapshot.locked)
        assertTrue(locked.sessionNotConfirmed)
        assertTrue(locked.signedOutByServer, "kept as a session that ended: \"Sign in again\" and \"Sign out\" stay")
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), lockEndLine(locked, signOutWayOutStands(fake.snapshot))?.shown())
        assertNotEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), lockEndLine(locked)?.shown(), "never the server's end")

        // "Sign in again": the first screen, the account kept signed out, the same end said there.
        fake.signInAgain(locked)
        assertEquals(AppPhase.ENTRY, fake.snapshot.phase)
        assertNotNull(fake.snapshot.keptSignedOut)
        assertTrue(fake.snapshot.keptSignedOutNotConfirmed)
        val first = assertIs<EntryScreen.FirstRun>(fake.snapshot.entry)
        assertFalse(signOutWayOutStands(fake.snapshot), "no way out that signs it out stands here")
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), sessionNotConfirmedLine(first, signOutWayOutStands(fake.snapshot))?.shown())
    }

    /**
     * The whole walk through the phone's model, step by step: the lock screen's card, the first screen after "Sign in
     * again", and another account's sign-in while this one is kept: refused with the kept account named, its sign-out as
     * the way out, never "sign in again" and never the server's end.
     */
    @Test
    fun aSessionThePhoneCouldNotConfirmIsItsOwnEndOnEveryScreenAndAnotherAccountsSignInOffersTheKeptOnesSignOut() {
        val fake = lockedNotConfirmed()
        val m = TrustModel(fake, kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)

        // d1. The lock screen.
        val locked = assertNotNull(fake.snapshot.locked)
        val end = assertNotNull(lockEndLine(locked, signOutWayOutStands(fake.snapshot)))
        WalkPrint.draws("d1 the lock screen", listOf(end, m.saidOn(fake.snapshot)?.text, UiText.ph(Placeholder.SIGN_IN_AGAIN)))
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), end.shown())
        assertNotEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), end.shown(), "never the server's end")
        kotlin.test.assertNull(m.saidOn(fake.snapshot))

        // d2. "Sign in again": the first screen says the same end, with no notice of the server's end.
        m.act { signInAgain(locked) }
        m.onSnapshot(fake.snapshot)
        val first = assertIs<EntryScreen.FirstRun>(fake.snapshot.entry)
        val firstLine = sessionNotConfirmedLine(first, signOutWayOutStands(fake.snapshot))
        WalkPrint.draws("d2 the first screen", listOf(firstLine, m.saidOn(fake.snapshot)?.text))
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), firstLine?.shown())
        kotlin.test.assertNull(first.notice, "no notice of the server's end")

        // d3. Another account's sign-in while this one is kept: refused, the kept account named, its sign-out offered.
        fake.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        m.act { entry.openSignIn(first) }
        m.act { entry.openPasswordSignIn(assertIs(snapshot.entry)) }
        kotlinx.coroutines.runBlocking { m.run({ entry.choosePublicInstance(assertIs(snapshot.entry)) }).join() }
        m.onSnapshot(fake.snapshot)
        var answer: io.silencelen.andvari.core.app.IntentResult? = null
        kotlinx.coroutines.runBlocking { m.run({ entry.submitSignIn(assertIs(snapshot.entry), "bo@example.com", FakeScenes.PASSWORD) }) { answer = it }.join() }
        m.onSnapshot(fake.snapshot)
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.ANOTHER_ACCOUNT_KEPT, answer)
        val said = assertNotNull(m.saidOn(fake.snapshot), "said on the sign-in screen")
        assertEquals(WayOut.KEPT_SIGN_OUT, wayOutFor(said.result), "the kept account's sign-out is the way out")
        assertTrue(offersKeptSignOut(fake.snapshot, said.result))
        WalkPrint.draws("d3 another account's sign-in refused", listOf(said.text, UiText.ph(Placeholder.KEPT_ACCOUNT_SIGN_OUT)))
        assertEquals(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST_NOT_CONFIRMED, (said.text as UiText.Ph).placeholder, "this phone's own end, never the server's")
        assertTrue(FakeScenes.EMAIL in said.text.shown(), "the kept account named: ${said.text.shown()}")
        assertNotEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), said.text.shown(), "never \"sign in again\" beside a sign-out")
        kotlin.test.assertFalse(WalkPrint.isBare(said.text))
    }

    @Test
    fun besideAWayOutThatSignsTheKeptAccountOutTheFirstScreenNeverSaysSignInAgain() {
        val fake = lockedNotConfirmed()
        fake.signInAgain(assertNotNull(fake.snapshot.locked))
        val notice = FakeKitNotices.afterRecoveryWhileKept(fake)
        assertEquals(KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, notice.wayOut)
        val s = fake.snapshot
        // On the stand-in's road the first screen's own line for that end is gone by now (the journey took its notice);
        // the screen as the shared code may hand it with both is its own screen with that field set.
        val first = StandIns.rebuilt(assertIs<EntryScreen.FirstRun>(s.entry), "sessionNotConfirmed" to true)
        assertTrue(signOutWayOutStands(s), "the notice's way out signs the kept account out, here")
        assertEquals(WayOut.KEPT_SIGN_OUT, kitWipedWayOut(notice, null, s), "and the screen offers it")
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST).shown(), sessionNotConfirmedLine(first, signOutWayOutStands(s))?.shown())
        assertNotEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), sessionNotConfirmedLine(first, signOutWayOutStands(s))?.shown(), "never \"sign in again\" beside it")
    }

    @Test
    fun onTheLockScreenTheSameLineStandsBesideSuchAWayOut() {
        val locked = assertNotNull(lockedNotConfirmed().snapshot.locked)
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST).shown(), lockEndLine(locked, besideSignOut = true)?.shown())
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), lockEndLine(locked, besideSignOut = false)?.shown())
        // A session its server ended keeps the server's line either way: only this phone's own end has a second line.
        val byServer = assertNotNull(FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED).also { it.script.sessionEndedByServer() }.snapshot.locked)
        assertEquals(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), lockEndLine(byServer, besideSignOut = true)?.shown())
    }
}
