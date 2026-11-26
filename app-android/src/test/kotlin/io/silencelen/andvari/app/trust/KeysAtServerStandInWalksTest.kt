package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.fillUnlockEndLine
import io.silencelen.andvari.app.autofill.fillUnlockNotice
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Walks over the stand-in with a server whose policy forbids keeping the vault on this phone, so the account's keys are
 * kept at the server and every unlock asks it: the lock screen of a session the server ended (the shared code's line for
 * that end, which claims no copy here, in place of the phone's own line for a server's end), an unlock the server did not
 * answer, an unlock that learns the session ended, an unlock the server refused, and the end's line beside a kept
 * account's sign-out. On each, the lock screen stays, nothing opens and nothing is removed, and quick unlock is not
 * offered. Each step prints what the phone draws.
 */
class KeysAtServerStandInWalksTest {
    private val pw = FakeScenes.PASSWORD

    private fun keysAtServer(): Pair<FakeAppApi, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        fake.script.publicInstance.offlineCacheAllowed = false
        fake.script.changed()
        val m = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)
        assertNotNull(fake.snapshot.locked?.keysAtServerLine, "the policy is recorded")
        return fake to m
    }

    /** An unlock as the lock screen's button runs it; its answer and what is said in place. */
    private fun TrustModel.unlockNow(password: String = pw): VaultUnlockResult {
        var r: VaultUnlockResult? = null
        runBlocking { runSaying({ unlock(assertNotNull(snapshot.locked), password) }, { unlockWords(it, api.retryAfterSeconds()) }) { r = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(r)
    }

    /** What the lock screen draws above the field: the end's line, the policy's line, and what the last try answered. */
    private fun lockLines(m: TrustModel, s: io.silencelen.andvari.core.app.AppSnapshot, locked: LockedScreen): List<UiText?> =
        listOf(lockEndLine(locked, signOutWayOutStands(s)), lockKeysAtServerLine(locked), m.saidOn(s)?.text)

    /** Nothing is open, nothing is removed, the lock screen stays and quick unlock is not offered. */
    private fun stays(fake: FakeAppApi, m: TrustModel) {
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
        assertNull(fake.snapshot.account, "nothing opened")
        assertNull(m.content.value, "no vault content")
        val locked = assertNotNull(fake.snapshot.locked, "the lock screen stays")
        assertNotNull(locked.keysAtServerLine, "the policy's line stays")
        assertFalse(locked.quickUnlock, "quick unlock is not offered")
        assertNull(m.wentWrong.value, "no general trouble line")
    }

    private val opensCopy = setOf(UiText.ph(Placeholder.SIGNED_OUT_BY_SERVER).shown(), UiText.ph(Placeholder.FILL_FROM_COPY).shown())

    @Test
    fun aSessionTheServerEndedIsSaidInTheSharedCodesLineOnTheLockScreenAndInTheFillWindowAndEveryUnlockSaysItsOwnSentence() {
        val (fake, m) = keysAtServer()
        fake.script.sessionEndedByServer()
        m.onSnapshot(fake.snapshot)
        val locked = assertNotNull(fake.snapshot.locked)
        assertTrue(locked.signedOutByServer)

        // k1. The lock screen: the shared code's line for that end, in place of the phone's own; no copy claimed.
        val drawn = lockLines(m, fake.snapshot, locked)
        WalkPrint.draws("k1 the lock screen, the server ended the session", drawn + UiText.ph(Placeholder.SIGN_IN_AGAIN))
        assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER, locked.endLine)
        assertEquals(UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER).shown(), lockEndLine(locked)?.shown(), "the shared code's line")
        assertNotEquals(UiText.ph(Placeholder.NOTICE_SIGNED_OUT_BY_SERVER).shown(), lockEndLine(locked)?.shown(), "not the phone's own line")
        assertTrue(drawn.filterNotNull().none { it.shown() in opensCopy }, "never a copy the password opens")
        assertFalse(locked.quickUnlock)

        // k2. The fill window: the end's line, then the policy's line; never "fills from the copy".
        val fill = listOf(fillUnlockEndLine(locked), fillUnlockNotice(locked))
        WalkPrint.draws("k2 the fill unlock window", fill)
        assertEquals(UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER).shown(), fillUnlockEndLine(locked)?.shown())
        assertEquals(lockKeysAtServerLine(locked)?.shown(), fillUnlockNotice(locked)?.shown())
        assertTrue(fill.filterNotNull().none { it.shown() in opensCopy })

        // k3. An unlock after the end, with the right password and a wrong one: the same sentence; nothing opens.
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, m.unlockNow())
        val said = assertNotNull(m.saidOn(fake.snapshot))
        WalkPrint.draws("k3 an unlock after the end", lockLines(m, fake.snapshot, assertNotNull(fake.snapshot.locked)))
        assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).shown(), said.text.shown())
        assertNull(wayOutFor(said.result))
        stays(fake, m)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, m.unlockNow("not the password at all 1"))
        assertEquals(said.text.shown(), m.saidOn(fake.snapshot)?.text?.shown(), "a wrong password reads the same")
        stays(fake, m)

        // k4. Beside a way out that signs this kept account out: the end's line without "sign in again".
        val beside = lockEndLine(locked, besideSignOut = true)
        WalkPrint.draws("k4 the end's line beside the kept account's sign-out", listOf(beside))
        assertEquals(UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST).shown(), beside?.shown())
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountScreens.kt").readText().contains("lockEndLine(locked, signOutWayOutStands(s))?.let {"))
    }

    @Test
    fun anUnlockTheServerDidNotAnswerSaysItsOwnSentenceAndTheLockScreenStays() {
        val (fake, m) = keysAtServer()
        fake.script.publicInstance.reachable = false
        val right = m.unlockNow()
        val drawn = lockLines(m, fake.snapshot, assertNotNull(fake.snapshot.locked))
        WalkPrint.draws("k5 an unlock the server did not answer", drawn)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, right)
        assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE).shown(), m.saidOn(fake.snapshot)?.text?.shown(), "its own sentence")
        assertNotEquals(UiText.ph(Placeholder.TROUBLE_UNREACHABLE).shown(), m.saidOn(fake.snapshot)?.text?.shown(), "not the general trouble line")
        assertNull(lockEndLine(assertNotNull(fake.snapshot.locked)), "no end: the session stands")
        stays(fake, m)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, m.unlockNow("not the password at all 1"), "a wrong password reads the same")
        stays(fake, m)
        // The server back: the same password opens.
        fake.script.publicInstance.reachable = true
        assertEquals(VaultUnlockResult.DONE, m.unlockNow())
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase)
    }

    @Test
    fun anUnlockThatLearnsTheSessionEndedAndAnUnlockTheServerRefusedEachSayTheirOwnSentence() {
        // k6. The unlock at which the end is learned (the stand-in plays the answer with forceNext; its lock screen learns
        // the end with sessionEndedByServer).
        val (fake, m) = keysAtServer()
        fake.script.forceNext(VaultUnlockResult.KEYS_AT_SERVER_ENDED)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, m.unlockNow())
        WalkPrint.draws("k6 the unlock that learns the session ended", lockLines(m, fake.snapshot, assertNotNull(fake.snapshot.locked)))
        assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).shown(), m.saidOn(fake.snapshot)?.text?.shown())
        stays(fake, m)

        // k7. An unlock the server refused.
        val (fake2, m2) = keysAtServer()
        fake2.script.forceNext(VaultUnlockResult.KEYS_AT_SERVER_REFUSED)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_REFUSED, m2.unlockNow())
        val drawn = lockLines(m2, fake2.snapshot, assertNotNull(fake2.snapshot.locked))
        WalkPrint.draws("k7 an unlock the server refused", drawn)
        assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_REFUSED).shown(), m2.saidOn(fake2.snapshot)?.text?.shown())
        assertNotEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE).shown(), m2.saidOn(fake2.snapshot)?.text?.shown(), "never \"did not answer\"")
        stays(fake2, m2)

        // k8. A wait at the keys' read: the wait, said as one.
        fake2.script.rateLimitNext(120)
        assertEquals(VaultUnlockResult.RATE_LIMITED, m2.unlockNow())
        WalkPrint.draws("k8 an unlock refused as one of too many", listOf(m2.saidOn(fake2.snapshot)?.text))
        assertTrue(assertNotNull(m2.saidOn(fake2.snapshot)).text.shown().contains("120"), "the wait is said")
        stays(fake2, m2)
    }

    @Test
    fun thePhonesOwnLineForAServersEndUnderSuchAPolicyIsGone() {
        val body = File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountScreens.kt").readText()
            .substringAfter("internal fun lockEndLine(").substringBefore("\n}\n")
        assertFalse(body.contains("keysAtServerLine"), "the shared code's endLine says that end; no branch of the phone's own for it")
    }
}
