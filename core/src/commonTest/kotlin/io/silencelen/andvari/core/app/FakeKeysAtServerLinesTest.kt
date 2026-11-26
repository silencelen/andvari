package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The stand-in plays what the engine hands under a server's policy that keeps the account's keys at the server, side by
 * side with `EngineKeysAtServerLinesTest`: the lock screen's line for the session's end, an unlock the server did not
 * answer, an unlock after the end, and the refusals at the read of the keys. Nothing opens in any of them.
 */
class FakeKeysAtServerLinesTest {
    private fun keysAtServer(): io.silencelen.andvari.core.app.fake.FakeAppApi {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.scriptServer(app.snapshot.instance!!.label.origin).offlineCacheAllowed = false
        app.lock()
        assertNotNull(app.snapshot.locked?.keysAtServerLine)
        return app
    }

    private fun io.silencelen.andvari.core.app.fake.FakeAppApi.unlockWith(password: String = PW) = await { unlock(assertNotNull(snapshot.locked), password) }

    private fun io.silencelen.andvari.core.app.fake.FakeAppApi.nothingOpen() {
        assertEquals(AppPhase.LOCKED, snapshot.phase)
        assertNull(snapshot.account)
    }

    @Test fun aSessionTheServerEndedIsSaidAsThatEndOnTheLockScreenAndAtEveryUnlock() {
        val app = keysAtServer()
        assertNull(app.snapshot.locked?.endLine)
        app.script.sessionEndedByServer()
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER, locked.endLine)
        assertEquals(CopyKey.SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST, locked.endLineBesideSignOut)
        assertNotNull(locked.keysAtServerLine)
        assertFalse(locked.quickUnlock)
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, app.unlockWith())
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, app.unlockWith("not the password at all 1"))
        app.nothingOpen()
    }

    @Test fun anUnlockTheServerDidNotAnswerHasItsOwnSentence() {
        val app = keysAtServer()
        app.scriptServer(app.snapshot.locked!!.prompt.instance.origin).reachable = false
        val right = app.unlockWith()
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, right)
        assertEquals(right, app.unlockWith("not the password at all 1"))
        assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE, right.sentence)
        assertNull(app.snapshot.locked?.endLine)
        app.nothingOpen()
        app.scriptServer(app.snapshot.locked!!.prompt.instance.origin).reachable = true
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
    }

    @Test fun theRefusalsAtTheKeysReadArePlayedAsTheEngineHandsThemOnceItsKeeperDoes() {
        val app = keysAtServer()
        app.script.rateLimitNext(120)
        assertEquals(VaultUnlockResult.RATE_LIMITED, app.unlockWith())
        assertEquals(120, app.retryAfterSeconds())
        app.nothingOpen()
        app.script.forceNext(VaultUnlockResult.KEYS_AT_SERVER_REFUSED)
        val refused = app.unlockWith()
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_REFUSED, refused)
        assertEquals(CopyKey.UNLOCK_KEYS_AT_SERVER_REFUSED, refused.sentence)
        app.nothingOpen()
    }

    @Test fun withoutSuchAPolicyTheServersEndIsAsBefore() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.lock()
        app.script.sessionEndedByServer()
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertNull(locked.keysAtServerLine)
        assertNull(locked.endLine, "the app's own line for the server's end")
        assertNull(locked.endLineBesideSignOut)
        assertEquals(VaultUnlockResult.DONE, app.unlockWith(), "the copy opens read-only, as before")
    }
}
