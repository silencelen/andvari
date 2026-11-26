package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeMoveNote
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** A move's notes in the fake go with the account's session, also a session this device never kept. */
class FakeMoveNotesTest {
    /**
     * A session that was never kept (the account signed in with nothing stored here) takes its account's notes with it when
     * it ends. Before: only a kept session's account lost its notes, and these stayed in the fake.
     */
    @Test
    fun anAccountsNotesGoWithItsSessionAlsoWhereNothingWasKept() {
        val app = FakeScenes.at(FakeScene.DELETION)
        val s = assertNotNull(app.session)
        val key = s.server.origin + "|" + s.account.userId
        app.moveNotesKept[key] = mutableListOf(FakeMoveNote("old", "new", listOf(CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL to listOf(null)), null))
        app.storedSession = null
        app.script.anotherAccountKnownAtServer = true
        assertEquals(DeletionResult.DONE, await { app.settings.deleteAccount(assertNotNull(app.account.deletion), ADA, PW, null) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertTrue(app.moveNotesKept[key].isNullOrEmpty(), "the notes went with the session")
    }
}
