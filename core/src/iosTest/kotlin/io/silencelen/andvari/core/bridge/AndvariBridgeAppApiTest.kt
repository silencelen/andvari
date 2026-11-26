package io.silencelen.andvari.core.bridge

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/** What the iOS bridge hands Swift for IF-3. The flows themselves are walked in commonTest, which runs on iOS too. */
class AndvariBridgeAppApiTest {
    @Test
    fun theBridgeHandsOutAFreshPhoneFakeAtTheScene() {
        // Tests are debug binaries, so the fake is there; a release framework answers nil.
        val app: AppApi = assertNotNull(AndvariBridge.fakeApp(FakeScene.FIRST_RUN))
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        val first = assertIs<EntryScreen.FirstRun>(app.snapshot.entry)
        assertFalse(first.takesSetupLinks, "a phone takes no setup link")
        assertFalse(app is DesktopAppApi, "and it has no operator views")

        val signedIn = assertNotNull(AndvariBridge.fakeApp(FakeScene.VAULTS))
        assertEquals(AppPhase.UNLOCKED, signedIn.snapshot.phase)
        assertNotNull(signedIn.snapshot.account)
        assertFalse(signedIn === AndvariBridge.fakeApp(FakeScene.VAULTS), "every call gives a fresh one")
    }
}
