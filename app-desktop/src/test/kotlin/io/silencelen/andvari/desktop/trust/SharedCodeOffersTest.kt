package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** What the shared code now offers the desktop, used: a server-ended session, the devices list, the left-behind notice. */
class SharedCodeOffersTest {
    private fun model(api: FakeDesktopAppApi) = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })

    private fun source(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    // ---- a session the server ended ----

    @Test
    fun aServerEndedSessionSaysSoOnTheLockScreenAndSignInAgainOpensTheJourney() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        api.script.sessionEndedByServer()
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        m.signInAgain()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "the journey, at its first screen with the notice")

        val lock = source("AccountScreens.kt").substringAfter("internal fun LockScreen(").substringBefore("\n}\n")
        assertTrue(lock.contains("if (locked.signedOutByServer) SignedOutByServerCard(model, s, offerSignOut = false)"))
        assertTrue(lock.contains("SecretField("), "the password still opens the copy, read-only")
    }

    @Test
    fun theOpenCopyOfAServerEndedSessionIsReadOnlyAndSignInAgainLocksFirst() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        api.script.sessionEndedByServer()
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val account = assertNotNull(api.snapshot.account)
        assertTrue(account.signedOutByServer)
        assertTrue(forked(api.snapshot), "read-only: the vault page only, nothing to sync, no prompts")
        m.signInAgain()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "locked, then the journey")

        val pages = source("AccountScreens.kt").substringAfter("private fun AttentionArea(").substringBefore("\n}\n")
        assertTrue(pages.contains("if (account.signedOutByServer) {"), "its own card, not the fork's")
        val card = source("AccountScreens.kt").substringAfter("internal fun SignedOutByServerCard(").substringBefore("\n}\n")
        assertTrue(card.contains("model.signInAgain()") && card.contains("if (offerSignOut) SignOutButton(model, s)"))
    }

    @Test
    fun signInAgainDoesNothingOnAnOrdinarySession() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        m.signInAgain()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    // ---- devices ----

    @Test
    fun everyDeviceButThisOneCanBeRevokedLiveOrNot() {
        val api = FakeScenes.desktopAt(FakeScene.DEVICES)
        val m = model(api)
        if (api.snapshot.account?.devices == null) m.run({ devices.openDevices() })
        val rows = assertNotNull(api.snapshot.account?.devices).devices
        assertTrue(rows.size > 1)
        for (row in rows) assertEquals(!row.current, canRevoke(row), row.name)
        assertFalse(source("SettingsScreens.kt").contains("!row.current && row.live"), "not live is no reason to hide it")
    }

    @Test
    fun aRequireLinkStateNotKnownOffersBothAnswers() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        m.run({ devices.openDevices() })
        val screen = assertNotNull(api.snapshot.account?.devices)
        assertFalse(screen.requireLinkKnown, "the server serves no read of it")
        assertEquals(listOf(true, false), requireLinkChoices(screen))
        var answer: Any? = null
        m.run({ devices.setRequireLink(true, FakeScenes.PASSWORD) }) { answer = it }
        assertTrue(answer.toString() == "DONE", "set: $answer")
        val set = assertNotNull(api.snapshot.account?.devices)
        assertTrue(set.requireLinkKnown && set.requireLink)
        assertEquals(listOf(false), requireLinkChoices(set), "known: the one answer that changes it")
        val section = source("SettingsScreens.kt").substringAfter("internal fun DevicesSection(").substringBefore("\n}\n")
        assertTrue(section.contains("Say(requireLinkState(screen))"))
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_NOT_KNOWN, requireLinkState(screen))
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_IS_ON, requireLinkState(set))
    }

    // ---- a write whose screen left ----

    /**
     * A write whose screen has left now ends as the vault's notice (core's `ContentState.notice`): the desktop's writes
     * run in their screen's own coroutine scope, so leaving the screen is what core sees, and the list (the screen the
     * person lands on) shows the notice with a way to dismiss it.
     */
    @Test
    fun aWriteWhoseScreenLeftIsSaidOnTheNextScreen() {
        val items = source("VaultItemsScreens.kt")
        // The screen's own scope is its composition's, wrapped so a lock overtaking the work is said (rememberWorkScope).
        val editor = items.substringAfter("val scope = rememberWorkScope()", "").let { it.isNotEmpty() }
        assertTrue(editor)
        val save = items.substringBefore("\"login\" -> c.saveLogin(").substringAfterLast("val scope = ")
        assertTrue(save.startsWith("rememberWorkScope()"), "the editor's save runs in the editor's scope")
        val work = source("Overtaken.kt").substringAfter("internal fun rememberWorkScope(").substringBefore("\n}\n")
        assertTrue(work.contains("rememberCoroutineScope()"), "which is the composition's own, cancelled when the screen leaves")
        val list = items.substringAfter("private fun VaultItemsList(").substringBefore("\n}\n")
        val said = items.substringAfter("internal fun ContentSaid(").substringBefore("\n}\n")
        assertTrue(list.contains("ContentSaid(c, state)") && said.contains("state.notice?.let {") && said.contains("c.dismissNotice()"))
    }
}
