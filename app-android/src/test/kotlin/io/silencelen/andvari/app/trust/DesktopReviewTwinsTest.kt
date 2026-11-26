package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Three rules the desktop has, on Android: "update required" is a notice, never a
 * wall; "Forget this server" always asks; and "Open the site" refuses an address with a user name
 * or password before the host). Each was real on Android; each test fails on the old code.
 */
class DesktopReviewTwinsTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun unlocked(): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    @Test
    fun updateRequiredIsANoticeAboveAVaultThatStaysOpen() {
        val (api, m) = unlocked()
        // The server is newer than this build: its answers say "update required", and core keeps that for it.
        val server = assertNotNull(api.script.server(assertNotNull(api.snapshot.instance).label.origin))
        server.tooNewForThisBuild = true
        m.run({ vaults.createVault("Trips") })
        assertEquals(VaultActionResult.UPDATE_REQUIRED, m.said.value?.result)
        assertTrue(assertNotNull(api.snapshot.instance).updateRequired, "core keeps it for the session's server")
        assertTrue(m.updateNoticeOn(api.snapshot), "the notice is on for this server")
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the vault stays open")
        assertNotNull(m.content.value, "and readable from the copy")
        // While it stands the copy is read-only, and the notice says so. The engine recomposes
        // the content with serverStopped (l2b-13); the fake does not yet, so its stopped content stands in for it.
        assertTrue(Placeholder.UPDATE_REQUIRED.gloss.contains("read-only"), "the notice says the copy is read-only")
        assertNotNull(api.fakeContent).stopServer()
        val stopped = assertNotNull(m.content.value).state
        assertTrue(stopped.serverStopped)
        assertFalse(canSave(stopped), "no screen offers a save on a read-only copy")
        // A later answer from that server that is not "update required" clears it.
        server.tooNewForThisBuild = false
        m.run({ vaults.createVault("Trips") })
        assertFalse(m.updateNoticeOn(api.snapshot))
        assertFalse(assertNotNull(api.snapshot.instance).updateRequired)
        // The app no longer keeps its own copy of the state: the notice follows core's.
        val model = src("TrustModel.kt")
        assertTrue(model.contains("s.instance?.updateRequired == true"))
        assertFalse(model.contains("updateFlow"))

        val app = src("TrustApp.kt")
        assertFalse(app.contains("UpdateWall"), "no wall replaces the screens")
        assertTrue(app.contains("if (model.updateNoticeOn(s)) UpdateNotice()"))
        val notice = app.substringAfter("private fun UpdateNotice()").substringBefore("\n}\n")
        assertFalse(notice.contains("SignOutButton") || notice.contains("ForgetServerButton"), "its exits never delete the copy")
    }

    @Test
    fun forgetThisServerAsksFirstOnEveryCardThatOffersIt() {
        val all = File("src/main/kotlin/io/silencelen/andvari/app/trust").listFiles()!!.filter { it.name.endsWith(".kt") }.joinToString("\n") { it.readText() }
        // The one place that forgets is the confirm of the question the button opens.
        assertEquals(1, Regex("""\.forgetServer\(instance\)""").findAll(all).count())
        val button = src("EntryScreens.kt").substringAfter("internal fun ForgetServerButton(").substringBefore("internal fun AskFirst(")
        assertTrue(button.contains("AskFirst(s, UiText.of(CopyKey.FORGET_THIS_SERVER)"))
        val ask = src("EntryScreens.kt").substringAfter("internal fun AskFirst(").substringBefore("\n}\n")
        assertTrue(ask.contains("{ asking = true }"), "the button only opens the question")
        assertTrue(ask.contains("confirmButton = { androidx.compose.material3.TextButton(onClick = { asking = false; act() })"))
        // Forgetting the server at the new address asks too.
        val moved = src("EntryScreens.kt").substringAfter("if (card.alreadyPinnedThere) {").substringBefore("} else {")
        assertTrue(moved.contains("AskFirst(s, UiText.ph(Placeholder.FORGET_OTHER_SERVER)"))
        assertEquals(1, Regex("""forgetServerAtNewAddress\(""").findAll(all).count())
        // Settings uses the same button.
        assertTrue(src("AccountScreens.kt").contains("ForgetServerButton(model, s, instance, quiet = true)"))
    }

    @Test
    fun openTheSiteRefusesAnAddressWithAUserNameOrPasswordBeforeTheHost() {
        for (bad in listOf(
            "https://bank.example@evil.example",
            "https://user:pw@bank.example/login",
            "bank.example@evil.example",
            "http://a@b",
        )) {
            assertTrue(carriesUserInfo(bad), bad)
            assertNull(webAddress(bad), bad)
        }
        // A backslash is read as a slash by browsers: not taken at all.
        assertNull(webAddress("https://bank.example\\@evil.example"))
        // An @ after the host (in the path, the query or the fragment) is not a user name.
        assertEquals("https://bank.example/@me", webAddress("https://bank.example/@me"))
        assertFalse(carriesUserInfo("https://bank.example/login?u=a@b"))
        assertEquals("https://bank.example", webAddress("bank.example"))
        // The screen says why instead of offering the button.
        val panel = src("VaultHealthScreens.kt")
        assertTrue(panel.contains("if (carriesUserInfo(site)) {") && panel.contains("Placeholder.OPEN_SITE_REFUSED"))
    }
}
