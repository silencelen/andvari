package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.InMemoryVaultCache
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** "Keep me signed in" and the files under an open vault. */
class KeepSignInTest {
    /** The switch as a test sees it: what it holds, and the phase each change found. */
    private class Switch(var on: Boolean = false, var keptFor: String? = null) {
        val phasesAtChange = ArrayList<AppPhase>()
        var api: FakeDesktopAppApi? = null

        val keeping = object : SignInKeeping {
            override val on: Boolean get() = this@Switch.on
            override val keptFor: String? get() = this@Switch.keptFor

            override fun set(on: Boolean, account: String?) {
                api?.let { phasesAtChange += it.snapshot.phase }
                this@Switch.on = on
                this@Switch.keptFor = account
            }

            override fun foreign(on: Boolean) {
                this@Switch.foreign = on
            }
        }

        var foreign = false
    }

    private fun unlocked(sw: Switch, before: (FakeDesktopAppApi) -> Unit = {}): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        before(api)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, sw.keeping)
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        sw.api = api
        return api to m
    }

    /**
     * The shared code now carries an open vault into memory itself (`atRestConsentChanged`), so the predecessor's
     * workaround (send what waits, else refuse; then lock) is gone: the switch goes off at once and the vault stays open.
     */
    @Test
    fun switchingOffUnderAnOpenVaultLeavesItOpen() {
        val sw = Switch()
        val (api, m) = unlocked(sw)
        m.setKeepSignIn(true)
        assertTrue(sw.on)
        assertEquals(assertNotNull(api.snapshot.account).accountId, sw.keptFor, "it belongs to the account on show")
        m.setKeepSignIn(false)
        assertFalse(sw.on)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "no lock: core goes on from memory")
        assertNotNull(m.content.value)
        assertNull(m.saidOn(api.snapshot), "nothing to say")
    }

    /** Seen in the run: core composing the vault again is not an unlock, so the page on show (Settings) stays. */
    @Test
    fun onlyAnUnlockCountsAsOneNotTheVaultComposedAgain() {
        val sw = Switch()
        val (api, m) = unlocked(sw)
        val first = m.unlocks.value
        assertEquals(1, first)
        m.onSnapshot(api.snapshot)
        m.onSnapshot(api.snapshot)
        assertEquals(first, m.unlocks.value, "snapshots of the open vault are not unlocks")
        m.lockNow()
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(first + 1, m.unlocks.value)
    }

    @Test
    fun withAChangeWaitingTheSwitchGoesOffAndTheChangeStaysQueued() {
        val sw = Switch(on = true)
        val (api, m) = unlocked(sw)
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        fake.setOffline(true)
        val personal = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal })
        assertEquals(ActionResult.Ok, runBlocking { c.saveNote(null, NoteInput("Wifi", "the code", false), personal.vaultId) })
        val waiting = c.state.queued
        assertTrue(waiting > 0)
        m.setKeepSignIn(false)
        assertFalse(sw.on, "off at once, though a change waits")
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertEquals(waiting, assertNotNull(m.content.value).state.queued, "what waited still waits")
    }

    /** Core is told before any file goes: when it is told the switch reads as off and every file is still there. */
    @Test
    fun theHomeTellsCoreAfterTheSwitchReadsOffAndBeforeAnyFileIsDeleted() {
        val root = home()
        val h = DesktopHome(root, TestKeyStore(), log = {})
        h.setKeepSignIn(true, "acct-1")
        h.secureFile.replace("""{"session":"x"}""")
        val record = h.content.storage.record("kept-abc")
        assertTrue(record.write(byteArrayOf(4, 2)))
        File(h.cacheDir, "vault-abc.db").apply { parentFile.mkdirs(); writeText("rows") }
        var seen: List<Boolean>? = null
        h.consentWithdrawn = {
            seen = listOf(
                h.keepsAtRest(),
                File(root, "v2/secure-state.json").exists(),
                File(root, "v2/vault-cache/vault-abc.db").exists(),
                File(root, "v2/content/kept-abc").exists(),
            )
            assertTrue(byteArrayOf(4, 2).contentEquals(record.read()), "what the content kept reads the same from memory")
        }
        h.setKeepSignIn(false)
        assertEquals(listOf(false, true, true, true), seen, "off, and nothing deleted yet")
        assertFalse(File(root, "v2/secure-state.json").exists())
        assertFalse(File(root, "v2/vault-cache/vault-abc.db").exists())
        assertFalse(File(root, "v2/content/kept-abc").exists())
        assertTrue(byteArrayOf(4, 2).contentEquals(record.read()), "and it is still in memory after")

        val seam = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustSeam.kt").readText()
        assertTrue(seam.contains("keepsAtRest = home::keepsAtRest"), "the engine reads the switch as its consent")
        assertTrue(seam.contains("home.consentWithdrawn = api::atRestConsentChanged"))
    }

    /**
     * The switch to the server of an invitation signs this account out here, as Sign out does, so it is a person's own
     * end too: "keep me signed in" goes off with it. Before, only Sign out reset it, and after a switch the setting
     * stayed on for an account no longer signed in here.
     */
    @Test
    fun switchingToAnotherServerResetsTheSwitchAsASignOutDoes() {
        val sw = Switch(on = true)
        val (api, m) = unlocked(sw)
        assertEquals(assertNotNull(api.snapshot.account).accountId, sw.keptFor)
        val other = api.script.addServer("https://family.example", "Family", io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER)
        m.run({ links.openInvite(api.script.invitation(other, "Bo"), io.silencelen.andvari.core.app.PayloadSource.PASTED) })
        val opened = assertIs<io.silencelen.andvari.core.app.OpenedInvite.OtherInstance>(assertNotNull(api.snapshot.account).opened)
        var answer: io.silencelen.andvari.core.app.ServerResult? = null
        m.switchInstance(opened, null) { answer = it }
        m.onSnapshot(api.snapshot)
        assertEquals(io.silencelen.andvari.core.app.ServerResult.DONE, answer)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertFalse(sw.on, "the switch signed this account out here: the setting goes with it")
        assertFalse(m.keepSignIn.value)
    }

    @Test
    fun signingOutResetsTheSwitchAndAnotherAccountNeverInheritsIt() {
        val sw = Switch(on = true)
        val (api, m) = unlocked(sw)
        assertEquals(assertNotNull(api.snapshot.account).accountId, sw.keptFor, "a switch from before is bound at the first unlock")
        m.signOut()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertFalse(sw.on, "a completed sign-out resets it")

        // Another account never inherits it, and its opening deletes nothing of the kept one:
        // the switch stays the kept account's, and this one is held in memory (SecondLookTest has the files).
        val other = Switch(on = true, keptFor = "an-account-that-is-not-this-one")
        val (api2, m2) = unlocked(other)
        assertTrue(other.foreign, "this account is held in memory")
        assertFalse(m2.keepSignIn.value, "the switch reads off for it")
        assertTrue(other.on, "and is not switched off for the kept one")
        assertEquals("an-account-that-is-not-this-one", other.keptFor)
        assertEquals(AppPhase.UNLOCKED, api2.snapshot.phase)
    }

    @Test
    fun aPolicyThatForbidsAnOfflineCopyWinsOverTheSwitch() {
        val sw = Switch(on = true)
        val (api, m) = unlocked(sw) { it.script.publicInstance.offlineCacheAllowed = false }
        assertTrue(m.keepForbidden(api.snapshot))
        assertFalse(sw.on, "switched off by the policy")
        m.setKeepSignIn(true)
        assertFalse(sw.on, "and it cannot be switched on")
        val tick = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText().substringAfter("fun KeepSignInTick(").substringBefore("\n}\n")
        assertTrue(tick.contains("(keep || !forbidden)"))
    }

    // ---- the files ----

    private fun home(): File = Files.createTempDirectory("andvari-keep").toFile().also { it.deleteOnExit() }

    private fun plant(root: File, prefs: String?) {
        val v2 = File(root, DesktopHome.NEW_DIR).also { it.mkdirs() }
        if (prefs != null) File(v2, "desktop-prefs.json").writeText(prefs)
        File(v2, "secure-state.json").writeText("""{"kept":"tokens"}""")
        File(v2, "vault-cache").mkdirs()
        File(v2, "vault-cache/vault-abc.db").writeText("rows")
        File(v2, "content").mkdirs()
        File(v2, "content/kept-record").writeText("sealed")
    }

    @Test
    fun aSettingsFileThatCannotBeReadIsUnknownAndNothingKeptIsReadOrDeleted() {
        val root = home()
        plant(root, "{ this is not json")
        val h = DesktopHome(root)
        assertEquals(Keep.UNKNOWN, h.keepAtStart)
        assertNull(h.secureFile.read(), "not read")
        assertTrue(File(root, "v2/secure-state.json").exists(), "not deleted")
        assertIs<InMemoryVaultCache>(h.cacheFiles.open("vault-abc.db", "u1"))
        assertTrue(File(root, "v2/vault-cache/vault-abc.db").exists())
        assertTrue(File(root, "v2/content/kept-record").exists())
        h.secureFile.replace("""{"new":"run"}""")
        assertEquals("""{"kept":"tokens"}""", File(root, "v2/secure-state.json").readText(), "nothing written over it meanwhile")
        assertTrue(HomeSignInKeeping(h).unknown)

        // The person answers: the unreadable file is kept aside, the answer written.
        h.answerUnreadablePrefs(false)
        assertEquals(Keep.OFF, h.prefs.keep())
        assertEquals(1, File(root, "v2").listFiles()!!.count { it.name.startsWith("desktop-prefs.json.unreadable-") })
        assertFalse(File(root, "v2/secure-state.json").exists(), "the person's answer deletes what was kept")
    }

    @Test
    fun atAStartWithTheSwitchOffTheFilesOfAKeptSignInGoUnread() {
        val root = home()
        plant(root, """{"keepSignIn":false}""")
        val h = DesktopHome(root)
        assertEquals(Keep.OFF, h.keepAtStart)
        assertFalse(File(root, "v2/secure-state.json").exists())
        assertFalse(File(root, "v2/vault-cache/vault-abc.db").exists(), "a cache file Windows held at the switch-off goes now")
        assertFalse(File(root, "v2/content").exists())
    }

    @Test
    fun theSwitchIsKeptWithItsAccount() {
        val root = home()
        val h = DesktopHome(root)
        assertEquals(Keep.OFF, h.keepAtStart, "no file: off")
        h.setKeepSignIn(true, "acct-1")
        assertEquals(Keep.ON, h.prefs.keep())
        assertEquals("acct-1", h.prefs.keptFor)
        h.setKeepSignIn(false, "acct-1")
        assertNull(h.prefs.keptFor, "off belongs to nobody")
    }
}
