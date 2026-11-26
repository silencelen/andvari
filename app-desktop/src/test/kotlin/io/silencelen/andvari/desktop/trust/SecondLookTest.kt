package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Only the person's own completed act deletes the kept sign-in, the vault's copy and the changes waiting to be sent:
 * the paths the first fix did not pin.
 */
class SecondLookTest {
    private val waiting = byteArrayOf(7)

    private fun tmp(): File = Files.createTempDirectory("andvari-look").toFile().also { it.deleteOnExit() }

    /** An earlier run kept an account's sign-in, its vault's copy and a change waiting; the switch is [keptFor]'s. */
    private fun earlierRun(root: File, store: OsKeyStore, keptFor: String, session: String = """{"session":"kept"}""") {
        val h = DesktopHome(root, store, log = {}, keyStorePause = {})
        h.setKeepSignIn(true, keptFor)
        h.secureFile.replace(session)
        File(h.cacheDir, "vault-abc.db").apply { parentFile.mkdirs(); writeText("rows") }
        assertTrue(h.content.storage.record("kept-waiting").write(waiting))
    }

    private fun assertAllThere(root: File, store: TestKeyStore, where: String) {
        assertTrue(File(root, "v2/secure-state.json").exists(), "$where: the kept sign-in")
        assertEquals(1, store.keys.size, "$where: its key-store item")
        assertTrue(File(root, "v2/vault-cache/vault-abc.db").exists(), "$where: the vault's copy")
        assertTrue(File(root, "v2/content/kept-waiting").exists(), "$where: what waits to be sent")
    }

    private fun model(home: DesktopHome, before: (FakeDesktopAppApi) -> Unit = {}): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        before(api)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home))
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /**
     * The kept account could not be opened (its keyring locked, say), so core let another account in. Opening it, and
     * signing it out, delete nothing of the kept one, and it inherits nothing.
     */
    @Test
    fun anotherAccountOpenWhileTheKeptOneCouldNotBeOpenedDeletesNothing() {
        val root = tmp()
        val store = TestKeyStore()
        earlierRun(root, store, keptFor = "the-kept-account")
        val home = DesktopHome(root, store, log = {}, keyStorePause = {})
        assertEquals("""{"session":"kept"}""", home.secureFile.read())
        val (api, m) = model(home)
        assertAllThere(root, store, "another account opened")
        assertFalse(m.keepSignIn.value, "the switch reads off for it")
        assertFalse(home.keepsAtRest(), "it is held in memory")
        assertEquals(Keep.ON, home.prefs.keep(), "the switch is still the kept account's")
        assertEquals("the-kept-account", home.prefs.keptFor)
        val said = assertIs<UiText.Ph>(assertNotNull(m.said.value).text)
        assertEquals(Placeholder.KEEP_BELONGS_TO_ANOTHER, said.placeholder)

        // What the engine writes for it is not written over the kept file.
        val kept = File(root, "v2/secure-state.json").readBytes()
        home.secureFile.replace("""{"session":"the other account's"}""")
        assertContentEquals(kept, File(root, "v2/secure-state.json").readBytes())

        m.signOut()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        assertAllThere(root, store, "the other account signed out")
        assertTrue(m.keepSignIn.value, "the switch is the kept account's again")
        assertEquals(Keep.ON, home.prefs.keep())
    }

    @Test
    fun aSignInFileWrittenForTheOtherAccountGoesAndNothingOfTheKeptOne() {
        val root = tmp()
        val store = TestKeyStore()
        earlierRun(root, store, keptFor = "the-kept-account")
        // The kept file's seal does not hold: final, so the other account's sign-in set it aside and was written.
        val f = File(root, "v2/secure-state.json")
        val sealed = f.readText().substringAfter("\"sealed\":\"").substringBefore("\"")
        f.writeText(f.readText().replace(sealed, (if (sealed.first() == 'A') "B" else "A") + sealed.drop(1)))
        val home = DesktopHome(root, store, log = {}, keyStorePause = {})
        home.secureFile.read()
        home.secureFile.replace("""{"session":"the other account's"}""")
        val aside = File(root, "v2").listFiles()!!.single { it.name.startsWith("secure-state.json.unreadable-") }
        model(home)
        assertFalse(f.exists(), "the other account's sign-in is not kept: it did not opt in")
        assertTrue(aside.exists(), "the kept one's file stays aside")
        assertTrue(File(root, "v2/vault-cache/vault-abc.db").exists())
        assertTrue(File(root, "v2/content/kept-waiting").exists())
        assertEquals(1, store.keys.size, "only the kept file's own item")
    }

    /**
     * Seen in the run: no key store, a kept file that cannot be opened, another account signs in and out. Its write,
     * held for the no-key-store question, raised that question on the first screen afterwards; answering it would have
     * acted on the kept account's switch. Nobody is asked about the other account's write.
     */
    @Test
    fun theOtherAccountsWriteRaisesNoQuestionOnceItHasGone() {
        val root = tmp()
        val v2 = File(root, DesktopHome.NEW_DIR).also { it.mkdirs() }
        File(v2, "desktop-prefs.json").writeText("""{"keepSignIn":true,"keptFor":"the-kept-account","wraps":true}""")
        File(v2, "secure-state.json").writeText("""{"session":"planted"}""")
        val home = DesktopHome(root, NoKeyStore, log = {}, keyStorePause = {})
        home.secureFile.read()
        assertEquals(KeptForm.UNOPENABLE, home.secureFile.form)
        home.secureFile.replace("""{"session":"the other account's"}""")
        val (api, m) = model(home)
        m.signOut()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        assertFalse(home.secureFile.choiceNeeded)
        assertFalse(m.noKeyStoreQuestion.value, "no question about a write that was not the kept account's")
        assertEquals(Keep.ON, home.prefs.keep())
        assertTrue(File(v2, "secure-state.json").exists() || v2.listFiles()!!.any { it.name.startsWith("secure-state.json.unreadable-") }, "the kept file is still there")
    }

    /**
     * The engine reaches the first screen with its session still kept when another server is forgotten (its
     * `forgetServer` ends the journey for any server). A done act that leaves a session kept is not the end of it.
     */
    @Test
    fun anActThatLeavesTheSessionKeptSwitchesNothingOff() {
        val root = tmp()
        val store = TestKeyStore()
        val home = DesktopHome(root, store, log = {}, keyStorePause = {})
        val (api, m) = model(home)
        m.setKeepSignIn(true)
        home.secureFile.replace("""{"ovh.session":"{\"userId\":\"u\",\"origin\":\"https://vault.example\"}"}""")
        File(home.cacheDir, "vault-abc.db").apply { parentFile.mkdirs(); writeText("rows") }
        assertTrue(home.content.storage.record("kept-waiting").write(waiting))
        // The fake's sign-out reaches the first screen without touching this computer's store: a session still kept.
        m.signOut()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertAllThere(root, store, "the first screen with a session still kept")
        assertTrue(m.keepSignIn.value)
    }

    /**
     * A policy that forbids the copy: while the shared code owes its removal (one try to send what waits, the count, the
     * removal; [io.silencelen.andvari.core.app.AppSnapshot.policyWipeOwed]) the desktop deletes nothing and leaves the
     * switch as it is, whatever is on the disk; once the snapshot says the removal is done the switch goes off, what waits
     * goes on from memory in the running session, and the person is told why.
     */
    @Test
    fun aPolicyThatForbidsTheCopySwitchesOffOnlyOnceTheCopyIsGoneAndKeepsWhatWaitsInMemory() {
        val root = tmp()
        val store = TestKeyStore()
        earlierRun(root, store, keptFor = "")
        val home = DesktopHome(root, store, log = {}, keyStorePause = {})
        home.prefs.write(true, null)
        // Core reads what waits when it composes the vault at the unlock, before any policy can be read.
        assertContentEquals(waiting, home.content.storage.record("kept-waiting").read())
        val (api, m) = model(home) {
            it.script.publicInstance.offlineCacheAllowed = false
            it.script.policyForbidsCopy()
        }
        assertTrue(m.keepForbidden())
        assertTrue(api.snapshot.policyWipeOwed)
        assertTrue(m.keepSignIn.value, "not switched off while the shared code owes the removal")
        assertAllThere(root, store, "while the shared code owes the removal")
        // The disk is no longer what is read: the copy's file gone while the removal is still owed switches nothing off.
        assertTrue(home.cacheFiles.delete("vault-abc.db"))
        m.onSnapshot(api.snapshot)
        assertTrue(m.keepSignIn.value, "still owed, so still as it was")
        // The shared code's removal is done and counted: the next snapshot says so.
        api.script.policyCopyRemoved(notSent = 0)
        assertFalse(api.snapshot.policyWipeOwed)
        m.onSnapshot(api.snapshot)
        assertFalse(m.keepSignIn.value, "switched off by the policy")
        assertFalse(File(root, "v2/content/kept-waiting").exists(), "off the disk")
        assertContentEquals(waiting, home.content.storage.record("kept-waiting").read(), "but it goes on from memory")
        val said = assertIs<UiText.Ph>(assertNotNull(m.said.value).text)
        assertEquals(Placeholder.KEEP_FORBIDDEN, said.placeholder, "and the person is told why")
    }

    /**
     * The case the look at the disk got wrong: another account's copy is on this computer, and the session's own account is
     * under a forbidding policy whose removal is done. The switch follows the policy at the next snapshot, and before it
     * the person can untick it; the other account's file is not what decides either.
     */
    @Test
    fun anotherAccountsCopyOnDiskNeitherHoldsTheSwitchNorRefusesItsUntick() {
        for (untickFirst in listOf(false, true)) {
            val root = tmp()
            val store = TestKeyStore()
            earlierRun(root, store, keptFor = "")
            val home = DesktopHome(root, store, log = {}, keyStorePause = {})
            home.prefs.write(true, null)
            val (api, m) = model(home) {
                it.script.publicInstance.offlineCacheAllowed = false
                it.script.policyForbidsCopy()
            }
            assertTrue(m.keepSignIn.value, "owed: as it was")
            // Another account's copy on this computer, beside this one's.
            File(home.cacheDir, "vault-another-account.db").writeText("rows")
            // This account's removal is done and counted.
            api.script.policyCopyRemoved(notSent = 0)
            assertFalse(api.snapshot.policyWipeOwed, "the session's own account owes nothing")
            assertTrue(home.vaultFileOnDisk(), "another account's copy is on the disk")
            if (untickFirst) {
                // The person unticks before the next snapshot: taken, not refused with the removal's line.
                m.setKeepSignIn(false)
                assertFalse(m.keepSignIn.value, "unticked")
                assertFalse(home.keepsAtRest())
                m.onSnapshot(api.snapshot)
                assertFalse(m.keepSignIn.value)
            } else {
                m.onSnapshot(api.snapshot)
                assertFalse(m.keepSignIn.value, "the switch follows the policy")
                assertEquals(Placeholder.KEEP_FORBIDDEN, assertIs<UiText.Ph>(assertNotNull(m.said.value).text).placeholder)
                assertFalse(home.keepsAtRest())
            }
        }
    }
}
