package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An unwrapped `secure-state.json` is accepted as the kept sign-in only when the person chose the
 * plain file on this computer, or once as the earlier build's migration (recorded). Any other is "cannot be opened":
 * nothing read as a session, nothing deleted.
 */
class PlainFileAcceptedTest {
    private val session = """{"session":"access-token-123 refresh-token-456"}"""
    private val planted = """{"session":"planted by whoever could write the file"}"""

    private fun tmp(): File = Files.createTempDirectory("andvari-plain").toFile().also { it.deleteOnExit() }

    private fun secure(root: File) = File(root, "v2/secure-state.json")

    private fun assertNotOpened(root: File, store: OsKeyStore) {
        val bytes = secure(root).readBytes()
        val h = DesktopHome(root, store, log = {})
        assertNull(h.secureFile.read(), "nothing read as a session")
        assertEquals(KeptForm.UNOPENABLE, h.secureFile.form)
        assertTrue(HomeSignInKeeping(h).keptUnopenable, "the person is asked to sign in again")
        assertContentEquals(bytes, secure(root).readBytes(), "nothing deleted or changed")
    }

    /** The attack: the file was wrapped, and a plain one is put in its place. */
    @Test
    fun aPlainFileInPlaceOfTheWrappedOneIsNotRead() {
        val root = tmp()
        val store = TestKeyStore()
        DesktopHome(root, store, log = {}).also { it.setKeepSignIn(true, "acct-1") }.secureFile.replace(session)
        assertTrue(SessionWrap.isWrapped(secure(root).readText()))
        secure(root).writeText(planted)
        assertNotOpened(root, store)
    }

    @Test
    fun settingsThisBuildWroteAcceptNoPlainFileThePersonDidNotChoose() {
        val root = tmp()
        DesktopHome(root, NoKeyStore, log = {}).setKeepSignIn(true, "acct-1")
        secure(root).writeText(planted)
        assertNotOpened(root, NoKeyStore)
        assertNotOpened(root, TestKeyStore())
    }

    @Test
    fun theEarlierBuildsFileIsAcceptedOnceAsItsMigrationAndThatIsRecorded() {
        val root = tmp()
        plantEarlierBuild(root)
        val h = DesktopHome(root, NoKeyStore, log = {})
        assertEquals(session, h.secureFile.read(), "the earlier build's file is its migration")
        assertNotNull(h.prefs.migratedAt, "recorded")
        // Not answered yet and no key store: the same file opens at the next start, and only that file.
        assertEquals(session, DesktopHome(root, NoKeyStore, log = {}).secureFile.read())
        secure(root).writeText(planted)
        assertNotOpened(root, NoKeyStore)
    }

    @Test
    fun onceTheMigratedFileIsWrappedNoPlainFileIsAcceptedAgain() {
        val root = tmp()
        plantEarlierBuild(root)
        val store = TestKeyStore()
        assertEquals(session, DesktopHome(root, store, log = {}).secureFile.read())
        assertTrue(SessionWrap.isWrapped(secure(root).readText()), "wrapped at once")
        // Even the very same text, put back unwrapped, is not the migration any more.
        secure(root).writeText(session)
        assertNotOpened(root, store)
    }

    @Test
    fun theFileThePersonChoseIsStillRead() {
        val root = tmp()
        val h = DesktopHome(root, NoKeyStore, log = {})
        h.setKeepSignIn(true, "acct-1", plainFile = true)
        h.secureFile.replace(session)
        assertEquals(session, secure(root).readText())
        assertEquals(session, DesktopHome(root, NoKeyStore, log = {}).secureFile.read())
    }

    private fun plantEarlierBuild(root: File) {
        val v2 = File(root, DesktopHome.NEW_DIR).also { it.mkdirs() }
        File(v2, "desktop-prefs.json").writeText("""{"keepSignIn":true,"keptFor":"acct-1"}""")
        File(v2, "secure-state.json").writeText(session)
    }
}
