package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A key store that refuses the next [failRecalls] recalls and [failKeeps] keeps, then answers as [inner]; or always, while [down]. */
internal class FlakyKeyStore(val inner: TestKeyStore = TestKeyStore()) : OsKeyStore {
    var failRecalls = 0
    var failKeeps = 0
    var down = false
    var recalls = 0

    override val kind: KeyStoreKind get() = inner.kind

    override fun keep(key: ByteArray): ByteArray {
        if (down) throw KeyStoreUnavailable("the keyring is locked")
        if (failKeeps > 0) { failKeeps--; throw KeyStoreUnavailable("the keyring is not up yet") }
        return inner.keep(key)
    }

    override fun recall(handle: ByteArray): ByteArray {
        recalls++
        if (down) throw KeyStoreUnavailable("the keyring is locked")
        if (failRecalls > 0) { failRecalls--; throw KeyStoreUnavailable("the keyring is not up yet") }
        return inner.recall(handle)
    }

    override fun forget(handle: ByteArray) = inner.forget(handle)
}

/**
 * Files set aside as unopenable, and their key-store items, go at the person's own ends; a key
 * store that does not answer is asked again before its refusal is final, and a refusal that may pass never sets the kept
 * file aside.
 */
class SetAsideFilesTest {
    private val session = """{"session":"old tokens"}"""

    private fun tmp(): File = Files.createTempDirectory("andvari-aside").toFile().also { it.deleteOnExit() }

    private fun v2(root: File) = File(root, DesktopHome.NEW_DIR)

    private fun secure(root: File) = File(v2(root), "secure-state.json")

    private fun asides(root: File) = v2(root).listFiles().orEmpty().filter { it.name.startsWith("secure-state.json.unreadable-") }

    private fun home(root: File, store: OsKeyStore) = DesktopHome(root, store, log = {}, keyStorePause = {})

    /** A kept file whose seal no longer holds (its key item is still in [store]): unopenable for good. */
    private fun brokenSeal(root: File, store: OsKeyStore) {
        home(root, store).also { it.setKeepSignIn(true, "acct-1") }.secureFile.replace(session)
        val wrapped = secure(root).readText()
        val sealed = wrapped.substringAfter("\"sealed\":\"").substringBefore("\"")
        secure(root).writeText(wrapped.replace(sealed, (if (sealed.first() == 'A') "B" else "A") + sealed.drop(1)))
    }

    /** The path that showed it: the file is set aside by a new sign-in, then the switch goes off. */
    @Test
    fun theFileSetAsideAndItsKeyStoreItemGoWhenTheSwitchGoesOff() {
        val root = tmp()
        val store = TestKeyStore()
        brokenSeal(root, store)
        val h = home(root, store)
        assertNull(h.secureFile.read())
        h.secureFile.replace("""{"session":"new"}""")
        assertEquals(1, asides(root).size, "set aside by the new sign-in, unread")
        assertEquals(2, store.keys.size, "the aside's key item and the new file's")
        // A state file the start found damaged is set aside under the same name.
        File(v2(root), "secure-state.json.unreadable-1").writeText("not json")

        h.setKeepSignIn(false)
        assertTrue(asides(root).isEmpty(), "every set-aside session file goes with the switch")
        assertFalse(secure(root).exists())
        assertTrue(store.keys.isEmpty(), "and their key-store items")
    }

    @Test
    fun aStartWithTheSwitchOffRemovesWhatWasSetAside() {
        val root = tmp()
        val store = TestKeyStore()
        brokenSeal(root, store)
        home(root, store).secureFile.let { it.read(); it.replace("""{"session":"new"}""") }
        assertEquals(1, asides(root).size)
        // A crash between the switch's record and the deletes: the next start finds the switch off.
        File(v2(root), "desktop-prefs.json").writeText("""{"keepSignIn":false,"wraps":true}""")
        home(root, store)
        assertTrue(asides(root).isEmpty())
        assertFalse(secure(root).exists())
        assertTrue(store.keys.isEmpty())
    }

    @Test
    fun aKeyStoreThatDoesNotAnswerAtOnceIsAskedAgain() {
        val root = tmp()
        val store = FlakyKeyStore()
        home(root, store).also { it.setKeepSignIn(true, "acct-1") }.secureFile.replace(session)
        store.failRecalls = 2
        val h = home(root, store)
        assertEquals(session, h.secureFile.read(), "the third ask answered")
        assertEquals(KeptForm.WRAPPED, h.secureFile.form)
    }

    @Test
    fun aRefusalThatMayPassNeverSetsTheKeptFileAside() {
        val root = tmp()
        val store = FlakyKeyStore()
        home(root, store).also { it.setKeepSignIn(true, "acct-1") }.secureFile.replace(session)
        val bytes = secure(root).readBytes()

        // A locked keyring whose prompt was dismissed: every ask is refused.
        store.down = true
        val h = home(root, store)
        assertNull(h.secureFile.read())
        assertEquals(KeptForm.UNOPENABLE, h.secureFile.form)
        assertTrue(store.recalls > 1, "asked again before the refusal was taken")

        // The person signs in again meanwhile: the new session is held in memory; the kept file stays as it is.
        h.secureFile.replace("""{"session":"new"}""")
        assertEquals("""{"session":"new"}""", h.secureFile.read())
        assertContentEquals(bytes, secure(root).readBytes(), "not set aside, not written over")
        assertTrue(asides(root).isEmpty())

        // The keyring answers again: the kept file opens with its key and the new session takes its place.
        store.down = false
        h.secureFile.replace("""{"session":"newer"}""")
        assertTrue(asides(root).isEmpty())
        assertEquals(1, store.inner.keys.size, "the file's own key is reused")
        assertEquals("""{"session":"newer"}""", home(root, store).secureFile.read())
    }

    @Test
    fun aStoreThatAnswersButNoLongerHoldsTheKeyIsFinal() {
        val root = tmp()
        val store = FlakyKeyStore()
        home(root, store).also { it.setKeepSignIn(true, "acct-1") }.secureFile.replace(session)
        val bytes = secure(root).readBytes()
        store.inner.keys.clear()
        val h = home(root, store)
        assertNull(h.secureFile.read())
        h.secureFile.replace("""{"session":"new"}""")
        assertContentEquals(bytes, asides(root).single().readBytes(), "set aside, unread, once the store answered without the key")
        assertEquals("""{"session":"new"}""", home(root, store).secureFile.read())
    }
}
