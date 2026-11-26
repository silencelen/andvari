package io.silencelen.andvari.desktop.trust

import com.sun.jna.Native
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** A key store in memory: a key per handle, and a switch that makes every call refuse (a store that errors). */
internal class TestKeyStore(override val kind: KeyStoreKind = KeyStoreKind.SECRET_SERVICE) : OsKeyStore {
    val keys = HashMap<String, ByteArray>()
    var refuse = false
    var keeps = 0

    override fun keep(key: ByteArray): ByteArray {
        if (refuse) throw KeyStoreUnavailable("refused")
        keeps++
        val h = "h$keeps"
        keys[h] = key.copyOf()
        return h.encodeToByteArray()
    }

    override fun recall(handle: ByteArray): ByteArray {
        if (refuse) throw KeyStoreUnavailable("refused")
        return keys[handle.decodeToString()]?.copyOf() ?: throw KeyStoreUnavailable("no such key")
    }

    override fun forget(handle: ByteArray) {
        keys.remove(handle.decodeToString())
    }
}

/** The kept session under the operating system's key store. */
class KeptSessionTest {
    private val session = """{"session":"access-token-123 refresh-token-456"}"""

    private fun tmp(): File = Files.createTempDirectory("andvari-wrap").toFile().also { it.deleteOnExit() }

    private fun secure(root: File) = File(root, "v2/secure-state.json")

    private fun keptHome(root: File, store: OsKeyStore): DesktopHome = DesktopHome(root, store, log = {}).also { it.setKeepSignIn(true, "acct-1") }

    @Test
    fun keptTheSessionIsWrappedOwnerOnlyAndARestartOpensIt() {
        val root = tmp()
        val store = TestKeyStore()
        val h = keptHome(root, store)
        assertTrue(h.secureFile.keyStoreReady())
        h.secureFile.replace(session)
        val onDisk = secure(root).readText()
        assertFalse(onDisk.contains("access-token-123"), "the tokens are not on disk as text")
        assertTrue(SessionWrap.isWrapped(onDisk))
        assertEquals(KeptForm.WRAPPED, h.secureFile.form)
        if (posix(root)) assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(secure(root).toPath())), "still owner-only")
        assertEquals(1, store.keeps, "one key for the file")

        val again = DesktopHome(root, store, log = {})
        assertEquals(session, again.secureFile.read(), "a restart opens it")
        assertEquals(KeptForm.WRAPPED, again.secureFile.form)
        again.secureFile.replace("""{"session":"rotated"}""")
        assertEquals(1, store.keeps, "a later write reuses the file's key")
        assertEquals("""{"session":"rotated"}""", DesktopHome(root, store, log = {}).secureFile.read())
    }

    @Test
    fun withNoKeyStoreNothingIsWrittenUntilThePersonChoosesAFile() {
        val root = tmp()
        val h = keptHome(root, NoKeyStore)
        assertFalse(h.secureFile.keyStoreReady())
        h.secureFile.replace(session)
        assertFalse(secure(root).exists(), "no silent fallback to a plain file")
        assertTrue(h.secureFile.choiceNeeded, "the person is asked")
        assertEquals(session, h.secureFile.read(), "the run holds it in memory")

        h.setKeepSignIn(true, "acct-1", plainFile = true)
        assertEquals(session, secure(root).readText(), "the person chose a file only their account can read")
        assertEquals(KeptForm.PLAIN, h.secureFile.form)
        assertFalse(h.secureFile.choiceNeeded)
        if (posix(root)) assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(secure(root).toPath())))
        assertEquals(session, DesktopHome(root, NoKeyStore, log = {}).secureFile.read(), "and a restart reads it")

        h.setKeepSignIn(false)
        assertFalse(h.prefs.plainFile, "the choice goes with the switch")
    }

    @Test
    fun aKeyStoreThatRefusesIsNoKeyStore() {
        val root = tmp()
        val store = TestKeyStore().apply { refuse = true }
        val h = keptHome(root, store)
        h.secureFile.replace(session)
        assertFalse(secure(root).exists())
        assertTrue(h.secureFile.choiceNeeded)
        // The store answers again: the next write is wrapped, and the question goes.
        store.refuse = false
        h.secureFile.replace(session)
        assertTrue(SessionWrap.isWrapped(secure(root).readText()))
        assertFalse(h.secureFile.choiceNeeded)
    }

    @Test
    fun aWrappedFileThatCannotBeOpenedIsUnknownAndNothingIsDeletedUnread() {
        val root = tmp()
        keptHome(root, TestKeyStore()).secureFile.replace(session)
        val bytes = secure(root).readBytes()

        // Another key store (its keys lost): the file cannot be opened.
        val other = TestKeyStore()
        val h = DesktopHome(root, other, log = {})
        assertNull(h.secureFile.read(), "no session from it")
        assertEquals(KeptForm.UNOPENABLE, h.secureFile.form)
        assertContentEquals(bytes, secure(root).readBytes(), "left as it is")
        assertTrue(HomeSignInKeeping(h).keptUnopenable, "the person is asked to sign in again")

        // The new sign-in is kept: the old file goes aside under a new name, unread, before anything takes its place.
        h.secureFile.replace("""{"session":"new"}""")
        val aside = File(root, "v2").listFiles()!!.single { it.name.startsWith("secure-state.json.unreadable-") }
        assertContentEquals(bytes, aside.readBytes())
        assertEquals("""{"session":"new"}""", DesktopHome(root, other, log = {}).secureFile.read())
        assertFalse(HomeSignInKeeping(h).keptUnopenable)
    }

    @Test
    fun aFileOfAnotherStoreOrWithABrokenSealDoesNotOpen() {
        val root = tmp()
        val store = TestKeyStore(KeyStoreKind.WINDOWS_DPAPI)
        keptHome(root, store).secureFile.replace(session)
        val wrapped = secure(root).readText()
        assertFailsWith<WrapUnopenable> { SessionWrap.open(wrapped, TestKeyStore(KeyStoreKind.SECRET_SERVICE).also { it.keys.putAll(store.keys) }) }
        val sealed = wrapped.substringAfter("\"sealed\":\"").substringBefore("\"")
        val flipped = (if (sealed.first() == 'A') "B" else "A") + sealed.drop(1)
        assertFailsWith<WrapUnopenable> { SessionWrap.open(wrapped.replace(sealed, flipped), store) }
        // A handle pointed elsewhere: the store has no such key, or the seal (which binds the handle) does not hold.
        kotlin.test.assertFails { SessionWrap.open(wrapped.replace("\"handle\":\"", "\"handle\":\"x"), store) }
        assertEquals(session, SessionWrap.open(wrapped, store).plain)
    }

    @Test
    fun aSessionAnEarlierBuildKeptUnwrappedIsWrappedOnceRead() {
        val root = tmp()
        plantEarlierBuild(root)
        val store = TestKeyStore()
        val h = DesktopHome(root, store, log = {})
        assertEquals(session, h.secureFile.read(), "read first")
        assertTrue(SessionWrap.isWrapped(secure(root).readText()), "then wrapped")
        assertFalse(secure(root).readText().contains("access-token-123"))
        assertEquals(session, DesktopHome(root, store, log = {}).secureFile.read())
    }

    @Test
    fun anEarlierBuildsFileWithNoKeyStoreIsUsedLeftAsItIsAndThePersonIsAsked() {
        val root = tmp()
        plantEarlierBuild(root)
        val h = DesktopHome(root, NoKeyStore, log = {})
        assertEquals(session, h.secureFile.read())
        assertEquals(session, secure(root).readText(), "not deleted, not changed")
        assertTrue(h.secureFile.choiceNeeded)
        h.secureFile.replace("""{"session":"rotated"}""")
        assertEquals(session, secure(root).readText(), "nothing new written unwrapped before the answer")
        HomeSignInKeeping(h).keepInPlainFile("acct-1")
        assertEquals("""{"session":"rotated"}""", secure(root).readText())
        assertFalse(h.secureFile.choiceNeeded)
    }

    @Test
    fun switchingOffDeletesTheFileAndItsKey() {
        val root = tmp()
        val store = TestKeyStore()
        val h = keptHome(root, store)
        h.secureFile.replace(session)
        assertEquals(1, store.keys.size)
        h.setKeepSignIn(false)
        assertFalse(secure(root).exists())
        assertTrue(store.keys.isEmpty(), "the key store's item goes too")
    }

    @Test
    fun theSwitchAsksWhenThereIsNoKeyStoreAndTheAnswerDecides() {
        class Keeping(var ready: Boolean) : SignInKeeping {
            var state = false
            var plain = false
            override val on: Boolean get() = state
            override fun set(on: Boolean, account: String?) {
                state = on
                if (!on) plain = false
            }
            override fun keyStoreReady(): Boolean = ready
            override fun keepInPlainFile(account: String?) {
                state = true
                plain = true
            }
        }
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val k = Keeping(ready = false)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, k)
        m.onSnapshot(api.snapshot)
        m.setKeepSignIn(true)
        assertFalse(k.on, "not switched on silently")
        assertTrue(m.noKeyStoreQuestion.value, "asked")
        m.answerNoKeyStore(false)
        assertFalse(k.on)
        assertFalse(m.noKeyStoreQuestion.value)

        m.setKeepSignIn(true)
        m.answerNoKeyStore(true)
        assertTrue(k.on && k.plain, "kept in a file only the account can read, as chosen")
        assertTrue(m.keepSignIn.value)
        assertFalse(m.noKeyStoreQuestion.value)

        val ready = Keeping(ready = true)
        val m2 = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, ready)
        m2.setKeepSignIn(true)
        assertTrue(ready.on && !ready.plain, "with a key store nothing is asked")
        assertFalse(m2.noKeyStoreQuestion.value)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
    }

    // ---- the platform calls ----

    @Test
    fun eachComputerGetsItsStore() {
        assertSame(WindowsDataProtection, OsKeyStores.forThisComputer("Windows 11"))
        assertSame(NoKeyStore, OsKeyStores.forThisComputer("Mac OS X"))
        assertFailsWith<KeyStoreUnavailable> { NoKeyStore.keep(ByteArray(32)) }
    }

    @Test
    fun theSecretServiceSchemaHasLibsecretsLayout() {
        if (Native.POINTER_SIZE != 8) return
        // const gchar *name; flags; SecretSchemaAttribute attributes[32] (16 bytes each); gint reserved; 7 pointers.
        assertEquals(592, SecretServiceKeyStore.SecretSchema().size())
    }

    /**
     * The real Linux store on this computer: it either keeps and gives back a key, or refuses with
     * [KeyStoreUnavailable] (this build machine has libsecret but no secret service). Never anything else.
     */
    @Test
    fun theRealLinuxStoreKeepsOrRefusesCleanly() {
        if (!System.getProperty("os.name").orEmpty().lowercase().contains("linux")) return
        val store = OsKeyStores.forThisComputer()
        val key = SessionWrap.newKey()
        val handle = try {
            store.keep(key)
        } catch (e: KeyStoreUnavailable) {
            println("this computer's key store (${store.kind.id}) refused: ${e.message}")
            return
        }
        try {
            assertContentEquals(key, store.recall(handle))
        } finally {
            store.forget(handle)
        }
        assertFailsWith<KeyStoreUnavailable> { store.recall(handle) }
    }

    private fun plantEarlierBuild(root: File) {
        val v2 = File(root, DesktopHome.NEW_DIR).also { it.mkdirs() }
        File(v2, "desktop-prefs.json").writeText("""{"keepSignIn":true,"keptFor":"acct-1"}""")
        File(v2, "secure-state.json").writeText(session)
    }
}
