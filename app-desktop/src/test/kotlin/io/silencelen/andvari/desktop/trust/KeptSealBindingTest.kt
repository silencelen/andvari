package io.silencelen.andvari.desktop.trust

import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The desktop's key store: the kept sign-in's seal binds the account and the server it is
 * for (a file made for one does not open as another's), a file sealed the old way is sealed again, and the store name
 * read from a file is escaped before it reaches the log.
 */
class KeptSealBindingTest {
    private fun tmp(): File = Files.createTempDirectory("andvari-bind").toFile().also { it.deleteOnExit() }

    private fun secure(root: File) = File(root, "v2/secure-state.json")

    private fun sessionFor(account: String, origin: String): String =
        Json.encodeToString(
            MapSerializer(String.serializer(), String.serializer()),
            mapOf("ovh.session" to """{"origin":"$origin","userId":"$account","accessToken":"token-of-$account"}"""),
        )

    private fun keptAs(root: File, store: OsKeyStore, account: String, origin: String) {
        DesktopHome(root, store, log = {}, keyStorePause = {}).also { it.setKeepSignIn(true, account) }.secureFile.replace(sessionFor(account, origin))
    }

    @Test
    fun theBindingIsReadFromTheSession() {
        assertEquals(KeptBinding("acct-a", "https://a.example"), SessionWrap.bindingOf(sessionFor("acct-a", "https://a.example")))
        assertEquals(KeptBinding.NONE, SessionWrap.bindingOf("""{"session":"no kept session in it"}"""))
    }

    /** One key store, two homes (two copies of the app for the same user): a file of one does not open in the other. */
    @Test
    fun aFileMadeForAnotherAccountOrServerDoesNotOpen() {
        val store = TestKeyStore()
        val a = tmp().also { keptAs(it, store, "acct-a", "https://a.example") }
        val b = tmp().also { keptAs(it, store, "acct-b", "https://b.example") }
        val sameAccountOtherServer = tmp().also { keptAs(it, store, "acct-a", "https://b.example") }

        for (target in listOf(b, sameAccountOtherServer)) {
            secure(a).copyTo(secure(target), overwrite = true)
            val h = DesktopHome(target, store, log = {}, keyStorePause = {})
            assertNull(h.secureFile.read(), "another account's or server's file is not read as this one's")
            assertEquals(KeptForm.UNOPENABLE, h.secureFile.form)
        }
        assertEquals(sessionFor("acct-a", "https://a.example"), DesktopHome(a, store, log = {}, keyStorePause = {}).secureFile.read(), "it still opens where it was made")
    }

    @Test
    fun theAccountTheFileNamesCannotBeChangedToPass() {
        val store = TestKeyStore()
        val a = tmp().also { keptAs(it, store, "acct-a", "https://a.example") }
        val edited = secure(a).readText().replace("\"acct-a\"", "\"acct-b\"").replace("https://a.example", "https://b.example")
        assertTrue(edited.contains("\"account\":\"acct-b\""))
        assertFailsWith<WrapUnopenable> { SessionWrap.open(edited, store, KeptBinding("acct-b", "https://b.example")) }
        assertFailsWith<WrapUnopenable> { SessionWrap.open(edited, store, null) }
    }

    @Test
    fun aFileSealedTheOldWayOpensAndIsSealedAgainForItsAccount() {
        val root = tmp()
        val store = TestKeyStore()
        val v2 = File(root, DesktopHome.NEW_DIR).also { it.mkdirs() }
        File(v2, "desktop-prefs.json").writeText("""{"keepSignIn":true,"keptFor":"acct-a","wraps":true}""")
        val key = SessionWrap.newKey()
        val handle = store.keep(key)
        val plain = sessionFor("acct-a", "https://a.example")
        secure(root).writeText(SessionWrap.sealVersion1(plain, key, store.kind, handle))

        assertEquals(plain, DesktopHome(root, store, log = {}, keyStorePause = {}).secureFile.read(), "the old seal still opens")
        val now = secure(root).readText()
        assertTrue(now.contains("\"andvari.wrap\":\"2\"") && now.contains("\"account\":\"acct-a\""), "sealed again, binding its account")
        assertEquals(1, store.keys.size, "with its own key")
        assertEquals(plain, DesktopHome(root, store, log = {}, keyStorePause = {}).secureFile.read())
    }

    @Test
    fun theStoreNameReadFromTheFileIsEscapedBeforeTheLog() {
        val root = tmp()
        val store = TestKeyStore()
        keptAs(root, store, "acct-a", "https://a.example")
        val forged = secure(root).readText().replace("\"store\":\"secret-service\"", "\"store\":\"x\\n2026-11-16T00:00:00Z forged line\\u2028and another\"")
        secure(root).writeText(forged)
        val lines = mutableListOf<String>()
        val h = DesktopHome(root, store, log = { lines += it }, keyStorePause = {})
        assertNull(h.secureFile.read())
        val line = lines.single { it.contains("forged line") }
        assertFalse(line.contains('\n') || line.contains('\u2028'), "one line, nothing forged: $line")
    }

    @Test
    fun printableEscapesWhatCouldBreakALine() {
        assertEquals("a\\nb\\rc\\u2028d\\u0000", printable("a\nb\rc\u2028d\u0000"))
        assertEquals("none", printable(null))
        assertEquals("x".repeat(120) + "…", printable("x".repeat(500)))
    }
}
