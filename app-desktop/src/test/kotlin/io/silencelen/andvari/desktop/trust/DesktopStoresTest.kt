package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.client.InMemoryVaultCache
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The new path's stores on this computer. */
class DesktopStoresTest {
    private val tmp: File = Files.createTempDirectory("andvari-l7-stores").toFile()

    @AfterTest
    fun cleanUp() {
        tmp.deleteRecursively()
    }

    @Test
    fun aMissingFileReadsAsNoneAndOneThatCannotBeReadThrows() {
        assertNull(OwnerOnlyFile(File(tmp, "absent.json")).read())
        val blocked = File(tmp, "device-state.json").apply { mkdirs(); File(this, "x").writeText("x") }
        assertFailsWith<IOException>("a trust record that cannot be read is unknown, never empty") { OwnerOnlyFile(blocked).read() }
    }

    @Test
    fun aReplacedFileIsOwnerOnly() {
        val f = File(tmp, "a/b.json")
        OwnerOnlyFile(f).replace("{\"k\":1}")
        assertEquals("{\"k\":1}", OwnerOnlyFile(f).read())
        if (Files.getFileStore(tmp.toPath()).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(f.toPath())))
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(f.parentFile.toPath())))
        }
        assertFalse(File(f.parentFile, "b.json.tmp").exists())
    }

    @Test
    fun theSignInStaysInMemoryUnlessThePersonOptedIn() {
        val store = TestKeyStore()
        val home = DesktopHome(tmp, store, log = {})
        assertFalse(home.prefs.keepSignIn, "off by default")
        home.secureFile.replace("{\"session\":1}")
        assertEquals("{\"session\":1}", home.secureFile.read())
        assertFalse(home.secureFile.onDisk, "nothing at rest without the opt-in")

        home.setKeepSignIn(true)
        assertTrue(home.secureFile.onDisk, "what was held goes to disk when the person opts in")
        assertEquals("{\"session\":1}", DesktopHome(tmp, store, log = {}).secureFile.read(), "and a restart reads it")

        home.setKeepSignIn(false)
        assertFalse(home.secureFile.onDisk, "opting out deletes it")
        assertEquals("{\"session\":1}", home.secureFile.read(), "the run keeps its session in memory")
    }

    @Test
    fun aSignInFileLeftOnDiskWithoutTheOptInIsDeletedUnread() {
        val home = DesktopHome(tmp)
        OwnerOnlyFile(File(home.dir, "secure-state.json")).replace("{\"left\":1}")
        assertNull(home.secureFile.read())
        assertFalse(home.secureFile.onDisk)
    }

    @Test
    fun withoutTheOptInTheVaultCacheIsMemory() {
        val home = DesktopHome(tmp)
        assertIs<InMemoryVaultCache>(home.cacheFiles.open("vault-u1.db", "u1"))
        assertTrue(home.cacheDir.listFiles().isNullOrEmpty())
    }

    @Test
    fun theWipeRemovesTheOldStoresKeepsThreePrefsAndNeverEntersTheNewDirectory() {
        val home = DesktopHome(tmp)
        File(home.dir, "device-state.json").writeText("{\"new\":1}")
        File(tmp, "session.json").writeText("{}")
        File(tmp, "pending-server.json").writeText("{}")
        File(tmp, "account-keys.json").writeText("{}")
        File(tmp, "vault-u1.db").writeText("x")
        File(tmp, "diagnostic.log").writeText("log")
        File(tmp, "prefs.json").writeText(
            """{"baseUrl":"https://andvari.monahanhosting.com","themeMode":"dark","lastExportAt":5,"lastAcceptedSeq":9,"origins":{"abc":{"cacheConsent":true}}}""",
        )
        val user = File(tmp, "ns/0123456789abcdef/u1").apply { mkdirs() }
        for (n in listOf("vault-u1.db", "vault-u1.db-wal", "account-keys.json", "device-state.json", "self-identity-pub")) File(user, n).writeText("x")
        File(tmp, "ns/0123456789abcdef/self-identity-by-email").apply { mkdirs() }.let { File(it, "aa").writeText("x") }

        val wipe = DesktopOldStores(tmp)
        assertTrue(PreCutoverStore.entries.all { wipe.wipe(it) })

        for (n in listOf("session.json", "pending-server.json", "account-keys.json", "vault-u1.db", "ns")) assertFalse(File(tmp, n).exists(), n)
        val prefs = Json.parseToJsonElement(File(tmp, "prefs.json").readText()).jsonObject
        assertEquals(setOf("themeMode", "lastExportAt", "lastAcceptedSeq"), prefs.keys, "the theme, the last backup and the rollback floor stay")
        assertEquals("log", File(tmp, "diagnostic.log").readText(), "not vault state")
        assertEquals("{\"new\":1}", File(home.dir, "device-state.json").readText(), "the new directory is never touched")
        assertTrue(PreCutoverStore.entries.all { wipe.wipe(it) }, "a second pass finds nothing and succeeds")
    }

    @Test
    fun aFileThatCannotBeDeletedFailsItsStore() {
        // A non-empty directory where the session file was: File.delete() refuses it, as Windows refuses a held file.
        File(tmp, "session.json").apply { mkdirs(); File(this, "held").writeText("x") }
        assertFalse(DesktopOldStores(tmp).wipe(PreCutoverStore.SAVED_SESSIONS))
        assertTrue(File(tmp, "session.json").exists())
    }
}
