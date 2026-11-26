package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The desktop's kept records under the content's [ContentStores], by the names core gives, and the sign-in opt-in on top. */
class DesktopContentStoresTest {
    private val tmp: File = Files.createTempDirectory("andvari-content").toFile()
    private val dir = File(tmp, "content")
    private var keep = false
    private val id = "0f8fad5b-d9cb-469f-a165-70867728950e"
    private val crypto = createCryptoProvider()
    private val origin = "https://vault.example.com"
    private val userId = "55555555-5555-4555-8555-555555555555"
    private val prefix = ItemCacheNames.keptPrefix(crypto, origin, userId)

    @AfterTest
    fun cleanUp() {
        tmp.deleteRecursively()
    }

    @Test
    fun withoutTheOptInNothingIsWritten() {
        val c = DesktopContentStores(dir) { keep }
        val saves = c.storage.record(prefix + ContentStores.KEPT_SAVES)
        val files = c.storage.blobs(prefix + ContentStores.FILES)
        assertTrue(saves.write(byteArrayOf(1, 2)))
        assertTrue(files.put(id, byteArrayOf(3)))
        assertContentEquals(byteArrayOf(1, 2), saves.read())
        assertContentEquals(byteArrayOf(3), files.get(id))
        assertFalse(dir.exists())
    }

    @Test
    fun theRecordsFollowTheOptInBothWays() {
        val c = DesktopContentStores(dir) { keep }
        val moves = c.storage.record(prefix + ContentStores.MOVES)
        val files = c.storage.blobs(prefix + ContentStores.FILES)
        moves.write(byteArrayOf(7))
        files.put(id, byteArrayOf(8))
        keep = true
        c.keepChanged(true)
        val movesFile = File(dir, prefix + ContentStores.MOVES)
        assertContentEquals(byteArrayOf(7), movesFile.readBytes())
        assertContentEquals(byteArrayOf(8), File(dir, prefix + ContentStores.FILES + "/$id").readBytes())
        assertContentEquals(byteArrayOf(7), moves.read())
        if (posix(dir)) assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(movesFile.toPath())))
        keep = false
        c.keepChanged(false)
        assertFalse(dir.exists())
        assertContentEquals(byteArrayOf(7), moves.read(), "a kept record survives the switch")
        assertEquals(listOf(id), files.ids())
    }

    @Test
    fun filesFoundWithoutTheOptInAreDeletedUnread() {
        File(dir, prefix + ContentStores.FILES).mkdirs()
        File(dir, prefix + ContentStores.KEPT_SAVES).writeBytes(byteArrayOf(9))
        val c = DesktopContentStores(dir) { false }
        assertFalse(dir.exists())
        assertNull(c.storage.record(prefix + ContentStores.KEPT_SAVES).read())
    }

    @Test
    fun aKeptFileIsNamedOnlyByAnIdThisAppMintsAndARecordOnlyByCoresNames() {
        keep = true
        val c = DesktopContentStores(dir) { keep }
        val files = c.storage.blobs(prefix + ContentStores.FILES)
        assertFalse(files.put("../escape", byteArrayOf(1)))
        assertFalse(File(tmp, "escape").exists())
        assertNull(files.get("../escape"))
        assertFailsWith<IllegalArgumentException> { c.storage.record("../escape") }
    }

    @Test
    fun aDropEmptiesDiskAndMemory() {
        keep = true
        val c = DesktopContentStores(dir) { keep }
        val applied = c.storage.record(prefix + ContentStores.APPLIED)
        val files = c.storage.blobs(prefix + ContentStores.FILES)
        applied.write(byteArrayOf(1))
        files.put(id, byteArrayOf(2))
        c.stores.drop(origin, userId, CopyDeletion.SIGNED_OUT)
        assertNull(applied.read())
        assertEquals(emptyList(), files.ids())
    }

    @Test
    fun theSeamPassesThemAndTheWindowReportsTheForeground() {
        val root = listOf(File("src/main/kotlin"), File("app-desktop/src/main/kotlin")).first { it.isDirectory }
        val seam = File(root, "io/silencelen/andvari/desktop/trust/TrustSeam.kt").readText()
        assertTrue("contentStores = home.content.stores" in seam)
        val main = File(root, "io/silencelen/andvari/desktop/Main.kt").readText()
        // Through the model, which says a fault instead of crashing.
        // A lock that fell due first, then the foreground ([TrustModel.cameBack]).
        assertTrue("model?.cameBack()" in main.substringAfter("windowGainedFocus").substringBefore("windowLostFocus"))
    }
}
