package io.silencelen.andvari.app.trust

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.app.readUnlessAbsent
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.engine.SqliteVaultCacheFiles
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The platform's side of the new shared code. The content's stores over app-private files, the
 * cache files' rename for a followed move, the bell through the dialer, and the read rule (null only for a file that is
 * not there).
 */
class ContentStoresOnAndroidTest {
    private val base = Files.createTempDirectory("andvari-l5-7-kept").toFile()

    @AfterTest
    fun cleanup() {
        base.deleteRecursively()
    }

    private fun code(path: String) = File("src/main/kotlin/io/silencelen/andvari/app/$path").readText()

    @Test
    fun aRecordThatCannotBeReadIsThrownNotReadAsEmpty() {
        assertNull(readUnlessAbsent({ false }) { throw FileNotFoundException("gone") })
        // A file that is there but refused (Java says FileNotFoundException for EACCES too) is unknown.
        assertFailsWith<FileNotFoundException> { readUnlessAbsent({ true }) { throw FileNotFoundException("EACCES") } }
        assertFailsWith<IOException> { readUnlessAbsent({ true }) { throw IOException("EIO") } }
        // The strict reader carries that rule, and the plain one keeps the shared code's promise.
        val apf = code("AppPrivateFile.kt")
        assertTrue(apf.contains("internal class AppPrivateFile(private val file: File) : FillSnapshotStore, StrictRecordStore {"))
        assertTrue(apf.contains("override fun readOrThrow(): ByteArray? = readUnlessAbsent({ file.exists() }) { atomic.readFully() }"))
        assertTrue(apf.contains("override fun read(): ByteArray? = quietly(null) { readOrThrow() }"))
    }

    /** The old readers' promise is kept: [quietly] answers the fallback for a read that threw, and only then. */
    @Test
    fun thePlainReadersNeverThrowAndTheStrictOnesDo() {
        assertNull(io.silencelen.andvari.app.quietly(null) { readUnlessAbsent({ true }) { throw IOException("EIO") } })
        assertContentEquals(byteArrayOf(5), io.silencelen.andvari.app.quietly(null) { byteArrayOf(5) })

        // A record with a directory in its place.
        File(base, "kept-cc-moves").mkdirs()
        val record = KeptFile(File(base, "kept-cc-moves"))
        assertFailsWith<IOException> { record.readOrThrow() }
        assertNull(record.read(), "the old reader: null, never a throw")
        assertNull(KeptFile(File(base, "kept-none")).readOrThrow(), "absent is null on the strict reader too")

        // Set-aside files: one unreadable (a directory under a valid id), and a listing that fails (a file in place of the directory).
        val id = "0a1b2c3d-0000-4000-8000-00000000000b"
        val blobs = KeptBlobs(File(base, "files"))
        File(base, "files/$id").mkdirs()
        assertFailsWith<IOException> { blobs.getOrThrow(id) }
        assertNull(blobs.get(id))
        assertEquals(listOf(id), blobs.idsOrThrow())
        File(base, "not-a-dir").writeText("x")
        val unlistable = KeptBlobs(File(base, "not-a-dir"))
        assertFailsWith<IOException> { unlistable.idsOrThrow() }
        assertEquals(emptyList(), unlistable.ids())
        assertEquals(emptyList(), KeptBlobs(File(base, "no-files")).idsOrThrow(), "no directory is no files")
    }

    @Test
    fun aKeptFileReadsNullOnlyWhenAbsent() {
        val f = KeptFile(File(base, "kept-aa-moves"))
        assertNull(f.read())
        assertTrue(f.write(byteArrayOf(1, 2, 3)))
        assertContentEquals(byteArrayOf(1, 2, 3), f.read())
        assertTrue(f.write(byteArrayOf(4)))
        assertContentEquals(byteArrayOf(4), f.read())
        assertFalse(File(base, "kept-aa-moves.tmp").exists(), "the write leaves no temporary file")
        f.delete()
        assertNull(f.read())
        // A directory where the record should be: there, and not readable.
        File(base, "kept-bb-moves").mkdirs()
        assertFailsWith<IOException> { KeptFile(File(base, "kept-bb-moves")).readOrThrow() }
    }

    @Test
    fun anUnreadableRecordStopsTheCarryAndMovesNothing() {
        val crypto = createCryptoProvider()
        val dir = File(base, "kept")
        val stores = ContentStores(crypto, AndroidKeptStorage(dir))
        val old = ItemCacheNames.keptPrefix(crypto, "https://a.example", "u1")
        val new = ItemCacheNames.keptPrefix(crypto, "https://b.example", "u1")
        // One readable record, one unreadable (a directory in its place).
        assertTrue(KeptFile(File(dir, "$old${ContentStores.MOVES}")).write(byteArrayOf(9)))
        File(dir, "$old${ContentStores.KEPT_SAVES}").mkdirs()
        assertFalse(stores.carry("https://a.example", "https://b.example", "u1"))
        assertTrue(File(dir, "$old${ContentStores.KEPT_SAVES}").isDirectory, "the unreadable record stays where it was")
        assertFalse(File(dir, "$new${ContentStores.KEPT_SAVES}").exists())

        // Readable everywhere: the carry moves every record and file to the new names.
        File(dir, "$old${ContentStores.KEPT_SAVES}").delete()
        val id = "0a1b2c3d-0000-4000-8000-00000000000a"
        assertTrue(KeptBlobs(File(dir, "$old${ContentStores.FILES}")).put(id, byteArrayOf(7)))
        assertTrue(stores.carry("https://a.example", "https://b.example", "u1"))
        assertContentEquals(byteArrayOf(9), KeptFile(File(dir, "$new${ContentStores.MOVES}")).read())
        assertContentEquals(byteArrayOf(7), KeptBlobs(File(dir, "$new${ContentStores.FILES}")).get(id))
        assertNull(KeptFile(File(dir, "$old${ContentStores.MOVES}")).read())
        assertEquals(emptyList(), KeptBlobs(File(dir, "$old${ContentStores.FILES}")).ids())
    }

    @Test
    fun keptNamesAndIdsAreCoresShapeOnly() {
        val s = AndroidKeptStorage(base)
        assertFailsWith<IllegalArgumentException> { s.record("../x") }
        assertFailsWith<IllegalArgumentException> { s.blobs("a/b") }
        assertFailsWith<IllegalArgumentException> { s.record("..") }
        val blobs = KeptBlobs(File(base, "files"))
        assertFalse(blobs.put("../escape", byteArrayOf(1)))
        assertFalse(File(base, "escape").exists())
        assertNull(blobs.get("not-an-id"))
    }

    @Test
    fun aFollowedMoveRenamesTheCacheAndNeverReplaces() {
        val cache = File(base, "vault-cache").apply { mkdirs() }
        val files = SqliteVaultCacheFiles(cache.absolutePath, AppFiles::moveWithoutReplacing, AppFiles::remove)
        File(cache, "vault-a.db").writeText("copy")
        File(cache, "vault-a.db-wal").writeText("wal")
        assertTrue(files.rename("vault-a.db", "vault-b.db"))
        assertEquals("copy", File(cache, "vault-b.db").readText())
        assertFalse(File(cache, "vault-a.db").exists())
        // Nothing to move is success; a file already at the new name is refused and both stay.
        assertTrue(files.rename("vault-none.db", "vault-c.db"))
        File(cache, "vault-b.db-wal").writeText("other")
        assertFalse(files.rename("vault-a.db-wal", "vault-b.db-wal"))
        assertEquals("wal", File(cache, "vault-a.db-wal").readText())
        assertEquals("other", File(cache, "vault-b.db-wal").readText())
        // The seam passes the mover (without it a followed move leaves the copy under the old names).
        val seam = code("trust/TrustSeam.kt")
        assertTrue(seam.contains("AppFiles::moveWithoutReplacing,"))
        assertTrue(seam.contains("contentStores = ContentStores(crypto, AndroidKeptStorage(File(dir, \"kept\")), saveQueue(app)),"))
    }

    @Test
    fun theBellOpensOnlyThroughTheDialersGuard() {
        val state = JsonDeviceState(object : DeviceStateFile {
            var text: String? = null
            override fun read(): String? = text
            override fun replace(text: String) {
                this.text = text
            }
        })
        val dialer = Dialer(PinStore(state), HttpClient(OkHttp), "android")
        // No pin in force for this origin: the guard opens nothing, and nothing is dialed.
        var ran = false
        val r = runBlocking { dialingTransport(dialer).bellSocket("https://vault.example.net")!!.open("https://vault.example.net", "ticket") { ran = true; 1 } }
        assertNull(r)
        assertFalse(ran)
        // The engine takes the bell from its transport: the seam's transport is the dialer's, never one with no bell.
        val seam = code("trust/TrustSeam.kt")
        assertTrue(seam.contains("transport = dialingTransport(dialer),"))
        assertFalse(seam.contains("WireTransport(dialer::open)\n") || seam.contains("transport = WireTransport("))
    }
}
