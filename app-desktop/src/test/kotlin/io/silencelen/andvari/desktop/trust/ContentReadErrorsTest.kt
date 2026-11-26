package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.content.StrictBlobStore
import io.silencelen.andvari.core.app.content.StrictRecordStore
import io.silencelen.andvari.desktop.DesktopDiagnostics
import java.io.File
import java.io.IOException
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A kept record or file reads as "nothing there" only when there is none: the strict readers ([StrictRecordStore],
 * [StrictBlobStore], which core reads wherever that answer would delete or replace something) let an I/O error go
 * through, and the plain readers keep core's old promise never to throw.
 */
class ContentReadErrorsTest {
    private val tmp: File = Files.createTempDirectory("andvari-l7-content-read").toFile()
    private val id = "0123abcd-0000-4000-8000-0123456789ab"

    @BeforeTest
    fun logHere() {
        DesktopDiagnostics.logFileOverride = File(tmp, "diagnostic.log")
    }

    @AfterTest
    fun cleanUp() {
        DesktopDiagnostics.logFileOverride = null
        tmp.deleteRecursively()
    }

    @Test
    fun aRecordIsNullOnlyWhenAbsent() {
        assertNull(FileRecord(File(tmp, "absent")).readOrThrow())
        val ok = File(tmp, "ok").apply { writeBytes(byteArrayOf(1, 2)) }
        assertContentEquals(byteArrayOf(1, 2), FileRecord(ok).readOrThrow())
        assertContentEquals(byteArrayOf(1, 2), FileRecord(ok).read())
        // Something at the name that cannot be read as a file (here a directory) is unknown, never empty.
        val blocked = File(tmp, "blocked").apply { mkdirs() }
        assertFailsWith<IOException> { FileRecord(blocked).readOrThrow() }
        assertNull(FileRecord(blocked).read(), "the plain reader keeps its promise: it never throws")
        assertTrue(File(tmp, "diagnostic.log").readText().contains("a kept record could not be read"), "and the failure is logged, not swallowed")
    }

    @Test
    fun aSetAsideFileAndTheListAreEmptyOnlyWhenAbsent() {
        val dir = File(tmp, "files")
        val blobs = FileBlobs(dir, tmp)
        assertEquals(emptyList(), blobs.idsOrThrow(), "no directory: nothing set aside")
        assertNull(blobs.getOrThrow(id))
        assertTrue(blobs.put(id, byteArrayOf(9)))
        assertContentEquals(byteArrayOf(9), blobs.getOrThrow(id))
        assertContentEquals(byteArrayOf(9), blobs.get(id))
        File(dir, id).delete()
        File(dir, id).mkdirs()
        assertFailsWith<IOException> { blobs.getOrThrow(id) }
        assertNull(blobs.get(id), "the plain reader never throws")
        assertNull(blobs.getOrThrow("not-an-id"), "a name this app does not mint names no file")

        val notADir = File(tmp, "not-a-dir").apply { writeText("x") }
        assertFailsWith<IOException>("there but cannot be listed") { FileBlobs(notADir, tmp).idsOrThrow() }
        assertEquals(emptyList(), FileBlobs(notADir, tmp).ids(), "the plain list never throws")
    }

    @Test
    fun theOptInStoresOfferTheStrictReadersToCore() {
        val dir = File(tmp, "content")
        val stores = DesktopContentStores(dir, wipeAtStart = false, within = tmp) { true }
        val rec: FillSnapshotStore = stores.storage.record("abc-def")
        val files: BlobStore = stores.storage.blobs("abc-files")
        assertIs<StrictRecordStore>(rec)
        assertIs<StrictBlobStore>(files)
        File(dir, "abc-def").mkdirs()
        assertFailsWith<IOException> { rec.readOrThrow() }
        assertNull(rec.read())
        File(dir, "abc-files").apply { mkdirs(); File(this, id).mkdirs() }
        assertFailsWith<IOException> { files.getOrThrow(id) }
        assertNull(files.get(id))
    }

    @Test
    fun theSwitchOffStillRemovesWhatCannotBeReadAndDoesNotThrow() {
        val blocked = File(tmp, "kept-rec").apply { mkdirs() }
        var keep = true
        val rec = OptInRecord(blocked) { keep }
        assertFailsWith<IOException> { rec.readOrThrow() }
        keep = false
        rec.keepChanged(false)
        assertNull(rec.readOrThrow(), "now in memory, and nothing was carried")
        assertFalse(blocked.exists(), "the switch-off removed it")

        val dir = File(tmp, "kept-files").apply { mkdirs() }
        File(dir, id).mkdirs()
        val blobs = OptInBlobs(dir, tmp) { false }
        blobs.keepChanged(false)
        assertFalse(dir.exists(), "the switch-off removes the files")
    }
}
