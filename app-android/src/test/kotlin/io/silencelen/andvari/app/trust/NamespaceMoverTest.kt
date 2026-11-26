package io.silencelen.andvari.app.trust

import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The host's side of a followed server move: the per-(server, account) directories move, idempotently, never merged. */
class NamespaceMoverTest {
    private val base: File = Files.createTempDirectory("ns-move").toFile()
    private val mover = AndroidNamespaceMover(base)
    private val from = "https://vault.family.example"
    private val to = "https://new.family.example"

    @AfterTest
    fun cleanUp() {
        base.deleteRecursively()
    }

    private fun put(origin: String, userId: String, name: String, text: String): File {
        val dir = NamespaceDirs.accountDir(base, origin, userId).apply { mkdirs() }
        return File(dir, name).apply { writeText(text) }
    }

    private fun read(origin: String, userId: String, name: String): String? =
        File(NamespaceDirs.accountDir(base, origin, userId), name).takeIf { it.isFile }?.readText()

    @Test
    fun everyAccountsDirectoryMovesAndNothingIsLeftAtTheOldAddress() {
        put(from, "u1", "kept.json", "one")
        put(from, "u2", "kept.json", "two")
        assertTrue(mover.onMoved(from, to))
        assertEquals("one", read(to, "u1", "kept.json"))
        assertEquals("two", read(to, "u2", "kept.json"))
        assertFalse(NamespaceDirs.originDir(base, from).exists(), "nothing left at the old address")
    }

    @Test
    fun calledAgainAfterItSucceededIsSuccessAndChangesNothing() {
        put(from, "u1", "kept.json", "one")
        assertTrue(mover.onMoved(from, to))
        assertTrue(mover.onMoved(from, to), "already there, nothing left at the old one: success (called again after a crash)")
        assertEquals("one", read(to, "u1", "kept.json"))
    }

    @Test
    fun nothingEverKeptAtTheOldAddressIsSuccess() {
        assertTrue(mover.onMoved(from, to))
        assertFalse(NamespaceDirs.originDir(base, to).exists(), "nothing is made for nothing")
    }

    @Test
    fun aPartDoneMoveIsFinishedFromWhereItStopped() {
        // The app stopped after one account had moved.
        put(from, "u2", "kept.json", "two")
        put(to, "u1", "kept.json", "one")
        assertTrue(mover.onMoved(from, to))
        assertEquals("one", read(to, "u1", "kept.json"))
        assertEquals("two", read(to, "u2", "kept.json"))
        assertFalse(NamespaceDirs.originDir(base, from).exists())
    }

    @Test
    fun anAccountAtBothAddressesIsNeverMergedOrOverwritten() {
        put(from, "u1", "kept.json", "old")
        put(to, "u1", "kept.json", "new")
        assertFalse(mover.onMoved(from, to), "a failure: the new address stays closed")
        assertEquals("old", read(from, "u1", "kept.json"), "the old copy is untouched")
        assertEquals("new", read(to, "u1", "kept.json"), "the new copy is untouched")
    }

    @Test
    fun theSameAddressWrittenTwoWaysIsNoMove() {
        put(from, "u1", "kept.json", "one")
        assertTrue(mover.onMoved(from, "$from:443"))
        assertEquals("one", read(from, "u1", "kept.json"))
    }

    @Test
    fun aFileWhereTheFolderShouldBeIsAFailure() {
        put(from, "u1", "kept.json", "one")
        NamespaceDirs.originDir(base, to).apply { parentFile.mkdirs(); writeText("not a folder") }
        assertFalse(mover.onMoved(from, to))
        assertEquals("one", read(from, "u1", "kept.json"))
    }

    @Test
    fun aHostileUserIdNeverLeavesTheNamespace() {
        val dir = NamespaceDirs.accountDir(base, from, "../../escape")
        assertTrue(dir.canonicalPath.startsWith(NamespaceDirs.originDir(base, from).canonicalPath + File.separator))
    }
}
