package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.PreCutoverStore
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The first-launch wipe and every recursive delete never follow a link. */
class SafeDeleteTest {
    private fun temp(name: String): File = Files.createTempDirectory(name).toFile().also { it.deleteOnExit() }

    private fun link(at: File, to: File) {
        at.parentFile.mkdirs()
        Files.createSymbolicLink(at.toPath(), to.toPath())
    }

    /** A link planted in the tree a wipe deletes, on the real file system. */
    @Test
    fun theFirstLaunchWipeRemovesPlantedLinksAsThemselvesAndNothingThroughThem() {
        val root = temp("andvari-root")
        val outside = temp("andvari-outside")
        val docs = File(outside, "Documents").also { it.mkdirs() }
        File(docs, "tax-return.pdf").writeText("pdf")
        File(docs, "notes.txt").writeText("notes")
        val other = File(outside, "other").also { it.mkdirs() }
        for (n in listOf("account-keys.json", "device-state.json", "self-identity-pub", "vault-cache.db")) File(File(other, "u1").also { it.mkdirs() }, n).writeText(n)
        File(root, "ns/origin1").mkdirs()
        link(File(root, "ns/origin1/self-identity-by-email"), docs)
        link(File(root, "ns/origin2"), other)
        // A real old store beside them still goes.
        File(root, "ns/origin3/u9").mkdirs()
        File(root, "ns/origin3/u9/account-keys.json").writeText("old")

        val wipe = DesktopOldStores(root)
        for (store in PreCutoverStore.entries) wipe.wipe(store)

        assertEquals(setOf("tax-return.pdf", "notes.txt"), docs.list()!!.toSet(), "nothing deleted through the link")
        assertEquals(setOf("account-keys.json", "device-state.json", "self-identity-pub", "vault-cache.db"), File(other, "u1").list()!!.toSet())
        assertFalse(File(root, "ns/origin3/u9/account-keys.json").exists(), "the real old store went")
        assertFalse(SafeDelete.exists(File(root, "ns/origin1/self-identity-by-email")), "the planted link went as itself")
        assertFalse(SafeDelete.exists(File(root, "ns/origin2")))
    }

    @Test
    fun theContentStoresAndTheCacheNeverDeleteThroughALink() {
        val root = temp("andvari-root")
        val outside = temp("andvari-outside").also { File(it, "keep.txt").writeText("mine") }
        val content = File(root, "v2/content").also { it.mkdirs() }
        link(File(content, "kept-abc"), outside)
        val stores = DesktopContentStores(content, wipeAtStart = false, within = root) { true }
        stores.keepChanged(false)
        assertTrue(File(outside, "keep.txt").exists())
        assertFalse(content.exists())

        val cache = File(root, "v2/vault-cache").also { it.mkdirs() }
        link(File(cache, "vault-x.db"), File(outside, "keep.txt"))
        link(File(cache, "a-dir"), outside)
        OptInCacheFiles(cache, root) { Keep.OFF }.deleteAll()
        assertEquals("mine", File(outside, "keep.txt").readText())
        assertTrue(cache.list()!!.isEmpty(), "the links went as themselves")
    }

    @Test
    fun aDirectoryThatResolvesOutsideTheAppsOwnIsLeftAlone() {
        val root = temp("andvari-root")
        val outside = temp("andvari-outside").also { File(it, "x").writeText("x") }
        assertFalse(SafeDelete.tree(File(outside, "x"), root), "not inside the app's directory")
        assertTrue(File(outside, "x").exists())
        // The app's directory reached through a linked parent: the real path decides.
        link(File(root, "via"), outside)
        assertFalse(SafeDelete.tree(File(root, "via/x"), root))
        assertTrue(File(outside, "x").exists())
    }
}
