@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import kotlinx.cinterop.BetaInteropApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.client.OriginCanon
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUUID
import platform.Foundation.create
import platform.Foundation.stringWithContentsOfFile
import platform.Foundation.writeToFile
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Item 1 of the iPhone's move (the seam): what the simulator can run without an app bundle. The Keychain needs one
 * (a test process gets `errSecMissingEntitlement`), so the session-grade store's own round trip is checked only where
 * the Keychain answers (see [theSessionGradeStoreRoundTripsWhereTheKeychainAnswers]); everything else runs anywhere.
 * WRITTEN ON LINUX, NEVER RUN: the first Mac run of `:core:iosSimulatorArm64Test` is the first time any of this runs.
 */
class IosAppSeamTest {
    private fun scratch(): String {
        val path = NSTemporaryDirectory() + "andvari-seam-" + NSUUID().UUIDString
        NSFileManager.defaultManager.createDirectoryAtPath(path, withIntermediateDirectories = true, attributes = null, error = null)
        return path
    }

    private fun drop(path: String) {
        NSFileManager.defaultManager.removeItemAtPath(path, error = null)
    }

    private fun write(path: String, text: String) {
        NSFileManager.defaultManager.createDirectoryAtPath(path.substringBeforeLast('/'), withIntermediateDirectories = true, attributes = null, error = null)
        check(NSString.create(string = text).writeToFile(path, atomically = true, encoding = NSUTF8StringEncoding, error = null)) { "could not write $path" }
    }

    private fun read(path: String): String? = NSString.stringWithContentsOfFile(path, NSUTF8StringEncoding, null)

    // ---- the vault cache's file calls ----

    @Test
    fun aMoveNeverReplacesAndCountsAMissingSourceAsDone() {
        val dir = scratch()
        try {
            assertTrue(IosFiles.moveWithoutReplacing("$dir/none", "$dir/to"), "nothing to move is done")
            write("$dir/a", "A")
            assertTrue(IosFiles.moveWithoutReplacing("$dir/a", "$dir/b"))
            assertFalse(IosFiles.exists("$dir/a"))
            assertEquals("A", read("$dir/b"))
            write("$dir/c", "C")
            assertFalse(IosFiles.moveWithoutReplacing("$dir/c", "$dir/b"), "a file at the target is never replaced")
            assertEquals("A", read("$dir/b"))
            assertEquals("C", read("$dir/c"), "and the source stays where it was")
        } finally {
            drop(dir)
        }
    }

    @Test
    fun aRemoveIsTrueOnceNothingIsLeft() {
        val dir = scratch()
        try {
            assertTrue(IosFiles.remove("$dir/none"))
            write("$dir/f", "x")
            assertTrue(IosFiles.remove("$dir/f"))
            assertFalse(IosFiles.exists("$dir/f"))
        } finally {
            drop(dir)
        }
    }

    // ---- the namespace mover (Android's AndroidNamespaceMover cases) ----

    private fun nsDir(base: String, origin: String) = "$base/ns/${OriginCanon.pathSafe(OriginCanon.originKey(origin))}"

    @Test
    fun theMoverTakesTheWholeFolderAndIsDoneWhenNothingIsLeft() {
        val base = scratch()
        try {
            val mover = IosNamespaceMover(base)
            assertTrue(mover.onMoved("https://old.example", "https://new.example"), "nothing at the old address is success")
            write("${nsDir(base, "https://old.example")}/u1/x", "1")
            assertTrue(mover.onMoved("https://old.example", "https://new.example"))
            assertEquals("1", read("${nsDir(base, "https://new.example")}/u1/x"))
            assertFalse(IosFiles.exists(nsDir(base, "https://old.example")))
            assertTrue(mover.onMoved("https://old.example", "https://new.example"), "called again after it finished: still success")
        } finally {
            drop(base)
        }
    }

    @Test
    fun theMoverFinishesAPartMoveAndNeverMergesAnAccountAtBothAddresses() {
        val base = scratch()
        try {
            val mover = IosNamespaceMover(base)
            val old = nsDir(base, "https://old.example")
            val new = nsDir(base, "https://new.example")
            // A part-done move: u1 already moved, u2 still at the old address.
            write("$new/u1/x", "1")
            write("$old/u2/x", "2")
            assertTrue(mover.onMoved("https://old.example", "https://new.example"))
            assertEquals("2", read("$new/u2/x"))
            assertFalse(IosFiles.exists(old))
            // One account at both addresses: a failure, both kept as they are.
            write("$old/u3/x", "old")
            write("$new/u3/x", "new")
            assertFalse(mover.onMoved("https://old.example", "https://new.example"))
            assertEquals("old", read("$old/u3/x"))
            assertEquals("new", read("$new/u3/x"))
        } finally {
            drop(base)
        }
    }

    @Test
    fun theSameAddressIsNoMove() {
        val base = scratch()
        try {
            write("${nsDir(base, "https://a.example")}/u1/x", "1")
            assertTrue(IosNamespaceMover(base).onMoved("https://a.example", "https://A.example:443"), "one canonical origin")
            assertEquals("1", read("${nsDir(base, "https://a.example")}/u1/x"))
        } finally {
            drop(base)
        }
    }

    // ---- the content's kept records ----

    @Test
    fun keptRecordsAreFilesUnderTheirOwnNamesOnly() {
        val dir = scratch()
        try {
            val kept = IosKeptStorage(dir)
            val record = kept.record("abc123-moves")
            assertTrue(record.write(byteArrayOf(1, 2, 3)))
            assertContentEquals(byteArrayOf(1, 2, 3), IosKeptStorage(dir).record("abc123-moves").read(), "read back by a new instance (a relaunch)")
            record.delete()
            assertNull(kept.record("abc123-moves").read())
            val blobs = kept.blobs("abc123-files")
            val id = "0123abcd-0000-4000-8000-0123456789ab"
            assertTrue(blobs.put(id, byteArrayOf(9)))
            assertEquals(listOf(id), blobs.ids())
            for (bad in listOf("../x", "a/b", ".", "..", "", "x".repeat(129))) {
                assertFailsWith<IllegalArgumentException>("'$bad' names no file") { kept.record(bad) }
            }
        } finally {
            drop(dir)
        }
    }

    // ---- the first start of an install ----

    @Test
    fun theFirstStartWaitsForTheProtectedDataAndAMarkerSettlesIt() {
        val root = scratch()
        try {
            val layout = IosAppLayout.under(root, null, "io.silencelen.andvari.test.${NSUUID().UUIDString}")
            val secure = KeychainStateFile(layout.keychainService, IosAppLayout.SECURE_ACCOUNT)
            assertFalse(IosAppSeam.firstStartSettled(layout, secure) { false }, "prewarmed before the first unlock: nothing built")
            assertFalse(IosFiles.exists(layout.installMarker), "and no marker written")
            IosFiles.touch(layout.installMarker)
            assertTrue(IosAppSeam.firstStartSettled(layout, secure) { false }, "a marker: settled, nothing deleted")
        } finally {
            drop(root)
        }
    }

    @Test
    fun theSessionGradeStoreRoundTripsWhereTheKeychainAnswers() {
        val service = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val file = KeychainStateFile(service, "secure-state", tries = 2, pause = {})
        val wrote = runCatching { file.replace("""{"a":"1"}""") }
        if (wrote.isFailure) {
            // A test process without an app bundle has no Keychain: what core is handed then is "nothing", flagged.
            assertNull(file.read())
            assertTrue(file.unreadable, "a Keychain that does not answer is 'unreadable', never 'no session'")
            return
        }
        try {
            assertEquals("""{"a":"1"}""", KeychainStateFile(service, "secure-state").read())
            file.replace("""{"a":"2"}""")
            assertEquals("""{"a":"2"}""", file.read())
            assertFalse(file.unreadable)
            assertTrue(file.delete())
            assertNull(file.read(), "no item reads as nothing")
            assertFalse(file.unreadable, "and is not 'unreadable'")
        } finally {
            file.delete()
        }
    }

    // ---- the seam itself ----

    private class Recording(private val answer: Boolean) : PreCutoverStores {
        val asked = ArrayList<PreCutoverStore>()

        override fun wipe(store: PreCutoverStore): Boolean {
            asked += store
            return answer
        }
    }

    @Test
    fun theSeamStartsAtTheFirstScreenWipesTheOldStoresOnceAndOffersNoQuickUnlock() {
        val root = scratch()
        val layout = IosAppLayout.under(root, null, "io.silencelen.andvari.test.${NSUUID().UUIDString}")
        IosFiles.touch(layout.installMarker) // not a first start: the Keychain is not asked to delete anything
        try {
            val stores = Recording(true)
            val seam = assertNotNull(IosAppSeam.build(layout, keyWrap = null, oldStores = stores, bakedSpec = null, protectedDataAvailable = { true }, deviceName = "iPhone"))
            try {
                assertEquals(AppPhase.ENTRY, seam.api.snapshot.phase, "no kept session: the first screen")
                assertEquals(PreCutoverStore.entries.toSet(), stores.asked.toSet(), "every old store is wiped at the first launch")
                assertNull(seam.joinBase)
                assertNull(seam.api.content)
            } finally {
                seam.api.close()
            }
            // A relaunch: every store is known to be gone, so none is asked again.
            val again = Recording(true)
            val second = assertNotNull(IosAppSeam.build(layout, null, again, null, { true }, "iPhone"))
            try {
                assertEquals(emptyList(), again.asked)
                assertTrue(IosFiles.exists("${layout.deviceStateDir}/device-state.json"), "the device state is a file of the new path's folder")
            } finally {
                second.api.close()
            }
        } finally {
            drop(root)
        }
    }

    @Test
    fun anOldStoreThatStaysIsAskedAgainAtTheNextStart() {
        val root = scratch()
        val layout = IosAppLayout.under(root, null, "io.silencelen.andvari.test.${NSUUID().UUIDString}")
        IosFiles.touch(layout.installMarker)
        try {
            val first = assertNotNull(IosAppSeam.build(layout, null, Recording(false), null, { true }, "iPhone"))
            assertNotNull(first.api.snapshot.oldData, "the first screen says old data is left")
            first.api.close()
            val again = Recording(true)
            assertNotNull(IosAppSeam.build(layout, null, again, null, { true }, "iPhone")).api.close()
            assertEquals(PreCutoverStore.entries.toSet(), again.asked.toSet())
        } finally {
            drop(root)
        }
    }

    @Test
    fun aBundledSpecWithPlaceholdersBakesNothingAndSaysSo() {
        val root = scratch()
        val layout = IosAppLayout.under(root, null, "io.silencelen.andvari.test.${NSUUID().UUIDString}")
        IosFiles.touch(layout.installMarker)
        val text = """{"v":1,"PUBLIC_INSTANCE":{"origin":"https://vault.andvaripass.com","instanceId":"PLACEHOLDER: a","card0Hash":"PLACEHOLDER: b","kind":"public"},"joinBase":"https://andvaripass.com"}"""
        try {
            val seam = assertNotNull(IosAppSeam.build(layout, null, Recording(true), text, { true }, "iPhone"))
            try {
                assertEquals("https://andvaripass.com", seam.joinBase)
                assertEquals(listOf("instanceId", "card0Hash"), seam.placeholders)
            } finally {
                seam.api.close()
            }
        } finally {
            drop(root)
        }
    }

    @Test
    fun theNewPathsNamesAreNotTheOldPaths() {
        val layout = IosAppLayout.shipping()
        assertTrue(layout.root.endsWith("/andvari-ovh"))
        assertFalse(layout.root == IosNamespaceStorage.defaultRoot())
        assertFalse(IosNamespaceStorage.defaultRoot().startsWith(layout.root + "/"))
        assertFalse(layout.root.startsWith(IosNamespaceStorage.defaultRoot() + "/"))
        assertEquals("io.silencelen.andvari.ovh", layout.keychainService)
        assertFalse(layout.keychainService == IosStorageConfig().keychainService)
        layout.groupDir?.let { assertTrue(it.endsWith("/ovh")) }
    }
}
