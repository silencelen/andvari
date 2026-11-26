@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.PreCutoverStore
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import platform.Foundation.NSUserDefaults
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Item 2 of the iPhone's move: the first-launch wipe of the old app's stores, over a layout of its own (temporary
 * folders, two test suites, a test Keychain service). The Keychain parts need an app bundle; without one their part of
 * a store answers false, and these tests check that the files and defaults of the same store went anyway.
 * WRITTEN ON LINUX, NEVER RUN.
 */
class IosOldStoresTest {
    private fun scratch(): String {
        val path = NSTemporaryDirectory() + "andvari-old-" + NSUUID().UUIDString
        NSFileManager.defaultManager.createDirectoryAtPath(path, withIntermediateDirectories = true, attributes = null, error = null)
        return path
    }

    private fun touch(path: String) = check(IosFiles.touch(path)) { "could not make $path" }

    private class World(val root: String, val group: String, val own: String, val shared: String) {
        val layout = IosOldLayout(root, group, own, shared, "io.silencelen.andvari.test.${NSUUID().UUIDString}", null)
        val ns = "$root/0123456789abcdef/u1"

        fun drop() {
            NSFileManager.defaultManager.removeItemAtPath(root, error = null)
            NSFileManager.defaultManager.removeItemAtPath(group, error = null)
            NSUserDefaults(suiteName = own).removePersistentDomainForName(own)
            NSUserDefaults(suiteName = shared).removePersistentDomainForName(shared)
        }
    }

    /** What the old build left: a namespace with its cache and device state, the root records, the group's files, both defaults. */
    private fun oldInstall(): World {
        val w = World(scratch(), scratch(), "io.silencelen.andvari.test.${NSUUID().UUIDString}", "io.silencelen.andvari.test.${NSUUID().UUIDString}")
        for (f in listOf("vault-u1.db", "vault-u1.db-wal", "vault-u1.db-shm", "device-state.json", "unrelated.txt")) touch("${w.ns}/$f")
        for (f in listOf("applied-saves.json", "move-memos.json", "pending-saves.json", "pending-files/0123abcd-0000-4000-8000-0123456789ab", ".installed")) touch("${w.root}/$f")
        for (f in listOf("autofill-snapshot.json", "saves/key.json", "saves/q-x.json", "ovh/saves/key.json", "ovh/autofill-snapshot.json")) touch("${w.group}/$f")
        for (suite in listOf(w.own, w.shared)) {
            val d = NSUserDefaults(suiteName = suite)
            for (k in listOf("baseUrl", "session", "pendingServer", "lastSyncAt", "ns.0123456789abcdef.cacheAllowed", "ns.0123456789abcdef.accountKeys.u1", "ns.0123456789abcdef.stamp.u1", "ns.0123456789abcdef.selfIdentity.u1", "appServer")) {
                d.setObject("x", forKey = k)
            }
            // The Swift app's own settings, which no store owns.
            d.setObject("on", forKey = "allowThirdPartyKeyboards")
        }
        return w
    }

    private fun exists(path: String) = NSFileManager.defaultManager.fileExistsAtPath(path)

    @Test
    fun theOfflineCacheGoesWithTheOldContentRecordsAndNothingElse() {
        val w = oldInstall()
        try {
            assertTrue(IosOldStores(w.layout).wipe(PreCutoverStore.OFFLINE_CACHE))
            for (f in listOf("vault-u1.db", "vault-u1.db-wal", "vault-u1.db-shm")) assertFalse(exists("${w.ns}/$f"), f)
            for (f in listOf("applied-saves.json", "move-memos.json", "pending-saves.json", "pending-files")) assertFalse(exists("${w.root}/$f"), f)
            assertTrue(exists("${w.ns}/device-state.json"), "the device state is another store's")
            assertTrue(exists("${w.ns}/unrelated.txt"))
            assertTrue(exists("${w.root}/.installed"), "the old install marker stays")
            assertTrue(IosOldStores(w.layout).wipe(PreCutoverStore.OFFLINE_CACHE), "again: nothing left is gone")
        } finally {
            w.drop()
        }
    }

    @Test
    fun savedSessionsTakeTheSessionKeysFromBothDefaultsAndLeaveTheAppsOwn() {
        val w = oldInstall()
        try {
            val keychainAnswers = IosOldStores(w.layout).wipe(PreCutoverStore.SAVED_SESSIONS)
            for (suite in listOf(w.own, w.shared)) {
                val d = NSUserDefaults(suiteName = suite)
                for (k in listOf("baseUrl", "session", "pendingServer", "lastSyncAt", "ns.0123456789abcdef.cacheAllowed", "ns.0123456789abcdef.accountKeys.u1", "ns.0123456789abcdef.stamp.u1", "appServer")) {
                    assertNull(d.objectForKey(k), "$suite: $k")
                }
                assertNotNull(d.objectForKey("ns.0123456789abcdef.selfIdentity.u1"), "an identity pin is the trust records'")
                assertEquals("on", d.stringForKey("allowThirdPartyKeyboards"), "the Swift app's own setting stays")
            }
            // With an app bundle the Keychain part answers too, and the whole store is gone.
            if (!keychainAnswers) println("SAVED_SESSIONS: the Keychain did not answer in this process (no app bundle)")
        } finally {
            w.drop()
        }
    }

    @Test
    fun trustRecordsTakeTheDeviceStatesAndPinsAndPruneEmptyFolders() {
        val w = oldInstall()
        try {
            val stores = IosOldStores(w.layout)
            assertTrue(stores.wipe(PreCutoverStore.OFFLINE_CACHE))
            NSFileManager.defaultManager.removeItemAtPath("${w.ns}/unrelated.txt", error = null)
            assertTrue(stores.wipe(PreCutoverStore.TRUST_RECORDS))
            assertFalse(exists("${w.ns}/device-state.json"))
            assertFalse(exists(w.ns), "an emptied namespace goes")
            assertFalse(exists("${w.root}/0123456789abcdef"))
            assertTrue(exists("${w.root}/.installed"))
            for (suite in listOf(w.own, w.shared)) {
                assertNull(NSUserDefaults(suiteName = suite).objectForKey("ns.0123456789abcdef.selfIdentity.u1"))
                assertNotNull(NSUserDefaults(suiteName = suite).objectForKey("baseUrl"), "the session keys are the saved sessions'")
            }
            assertTrue(stores.wipe(PreCutoverStore.PERSONAL_WRAP_CACHE), "the personal wrap lived in the device state, gone already")
        } finally {
            w.drop()
        }
    }

    @Test
    fun theGroupsOldSnapshotAndQueueGoAndTheNewPathsStay() {
        val w = oldInstall()
        try {
            assertTrue(IosOldStores(w.layout).wipe(PreCutoverStore.APP_GROUP_SNAPSHOT_AND_SAVE_QUEUE))
            assertFalse(exists("${w.group}/autofill-snapshot.json"))
            assertFalse(exists("${w.group}/saves"))
            assertTrue(exists("${w.group}/ovh/saves/key.json"), "the new path's queue is not the old one")
            assertTrue(exists("${w.group}/ovh/autofill-snapshot.json"))
        } finally {
            w.drop()
        }
    }

    @Test
    fun noGroupMeansNothingThereToWipe() {
        val w = oldInstall()
        try {
            val noGroup = IosOldLayout(w.root, null, w.own, w.shared, w.layout.keychainService, null)
            assertTrue(IosOldStores(noGroup).wipe(PreCutoverStore.APP_GROUP_SNAPSHOT_AND_SAVE_QUEUE))
        } finally {
            w.drop()
        }
    }

    @Test
    fun theKeysAreSortedByWhatTheOldPathWroteThem() {
        assertTrue(IosOldStores.isSessionKey("baseUrl"))
        assertTrue(IosOldStores.isSessionKey("highWaterWallMs"))
        assertTrue(IosOldStores.isSessionKey("ns.abc.policyFetchedAt"))
        assertTrue(IosOldStores.isSessionKey("ns.abc.accountKeys.u_1"))
        assertFalse(IosOldStores.isSessionKey("ns.abc.selfIdentity.u1"))
        assertTrue(IosOldStores.isTrustKey("ns.abc.selfIdentity.u1"))
        assertFalse(IosOldStores.isTrustKey("ns.abc.stamp.u1"))
        assertFalse(IosOldStores.isTrustKey("ns."))
        assertFalse(IosOldStores.isTrustKey("ns.abc"))
        assertFalse(IosOldStores.isSessionKey("allowThirdPartyKeyboards"))
        assertFalse(IosOldStores.isTrustKey("nsSomething"))
        assertTrue(IosOldStores.OLD_KEY_TAG_PREFIX.startsWith("io.silencelen.andvari.quickunlock."))
    }
}
