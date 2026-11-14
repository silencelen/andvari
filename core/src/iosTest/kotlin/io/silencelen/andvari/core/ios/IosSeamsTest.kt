@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.ios

import io.ktor.client.request.get
import io.silencelen.andvari.core.app.AutofillVault
import io.silencelen.andvari.core.app.FillAvailability
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.client.session.InMemorySecrets
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.StoredSession
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import platform.Foundation.NSUserDefaults
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The iOS storage seams the simulator can run without an app bundle (the Keychain needs one). */
class IosSeamsTest {
    @Test
    fun nonSecretStateRoundTripsThroughUserDefaults() {
        val suite = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        try {
            val prefs = UserDefaultsPrefs(suite)
            prefs.putString("k", "v")
            assertEquals("v", prefs.getString("k"))
            prefs.putString("k", null)
            assertNull(prefs.getString("k"))
            val store = PrefsSessionPersistence(prefs, InMemorySecrets())
            assertNull(store.baseUrl, "no default server")
            store.moveOrigin("https://home.example")
            val secrets = InMemorySecrets()
            PrefsSessionPersistence(prefs, secrets).save(StoredSession("https://home.example", "u1", "u@example.com", "a1", "r1"))
            // A new instance over the same defaults (a relaunch) reads what the last one wrote.
            val relaunched = PrefsSessionPersistence(UserDefaultsPrefs(suite), secrets)
            assertEquals("https://home.example", relaunched.baseUrl)
            assertEquals("u1", relaunched.load()?.userId)
        } finally {
            NSUserDefaults(suiteName = suite).removePersistentDomainForName(suite)
        }
    }

    @Test
    fun theServerOriginIsSharedThroughTheAppGroupSuiteOnly() {
        assertEquals(IOS_APP_GROUP, IosStorageConfig().sharedSuite, "the app shares through its App Group by default")
        val suite = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val own = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        try {
            val seams = IosSeams(IosStorageConfig(own, "io.silencelen.andvari.test", null, suite))
            seams.serverShare.publish("https://home.example")
            // What SafariWebExtensionHandler reads: the same suite and key, through a fresh instance.
            assertEquals("https://home.example", NSUserDefaults(suiteName = suite).stringForKey(IOS_APP_SERVER_KEY))
            seams.serverShare.publish(null)
            assertNull(NSUserDefaults(suiteName = suite).stringForKey(IOS_APP_SERVER_KEY), "no server: the extension is told there is none")
        } finally {
            NSUserDefaults(suiteName = suite).removePersistentDomainForName(suite)
            NSUserDefaults(suiteName = own).removePersistentDomainForName(own)
        }
    }

    @Test
    fun theShippingLayoutKeepsTheAppsStatePrivateAndNeverSharesTheTokens() {
        val config = IosStorageConfig()
        assertNull(config.defaultsSuite, "the app's own state is in its private defaults")
        assertEquals(IOS_APP_GROUP, config.sharedSuite, "a copy is published to the group")
        assertEquals(IOS_APP_GROUP, config.keychainAccessGroup, "the quick-unlock blob and key are readable by the AutoFill extension")
        // The extensions' persistence has no secret store behind it: a session never loads there.
        assertNull(NoSecrets.read("session.tokens"))
        assertFalse(NoSecrets.write("session.tokens", "x"))
    }

    @Test
    fun aChangedGroupValueDoesNotChangeWhereTheAppConnects() {
        val own = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val group = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        try {
            val seams = IosSeams(IosStorageConfig(own, "io.silencelen.andvari.test", null, group))
            seams.store.moveOrigin("https://home.example")
            seams.store.origin("0123456789abcdef").cacheAllowed = false
            val shared = NSUserDefaults(suiteName = group)
            assertEquals("https://home.example", shared.stringForKey("baseUrl"), "published for the extensions")
            // A compromised extension rewrites the group's copy: another server, a relaxed policy.
            shared.setObject("https://evil.example", forKey = "baseUrl")
            shared.setObject("""{"baseUrl":"https://evil.example","userId":"u2","email":"x@evil.example"}""", forKey = "session")
            shared.setObject("true", forKey = "ns.0123456789abcdef.cacheAllowed")
            assertEquals("https://home.example", seams.store.baseUrl)
            assertNull(seams.store.storedIdentity(), "nobody is signed in, whatever the copy says")
            assertFalse(seams.store.origin("0123456789abcdef").cacheAllowed)
            // And after a relaunch.
            val relaunched = IosSeams(IosStorageConfig(own, "io.silencelen.andvari.test", null, group))
            assertEquals("https://home.example", relaunched.store.baseUrl)
            assertNull(relaunched.store.storedIdentity())
        } finally {
            NSUserDefaults(suiteName = own).removePersistentDomainForName(own)
            NSUserDefaults(suiteName = group).removePersistentDomainForName(group)
        }
    }

    /**
     * Round-7 review L6, round-8 review L: the first start of an install (the Keychain outlives an uninstall, the app's
     * container and private defaults do not) deletes what an earlier install left in the Keychain, tokens and quick
     * unlock alike, before anything else; the app never reads the group's copy of its state, and starts at the server
     * screen, signed out. An install marker in the app's container says the first start ran; nothing is deleted while
     * the protected data cannot be read (a launch prewarmed before the first unlock), nor once the marker is there, nor
     * when the private store holds state (an update from a build before the marker).
     */
    @Test
    fun aReinstallDeletesTheEarlierInstallsKeychainItemsOnceAndStartsSignedOut() {
        val own = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val group = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val dir = NSTemporaryDirectory() + "andvari-test-" + NSUUID().UUIDString
        val marker = "$dir/.installed"
        val config = IosStorageConfig(own, "io.silencelen.andvari.test", null, group)
        try {
            // What the group may hold before the first start: a build's published copy, or an extension's planting.
            val shared = NSUserDefaults(suiteName = group)
            shared.setObject("https://home.example", forKey = "baseUrl")
            shared.setObject("""{"baseUrl":"https://home.example","userId":"u1","email":"u@example.com"}""", forKey = "session")
            var dropped = 0
            // A launch iOS prewarmed before the first unlock: nothing is deleted, and the first start is still to come.
            IosSeams(config, dropStaleInstall = { dropped++; true }, installMarker = marker, protectedDataAvailable = { false })
            assertEquals(0, dropped)
            assertFalse(NSFileManager.defaultManager.fileExistsAtPath(marker))
            // A delete that fails leaves no marker, so the next start tries again (round-9 review 7).
            IosSeams(config, dropStaleInstall = { dropped++; false }, installMarker = marker, protectedDataAvailable = { true })
            assertEquals(1, dropped)
            assertFalse(NSFileManager.defaultManager.fileExistsAtPath(marker))
            // The first start proper.
            val seams = IosSeams(config, dropStaleInstall = { dropped++; true }, installMarker = marker, protectedDataAvailable = { true })
            assertEquals(2, dropped, "the earlier install's tokens and quick-unlock items are deleted")
            assertTrue(NSFileManager.defaultManager.fileExistsAtPath(marker), "and the install is marked")
            assertNull(seams.store.baseUrl, "the server screen: nothing is taken from the group")
            assertNull(seams.store.load(), "signed out")
            assertNull(seams.store.storedIdentity())
            // Later starts never delete anything, even with an empty private store (signed out in this install).
            IosSeams(config, dropStaleInstall = { dropped++; true }, installMarker = marker, protectedDataAvailable = { true })
            assertEquals(2, dropped)
            // An update from a build before the marker: the private store holds state, so nothing is deleted.
            NSFileManager.defaultManager.removeItemAtPath(marker, error = null)
            seams.store.moveOrigin("https://home.example")
            IosSeams(config, dropStaleInstall = { dropped++; true }, installMarker = marker, protectedDataAvailable = { true })
            assertEquals(2, dropped)
            assertTrue(NSFileManager.defaultManager.fileExistsAtPath(marker))
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(dir, error = null)
            NSUserDefaults(suiteName = own).removePersistentDomainForName(own)
            NSUserDefaults(suiteName = group).removePersistentDomainForName(group)
        }
    }

    @Test
    fun theExtensionsReadThePublishedCopy() {
        val own = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val group = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val dir = NSTemporaryDirectory() + "andvari-test-" + NSUUID().UUIDString
        try {
            val seams = IosSeams(IosStorageConfig(own, "io.silencelen.andvari.test", null, group), "$dir/autofill-snapshot.json", "$dir/saves")
            seams.store.moveOrigin("https://home.example")
            // The extension's store is the group's copy: it sees the server the app published.
            assertEquals("https://home.example", PrefsSessionPersistence(UserDefaultsPrefs(group), NoSecrets).baseUrl)
            val fill = IosAutofill(IosStorageConfig(own, "io.silencelen.andvari.test", null, group), "$dir/autofill-snapshot.json", "$dir/saves")
            assertEquals(FillAvailability.OpenApp(AutofillVault.NO_SNAPSHOT), fill.availability(), "nobody signed in: nothing to fill")
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(dir, error = null)
            NSUserDefaults(suiteName = own).removePersistentDomainForName(own)
            NSUserDefaults(suiteName = group).removePersistentDomainForName(group)
        }
    }

    @Test
    fun theSnapshotFileIsReplacedWholeAndTheExtensionReadsIt() {
        val dir = NSTemporaryDirectory() + "andvari-test-" + NSUUID().UUIDString
        val suite = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        try {
            NSFileManager.defaultManager.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
            val path = "$dir/autofill-snapshot.json"
            val files = FileFillSnapshots(path)
            assertNull(files.read())
            assertTrue(files.write("one".encodeToByteArray()))
            assertTrue(files.write("two-longer".encodeToByteArray()))
            assertEquals("two-longer", files.read()?.decodeToString())
            assertFalse(NSFileManager.defaultManager.fileExistsAtPath("$path.tmp"), "no temporary file is left")
            // The extension's vault over the same file: a file that is not a snapshot is no snapshot.
            val fill = IosAutofill(IosStorageConfig(suite, "io.silencelen.andvari.test", null, null), path, "$dir/saves")
            assertEquals(FillAvailability.OpenApp(AutofillVault.NO_SNAPSHOT), fill.availability())
            assertTrue(fill.logins(listOf("example.com")).isEmpty())
            files.delete()
            assertNull(files.read())

            // The save queue beside it: no key published, so the extension queues nothing.
            assertEquals(SaveQueued.NO_ACCOUNT, fill.queueSave("shop.example", "me", "pw"))
            val queue = FileSaveQueue("$dir/saves")
            val key = createCryptoProvider().boxKeypairFromSeed(ByteArray(32) { 7 })
            queue.publish("""{"v":1,"origin":"https://home.example","userId":"u1","identityPub":"${Bytes.toB64(key.publicKey)}"}""".encodeToByteArray())
            // Three saves in a row (the system's sessionID says "1" for each): three entries, none replacing another.
            assertEquals(SaveQueued.QUEUED, fill.queueSave("shop.example", "me", "pw"))
            assertEquals(SaveQueued.QUEUED, fill.queueSave("shop.example", "me", "pw2"))
            assertEquals(SaveQueued.QUEUED, fill.queueSave("other.example", "me", "pw"))
            val entries = queue.entries()
            assertEquals(3, entries.size)
            assertTrue(entries.keys.all { it.matches(Regex("s-[0-9a-f]{32}")) }, entries.keys.toString())
            assertTrue(entries.values.none { it.decodeToString().contains("password") || it.decodeToString().contains("shop.example") }, "sealed at rest")
            assertFalse(queue.add("../escape", "x".encodeToByteArray()))
            // An entry is never replaced, by this process or another (the Safari handler renames the same way).
            val taken = entries.keys.first()
            assertFalse(queue.add(taken, "other".encodeToByteArray()), "a taken id is refused")
            assertContentEquals(entries.getValue(taken), queue.entries().getValue(taken), "and the entry is untouched")
            assertTrue(queue.add("s-new", "x".encodeToByteArray()))
            queue.remove("s-new")
            assertTrue(NSFileManager.defaultManager.contentsOfDirectoryAtPath("$dir/saves", error = null).orEmpty().none { (it as String).endsWith(".tmp") }, "no temporary file is left")
            // What another process may leave here: an oversized entry, a name that is not an id, a stray file.
            val fm = NSFileManager.defaultManager
            fm.createFileAtPath("$dir/saves/q-huge.json", contents = ByteArray(SaveQueue.MAX_ENTRY_BYTES + 1) { 97 }.toNSData(), attributes = null)
            fm.createFileAtPath("$dir/saves/q-bad id!.json", contents = "x".encodeToByteArray().toNSData(), attributes = null)
            fm.createFileAtPath("$dir/saves/stray.bin", contents = "x".encodeToByteArray().toNSData(), attributes = null)
            assertEquals(entries.keys, queue.entries().keys, "only the listed, bounded entries are read")
            assertFalse(fm.fileExistsAtPath("$dir/saves/q-huge.json") || fm.fileExistsAtPath("$dir/saves/stray.bin"), "the rest is removed")
            assertEquals("""{"v":1,"origin":"https://home.example","userId":"u1","identityPub":"${Bytes.toB64(key.publicKey)}"}""", queue.publication()?.decodeToString(), "the key file is not an entry")
            queue.remove(entries.keys.first())
            assertEquals(2, queue.entries().size)
            queue.clear()
            assertTrue(queue.entries().isEmpty())
            assertNull(queue.publication())
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(dir, error = null)
            NSUserDefaults(suiteName = suite).removePersistentDomainForName(suite)
        }
    }

    @Test
    fun theFilesSetAsideForASaveAreKeptWholeUnderTheirIdsOnly() {
        val dir = NSTemporaryDirectory() + "andvari-test-" + NSUUID().UUIDString
        try {
            val files = FileBlobStore("$dir/pending-files")
            val id = "00000000-0000-4000-8000-0000000000f1"
            assertTrue(files.ids().isEmpty())
            assertTrue(files.put(id, "one".encodeToByteArray()))
            assertTrue(files.put(id, "two-longer".encodeToByteArray()))
            assertEquals("two-longer", files.get(id)?.decodeToString())
            assertEquals(listOf(id), files.ids(), "no temporary file is left")
            assertFalse(files.put("../escape", "x".encodeToByteArray()), "only an id names a file")
            assertFalse(files.put("ABC", "x".encodeToByteArray()))
            assertNull(files.get("../pending-files/$id"))
            NSFileManager.defaultManager.createFileAtPath("$dir/pending-files/stray.bin", contents = "x".encodeToByteArray().toNSData(), attributes = null)
            assertEquals(listOf(id), files.ids(), "what is not an id is not listed")
            files.delete(id)
            assertNull(files.get(id))
            assertTrue(files.put(id, "three".encodeToByteArray()))
            files.clear()
            assertTrue(files.ids().isEmpty())
            assertFalse(NSFileManager.defaultManager.fileExistsAtPath("$dir/pending-files"))
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(dir, error = null)
        }
    }

    @Test
    fun aNamespaceHoldsItsCacheAndDeviceStateAndTheCacheCanGo() {
        val root = NSTemporaryDirectory() + "andvari-test-" + NSUUID().UUIDString
        try {
            val ns = IosNamespaceStorage(root)
            ns.openVaultCache("0123456789abcdef", "u1").close()
            val db = "$root/0123456789abcdef/u1/vault-u1.db"
            assertTrue(NSFileManager.defaultManager.fileExistsAtPath(db))
            ns.deviceState("0123456789abcdef", "u1").set("personal.last", "v1")
            assertEquals("v1", ns.deviceState("0123456789abcdef", "u1").get("personal.last"))
            ns.deleteVaultCache("0123456789abcdef", "u1")
            assertFalse(NSFileManager.defaultManager.fileExistsAtPath(db))
            assertEquals("v1", ns.deviceState("0123456789abcdef", "u1").get("personal.last"), "no purge reaches the device state")
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(root, error = null)
        }
    }

    @Test
    fun theDarwinClientRefusesPlainHttpToAnotherHost() = runBlocking<Unit> {
        val client = IosHttpClients.create()
        try {
            assertFailsWith<IOException> { client.get("http://192.168.1.9:8080/") }
        } finally {
            client.close()
        }
        assertEquals("ios", IosHttpClients.wirePlatform)
    }
}
