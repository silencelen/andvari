@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.ios

import io.ktor.client.request.get
import io.silencelen.andvari.core.app.AutofillVault
import io.silencelen.andvari.core.app.FillAvailability
import io.silencelen.andvari.core.client.session.InMemorySecrets
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.StoredSession
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import platform.Foundation.NSUserDefaults
import kotlin.test.Test
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
        try {
            val seams = IosSeams(IosStorageConfig(null, "io.silencelen.andvari.test", null, suite))
            seams.serverShare.publish("https://home.example")
            // What SafariWebExtensionHandler reads: the same suite and key, through a fresh instance.
            assertEquals("https://home.example", NSUserDefaults(suiteName = suite).stringForKey(IOS_APP_SERVER_KEY))
            seams.serverShare.publish(null)
            assertNull(NSUserDefaults(suiteName = suite).stringForKey(IOS_APP_SERVER_KEY), "no server: the extension is told there is none")
        } finally {
            NSUserDefaults(suiteName = suite).removePersistentDomainForName(suite)
        }
    }

    @Test
    fun theShippingLayoutSharesStateButNeverTheTokens() {
        val config = IosStorageConfig()
        assertEquals(IOS_APP_GROUP, config.defaultsSuite)
        assertEquals(IOS_APP_GROUP, config.keychainAccessGroup, "the quick-unlock blob and key are readable by the AutoFill extension")
        // The extensions' persistence has no secret store behind it: a session never loads there.
        assertNull(NoSecrets.read("session.tokens"))
        assertFalse(NoSecrets.write("session.tokens", "x"))
    }

    @Test
    fun anOlderLayoutMovesToTheSharedSuiteOnce() {
        val suite = "io.silencelen.andvari.test.${NSUUID().UUIDString}"
        val standard = NSUserDefaults.standardUserDefaults
        try {
            standard.setObject("https://home.example", forKey = "baseUrl")
            standard.setObject("12345", forKey = "ns.0123456789abcdef.policyFetchedAt")
            standard.setObject("keep", forKey = "somethingElse")
            val seams = IosSeams(IosStorageConfig(suite, "io.silencelen.andvari.test", null, null))
            assertEquals("https://home.example", seams.store.baseUrl)
            assertEquals(12345L, seams.store.origin("0123456789abcdef").policyFetchedAt)
            assertNull(standard.stringForKey("baseUrl"), "moved, not copied")
            assertEquals("keep", standard.stringForKey("somethingElse"))
            // A second start moves nothing: a value that reappears in the old place is not adopted.
            standard.setObject("https://other.example", forKey = "baseUrl")
            assertEquals("https://home.example", IosSeams(IosStorageConfig(suite, "io.silencelen.andvari.test", null, null)).store.baseUrl)
        } finally {
            for (k in listOf("baseUrl", "ns.0123456789abcdef.policyFetchedAt", "somethingElse")) standard.removeObjectForKey(k)
            NSUserDefaults(suiteName = suite).removePersistentDomainForName(suite)
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
            val fill = IosAutofill(IosStorageConfig(suite, "io.silencelen.andvari.test", null, null), path)
            assertEquals(FillAvailability.OpenApp(AutofillVault.NO_SNAPSHOT), fill.availability())
            assertTrue(fill.logins(listOf("example.com")).isEmpty())
            files.delete()
            assertNull(files.read())
        } finally {
            NSFileManager.defaultManager.removeItemAtPath(dir, error = null)
            NSUserDefaults(suiteName = suite).removePersistentDomainForName(suite)
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
