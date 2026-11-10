@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.ios

import io.ktor.client.request.get
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
