package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Account deletion on the desktop (spec 03 §13, owner decision 2026-11-15): once the server deleted the account, this
 * computer is left as a fresh install, with nothing of the account and nothing of its server. Against a real store
 * directory: what [DesktopSessionStore.forgetServer] removes, what a new process then reads, and what is not its to
 * remove (another server's namespace, the device's own settings and its update floor).
 */
class AccountDeletionStoreTest {
    private val root = Files.createTempDirectory("andvari-desktop-deletion").toFile()
    private val crypto = createCryptoProvider()
    private val password = "correct horse battery staple"
    private val home = "https://vault.example.net"
    private val homeKey = originKey(home)
    private val other = "https://other.example.org"
    private val otherKey = originKey(other)
    private val forged = "99999999-9999-4999-8999-999999999999"

    /** An account of the other server, which this computer also used. */
    private val elsewhere = "00000000-0000-4000-8000-0000000000cc"

    private fun keysFile(store: DesktopSessionStore, key: String, userId: String) = File(store.nsDir(key, userId), "account-keys.json")

    @AfterTest
    fun cleanup() {
        root.deleteRecursively()
    }

    private fun account(email: String): Pair<Account, AccountKeys> {
        val r = Account.enroll("inv", email, "m", password, KdfParams(ops = 1, memBytes = 8192), null, null, "dev", crypto)
        val keys = AccountKeys(r.request.kdfSalt, r.request.kdfParams, r.request.wrappedUvk, r.request.encryptedIdentitySeed, r.request.identityPub, "")
        return Account.unlock(r.request.userId, password, keys, crypto) to keys
    }

    /** A computer that used [home] with two accounts (one signed in now) and [other] before it. */
    private fun usedStore(): Triple<DesktopSessionStore, Account, Account> {
        val store = DesktopSessionStore(root)
        store.baseUrl = home
        val (ann, annKeys) = account("ann@example.com")
        val (bob, bobKeys) = account("bob@example.com")
        store.save(DesktopSession(home, ann.userId, "ann@example.com", "access-token-1", "refresh-token-1"))
        for ((who, keys, email) in listOf(Triple(ann, annKeys, "ann@example.com"), Triple(bob, bobKeys, "bob@example.com"))) {
            store.saveAccountKeys(homeKey, who.userId, keys)
            store.recordSelfIdentityPub(homeKey, who.userId, email, who)
            store.personalDeviceState(homeKey, who.userId).set("personal.last", "v-personal")
            store.cacheDbFile(homeKey, who.userId).writeText("ciphertext")
            File(store.cacheDbFile(homeKey, who.userId).path + "-wal").writeText("ciphertext")
        }
        store.setOrgCacheAllowed(homeKey, true)
        store.setCacheConsent(homeKey, true)
        store.setOriginAutoLockSeconds(homeKey, 300)
        store.lastExportAt = 1_700_000_000_000
        store.lastSyncAt = 1_700_000_100_000
        store.setPendingServer(PendingServer(home, "ann@example.com", 1))
        // Another server this computer used before, and what is the device's own.
        store.saveAccountKeys(otherKey, elsewhere, annKeys)
        store.setCacheConsent(otherKey, true)
        store.themeMode = "dark"
        store.lastAcceptedSeq = 7
        return Triple(store, ann, bob)
    }

    @Test
    fun aDeletedAccountLeavesNothingOfItselfOrItsServer() {
        val (store, ann, bob) = usedStore()
        assertFailsWith<CryptoException> { store.selfIdentityPubFor(homeKey, "ann@example.com", forged) }
        assertTrue(keysFile(store, homeKey, ann.userId).isFile && keysFile(store, homeKey, bob.userId).isFile)

        store.forgetServer(homeKey)

        // Nothing of the account: no session, no tokens on disk.
        assertNull(store.load())
        assertFalse(File(root, "session.json").exists())
        // Nothing of its server: the address, and everything kept under its origin, whoever's.
        assertEquals(DesktopSessionStore.DEFAULT_BASE_URL, store.baseUrl, "the default server, as a first launch has it")
        assertFalse(File(File(root, "ns"), homeKey).exists(), "every namespace at that server: caches, cached keys, device states, pins, bindings")
        assertFalse(keysFile(store, homeKey, ann.userId).exists())
        assertFalse(keysFile(store, homeKey, bob.userId).exists(), "another account's there too")
        assertNull(store.selfIdentityPubFor(homeKey, "ann@example.com", forged), "the address can register again here as a new account")
        assertNull(store.loadSelfIdentityPub(homeKey, bob.userId))
        assertNull(store.cacheConsent(homeKey), "the cache consent is unanswered again")
        assertFalse(store.orgCacheAllowed(homeKey))
        assertEquals(0, store.originAutoLockSeconds(homeKey))
        assertNull(store.loadPendingServer())
        assertEquals(0, store.lastExportAt, "the last backup was that account's")
        assertEquals(0, store.lastSyncAt)
        // No file left in the store names the server or either account.
        val named = listOf(homeKey, "vault.example.net", ann.userId, bob.userId, "ann@example.com", "bob@example.com", "refresh-token-1")
        for (f in root.walkTopDown().filter { it.isFile }) {
            val text = f.readText()
            for (n in named) {
                assertFalse(f.path.contains(n) || text.contains(n), "${f.relativeTo(root)} still names $n")
            }
        }
        // Not this deletion's: another server's namespace (§4.2), and the device's own settings and update floor.
        assertTrue(keysFile(store, otherKey, elsewhere).isFile)
        assertEquals(true, store.cacheConsent(otherKey))
        assertEquals("dark", store.themeMode)
        assertEquals(7, store.lastAcceptedSeq, "the update channel's anti-rollback floor never goes back")

        // A new process over the same directory starts as a first launch does.
        val relaunched = DesktopSessionStore(root)
        relaunched.migrateDefaultOnce()
        relaunched.adoptNamespacesOnce()
        assertNull(relaunched.load())
        assertEquals(DesktopSessionStore.DEFAULT_BASE_URL, relaunched.baseUrl)
        assertNull(relaunched.loadPendingServer())
        assertFalse(File(File(root, "ns"), homeKey).exists(), "and brings nothing back")
    }

    @Test
    fun aSessionKeptInMemoryGoesToo() {
        val store = DesktopSessionStore(root)
        store.baseUrl = home
        store.tokensAtRest = false
        store.save(DesktopSession(home, "u1", "ann@example.com", "a", "r"))
        assertNotNull(store.load())
        store.forgetServer(homeKey)
        assertNull(store.load())
    }

    @Test
    fun forgettingAServerTheComputerDoesNotDialKeepsItsAddressAndItsSession() {
        val (store, ann, _) = usedStore()
        store.forgetServer(otherKey)
        assertEquals(home, store.baseUrl)
        assertEquals(ann.userId, store.load()?.userId, "the session is another server's")
        assertTrue(keysFile(store, homeKey, ann.userId).isFile)
        assertFalse(keysFile(store, otherKey, elsewhere).exists())
        assertNull(store.cacheConsent(otherKey))
        assertTrue(File(File(root, "ns"), homeKey).isDirectory)
        // What belongs to the server the computer dials stays: the pending marker and the last sync and backup times.
        assertNotNull(store.loadPendingServer())
        assertEquals(1_700_000_000_000, store.lastExportAt)
        assertEquals(1_700_000_100_000, store.lastSyncAt)
    }
}
