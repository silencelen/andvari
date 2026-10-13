package io.silencelen.andvari.desktop

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A, branch A5b (A5 re-review M-1): the desktop runs an IN-MEMORY offline
 * cache by default (consent unanswered) and under an org-forbid policy, and a revocation purge deletes the
 * durable one. The cached personal wrap used to live only in that cache, so after a restart a server that
 * withheld the wrap met a device with no history: "Which vault is your Personal vault?" again instead of the
 * WITHHELD anomaly. The wrap (UVK-sealed) and the pinned vault id now live in the namespace's device state,
 * which no cache policy or purge removes.
 */
class PersonalWrapDurabilityTest {
    private val root = Files.createTempDirectory("andvari-desktop-a5b").toFile()
    private val crypto = createCryptoProvider()
    private val password = "correct horse battery staple"

    @AfterTest
    fun cleanup() {
        root.deleteRecursively()
    }

    private fun idleApi() = AndvariApi("https://vault.example.net", HttpClient(Java)) // hydrate() never calls it

    @Test
    fun aWithheldWrapStaysWithheldAfterARestartAndARevocationPurge() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (reg, registering) = Account.enroll("inv", "a5b@example.com", "a5b", password, KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "dev", crypto)
        val keys = AccountKeys(reg.kdfSalt, reg.kdfParams, reg.wrappedUvk, reg.encryptedIdentitySeed, reg.identityPub, escrowFingerprint = reg.escrow!!.fingerprint)
        val key = originKey("https://vault.example.net")

        // Session 1: the REGISTERING device (A9: it designates the wrap it minted at its first decision, offline too);
        // the offline cache is in memory (the desktop default).
        val store1 = DesktopSessionStore(root)
        val first = registering
        SyncEngine(idleApi(), first, InMemoryVaultCache(), deviceState = store1.personalDeviceState(key, reg.userId)).hydrate()
        assertEquals(Account.PersonalStatus.CONFIRMED, first.personalStatus)

        // Revocation purge + sign-out: the cache DB, the cached account keys and the session all go.
        store1.deleteCacheDb(key, reg.userId)
        store1.clearAccountKeys(key, reg.userId)
        store1.clear()

        // Restart (a new store over the same directory). The server now withholds the wrap.
        val store2 = DesktopSessionStore(root)
        val again = Account.unlock(reg.userId, password, keys, crypto)
        val engine = SyncEngine(idleApi(), again, InMemoryVaultCache(), deviceState = store2.personalDeviceState(key, reg.userId))
        engine.hydrate()
        assertEquals(Account.PersonalStatus.WITHHELD, again.personalStatus)
        assertEquals(reg.personalVault.vaultId, again.personalVaultId)
        assertNull(engine.personalVaultChoices, "no migration question over a withheld wrap")
        assertTrue(File(store2.nsDir(key, reg.userId), io.silencelen.andvari.core.client.FileDeviceState.FILE_NAME).exists())
    }
}
