package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.LoginRequest
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Drives the real :core client on the DURABLE SqliteVaultCache against an in-process
 * server, proving the offline-cache invariants that only surface across a simulated
 * "process death": cold-start reconstruction from cached rows (grants are pull deltas),
 * queue survival, transactional 410 resync, and the rev-regression guard.
 */
class DurableCacheEngineTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "durable-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-durable").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "srv-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 5 }, publicHostname = null, bootstrapToken = bootstrap,
    )

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    private suspend fun enroll(api: AndvariApi, email: String, password: String): Account {
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            bootstrap, email, email.substringBefore('@'), password,
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "device", crypto,
        )
        api.register(req)
        return account
    }

    @Test
    fun coldStartWithCursor_reconstructsFromCache_withoutGrantResend() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val dbPath = File(tmp, "cold-cache.db").absolutePath
        val password = "durable cold start password"

        // Session 1: enroll + save 2 items on a durable cache; record the cursor.
        val api1 = AndvariApi("", createClient { })
        val account1 = enroll(api1, "cold@x.com", password)
        val userId = account1.userId
        val cache1 = sqliteVaultCache(dbPath, userId)
        val engine1 = SyncEngine(api1, account1, cache1).also { it.hydrate() }
        engine1.sync()
        engine1.save(null, ItemDoc(type = "note", name = "one"))
        engine1.save(null, ItemDoc(type = "note", name = "two"))
        val cursor = cache1.cursor()
        assertTrue(cursor > 0)
        engine1.close() // "process death"

        // The server sends grants/vaults only as deltas: pulling from `cursor` returns NONE.
        val probe = AndvariApi("", createClient { })
        val pre = probe.prelogin("cold@x.com")
        val s = probe.login(LoginRequest("cold@x.com", Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams, crypto), Account.deviceInfo("probe")))
        val delta = probe.sync(cursor)
        assertTrue(delta.grants.isEmpty() && delta.vaults.isEmpty(), "grants/vaults are deltas — none re-sent past the cursor")

        // Session 2 ("relaunch"): fresh Account.unlock + a NEW cache on the SAME file +
        // hydrate() → the vault is rebuilt from cached rows BEFORE any network sync, and a
        // 3rd save works (proves personalVaultId + VK came purely from the cache).
        val account2 = Account.unlock(userId, password, s.accountKeys, crypto)
        val cache2 = sqliteVaultCache(dbPath, userId)
        val engine2 = SyncEngine(probe, account2, cache2).also { it.hydrate() }
        assertEquals(2, engine2.items().size, "cold-start hydrate rebuilt the working set offline")
        engine2.save(null, ItemDoc(type = "note", name = "three")) // needs a VK for the personal vault
        assertEquals(3, engine2.items().size)
        engine2.close()
    }

    @Test
    fun queueSurvivesProcessDeath_thenFlushes() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val dbPath = File(tmp, "queue-cache.db").absolutePath
        val password = "durable queue password value"

        val api1 = AndvariApi("", createClient { })
        val account = enroll(api1, "queue@x.com", password)
        val cache1 = sqliteVaultCache(dbPath, account.userId)
        val engine1 = SyncEngine(api1, account, cache1).also { it.hydrate() }
        engine1.sync()
        // Enqueue WITHOUT flushing (simulate crash-before-send), then "die".
        cache1.enqueue(engine1.putMutation(account.newItemId(), account.personalVaultId, ItemDoc(type = "note", name = "pending"), 0))
        assertEquals(1, cache1.pending().size)
        engine1.close()

        // Reopen the cache from the file with a fresh engine → sync flushes the queue.
        val cache2 = sqliteVaultCache(dbPath, account.userId)
        val engine2 = SyncEngine(api1, account, cache2).also { it.hydrate() }
        engine2.sync()
        assertTrue(cache2.pending().isEmpty(), "queued mutation flushed after process death")
        assertTrue(engine2.items().any { it.doc.name == "pending" })
        engine2.close()
    }

    @Test
    fun resync410_repopulatesAndKeepsQueue() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val dbPath = File(tmp, "resync-cache.db").absolutePath
        val password = "durable resync password value"

        val api = AndvariApi("", createClient { })
        val account = enroll(api, "resync@x.com", password)
        val cache = sqliteVaultCache(dbPath, account.userId)
        val engine = SyncEngine(api, account, cache).also { it.hydrate() }
        engine.save(null, ItemDoc(type = "note", name = "kept"))
        assertEquals(1, engine.items().size)

        // Force the server to 410 the client's cursor (its cursor now predates retained history),
        // and queue a mutation that must survive the resync and flush on top.
        services.repo.setMeta("oldestRetainedRev", (cache.cursor() + 1).toString())
        cache.enqueue(engine.putMutation(account.newItemId(), account.personalVaultId, ItemDoc(type = "note", name = "queued-through-resync"), 0))
        engine.sync() // flushQueue (drains the queued one) → pull → 410 → transactional full re-pull

        assertTrue(cache.pending().isEmpty())
        val names = engine.items().map { it.doc.name }.toSet()
        assertTrue(names.contains("kept") && names.contains("queued-through-resync"), "resync rebuilt items + kept-queue flushed: $names")
        engine.close()
    }

    @Test
    fun revRegressionGuard_keepsLocalState() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val api = AndvariApi("", createClient { })
        val account = enroll(api, "rev@x.com", "durable rev guard password")
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(api, account, cache).also { it.hydrate() }
        engine.save(null, ItemDoc(type = "note", name = "local"))
        val realCursor = cache.cursor()

        // Jam the cursor far ahead: a normal (non-full) pull now returns rev < cursor → guard trips.
        cache.setCursor(realCursor + 1000)
        val e = assertFailsWith<ApiException> { engine.sync() }
        assertEquals("rev_regression", e.code)
        assertEquals(realCursor + 1000, cache.cursor(), "cursor untouched by a rejected rollback")
        assertTrue(engine.items().any { it.doc.name == "local" }, "local state kept")
    }
}
