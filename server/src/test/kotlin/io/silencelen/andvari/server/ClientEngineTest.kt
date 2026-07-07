package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.LoginRequest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Drives the REAL Kotlin client stack (Account + AndvariApi + SyncEngine) against an
 * in-process server — the P2 counterpart to the web live-e2e. Proves the native
 * client is wire- and crypto-compatible with the server and the web client. The ktor
 * test `client` resolves relative URLs to the in-process host, so baseUrl = "".
 */
class ClientEngineTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "client-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-client-it").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "c-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 3 }, publicHostname = null, bootstrapToken = bootstrap,
    )

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    @Test
    fun kotlinClient_enroll_save_freshDeviceUnlock() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }

        val api = AndvariApi("", createClient { })
        val policy = api.clientPolicy()
        assertEquals(fingerprint, policy.recoveryFingerprint)
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())

        val password = "kotlin client password 123"
        val (req, account) = Account.enroll(
            inviteToken = bootstrap,
            email = "kc@x.com",
            displayName = "KC",
            password = password,
            params = policy.kdfParams,
            recoveryPublicKey = recoveryPub,
            recoveryFingerprint = policy.recoveryFingerprint,
            deviceName = "kc-device",
            crypto = crypto,
        )
        api.register(req)
        val engineA = SyncEngine(api, account, InMemoryVaultCache())
        engineA.sync()

        engineA.save(null, ItemDoc(type = "login", name = "GitHub", login = LoginData(username = "jacob", password = "s3cret")))
        engineA.save(null, ItemDoc(type = "note", name = "Note", notes = "hello"))
        assertEquals(2, engineA.items().size)

        // Fresh device: only password + account keys → reconstruct + decrypt.
        val api2 = AndvariApi("", createClient { })
        val pre = api2.prelogin("kc@x.com")
        val authKey = Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams, crypto)
        val s2 = api2.login(LoginRequest("kc@x.com", authKey, Account.deviceInfo("fresh")))
        val account2 = Account.unlock(s2.userId, password, s2.accountKeys, crypto)
        val engineB = SyncEngine(api2, account2, InMemoryVaultCache())
        engineB.sync()

        val gh = engineB.items().find { it.doc.name == "GitHub" }
        assertTrue(gh != null && gh.doc.login?.password == "s3cret", "fresh device decrypted the item")
    }

    @Test
    fun offlineQueueSurvivesAndFlushes() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val api = AndvariApi("", createClient { })
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            "client-bootstrap", "q@x.com", "Q", "queue password value",
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "q-device", crypto,
        )
        api.register(req)
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(api, account, cache)
        engine.sync()

        engine.save(null, ItemDoc(type = "note", name = "queued"))
        assertTrue(cache.pending().isEmpty(), "queue drains after a successful push")
        assertEquals(1, engine.items().size)
    }

    @Test
    fun csvImport_multiChunk_freshDeviceDecrypts() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val api = AndvariApi("", createClient { })
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            "client-bootstrap", "csv@x.com", "CSV", "csv import password value",
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "csv-device", crypto,
        )
        api.register(req)
        val engine = SyncEngine(api, account, InMemoryVaultCache())
        engine.sync()

        // 250 rows (forces >1 chunk at the 200 cap) + one exact dupe that must collapse.
        val header = "name,url,username,password,note\n"
        val body = buildString {
            for (i in 0 until 250) append("site$i,https://s$i.test,user$i,pw$i,\n")
            append("site0,https://s0.test,user0,pw0,\n") // exact dupe of row 0 → collapsed
        }
        val plan = CsvImport.plan(CsvImport.parse((header + body).encodeToByteArray())) { account.newItemId() }
        assertEquals(250, plan.items.size)
        assertEquals(1, plan.report.collapsed)
        engine.importAll(plan.items)
        assertEquals(250, engine.items().size)

        // Re-running the SAME plan is idempotent (stable mutationIds) — no duplicates.
        engine.importAll(plan.items)
        assertEquals(250, engine.items().size, "re-running the same import plan must not duplicate")

        // A fresh device decrypts every imported item.
        val api2 = AndvariApi("", createClient { })
        val pre = api2.prelogin("csv@x.com")
        val s2 = api2.login(LoginRequest("csv@x.com", Account.deriveAuthKey("csv import password value", pre.kdfSalt, pre.kdfParams, crypto), Account.deviceInfo("fresh")))
        val account2 = Account.unlock(s2.userId, "csv import password value", s2.accountKeys, crypto)
        val engine2 = SyncEngine(api2, account2, InMemoryVaultCache())
        engine2.sync()
        assertEquals(250, engine2.items().size, "fresh device pulled + decrypted all imported items")
        assertTrue(engine2.items().any { it.doc.login?.password == "pw123" })
    }

    /**
     * spec 02 §3 + spec 03 §5: conflict materialization must not strip unknown fields.
     * A doc written by a "future" client (unknown keys at top, login, and history-entry
     * level) goes through the REAL conflict path — stale edit → server flags → engine
     * materializes copy + flag-clear rewrite — and BOTH pushed mutations must still
     * carry the unknowns when decrypted.
     */
    @Test
    fun conflictMaterialization_preservesUnknownFields() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val api = AndvariApi("", createClient { })
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            "client-bootstrap", "cf@x.com", "CF", "conflict unknown password",
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "cf-device", crypto,
        )
        api.register(req)
        val engineA = SyncEngine(api, account, InMemoryVaultCache())
        engineA.sync()

        // As decoded from a future client's plaintext (Account's json config shape).
        val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        val futureDoc = json.decodeFromString(
            ItemDoc.serializer(),
            """{"type":"login","name":"Future","x-top":{"a":1},
                "login":{"username":"u","password":"p1","x-flag":true,
                         "passwordHistory":[{"password":"p0","retiredAt":1690000000000,"x-hist":"h"}]}}""",
        )
        engineA.save(null, futureDoc)
        val itemId = engineA.items().single().itemId

        // "Device B": second engine over an independent cache, synced to the same rev.
        val engineB = SyncEngine(api, account, InMemoryVaultCache())
        engineB.sync()

        // A advances the item; B then edits from its now-STALE base rev → server flags
        // the item, and B's post-push pull materializes the conflict (copy + flag-clear).
        engineA.save(itemId, engineA.item(itemId)!!.doc.copy(name = "Future v2"))
        engineB.save(itemId, engineB.item(itemId)!!.doc.copy(name = "Future stale"))

        // Decrypt both pushed mutations through a plain pull on engine A.
        engineA.sync()
        val rewrite = engineA.item(itemId)
        val copy = engineA.items().singleOrNull { it.doc.name.contains("(conflict ") }
        assertNotNull(rewrite, "flag-clear rewrite still present")
        assertNotNull(copy, "conflict copy materialized")
        for ((label, doc) in listOf("copy" to copy.doc, "rewrite" to rewrite.doc)) {
            assertEquals(buildJsonObject { put("a", 1) }, doc.extras["x-top"], "$label lost top-level unknown")
            assertEquals(JsonPrimitive(true), doc.login?.extras?.get("x-flag"), "$label lost login-level unknown")
            assertEquals(JsonPrimitive("h"), doc.login?.passwordHistory?.single()?.extras?.get("x-hist"), "$label lost history-entry unknown")
        }
    }
}
