package io.silencelen.andvari.server

import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.WireJson
import java.io.File
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Slice 1: the fresh baseline (design §14.3), the boot rules (spec 03 §1.1, §14.4), the generic plumbing (§0.1). */
class BaselineTest {
    @Test
    fun freshBaseline_andRefusalOfAPreCutOverDatabase() {
        val dir = TestKit.tempDir()
        Db(File(dir, "new.db").path).use { db ->
            assertEquals(Db.BASELINE, db.read { c -> c.queryOne("SELECT value FROM meta WHERE key='baseline'") { it.getString(1) } })
        }
        // Reopening the same file is fine.
        Db(File(dir, "new.db").path).close()
        // A database a 0.x build made: a meta table with schemaVersion and no baseline marker.
        val old = File(dir, "old.db").path
        DriverManager.getConnection("jdbc:sqlite:$old").use { c ->
            c.createStatement().use { st ->
                st.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                st.execute("INSERT INTO meta VALUES('schemaVersion','17')")
                st.execute("CREATE TABLE users(userId TEXT PRIMARY KEY)")
            }
        }
        val e = assertFailsWith<IncompatibleDatabase> { Db(old) }
        assertEquals(Db.OLD_DATABASE_MESSAGE, e.message)
    }

    @Test
    fun bootRules() {
        val ok = TestKit.config()
        assertEquals("members", ok.registerLinks)
        assertEquals("operator", TestKit.config(kind = "public").registerLinks)
        // A public instance can never carry a recovery key (variant R by configuration).
        assertFailsWith<ConfigError> { TestKit.config(kind = "public", recoveryKey = ByteArray(32) { 1 }) }
        // Test mode only on a loopback origin; an https origin needs HSTS; open needs mail.
        assertFailsWith<ConfigError> {
            Config(dbPath = "x", blobDir = "y", canonicalOrigin = "https://vault.example.com", enumSecret = ByteArray(32), testMode = true, forceHsts = true)
        }
        assertFailsWith<ConfigError> { Config(dbPath = "x", blobDir = "y", canonicalOrigin = "https://vault.example.com", enumSecret = ByteArray(32)) }
        assertFailsWith<ConfigError> {
            Config(dbPath = "x", blobDir = "y", canonicalOrigin = "https://vault.example.com", enumSecret = ByteArray(32), forceHsts = true, signupMode = "open", signupSecret = ByteArray(32))
        }
        assertFailsWith<ConfigError> { Config(dbPath = "x", blobDir = "y", canonicalOrigin = "https://Vault.example.com/", enumSecret = ByteArray(32), forceHsts = true) }
        assertFailsWith<ConfigError> { Config(dbPath = "x", blobDir = "y", canonicalOrigin = "http://127.0.0.1:8080", enumSecret = ByteArray(32), mailSinkDir = "/tmp/x") }
        // A fingerprint that is not the key's own SHA-256.
        assertFailsWith<ConfigError> {
            Config(dbPath = "x", blobDir = "y", canonicalOrigin = "http://127.0.0.1:8080", enumSecret = ByteArray(32), recoveryPublicKey = ByteArray(32), recoveryFingerprint = "0".repeat(64))
        }
        assertTrue(Config.envLint(mapOf("ANDVARI_PUBLIC_HOSTNAME" to "x", "ANDVARI_SIGNUP_MODE" to "landing")).size == 2)
    }

    /**
     * Row 91 serves every file directly inside the downloads directory to anyone, so the server refuses to boot with it
     * pointed at the directory that holds the database or at the blob directory, by any spelling or through a link.
     */
    @Test
    fun bootRules_theDownloadsDirectoryNeverHoldsTheDatabaseOrTheBlobs() {
        val dir = TestKit.tempDir()
        fun cfg(downloads: String?) = TestKit.config(dir = dir, downloadsDir = downloads)
        for (bad in listOf(dir.path, "${dir.path}/", "${dir.path}/blobs/../.", File(dir, "blobs").path)) {
            assertFailsWith<ConfigError>(bad) { cfg(bad) }
        }
        val link = File(TestKit.tempDir(), "dl")
        java.nio.file.Files.createSymbolicLink(link.toPath(), dir.toPath())
        assertFailsWith<ConfigError> { cfg(link.path) }
        // A directory of its own (the deploy template's /data/downloads beside the database) is fine.
        assertEquals(File(dir, "downloads").path, cfg(File(dir, "downloads").path).downloadsDir)
        // A blank value is no downloads directory at all (row 91 absent), as an unset one is.
        val env = mapOf("ANDVARI_CANONICAL_ORIGIN" to "http://127.0.0.1:8080", "ANDVARI_ENUM_SECRET" to "A".repeat(43), "ANDVARI_DOWNLOADS_DIR" to " ")
        assertEquals(null, Config.fromEnv { env[it] }.downloadsDir)
    }

    @Test
    fun clientPolicy_carriesTheEffectiveSignupStance() = testApplication {
        val s = TestKit.services(TestKit.config(mode = "open", requireAgeConfirm = true, powBits = 12, signupCap = 1))
        application { andvariModule(s) }
        val p = WireJson.json.decodeFromString(ClientPolicy.serializer(), client.call(HttpMethod.Get, "/api/v1/client-policy").bodyAsText())
        assertEquals("open", p.signup.mode)
        assertFalse(p.signup.full)
        assertTrue(p.signup.ageConfirmRequired)
        assertEquals(12, p.signup.powBits)
        assertEquals("http://127.0.0.1:8080", p.canonicalOrigin)
        assertEquals("http://127.0.0.1:8080/selfhost", p.selfHostDocsUrl)
        TestKit.seedAccount(s, "a@example.com")
        val p2 = WireJson.json.decodeFromString(ClientPolicy.serializer(), client.call(HttpMethod.Get, "/api/v1/client-policy").bodyAsText())
        assertTrue(p2.signup.full)
        // The operator account does not count against the cap.
        val s2 = TestKit.services(TestKit.config(signupCap = 1))
        TestKit.seedAccount(s2, "op@example.com", role = "operator")
        assertFalse(s2.db.read { s2.policy.signupFull(it) })
    }

    @Test
    fun genericPlumbing_bodyCap_unknownApiPath_rateBucket_securityHeaders() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val big = client.call(HttpMethod.Put, "/api/v1/instance/card", "{\"card\":\"${"x".repeat(300 * 1024)}\"}")
        assertEquals(413, big.status.value)
        assertEquals("body_too_large", big.errorCode())
        val unknown = client.call(HttpMethod.Get, "/api/v1/no-such-route")
        assertEquals(404, unknown.status.value)
        assertEquals("not_found", unknown.errorCode())
        repeat(60) { assertEquals(200, client.call(HttpMethod.Get, "/api/v1/client-policy", ip = "10.9.9.9").status.value) }
        val limited = client.call(HttpMethod.Get, "/api/v1/client-policy", ip = "10.9.9.9")
        assertEquals(429, limited.status.value)
        assertEquals("rate_limited", limited.errorCode())
        assertTrue((limited.headers["Retry-After"]?.toLong() ?: 0) >= 1)
        assertEquals("nosniff", limited.headers["X-Content-Type-Options"])
        assertEquals("ok", client.call(HttpMethod.Get, "/healthz").bodyAsText())
        assertTrue(client.call(HttpMethod.Get, "/robots.txt").bodyAsText().contains("Disallow: /"))
        // /metrics refuses anything that came through a front.
        assertEquals(403, client.call(HttpMethod.Get, "/metrics").status.value)
    }

    @Test
    fun minVersionPin_answers426OnVersionCheckedRoutes() = testApplication {
        val s = TestKit.services()
        s.db.tx { c -> s.policy.storeOn(c, s.policy.defaults().copy(minVersion = mapOf("linux" to "2.0.0"))) }
        application { andvariModule(s) }
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        // PUT /instance/card is not V: no pin applies. GET /client-policy is not V either.
        assertEquals(200, client.call(HttpMethod.Get, "/api/v1/client-policy", client = "linux/1.0.0").status.value)
        assertEquals("reauth_failed", client.call(HttpMethod.Put, "/api/v1/instance/card", """{"card":"AAAA","currentAuthKey":"AAAA"}""", TestKit.session(s, op), client = "linux/1.0.0").errorCode())
    }
}
