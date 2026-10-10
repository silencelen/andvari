package io.silencelen.andvari.server

import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (server F2): `seedBootstrap` skipped minting only when
 * ANDVARI_BOOTSTRAP_TOKEN was ABSENT. A present-but-empty value — exactly what the shipped env
 * template line produces, and the state the self-hosting docs tell operators to leave after the
 * first enrollment — minted an admin, any-email invite stored as sha256(""), which the
 * unauthenticated register route then matched for `inviteToken: ""`. On a fresh or wiped
 * instance, whoever registered first became the admin.
 *
 * Now: blank = unset (no invite, loud boot line), non-blank-but-short = refuse to start (the
 * ANDVARI_ENUM_SECRET pattern), and register refuses a short invite token before any lookup, so
 * an sha256("") row an older server already minted is unredeemable too.
 */
class BootstrapTokenTest : P4TestSupport() {

    private val secret = Bytes.toB64(ByteArray(32) { 1 })
    private fun envOf(vararg pairs: Pair<String, String>): (String) -> String? {
        val m = mapOf("ANDVARI_ENUM_SECRET" to secret, *pairs)
        return { name -> m[name] }
    }

    @Test
    fun fromEnv_blankToken_isTreatedAsUnset() {
        assertNull(Config.fromEnv(envOf("ANDVARI_BOOTSTRAP_TOKEN" to "")).bootstrapToken)
        assertNull(Config.fromEnv(envOf("ANDVARI_BOOTSTRAP_TOKEN" to "   ")).bootstrapToken)
        assertNull(Config.fromEnv(envOf()).bootstrapToken)
    }

    @Test
    fun fromEnv_shortToken_refusesToStart() {
        val e = assertFailsWith<IllegalStateException> {
            Config.fromEnv(envOf("ANDVARI_BOOTSTRAP_TOKEN" to "letmein"))
        }
        assertTrue(e.message!!.contains("ANDVARI_BOOTSTRAP_TOKEN"), e.message)
    }

    @Test
    fun fromEnv_bringupShapedToken_isKept() {
        // deploy/bringup.sh mints `gen_secret 24` = 24 random bytes → 32 base64url chars.
        val token = Bytes.toB64(ByteArray(24) { (it * 7).toByte() })
        assertEquals(token, Config.fromEnv(envOf("ANDVARI_BOOTSTRAP_TOKEN" to token)).bootstrapToken)
    }

    @Test
    fun blankTokenOnAFreshInstance_mintsNoInvite_andEmptyInviteIsRefused() = testApplication {
        // A Config built directly (not via fromEnv) can still carry "" — seedBootstrap must not
        // trust that fromEnv normalised it.
        val cfg = config().let {
            Config(
                host = it.host, port = 0, dbPath = it.dbPath, blobDir = it.blobDir, webDir = null,
                recoveryPublicKey = it.recoveryPublicKey, recoveryFingerprint = it.recoveryFingerprint,
                enumSecret = it.enumSecret, publicHostname = null, bootstrapToken = "",
            )
        }
        val services = buildServices(cfg, Notifier())
        val invites = services.repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM invites") { it.getInt(1) } }
        assertEquals(0, invites, "a blank bootstrap token must not mint an admin invite")

        application { andvariModule(services) }
        val client = jsonClient(this)
        val resp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(VirtualClient("squatter@x.com", "first come first served").buildRegister("", recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.BadRequest, resp.status, resp.bodyAsText())
        assertEquals("invalid_invite", errorOf(resp))
    }

    @Test
    fun anEmptyTokenInviteAlreadyInTheDb_cannotBeRedeemed() = testApplication {
        // An instance first booted by an OLDER server with a blank token already holds the
        // sha256("") admin invite. Upgrading must not leave it redeemable.
        val services = buildServices(config(), Notifier())
        services.repo.db.tx { c ->
            c.exec("DELETE FROM invites")
            c.exec(
                "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt) VALUES(?,?,1,?,?)",
                ServerCrypto.hashToken(""), BOOTSTRAP_ANY_EMAIL, now(), now() + 3_600_000,
            )
        }
        application { andvariModule(services) }
        val client = jsonClient(this)
        val resp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(VirtualClient("legacy@x.com", "legacy empty invite pw").buildRegister("", recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.BadRequest, resp.status, resp.bodyAsText())
        assertEquals("invalid_invite", errorOf(resp))
        val users = services.repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM users") { it.getInt(1) } }
        assertEquals(0, users)
    }

    @Test
    fun aRealTokenStillBootstraps() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val s = client.register(VirtualClient("admin@x.com", "real bootstrap admin pw"), bootstrapToken)
        assertTrue(s.isAdmin)
    }
}
