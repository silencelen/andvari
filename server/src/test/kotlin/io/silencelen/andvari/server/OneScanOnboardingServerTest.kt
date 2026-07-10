package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * S4 one-scan-onboarding server slice (design 2026-07-10 §Server work):
 *  1. `InviteRequest.ttlMinutes` → createInvite clamps to [5 min, 72 h]; absent → 72 h.
 *     The clamp is the SOLE containment for a photographed QR (no invite revoke surface).
 *  2. `/.well-known/assetlinks.json` is served as application/json by the SPA catch-all
 *     (a real file under webDir), NOT swallowed by the index.html fallback.
 */
class OneScanOnboardingServerTest : P4TestSupport() {

    private val hour72Ms = 72L * 3600 * 1000

    @Test
    fun inviteTtlClampBounds() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken)

        // Mint an invite bracketing the call with local now(); the server's expiresAt is
        // minted from the same clock, so expiresAt - expectedTtl must land in [before, after].
        suspend fun mint(email: String, ttlMinutes: Int?): Triple<Long, InviteResponse, Long> {
            val before = now()
            val resp = client.post("/api/v1/admin/users") {
                contentType(ContentType.Application.Json); authed(admin)
                setBody(InviteRequest(email, isAdmin = false, ttlMinutes = ttlMinutes))
            }
            val after = now()
            assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            return Triple(before, json.decodeFromString(InviteResponse.serializer(), resp.bodyAsText()), after)
        }

        fun assertTtl(case: String, minted: Triple<Long, InviteResponse, Long>, expectedTtlMs: Long) {
            val (before, invite, after) = minted
            assertTrue(
                invite.expiresAt in (before + expectedTtlMs)..(after + expectedTtlMs),
                "$case: expiresAt=${invite.expiresAt} outside [${before + expectedTtlMs}, ${after + expectedTtlMs}]",
            )
        }

        assertTtl("null → 72 h default", mint("a@x.com", null), hour72Ms)
        assertTtl("1 → clamped to the 5 min floor", mint("b@x.com", 1), 5 * 60_000L)
        assertTtl("99999 → clamped to the 72 h ceiling", mint("c@x.com", 99_999), hour72Ms)
        assertTtl("60 → honored as-is", mint("d@x.com", 60), 60 * 60_000L)

        // Legacy wire shape (pre-S4 clients): no ttlMinutes key at all → 72 h, additive-safe.
        val before = now()
        val legacy = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody("""{"email":"e@x.com","isAdmin":false}""")
        }
        val after = now()
        assertEquals(HttpStatusCode.OK, legacy.status, legacy.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), legacy.bodyAsText())
        assertTrue(invite.expiresAt in (before + hour72Ms)..(after + hour72Ms), "legacy body must keep the 72 h TTL")
    }

    /**
     * The benign two-device race the QR UX now invites (two family devices scanning the same
     * QR) must never double-spend one invite. The property is structurally guaranteed —
     * register's lookup, usedAt check, and `UPDATE invites SET usedAt` all run in one
     * repo.db.tx and Db serializes every tx on one connection behind a ReentrantLock — but it
     * was untested (design §Tests & gates ordered this regression net). A second redeem of the
     * same token must fail invite_used (checked inside that tx, ahead of email_taken).
     */
    @Test
    fun inviteIsSingleUse_secondRedeemRejected() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken)

        val mint = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(InviteRequest("member@x.com", isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, mint.status, mint.bodyAsText())
        val token = json.decodeFromString(InviteResponse.serializer(), mint.bodyAsText()).inviteToken

        // First redemption succeeds (the helper asserts 200 and consumes the invite).
        client.register(VirtualClient("member@x.com", "member password value"), token)

        // Second redemption of the SAME token, SAME bound email (else invite_email_mismatch
        // would mask the property), fresh userId → invite_used. Raw post keeps the response.
        val second = VirtualClient("member@x.com", "another password value")
        val resp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(second.buildRegister(token, recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.BadRequest, resp.status, resp.bodyAsText())
        assertEquals("invite_used", errorOf(resp))
    }

    @Test
    fun assetlinksServedAsJson_notSpaFallback() = testApplication {
        // Pin the REAL shipped artifact: web/public/ is vite's default publicDir, copied
        // verbatim into dist/ — which is what ANDVARI_WEB_DIR serves in production. Walking
        // up from the test working dir keeps this immune to gradle workingDir differences.
        val shipped = generateSequence(File("").absoluteFile) { it.parentFile }
            .map { File(it, "web/public/.well-known/assetlinks.json") }
            .firstOrNull { it.isFile }
            ?: error("web/public/.well-known/assetlinks.json missing from the repo")

        val webRoot = File(tmpDir, "web-${System.nanoTime()}")
        File(webRoot, ".well-known").mkdirs()
        File(webRoot, ".well-known/assetlinks.json").writeText(shipped.readText())
        File(webRoot, "index.html").writeText("<!doctype html><div id=\"spa-marker\"></div>")

        val cfg = Config(
            host = "127.0.0.1", port = 0,
            dbPath = File(tmpDir, "al-${System.nanoTime()}.db").absolutePath,
            blobDir = File(tmpDir, "al-blobs-${System.nanoTime()}").absolutePath,
            webDir = webRoot.absolutePath,
            recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
            enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
        )
        application { andvariModule(buildServices(cfg, Notifier())) }

        val resp = client.get("/.well-known/assetlinks.json")
        assertEquals(HttpStatusCode.OK, resp.status)
        assertEquals(
            ContentType.Application.Json, resp.contentType()?.withoutParameters(),
            "assetlinks.json must be served as application/json, not the SPA fallback",
        )
        val body = resp.bodyAsText()
        assertTrue(body.contains("\"com.silencelen.andvari\""), "package_name must be the applicationId")
        assertTrue(body.contains("delegate_permission/common.handle_all_urls"))
        assertFalse(body.contains("spa-marker"), "must not be the index.html fallback")

        // And the fallback DOES fire for SPA routes — proves the distinction above is live.
        val spa = client.get("/enroll")
        assertEquals(HttpStatusCode.OK, spa.status)
        assertEquals(ContentType.Text.Html, spa.contentType()?.withoutParameters())
        assertTrue(spa.bodyAsText().contains("spa-marker"))
    }
}
