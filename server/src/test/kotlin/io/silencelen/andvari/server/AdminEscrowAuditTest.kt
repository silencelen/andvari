package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.RecoveryUpload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * H61 (audit 2026-09-13): the two admin-recovery legs that fell outside their siblings' rules.
 * (1) `GET /admin/users/{id}/escrow` — step 1 of the takeover-capable ceremony (spec 04 §4) —
 * wrote no audit row although spec 03 §7 says every admin call is audited, so an operator
 * reviewing GET /admin/audit after a suspected admin-session hijack could not see whose sealed
 * blobs were pulled (trail completeness: the blob is useless without the offline sheet).
 * (2) `POST /admin/recovery` runs a memory-hard argon2 (hashVerifier) with no bucket while
 * PUT /account/password earned one for exactly that cost (bug-server--5).
 */
class AdminEscrowAuditTest : P4TestSupport() {

    @Test
    fun escrowRead_isAudited_hitAndMiss() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "escrow audit password one", fast = true)
        client.register(admin, bootstrapToken) // required-escrow bootstrap ⇒ the admin has a blob

        // Hit: the row names the ACTING admin and carries the TARGET in meta.
        val hit = client.get("/api/v1/admin/users/${admin.userId}/escrow") { authed(admin) }
        assertEquals(HttpStatusCode.OK, hit.status, hit.bodyAsText())
        val rows = client.auditRows(admin, "escrow_admin_read")
        assertEquals(1, rows.size, "$rows")
        assertEquals(admin.userId, rows.single().userId, "the acting admin")
        assertEquals(admin.userId, rows.single().meta, "the target member")
        assertNull(rows.single().deviceId, "same shape as the other admin rows (user_disable, recovery_apply)")

        // Miss: a pull for a member with no blob (or no such member) is still an ATTEMPT — the
        // interesting event for a hijack review — so it is recorded before the 404.
        val ghost = "00000000-0000-4000-8000-000000000000"
        val miss = client.get("/api/v1/admin/users/$ghost/escrow") { authed(admin) }
        assertEquals(HttpStatusCode.NotFound, miss.status)
        val after = client.auditRows(admin, "escrow_admin_read")
        assertEquals(2, after.size)
        assertEquals(ghost, after.first().meta, "newest first — the miss carries the id that was asked for")

        // A malformed id never reaches the audit (it is refused as a 400 before the route body).
        assertEquals(HttpStatusCode.BadRequest, client.get("/api/v1/admin/users/123/escrow") { authed(admin) }.status)
        assertEquals(2, client.auditRows(admin, "escrow_admin_read").size)
    }

    @Test
    fun recoveryApply_isRateBucketed_perAdmin() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "recovery bucket password one", fast = true)
        client.register(admin, bootstrapToken)

        suspend fun post() = client.post("/api/v1/admin/recovery") {
            contentType(ContentType.Application.Json); authed(admin)
            // A well-formed bundle for a member that does not exist: the floor passes, the argon2
            // runs, the lookup fails — exactly the loop a hijacked session could otherwise spin.
            setBody(RecoveryUpload("00000000-0000-4000-8000-000000000000", "AA", "AA", "AA", KdfParams.DEFAULT))
        }
        repeat(5) {
            val r = post()
            assertEquals(HttpStatusCode.BadRequest, r.status, r.bodyAsText())
            assertEquals("no_such_user", errorOf(r))
        }
        val sixth = post()
        assertEquals(HttpStatusCode.TooManyRequests, sixth.status, "5/min per admin, the password_change shape")
        assertEquals("rate_limited", errorOf(sixth))
    }
}
