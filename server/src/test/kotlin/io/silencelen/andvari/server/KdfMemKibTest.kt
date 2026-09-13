package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.ClientPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * H16 (audit 2026-09-13): the server-side half of the Argon2id KiB-multiple rule (spec 01 §1).
 * libsodium floors memlimit to KiB; @noble's argon2id (the extension) requires an integer `m` in
 * KiB — the two engines agree only when memBytes is a multiple of 1024. Nothing in the hierarchy
 * used to constrain it: an admin who PUT "100 MB" (100000000) produced a fleet where web/Android/
 * desktop derived the floored key and the extension could never sign in, blaming the user. The
 * extension now floors too; this pins the DEFENCE IN DEPTH — the value can no longer be PERSISTED
 * on any path that sets it: the org policy, and every password-set path via requireKdfFloor.
 */
class KdfMemKibTest : P4TestSupport() {

    @Test
    fun adminPolicy_refusesNonKibMemBytes_andPersistsNothing() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "kib multiple password one", fast = true)
        client.register(admin, bootstrapToken)

        suspend fun putPolicy(memBytes: Long) = client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(ClientPolicy(kdfParams = KdfParams(ops = 3, memBytes = memBytes)))
        }
        suspend fun storedMemBytes(): Long {
            val resp = client.get("/api/v1/admin/policy") { authed(admin) }
            return json.decodeFromString(ClientPolicy.serializer(), resp.bodyAsText()).kdfParams.memBytes
        }

        // "100 MB" — in range for every fence (64 MiB..1 GiB), fatal for the extension. Refused
        // with its OWN reason: the admin needs to know it is the shape, not the strength.
        val bad = putPolicy(100_000_000)
        assertEquals(HttpStatusCode.BadRequest, bad.status, bad.bodyAsText())
        assertEquals("kdf_mem_not_kib_multiple", errorOf(bad))
        assertEquals(KdfParams.DEFAULT.memBytes, storedMemBytes(), "a refused policy must not be persisted")

        // Off by one byte is the same refusal — the rule is divisibility, not magnitude.
        assertEquals("kdf_mem_not_kib_multiple", errorOf(putPolicy(67_108_865)))

        // A KiB multiple that is not the default persists normally (the rule is not "default only").
        val ok = putPolicy(67_108_864 + 1024)
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        assertEquals(67_108_864L + 1024, storedMemBytes())
    }

    @Test
    fun passwordSetPath_refusesNonKibMemBytes_beforeAnyWrite() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "kib password change one", fast = true)
        client.register(admin, bootstrapToken)

        val req = admin.buildPasswordChange("kib password change two").copy(newKdfParams = KdfParams(ops = 3, memBytes = 67_108_865))
        val resp = client.put("/api/v1/account/password") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(req)
        }
        assertEquals(HttpStatusCode.BadRequest, resp.status, resp.bodyAsText())
        assertEquals("kdf_mem_not_kib_multiple", errorOf(resp))
        assertTrue(client.auditRows(admin, "password_change").isEmpty(), "refused before the verifier/UVK write")
    }

    /** The shared gate itself: the floor passes, the KiB rule is the second check, and the test
     *  config's floor of 0/0 does not switch it off (it is a shape rule, not a strength floor). */
    @Test
    fun requireKdfFloor_carriesTheKibRule() {
        requireKdfFloor(KdfParams.DEFAULT, config())
        requireKdfFloor(KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), config())
        val e = assertFailsWith<BadRequest> { requireKdfFloor(KdfParams(ops = 3, memBytes = 100_000_000), config()) }
        assertEquals("kdf_mem_not_kib_multiple", e.reason)
    }
}
