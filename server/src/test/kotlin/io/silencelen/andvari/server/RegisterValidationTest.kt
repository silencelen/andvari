package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.AdminUserSummary
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.RegisterRequest
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * H62 (audit 2026-09-13): register() persisted vaultId, metaBlob, wrappedVk, wrappedUvk,
 * identityPub, encryptedIdentitySeed, displayName and the device name/platform with no shape or
 * size gate — the same fields createSharedVault UUID-checks and requireB64-bounds — so under the
 * 256 KiB body cap an invitee could park ~250 KB of text in a name the Admin console and every
 * co-member's list render, persist an UPPERCASE personal vaultId that later fails requireUuid on
 * the attachment upload route (attachments silently unusable for that account), or collide with
 * an existing vaultId and surface a logged 500 from the PRIMARY KEY instead of a 400. Every
 * refusal here is a pre-flight (the invite is not consumed), so one invite serves every case and
 * is finally redeemed by the well-formed body.
 */
class RegisterValidationTest : P4TestSupport() {

    @Test
    fun register_refusesMalformedOrOversizedFields_asFourHundreds() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "register validation password", fast = true)
        client.register(admin, bootstrapToken)

        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(InviteRequest("newbie@x.com", false))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())
        val newbie = VirtualClient("newbie@x.com", "newbie register password one", fast = true)
        val good = newbie.buildRegister(invite.inviteToken, recovery.publicKey, fingerprint)

        suspend fun attempt(req: RegisterRequest): HttpResponse = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(req)
        }
        // The register route carries a 5/min per-IP bucket (F22), so the taxonomy is proven over
        // HTTP for the two cases that used to surface WRONG (a 500, and a late failure elsewhere)
        // and the rest drive Service.register directly — the same production function the route
        // calls, with the same BadRequest the StatusPages mapping turns into the 400 body.
        suspend fun refusedOverHttp(req: RegisterRequest, reason: String) {
            val resp = attempt(req)
            assertEquals(HttpStatusCode.BadRequest, resp.status, "$reason: ${resp.bodyAsText()}")
            assertEquals(reason, errorOf(resp))
        }
        fun refused(req: RegisterRequest, reason: String) {
            val e = assertFailsWith<BadRequest>(reason) { services.service.register(req, "127.0.0.1", "1.0.0") }
            assertEquals(reason, e.reason)
        }

        // Non-canonical (uppercase) personal vaultId: refused now, not at the first attachment.
        refusedOverHttp(good.copy(personalVault = good.personalVault.copy(vaultId = good.personalVault.vaultId.uppercase())), "bad_vault_id")
        // A vaultId that already exists (the admin's own personal vault): a refusal, not a 500.
        refusedOverHttp(good.copy(personalVault = good.personalVault.copy(vaultId = admin.personalVaultId)), "vault_id_taken")
        // Ciphertext fields: base64url alphabet and a byte bound, exactly the sibling's gates.
        refused(good.copy(personalVault = good.personalVault.copy(metaBlob = "not base64!!")), "bad_meta_blob")
        // R26: the salt — echoed to an unauthenticated prelogin and asserted exactly 16 bytes by
        // every client's KDF — gets the same alphabet + bound; junk here used to persist.
        refused(good.copy(kdfSalt = "not base64!!"), "bad_kdf_salt")
        refused(good.copy(kdfSalt = "A".repeat(200)), "bad_kdf_salt")
        refused(good.copy(kdfSalt = ""), "bad_kdf_salt")
        refused(good.copy(personalVault = good.personalVault.copy(wrappedVk = "A".repeat(2000))), "bad_wrapped_vk")
        refused(good.copy(wrappedUvk = "x".repeat(2000)), "bad_wrapped_uvk")
        refused(good.copy(identityPub = "A".repeat(200)), "bad_identity_pub")
        refused(good.copy(encryptedIdentitySeed = ""), "bad_encrypted_identity_seed")
        // Rendered free text past the cap: a display name / device label is never a paragraph.
        refused(good.copy(displayName = "n".repeat(Service.TEXT_MAX + 1)), "bad_display_name")
        refused(good.copy(device = DeviceInfo("test", "d".repeat(Service.TEXT_MAX + 1))), "bad_device_name")
        refused(good.copy(device = DeviceInfo("p".repeat(Service.TEXT_MAX + 1), "phone")), "bad_device_platform")

        // Nothing above consumed the invite or created anything.
        assertEquals(1, services.repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM users") { it.getInt(1) } })

        // Control characters are STRIPPED, not refused: a pasted name with a stray newline enrols,
        // and what the Admin console renders is the cleaned form.
        val ok = attempt(good.copy(displayName = "Newbie\n Jr", device = DeviceInfo("te\u0007st", "my\tphone")))
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
        val users = json.decodeFromString(ListSerializer(AdminUserSummary.serializer()), client.get("/api/v1/admin/users") { authed(admin) }.bodyAsText())
        assertEquals("Newbie Jr", users.single { it.email == "newbie@x.com" }.displayName)
        val device = json.decodeFromString(
            ListSerializer(AdminDeviceView.serializer()),
            client.get("/api/v1/admin/users/${users.single { it.email == "newbie@x.com" }.userId}/devices") { authed(admin) }.bodyAsText(),
        ).single()
        assertEquals("myphone", device.name)
        assertEquals("test", device.platform)
    }

    /** The device bound lives in issueSession so LOGIN inherits it — register is not the only door. */
    @Test
    fun login_inheritsTheDeviceTextBound() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "login device bound password", fast = true)
        client.register(admin, bootstrapToken)

        val resp = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(admin.email, admin.authKey, DeviceInfo("test", "d".repeat(Service.TEXT_MAX + 1))))
        }
        assertEquals(HttpStatusCode.BadRequest, resp.status, resp.bodyAsText())
        assertEquals("bad_device_name", errorOf(resp))
    }
}
