package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.AdminDeviceSummary
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.TotpCodeRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** P4 admin surface (spec 03 §7): /admin/status, /admin/users/{id}/devices, revoke, admin_only gating. */
class AdminP4Test : P4TestSupport() {

    @Test
    fun status_devices_nonAdminForbidden_andRevokeKillsSession() = testApplication {
        // publicHostname set → breakGlassConfigured must report true.
        application { andvariModule(buildServices(config(publicHostname = "public.test"), Notifier())) }
        val client = jsonClient(this)

        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken)
        client.push(admin, putMutation(admin, admin.newItemId(), """{"type":"note","name":"seed"}""", 0))

        // Invite + register the second, non-admin user.
        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(InviteRequest("user2@x.com", isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())
        val user2 = VirtualClient("user2@x.com", "second user password")
        val user2Session = client.register(user2, invite.inviteToken)
        assertFalse(user2Session.isAdmin)

        // The non-admin is locked out of both new admin endpoints.
        val stForbidden = client.get("/api/v1/admin/status") { authed(user2) }
        assertEquals(HttpStatusCode.Forbidden, stForbidden.status)
        assertEquals("admin_only", errorOf(stForbidden))
        val devForbidden = client.get("/api/v1/admin/users/${admin.userId}/devices") { authed(user2) }
        assertEquals(HttpStatusCode.Forbidden, devForbidden.status)
        assertEquals("admin_only", errorOf(devForbidden))

        // Status sanity.
        val status1 = client.adminStatus(admin)
        assertEquals(SERVER_VERSION, status1.serverVersion)
        assertEquals(2, status1.userCount)
        assertEquals(1, status1.itemCount)
        assertTrue(status1.escrowConfigured)
        assertEquals(fingerprint, status1.recoveryFingerprint)
        assertTrue(status1.breakGlassConfigured, "publicHostname is configured")
        assertEquals(0, status1.totpEnrolledCount)
        assertEquals(0, status1.attachmentCount)
        assertEquals(0L, status1.attachmentBytes)
        assertFalse(status1.downloadsManifest)

        // A TOTP enrollment shows up in the counter.
        val setupResp = client.post("/api/v1/account/totp/setup") { authed(user2) }
        assertEquals(HttpStatusCode.OK, setupResp.status, setupResp.bodyAsText())
        val setup = json.decodeFromString(TotpSetupResponse.serializer(), setupResp.bodyAsText())
        val confirm = client.post("/api/v1/account/totp/confirm") {
            contentType(ContentType.Application.Json); authed(user2)
            setBody(TotpCodeRequest(totpCode(setup.secretBase32)))
        }
        assertEquals(HttpStatusCode.OK, confirm.status, confirm.bodyAsText())
        assertEquals(1, client.adminStatus(admin).totpEnrolledCount)

        // Device listing shows user2's register device with platform + name.
        val devicesResp = client.get("/api/v1/admin/users/${user2.userId}/devices") { authed(admin) }
        assertEquals(HttpStatusCode.OK, devicesResp.status, devicesResp.bodyAsText())
        val device = json.decodeFromString(ListSerializer(AdminDeviceSummary.serializer()), devicesResp.bodyAsText()).single()
        assertEquals(user2Session.deviceId, device.deviceId)
        assertEquals("test", device.platform)
        assertEquals("vc-use", device.name)
        assertNull(device.revokedAt)

        // Revoke → the device's access token stops working immediately.
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/admin/devices/${device.deviceId}/revoke") { authed(admin) }.status)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/v1/sync?since=0") { authed(user2) }.status)
        val after = json.decodeFromString(
            ListSerializer(AdminDeviceSummary.serializer()),
            client.get("/api/v1/admin/users/${user2.userId}/devices") { authed(admin) }.bodyAsText(),
        ).single()
        assertNotNull(after.revokedAt)
    }
}
