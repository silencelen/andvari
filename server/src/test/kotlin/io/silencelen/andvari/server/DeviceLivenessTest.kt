package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.AdminUserSummary
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.SessionResponse
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * H25 (audit 2026-09-13): the Admin device list and the user table's device count answer "which
 * devices still hold access to the household vault" — and answered it wrong on every row. Only
 * the admin revoke path ever stamped `devices.revokedAt`; a member's own sign-out revoked the
 * sessions and left the device row untouched, every login minted a fresh row, and no janitor rule
 * touched `devices`. So a member who signed in from five phones over a year showed "5 devices"
 * with five Revoke buttons, none holding a session, and the admin could not tell a compromised
 * live device from a long-gone one. Liveness is now DERIVED from the sessions join (one rule for
 * list and count), logout stamps `signedOutAt` (its own column — a sign-out is not a revoke), and
 * the janitor ages session-less device rows out with the sessions that were their evidence.
 */
class DeviceLivenessTest : P4TestSupport() {

    private suspend fun HttpClient.users(admin: VirtualClient): List<AdminUserSummary> =
        json.decodeFromString(ListSerializer(AdminUserSummary.serializer()), get("/api/v1/admin/users") { authed(admin) }.bodyAsText())

    private suspend fun HttpClient.devices(admin: VirtualClient, userId: String): List<AdminDeviceView> {
        val resp = get("/api/v1/admin/users/$userId/devices") { authed(admin) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(ListSerializer(AdminDeviceView.serializer()), resp.bodyAsText())
    }

    private suspend fun HttpClient.loginSecondDevice(vc: VirtualClient): SessionResponse {
        val resp = post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "second-phone")))
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
    }

    @Test
    fun deviceListAndCount_followLiveSessions_notTheRevokeColumn() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "device liveness password one", fast = true)
        val first = client.register(admin, bootstrapToken)
        val second = client.loginSecondDevice(admin)

        // Two logins, two live devices: the count and every row agree.
        assertEquals(2, client.users(admin).single().deviceCount)
        val both = client.devices(admin, admin.userId)
        assertEquals(2, both.size)
        assertTrue(both.all { it.live && it.signedOutAt == null && it.revokedAt == null }, "$both")

        // The second device signs itself out. Before the fix this row was indistinguishable from
        // a live one — revokedAt NULL, a Revoke button — and the count stayed at 2 forever.
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/auth/logout") { authed(second.accessToken) }.status)
        assertEquals(1, client.users(admin).single().deviceCount, "a signed-out device holds no access")
        val afterLogout = client.devices(admin, admin.userId)
        val signedOut = afterLogout.single { it.deviceId == second.deviceId }
        assertFalse(signedOut.live)
        assertNotNull(signedOut.signedOutAt, "logout stamps the device row")
        assertNull(signedOut.revokedAt, "a member's sign-out is NOT an admin revoke — the two stay distinct")
        assertTrue(afterLogout.single { it.deviceId == first.deviceId }.live, "the device that stayed signed in is still live")

        // A device whose refresh chain lapsed without ever signing out is not live either — it
        // cannot come back without a fresh login, which mints a NEW row. No stamp: nothing happened
        // to it; the join is the truth, the stamp is only the human-readable "when".
        services.repo.db.tx { c -> c.exec("UPDATE sessions SET refreshExpiresAt=? WHERE deviceId=?", now() - 1, first.deviceId) }
        assertEquals(0, client.users(admin).single().deviceCount)
        val lapsed = client.devices(admin, admin.userId).single { it.deviceId == first.deviceId }
        assertFalse(lapsed.live)
        assertNull(lapsed.signedOutAt)
        assertNull(lapsed.revokedAt)

        // The admin revoke path still works on a live row and is still visible as a REVOKE.
        val third = client.loginSecondDevice(admin)
        assertEquals(1, client.users(admin).single().deviceCount)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/admin/devices/${third.deviceId}/revoke") { authed(admin) }.status)
        val revoked = client.devices(admin, admin.userId).single { it.deviceId == third.deviceId }
        assertFalse(revoked.live)
        assertNotNull(revoked.revokedAt)
        assertNull(revoked.signedOutAt)
        assertEquals(0, client.users(admin).single().deviceCount)
    }

    @Test
    fun janitor_agesSessionLessDeviceRowsOut_withTheirSessions() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val admin = VirtualClient("admin@x.com", "device janitor password one", fast = true)
        val first = client.register(admin, bootstrapToken)
        val second = client.loginSecondDevice(admin)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/auth/logout") { authed(second.accessToken) }.status)
        val t = now()

        // Age the signed-out device past the 90 d session horizon: its (revoked) session row goes
        // under rule (e) and the device row — now session-less — under the new device rule, in the
        // SAME sweep. The still-live first device keeps both its rows.
        services.repo.db.tx { c ->
            c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=?", t - 91 * Service.DAY_MS, second.deviceId)
            c.exec("UPDATE devices SET createdAt=?, signedOutAt=? WHERE deviceId=?", t - 92 * Service.DAY_MS, t - 91 * Service.DAY_MS, second.deviceId)
        }
        val res = services.janitor.sweep(t)
        assertEquals(1L, res.prunedSessions)
        assertEquals(1L, res.prunedDevices, "a device whose last session aged out ages out with it")
        val remaining = client.devices(admin, admin.userId)
        assertEquals(listOf(first.deviceId), remaining.map { it.deviceId })
        assertTrue(remaining.single().live)

        // A device that is dead but whose session row is still INSIDE the horizon is kept: the
        // session is evidence an admin may still want, and the FK forbids the delete anyway.
        val third = client.loginSecondDevice(admin)
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/auth/logout") { authed(third.accessToken) }.status)
        services.repo.db.tx { c -> c.exec("UPDATE devices SET createdAt=? WHERE deviceId=?", t - 92 * Service.DAY_MS, third.deviceId) }
        val res2 = services.janitor.sweep(t)
        assertEquals(0L, res2.prunedDevices)
        assertEquals(2, client.devices(admin, admin.userId).size)
    }
}
