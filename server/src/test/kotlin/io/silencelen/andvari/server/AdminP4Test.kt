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
import io.silencelen.andvari.core.model.AdminDeviceSummary
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.TokenPair
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
        assertEquals("1.0.0", device.clientVersion, "F23: the register call's X-Andvari-Client build is stamped on the row")
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

    /**
     * F23: the column, the wire field and the Admin console's "Client" cell all existed — and nothing
     * ever WROTE the value, so every device on every instance read "—" forever. That is precisely the
     * question an operator asks before arming a minVersion pin that will silently 426 anything older.
     */
    @Test
    fun deviceList_carriesTheDeclaredBuild_andFollowsAnUpgrade() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken) // the register call declares test/1.0.0

        suspend fun deviceRow() = json.decodeFromString(
            ListSerializer(AdminDeviceSummary.serializer()),
            client.get("/api/v1/admin/users/${admin.userId}/devices") { authed(admin) }.bodyAsText(),
        ).single()

        assertEquals("1.0.0", deviceRow().clientVersion)

        // The device updates itself: its next refresh re-stamps the row, so the admin sees the new
        // build without waiting for a re-login (refresh is the only heartbeat a device sends).
        val refreshed = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.4.0")
            setBody(RefreshRequest(admin.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, refreshed.status, refreshed.bodyAsText())
        assertEquals("1.4.0", deviceRow().clientVersion)

        // A caller that declares NO build leaves the last known one standing — the column must never
        // regress to a "0.0.0" that no device is actually running.
        val next = json.decodeFromString(TokenPair.serializer(), refreshed.bodyAsText())
        val silent = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            setBody(RefreshRequest(next.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, silent.status, silent.bodyAsText())
        assertEquals("1.4.0", deviceRow().clientVersion)
    }

    /**
     * F23 follow-up (server review 2026-08-13): the declared build is attacker-chosen text on an
     * UNAUTHENTICATED route (register/login both stamp it) that is now PERSISTED and rendered in the
     * Admin console, so it is validated before it reaches the column — semver alphabet, ≤32 chars.
     * A value that fails is treated as "never said" (null → "—") rather than truncated, because the
     * operator reads this column to decide a minVersion pin and a half-string would be a lie.
     */
    @Test
    fun deviceList_dropsAnImplausibleDeclaredBuild() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("root@x.com", "admin password value")

        // Register declaring a build no client could be running: markup, and far past the cap.
        val junk = "1.0.0<script>x</script>" + "9".repeat(64)
        val resp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/$junk")
            setBody(admin.buildRegister(bootstrapToken, recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        val session = json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
        admin.userId = session.userId; admin.accessToken = session.accessToken; admin.refreshToken = session.refreshToken

        suspend fun deviceRow() = json.decodeFromString(
            ListSerializer(AdminDeviceSummary.serializer()),
            client.get("/api/v1/admin/users/${admin.userId}/devices") { authed(admin) }.bodyAsText(),
        ).single()

        assertNull(deviceRow().clientVersion, "junk is 'never said', never a truncation of itself")

        // A long-but-real semver (pre-release + build metadata) must still be accepted — the guard
        // bounds the value, it does not narrow what a legitimate client may call itself.
        val real = "1.2.3-rc.4+build.9"
        val refreshed = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/$real")
            setBody(RefreshRequest(admin.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, refreshed.status, refreshed.bodyAsText())
        assertEquals(real, deviceRow().clientVersion)

        // A later junk declaration leaves the last GOOD build standing (the COALESCE), so the column
        // can't be poisoned by one request from a device that already reported honestly.
        val next = json.decodeFromString(TokenPair.serializer(), refreshed.bodyAsText())
        val poisoned = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/" + "0".repeat(33)) // one character over the cap
            setBody(RefreshRequest(next.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, poisoned.status, poisoned.bodyAsText())
        assertEquals(real, deviceRow().clientVersion)
    }

    @Test
    fun lastActiveAdminCannotBeDisabled() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken)

        // Sole admin disabling themselves = instance-wide lockout → refused.
        val selfDisable = client.post("/api/v1/admin/users/${admin.userId}/disable") { authed(admin) }
        assertEquals(HttpStatusCode.BadRequest, selfDisable.status, selfDisable.bodyAsText())
        assertEquals("last_admin", errorOf(selfDisable))

        // Add a second ADMIN — now the first can be disabled (an active admin remains)...
        val invResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(InviteRequest("admin2@x.com", isAdmin = true))
        }
        val invite = json.decodeFromString(InviteResponse.serializer(), invResp.bodyAsText())
        val admin2 = VirtualClient("admin2@x.com", "second admin password")
        assertTrue(client.register(admin2, invite.inviteToken).isAdmin)

        val disableFirst = client.post("/api/v1/admin/users/${admin.userId}/disable") { authed(admin2) }
        assertEquals(HttpStatusCode.OK, disableFirst.status, disableFirst.bodyAsText())

        // ...but the remaining admin is now the last one and is protected again.
        val disableLast = client.post("/api/v1/admin/users/${admin2.userId}/disable") { authed(admin2) }
        assertEquals(HttpStatusCode.BadRequest, disableLast.status, disableLast.bodyAsText())
        assertEquals("last_admin", errorOf(disableLast))

        // Unknown target is a clean 400, not a silent no-op audit row.
        val ghost = client.post("/api/v1/admin/users/00000000-0000-4000-8000-000000000000/disable") { authed(admin2) }
        assertEquals(HttpStatusCode.BadRequest, ghost.status)
        assertEquals("no_such_user", errorOf(ghost))
    }

    /**
     * bug-server--8: revoking an id that names no device used to run both UPDATEs against zero
     * rows, write a device_revoke audit row for the phantom, and answer "ok". An admin who
     * mistyped or pasted a stale id was told the compromised device was locked out while it was
     * still live, and the incident reviewer later read that row as a completed revocation.
     * Refusal shape is disableUser's: audited INSIDE the tx, thrown OUTSIDE it.
     */
    @Test
    fun revokingAnUnknownDeviceRefuses_andAuditsTheDenialNotARevocation() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken)

        val ghostDevice = "00000000-0000-4000-8000-0000000000ff"
        val resp = client.post("/api/v1/admin/devices/$ghostDevice/revoke") { authed(admin) }
        assertEquals(HttpStatusCode.NotFound, resp.status, resp.bodyAsText())
        assertEquals("no_such_device", errorOf(resp))

        assertTrue(
            client.auditRows(admin, "device_revoke").none { it.deviceId == ghostDevice },
            "a device that never existed must not appear as a completed revocation",
        )
        val denied = client.auditRows(admin, "device_revoke_denied").single()
        assertEquals(ghostDevice, denied.deviceId)
        assertEquals("no_such_device", denied.meta)

        // The real device still revokes cleanly (the guard is the only thing that changed).
        val own = client.get("/api/v1/admin/users/${admin.userId}/devices") { authed(admin) }
        val device = json.decodeFromString(ListSerializer(AdminDeviceSummary.serializer()), own.bodyAsText()).single()
        assertEquals(HttpStatusCode.OK, client.post("/api/v1/admin/devices/${device.deviceId}/revoke") { authed(admin) }.status)
    }

    /**
     * bug-server--9: a member with no escrow row is a state-of-the-world miss, not a malformed
     * request — 404 like no_such_user / not_a_member, so the Admin UI can tell "waived, no
     * backstop" from "you sent a bad id". (The UI keys off the body code either way, which is
     * why this is a low: the taxonomy was the defect, not the behavior.)
     */
    @Test
    fun escrowFetchForAUserWithoutOne_isNotFound_notBadRequest() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("root@x.com", "admin password value")
        client.register(admin, bootstrapToken)

        // Well-formed id, no such user ⇒ no escrow row.
        val resp = client.get("/api/v1/admin/users/00000000-0000-4000-8000-000000000000/escrow") { authed(admin) }
        assertEquals(HttpStatusCode.NotFound, resp.status, resp.bodyAsText())
        assertEquals("no_escrow", errorOf(resp))
        // A malformed id stays a 400 — the two failures remain distinguishable.
        val bad = client.get("/api/v1/admin/users/123/escrow") { authed(admin) }
        assertEquals(HttpStatusCode.BadRequest, bad.status)
        assertEquals("bad_user_id", errorOf(bad))
    }
}
