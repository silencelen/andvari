package io.silencelen.andvari.server

import io.ktor.client.plugins.websocket.webSocket
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.model.ApiError
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.WsTicketResponse
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Exercises the 426 upgrade_required min-version pin end-to-end (spec 03 §1) — the
 * machinery had never been fired before real secrets. Policy pins live in the DB
 * (PUT /admin/policy → Service.setPolicy), NOT env; the drill doc is
 * docs/drills/426-min-version-drill.md.
 */
class MinVersionGateTest : P4TestSupport() {

    private fun pin(services: Services, platform: String, min: String) =
        services.service.setPolicy(services.service.policy().copy(minVersion = mapOf(platform to min)))

    @Test
    fun oldClientBlocked_currentClientPasses_onAuthedAndLoginRoutes() = testWith { services, builder ->
        val client = jsonClient(builder)
        val vc = VirtualClient("min@x.com", "min version password one")
        client.register(vc, bootstrapToken) // registers as test/1.0.0 BEFORE the pin

        pin(services, "test", "2.0.0")

        // Authenticated route (sync): old build → 426 with the documented body.
        val oldSync = client.get("/api/v1/sync?since=0") {
            header("Authorization", "Bearer ${vc.accessToken}")
            header("X-Andvari-Client", "test/1.9.9")
        }
        assertEquals(426, oldSync.status.value)
        val body = json.decodeFromString(ApiError.serializer(), oldSync.bodyAsText())
        assertEquals("upgrade_required", body.error)
        assertEquals("min test 2.0.0", body.message)

        // Login path: gated BEFORE credentials are even read — old build can't mint sessions.
        val oldLogin = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "old-build")))
        }
        assertEquals(426, oldLogin.status.value)
        assertEquals("upgrade_required", errorOf(oldLogin))

        // Exactly-min and above-min builds pass both routes.
        for (v in listOf("2.0.0", "2.1.3")) {
            val sync = client.get("/api/v1/sync?since=0") {
                header("Authorization", "Bearer ${vc.accessToken}")
                header("X-Andvari-Client", "test/$v")
            }
            assertEquals(HttpStatusCode.OK, sync.status, "test/$v sync: ${sync.bodyAsText()}")
            val login = client.post("/api/v1/auth/login") {
                contentType(ContentType.Application.Json)
                header("X-Andvari-Client", "test/$v")
                setBody(LoginRequest(vc.email, vc.authKey, DeviceInfo("test", "cur-$v")))
            }
            assertEquals(HttpStatusCode.OK, login.status, "test/$v login: ${login.bodyAsText()}")
        }

        // The pin is per-platform: a different platform id is not caught by the "test" pin.
        val other = client.get("/api/v1/sync?since=0") {
            header("Authorization", "Bearer ${vc.accessToken}")
            header("X-Andvari-Client", "web/0.0.1")
        }
        assertEquals(HttpStatusCode.OK, other.status)

        // client-policy stays reachable for the banned build — it's how a client LEARNS
        // it must upgrade (and where the web app reads the pin from).
        val pol = client.get("/api/v1/client-policy") { header("X-Andvari-Client", "test/1.0.0") }
        assertEquals(HttpStatusCode.OK, pol.status)
        val polBody = pol.bodyAsText()
        assertTrue("\"test\"" in polBody && "2.0.0" in polBody, polBody)
    }

    @Test
    fun blockedRegisterDoesNotConsumeInvite() = testWith { services, builder ->
        val client = jsonClient(builder)
        val admin = VirtualClient("admin@x.com", "admin password value 1")
        client.register(admin, bootstrapToken)

        pin(services, "test", "2.0.0")

        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json)
            authed(admin)
            header("X-Andvari-Client", "test/2.0.0") // admin runs a current build
            setBody(InviteRequest("newbie@x.com", false))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())

        // Old build tries to enroll → 426, before the invite is touched.
        val newbie = VirtualClient("newbie@x.com", "newbie password value 1")
        val req = newbie.buildRegister(invite.inviteToken, recovery.publicKey, fingerprint)
        val blocked = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(req)
        }
        assertEquals(426, blocked.status.value)

        // Same invite still redeemable from a current build.
        val ok = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/2.0.0")
            setBody(req)
        }
        assertEquals(HttpStatusCode.OK, ok.status, ok.bodyAsText())
    }

    @Test
    fun wsTicketPathStaysUsableUnderThePin() = testWith { services, builder ->
        // Deliberate current behavior: the events dirty-bell is NOT version-gated — it
        // carries zero vault data (rev notifications only) and every data route the bell
        // would trigger (sync/push) IS gated. This test pins that behavior so a future
        // change to it is a conscious one.
        val wsClient = builder.createClient {
            install(ContentNegotiation) { json(json) }
            install(io.ktor.client.plugins.websocket.WebSockets)
        }
        val vc = VirtualClient("ws@x.com", "ws password value here1")
        wsClient.register(vc, bootstrapToken)

        pin(services, "test", "2.0.0")

        val ticketResp = wsClient.post("/api/v1/events/ticket") {
            header("Authorization", "Bearer ${vc.accessToken}")
            header("X-Andvari-Client", "test/1.0.0") // old build
        }
        assertEquals(HttpStatusCode.OK, ticketResp.status, "ticket mint is not version-gated (dirty-bell only)")
        val ticket = json.decodeFromString(WsTicketResponse.serializer(), ticketResp.bodyAsText()).ticket

        wsClient.webSocket("/api/v1/events?ticket=$ticket") {
            outgoing.send(Frame.Text("ping"))
            val reply = incoming.receive() as Frame.Text
            assertEquals("pong", reply.readText())
        }

        // ...but the data the bell points at stays blocked for that build.
        val sync = wsClient.get("/api/v1/sync?since=0") {
            header("Authorization", "Bearer ${vc.accessToken}")
            header("X-Andvari-Client", "test/1.0.0")
        }
        assertEquals(426, sync.status.value)
    }

    @Test
    fun kotlinClientSurfacesTyped426() = testWith { services, builder ->
        val client = jsonClient(builder)
        val vc = VirtualClient("kc426@x.com", "kotlin 426 password one")
        client.register(vc, bootstrapToken)

        // AndvariApi self-identifies as android/0.3.0 — pin android above it.
        val api = AndvariApi("", builder.createClient { }, Tokens(vc.accessToken, vc.refreshToken))
        runBlocking { api.sync(0) } // sane before the pin

        pin(services, "android", "99.0.0")

        val onSync = assertFailsWith<UpgradeRequiredException> { runBlocking { api.sync(0) } }
        assertEquals(426, onSync.status)
        assertEquals("upgrade_required", onSync.code)
        assertTrue("99.0.0" in (onSync.message ?: ""), "carries the server's min: ${onSync.message}")
        // Subclass of ApiException — every existing `catch (e: ApiException)` keeps working
        // (compile-time proof: the typed assignment below).
        val asGeneric: ApiException = onSync
        assertEquals(426, asGeneric.status)

        val onLogin = assertFailsWith<UpgradeRequiredException> {
            runBlocking { api.login(LoginRequest(vc.email, vc.authKey, DeviceInfo("android", "pixel"))) }
        }
        assertEquals(426, onLogin.status)
    }

    /** testApplication with the Services handle exposed so tests can flip policy mid-flight. */
    private fun testWith(block: suspend (Services, io.ktor.server.testing.ApplicationTestBuilder) -> Unit) =
        io.ktor.server.testing.testApplication {
            val services = buildServices(config(), Notifier())
            application { andvariModule(services) }
            block(services, this)
        }
}
