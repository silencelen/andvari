package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TokenPair
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ServerIntegrationTest {
    private val crypto = createCryptoProvider()
    private val recoverySeed = crypto.randomBytes(32)
    private val recovery = crypto.boxKeypairFromSeed(recoverySeed)
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrapToken = "test-bootstrap-token"
    private val tmpDir = Files.createTempDirectory("andvari-it").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "it-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 1 }, publicHostname = null, bootstrapToken = bootstrapToken,
    )

    @AfterTest fun cleanup() { tmpDir.deleteRecursively() }

    private fun jsonClient(builder: ApplicationTestBuilder): HttpClient = builder.createClient {
        install(ContentNegotiation) { json(json) }
        install(WebSockets)
    }

    private suspend fun HttpClient.registerAdmin(vc: VirtualClient, invite: String): SessionResponse {
        val resp = post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json)
            header("X-Andvari-Client", "test/1.0.0")
            setBody(vc.buildRegister(invite, recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.OK, resp.status, "register: ${resp.bodyAsText()}")
        val session = json.decodeFromString(SessionResponse.serializer(), resp.bodyAsText())
        vc.userId = session.userId; vc.accessToken = session.accessToken; vc.refreshToken = session.refreshToken
        return session
    }

    private suspend fun HttpClient.push(vc: VirtualClient, vararg mutations: Mutation): PushResponse {
        val resp = post("/api/v1/sync/push") {
            contentType(ContentType.Application.Json)
            header("Authorization", "Bearer ${vc.accessToken}")
            header("X-Andvari-Client", "test/1.0.0")
            setBody(PushRequest(mutations.toList()))
        }
        assertEquals(HttpStatusCode.OK, resp.status, "push: ${resp.bodyAsText()}")
        return json.decodeFromString(PushResponse.serializer(), resp.bodyAsText())
    }

    private suspend fun HttpClient.sync(vc: VirtualClient, since: Long): SyncResponse {
        val resp = get("/api/v1/sync?since=$since") {
            header("Authorization", "Bearer ${vc.accessToken}")
            header("X-Andvari-Client", "test/1.0.0")
        }
        assertEquals(HttpStatusCode.OK, resp.status, "sync: ${resp.bodyAsText()}")
        return json.decodeFromString(SyncResponse.serializer(), resp.bodyAsText())
    }

    private fun putMutation(vc: VirtualClient, itemId: String, plaintext: String, baseRev: Long) =
        Mutation(uuid(), "put", itemId, vc.personalVaultId, baseRev, vc.encItem(itemId, plaintext))

    /** The end-to-end P1 proof: enroll → items → fresh-device unlock decrypts. */
    @Test
    fun enroll_push_freshDeviceUnlock_decrypts() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)

        val admin = VirtualClient("jacob@example.com", "correct horse battery staple")
        client.registerAdmin(admin, bootstrapToken)
        assertTrue(admin.userId.isNotEmpty())

        // Add 3 items.
        val ids = (1..3).map { admin.newItemId() }
        val push = client.push(
            admin,
            putMutation(admin, ids[0], """{"type":"login","name":"GitHub","login":{"username":"jacob","password":"s3cret"}}""", 0),
            putMutation(admin, ids[1], """{"type":"note","name":"Recovery codes","notes":"abc-def"}""", 0),
            putMutation(admin, ids[2], """{"type":"login","name":"Email"}""", 0),
        )
        assertTrue(push.results.all { it.status == "applied" })

        // A brand-new device: only email + password. Prove it reconstructs keys and decrypts.
        val fresh = VirtualClient(admin.email, admin.password)
        fresh.userId = admin.userId
        fresh.personalVaultId = admin.personalVaultId
        val loginResp = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(admin.email, fresh.authKeyWith(Bytes.toB64(admin.kdfSalt), admin.kdfParams), DeviceInfo("test", "fresh")))
        }
        assertEquals(HttpStatusCode.OK, loginResp.status, loginResp.bodyAsText())
        val freshSession = json.decodeFromString(SessionResponse.serializer(), loginResp.bodyAsText())
        fresh.accessToken = freshSession.accessToken

        val snap = client.sync(fresh, 0)
        assertEquals(3, snap.items.size)
        val grant = snap.grants.single { it.vaultId == fresh.personalVaultId }
        fresh.unlockFromServer(freshSession.accountKeys, grant.wrappedVk)
        val gh = snap.items.single { it.itemId == ids[0] }
        assertTrue(fresh.decItem(ids[0], gh.blob!!).contains("GitHub"))
    }

    @Test
    fun conflict_putOverNewer_archivesAndFlags() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("a@x.com", "password one two three")
        client.registerAdmin(vc, bootstrapToken)

        val id = vc.newItemId()
        val r1 = client.push(vc, putMutation(vc, id, """{"type":"note","name":"v1"}""", 0))
        val rev1 = r1.results[0].newItemRev!!
        // Device B still thinks base is rev1, but device A already advanced it.
        client.push(vc, putMutation(vc, id, """{"type":"note","name":"v2-deviceA"}""", rev1))
        val conflicting = client.push(vc, putMutation(vc, id, """{"type":"note","name":"v3-deviceB-stale"}""", rev1))
        assertEquals("conflict", conflicting.results[0].status)
        assertNotNull(conflicting.results[0].serverItem, "loser must be returned for conflict-copy materialization")
    }

    @Test
    fun editBeatsDelete_bothDirections() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("b@x.com", "another password here")
        client.registerAdmin(vc, bootstrapToken)

        val id = vc.newItemId()
        val r1 = client.push(vc, putMutation(vc, id, """{"type":"note","name":"live"}""", 0))
        val rev1 = r1.results[0].newItemRev!!
        // Someone edits to rev2; a stale delete against rev1 must NOT win.
        client.push(vc, putMutation(vc, id, """{"type":"note","name":"edited"}""", rev1))
        val staleDelete = client.push(vc, Mutation(uuid(), "delete", id, vc.personalVaultId, rev1, null))
        assertEquals("conflict", staleDelete.results[0].status, "stale delete must lose to newer edit")

        // Non-stale delete succeeds and is idempotent.
        val curRev = staleDelete.results[0].serverItem!!.rev
        val del = client.push(vc, Mutation(uuid(), "delete", id, vc.personalVaultId, curRev, null))
        assertEquals("applied", del.results[0].status)
        val delAgain = client.push(vc, Mutation(uuid(), "delete", id, vc.personalVaultId, curRev, null))
        assertEquals("applied", delAgain.results[0].status, "delete is idempotent")
    }

    @Test
    fun mutationIdReplayIsIdempotent() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("c@x.com", "third password value")
        client.registerAdmin(vc, bootstrapToken)

        val id = vc.newItemId()
        val m = putMutation(vc, id, """{"type":"note","name":"once"}""", 0)
        val first = client.push(vc, m)
        val replay = client.push(vc, m) // same mutationId
        assertEquals(first.results[0].newItemRev, replay.results[0].newItemRev)
        // Exactly one item exists.
        assertEquals(1, client.sync(vc, 0).items.size)
    }

    @Test
    fun refreshRotationAndReuseRevokesDevice() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("d@x.com", "fourth password value")
        val session = client.registerAdmin(vc, bootstrapToken)

        val r1 = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json); setBody(RefreshRequest(session.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, r1.status)
        val pair = json.decodeFromString(TokenPair.serializer(), r1.bodyAsText())
        assertTrue(pair.refreshToken != session.refreshToken, "refresh must rotate")

        // Reusing the now-consumed original refresh token → 401 + device revoked.
        val reuse = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json); setBody(RefreshRequest(session.refreshToken))
        }
        assertEquals(HttpStatusCode.Unauthorized, reuse.status)
        // Even the freshly-rotated token is now dead (whole session revoked).
        val afterReuse = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json); setBody(RefreshRequest(pair.refreshToken))
        }
        assertEquals(HttpStatusCode.Unauthorized, afterReuse.status)
    }

    @Test
    fun escrowBlobOpensWithRecoveryKey() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("e@x.com", "fifth password value")
        client.registerAdmin(vc, bootstrapToken)

        // Admin pulls the user's sealed escrow blob; the offline recovery key opens it.
        val sealed = client.get("/api/v1/admin/users/${vc.userId}/escrow") {
            header("Authorization", "Bearer ${vc.accessToken}"); header("X-Andvari-Client", "test/1.0.0")
        }.bodyAsText()
        val payload = Escrow.open(crypto, recovery.publicKey, recovery.privateKey, Bytes.fromB64(sealed))
        assertEquals(vc.userId, payload.userId)
        assertEquals(Escrow.KEY_TYPE_UVK, payload.keyType)
        // The escrowed key IS the client's UVK — recovery can rebuild the vault.
        assertEquals(Bytes.toB64(vc.uvk), payload.key)
    }

    @Test
    fun preloginDoesNotLeakUserExistence() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("real@x.com", "sixth password value")
        client.registerAdmin(vc, bootstrapToken)

        suspend fun salt(email: String): String {
            val resp = client.post("/api/v1/auth/prelogin") {
                contentType(ContentType.Application.Json); setBody(io.silencelen.andvari.core.model.PreloginRequest(email))
            }
            return json.decodeFromString(io.silencelen.andvari.core.model.PreloginResponse.serializer(), resp.bodyAsText()).kdfSalt
        }
        // Unknown email returns a deterministic fake salt (stable across calls, non-empty).
        val s1 = salt("ghost@x.com"); val s2 = salt("ghost@x.com")
        assertEquals(s1, s2)
        assertTrue(s1.isNotEmpty())
        // Real user's salt is its actual stored salt.
        assertEquals(Bytes.toB64(vc.kdfSalt), salt("real@x.com"))
    }

    @Test
    fun healthzOk() = testApplication {
        val cfg = config()
        application { andvariModule(buildServices(cfg, Notifier())) }
        assertEquals("ok", client.get("/healthz").bodyAsText())
    }
}
