package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.header
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.AuditEvent
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.TokenPair
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Regression locks for six server hardening fixes (spec 05 T8 / spec 03 §§2,5 / spec 04):
 *   LOW-1 KDF floor, LOW-2 refresh guarded-consume, LOW-4 enum-secret fail-closed,
 *   LOW-5 post-commit attachment unlink, LOW-7 push_denied audit, LOW-8 escrow_self_upload audit.
 * House style: VirtualClient does the real client crypto; helpers reused from P4TestSupport.
 */
class AuditHardeningTest : P4TestSupport() {

    /** Like [config] but with the production Argon2id floor turned on (64 MiB / ops 3). */
    private fun flooredConfig() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmpDir, "floor-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmpDir, "floor-blobs-${System.nanoTime()}").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
        minKdfMemBytes = 67_108_864L, minKdfOps = 3L,
    )

    private suspend fun HttpClient.auditRows(admin: VirtualClient, type: String): List<AuditEvent> {
        val resp = get("/api/v1/admin/audit?type=$type") { authed(admin) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(ListSerializer(AuditEvent.serializer()), resp.bodyAsText())
    }

    // ---- LOW-1: KDF floor is enforced at enrollment ----

    /**
     * With the production floor armed, enrollment below 64 MiB / ops 3 is refused, but a
     * conforming DEFAULT-param client enrolls. The default client pays a real 64 MiB
     * argon2id — kept to THIS one test.
     */
    @Test
    fun kdfFloor_rejectsWeakParams_butAcceptsDefault() = testApplication {
        application { andvariModule(buildServices(flooredConfig(), Notifier())) }
        val client = jsonClient(this)

        // Fast params (ops 1 / 8 MiB) are below the floor → refused before anything persists.
        val weak = VirtualClient("weak@x.com", "weak enrollment password", fast = true)
        val weakResp = client.post("/api/v1/auth/register") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(weak.buildRegister(bootstrapToken, recovery.publicKey, fingerprint))
        }
        assertEquals(HttpStatusCode.BadRequest, weakResp.status, weakResp.bodyAsText())
        assertEquals("kdf_too_weak", errorOf(weakResp))

        // The rejected attempt rolled back (invite unconsumed): a DEFAULT-param client still enrolls.
        val strong = VirtualClient("strong@x.com", "strong enrollment password", fast = false)
        val ok = client.register(strong, bootstrapToken) // asserts 200
        assertTrue(ok.userId.isNotEmpty())
    }

    /** Guard the default-off behavior: with floor 0/0 (the test config) fast params still enroll. */
    @Test
    fun kdfFloor_offByDefault_acceptsFastParams() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("fastok@x.com", "fast params are fine here", fast = true)
        assertTrue(client.register(vc, bootstrapToken).userId.isNotEmpty())
    }

    // ---- LOW-2: reuse of a consumed refresh token revokes the whole device ----

    /**
     * refresh once (rotates + consumes the original), then present the ORIGINAL again: the
     * guarded consume treats it as reuse → 401 refresh_reuse AND every session on the device
     * is revoked, so the freshly-rotated access token can no longer /sync.
     */
    @Test
    fun refreshReuse_revokesEntireDevice() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("refresh@x.com", "refresh reuse password", fast = true)
        val session = client.register(vc, bootstrapToken)

        // First refresh: get a new pair; the original refresh token is now consumed.
        val r1 = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json); setBody(RefreshRequest(session.refreshToken))
        }
        assertEquals(HttpStatusCode.OK, r1.status, r1.bodyAsText())
        val pair = json.decodeFromString(TokenPair.serializer(), r1.bodyAsText())
        // The rotated access token authorizes a sync right now.
        assertEquals(HttpStatusCode.OK, client.get("/api/v1/sync?since=0") { authed(pair.accessToken) }.status)

        // Reusing the now-consumed ORIGINAL refresh token → 401 refresh_reuse.
        val reuse = client.post("/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json); setBody(RefreshRequest(session.refreshToken))
        }
        assertEquals(HttpStatusCode.Unauthorized, reuse.status)
        assertEquals("refresh_reuse", errorOf(reuse))

        // Device-wide revocation: even the freshly-rotated access token is dead now — reuse
        // revokes EVERY session on the device, so no token from it can query the audit log
        // (which is why the refresh_reuse audit row is not read back here).
        assertEquals(
            HttpStatusCode.Unauthorized,
            client.get("/api/v1/sync?since=0") { authed(pair.accessToken) }.status,
            "reuse must revoke the whole device, not just the replayed token",
        )
    }

    // ---- LOW-4: Config.fromEnv fails closed without a strong enum secret ----

    @Test
    fun fromEnv_failsClosed_withoutEnumSecret_elseFloorDefaultsApply() {
        // (a) ANDVARI_ENUM_SECRET unset → refuse to start (guessable fake-salt secret).
        assertFailsWith<IllegalStateException> { Config.fromEnv { _ -> null } }

        // Blank is also rejected.
        assertFailsWith<IllegalStateException> {
            Config.fromEnv { name -> if (name == "ANDVARI_ENUM_SECRET") "   " else null }
        }

        // (b) A valid >=32-byte base64url enum secret is the only hard requirement; the
        // production KDF floor defaults come along for free.
        val secret = Bytes.toB64(ByteArray(32) { 1 })
        val cfg = Config.fromEnv { name -> if (name == "ANDVARI_ENUM_SECRET") secret else null }
        assertEquals(67_108_864L, cfg.minKdfMemBytes)
        assertEquals(3L, cfg.minKdfOps)
    }

    // ---- LOW-5: a rolled-back batch must NOT unlink a tombstoned item's blob ----

    /**
     * The dangerous regression: unlinking blob files mid-tx would orphan them when a later
     * mutation in the same batch throws and rolls back (item restored, ciphertext gone). Push
     * [delete X, put Y-that-throws] as one batch; assert X stays live AND blob A survives.
     * (The successful-delete-drops-the-file path is already covered by AttachmentP4Test.)
     */
    @Test
    fun rolledBackBatch_preservesTombstonedItemBlob() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("unlink@x.com", "post commit unlink password", fast = true)
        client.register(vc, bootstrapToken)
        val store = services.service.attachments
        val fileKey = crypto.randomBytes(32)

        // Item X owns attachment A; the blob file is on disk.
        val attId = uuid()
        val itemX = vc.newItemId()
        val enc = Attachments.encrypt(crypto, fileKey, crypto.randomBytes(1024))
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, attId, itemX, enc.header + enc.ciphertext).status)
        val revX = client.push(vc, putMutation(vc, itemX, """{"type":"note","name":"keep"}""", 0, listOf(attId)))
            .results[0].newItemRev!!
        assertTrue(store.file(attId).isFile)

        // One batch: delete X (queues blob A for unlink), then a put that references an unknown
        // attachment id → throws unknown_attachment → the WHOLE tx rolls back.
        val rolled = client.pushRaw(
            vc,
            Mutation(uuid(), "delete", itemX, vc.personalVaultId, revX, null),
            putMutation(vc, vc.newItemId(), """{"type":"note","name":"boom"}""", 0, listOf(uuid())),
        )
        assertEquals(HttpStatusCode.BadRequest, rolled.status)
        assertEquals("unknown_attachment", errorOf(rolled))

        // Rollback preserved both the item (still live, still referencing A) and the blob file.
        assertEquals(listOf(attId), client.sync(vc).items.single { it.itemId == itemX }.attachmentIds)
        assertTrue(store.file(attId).isFile, "a rolled-back batch must NOT unlink the tombstoned blob")
    }

    // ---- LOW-7: a denied push writes a push_denied audit row ----

    /**
     * A second user pushing to the first user's personal vault has no grant → the mutation is
     * denied and the intrusion is audited (spec 03 §5). Cross-user vault ids are reachable here
     * because both users are in-test VirtualClients.
     */
    @Test
    fun deniedPush_writesPushDeniedAudit() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)

        val user1 = VirtualClient("owner@x.com", "owner vault password one", fast = true)
        client.register(user1, bootstrapToken)

        // Admin invites a second, non-admin user who then enrolls.
        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(user1)
            setBody(InviteRequest("intruder@x.com", isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())
        val user2 = VirtualClient("intruder@x.com", "intruder vault password two", fast = true)
        client.register(user2, invite.inviteToken)

        // user2 pushes a put into user1's personal vault → no grant → denied (HTTP 200, per-item denied).
        val itemId = user2.newItemId()
        val denied = client.push(
            user2,
            Mutation(uuid(), "put", itemId, user1.personalVaultId, 0, user2.encItem(itemId, """{"type":"note","name":"steal"}""")),
        )
        assertEquals("denied", denied.results[0].status)

        val rows = client.auditRows(user1, "push_denied")
        assertTrue(
            rows.any { it.userId == user2.userId },
            "a denied write must leave a push_denied audit row attributed to the actor",
        )
    }

    // ---- LOW-8: self escrow upload is audited ----

    @Test
    fun escrowSelfUpload_isAudited() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("escrow@x.com", "escrow self upload password", fast = true)
        client.register(admin, bootstrapToken)

        // fingerprint must match the server's pinned recovery fingerprint (P4TestSupport's keypair).
        val put = client.put("/api/v1/escrow/self") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(EscrowUpload(Bytes.toB64(crypto.randomBytes(48)), fingerprint))
        }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())

        val rows = client.auditRows(admin, "escrow_self_upload")
        assertTrue(
            rows.any { it.userId == admin.userId },
            "replacing self escrow (sole recovery path) must be audited",
        )
    }
}
