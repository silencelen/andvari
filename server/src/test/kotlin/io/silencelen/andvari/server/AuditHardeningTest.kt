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
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.websocket.WebSockets
import io.ktor.client.plugins.websocket.webSocket
import io.ktor.http.encodeURLParameter
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeFully
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.readText
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.AuditEvent
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.RefreshRequest
import io.silencelen.andvari.core.model.TokenPair
import io.silencelen.andvari.core.model.WsTicketResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
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

        // fingerprint must match the server's pinned recovery fingerprint (P4TestSupport's
        // keypair), and the blob must be structurally valid (requireEscrowBlob) — a real
        // sealed UVK, exactly what a conforming client re-uploads.
        val put = client.put("/api/v1/escrow/self") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recovery.publicKey, admin.userId, crypto.randomBytes(32))), fingerprint))
        }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())

        val rows = client.auditRows(admin, "escrow_self_upload")
        assertTrue(
            rows.any { it.userId == admin.userId },
            "replacing self escrow (sole recovery path) must be audited",
        )
    }

    // ---- LOW-3: forwarded client IP is trusted only from a loopback peer ----

    /** Route-level plumbing: audit rows record the forwarded IP (testApplication's peer is loopback). */
    @Test
    fun clientIp_forwardedHeaders_reachAuditRows() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("ip@x.com", "client ip audit password", fast = true)
        client.register(admin, bootstrapToken)

        suspend fun escrowWith(vararg headers: Pair<String, String>): String? {
            val resp = client.put("/api/v1/escrow/self") {
                contentType(ContentType.Application.Json); authed(admin)
                headers.forEach { (k, v) -> header(k, v) }
                setBody(EscrowUpload(Bytes.toB64(Escrow.sealUvk(crypto, recovery.publicKey, admin.userId, crypto.randomBytes(32))), fingerprint))
            }
            assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            return client.auditRows(admin, "escrow_self_upload").first().ip // DESC → latest
        }

        // CF-Connecting-IP wins outright over XFF.
        assertEquals("203.0.113.9", escrowWith("CF-Connecting-IP" to "203.0.113.9", "X-Forwarded-For" to "6.6.6.6, 100.101.102.103"))
        // No CF header → RIGHTMOST XFF entry (proxy-appended), never the forgeable left one.
        assertEquals("100.101.102.103", escrowWith("X-Forwarded-For" to "6.6.6.6, 100.101.102.103"))
        // Garbage header falls back to the raw peer — no crash, no garbage in the audit.
        val fallback = escrowWith("X-Forwarded-For" to "not-an-ip")
        assertTrue(fallback == null || !fallback.contains("not-an-ip"), "garbage header must not reach audit: $fallback")
    }

    /** Pure selection rules (no ktor): loopback gating, rightmost-XFF, literal-only, loopback-literal skip. */
    @Test
    fun pickClientIp_pureRules() {
        val trusted = listOf("CF-Connecting-IP", "X-Forwarded-For")
        fun of(vararg h: Pair<String, String>): (String) -> String? = { name -> h.toMap()[name] }

        // Non-loopback peer: headers are NEVER trusted (LAN spoof-proof).
        assertEquals("10.0.0.5", pickClientIp(false, of("CF-Connecting-IP" to "203.0.113.9"), trusted, "10.0.0.5"))
        // Loopback peer: first trusted header wins; XFF contributes its rightmost entry.
        assertEquals("203.0.113.9", pickClientIp(true, of("CF-Connecting-IP" to "203.0.113.9", "X-Forwarded-For" to "6.6.6.6, 198.51.100.7"), trusted, "127.0.0.1"))
        assertEquals("198.51.100.7", pickClientIp(true, of("X-Forwarded-For" to "6.6.6.6, 198.51.100.7"), trusted, "127.0.0.1"))
        // Hostnames (would DNS-resolve), blanks, and loopback literals all fall through.
        assertEquals("127.0.0.1", pickClientIp(true, of("X-Forwarded-For" to "evil.example.com"), trusted, "127.0.0.1"))
        assertEquals("127.0.0.1", pickClientIp(true, of("CF-Connecting-IP" to "   "), trusted, "127.0.0.1"))
        assertEquals("127.0.0.1", pickClientIp(true, of("X-Forwarded-For" to "127.0.0.1"), trusted, "127.0.0.1"))
        // IPv6 literal accepted; bad IPv4 octet rejected.
        assertEquals("2001:db8::7", pickClientIp(true, of("CF-Connecting-IP" to "2001:db8::7"), trusted, "127.0.0.1"))
        assertEquals("127.0.0.1", pickClientIp(true, of("CF-Connecting-IP" to "999.1.1.1"), trusted, "127.0.0.1"))
    }

    // ---- LOW-6: per-user in-flight upload cap + quota accounting (drives store() directly:
    // testApplication cannot hold a request body open) ----

    private fun bareStore(maxConcurrent: Int): Pair<AttachmentStore, File> {
        val repo = Repo(Db(File(tmpDir, "inflight-${System.nanoTime()}.db").absolutePath))
        val dir = File(tmpDir, "inflight-blobs-${System.nanoTime()}")
        return AttachmentStore(repo, dir.absolutePath, maxConcurrent) to dir
    }

    @Test
    fun uploadCap_secondConcurrentUploadRejected_capReleasesOnCompletion() {
        val (store, _) = bareStore(maxConcurrent = 1)
        val policy = ClientPolicy()
        runBlocking {
            val ch1 = ByteChannel(autoFlush = true)
            val first = async(Dispatchers.IO) { runCatching { store.store("user-1", uuid(), uuid(), uuid(), ch1, policy) } }
            ch1.writeFully(ByteArray(Attachments.HEADER_BYTES + 100) { 1 }) // header + some ciphertext, then HOLD open
            delay(250) // let the first store acquire its permit and enter the read loop

            // Same user, concurrent → semaphore full → 429. The failed acquire must NOT
            // release a permit it never took (over-release would corrupt the cap).
            val second = runCatching { store.store("user-1", uuid(), uuid(), uuid(), ByteChannel(autoFlush = true), policy) }
            assertTrue(second.exceptionOrNull() is RateLimited, "expected RateLimited, got $second")
            // Still rejected (permit count uncorrupted by the failed acquire above).
            val secondAgain = runCatching { store.store("user-1", uuid(), uuid(), uuid(), ByteChannel(autoFlush = true), policy) }
            assertTrue(secondAgain.exceptionOrNull() is RateLimited)

            // A DIFFERENT user is unaffected (the cap is per-user).
            val chOther = ByteChannel(autoFlush = true)
            val other = async(Dispatchers.IO) { runCatching { store.store("user-2", uuid(), uuid(), uuid(), chOther, policy) } }
            chOther.writeFully(ByteArray(Attachments.HEADER_BYTES + 64) { 2 })
            chOther.flushAndClose()
            assertTrue(other.await().isSuccess, "other user's upload: ${other.await()}")

            // Completing the first upload releases the permit → a third same-user upload works.
            ch1.flushAndClose()
            assertTrue(first.await().isSuccess, "first upload: ${first.await()}")
            val ch3 = ByteChannel(autoFlush = true)
            val third = async(Dispatchers.IO) { runCatching { store.store("user-1", uuid(), uuid(), uuid(), ch3, policy) } }
            ch3.writeFully(ByteArray(Attachments.HEADER_BYTES + 64) { 3 })
            ch3.flushAndClose()
            assertTrue(third.await().isSuccess, "cap must release after completion: ${third.await()}")
        }
    }

    @Test
    fun uploadQuota_idempotentReUpload_atQuota_isExempt_not413() {
        val (store, _) = bareStore(maxConcurrent = 4)
        val policy = ClientPolicy(userAttachmentsMaxBytes = 4096)
        runBlocking {
            val userId = "user-r"; val itemId = uuid(); val vaultId = uuid(); val attId = uuid()
            // First upload fills most of the tiny quota and commits.
            val body = ByteArray(Attachments.HEADER_BYTES + 3000) { 9 }
            val ch = ByteChannel(autoFlush = true); ch.writeFully(body); ch.flushAndClose()
            val meta = store.store(userId, attId, itemId, vaultId, ch, policy)
            assertEquals(attId, meta.attachmentId)

            // Idempotent RE-upload of the SAME id+bytes (a normal retry). The bytes already
            // count in committedBytes; the mid-stream bound must NOT re-count them and 413.
            val ch2 = ByteChannel(autoFlush = true); ch2.writeFully(body); ch2.flushAndClose()
            val again = runCatching { store.store(userId, attId, itemId, vaultId, ch2, policy) }
            assertTrue(again.isSuccess, "idempotent re-upload near quota must return stored meta, not 413: $again")
            assertEquals(attId, again.getOrThrow().attachmentId)
        }
    }

    @Test
    fun uploadQuota_countsInFlightBytes_beforeCommit() {
        val (store, dir) = bareStore(maxConcurrent = 4)
        val policy = ClientPolicy(userAttachmentsMaxBytes = 4096) // tiny per-user budget
        runBlocking {
            // First upload streams ~3 KiB and stays OPEN — nothing committed yet.
            val ch1 = ByteChannel(autoFlush = true)
            val first = async(Dispatchers.IO) { runCatching { store.store("user-q", uuid(), uuid(), uuid(), ch1, policy) } }
            ch1.writeFully(ByteArray(Attachments.HEADER_BYTES + 3072) { 1 })
            delay(250)

            // Second upload crosses committed+in-flight mid-stream → 413 BEFORE any commit.
            val attId2 = uuid()
            val ch2 = ByteChannel(autoFlush = true)
            val second = async(Dispatchers.IO) { runCatching { store.store("user-q", attId2, uuid(), uuid(), ch2, policy) } }
            ch2.writeFully(ByteArray(Attachments.HEADER_BYTES + 3072) { 2 })
            ch2.flushAndClose()
            val err = second.await().exceptionOrNull()
            assertTrue(err is PayloadTooLarge && err.reason == "user_attachment_quota", "expected mid-stream quota, got $err")
            assertTrue(!File(dir, "$attId2.part").exists(), "rejected upload's .part must be cleaned up")

            // Draining: finish the first (fits alone); accounting returns; a small upload succeeds.
            ch1.flushAndClose()
            assertTrue(first.await().isSuccess, "first upload: ${first.await()}")
            val ch3 = ByteChannel(autoFlush = true)
            val third = async(Dispatchers.IO) { runCatching { store.store("user-q", uuid(), uuid(), uuid(), ch3, policy) } }
            ch3.writeFully(ByteArray(Attachments.HEADER_BYTES + 128) { 3 })
            ch3.flushAndClose()
            assertTrue(third.await().isSuccess, "in-flight accounting must drain: ${third.await()}")
        }
    }

    // ---- LOW-9: WS auth via single-use ticket; raw access token in query removed ----

    @Test
    fun wsTicket_mint_connect_singleUse_bearerStays_accessQueryRemoved() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val ws = createClient {
            install(ContentNegotiation) { json(json) }
            install(WebSockets)
        }
        val admin = VirtualClient("ws@x.com", "ws ticket password one", fast = true)
        ws.register(admin, bootstrapToken)

        suspend fun mint(): String {
            val resp = ws.post("/api/v1/events/ticket") { authed(admin) }
            assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            return json.decodeFromString(WsTicketResponse.serializer(), resp.bodyAsText()).ticket
        }

        // Mint → connect → live socket (ping/pong).
        val ticket = mint()
        ws.webSocket("/api/v1/events?ticket=${ticket.encodeURLParameter()}") {
            outgoing.send(Frame.Text("ping"))
            assertEquals("pong", (incoming.receive() as Frame.Text).readText())
        }

        // Strictly single-use: replaying the SAME ticket is refused.
        ws.webSocket("/api/v1/events?ticket=${ticket.encodeURLParameter()}") {
            assertEquals(CloseReason.Codes.VIOLATED_POLICY.code, closeReason.await()?.code)
        }

        // The removed ?access= path stays removed — even with a VALID access token.
        ws.webSocket("/api/v1/events?access=${admin.accessToken.encodeURLParameter()}") {
            assertEquals(CloseReason.Codes.VIOLATED_POLICY.code, closeReason.await()?.code)
        }

        // Authorization: Bearer on the upgrade still works (non-browser callers).
        ws.webSocket("/api/v1/events", request = { authed(admin) }) {
            outgoing.send(Frame.Text("ping"))
            assertEquals("pong", (incoming.receive() as Frame.Text).readText())
        }
    }

    @Test
    fun wsTicket_expiry_and_atomicRedeem() {
        val expired = WsTicketStore(ttlMs = 1)
        val t = expired.mint("user-x")
        Thread.sleep(10)
        assertNull(expired.redeem(t), "an expired ticket must not redeem")

        val store = WsTicketStore()
        val t2 = store.mint("user-y")
        assertEquals("user-y", store.redeem(t2))
        assertNull(store.redeem(t2), "a redeemed ticket must not redeem twice")
        assertNull(store.redeem("garbage"))
    }

    // ---- INFO-1: no PII in audit meta; create↔redeem correlate via token-hash prefix ----

    @Test
    fun auditMeta_carriesTokenHashPrefix_notEmail() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("meta@x.com", "audit meta password one", fast = true)
        client.register(admin, bootstrapToken)

        val inviteResp = client.post("/api/v1/admin/users") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(InviteRequest("second@x.com", isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inviteResp.status, inviteResp.bodyAsText())
        val invite = json.decodeFromString(InviteResponse.serializer(), inviteResp.bodyAsText())
        val second = VirtualClient("second@x.com", "second user password xyz", fast = true)
        client.register(second, invite.inviteToken)

        val creates = client.auditRows(admin, "invite_create")
        val registers = client.auditRows(admin, "register")
        assertTrue((creates + registers).none { it.meta?.contains("@") == true }, "no email may appear in audit meta")
        val createMeta = creates.first().meta
        assertEquals(12, createMeta?.length)
        assertTrue(
            registers.any { it.userId == second.userId && it.meta == createMeta },
            "the register row must carry the SAME token-hash prefix as its invite_create",
        )
    }

    // ---- INFO-3: prelogin answers the STORED org-default params for unknown emails ----

    @Test
    fun prelogin_unknownEmail_reflectsStoredPolicyParams() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("pol@x.com", "prelogin policy password", fast = true)
        client.register(admin, bootstrapToken)

        // Bump the org default params (the KDF floor is off in the test config).
        val put = client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(ClientPolicy(kdfParams = KdfParams(ops = 2, memBytes = 32L * 1024 * 1024)))
        }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())

        suspend fun prelogin(email: String): PreloginResponse {
            val resp = client.post("/api/v1/auth/prelogin") {
                contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
                setBody(PreloginRequest(email))
            }
            assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
            return json.decodeFromString(PreloginResponse.serializer(), resp.bodyAsText())
        }

        // Unknown email → the CURRENT stored default, not the compile-time one.
        val unknown = prelogin("nobody@x.com")
        assertEquals(2, unknown.kdfParams.ops)
        assertEquals(32L * 1024 * 1024, unknown.kdfParams.memBytes)
        // Known account → its own real params (clients need them pre-auth).
        assertEquals(1, prelogin("pol@x.com").kdfParams.ops)
    }

    // ---- INFO-5: policy_update audit rides the policy tx (exactly one row) ----

    @Test
    fun policyUpdate_auditedExactlyOnce_inTx() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("ptx@x.com", "policy tx audit password", fast = true)
        client.register(admin, bootstrapToken)

        val put = client.put("/api/v1/admin/policy") {
            contentType(ContentType.Application.Json); authed(admin)
            setBody(ClientPolicy(autoLockSeconds = 123))
        }
        assertEquals(HttpStatusCode.OK, put.status, put.bodyAsText())
        val rows = client.auditRows(admin, "policy_update")
        assertEquals(1, rows.size, "exactly one policy_update row per change")
        assertEquals(admin.userId, rows.first().userId)
        val pol = client.get("/api/v1/admin/policy") { authed(admin) }
        assertTrue(pol.bodyAsText().contains("\"autoLockSeconds\":123"), "the change itself must land")
    }

    // ---- INFO-6: admin ids are UUID-validated (400, not a silent no-op UPDATE) ----

    @Test
    fun adminIds_rejectNonUuid() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val admin = VirtualClient("uuid@x.com", "admin uuid guard password", fast = true)
        client.register(admin, bootstrapToken)

        val disable = client.post("/api/v1/admin/users/not-a-uuid/disable") { authed(admin) }
        assertEquals(HttpStatusCode.BadRequest, disable.status)
        assertEquals("bad_user_id", errorOf(disable))
        val revoke = client.post("/api/v1/admin/devices/zzz/revoke") { authed(admin) }
        assertEquals(HttpStatusCode.BadRequest, revoke.status)
        assertEquals("bad_device_id", errorOf(revoke))
        val escrow = client.get("/api/v1/admin/users/123/escrow") { authed(admin) }
        assertEquals(HttpStatusCode.BadRequest, escrow.status)
        assertEquals("bad_user_id", errorOf(escrow))
    }

    // ---- INFO-8: CSP on static web gains object-src / form-action ----

    @Test
    fun csp_includesObjectSrcAndFormAction() = testApplication {
        val webDir = File(tmpDir, "web-${System.nanoTime()}").apply { mkdirs() }
        File(webDir, "index.html").writeText("<!doctype html><title>andvari</title>")
        val cfg = Config(
            host = "127.0.0.1", port = 0,
            dbPath = File(tmpDir, "csp-${System.nanoTime()}.db").absolutePath,
            blobDir = File(tmpDir, "csp-blobs-${System.nanoTime()}").absolutePath,
            webDir = webDir.absolutePath,
            recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
            enumSecret = ByteArray(32) { 7 }, publicHostname = null, bootstrapToken = bootstrapToken,
        )
        application { andvariModule(buildServices(cfg, Notifier())) }
        val client = jsonClient(this)
        val resp = client.get("/")
        assertEquals(HttpStatusCode.OK, resp.status)
        val csp = resp.headers["Content-Security-Policy"] ?: ""
        assertTrue(csp.contains("object-src 'none'"), csp)
        assertTrue(csp.contains("form-action 'none'"), csp)
        assertTrue(csp.contains("script-src 'self' 'wasm-unsafe-eval'"), csp)
    }
}
