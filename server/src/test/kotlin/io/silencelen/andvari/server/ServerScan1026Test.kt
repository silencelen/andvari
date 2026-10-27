package io.silencelen.andvari.server

import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.EscrowUpload
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.PersonalWrapPut
import io.silencelen.andvari.core.model.PreloginRequest
import io.silencelen.andvari.core.model.UsageUpload
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Server scan 2026-10-26 (Claude Security, `server` scope at 0.28.1, 0 crit / 0 high / 6 med / 5 low):
 * one pin per fixed finding, each written so that reverting the fix turns exactly that test red.
 *
 *  F1  `attachmentIds` list unbounded, duplicate-tolerant, outside every quota   → shape gate, `rejected`
 *  F2  `mutationId` of unbounded length persisted twice per mutation for 180 d  → length gate, `rejected`
 *  F3  login/prelogin email unbounded; EmailBackoff keyed on the raw string     → 400 + digest key
 *  F4  changePassword / recoverySelfSetup / putPersonalWrap verify-then-write    → compare-and-swap
 *  F5  retired-key escrow blobs survive the rotation purge in free pages + WAL   → secure_delete + checkpoint
 *  F8  pickClientIp read only the FIRST X-Forwarded-For line                     → AuditHardeningTest
 *  F10 attachment upload distinguished a foreign vault's id (`attachment_id_taken`) → uniform `no_grant`
 *  F11 PUT /usage, PUT /escrow/self, POST /events/ticket had no rate bucket     → per-user buckets
 */
class ServerScan1026Test : P4TestSupport() {

    private val ip = "test"

    // ---- F1: the attachmentIds LIST is bounded before its members are resolved ----

    @Test
    fun f1_attachmentList_tooLong_duplicate_orMalformed_isRejectedPerMutation() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("f1@x.com", "attachment list password 1")
        client.register(vc, bootstrapToken)

        val enc = Attachments.encrypt(crypto, crypto.randomBytes(32), crypto.randomBytes(64))
        val attId = uuid()
        val itemId = vc.newItemId()
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(vc, attId, itemId, enc.header + enc.ciphertext).status)

        // The exploit shape: ONE real id, repeated. Before the fix this passed the reference check
        // (dedup → one lookup) and the quota (zero-byte blob) and persisted the whole list.
        val repeated = client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"dup"}""", 0, List(2_000) { attId }))
        assertEquals("rejected", repeated.results[0].status)
        assertEquals("too_many_attachments", repeated.results[0].reason)

        val twice = client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"dup"}""", 0, listOf(attId, attId)))
        assertEquals("rejected", twice.results[0].status)
        assertEquals("duplicate_attachment", twice.results[0].reason)

        val malformed = client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"bad"}""", 0, listOf(attId.uppercase())))
        assertEquals("rejected", malformed.results[0].status)
        assertEquals("bad_attachment_id", malformed.results[0].reason)

        // Nothing was persisted by any of the three, and the honest put still lands.
        assertTrue(client.sync(vc).items.none { it.itemId == itemId })
        val ok = client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"good"}""", 0, listOf(attId)))
        assertEquals("applied", ok.results[0].status)
        assertEquals(listOf(attId), client.sync(vc).items.single { it.itemId == itemId }.attachmentIds)

        // The restore route shares the gate, in its thrown form (spec 03 §8).
        client.push(vc, Mutation(uuid(), "delete", itemId, vc.personalVaultId, ok.results[0].newItemRev!!))
        val restore = client.post("/api/v1/items/$itemId/restore") {
            contentType(ContentType.Application.Json); authed(vc)
            setBody(vc.encItem(itemId, """{"type":"note","name":"back"}""").copy(attachmentIds = listOf(attId, attId)))
        }
        assertEquals(HttpStatusCode.BadRequest, restore.status, restore.bodyAsText())
        assertEquals("duplicate_attachment", errorOf(restore))
    }

    // ---- F2: the mutationId is bounded before the idempotency lookup ----

    @Test
    fun f2_oversizedMutationId_isRejected_andNeverJournaled() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("f2@x.com", "mutation id password 1")
        client.register(vc, bootstrapToken)

        // The exploit shape: a no-op delete in the caller's own vault (`applied`, and cached) with a
        // huge id. 64 KiB here stands in for the 8 MiB the body cap allows.
        val huge = "m".repeat(64 * 1024)
        val resp = client.push(vc, Mutation(huge, "delete", vc.newItemId(), vc.personalVaultId, 0))
        assertEquals("rejected", resp.results[0].status)
        assertEquals("bad_mutation_id", resp.results[0].reason)
        assertEquals(MUTATION_ID_MAX_CHARS, resp.results[0].mutationId.length, "the echo is truncated, not reflected")
        val journaled = services.repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM mutations WHERE deviceId<>''") { it.getInt(1) } ?: 0 }
        assertEquals(0, journaled, "a rejected mutation is never written to the idempotency journal")

        // The boundary: a 64-char id is accepted (and journaled), a 65-char one is not, an empty one is not.
        assertEquals("applied", client.push(vc, Mutation("a".repeat(MUTATION_ID_MAX_CHARS), "delete", vc.newItemId(), vc.personalVaultId, 0)).results[0].status)
        assertEquals("rejected", client.push(vc, Mutation("a".repeat(MUTATION_ID_MAX_CHARS + 1), "delete", vc.newItemId(), vc.personalVaultId, 0)).results[0].status)
        assertEquals("rejected", client.push(vc, Mutation("", "delete", vc.newItemId(), vc.personalVaultId, 0)).results[0].status)
        // And the honest UUID shape every client sends still works end to end.
        val itemId = vc.newItemId()
        assertEquals("applied", client.push(vc, putMutation(vc, itemId, """{"type":"note","name":"n"}""", 0)).results[0].status)
    }

    // ---- F3: the submitted email is bounded, and the backoff key is a digest ----

    @Test
    fun f3_oversizedEmail_is400_beforeAnyLookup_andBackoffStillKeysPerEmail() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val vc = VirtualClient("f3@x.com", "email bound password 1")
        client.register(vc, bootstrapToken)

        val tooLong = "a".repeat(EMAIL_MAX_CHARS - 5) + "@x.com" // 255
        val login = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(tooLong, vc.authKey, DeviceInfo("test", "f3")))
        }
        assertEquals(HttpStatusCode.BadRequest, login.status, login.bodyAsText())
        assertEquals("invalid_email", errorOf(login))
        val prelogin = client.post("/api/v1/auth/prelogin") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(PreloginRequest(tooLong))
        }
        assertEquals(HttpStatusCode.BadRequest, prelogin.status, prelogin.bodyAsText())
        // The refusal left no backoff state behind: the oversized string never reached the map.
        assertFalse(services.service.loginBackoff.blocked(tooLong))

        // The longest legal address is NOT refused by shape (it falls through to the uniform 401).
        val longest = "a".repeat(EMAIL_MAX_CHARS - 6) + "@x.com" // 254
        val legal = client.post("/api/v1/auth/login") {
            contentType(ContentType.Application.Json); header("X-Andvari-Client", "test/1.0.0")
            setBody(LoginRequest(longest, vc.authKey, DeviceInfo("test", "f3")))
        }
        assertEquals(HttpStatusCode.Unauthorized, legal.status)

        // Digest keying is transparent: normalisation and per-email isolation hold as before.
        val backoff = EmailBackoff(threshold = 2)
        repeat(2) { backoff.fail("  Who@Example.ORG ") }
        assertTrue(backoff.blocked("who@example.org"))
        assertFalse(backoff.blocked("other@example.org"))
        backoff.success("WHO@example.org")
        assertFalse(backoff.blocked("who@example.org"))
    }

    // ---- F4: password-gated writes are a compare-and-swap on the credential epoch ----

    private fun enrolledDirect(email: String): Pair<Services, VirtualClient> {
        val services = buildServices(config(), Notifier())
        val vc = VirtualClient(email, "the old password, phished")
        val s = services.service.register(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), ip)
        vc.userId = s.userId; vc.accessToken = s.accessToken; vc.refreshToken = s.refreshToken
        return services to vc
    }

    private fun liveSessions(services: Services, userId: String): Int = services.repo.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL", userId) { it.getInt(1) } ?: 0
    }

    private fun verifierOf(services: Services, userId: String): String = services.repo.db.read { c ->
        c.queryOne("SELECT verifier FROM users WHERE userId=?", userId) { it.getString(1) }!!
    }

    @Test
    fun f4_changePassword_landingAfterTheVictimsOwnChange_writesNothing() {
        val (services, victim) = enrolledDirect("f4a@x.com")
        // The attacker holds the (phished) password and a live token: the register session.
        val attacker = assertNotNull(services.service.authenticate(victim.accessToken))
        // The victim remediates from a second device.
        val victimSession = services.service.login(LoginRequest(victim.email, victim.authKey, DeviceInfo("test", "victim-phone")), ip)
        val victimPrincipal = assertNotNull(services.service.authenticate(victimSession.accessToken))
        val remediation = victim.buildPasswordChange("the new password, private")

        services.service.credentialWritePreTxProbe = {
            services.service.credentialWritePreTxProbe = null
            // Lands between the attacker's verify and the attacker's write tx.
            services.service.changePassword(victimPrincipal, remediation, ip)
        }
        val attack = victim.buildPasswordChange("attacker chosen password")
        val refused = assertFailsWith<Unauthorized> { services.service.changePassword(attacker, attack, ip) }
        assertEquals("credential_changed", refused.reason)

        // The victim's credentials stand, the attacker's never landed, and only the victim's session lives.
        assertTrue(ServerCrypto.verify(verifierOf(services, victim.userId), remediation.newAuthKey), "the victim's new password is the one on file")
        assertFalse(ServerCrypto.verify(verifierOf(services, victim.userId), attack.newAuthKey), "the attacker's password never landed")
        assertEquals(1, liveSessions(services, victim.userId))
        assertNull(services.service.authenticate(victim.accessToken), "the attacker's session was revoked by the victim's change")
        val fails = services.repo.db.read { c -> c.queryAll("SELECT meta FROM audit WHERE type='password_change_fail' AND userId=?", victim.userId) { it.getString(1) } }
        assertEquals(listOf("credential_changed"), fails)
    }

    @Test
    fun f4_changePassword_landingAfterARecoveryCommit_writesNothing() {
        val (services, victim) = enrolledDirect("f4b@x.com")
        val attacker = assertNotNull(services.service.authenticate(victim.accessToken))
        // An admin recovery replaces the verifier + wrappedUvk and revokes every session.
        services.service.credentialWritePreTxProbe = {
            services.service.credentialWritePreTxProbe = null
            services.repo.db.tx { c ->
                c.exec("UPDATE users SET verifier=? WHERE userId=?", ServerCrypto.hashVerifier(Bytes.toB64(crypto.randomBytes(32))), victim.userId)
                c.exec("UPDATE sessions SET revokedAt=? WHERE userId=? AND revokedAt IS NULL", now(), victim.userId)
            }
        }
        val before = verifierOf(services, victim.userId)
        assertFailsWith<Unauthorized> { services.service.changePassword(attacker, victim.buildPasswordChange("attacker chosen"), ip) }
        assertNotEquals(before, verifierOf(services, victim.userId), "the remediation's verifier is the one on file")
        assertEquals(0, liveSessions(services, victim.userId), "the attacker's write did not resurrect any session")
    }

    @Test
    fun f4_recoverySelfSetup_andReauthedPersonalWrap_shareTheCompareAndSwap() {
        val (services, victim) = enrolledDirect("f4c@x.com")
        val attacker = assertNotNull(services.service.authenticate(victim.accessToken))
        val victimSession = services.service.login(LoginRequest(victim.email, victim.authKey, DeviceInfo("test", "victim-phone")), ip)
        val victimPrincipal = assertNotNull(services.service.authenticate(victimSession.accessToken))
        val pieceBefore = services.repo.db.read { c -> c.queryOne("SELECT pieceId FROM member_recovery WHERE userId=?", victim.userId) { it.getString(1) } }

        // recoverySelfSetup: the attacker tries to replace the member's recovery piece mid-remediation.
        services.service.credentialWritePreTxProbe = {
            services.service.credentialWritePreTxProbe = null
            services.service.changePassword(victimPrincipal, victim.buildPasswordChange("remediated once"), ip)
        }
        val setup = assertFailsWith<Unauthorized> { services.service.recoverySelfSetup(attacker, victim.buildRecoverySelfSetup(), ip) }
        assertEquals("credential_changed", setup.reason)
        val pieceAfter = services.repo.db.read { c -> c.queryOne("SELECT pieceId FROM member_recovery WHERE userId=?", victim.userId) { it.getString(1) } }
        assertEquals(pieceBefore, pieceAfter, "the recovery piece was not replaced")

        // putPersonalWrap (re-authenticated replace): the attacker's session is already revoked by the
        // change above, so the epoch check fails on the session leg too — the write must not happen.
        val wrap = victim.personalWrap()
        val put = assertFailsWith<Unauthorized> {
            services.service.putPersonalWrap(attacker, PersonalWrapPut(wrap.vaultId, wrap.wrappedVk, currentAuthKey = victim.authKey), ip)
        }
        // Either leg refuses (the password no longer verifies, or the epoch moved) — nothing is written.
        assertTrue(put.reason == "credential_changed" || put.reason == "invalid_credentials", put.reason)
        val wrapRow = services.repo.db.read { c -> c.queryOne("SELECT vaultId FROM personal_wrap WHERE userId=?", victim.userId) { it.getString(1) } }
        assertNull(wrapRow, "no personal wrap was written by the refused call")
    }

    // ---- F5: retired-key escrow blobs do not survive the rotation purge in the file or the WAL ----

    private fun fileContains(f: File, needle: ByteArray): Boolean {
        if (!f.exists()) return false
        val bytes = f.readBytes()
        outer@ for (i in 0..bytes.size - needle.size) {
            for (j in needle.indices) if (bytes[i + j] != needle[j]) continue@outer
            return true
        }
        return false
    }

    @Test
    fun f5_rotationPurge_leavesNoRetiredBlobBytes_inTheDatabaseFileOrItsWal() {
        val cfg = config()
        val services = buildServices(cfg, Notifier())
        val vc = VirtualClient("f5@x.com", "secure delete password 1")
        val s = services.service.register(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), ip)
        vc.userId = s.userId

        // A blob sealed to a RETIRED org key, retained by an older build: a recognisable 300-char
        // base64 string so the file scan below is unambiguous.
        val retiredSealed = Bytes.toB64(crypto.randomBytes(225))
        val needle = retiredSealed.encodeToByteArray()
        services.repo.db.tx { c ->
            c.exec(
                "INSERT INTO escrow_legacy(userId,sealed,fingerprint,updatedAt,retainedAt) VALUES(?,?,?,?,?)",
                vc.userId, retiredSealed, "0".repeat(64), now(), now(),
            )
        }
        val db = File(cfg.dbPath)
        val wal = File(cfg.dbPath + "-wal")
        assertTrue(fileContains(db, needle) || fileContains(wal, needle), "control: the blob is on disk before the purge")

        purgeRetiredEscrowLegacy(services.repo, cfg)

        val rows = services.repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM escrow_legacy") { it.getInt(1) } }
        assertEquals(0, rows)
        assertFalse(fileContains(db, needle), "secure_delete zeroed the freed cell in the main file")
        assertFalse(fileContains(wal, needle), "the checkpoint flushed and truncated the WAL frames that carried it")
        assertEquals(0L, if (wal.exists()) wal.length() else 0L, "wal_checkpoint(TRUNCATE) leaves an empty -wal")
    }

    // ---- F10: a foreign vault's attachment id is indistinguishable from a missing one ----

    @Test
    fun f10_uploadUnderOwnVault_withAnotherVaultsAttachmentId_isAUniformNoGrant() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("f10a@x.com", "owner password one one")
        client.register(owner, bootstrapToken)
        val invite = client.post("/api/v1/admin/users") { contentType(ContentType.Application.Json); authed(owner); setBody(InviteRequest("f10b@x.com", isAdmin = false)) }
        assertEquals(HttpStatusCode.OK, invite.status, invite.bodyAsText())
        val token = json.decodeFromString(InviteResponse.serializer(), invite.bodyAsText()).inviteToken
        val other = VirtualClient("f10b@x.com", "other password two two")
        client.register(other, token)

        val enc = Attachments.encrypt(crypto, crypto.randomBytes(32), crypto.randomBytes(64))
        val attId = uuid()
        assertEquals(HttpStatusCode.OK, client.uploadAttachment(owner, attId, owner.newItemId(), enc.header + enc.ciphertext).status)

        // The ex-member probe: a tiny body under THEIR OWN vault, the victim's id. Was `400
        // attachment_id_taken` (exists) vs `200` (gone); now the GET route's `403 no_grant` either way.
        val probe = client.uploadAttachment(other, attId, other.newItemId(), enc.header + enc.ciphertext)
        assertEquals(HttpStatusCode.Forbidden, probe.status, probe.bodyAsText())
        assertEquals("no_grant", errorOf(probe))
        // Same vault, different bytes: still the honest client's `attachment_id_taken` (plan retry, spec 07).
        val other2 = Attachments.encrypt(crypto, crypto.randomBytes(32), crypto.randomBytes(64))
        val taken = client.uploadAttachment(owner, attId, owner.newItemId(), other2.header + other2.ciphertext)
        assertEquals(HttpStatusCode.BadRequest, taken.status)
        assertEquals("attachment_id_taken", errorOf(taken))
    }

    // ---- F11: the three unbucketed authenticated writers/allocators ----

    @Test
    fun f11_usage_escrowSelf_andEventsTicket_areBucketedPerUser() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val vc = VirtualClient("f11@x.com", "rate bucket password 1")
        client.register(vc, bootstrapToken)

        repeat(60) {
            val r = client.put("/api/v1/usage") { contentType(ContentType.Application.Json); authed(vc); setBody(UsageUpload("AAAA")) }
            assertEquals(HttpStatusCode.OK, r.status, "usage put ${it + 1} of 60: ${r.bodyAsText()}")
        }
        val usageOver = client.put("/api/v1/usage") { contentType(ContentType.Application.Json); authed(vc); setBody(UsageUpload("AAAA")) }
        assertEquals(HttpStatusCode.TooManyRequests, usageOver.status)
        assertEquals("rate_limited", errorOf(usageOver))

        repeat(60) {
            val r = client.post("/api/v1/events/ticket") { authed(vc) }
            assertEquals(HttpStatusCode.OK, r.status, "ticket ${it + 1} of 60")
        }
        assertEquals(HttpStatusCode.TooManyRequests, client.post("/api/v1/events/ticket") { authed(vc) }.status)

        val sealed = vc.sealEscrowV2(recovery.publicKey, fingerprint)
        repeat(10) {
            val r = client.put("/api/v1/escrow/self") { contentType(ContentType.Application.Json); authed(vc); setBody(EscrowUpload(sealed, fingerprint)) }
            assertEquals(HttpStatusCode.OK, r.status, "escrow re-seal ${it + 1} of 10: ${r.bodyAsText()}")
        }
        val escrowOver = client.put("/api/v1/escrow/self") { contentType(ContentType.Application.Json); authed(vc); setBody(EscrowUpload(sealed, fingerprint)) }
        assertEquals(HttpStatusCode.TooManyRequests, escrowOver.status)
    }
}
