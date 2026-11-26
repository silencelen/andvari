package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.VaultLog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Password change, recovery posture, the kit, assisted recovery and account deletion (spec 03 §3, §12, §13, §18). */
class RecoveryAndDeletionTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun reset(newKey: String) =
        """"newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA""""

    @Test
    fun passwordChange_revokesOthers_andIsACompareAndSwap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = WireJson.json.decodeFromString(SessionResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody()).bodyAsText())
        val newKey = b32()
        val body = """{"currentAuthKey":"${me.authKey}",${reset(newKey).replace("newKdfSalt", "newKdfSalt")}}"""
        assertEquals("reauth_failed", c.call(HttpMethod.Put, "/api/v1/account/password", body.replace(me.authKey, b32()), me.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/password", body, me.token).status.value)
        assertEquals(200, c.call(HttpMethod.Get, "/api/v1/account/keys", token = me.token).status.value)
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = other.accessToken).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(authKey = newKey)).status.value)
        assertEquals("password_changed", Flow.sink(s).last { it.first == "password_changed" }.first)
    }

    @Test
    fun kitRecovery_verifyCommit_replacesTheKit_clearsRequireLinkAndTotp() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        s.db.tx { it.exec("UPDATE users SET requireLink=1, totpSecret='JBSWY3DPEHPK3PXP' WHERE userId=?", me.userId) }
        // Unknown address, wrong key: the same 401.
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"nobody@example.com","recoveryAuthKey":"${b32()}"}""").errorCode())
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${b32()}"}""").errorCode())
        val v = WireJson.json.decodeFromString(RecoveryVerifyResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").bodyAsText())
        assertEquals(me.userId, v.userId)
        val newKey = b32()
        val newKit = b32()
        val commit = """{"recoveryTicket":"${v.recoveryTicket}",${reset(newKey)},"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$newKit"},"device":{"platform":"ios","name":"new phone","deviceSecret":"${b32()}"}}"""
        assertEquals("recovery_required", c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", commit.replace(""","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$newKit"}""", "")).errorCode())
        // That burned the ticket (it is validated first).
        assertEquals("invalid_ticket", c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", commit).errorCode())
        val v2 = WireJson.json.decodeFromString(RecoveryVerifyResponse.serializer(), c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").bodyAsText())
        val r = c.call(HttpMethod.Post, "/api/v1/recovery/self/commit", commit.replace(v.recoveryTicket, v2.recoveryTicket))
        assertEquals(200, r.status.value, r.bodyAsText())
        val sess = WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        assertTrue(sess.recoveryPieceId != null)
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = me.token).errorCode())
        // The old kit is dead; requireLink and TOTP are off.
        assertEquals("invalid_credentials", c.call(HttpMethod.Post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"${me.recoveryAuthKey}"}""").errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(authKey = newKey)).status.value)
        val mails = Flow.sink(s).map { it.first }
        assertTrue(mails.containsAll(listOf("recovery_applied", "two_step_off", "require_link_cleared")), mails.toString())
        // The capture gate: a stale piece id is refused, the current one confirms.
        assertEquals("recovery_piece_stale", c.call(HttpMethod.Post, "/api/v1/recovery/self/confirm", """{"pieceId":"nope"}""", sess.accessToken).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/recovery/self/confirm", """{"pieceId":"${sess.recoveryPieceId}"}""", sess.accessToken).status.value)
        assertTrue(c.call(HttpMethod.Get, "/api/v1/account/keys", token = sess.accessToken).bodyAsText().contains("\"recoveryConfirmed\":true"))
    }

    @Test
    fun recoveryPosture_andEscrowReseal() = testApplication {
        val recovery = TestKit.Identity()
        val key = recovery.curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val fp = sha256Hex(key)
        val esc = Flow.escrow(me, fp)
        val body = { posture: String, escrow: String, base: Long -> """{"posture":"$posture"$escrow,"currentAuthKey":"${me.authKey}","accountState":{"sealedState":"AAAA","baseSeq":$base}}""" }
        assertEquals("bad_escrow", c.call(HttpMethod.Put, "/api/v1/account/recovery", body("operator", ""","escrow":{"sealed":"AAAA","fingerprint":"$fp"}""", 0), me.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/recovery", body("operator", ""","escrow":{"sealed":"${esc.sealed}","fingerprint":"$fp"}""", 0), me.token).status.value)
        assertEquals("stale_state", c.call(HttpMethod.Put, "/api/v1/account/recovery", body("private", "", 0), me.token).errorCode())
        // A re-seal needs a rotation chain from the stored fingerprint.
        val next = TestKit.Identity()
        val nextFp = sha256Hex(next.curvePub)
        val instanceId = s.db.read { s.instance.instanceId(it) }
        val rot = recovery.frame(8, """{"v":2,"purpose":"recovery-rotation","instanceId":"$instanceId","fromFp":"$fp","toFp":"$nextFp","issuedAt":1800000000000}""")
        assertEquals("escrow_not_due", c.call(HttpMethod.Put, "/api/v1/escrow/self", """{"sealed":"${esc.sealed}","fingerprint":"$nextFp","rotations":[]}""", me.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/escrow/self", """{"sealed":"${esc.sealed}","fingerprint":"$nextFp","rotations":["${Bytes.toB64(rot)}"]}""", me.token).status.value)
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/recovery", body("private", "", 1), me.token).status.value)
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM escrow WHERE userId=?", me.userId) })
        assertEquals("escrow_not_allowed", c.call(HttpMethod.Put, "/api/v1/escrow/self", """{"sealed":"${esc.sealed}","fingerprint":"$nextFp","rotations":["${Bytes.toB64(rot)}"]}""", me.token).errorCode())
    }

    /** Spec 03 §3.2's order: the posture, then the blob's shape, then the rotations; a malformed frame is a chain failure. */
    @Test
    fun escrowReseal_checksPostureThenShapeThenRotations() = testApplication {
        val recovery = TestKit.Identity()
        val key = recovery.curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val fp = sha256Hex(key)
        val good = Flow.escrowFor("op@example.com", fp).sealed
        val priv = Flow.member(c, s, "private@example.com")
        val op = Me("op@example.com")
        Flow.register(c, s, op, Flow.enrolAuth(s), "operator", EscrowUpload(good, fp))
        val malformed = """["!!"]"""
        val put = { sealed: String, rotations: String -> """{"sealed":"$sealed","fingerprint":"$fp","rotations":$rotations}""" }
        // A private account: the posture is checked before the malformed frame.
        val r1 = c.call(HttpMethod.Put, "/api/v1/escrow/self", put(good, malformed), priv.token)
        assertEquals(400, r1.status.value, r1.bodyAsText()); assertEquals("escrow_not_allowed", r1.errorCode())
        // An operator account with a malformed blob: the shape is checked before the frame.
        val r2 = c.call(HttpMethod.Put, "/api/v1/escrow/self", put("AAAA", malformed), op.token)
        assertEquals(400, r2.status.value, r2.bodyAsText()); assertEquals("bad_escrow", r2.errorCode())
        // A good blob with a malformed frame: the chain fails, 409.
        val r3 = c.call(HttpMethod.Put, "/api/v1/escrow/self", put(good, malformed), op.token)
        assertEquals(409, r3.status.value, r3.bodyAsText()); assertEquals("escrow_not_due", r3.errorCode())
        // More than 64 rotations is the same answer.
        val many = (1..65).joinToString(",", "[", "]") { "\"AAAAAAAA\"" }
        val r4 = c.call(HttpMethod.Put, "/api/v1/escrow/self", put(good, many), op.token)
        assertEquals(409, r4.status.value, r4.bodyAsText()); assertEquals("escrow_not_due", r4.errorCode())
    }

    @Test
    fun assistedRecovery_create_verify_list_veto_poll() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        val priv = Flow.member(c, s, "private@example.com")
        Flow.sink(s)
        val poll = TestKit.crypto.randomBytes(32)
        val create = { email: String -> """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(poll)}","platform":"android"}""" }
        val unknown = c.call(HttpMethod.Post, "/api/v1/recovery/requests", create("nobody@example.com"))
        assertEquals(202, unknown.status.value)
        c.call(HttpMethod.Post, "/api/v1/recovery/requests", create(priv.email))
        val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), c.call(HttpMethod.Post, "/api/v1/recovery/requests", create(me.email)).bodyAsText()).requestId
        val mails = Flow.sink(s)
        assertEquals(listOf("recovery_request_private", "recovery_request_code"), mails.map { it.first })
        val code = Flow.codeIn(mails.last().third)
        assertEquals("""{"state":"unverified"}""", c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", """{"pollSecret":"${Bytes.toB64(poll)}"}""").bodyAsText())
        assertEquals("request_unknown", c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", """{"pollSecret":"${b32()}"}""").errorCode())
        assertEquals("bad_code", c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"${if (code == "000000") "111111" else "000000"}"}""").errorCode())
        val ver = c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""")
        assertEquals(200, ver.status.value, ver.bodyAsText())
        assertTrue(c.call(HttpMethod.Get, "/api/v1/account/recovery-requests", token = me.token).bodyAsText().contains(reqId))
        assertTrue(c.call(HttpMethod.Get, "/api/v1/sync?since=0", token = me.token).bodyAsText().contains("\"recoveryRequests\":1"))
        // The veto is a statement signed by the account.
        val veto = me.identity.frame(10, """{"v":2,"purpose":"recovery-veto","requestId":"$reqId","userId":"${me.userId}","issuedAt":1800000000000}""")
        val forged = TestKit.Identity().frame(10, """{"v":2,"purpose":"recovery-veto","requestId":"$reqId","userId":"${me.userId}","issuedAt":1800000000000}""")
        assertEquals("bad_signer", c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/veto", """{"statement":"${Bytes.toB64(forged)}"}""", me.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/veto", """{"statement":"${Bytes.toB64(veto)}"}""", me.token).status.value)
        assertEquals("""{"state":"vetoed"}""", c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", """{"pollSecret":"${Bytes.toB64(poll)}"}""").bodyAsText())
        assertEquals("request_state", c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", """{"pollSecret":"${Bytes.toB64(poll)}",${reset(b32())},"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}}""").errorCode())
    }

    @Test
    fun publicInstance_hidesEveryAssistedRecoveryRoute() = testApplication {
        val s = TestKit.services(TestKit.config(kind = "public"))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        for ((m, path, tok) in listOf(
            Triple(HttpMethod.Post, "/api/v1/recovery/requests", null), Triple(HttpMethod.Post, "/api/v1/recovery/requests/AAAAAAAAAAAAAAAAAAAAAA/verify", null),
            Triple(HttpMethod.Post, "/api/v1/recovery/requests/AAAAAAAAAAAAAAAAAAAAAA/veto", me.token), Triple(HttpMethod.Post, "/api/v1/recovery/requests/AAAAAAAAAAAAAAAAAAAAAA/poll", null),
            Triple(HttpMethod.Post, "/api/v1/recovery/requests/AAAAAAAAAAAAAAAAAAAAAA/commit", null), Triple(HttpMethod.Get, "/api/v1/account/recovery-requests", me.token),
            Triple(HttpMethod.Put, "/api/v1/escrow/self", me.token),
        )) {
            val r = c.call(m, path, "{}", tok)
            assertEquals(404, r.status.value, path)
            assertEquals("not_found", r.errorCode(), path)
        }
    }

    @Test
    fun accountDeletion_blockers_leaves_effect() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        s.db.tx { writeConnection(it, a.userId, b.userId, clock.now()) }
        val vaultId = uuid()
        val crypto = TestKit.crypto
        val t = clock.now()
        val g = VaultLog.sign(crypto, a.identity.sign, LogEntry.Genesis(vaultId, a.userId, t, a.identity.identityPubB64, "a".repeat(64)))
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"${Bytes.toB64(g)}","metaBlob":"AAAA","wrappedVk":"AAAA"}""", a.token).status.value)
        val add = VaultLog.sign(crypto, a.identity.sign, LogEntry.Add(vaultId, 1, sha256Hex(g), a.userId, t, b.userId, b.identity.identityPubB64, MemberRole.WRITER, Bytes.toB64(crypto.randomBytes(16))))
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"${Bytes.toB64(add)}","grant":"AAAA"}""", a.token).status.value)
        // The owner of a shared vault with a member is blocked; the operator account is blocked.
        val del = { me: Me, leaves: String -> """{"confirmEmail":"${me.email.uppercase()}","currentAuthKey":"${me.authKey}","leaves":[$leaves]}""" }
        val blocked = c.call(HttpMethod.Post, "/api/v1/account/delete", del(a, ""), a.token)
        assertEquals("account_delete_blocked", blocked.errorCode()); assertTrue(blocked.bodyAsText().contains(vaultId))
        assertTrue(c.call(HttpMethod.Post, "/api/v1/account/delete", del(op, ""), op.token).bodyAsText().contains("\"kind\":\"operator\""))
        assertEquals("confirm_email_mismatch", c.call(HttpMethod.Post, "/api/v1/account/delete", del(b, "").replace(b.email.uppercase(), "x@example.com"), b.token).errorCode())
        // The member needs a leave at the served head.
        val preview = WireJson.json.decodeFromString(AccountDeletePreview.serializer(), c.call(HttpMethod.Get, "/api/v1/account/delete/preview", token = b.token).bodyAsText())
        assertEquals(listOf(vaultId), preview.memberships.map { it.vaultId })
        val stale = c.call(HttpMethod.Post, "/api/v1/account/delete", del(b, ""), b.token)
        assertEquals("account_delete_log_stale", stale.errorCode()); assertTrue(stale.bodyAsText().contains(vaultId))
        val head = preview.memberships.single().head
        val leave = VaultLog.sign(crypto, b.identity.sign, LogEntry.Leave(vaultId, head.seq + 1, head.hash, b.userId, maxOf(t, head.at)))
        // An `account` rev names the userId as its entity (DeviceLinks' pickup writes one the same way).
        s.db.tx { nextRev(it, "account", b.userId, null, 0L) }
        val revBefore = s.db.read { currentRev(it) }
        val ok = c.call(HttpMethod.Post, "/api/v1/account/delete", del(b, "\"${Bytes.toB64(leave)}\""), b.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        s.db.read { db ->
            // No `changes` row keeps the id, and the global rev never moves backwards.
            assertEquals(0L, db.count("SELECT COUNT(*) FROM changes WHERE entityId=?", b.userId))
            assertTrue(currentRev(db) >= revBefore)
            assertEquals(0L, db.count("SELECT COUNT(*) FROM users WHERE userId=?", b.userId))
            assertEquals(1L, db.count("SELECT COUNT(*) FROM retired_ids WHERE idHash=?", sha256Hex(b.userId)))
            assertEquals(2L, db.count("SELECT COUNT(*) FROM vault_log WHERE vaultId=? AND kind='leave'", vaultId).plus(1))
            assertEquals(0L, db.count("SELECT COUNT(*) FROM connections"))
            assertEquals(0L, db.count("SELECT COUNT(*) FROM audit WHERE userId=?", b.userId))
            assertEquals(1L, db.count("SELECT COUNT(*) FROM vaults WHERE vaultId=? AND purgedAt IS NOT NULL", b.personalVaultId))
        }
        assertEquals("account_deleted", Flow.sink(s).last().first)
        // The address can register again as a new account; the old id cannot.
        assertEquals("user_id_taken", c.call(HttpMethod.Post, "/api/v1/auth/register", Me(b.email, userId = b.userId).register(s, Flow.enrolAuth(s))).errorCode())
        Flow.register(c, s, Me(b.email), Flow.enrolAuth(s))
    }
}
