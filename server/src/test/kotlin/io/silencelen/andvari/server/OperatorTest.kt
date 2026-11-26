package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.EscrowUpload
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The operator routes (spec 03 §7, §18.6) and the janitor (§11.1, §15.8). */
class OperatorTest {
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun reauth(me: Me) = """{"currentAuthKey":"${me.authKey}"}"""

    @Test
    fun accounts_disable_enable_delete_devices_quota() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        // Members and web sessions are refused.
        assertEquals("not_operator", c.call(HttpMethod.Get, "/api/v1/admin/accounts", token = m.token).errorCode())
        val list = WireJson.json.decodeFromString(ListSerializer(AccountSummary.serializer()), c.call(HttpMethod.Get, "/api/v1/admin/accounts", token = op.token).bodyAsText())
        assertEquals(setOf("operator", "member"), list.map { it.role }.toSet())
        assertEquals(1L, list.single { it.userId == m.userId }.liveDeviceCount)
        assertEquals("cannot_target_self", c.call(HttpMethod.Post, "/api/v1/admin/accounts/${op.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token).errorCode())
        assertEquals("no_such_user", c.call(HttpMethod.Post, "/api/v1/admin/accounts/${uuid()}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        assertEquals("invalid_credentials", c.call(HttpMethod.Get, "/api/v1/account/keys", token = m.token).errorCode())
        // Deletion waits 30 days after the disable.
        val early = c.call(HttpMethod.Post, "/api/v1/admin/accounts/${m.userId}/delete", reauth(op), op.token)
        assertEquals("not_disabled_long_enough", early.errorCode()); assertTrue(early.bodyAsText().contains("\"disabledAt\""))
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/admin/accounts/${m.userId}/enable", reauth(op), op.token).status.value)
        // Quota: every key required.
        assertEquals("bad_request", c.call(HttpMethod.Put, "/api/v1/admin/accounts/${m.userId}/quota", """{"accountBytes":5,"items":null,"ownedSharedVaults":null,"currentAuthKey":"${op.authKey}"}""", op.token).errorCode())
        val q = c.call(HttpMethod.Put, "/api/v1/admin/accounts/${m.userId}/quota", """{"accountBytes":5,"items":null,"ownedSharedVaults":null,"openLinks":3,"currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals("""{"accountBytes":5,"items":5000,"ownedSharedVaults":50,"openLinks":3}""", q.bodyAsText())
        // Devices and revoke.
        assertTrue(c.call(HttpMethod.Get, "/api/v1/admin/accounts/${m.userId}/devices", token = op.token).bodyAsText().contains(m.deviceId))
        assertEquals("no_such_device", c.call(HttpMethod.Post, "/api/v1/admin/devices/${uuid()}/revoke", reauth(op), op.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/admin/devices/${m.deviceId}/revoke", reauth(op), op.token).status.value)
        assertTrue(Flow.sink(s).map { it.first }.containsAll(listOf("account_disabled", "account_enabled", "device_removed")))
        // Disable, wait 30 days, delete.
        c.call(HttpMethod.Post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"request","currentAuthKey":"${op.authKey}"}""", op.token)
        clock.advance(31 * Clock.DAY_MS)
        val op2 = c.call(HttpMethod.Post, "/api/v1/auth/login", op.loginBody(deviceId = op.deviceId))
        val token = WireJson.json.parseToJsonElement(op2.bodyAsText()).let { (it as kotlinx.serialization.json.JsonObject)["accessToken"]!!.toString().trim('"') }
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/admin/accounts/${m.userId}/delete", reauth(op), token).status.value)
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM users WHERE userId=?", m.userId) })
        assertEquals("account_deleted_by_operator", Flow.sink(s).last().first)
        // The audit carries ids only.
        val audit = c.call(HttpMethod.Get, "/api/v1/admin/audit?type=operator_disable", token = token).bodyAsText()
        assertTrue(audit.contains("operator_disable") && !audit.contains("@example.com"))
    }

    @Test
    fun policy_tightenOnly_andStatus() = testApplication {
        val s = TestKit.services(TestKit.config(mode = "open"))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val p = WireJson.json.decodeFromString(AdminPolicy.serializer(), c.call(HttpMethod.Get, "/api/v1/admin/policy", token = op.token).bodyAsText())
        assertEquals(AdminSignupPolicy(null, null), p.signup)
        fun put(sp: AdminSignupPolicy) = WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(signup = sp), op.authKey))
        assertEquals("not_tighter", c.call(HttpMethod.Put, "/api/v1/admin/policy", put(AdminSignupPolicy(null, 500)), op.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/admin/policy", put(AdminSignupPolicy("links", 10)), op.token).status.value)
        // Once links, open is looser: refused; null leaves the stored value.
        assertEquals("not_tighter", c.call(HttpMethod.Put, "/api/v1/admin/policy", put(AdminSignupPolicy("open", null)), op.token).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/admin/policy", put(AdminSignupPolicy(null, null)), op.token).status.value)
        val st = WireJson.json.decodeFromString(AdminStatus.serializer(), c.call(HttpMethod.Get, "/api/v1/admin/status", token = op.token).bodyAsText())
        assertEquals("links", st.signup.mode); assertEquals(10, st.signup.cap)
        assertEquals("signup_closed", c.call(HttpMethod.Post, "/api/v1/signup/start", """{"email":"a@example.com","ageConfirmed":true}""").errorCode())
        val bad = p.copy(kdfParams = io.silencelen.andvari.core.crypto.KdfParams(ops = 1, memBytes = 8 * 1024 * 1024 + 1))
        assertEquals("kdf_mem_not_kib_multiple", c.call(HttpMethod.Put, "/api/v1/admin/policy", WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(bad, op.authKey)), op.token).errorCode())
    }

    @Test
    fun escrowRead_andFulfil_afterTheHold() = testApplication {
        val clock = MutableClock()
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Me("me@example.com")
        Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
        val priv = Flow.member(c, s, "p@example.com")
        assertEquals("no_escrow", c.call(HttpMethod.Post, "/api/v1/admin/accounts/${priv.userId}/escrow", reauth(op), op.token).errorCode())
        assertTrue(c.call(HttpMethod.Post, "/api/v1/admin/accounts/${me.userId}/escrow", reauth(op), op.token).bodyAsText().contains("\"sealed\""))
        val poll = TestKit.crypto.randomBytes(32)
        val rPub = b32()
        val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), c.call(HttpMethod.Post, "/api/v1/recovery/requests", """{"email":"${me.email}","rPub":"$rPub","pollHash":"${sha256Hex(poll)}","platform":"ios"}""").bodyAsText()).requestId
        val code = Flow.codeIn(Flow.sink(s).last { it.first == "recovery_request_code" }.third)
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
        val listed = c.call(HttpMethod.Get, "/api/v1/admin/recovery-requests", token = op.token).bodyAsText()
        assertTrue(listed.contains(reqId) && !listed.contains(code))
        // spec 03 §18.6: the token's parts (the answer of the one size for this address, the request key, the commit hash).
        val commitValue = TestKit.crypto.randomBytes(32)
        val fulfil = """{"sealed":"${Bytes.toB64(ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(me.email)) { 2 })}","requestKey":"$rPub",""" +
            """"commitHash":"${io.silencelen.andvari.core.trust.AssistedRecovery.commitHash(TestKit.crypto, commitValue)}","currentAuthKey":"${op.authKey}"}"""
        assertEquals("request_state", c.call(HttpMethod.Post, "/api/v1/admin/recovery-requests/$reqId/fulfil", fulfil, op.token).errorCode())
        clock.advance(Assisted.HOLD_MS + 1)
        val op2 = c.call(HttpMethod.Post, "/api/v1/auth/login", op.loginBody(deviceId = op.deviceId)).bodyAsText()
        val token = Regex("\"accessToken\":\"([^\"]+)\"").find(op2)!!.groupValues[1]
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/admin/recovery-requests/$reqId/fulfil", fulfil, token).status.value)
        assertTrue(c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/poll", """{"pollSecret":"${Bytes.toB64(poll)}"}""").bodyAsText().contains("\"state\":\"ready\""))
        val newKey = b32()
        val commit = """{"pollSecret":"${Bytes.toB64(poll)}","commit":"${Bytes.toB64(commitValue)}","newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 4 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"phone","deviceSecret":"${b32()}"}}"""
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/recovery/requests/$reqId/commit", commit).status.value)
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM recovery_requests") })
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(authKey = newKey)).status.value)
    }

    @Test
    fun janitor_purgesAfterTheGrace_keepsTheTombstoneLog_expiresLinks() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val crypto = TestKit.crypto
        val vaultId = uuid()
        val t = clock.now()
        val g = VaultLog.sign(crypto, a.identity.sign, LogEntry.Genesis(vaultId, a.userId, t, a.identity.identityPubB64, "a".repeat(64)))
        c.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"${Bytes.toB64(g)}","metaBlob":"AAAA","wrappedVk":"AAAA"}""", a.token)
        val d = VaultLog.sign(crypto, a.identity.sign, LogEntry.Delete(vaultId, 1, sha256Hex(g), a.userId, t, Bytes.toB64(crypto.randomBytes(16))))
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/vaults/$vaultId/log", """{"entry":"${Bytes.toB64(d)}"}""", a.token).status.value)
        val linkId = Bytes.toB64(crypto.randomBytes(16))
        c.call(HttpMethod.Post, "/api/v1/links", """{"linkId":"$linkId","kind":"connect","offer":"AAAA","expiresAt":${t + 60_000}}""", a.token)
        clock.advance(8 * Clock.DAY_MS)
        s.janitor.sweep()
        s.db.read { db ->
            assertEquals(1L, db.count("SELECT COUNT(*) FROM vaults WHERE vaultId=? AND purgedAt IS NOT NULL AND finalSeq=1", vaultId))
            assertEquals(2L, db.count("SELECT COUNT(*) FROM vault_log WHERE vaultId=?", vaultId))
            assertEquals("expired", db.queryOne("SELECT state FROM links WHERE linkId=?", linkId) { it.getString(1) })
        }
        // The owner still fetches the tombstone log, marked purged.
        assertTrue(c.call(HttpMethod.Get, "/api/v1/vaults/$vaultId/log", token = Regex("\"accessToken\":\"([^\"]+)\"").find(c.call(HttpMethod.Post, "/api/v1/auth/login", a.loginBody(deviceId = a.deviceId)).bodyAsText())!!.groupValues[1]).bodyAsText().contains("\"purged\""))
        clock.advance(366 * Clock.DAY_MS)
        s.janitor.sweep()
        s.db.read { db ->
            assertEquals(0L, db.count("SELECT COUNT(*) FROM vault_log WHERE vaultId=?", vaultId))
            assertEquals(1L, db.count("SELECT COUNT(*) FROM vaults WHERE vaultId=?", vaultId))
            assertEquals(0L, db.count("SELECT COUNT(*) FROM links WHERE linkId=?", linkId))
        }
    }
}
