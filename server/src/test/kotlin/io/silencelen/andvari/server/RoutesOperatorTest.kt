package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.MemberRole
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Index rows 74–86 (spec 03 §7, §18.6): the refusals OperatorTest leaves. */
class RoutesOperatorTest {
    /** A fulfil body of the right shape (spec 03 §18.6), so the refusal under test is the one the row decides. */
    private fun fulfilBody(op: Me) =
        """{"sealed":"AAAA","requestKey":"${io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 3 })}","commitHash":"${"ab".repeat(32)}","currentAuthKey":"${op.authKey}"}"""

    private val post = HttpMethod.Post
    private val get = HttpMethod.Get
    private val put = HttpMethod.Put

    @Test
    fun noSuchUser_cannotTargetSelf_unknownRequest_onEveryRowThatNamesOne() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val t = op.token
        val auth = """{"currentAuthKey":"${op.authKey}"}"""
        val nobody = uuid()
        val rows = mutableListOf<Expect>()
        for (id in listOf(nobody, "not-a-uuid")) rows += listOf(
            Expect("74 disable", post, "/api/v1/admin/accounts/$id/disable", t, 400, "no_such_user", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}"""),
            Expect("75 enable", post, "/api/v1/admin/accounts/$id/enable", t, 400, "no_such_user", auth),
            Expect("76 delete", post, "/api/v1/admin/accounts/$id/delete", t, 400, "no_such_user", auth),
            Expect("77 devices", get, "/api/v1/admin/accounts/$id/devices", t, 400, "no_such_user"),
            Expect("79 quota", put, "/api/v1/admin/accounts/$id/quota", t, 400, "no_such_user", """{"accountBytes":null,"items":null,"ownedSharedVaults":null,"openLinks":null,"currentAuthKey":"${op.authKey}"}"""),
            Expect("85 escrow", post, "/api/v1/admin/accounts/$id/escrow", t, 400, "no_such_user", auth),
        )
        rows += listOf(
            Expect("76 delete self", post, "/api/v1/admin/accounts/${op.userId}/delete", t, 400, "cannot_target_self", auth),
            Expect("78 revoke unknown", post, "/api/v1/admin/devices/$nobody/revoke", t, 404, "no_such_device", auth),
            Expect("86 fulfil unknown", post, "/api/v1/admin/recovery-requests/${b16()}/fulfil", t, 404, "request_unknown", fulfilBody(op)),
            Expect("86 fulfil malformed id", post, "/api/v1/admin/recovery-requests/x/fulfil", t, 404, "request_unknown", fulfilBody(op)),
            // The body's shape comes before anything stored is read (spec 03 §18.6).
            Expect("86 fulfil without its request key", post, "/api/v1/admin/recovery-requests/${b16()}/fulfil", t, 400, "bad_request_key", """{"sealed":"AAAA","currentAuthKey":"${op.authKey}"}"""),
        )
        // Each of these is a † route (5 a minute); the bucket has its own test.
        val wrong = ArrayList<String>()
        for (r in rows) {
            s.limiter.clear()
            val resp = c.call(r.method, r.path, r.body, r.token)
            if (resp.status.value != r.status || resp.errorCode() != r.code) wrong += "${r.name} ${r.path}: ${resp.status.value} ${resp.bodyAsText().take(100)}"
        }
        assertEquals(emptyList(), wrong, wrong.joinToString("\n"))
        // The operator's own devices and quota are readable (self allowed there).
        assertEquals(200, c.call(get, "/api/v1/admin/accounts/${op.userId}/devices", token = t).status.value)
    }

    @Test
    fun row76_aLongDisabledOwnerOfASharedVaultWithMembers_isBlocked() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val owner = Flow.member(c, s, "owner@example.com")
        val m = Flow.member(c, s, "m@example.com")
        val v = SharedVault(c, s, owner).create()
        v.add(m, MemberRole.WRITER)
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${owner.userId}/disable", """{"reason":"request","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        clock.advance(31 * Clock.DAY_MS)
        val tok = s.db.tx { db -> s.sessions.issue(db, op.userId, op.deviceId, "linux", passwordLogin = true).accessToken }
        val r = c.call(post, "/api/v1/admin/accounts/${owner.userId}/delete", """{"currentAuthKey":"${op.authKey}"}""", tok)
        assertEquals(409, r.status.value, r.bodyAsText()); assertEquals("account_delete_blocked", r.errorCode())
        assertTrue(r.bodyAsText().contains(v.vaultId) && r.bodyAsText().contains("\"kind\":\"shared_vault\""))
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM users WHERE userId=?", owner.userId) })
    }

    @Test
    fun row81_policy_kdfBelowTheFloor_isTooWeak() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val p = WireJson.json.decodeFromString(AdminPolicy.serializer(), c.call(get, "/api/v1/admin/policy", token = op.token).bodyAsText())
        for (k in listOf(KdfParams(ops = 1, memBytes = 4096), KdfParams(ops = 0, memBytes = 8_388_608), KdfParams(ops = 65, memBytes = 8_388_608))) {
            s.limiter.clear()
            val r = c.call(put, "/api/v1/admin/policy", WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(kdfParams = k), op.authKey)), op.token)
            assertEquals(400, r.status.value, "$k ${r.bodyAsText()}"); assertEquals("kdf_too_weak", r.errorCode())
        }
        s.limiter.clear()
        val k2 = KdfParams(ops = 2, memBytes = 16 * 1024 * 1024)
        val ok = c.call(put, "/api/v1/admin/policy", WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(p.copy(kdfParams = k2), op.authKey)), op.token)
        assertEquals(200, ok.status.value, ok.bodyAsText())
        // The new default reaches prelogin for an unknown address.
        assertTrue(c.call(post, "/api/v1/auth/prelogin", """{"email":"nobody@example.com"}""").bodyAsText().contains("\"memBytes\":16777216"))
    }
}
