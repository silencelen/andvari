package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The password proofs' own back-off (spec 03 §0.1, §8). A failed proof on a live session counts per device (the
 * session's device row; per account until 2026-11-17), with the sign-in back-off's curve, on every route that takes one, and is
 * refused while that back-off is in force with the answer a sign-in gets. It is a counter of its own: only proofs
 * on the account's own sessions arm it and it refuses only proofs, while the sign-in back-off is armed only by
 * sign-ins and refuses only sign-ins. Before N3 the two were one counter keyed on the address, so anyone without a
 * session could send a few wrong sign-ins and have the account's own proofs refused for up to fifteen minutes.
 */
class ProofBackoffTest {
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put
    private val get = HttpMethod.Get

    private class Step(val name: String, val method: HttpMethod, val path: String, val body: (String) -> String)

    /** The operator's ten † routes, each with a body whose only fault is the proof. */
    private suspend fun operatorRoutes(c: HttpClient, op: Me, target: Me): List<Step> {
        val policy = WireJson.json.decodeFromString(AdminPolicy.serializer(), c.call(get, "/api/v1/admin/policy", token = op.token).bodyAsText())
        val k = { key: String -> """{"currentAuthKey":"$key"}""" }
        return listOf(
            Step("3 card", put, "/api/v1/instance/card") { """{"card":"AAAA","currentAuthKey":"$it"}""" },
            Step("4 rotation", put, "/api/v1/instance/rotation") { """{"statement":"AAAA","currentAuthKey":"$it"}""" },
            Step("74 disable", post, "/api/v1/admin/accounts/${target.userId}/disable") { """{"reason":"abuse","currentAuthKey":"$it"}""" },
            Step("75 enable", post, "/api/v1/admin/accounts/${target.userId}/enable", k),
            Step("76 delete", post, "/api/v1/admin/accounts/${target.userId}/delete", k),
            Step("78 device revoke", post, "/api/v1/admin/devices/${target.deviceId}/revoke", k),
            Step("79 quota", put, "/api/v1/admin/accounts/${target.userId}/quota") {
                """{"accountBytes":null,"items":null,"ownedSharedVaults":null,"openLinks":null,"currentAuthKey":"$it"}"""
            },
            Step("81 policy", put, "/api/v1/admin/policy") { WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(policy, it)) },
            Step("85 escrow", post, "/api/v1/admin/accounts/${target.userId}/escrow", k),
            Step("86 fulfil", post, "/api/v1/admin/recovery-requests/x/fulfil") { """{"sealed":"AAAA","currentAuthKey":"$it"}""" },
        )
    }

    private fun statusOf(s: Services, userId: String) = s.db.read { it.queryOne("SELECT status FROM users WHERE userId=?", userId) { r -> r.getString(1) } }

    private fun passwordChange(me: Me, current: String, newKey: String) =
        """{"currentAuthKey":"$current","newAuthKey":"$newKey","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}",""" +
            """"newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""

    /** One wrong sign-in for [me]'s address with no session, the per-IP bucket emptied first so only the back-off answers. */
    private suspend fun wrongSignIn(c: HttpClient, s: Services, me: Me): String? {
        s.limiter.clear()
        return c.call(post, "/api/v1/auth/login", me.loginBody(authKey = b32())).errorCode()
    }

    @Test
    fun fiveWrongSignInsForTheOperatorsAddress_neverRefuseTheOperatorsRightProof() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        // The attack: a stranger with no session sends five wrong sign-ins for the operator's address.
        repeat(5) { assertEquals("invalid_credentials", wrongSignIn(c, s, op)) }
        s.limiter.clear()
        val locked = c.call(post, "/api/v1/auth/login", op.loginBody())
        assertEquals(429, locked.status.value, "the sign-in back-off holds for sign-ins"); assertEquals("60", locked.headers["Retry-After"])
        // The operator, on the session they already hold, disables the abusive member with the right proof: served.
        val disable = c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, disable.status.value, disable.bodyAsText())
        assertEquals("disabled", statusOf(s, m.userId))
    }

    @Test
    fun fiveWrongSignInsForAMembersAddress_neverRefuseTheirPasswordChange() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        repeat(5) { assertEquals("invalid_credentials", wrongSignIn(c, s, me)) }
        s.limiter.clear()
        assertEquals(429, c.call(post, "/api/v1/auth/login", me.loginBody()).status.value)
        val newKey = b32()
        val change = c.call(put, "/api/v1/account/password", passwordChange(me, me.authKey, newKey), me.token)
        assertEquals(200, change.status.value, change.bodyAsText())
        // The new password works once the sign-in's own lock lapses (a stranger's lock is not lifted by the change).
        clock.advance(2_000)
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody(authKey = newKey)).status.value)
    }

    @Test
    fun seventeenRequests_raiseTheSignInLockToFifteenMinutes_andTheProofsStillPass() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        // Fifteen counted wrong sign-ins, each sent as the previous lock lapses, take the lock to its cap of 900 s.
        for (n in 1..15) {
            assertEquals("invalid_credentials", wrongSignIn(c, s, op), "wrong sign-in $n")
            if (n >= 5 && n < 15) clock.advance((1000L shl (n - 5)).coerceAtMost(900_000) + 1)
        }
        // The sixteenth, at once: refused by the lock, which now holds for 15 minutes.
        assertEquals("rate_limited", wrongSignIn(c, s, op))
        clock.advance(14 * 60_000L)
        // The seventeenth, 14 minutes on: the sign-in is still refused ...
        s.limiter.clear()
        assertEquals(429, c.call(post, "/api/v1/auth/login", op.loginBody()).status.value)
        // ... and the operator's right proofs on their session are served throughout.
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${m.userId}/enable", """{"currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        assertEquals("active", statusOf(s, m.userId))
    }

    @Test
    fun fiftyWrongProofsAcrossTheOperatorsRoutes_runIntoTheProofsBackoff_andNeverTheSignIns() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        val routes = operatorRoutes(c, op, m)
        // Five wrong proofs on each of the ten routes, inside one minute, the routes' own buckets emptied before each (a
        // route with a smaller bucket, the card's, would otherwise refuse some of them by its own window).
        val answers = ArrayList<String>()
        for (r in routes) repeat(5) {
            s.limiter.clear()
            val resp = c.call(r.method, r.path, r.body(b32()), op.token)
            answers += "${r.name}:${resp.status.value}:${resp.errorCode()}"
            // The proofs' lock names its real wait: one second after the fifth wrong proof, the clock standing still.
            if (resp.status.value == 429) assertEquals("1", resp.headers["Retry-After"], r.name)
        }
        assertEquals(5, answers.count { it.endsWith(":403:reauth_failed") }, answers.joinToString("\n"))
        assertEquals(45, answers.count { it.endsWith(":429:rate_limited") }, answers.joinToString("\n"))
        assertEquals(5L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='reauth_fail' AND userId=?", op.userId) })
        // A right proof is refused too while the proofs' lock is in force (the routes' own buckets emptied, so the
        // refusal is the back-off's), before any verifier work: nothing changes.
        s.limiter.clear()
        val disable = """{"reason":"abuse","currentAuthKey":"${op.authKey}"}"""
        val right = c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", disable, op.token)
        assertEquals(429, right.status.value, right.bodyAsText()); assertEquals("1", right.headers["Retry-After"])
        assertEquals("active", statusOf(s, m.userId))
        // Fifty failed proofs never armed the sign-in's lock: the right password signs in at once, and one wrong sign-in
        // is an ordinary wrong sign-in, not a refusal.
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/auth/login", op.loginBody()).status.value)
        assertEquals("invalid_credentials", wrongSignIn(c, s, op))
        // That successful sign-in did not lift the proofs' lock either: the counters share nothing.
        s.limiter.clear()
        assertEquals(429, c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", disable, op.token).status.value)
        // Once it lapses the right proof is served.
        clock.advance(2_000)
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", disable, op.token).status.value)
    }

    @Test
    fun wrongProofsOnAnOrdinaryAccountsRoutes_countToo_andLeaveTheSignInAlone() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val other = c.login(me)
        val routes = listOf(
            Step("28 require-link", put, "/api/v1/account/require-link") { """{"enabled":true,"currentAuthKey":"$it"}""" },
            Step("27 device revoke", post, "/api/v1/account/devices/${other.deviceId}/revoke") { """{"currentAuthKey":"$it"}""" },
            Step("34 self-setup", put, "/api/v1/recovery/self-setup") { """{"currentAuthKey":"$it","memberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"}}""" },
            Step("14 totp setup", post, "/api/v1/account/totp/setup") { """{"currentAuthKey":"$it"}""" },
            Step("31 delete", post, "/api/v1/account/delete") { """{"confirmEmail":"${me.email}","currentAuthKey":"$it","leaves":[]}""" },
        )
        val answers = ArrayList<String>()
        for (r in routes) repeat(3) {
            val resp = c.call(r.method, r.path, r.body(b32()), me.token)
            answers += "${r.name}:${resp.status.value}:${resp.errorCode()}"
        }
        assertEquals(5, answers.count { it.endsWith(":403:reauth_failed") }, answers.joinToString("\n"))
        assertEquals(10, answers.count { it.endsWith(":429:rate_limited") }, answers.joinToString("\n"))
        // A right proof on the account's other device is served at once: the counter is the device's, not the account's
        // (until 2026-11-17 it was the account's, and this was refused too). The first device stays refused.
        assertEquals(200, c.call(put, "/api/v1/account/require-link", """{"enabled":false,"currentAuthKey":"${me.authKey}"}""", other.accessToken).status.value)
        s.limiter.clear()
        assertEquals(429, c.call(put, "/api/v1/account/require-link", """{"enabled":false,"currentAuthKey":"${me.authKey}"}""", me.token).status.value)
        // The sign-in is not: the proofs' failures are not the sign-in's.
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody()).status.value)
        // Nothing was changed by any of them: the other device is live and the account exists.
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = other.accessToken).status.value)
    }

    @Test
    fun aMembersToken_stillCannotTestTheOperatorsPassword() = testApplication {
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key))
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        val routes = operatorRoutes(c, op, m)
        for (r in routes) repeat(5) {
            for (proof in listOf(op.authKey, b32())) {
                val resp = c.call(r.method, r.path, r.body(proof), m.token)
                assertEquals(403, resp.status.value, "${r.name}: ${resp.bodyAsText()}"); assertEquals("not_operator", resp.errorCode(), r.name)
            }
        }
        // No proof was evaluated against anyone: no row, and neither account's back-off moved.
        assertEquals(0L, s.db.read { it.count("SELECT COUNT(*) FROM audit WHERE type='reauth_fail'") })
        assertEquals(200, c.call(post, "/api/v1/auth/login", op.loginBody()).status.value)
        assertEquals(200, c.call(post, "/api/v1/auth/login", m.loginBody()).status.value)
        val right = c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, right.status.value, right.bodyAsText())
    }

    @Test
    fun anHonestMistype_isNotALockout() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val link = { key: String -> """{"enabled":false,"currentAuthKey":"$key"}""" }
        // One slip, then the right password: served, and the sign-in after it too.
        assertEquals("reauth_failed", c.call(put, "/api/v1/account/require-link", link(b32()), me.token).errorCode())
        assertEquals(200, c.call(put, "/api/v1/account/require-link", link(me.authKey), me.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody()).status.value)
        // Four slips, then the right password: served; the right proof clears the four, as a right sign-in clears the
        // sign-in's, so a later slip is an ordinary slip and not the fifth.
        s.limiter.clear()
        repeat(4) { assertEquals("reauth_failed", c.call(put, "/api/v1/account/require-link", link(b32()), me.token).errorCode()) }
        assertEquals(200, c.call(put, "/api/v1/account/require-link", link(me.authKey), me.token).status.value)
        s.limiter.clear()
        assertEquals("reauth_failed", c.call(put, "/api/v1/account/require-link", link(b32()), me.token).errorCode())
        assertEquals(200, c.call(put, "/api/v1/account/require-link", link(me.authKey), me.token).status.value)
        // Four wrong sign-ins and then a slip on the session: neither counter reached its fifth.
        repeat(4) { assertEquals("invalid_credentials", wrongSignIn(c, s, me)) }
        s.limiter.clear()
        assertEquals("reauth_failed", c.call(put, "/api/v1/account/require-link", link(b32()), me.token).errorCode())
        s.limiter.clear()
        assertEquals(200, c.call(post, "/api/v1/auth/login", me.loginBody()).status.value)
    }
}
