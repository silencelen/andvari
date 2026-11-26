package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What `GET /account/keys` (spec 03 §3, row 17) asks of its caller, and what it leaves behind. The route serves an
 * account's wrapped keys and its sealed seed: with them, whoever holds them can guess the master password away from the
 * server. A device under a policy that forbids keeping data asks for them at every unlock, with the session it holds, so
 * these tests pin what that session alone is worth. They describe the route as it is; they change nothing.
 */
class AccountKeysRouteTest {
    private val get = HttpMethod.Get
    private val post = HttpMethod.Post
    private val path = "/api/v1/account/keys"

    private fun keysOf(body: String) = WireJson.json.decodeFromString(AccountKeys.serializer(), body)

    private fun auditRows(s: Services): Long = s.db.read { it.count("SELECT COUNT(*) FROM audit") }

    /**
     * The session's access token is all the route asks for: no `X-Andvari-Client` header (and so no version check), no
     * client address of the session's, nothing of the device (no device secret, no proof of holding one). The keys served
     * are always those of the token's own account. Without a bearer it is `401 missing_token`; a refresh token in its
     * place, or an unknown token, is `401 invalid_credentials`.
     */
    @Test
    fun theAccessTokenAlone_isEnough_nothingOfTheDevice_andTheKeysAreTheTokensAccounts() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // No client header, no forwarded address: only the bearer.
        val bare = c.request(path) { method = get; header("Authorization", "Bearer ${me.token}") }
        assertEquals(200, bare.status.value, bare.bodyAsText())
        assertEquals(me.identity.identityPubB64, keysOf(bare.bodyAsText()).identityPub)
        // Any address, any client name and version, the oldest too: the same answer.
        for (name in listOf("linux/1.0.0", "android/0.0.1", "web/0.0.1", "ios/0.0.1")) {
            val r = c.call(get, path, token = me.token, client = name, ip = randomIp())
            assertEquals(200, r.status.value, "$name: ${r.bodyAsText()}")
            assertEquals(bare.bodyAsText(), r.bodyAsText(), name)
        }
        val missing = c.call(get, path)
        assertEquals(401, missing.status.value); assertEquals("missing_token", missing.errorCode())
        val refresh = c.call(get, path, token = me.session!!.refreshToken)
        assertEquals(401, refresh.status.value); assertEquals("invalid_credentials", refresh.errorCode())
        val unknown = c.call(get, path, token = b32())
        assertEquals(401, unknown.status.value); assertEquals("invalid_credentials", unknown.errorCode())
    }

    /**
     * A session of any kind serves its own account's keys: one of a second device, one the web client minted, and the
     * operator's (the operator's own keys, never another account's). A session that must first set up two-step sign-in is
     * refused (`403 totp_enrollment_required`, pinned in `SignupLoginTest`).
     */
    @Test
    fun aSessionOfAnyKind_webAndOperatorToo_servesItsOwnAccountsKeys() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val second = c.login(me)
        val webLogin = c.call(post, "/api/v1/auth/login", me.loginBody(secret = b32(), platform = "web"), client = "web/1.0.0")
        assertEquals(200, webLogin.status.value, webLogin.bodyAsText())
        val web = WireJson.json.decodeFromString(SessionResponse.serializer(), webLogin.bodyAsText())
        for ((what, token) in listOf("second device" to second.accessToken, "web" to web.accessToken)) {
            val r = c.call(get, path, token = token)
            assertEquals(200, r.status.value, "$what: ${r.bodyAsText()}")
            assertEquals(me.identity.identityPubB64, keysOf(r.bodyAsText()).identityPub, what)
        }
        val opKeys = c.call(get, path, token = op.token)
        assertEquals(200, opKeys.status.value, opKeys.bodyAsText())
        assertEquals(op.identity.identityPubB64, keysOf(opKeys.bodyAsText()).identityPub)
    }

    /**
     * The route's limit is the default one of a read: `read_account_keys`, 60 a minute per device, with a ceiling of 240 a
     * minute per account (four times the device's) that every device of the account draws on. A second device of the
     * account has 60 of its own. The refusal is `429 rate_limited` and leaves no audit row.
     */
    @Test
    fun theLimit_isTheReadDefault_60aMinutePerDevice_240PerAccount() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val bucket = defaultBucket(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_KEYS)
        assertEquals(Bucket.devicePerMinute("read_account_keys", 60), bucket)
        assertEquals(240, bucket.accountCeiling)
        repeat(60) { assertEquals(200, c.call(get, path, token = me.token).status.value) }
        val audit = auditRows(s)
        val limited = c.call(get, path, token = me.token)
        assertEquals(429, limited.status.value); assertEquals("rate_limited", limited.errorCode())
        assertEquals(audit, auditRows(s), "a refusal by the limit leaves no audit row")
        val second = c.login(me)
        assertEquals(200, c.call(get, path, token = second.accessToken).status.value, "another device has its own 60")
        assertEquals(61, s.limiter.count(Bucket.accountKey(bucket, me.userId)), "both devices draw on the account's ceiling")
    }

    /**
     * An ended session (signed out, or past its access lifetime), an ended device (removed by the account's owner) and a
     * disabled account each get `401 invalid_credentials`, the very answer of an unknown token, naming nothing. (A
     * session replaced by a sign-in, a refresh, a reused refresh token, an operator's removal of the device and a deleted
     * account are pinned the same way in `SignupLoginTest`, `OperatorRevokeRecordTest` and `RoutesAccountTest`.)
     */
    @Test
    fun anEndedSession_anEndedDevice_aDisabledAccount_getTheUnknownTokensAnswer() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val unknown = c.call(get, path, token = b32()).bodyAsText()
        suspend fun HttpClient.refused(what: String, token: String) {
            val r = call(get, path, token = token)
            assertEquals(401, r.status.value, "$what: ${r.bodyAsText()}")
            assertEquals(unknown, r.bodyAsText(), what)
        }
        // Signed out.
        val out = c.login(me)
        assertEquals(200, c.call(post, "/api/v1/auth/logout", token = out.accessToken).status.value)
        c.refused("signed out", out.accessToken)
        // The device removed by the account's owner, from another device.
        val removed = c.login(me)
        assertEquals(200, c.call(get, path, token = removed.accessToken).status.value)
        val rv = c.call(post, "/api/v1/account/devices/${removed.deviceId}/revoke", """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, rv.status.value, rv.bodyAsText())
        c.refused("removed device", removed.accessToken)
        // Past the access token's lifetime (an hour by default); its refresh gives a token that is served again.
        val aged = c.login(me)
        clock.advance(s.sessions.accessTtlMs)
        c.refused("expired access token", aged.accessToken)
        val r = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${aged.refreshToken}"}""")
        assertEquals(200, r.status.value, r.bodyAsText())
        val fresh = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.TokenPair.serializer(), r.bodyAsText())
        assertEquals(200, c.call(get, path, token = fresh.accessToken).status.value)
        // The account disabled by the operator: every session of it, the fresh one too.
        val opRefresh = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${op.session!!.refreshToken}"}""")
        assertEquals(200, opRefresh.status.value, opRefresh.bodyAsText())
        val opNow = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.TokenPair.serializer(), opRefresh.bodyAsText())
        val d = c.call(post, "/api/v1/admin/accounts/${me.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", opNow.accessToken)
        assertEquals(200, d.status.value, d.bodyAsText())
        c.refused("disabled account", fresh.accessToken)
    }

    /**
     * A call writes no audit row (so nothing in `GET /admin/audit` or the audit journal); of the account's records it
     * moves only the calling device's `lastSeenAt` (pinned below). The only other trace is the request meter of the
     * loopback-only `/metrics`, by route and status, which names no account, device or address.
     */
    @Test
    fun aCall_leavesNoAuditRow_andOnlyTheRoutesRequestMeterCountsIt() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val audit = auditRows(s)
        repeat(5) { assertEquals(200, c.call(get, path, token = me.token).status.value) }
        assertEquals(audit, auditRows(s), "no audit row")
        // The request meter is recorded as the call completes, which can be just after the client has its answer.
        fun keysMeters() = s.metrics.meters.filter { m -> m.id.name.startsWith("ktor.") && m.id.tags.any { it.value.contains(path) } }
        repeat(50) { if (keysMeters().isEmpty()) kotlinx.coroutines.delay(100) }
        assertTrue(keysMeters().isNotEmpty(), "the route's request meter")
        for (m in keysMeters()) {
            val tags = m.id.tags.joinToString { "${it.key}=${it.value}" }
            assertFalse(tags.contains(me.userId) || tags.contains(me.deviceId) || tags.contains(me.token), tags)
        }
    }

    private suspend fun HttpClient.devices(token: String): List<io.silencelen.andvari.core.model.wire.Device> {
        val r = call(get, "/api/v1/account/devices", token = token)
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.wire.Device.serializer()), r.bodyAsText())
    }

    private fun lastSeenOf(s: Services, deviceId: String): Long? =
        s.db.read { db -> db.queryOne("SELECT lastSeenAt FROM devices WHERE deviceId=?", deviceId) { it.longOrNull("lastSeenAt") } }

    /**
     * A device that only fetches the keys (every unlock under a policy that forbids keeping data does exactly that, and
     * nothing else) is seen: each answered call moves its `lastSeenAt` to the call's time, as a sign-in and a refresh do,
     * so the account's list of devices shows it as in use. Nothing else of the device is recorded: not the client version
     * the call names (a refresh records that; this route does not), and no audit row.
     */
    @Test
    fun aDeviceThatOnlyFetchesTheKeys_isListedWithALastSeenThatMoved_andNothingElseIsRecorded() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val held = c.login(me)
        val signedInAt = clock.now()
        val before = c.devices(me.token).single { it.deviceId == held.deviceId }
        assertEquals(signedInAt, before.lastSeenAt)
        val otherSeen = lastSeenOf(s, me.deviceId)
        val audit = auditRows(s)
        clock.advance(20 * Clock.MINUTE_MS)
        val r = c.call(get, path, token = held.accessToken, client = "android/9.9.9")
        assertEquals(200, r.status.value, r.bodyAsText())
        val after = c.devices(me.token).single { it.deviceId == held.deviceId }
        assertEquals(signedInAt + 20 * Clock.MINUTE_MS, after.lastSeenAt, "the keys call moves the device's last-seen time")
        assertEquals(before.clientVersion, after.clientVersion, "the version the call names is not recorded")
        assertEquals(before.copy(lastSeenAt = after.lastSeenAt), after, "nothing else of the listed device changes")
        assertEquals(audit, auditRows(s), "no audit row")
        // Again later: each answered call moves it, no more.
        clock.advance(5 * Clock.MINUTE_MS)
        assertEquals(200, c.call(get, path, token = held.accessToken).status.value)
        assertEquals(signedInAt + 25 * Clock.MINUTE_MS, lastSeenOf(s, held.deviceId))
        // Only the calling device: the account's other device is not moved by it.
        assertEquals(otherSeen, lastSeenOf(s, me.deviceId), "the other device's last-seen time stays")
    }

    /**
     * A call that is not answered moves nothing: a signed-out session's, a removed device's, an access token past its
     * lifetime, and a call refused by the route's limit. Each leaves the device's `lastSeenAt` where it was.
     */
    @Test
    fun aCallThatIsNotAnswered_anEndedSessionsToo_movesNothing() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // Signed out.
        val out = c.login(me)
        val outSeen = lastSeenOf(s, out.deviceId)
        assertEquals(200, c.call(post, "/api/v1/auth/logout", token = out.accessToken).status.value)
        clock.advance(Clock.MINUTE_MS)
        assertEquals(401, c.call(get, path, token = out.accessToken).status.value)
        assertEquals(outSeen, lastSeenOf(s, out.deviceId), "signed out")
        // Removed by the account's owner.
        val removed = c.login(me)
        val removedSeen = lastSeenOf(s, removed.deviceId)
        assertEquals(200, c.call(post, "/api/v1/account/devices/${removed.deviceId}/revoke", """{"currentAuthKey":"${me.authKey}"}""", me.token).status.value)
        clock.advance(Clock.MINUTE_MS)
        assertEquals(401, c.call(get, path, token = removed.accessToken).status.value)
        assertEquals(removedSeen, lastSeenOf(s, removed.deviceId), "removed device")
        // Past the access token's lifetime.
        val aged = c.login(me)
        val agedSeen = lastSeenOf(s, aged.deviceId)
        clock.advance(s.sessions.accessTtlMs)
        assertEquals(401, c.call(get, path, token = aged.accessToken).status.value)
        assertEquals(agedSeen, lastSeenOf(s, aged.deviceId), "expired access token")
        // Refused by the limit: the sixty answered calls moved it, the sixty-first does not.
        val busy = c.login(me)
        clock.advance(Clock.MINUTE_MS)
        repeat(60) { assertEquals(200, c.call(get, path, token = busy.accessToken).status.value) }
        val busySeen = lastSeenOf(s, busy.deviceId)
        assertEquals(clock.now(), busySeen)
        clock.advance(1_000)
        assertEquals(429, c.call(get, path, token = busy.accessToken).status.value)
        assertEquals(busySeen, lastSeenOf(s, busy.deviceId), "a call refused by the limit")
    }
}
