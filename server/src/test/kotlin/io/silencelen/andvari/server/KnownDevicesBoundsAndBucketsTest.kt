package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminPolicyPut
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** What was decided for the server's known gaps (known devices, policy bounds, per-account buckets). */
class KnownDevicesBoundsAndBucketsTest {
    @Test
    fun knownDevice_needsNoLiveSession_andSurvivesTheJanitor() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        // The registering device signs out; every session dies and, months later, the janitor prunes them.
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/auth/logout", token = me.token).status.value)
        clock.advance(Janitor.SESSION_RETENTION_MS + 31 * Clock.DAY_MS)
        s.janitor.sweep(clock.now())
        s.db.read { db ->
            assertEquals(0L, db.count("SELECT COUNT(*) FROM sessions WHERE deviceId=?", me.deviceId))
            assertEquals(1L, db.count("SELECT COUNT(*) FROM devices WHERE deviceId=? AND deviceSecretHash IS NOT NULL", me.deviceId))
        }
        s.db.tx { it.exec("UPDATE users SET requireLink=1 WHERE userId=?", me.userId) }
        val before = Flow.sink(s).count { it.first == "new_device" }
        // Its id and secret still make it known: requireLink lets it in, on the same row, with no notice.
        val r = c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId))
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(me.deviceId, WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText()).deviceId)
        assertEquals(before, Flow.sink(s).count { it.first == "new_device" })
        // The id with another secret, or another account's device id, is a new device: refused under requireLink.
        assertEquals("link_required", c.call(HttpMethod.Post, "/api/v1/auth/login", me.loginBody(deviceId = me.deviceId, secret = io.silencelen.andvari.core.crypto.Bytes.toB64(TestKit.crypto.randomBytes(32)))).errorCode())
    }

    @Test
    fun policyBounds_areThePreviousServersAndTheClientCeilings_andNameTheFailingField() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val p = WireJson.json.decodeFromString(AdminPolicy.serializer(), c.call(HttpMethod.Get, "/api/v1/admin/policy", token = op.token).bodyAsText())
        // Each PUT is a † route (5 a minute): step past the bucket's window between them.
        suspend fun put(x: AdminPolicy) = clock.advance(Clock.MINUTE_MS).let { _ -> c }.call(HttpMethod.Put, "/api/v1/admin/policy", WireJson.json.encodeToString(AdminPolicyPut.serializer(), AdminPolicyPut.of(x, op.authKey)), op.token)
        val cases = listOf(
            p.copy(autoLockSeconds = 0) to "bad_auto_lock_seconds",
            p.copy(autoLockSeconds = ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS + 1L) to "bad_auto_lock_seconds",
            p.copy(clipboardClearSeconds = 0) to "bad_clipboard_clear_seconds",
            p.copy(clipboardClearSeconds = ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS + 1L) to "bad_clipboard_clear_seconds",
            p.copy(sessionAccessTtlSeconds = 59) to "bad_session_access_ttl_seconds",
            p.copy(sessionRefreshTtlDays = 0) to "bad_session_refresh_ttl_days",
            p.copy(sessionRefreshTtlDays = Long.MAX_VALUE) to "bad_session_refresh_ttl_days",
            p.copy(attachmentMaxBytes = p.quotaDefaults.accountBytes + 1) to "bad_attachment_max_bytes",
            p.copy(itemAttachmentsMaxBytes = 0) to "bad_item_attachments_max_bytes",
            p.copy(minVersion = mapOf("linux" to "1.0")) to "bad_min_version",
            // Two bad fields: the first in body order decides.
            p.copy(autoLockSeconds = 0, sessionRefreshTtlDays = 0) to "bad_auto_lock_seconds",
        )
        for ((x, code) in cases) assertEquals(code, put(x).errorCode(), x.toString())
        // The edges themselves are accepted; the previous server had no upper bound on the session lifetimes.
        val edge = p.copy(autoLockSeconds = ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS.toLong(), clipboardClearSeconds = 1, sessionAccessTtlSeconds = 60, sessionRefreshTtlDays = 3650)
        val r = put(edge)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertTrue(r.bodyAsText().contains("\"sessionRefreshTtlDays\":3650"))
    }

    @Test
    fun kitSetupAndConfirm_areBucketedPerAccount_notPerIp() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        val ip = "10.9.9.9"
        // Five confirms from one address spend account a's bucket only; b, from the same address, is untouched.
        repeat(5) { c.call(HttpMethod.Post, "/api/v1/recovery/self/confirm", "{}", a.token, ip = ip) }
        assertEquals("rate_limited", c.call(HttpMethod.Post, "/api/v1/recovery/self/confirm", "{}", a.token, ip = randomIp()).errorCode())
        assertEquals(200, c.call(HttpMethod.Post, "/api/v1/recovery/self/confirm", "{}", b.token, ip = ip).status.value)
        val setup = { me: Me -> """{"currentAuthKey":"${me.authKey}","memberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${io.silencelen.andvari.core.crypto.Bytes.toB64(TestKit.crypto.randomBytes(32))}"}}""" }
        repeat(5) { assertEquals(200, c.call(HttpMethod.Put, "/api/v1/recovery/self-setup", setup(a), a.token, ip = ip).status.value) }
        assertEquals("rate_limited", c.call(HttpMethod.Put, "/api/v1/recovery/self-setup", setup(a), a.token, ip = randomIp()).errorCode())
        assertEquals(200, c.call(HttpMethod.Put, "/api/v1/recovery/self-setup", setup(b), b.token, ip = ip).status.value)
    }
}
