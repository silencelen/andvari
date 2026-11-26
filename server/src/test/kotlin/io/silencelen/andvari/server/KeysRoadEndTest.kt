package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.TokenPair
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * What ends the road to an account's wrapped keys (`GET /account/keys`, spec 03 §3) for a device that holds a live session:
 * what the route answers at the very next call with the access token the device already holds, after each act that can
 * end that session, and what its refresh token is then worth. The access token is checked against the stored session,
 * the device row and the account at every call, so an ended session's token is refused at once, never "until it runs
 * out". These tests describe the server as it is; they change nothing.
 */
class KeysRoadEndTest {
    private val get = HttpMethod.Get
    private val post = HttpMethod.Post
    private val put = HttpMethod.Put
    private val keys = "/api/v1/account/keys"

    private fun keysOf(body: String) = WireJson.json.decodeFromString(AccountKeys.serializer(), body)
    private fun pairOf(body: String) = WireJson.json.decodeFromString(TokenPair.serializer(), body)
    private suspend fun HttpClient.refresh(token: String) = call(post, "/api/v1/auth/refresh", """{"refreshToken":"$token"}""")

    /** The answer to a token the server never issued: what an ended session must be indistinguishable from. */
    private suspend fun HttpClient.unknownTokensAnswer(): String {
        val r = call(get, keys, token = b32())
        assertEquals(401, r.status.value)
        return r.bodyAsText()
    }

    private suspend fun HttpClient.refusedAtOnce(what: String, token: String, unknown: String) {
        val r = call(get, keys, token = token)
        assertEquals(401, r.status.value, "$what: ${r.bodyAsText()}")
        assertEquals(unknown, r.bodyAsText(), what)
    }

    /**
     * The account's owner removes the device from the list of devices (from another of its devices): the next keys call
     * with the access token the device holds is `401 invalid_credentials`, the unknown token's answer, at once; its refresh
     * token is `401 session_revoked`. The removal ends that device's road only: whoever knows the master password signs in
     * again as a new device row (unless the account requires a link), and that session is served the keys.
     */
    @Test
    fun theOwnerRemovesTheDevice_theNextCallIsRefused_andItsRefreshTokenToo() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val unknown = c.unknownTokensAnswer()
        val held = c.login(me)
        assertEquals(200, c.call(get, keys, token = held.accessToken).status.value)
        val rv = c.call(post, "/api/v1/account/devices/${held.deviceId}/revoke", """{"currentAuthKey":"${me.authKey}"}""", me.token)
        assertEquals(200, rv.status.value, rv.bodyAsText())
        c.refusedAtOnce("removed device", held.accessToken, unknown)
        val r = c.refresh(held.refreshToken)
        assertEquals(401, r.status.value); assertEquals("session_revoked", r.errorCode())
        // The password still opens a new road, on a new device row.
        val again = c.login(me)
        assertNotEquals(held.deviceId, again.deviceId)
        assertEquals(200, c.call(get, keys, token = again.accessToken).status.value)
    }

    /**
     * The server has no "sign out everywhere": the session routes under `/auth/` are the registration, the sign-in's two,
     * the refresh, the sign-out and the end of one session. A sign-out ends only the calling device's sessions: another
     * device's held access token is still served the keys at once, and its refresh token still refreshes. (What ends every
     * other session at once is a password change, below, and an operator's disable.)
     */
    @Test
    fun thereIsNoSignOutEverywhere_aSignOutEndsOnlyItsOwnDevice() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val authRoutes = WireRoute.entries.filter { it.path.startsWith("/api/v1/auth/") }.map { it.path }.toSet()
        assertEquals(
            setOf("/api/v1/auth/register", "/api/v1/auth/prelogin", "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/logout", "/api/v1/auth/end-session"),
            authRoutes,
        )
        val held = c.login(me)
        assertEquals(200, c.call(post, "/api/v1/auth/logout", token = me.token).status.value)
        assertEquals(401, c.call(get, keys, token = me.token).status.value, "the signed-out device's own token")
        assertEquals(200, c.call(get, keys, token = held.accessToken).status.value, "another device's held token")
        val r = c.refresh(held.refreshToken)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(200, c.call(get, keys, token = pairOf(r.bodyAsText()).accessToken).status.value)
    }

    /**
     * The master password is changed from another device: every other session of the account ends in that transaction,
     * so this device's held access token is refused at once (the unknown token's answer) and its refresh token is
     * `401 session_revoked`. The device's row is not removed. The changing session lives on and is served the NEW wrap
     * (new salt, new wrapped key) at its next call; the identity key and its sealed seed are unchanged, and so is the
     * account key under the wrap (the route's own rule: the UVK is unchanged), so a wrap fetched before the change still
     * opens the account to whoever guesses the OLD password. The old password no longer signs in.
     */
    @Test
    fun aPasswordChangeFromAnotherDevice_endsThisDevicesSession_andTheChangerIsServedTheNewWrap() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val unknown = c.unknownTokensAnswer()
        val held = c.login(me)
        val before = keysOf(c.call(get, keys, token = held.accessToken).bodyAsText())
        val newKey = b32()
        val newSalt = Bytes.toB64(ByteArray(16) { 9 })
        val newWrap = "BBBBBBBBBBBBBBBB"
        val change = c.call(
            put, "/api/v1/account/password",
            """{"currentAuthKey":"${me.authKey}","newAuthKey":"$newKey","newKdfSalt":"$newSalt","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"$newWrap"}""",
            me.token,
        )
        assertEquals(200, change.status.value, change.bodyAsText())
        c.refusedAtOnce("after a password change elsewhere", held.accessToken, unknown)
        val r = c.refresh(held.refreshToken)
        assertEquals(401, r.status.value); assertEquals("session_revoked", r.errorCode())
        // The changer's own session is served the new wrap.
        val after = keysOf(c.call(get, keys, token = me.token).bodyAsText())
        assertEquals(newWrap, after.wrappedUvk)
        assertEquals(newSalt, after.kdfSalt)
        assertNotEquals(before.wrappedUvk, after.wrappedUvk)
        assertEquals(before.identityPub, after.identityPub)
        assertEquals(before.encryptedIdentitySeed, after.encryptedIdentitySeed)
        // The device's row stays (not removed); the old password no longer signs in.
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM devices WHERE deviceId=? AND revokedAt IS NULL", held.deviceId) })
        assertEquals(401, c.call(post, "/api/v1/auth/login", me.loginBody(secret = b32())).status.value)
    }

    /**
     * An operator disables the account: every session of it ends in that transaction, so the held access token is
     * refused at once (the unknown token's answer) and the refresh token is `401 session_revoked`. Enabling the account
     * again does not bring them back: they stay refused, and only a new sign-in opens a session.
     */
    @Test
    fun anOperatorsDisable_endsEverySessionAtOnce_andAnEnableDoesNotBringThemBack() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val unknown = c.unknownTokensAnswer()
        val held = c.login(me)
        assertEquals(200, c.call(get, keys, token = held.accessToken).status.value)
        val d = c.call(post, "/api/v1/admin/accounts/${me.userId}/disable", """{"reason":"abuse","currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, d.status.value, d.bodyAsText())
        c.refusedAtOnce("disabled account", held.accessToken, unknown)
        val r = c.refresh(held.refreshToken)
        assertEquals(401, r.status.value); assertEquals("session_revoked", r.errorCode())
        val e = c.call(post, "/api/v1/admin/accounts/${me.userId}/enable", """{"currentAuthKey":"${op.authKey}"}""", op.token)
        assertEquals(200, e.status.value, e.bodyAsText())
        c.refusedAtOnce("enabled again: the old access token", held.accessToken, unknown)
        val r2 = c.refresh(held.refreshToken)
        assertEquals(401, r2.status.value); assertEquals("session_revoked", r2.errorCode())
        assertEquals(200, c.call(get, keys, token = c.login(me).accessToken).status.value, "a new sign-in")
    }

    /**
     * The account is deleted (from another of its devices): its sessions and devices go with it, so the held access token
     * is refused at once (the unknown token's answer) and the refresh token is `401 invalid_refresh`, byte for byte the
     * answer to a refresh token the server never issued.
     */
    @Test
    fun theAccountsDeletion_endsEverySessionAtOnce_andTheRefreshTokenIsUnknown() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val unknown = c.unknownTokensAnswer()
        val unknownRefresh = c.refresh(b32())
        assertEquals(401, unknownRefresh.status.value)
        val held = c.login(me)
        val del = c.call(post, "/api/v1/account/delete", """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","leaves":[]}""", me.token)
        assertEquals(200, del.status.value, del.bodyAsText())
        c.refusedAtOnce("deleted account", held.accessToken, unknown)
        val r = c.refresh(held.refreshToken)
        assertEquals(401, r.status.value); assertEquals("invalid_refresh", r.errorCode())
        assertEquals(unknownRefresh.bodyAsText(), r.bodyAsText())
    }

    /**
     * Without any of those acts, the held access token is served until its lifetime ends (one hour by default: the
     * operator's policy sets it, from 60 seconds up), and the refresh token renews the session: each refresh gives a fresh
     * pair whose refresh token lives the policy's days again (30 by default), with no limit on the chain's age, so a device
     * that refreshes at least once in every 30 days keeps its road to the keys with no end of its own. A refresh token left
     * unused for its whole lifetime is `401 refresh_expired`.
     */
    @Test
    fun withoutThem_theHeldTokenLivesItsHour_andARefreshedChainHasNoEndOfItsOwn() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        assertEquals(3_600_000L, s.sessions.accessTtlMs)
        assertEquals(30 * Clock.DAY_MS, s.sessions.refreshTtlMs)
        var held: TokenPair = c.login(me).let { TokenPair(it.accessToken, it.refreshToken) }
        clock.advance(s.sessions.accessTtlMs - 1)
        assertEquals(200, c.call(get, keys, token = held.accessToken).status.value, "a millisecond before the hour ends")
        clock.advance(1)
        assertEquals(401, c.call(get, keys, token = held.accessToken).status.value, "at the hour's end")
        // Refreshed once in every 29 days, for 116 days: the chain lives on.
        repeat(4) { round ->
            clock.advance(29 * Clock.DAY_MS)
            val r = c.refresh(held.refreshToken)
            assertEquals(200, r.status.value, "round $round: ${r.bodyAsText()}")
            held = pairOf(r.bodyAsText())
            assertEquals(200, c.call(get, keys, token = held.accessToken).status.value, "round $round")
        }
        // Unused for its whole lifetime, a refresh token is refused.
        clock.advance(s.sessions.refreshTtlMs)
        val late = c.refresh(held.refreshToken)
        assertEquals(401, late.status.value); assertEquals("refresh_expired", late.errorCode())
    }
}
