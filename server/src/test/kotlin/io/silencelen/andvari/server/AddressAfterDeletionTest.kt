package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * An address after its account's deletion (spec 03 §13): when it can register again, that the new account never has
 * the earlier account's id, and what the server answers a client that still holds the earlier account's tokens or asks
 * for its records by id. The clients' offer to forget an earlier account stands on these facts. (A self-deletion's
 * registration again at once and the refusal of the old id under the same address are pinned in
 * `RecoveryAndDeletionTest.accountDeletion_blockers_leaves_effect`.) These tests describe the server as it is.
 */
class AddressAfterDeletionTest {
    private val get = HttpMethod.Get
    private val post = HttpMethod.Post

    private suspend fun HttpClient.selfDelete(me: Me) {
        val r = call(post, "/api/v1/account/delete", """{"confirmEmail":"${me.email}","currentAuthKey":"${me.authKey}","leaves":[]}""", me.token)
        assertEquals(200, r.status.value, r.bodyAsText())
    }

    private suspend fun HttpClient.register(s: Services, me: Me) = call(post, "/api/v1/auth/register", me.register(s, Flow.enrolAuth(s)))

    /**
     * After an operator's deletion (here the one that needs no 30 days: a disabled account under the minimum age), the
     * address registers again at once, in the same instant, as a new account. The earlier account's id is refused for
     * good (`409 user_id_taken`), under that address and under any other, and so is the pseudonym its audit rows were
     * moved to. The id is the client's choice at registration, so it is this refusal that keeps a remade account from
     * coming back under its old id.
     */
    @Test
    fun afterAnOperatorsDeletion_theAddressRegistersAgainAtOnce_neverUnderAnEarlierId() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val m = Flow.member(c, s, "m@example.com")
        assertEquals(200, c.call(post, "/api/v1/admin/accounts/${m.userId}/disable", """{"reason":"other","currentAuthKey":"${op.authKey}"}""", op.token).status.value)
        val d = c.call(post, "/api/v1/admin/accounts/${m.userId}/delete", """{"currentAuthKey":"${op.authKey}","reason":"under_minimum_age"}""", op.token)
        assertEquals(200, d.status.value, d.bodyAsText())
        val pseudonym = s.db.read { it.queryOne("SELECT meta FROM audit WHERE type='operator_delete'") { r -> r.getString(1) } }!!
            .removePrefix("target=").substringBefore(',')
        for ((what, again) in listOf(
            "the old id, same address" to Me(m.email, userId = m.userId),
            "the old id, another address" to Me("n@example.com", userId = m.userId),
            "the audit pseudonym" to Me("p@example.com", userId = pseudonym),
        )) {
            val r = c.register(s, again)
            assertEquals(409, r.status.value, "$what: ${r.bodyAsText()}"); assertEquals("user_id_taken", r.errorCode(), what)
        }
        val fresh = Me(m.email)
        val r = c.register(s, fresh)
        assertEquals(200, r.status.value, r.bodyAsText())
        val session = WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
        assertNotEquals(m.userId, fresh.userId)
        assertEquals(1L, s.db.read { it.count("SELECT COUNT(*) FROM users WHERE email=? AND userId=?", m.email, fresh.userId) })
        assertNotEquals(m.deviceId, session.deviceId)
    }

    /**
     * A client that still holds the earlier account's session gets, also after the address was taken again by a new
     * account: for its access token, `401 invalid_credentials`, byte for byte the answer to a token never issued, on
     * every session route; for its refresh token, `401 invalid_refresh`, byte for byte the answer to an unknown refresh
     * token; and the end of a session answers `200` as for any token. A sign-in at the address with the earlier password
     * is `401 invalid_credentials`; one with the new account's password that names the earlier device row and its secret
     * is not taken as that device: the new account gets a new row.
     */
    @Test
    fun theEarlierAccountsTokens_areAnsweredAsTokensNeverIssued_alsoAfterTheAddressIsTakenAgain() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val held = c.login(me)
        val unknown = c.call(get, "/api/v1/account/keys", token = b32()).bodyAsText()
        val unknownRefresh = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"${b32()}"}""").bodyAsText()
        c.selfDelete(me)
        val fresh = Me(me.email)
        Flow.register(c, s, fresh, Flow.enrolAuth(s))
        for (token in listOf(me.token, held.accessToken)) {
            for (path in listOf("/api/v1/account/keys", "/api/v1/account/devices", "/api/v1/sync", "/api/v1/account/state")) {
                val r = c.call(get, path, token = token)
                assertEquals(401, r.status.value, "$path: ${r.bodyAsText()}")
                assertEquals(unknown, r.bodyAsText(), path)
            }
        }
        for (refresh in listOf(me.session!!.refreshToken, held.refreshToken)) {
            val r = c.call(post, "/api/v1/auth/refresh", """{"refreshToken":"$refresh"}""")
            assertEquals(401, r.status.value); assertEquals("invalid_refresh", r.errorCode())
            assertEquals(unknownRefresh, r.bodyAsText())
            assertEquals(200, c.call(post, "/api/v1/auth/end-session", """{"refreshToken":"$refresh"}""").status.value)
        }
        // The new account's session is untouched by those calls.
        assertEquals(200, c.call(get, "/api/v1/account/keys", token = fresh.token).status.value)
        // The earlier password does not sign in at the address.
        val old = c.call(post, "/api/v1/auth/login", me.loginBody(secret = b32()))
        assertEquals(401, old.status.value); assertEquals("invalid_credentials", old.errorCode())
        // The earlier device row and its secret, with the new account's password: a new row.
        val named = c.call(post, "/api/v1/auth/login", fresh.loginBody(deviceId = me.deviceId, secret = me.deviceSecret))
        assertEquals(200, named.status.value, named.bodyAsText())
        val signedIn = WireJson.json.decodeFromString(SessionResponse.serializer(), named.bodyAsText())
        assertNotEquals(me.deviceId, signedIn.deviceId)
        assertEquals(fresh.userId, signedIn.userId)
    }

    /**
     * A client that asks for the earlier account's records by id gets the answer for an id that never existed: the new
     * account at the same address asking for the earlier personal vault's log or members is `403 no_grant`, and for the
     * earlier device's removal `404 no_such_device`, each byte for byte as for a random id; its keys are its own, never
     * the earlier account's. The operator asking for the earlier account's devices is `400 no_such_user`, as for a random
     * id, and the list of accounts does not name it. No route serves an account's keys by the account's id: the only
     * routes that take one are the operator's.
     */
    @Test
    fun theEarlierAccountsIds_areAnsweredAsIdsThatNeverExisted() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        c.selfDelete(me)
        val fresh = Me(me.email)
        Flow.register(c, s, fresh, Flow.enrolAuth(s))
        suspend fun sameAsRandom(what: String, status: Int, code: String, earlier: String, random: String, token: String, body: String? = null) {
            val method = if (body == null) get else post
            val a = c.call(method, earlier, body, token)
            val b = c.call(method, random, body, token)
            assertEquals(status, a.status.value, "$what: ${a.bodyAsText()}"); assertEquals(code, a.errorCode(), what)
            assertEquals(b.status.value, a.status.value, what); assertEquals(b.bodyAsText(), a.bodyAsText(), what)
        }
        val rnd = uuid()
        sameAsRandom("vault log", 403, "no_grant", "/api/v1/vaults/${me.personalVaultId}/log", "/api/v1/vaults/$rnd/log", fresh.token)
        sameAsRandom("vault members", 403, "no_grant", "/api/v1/vaults/${me.personalVaultId}/members", "/api/v1/vaults/$rnd/members", fresh.token)
        sameAsRandom(
            "device removal", 404, "no_such_device", "/api/v1/account/devices/${me.deviceId}/revoke", "/api/v1/account/devices/$rnd/revoke",
            fresh.token, """{"currentAuthKey":"${fresh.authKey}"}""",
        )
        sameAsRandom("operator: devices", 400, "no_such_user", "/api/v1/admin/accounts/${me.userId}/devices", "/api/v1/admin/accounts/$rnd/devices", op.token)
        val keys = WireJson.json.decodeFromString(AccountKeys.serializer(), c.call(get, "/api/v1/account/keys", token = fresh.token).bodyAsText())
        assertEquals(fresh.identity.identityPubB64, keys.identityPub)
        assertNotEquals(me.identity.identityPubB64, keys.identityPub)
        val accounts = c.call(get, "/api/v1/admin/accounts", token = op.token)
        assertEquals(200, accounts.status.value)
        assertFalse(accounts.bodyAsText().contains(me.userId))
        assertTrue(accounts.bodyAsText().contains(fresh.userId))
        val byAccountId = WireRoute.entries.filter { it.path.contains("{userId}") }
        assertTrue(byAccountId.isNotEmpty() && byAccountId.all { it.path.startsWith("/api/v1/admin/") }, byAccountId.joinToString { it.path })
    }
}
