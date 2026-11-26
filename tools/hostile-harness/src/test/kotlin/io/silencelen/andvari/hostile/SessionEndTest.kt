package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Endless
import io.silencelen.andvari.hostile.proxy.Resp
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The app interface's rules for a session the server ends (design §4.4 "A session the server ends does not delete the
 * device's copy"), shown through the command-line host: a device the operator revoked ends its session at the next
 * refresh and keeps its records; every 401 to a refresh ends the session and no other answer does; and a server that
 * ends a session cannot make the device delete what it holds.
 */
class SessionEndTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    private fun snapshot(h: Host): Map<String, String?> = h.state.keys()!!.associateWith { h.state.get(it) }

    /** One authenticated call whose first answer is a 401, so the host refreshes once. */
    private suspend fun World.forceRefresh(h: Host) {
        val rule = proxy.on(WireRoute.ACCOUNT_KEYS, tag(h), times = 1) { _ -> Resp.error(401, "invalid_credentials") }
        h.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
        rule.remove()
    }

    /** Signing in again, at the same pin; an enrol pin is no password pin, so the first password sign-in passes the Trust Gate (§4.4). */
    private suspend fun World.signInAgain(h: Host, email: String) {
        var r = h.onboarding(origin).signIn(email, password)
        if (r is SignIn.TrustGateFirst) {
            val g = assertIs<io.silencelen.andvari.core.client.pin.FirstPin.NeedsTrustGate>(
                h.trust.beginTrustGate(origin, io.silencelen.andvari.core.client.pin.TrustGateWording.TYPED_ADDRESS))
            assertIs<io.silencelen.andvari.core.client.pin.FirstPin.Pinned>(h.trust.confirmTrustGate(g.confirm))
            r = h.onboarding(origin).signIn(email, password)
        }
        assertIs<SignIn.SignedIn>(r, "signing in again continues: $r")
    }

    @Test fun aDeviceTheOperatorRevokedEndsItsSessionAtTheNextRefreshAndKeepsItsRecords() = world {
        val op = operator()
        val ah = member("alice")
        val a = account(ah)
        a.putItem(a.personalVaultId!!, doc("kept"))
        a.synced()
        val revoked = ah.session(origin)!!.session.deviceId
        assertIs<io.silencelen.andvari.core.client.account.Reauthed.Done<*>>(op.operator(op.session(origin)!!).revokeDevice(revoked, password))
        val before = snapshot(ah)
        val mark = proxy.mark()
        // The access token is refused (401), the refresh is refused (401 session_revoked): the session ends.
        assertIs<WireResult.Refused>(ah.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it }))
        assertTrue(sent(ah, WireRoute.REFRESH, mark).isNotEmpty(), "the refresh was asked")
        assertNotNull(ah.endedByServer(origin), "the session ended")
        assertNull(ah.session(origin), "no request carries its tokens any more")
        assertEquals(before, snapshot(ah), "everything the device keeps for the account stays")
        // Nothing more goes with the ended session's tokens.
        val after = proxy.mark()
        ah.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
        assertTrue(proxy.requests(tag = "alice", since = after).none { it.bearer != null }, "no bearer after the end")
    }

    @Test fun every401ToARefreshEndsTheSessionAndNothingElseDoes() = world {
        operator()
        val ah = member("alice")
        account(ah).synced()
        // Answers to the refresh in the server's own envelope that are not a 401: the session is kept, whatever they say,
        // and each of them is an answer, so nothing of the token is out afterwards.
        val keeps = listOf<Pair<String, () -> Resp?>>(
            "403" to { Resp.error(403, "invalid_refresh") },
            "400" to { Resp.error(400, "bad_request") },
            "429" to { Resp.error(429, "rate_limited") },
            "500" to { Resp.error(500, "internal") },
        )
        for ((what, answer) in keeps) {
            val held = ah.session(origin)
            assertNotNull(held, what)
            val rule = proxy.on(WireRoute.REFRESH, "alice") { _ -> answer() }
            forceRefresh(ah)
            rule.remove()
            assertNull(ah.endedByServer(origin), "$what: the session is not ended")
            assertTrue(ah.session(origin) === held, "$what: the same session is held")
            assertNull(held.refreshOutAt, "$what: an answer in the server's envelope leaves no refresh out")
        }
        // Answers that are not the server's own (a proxy's page, a body too large or of the wrong shape, none at all): the
        // session is kept too, but the server may have taken the refresh all the same, so the token counts as out. It is
        // sent once more inside the window; here the server itself answers that try, and the session lives.
        val out = listOf<Pair<String, () -> Resp?>>(
            "a 401 that is not the envelope" to { Resp(401, mapOf("Content-Type" to "text/html"), "<html>proxy</html>".encodeToByteArray()) },
            "a 401 too large to read" to { Resp(401, mapOf("Content-Type" to "application/json"), ByteArray(0), Endless(declaredLength = null, upTo = 8L shl 20)) },
            "a 200 that is not a token pair" to { Resp(200, mapOf("Content-Type" to "application/json"), "{}".encodeToByteArray()) },
            "no answer" to { null },
        )
        for ((what, answer) in out) {
            val held = ah.session(origin)
            assertNotNull(held, what)
            val rule = proxy.on(WireRoute.REFRESH, "alice") { _ -> answer() }
            forceRefresh(ah)
            rule.remove()
            assertNull(ah.endedByServer(origin), "$what: the session is not ended")
            assertTrue(ah.session(origin) === held, "$what: the same session is held")
            assertNotNull(held.refreshOutAt, "$what: the refresh counts as out")
            val again = proxy.mark()
            forceRefresh(ah)
            assertEquals(1, sent(ah, WireRoute.REFRESH, again).size, "$what: the token is sent once more")
            assertNull(ah.endedByServer(origin), "$what: the server's own answer to the second try ends nothing")
            assertTrue(ah.session(origin) === held, "$what: the same session is still held")
            assertNull(held.refreshOutAt, "$what: the server's own answer leaves no refresh out")
        }
        // After two answers in a row that are not the server's own, no try is left: nothing is sent with the token any
        // more (a third send could read as a stolen token and end every session of the device), and nothing is ended.
        run {
            val held = ah.session(origin)
            assertNotNull(held)
            val rule = proxy.on(WireRoute.REFRESH, "alice") { _ -> null }
            forceRefresh(ah)
            forceRefresh(ah)
            val third = proxy.mark()
            forceRefresh(ah)
            rule.remove()
            assertEquals(emptyList(), sent(ah, WireRoute.REFRESH, third), "no third refresh is sent")
            assertNull(ah.endedByServer(origin), "no try left: the server ended nothing")
            assertTrue(ah.session(origin) === held, "no try left: the session is still held for the sign-in to name")
            ah.dropSession(origin)
            signInAgain(ah, "alice@example.org")
        }
        // Every 401 envelope to the refresh ends it, the codes the server sends and one it may send tomorrow.
        for (code in listOf("invalid_refresh", "refresh_reuse", "refresh_expired", "session_revoked", "invalid_credentials", "something_new")) {
            val before = snapshot(ah)
            val rule = proxy.on(WireRoute.REFRESH, "alice") { _ -> Resp.error(401, code) }
            forceRefresh(ah)
            rule.remove()
            assertEquals(code, ah.endedByServer(origin)?.code, "$code ends the session")
            assertNull(ah.session(origin), code)
            assertEquals(before, snapshot(ah), "$code: nothing the device keeps is deleted")
            ah.dropSession(origin)
            signInAgain(ah, "alice@example.org")
        }
    }

    @Test fun aServerThatEndsASessionCannotMakeTheDeviceDeleteWhatItHolds() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        a.putItem(a.personalVaultId!!, doc("still here"))
        a.synced()
        val before = snapshot(ah)
        // The server ends the session, and then answers everything this device asks with "gone".
        val ends = proxy.on(WireRoute.REFRESH, "alice") { _ -> Resp.error(401, "session_revoked") }
        val gone = proxy.on(null, "alice", where = { it.route != WireRoute.REFRESH }) { _ -> Resp.error(401, "account_deleted") }
        forceRefresh(ah)
        assertNotNull(ah.endedByServer(origin))
        a.sync()
        ah.client(origin).call(WireRoute.SYNC, query = "since=0", decode = { it })
        gone.remove()
        ends.remove()
        assertEquals(before, snapshot(ah), "the pin, the account's records and the device record are all still there")
        // The account opens again with its password, and its items come back.
        ah.dropSession(origin)
        signInAgain(ah, "alice@example.org")
        val again = account(ah)
        again.synced()
        assertTrue(again.items(again.personalVaultId!!).any { it.doc["name"].toString().contains("still here") }, "the item is there")
    }
}
