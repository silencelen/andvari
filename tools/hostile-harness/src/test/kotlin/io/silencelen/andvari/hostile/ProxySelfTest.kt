package io.silencelen.andvari.hostile

import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Gate
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.Routes
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.drop
import io.silencelen.andvari.hostile.proxy.dropAnswer
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.hold
import io.silencelen.andvari.hostile.proxy.refuse
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import io.silencelen.andvari.hostile.proxy.twice
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The proxy's own behaviours, each against the real server: a scenario is only as good as the lie it tells. */
class ProxySelfTest {
    private suspend fun policy(w: World, tag: String) = w.device(tag).client(w.origin).call(WireRoute.CLIENT_POLICY, decode = { it })

    @Test fun routesAreRecognisedWithTheirParametersAndALiteralPathWins() {
        assertEquals(WireRoute.LINK_ANSWERS, Routes.of("GET", "/api/v1/links/answers"))
        assertEquals(WireRoute.LINK_FETCH, Routes.of("GET", "/api/v1/links/AAAAAAAAAAAAAAAAAAAAAA"))
        assertEquals(WireRoute.LOG_APPEND, Routes.of("POST", "/api/v1/vaults/v1/log"))
        assertEquals(WireRoute.LOG_FETCH, Routes.of("GET", "/api/v1/vaults/v1/log"))
        assertEquals(mapOf("vaultId" to "v1"), Routes.params(WireRoute.LOG_FETCH, "/api/v1/vaults/v1/log"))
        assertNull(Routes.of("GET", "/api/v1/nothing"))
    }

    @Test fun aRequestNoRuleClaimsPassesUntouchedAndIsRecordedWithItsBody() = world {
        // A pre-login carries something derived from a password, so it leaves only a device that holds a pin (design
        // §4.4): the instance is set up first, then the device confirms its Trust Gate.
        operator()
        val d = pinnedDevice("d")
        val r = d.client(origin).call(WireRoute.PRELOGIN, bodyJson = """{"email":"nobody@example.org"}""", decode = { it })
        assertIs<WireResult.Ok<String>>(r, "prelogin for an unknown address still answers (it is uniform): $r")
        val seen = proxy.requests(WireRoute.PRELOGIN, "d").single()
        assertEquals("nobody@example.org", seen.json!!.str("email"), "the recording holds the request body")
        val ex = proxy.last(WireRoute.PRELOGIN, "d")!!
        assertEquals(1, ex.forwards)
        assertEquals(ex.upstream!!.text, ex.served!!.text, "what the server said is what the device got")
        assertNull(ex.rule)
    }

    /**
     * H7, declined by the owner on 2026-11-15: a device that dials a loopback address under an origin cannot name the
     * origin in its `Host` header (the tool's HTTP client drops a `Host` the caller sets; the library that could was taken
     * out), so its request names the address it dialed. The tool itself therefore refuses `--connect` to any address but
     * the origin's own (design §9.5 C2-R11). Nothing in the trust design rests on `Host` (every check uses the origin
     * the engine holds), and the proxy names the origin to the server itself, so the server is still served.
     */
    @Test fun aDeviceThatDialsALoopbackAddressUnderAnOriginNamesTheDialedAddressNotTheOrigin() = world {
        val r = device("d").client(origin).call(WireRoute.CLIENT_POLICY, decode = { it })
        assertIs<WireResult.Ok<String>>(r, "the proxy names the origin upstream, so the server answers: $r")
        val sent = proxy.requests(WireRoute.CLIENT_POLICY, "d").single().header("Host")
        assertEquals(proxy.dial("d").substringAfter("://"), sent, "the limit: the dialed address")
        assertNotEquals(origin.substringAfter("://"), sent)
    }

    @Test fun aDroppedRequestIsNoAnswerAndNeverReachesTheServer() = world {
        proxy.on(WireRoute.CLIENT_POLICY, "d", handler = drop)
        assertEquals(WireResult.NoAnswer(NoAnswerKind.TRANSPORT), policy(this, "d"))
        val ex = proxy.last(WireRoute.CLIENT_POLICY, "d")!!
        assertTrue(ex.dropped)
        assertEquals(0, ex.forwards)
        // Another device is served as usual: rules are per device.
        assertIs<WireResult.Ok<String>>(policy(this, "other"))
    }

    @Test fun aDroppedAnswerReachesTheServerButNotTheDevice() = world {
        proxy.on(WireRoute.CLIENT_POLICY, "d", handler = dropAnswer)
        assertEquals(WireResult.NoAnswer(NoAnswerKind.TRANSPORT), policy(this, "d"))
        val ex = proxy.last(WireRoute.CLIENT_POLICY, "d")!!
        assertEquals(1, ex.forwards)
        assertNotNull(ex.upstream)
        assertNull(ex.served)
    }

    @Test fun aChosenStatusIsARefusalInTheSpecsEnvelope() = world {
        proxy.on(WireRoute.CLIENT_POLICY, "d", handler = refuse(409, "link_used"))
        val r = assertIs<WireResult.Refused>(policy(this, "d"))
        assertEquals(409, r.status)
        assertEquals("link_used", r.code)
    }

    @Test fun aRuleLimitedToSomeRequestsStepsAsideAndTheNewestRuleWins() = world {
        proxy.on(WireRoute.CLIENT_POLICY, "d", handler = refuse(503, "first"))
        val once = proxy.on(WireRoute.CLIENT_POLICY, "d", times = 1, handler = refuse(503, "newest"))
        assertEquals("newest", assertIs<WireResult.Refused>(policy(this, "d")).code)
        assertEquals("first", assertIs<WireResult.Refused>(policy(this, "d")).code)
        assertEquals(1, once.hits.get())
        proxy.honest()
        assertIs<WireResult.Ok<String>>(policy(this, "d"))
    }

    @Test fun aHeldRequestWaitsForItsGateAndTheServerHasNotSeenItMeanwhile() = world {
        val gate = Gate()
        proxy.on(WireRoute.CLIENT_POLICY, "d", handler = hold(gate))
        val d = device("d")
        withContext(Dispatchers.IO) {
            val call = async { d.client(origin).call(WireRoute.CLIENT_POLICY, decode = { it }) }
            gate.awaitArrival()
            delay(200)
            assertFalse(call.isCompleted, "the device is still waiting")
            assertEquals(0, proxy.last(WireRoute.CLIENT_POLICY, "d")!!.forwards)
            gate.release()
            assertIs<WireResult.Ok<String>>(call.await())
        }
    }

    @Test fun anAnswerIsReplayedOrRewrittenFieldByField() = world {
        val first = assertIs<WireResult.Ok<String>>(policy(this, "d")).value
        val recorded = proxy.last(WireRoute.CLIENT_POLICY, "d")!!.upstream!!
        // A replay: the old answer, and the server is not asked.
        proxy.on(WireRoute.CLIENT_POLICY, "d", times = 1, handler = answer { recorded })
        assertEquals(first, assertIs<WireResult.Ok<String>>(policy(this, "d")).value)
        assertEquals(0, proxy.last(WireRoute.CLIENT_POLICY, "d")!!.forwards)
        // One field substituted, the rest genuine.
        proxy.on(WireRoute.CLIENT_POLICY, "d", times = 1, handler = editAnswer { it.set("canonicalOrigin", "https://evil.example") })
        val edited = Resp(200, emptyMap(), assertIs<WireResult.Ok<String>>(policy(this, "d")).value.encodeToByteArray()).json!!
        assertEquals("https://evil.example", edited.str("canonicalOrigin"))
        assertEquals(recorded.json!!.keys, edited.keys)
    }

    @Test fun aDuplicatedRequestReachesTheServerTwice() = world {
        proxy.on(WireRoute.CLIENT_POLICY, "d", handler = twice)
        assertIs<WireResult.Ok<String>>(policy(this, "d"))
        assertEquals(2, proxy.last(WireRoute.CLIENT_POLICY, "d")!!.forwards)
    }

    @Test fun aWebSocketUpgradeIsRefusedAndRecorded() = world {
        val port = proxy.dial("ws").substringAfterLast(':').toInt()
        val status = Socket("127.0.0.1", port).use { s ->
            s.getOutputStream().write("GET /api/v1/events HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".toByteArray())
            s.getOutputStream().flush()
            s.getInputStream().bufferedReader().readLine()
        }
        assertTrue(status.contains("501"), status)
        val ex = proxy.last(WireRoute.EVENTS, "ws")!!
        assertEquals(0, ex.forwards, "the upgrade never reaches the server")
    }
}
