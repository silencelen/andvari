package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import java.net.InetSocketAddress
import java.nio.file.Files
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Security review 2026-10, branch A14 (F8) — an enroll is bound to the origin its client was built
 * for. `enrollOp` registered at the pending invite origin B and then saved the session under the
 * LIVE `baseUrl`, re-read after seconds of Argon2id and network; Cancel (or a re-pasted invite)
 * during that window moved `baseUrl` back to A, so session.json paired A with B's tokens and the
 * next unlock sent them to A (§4.1 rule 1). The A12 fence/lockout tests are the model.
 *
 *  - layer 1: while an op holds a client for a pending origin, cancel / re-point / connect are
 *    refused at the state layer, and the session is saved under the client's own origin;
 *  - layer 2: if the origin moves anyway (a manual repoint), the commit is aborted, the tokens are
 *    dropped and best-effort revoked at the origin that issued them;
 *  - layer 3: unlock() and signOut() never send a stored session's tokens to an origin other than
 *    the session's own.
 */
class EnrollOriginBindingTest {
    private val root = Files.createTempDirectory("andvari-desktop-a14-test").toFile()
    private val servers = mutableListOf<HttpServer>()
    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "andvari-a14-test").apply { isDaemon = true } }
    private val liveScope = CoroutineScope(executor.asCoroutineDispatcher())
    private val password = "Tr0ub4dor&3-horse-Battery"

    @AfterTest
    fun cleanup() {
        liveScope.cancel()
        executor.shutdownNow()
        servers.forEach { it.stop(0) }
        root.deleteRecursively()
    }

    private fun awaitUntil(what: String, timeoutMs: Long = 30_000, cond: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cond()) return
            Thread.sleep(10)
        }
        fail("timed out after ${timeoutMs}ms waiting for: $what")
    }

    /** One request a fake origin saw: its path and the bearer token it carried, if any. */
    data class Hit(val path: String, val bearer: String?)

    /** A fake andvari origin. Policy answers at once; register (when [registerHold] is given) parks
     *  until released and then answers a session built from the client's own request, with the
     *  tokens "<name>-access" / "<name>-refresh"; every request is recorded in [hits]. With an
     *  [account] (A14 review N4) it also answers prelogin and login for that account, login parked
     *  on [loginHold] when given. */
    private inner class Origin(
        val name: String,
        private val registerHold: CountDownLatch? = null,
        private val account: JsonObject? = null,
        private val loginHold: CountDownLatch? = null,
    ) {
        val hits: MutableList<Hit> = Collections.synchronizedList(mutableListOf())
        val registerArrived = CountDownLatch(1)
        val loginArrived = CountDownLatch(1)
        val url: String

        init {
            val s = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
            s.executor = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
            s.createContext("/") { ex -> handle(ex) }
            s.start()
            servers += s
            url = "http://127.0.0.1:${s.address.port}"
        }

        private fun handle(ex: HttpExchange) {
            val path = ex.requestURI.path
            hits += Hit(path, ex.requestHeaders.getFirst("Authorization")?.removePrefix("Bearer "))
            val body = ex.requestBody.readBytes().decodeToString()
            when (path) {
                "/api/v1/client-policy" -> respond(ex, 200, """{"recoveryFingerprint":"$name-fp","offlineCacheAllowed":true}""")
                "/api/v1/auth/register" -> {
                    registerArrived.countDown()
                    registerHold?.await(30, TimeUnit.SECONDS)
                    respond(ex, 200, sessionFor(Json.parseToJsonElement(body).jsonObject))
                }
                "/api/v1/auth/logout" -> respond(ex, 204, null)
                "/api/v1/auth/prelogin" -> if (account == null) respond(ex, 404, """{"error":"not_found","message":"not here"}""") else
                    respond(ex, 200, buildJsonObject { put("kdfSalt", account["kdfSalt"]!!); put("kdfParams", account["kdfParams"]!!) }.toString())
                "/api/v1/auth/login" -> if (account == null) respond(ex, 404, """{"error":"not_found","message":"not here"}""") else {
                    loginArrived.countDown()
                    loginHold?.await(30, TimeUnit.SECONDS)
                    respond(ex, 200, sessionFor(account))
                }
                else -> respond(ex, 404, """{"error":"not_found","message":"not here"}""")
            }
        }

        private fun sessionFor(req: JsonObject): String = buildJsonObject {
            put("userId", req["userId"]!!)
            put("deviceId", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
            put("accessToken", "$name-access")
            put("refreshToken", "$name-refresh")
            put("isAdmin", false)
            put(
                "accountKeys",
                buildJsonObject {
                    for (k in listOf("kdfSalt", "kdfParams", "wrappedUvk", "encryptedIdentitySeed", "identityPub")) put(k, req[k]!!)
                    put("escrowFingerprint", "")
                    put("personalWrap", req["personalWrap"] ?: JsonNull)
                },
            )
            put("recoveryPieceId", JsonPrimitive("piece-1"))
        }.toString()

        private fun respond(ex: HttpExchange, status: Int, body: String?) {
            runCatching {
                if (body == null) {
                    ex.sendResponseHeaders(status, -1)
                } else {
                    val bytes = body.toByteArray()
                    ex.responseHeaders.add("Content-Type", "application/json")
                    ex.sendResponseHeaders(status, bytes.size.toLong())
                    ex.responseBody.use { it.write(bytes) }
                }
            }
            ex.close()
        }

        fun sawToken(token: String): Boolean = hits.any { it.bearer == token }
    }

    private class Enrolling(val state: DesktopState, val store: DesktopSessionStore, val home: Origin, val invite: Origin, val hold: CountDownLatch)

    /** Home origin A, invite origin B (register held), the app connected to B and enrolling. */
    private fun enrollingAtB(): Enrolling {
        val home = Origin("a")
        val hold = CountDownLatch(1)
        val invite = Origin("b", registerHold = hold)
        val store = DesktopSessionStore(root).also { it.baseUrl = home.url }
        val state = DesktopState(liveScope, store)
        state.beginEnrollSwitch(invite.url, "m@x.example")
        state.trustGateConnect()
        awaitUntil("B's policy") { state.policy?.recoveryFingerprint == "b-fp" }
        state.enroll("invite-token", "m@x.example", "M", password, typedShortFp = "", hasSheet = false)
        assertTrue(invite.registerArrived.await(30, TimeUnit.SECONDS), "register is in flight at B")
        return Enrolling(state, store, home, invite, hold)
    }

    // ---- layer 1: the switch is frozen while the enroll holds B's client ----

    @Test
    fun cancelRepointAndConnectAreRefusedWhileTheEnrollIsInFlight() {
        val e = enrollingAtB()

        e.state.cancelPendingSwitch() // the always-enabled "Cancel and return" in 0.28.1
        e.state.beginEnrollSwitch("https://other.example", "m@x.example") // the still-editable invite field
        e.state.trustGateConnect()

        assertEquals(e.invite.url, e.state.baseUrl, "the runtime origin must not move while register is in flight")
        assertEquals(e.invite.url, e.state.pendingServer?.origin, "the pending switch is untouched")

        e.hold.countDown()
        awaitUntil("the session to be saved") { e.store.load() != null }
        assertEquals(e.invite.url, e.store.load()?.baseUrl, "B's tokens are saved under B")
        assertEquals("b-access", e.store.load()?.accessToken)
        assertTrue(!e.home.sawToken("b-access") && !e.home.sawToken("b-refresh"), "A never sees B's tokens")
    }

    @Test
    fun aManualRepointIsRefusedAtTheStateLayerWhileAnOpRuns() {
        // A14 review N4: updateServer / manualSwitchConnect were guarded only by the dialog's enabled = !busy.
        val e = enrollingAtB()

        e.state.updateServer(e.home.url)
        e.state.beginManualSwitch(e.home.url)
        e.state.manualSwitchConnect()

        assertEquals(e.invite.url, e.state.baseUrl, "a repoint must not move the origin under the enroll's client")
        e.hold.countDown()
        awaitUntil("the session to be saved") { e.store.load() != null }
        assertEquals(e.invite.url, e.store.load()?.baseUrl, "B's tokens are saved under B")
    }

    // ---- layer 2: an origin change that lands anyway aborts the commit ----

    @Test
    fun aRepointThatLandsMidEnrollAbortsTheCommitAndRevokesAtTheIssuer() {
        val e = enrollingAtB()

        // Every public repoint is refused while the op runs (above); the ungated commit stands in for any future
        // path that moves the origin anyway, so the fence must hold.
        e.state.commitServer(e.home.url)
        e.hold.countDown()

        awaitUntil("the enroll to finish") { !e.state.busy && e.state.error != null }
        awaitUntil("the revocation at B") { e.invite.hits.any { it.path == "/api/v1/auth/logout" } }
        assertNull(e.store.load(), "no session may be saved: B's tokens under A is the bug")
        assertEquals("b-access", e.invite.hits.last { it.path == "/api/v1/auth/logout" }.bearer, "the tokens are revoked at the origin that issued them")
        assertTrue(!e.home.sawToken("b-access") && !e.home.sawToken("b-refresh"), "A never sees B's tokens")
        assertNotNull(e.state.error, "the user is told the enrollment did not finish here")
        assertEquals(e.home.url, e.state.baseUrl)
    }

    // ---- layer 3: a stored session's tokens only ever go to the session's own origin ----

    @Test
    fun unlockRefusesASessionSavedForAnotherOrigin() {
        val home = Origin("a")
        val store = DesktopSessionStore(root).also { it.baseUrl = home.url }
        store.save(DesktopSession("https://b.example", "11111111-1111-4111-8111-111111111111", "m@x.example", "b-access", "b-refresh"))
        val state = DesktopState(liveScope, store)

        state.unlock("m@x.example", password)
        awaitUntil("unlock to be refused") { !state.busy && state.error != null }

        assertTrue(home.hits.none { it.bearer != null }, "no token reaches the live origin: ${home.hits}")
        assertNotNull(state.error)
        assertEquals("b-access", store.load()?.accessToken, "unlock does not silently discard the session; sign-out does")
    }

    @Test
    fun lockedSignOutRevokesOnlyAtTheSessionsOwnOriginAndStillWipesLocally() {
        val home = Origin("a")
        val issuer = Origin("b")
        val store = DesktopSessionStore(root).also { it.baseUrl = home.url }
        store.save(DesktopSession(issuer.url, "11111111-1111-4111-8111-111111111111", "m@x.example", "b-access", "b-refresh"))
        val state = DesktopState(liveScope, store)

        state.signOut()
        awaitUntil("sign-out to finish") { !state.busy && store.load() == null }

        assertTrue(home.hits.none { it.bearer != null }, "no token reaches the live origin: ${home.hits}")
        assertEquals(listOf("b-access"), issuer.hits.filter { it.path == "/api/v1/auth/logout" }.map { it.bearer }, "revoked where it was issued")
        assertNull(store.load(), "sign-out still wipes locally")
    }

    // ---- A14 review N4: a sign-in is bound to the origin its client dialed ----

    /** A real account's register request (so the fake origin can answer prelogin and login for it). */
    private fun accountFor(email: String): JsonObject {
        val enrolled = io.silencelen.andvari.core.client.Account.enroll(
            inviteToken = "t", email = email, displayName = "M", password = password,
            params = io.silencelen.andvari.core.crypto.KdfParams(), recoveryPublicKey = null, recoveryFingerprint = null,
            deviceName = "test", platform = "linux",
        )
        return Json.encodeToJsonElement(io.silencelen.andvari.core.model.RegisterRequest.serializer(), enrolled.request).jsonObject
    }

    @Test
    fun aSignInSavesItsSessionUnderTheOriginItsClientDialed() {
        val home = Origin("a", account = accountFor("m@x.example"))
        val store = DesktopSessionStore(root).also { it.baseUrl = home.url }
        val state = DesktopState(liveScope, store)

        state.signIn("m@x.example", password)
        awaitUntil("the session to be saved") { store.load() != null }
        assertEquals(home.url, store.load()?.baseUrl, "saved under the client's own origin")
        assertEquals("a-access", store.load()?.accessToken)
    }

    @Test
    fun aRepointThatLandsMidSignInAbortsTheCommitAndRevokesAtTheIssuer() {
        val hold = CountDownLatch(1)
        val home = Origin("a", account = accountFor("m@x.example"), loginHold = hold)
        val other = Origin("b")
        val store = DesktopSessionStore(root).also { it.baseUrl = home.url }
        val state = DesktopState(liveScope, store)

        state.signIn("m@x.example", password)
        assertTrue(home.loginArrived.await(30, TimeUnit.SECONDS), "login is in flight at A")
        state.updateServer(other.url)
        assertEquals(home.url, state.baseUrl, "layer 1: the public repoint is refused while the sign-in runs")
        state.commitServer(other.url) // any future path that moves the origin anyway
        hold.countDown()

        awaitUntil("the sign-in to finish") { !state.busy && state.error != null }
        awaitUntil("the revocation at A") { home.hits.any { it.path == "/api/v1/auth/logout" } }
        assertNull(store.load(), "no session may be saved: A's tokens under B is the bug")
        assertEquals("a-access", home.hits.last { it.path == "/api/v1/auth/logout" }.bearer, "revoked at the origin that issued them")
        assertTrue(!other.sawToken("a-access") && !other.sawToken("a-refresh"), "B never sees A's tokens")
        assertEquals(DesktopState.signInOriginMoved(home.url), state.error)
    }
}
