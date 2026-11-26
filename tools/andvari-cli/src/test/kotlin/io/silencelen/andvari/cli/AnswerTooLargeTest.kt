package io.silencelen.andvari.cli

import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * An answer the engine refuses as larger than its route accepts (`body_over_limit`, the engine's response caps) is a
 * fault of the server's answer: every command reports it with its own exit code ([EXIT_SERVER_ANSWER]) and message key
 * ([KEY_SERVER_ANSWER_TOO_LARGE]), never as a wrong password, an answer that did not come, or something not found.
 */
class AnswerTooLargeTest {
    /**
     * A proxy in front of [s]: every request goes on to the real server, except the one route [oversize] names, which is
     * answered with a body longer than that route's cap (with its stated length, so the engine refuses it unread).
     */
    private class Proxy(private val s: TestServer) : AutoCloseable {
        @Volatile var oversize: Pair<WireRoute, Int>? = null
        private val forward = HttpClient.newHttpClient()
        private val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 50).apply {
            createContext("/") { ex ->
                try {
                    val path = ex.requestURI.rawPath
                    val big = oversize?.takeIf { (route, _) -> ex.requestMethod == route.method && pathOf(route).matches(path) }
                    if (big != null) {
                        val body = ByteArray(capOf(big.first) + 1024) { ' '.code.toByte() }
                        ex.responseHeaders.add("Content-Type", "application/json")
                        ex.sendResponseHeaders(big.second, body.size.toLong())
                        ex.responseBody.write(body)
                        return@createContext
                    }
                    val req = HttpRequest.newBuilder(URI.create(s.origin + ex.requestURI.toString()))
                        .method(ex.requestMethod, HttpRequest.BodyPublishers.ofByteArray(ex.requestBody.readBytes()))
                    for ((k, vs) in ex.requestHeaders) if (k.lowercase() !in RESTRICTED) vs.forEach { req.header(k, it) }
                    val r = forward.send(req.build(), HttpResponse.BodyHandlers.ofByteArray())
                    for ((k, vs) in r.headers().map()) if (k.lowercase() !in RESTRICTED && k != ":status") vs.forEach { ex.responseHeaders.add(k, it) }
                    val body = r.body()
                    ex.sendResponseHeaders(r.statusCode(), if (body.isEmpty()) -1 else body.size.toLong())
                    if (body.isNotEmpty()) ex.responseBody.write(body)
                } finally {
                    ex.close()
                }
            }
            start()
        }
        val address = "http://127.0.0.1:${server.address.port}"
        override fun close() = server.stop(0)

        companion object {
            val RESTRICTED = setOf("host", "content-length", "connection", "transfer-encoding", "upgrade", "expect", "keep-alive")
            fun capOf(route: WireRoute): Int = io.silencelen.andvari.core.client.net.ResponseCaps.of(route).toInt()

            /** [route]'s path with each `{param}` matching one path segment. */
            fun pathOf(route: WireRoute): Regex = Regex(route.path.split(Regex("\\{[^}]+}")).joinToString("[^/]+") { Regex.escape(it) })
        }
    }

    private fun assertServerFault(r: CliRun, what: String) {
        assertEquals(EXIT_SERVER_ANSWER, r.code, "$what: ${r.out}${r.err}")
        assertTrue(r.err.contains("[$KEY_SERVER_ANSWER_TOO_LARGE]") && r.err.contains("fault of the server's answer"), "$what: ${r.err}")
        for (wrong in listOf("wrong", "no account", "no such", "did not answer", "no answer", "may have landed", "does not verify")) {
            assertFalse(r.err.lowercase().contains(wrong), "$what is not said as '$wrong': ${r.err}")
        }
    }

    @Test fun anAnswerTooLargeIsTheServersFaultInEveryFlowNeverAWrongPasswordOrNotFound() {
        TestServer().use { s ->
            Proxy(s).use { p ->
                val tmp = Files.createTempDirectory("andvari-cli").toFile()
                val op = File(tmp, "operator")
                val me = File(tmp, "me")
                CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
                val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
                CliRun.run(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0).ok()
                CliRun.run(s, me, "sign-out").ok()

                // A wrong password with an honest server is still a wrong password (exit 1).
                val wrongPw = CliRun.run(s, me, "sign-in", "--email", "me@example.org", "--trust-card", card0, env = { if (it == "ANDVARI_PASSWORD") "not the password" else null })
                assertEquals(1, wrongPw.code, wrongPw.err)
                assertTrue(wrongPw.err.contains("wrong email or master password"), wrongPw.err)

                // 1. Sign-in: the login's refusal envelope is too large. Not a wrong password.
                p.oversize = WireRoute.LOGIN to 401
                assertServerFault(CliRun.run(s, me, "sign-in", "--email", "me@example.org", "--trust-card", card0, dial = p.address), "the login")

                // 2. Reopening a saved session: the account's keys are too large. The saved session is kept.
                p.oversize = null
                CliRun.run(s, me, "sign-in", "--email", "me@example.org", "--trust-card", card0).ok()
                p.oversize = WireRoute.ACCOUNT_KEYS to 200
                assertServerFault(CliRun.run(s, me, "item", "list", "personal", dial = p.address), "the saved session's keys")
                assertTrue(SavedSessions(CliHome(me).secureState()).has(s.origin, "me@example.org"), "the saved session is kept")

                // 3. An operator read: the status is too large.
                p.oversize = WireRoute.ADMIN_STATUS to 200
                assertServerFault(CliRun.run(s, op, "operator", "status", dial = p.address), "the operator's status")

                // 4. An operator write: its own answer is too large (the re-authentication asks the server for nothing first,
                // spec 01 §7). Not "no answer, it may have landed"; this proxy answered in the server's place, so the
                // account is still active.
                p.oversize = WireRoute.ADMIN_ACCOUNT_DISABLE to 200
                assertServerFault(CliRun.run(s, op, "operator", "disable", "me@example.org", dial = p.address), "the re-authentication")
                assertTrue(CliRun.run(s, op, "operator", "accounts").ok().lines().any { it.contains("me@example.org") && it.contains("active") })

                // 5. The Trust Gate on a fresh device: the card chain is too large. Nothing is pinned.
                val fresh = File(tmp, "fresh")
                p.oversize = WireRoute.INSTANCE to 200
                assertServerFault(CliRun.run(s, fresh, "sign-in", "--email", "me@example.org", "--trust-card", card0, dial = p.address), "the card chain")
                assertTrue(CliRun.run(s, fresh, "whoami").ok().contains("not pinned on this device"))

                // The same commands through the same proxy, with nothing too large, succeed.
                p.oversize = null
                CliRun.run(s, fresh, "sign-in", "--email", "me@example.org", "--trust-card", card0, dial = p.address).ok()
                CliRun.run(s, op, "operator", "status", dial = p.address).ok()
            }
        }
    }
}
