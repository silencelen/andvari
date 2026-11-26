package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §4.4 "A session the server ends does not delete the device's copy": the operator revokes the device, so the
 * server refuses the session's refresh. The session ends and its tokens go; everything else the device keeps for the
 * account stays; the person is told the server ended it and that signing in again continues, and it does.
 */
class SessionEndedTest {
    private fun deviceIdOf(secure: DeviceState, origin: String, email: String): String =
        WireJson.json.parseToJsonElement(secure.get("cli.session|$origin|$email")!!).jsonObject.getValue("deviceId").jsonPrimitive.content

    private fun snapshot(state: DeviceState): Map<String, String?> = state.keys()!!.associateWith { state.get(it) }

    @Test fun aSessionTheServerEndsLosesOnlyItsTokensAndSigningInAgainContinues() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            CliRun.run(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0).ok()
            CliRun.run(s, me, "item", "put", "personal", "--trust-card", card0, stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}""")).ok()
            val state = CliHome(me).deviceState()
            val secure = CliHome(me).secureState()

            // 1. The server ends the session between two runs: the saved session's refresh is refused when it reopens.
            CliRun.run(s, op, "operator", "revoke-device", deviceIdOf(secure, s.origin, "me@example.org")).ok()
            val before = snapshot(state)
            val ended = CliRun.run(s, me, "item", "list", "personal")
            assertEquals(1, ended.code, ended.out + ended.err)
            assertTrue(ended.err.contains("ended this device's session") && ended.err.contains("andvari-cli sign-in"), ended.err)
            assertFalse(ended.err.contains("Exception"), ended.err)
            assertFalse(SavedSessions(secure).has(s.origin, "me@example.org"), "the session's tokens are deleted")
            assertEquals(before, snapshot(state), "nothing else this device keeps for the account is touched")
            assertTrue(CliRun.run(s, me, "whoami").ok().contains("account: me@example.org"), "the account is still the remembered one")

            // Signing in again continues, at the same pin, with the account's items (an enrol pin is no password pin, so the
            // first password sign-in passes the Trust Gate, design §4.4).
            val again = CliRun.run(s, me, "sign-in", "--trust-card", card0)
            assertEquals(0, again.code, again.err)
            assertTrue(CliRun.run(s, me, "item", "list", "personal").ok().contains("GitHub"))

            // 2. The server ends the session during a command: the refused refresh drops it from the host at once, and the
            // saved tokens go through the host's callback, never written back at the end of the command.
            val host = Host(state, secure, s::now)
            val saved = SavedSessions(secure)
            host.onSession = { saved.save(it) }
            var endedHere: HeldSession? = null
            host.onEnded = { endedHere = it; saved.forget(it.origin, it.emailNorm) }
            runBlocking {
                assertEquals(SavedSessions.Reopen.Reopened, saved.reopen(host, s.origin, "me@example.org", Steps.PASSWORD.toCharArray()))
                CliRun.run(s, op, "operator", "revoke-device", deviceIdOf(secure, s.origin, "me@example.org")).ok()
                val r = host.client(s.origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
                assertIs<WireResult.Refused>(r)
            }
            assertNotNull(host.endedByServer(s.origin), "the refused refresh ended the session")
            assertNull(host.session(s.origin), "no request carries its tokens any more")
            assertEquals("me@example.org", endedHere?.emailNorm)
            assertFalse(saved.has(s.origin, "me@example.org"))
            host.dropSession(s.origin)
            assertTrue(state.get("cli.email|${s.origin}") == "me@example.org" && state.get("ovh.dev|${s.origin}|me@example.org") != null)

            // A rate limit or a stop on this device is not the server ending the session.
            assertFalse(Host.endsSession(WireResult.Refused(429, io.silencelen.andvari.core.model.wire.WireError("rate_limited", ""))))
            assertFalse(Host.endsSession(WireResult.Refused(0, io.silencelen.andvari.core.model.wire.WireError("origin_stopped", ""))))
            tmp.deleteRecursively()
        }
    }
}
