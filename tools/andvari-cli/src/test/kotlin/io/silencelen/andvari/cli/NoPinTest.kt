package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.net.originStopped
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Design §4.4 "No credential goes to an origin without a pin in force", in the tool's words: a kept session whose pin
 * record was removed is a blocked server that can be forgotten (no password is asked, nothing is dialed, and sign-out
 * ends it on the device without telling the server), and a command given `--origin` for a server never connected to
 * says what happened and what to do. Never a stack trace, never a bare code.
 */
class NoPinTest {
    private val noPassword: (String) -> String? = { null }

    /** A listener that only counts connections ([ConnectionCounter]); [block] gets its address and the counter. */
    private fun <T> counting(block: (String, ConnectionCounter) -> T): T = ConnectionCounter().use { block(it.address, it) }

    private fun plainWords(r: CliRun) {
        assertFalse(r.err.contains("Exception") || r.err.contains("\tat ") || r.err.contains("origin_stopped"), r.err)
    }

    @Test fun aKeptSessionWithNoPinIsBlockedAndANeverConnectedOriginIsSentNoCredential() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            CliRun.run(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0).ok()
            val state = CliHome(me).deviceState()
            val secure = CliHome(me).secureState()

            // The pin record is lost; the saved session is still kept.
            PinStore(state).remove(s.origin)
            assertTrue(SavedSessions(secure).has(s.origin, "me@example.org"))
            counting { dial, connections ->
                for (cmd in listOf(listOf("sync"), listOf("item", "list", "personal"), listOf("sign-in"), listOf("vault", "create", "X"),
                    listOf("link-device", "show"), listOf("card", "sign"), listOf("operator", "accounts"))) {
                    val r = CliRun.run(s, me, *cmd.toTypedArray(), env = noPassword, dial = dial)
                    assertEquals(1, r.code, "$cmd: ${r.err}")
                    assertTrue(r.err.contains("no pin") && r.err.contains("forget-server --yes") && r.err.contains("sign-out"), "$cmd: ${r.err}")
                    assertFalse(r.err.contains("Master password") || r.err.contains("no password given"), "$cmd asks no password: ${r.err}")
                    plainWords(r)
                }
                assertTrue(CliRun.run(s, me, "whoami", dial = dial).ok().contains("blocked"))
                // Signing out ends it on this device only, and says the server was not told.
                val out = CliRun.run(s, me, "sign-out", dial = dial).ok()
                assertTrue(out.contains("not told") && out.contains("no pin"), out)
                assertEquals(0, connections.settled(), "a kept session with no pin dials nothing")
            }
            assertFalse(SavedSessions(secure).has(s.origin, "me@example.org"))
            // Afterwards the Trust Gate pins the server again and the account signs in.
            CliRun.run(s, me, "sign-in", "--email", "me@example.org", "--trust-card", card0).ok()

            // A server this device never connected to.
            val fresh = File(tmp, "fresh")
            counting { never, connections ->
                for (cmd in listOf(listOf("card", "follow", "--yes"), listOf("card", "show"))) {
                    val r = CliRun.run(s, fresh, *cmd.toTypedArray(), origin = never)
                    assertEquals(1, r.code, "$cmd: ${r.err}")
                    assertTrue(r.err.contains("no pin"), "$cmd: ${r.err}")
                    plainWords(r)
                }
                assertTrue(CliRun.run(s, fresh, "sign-out", "--email", "me@example.org", origin = never).ok().contains("no session"))
                CliRun.run(s, fresh, "forget-server", "--yes", origin = never).ok()
                assertEquals(0, connections.settled(), "nothing is dialed for these")

                // The engine stops every credentialed request there; the tool says so in words.
                val host = Host(CliHome(fresh).deviceState(), CliHome(fresh).secureState(), s::now)
                runBlocking {
                    assertTrue(host.client(never).call(WireRoute.ACCOUNT_KEYS, decode = { it }).originStopped)
                    assertTrue(host.withToken(never, "t").call(WireRoute.LOGOUT, decode = { }).originStopped)
                }
                assertEquals(0, connections.settled(), "no credential goes to an origin without a pin")
                val said = stoppedError(never, OriginAccess.OPEN, pinned = false).message!!
                assertTrue(said.contains("nothing was sent") && said.contains("Trust Gate") && said.contains("forget-server --yes"), said)
                assertTrue(stoppedError(never, OriginAccess.MOVING).message!!.contains("card follow"))

                // A sign-in there runs the Trust Gate first (its card fetch carries no credential), and says why it stops.
                val r = CliRun.run(s, fresh, "sync", "--email", "me@example.org", origin = never)
                assertEquals(1, r.code, r.err)
                plainWords(r)
            }
            tmp.deleteRecursively()
        }
    }
}
