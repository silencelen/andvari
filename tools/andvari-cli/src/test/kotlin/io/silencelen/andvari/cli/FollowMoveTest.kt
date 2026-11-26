package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Design §4.4 "A namespace's trust records move with its pin": the operator signs a move, the everyday device follows
 * it with `card follow --yes`, and afterwards the tool finds at the new address what it kept at the old one: the
 * account's name, the remembered account, the last-used origin and the saved session.
 */
class FollowMoveTest {
    @Test fun aFollowedMoveTakesTheToolsOwnRecordsAndItsSavedSessionToTheNewAddress() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            val reg = CliRun.run(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--name", "Me Myself",
                "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0).ok()
            val userId = Regex("\\(([0-9a-f-]{36})\\)").find(reg)!!.groupValues[1]
            CliRun.run(s, me, "item", "put", "personal", "--trust-card", card0, stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}""")).ok()

            // The same server under another address: the operator signs the move.
            val moved = "http://localhost:${s.originPort}"
            assertTrue(CliRun.run(s, op, "card", "sign", "--move-to", moved).ok().contains("card 1 stored"))

            val state = CliHome(me).deviceState()
            val secure = CliHome(me).secureState()
            val before = PinStore(state).get(s.origin)!!
            // Shown, and not followed without the person's word.
            val asked = CliRun.run(s, me, "card", "follow")
            assertEquals(2, asked.code, asked.err)
            assertTrue(asked.err.contains("moved to $moved"), asked.err)
            assertEquals(before, PinStore(state).get(s.origin))
            assertEquals(PinState.None, PinStore(state).state(moved))

            assertTrue(CliRun.run(s, me, "card", "follow", "--yes").ok().contains("now uses"))
            assertEquals(PinState.None, PinStore(state).state(s.origin), "the namespace moved")
            assertEquals(moved, PinStore(state).get(moved)!!.origin)

            // The tool's own records are at the new address, and none is left at the old one.
            assertEquals("Me Myself", state.get("cli.name|$moved|$userId"))
            assertEquals("me@example.org", state.get("cli.email|$moved"))
            assertEquals(moved, state.get(Ctx.K_ORIGIN))
            assertTrue(SavedSessions(secure).has(moved, "me@example.org"), "the saved session moved")
            assertEquals(emptyList(), (state.keys() + secure.keys()).filter { it.contains("|${s.origin}|") || it.endsWith("|${s.origin}") })

            // Without --origin the tool now works at the new address: the saved session reopens there and the items are read.
            val who = CliRun.run(s, me, "whoami", origin = null).ok()
            assertTrue(who.contains("origin:  $moved") && who.contains("account: me@example.org"), who)
            assertTrue(CliRun.run(s, me, "item", "list", "personal", origin = null).ok().contains("GitHub"))
            assertTrue(Host(state, secure, s::now).displayName(moved, userId) == "Me Myself")
            tmp.deleteRecursively()
        }
    }
}
