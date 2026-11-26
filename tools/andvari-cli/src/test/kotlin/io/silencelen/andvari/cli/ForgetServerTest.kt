package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Redirect
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.ServerForgotten
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * `forget-server` forgets everything (design §4.4, §12.3): the pin with its marks, the saved session, the accounts'
 * records and the tool's own names, under a forked, damaged or unreadable pin and with no pin at all, sending nothing.
 * A partial wipe says so and a second run finishes it. Another server's and another account's records stay.
 */
class ForgetServerTest {
    private class Run(val code: Int, val out: String, val err: String)

    private fun cli(s: TestServer, home: File, vararg args: String, stdin: String = "", dial: String? = null): Run {
        val buf = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val lines = stdin.lines().filter { it.isNotEmpty() }.iterator()
        val oldErr = System.err
        System.setErr(PrintStream(err, true))
        val code = try {
            Cli.runWith(listOf("--home", home.path, "--origin", s.origin) + args, PrintStream(buf), { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null },
                { if (lines.hasNext()) lines.next() else null }, s::now, dial?.let { d -> { Redirect.client(s.origin, d) } })
        } finally {
            System.setErr(oldErr)
        }
        return Run(code, buf.toString(), err.toString())
    }

    private fun ok(r: Run): String { assertEquals(0, r.code, r.out + r.err); return r.out }

    /** A device state whose listing, chosen deletes or chosen reads fail, as a store on a failing disk would. */
    private class Flaky(private val inner: DeviceState) : DeviceState {
        var listFails = false
        var deleteFails: (String) -> Boolean = { false }
        var readFails: (String) -> Boolean = { false }
        override fun get(key: String): String? = if (readFails(key)) throw IllegalStateException("unreadable") else inner.get(key)
        override fun set(key: String, value: String?) {
            if (value == null && deleteFails(key)) throw IllegalStateException("cannot delete")
            inner.set(key, value)
        }
        override fun keys(): Set<String>? = if (listFails) null else inner.keys()
    }

    @Test fun forgettingAServerDeletesEverythingItKeptInEveryPinStateAndNothingElse() {
        TestServer().use { s ->
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val me = File(tmp, "me")
            ok(cli(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path))
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(ok(cli(s, op, "card", "show")))!!.groupValues[1]
            val reg = ok(cli(s, me, "enrol", Steps.enrolLink(s, "me@example.org"), "--email", "me@example.org", "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0))
            val userId = Regex("\\(([0-9a-f-]{36})\\)").find(reg)!!.groupValues[1]
            ok(cli(s, me, "item", "put", "personal", "--trust-card", card0, stdin = """{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}"""))

            // Another server's and another account's records, and a look-alike origin's (the same address with one more digit).
            val state = CliHome(me).deviceState()
            val secure = CliHome(me).secureState()
            val other = "https://other.example"
            val lookAlike = s.origin + "9"
            val otherUser = "44444444-4444-4444-8444-444444444444"
            val others = mapOf(
                "cli.name|$other|$otherUser" to "Other", "cli.email|$other" to "o@example.org", "ovh.acct|$otherUser" to "a",
                "ovh.dev|$other|o@example.org" to "d", "cli.name|$lookAlike|$otherUser" to "Look", "cli.email|$lookAlike" to "l@example.org",
                "ovh.links|$lookAlike|$otherUser" to "k",
            )
            val otherSecure = mapOf("cli.session|$other|o@example.org" to "{}", "cli.session|$lookAlike|l@example.org" to "{}", "ovh.assist|$other" to "{}")
            others.forEach { (k, v) -> state.set(k, v) }
            otherSecure.forEach { (k, v) -> secure.set(k, v) }

            /** Nothing this device kept for the origin or its account is left, but the identity record; the others are untouched. */
            fun allGone(round: String) {
                val keys = state.keys()
                assertEquals(emptyList(), keys.filter { it.contains("|${s.origin}|") || it.endsWith("|${s.origin}") }, "$round: per-origin records")
                // The identity record, if any, is kept by design (it only makes a later open stricter).
                assertEquals(emptyList(), keys.filter { it.contains(userId) && it != "ovh.identity|$userId" }, "$round: the account's records")
                assertEquals(emptyList(), secure.keys().filter { it.contains("|${s.origin}|") || it.endsWith("|${s.origin}") }, "$round: the saved session")
                assertTrue(state.get(Ctx.K_ORIGIN) != s.origin, "$round: the last-used origin")
                others.forEach { (k, v) -> assertEquals(v, state.get(k), "$round: $k stays") }
                otherSecure.forEach { (k, v) -> assertEquals(v, secure.get(k), "$round: $k stays") }
                assertEquals(PinState.None, PinStore(state).state(s.origin))
            }

            /** `forget-server --yes` through a listener that only counts connections: it sends nothing. */
            fun forgetThroughCounter(expectWas: String) {
                ConnectionCounter().use { counter ->
                    val said = ok(cli(s, me, "forget-server", "--yes", dial = counter.address))
                    assertTrue(said.contains("it was $expectWas") && said.contains("nothing was sent"), said)
                    assertEquals(0, counter.settled(), "forgetting sends nothing")
                }
            }

            /**
             * Sign in again through the Trust Gate and sync, so the device keeps a session and its device record again. A
             * sync writes no account-state copy, so one account-keyed record stands in for the copy the device keeps.
             */
            fun again() {
                ok(cli(s, me, "sync", "--email", "me@example.org", "--trust-card", card0))
                assertTrue(SavedSessions(secure).has(s.origin, "me@example.org"))
                assertTrue(state.get("ovh.dev|${s.origin}|me@example.org") != null)
                state.set("ovh.acct|$userId|copy", "kept")
            }

            // Before: the device keeps the pin, the session, the account's records and the tool's own name and account.
            assertTrue(state.get("cli.name|${s.origin}|$userId") != null && state.get("cli.email|${s.origin}") != null)
            assertTrue(state.keys().any { it.startsWith("ovh.acct|$userId") })

            // An assisted-recovery request this server left under an older address (a followed move does not carry the
            // secure store), bound to its instance and card 0: the pin read before the engine's wipe names it, so it goes.
            val pin0 = PinStore(state).get(s.origin)!!
            val olderAddress = "https://older.example"
            fun b64(n: Int) = io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(n) { 3 })
            // Written as the shared code keeps such a request in the secure store (its record and its index), since the
            // tool reaches nothing internal of it: the record's own fields, bound to the server's instance and card 0.
            val record = kotlinx.serialization.json.buildJsonObject {
                put("origin", kotlinx.serialization.json.JsonPrimitive(olderAddress))
                put("email", kotlinx.serialization.json.JsonPrimitive("me@example.org"))
                put("requestId", kotlinx.serialization.json.JsonPrimitive(b64(16)))
                put("rPub", kotlinx.serialization.json.JsonPrimitive(b64(32)))
                put("rSec", kotlinx.serialization.json.JsonPrimitive(b64(32)))
                put("pollSecret", kotlinx.serialization.json.JsonPrimitive(b64(32)))
                put("createdAt", kotlinx.serialization.json.JsonPrimitive(1))
                put("instanceId", kotlinx.serialization.json.JsonPrimitive(pin0.instanceId))
                put("card0Hash", kotlinx.serialization.json.JsonPrimitive(pin0.card0Hash))
            }
            secure.set("ovh.assist|$olderAddress", record.toString())
            secure.set("ovh.assist.index", kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive(olderAddress))).toString())
            assertTrue(secure.get("ovh.assist|$olderAddress") != null)

            // 1. Under a fork.
            PinStore(state).let { it.markForked(it.get(s.origin)!!) }
            forgetThroughCounter("fork")
            allGone("forked")
            assertEquals(null, secure.get("ovh.assist|$olderAddress"), "the request bound to the forgotten server, under its older address")

            // 2. Under a damaged pin.
            again()
            state.set(PinStore.KEY_PREFIX + s.origin, "{ not a pin")
            forgetThroughCounter("damaged")
            allGone("damaged")

            // 3. With no pin at all (a record lost; the session and the account's records are still kept).
            again()
            PinStore(state).remove(s.origin)
            forgetThroughCounter("open")
            allGone("no pin")

            // 4. Under a pin that cannot be read.
            again()
            val unreadable = Flaky(state).apply { readFails = { it == PinStore.KEY_PREFIX + s.origin } }
            val h = Host(unreadable, secure, s::now)
            assertEquals(OriginAccess.BLOCKED, h.access(s.origin))
            assertEquals(ServerForgotten.Done, h.forgetServer(s.origin, SavedSessions(secure), "me@example.org"))
            allGone("unreadable")

            // 5. A partial wipe: the store cannot list its keys, then one record cannot be deleted. Each time the pin is gone,
            // the saved session (the list of what to finish) is kept, and the next run goes further; the third finishes.
            again()
            val flaky = Flaky(state).apply { listFails = true }
            assertEquals(ServerForgotten.Partly(ServerForgotten.CANNOT_LIST), Host(flaky, secure, s::now).forgetServer(s.origin, SavedSessions(secure), "me@example.org"))
            assertEquals(PinState.None, PinStore(state).state(s.origin), "the pin goes even when the rest cannot")
            assertTrue(SavedSessions(secure).has(s.origin, "me@example.org"))
            flaky.listFails = false
            flaky.deleteFails = { it.startsWith("ovh.acct|$userId") }
            assertEquals(ServerForgotten.Partly(ServerForgotten.CANNOT_DELETE), Host(flaky, secure, s::now).forgetServer(s.origin, SavedSessions(secure), "me@example.org"))
            assertTrue(state.keys().any { it.startsWith("ovh.acct|$userId") })
            assertTrue(SavedSessions(secure).has(s.origin, "me@example.org"), "the second run still knows which account to finish")
            flaky.deleteFails = { false }
            assertEquals(ServerForgotten.Done, Host(flaky, secure, s::now).forgetServer(s.origin, SavedSessions(secure), "me@example.org"))
            allGone("partly, then finished")

            // What the person reads about a partial wipe: what happened, that nothing was sent, and to run it again.
            for (r in listOf(ServerForgotten.Partly(ServerForgotten.CANNOT_LIST), ServerForgotten.Partly(ServerForgotten.CANNOT_DELETE))) {
                val said = Commands.forgotten(s.origin, "fork", r, me.path)
                assertTrue(said.contains("only in part") && said.contains("nothing was sent") && said.contains("forget-server --yes` again") && said.contains(me.path), said)
            }
            assertFalse(Commands.forgotten(s.origin, "fork", ServerForgotten.Done, me.path).contains("again`"))

            // Afterwards the Trust Gate runs again: no silent first trust.
            assertEquals(1, cli(s, me, "sign-in", "--email", "me@example.org").code)

            // Without --yes nothing is deleted, and the person is told what would be.
            again()
            val asked = cli(s, me, "forget-server")
            assertEquals(2, asked.code)
            assertTrue(asked.err.contains("deletes everything") && asked.err.contains("Nothing is sent"), asked.err)
            assertTrue(SavedSessions(secure).has(s.origin, "me@example.org") && PinStore(state).get(s.origin) != null)
            tmp.deleteRecursively()
        }
    }
}
