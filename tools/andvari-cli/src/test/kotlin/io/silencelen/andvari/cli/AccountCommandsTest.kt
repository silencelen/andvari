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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A person's own account from the tool, with no terminal, against the real server (design §8.6, §8.7, §10, §3.11 and the
 * account-deletion design): the master password, a new kit, the devices, "new devices must be linked", and deletion.
 */
class AccountCommandsTest {
    private val newPw = "a New master Password 2 for me"
    private fun pw(p: String): (String) -> String? = { if (it == "ANDVARI_PASSWORD") p else null }

    @Test fun passwordKitDevicesAndRequireLink() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            w.run(me, "item", "put", "personal", stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}""")).ok()
            val saved = SavedSessions(CliHome(me).secureState())
            fun token() = assertNotNull(saved.accessToken(s.origin, "me@example.org"), "a saved session")

            // The new password is never an argument; a weak one is refused before anything is sent.
            assertEquals(2, w.run(me, "account", "password", "--new-password", newPw).code)
            val weak = w.run(me, "account", "password", env = { mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD, "ANDVARI_NEW_PASSWORD" to "short")[it] })
            assertEquals(1, weak.code, weak.err)
            assertTrue(weak.err.contains("too weak") && weak.err.contains("nothing was sent"), weak.err)

            // The new password from a file. Afterwards the SAVED session opens with it (its tokens are the same), and not
            // with the old one, which is then refused.
            val newFile = File(w.tmp, "new-password.txt").apply { writeText(newPw + "\n") }
            val changed = w.run(me, "account", "password", "--new-password-file", newFile.path).ok()
            // The approved words; they say the other devices were signed out, as the server does at a password change.
            assertEquals(fill(PASSWORD_CHANGED, "me@example.org", s.origin), changed.trim(), changed)
            assertFalse(changed.contains("stay signed in"), changed)
            val before = token()
            assertTrue(w.run(me, "item", "list", "personal", env = pw(newPw)).ok().contains("GitHub"))
            assertEquals(before, token(), "the saved session reopened with the new password; no new sign-in")
            // (--trust-card: when the saved session does not open, the sign-in that follows passes the Trust Gate again.)
            val old = w.run(me, "item", "list", "personal", "--trust-card", w.card0)
            assertEquals(1, old.code, "the old password no longer opens the account: ${old.err}")
            assertTrue(old.err.contains("wrong email or master password"), old.err)
            // And back, the new one from the environment and the current one from a file.
            val curFile = File(w.tmp, "current-password.txt").apply { writeText(newPw) }
            w.run(me, "account", "password", "--password-file", curFile.path, env = { if (it == "ANDVARI_NEW_PASSWORD") Steps.PASSWORD else null }).ok()
            assertTrue(w.run(me, "item", "list", "personal").ok().contains("GitHub"))

            // A new kit that cannot be captured is refused before anything is sent: the server stored no new kit.
            fun setups() = w.run(w.op, "operator", "audit", "--type", "recovery_self_setup", "--user", "me@example.org").ok().lines().count { it.isNotBlank() }
            val setupsBefore = setups()
            val noKit = w.run(me, "account", "kit")
            assertEquals(2, noKit.code, noKit.err)
            assertTrue(noKit.err.contains("--kit-out FILE") && noKit.err.contains("Nothing was sent"), noKit.err)
            assertEquals(setupsBefore, setups(), "nothing was sent")
            assertEquals(2, w.run(me, "account", "kit", "--kit-out", w.kit("me@example.org").path).code, "an existing kit file is never overwritten")
            val kit2 = File(w.tmp, "me-kit-2.txt")
            assertTrue(w.run(me, "account", "kit", "--kit-out", kit2.path).ok().contains("the old kit no longer works"))
            assertTrue(kit2.readText().startsWith("andvari recovery kit for account"))
            assertEquals(setupsBefore + 1, setups())

            // Devices: a second device that signed out (not signed in) and a third that is. (The server allows ten prelogins
            // a minute from one address; each re-authentication and sign-in makes one, so the test clock moves on.)
            s.advance(61_000)
            val two = File(w.tmp, "me-2")
            val three = File(w.tmp, "me-3")
            w.run(two, "sign-in", "--email", "me@example.org", "--trust-card", w.card0, "--device-name", "second").ok()
            w.run(two, "sign-out").ok()
            w.run(three, "sign-in", "--email", "me@example.org", "--trust-card", w.card0, "--device-name", "third").ok()
            val list = w.run(me, "account", "devices").ok().lines().filter { it.isNotBlank() }
            assertEquals(3, list.size, list.toString())
            fun idOf(name: String) = list.first { it.contains("“$name”") }.substringBefore(' ')
            assertTrue(list.single { it.endsWith("(this device)") }.contains("“me”"), list.toString())
            assertTrue(list.first { it.contains("“second”") }.contains("not signed in"), list.toString())
            assertTrue(list.first { it.contains("“third”") }.contains(" signed in"), list.toString())

            // This device and an id not in the list are refused before anything is sent.
            val self = w.run(me, "account", "revoke-device", idOf("me"))
            assertEquals(1, self.code)
            assertTrue(self.err.contains("is this device") && self.err.contains("sign-out") && self.err.contains("Nothing was sent"), self.err)
            assertEquals(1, w.run(me, "account", "revoke-device", "00000000-0000-4000-8000-000000000000").code)
            // Any other device, signed in or not.
            assertTrue(w.run(me, "account", "revoke-device", idOf("second")).ok().contains("revoked: “second”"))
            assertTrue(w.run(me, "account", "revoke-device", idOf("third")).ok().contains("revoked: “third”"))
            val ended = w.run(three, "item", "list", "personal")
            assertEquals(1, ended.code)
            assertTrue(ended.err.contains("ended this device's session"), ended.err)
            assertTrue(w.run(me, "account", "devices").ok().lines().filter { it.contains("“second”") || it.contains("“third”") }.none { it.contains(" signed in") && !it.contains("not signed in") })

            // A re-authentication asks the server for nothing first (spec 01 §7: the password is proven on this device, against
            // the session's own wrap): with the minute's prelogins used up by ten sign-in attempts from this address for
            // accounts that do not exist, it still goes. (LocalProofTest counts the requests of a wrong password: none.)
            s.advance(61_000)
            val nobody = File(w.tmp, "nobody")
            for (i in 1..10) w.run(nobody, "sign-in", "--email", "nobody$i@example.org", "--trust-card", w.card0)
            val prelogin = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(s.origin + WireRoute.PRELOGIN.path)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("""{"email":"nobody11@example.org"}""")).build(),
                HttpResponse.BodyHandlers.ofString(),
            )
            assertEquals(429, prelogin.statusCode(), "the minute's prelogins are used up: ${prelogin.body()}")
            assertTrue(w.run(me, "account", "require-link", "off").ok().contains("must be linked: off"))
            s.advance(61_000)

            // New devices must be linked: a device the account never used is refused, and so is a revoked one.
            assertTrue(w.run(me, "account", "require-link", "on").ok().contains("must be linked: on"))
            val fresh = File(w.tmp, "me-4")
            val refused = w.run(fresh, "sign-in", "--email", "me@example.org", "--trust-card", w.card0)
            assertEquals(1, refused.code)
            assertTrue(refused.err.contains("new devices must be linked"), refused.err)
            assertEquals(1, w.run(two, "sign-in", "--email", "me@example.org", "--trust-card", w.card0).code, "a revoked device is not known")
            assertTrue(w.run(me, "account", "require-link", "off").ok().contains("must be linked: off"))
            w.run(fresh, "sign-in", "--email", "me@example.org", "--trust-card", w.card0).ok()
            assertEquals(2, w.run(me, "account", "require-link", "maybe").code)

            // The kit `account kit` captured is the account's kit now; the first one is refused.
            val oldKit = w.run(File(w.tmp, "d1"), "recover", "kit", "--kit-file", w.kit("me@example.org").path, "--kit-out", File(w.tmp, "never.txt").path, origin = null, env = pw(newPw))
            assertEquals(1, oldKit.code, oldKit.err)
            assertTrue(oldKit.err.contains(Commands.KIT_REJECTED), oldKit.err)
            w.run(File(w.tmp, "d2"), "recover", "kit", "--kit-file", kit2.path, "--kit-out", File(w.tmp, "me-kit-3.txt").path, origin = null, env = pw(newPw)).ok()
        }
    }

    /**
     * A proxy in front of [s] that loses the answer to `POST /account/delete`: [forward] false answers 502 without sending
     * it on (nothing was deleted), true sends it on and then answers 502 (the server deleted the account).
     */
    private class LosingProxy(private val s: TestServer) : AutoCloseable {
        @Volatile var lose = false
        @Volatile var forward = false
        private val http = HttpClient.newHttpClient()
        private val server = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 50).apply {
            createContext("/") { ex ->
                try {
                    val deletion = lose && ex.requestMethod == WireRoute.ACCOUNT_DELETE.method && ex.requestURI.rawPath == WireRoute.ACCOUNT_DELETE.path
                    val body = ex.requestBody.readBytes()
                    if (deletion && !forward) { ex.sendResponseHeaders(502, -1); return@createContext }
                    val req = HttpRequest.newBuilder(URI.create(s.origin + ex.requestURI.toString())).method(ex.requestMethod, HttpRequest.BodyPublishers.ofByteArray(body))
                    for ((k, vs) in ex.requestHeaders) if (k.lowercase() !in RESTRICTED) vs.forEach { req.header(k, it) }
                    val r = http.send(req.build(), HttpResponse.BodyHandlers.ofByteArray())
                    if (deletion) { ex.sendResponseHeaders(502, -1); return@createContext }
                    for ((k, vs) in r.headers().map()) if (k.lowercase() !in RESTRICTED && k != ":status") vs.forEach { ex.responseHeaders.add(k, it) }
                    val answer = r.body()
                    ex.sendResponseHeaders(r.statusCode(), if (answer.isEmpty()) -1 else answer.size.toLong())
                    if (answer.isNotEmpty()) ex.responseBody.write(answer)
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
        }
    }

    @Test fun deleteShowsThePlanAndBlockersAsksForTheTypedAddressSaysCannotTellAndLeavesNothingInTheHome() {
        TestServer().use { s ->
            LosingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val alice = w.account("alice@example.org")
                val (meId, aliceId) = w.connect(me, alice)
                val mine = CliWorld.vaultId(w.run(me, "vault", "create", "Mine").ok())
                w.run(me, "vault", "add", mine, aliceId).ok()
                w.run(alice, "vault", "incoming", mine, "--accept").ok()
                val hers = CliWorld.vaultId(w.run(alice, "vault", "create", "Hers").ok())
                w.run(alice, "vault", "add", hers, meId).ok()
                w.run(me, "vault", "incoming", hers, "--accept").ok()
                val myDevice = w.run(me, "account", "devices").ok().lines().single { it.endsWith("(this device)") }.substringBefore(' ')
                fun active(email: String) = w.run(w.op, "operator", "accounts").ok().lines().any { it.contains(" $email ") && it.contains("active") }

                // 1. A blocker: the plan first, then why, and nothing is asked or sent.
                val blocked = w.run(me, "account", "delete", "--confirm-email", "me@example.org")
                assertEquals(1, blocked.code, blocked.err)
                assertTrue(blocked.out.contains("Deleting me@example.org") && blocked.out.contains("“Hers”") && blocked.out.contains("can't be undone"), blocked.out)
                assertTrue(blocked.err.contains("cannot be deleted yet") && blocked.err.contains("“Mine”") && blocked.err.contains("1 other member") &&
                    blocked.err.contains("Nothing was deleted"), blocked.err)
                assertTrue(active("me@example.org"))

                // 2. Unblocked: without a terminal the typed address must be given; a wrong one is refused. Nothing is sent.
                w.run(me, "vault", "remove", mine, aliceId).ok()
                val noTty = w.run(me, "account", "delete")
                assertEquals(2, noTty.code, noTty.err)
                assertTrue(noTty.out.contains("only it holds: “Mine”") && noTty.out.contains("leaves these shared vaults") && noTty.out.contains("“Hers”"), noTty.out)
                assertTrue(noTty.err.contains("--confirm-email") && noTty.err.contains("Nothing was sent"), noTty.err)
                val wrong = w.run(me, "account", "delete", "--confirm-email", "alice@example.org")
                assertEquals(1, wrong.code)
                assertTrue(wrong.err.contains("not this account's") && wrong.err.contains("nothing was sent"), wrong.err)
                assertTrue(active("me@example.org"))

                // 3. The answer is lost before the server saw the request: "cannot tell yet", with the command that checks,
                // and the check says it still exists.
                p.lose = true
                val lost = w.run(me, "account", "delete", "--confirm-email", "me@example.org", dial = p.address)
                assertEquals(1, lost.code, lost.err)
                assertTrue(lost.err.contains("[${Commands.KEY_DELETION_UNKNOWN}]") && lost.err.contains("cannot tell yet") &&
                    lost.err.contains("andvari-cli account delete --check"), lost.err)
                assertFalse(lost.out.contains("deleted:"), lost.out)
                assertTrue(w.run(me, "account", "delete", "--check").ok().contains("not deleted"))

                // 4. Deleted: the leave reaches Hers, and nothing of the account is left in this device's home.
                p.lose = false
                val done = w.run(me, "account", "delete", "--confirm-email", "ME@example.org")
                assertEquals(0, done.code, done.out + done.err)
                assertTrue(done.out.contains("deleted: me@example.org") && done.out.contains("This device forgot the account"), done.out)
                assertFalse(active("me@example.org"))
                assertTrue(w.run(alice, "vault", "list").ok().lines().first { it.startsWith(hers) }.contains("1 members"), "the leave verifies for the owner")
                for (f in me.walkTopDown().filter { it.isFile }) {
                    val text = f.readText()
                    for (trace in listOf(meId, "me@example.org", myDevice)) assertFalse(text.contains(trace), "${f.name} still holds $trace")
                }
                assertTrue(w.run(me, "whoami").ok().contains("account: (none)"))
                assertEquals(1, w.run(me, "sign-in", "--email", "me@example.org").code, "the account is gone")

                // 5. The answer is lost after the server deleted the account: "cannot tell yet", and the check cannot tell
                // either (a session the server no longer accepts reads like a revocation); nothing is wiped meanwhile.
                val zed = w.account("zed@example.org")
                p.lose = true; p.forward = true
                val after = w.run(zed, "account", "delete", "--confirm-email", "zed@example.org", dial = p.address)
                assertEquals(1, after.code, after.err)
                assertTrue(after.err.contains("cannot tell yet"), after.err)
                assertFalse(active("zed@example.org"))
                val check = w.run(zed, "account", "delete", "--check")
                assertEquals(1, check.code, check.out + check.err)
                assertTrue(check.err.contains("[${Commands.KEY_DELETION_UNKNOWN}]") && check.err.contains("cannot tell") && !check.out.contains("not deleted"), check.err)
            }
        }
    }
}
