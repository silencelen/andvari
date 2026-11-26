package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Spec 03 §8, against the real server: the server keeps two back-offs. The sign-in back-off is armed only by sign-ins
 * and refuses only sign-ins; a password proof made on a live session has a back-off of its own, per account, armed only
 * by wrong proofs on that account's own sessions. While one is in force the server answers `429 rate_limited` with
 * `Retry-After`, the right password included. The tool says exactly that under its own exit code ([EXIT_TOO_MANY_PASSWORDS]);
 * never "wrong password", and it does not try again by itself (one request each). For a proof the wait is the one the
 * server named, the device's real remaining wait; for a sign-in, whose answer is a fixed minute whatever the lock, it is
 * "at least a minute" ([SIGN_IN_TOO_MANY_TRIES]).
 */
class TooManyPasswordsTest {
    private val right: (String) -> String? = { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null }
    private val newPassword: (String) -> String? = {
        when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null }
    }

    /** A proof refused by its session's back-off: the wait the tool printed is exactly [wait], the one it was given. */
    private fun said(r: CliRun, unchanged: String, wait: String) {
        assertEquals(EXIT_TOO_MANY_PASSWORDS, r.code, r.out + r.err)
        assertTrue(r.err.contains("[$KEY_TOO_MANY_PASSWORDS]") && r.err.contains("too many wrong passwords") &&
            r.err.contains("Wait $wait, then try again;") && r.err.contains("does not try again by itself") && r.err.contains(unchanged), r.err)
        assertEquals(1, Regex("Wait ").findAll(r.err).count(), "one wait, the one given: ${r.err}")
        assertFalse(r.err.contains("wrong master password") || r.err.contains("wrong email"), r.err)
    }

    /** The `Retry-After` the server sent for the newest request to [path] through [p]. */
    private fun sent(p: LyingProxy, path: String): Long =
        p.retryAfters.last { it.first.contains(path) }.second.trim().toLong()

    /** [args] on the operator's device through [p], counting the requests to [path]: exactly one, never tried again. */
    private fun CliWorld.once(p: LyingProxy, path: String, vararg args: String, env: (String) -> String? = right): CliRun {
        val before = p.seen.count { it.contains(path) }
        val r = run(op, *args, env = env, dial = p.address)
        assertEquals(1, p.seen.count { it.contains(path) } - before, "one request, not tried again: ${p.seen.takeLast(8)}")
        return r
    }

    /** Wrong sign-ins for the operator's address, from a device of nobody's, refuse sign-ins and nothing else. */
    @Test fun wrongSignInsRefuseASignInAndNeverTheOperatorsOwnProof() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            w.account("bob@example.org")
            val stranger = w.home("stranger@example.org")
            val wrong: (String) -> String? = { if (it == "ANDVARI_PASSWORD") "not the password at all 42" else null }
            repeat(5) { w.run(stranger, "sign-in", "--email", "op@example.org", "--trust-card", w.card0, env = wrong) }
            // The sign-in's wait is a fixed minute whatever the lock, so the tool says "at least a minute" (decided on
            // 2026-11-17), never the number: neither the server's own 60 nor any other it might be given.
            for (given in listOf(null, "900")) {
                p.retryAfterAs = given?.let { g -> { _: String -> g } }
                val r = w.run(stranger, "sign-in", "--email", "op@example.org", "--trust-card", w.card0, env = wrong, dial = p.address)
                assertEquals(60L, sent(p, "/auth/login"), "the server's fixed minute")
                assertEquals(EXIT_TOO_MANY_PASSWORDS, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_TOO_MANY_PASSWORDS]: $SIGN_IN_TOO_MANY_TRIES"), r.err)
                assertFalse(r.err.contains("second") || r.err.contains("wrong master password") || r.err.contains("wrong email"), r.err)
                // The server refuses alike for too many tries from one network address: the line names no address.
                assertFalse(r.err.contains("email address"), r.err)
            }
            p.retryAfterAs = null

            // The operator's own command, with the right password, is served: the sign-in back-off refuses only sign-ins.
            val served = w.once(p, "/enable", "operator", "enable", "bob@example.org")
            assertEquals(0, served.code, served.out + served.err)
        } }
    }

    /**
     * Five wrong proofs on the operator's own session reach the server (the test's proxy changes the right proof on its
     * way, since the tool sends none for a wrong password): each command that proves the password is then refused as
     * too many, with the wait, one request each. A sign-in is still served: the proofs' back-off refuses only proofs.
     */
    @Test fun wrongProofsOnTheOwnSessionRefuseEachProofButNeverASignIn() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            w.account("bob@example.org")
            // Spread over three routes, so that no route's own per-minute bucket (5) is what refuses the commands after.
            p.wrongProofs = 5
            val wrongs = listOf(
                w.once(p, "/enable", "operator", "enable", "bob@example.org"),
                w.once(p, "PUT /api/v1/instance/card", "card", "sign", "--name", "A new name"),
                w.once(p, "/enable", "operator", "enable", "bob@example.org"),
                w.once(p, "PUT /api/v1/instance/card", "card", "sign", "--name", "A new name"),
                w.once(p, "PUT /api/v1/account/password", "account", "password", env = newPassword),
            )
            assertEquals(5, p.proofsChanged.get(), "five wrong proofs reached the server")
            for (r in wrongs) {
                assertNotEquals(0, r.code, r.out + r.err)
                assertNotEquals(EXIT_TOO_MANY_PASSWORDS, r.code, "a wrong proof is refused as one, not as too many: ${r.err}")
            }

            // The server names its device's real remaining wait; the tool prints exactly the wait it was given.
            val enable = w.once(p, "/enable", "operator", "enable", "bob@example.org")
            said(enable, "Nothing changed", seconds(sent(p, "/enable")))
            p.retryAfterAs = { "517" }
            said(w.once(p, "PUT /api/v1/instance/card", "card", "sign", "--name", "A new name"), "Nothing was stored", "517 seconds")
            p.retryAfterAs = { "1" }
            said(w.once(p, "PUT /api/v1/account/password", "account", "password", env = newPassword), "Nothing changed", "1 second")
            // A wait longer than a day reaches the tool as none: the words never say that the server named no time.
            p.retryAfterAs = { "90000" }
            said(w.once(p, "PUT /api/v1/instance/card", "card", "sign", "--name", "A new name"), "Nothing was stored", WAIT_UNNAMED)
            p.retryAfterAs = null
            said(w.once(p, "/enable", "operator", "enable", "bob@example.org"), "Nothing changed", seconds(sent(p, "/enable")))
            assertTrue(p.retryAfters.none { it.second.trim() == "60" }, "the real wait, not the old fixed minute: ${p.retryAfters}")
            assertEquals(5, p.proofsChanged.get(), "the right proofs went as they were")

            // A sign-in of the same account is served meanwhile.
            val signIn = w.run(w.home("op2@example.org"), "sign-in", "--email", "op@example.org", "--trust-card", w.card0, dial = p.address)
            assertEquals(0, signIn.code, signIn.out + signIn.err)
        } }
    }
}
