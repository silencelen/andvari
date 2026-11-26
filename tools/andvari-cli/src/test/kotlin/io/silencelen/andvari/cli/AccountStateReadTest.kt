package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A command-line session reads the account's state once before its first
 * sync (and before a command that shows what the state holds), so that what another device of the account decided is
 * known here as it is to the apps. Alice's second device, signed in with her password before her first device compared
 * codes with Bob, learns of that comparison in its next session.
 */
class AccountStateReadTest {
    @Test fun aSecondDevicesDecisionIsKnownToTheNextSession() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val laptop = w.account("alice@example.org")
            val bob = w.account("bob@example.org")
            val desk = w.home("alice-desk@example.org")
            w.run(desk, "sign-in", "--email", "alice@example.org", "--trust-card", w.card0).ok()
            val (_, bobId) = w.connect(laptop, bob)

            // The next session on the second device: the state is read once, before the first sync's pull.
            p.seen.clear()
            w.run(desk, "sync", dial = p.address).ok()
            val seen = p.seen.map { it.substringBefore('?') }
            val state = seen.indexOf("GET /api/v1/account/state")
            assertTrue(state >= 0 && state < seen.indexOf("GET /api/v1/sync"), "the state read comes before the pull: $seen")
            assertEquals(1, seen.count { it == "GET /api/v1/account/state" }, "read once: $seen")

            // And the comparison made on the first device is known on the second.
            val contacts = w.run(desk, "contacts").ok()
            assertTrue(contacts.lines().any { it.startsWith(bobId) && it.contains(" compared") }, contacts)
        } }
    }
}
