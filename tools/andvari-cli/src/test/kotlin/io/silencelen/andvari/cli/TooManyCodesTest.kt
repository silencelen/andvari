package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.account.TwoStepAnswer
import io.silencelen.andvari.core.client.account.TwoStepSetup
import io.silencelen.andvari.core.client.account.WireTwoStep
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec 03 §8: the two-step codes a session sends have their own back-off at the server, per device, apart from the
 * password proofs'. When an account deletion with a code runs into it, the tool says that codes were refused, with the
 * wait the server named: never "too many wrong passwords", since the password was right (the tool proves it on the
 * device before it sends anything).
 */
class TooManyCodesTest {
    private val crypto = createCryptoProvider()

    @Test fun anAccountDeletionThatRunsIntoTheCodesBackOffSaysCodes() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val email = "dana@example.org"
            // Two-step sign-in is turned on from another device (the engine's own Settings flow).
            val config = runBlocking {
                val d = s.device("dana phone")
                Steps.registerThrough(d, s.origin, Steps.enrolLink(s, email), email, trustGate = true)
                val two = WireTwoStep(d.client(s.origin), d.reauth(d.session(s.origin)!!))
                val ready = assertIs<TwoStepSetup.Ready>(two.setup(Steps.PASSWORD.toCharArray()))
                val cfg = Totp.parseUri(ready.secret.otpauthUri)
                assertEquals(TwoStepAnswer.Ok, two.confirm(Totp.code(crypto, cfg, s.now() / 1000)))
                cfg
            }
            s.advance(31_000)
            val dana = w.home(email)
            val right = Totp.code(crypto, config, s.now() / 1000)
            w.run(dana, "sign-in", "--email", email, "--trust-card", w.card0,
                env = { mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD, "ANDVARI_TOTP" to right)[it] }).ok()
            val wrong = if (right == "000000") "111111" else "000000"
            val env: (String) -> String? = { mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD, "ANDVARI_TOTP" to wrong)[it] }
            fun delete() = w.run(dana, "account", "delete", "--confirm-email", email, env = env)
            // Five wrong codes, each a minute after the last (so the route's own few a minute are not what answers).
            repeat(5) {
                s.advance(61_000)
                val r = delete()
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("that two-step code is wrong"), r.err)
            }
            // The fifth locked the codes on this device; the server's clock stands still, so the next is refused unread.
            val locked = delete()
            assertEquals(EXIT_TOO_MANY_PASSWORDS, locked.code, locked.out + locked.err)
            assertTrue(locked.err.contains("[$KEY_TOO_MANY_CODES]: " + TOO_MANY_CODES.substringBefore("{0}")), locked.err)
            assertTrue(locked.err.contains("Nothing was deleted"), locked.err)
            assertFalse(locked.err.contains("too many wrong passwords") || locked.err.contains(KEY_TOO_MANY_PASSWORDS), locked.err)
            assertTrue(w.run(dana, "whoami").ok().contains(email), "not deleted")
        }
    }
}
