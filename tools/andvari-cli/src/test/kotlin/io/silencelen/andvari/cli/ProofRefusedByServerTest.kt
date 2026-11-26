package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec 01 §7: a proof of the master password that this device made and sent, and that the server refused, reaches the
 * tool as the engine's own result (`reauth_failed`), never as a wrong password. Every command of the tool that proves the
 * password says it as the server's refusal of a proof that was sent, with its own exit code ([EXIT_PROOF_REFUSED]): the
 * password change, a new kit, "new devices must be linked", the recovery setting, the account's deletion, the operator's
 * proofs and a card change. (A password that does not open the account here stays a wrong password with nothing sent:
 * [LocalProofTest].)
 *
 * Against the real server through a proxy that changes the right proof on its way ([LyingProxy.wrongProofs]): the server
 * then refuses a proof the right password made here. Each account is given at most three such proofs, below the server's
 * back-off for wrong proofs.
 */
class ProofRefusedByServerTest {
    private val newPassword: (String) -> String? = {
        when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null }
    }

    /** [args] for [home] through [p] with one proof changed on its way: it was sent, and the refusal is said as the server's. */
    private fun CliWorld.refused(p: LyingProxy, home: File, vararg args: String, env: (String) -> String? = { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null }) {
        val before = p.proofsChanged.get()
        p.wrongProofs = 1
        val r = run(home, *args, env = env, dial = p.address)
        p.wrongProofs = 0
        val what = args.joinToString(" ")
        assertEquals(before + 1, p.proofsChanged.get(), "the proof was made here and sent: $what")
        assertEquals(EXIT_PROOF_REFUSED, r.code, "$what: ${r.out}${r.err}")
        assertTrue(r.err.contains("[$KEY_PROOF_REFUSED]") && r.err.contains("refused the proof of your master password") &&
            r.err.contains("The proof was sent"), "$what: ${r.err}")
        assertFalse(r.err.contains("wrong", ignoreCase = true) || r.err.contains("nothing was sent"), "$what: ${r.err}")
    }

    @Test fun everyCommandThatProvesThePasswordSaysTheServersRefusalAsSuch() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                w.account("bob@example.org")
                val a = w.account("anna@example.org")
                w.refused(p, a, "account", "password", env = newPassword)
                w.refused(p, a, "account", "require-link", "on")
                w.refused(p, a, "recovery", "private")

                val c = w.account("carl@example.org")
                w.refused(p, c, "account", "delete", "--confirm-email", "carl@example.org")
                w.refused(p, c, "account", "kit", "--kit-out", File(w.tmp, "carl-new-kit.txt").path)

                w.refused(p, w.op, "operator", "enable", "bob@example.org")
                w.refused(p, w.op, "card", "sign", "--name", "A new name")

                // Nothing was changed by any of them: the same password and the same account go on.
                w.run(c, "item", "list", "personal").ok()
                w.run(a, "item", "list", "personal").ok()
            }
        }
    }
}
