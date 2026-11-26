package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The tool signs the server's card by the desktop's rules, through the shared code's own path. One
 * change per card; an unsigned change from one recovery key to another is refused; removing the key is said first and
 * needs a typed confirmation; a rotation statement is verified before the master password is asked, and a typed
 * fingerprint must be the one it leads to. Before, `card sign` signed any mix of fields, a key-to-key change with no
 * rotation and `none` unasked, and `card rotation` uploaded the last line of any file with the password proof.
 */
class CardSigningRulesTest {
    private val crypto = createCryptoProvider()
    private val noPassword: (String) -> String? = { null }

    @Test fun theCardIsSignedByTheDesktopsRules() {
        val seed1 = crypto.randomBytes(32)
        val pub1 = crypto.boxKeypairFromSeed(seed1).publicKey
        val pub2 = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        val fp1 = Escrow.fingerprint(crypto, pub1)
        val fp2 = Escrow.fingerprint(crypto, pub2)
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub1))).use { s ->
            val w = CliWorld(s)
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            fun card() = w.run(w.op, "card", "show").ok()
            fun asksNothing(what: String, r: CliRun) {
                assertFalse(r.err.contains("no password given") || r.err.contains("Master password"), "$what: the password was asked: ${r.err}")
            }

            // One change per card.
            val two = w.run(w.op, "card", "sign", "--name", "Renamed", "--move-to", "https://moved.example.org")
            assertEquals(2, two.code, two.err)
            assertTrue(two.err.contains("one change per card"), two.err)

            // A change from one key to another without its signed rotation is refused, and the card stays.
            val unsigned = w.run(w.op, "card", "sign", "--recovery-fp", fp2)
            assertEquals(2, unsigned.code, unsigned.out + unsigned.err)
            assertTrue(unsigned.err.contains("needs its signed rotation") && unsigned.err.contains("unsigned change is refused"), unsigned.err)
            assertTrue(card().contains("recoveryFp:  $fp1") && card().contains("card:        seq 0"), card())

            // Rotation statements are checked before the password is asked: one made for another instance, one that is not
            // a statement at all, and a good one with a typed fingerprint it does not lead to.
            val other = File(w.tmp, "other-instance.txt").apply {
                writeText(s.recoveryCli(listOf("rotate", "--instance", "00000000-0000-4000-8000-000000000000", "--to", Bytes.toB64(pub2)), Bytes.toB64(seed1) + "\n"))
            }
            val forged = File(w.tmp, "forged.txt").apply { writeText("Rotation for instance $instanceId\n\n${Bytes.toB64(crypto.randomBytes(200))}\n") }
            val good = File(w.tmp, "rotation.txt").apply {
                writeText(s.recoveryCli(listOf("rotate", "--instance", instanceId, "--to", Bytes.toB64(pub2)), Bytes.toB64(seed1) + "\n"))
            }
            for ((what, args) in listOf(
                "another instance's statement" to listOf("--file", other.path),
                "a line that is no statement" to listOf("--file", forged.path),
                "a typed fingerprint the statement does not lead to" to listOf("--file", good.path, "--recovery-fp", fp1.reversed()),
            )) {
                val r = w.run(w.op, "card", "rotation", *args.toTypedArray(), env = noPassword)
                assertEquals(1, r.code, "$what: ${r.out}${r.err}")
                assertTrue(r.err.contains("Nothing was asked or sent"), "$what: ${r.err}")
                asksNothing(what, r)
            }
            assertTrue(card().contains("card:        seq 0"), card())

            // Removing the key: said first, and refused without the typed confirmation.
            val unconfirmed = w.run(w.op, "card", "sign", "--recovery-fp", "none", env = noPassword)
            assertEquals(2, unconfirmed.code, unconfirmed.err)
            assertTrue(unconfirmed.err.contains("can never be covered by a signed rotation later") && unconfirmed.err.contains("--confirm"), unconfirmed.err)
            asksNothing("an unconfirmed removal", unconfirmed)
            val wrongWords = w.run(w.op, "card", "sign", "--recovery-fp", "none", "--confirm", "yes", env = noPassword)
            assertEquals(1, wrongWords.code, wrongWords.err)
            asksNothing("a removal confirmed with other words", wrongWords)
            assertTrue(card().contains("recoveryFp:  $fp1"), card())
            assertTrue(w.run(w.op, "card", "sign", "--recovery-fp", "none", "--confirm", CardChanges.REMOVE_PHRASE).ok().contains("card 1 stored"))
            assertTrue(card().contains("recoveryFp:  none"), card())

            // From none, a key is named again (said as a change no rotation covers); then the signed rotation moves it.
            val named = w.run(w.op, "card", "sign", "--recovery-fp", fp1).ok()
            assertTrue(named.contains("card 2 stored") && named.contains("no signed rotation"), named)
            assertTrue(w.run(w.op, "card", "rotation", "--file", good.path).ok().contains("card 3 stored"))
            assertTrue(card().contains("recoveryFp:  $fp2"), card())
        }
    }
}
