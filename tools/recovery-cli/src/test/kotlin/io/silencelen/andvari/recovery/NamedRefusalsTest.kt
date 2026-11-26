package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * spec 04 §4, "Every refusal has a name": `rotate`'s and `canary`'s refusals too, and an option given twice, which is
 * refused by a name of its own and never taken as its last value. Every seed here is a made-up test seed.
 */
class NamedRefusalsTest {
    private val r = AssistRun()

    private fun refusedAs(name: String, block: () -> Unit) {
        val e = assertFailsWith<RecoverRefused> { block() }
        assertTrue(e.message!!.startsWith("REFUSED ($name)"), e.message)
    }

    @Test
    fun anOptionGivenTwice_isRefusedByItsName_beforeAnythingIsReadOrAsked() {
        for (option in listOf("--user", "--instance", "--email", "--request-code", "--identity-file", "--identity-fp", "--instance-file")) {
            // r.args() gives every option but --instance-file once.
            val args = r.args() + listOf(option, "x") + (if (option == "--instance-file") listOf(option, "y") else emptyList())
            val seen = r.run(args)
            assertEquals(1, seen.status, "$option: $seen")
            assertTrue(seen.err.startsWith("REFUSED (repeated_option): $option is given more than once"), "$option: $seen")
            assertEquals(0, seen.secretsAsked, seen.toString())
            assertTrue(seen.filesRead.isEmpty(), seen.toString())
        }
        // The same value twice is refused too; and the command line is read before any value is checked.
        assertTrue(r.run(r.args() + listOf("--instance", r.instanceId)).err.startsWith("REFUSED (repeated_option)"))
        assertTrue(r.run(r.args("--instance" to "not-a-uuid") + listOf("--user", r.member.userId)).err.startsWith("REFUSED (repeated_option)"))
        assertTrue(r.run(r.args().filter { it != "--identity-fp" && it != r.member.identityFp.take(32) } + listOf("--no-identity-anchor", "--no-identity-anchor")).err.startsWith("REFUSED (repeated_option)"))
        refusedAs("repeated_option") { RecoverCommand.parse(listOf("--user", r.member.userId, "--user", r.member.userId, "--no-identity-anchor", "--identity-file", "f")) }
        refusedAs("repeated_option") { verifyOptions(listOf("--instance-file", "a", "--instance-file", "b")) }
    }

    @Test
    fun rotate_namesEveryRefusal() {
        val to = Bytes.toB64(r.crypto.boxKeypairFromSeed(r.crypto.randomBytes(32)).publicKey)
        refusedAs("bad_instance") { RotateCommand.parse(listOf("--to", to)) }
        refusedAs("bad_instance") { RotateCommand.parse(listOf("--to", to, "--instance")) }
        refusedAs("bad_instance") { RotateCommand.parse(listOf("--instance", "NOT", "--to", to)) }
        refusedAs("bad_key") { RotateCommand.parse(listOf("--instance", r.instanceId)) }
        refusedAs("bad_key") { RotateCommand.parse(listOf("--instance", r.instanceId, "--to", "$to ")) }
        refusedAs("unknown_option") { RotateCommand.parse(listOf("--instance", r.instanceId, "--to", to, "--frob")) }
        refusedAs("repeated_option") { RotateCommand.parse(listOf("--instance", r.instanceId, "--to", to, "--to", to)) }
        refusedAs("same_key") { RotateCommand.statement(r.crypto, r.seed, RotateCommand.Options(r.instanceId, r.org.publicKey), 1_800_000_000_000L) }
    }

    @Test
    fun canary_namesEveryRefusal() {
        val sealed = Bytes.toB64(Escrow.sealCanary(r.crypto, r.org.publicKey))
        assertTrue(canaryCheck(r.crypto, sealed) { Bytes.toB64(r.seed) }.first().startsWith("CANARY VERIFIED"))
        refusedAs("bad_copy") { canaryCheck(r.crypto, "$sealed ") { Bytes.toB64(r.seed) } }
        refusedAs("bad_seed") { canaryCheck(r.crypto, sealed) { "not a seed" } }
        refusedAs("bad_seed") { canaryCheck(r.crypto, sealed) { null } }
        refusedAs("canary_failed") { canaryCheck(r.crypto, sealed) { Bytes.toB64(r.crypto.randomBytes(32)) } }
        refusedAs("canary_failed") { canaryCheck(r.crypto, Bytes.toB64(r.crypto.randomBytes(120))) { Bytes.toB64(r.seed) } }
    }
}
