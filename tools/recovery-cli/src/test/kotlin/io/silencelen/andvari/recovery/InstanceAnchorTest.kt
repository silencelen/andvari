package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * spec 04 §5: the saved `--instance-file` is the server's word, and a server can make up a whole card chain under its real
 * instance ID, with a card key and recovery keys of its own and rotations they sign. So the tool checks the file's first
 * card against the hash the operator holds (`--card0-hash`) before any sheet is asked for, refuses without it, and goes on
 * without it only on `--instance-file-unchecked`, saying on every line about the file that it is not checked against
 * anything the operator holds. The same for `assist` and the fleet check. Every seed here is a made-up test seed.
 */
class InstanceAnchorTest {
    private val r = AssistRun()
    private val crypto = r.crypto
    private val current = r.seed
    private val genuineOld = crypto.randomBytes(32)

    /** The server the operator knows: card 0 names the old key, a rotation signed by it, card 1 names the current key. */
    private val genuine = ServedInstance(crypto, r.instanceId).card(genuineOld, 1_790_000_000_000L).rotate(genuineOld, current, 1_793_000_000_000L).card(current, 1_793_000_060_000L)

    /** A chain the server made up under the real instance ID: its own card key, a recovery key of its own made "outgoing". */
    private val made = crypto.randomBytes(32)
    private val madeUp = ServedInstance(crypto, r.instanceId).card(made, 1_790_000_000_000L).rotate(made, current, 1_793_000_000_000L).card(current, 1_793_000_060_000L)
    private val madeFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(made).publicKey)

    private fun assist(file: ByteArray, vararg anchor: String): AssistRun.Seen {
        r.files["instance.json"] = file
        r.seedLines = listOf(Bytes.toB64(current))
        return r.run(r.args() + listOf("--instance-file", "instance.json") + anchor)
    }

    private fun refusedBeforeAnySeed(s: AssistRun.Seen, name: String, filesRead: Int) {
        assertEquals(1, s.status, s.toString())
        // A refusal of the command line ends with the usage: its first line names it.
        assertTrue(s.err.lines().first { it.isNotEmpty() }.startsWith("REFUSED ($name)"), s.toString())
        assertEquals(1, s.err.lines().count { it.startsWith("REFUSED") }, s.toString())
        assertEquals(0, s.secretsAsked, s.toString())
        assertEquals(0, s.linesAsked, s.toString())
        assertEquals(filesRead, s.filesRead.size, s.toString())
        assertFalse("ANSWER" in s.out, s.toString())
    }

    @Test
    fun aMadeUpChain_withTheHashMissing_isRefused_withWhereToReadTheHash() {
        val s = assist(madeUp.json())
        refusedBeforeAnySeed(s, "card0_hash_required", filesRead = 0)
        val sentence = s.err.toString()
        for (where in listOf("--card0-hash", "andvari-cli card show", "card0Hash", "Instance details", "card 0's hash", "recovery kit", "--instance-file-unchecked")) {
            assertTrue(where in sentence, "the refusal says where to read the hash ($where): $sentence")
        }
    }

    @Test
    fun aMadeUpChain_withTheRightHash_isRefused_andAWrongHashToo() {
        refusedBeforeAnySeed(assist(madeUp.json(), "--card0-hash", genuine.card0Hash()), "card0_mismatch", filesRead = 2)
        refusedBeforeAnySeed(assist(genuine.json(), "--card0-hash", "ab".repeat(32)), "card0_mismatch", filesRead = 2)
        // The hash is never taken from the file: the refusal does not print the file's own.
        val s = assist(madeUp.json(), "--card0-hash", genuine.card0Hash())
        assertFalse(madeUp.card0Hash() in s.err, s.toString())
    }

    @Test
    fun aGenuineFile_withTheRightHash_isChecked_andSaysNothingOfAnUncheckedFile() {
        // Printed in groups, as a hash may be: spaces are removed.
        val s = assist(genuine.json(), "--card0-hash", genuine.card0Hash().chunked(4).joinToString(" "))
        assertEquals(0, s.status, s.toString())
        assertTrue("checked here from its first card, whose hash you gave" in s.err, s.toString())
        assertFalse("NOT checked" in s.err.toString() + s.prompts, s.toString())
    }

    @Test
    fun aMadeUpChain_withTheUncheckedOption_goesOn_andEveryLineAboutTheFileSaysItIsNotChecked() {
        val s = assist(madeUp.json(), "--instance-file-unchecked")
        assertEquals(0, s.status, s.toString())
        // The made-up outgoing key is shown, as the file says, and never without the words.
        assertTrue(KeyHistory.short(madeFp) in s.err, s.toString())
        val aboutTheFile = (s.err.lines() + s.prompts).filter { l -> listOf("CURRENT", "OUTGOING", "--instance-file", "outgoing").any { it in l } }
        assertTrue(aboutTheFile.size >= 4, s.toString())
        for (line in aboutTheFile) assertTrue("NOT checked against anything you hold" in line, "every line about the file says it: $line")
    }

    @Test
    fun theTwoOptions_areDecidedWithTheCommandLine() {
        refusedBeforeAnySeed(assist(genuine.json(), "--card0-hash", genuine.card0Hash(), "--instance-file-unchecked"), "bad_card0_hash", filesRead = 0)
        refusedBeforeAnySeed(assist(genuine.json(), "--card0-hash", genuine.card0Hash().uppercase()), "bad_card0_hash", filesRead = 0)
        refusedBeforeAnySeed(assist(genuine.json(), "--card0-hash", genuine.card0Hash().drop(1)), "bad_card0_hash", filesRead = 0)
        refusedBeforeAnySeed(assist(genuine.json(), "--card0-hash"), "bad_card0_hash", filesRead = 0)
        refusedBeforeAnySeed(assist(genuine.json(), "--card0-hash", genuine.card0Hash(), "--card0-hash", genuine.card0Hash()), "repeated_option", filesRead = 0)
        r.seedLines = listOf(Bytes.toB64(current))
        refusedBeforeAnySeed(r.run(r.args() + listOf("--card0-hash", genuine.card0Hash())), "instance_file_missing", filesRead = 0)
        refusedBeforeAnySeed(r.run(r.args() + listOf("--instance-file-unchecked")), "instance_file_missing", filesRead = 0)
    }

    // ---- the fleet check, given the file ----

    private fun fleet(file: ByteArray, vararg anchor: String): Pair<Int, String> {
        val damaged = Member(crypto, crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey, "cy@family.example")
        val rows = listOf(
            EscrowDumpRow(r.member.userId, r.member.sealed, Escrow.fingerprint(crypto, r.org.publicKey), 1L, r.member.download.encryptedIdentitySeed, r.member.download.identityPub),
            // Labelled with the key the server made up and made "outgoing".
            EscrowDumpRow(damaged.userId, damaged.sealed, madeFp, 1L, damaged.download.encryptedIdentitySeed, damaged.download.identityPub),
        )
        val files = mapOf(
            "seed.txt" to (Bytes.toB64(current) + "\n").encodeToByteArray(),
            "dump.json" to Json.encodeToString(ListSerializer(EscrowDumpRow.serializer()), rows).encodeToByteArray(),
            "instance.json" to file,
        )
        val all = StringBuilder()
        val io = AssistIo(
            readFile = { p, _ -> files[p] ?: throw java.io.FileNotFoundException(p) },
            readSecret = { all.appendLine("ask: $it"); null },
            readLine = { null },
            out = { all.append(it) },
            err = { all.appendLine(it) },
            clock = { r.clock },
        )
        return runVerify(crypto, listOf("seed.txt", "dump.json", "--instance-file", "instance.json") + anchor, io) to all.toString()
    }

    @Test
    fun theFleetCheck_takesTheSameAnchor() {
        val (missing, missingOut) = fleet(madeUp.json())
        assertEquals(1, missing, missingOut)
        assertTrue("REFUSED (card0_hash_required)" in missingOut && "PASS" !in missingOut, missingOut)

        val (wrong, wrongOut) = fleet(madeUp.json(), "--card0-hash", genuine.card0Hash())
        assertEquals(1, wrong, wrongOut)
        assertTrue("REFUSED (card0_mismatch)" in wrongOut && "PASS" !in wrongOut, wrongOut)

        val (unchecked, uncheckedOut) = fleet(madeUp.json(), "--instance-file-unchecked")
        assertEquals(EscrowVerify.EXIT_NOT_ALL_CHECKED, unchecked, uncheckedOut)
        val aboutTheFile = uncheckedOut.lines().filter { l -> listOf("CURRENT", "OUTGOING", "outgoing", "current", "--instance-file", "SKIP").any { it in l } }
        assertTrue(aboutTheFile.size >= 5, uncheckedOut)
        for (line in aboutTheFile) assertTrue("NOT checked against anything you hold" in line, "every line about the file says it: $line")

        val (good, goodOut) = fleet(genuine.json(), "--card0-hash", genuine.card0Hash())
        // With the genuine chain, the server's label names a key of no history: a FAIL, as a key nothing proves.
        assertEquals(EscrowVerify.EXIT_FAILED, good, goodOut)
        assertTrue("recovery_fp_mismatch" in goodOut && "NOT checked" !in goodOut, goodOut)
    }
}
