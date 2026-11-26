package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * spec 04 §4, "Which key each copy is sealed to": a copy the fleet check did not open is never counted as recoverable.
 * The verdict names how many were not checked and why, never says "all" when any was not, and the exit status tells
 * the three outcomes apart; the operator can give the outgoing sheets too (asked for after the seed file, never on the
 * command line), and then those copies are opened and checked. Every seed here is a made-up test seed.
 */
class FleetNotCheckedTest {
    private val crypto = createCryptoProvider()
    private val current = crypto.randomBytes(32)
    private val outgoing = crypto.randomBytes(32)
    private val currentPub = crypto.boxKeypairFromSeed(current).publicKey
    private val outgoingPub = crypto.boxKeypairFromSeed(outgoing).publicKey
    private val currentFp = Escrow.fingerprint(crypto, currentPub)
    private val outgoingFp = Escrow.fingerprint(crypto, outgoingPub)
    private val instanceId = "12345678-1234-4234-8234-123456789abc"
    private val served = ServedInstance(crypto, instanceId).card(outgoing, 1_790_000_000_000L).rotate(outgoing, current, 1_793_000_000_000L).card(current, 1_793_000_060_000L)

    private fun row(m: Member, fp: String?) = EscrowDumpRow(m.userId, m.sealed, fp, 1L, m.download.encryptedIdentitySeed, m.download.identityPub)

    private val onCurrent = Member(crypto, currentPub, "ann@family.example")
    private val onOutgoing = Member(crypto, outgoingPub, "bo@family.example")

    /** The review's sequence: after the rotation, the server replaces a copy with one no sheet opens and labels it with the outgoing key. */
    private val damaged = row(Member(crypto, crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey, "cy@family.example"), outgoingFp)

    private class Seen {
        val filesRead = ArrayList<String>()
        val prompts = ArrayList<String>()
        val out = StringBuilder()
        val err = StringBuilder()
        var status = -1
        override fun toString() = "status $status, files $filesRead, prompts $prompts\nout: $out\nerr: $err"
    }

    private fun run(args: List<String>, rows: List<EscrowDumpRow>, seedFile: ByteArray = current, pasted: List<String?> = emptyList()): Seen {
        val seen = Seen()
        val files = mapOf(
            "seed.txt" to (Bytes.toB64(seedFile) + "\n").encodeToByteArray(),
            "dump.json" to Json.encodeToString(ListSerializer(EscrowDumpRow.serializer()), rows).encodeToByteArray(),
            "instance.json" to served.json(),
        )
        val seeds = pasted.iterator()
        val io = AssistIo(
            readFile = { p, _ -> seen.filesRead += p; files[p] ?: throw java.io.FileNotFoundException(p) },
            readSecret = { p -> seen.prompts += p; if (seeds.hasNext()) seeds.next() else null },
            readLine = { null },
            out = { seen.out.append(it) },
            err = { seen.err.appendLine(it) },
            clock = { 1_794_858_966_854L },
        )
        seen.status = runVerify(crypto, args, io)
        return seen
    }

    private val withFile = listOf("seed.txt", "dump.json", "--instance-file", "instance.json", "--card0-hash", served.card0Hash())
    private val withSheets = withFile + "--outgoing-sheets"

    @Test
    fun aDamagedCopyLabelledWithTheOutgoingKey_isNotChecked_andTheVerdictSaysSo_withoutTheOutgoingSheet() {
        val s = run(withFile, listOf(row(onCurrent, currentFp), damaged))
        assertEquals(EscrowVerify.EXIT_NOT_ALL_CHECKED, s.status, s.toString())
        assertFalse("All escrowed accounts" in s.out.toString() + s.err, s.toString())
        assertTrue(
            s.err.trim().endsWith(
                "NOT ALL CHECKED: 1 of the 2 copies in this download were not opened here, so not every account is proven recoverable; " +
                    "the 1 that were opened are recoverable with this sheet.",
            ),
            s.toString(),
        )
        assertTrue(
            "1 NOT CHECKED (SKIP): 1 sealed, by the server's word, to the outgoing key ${KeyHistory.short(outgoingFp)}, whose sheet was not given." in s.out,
            s.toString(),
        )
        assertTrue("(an outgoing sheet: add --outgoing-sheets)" in s.out, s.toString())
        assertTrue(s.prompts.isEmpty(), "no sheet is asked for without --outgoing-sheets: $s")
    }

    @Test
    fun withTheOutgoingSheet_theDamagedCopyIsOpened_andFails() {
        val s = run(withSheets, listOf(row(onCurrent, currentFp), damaged), pasted = listOf(Bytes.toB64(outgoing)))
        assertEquals(EscrowVerify.EXIT_FAILED, s.status, s.toString())
        // Asked after the seed file, by its name and fingerprint; every file was read before.
        assertEquals(listOf("instance.json", "dump.json", "seed.txt"), s.filesRead)
        assertEquals(1, s.prompts.size, s.toString())
        assertTrue("OUTGOING sheet (${KeyHistory.short(outgoingFp)}" in s.prompts.single(), s.prompts.single())
        val damagedLine = s.out.lines().single { it.startsWith(damaged.userId) }
        assertTrue("FAIL" in damagedLine && "refused: unopenable" in damagedLine, damagedLine)
        assertTrue("1 escrow blob(s) FAILED" in s.err, s.toString())
        assertFalse("NOT CHECKED" in s.out.toString() + s.err, s.toString())
    }

    @Test
    fun anHonestCopyOnTheOutgoingKey_isCheckedAndGood_withTheOutgoingSheet() {
        val s = run(withSheets, listOf(row(onCurrent, currentFp), row(onOutgoing, outgoingFp)), pasted = listOf(Bytes.toB64(outgoing)))
        assertEquals(EscrowVerify.EXIT_ALL_GOOD, s.status, s.toString())
        val line = s.out.lines().single { it.startsWith(onOutgoing.userId) }
        assertTrue("PASS" in line && "outgoing " in line && "(server)" !in line && "bo@family.example" in line, line)
        assertTrue("All escrowed accounts in this download (2) are recoverable with these sheets." in s.out, s.toString())
        assertTrue("Accounts still on an outgoing key: 1. Keep the outgoing sheet (${KeyHistory.short(outgoingFp)}) until this line says 0." in s.out, s.toString())

        // The same rows without the outgoing sheet: the honest one too is not checked, never counted.
        val without = run(withFile, listOf(row(onCurrent, currentFp), row(onOutgoing, outgoingFp)))
        assertEquals(EscrowVerify.EXIT_NOT_ALL_CHECKED, without.status, without.toString())
    }

    @Test
    fun anOutgoingSheetTheOperatorNoLongerHolds_failsItsCopies() {
        val s = run(withSheets, listOf(row(onCurrent, currentFp), row(onOutgoing, outgoingFp)), pasted = listOf(""))
        assertEquals(EscrowVerify.EXIT_FAILED, s.status, s.toString())
        val line = s.out.lines().single { it.startsWith(onOutgoing.userId) }
        assertTrue("FAIL" in line && "refused: outgoing_sheet_gone" in line && "NOT recoverable" in line, line)
    }

    @Test
    fun theDestroyLine_saysWhatItRestsOn() {
        // A download that leaves out the account still on the outgoing key: the line says it covers only this download.
        val s = run(withFile, listOf(row(onCurrent, currentFp)))
        assertEquals(EscrowVerify.EXIT_ALL_GOOD, s.status, s.toString())
        assertTrue(
            "Accounts still on an outgoing key: 0. Every copy in this download (1) opened with the current sheet, so none of these accounts needs an " +
                "outgoing sheet any more. That rests on the download: an account the server left out of it is not covered. Before you destroy an " +
                "outgoing sheet, check that 1 is the number of accounts you know have operator recovery on." in s.out,
            s.toString(),
        )
        assertTrue("All escrowed accounts in this download (1) are recoverable with this sheet." in s.out, s.toString())
    }

    @Test
    fun everyRefusal_comesBeforeAnySheetIsReadOrAskedFor() {
        fun refused(name: String, s: Seen, seedFileRead: Boolean = false) {
            assertEquals(1, s.status, s.toString())
            assertTrue("REFUSED ($name)" in s.err, s.toString())
            assertEquals(seedFileRead, "seed.txt" in s.filesRead, s.toString())
            assertTrue(s.prompts.isEmpty() || name == "wrong_sheet" || name == "bad_seed", s.toString())
            assertFalse("PASS" in s.out, s.toString())
        }
        val rows = listOf(row(onCurrent, currentFp), damaged)
        refused("instance_file_missing", run(listOf("seed.txt", "dump.json", "--outgoing-sheets"), rows))
        refused("repeated_option", run(withSheets + "--outgoing-sheets", rows))
        refused("bad_dump", run(listOf("seed.txt", "missing.json") + withSheets.drop(2), rows))
        refused("bad_instance_file", run(withSheets.map { if (it == "instance.json") "missing.json" else it }, rows))
        // The seed file must be the CURRENT sheet when the outgoing ones are asked for after it: refused before any prompt.
        val swapped = run(withSheets, rows, seedFile = outgoing, pasted = listOf(Bytes.toB64(current)))
        refused("wrong_sheet", swapped, seedFileRead = true)
        assertTrue(swapped.prompts.isEmpty(), swapped.toString())
        // A pasted seed that is not the outgoing sheet named: nothing is checked.
        val wrong = run(withSheets, rows, pasted = listOf(Bytes.toB64(crypto.randomBytes(32))))
        refused("wrong_sheet", wrong, seedFileRead = true)
        refused("bad_seed", run(withSheets, rows, pasted = listOf(null)), seedFileRead = true)
    }
}
