package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * spec 04 §4, "Which key each copy is sealed to": the fleet check says, per account, which key its copy is sealed to
 * and whether that is the current key, an outgoing one the rotations prove, or one nothing proves, and one line says
 * how many accounts are still on an outgoing key. Every seed here is a made-up test seed.
 */
class VerifyKeysTest {
    private val crypto = createCryptoProvider()
    private val current = crypto.randomBytes(32)
    private val outgoing = crypto.randomBytes(32)
    private val currentPub = crypto.boxKeypairFromSeed(current).publicKey
    private val outgoingPub = crypto.boxKeypairFromSeed(outgoing).publicKey
    private val currentFp = Escrow.fingerprint(crypto, currentPub)
    private val outgoingFp = Escrow.fingerprint(crypto, outgoingPub)
    private val instanceId = "12345678-1234-4234-8234-123456789abc"

    private val served = ServedInstance(crypto, instanceId).card(outgoing, 1_790_000_000_000L).rotate(outgoing, current, 1_793_000_000_000L).card(current, 1_793_000_060_000L)
    private val history = KeyHistory.read(crypto, served.json(), null, served.card0Hash())

    private fun row(m: Member, fp: String?) = EscrowDumpRow(m.userId, m.sealed, fp, 1L, m.download.encryptedIdentitySeed, m.download.identityPub)

    private val onCurrent = Member(crypto, currentPub, "ann@family.example")
    private val onOutgoing = Member(crypto, outgoingPub, "bo@family.example")
    private val elsewhere = Member(crypto, crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey, "cy@family.example")
    private val rows = listOf(row(onCurrent, currentFp), row(onOutgoing, outgoingFp), row(elsewhere, "ab".repeat(32)))

    @Test
    fun withTheCurrentSheet_eachAccountsKey_isCurrentOutgoingOrUnproven_andTheLineCountsTheOutgoing() {
        val (a, b, c) = EscrowVerify.verify(crypto, current, rows, history)
        // Opened here: the key is proven (the copy's own statement names it), and the address is the copy's.
        assertTrue(a.pass && a.keyProven, a.toString())
        assertEquals(currentFp, a.keyFp)
        assertEquals(KeyStanding.CURRENT, a.keyStanding)
        assertEquals("ann@family.example", a.address)
        // Sealed to the outgoing key the rotations prove: not opened with this sheet, the server's word, neither PASS nor FAIL.
        assertTrue(b.skipped && !b.pass && !b.keyProven, b.toString())
        assertEquals(KeyStanding.OUTGOING, b.keyStanding)
        assertEquals(outgoingFp, b.keyFp)
        assertNull(b.address)
        // A key nothing proves is the fingerprint mismatch it always was.
        assertTrue(!c.pass && !c.skipped && c.detail.startsWith("refused: recovery_fp_mismatch"), c.toString())
        assertEquals(KeyStanding.UNPROVEN, c.keyStanding)

        val out = EscrowVerify.reportLines(listOf(a, b, c), history)
        assertTrue(out.any { it.startsWith(a.userId) && "PASS" in it && "${Fingerprint.shortForm(currentFp)} current " in it && "ann@family.example" in it }, out.joinToString("\n"))
        assertTrue(out.any { it.startsWith(b.userId) && "SKIP" in it && "${Fingerprint.shortForm(outgoingFp)} outgoing (server)" in it }, out.joinToString("\n"))
        assertTrue(out.any { it.startsWith(c.userId) && "FAIL" in it && "unproven (server)" in it }, out.joinToString("\n"))
        assertTrue("Accounts still on an outgoing key: 1. Keep the outgoing sheet (${KeyHistory.short(outgoingFp)}) until this line says 0." in out, out.joinToString("\n"))
    }

    @Test
    fun withTheOutgoingSheet_itsAccountsAreOpened_andStillCounted() {
        val (a, b) = EscrowVerify.verify(crypto, outgoing, rows.take(2), history)
        assertTrue(a.skipped && a.keyStanding == KeyStanding.CURRENT, a.toString())
        assertTrue(b.pass && b.keyProven && b.keyStanding == KeyStanding.OUTGOING && b.address == "bo@family.example", b.toString())
        assertTrue(EscrowVerify.outgoingLine(listOf(a, b), history).startsWith("Accounts still on an outgoing key: 1."))
    }

    @Test
    fun theOutgoingSheetMayGo_onlyWhenEveryCopyOpenedWithTheCurrentOne() {
        val all = EscrowVerify.verify(crypto, current, rows.take(1), history)
        assertTrue(
            EscrowVerify.outgoingLine(all, history).startsWith(
                "Accounts still on an outgoing key: 0. Every copy in this download (1) opened with the current sheet, so none of these accounts needs an outgoing sheet any more.",
            ),
        )
        // A failing row, even on no outgoing key, keeps the sheet: nothing proves where that copy is.
        val withFail = EscrowVerify.verify(crypto, current, listOf(rows[0], rows[2]), history)
        assertTrue("do not destroy an outgoing sheet yet" in EscrowVerify.outgoingLine(withFail, history))
    }

    @Test
    fun withoutTheFile_nothingIsProvenOutgoing_andTheOldRowsFailAsBefore() {
        val (a, b) = EscrowVerify.verify(crypto, current, rows.take(2))
        assertTrue(a.pass && a.keyStanding == KeyStanding.CURRENT, a.toString())
        assertFalse(b.pass || b.skipped, b.toString())
        assertTrue(b.detail.startsWith("refused: recovery_fp_mismatch"), b.detail)
        assertEquals(KeyStanding.UNPROVEN, b.keyStanding)
        assertTrue(EscrowVerify.outgoingLine(listOf(a, b), null).startsWith("Accounts still on an outgoing key: not known"))
    }
}
