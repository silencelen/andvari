package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AdminEscrowDownload
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The escrow-opening order `assist` runs (spec 04 §4): it must name the account and its identity anchor and the address
 * of the person the operator is helping; it goes through Escrow.openForAssist (so a swapped, forged, old-form or other
 * address's copy is refused); an unanchored run needs the typed acknowledgment; and nothing is generated before the
 * operator types `RECOVER <first 8>` having seen whose copy it is.
 */
class RecoverOrderTest {
    private val crypto = createCryptoProvider()
    private val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))

    private fun member(email: String, v3: Boolean = true) = Member(crypto, org.publicKey, email, v3)

    private fun opts(vararg args: String) = RecoverCommand.parse(args.toList())

    private fun run(m: Member, o: RecoverOptions, typed: String, lines: List<String>, download: AdminEscrowDownload = m.download): Pair<Result<io.silencelen.andvari.core.crypto.EscrowOpened>, String> {
        val out = StringBuilder()
        val input = lines.iterator()
        val text = Json.encodeToString(AdminEscrowDownload.serializer(), download)
        val res = runCatching {
            val (check, sealed) = RecoverCommand.readIdentityFile(text, o)
            RecoverCommand.openAndConfirm(crypto, org, o, typed, check, sealed, "the signed answer", { if (input.hasNext()) input.next() else null }) { out.appendLine(it) }
        }
        return res to out.toString()
    }

    private fun anchored(m: Member) = opts("--user", m.userId, "--identity-fp", m.identityFp.take(32), "--identity-file", "f.json")

    @Test
    fun step0_refusesWithoutTheAccountOrTheAnchor() {
        val noUser = assertFailsWith<RecoverRefused> { opts("--identity-fp", "a".repeat(32), "--identity-file", "f.json") }
        assertTrue("must name the account and its identity fingerprint" in noUser.message!!)
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-file", "f.json") }
        // A 16-hex short id is not an anchor (design §7.1); a human entry tolerates spaces and dashes.
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(16), "--identity-file", "f.json") }
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "g".repeat(32), "--identity-file", "f.json") }
        assertEquals("ab12".repeat(8), opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "ab12 ab12-ab12 ab12\tab12 ab12 ab12 ab12", "--identity-file", "f.json").identityFpPrefix)
        // The tool removes separators and keeps case, so an upper-case letter is bad_anchor.
        assertTrue(assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "AB12 ab12-ab12 ab12 ab12 ab12 ab12 ab12", "--identity-file", "f.json") }
            .message!!.startsWith("REFUSED (bad_anchor)"))
        // B2, B3: an absent --user is bad_user_id, an absent anchor bad_anchor, both anchor flags bad_anchor, in step 0's order.
        assertTrue(noUser.message!!.startsWith("REFUSED (bad_user_id)"))
        assertTrue(assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-file", "f.json") }.message!!.startsWith("REFUSED (bad_anchor)"))
        assertTrue(assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(32), "--no-identity-anchor") }.message!!.startsWith("REFUSED (bad_anchor)"))
        assertTrue(assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(32)) }.message!!.startsWith("REFUSED (identity_check_required)"))
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(32)) }
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(32), "--no-identity-anchor", "--identity-file", "f.json") }
        val un = opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--no-identity-anchor", "--identity-file", "f.json")
        assertTrue(un.unanchored)
        assertNull(un.identityFpPrefix)
    }

    @Test
    fun anchoredV3_opensOnlyAfterTheTypedConfirmation_andShowsWhoseCopyItIs() {
        val m = member("ann@family.example")
        val o = anchored(m)
        val (refused, _) = run(m, o, "ann@family.example", listOf("RECOVER wrong"))
        assertTrue(refused.exceptionOrNull() is RecoverRefused, "no confirmation, nothing generated")
        val (ok, out) = run(m, o, "ann@family.example", listOf("RECOVER ${m.userId.take(8)}"))
        val opened = ok.getOrThrow()
        assertEquals(EscrowFormat.V3, opened.format)
        assertEquals("ann@family.example", opened.email)
        assertTrue(opened.anchored)
        assertContentEquals(m.uvk, opened.uvk)
        assertTrue("anchored: yes" in out && "format:   v3" in out, out)
        // The address is shown before the confirmation, in the copy's own signed words.
        assertTrue(out.indexOf("address:  ann@family.example") in 0 until out.indexOf("Type 'RECOVER"), out)
    }

    /**
     * The server put another member's copy under the request. The operator typed the
     * address of the person they are helping; the copy names someone else; the tool refuses and says whose it is.
     */
    @Test
    fun aCopyOfAnotherAddress_isRefusedAndTheToolSaysWhoseItIs() {
        val victim = member("bo@family.example")
        // Anchored to the copy's own identity (an anchor copied from the console would match it too, F2): only the address stops it.
        val (res, _) = run(victim, anchored(victim), "cy@family.example", listOf("RECOVER ${victim.userId.take(8)}"))
        val msg = res.exceptionOrNull()!!.message!!
        assertTrue(msg.startsWith("REFUSED (email_mismatch)"), msg)
        assertTrue("This recovery copy is bo@family.example's, not cy@family.example's" in msg && "another account's copy" in msg, msg)
        // Unanchored, the same.
        val un = opts("--user", victim.userId, "--no-identity-anchor", "--identity-file", "f.json")
        assertTrue("email_mismatch" in run(victim, un, "cy@family.example", listOf(Escrow.UNANCHORED_ACK, "x")).first.exceptionOrNull()!!.message!!)
    }

    /** A copy of the old form does not say whose it is, and assist refuses it with the specification's sentence. */
    @Test
    fun anOldFormCopy_isRefusedWithWhatToDo() {
        val m = member("ann@family.example", v3 = false)
        val msg = run(m, anchored(m), "ann@family.example", listOf("RECOVER ${m.userId.take(8)}")).first.exceptionOrNull()!!.message!!
        assertTrue(msg.startsWith("REFUSED (no_address)") && RecoverCommand.NO_ADDRESS_SENTENCE in msg, msg)
        // The truth for a person who cannot sign in anywhere.
        assertTrue("If the person can still sign in on some device" in msg && "the operator cannot recover this account" in msg, msg)
        assertTrue("Ask them to sign in" !in msg, msg)
    }

    @Test
    fun wrongAccount_isNamedAsASubstitution() {
        val a = member("a@x.example")
        val x = member("x@x.example")
        // The operator asks for X with X's anchor and X's identity file; the server served A's blob.
        val (res, _) = run(x, anchored(x), "x@x.example", listOf("RECOVER ${x.userId.take(8)}"), x.download.copy(sealed = a.download.sealed))
        val msg = res.exceptionOrNull()!!.message!!
        assertTrue("belongs to another account" in msg && "the server substituted it" in msg, msg)
    }

    @Test
    fun wrongAnchor_isRefused() {
        val e = member("a@x.example")
        val other = member("b@x.example")
        val o = opts("--user", e.userId, "--identity-fp", other.identityFp.take(32), "--identity-file", "f.json")
        val msg = run(e, o, "a@x.example", listOf("RECOVER ${e.userId.take(8)}")).first.exceptionOrNull()!!.message!!
        assertTrue("identity does not match the fingerprint you were given" in msg, msg)
    }

    @Test
    fun unanchored_needsTheTypedAcknowledgment_andIsReportedAsSuch() {
        val e = member("a@x.example")
        val o = opts("--user", e.userId, "--no-identity-anchor", "--identity-file", "f.json")
        val noAck = run(e, o, "a@x.example", listOf("yes", "RECOVER ${e.userId.take(8)}")).first.exceptionOrNull()!!.message!!
        assertTrue("not acknowledged" in noAck, noAck)
        val (ok, out) = run(e, o, "a@x.example", listOf(Escrow.UNANCHORED_ACK, "RECOVER ${e.userId.take(8)}"))
        assertFalse(ok.getOrThrow().anchored)
        assertTrue("NO — UNANCHORED" in out, out)
    }

    @Test
    fun legacyV1_isUnknownFormatUnread_andAnotherAccountsIdentityFileBeforeAnythingOpens() {
        val e = member("a@x.example")
        val v1 = Bytes.toB64(Escrow.sealUvkV1(crypto, org.publicKey, e.userId, e.uvk))
        val o = opts("--user", e.userId, "--identity-fp", e.identityFp.take(32), "--identity-file", "f.json", "--legacy")
        val msg = run(e, o, "a@x.example", listOf("RECOVER ${e.userId.take(8)}"), e.download.copy(legacySealed = v1)).first.exceptionOrNull()!!.message!!
        // Nothing without the magic is read by the tool; the sentence says both causes and what to do.
        assertTrue(msg.startsWith("REFUSED (unknown_format)") && RecoverCommand.UNKNOWN_FORMAT_SENTENCE in msg, msg)
        val other = member("b@x.example")
        assertFailsWith<RecoverRefused> { RecoverCommand.readIdentityFile(Json.encodeToString(AdminEscrowDownload.serializer(), other.download), o) }
    }
}
