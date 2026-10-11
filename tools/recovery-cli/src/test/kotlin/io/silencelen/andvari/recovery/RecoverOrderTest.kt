package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.KdfParams
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
 * `recover`'s verification order (security review 2026-10, root cause A §2.3; spec 04 §4): it must name
 * the account and its identity anchor, it goes through Escrow.open (so a swapped, forged or v1 blob is
 * refused unless provably this account's), an unanchored run needs the typed acknowledgment, and nothing
 * is generated before the admin types `RECOVER <first 8>`.
 */
class RecoverOrderTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val org = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val orgFp = Escrow.fingerprint(crypto, org.publicKey)

    private class Enrolled(val userId: String, val download: AdminEscrowDownload, val identityFp: String, val uvk: ByteArray)

    private fun enrol(email: String): Enrolled {
        val r = Account.enroll("inv", email, "m", "pw", kdf, org.publicKey, orgFp, "dev", crypto)
        val dl = AdminEscrowDownload(r.request.userId, r.request.escrow!!.sealed, r.request.encryptedIdentitySeed, r.request.identityPub)
        return Enrolled(r.request.userId, dl, Escrow.fingerprint(crypto, r.account.identityPub), r.account.uvkCopyForPlatformWrap())
    }

    private fun opts(vararg args: String) = RecoverCommand.parse(args.toList())

    private fun run(e: Enrolled, o: RecoverOptions, lines: List<String>, download: AdminEscrowDownload = e.download): Pair<Result<io.silencelen.andvari.core.crypto.EscrowOpened>, String> {
        val out = StringBuilder()
        val input = lines.iterator()
        val text = Json.encodeToString(AdminEscrowDownload.serializer(), download)
        val res = runCatching {
            val (check, sealed) = RecoverCommand.readIdentityFile(text, o)
            RecoverCommand.openAndConfirm(crypto, org, o, check, sealed, { if (input.hasNext()) input.next() else null }) { out.appendLine(it) }
        }
        return res to out.toString()
    }

    @Test
    fun step0_refusesWithoutTheAccountOrTheAnchor() {
        val noUser = assertFailsWith<RecoverRefused> { opts("--identity-fp", "a".repeat(32), "--identity-file", "f.json") }
        assertTrue("must name the account and its identity fingerprint" in noUser.message!!)
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-file", "f.json") }
        // A 16-hex short id is not an anchor (design §7.1); a human entry tolerates spaces and dashes.
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(16), "--identity-file", "f.json") }
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "g".repeat(32), "--identity-file", "f.json") }
        assertEquals("ab12".repeat(8), opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "AB12 ab12-ab12 ab12 ab12 ab12 ab12 ab12", "--identity-file", "f.json").identityFpPrefix)
        // The identity file is mandatory: a v1 blob can only ever be recovered through it.
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(32)) }
        assertFailsWith<RecoverRefused> { opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--identity-fp", "a".repeat(32), "--no-identity-anchor", "--identity-file", "f.json") }
        val un = opts("--user", "dddddddd-dddd-4ddd-8ddd-dddddddddddd", "--no-identity-anchor", "--identity-file", "f.json")
        assertTrue(un.unanchored)
        assertNull(un.identityFpPrefix)
    }

    @Test
    fun anchoredV2_opensOnlyAfterTheTypedConfirmation() {
        val e = enrol("a@x.com")
        val o = opts("--user", e.userId, "--identity-fp", e.identityFp.take(32), "--identity-file", "f.json")
        val (refused, _) = run(e, o, listOf("RECOVER wrong"))
        assertTrue(refused.exceptionOrNull() is RecoverRefused, "no confirmation, nothing generated")
        val (ok, out) = run(e, o, listOf("RECOVER ${e.userId.take(8)}"))
        val opened = ok.getOrThrow()
        assertEquals(EscrowFormat.V2, opened.format)
        assertTrue(opened.anchored)
        assertContentEquals(e.uvk, opened.uvk)
        assertTrue("anchored: yes" in out && "format:   v2" in out, out)
    }

    @Test
    fun wrongAccount_isNamedAsASubstitution() {
        val a = enrol("a@x.com")
        val x = enrol("x@x.com")
        // The admin asks for X with X's anchor and X's identity file; the server served A's blob.
        val o = opts("--user", x.userId, "--identity-fp", x.identityFp.take(32), "--identity-file", "f.json")
        val (res, _) = run(x, o, listOf("RECOVER ${x.userId.take(8)}"), x.download.copy(sealed = a.download.sealed))
        val msg = res.exceptionOrNull()!!.message!!
        assertTrue("belongs to another account" in msg && "the server substituted it" in msg, msg)
    }

    @Test
    fun wrongAnchor_isRefused() {
        val e = enrol("a@x.com")
        val other = enrol("b@x.com")
        val o = opts("--user", e.userId, "--identity-fp", other.identityFp.take(32), "--identity-file", "f.json")
        val msg = run(e, o, listOf("RECOVER ${e.userId.take(8)}")).first.exceptionOrNull()!!.message!!
        assertTrue("identity does not match the fingerprint you were given" in msg, msg)
    }

    @Test
    fun unanchored_needsTheTypedAcknowledgment_andIsReportedAsSuch() {
        val e = enrol("a@x.com")
        val o = opts("--user", e.userId, "--no-identity-anchor", "--identity-file", "f.json")
        val noAck = run(e, o, listOf("yes", "RECOVER ${e.userId.take(8)}")).first.exceptionOrNull()!!.message!!
        assertTrue("not acknowledged" in noAck, noAck)
        val (ok, out) = run(e, o, listOf(Escrow.UNANCHORED_ACK, "RECOVER ${e.userId.take(8)}"))
        assertFalse(ok.getOrThrow().anchored)
        assertTrue("NO — UNANCHORED" in out, out)
    }

    @Test
    fun legacyV1_recoverableOnlyWithTheIdentityCheck_viaTheRetainedBlob() {
        val e = enrol("a@x.com")
        val v1 = Bytes.toB64(Escrow.sealUvkV1(crypto, org.publicKey, e.userId, e.uvk))
        val dl = e.download.copy(legacySealed = v1)
        val o = opts("--user", e.userId, "--identity-fp", e.identityFp.take(32), "--identity-file", "f.json", "--legacy")
        val (ok, out) = run(e, o, listOf("RECOVER ${e.userId.take(8)}"), dl)
        assertEquals(EscrowFormat.V1_LEGACY, ok.getOrThrow().format)
        assertTrue("v1 (legacy, identity-checked)" in out, out)
        // The identity file belongs to another account → refused before anything is opened.
        val other = enrol("b@x.com")
        assertFailsWith<RecoverRefused> { RecoverCommand.readIdentityFile(Json.encodeToString(AdminEscrowDownload.serializer(), other.download), o) }
    }
}
