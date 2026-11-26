package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The fleet escrow canary (`verify` subcommand) — a generated keypair + sealed blobs,
 * same style as RecoveryCeremonyTest: exercise the pure logic, no filesystem/stdin.
 * Since escrow v2 (security review 2026-10, root cause A) the drill goes through the SAME
 * Escrow.open as `recover`, so every member row carries its identity file.
 */
class EscrowVerifyTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val kp = crypto.boxKeypairFromSeed(seed)
    private val fp = Escrow.fingerprint(crypto, kp.publicKey)

    private class Member(val userId: String, val idSeed: ByteArray, val uvk: ByteArray)

    private fun member(userId: String) = Member(userId, crypto.randomBytes(32), crypto.randomBytes(32))

    private fun row(m: Member, sealed: ByteArray, recoveryFp: String? = fp) = EscrowDumpRow(
        m.userId, Bytes.toB64(sealed), recoveryFp, 1L,
        encryptedIdentitySeed = Envelope.sealB64(crypto, m.uvk, m.idSeed, Ad.idkey(m.userId)),
        identityPub = Bytes.toB64(crypto.boxKeypairFromSeed(m.idSeed).publicKey),
    )

    private fun v2(m: Member, toPub: ByteArray = kp.publicKey) = Escrow.sealUvkV2(
        crypto, toPub, Escrow.fingerprint(crypto, toPub), m.userId, crypto.boxKeypairFromSeed(m.idSeed).publicKey,
        crypto.signKeypairFromSeed(m.idSeed), m.uvk, 1_791_590_400_000L,
    )

    /** The copy every client seals now (spec 04 §3): it names the account's address. */
    private fun v3(m: Member, toPub: ByteArray = kp.publicKey) = Escrow.sealUvkV3(
        crypto, toPub, Escrow.fingerprint(crypto, toPub), m.userId, "m@example.com", crypto.boxKeypairFromSeed(m.idSeed).publicKey,
        crypto.signKeypairFromSeed(m.idSeed), m.uvk, 1_791_590_400_000L,
    )

    private fun goodRow(userId: String): EscrowDumpRow = member(userId).let { row(it, v3(it)) }

    @Test
    fun aV3CopyPasses_andTheOldFormsFailBecauseTheyDoNotSayWhoseTheyAre() {
        val old = member("33333333-3333-4333-8333-333333333333")
        val legacy = member("22222222-2222-4222-8222-222222222222")
        val rows = listOf(
            goodRow("11111111-1111-4111-8111-111111111111"),
            row(old, v2(old)),
            row(legacy, Escrow.sealUvkV1(crypto, kp.publicKey, legacy.userId, legacy.uvk)),
        )
        val results = EscrowVerify.verify(crypto, seed, rows)
        assertEquals(3, results.size)
        assertTrue(results[0].pass && results[0].detail.startsWith("v3 ok"), results[0].detail)
        // spec 04 §4 steps 4 and 7: assist cannot use them, so the drill names
        // them; the pre-signed form is not read at all.
        assertFalse(results[1].pass)
        assertTrue(results[1].detail.startsWith("refused: no_address") && "the operator cannot recover this account" in results[1].detail, results[1].detail)
        assertFalse(results[2].pass)
        assertTrue(results[2].detail.startsWith("refused: unknown_format") && "the operator cannot recover this account" in results[2].detail, results[2].detail)
    }

    @Test
    fun canaryRowPasses() {
        val row = EscrowDumpRow(Escrow.CANARY_USER_ID, Bytes.toB64(Escrow.sealCanary(crypto, kp.publicKey)), fp)
        val r = EscrowVerify.verify(crypto, seed, listOf(row)).single()
        assertTrue(r.pass, r.detail)
        assertEquals("canary ok", r.detail)
    }

    @Test
    fun userIdMismatchFails() {
        // Blob sealed for user A but stored under user B's row — the exact swap/DB-corruption
        // case the drill exists to catch before a real recovery depends on it.
        val a = member("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        val b = member("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        val r = EscrowVerify.verify(crypto, seed, listOf(row(b, v2(a)))).single()
        assertFalse(r.pass)
        assertEquals("refused: user_mismatch", r.detail)
    }

    @Test
    fun rowWithoutTheIdentityColumnsFails_soAPassAlwaysMeansRecoverable() {
        val r = EscrowVerify.verify(crypto, seed, listOf(goodRow("cccccccc-cccc-4ccc-8ccc-cccccccccccc").copy(encryptedIdentitySeed = null))).single()
        assertFalse(r.pass)
        assertTrue("identity columns" in r.detail, r.detail)
    }

    /** A row without its identity columns is refused by the name spec 04 §4 step 0.3 gives it, with the re-export sentence. */
    @Test
    fun rowWithoutTheIdentityColumns_isIdentityCheckRequired_withItsSentence() {
        for (r in EscrowVerify.verify(
            crypto, seed,
            listOf(
                goodRow("cccccccc-cccc-4ccc-8ccc-cccccccccccc").copy(encryptedIdentitySeed = null),
                goodRow("dddddddd-dddd-4ddd-8ddd-dddddddddddd").copy(identityPub = null),
            ),
        )) {
            assertFalse(r.pass)
            assertTrue(r.detail.startsWith("refused: identity_check_required ("), r.detail)
            assertTrue("re-export with: ${EscrowVerify.DUMP_SQL}" in r.detail, r.detail)
        }
    }

    /** Every refusal the fleet check can make has a name, and none quotes an exception's message. */
    @Test
    fun everyRefusalOfTheFleetCheck_hasAName() {
        val good = goodRow("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        val (spaced, otherKey) = EscrowVerify.verify(crypto, seed, listOf(good.copy(sealed = good.sealed + " "), good.copy(fingerprint = "0".repeat(64))))
        assertTrue(spaced.detail.startsWith("refused: bad_copy ("), spaced.detail)
        assertTrue(otherKey.detail.startsWith("refused: recovery_fp_mismatch ("), otherKey.detail)
    }

    @Test
    fun identityFileThatTheEscrowedKeyDoesNotOpen_fails() {
        val m = member("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        val other = member(m.userId)
        val r = EscrowVerify.verify(crypto, seed, listOf(row(m, v2(m)).copy(encryptedIdentitySeed = row(other, v2(other)).encryptedIdentitySeed))).single()
        assertFalse(r.pass)
        assertEquals("refused: identity_check_failed", r.detail)
    }

    @Test
    fun corruptedBlobFails() {
        val good = goodRow("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        val bytes = Bytes.fromB64(good.sealed)
        bytes[bytes.size / 2] = (bytes[bytes.size / 2] + 1).toByte() // flip one byte mid-ciphertext
        val r = EscrowVerify.verify(crypto, seed, listOf(good.copy(sealed = Bytes.toB64(bytes)))).single()
        assertFalse(r.pass)
        assertEquals("refused: unopenable", r.detail)
    }

    @Test
    fun blobSealedToDifferentKeyFails() {
        val otherKp = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val m = member("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        // No fingerprint column → falls through to the unseal, which must fail.
        val r = EscrowVerify.verify(crypto, seed, listOf(row(m, v2(m, otherKp.publicKey), recoveryFp = null))).single()
        assertFalse(r.pass)
        assertEquals("refused: unopenable", r.detail)
    }

    @Test
    fun fingerprintColumnMismatchFailsFast() {
        val row = goodRow("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").copy(fingerprint = "0".repeat(64))
        val r = EscrowVerify.verify(crypto, seed, listOf(row)).single()
        assertFalse(r.pass)
        assertTrue("different recovery key" in r.detail, r.detail)
    }

    @Test
    fun mixedFleetReportsPerUser_andPrintsNoReceipt() {
        val rows = listOf(
            goodRow("11111111-1111-4111-8111-111111111111"),
            goodRow("22222222-2222-4222-8222-222222222222").copy(sealed = Bytes.toB64(crypto.randomBytes(226))),
            EscrowDumpRow(Escrow.CANARY_USER_ID, Bytes.toB64(Escrow.sealCanary(crypto, kp.publicKey)), fp),
        )
        val results = EscrowVerify.verify(crypto, seed, rows)
        assertTrue(results[0].pass)
        assertFalse(results[1].pass)
        assertEquals(1, results.count { !it.pass }) // the exit-nonzero condition in main()
        // No receipt for a route the server does not have
        // (`/admin/escrow/drill`); the verification itself is the whole output.
        for (fleet in listOf(results, results.filter { it.pass })) {
            val out = EscrowVerify.reportLines(fleet).joinToString("\n")
            assertFalse("receipt" in out.lowercase() || "escrow/drill" in out || "/api/" in out, out)
            assertTrue("${fleet.count { it.pass }}/${fleet.size} PASS" in out, out)
        }
        assertTrue(EscrowVerify.reportLines(results).last().contains("1 escrow blob(s) FAILED"))
        assertEquals("All escrowed accounts in this download (2) are recoverable with this sheet.", EscrowVerify.reportLines(results.filter { it.pass }).last())
    }

    // ---- A14 (F12): the table prints server-supplied strings ----

    @Test
    fun theTableEscapesHostileUserIdsAndDetail() {
        // The dump is the server's data: a hostile server names a row with terminal escapes, and the
        // unseal failure's detail carries exception text.
        val hostile = goodRow("11111111-1111-4111-8111-111111111111")
            .copy(userId = "\u001B[1A\u001B[2K11111111-1111-4111-8111-111111111111\u009B", sealed = Bytes.toB64(crypto.randomBytes(226)))
        val results = EscrowVerify.verify(crypto, seed, listOf(hostile)) +
            EscrowVerifyResult("u2", false, "unseal failed: \u001B]52;c;cHduZWQ=\u0007")
        val out = EscrowVerify.tableLines(results).joinToString("\n")
        assertEquals("", out.filter { it != '\n' && io.silencelen.andvari.core.client.TerminalText.isControl(it) }, out)
        assertTrue("\\u001B[1A\\u001B[2K11111111" in out, out)
        assertTrue("\\u009B" in out && "\\u001B]52;c;cHduZWQ=\\u0007" in out, out)
        assertEquals(3, out.lines().size, "header + one line per row")
    }

    @Test
    fun parsesSqliteJsonDumpShape() {
        // Exactly what `sqlite3 -json db "<EscrowVerify.DUMP_SQL>"` emits (identity columns null for a canary row).
        val text = """[{"userId":"11111111-1111-4111-8111-111111111111","sealed":"QUJD","fingerprint":"$fp","updatedAt":1751771000000,"encryptedIdentitySeed":"RUlT","identityPub":"SVA"},
            {"userId":"22222222-2222-4222-8222-222222222222","sealed":"REVG","fingerprint":null,"updatedAt":null,"encryptedIdentitySeed":null,"identityPub":null}]"""
        val rows = EscrowVerify.parseDump(text)
        assertEquals(2, rows.size)
        assertEquals(fp, rows[0].fingerprint)
        assertEquals("RUlT", rows[0].encryptedIdentitySeed)
        assertEquals(null, rows[1].fingerprint)
        assertTrue("u.encryptedIdentitySeed" in EscrowVerify.DUMP_SQL && "u.identityPub" in EscrowVerify.DUMP_SQL)
    }
}
