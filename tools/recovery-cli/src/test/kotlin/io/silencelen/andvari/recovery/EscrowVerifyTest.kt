package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The fleet escrow canary (`verify` subcommand) — a generated keypair + sealed blobs,
 * same style as RecoveryCeremonyTest: exercise the pure logic, no filesystem/stdin.
 */
class EscrowVerifyTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val kp = crypto.boxKeypairFromSeed(seed)
    private val fp = Escrow.fingerprint(crypto, kp.publicKey)

    private fun goodRow(userId: String): EscrowDumpRow =
        EscrowDumpRow(userId, Bytes.toB64(Escrow.sealUvk(crypto, kp.publicKey, userId, crypto.randomBytes(32))), fp, 1L)

    @Test
    fun allGoodBlobsPass() {
        val rows = listOf(
            goodRow("11111111-1111-4111-8111-111111111111"),
            goodRow("22222222-2222-4222-8222-222222222222"),
        )
        val results = EscrowVerify.verify(crypto, seed, rows)
        assertEquals(2, results.size)
        assertTrue(results.all { it.pass }, results.toString())
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
        val sealedForA = Bytes.toB64(Escrow.sealUvk(crypto, kp.publicKey, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", crypto.randomBytes(32)))
        val row = EscrowDumpRow("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", sealedForA, fp)
        val r = EscrowVerify.verify(crypto, seed, listOf(row)).single()
        assertFalse(r.pass)
        assertTrue("does not match row" in r.detail, r.detail)
    }

    @Test
    fun corruptedBlobFails() {
        val good = goodRow("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
        val bytes = Bytes.fromB64(good.sealed)
        bytes[bytes.size / 2] = (bytes[bytes.size / 2] + 1).toByte() // flip one byte mid-ciphertext
        val r = EscrowVerify.verify(crypto, seed, listOf(good.copy(sealed = Bytes.toB64(bytes)))).single()
        assertFalse(r.pass)
        assertTrue("unseal failed" in r.detail, r.detail)
    }

    @Test
    fun blobSealedToDifferentKeyFails() {
        val otherKp = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val userId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        val sealed = Bytes.toB64(Escrow.sealUvk(crypto, otherKp.publicKey, userId, crypto.randomBytes(32)))
        // No fingerprint column → falls through to the unseal, which must fail.
        val r = EscrowVerify.verify(crypto, seed, listOf(EscrowDumpRow(userId, sealed))).single()
        assertFalse(r.pass)
        assertTrue("unseal failed" in r.detail, r.detail)
    }

    @Test
    fun fingerprintColumnMismatchFailsFast() {
        val row = goodRow("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee").copy(fingerprint = "0".repeat(64))
        val r = EscrowVerify.verify(crypto, seed, listOf(row)).single()
        assertFalse(r.pass)
        assertTrue("different recovery key" in r.detail, r.detail)
    }

    @Test
    fun mixedFleetReportsPerUser() {
        val rows = listOf(
            goodRow("11111111-1111-4111-8111-111111111111"),
            goodRow("22222222-2222-4222-8222-222222222222").copy(sealed = Bytes.toB64(crypto.randomBytes(226))),
        )
        val results = EscrowVerify.verify(crypto, seed, rows)
        assertTrue(results[0].pass)
        assertFalse(results[1].pass)
        assertEquals(1, results.count { !it.pass }) // the exit-nonzero condition in main()
    }

    @Test
    fun parsesSqliteJsonDumpShape() {
        // Exactly what `sqlite3 -json db "SELECT userId, sealed, fingerprint, updatedAt FROM escrow"` emits.
        val text = """[{"userId":"11111111-1111-4111-8111-111111111111","sealed":"QUJD","fingerprint":"$fp","updatedAt":1751771000000},
            {"userId":"22222222-2222-4222-8222-222222222222","sealed":"REVG","fingerprint":null,"updatedAt":null}]"""
        val rows = EscrowVerify.parseDump(text)
        assertEquals(2, rows.size)
        assertEquals(fp, rows[0].fingerprint)
        assertEquals(null, rows[1].fingerprint)
    }
}
