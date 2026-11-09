package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (root cause D): `AttachmentRef.size` is plaintext a co-member writes, and
 * nothing measured it. The backup planner summed it as the ONLY gate on the 64 MiB in-memory cap —
 * a `-1` or a `Long.MAX_VALUE` (wrapping the running total negative) let every attachment in, and
 * the backup then held hundreds of MiB in heap. The download path read whatever body arrived.
 * Now the declared size is a claim checked against the ciphertext: the planner's arithmetic is
 * overflow-safe and refuses a negative claim, and a download refuses (and stops reading) any body
 * whose length is not exactly what the declared size implies — so `plan.totalBytes` IS the bytes
 * the backup will hold.
 */
class AttachmentDeclaredSizeTest {
    private val crypto = createCryptoProvider()
    private val cap = Backup.MAX_TOTAL_ATTACHMENT_PLAINTEXT

    private fun ref(name: String, size: Long) = AttachmentRef(id = "a-$name", name = name, size = size, fileKey = "a2V5")
    private fun item(vararg refs: AttachmentRef) = VaultItem("i-${refs.first().name}", "v", 1, 0, ItemDoc(type = "note", name = "n", attachments = refs.toList()))

    @Test
    fun planAttachments_aNegativeOrWrappingClaim_cannotOpenTheCap() {
        val honest = (1..3).map { item(ref("big$it", 25L * 1024 * 1024)) } // 75 MiB declared honestly
        // A negative claim used to drive the running total DOWN; MAX_VALUE used to wrap it negative.
        for (lie in listOf(-1L, -cap, Long.MAX_VALUE, Long.MAX_VALUE - 1)) {
            val plan = ExportPlanner.planAttachments(listOf(item(ref("liar", lie))) + honest)
            assertTrue("liar" in plan.overCap, "a claim of $lie is never planned in")
            assertTrue(plan.totalBytes in 0..cap, "total stays within the cap: ${plan.totalBytes}")
            assertEquals(listOf("big1", "big2"), plan.included.map { it.ref.name }, "the honest refs still plan normally (claim $lie)")
        }
    }

    @Test
    fun wireLength_isTheExactUploadedLength() {
        for (n in listOf(1, 100, Attachments.CHUNK - 1, Attachments.CHUNK, Attachments.CHUNK + 1, 3 * Attachments.CHUNK + 7)) {
            val enc = Attachments.encrypt(crypto, crypto.randomBytes(32), ByteArray(n))
            assertEquals((enc.header.size + enc.ciphertext.size).toLong(), Attachments.wireLength(n.toLong()), "n=$n")
        }
    }

    private fun account(): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("t", "size@x.test", "s", "pw size", KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), recovery.publicKey, fp, "d", crypto).account
    }

    private fun engineServing(body: ByteArray, repeat: Int = 1): SyncEngine {
        val engine = MockEngine { _ ->
            // A streamed body (no Content-Length) — the reader must bound itself.
            val channel = ByteReadChannel(ByteArray(body.size * repeat) { body[it % body.size] })
            respond(channel, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/octet-stream"))
        }
        return SyncEngine(AndvariApi("http://fake", HttpClient(engine), Tokens("a", "r")), account(), InMemoryVaultCache())
    }

    @Test
    fun downloadAttachment_refusesABodyThatContradictsTheDeclaredSize() = runBlocking {
        val key = crypto.randomBytes(32)
        val data = ByteArray(100_000) { it.toByte() }
        val enc = Attachments.encrypt(crypto, key, data)
        val wire = enc.header + enc.ciphertext
        fun r(size: Long) = AttachmentRef("0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", "f.bin", size, Bytes.toB64(key))

        assertContentEquals(data, engineServing(wire).downloadAttachment(r(data.size.toLong())), "the honest claim opens")
        // Claims smaller than the bytes: refused, whether the server sends the real blob or a flood.
        assertFailsWith<CryptoException> { engineServing(wire).downloadAttachment(r(10)) }
        assertFailsWith<CryptoException> { engineServing(wire, repeat = 200).downloadAttachment(r(10)) }
        // A claim larger than the bytes (the idle-lock / backup-cap inflation): refused.
        assertFailsWith<CryptoException> { engineServing(wire).downloadAttachment(r(100_000_000_000_000L)) }
        // A negative or zero claim is refused before any request.
        assertFailsWith<CryptoException> { engineServing(wire).downloadAttachment(r(-1)) }
        assertFailsWith<CryptoException> { engineServing(wire).downloadAttachment(r(0)) }
        Unit
    }
}
