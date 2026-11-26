package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * An attachment's file key is the item document's (spec 02 §6), which any writer of a shared vault authors: a key that
 * is not one is damaged content, refused before anything is fetched or decrypted, and a lock met on the way is the
 * lock's own result, never damage (spec 01 §8 rules 4 and 5).
 */
class AttachmentFileKeyTest {
    private val data = ByteArray(70_000) { (it % 251).toByte() }

    /** A real file saved with a real key, so that a forged ref of the same id would find a body to download. */
    private suspend fun saved(r: ItemRig): AttachmentRef {
        val ref = AttachmentRef(r.id(), "scan.pdf", data.size.toLong(), Bytes.toB64(r.crypto.randomBytes(32)))
        r.engine.save(null, r.doc.copy(attachments = listOf(ref)), uploads = listOf(NewAttachment(ref, data))).ok()
        return ref
    }

    @Test
    fun aFileKeyOfTheWrongLengthOrNotBase64IsDamagedContent_refusedBeforeAnythingIsFetched() = runBlocking<Unit> {
        val r = ItemRig()
        val ref = saved(r)
        val calls = r.server.calls
        for (key in listOf(Bytes.toB64(ByteArray(16) { 5 }), Bytes.toB64(ByteArray(33) { 5 }), "", "not base64 !")) {
            assertEquals(ItemFailure.Corrupt("content"), r.engine.downloadAttachment(ref.copy(fileKey = key)).failure(), "key \"$key\"")
        }
        assertEquals(calls, r.server.calls, "nothing was fetched for a key that is not one")
        assertContentEquals(data, r.engine.downloadAttachment(ref).ok(), "the real key still opens it")
    }

    /** The hostile input: [ref] with a file key of 32 zero bytes, as whoever writes an item could set it. Nothing else is built here, and nothing is sealed or opened under it. */
    private fun allZeroFileKey(ref: AttachmentRef): AttachmentRef = ref.copy(fileKey = Bytes.toB64(ByteArray(32)))

    /**
     * A file key of the right length that is all zeros is refused as damaged content before anything is downloaded, so
     * nothing is ever opened under it. The test only hands the forged reference to the engine; it runs with the
     * zero-key tripwire on like every other test, and the tripwire has nothing to record for it unless the refusal
     * were ever lost.
     */
    @Test
    fun aFileKeyOfAllZerosIsDamagedContent_refusedBeforeAnythingIsFetched() = runBlocking<Unit> {
        val r = ItemRig()
        val ref = saved(r)
        val hostile = allZeroFileKey(ref)
        val calls = r.server.calls
        assertEquals(ItemFailure.Corrupt("content"), r.engine.downloadAttachment(hostile).failure())
        assertEquals(calls, r.server.calls, "no download, so nothing to decrypt")
        assertContentEquals(data, r.engine.downloadAttachment(ref).ok(), "the real key still opens it")
    }

    @Test
    fun aLockDuringTheDownloadIsTheLocksOwnResult_neverDamage_andOpensNothing() = runBlocking<Unit> {
        val r = ItemRig()
        val ref = saved(r)
        r.server.hold = { route -> if (route == "download") r.keys.locked = true }
        assertFailsWith<KeysGoneException> { r.engine.downloadAttachment(ref) }
    }

    @Test
    fun aLockRaisedInsideTheOpenIsPassedOnAsTheLock_neverReadAsDamage() = runBlocking<Unit> {
        val r = ItemRig()
        val ref = saved(r)
        val lockedInTheOpen = object : CryptoProvider by r.crypto {
            override fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray> = throw KeysGoneException()
        }
        val engine = ItemEngine(r.server, r.keys, r.gate, r.cache, r.userId, lockedInTheOpen, { r.now })
        assertFailsWith<KeysGoneException> { engine.downloadAttachment(ref) }
    }
}
