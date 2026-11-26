package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.NewAttachment
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Ctx
import io.silencelen.andvari.hostile.proxy.Resp
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Attachments under a hostile server (spec 05 T1 "swap ciphertexts between slots — blocked by AD binding"; spec 02 §6).
 * An attachment is fetched by the id the encrypted item names and opened under the key the item carries; the server
 * chooses only the bytes. Whatever it serves in an attachment's place opens to nothing, and nothing is shown.
 */
class AttachmentTest {
    /** One file of [size] bytes, every byte [fill]: the three files below are the same size, so only the content can tell them apart. */
    private fun file(fill: Int, size: Int = 4096) = ByteArray(size) { fill.toByte() }

    private suspend fun AccountSession.saveWithFile(vaultId: String, name: String, data: ByteArray): AttachmentRef {
        val ref = AttachmentRef(Bytes.uuidV4FromBytes(host.crypto.randomBytes(16)), "$name.bin", data.size.toLong(), Bytes.toB64(host.crypto.randomBytes(32)))
        val r = items.save(null, ItemDoc(type = "note", name = name, attachments = listOf(ref)), vaultId, uploads = listOf(NewAttachment(ref, data)))
        assertIs<ItemResult.Ok<*>>(r, "save $name with a file: $r")
        return ref
    }

    private fun AccountSession.refOf(name: String): AttachmentRef = items.items().single { it.doc.name == name }.doc.attachments.single()

    /**
     * The server serves, for one item's attachment, the ciphertext of another item's attachment in the same vault, then of
     * an item in another vault, then the genuine ciphertext cut short and padded back to its length: each is refused as
     * corrupt content, and the plaintext of the other file is never handed out. The genuine bytes still open.
     */
    @Test fun anAttachmentServedInAnotherAttachmentsPlaceOpensToNothing() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        val one = sharedVault(ah, bh, "One")
        val two = a.ok(null, LogAction.Create("Two"))
        a.ok(two, LogAction.Add(b.userId, "writer"))
        accept(b, two, "Two")
        a.synced()
        val mine = file(1)
        val sibling = file(2)
        val foreign = file(3)
        a.saveWithFile(one, "mine", mine)
        val siblingRef = a.saveWithFile(one, "sibling", sibling)
        val foreignRef = a.saveWithFile(two, "foreign", foreign)
        b.synced()
        val ref = b.refOf("mine")
        assertContentEquals(mine, assertIs<ItemResult.Ok<ByteArray>>(b.items.downloadAttachment(ref)).value, "the genuine file opens")

        val lies: List<Pair<String, (Ctx) -> Resp>> = listOf(
            "another item's attachment in the same vault" to { x: Ctx -> x.ask(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to siblingRef.id)) },
            "an attachment of another vault" to { x: Ctx -> x.ask(WireRoute.ATTACHMENT_GET, mapOf("attachmentId" to foreignRef.id)) },
            "its own ciphertext with the last half replaced" to { x: Ctx ->
                val real = x.forward()
                Resp(real.status, real.headers, real.body.copyOf().also { it.fill(0, it.size / 2, it.size) })
            },
        )
        for ((what, lie) in lies) {
            val rule = proxy.on(WireRoute.ATTACHMENT_GET, "bob", where = { it.param("attachmentId") == ref.id }) { x -> lie(x) }
            val mark = proxy.mark()
            val got = b.items.downloadAttachment(ref)
            assertEquals(1, sent(bh, WireRoute.ATTACHMENT_GET, mark).size, "$what: the device asked once and was served the lie")
            val failed = assertIs<ItemResult.Failed>(got, "$what: nothing opens")
            assertEquals(ItemFailure.Corrupt("content"), failed.why, what)
            rule.remove()
        }
        assertContentEquals(mine, assertIs<ItemResult.Ok<ByteArray>>(b.items.downloadAttachment(ref)).value, "served the genuine bytes again, the file opens")
    }
}
