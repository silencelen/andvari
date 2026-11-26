package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.net.BODY_OVER_LIMIT
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Attachments over the session's own client: its raw-body calls, so its guard, bearer and refresh hold for files too. */
class WireAttachmentsTest {
    private class RawClient : WireClient {
        override val origin = "https://vault.example.com"
        val calls = mutableListOf<String>()
        var served: ByteArray = ByteArray(0)
        var lastSent: ByteArray? = null
        var refusal: WireResult.Refused? = null

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            WireResult.NoAnswer(NoAnswerKind.TRANSPORT)

        override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls += "${route.name} ${pathParams.values.single()} $query ${body.size} $authenticated"
            return WireResult.Ok(decode("""{"attachmentId":"${pathParams.values.single()}","itemId":"i","vaultId":"v","size":${body.size},"sha256":"00","createdAt":1}"""), 200)
        }

        override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> {
            calls += "${route.name} ${pathParams.values.single()} $authenticated"
            refusal?.let { return it }
            return WireResult.Ok(served.copyOf().also { lastSent = it }, 200)
        }

        /** The cap each capped fetch asked for; the cap itself is the interface's default (fetch whole, refuse after). */
        val caps = mutableListOf<Long?>()

        override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?): WireResult<ByteArray> {
            caps += maxBytes
            return super.fetchBytes(route, pathParams, query, authenticated, maxBytes)
        }
    }

    @Test
    fun aDownloadIsReadNoFurtherThanTheItemsClaim() = runBlocking<Unit> {
        val c = RawClient()
        c.served = ByteArray(4096) { 1 }
        assertTrue(WireItemTransport(c).downloadAttachment(a, 4096) is WireResult.Ok)
        assertEquals(listOf<Long?>(4096), c.caps, "the claimed size is the read's cap")
    }

    @Test
    fun aServerSendingMoreThanTheClaim_isRefusedNamingTheClaim_andTheBytesAreWiped() = runBlocking<Unit> {
        val c = RawClient()
        c.served = ByteArray(5000) { 9 }
        val r = WireItemTransport(c).downloadAttachment(a, 4096)
        assertTrue(r is WireResult.Refused, "$r")
        assertEquals(ItemTransport.ATTACHMENT_SIZE_MISMATCH, r.code)
        assertTrue("4096" in r.error.message, r.error.message)
        assertTrue(c.lastSent!!.all { it == 0.toByte() }, "the oversized answer is zeroed")
    }

    @Test
    fun aHeldReadCutOff_isTheItemsSizeMismatch() = runBlocking<Unit> {
        val c = RawClient()
        c.refusal = WireResult.Refused(0, io.silencelen.andvari.core.model.wire.WireError(BODY_OVER_LIMIT, "over"))
        val r = WireItemTransport(c).downloadAttachment(a, 4096) as WireResult.Refused
        assertEquals(ItemTransport.ATTACHMENT_SIZE_MISMATCH, r.code)
        assertTrue("4096" in r.error.message, r.error.message)
    }

    private val a = "11111111-1111-4111-8111-111111111111"
    private val item = "22222222-2222-4222-8222-222222222222"
    private val vault = "33333333-3333-4333-8333-333333333333"

    @Test
    fun anUploadGoesThroughTheClientsRawBodyCall_withItsVaultAndItem() = runBlocking<Unit> {
        val c = RawClient()
        val r = WireItemTransport(c).uploadAttachment(a, item, vault, ByteArray(5))
        assertTrue(r is WireResult.Ok, "$r")
        assertEquals(listOf("ATTACHMENT_UPLOAD $a vaultId=$vault&itemId=$item 5 true"), c.calls)
    }

    @Test
    fun aDownloadIsHeldToTheSizeItsItemSays() = runBlocking<Unit> {
        val c = RawClient()
        c.served = "hello".encodeToByteArray()
        val t = WireItemTransport(c)
        assertContentEquals("hello".encodeToByteArray(), (t.downloadAttachment(a, 5) as WireResult.Ok).value)
        assertEquals(ItemTransport.ATTACHMENT_SIZE_MISMATCH, (t.downloadAttachment(a, 4) as WireResult.Refused).code)
        assertEquals(listOf("ATTACHMENT_GET $a true", "ATTACHMENT_GET $a true"), c.calls)
    }

    @Test
    fun anIdOutsideTheGrammar_isNeverSent() = runBlocking<Unit> {
        val c = RawClient()
        val t = WireItemTransport(c)
        assertEquals(ItemTransport.BAD_PATH_SEGMENT, (t.uploadAttachment("../x", item, vault, ByteArray(1)) as WireResult.Refused).code)
        assertEquals(ItemTransport.BAD_PATH_SEGMENT, (t.downloadAttachment("a/b", 1) as WireResult.Refused).code)
        assertTrue(c.calls.isEmpty())
    }
}
