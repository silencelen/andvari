package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The backup reader and a document nested deeper than any andvari writer makes one: refused as `bad_payload` before the
 * parser descends into it, never a crash. Nesting inside a string is no nesting.
 */
class BackupNestingTest {
    private val crypto = createCryptoProvider()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val pass = "nesting pass phrase"

    /** The deepest nesting the reader takes, the payload's own object counted as one. */
    private val bound = Backup.MAX_PAYLOAD_DEPTH

    private fun sealed(text: String): ByteArray {
        val out = ArrayList<ByteArray>()
        Backup.buildWithPayloadBytes(crypto, pass, "eeeeeeee-eeee-4eee-8eee-eeeeeeeee301", crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), text.encodeToByteArray(), emptyList(), null) { out += it.copyOf() }
        val all = ByteArray(out.sumOf { it.size })
        var at = 0
        for (b in out) {
            b.copyInto(all, at)
            at += b.size
        }
        return all
    }

    /** A payload whose deepest point is [depth] containers: its object, its items, the item, its document, then arrays. */
    private fun payload(depth: Int): String {
        val p = BackupPayload(
            exportedAt = 1L,
            vaults = listOf(BackupVault("11111111-1111-4111-8111-111111111111", "personal", "Personal", "owner")),
            items = listOf(BackupItem("22222222-2222-4222-8222-000000000001", "11111111-1111-4111-8111-111111111111", 1, 1L, ItemDoc("login", "Deep", notes = "MARK"))),
        )
        val k = depth - 4
        return json.encodeToString(BackupPayload.serializer(), p).replace("\"notes\":\"MARK\"", "\"notes\":\"x\",\"deep\":" + "[".repeat(k) + "]".repeat(k))
            .also { assertTrue(it.contains("\"deep\":" + "[".repeat(k) + "]")) }
    }

    @Test fun aPayloadNestedTenThousandDeepIsBadPayloadNotACrash() {
        val e = assertFailsWith<BackupException> { Backup.open(crypto, pass, sealed(payload(10_000))) }
        assertEquals(Backup.ERR_BAD_PAYLOAD, e.code)
    }

    @Test fun onePastTheBoundIsBadPayloadAndTheBoundItselfIsRead() {
        val e = assertFailsWith<BackupException> { Backup.open(crypto, pass, sealed(payload(bound + 1))) }
        assertEquals(Backup.ERR_BAD_PAYLOAD, e.code)
        val opened = Backup.open(crypto, pass, sealed(payload(bound)))
        assertEquals("Deep", opened.payload.items.single().doc.name)
    }

    @Test fun bracketsInsideAStringAreNoNesting() {
        val p = BackupPayload(
            exportedAt = 1L,
            vaults = listOf(BackupVault("11111111-1111-4111-8111-111111111111", "personal", "Personal", "owner")),
            items = listOf(BackupItem("22222222-2222-4222-8222-000000000001", "11111111-1111-4111-8111-111111111111", 1, 1L, ItemDoc("login", "[{\\\"".repeat(5_000)))),
        )
        val opened = Backup.open(crypto, pass, sealed(json.encodeToString(BackupPayload.serializer(), p)))
        assertEquals("[{\\\"".repeat(5_000), opened.payload.items.single().doc.name)
    }

    /**
     * A closer where nothing is open is the scanner's own refusal: asked directly, with no parser behind it, so its
     * answer cannot be the parser's. Thirty thousand stray closers then twenty thousand openers would otherwise read
     * as never deeper than the bound.
     */
    @Test fun theScannerRefusesACloserWhereNothingIsOpen() {
        val stray = ("]".repeat(30_000) + "[".repeat(20_000)).encodeToByteArray()
        assertTrue(Backup.nestedDeeperThan(stray, Backup.MAX_PAYLOAD_DEPTH), "refused by the scanner itself")
        assertTrue(Backup.nestedDeeperThan("{}}".encodeToByteArray(), Backup.MAX_PAYLOAD_DEPTH), "one stray closer")
        assertTrue(!Backup.nestedDeeperThan("{\"a\":[1,{\"b\":\"]]]\"}]}".encodeToByteArray(), Backup.MAX_PAYLOAD_DEPTH), "closers in a string are none")
    }

    @Test fun aHeaderNestedThirtyThousandDeepIsRefusedNotACrash() {
        val good = sealed(payload(5))
        val headerLen = (0 until 4).fold(0) { acc, i -> acc or ((good[8 + i].toInt() and 0xFF) shl (8 * i)) }
        val header = good.copyOfRange(12, 12 + headerLen).decodeToString()
        val deep = header.dropLast(1) + ",\"x\":" + "[".repeat(30_000) + "]".repeat(30_000) + "}"
        val bytes = deep.encodeToByteArray()
        val len = ByteArray(4) { i -> ((bytes.size ushr (8 * i)) and 0xFF).toByte() }
        val file = good.copyOfRange(0, 8) + len + bytes + good.copyOfRange(12 + headerLen, good.size)
        // Either refused, or read past the unknown key: never an Error out of the reader.
        runCatching { Backup.open(crypto, pass, file) }.exceptionOrNull()?.let { assertTrue(it is BackupException, "$it") }
    }
}
