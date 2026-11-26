package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.UsageLedger
import io.silencelen.andvari.core.client.UsageRecorderCore
import io.silencelen.andvari.core.client.items.SessionUsage
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.refuse
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * `GET /usage` (row 24), the usage ledger the item engine's recorder reads before each write (spec 02 §8.2, spec 03 §3):
 * "a client that could not GET the current blob, or could not open the one it got, MUST NOT PUT that round". Lies: the
 * blob altered (W), Bob's real blob (A: its AD names Bob), `{}`, `ok`, a `500` (X), each with a use buffered. None of
 * them is followed by a `PUT`, and the uses stay buffered: the next honest round writes them, and the ledger the server
 * then holds has every earlier entry. Alice's earlier blob (R) and `sealedUsage: null` for a ledger that exists (W,
 * withheld) are written over: the device cannot tell either from the truth (there is no counter in the ledger, and
 * `null` is "never written"), and the server, which stores the blob, could drop or roll it back itself (the stated limit).
 */
class UsageLedgerLiesTest {
    private val crypto = createCryptoProvider()

    @Test fun aUsageAnswerThatCannotBeReadOrOpenedIsNeverWrittenOver() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        a.synced()
        b.synced()
        // The recorders' own scope: their hour-long debounce never fires here; each round is flushed by hand.
        val scope = CoroutineScope(SupervisorJob())
        try {
            fun recorder(s: AccountSession) = UsageRecorderCore(scope, 3_600_000, 10_000, { s }, { SessionUsage(it.client, it.vaultKeys, crypto, it.userId) })
            val ra = recorder(a)
            val rb = recorder(b)
            suspend fun item(s: AccountSession, name: String) = assertNotNull(s.putItem(s.personalVaultId!!, doc(name)).first).itemId
            val first = item(a, "first")
            val second = item(a, "second")
            val bobs = item(b, "bob's")

            rb.record(bobs, server.now())
            rb.flush()
            val bobsBlob = assertNotNull(proxy.last(WireRoute.USAGE_PUT, "bob")?.req?.json?.str("sealedUsage"))
            ra.record(first, server.now())
            ra.flush()
            val aliceBlob = assertNotNull(proxy.last(WireRoute.USAGE_PUT, "alice")?.req?.json?.str("sealedUsage"))
            fun usage(blob: String?) = JsonObject(mapOf("sealedUsage" to (blob?.let { JsonPrimitive(it) } ?: JsonNull), "updatedAt" to JsonPrimitive(server.now())))

            val unreadable: List<Pair<String, Handler>> = listOf(
                "the blob altered (W)" to answer { Resp.json(200, usage(aliceBlob.dropLast(4) + if (aliceBlob.endsWith("AAAA")) "BBBB" else "AAAA")) },
                "Bob's blob (A)" to answer { Resp.json(200, usage(bobsBlob)) },
                "an empty object (X)" to answer { Resp.json(200, JsonObject(emptyMap())) },
                "a plain ok (X)" to answer { Resp.ok() },
                "a 500 (X)" to refuse(500, "internal"),
            )
            for ((what, lie) in unreadable) {
                val mark = proxy.mark()
                val rule = proxy.on(WireRoute.USAGE_GET, "alice", handler = lie)
                server.advance(1000)
                ra.record(second, server.now())
                ra.flush()
                rule.remove()
                assertTrue(proxy.requests(WireRoute.USAGE_PUT, "alice", since = mark).isEmpty(), "$what: nothing is written over the ledger")
                assertTrue(second in ra.peek(), "$what: the use stays buffered for the next round")
            }
            // The next honest round writes the buffered use beside every earlier entry.
            val mark = proxy.mark()
            ra.flush()
            val written = assertNotNull(proxy.requests(WireRoute.USAGE_PUT, "alice", since = mark).singleOrNull()?.json?.str("sealedUsage"))
            val held = UsageLedger.parse(SessionUsage(a.client, a.vaultKeys, crypto, a.userId).open(written).decodeToString())
            assertEquals(setOf(first, second), held.keys, "the ledger holds every entry")
            assertTrue(ra.peek().isEmpty())

            // The stated limit: an earlier blob, or null for a ledger that exists, is written over (the server could do it itself).
            for ((what, body) in listOf("Alice's earlier blob (R)" to usage(aliceBlob), "null for a ledger that exists (W)" to usage(null))) {
                val m = proxy.mark()
                val rule = proxy.on(WireRoute.USAGE_GET, "alice", handler = answer { Resp.json(200, body) })
                server.advance(1000)
                ra.record(first, server.now())
                ra.flush()
                rule.remove()
                assertEquals(1, proxy.requests(WireRoute.USAGE_PUT, "alice", since = m).size, "$what: written over (the stated limit)")
            }
        } finally {
            scope.cancel()
        }
    }
}
