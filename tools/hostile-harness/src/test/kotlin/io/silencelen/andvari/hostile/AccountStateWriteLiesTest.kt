package io.silencelen.andvari.hostile

import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.refuse
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * `PUT /account/state` (spec 03 §3; design §5.4), the last row's first route. The device seals the whole document, sends
 * it with the compare-and-set token it holds, and keeps from the answer only the next token (`seq`): never the blob the
 * answer carries. So whatever the answer says, the document the device holds is the one it wrote, and the token is only
 * a hint for the next write, which a `409 stale_state` corrects by a read, a merge and a retry (bounded).
 *
 * The lies, each after the server stored the write honestly: the token far below or far above the true one, or the
 * answer's blob altered (W); Bob's own answer (A); Alice's earlier answer (R). Then, with nothing stored: `ok`, `{}` and
 * a `500` (X), and `409 stale_state` to every attempt. The properties: the device never takes another blob for its own;
 * nothing written is lost; a write it cannot be sure of is never reported written; and the next honest write lands with
 * every earlier change, with no write after a bounded number of attempts.
 */
class AccountStateWriteLiesTest {
    private fun mark(key: String): (AccountDocument) -> AccountDocument = { d -> d.copy(unknown = d.unknown + (key to "\"$key\"")) }

    private fun World.lastAnswer(tag: String): JsonObject =
        Json.parseToJsonElement(proxy.log().last { it.req.route == WireRoute.ACCOUNT_STATE_PUT && it.req.tag == tag && it.upstream?.ok == true }.upstream!!.text).jsonObject

    /** The write is stored by the server, then answered with [lie] of the true answer. */
    private fun storedThen(lie: (JsonObject) -> JsonObject) = Handler { x -> x.forward().withJson(lie) }

    @Test fun aWriteAnswerThatLiesNeverReplacesTheDocumentAndTheNextWriteLandsWithEverything() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val a = account(ah)
        val b = account(bh)
        assertIs<AccountStateWrite.Written>(a.store.update(mark("a0")))
        val alicesEarlier = lastAnswer("alice")
        assertIs<AccountStateWrite.Written>(b.store.update(mark("b0")))
        val bobs = lastAnswer("bob")
        assertIs<AccountStateWrite.Written>(a.store.update(mark("a1")))
        val written = ArrayList(listOf("a0", "a1"))

        val lies: List<Pair<String, (JsonObject) -> JsonObject>> = listOf(
            "the token far below the true one (W)" to { it.set("seq", 0L) },
            "the token far above the true one (W)" to { it.set("seq", it.getValue("seq").jsonPrimitive.content.toLong() + 1_000_000L) },
            "the answer's blob altered (W)" to { o -> o.set("sealedState", o.getValue("sealedState").jsonPrimitive.content.let { s -> (if (s[5] == 'A') "B" else "A").let { c -> s.substring(0, 5) + c + s.substring(6) } }) },
            "Bob's answer (A)" to { _ -> bobs },
            "Alice's earlier answer (R)" to { _ -> alicesEarlier },
        )
        for ((n, lie) in lies.withIndex()) {
            val (what, edit) = lie
            val rule = proxy.on(WireRoute.ACCOUNT_STATE_PUT, "alice", handler = storedThen(edit))
            val key = "lie$n"
            val w = a.store.update(mark(key))
            rule.remove()
            // The write was stored; the device cannot tell the answer lied, and holds exactly what it wrote.
            val held = assertIs<AccountStateWrite.Written>(w, what).document
            assertEquals(held, a.store.local(), "$what: the document held is the one written, never the answer's blob")
            assertTrue("b0" !in held.unknown, "$what: nothing of Bob's")
            written += key
            // The next honest write lands, with every change so far.
            val next = "after$n"
            assertIs<AccountStateWrite.Written>(a.store.update(mark(next)), "$what: the next write")
            written += next
            val served = assertIs<AccountStateRead.Ok>(a.store.read(), what).document
            assertTrue(written.all { it in served.unknown }, "$what: every change is stored: ${served.unknown.keys}")
            assertTrue("b0" !in served.unknown, "$what: nothing of Bob's")
        }

        // Nothing stored, and an answer the route never gives (X): never reported written; the next write carries the change.
        val notStored: List<Pair<String, Handler>> = listOf(
            "a plain ok (X)" to answer { Resp.ok() },
            "an empty object (X)" to answer { Resp.json(200, JsonObject(emptyMap())) },
            "a 500 (X)" to refuse(500, "internal"),
        )
        for ((n, pair) in notStored.withIndex()) {
            val (what, lie) = pair
            val rule = proxy.on(WireRoute.ACCOUNT_STATE_PUT, "alice", handler = lie)
            val w = a.store.update(mark("x$n"))
            rule.remove()
            assertTrue(w !is AccountStateWrite.Written && w !is AccountStateWrite.Unchanged, "$what: never reported written: $w")
            assertTrue(assertIs<AccountStateRead.Ok>(a.store.read(), what).document.unknown.keys.containsAll(written), "$what: nothing earlier lost")
            assertIs<AccountStateWrite.Written>(a.store.update(mark("x$n")), "$what: the change is written by the next honest write")
            written += "x$n"
        }

        // A server that answers every attempt with `409 stale_state`: a bounded number of attempts, then Contended.
        val before = proxy.requests(WireRoute.ACCOUNT_STATE_PUT, "alice").size
        val stale = proxy.on(WireRoute.ACCOUNT_STATE_PUT, "alice", handler = refuse(409, "stale_state"))
        val w = a.store.update(mark("contended"))
        stale.remove()
        assertEquals(AccountStateWrite.Contended, w)
        val tries = proxy.requests(WireRoute.ACCOUNT_STATE_PUT, "alice").size - before
        assertTrue(tries in 1..10, "a bounded number of attempts: $tries")

        val last = assertIs<AccountStateRead.Ok>(a.store.read()).document
        assertTrue(last.unknown.keys.containsAll(written) && "contended" !in last.unknown, "${last.unknown.keys}")
        assertIs<AccountStateWrite.Written>(a.store.update(mark("contended")))
    }
}
