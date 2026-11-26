package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.account.CardChangeResult
import io.silencelen.andvari.core.client.account.WireOperatorCards
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.refuse
import io.silencelen.andvari.hostile.proxy.set
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The operator's card change (`PUT /instance/card`, spec 03 §17.2; design §4.3, §4.4; the last row, the most dangerous
 * left after the rename), through the shared code's own path (`WireOperatorCards`), against the real server. The
 * property: no answer moves a pin. The operator's device and every member's pin a card only through the chain the
 * server serves and the device verifies; an answer that names another card than the one signed is refused as a
 * mismatch, and one that claims a card stored that the server never stored is at most "stored, not yet served", never
 * "changed".
 */
class InstanceCardLiesTest {
    private val crypto = createCryptoProvider()

    @Test fun aCardUploadAnswerThatLiesNeverMovesAPinPastTheChainTheServerServes() = world {
        val oh = operator()
        val ah = member("alice")
        val cards = oh.operatorCards(assertNotNull(oh.session(origin)))
        fun pw() = Steps.PASSWORD.toCharArray()
        suspend fun opPin() = assertIs<CardStatus.Ok>(oh.trust.refresh(origin)).pin
        suspend fun alicePin() = assertIs<CardStatus.Ok>(ah.trust.refresh(origin)).pin

        // An honest change first, for its answer.
        assertIs<CardChangeResult.Changed>(cards.rename("Home 1", pw()))
        val earlier = Json.parseToJsonElement(assertNotNull(proxy.last(WireRoute.INSTANCE_CARD_PUT, "op")?.upstream).text)
        assertEquals("Home 1", alicePin().name)

        // Stored, then answered with another card's seq or hash (W) or the earlier upload's answer (R): a mismatch, and
        // every device pins the stored card through the chain, as the server serves it.
        val stored: List<Pair<String, Handler>> = listOf(
            "a seq far above (W)" to editAnswer { it.set("seq", 1_000_000L) },
            "another card's hash (W)" to editAnswer { it.set("hash", "ab".repeat(32)) },
            "an earlier upload's answer (R)" to Handler { x -> x.forward(); Resp.json(200, earlier) },
        )
        for ((i, pair) in stored.withIndex()) {
            val (what, lie) = pair
            val name = "Home ${i + 2}"
            val rule = proxy.on(WireRoute.INSTANCE_CARD_PUT, "op", handler = lie)
            val got = cards.rename(name, pw())
            rule.remove()
            assertEquals(WireOperatorCards.CARD_MISMATCH, assertIs<CardChangeResult.Refused>(got, what).code, what)
            assertEquals(name, opPin().name, "$what: the operator's device pins the stored card, through the chain")
            assertEquals(name, alicePin().name, "$what: and so does a member's")
        }
        val held = opPin()

        // Not stored, answered with a shape or status the route never gives (X): never "changed", and no pin moves.
        val notStored: List<Pair<String, Handler>> = listOf(
            "ok (X)" to answer { Resp.ok() },
            "{} (X)" to answer { Resp.json(200, Json.parseToJsonElement("{}")) },
            "a 500 (X)" to refuse(500, "internal"),
        )
        for ((what, lie) in notStored) {
            val rule = proxy.on(WireRoute.INSTANCE_CARD_PUT, "op", handler = lie)
            val got = cards.rename("never stored", pw())
            rule.remove()
            assertFalse(got is CardChangeResult.Changed || got is CardChangeResult.Stored, "$what: $got")
            assertEquals(held.hash, opPin().hash, what)
            assertEquals(held.hash, alicePin().hash, what)
        }

        // Not stored, answered as done with the very seq and hash of the card the device signed (W): "stored, not yet
        // served" at most, never "changed", and no pin moves (the stated limit: the device cannot tell at once).
        val done = proxy.on(WireRoute.INSTANCE_CARD_PUT, "op", handler = Handler { x ->
            val frame = Bytes.fromB64(assertNotNull(x.req.json?.get("card")).jsonPrimitive.content)
            Resp.json(200, Json.parseToJsonElement("""{"seq":${held.seq + 1},"hash":"${SignedFrame.hash(crypto, frame)}"}"""))
        })
        val claimed = cards.rename("claimed only", pw())
        done.remove()
        assertIs<CardChangeResult.Stored>(claimed, "$claimed")
        assertEquals(held.hash, opPin().hash, "done, never stored: the operator's pin stays")
        assertEquals(held.hash, alicePin().hash, "and a member's")

        // The next honest change lands, on every device (an hour on: the route's own rate limit has refilled).
        server.advance(3_600_000L)
        assertIs<CardChangeResult.Changed>(cards.rename("Home at last", pw()))
        assertEquals("Home at last", alicePin().name)
        assertTrue(proxy.requests(WireRoute.INSTANCE_CARD_PUT, "alice").isEmpty())
    }
}
