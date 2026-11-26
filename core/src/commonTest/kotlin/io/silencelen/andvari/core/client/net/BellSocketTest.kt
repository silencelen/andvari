package io.silencelen.andvari.core.client.net

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.BellLink
import io.silencelen.andvari.core.client.items.BellSocket
import io.silencelen.andvari.core.client.onboard.KeptSetup
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The event bell's socket from the [Dialer] (spec 03 §6, design §4.4): opened only for its own origin, only for an
 * address the origin grammar accepts, and only while the pin there is in force; asked again before every frame. What
 * reaches the socket below the guard (and, for the dialer, the HTTP engine) is recorded, so "nothing is sent" is seen.
 */
class BellSocketTest {
    private val origin = "https://home.example"

    private fun pin(o: String = origin) = CardPin("0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", 1, "a".repeat(64), o, "Home", "private",
        "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f", "A".repeat(43), "none", PinRoot.TRUST_GATE, null, "b".repeat(64))

    /** A socket that always opens, records the address it was given and what is sent, and serves [incoming]. */
    private class Recording : PlatformBellSocket {
        val opened = ArrayList<String>()
        val sent = ArrayList<String>()
        val incoming = ArrayDeque<String>()
        override suspend fun <T> connect(url: String, headers: Map<String, String>, maxMessageBytes: Int, block: suspend (BellLink) -> T): T {
            opened += url
            return block(object : BellLink {
                override suspend fun send(text: String): Boolean { sent += text; return true }
                override suspend fun receive(): String? = incoming.removeFirstOrNull()
            })
        }
    }

    private fun guarded(state: MemoryDeviceState, inner: PlatformBellSocket, o: String = origin): BellSocket = DialedBellSocket(o, OriginGuard(PinStore(state)), inner, "linux")

    @Test fun aPinInForceOpensTheSocketForItsOwnOriginOnly() = runBlocking<Unit> {
        val state = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val inner = Recording().also { it.incoming += """{"type":"pong"}""" }
        val s = guarded(state, inner)
        val got = s.open(origin, "ticketticketticket") { link -> link.send("""{"type":"ping"}""") to link.receive() }
        assertEquals(true to """{"type":"pong"}""", got)
        assertEquals(listOf("wss://home.example/api/v1/events?ticket=ticketticketticket"), inner.opened)
        assertEquals(listOf("""{"type":"ping"}"""), inner.sent)
        // Another origin than the one the socket was made for opens nothing, pinned or not.
        PinStore(state).put(pin("https://other.example"))
        assertNull(s.open("https://other.example", "ticketticketticket") { "opened" })
        assertEquals(1, inner.opened.size)
    }

    @Test fun noPinAForkADamagedPinOrOnlyASetupOfferOpensNothing() = runBlocking<Unit> {
        val inner = Recording()
        // No pin record at all.
        assertNull(guarded(MemoryDeviceState(), inner).open(origin, "ticketticketticket") { "opened" })
        // A kept setup offer lets the setup root's requests carry a credential, but opens no socket.
        val setup = MemoryDeviceState().also {
            it.set("ovh.setup|$origin", WireJson.json.encodeToString(KeptSetup.serializer(), KeptSetup(origin, "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e", "Home", "private", "none")))
        }
        assertTrue(OriginGuard(PinStore(setup)).mayDial(origin), "the setup offer counts for requests")
        assertNull(guarded(setup, inner).open(origin, "ticketticketticket") { "opened" })
        // A forked pin, and a damaged one.
        val forked = MemoryDeviceState().also { PinStore(it).put(pin()); PinStore(it).markForked(pin()) }
        assertNull(guarded(forked, inner).open(origin, "ticketticketticket") { "opened" })
        val damaged = MemoryDeviceState().also { it.set(PinStore.KEY_PREFIX + origin, "{not a pin") }
        assertNull(guarded(damaged, inner).open(origin, "ticketticketticket") { "opened" })
        assertTrue(inner.opened.isEmpty())
    }

    @Test fun anAddressTheOriginGrammarRefusesOpensNothingEvenWithAPinRecord() = runBlocking<Unit> {
        val inner = Recording()
        for (bad in listOf("https://10.0.0.1", "https://example.123", "http://home.example", "https://home.example/path", "wss://home.example")) {
            val state = MemoryDeviceState()
            // Written as a store would hold it, whatever the store's own checks say about it.
            PinStore(state).put(pin(bad))
            assertTrue(!OriginGuard(PinStore(state)).mayOpenSocket(bad), bad)
            assertNull(guarded(state, inner, bad).open(bad, "ticketticketticket") { "opened" }, bad)
        }
        assertTrue(inner.opened.isEmpty())
    }

    @Test fun onceThePinStopsNothingMoreIsSentOnAnOpenSocket() = runBlocking<Unit> {
        val state = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val inner = Recording().also { it.incoming += "one"; it.incoming += "two" }
        val result = guarded(state, inner).open(origin, "ticketticketticket") { link ->
            assertTrue(link.send("first"))
            assertEquals("one", link.receive())
            PinStore(state).markForked(pin())
            listOf(link.send("second"), link.receive())
        }
        assertEquals(listOf(false, null), result)
        assertEquals(listOf("first"), inner.sent, "nothing after the fork")
        // "Forget this server" on an open socket: the same.
        val s2 = MemoryDeviceState().also { PinStore(it).put(pin()) }
        val inner2 = Recording()
        guarded(s2, inner2).open(origin, "ticketticketticket") { link ->
            PinStore(s2).remove(origin)
            assertTrue(!link.send("after forget"))
        }
        assertTrue(inner2.sent.isEmpty())
    }

    @Test fun theDialersSocketUsesItsOwnEngineAndDialsNothingWithoutAPin() = runBlocking<Unit> {
        val seen = ArrayList<String>()
        val http = HttpClient(MockEngine { req ->
            seen += "${req.url.protocol.name}://${req.url.host}${req.url.encodedPath}?${req.url.encodedQuery} ${req.headers["X-Andvari-Client"]}"
            respond("no upgrade", HttpStatusCode.BadRequest)
        })
        val state = MemoryDeviceState()
        val dialer = Dialer(PinStore(state), http, "linux")
        assertNull(dialer.bellSocket(origin).open(origin, "ticketticketticket") { "opened" })
        assertTrue(seen.isEmpty(), "no pin: nothing reached the engine")
        PinStore(state).put(pin())
        // The mock engine cannot upgrade, so the socket does not open; what matters is where the attempt went.
        assertNull(dialer.bellSocket(origin).open(origin, "ticket+/ticketticket") { "opened" })
        assertEquals(1, seen.size, "a pin in force: the attempt reached the dialer's engine")
        assertTrue(seen.single().startsWith("wss://home.example/api/v1/events?ticket=ticket%2B%2Fticketticket linux/"), seen.single())
        assertNull(dialer.bellSocket(origin).open("https://other.example", "ticketticketticket") { "opened" })
        assertEquals(1, seen.size)
    }
}
