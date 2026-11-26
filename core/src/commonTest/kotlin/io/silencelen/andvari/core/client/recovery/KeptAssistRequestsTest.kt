package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A host with a second store (the command-line tool's secure store) forgets the assisted-recovery request it keeps
 * there for one server ([KeptAssistRequests.forget]): the engine's own wipe cannot reach that store.
 */
class KeptAssistRequestsTest {
    private val a = "https://a.example"
    private val b = "https://b.example"
    private val old = "https://old.example"
    private val instA = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
    private val instB = "1c7f4d3f-5e6b-4c8d-9eaf-1a2b3c4d5e6f"
    private val c0A = "a".repeat(64)
    private val c0B = "b".repeat(64)

    private fun b64(n: Int, v: Int) = Bytes.toB64(ByteArray(n) { v.toByte() })

    private fun req(origin: String, inst: String?, c0: String?, v: Int = 1) =
        KeptAssistRequest(origin, "p@example.org", b64(16, v), b64(32, v), b64(32, v + 1), b64(32, v + 2), createdAt = 1_000, instanceId = inst, card0Hash = c0)

    private fun pin(origin: String, inst: String, c0: String) =
        CardPin(inst, 3, "c".repeat(64), origin, "Home", "private", "op", b64(32, 9), "none", PinRoot.TRUST_GATE, null, c0)

    private fun store(vararg kept: KeptAssistRequest) = MemoryDeviceState().also { s ->
        val r = AssistRequests(s, { 2_000 })
        kept.forEach { r.put(it) }
    }

    @Test fun theRequestKeptForOneOriginGoesAndAnotherOriginsStays() {
        val s = store(req(a, instA, c0A), req(b, instB, c0B, 5))
        val bBefore = s.get("ovh.assist|$b")
        assertEquals(1, KeptAssistRequests.forget(s, a))
        assertNull(s.get("ovh.assist|$a"))
        assertEquals(bBefore, s.get("ovh.assist|$b"), "another server's request stays, byte for byte")
        assertEquals(listOf(b), WireJson.json.decodeFromString(ListSerializer(String.serializer()), s.get("ovh.assist.index")!!), "the index no longer names it")
        assertEquals(0, KeptAssistRequests.forget(s, a), "again: nothing left")
    }

    /**
     * "Forget this server" for a FORKED server, as the documentation says to do it: the issuer is the pin in force or
     * forked (`CardTrust.pinForForget`), read before the wipe. `pinFor` answers null under a fork, so a host that read it
     * would keep the forked server's request kept under its old address.
     */
    @Test fun aForkedServersRequestGoesEverywhereWhenTheIssuerIsThePinInForceOrForked() {
        val pins = io.silencelen.andvari.core.client.pin.PinStore(MemoryDeviceState())
        val trust = io.silencelen.andvari.core.client.pin.CardTrust(pins, { _, _ -> io.silencelen.andvari.core.client.pin.ChainCheck.Refused("unused") },
            { error("nothing is dialled") }, io.silencelen.andvari.core.crypto.createCryptoProvider(), null, false)
        val p = pin(a, instA, c0A)
        pins.put(p)
        assertEquals(c0A, trust.pinForForget(a)?.card0Hash, "in force")
        assertEquals(true, pins.markForked(p))
        assertNull(trust.pinFor(a), "pinFor says nothing under a fork")
        val issuer = assertNotNull(trust.pinForForget(a), "the forked pin is still the issuer")
        assertNull(trust.pinForForget(b), "no pin")

        // The request is kept under this address and, from before a followed move, under the old one.
        val s = store(req(a, instA, c0A), req(old, instA, c0A, 3), req(b, instB, c0B, 5))
        val withPinFor = MemoryDeviceState().also { t -> listOf(a, old, b).forEach { o -> s.get("ovh.assist|$o")?.let { t.set("ovh.assist|$o", it) } }; s.get("ovh.assist.index")?.let { t.set("ovh.assist.index", it) } }
        assertEquals(1, KeptAssistRequests.forget(withPinFor, a, trust.pinFor(a)), "the old reading leaves the moved request behind")
        assertNotNull(withPinFor.get("ovh.assist|$old"))
        assertEquals(2, KeptAssistRequests.forget(s, a, issuer))
        assertNull(s.get("ovh.assist|$old"))
        assertNotNull(s.get("ovh.assist|$b"), "another server's request stays")
        trust.forgetServer(a)
        assertNull(trust.pinForForget(a), "forgotten")
    }

    @Test fun aRecordThatDoesNotReadOrPredatesTheBindingGoesToo() {
        val s = store(req(b, instB, c0B, 5))
        s.set("ovh.assist|$a", "{not json")
        assertEquals(1, KeptAssistRequests.forget(s, a))
        assertNull(s.get("ovh.assist|$a"))
        val legacy = store(req(a, null, null))
        assertEquals(1, KeptAssistRequests.forget(legacy, a))
        assertNull(legacy.get("ovh.assist|$a"))
    }

    @Test fun withTheIssuersPinARequestTheServerLeftUnderAnOlderAddressGoesAsWell() {
        // The request was made at the old address; a followed move took the pin to [a] but not this separate store.
        val s = store(req(old, instA, c0A), req(b, instB, c0B, 5))
        assertEquals(0, KeptAssistRequests.forget(s, a), "without the pin only the origin's own key is looked at")
        assertNotNull(s.get("ovh.assist|$old"))
        assertEquals(1, KeptAssistRequests.forget(s, a, pin(a, instA, c0A)))
        assertNull(s.get("ovh.assist|$old"), "bound to the forgotten server: it goes")
        assertNotNull(s.get("ovh.assist|$b"), "bound to another server: it stays")
        // Another server's pin at the same address does not take a request of the old server with it.
        val t = store(req(old, instA, c0A))
        assertEquals(0, KeptAssistRequests.forget(t, a, pin(a, instA, c0B)))
        assertNotNull(t.get("ovh.assist|$old"))
    }
}
