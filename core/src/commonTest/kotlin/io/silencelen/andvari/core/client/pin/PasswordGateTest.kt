package io.silencelen.andvari.core.client.pin

import io.silencelen.andvari.core.client.pin.GateDecision.PROCEED
import io.silencelen.andvari.core.client.pin.GateDecision.REFUSE_ENTRY
import io.silencelen.andvari.core.client.pin.GateDecision.TRUST_GATE
import kotlin.test.Test
import kotlin.test.assertEquals

/** The rows design §17 lists for `passwordgate.json`, until the vector file lands (then graded row by row). */
class PasswordGateTest {
    private val o = "https://home.example"
    private val baked = "https://vault.andvaripass.com"

    private fun d(
        purpose: GatePurpose, entry: GateEntry, payload: GatePayload? = null, origin: String = o,
        account: String? = "a@x.example", pins: List<GatePin> = emptyList(), session: String? = null, entryNull: Boolean = false,
    ) = PasswordGate.decide(GateInput(purpose, if (entryNull) null else entry, payload, origin, account, pins, session?.let { GateSession(origin, it) }))

    @Test fun deviceLinkOnlyFromItsOwnScreen() {
        for (e in listOf(GateEntry.SCAN_INVITE, GateEntry.PASTE_INVITE, GateEntry.APP_LINK, GateEntry.SERVER_CHOICE))
            assertEquals(REFUSE_ENTRY, d(GatePurpose.DEVICE_LINK, e, GatePayload.D, pins = listOf(GatePin(o, PinRoot.TRUST_GATE))), e.code)
        assertEquals(REFUSE_ENTRY, d(GatePurpose.SIGN_IN, GateEntry.SCAN_INVITE, GatePayload.D, pins = listOf(GatePin(o, PinRoot.BAKED))))
        assertEquals(PROCEED, d(GatePurpose.DEVICE_LINK, GateEntry.CLI_LINK_DEVICE, GatePayload.D, pins = listOf(GatePin(o, PinRoot.TRUST_GATE))))
        assertEquals(REFUSE_ENTRY, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.L))
        assertEquals(REFUSE_ENTRY, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.KIT))
    }

    @Test fun kitOnlyFromTheKitScreen() {
        for (e in GateEntry.entries.filter { it != GateEntry.KIT_RECOVERY_SCREEN })
            assertEquals(REFUSE_ENTRY, d(GatePurpose.KIT_RECOVERY, e, GatePayload.KIT, pins = listOf(GatePin(o, PinRoot.KIT, "a@x.example"))), e.code)
        assertEquals(REFUSE_ENTRY, d(GatePurpose.REGISTER, GateEntry.SCAN_INVITE, GatePayload.KIT, pins = listOf(GatePin(o, PinRoot.BAKED))))
        assertEquals(PROCEED, d(GatePurpose.KIT_RECOVERY, GateEntry.KIT_RECOVERY_SCREEN, GatePayload.KIT, pins = listOf(GatePin(o, PinRoot.KIT, "a@x.example"))))
        assertEquals(TRUST_GATE, d(GatePurpose.KIT_RECOVERY, GateEntry.KIT_RECOVERY_SCREEN, GatePayload.KIT, pins = listOf(GatePin(o, PinRoot.KIT, "b@x.example"))))
        assertEquals(REFUSE_ENTRY, d(GatePurpose.SIGN_IN, GateEntry.KIT_RECOVERY_SCREEN, GatePayload.KIT, pins = listOf(GatePin(o, PinRoot.BAKED))))
    }

    @Test fun kitAndSetupPinsCountOnlyForTheirOwnFlow() {
        assertEquals(TRUST_GATE, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.KIT, "b@x.example"))))
        assertEquals(TRUST_GATE, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.SETUP, "b@x.example"))))
        assertEquals(TRUST_GATE, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.D, pins = listOf(GatePin(o, PinRoot.KIT, "a@x.example"))))
        assertEquals(TRUST_GATE, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.D, pins = listOf(GatePin(o, PinRoot.SETUP, "a@x.example"))))
        assertEquals(PROCEED, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.SETUP, "a@x.example"))))
        assertEquals(TRUST_GATE, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.KIT, "a@x.example"))), "a kit pin never signs in, even its own account")
        assertEquals(PROCEED, d(GatePurpose.KIT_RECOVERY, GateEntry.KIT_RECOVERY_SCREEN, GatePayload.KIT, pins = listOf(GatePin(o, PinRoot.SETUP, "a@x.example"))), "a setup pin of the account proceeds to its kit recovery")
        assertEquals(TRUST_GATE, d(GatePurpose.ASSISTED_RECOVERY, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.SETUP, "a@x.example"))), "a setup pin never proceeds to an assisted recovery")
    }

    @Test fun linkOfferAndEnrolPinsCreateButNeverSignIn() {
        assertEquals(TRUST_GATE, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.ENROL))))
        assertEquals(TRUST_GATE, d(GatePurpose.SIGN_IN, GateEntry.SCAN_INVITE, GatePayload.L, pins = listOf(GatePin(o, PinRoot.LINK_OFFER))))
        assertEquals(PROCEED, d(GatePurpose.REGISTER, GateEntry.SCAN_INVITE, GatePayload.L, pins = listOf(GatePin(o, PinRoot.LINK_OFFER))))
        assertEquals(PROCEED, d(GatePurpose.REGISTER, GateEntry.APP_LINK, GatePayload.L, pins = listOf(GatePin(o, PinRoot.ENROL))))
        assertEquals(TRUST_GATE, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.D, pins = listOf(GatePin(o, PinRoot.LINK_OFFER))))
        assertEquals(TRUST_GATE, d(GatePurpose.REGISTER, GateEntry.SERVER_CHOICE))
    }

    @Test fun passwordPins() {
        assertEquals(PROCEED, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.D, origin = baked, pins = listOf(GatePin(baked, PinRoot.BAKED))))
        assertEquals(TRUST_GATE, d(GatePurpose.DEVICE_LINK, GateEntry.LINK_DEVICE_SCREEN, GatePayload.D))
        assertEquals(PROCEED, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.TRUST_GATE))))
        assertEquals(TRUST_GATE, d(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, pins = listOf(GatePin("https://other.example", PinRoot.TRUST_GATE))), "a pin of another origin")
        assertEquals(PROCEED, d(GatePurpose.ASSISTED_RECOVERY, GateEntry.SERVER_CHOICE, pins = listOf(GatePin(o, PinRoot.BAKED))))
    }

    @Test fun reauthWithASessionForThatAccount() {
        val pinned = listOf(GatePin(o, PinRoot.TRUST_GATE))
        assertEquals(PROCEED, d(GatePurpose.REAUTH, GateEntry.SERVER_CHOICE, session = "a@x.example", pins = pinned))
        assertEquals(REFUSE_ENTRY, d(GatePurpose.REAUTH, GateEntry.SERVER_CHOICE, session = "b@x.example", pins = pinned), "a session of another account refuses the re-authentication")
        // Design §4.4 "No credential goes to an origin without a pin in force": a session alone is not enough.
        assertEquals(REFUSE_ENTRY, d(GatePurpose.REAUTH, GateEntry.SERVER_CHOICE, session = "a@x.example"))
    }
}
