package io.silencelen.andvari.core.client.pin

/**
 * The password rule (design §4.4, T2-B1) and the device-link entry rule (design §8.2 step 0, §12.1,
 * FS-B1) as one pure decision, pinned row by row by `spec/test-vectors/passwordgate.json`.
 *
 * A client sends a value derived from an account's secrets — prelogin for its email, `authKey`,
 * `currentAuthKey`, `recoveryAuthKey`, a TOTP code, or a device-link claim — ONLY after
 * [GateDecision.PROCEED]. Every native client and the CLI call this one function; no flow in the engine
 * sends such a value without it.
 */
object PasswordGate {
    /**
     * The decision for [input]. Pure and total. Order:
     * 1. **Entry** (design §8.2 step 0, §12.1, FS-B1): a `/d` link or a device link only from
     *    "Link from your other device" or `andvari-cli link-device`; a kit, or kit recovery, only from
     *    "Scan your recovery kit"; those two screens take nothing else. Anything else is [GateDecision.REFUSE_ENTRY].
     * 2. **Re-authentication** needs a session for that account at that origin AND a pin in force there (design §4.4
     *    "No credential goes to an origin without a pin in force"); without both it is [GateDecision.REFUSE_ENTRY].
     *    With both, every purpose proceeds. A session at an origin with no pin record counts as no session for the
     *    other purposes: they take the pin rule below (the Trust Gate first).
     * 3. **Register** proceeds with any pin of the origin (any root may CREATE an account); with none, the
     *    Trust Gate (a typed address).
     * 4. **Everything else needs a password pin** for its purpose (design §4.4): `baked` and `trust_gate`
     *    pins for any account and purpose; a `kit` pin only for recovering the kit's own account; a
     *    `setup` pin only for signing in to, or kit-recovering, the operator account it enrolled;
     *    `link_offer` and `enrol` pins never. Without one, the Trust Gate.
     *
     * A device keeps at most one pin per origin (design §4.4); with several, any qualifying one counts.
     */
    fun decide(input: GateInput): GateDecision {
        if (!entryAccepts(input)) return GateDecision.REFUSE_ENTRY
        // A forked or damaged pin stops the origin for every purpose until "Forget this server" (design §4.4).
        if (input.pins.any { it.origin == input.origin && it.blocked }) return GateDecision.REFUSE_ENTRY
        val pins = input.pins.filter { it.origin == input.origin }
        val s = input.session
        // Every pin left here is in force (a blocked one refused above): a session counts only beside one (design §4.4).
        val hasSession = s != null && input.account != null && s.origin == input.origin && s.account == input.account && pins.isNotEmpty()
        if (input.purpose == GatePurpose.REAUTH) return if (hasSession) GateDecision.PROCEED else GateDecision.REFUSE_ENTRY
        if (hasSession) return GateDecision.PROCEED
        if (input.purpose == GatePurpose.REGISTER) {
            return if (pins.isNotEmpty()) GateDecision.PROCEED else GateDecision.TRUST_GATE
        }
        return if (pins.any { isPasswordPin(it, input.purpose, input.account) }) GateDecision.PROCEED else GateDecision.TRUST_GATE
    }

    /**
     * What the device may do with [origin] (design §4.4 "A fork stops traffic, not reading"), from the same [pins] the
     * decision takes: [OriginAccess.FORKED] refuses every purpose above but leaves an offline unlock of the device's own
     * copy, reading, copying, filling and export; [OriginAccess.BLOCKED] (damaged) leaves nothing.
     */
    fun access(origin: String, pins: List<GatePin>): OriginAccess {
        val here = pins.filter { it.origin == origin && it.blocked }
        return when {
            here.any { it.damaged } -> OriginAccess.BLOCKED
            here.isNotEmpty() -> OriginAccess.FORKED
            else -> OriginAccess.OPEN
        }
    }

    /** True when [pin] lets [purpose] send a secret-derived value for [account] (design §4.4, FS-B1). */
    fun isPasswordPin(pin: GatePin, purpose: GatePurpose, account: String?): Boolean = when (pin.root) {
        PinRoot.BAKED, PinRoot.TRUST_GATE -> true
        PinRoot.KIT -> purpose == GatePurpose.KIT_RECOVERY && account != null && pin.account == account
        PinRoot.SETUP -> (purpose == GatePurpose.SIGN_IN || purpose == GatePurpose.KIT_RECOVERY) && account != null && pin.account == account
        PinRoot.LINK_OFFER, PinRoot.ENROL -> false
    }

    private fun entryAccepts(input: GateInput): Boolean {
        val deviceLinkEntry = input.entry == GateEntry.LINK_DEVICE_SCREEN || input.entry == GateEntry.CLI_LINK_DEVICE
        val kitEntry = input.entry == GateEntry.KIT_RECOVERY_SCREEN
        when (input.payload) {
            GatePayload.D -> if (!deviceLinkEntry) return false
            GatePayload.KIT -> if (!kitEntry) return false
            GatePayload.L -> if (deviceLinkEntry || kitEntry) return false
            null -> {}
        }
        if (input.purpose == GatePurpose.DEVICE_LINK && !deviceLinkEntry) return false
        if (input.purpose == GatePurpose.KIT_RECOVERY && !kitEntry) return false
        // The two dedicated screens start only their own flow.
        if (deviceLinkEntry && input.purpose != GatePurpose.DEVICE_LINK) return false
        if (kitEntry && input.purpose != GatePurpose.KIT_RECOVERY) return false
        return true
    }
}

/** What the person is doing (`purpose` in passwordgate.json). */
enum class GatePurpose(val code: String) {
    SIGN_IN("sign_in"),
    DEVICE_LINK("device_link"),
    KIT_RECOVERY("kit_recovery"),
    ASSISTED_RECOVERY("assisted_recovery"),
    REGISTER("register"),
    REAUTH("reauth"),
}

/** Where the flow was started (`entry`). */
enum class GateEntry(val code: String) {
    LINK_DEVICE_SCREEN("link_device_screen"),
    KIT_RECOVERY_SCREEN("kit_recovery_screen"),
    SCAN_INVITE("scan_invite"),
    PASTE_INVITE("paste_invite"),
    APP_LINK("app_link"),
    CLI_LINK_DEVICE("cli_link_device"),
    SERVER_CHOICE("server_choice"),
}

/** What was scanned or pasted, if anything (`payload`): an `/l` link, a `/d` link, or a kit. */
enum class GatePayload(val code: String) { L("l"), D("d"), KIT("kit") }

/**
 * One pin this device holds (`pins[]`): its origin, root and, for a kit or setup pin, the account
 * (`emailNorm`) it is limited to. [blocked] marks a forked or damaged pin: the password rule refuses everything
 * there. [damaged] tells the two apart for the layers above ([PasswordGate.access]): a fork stops traffic but not
 * reading what the device holds; a damaged (or unreadable) pin blocks both.
 */
data class GatePin(val origin: String, val root: PinRoot, val account: String? = null, val blocked: Boolean = false, val damaged: Boolean = false)

/**
 * One decision request (a passwordgate.json row's input).
 */
data class GateInput(
    val purpose: GatePurpose,
    /** Null where the flow has no entry screen (a re-authentication inside a session). */
    val entry: GateEntry?,
    val payload: GatePayload?,
    val origin: String,
    /** The account's `emailNorm`; null for a device link (the account is not known before `outer`). */
    val account: String?,
    val pins: List<GatePin>,
    val session: GateSession? = null,
)

/** A session this device holds: its origin and account (`emailNorm`). */
data class GateSession(val origin: String, val account: String)

/** The three answers. */
enum class GateDecision(val code: String) {
    /** The secret-derived value may be sent to the origin. */
    PROCEED("proceed"),

    /** Show the Trust Gate for the origin first; after it, the pin is a password pin. */
    TRUST_GATE("trust_gate"),

    /** This entry does not take this payload or purpose: start nothing, send nothing (design §12.1). */
    REFUSE_ENTRY("refuse_entry"),
}
