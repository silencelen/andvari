package io.silencelen.andvari.core.client.pin

/**
 * Where a pin came from (design §4.4). The root decides what the pin is good for under the password
 * rule ([PasswordGate]): `BAKED` and `TRUST_GATE` pins are password pins for any account; a `KIT` pin
 * only for recovering the kit's own account; a `SETUP` pin only for the operator account it enrolled;
 * `LINK_OFFER` and `ENROL` pins are enough to CREATE an account, never to sign in to one.
 *
 * A device link is not a root: it only confirms a pin made before the claim (design §4.4, §8.2 step 8).
 */
enum class PinRoot(val code: String) {
    BAKED("baked"),
    LINK_OFFER("link_offer"),
    SETUP("setup"),
    KIT("kit"),
    TRUST_GATE("trust_gate"),
    ENROL("enrol"),
}

/**
 * The pinned card record of one origin namespace (design §4.4): the newest card this device verified
 * forward from its first pin, and how that first pin was made.
 *
 * Every field came out of a card frame this device verified (signature chain from the root, design
 * §4.2); none is ever copied from a served JSON field. [rootAccount] names the account a `KIT` or `SETUP`
 * pin is limited to (its `userId` for setup, its `emailNorm` for a kit).
 */
data class CardPin(
    val instanceId: String,
    val seq: Long,
    /** `hex64` frame hash of the pinned card. */
    val hash: String,
    val origin: String,
    /** The card's `name` as decoded plain text (rendered only as plain text, always with [origin]). */
    val name: String,
    /** `public` or `private`; only this value decides kind-specific rules (design §4.4, §7.7). */
    val kind: String,
    val operator: String,
    /** `b64_32` Ed25519. */
    val operatorSignKey: String,
    /** `hex64n` */
    val recoveryFp: String,
    val root: PinRoot,
    val rootAccount: String? = null,
    /** `hex64` of card 0 as this device verified it (the kit's `card0Hash`, design §10). */
    val card0Hash: String,
)

/** What a chain refresh found (design §4.4). Each case names the copy the apps show; nothing here is free text. */
sealed class CardStatus {
    /**
     * The chain extends the pin (or equals it); [pin] is the newest verified card, now pinned. [newKitDue] is true only on
     * the answer of [InstanceTrust.followMove]: the namespace moved to a new origin, and a recovery kit names the address it
     * was made for (design §4.4, §10), so the person should make a new kit.
     */
    data class Ok(val pin: CardPin, val newKitDue: Boolean = false) : CardStatus()

    /**
     * The chain does not contain the pinned hash at the pinned `seq`: STOP using the instance (no sign-in,
     * sync or writes) until "Forget this server". Also a new card 0 after an operator reset (design §4.6).
     */
    data class Fork(val pinned: CardPin) : CardStatus()

    /** The chain ends below the pin (or is empty while a pin exists): keep the pin, show "older version", retry. */
    data class Withheld(val pinned: CardPin, val servedSeq: Long?) : CardStatus()

    /**
     * The newest verified card moved the origin (and kept the `kind`; a card that changes both is a
     * [KindChanged]). A one-tap prompt moves the namespace with no Trust Gate, EXCEPT for the baked public
     * instance in a store build ([storeBuildMustUpdate]): "Update andvari". Only the engine makes one, and
     * [InstanceTrust.followMove] re-judges the served chain rather than trusting these fields.
     */
    class Moved internal constructor(val pinned: CardPin, val newest: CardPin, val storeBuildMustUpdate: Boolean) : CardStatus()

    /**
     * The newest verified card changed `kind` (with or without a move). Never followed silently: the Trust
     * Gate names the change (or "Update andvari" for the baked instance in a store build); until confirmed
     * the old kind stays. Only the engine makes one; [InstanceTrust.acceptKindChange] re-judges.
     */
    class KindChanged internal constructor(val pinned: CardPin, val newest: CardPin, val storeBuildMustUpdate: Boolean) : CardStatus()

    /**
     * §4.4 "A move never replaces a pin that already exists for the new origin" (`pin_conflict`): [newest]
     * names an origin this device already pins (or has blocked). Nothing changed. Only the engine makes one.
     */
    class PinConflict internal constructor(val pinned: CardPin, val newest: CardPin) : CardStatus() {
        val verdict: String get() = PIN_CONFLICT
    }

    /** A card failed verification (a shared verifier's verdict code, e.g. `bad_signature`, `instance_mismatch`); the pin stays. */
    data class Refused(val pinned: CardPin?, val verdict: String) : CardStatus()

    /** The chain could not be fetched; the pin stays and the client retries on the next probe. */
    data object Unreachable : CardStatus()
}

/**
 * What a first pin attempt found (design §4.4 roots). A first pin is never made from a served value
 * alone: the baked root checks card 0 against `PUBLIC_INSTANCE.card0Hash`, a kit against the kit's
 * `card0Hash`, a link offer against the offer's signed `cardHash`, and a typed address or an enrol link
 * shows the Trust Gate first.
 */
sealed class FirstPin {
    /** Pinned. [handle] names exactly this pin attempt, for [InstanceTrust.dropPinMade]. */
    class Pinned internal constructor(val pin: CardPin, val handle: PinHandle) : FirstPin()

    /**
     * The person must confirm the Trust Gate before the pin exists. [operatorShortFp] is the operator key's
     * 32-hex short form; [name] is shown "(as the server names itself)".
     */
    class NeedsTrustGate internal constructor(val origin: String, val name: String, val operatorShortFp: String, val wording: TrustGateWording, val confirm: TrustGateTicket) : FirstPin()

    /** The anchor did not match (baked or kit `card0Hash`, offer `cardHash`), or the chain failed: nothing pinned. */
    data class Refused(val reason: String) : FirstPin()

    /** A kit made before an operator reset: the Trust Gate with the "identity changed since your kit" warning (design §4.4). */
    class KitAnchorMismatch internal constructor(val gate: NeedsTrustGate) : FirstPin()

    /**
     * §2.4 pinning, the first verdict (`origin_mismatch`): the newest verified card names [cardOrigin], not
     * [dialedOrigin], the origin this device dialed and holds no pin for (cards are public, so any server can
     * serve another instance's genuine chain). Nothing is pinned. The app may offer to dial [cardOrigin]
     * instead; every check then runs again from the start there (a kit's `card0Hash` still anchors it, a
     * typed address passes the Trust Gate for the new origin). Screens name [dialedOrigin], whole.
     */
    class OriginMismatch internal constructor(val dialedOrigin: String, val cardOrigin: String) : FirstPin() {
        val verdict: String get() = ORIGIN_MISMATCH
    }

    /**
     * Under an existing pin the served chain moved the origin or changed the `kind` ([status] is a
     * [CardStatus.Moved] or [CardStatus.KindChanged]). §2.4: it is handled as a move first
     * ([InstanceTrust.followMove], [InstanceTrust.acceptKindChange]) and the root, link or kit is then
     * opened again. Nothing changed.
     */
    class PinChanged internal constructor(val status: CardStatus) : FirstPin()

    /**
     * The origin is blocked (§4.4) and nothing changed: [state] is [PinState.Forked] (a fork, durable until
     * "Forget this server"; also when this call found it) or [PinState.Damaged] (a pin record that does not decode).
     */
    class Blocked internal constructor(val state: PinState) : FirstPin() {
        val verdict: String get() = if (state is PinState.Damaged) "damaged" else "fork"
    }

    /**
     * §4.4 `pin_conflict`: the call would swap the chain an existing pin holds (a Trust Gate ticket for
     * another chain, a setup card 0 of another chain). [pinned] stays as it was.
     */
    class PinConflict internal constructor(val pinned: CardPin) : FirstPin() {
        val verdict: String get() = PIN_CONFLICT
    }

    data object Unreachable : FirstPin()
}

/**
 * The pin a first-pin call made or kept. [madeNow] is true only when no pin existed for the origin before
 * the call, so dropping it can never remove a pin the device already had (design §8.2 step 8).
 */
class PinHandle internal constructor(internal val origin: String, internal val hash: String, internal val madeNow: Boolean)

/** What the device holds for an origin (design §4.4). */
sealed class PinState {
    data object None : PinState()

    /** In force. */
    class Pinned internal constructor(val pin: CardPin) : PinState()

    /** A fork was seen: durable, and the origin is stopped until "Forget this server". */
    class Forked internal constructor(val pin: CardPin) : PinState()

    /**
     * The stored record does not decode, or cannot be read at all (a storage error): the origin is blocked, never read
     * as "no pin" (design §4.4 "A trust record that cannot be read is not an empty one"). A record that does not decode
     * stays so until "Forget this server"; nothing is ever written over one that could not be read.
     */
    data object Damaged : PinState()
}

/**
 * What this device may do with an origin and what it holds from it (design §4.4 "A fork stops traffic, not reading").
 * The layers above key on this, not on [PinState] alone:
 * - [OPEN]: no pin (the Trust Gate's public card fetch) or a pin in force: traffic as the flows decide.
 * - [FORKED]: nothing is sent to the origin, nothing from it is accepted, nothing is written, the password rule
 *   refuses; BUT what the device already holds stays readable: an offline unlock of the device's own copy, reading,
 *   copying, filling and export, with the warning in view.
 * - [BLOCKED]: the pin is damaged or cannot be read: the device can check nothing it holds against anything, so it
 *   stays blocked, reading included.
 * - [MOVING]: a move to this origin was followed but the host has not moved its platform namespace yet
 *   ([NamespaceMover], [CardTrust.finishMove]): nothing is sent to the origin and nothing is written under it. What
 *   the device holds is still in the namespace of the OLD origin, so nothing is read under the new one either; the app
 *   shows [MOVE_UNFINISHED] and offers [CardTrust.finishMove] again.
 */
enum class OriginAccess(val code: String) {
    OPEN("open"),
    FORKED("fork"),
    BLOCKED("damaged"),
    MOVING(MOVE_UNFINISHED);

    /** A request may be sent to the origin. */
    val mayDial: Boolean get() = this == OPEN

    /** The device may open and read its own copy of what it holds from the origin (no traffic). */
    val mayReadLocal: Boolean get() = this == OPEN || this == FORKED
}

/**
 * The host's side of a followed move (design §4.4 "A namespace's trust records move with its pin"). On a platform that
 * keeps a device's state in a directory per (origin, user) (Android, the iPhone), [CardTrust] moves its records inside
 * one [io.silencelen.andvari.core.client.DeviceState]; the host moves the directory.
 */
fun interface NamespaceMover {
    /**
     * Move the platform namespace of [from] to [to]; true when it is there now. Called right after the pin and the
     * engine's records moved and before anything is sent to [to]. Called again by [CardTrust.finishMove] after a
     * failure or a crash, so it must be idempotent: a namespace already at [to] with nothing left at [from] is success.
     * False or an exception is a failure: the origin stays [OriginAccess.MOVING] and nothing is sent to [to].
     */
    fun onMoved(from: String, to: String): Boolean
}

/**
 * [CardStatus.Refused]'s verdict (its `pinned` is the pin at the NEW origin), [FirstPin.Refused]'s reason and
 * [OriginAccess.MOVING]'s code: the move was followed but the host's [NamespaceMover] has not succeeded yet.
 */
const val MOVE_UNFINISHED = "move_unfinished"

/** The §2.4 / §4.4 verdict string of [FirstPin.OriginMismatch]. */
const val ORIGIN_MISMATCH = "origin_mismatch"

/**
 * What [CardTrust.forgetServer] did ("Forget this server", design §4.4 and §12.3: it removes the namespace's card pin
 * and data). Local only: nothing is sent.
 */
sealed class ServerForgotten {
    /** The pin (with its fork or move mark) and every record this device kept for the origin and its accounts are gone. */
    data object Done : ServerForgotten()

    /**
     * The pin is gone, but some records could not be listed or deleted ([reason]: [CANNOT_LIST] or [CANNOT_DELETE]), or a
     * record that says which account an address is could not be read, so every account's identity record stayed
     * ([CANNOT_READ]).
     * What is left cannot be read as trusted at that origin (no pin), and calling again retries it.
     */
    data class Partly(val reason: String) : ServerForgotten()

    companion object {
        const val CANNOT_LIST = "cannot_list"
        const val CANNOT_DELETE = "cannot_delete"
        const val CANNOT_READ = "cannot_read"
    }
}

/**
 * [CardStatus.Refused]'s verdict when a move names the baked origin and the moving instance is not the baked instance
 * (design §4.4: the target of a move is checked for whether this device can keep a pin for it; at the baked origin the
 * baked root always comes first). Refused before either pin is touched; the old pin stays in force.
 */
const val MOVE_TO_BAKED_ORIGIN = "move_to_baked_origin"

/** The §4.4 verdict string of [FirstPin.PinConflict] and [CardStatus.PinConflict]. */
const val PIN_CONFLICT = "pin_conflict"

/**
 * [CardStatus.Refused]'s verdict when a move cannot be followed because the device store cannot list its records, so
 * the namespace's trust records could not move with the pin (design §4.4). Nothing was touched.
 */
const val CANNOT_CARRY_RECORDS = "cannot_carry_records"

/**
 * [FirstPin.Refused]'s reason when the card the Trust Gate would show names an operator key with no X25519 image: no
 * operator fingerprint can be shown for it (design §4.1, §4.4), so nothing is offered or pinned.
 */
const val BAD_OPERATOR_KEY = "bad_operator_key"

/** Which Trust Gate copy applies (design §12.3). */
enum class TrustGateWording { TYPED_ADDRESS, DEVICE_LINK, LINK_OFFER_SIGN_IN, KIND_CHANGE, ENROL_LINK }

/**
 * Proof that the Trust Gate was shown for one exact chain. Only the engine can make one, and confirming
 * it pins exactly the chain the person was shown; a ticket for another origin or a newer chain is refused.
 */
class TrustGateTicket internal constructor(
    internal val origin: String,
    internal val wording: TrustGateWording,
    /** The newest card of the chain the person was shown, with the root the confirmation will record. */
    internal val candidate: CardPin,
) {
    /**
     * The `card0Hash` of the chain the person is shown (public: every card is): what a host prints beside the Trust Gate so
     * a script can confirm the exact server with it (the command-line tool's `--trust-card`). Reading it confirms nothing.
     */
    val card0Hash: String get() = candidate.card0Hash
}

/**
 * Instance trust for one device (design §4.4, §4.6): first pins, refreshes, moves and kind changes, and
 * "Forget this server". Stored per origin namespace in device state; it outlives sign-out and cache wipes.
 */
interface InstanceTrust {
    /** What the device holds for [origin]. */
    fun pinState(origin: String): PinState

    /** What the device may do with [origin] (design §4.4): a fork stops traffic but not reading; a damaged pin blocks both. */
    fun access(origin: String): OriginAccess = when (pinState(origin)) {
        PinState.None, is PinState.Pinned -> OriginAccess.OPEN
        is PinState.Forked -> OriginAccess.FORKED
        PinState.Damaged -> OriginAccess.BLOCKED
    }

    /** The pin of [origin]'s namespace when it is in force; null when none, forked or damaged. */
    fun pinFor(origin: String): CardPin?

    /** Every pinned namespace in force. */
    fun pins(): List<CardPin>

    /** The pins as the password gate takes them, a forked or damaged origin marked blocked. */
    fun gatePins(): List<GatePin>

    /**
     * Every first-pin call below follows one rule (design §4.4): when a pin exists for the origin, the
     * served chain is first judged against it and anything but ok refuses; the call may then add an anchor
     * or upgrade the root, never swap the chain. A forked or damaged origin refuses every call.
     */

    /** Pin [origin] through the baked root (design §0.3 `PUBLIC_INSTANCE`). */
    suspend fun pinBaked(origin: String): FirstPin

    /** Pin [origin] from a kit's `card0Hash`, limited to [kitEmailNorm] (design §10, FS-B1). The public origin also takes the baked check. */
    suspend fun pinFromKit(origin: String, card0Hash: String, kitEmailNorm: String): FirstPin

    /**
     * Pin from a verified connect/register offer: the chain must contain [cardHash] with [instanceId]
     * (design §4.4). Only [io.silencelen.andvari.core.client.link.LinkFlows] calls this, after the offer's
     * signature, `F` and creator checks passed. The public origin also takes the baked check.
     */
    suspend fun pinFromLinkOffer(origin: String, instanceId: String, cardHash: String): FirstPin

    /**
     * Design §12.2 rule 7: does the newest card this device verified for [origin] name [userId] as `operator`? True or
     * false from the pin's card (also a forked pin's last verified card); null when this device holds no readable pin
     * for [origin] (none, or damaged). Reads only: [refresh] first to take in the served chain's newest card. A client
     * that must not hold the operator account (the extension, the web client, a phone) signs the account out on true,
     * also after a quick unlock, which carries no role.
     */
    fun cardNamesOperator(origin: String, userId: String): Boolean? = when (val s = pinState(origin)) {
        is PinState.Pinned -> s.pin.operator == userId
        is PinState.Forked -> s.pin.operator == userId
        PinState.None, PinState.Damaged -> null
    }

    /** True when this build bakes a public instance and [origin] is its origin (design §0.3, §4.4). */
    fun isBakedOrigin(origin: String): Boolean = false

    /**
     * A setup link at the baked origin is refused (design §4.4): the verdict to stop on, never "go on". The baked checks
     * run in §2.4's order (an empty chain is `withheld`; `origin_mismatch`, `card0_mismatch`, `instance_mismatch`); a
     * chain that passes them is `already_set_up`. Under a pin, the pin is compared first (`fork`, `withheld`, …).
     * Nothing is pinned. An implementation without a baked instance answers `no_baked_instance`.
     */
    suspend fun setupVerdictAtBaked(origin: String): String = "no_baked_instance"

    /** A typed address or an enrol link: always [FirstPin.NeedsTrustGate] first (or the baked root for the public origin). */
    suspend fun beginTrustGate(origin: String, wording: TrustGateWording): FirstPin

    /** The person confirmed the gate: pins exactly what the ticket showed. A pin through an enrol link records root `ENROL`. */
    suspend fun confirmTrustGate(ticket: TrustGateTicket): FirstPin

    /**
     * The setup root: THIS device signed [card0Frame] with its own operator key [ownSignPub] for the
     * operator account [operatorUserId], whose email [operatorEmailNorm] the pin is limited to (design §6.7).
     * A card 0 whose `operatorSignKey` is not [ownSignPub] is refused, so a served card 0 never becomes a
     * setup pin.
     */
    suspend fun pinFromOwnCard0(origin: String, card0Frame: String, operatorUserId: String, operatorEmailNorm: String, ownSignPub: ByteArray): FirstPin

    /** Fetch the chain and verify forward from the pin (design §4.4: every policy probe or sync). A forked origin answers Fork without fetching. */
    suspend fun refresh(origin: String): CardStatus

    /**
     * One tap on a [CardStatus.Moved] prompt (not offered when `storeBuildMustUpdate`); re-judged first; [CardStatus.PinConflict]
     * when the new origin is pinned. Once the namespace moved the answer is [CardStatus.Ok] with `newKitDue` (the kit names
     * the old address), unless the new origin then answers a fork or a refusal, which is returned as it is.
     */
    suspend fun followMove(status: CardStatus.Moved): CardStatus

    /** The person confirmed a `kind` change through the Trust Gate; re-judged first. A change that also moved then shows the move prompt. */
    suspend fun acceptKindChange(status: CardStatus.KindChanged): CardStatus

    /** Removes the namespace's pin and its fork or damage mark (and the caller wipes its data): the only way out of a fork (design §12.3). */
    fun forget(origin: String)

    /** Removes the pin [handle] made, only if it made it and it is still the stored pin (design §8.2 step 8). */
    fun dropPinMade(handle: PinHandle)
}
