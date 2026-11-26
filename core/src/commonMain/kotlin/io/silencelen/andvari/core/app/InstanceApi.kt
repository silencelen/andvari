package io.silencelen.andvari.core.app

/**
 * A server this device holds a pin for, as a screen shows it: the pinned card of its namespace (§4.4) and what the
 * last check of its chain found. [AppSnapshot.instance] is the one on show: the session's server, or, signed out, the
 * server of the screen on show. [EntryScreen.ServerChanged] carries the one a flow could not open.
 */
class InstanceSnapshot internal constructor(
    val label: InstanceLabel,
    val card: InstanceCardState,
    val details: InstanceDetails,
    /**
     * Non-null while a move to this server's address was followed but this device's data has not moved with it yet
     * (see [UnfinishedMove]). Check it before [card], which shows [InstanceCardState.NotVerified] meanwhile.
     */
    val unfinishedMove: UnfinishedMove? = null,
    /**
     * The server this session is at answered its latest request "update required" (this build is too old for it):
     * show the notice that asks to update Andvari. Only ever true for the session's own server. It is a notice and no
     * more: the vault and its copy stay as they are, and it clears by itself once a later answer from that server is not
     * "update required".
     */
    val updateRequired: Boolean = false,
)

/**
 * A followed move (§4.4) whose data on this device has not reached the new address yet: moving the platform's data
 * failed, or the app stopped between the two. The server is at [InstanceSnapshot.label]'s origin already, and the
 * move is not undone. Until [InstanceApi.finishMove] succeeds, nothing is sent to the new address, nothing is read from
 * this device's copy, and no vault opens there: the lock screen's unlock answers
 * [VaultUnlockResult.SERVER_BLOCKED]. The app tries once by itself at every start.
 *
 * GAP (§4.4): the design gives no wording for it; offer "Try again" ([InstanceApi.finishMove]) and
 * [InstanceApi.forgetServer].
 */
class UnfinishedMove internal constructor(
    /** The address the server moved from. */
    val fromOrigin: String,
)

/** What "Instance details" shows. */
class InstanceDetails internal constructor(
    /** The operator key's short form, 32 hex: what `andvari setup` prints for comparison (§9.5 step 8). */
    val operatorKeyShort: String,
    /** The pinned card's `seq`. */
    val cardSeq: Long,
    /**
     * The hash of card 0, **only on the device that signed it** (a setup pin); empty anywhere else. The value baked
     * into store builds is taken from the signing device, never from a fetch (§14.1, T-R10).
     */
    val card0Hash: String,
    /**
     * The hash of card 0 as this device pinned it, for every kind of pin (the baked root, a link offer, a kit, the Trust
     * Gate or the setup): what the person can compare with the hash the operator gives, labelled [pinnedCard0Label]. Empty
     * only while no pin is held. Unlike [card0Hash] it is never the value a store build bakes. Additive.
     */
    val pinnedCard0Hash: String = "",
) {
    /** The label beside [pinnedCard0Hash]. */
    val pinnedCard0Label: CopyKey get() = CopyKey.INSTANCE_CARD0_PINNED
}

/**
 * What the last check of the card chain found (§4.4; it runs on every policy probe and sync). One to one with the
 * engine's `CardStatus`, except `Unreachable`, which changes nothing here: the state before it stays. [Stopped] is
 * also its `PinState.Forked`, and [Damaged] its `PinState.Damaged`: both are kept with the pin and outlast a restart.
 */
sealed class InstanceCardState {
    /** The chain continues the pin (`CardStatus.Ok`). */
    class Ok internal constructor() : InstanceCardState()

    /**
     * Fork (`CardStatus.Fork`): the chain no longer contains the pinned card. **The app has stopped using the
     * instance: no sign-in, no sync, no writes.** Show [CopyKey.CARD_FORK]; the only way on is
     * [InstanceApi.forgetServer]. A server whose operator reset its identity shows as [Withheld] until the new
     * card 0 appears, and then as this (§4.6, FC-4). **A fork is durable**: it is stored with the pin, and a server
     * that serves the old chain again later stays stopped until it is forgotten.
     */
    class Stopped internal constructor() : InstanceCardState()

    /**
     * This device's stored pin for the server does not decode (`PinState.Damaged`). It is never read as "no pin":
     * the server is blocked for everything, as in [Stopped], until [InstanceApi.forgetServer].
     * [InstanceSnapshot.label] then carries the origin with an empty name, because there is no readable card to take
     * a name from.
     *
     * GAP (§4.4 "Rules for the pin store"): the design gives no wording for it.
     */
    class Damaged internal constructor() : InstanceCardState()

    /** Withheld (`CardStatus.Withheld`): the chain ends below the pin. Nothing stops; show [CopyKey.CARD_WITHHELD]. */
    class Withheld internal constructor() : InstanceCardState()

    /**
     * A newer card failed verification (`CardStatus.Refused`). The pin stays and nothing is followed.
     *
     * GAP (§4.4): the design names the fork and the withheld chain; it gives no wording for a chain whose newer
     * card does not verify.
     */
    class NotVerified internal constructor() : InstanceCardState()

    /**
     * The newest verified card moves the instance to [toOrigin] (`CardStatus.Moved`). One tap on
     * [InstanceApi.followMove] moves the namespace, with no Trust Gate: the move is signed by the pinned operator key.
     * A card that changes both the address and the kind shows as [KindChanged] first; the move follows it.
     */
    class Moved internal constructor(
        /** The instance as pinned: its name and the old origin. */
        val from: InstanceLabel,
        val toOrigin: String,
        /**
         * This device already holds a pin for [toOrigin] (`CardStatus.PinConflict`, §4.4 `pin_conflict`): a move
         * never replaces a pin that exists, so [InstanceApi.followMove] answers [MoveResult.ALREADY_PINNED_THERE]
         * and nothing moves. The way on is to forget one of the two servers: this one
         * ([InstanceApi.forgetServer]), or the one this device knows at the new address
         * ([InstanceApi.forgetServerAtNewAddress]), after which the move can be followed. It is set once a follow
         * was refused for it, or a check of the chain found it.
         *
         * GAP (§4.4): the design gives no wording for it.
         */
        val alreadyPinnedThere: Boolean,
    ) : InstanceCardState() {
        val line: CopyLine get() = CopyLine.of(CopyKey.CARD_MOVED, from.name, from.origin, toOrigin)
    }

    /**
     * The newest verified card changes the instance's `kind` (`CardStatus.KindChanged`). It decides which recovery
     * rules apply, so it is never followed silently: [gate] is the Trust Gate in its `KIND_CHANGE` wording, and
     * until [InstanceApi.acceptKindChange] the app keeps using the old kind (T2-Rec).
     */
    class KindChanged internal constructor(
        val gate: TrustGatePrompt,
        /**
         * The person answered "not now" ([InstanceApi.kindChangeNotNow]): do not raise the gate again by itself
         * until the next unlock. The old kind stays in force, and "Instance details" still says the server claims a
         * change, where [InstanceApi.acceptKindChange] is offered.
         */
        val putOff: Boolean,
    ) : InstanceCardState()

    /**
     * The baked public instance says it moved or changed its kind. A store build follows neither (T-R7): show
     * [sentence]. There is no intent; only an app update helps.
     */
    class UpdateAndvari internal constructor(
        /** [CopyKey.CARD_MOVED_UPDATE] or [CopyKey.CARD_CHANGED_UPDATE]. */
        val sentence: CopyKey,
    ) : InstanceCardState()
}

interface InstanceApi {
    /**
     * Follow a signed move: the namespace moves to the new origin, unless this device already pins that origin.
     * [card] is one on show: [AppSnapshot.instance]'s (which is also [EntryScreen.ServerChanged]'s while that screen
     * is up), or the one on [OpenedInvite.ServerChanged]. Either way the move acts on the server the card names.
     * When that is the server this app is signed in to, the session moves with its namespace: the app goes on at
     * the new address.
     */
    suspend fun followMove(card: InstanceCardState.Moved): MoveResult

    /**
     * "Try again" on an [UnfinishedMove]: move this device's data to the new address once more. [move] is the one on
     * [AppSnapshot.instance]. [MoveResult.DONE]: the server opens at the new address, as after a followed move (a new
     * kit is asked for at the next unlock). [MoveResult.NOT_FINISHED]: it failed again, and nothing changed.
     */
    suspend fun finishMove(move: UnfinishedMove): MoveResult

    /**
     * The way on from [MoveResult.ALREADY_PINNED_THERE] that keeps this server: forget the server this device
     * already knows at [InstanceCardState.Moved.toOrigin], its pin and its data on this device, so the move can be
     * followed. Only for a card whose [InstanceCardState.Moved.alreadyPinnedThere] is set
     * ([PlainResult.STALE] otherwise). The server is told nothing, and the move itself is still [followMove].
     */
    suspend fun forgetServerAtNewAddress(card: InstanceCardState.Moved): PlainResult

    /** Confirm the Trust Gate of a `kind` change: the new kind's rules apply from here. [card] as for [followMove]. */
    suspend fun acceptKindChange(card: InstanceCardState.KindChanged): PlainResult

    /**
     * "Not now" on the gate of a `kind` change: the gate closes until the next unlock
     * ([InstanceCardState.KindChanged.putOff]) and the old kind stays in force. Nothing is sent or stored.
     */
    fun kindChangeNotNow(card: InstanceCardState.KindChanged)

    /**
     * "Forget this server": remove [instance]'s card pin and its namespace's data from this device, and return to
     * the first screen. It is the way out of [InstanceCardState.Stopped] and [InstanceCardState.Damaged] (§12.3). A
     * session on that server is dropped with it. The server is told nothing.
     *
     * [instance] is one on show: [AppSnapshot.instance] (which is also the one on [EntryScreen.ServerChanged] while
     * that screen is up), or the one on [OpenedInvite.ServerChanged] ([PlainResult.STALE] for any other). So what is
     * forgotten is what the screen named: forgetting the server an opened invite named leaves this app signed in
     * where it is and only closes the invite.
     */
    suspend fun forgetServer(instance: InstanceSnapshot): PlainResult
}

/** What following a signed move came to (the engine's `InstanceTrust.followMove`). */
enum class MoveResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** The namespace moved to the new address. */
    DONE,

    /**
     * This device already holds a pin for the new address (`pin_conflict`): a move never replaces a pin that exists
     * (§4.4 "Rules for the pin store"). Nothing moved, and the prompt stays, now with
     * [InstanceCardState.Moved.alreadyPinnedThere] set: the way on is to forget one of the two servers.
     *
     * GAP (§4.4): the design gives no wording for it.
     */
    ALREADY_PINNED_THERE,

    /**
     * The move stands, but this device's data could not be moved to the new address: [AppSnapshot.instance] now
     * carries [InstanceSnapshot.unfinishedMove], and [InstanceApi.finishMove] tries again. A vault that was open is
     * locked, and does not open until the move is finished.
     */
    NOT_FINISHED,

    /**
     * The address moved and this device followed (the pin, its records and the session are at the new address), but the
     * new address did not check out: it serves another chain (a fork), an older one, or one that is refused.
     * [AppSnapshot.instance] is now the new address with the card that says so (a fork shows the stop card and
     * "Forget this server"). Nothing is sent there while it stands.
     *
     * GAP (§4.4): the design gives no wording for it.
     */
    MOVED_NOT_VERIFIED,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
