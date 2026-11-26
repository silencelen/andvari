package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import kotlinx.coroutines.launch
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InstanceApi
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.InstanceDetails
import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.app.InstanceSnapshot
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.TrustGatePrompt
import io.silencelen.andvari.core.app.UnfinishedMove
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.MOVE_UNFINISHED
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording

/**
 * The card of a server on show (§4.4) over [io.silencelen.andvari.core.client.pin.InstanceTrust]: what the last check
 * of its chain found, a signed move, a `kind` change, and "Forget this server". A fork and a damaged record are read
 * from the pin store itself, so they outlast a restart.
 *
 * Every intent here acts on the server whose card or instance it was handed, and only while that object is on show:
 * there is no "connected server" for it to act on instead.
 */
internal class EngineInstance(private val app: EngineAppApi) : InstanceApi {
    /** What was last shown for an origin, so that what did not change keeps its identity. */
    private class Shown(
        val label: InstanceLabel,
        val status: CardStatus?,
        val block: String,
        val putOff: Boolean,
        val taken: Boolean,
        val card: InstanceCardState,
        val details: InstanceDetails,
        val unfinished: UnfinishedMove?,
        val snapshot: InstanceSnapshot,
    )

    private val shown = HashMap<String, Shown>()

    /** Origins whose `kind`-change gate the person put off until the next unlock. */
    private val kindPutOff = HashSet<String>()

    /** The next unlock: what was put off until then returns. */
    fun unlocked(origin: String) {
        kindPutOff -= origin
    }

    /**
     * [origin] as a screen shows it, or null while this device holds no pin record for it. The same object, with the
     * same card, while nothing it shows changed.
     */
    fun snapshot(origin: String): InstanceSnapshot? {
        val pinState = app.trust.pinState(origin)
        val pin = when (pinState) {
            is PinState.Pinned -> pinState.pin
            is PinState.Forked -> pinState.pin
            PinState.Damaged -> null
            PinState.None -> {
                shown.remove(origin)
                // A kept session at an address with no pin record (a move left it behind): a blocked server, shown so it
                // can be forgotten. It never unlocks (no pin to open against) and carries no bearer (none in force).
                return if (app.keeper.session?.origin == origin) orphan(origin) else null
            }
        }
        // A followed move whose platform data has not moved (design §4.4): read from the durable mark, so it outlasts a restart.
        val from = app.trust.unfinishedMove(origin)
        val block = when {
            pinState == PinState.Damaged -> "damaged"
            pinState is PinState.Forked -> "forked"
            from != null -> "moving"
            else -> ""
        }
        val status = app.cardStatuses[origin]
        val putOff = origin in kindPutOff
        val moveTo = when (status) {
            is CardStatus.Moved -> status.newest.origin
            is CardStatus.PinConflict -> status.newest.origin
            else -> null
        }
        val taken = moveTo != null && app.trust.pinState(moveTo) != PinState.None
        val before = shown[origin]
        val fresh = app.labelFor(origin) ?: return null
        val label = before?.label?.takeIf { app.sameLabel(it, fresh) } ?: fresh
        val card = if (before != null && before.label === label && before.status === status && before.block == block && before.putOff == putOff && before.taken == taken) {
            before.card
        } else {
            if (from != null) InstanceCardState.NotVerified() else cardFor(label, pinState, status, putOff, taken)
        }
        val unfinished = if (from == null) null else before?.unfinished?.takeIf { it.fromOrigin == from } ?: UnfinishedMove(from)
        val keyShort = pin?.let { app.operatorKeyShort(it.operatorSignKey) } ?: ""
        val seq = pin?.seq ?: 0L
        val card0 = if (pin?.root == PinRoot.SETUP) pin.card0Hash else ""
        // Every kind of pin shows the first card's hash it holds, labelled as what this device pinned.
        val pinned0 = pin?.card0Hash.orEmpty()
        val details = before?.details?.takeIf { it.operatorKeyShort == keyShort && it.cardSeq == seq && it.card0Hash == card0 && it.pinnedCard0Hash == pinned0 }
            ?: InstanceDetails(keyShort, seq, card0, pinned0)
        // Only the session's own server carries "update required" (its answers are the ones this device acts on).
        val update = app.keeper.session?.origin == origin && origin in app.keeper.updateRequired.value
        if (before != null && before.label === label && before.card === card && before.details === details && before.unfinished === unfinished &&
            before.snapshot.updateRequired == update
        ) return before.snapshot
        val made = InstanceSnapshot(label, card, details, unfinished, update)
        shown[origin] = Shown(label, status, block, putOff, taken, card, details, unfinished, made)
        return made
    }

    private var orphanShown: InstanceSnapshot? = null

    /** The kept session's server when no pin record is left for it: the same object while it stays so. */
    private fun orphan(origin: String): InstanceSnapshot =
        orphanShown?.takeIf { it.label.origin == origin } ?: InstanceSnapshot(
            InstanceLabel("", origin, io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, selfNamed = true),
            InstanceCardState.Damaged(), InstanceDetails("", 0L, ""), null,
        ).also { orphanShown = it }

    private fun cardFor(label: InstanceLabel, pinState: PinState, status: CardStatus?, putOff: Boolean, taken: Boolean): InstanceCardState = when (pinState) {
        PinState.Damaged -> InstanceCardState.Damaged()
        is PinState.Forked -> InstanceCardState.Stopped()
        else -> when (status) {
            null, is CardStatus.Ok, CardStatus.Unreachable -> InstanceCardState.Ok()
            is CardStatus.Fork -> InstanceCardState.Stopped()
            is CardStatus.Withheld -> InstanceCardState.Withheld()
            is CardStatus.Refused -> InstanceCardState.NotVerified()
            is CardStatus.Moved ->
                if (status.storeBuildMustUpdate) InstanceCardState.UpdateAndvari(CopyKey.CARD_MOVED_UPDATE)
                else InstanceCardState.Moved(label, status.newest.origin, alreadyPinnedThere = taken)
            is CardStatus.KindChanged ->
                if (status.storeBuildMustUpdate) InstanceCardState.UpdateAndvari(CopyKey.CARD_CHANGED_UPDATE)
                else InstanceCardState.KindChanged(kindGate(status.newest), putOff)
            // The move prompt stays: a move never replaces a pin that exists.
            is CardStatus.PinConflict -> InstanceCardState.Moved(label, status.newest.origin, alreadyPinnedThere = true)
        }
    }

    private fun kindGate(newest: CardPin): TrustGatePrompt = TrustGatePrompt(
        wording = TrustGateWording.KIND_CHANGE,
        origin = newest.origin,
        name = newest.name,
        operatorKeyShort = app.operatorKeyShort(newest.operatorSignKey),
        switching = false,
        punycodeCaution = newest.origin.contains("xn--"),
        httpCaution = newest.origin.startsWith("http://"),
        kitIdentityChanged = false,
        typedKit = false,
        claimedKind = app.kindOf(newest.kind),
    )

    /** The instances on show: the snapshot's own, which is also the one on a server-changed screen while that is up. */
    private fun onShow(): List<InstanceSnapshot> = listOfNotNull(app.snapshot.instance)

    /** The origin whose card on show is the very object [card]. */
    private fun originOf(card: InstanceCardState): String? = onShow().firstOrNull { it.card === card }?.label?.origin

    /** Check the chain of the origin on show again (§4.4: every policy probe and sync). An unreachable server changes nothing. */
    suspend fun refresh(): CardStatus? {
        val origin = app.originOnShow() ?: return null
        val status = app.trust.refresh(origin)
        if (status != CardStatus.Unreachable) app.cardStatuses[origin] = status
        // §12.2 rule 7: the newest card may now name the signed-in account as the operator.
        if (app.refuseHeldOperator()) return status
        app.publish()
        return status
    }

    /**
     * A check of [origin]'s chain made while signed in (the item engine's gate, at every sync)
     * found [status]: it reaches the screen as [refresh]'s does. An unreachable server changes nothing. When the newest
     * card names the signed-in account as the operator (§12.2 rule 7) the session is refused right after the check, out
     * of the sync that made it, so the sync never runs on over a closed vault.
     */
    internal fun chainChecked(origin: String, status: CardStatus) {
        if (status == CardStatus.Unreachable) return
        if (app.keeper.session?.origin != origin) return
        app.cardStatuses[origin] = status
        app.scope.launch {
            if (app.keeper.session?.origin != origin) return@launch
            if (app.refuseHeldOperator()) return@launch
            app.publish()
        }
    }

    override suspend fun followMove(card: InstanceCardState.Moved): MoveResult {
        val origin = originOf(card) ?: return MoveResult.STALE
        val moved = when (val status = app.cardStatuses[origin]) {
            is CardStatus.Moved -> status
            // A move that was refused for a pin at the new address is judged again from the chain.
            is CardStatus.PinConflict -> app.working { app.trust.refresh(origin) } as? CardStatus.Moved ?: return MoveResult.STALE
            else -> return MoveResult.STALE
        }
        return app.working {
            val r = app.trust.followMove(moved)
            val to = moved.newest.origin
            when {
                r is CardStatus.Ok -> {
                    moveSettled(origin, r)
                    MoveResult.DONE
                }
                r is CardStatus.PinConflict -> {
                    app.cardStatuses[origin] = r
                    MoveResult.ALREADY_PINNED_THERE
                }
                // Decided by where the pin is, not by the status: the pin left the old address,
                // so the session goes with it, and the new address's card says what its check found.
                movedAway(origin, to) && (r as? CardStatus.Refused)?.verdict != MOVE_UNFINISHED -> {
                    sessionFollowed(origin, to, r)
                    if (r == CardStatus.Unreachable) MoveResult.UNREACHABLE else MoveResult.MOVED_NOT_VERIFIED
                }
                r == CardStatus.Unreachable -> MoveResult.UNREACHABLE
                else -> {
                    val to = (r as? CardStatus.Refused)?.takeIf { it.verdict == MOVE_UNFINISHED }?.pinned?.origin
                    if (to != null && to != origin) {
                        moveHeld(origin, to)
                        MoveResult.NOT_FINISHED
                    } else {
                        app.cardStatuses[origin] = r
                        MoveResult.FAILED
                    }
                }
            }
        }
    }

    /**
     * The namespace moved from [from] to [r]'s origin and the platform's data is there (design §4.4): what was known of
     * the old address goes with it, and so does the session. Run after a followed move, and after a finished one.
     */
    private fun moveSettled(from: String, r: CardStatus.Ok) {
        val to = r.pin.origin
        sessionFollowed(from, to, r)
        // R36: a kit made before the move names the old address; the app asks for a new one.
        if (r.newKitDue) app.newKitDue(to)
    }

    /** The old address holds no pin and the new one holds a record (in force or forked): the move happened. */
    private fun movedAway(from: String, to: String): Boolean {
        if (to == from || app.trust.pinState(from) != PinState.None) return false
        val there = app.trust.pinState(to)
        return there is PinState.Pinned || there is PinState.Forked
    }

    /**
     * The pin and its records went from [from] to [to]: what was known of the old address goes with it, and so does the
     * session, whatever the new address then answered ([status], filed under [to] unless it did not answer).
     */
    private fun sessionFollowed(from: String, to: String, status: CardStatus) {
        app.cardStatuses.remove(from)
        if (status != CardStatus.Unreachable) app.cardStatuses[to] = status
        shown.remove(from)
        if (kindPutOff.remove(from)) kindPutOff += to
        // Nothing happens here when the session went to the new address already (the trust's mover, a held move).
        app.keeper.moved(from, to)
        app.kitMarksMoved(from, to)
        app.vaultMoved(from)
        app.policies.forget(from)
        app.entryFlow.serverSettled(from)
    }

    /**
     * A followed move from [from] to [to] that the engine made (the pin and its records are at [to]) while the platform's
     * data did not move (`CardStatus.Refused(MOVE_UNFINISHED)`, [io.silencelen.andvari.core.client.pin.OriginAccess.MOVING]).
     * The session goes with the namespace now, so its tokens are never sent to the old address; nothing is sent to [to]
     * either (the engine's guard refuses it) and no vault opens there until [finishMove] succeeds.
     */
    private fun moveHeld(from: String, to: String) {
        app.cardStatuses.remove(from)
        app.cardStatuses.remove(to)
        shown.remove(from)
        if (kindPutOff.remove(from)) kindPutOff += to
        app.keeper.moved(from, to)
        app.moveHeld(from)
        app.policies.forget(from)
        app.entryFlow.serverSettled(from)
    }

    override suspend fun finishMove(move: UnfinishedMove): MoveResult {
        val instance = onShow().firstOrNull { it.unfinishedMove === move } ?: return MoveResult.STALE
        return finish(instance.label.origin, move.fromOrigin)
    }

    /**
     * Finish the move [from] → [to] (design §4.4): the platform moves its data again ([CardTrust.finishMove]), and on
     * success the server opens at [to] as after a followed move. At a start the app calls it once for every move left
     * unfinished, before any session opens there.
     */
    suspend fun finish(to: String, from: String): MoveResult = app.working {
        if (app.trust.unfinishedMove(to) != from) return@working MoveResult.STALE
        when (val r = app.trust.finishMove(to)) {
            is CardStatus.Ok -> {
                moveSettled(from, r)
                MoveResult.DONE
            }
            CardStatus.Unreachable -> MoveResult.UNREACHABLE
            else -> {
                if ((r as? CardStatus.Refused)?.verdict == MOVE_UNFINISHED) {
                    MoveResult.NOT_FINISHED
                } else if (movedAway(from, to)) {
                    // The platform's data is at the new address, which did not check out: the session is there too.
                    sessionFollowed(from, to, r)
                    MoveResult.MOVED_NOT_VERIFIED
                } else {
                    app.cardStatuses[to] = r
                    MoveResult.FAILED
                }
            }
        }
    }

    override suspend fun forgetServerAtNewAddress(card: InstanceCardState.Moved): PlainResult {
        val origin = originOf(card) ?: return PlainResult.STALE
        if (!card.alreadyPinnedThere) return PlainResult.STALE
        val there = card.toOrigin
        // Never the session's own server from here: that one is forgotten as itself.
        if (app.keeper.session?.origin == there) return PlainResult.STALE
        forgetOrigin(there)
        app.sweepAccounts()
        // The move is judged again from the chain, now that nothing stands at the new address.
        val status = app.working { app.trust.refresh(origin) }
        if (status != CardStatus.Unreachable) app.cardStatuses[origin] = status
        app.publish()
        return PlainResult.DONE
    }

    override suspend fun acceptKindChange(card: InstanceCardState.KindChanged): PlainResult {
        val origin = originOf(card) ?: return PlainResult.STALE
        val changed = app.cardStatuses[origin] as? CardStatus.KindChanged ?: return PlainResult.STALE
        return app.working {
            when (val r = app.trust.acceptKindChange(changed)) {
                is CardStatus.Ok, is CardStatus.Moved -> {
                    // A card that also moved shows its move next, as its own prompt.
                    app.cardStatuses[origin] = r
                    kindPutOff -= origin
                    if (r is CardStatus.Ok) app.entryFlow.serverSettled(origin)
                    PlainResult.DONE
                }
                CardStatus.Unreachable -> PlainResult.UNREACHABLE
                else -> {
                    app.cardStatuses[origin] = r
                    PlainResult.FAILED
                }
            }
        }
    }

    override fun kindChangeNotNow(card: InstanceCardState.KindChanged) {
        val origin = originOf(card) ?: return
        // Nothing is sent or stored: the old kind stays in force, and the gate stays shut until the next unlock.
        kindPutOff += origin
        app.publish()
    }

    /**
     * The pin of [origin], with its fork or damage mark, and everything this binding kept about it go from this device:
     * "Forget this server", and a confirmed deletion of an account there ([accounts] the ones whose records go by name).
     */
    internal fun forgetOrigin(origin: String, accounts: Collection<String> = emptyList(), tied: Collection<String> = emptyList()) {
        // Read before anything goes: the accounts the sweep's own rule knows apart from this server keep what is kept by
        // their id, as an account another server ties does ([AccountSweep.knownApartFrom]).
        val knownElsewhere = app.knownApartFrom(origin, null)
        // The person's own act (design §4.4): the cache files and kept records of every account held there go, then
        // the engine's per-origin wipe takes the pin and every record kept under the origin and its accounts.
        val held = app.dropHeldAt(origin)
        // A request for an operator's help kept for this server goes too, judged by the pin before the wipe takes it:
        // forgetting a server forgets what this device holds for it. `pinForForget`, not `pinFor`:
        // the latter answers null under a fork, and a forked server's request kept under an older address would stay.
        io.silencelen.andvari.core.client.recovery.KeptAssistRequests.forget(app.requestStore, origin, app.trust.pinForForget(origin))
        app.trust.forgetServer(origin, (accounts + held).distinct(), (tied + knownElsewhere).distinct())
        app.cardStatuses.remove(origin)
        shown.remove(origin)
        kindPutOff -= origin
        app.newKitDone(origin)
        app.policies.forget(origin)
        // A kit's notice or mark of an account there, and the kept session's mark, go with the server.
        app.kitMarksForgotten(origin)
    }

    override suspend fun forgetServer(instance: InstanceSnapshot): PlainResult {
        if (app.phase == AppPhase.STARTING || onShow().none { it === instance }) return PlainResult.STALE
        val origin = instance.label.origin
        app.kitFlow.drop()
        val session = app.keeper.session
        val ownSession = session != null && session.origin == origin
        // The session ends on the device only (no logout: the server is told nothing), its quick-unlock key with it; the
        // vault closes first, so its cache file is not open while it is deleted.
        if (ownSession) {
            app.endVault(null)
            app.keeper.forget(forgetIdentity = false)
        }
        forgetOrigin(origin, listOfNotNull(session?.userId?.takeIf { ownSession }))
        // The server is told nothing. The journey that led here is over either way.
        app.sessionGone()
        // Then what is kept by the id of an account this device no longer knows anywhere goes ([AccountSweep]).
        app.sweepAccounts()
        return PlainResult.DONE
    }
}
