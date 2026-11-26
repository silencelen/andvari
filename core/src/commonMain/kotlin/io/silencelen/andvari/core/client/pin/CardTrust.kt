package io.silencelen.andvari.core.client.pin

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.SetupOffers
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.model.wire.InstanceResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checkpoint
import io.silencelen.andvari.core.trust.CheckpointVerdict
import io.silencelen.andvari.core.trust.Checkpoints
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.OperatorKeys
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer

/**
 * One instance card as the chain verifier returned it: every field from a frame whose signature
 * chain verified from card 0 (design §4.2). [name] is the decoded plain text of the `name` field.
 */
data class VerifiedCard(
    val seq: Long,
    val hash: String,
    val instanceId: String,
    val origin: String,
    val name: String,
    val kind: String,
    val operator: String,
    val operatorSignKey: String,
    val recoveryFp: String,
)

/**
 * The first-pin root checks over one verified chain (design §4.4, §2.4 order), each answering a pin
 * verdict code or null when the root holds. Bound to `InstanceCard.checkBakedRoot`,
 * `checkKitRoot` and `checkOfferRoot` ([TrustCardChainVerifier]).
 */
interface RootChecks {
    /**
     * The typed-address root (§2.4 pinning, the first verdict): `origin_mismatch` when the newest verified card's
     * `origin` is not [dialedOrigin]. Asked only when the device holds no pin for [dialedOrigin]; under a pin a
     * changed origin is a move. Never called on an empty chain (that is `withheld` for every root).
     */
    fun typed(dialedOrigin: String): String?
    fun baked(dialedOrigin: String, card0Hash: String, instanceId: String): String?
    fun kit(dialedOrigin: String, card0Hash: String): String?
    fun offer(dialedOrigin: String, cardHash: String, instanceId: String): String?
}

/** The verdict of verifying a served chain from card 0. */
sealed class ChainCheck {
    /** Card 0 first; every link verified (signer = previous `operatorSignKey`, `prev`, constant `instanceId`). */
    class Ok(val cards: List<VerifiedCard>, val roots: RootChecks) : ChainCheck()
    data class Refused(val verdict: String) : ChainCheck()
}

/**
 * The engine's port to the `InstanceCard` verifier (design §4.2, §18.2). Pure: same frames, same
 * answer. [operatorKeys] (the operator account's own devices only) adds the `operator_key_mismatch` check.
 */
fun interface CardChainVerifier {
    fun verify(frames: List<ByteArray>, operatorKeys: OperatorKeys?): ChainCheck
}

/** The store-build constants (design §0.3, `spec/public-instance.json`): the baked public instance. */
data class BakedInstance(val origin: String, val instanceId: String, val card0Hash: String, val kind: String)

/**
 * The pure chain rules of design §4.4: what a verified chain means against a pin, and which first pins
 * a root may make. No I/O, no clock. The pin's `card0Hash` is checked before anything else: a served
 * card 0 that does not hash to it is a fork however short the chain (an operator reset shows at once);
 * withheld is only the same chain ending below the pin. Pinned, baked, kit and offer instance ids are
 * never handed to the chain verifier; they are pin verdicts after it (design §2.4).
 */
object CardChainRules {
    /**
     * True when "a store build never follows a move or a kind change" applies to [pin]: keyed on the
     * INSTANCE (its card 0 is the baked card 0, or its origin is the baked origin), not on the root.
     */
    fun isBakedInstance(pin: CardPin, baked: BakedInstance?): Boolean =
        baked != null && (pin.card0Hash == baked.card0Hash || pin.origin == baked.origin)

    /** Judge a verified [cards] chain (card 0 first) against [pin] (design §4.4, T-R7, T2-Rec). */
    fun judge(pin: CardPin, cards: List<VerifiedCard>, baked: BakedInstance?, storeBuild: Boolean): CardStatus {
        // Fork and withheld are the checkpoint verdict (design §2.4 "Checkpoints").
        when (Checkpoints.compareCard(pin.card0Hash, Checkpoint(pin.seq, pin.hash), cards.map { it.hash })) {
            CheckpointVerdict.WITHHELD -> return CardStatus.Withheld(pin, if (cards.isEmpty()) null else cards.size - 1L)
            CheckpointVerdict.FORK, CheckpointVerdict.ROLLBACK -> return CardStatus.Fork(pin)
            CheckpointVerdict.OK -> {}
        }
        if (cards[0].instanceId != pin.instanceId) return CardStatus.Fork(pin)
        val newest = advance(pin, cards.last())
        val mustUpdate = storeBuild && isBakedInstance(pin, baked)
        // A card that changes both origin and kind is a kind change, never a move alone.
        if (newest.kind != pin.kind) return CardStatus.KindChanged(pin, newest, mustUpdate)
        if (newest.origin != pin.origin) return CardStatus.Moved(pin, newest, mustUpdate)
        return CardStatus.Ok(newest)
    }

    /** [pin] advanced to [card], keeping its root, its account and its card 0. */
    fun advance(pin: CardPin, card: VerifiedCard): CardPin = pin.copy(
        instanceId = card.instanceId, seq = card.seq, hash = card.hash, origin = card.origin, name = card.name,
        kind = card.kind, operator = card.operator, operatorSignKey = card.operatorSignKey, recoveryFp = card.recoveryFp,
    )

    /** A first pin of [root] at the newest card of [cards]. */
    fun firstPin(cards: List<VerifiedCard>, root: PinRoot, rootAccount: String?): CardPin {
        val c = cards.last()
        return CardPin(c.instanceId, c.seq, c.hash, c.origin, c.name, c.kind, c.operator, c.operatorSignKey, c.recoveryFp, root, rootAccount, cards[0].hash)
    }

    /**
     * The baked root (design §4.4): the verifier's verdict ([RootChecks.baked]: `withheld`, `card0_mismatch`,
     * `instance_mismatch`), then the store-build rule: a newest card that moved or changed `kind` is
     * `update_required`. Null when it holds.
     */
    fun bakedVerdict(check: ChainCheck.Ok, baked: BakedInstance, storeBuild: Boolean): String? {
        check.roots.baked(baked.origin, baked.card0Hash, baked.instanceId)?.let { return it }
        val newest = check.cards.last()
        return if (storeBuild && (newest.origin != baked.origin || newest.kind != baked.kind)) "update_required" else null
    }

    /** How much a root lets a pin do; a first-pin call on an existing pin may only raise it. */
    fun rank(root: PinRoot): Int = when (root) {
        PinRoot.BAKED, PinRoot.TRUST_GATE -> 4
        PinRoot.SETUP, PinRoot.KIT -> 3
        PinRoot.LINK_OFFER -> 2
        PinRoot.ENROL -> 1
    }
}

/**
 * Durable pins, one per origin namespace, in device state (design §4.4): each with its fork mark. A
 * record that does not decode is [PinState.Damaged], never "no pin".
 *
 * A followed move writes several records one after another ([move]), and device state has no transaction across
 * keys, so the app can stop between any two. Every move therefore writes its intent first: `ovh.moving|<new origin>`
 * naming the old origin and the phase. Before this store answers anything, it settles each move it finds stopped in
 * its first phase ([settle]): with no pin written at the new origin it is rolled back (only the intent is cleared;
 * nothing was carried yet), with the new pin written it is rolled forward (the records carried again, which is
 * idempotent, the old pin removed). So a stopped move is either not done (the old origin pinned and open with all its
 * records) or done (the new origin pinned with all of them; with a host namespace, [OriginAccess.MOVING] until the
 * host's [NamespaceMover] succeeded). A move this store cannot settle (a record it cannot read or write) closes both
 * origins until it can, or until "Forget this server" removes the new one.
 */
class PinStore(private val state: DeviceState) {
    @Serializable
    private data class Stored(
        val instanceId: String, val seq: Long, val hash: String, val origin: String, val name: String, val kind: String,
        val operator: String, val operatorSignKey: String, val recoveryFp: String, val root: String,
        val rootAccount: String? = null, val card0Hash: String, val forked: Boolean = false,
    )

    /** A move's intent record at its new origin: the old origin, the phase, and whether a host namespace follows. */
    @Serializable
    private data class Intent(val from: String, val phase: String, val host: Boolean)

    /**
     * The origins of the interrupted moves this store could not settle (both ends of each): read as damaged until they
     * are settled. Null: the store could not even look for them, so every origin reads as damaged meanwhile.
     */
    private var unsettled: Set<String>? = emptySet()

    /** The [interrupted] count this store last settled at; -1 before its first use. */
    private var settledAt = -1

    fun state(origin: String): PinState {
        settle()
        return stateOf(origin)
    }

    /** [state] without settling first (the caller did), an unsettled move's origins read as damaged. */
    private fun stateOf(origin: String): PinState =
        if (unsettled?.contains(origin) != false) PinState.Damaged else read(origin)

    /** The pin record of [origin] as stored. */
    private fun read(origin: String): PinState {
        // A storage error is not "no pin" (design §4.4): the origin stays closed while the record cannot be read.
        val text = try { state.get(KEY_PREFIX + origin) } catch (e: Exception) { return PinState.Damaged } ?: return PinState.None
        val s = runCatching { WireJson.strict.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return PinState.Damaged
        val root = PinRoot.entries.firstOrNull { it.code == s.root } ?: return PinState.Damaged
        if (s.origin != origin) return PinState.Damaged
        val pin = CardPin(s.instanceId, s.seq, s.hash, s.origin, s.name, s.kind, s.operator, s.operatorSignKey, s.recoveryFp, root, s.rootAccount, s.card0Hash)
        return if (s.forked) PinState.Forked(pin) else PinState.Pinned(pin)
    }

    fun get(origin: String): CardPin? = (state(origin) as? PinState.Pinned)?.pin

    /**
     * [OriginAccess] of [origin]: open with no pin or a pin in force, forked under a fork mark, [OriginAccess.MOVING]
     * while a followed move waits for the host's namespace ([unfinishedMove]), blocked otherwise (a damaged pin, a
     * move mark that cannot be read, or an interrupted move this store could not settle yet).
     */
    fun access(origin: String): OriginAccess {
        settle()
        return when (stateOf(origin)) {
            PinState.Damaged -> OriginAccess.BLOCKED
            is PinState.Forked -> OriginAccess.FORKED
            PinState.None, is PinState.Pinned -> when (mark(origin)) {
                Mark.None -> OriginAccess.OPEN
                is Mark.Namespace -> OriginAccess.MOVING
                is Mark.Begun, Mark.Unreadable -> OriginAccess.BLOCKED
            }
        }
    }

    /**
     * Design §4.4 "No credential goes to an origin without a pin in force": true when a request that carries a
     * credential (a bearer, a refresh token, a logout, anything derived from the master password) may go to [origin].
     * That is a pin in force there with [access] open, or, while [origin] holds no pin record at all, a setup offer
     * this device opened for it and has not finished (the setup root, design §6.7: no card exists yet, so the account
     * registers and signs card 0 before any pin can exist; the offer is removed when card 0 is pinned). A setup offer
     * that cannot be read counts as none.
     */
    fun credentialsAllowed(origin: String): Boolean {
        if (access(origin) != OriginAccess.OPEN) return false
        return when (stateOf(origin)) {
            is PinState.Pinned -> true
            PinState.None -> try { SetupOffers(state).get(origin) != null } catch (e: Exception) { false }
            is PinState.Forked, PinState.Damaged -> false
        }
    }

    /** A move's intent record on its new origin ([Intent]). */
    private sealed class Mark {
        data object None : Mark()
        /**
         * The move has begun: the new pin may or may not be written, the records may be partly carried, the old pin may
         * or may not be removed yet. Settled before anything is answered ([settle]).
         */
        data class Begun(val from: String, val host: Boolean) : Mark()
        /** The pin and the records moved; the host's [NamespaceMover] has not succeeded yet. */
        data class Namespace(val from: String) : Mark()
        /** A storage error: unknown, so the origin stays closed (design §4.4 "A trust record that cannot be read"). */
        data object Unreadable : Mark()
    }

    private fun mark(origin: String): Mark {
        val text = try { state.get(MOVE_PREFIX + origin) } catch (e: Exception) { return Mark.Unreadable } ?: return Mark.None
        // A mark written before move intents existed is the old origin's text alone: the namespace phase.
        if (!text.startsWith("{")) return if (TrustGrammar.isOrigin(text)) Mark.Namespace(text) else Mark.Unreadable
        val i = runCatching { WireJson.strict.decodeFromString(Intent.serializer(), text) }.getOrNull() ?: return Mark.Unreadable
        if (!TrustGrammar.isOrigin(i.from)) return Mark.Unreadable
        return when (i.phase) {
            PHASE_BEGUN -> Mark.Begun(i.from, i.host)
            PHASE_NAMESPACE -> Mark.Namespace(i.from)
            else -> Mark.Unreadable
        }
    }

    private fun intent(from: String, phase: String, host: Boolean): String =
        WireJson.json.encodeToString(Intent.serializer(), Intent(from, phase, host))

    /**
     * The old origin of a move followed to [origin] whose platform namespace has not moved yet ([CardTrust]'s
     * [NamespaceMover] failed, or the app stopped before it ran); null when none is pending or the mark cannot be read
     * (then [access] is [OriginAccess.BLOCKED]). Only a move whose pin and records are at [origin] is ever named here:
     * one stopped before that is settled first, and one that cannot be settled is not named. Nothing is sent to
     * [origin] while it is pending.
     */
    fun unfinishedMove(origin: String): String? {
        settle()
        if (stateOf(origin) !is PinState.Pinned) return null
        return (mark(origin) as? Mark.Namespace)?.from
    }

    /** Clears [to]'s move mark, only while it still names [from] in the namespace phase. False, nothing written, otherwise. */
    internal fun clearMove(to: String, from: String): Boolean = synchronized(LOCK) {
        settle()
        if (mark(to) != Mark.Namespace(from)) return@synchronized false
        state.set(MOVE_PREFIX + to, null)
        true
    }

    /**
     * Settles every move found stopped in its first phase ([Mark.Begun]), once per store and again after any move in
     * this process was interrupted, before anything is answered. Runs under [LOCK], so no move is in flight meanwhile.
     */
    private fun settle(): Unit = synchronized(LOCK) {
        if (settledAt == interrupted) return@synchronized
        val at = interrupted
        val left = try { settleMoves() } catch (e: Exception) { null }
        unsettled = left
        // A move left unsettled is tried again at the next call.
        if (left != null && left.isEmpty()) settledAt = at
    }

    /** Settles each interrupted move; the origins of those it could not settle. */
    private fun settleMoves(): Set<String> {
        // A store that cannot list its keys never followed a move (planMove refuses it), so nothing can be interrupted.
        val keys = state.keys() ?: return emptySet()
        val left = mutableSetOf<String>()
        for (key in keys) {
            if (!key.startsWith(MOVE_PREFIX)) continue
            val to = key.removePrefix(MOVE_PREFIX)
            val begun = mark(to) as? Mark.Begun ?: continue
            try {
                settleMove(begun.from, to, begun.host)
            } catch (e: Exception) {
                left += begun.from
                left += to
            }
        }
        return left
    }

    /** Rolls a move [from] → [to] stopped in its first phase back (no new pin yet) or forward (the new pin written). */
    private fun settleMove(from: String, to: String, host: Boolean) {
        when (val now = read(to)) {
            // The new pin is written before anything is carried: with none, nothing moved. The old origin stays as it was.
            PinState.None -> state.set(MOVE_PREFIX + to, null)
            is PinState.Pinned -> {
                index()?.let { all -> if (to !in all) writeIndex(all + to) }
                carry(carriable(from, to) ?: error("the records cannot be listed"))
                when (val old = read(from)) {
                    is PinState.Pinned -> {
                        // Only the pin this move took its chain from: anything else is not a move this store can finish.
                        check(old.pin.card0Hash == now.pin.card0Hash && old.pin.instanceId == now.pin.instanceId) { "another pin at the old origin" }
                        delete(from)
                    }
                    PinState.None -> index()?.let { all -> if (from in all) writeIndex(all - from) }
                    // A fork mark is never cleared by a write, and a record that cannot be read is never written over.
                    is PinState.Forked, PinState.Damaged -> error("the old pin cannot be removed")
                }
                state.set(MOVE_PREFIX + to, if (host) intent(from, PHASE_NAMESPACE, true) else null)
            }
            is PinState.Forked, PinState.Damaged -> error("the new pin cannot be judged")
        }
    }

    /*
     * Every write below runs under [LOCK] and re-reads the record it replaces, because a write decided before a
     * suspension (a fetch) must not land over a fork mark set meanwhile (design §4.4 "A fork is durable"): the only
     * way a fork mark goes is [remove], which is "Forget this server". The lock is shared by every PinStore so two
     * stores over one device state cannot interleave either.
     */

    /**
     * Stores [pin] in force. Refused (false, nothing written) when the origin's record is forked or damaged: a fork
     * mark is never cleared by a write, and a record that cannot be read is never written over.
     */
    fun put(pin: CardPin): Boolean = synchronized(LOCK) {
        settle()
        if (mark(pin.origin) != Mark.None) return@synchronized false
        when (stateOf(pin.origin)) {
            is PinState.Forked, PinState.Damaged -> false
            PinState.None, is PinState.Pinned -> { write(pin, forked = false); true }
        }
    }

    /**
     * Compare-and-set: stores [pin] only when the origin's record is still exactly the one the caller read: no pin
     * when [expected] is null, else [expected] in force (not forked). False, and nothing written, otherwise.
     */
    internal fun replace(expected: CardPin?, pin: CardPin): Boolean = synchronized(LOCK) {
        settle()
        if (!holds(pin.origin, expected)) return@synchronized false
        write(pin, forked = false)
        true
    }

    /**
     * Marks the origin's pin forked, as a compare-and-set against [judged], the pin the caller judged the served chain
     * against: only while the stored record is still exactly [judged] in force, with no move
     * mark. A judgement made before a suspension (a fetch) therefore never lands on a pin written, moved or forgotten
     * meanwhile: not on a fresh Trust Gate pin after an operator reset, not as a second record at the old origin of a
     * move, and it never brings a forgotten pin back. Durable until [remove].
     *
     * True when the record holds [judged] forked now (written here, or already so); false, and nothing written,
     * otherwise (a damaged record stays damaged; another pin, no pin or a move mark is left as it is).
     */
    fun markForked(judged: CardPin): Boolean = synchronized(LOCK) {
        settle()
        if (mark(judged.origin) != Mark.None) return@synchronized false
        when (val s = stateOf(judged.origin)) {
            is PinState.Pinned -> if (s.pin == judged) { write(judged, forked = true); true } else false
            is PinState.Forked -> s.pin == judged
            PinState.None, PinState.Damaged -> false
        }
    }

    /**
     * Removes the origin's pin whatever it holds, fork mark and move mark included: "Forget this server" (design §4.4).
     * Forgetting the new origin of a move this store could not settle ends that move: its intent goes with the pin, and
     * the old origin reads again as it is stored.
     */
    fun remove(origin: String): Unit = synchronized(LOCK) {
        delete(origin)
        state.set(MOVE_PREFIX + origin, null)
        if (unsettled?.isEmpty() != true) settledAt = -1
    }

    /**
     * "Forget this server" in full (design §4.4, §12.3: the namespace's card pin and data): removes, in this order,
     * 1. the records of every account kept under [origin]: those named in [accounts] (user ids; a host passes the kept
     *    session's) and those this store finds in the origin's own records (`<prefix><origin>|<userId>…`): the account
     *    state copy and its marks (`ovh.acct|`), the vault logs (`ovh.log|`), the recovery mirror (`ovh.rmirror|`), the
     *    escrow mark (`ovh.escrowfp|`) and the item engine's records (`ovh.items|`), kept by the account's id alone, so
     *    only for an account that nothing at ANOTHER origin ties ([tiedElsewhere]: the same id served there too);
     * 2. every per-origin record of [origin] ([serverKeyed]: hosts' registered prefixes and the session keeper's records of
     *    which account each address there is included);
     * 3. the identity record (`ovh.identity|<userId>`) of every account there (those of step 1 and those an address's
     *    record there names), except one that something at ANOTHER origin ties ([tiedElsewhere]); where an address's
     *    record cannot be read, none (it names every account), and the answer is [ServerForgotten.CANNOT_READ];
     * 4. last, the pin with its fork mark and its move mark, whatever state it is in.
     *
     * Local only (nothing is dialed), so it works under a forked, damaged or unreadable pin and with no session. It is the
     * person's own act of making the server new to this device. Records outside this device state are the host's: the kept
     * session and quick-unlock key, the item cache files, and any per-origin record under a prefix it did not register.
     */
    fun wipeOrigin(origin: String, accounts: Collection<String> = emptyList(), tied: Collection<String> = emptyList()): ServerForgotten = synchronized(LOCK) {
        var failed: String? = null
        val keys = try { state.keys() } catch (e: Exception) { null }
        if (keys == null) {
            failed = ServerForgotten.CANNOT_LIST
        } else {
            val prefixes = serverKeyed()
            val here = keys.filter { originOf(it) == origin }
            val found = here.mapNotNull { k ->
                val prefix = prefixes.firstOrNull { k.startsWith(it) } ?: return@mapNotNull null
                k.removePrefix(prefix).split('|').getOrNull(1)
            }
            val users = (accounts + found).filter { TrustGrammar.isUuid(it) }.toSet()
            // The account each address's record names (`<userId>|<identity key>`), at every origin. One that cannot be read
            // names every account: then no identity record goes, everything else does, and the answer says so.
            val (named, unreadable, attemptsOnly) = addressRecords(state, keys)
            if (unreadable.isNotEmpty()) failed = ServerForgotten.CANNOT_READ
            // An account that something at another origin ties keeps what is kept by its id alone: another server serves it.
            // [tied]: accounts a caller found tied before it removed anything of its own (a confirmed deletion reads its tie
            // before the keeper removes the address's record here, which a tie can run through).
            val untied = users.filter { it !in tied && !tiedElsewhere(it, origin, keys, named, unreadable, attemptsOnly) }
            val owned = keys.filter { k -> untied.any { u -> ACCOUNT_WIPED.any { p -> k == p + u || k.startsWith("$p$u|") } } }
            val namedHere = named.filterKeys { originOf(it) == origin }.values.filterNotNull()
            val identities = if (unreadable.isNotEmpty()) emptyList() else (users + namedHere)
                .filter { TrustGrammar.isUuid(it) && it !in tied && !tiedElsewhere(it, origin, keys, named, unreadable, attemptsOnly) }.map { IDENTITY_PREFIX + it }
            for (k in owned + here + identities) {
                try { state.set(k, null) } catch (e: Exception) { failed = ServerForgotten.CANNOT_DELETE }
            }
        }
        try {
            delete(origin)
            state.set(MOVE_PREFIX + origin, null)
        } catch (e: Exception) {
            failed = ServerForgotten.CANNOT_DELETE
        }
        if (unsettled?.isEmpty() != true) settledAt = -1
        failed?.let { ServerForgotten.Partly(it) } ?: ServerForgotten.Done
    }

    /** Removes the origin's pin only while it is in force with [hash]; a forked record stays. */
    internal fun removeIf(origin: String, hash: String): Boolean = synchronized(LOCK) {
        settle()
        val s = stateOf(origin) as? PinState.Pinned ?: return@synchronized false
        if (s.pin.hash != hash) return@synchronized false
        delete(origin)
        true
    }

    /** How [move] ended. */
    internal enum class MoveOutcome { MOVED, CHANGED, TARGET_TAKEN, CANNOT_CARRY }

    /**
     * Follows a move as one step: [from] must still hold [from] in force and [to]'s namespace no pin; every per-origin
     * record must be carriable ([planMove]). Then, in this order: [to]'s intent naming [from]'s origin, the new pin,
     * the records carried, the old pin removed, and last the intent cleared, or with [marked] turned into the
     * namespace phase, so the new origin is never open before the host moved its namespace ([clearMove]).
     *
     * A write that throws stops the move where it is and the exception is the answer; every store in this process then
     * settles it before its next answer ([settle]), as a store does after a restart.
     */
    internal fun move(from: CardPin, to: CardPin, marked: Boolean = false): MoveOutcome = synchronized(LOCK) {
        settle()
        if (!holds(from.origin, from)) return@synchronized MoveOutcome.CHANGED
        if (stateOf(to.origin) != PinState.None || mark(to.origin) != Mark.None) return@synchronized MoveOutcome.TARGET_TAKEN
        val carried = planMove(from.origin, to.origin)
            ?: return@synchronized if (keysListable()) MoveOutcome.TARGET_TAKEN else MoveOutcome.CANNOT_CARRY
        try {
            state.set(MOVE_PREFIX + to.origin, intent(from.origin, PHASE_BEGUN, marked))
            write(to, forked = false)
            carry(carried)
            delete(from.origin)
            state.set(MOVE_PREFIX + to.origin, if (marked) intent(from.origin, PHASE_NAMESPACE, true) else null)
        } catch (e: Throwable) {
            interrupted++
            throw e
        }
        MoveOutcome.MOVED
    }

    /** Also false while a move to [origin] is unfinished: no write lands on a pin whose namespace has not moved. */
    private fun holds(origin: String, expected: CardPin?): Boolean = if (mark(origin) != Mark.None) false else when (val s = stateOf(origin)) {
        PinState.None -> expected == null
        is PinState.Pinned -> expected != null && s.pin == expected
        is PinState.Forked, PinState.Damaged -> false
    }

    private fun write(pin: CardPin, forked: Boolean) {
        val s = Stored(pin.instanceId, pin.seq, pin.hash, pin.origin, pin.name, pin.kind, pin.operator, pin.operatorSignKey,
            pin.recoveryFp, pin.root.code, pin.rootAccount, pin.card0Hash, forked)
        state.set(KEY_PREFIX + pin.origin, WireJson.json.encodeToString(Stored.serializer(), s))
        index()?.let { all -> if (pin.origin !in all) writeIndex(all + pin.origin) }
    }

    private fun delete(origin: String) {
        state.set(KEY_PREFIX + origin, null)
        index()?.let { all -> writeIndex(all - origin) }
    }

    /**
     * The per-origin records to carry from [from] to [to] when a move is followed (design §4.4 "A namespace's trust
     * records move with its pin"), as (old key, new key) pairs; null when they cannot be carried: the store cannot list
     * its keys, or a record already exists under [to] (a move never replaces what the new origin holds).
     *
     * Every store the engine keys by origin ([ORIGIN_KEYED]): link secrets and comparison records, contact currency
     * and the one-tap mark, the device-link bundle's vault checkpoints, setup offers, assisted-recovery state and the
     * device record (`deviceSecret`, `deviceId`). The pin itself, with its fork mark, is moved by [CardTrust.followMove].
     * The account-state document, its high-water mark and CAS token, the vault-log states, hashes, checkpoints and
     * pending appends, the identity record and the recovery mirrors are keyed by the account's `userId`, not by origin:
     * in one store they stay where they are and stay in force after the move.
     */
    internal fun planMove(from: String, to: String): List<Pair<String, String>>? {
        val all = state.keys() ?: return null
        // The target holds no per-origin record at all, carried or not: this device keeps
        // one namespace per origin, and a move never joins two.
        if (all.any { originOf(it) == to }) return null
        return carriable(from, to, all)
    }

    /** The origin a per-origin record ([serverKeyed]) is kept under; null for any other key. */
    private fun originOf(key: String): String? {
        val prefix = serverKeyed().firstOrNull { key.startsWith(it) } ?: return null
        return key.removePrefix(prefix).substringBefore('|')
    }

    /**
     * Every record still under [from]'s namespace with its key under [to]'s ([planMove] without its check, for settling
     * a move stopped part-way: a record already copied is copied again with the same value, which is idempotent).
     */
    private fun carriable(from: String, to: String, all: Set<String>? = state.keys()): List<Pair<String, String>>? {
        val prefixes = serverKeyed()
        return all?.mapNotNull { key ->
            val prefix = prefixes.firstOrNull { key.startsWith(it) } ?: return@mapNotNull null
            val rest = key.removePrefix(prefix)
            val origin = rest.substringBefore('|')
            if (origin != from) null else key to (prefix + to + rest.removePrefix(origin))
        }
    }

    internal fun keysListable(): Boolean = state.keys() != null

    /** Copies each planned record to its new key, then removes the old one. Nothing is reset: values move as they are. */
    internal fun carry(moves: List<Pair<String, String>>) {
        for ((old, new) in moves) state.set(new, state.get(old))
        for ((old, _) in moves) state.set(old, null)
    }

    /** Every origin with a record (decodable or not). A damaged index is left as it is and read as empty. */
    fun origins(): List<String> {
        settle()
        return index() ?: emptyList()
    }

    private fun index(): List<String>? {
        val text = state.get(KEY_INDEX) ?: return emptyList()
        return runCatching { WireJson.json.decodeFromString(ListSerializer(String.serializer()), text) }.getOrNull()
    }

    private fun writeIndex(all: List<String>) =
        state.set(KEY_INDEX, WireJson.json.encodeToString(ListSerializer(String.serializer()), all.distinct().sorted()))

    companion object {
        private val LOCK = SynchronizedObject()
        const val KEY_PREFIX = "ovh.pin|"
        const val KEY_INDEX = "ovh.pins"

        /**
         * `ovh.moving|<new origin>` = a move's intent ([Intent]): written first by every move, cleared at its end, or
         * kept in the namespace phase while a followed move waits for the host's namespace.
         */
        internal const val MOVE_PREFIX = "ovh.moving|"
        private const val PHASE_BEGUN = "begun"
        private const val PHASE_NAMESPACE = "namespace"

        /** How many moves in this process stopped at a write that threw; a store settles again when it grows. */
        private var interrupted = 0

        /**
         * The key prefixes of every record the engine keeps per origin (`<prefix><origin>` or `<prefix><origin>|…`), the
         * app interface's two included (`ovh.notused|`, `ovh.quick.offer|`). A host adds its own with [carryWithMoves].
         */
        internal val ORIGIN_KEYED: List<String> = listOf(
            "ovh.links|", "ovh.links.dropped|", "ovh.codes|", "ovh.current|", "ovh.onetap|", "ovh.bundlevaults|", "ovh.setup|",
            "ovh.assist|", "ovh.dev|", "ovh.notused|", "ovh.quick.offer|",
        )

        /** The prefixes hosts registered ([carryWithMoves]), process-wide: replaced whole under [LOCK], read without it. */
        @kotlin.concurrent.Volatile
        private var registered: List<String> = emptyList()

        private val PREFIX_GRAMMAR = Regex("^[a-z][a-z0-9.-]*\\|$")

        /**
         * The key prefixes of the records the engine kept by account (`<prefix><userId>…`): never per origin. The engine's
         * sweep of accounts the device no longer knows removes exactly these.
         */
        internal val ACCOUNT_KEYED =listOf("ovh.acct|", "ovh.log|", "ovh.identity|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.items|")

        /** The account-keyed records [wipeOrigin] deletes by account: all of [ACCOUNT_KEYED] but the identity record. */
        private const val IDENTITY_PREFIX = "ovh.identity|"
        private val ACCOUNT_WIPED = ACCOUNT_KEYED - IDENTITY_PREFIX

        /**
         * The session keeper's records of which account an address is at a server (`<prefix><origin>|<emailNorm>` →
         * `<userId>|<identity key>`): per origin, carried with a followed move and removed by [wipeOrigin], beside
         * [originKeyed]; a move to an origin that holds one is refused as for any other record there.
         */
        private const val ADDRESS_PREFIX = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX

        /** A device's record of an address at an origin ([KnownDevices]): it ties only where it holds a device id. */
        private const val DEVICE_PREFIX = KnownDevices.PREFIX

        /** Every per-origin prefix [wipeOrigin] and a move read: [originKeyed] and the keeper's address records. */
        internal fun serverKeyed(): List<String> = (originKeyed() + ADDRESS_PREFIX).distinct()

        /**
         * Whether anything at an origin other than [origin] ties the account [userId], among the device state's [keys]
         * ([named]: each address record's key → the account its value names, as read once): an address record there that
         * names it; any record there keyed by its id under a per-server prefix ([serverKeyed]: the key a forgetting keeps
         * of an earlier account among them); any record there for an address whose record at [origin] names it (a device's
         * record of that address, or an address record there naming it), unless that origin's own address record for the
         * address names ANOTHER account: then the address there is someone else's (the same email address used for another
         * account at an unrelated server), and nothing there for it ties. Records there for the address with no address
         * record there still tie (the old address of a server that moved), except a device's record that holds no device id
         * ([attemptsOnly]: no session was ever opened for it there, only an attempt was made); a device's record that
         * cannot be read as one ties. An address record there that cannot be read ([unreadable]), or whose value names no
         * account, names every account. The kept session is not in this store: its account is the host's to pass. One rule
         * for every record that names an account and no server.
         */
        internal fun tiedElsewhere(
            userId: String, origin: String, keys: Collection<String>, named: Map<String, String?>, unreadable: Collection<String>,
            attemptsOnly: Collection<String>,
        ): Boolean {
            val prefixes = serverKeyed()
            fun split(k: String): Pair<String, List<String>>? {
                val prefix = prefixes.firstOrNull { k.startsWith(it) } ?: return null
                return prefix to k.removePrefix(prefix).split('|')
            }
            // The addresses whose record at [origin] names the account.
            val addresses = named.filter { (k, u) -> u == userId && split(k)?.second?.firstOrNull() == origin }
                .keys.mapNotNull { split(it)?.second?.getOrNull(1) }.toSet()
            if (unreadable.any { split(it)?.second?.firstOrNull() != origin }) return true
            // The address at [at] is another account's there: that origin's address record for it names another account.
            fun anotherAccounts(at: String, address: String): Boolean =
                named["$ADDRESS_PREFIX$at|$address"]?.let { TrustGrammar.isUuid(it) && it != userId } == true
            return keys.any { k ->
                val (prefix, parts) = split(k) ?: return@any false
                val second = parts.getOrNull(1)
                parts[0] != origin && second != null &&
                    (second == userId || (second in addresses && !anotherAccounts(parts[0], second) && k !in attemptsOnly) ||
                        (prefix == ADDRESS_PREFIX && named[k] == userId))
            }
        }

        /**
         * [tiedElsewhere] over [state] as it is now. A store that cannot list its keys cannot tell, and counts as a tie
         * (the safer side: the record stays).
         */
        internal fun tiedElsewhere(state: DeviceState, userId: String, origin: String): Boolean {
            val keys = try { state.keys() } catch (e: Exception) { null } ?: return true
            val (named, unreadable, attemptsOnly) = addressRecords(state, keys)
            return tiedElsewhere(userId, origin, keys, named, unreadable, attemptsOnly)
        }

        /**
         * Every address record among [keys], read once: its key → the account its value names; and those that threw. Also
         * every device's record among them read as one that holds no device id ([KnownDevices.holdsDeviceId] false: only an
         * attempt was made there); one that cannot be read, or not as a device's record, is not among them.
         */
        private fun addressRecords(state: DeviceState, keys: Collection<String>): Triple<Map<String, String?>, List<String>, Set<String>> {
            val named = HashMap<String, String?>()
            val unreadable = ArrayList<String>()
            val attemptsOnly = HashSet<String>()
            for (k in keys) if (k.startsWith(ADDRESS_PREFIX)) {
                try { named[k] = state.get(k)?.substringBefore('|') } catch (e: Exception) { unreadable += k }
            } else if (k.startsWith(DEVICE_PREFIX)) {
                val text = try { state.get(k) } catch (e: Exception) { continue }
                if (text == null || KnownDevices.holdsDeviceId(text) == false) attemptsOnly += k
            }
            return Triple(named, unreadable, attemptsOnly)
        }

        /**
         * Registers [prefix] as the prefix of records a host keeps per origin, keyed `<prefix><origin>` or
         * `<prefix><origin>|…` in the same device state as the pins (design §4.4 "A namespace's trust records move with
         * its pin"): from then on, in this process, a followed move carries them with the pin like the engine's own
         * ([ORIGIN_KEYED]), a move to an origin holding one is refused, and [PinStore.wipeOrigin] deletes them. A host
         * registers each of its prefixes once at start, before any move can be followed. A prefix is lowercase letters,
         * digits, `.` and `-`, ending in `|`; the pin store's own and the account-keyed prefixes are refused. Registering
         * one already known changes nothing. Throws [IllegalArgumentException] for a prefix it refuses.
         */
        fun carryWithMoves(prefix: String) {
            require(PREFIX_GRAMMAR.matches(prefix)) { "not a per-origin key prefix: $prefix" }
            require(prefix != KEY_PREFIX && prefix != MOVE_PREFIX && prefix !in ACCOUNT_KEYED) { "a reserved key prefix: $prefix" }
            synchronized(LOCK) { if (prefix !in ORIGIN_KEYED && prefix !in registered) registered = registered + prefix }
        }

        /** Every per-origin prefix known now: the engine's and those hosts registered. */
        internal fun originKeyed(): List<String> = ORIGIN_KEYED + registered
    }
}

/**
 * [InstanceTrust] over [PinStore], the chain verifier and the instance's `GET /instance`.
 *
 * Trust: a pin is made only from verified cards, anchored by the root's own value (baked or kit
 * `card0Hash`, an offer's signed `cardHash`, this device's own card 0 under its own key) or by the
 * person's Trust Gate confirmation of exactly the chain shown. An existing pin is never swapped by a
 * first-pin call; a fork is durable; a damaged record blocks. Served JSON (`setup`, the policy's
 * `instanceName` or `canonicalOrigin`) never becomes a pin.
 */
class CardTrust(
    private val store: PinStore,
    private val verifier: CardChainVerifier,
    private val clientFor: (String) -> WireClient,
    private val crypto: CryptoProvider,
    private val baked: BakedInstance?,
    private val storeBuild: Boolean,
    /** The operator account's own devices pass their keys so the chain gets `operator_key_mismatch` (VR-11). */
    private val operatorKeys: OperatorKeys? = null,
    /**
     * A host that keeps the device state in a directory per (origin, user) passes its [NamespaceMover]: a followed move
     * calls it after the pin moved and before the new origin is fetched, and the new origin stays
     * [OriginAccess.MOVING] (nothing sent, nothing written) until it succeeded. Null: one namespace for every origin.
     */
    private val onMoved: NamespaceMover? = null,
) : InstanceTrust {

    override fun pinState(origin: String): PinState = store.state(origin)

    override fun access(origin: String): OriginAccess = store.access(origin)

    override fun pinFor(origin: String): CardPin? = store.get(origin)

    override fun pins(): List<CardPin> = store.origins().mapNotNull(store::get)

    override fun gatePins(): List<GatePin> = store.origins().mapNotNull { o ->
        when (val s = store.state(o)) {
            // An unfinished move (or its unreadable mark) leaves nothing: the device's copy is not under this origin yet.
            is PinState.Pinned -> if (store.access(o) == OriginAccess.OPEN) GatePin(o, s.pin.root, s.pin.rootAccount)
                else GatePin(o, s.pin.root, s.pin.rootAccount, blocked = true, damaged = true)
            is PinState.Forked -> GatePin(o, s.pin.root, s.pin.rootAccount, blocked = true)
            PinState.Damaged -> GatePin(o, PinRoot.ENROL, null, blocked = true, damaged = true)
            PinState.None -> null
        }
    }

    private sealed class Fetch {
        data class Cards(val check: ChainCheck) : Fetch()
        data object Empty : Fetch()
        data object Unreachable : Fetch()
    }

    private suspend fun fetch(origin: String): Fetch {
        val r = clientFor(origin).call(WireRoute.INSTANCE, decode = { WireJson.json.decodeFromString(InstanceResponse.serializer(), it) })
        val resp = (r as? WireResult.Ok)?.value ?: return Fetch.Unreachable
        if (resp.cards.isEmpty()) return Fetch.Empty
        val frames = resp.cards.map { runCatching { Bytes.fromB64(it) }.getOrNull() ?: return Fetch.Cards(ChainCheck.Refused("bad_frame")) }
        return Fetch.Cards(verifier.verify(frames, keys))
    }

    /** The signed-in account's own Ed25519 key ([signedIn]), for its own `userId` only. */
    private class OwnKey(val userId: String, val signKey: ByteArray)

    private val ownLock = SynchronizedObject()
    private var own: OwnKey? = null

    /**
     * The keys the chain is verified with: the host's [operatorKeys] first, then the signed-in account's own key for its
     * own `userId`. A card naming this account as `operator` must name exactly this account's Ed25519 key, byte for byte
     * (`operator_key_mismatch`, design §4.1, VR-11); every other card is checked as before.
     */
    private val keys = OperatorKeys { id ->
        operatorKeys?.signKeyOf(id) ?: synchronized(ownLock) { own?.takeIf { it.userId == id }?.signKey?.copyOf() }
    }

    /**
     * The device's own check of its operator key (design §4.1, VR-11): from now on every chain this device verifies, at
     * every origin, refuses a card that names [account] as the operator with any key but [account]'s own Ed25519 signing
     * key (`operator_key_mismatch`; the pin stays and nothing is pinned from it). This is "the operator's own devices
     * check": a device holds that key only while it is signed in to the account the card names, and a card naming another
     * account is not checked. The host calls it when a session of [account] opens (sign-in, unlock, a cold start that
     * reopens the account) and [signedOut] when the session ends. The key is public, so it may stay set while locked.
     */
    fun signedIn(account: io.silencelen.andvari.core.client.onboard.OpenedAccount) {
        val key = account.signing.publicKey.copyOf()
        synchronized(ownLock) { own = OwnKey(account.userId, key) }
    }

    /** Ends [signedIn]'s check: cards are verified with the host's [operatorKeys] only. */
    fun signedOut() {
        synchronized(ownLock) { own = null }
    }

    /**
     * The verified served chain of [origin], or why a first-pin call stops before any root check (§2.4):
     * an empty chain is `withheld` for every root; with no pin, a newest card naming another origin is
     * [FirstPin.OriginMismatch]; with a pin, the chain is judged against it first, so a fork, a withheld
     * chain, a move or a kind change stops the call before any root can act (§4.4, "a root never replaces
     * an existing pin"; a move met under a pin is handled as a move first).
     */
    private suspend fun verifiedCards(origin: String): Pair<ChainCheck.Ok?, FirstPin?> {
        val c = when (val f = fetch(origin)) {
            Fetch.Unreachable -> return null to FirstPin.Unreachable
            Fetch.Empty -> return null to FirstPin.Refused("withheld")
            is Fetch.Cards -> when (val c = f.check) {
                is ChainCheck.Refused -> return null to FirstPin.Refused(c.verdict)
                is ChainCheck.Ok -> c
            }
        }
        if (c.cards.isEmpty()) return null to FirstPin.Refused("withheld")
        val existing = store.get(origin)
        if (existing == null) {
            when (val v = c.roots.typed(origin)) {
                null -> {}
                ORIGIN_MISMATCH -> return null to FirstPin.OriginMismatch(origin, c.cards.last().origin)
                else -> return null to FirstPin.Refused(v)
            }
            return c to null
        }
        return when (val j = CardChainRules.judge(existing, c.cards, baked, storeBuild)) {
            is CardStatus.Ok -> c to null
            // Marked only while the pin judged is still the stored one; else the record changed meanwhile.
            is CardStatus.Fork -> null to (if (store.markForked(existing)) FirstPin.Blocked(store.state(origin)) else lostRace(origin))
            is CardStatus.Withheld -> null to FirstPin.Refused("withheld")
            is CardStatus.Moved, is CardStatus.KindChanged -> null to FirstPin.PinChanged(j)
            is CardStatus.Refused -> null to FirstPin.Refused(j.verdict)
            is CardStatus.PinConflict -> null to FirstPin.PinConflict(existing)
            CardStatus.Unreachable -> null to FirstPin.Unreachable
        }
    }

    /**
     * The one path every first pin takes (design §4.4). With no pin: pin [candidate]. With a pin: judge
     * the served chain against it and refuse on anything but ok; then keep the pin's chain, raising its
     * root only when [root] is stronger. A forked or damaged origin refuses.
     */
    private fun settle(origin: String, cards: List<VerifiedCard>, root: PinRoot, rootAccount: String?): FirstPin {
        // Each write is a compare-and-set against the record read here; a lost race re-reads and decides again.
        repeat(RACE_RETRIES) { settleOnce(origin, cards, root, rootAccount)?.let { return it } }
        return lostRace(origin)
    }

    /** One pass of [settle]; null when the record changed between the read and the write. */
    private fun settleOnce(origin: String, cards: List<VerifiedCard>, root: PinRoot, rootAccount: String?): FirstPin? {
        return when (val st = store.state(origin)) {
            PinState.Damaged, is PinState.Forked -> FirstPin.Blocked(st)
            PinState.None -> {
                if (cards.isEmpty()) return FirstPin.Refused("withheld")
                val pin = CardChainRules.firstPin(cards, root, rootAccount)
                if (!store.replace(null, pin)) return null
                FirstPin.Pinned(pin, PinHandle(origin, pin.hash, madeNow = true))
            }
            is PinState.Pinned -> {
                val existing = st.pin
                when (val j = CardChainRules.judge(existing, cards, baked, storeBuild)) {
                    is CardStatus.Ok -> {
                        val raise = raises(root, existing.root)
                        val pin = if (raise) j.pin.copy(root = root, rootAccount = rootAccount) else j.pin
                        if (!store.replace(existing, pin)) return null
                        FirstPin.Pinned(pin, PinHandle(origin, pin.hash, madeNow = false))
                    }
                    // A lost compare-and-set: the record changed since it was read; decide again from it.
                    is CardStatus.Fork -> if (store.markForked(existing)) FirstPin.Blocked(store.state(origin)) else null
                    is CardStatus.Withheld -> FirstPin.Refused("withheld")
                    is CardStatus.Moved, is CardStatus.KindChanged -> FirstPin.PinChanged(j)
                    is CardStatus.Refused -> FirstPin.Refused(j.verdict)
                    is CardStatus.PinConflict -> FirstPin.PinConflict(existing)
                    CardStatus.Unreachable -> FirstPin.Unreachable
                }
            }
        }
    }

    private fun blocked(origin: String): FirstPin? = when (val st = store.state(origin)) {
        PinState.Damaged, is PinState.Forked -> FirstPin.Blocked(st)
        // A move to this origin waits for the host's namespace: nothing is fetched or pinned here meanwhile.
        else -> when (store.access(origin)) {
            OriginAccess.MOVING -> FirstPin.Refused(MOVE_UNFINISHED)
            OriginAccess.BLOCKED -> FirstPin.Blocked(PinState.Damaged)
            OriginAccess.OPEN, OriginAccess.FORKED -> null
        }
    }

    /**
     * Whether a first pin of [root] raises an existing pin of [current] root. The baked root always does (design §4.4
     * "Under an existing pin at the baked origin": the baked checks passing makes the pin's root `baked`), including
     * over a Trust Gate pin of the same rank; every other root only when it ranks higher.
     */
    private fun raises(root: PinRoot, current: PinRoot): Boolean =
        (root == PinRoot.BAKED && current != PinRoot.BAKED) || CardChainRules.rank(root) > CardChainRules.rank(current)

    /** The answer when a pin write kept losing its compare-and-set: what the record holds now, never a write. */
    private fun lostRace(origin: String): FirstPin = when (val st = store.state(origin)) {
        PinState.Damaged, is PinState.Forked -> FirstPin.Blocked(st)
        is PinState.Pinned -> FirstPin.PinConflict(st.pin)
        PinState.None -> FirstPin.Unreachable
    }

    /** The status a refresh answers when its write lost to a write made meanwhile, from what the record holds now. */
    private fun lostRaceStatus(origin: String): CardStatus? = when (val st = store.state(origin)) {
        is PinState.Forked -> CardStatus.Fork(st.pin)
        PinState.Damaged -> CardStatus.Refused(null, "damaged")
        PinState.None -> CardStatus.Refused(null, "no_pin")
        is PinState.Pinned -> null
    }


    override suspend fun pinBaked(origin: String): FirstPin {
        val b = baked ?: return FirstPin.Refused("no_baked_instance")
        if (origin != b.origin) return FirstPin.Refused("not_baked_origin")
        blocked(origin)?.let { return it }
        val (check, stop) = verifiedCards(origin)
        if (stop != null) return stop
        CardChainRules.bakedVerdict(check!!, b, storeBuild)?.let { return FirstPin.Refused(it) }
        return settle(origin, check.cards, PinRoot.BAKED, null)
    }

    override suspend fun pinFromKit(origin: String, card0Hash: String, kitEmailNorm: String): FirstPin {
        blocked(origin)?.let { return it }
        val (check, stop) = verifiedCards(origin)
        if (stop != null) return stop
        val cards = check!!.cards
        when (val v = check.roots.kit(origin, card0Hash)) {
            null -> {}
            "card0_mismatch" -> return gateFor(cards, TrustGateWording.TYPED_ADDRESS, PinRoot.TRUST_GATE, null)
                ?.let { FirstPin.KitAnchorMismatch(it) } ?: FirstPin.Refused(BAD_OPERATOR_KEY)
            else -> return FirstPin.Refused(v)
        }
        if (isBakedOrigin(origin)) {
            CardChainRules.bakedVerdict(check, baked!!, storeBuild)?.let { return FirstPin.Refused(it) }
            return settle(origin, cards, PinRoot.BAKED, null)
        }
        return settle(origin, cards, PinRoot.KIT, kitEmailNorm)
    }

    override suspend fun pinFromLinkOffer(origin: String, instanceId: String, cardHash: String): FirstPin {
        blocked(origin)?.let { return it }
        val (check, stop) = verifiedCards(origin)
        if (stop != null) return stop
        val cards = check!!.cards
        if (isBakedOrigin(origin)) {
            // Design §4.4 "At the baked origin the baked root always comes first": its checks, then the link's own on top.
            CardChainRules.bakedVerdict(check, baked!!, storeBuild)?.let { return FirstPin.Refused(it) }
            check.roots.offer(origin, cardHash, instanceId)?.let { return FirstPin.Refused(it) }
            return settle(origin, cards, PinRoot.BAKED, null)
        }
        check.roots.offer(origin, cardHash, instanceId)?.let { return FirstPin.Refused(it) }
        return settle(origin, cards, PinRoot.LINK_OFFER, null)
    }

    override fun isBakedOrigin(origin: String): Boolean = baked != null && origin == baked.origin

    override suspend fun setupVerdictAtBaked(origin: String): String {
        val b = baked ?: return "no_baked_instance"
        if (origin != b.origin) return "not_baked_origin"
        when (val stop = blocked(origin)) {
            is FirstPin.Blocked -> return stop.verdict
            is FirstPin.Refused -> return stop.reason
            else -> {}
        }
        val (check, stop) = verifiedCards(origin)
        if (stop != null) return when (stop) {
            is FirstPin.Refused -> stop.reason
            is FirstPin.OriginMismatch -> stop.verdict
            is FirstPin.Blocked -> stop.verdict
            is FirstPin.PinConflict -> stop.verdict
            FirstPin.Unreachable -> "unreachable"
            else -> "pin_changed"
        }
        return CardChainRules.bakedVerdict(check!!, b, storeBuild) ?: "already_set_up"
    }

    /** The Trust Gate for the newest of [cards]; null when its operator key has no X25519 image, so no fingerprint can be shown. */
    private fun gateFor(cards: List<VerifiedCard>, wording: TrustGateWording, root: PinRoot, account: String?): FirstPin.NeedsTrustGate? {
        val candidate = CardChainRules.firstPin(cards, root, account)
        val fp = operatorShortFp(candidate.operatorSignKey) ?: return null
        return FirstPin.NeedsTrustGate(candidate.origin, candidate.name, fp, wording, TrustGateTicket(candidate.origin, wording, candidate))
    }

    /**
     * The operator key's 32-hex short identity fingerprint, over its X25519 image (design §4.1), or null when the key has
     * no image ([InstanceCard.operatorIdentityKey]): a verified card can name such a key, and the gate then refuses.
     *
     * The one value every screen shows for an operator key: the Trust Gate, the instance details and the kind-change
     * prompt pass a pin's or a card's `operatorSignKey` here, never a fingerprint of the Ed25519 key itself.
     */
    fun operatorShortFp(operatorSignKeyB64: String): String? = operatorShortFp(crypto, operatorSignKeyB64)

    companion object {
        /** [operatorShortFp] for a host that holds no [CardTrust] (the same value). */
        fun operatorShortFp(crypto: CryptoProvider, operatorSignKeyB64: String): String? {
            val x = InstanceCard.operatorIdentityKey(crypto, operatorSignKeyB64) ?: return null
            return Fingerprint.shortForm(Bytes.toHexLower(crypto.sha256(x)))
        }

        /** How often a pin write that lost its compare-and-set decides again before answering from the record. */
        private const val RACE_RETRIES = 3
    }

    override suspend fun beginTrustGate(origin: String, wording: TrustGateWording): FirstPin {
        if (isBakedOrigin(origin)) return pinBaked(origin)
        blocked(origin)?.let { return it }
        val (check, stop) = verifiedCards(origin)
        if (stop != null) return stop
        val cards = check!!.cards
        val root = if (wording == TrustGateWording.ENROL_LINK) PinRoot.ENROL else PinRoot.TRUST_GATE
        // Re-read after the fetch: a fork marked meanwhile stops the gate here.
        blocked(origin)?.let { return it }
        val existing = store.get(origin)
        if (existing != null) {
            // verifiedCards judged the chain against the pin: anything but ok has already stopped.
            val j = CardChainRules.judge(existing, cards, baked, storeBuild) as? CardStatus.Ok ?: return FirstPin.PinConflict(existing)
            if (!raises(root, existing.root)) {
                if (!store.replace(existing, j.pin)) return lostRace(origin)
                return FirstPin.Pinned(j.pin, PinHandle(origin, j.pin.hash, madeNow = false))
            }
            val candidate = j.pin.copy(root = root, rootAccount = null)
            val fp = operatorShortFp(candidate.operatorSignKey) ?: return FirstPin.Refused(BAD_OPERATOR_KEY)
            return FirstPin.NeedsTrustGate(origin, candidate.name, fp, wording, TrustGateTicket(origin, wording, candidate))
        }
        return gateFor(cards, wording, root, null) ?: FirstPin.Refused(BAD_OPERATOR_KEY)
    }

    override suspend fun confirmTrustGate(ticket: TrustGateTicket): FirstPin {
        repeat(RACE_RETRIES) { confirmOnce(ticket)?.let { return it } }
        return lostRace(ticket.origin)
    }

    /** One pass of [confirmTrustGate]; null when the record changed between the read and the write. */
    private fun confirmOnce(ticket: TrustGateTicket): FirstPin? {
        val c = ticket.candidate
        return when (val st = store.state(ticket.origin)) {
            PinState.Damaged, is PinState.Forked -> FirstPin.Blocked(st)
            PinState.None -> if (store.replace(null, c)) FirstPin.Pinned(c, PinHandle(ticket.origin, c.hash, madeNow = true)) else null
            is PinState.Pinned -> {
                val existing = st.pin
                // The ticket's chain must be the existing pin's chain at or after it.
                if (existing.card0Hash != c.card0Hash || existing.instanceId != c.instanceId || existing.seq > c.seq) return FirstPin.PinConflict(existing)
                if (existing.seq == c.seq && existing.hash != c.hash) return FirstPin.PinConflict(existing)
                if (!raises(c.root, existing.root)) return FirstPin.Pinned(existing, PinHandle(ticket.origin, existing.hash, madeNow = false))
                // A ticket made from a judged chain extends the pin (beginTrustGate judged it); keep the newer of the two.
                val pin = if (c.seq >= existing.seq) c else existing.copy(root = c.root, rootAccount = c.rootAccount)
                if (!store.replace(existing, pin)) return null
                FirstPin.Pinned(pin, PinHandle(ticket.origin, pin.hash, madeNow = false))
            }
        }
    }

    override suspend fun pinFromOwnCard0(origin: String, card0Frame: String, operatorUserId: String, operatorEmailNorm: String, ownSignPub: ByteArray): FirstPin {
        blocked(origin)?.let { return it }
        val frame = runCatching { Bytes.fromB64(card0Frame) }.getOrNull() ?: return FirstPin.Refused("bad_frame")
        return when (val c = verifier.verify(listOf(frame), keys)) {
            is ChainCheck.Refused -> FirstPin.Refused(c.verdict)
            is ChainCheck.Ok -> {
                val card = c.cards.singleOrNull() ?: return FirstPin.Refused("bad_card")
                if (card.seq != 0L || card.origin != origin || card.operator != operatorUserId) return FirstPin.Refused("bad_card")
                // This device's own key signed it (card 0 is self-signed by its operatorSignKey).
                if (card.operatorSignKey != Bytes.toB64(ownSignPub)) return FirstPin.Refused("not_own_card")
                repeat(RACE_RETRIES) {
                    val existing = when (val st = store.state(origin)) {
                        PinState.Damaged, is PinState.Forked -> return FirstPin.Blocked(st)
                        PinState.None -> null
                        is PinState.Pinned -> st.pin
                    }
                    if (existing != null) {
                        if (existing.card0Hash != card.hash) return FirstPin.PinConflict(existing)
                        if (!raises(PinRoot.SETUP, existing.root)) return FirstPin.Pinned(existing, PinHandle(origin, existing.hash, madeNow = false))
                        val pin = existing.copy(root = PinRoot.SETUP, rootAccount = operatorEmailNorm)
                        if (store.replace(existing, pin)) return FirstPin.Pinned(pin, PinHandle(origin, pin.hash, madeNow = false))
                    } else {
                        val pin = CardChainRules.firstPin(c.cards, PinRoot.SETUP, operatorEmailNorm)
                        if (store.replace(null, pin)) return FirstPin.Pinned(pin, PinHandle(origin, pin.hash, madeNow = true))
                    }
                }
                lostRace(origin)
            }
        }
    }

    /** Judge the served chain against the stored pin; marks a fork durably. Does not store moves or kind changes. */
    private suspend fun judgeNow(origin: String): CardStatus = judged(origin).second

    /**
     * [judgeNow], with the pin in force it judged against (null when there was none in force). A fork is marked only on
     * the pin judged ([PinStore.markForked]); when the record changed during the fetch, the origin is judged again from
     * what it holds now.
     */
    private suspend fun judged(origin: String): Pair<CardPin?, CardStatus> {
        repeat(RACE_RETRIES) { judgedOnce(origin)?.let { return it } }
        return null to (lostRaceStatus(origin) ?: CardStatus.Unreachable)
    }

    /** One pass of [judged]; null when a fork could not be marked because the record changed since it was read. */
    private suspend fun judgedOnce(origin: String): Pair<CardPin?, CardStatus>? {
        val pin = when (val st = store.state(origin)) {
            PinState.None -> return null to CardStatus.Refused(null, "no_pin")
            PinState.Damaged -> return null to CardStatus.Refused(null, "damaged")
            is PinState.Forked -> return null to CardStatus.Fork(st.pin)
            is PinState.Pinned -> st.pin
        }
        // A followed move whose host namespace has not moved: the new origin is not fetched (nothing is sent to it).
        when (store.access(origin)) {
            OriginAccess.MOVING -> return null to CardStatus.Refused(pin, MOVE_UNFINISHED)
            OriginAccess.BLOCKED -> return null to CardStatus.Refused(null, "damaged")
            OriginAccess.OPEN, OriginAccess.FORKED -> {}
        }
        val status = when (val f = fetch(origin)) {
            Fetch.Unreachable -> CardStatus.Unreachable
            Fetch.Empty -> CardStatus.Withheld(pin, null)
            is Fetch.Cards -> when (val c = f.check) {
                is ChainCheck.Refused -> CardStatus.Refused(pin, c.verdict)
                is ChainCheck.Ok -> CardChainRules.judge(pin, c.cards, baked, storeBuild)
            }
        }
        if (status is CardStatus.Fork && !store.markForked(pin)) return null
        return pin to status
    }

    override suspend fun refresh(origin: String): CardStatus {
        repeat(RACE_RETRIES) {
            val (read, status) = judged(origin)
            // The write is a compare-and-set against the pin judged: a fork marked during the fetch, a forget or another
            // refresh's newer pin is never written over (design §4.4 "A fork is durable").
            if (status !is CardStatus.Ok || read == null) return status
            if (store.replace(read, status.pin)) return status
            lostRaceStatus(origin)?.let { return it }
            // Another refresh advanced the pin meanwhile: judge again from it.
        }
        return lostRaceStatus(origin) ?: CardStatus.Unreachable
    }

    override suspend fun followMove(status: CardStatus.Moved): CardStatus {
        // Re-judge: the prompt's fields are not trusted, only what the served chain says now.
        val now = judgeNow(status.pinned.origin)
        // The same move followed before and stopped once the new pin was written (the app stopped, or a write threw):
        // the store settled it as done, so this attempt finishes it rather than failing on the missing old pin.
        if (now is CardStatus.Refused && now.pinned == null && now.verdict == "no_pin") followedBefore(status)?.let { return it }
        if (now !is CardStatus.Moved) return now
        if (now.storeBuildMustUpdate) return now
        if (now.pinned != status.pinned || now.newest.hash != status.newest.hash) return CardStatus.Refused(now.pinned, "stale_prompt")
        // The target is checked before either pin is touched (design §4.4): its grammar, that it holds no pin, and that
        // every record of the old namespace can be carried there without replacing one.
        if (!io.silencelen.andvari.core.trust.TrustGrammar.isOrigin(now.newest.origin)) return CardStatus.Refused(now.pinned, "bad_origin")
        // This device cannot keep a pin for the baked origin under any instance but the baked one:
        // there the baked root always comes first. An origin that already holds a record (a pin of any state, a
        // move mark, or any per-origin record) is refused by the move itself as [CardStatus.PinConflict], also before
        // either pin is touched.
        if (baked != null && now.newest.origin == baked.origin &&
            (now.pinned.card0Hash != baked.card0Hash || now.pinned.instanceId != baked.instanceId)
        ) return CardStatus.Refused(now.pinned, MOVE_TO_BAKED_ORIGIN)
        // One locked step against the pin judged: a fork marked during the fetch is never moved away or cleared.
        // With a host namespace, the new origin is marked MOVING in the same step and stays closed until the host moved it.
        when (store.move(now.pinned, now.newest, marked = onMoved != null)) {
            PinStore.MoveOutcome.MOVED -> {}
            PinStore.MoveOutcome.CHANGED -> return lostRaceStatus(now.pinned.origin) ?: CardStatus.Refused(now.pinned, "stale_prompt")
            PinStore.MoveOutcome.TARGET_TAKEN -> return CardStatus.PinConflict(now.pinned, now.newest)
            PinStore.MoveOutcome.CANNOT_CARRY -> return CardStatus.Refused(now.pinned, CANNOT_CARRY_RECORDS)
        }
        // Before the new origin is fetched: the host moves its directory, so no session there opens on an empty one.
        hostMove(now.pinned.origin, now.newest.origin)?.let { return it }
        return afterMove(now.newest)
    }

    /**
     * Finishes a followed move to [origin] whose host namespace did not move ([PinStore.unfinishedMove]: the
     * [NamespaceMover] failed, or the app stopped between the two). Calls the mover again; on success the origin opens
     * and is refreshed as [followMove] does ([CardStatus.Ok] with `newKitDue`). Still failing:
     * `CardStatus.Refused(pin at origin, MOVE_UNFINISHED)`, nothing sent. No move pending: the answer of [refresh].
     * A move mark that cannot be read: `Refused(null, "damaged")`; only "Forget this server" clears it.
     */
    suspend fun finishMove(origin: String): CardStatus {
        val from = store.unfinishedMove(origin) ?: return refresh(origin)
        hostMove(from, origin)?.let { return it }
        return afterMove(store.get(origin) ?: return lostRaceStatus(origin) ?: CardStatus.Refused(null, "no_pin"))
    }

    /**
     * [followMove] of a prompt whose move this device already made: no pin at the old origin, and a pin in force at the
     * new one from the same instance (same card 0 and instance id; only the pin is used, never the prompt's fields).
     * Answers as [finishMove] does, with `newKitDue` also when no host namespace is pending. Null when that is not so.
     */
    private suspend fun followedBefore(status: CardStatus.Moved): CardStatus? {
        val to = status.newest.origin
        val pin = store.get(to) ?: return null
        if (pin.card0Hash != status.pinned.card0Hash || pin.instanceId != status.pinned.instanceId) return null
        val from = store.unfinishedMove(to) ?: return afterMove(pin)
        hostMove(from, to)?.let { return it }
        return afterMove(store.get(to) ?: return lostRaceStatus(to) ?: CardStatus.Refused(null, "no_pin"))
    }

    /** The old origin of a move to [origin] still waiting for the host's namespace; null when none is pending. */
    fun unfinishedMove(origin: String): String? = store.unfinishedMove(origin)

    /**
     * Runs the host's [NamespaceMover] for a move [from] → [to] and opens [to] when it succeeded: null then (also with no
     * mover). Otherwise the status to answer; [to] stays [OriginAccess.MOVING]. An exception from the host is its failure.
     */
    private fun hostMove(from: String, to: String): CardStatus? {
        val mover = onMoved ?: return if (store.unfinishedMove(to) == null) null else CardStatus.Refused(store.get(to), MOVE_UNFINISHED)
        val moved = try {
            mover.onMoved(from, to)
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            false
        }
        if (!moved) return CardStatus.Refused(store.get(to), MOVE_UNFINISHED)
        if (store.clearMove(to, from)) return null
        // The mark changed meanwhile: another finish cleared it (the origin is open), or "Forget this server" removed it
        // with the pin. Answer from what the records hold now.
        if (store.access(to) == OriginAccess.OPEN && store.get(to) != null) return null
        return lostRaceStatus(to) ?: CardStatus.Refused(store.get(to), MOVE_UNFINISHED)
    }

    /** The answer of a followed move once the namespace is at [moved]'s origin: its refresh, with the new-kit flag. */
    private suspend fun afterMove(moved: CardPin): CardStatus =
        // A recovery kit names the address it was made for (design §4.4, §10): after a move the person makes a new one.
        when (val after = refresh(moved.origin)) {
            is CardStatus.Ok -> after.copy(newKitDue = true)
            // The move stands; the new origin's chain is only late or out of reach for now.
            is CardStatus.Withheld, CardStatus.Unreachable -> CardStatus.Ok(store.get(moved.origin) ?: moved, newKitDue = true)
            else -> after
        }

    override suspend fun acceptKindChange(status: CardStatus.KindChanged): CardStatus {
        val now = judgeNow(status.pinned.origin)
        if (now !is CardStatus.KindChanged) return now
        if (now.storeBuildMustUpdate) return now
        if (now.pinned != status.pinned || now.newest.hash != status.newest.hash) return CardStatus.Refused(now.pinned, "stale_prompt")
        // Both writes are compare-and-set against the pin judged, so a fork marked during the fetch stands.
        if (now.newest.origin == now.pinned.origin) {
            if (!store.replace(now.pinned, now.newest)) return lostRaceStatus(now.pinned.origin) ?: CardStatus.Refused(now.pinned, "stale_prompt")
            return CardStatus.Ok(now.newest)
        }
        // A kind change that also moved: the kind is accepted on the old namespace, and the move is its own prompt.
        if (!store.replace(now.pinned, now.pinned.copy(kind = now.newest.kind))) {
            return lostRaceStatus(now.pinned.origin) ?: CardStatus.Refused(now.pinned, "stale_prompt")
        }
        return judgeNow(now.pinned.origin)
    }

    /** "Forget this server": the one path that removes a fork mark (design §4.4). The pin only: see [forgetServer]. */
    override fun forget(origin: String) = store.remove(origin)

    /**
     * "Forget this server" with the data the device kept for it ([PinStore.wipeOrigin]): the pin, every per-origin record
     * and the records of the accounts kept under [origin] ([accounts]: the kept session's user id, if any; the store
     * finds the others). Local, so it works under a fork, a damaged pin and with no session. The host then deletes what
     * lives outside the device state: it ends the kept session on the device without telling the server, drops the
     * quick-unlock key, and deletes the item cache of each account.
     *
     * A host that keeps assisted-recovery requests in a second store (the session-grade `secure` store it gives
     * `WireAssistedRecovery`, when that is not this pin store's device state: the command-line tool's case) must also
     * remove the request kept there: read the pin IN FORCE OR FORKED first, [pinForForget]`(origin)` (a forked server is
     * the usual reason to forget one, and [pinFor] answers null under a fork, which would leave that server's request
     * behind under another address), then, after this call, `KeptAssistRequests.forget(secure, origin, thatPin)` (in
     * `client.recovery`). This wipe cannot reach that store.
     *
     * [tied]: accounts the caller found tied at another server before it removed anything of its own ([PinStore.wipeOrigin]).
     */
    fun forgetServer(origin: String, accounts: Collection<String> = emptyList(), tied: Collection<String> = emptyList()): ServerForgotten =
        store.wipeOrigin(origin, accounts, tied)

    /**
     * The pin [origin] holds, in force OR FORKED ([PinStore.state]: the pin of [PinState.Pinned] or [PinState.Forked]);
     * null for no pin, a damaged one or an unreadable store. What a host reads BEFORE [forgetServer] to hand to
     * `KeptAssistRequests.forget` as the issuer. Not for dialing or trusting anything: a forked pin is one this device
     * stopped trusting.
     */
    fun pinForForget(origin: String): CardPin? = try {
        when (val s = store.state(origin)) {
            is PinState.Pinned -> s.pin
            is PinState.Forked -> s.pin
            else -> null
        }
    } catch (e: Exception) {
        null
    }

    override fun dropPinMade(handle: PinHandle) {
        if (!handle.madeNow) return
        // Only the pin this call made, still in force: a fork marked since stays.
        store.removeIf(handle.origin, handle.hash)
    }
}

/**
 * [CardChainVerifier] bound to [io.silencelen.andvari.core.trust.InstanceCard.verifyChain]:
 * card 0 first, each card signed by the previous card's `operatorSignKey`, `prev` chained, `instanceId`
 * constant, and on the operator's own devices the operator key check. A chain that fails part-way is
 * refused with the verifier's verdict code; nothing after the failing card is trusted.
 */
class TrustCardChainVerifier(private val crypto: CryptoProvider) : CardChainVerifier {
    override fun verify(frames: List<ByteArray>, operatorKeys: OperatorKeys?): ChainCheck {
        // A client never passes an expected instanceId: those are pin verdicts after the chain (design §2.4).
        val r = InstanceCard.verifyChain(crypto, frames, operatorKeys = operatorKeys)
        if (r.verdict != null) return ChainCheck.Refused(r.verdict!!.code)
        val chain = r.chain
        val cards = chain.cards.map { c ->
            val f = c.fields
            // The verifier hands the name already decoded and checked against the `name` grammar (CardFields.name).
            VerifiedCard(f.seq, c.hash, f.instanceId, f.origin, f.name, f.kind.literal, f.operator, f.operatorSignKey, f.recoveryFp ?: "none")
        }
        return ChainCheck.Ok(cards, object : RootChecks {
            // The verifier's root checks, each of which runs the dialed-origin check first (§2.4).
            override fun typed(dialedOrigin: String) = InstanceCard.checkTypedRoot(chain, dialedOrigin)?.code
            override fun baked(dialedOrigin: String, card0Hash: String, instanceId: String) = InstanceCard.checkBakedRoot(chain, dialedOrigin, card0Hash, instanceId)?.code
            override fun kit(dialedOrigin: String, card0Hash: String) = InstanceCard.checkKitRoot(chain, dialedOrigin, card0Hash)?.code
            override fun offer(dialedOrigin: String, cardHash: String, instanceId: String) = InstanceCard.checkOfferRoot(chain, dialedOrigin, cardHash, instanceId)?.code
        })
    }
}
