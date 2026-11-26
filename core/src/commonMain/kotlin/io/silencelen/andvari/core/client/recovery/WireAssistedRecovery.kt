package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.KeptAccountCheck
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.KnownKdf
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.onboard.OperatorRecovery
import io.silencelen.andvari.core.client.onboard.Opening
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.onboard.SessionOpener
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.PinHandle
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.RecoveryPollRequest
import io.silencelen.andvari.core.model.wire.RecoveryPollResponse
import io.silencelen.andvari.core.model.wire.RecoveryRequestCommit
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreate
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.RecoveryRequestSummary
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerified
import io.silencelen.andvari.core.model.wire.RecoveryRequestVerify
import io.silencelen.andvari.core.model.wire.RecoveryVetoRequest
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.AssistedRecovery as Assisted
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.OpenedAssistedRecovery
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.RecoveryVeto
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.trust.VetoFields
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer

/**
 * A request this device opened, kept until commit, veto, rejection or expiry (design §9.3 step 1, N11): `rSec` and
 * `pollSecret` must outlive a restart on a fresh install that holds no account. [holdEndsAt] is set once the emailed
 * code verified.
 *
 * [instanceId] and [card0Hash] name the server that issued the request: the pin in force at [origin] when it was made.
 * They are what a kept request is bound to ([AssistRequests]); a record written before they existed has neither and is
 * bound to [origin] alone.
 */
@Serializable
internal data class KeptAssistRequest(
    val origin: String,
    val email: String,
    val requestId: String,
    val rPub: String,
    val rSec: String,
    val pollSecret: String,
    val createdAt: Long,
    val holdEndsAt: Long? = null,
    val instanceId: String? = null,
    val card0Hash: String? = null,
    /**
     * The fingerprint of the server's recovery key this request is bound to: the pinned card's `recoveryFp` when the
     * request was made, moved forward only by rotations this device verified. Null in a record kept before it existed.
     */
    val recoveryFp: String? = null,
    /** The key the request was made under, once a verified rotation moved [recoveryFp] on; with [keyChangedAt], the newest rotation's `issuedAt`. */
    val keyChangedFrom: String? = null,
    val keyChangedAt: Long? = null,
) {
    fun valid(): Boolean = TrustGrammar.isOrigin(origin) && TrustGrammar.emailNorm(email) != null && TrustGrammar.isB64_16(requestId) &&
        TrustGrammar.isB64_32(rPub) && TrustGrammar.isB64_32(rSec) && TrustGrammar.isB64_32(pollSecret) &&
        ((instanceId == null && card0Hash == null) || (instanceId != null && TrustGrammar.isUuid(instanceId) && card0Hash != null && TrustGrammar.isHex64(card0Hash))) &&
        (recoveryFp == null || TrustGrammar.isHex64(recoveryFp)) &&
        ((keyChangedFrom == null && keyChangedAt == null) || (keyChangedFrom != null && TrustGrammar.isHex64(keyChangedFrom) && keyChangedAt != null && recoveryFp != null))

    /** True when this request names a server, and [pin] is that server's pin: the same instance, the same card 0. */
    fun issuedBy(pin: CardPin?): Boolean = instanceId != null && pin != null && pin.instanceId == instanceId && pin.card0Hash == card0Hash
}

/**
 * The kept requests, one per origin. The [DeviceState] given here must be the store a platform protects like a
 * session (Keychain or Keystore, design §9.3 step 1): it holds `rSec` and `pollSecret`. A record that does not decode,
 * or that outlived its lifetime (FI-R9: an unverified request 24 hours after creation, a verified one 30 days after
 * its hold ended), is read as none and removed.
 *
 * What the origin check protects, and what protects it now. A kept request holds `pollSecret` (the credential that
 * polls, picks up and commits the request), `rSec` (the key the operator's payload is sealed to), the request id and
 * the email. Comparing the record's own origin with the key's origin made sure those go only to the server that issued
 * the request, and that a record found under another origin's key (a copy, a carried record, a store mix-up) is never
 * sent there. Origin was standing in for "the same server". The binding now is the server itself: the pin in force when
 * the request was made, by instance id AND card 0 hash ([KeptAssistRequest.issuedBy]). Card 0 is signed by the
 * instance's root key, so a server at another address cannot claim it without that key, and a followed move keeps the
 * chain and so both values. So a bound record is used at an origin only while the pin in force there is the issuing
 * server's, wherever the record is kept:
 * - under its own origin's key, while that origin's pin is the issuer's; a different pin there (the server was
 *   forgotten and another pinned at that address) removes it, and no pin leaves it unread;
 * - under another origin's key (a move carried it in the same store), only when that origin's pin is the issuer's;
 *   it is then rewritten for that origin; otherwise it is removed, as before;
 * - left under an origin the issuer left (no pin record there any more, or another server's pin in force there: the pin
 *   moved away while the record lives in a separate secure store the move did not touch), it follows the move to the one
 *   pinned origin whose pin is the issuer's, if that origin keeps no request of its own; with none, or more than one, it
 *   stays where it is, unused. A forked, damaged or unreadable pin at its origin moves nothing.
 * A record written before the binding existed is bound to its origin alone, as before, and fails closed after a move.
 */
internal class AssistRequests(private val state: DeviceState, private val clock: () -> Long, private val trust: InstanceTrust? = null) {
    private fun key(origin: String) = "ovh.assist|$origin"
    private val indexKey = "ovh.assist.index"

    fun get(origin: String): KeptAssistRequest? {
        relocateMoved()
        return read(origin)
    }

    private fun decode(text: String): KeptAssistRequest? =
        runCatching { WireJson.strict.decodeFromString(KeptAssistRequest.serializer(), text) }.getOrNull()

    private fun read(origin: String): KeptAssistRequest? {
        val text = state.get(key(origin)) ?: return null
        val k = decode(text)
        if (k == null || !k.valid() || expired(k)) {
            remove(origin)
            return null
        }
        if (k.instanceId == null) {
            if (k.origin != origin) { remove(origin); return null }
            return k
        }
        val pin = trust?.pinFor(origin)
        if (k.issuedBy(pin)) {
            if (k.origin == origin) return k
            // Carried here by a followed move: the same server, now at this origin.
            val here = k.copy(origin = origin)
            put(here)
            return here
        }
        // Another server's pin at this address: the issuer is not here. No pin in force: nothing can be judged, so
        // nothing is used, and a record still under its own origin stays for when the pin is readable again.
        if (pin != null || k.origin != origin) remove(origin)
        return null
    }

    /**
     * A bound record left under an origin that holds no pin record any more follows the issuing server to the one
     * pinned origin whose pin is that server's, when that origin keeps no request of its own (see the class comment).
     */
    private fun relocateMoved() {
        val t = trust ?: return
        val candidates = (index() + listedOrigins()).distinct()
        if (candidates.isEmpty()) return
        for (from in candidates) {
            val k = state.get(key(from))?.let(::decode) ?: continue
            if (k.instanceId == null || k.origin != from || !k.valid()) continue
            // The issuer left [from]: no pin record there any more, or another server's pin in force there. A forked,
            // damaged or unreadable pin there cannot be judged, and the record stays.
            val left = try {
                when (t.pinState(from)) {
                    PinState.None -> true
                    is PinState.Pinned -> t.pinFor(from)?.let { !k.issuedBy(it) } ?: false
                    else -> false
                }
            } catch (e: Exception) { false }
            if (!left) continue
            val to = t.pins().filter { k.issuedBy(it) && it.origin != from }.map { it.origin }.distinct().singleOrNull() ?: continue
            if (state.get(key(to)) != null) continue
            put(k.copy(origin = to))
            remove(from)
        }
    }

    /** The origins with a kept record by key, when the store can list its keys. */
    private fun listedOrigins(): List<String> =
        state.keys()?.filter { it.startsWith("ovh.assist|") }?.map { it.removePrefix("ovh.assist|") } ?: emptyList()

    private fun expired(k: KeptAssistRequest): Boolean {
        val now = clock()
        val hold = k.holdEndsAt
        return if (hold == null) now >= k.createdAt + UNVERIFIED_LIFETIME_MS else now >= hold + VERIFIED_LIFETIME_MS
    }

    fun put(k: KeptAssistRequest) {
        if (!k.valid()) return
        state.set(key(k.origin), WireJson.json.encodeToString(KeptAssistRequest.serializer(), k))
        val all = index()
        if (k.origin !in all) writeIndex(all + k.origin)
    }

    fun remove(origin: String) {
        state.set(key(origin), null)
        val all = index()
        if (origin in all) writeIndex(all - origin)
    }

    fun origins(): List<String> {
        relocateMoved()
        return (index() + listedOrigins()).distinct().filter { read(it) != null }
    }

    /**
     * "Forget this server" in this store ([KeptAssistRequests.forget]): the record kept under [origin]'s key, whatever it
     * holds (unreadable, expired, another server's), and, when [issuer] is given, every record bound to that server
     * wherever it is kept (one a move left under an older address). Answers how many records went. A store that cannot
     * be written throws, as [DeviceState.set] does.
     */
    fun forgetServer(origin: String, issuer: CardPin?): Int {
        var gone = 0
        if (state.get(key(origin)) != null) gone++
        remove(origin)
        if (issuer != null) {
            for (from in (index() + listedOrigins()).distinct()) {
                if (from == origin) continue
                val k = state.get(key(from))?.let(::decode) ?: continue
                if (k.issuedBy(issuer)) {
                    remove(from)
                    gone++
                }
            }
        }
        return gone
    }

    private fun index(): List<String> = state.get(indexKey)?.let {
        runCatching { WireJson.strict.decodeFromString(ListSerializer(String.serializer()), it) }.getOrNull()
    } ?: emptyList()

    private fun writeIndex(all: List<String>) =
        state.set(indexKey, if (all.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(String.serializer()), all))

    companion object {
        const val UNVERIFIED_LIFETIME_MS = 24L * 3_600_000L
        const val VERIFIED_LIFETIME_MS = 30L * 86_400_000L
    }
}

/**
 * The assisted-recovery requests a host keeps in a store of its own (design §9.3 step 1: the session-grade store, the
 * `secure` given to [WireAssistedRecovery]). When that is not the pin store's [DeviceState], the engine's wipe
 * (`CardTrust.forgetServer`) cannot reach it, and a host calls [forget] for "Forget this server" as well.
 */
object KeptAssistRequests {
    /**
     * Removes from [store] the request kept for [origin], whatever it holds, and nothing kept for another origin.
     * [issuer] is the pin [origin] held before the server was forgotten, IN FORCE OR FORKED: `CardTrust.pinForForget(origin)`
     * (the pin of `PinStore.state(origin)` when that is `PinState.Pinned` or `PinState.Forked`), read BEFORE
     * `CardTrust.forgetServer`; null when there was none, it was damaged or it could not be read. Not `pinFor(origin)`,
     * which answers null under a fork, the usual reason to forget a server. With it, a request bound to that
     * server and kept under another address (a followed move leaves it there in a separate store) goes too, so it can
     * never follow the server back when the person pins it again. Local only: nothing is sent, and no pin is needed.
     * Answers how many records were removed; a store that cannot be written throws, as [DeviceState.set] does.
     */
    fun forget(store: DeviceState, origin: String, issuer: CardPin? = null): Int =
        AssistRequests(store, { 0L }).forgetServer(origin, issuer)
}

/**
 * [AssistedRecovery] over spec 03 §18 (design §9.3, §4.4, §2.4 "Assisted recovery").
 *
 * Trust: started for a typed email at an origin; nothing is sent before the person confirmed the target and
 * [PasswordGate] answered `proceed` for purpose `assisted_recovery` (a kit or setup pin is no password pin here, so it
 * is the Trust Gate, in the same confirmation). Never started, polled or committed when the pinned card is `public`
 * or names no recovery key (variant R). The pick-up runs the shared verifiers' [Assisted.open] against the PINNED card's
 * `recoveryFp` and `instanceId`, with no `userId` (a fresh install holds none). Then the person must confirm the
 * delivered account ID ([AssistedStep.CheckAccount]) before any password: [confirmAccount] is the only way to
 * [AssistedStep.ChoosePassword], and [commit] re-checks that confirmation in its own state. The commit opens the
 * session through [SessionOpener] for the delivered `userId` and reveals a new kit, which the commit already made the
 * only one.
 *
 * [secure] holds `rSec` and `pollSecret`: it must be the session-grade store (see [AssistRequests]).
 */
class WireAssistedRecovery(
    private val clientFor: (String) -> WireClient,
    private val trust: InstanceTrust,
    private val devices: KnownDevices,
    private val sink: SessionSink,
    private val crypto: CryptoProvider,
    secure: DeviceState,
    private val platform: String,
    private val deviceName: String,
    private val clock: () -> Long,
    private val kdfParams: KdfParams = KdfParams.DEFAULT,
    private val knownIdentity: (String) -> ByteArray? = { null },
) : AssistedRecovery {
    private val kept = AssistRequests(secure, clock, trust)
    private val late = LateOutcomes()

    init {
        // A request for the operator's help is a flow under way for its address from its confirmed target for as long as
        // this device keeps it ([SessionSink.underWayWhileKept]), across restarts too. A question that cannot be answered
        // (a list changed while it was read) counts as under way: the forgetting is refused, never made.
        sink.underWayWhileKept { origin, emailNorm ->
            try {
                targets.values.toList().any { it.origin == origin && it.emailNorm == emailNorm } ||
                    kept.get(origin)?.let { TrustGrammar.emailNorm(it.email) == emailNorm } == true
            } catch (e: kotlin.coroutines.cancellation.CancellationException) {
                throw e
            } catch (e: Exception) {
                true
            }
        }
    }

    override fun takeLateOutcome(): LateRecoveryOutcome? = late.take()

    override var onLateOutcome: (() -> Unit)?
        get() = late.onPublished
        set(value) { late.onPublished = value }

    /**
     * A bound request whose issuing server is not [pin]'s ([KeptAssistRequest.issuedBy]): forgotten, and the flow stops
     * with [PIN_CHANGED] before `pollSecret`, the code or the new password's proof is sent. Null when [pin] is the issuer
     * (or the record predates the binding and is held to its origin instead).
     */
    private fun notTheIssuer(k: KeptAssistRequest, pin: CardPin): AssistedStep.Stopped? {
        if (k.instanceId == null || k.issuedBy(pin)) return null
        forget(k.origin)
        return AssistedStep.Stopped(PIN_CHANGED)
    }

    /** [SENDING]: a confirmed target whose request is on its way; it stays under its handle so that a leave can remove it. */
    private enum class Stage { TARGET, SENDING, REQUESTED, WAITING, CHECK, CHOOSE }

    /** What a handle stands for: never a conclusion the app could hand back, only where to look in this engine's state. */
    private class Ref(val origin: String, val stage: Stage, val requestId: String?)

    /** A confirmation not yet sent. */
    private class Target(val origin: String, val email: String, val emailNorm: String, val made: PinHandle?)

    /** A payload that passed every check of [Assisted.open], held in memory only, until commit or rejection. */
    private class Delivered(val requestId: String, val opened: OpenedAssistedRecovery, val accountId: String, val identityPub: ByteArray) {
        var confirmed = false
    }

    private val refs = HashMap<String, Ref>()
    private val targets = HashMap<String, Target>()
    private val delivered = HashMap<String, Delivered>()

    private fun handle(ref: Ref): String {
        val h = Bytes.toB64(crypto.randomBytes(16))
        refs[h] = ref
        return h
    }

    /**
     * Whether the flow [handle] stood for when a call began is still [ref] after one of its waits (the shape
     * found in the kit recovery): a person who left ([cancel]) or started over (a new request for the origin forgets the
     * old one, [forget]) removed it while the request was in flight. The call then keeps nothing, opens nothing and hands
     * nothing on: it answers [STALE].
     */
    private fun still(handle: String, ref: Ref): Boolean = refs[handle] === ref

    private fun gate(origin: String, emailNorm: String): GateDecision = PasswordGate.decide(
        GateInput(GatePurpose.ASSISTED_RECOVERY, GateEntry.SERVER_CHOICE, null, origin, emailNorm, trust.gatePins()),
    )

    private fun requestCode(rPub: String): String = Assisted.groupedRequestCode(Assisted.requestCode(crypto, Bytes.fromB64(rPub)))

    /** Forget everything held for [origin]: the kept request, a delivered payload, and every handle. */
    private fun forget(origin: String) {
        kept.remove(origin)
        delivered.remove(origin)?.opened?.wipe()
        refs.entries.removeAll { it.value.origin == origin }
    }

    private fun pinStop(r: FirstPin): AssistedStep.Stopped = when (r) {
        is FirstPin.PinChanged -> AssistedStep.Stopped(PIN_CHANGED)
        is FirstPin.Blocked -> AssistedStep.Stopped(INSTANCE_BLOCKED)
        is FirstPin.PinConflict -> AssistedStep.Stopped(r.verdict)
        is FirstPin.Refused -> AssistedStep.Stopped(r.reason)
        is FirstPin.OriginMismatch -> AssistedStep.Stopped(ORIGIN_MISMATCH)
        else -> AssistedStep.Stopped(UNREACHABLE)
    }

    // ---------------------------------------------------------------------------------------------
    // Step 1: the target, the gate and the request
    // ---------------------------------------------------------------------------------------------

    override suspend fun start(email: String, origin: String): AssistedStep {
        if (!TrustGrammar.isOrigin(origin)) return AssistedStep.Stopped(BAD_ORIGIN)
        val emailNorm = TrustGrammar.emailNorm(email) ?: return AssistedStep.Stopped(INVALID_EMAIL)
        if (!TrustGrammar.isPlatform(platform)) return AssistedStep.Stopped(BAD_PLATFORM)
        trust.pinFor(origin)?.let { if (!OperatorRecovery.offered(it)) return AssistedStep.Stopped(NOT_OFFERED) }
        val t = Target(origin, email, emailNorm, null)
        return when (gate(origin, emailNorm)) {
            GateDecision.REFUSE_ENTRY -> AssistedStep.Stopped(INSTANCE_BLOCKED)
            GateDecision.PROCEED -> {
                val pin = trust.pinFor(origin) ?: return AssistedStep.Stopped(TRUST_GATE_FIRST)
                confirmTarget(t, pin.name, null)
            }
            GateDecision.TRUST_GATE -> when (val g = trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS)) {
                // The card the gate would pin decides before the person is asked anything (variant R).
                is FirstPin.NeedsTrustGate -> if (OperatorRecovery.offered(g.confirm.candidate)) confirmTarget(t, g.name, g) else AssistedStep.Stopped(NOT_OFFERED)
                is FirstPin.Pinned -> when {
                    !OperatorRecovery.offered(g.pin) -> AssistedStep.Stopped(NOT_OFFERED)
                    gate(origin, emailNorm) == GateDecision.PROCEED -> confirmTarget(t, g.pin.name, null)
                    else -> AssistedStep.Stopped(TRUST_GATE_FIRST)
                }
                else -> pinStop(g)
            }
        }
    }

    private fun confirmTarget(t: Target, name: String, gate: FirstPin.NeedsTrustGate?): AssistedStep.ConfirmTarget {
        val h = handle(Ref(t.origin, Stage.TARGET, null))
        targets[h] = t
        return AssistedStep.ConfirmTarget(t.email, name, t.origin, gate, h)
    }

    override suspend fun request(step: AssistedStep.ConfirmTarget, mailboxValue: String?): AssistedStep {
        if (refs[step.handle]?.stage != Stage.TARGET) return AssistedStep.Stopped(STALE)
        // A value that cannot be one stops before anything is sent, and the step stays (the person corrects it or clears it).
        val value = mailboxValue?.let { typed -> if (mailboxFieldEmpty(typed)) null else mailboxValueOf(typed) ?: return AssistedStep.Stopped(BAD_MAILBOX_VALUE) }
        refs.remove(step.handle)
        val t = targets.remove(step.handle) ?: return AssistedStep.Stopped(STALE)
        // The confirmed target stays under its handle while this call waits, so a leave ([cancel]) or a newer request for
        // the origin ([forget]) can remove it; after each wait the call asks [still].
        val going = Ref(t.origin, Stage.SENDING, null)
        refs[step.handle] = going
        // Under way while it is sent, between the confirmed target and the kept request ([SessionSink.underWayWhileKept]).
        val done = sink.underWay(t.origin, t.emailNorm)
        try {
            return requestSent(step, t, going, value)
        } finally {
            if (refs[step.handle] === going) refs.remove(step.handle)
            done()
        }
    }

    private suspend fun requestSent(step: AssistedStep.ConfirmTarget, t: Target, going: Ref, mailboxValue: String?): AssistedStep {
        var made: PinHandle? = null
        fun stop(reason: String, retry: Long? = null): AssistedStep.Stopped {
            made?.let(trust::dropPinMade)
            return AssistedStep.Stopped(reason, retry)
        }
        step.gate?.let { g ->
            when (val r = trust.confirmTrustGate(g.confirm)) {
                is FirstPin.Pinned -> made = r.handle
                else -> return pinStop(r)
            }
            // A wait: left during the Trust Gate, nothing is sent and the pin this flow made goes.
            if (!still(step.handle, going)) return stop(STALE)
        }
        // The rule itself, asked again now, and the pinned card's kind (variant R).
        if (gate(t.origin, t.emailNorm) != GateDecision.PROCEED) return stop(TRUST_GATE_FIRST)
        val pin = trust.pinFor(t.origin) ?: return stop(TRUST_GATE_FIRST)
        if (!OperatorRecovery.offered(pin)) return stop(NOT_OFFERED)
        val seed = crypto.randomBytes(32)
        val pair = try { crypto.boxKeypairFromSeed(seed) } finally { seed.fill(0) }
        val pollSecret = crypto.randomBytes(32)
        try {
            val rPub = Bytes.toB64(pair.publicKey)
            // The mailbox value rides with the request when given and is left out when not; nothing below reads anything
            // of the answer that could depend on it (the server answers alike, spec 03 §18.1).
            val body = RecoveryRequestCreate(t.email, rPub, Bytes.toHexLower(crypto.sha256(pollSecret)), platform, mailboxValue)
            val r = clientFor(t.origin).call(WireRoute.RECOVERY_REQUEST_CREATE, bodyJson = WireJson.json.encodeToString(RecoveryRequestCreate.serializer(), body),
                decode = { WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), it) })
            // Left (or started over) while the request was on its way: the server may hold it and email its code, but this
            // device keeps no request, no secret and no pin of a flow the person ended; the request expires on its own.
            if (!still(step.handle, going)) return stop(STALE)
            val created = when (r) {
                is WireResult.Ok -> r.value
                is WireResult.Refused -> return when {
                    r.status == 404 -> stop(NOT_OFFERED) // variant R: the route does not exist here
                    r.status >= 500 && r.code != MAIL_UNAVAILABLE -> stop(UNREACHABLE)
                    else -> stop(r.code, r.retryAfterSeconds)
                }
                is WireResult.NoAnswer -> return stop(UNREACHABLE)
            }
            if (!TrustGrammar.isB64_16(created.requestId)) return stop(BAD_RESPONSE)
            // A new request replaces one this device kept for the same origin.
            forget(t.origin)
            // Bound to the server that issued it (see AssistRequests): the pin in force now, by instance and card 0.
            // And to the recovery key the pinned card names now: a later change is followed only through verified rotations.
            kept.put(KeptAssistRequest(t.origin, t.email, created.requestId, rPub, Bytes.toB64(pair.privateKey), Bytes.toB64(pollSecret), clock(),
                instanceId = pin.instanceId, card0Hash = pin.card0Hash, recoveryFp = pin.recoveryFp))
            return AssistedStep.Requested(t.origin, requestCode(rPub), handle(Ref(t.origin, Stage.REQUESTED, created.requestId)))
        } finally {
            pair.privateKey.fill(0)
            pollSecret.fill(0)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Step 2: the emailed code
    // ---------------------------------------------------------------------------------------------

    /** The kept request [ref] stands for, when it is still the one kept for its origin. */
    private fun keptFor(ref: Ref?): KeptAssistRequest? {
        ref ?: return null
        kept.get(ref.origin)?.let { return it.takeIf { k -> k.requestId == ref.requestId } }
        // A followed move took the request to its server's new origin (AssistRequests): the same request, found there.
        return kept.origins().firstNotNullOfOrNull { o -> kept.get(o)?.takeIf { it.requestId == ref.requestId && it.instanceId != null } }
    }

    override suspend fun verifyCode(step: AssistedStep.Requested, code: String): AssistedStep {
        val ref = refs[step.handle]?.takeIf { it.stage == Stage.REQUESTED } ?: return AssistedStep.Stopped(STALE)
        val k = keptFor(ref) ?: return AssistedStep.Stopped(STALE)
        val pin = trust.pinFor(k.origin) ?: return AssistedStep.Stopped(TRUST_GATE_FIRST)
        notTheIssuer(k, pin)?.let { return it }
        if (!OperatorRecovery.offered(pin)) return AssistedStep.Stopped(NOT_OFFERED)
        val typed = code.filter { !TrustGrammar.isAsciiSpace(it) }
        // A code that cannot be one is the same answer the server gives, without asking it.
        if (typed.length != 6 || !typed.all { it in '0'..'9' }) return AssistedStep.Stopped(BAD_CODE)
        val r = clientFor(k.origin).call(WireRoute.RECOVERY_REQUEST_VERIFY, pathParams = mapOf("requestId" to k.requestId),
            bodyJson = WireJson.json.encodeToString(RecoveryRequestVerify.serializer(), RecoveryRequestVerify(typed)),
            decode = { WireJson.json.decodeFromString(RecoveryRequestVerified.serializer(), it) })
        // Left while the code was on its way: the leave forgot the kept request, and it is not written back.
        if (!still(step.handle, ref)) return AssistedStep.Stopped(STALE)
        return when (r) {
            is WireResult.Ok -> {
                kept.put(k.copy(holdEndsAt = r.value.holdEndsAt))
                refs.remove(step.handle)
                AssistedStep.Waiting(k.origin, RecoveryRequestState.HOLDING, r.value.holdEndsAt, requestCode(k.rPub), handle(Ref(k.origin, Stage.WAITING, k.requestId)))
            }
            is WireResult.Refused -> when {
                // The server no longer knows this request (it lost the row, or lies): kept until its own lifetime ends.
                r.status == 404 -> AssistedStep.Stopped(REQUEST_UNKNOWN)
                r.status >= 500 -> AssistedStep.Stopped(UNREACHABLE)
                // The right code for a request the account's owner cancelled before it was verified (a password change,
                // recovery switched to private, or a recovery of the account): the server marks it vetoed. A final stop:
                // the kept request is forgotten and the step does not stay.
                r.status == 409 && r.code == REQUEST_STATE -> {
                    forget(k.origin)
                    refs.remove(step.handle)
                    AssistedStep.Stopped(REQUEST_CANCELLED)
                }
                else -> AssistedStep.Stopped(r.code, r.retryAfterSeconds) // bad_code and rate_limited: the step stays
            }
            is WireResult.NoAnswer -> AssistedStep.Stopped(UNREACHABLE)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Step 4: the poll and the pick-up
    // ---------------------------------------------------------------------------------------------

    override fun keptOrigins(): List<String> = kept.origins()

    override suspend fun resume(origin: String): AssistedStep? {
        val k = kept.get(origin) ?: return null
        // No handle yet: the flow is this kept request, until a newer request or a leave forgets it.
        return pollKept(k) { kept.get(k.origin)?.requestId == k.requestId }
    }

    override suspend fun poll(step: AssistedStep): AssistedStep {
        val h = when (step) {
            is AssistedStep.Requested -> step.handle
            is AssistedStep.Waiting -> step.handle
            else -> return AssistedStep.Stopped(STALE)
        }
        val ref = refs[h]?.takeIf { it.stage == Stage.REQUESTED || it.stage == Stage.WAITING } ?: return AssistedStep.Stopped(STALE)
        val k = keptFor(ref) ?: return AssistedStep.Stopped(STALE)
        // A stop leaves the step the app holds valid for another poll; anything else replaces it.
        return pollKept(k) { still(h, ref) }.also { if (it !is AssistedStep.Stopped) refs.remove(h) }
    }

    /** The pinned card the payload must be signed for: refreshed forward first, so a key rotated during the hold is the one asked for. */
    private suspend fun currentPin(origin: String): CardPin? = when (val s = trust.refresh(origin)) {
        is CardStatus.Ok -> s.pin
        is CardStatus.Withheld, CardStatus.Unreachable -> trust.pinFor(origin)
        else -> null
    }

    /**
     * One poll of [k]. [still] is asked after each wait (the card's refresh, the poll): a flow the person left or replaced
     * meanwhile is answered [STALE], and nothing is picked up, held in memory or handed on.
     */
    private suspend fun pollKept(kept0: KeptAssistRequest, still: () -> Boolean): AssistedStep {
        val pin = currentPin(kept0.origin)
        if (!still()) return AssistedStep.Stopped(STALE)
        pin ?: return AssistedStep.Stopped(PIN_CHANGED)
        notTheIssuer(kept0, pin)?.let { return it }
        if (!OperatorRecovery.offered(pin)) return AssistedStep.Stopped(NOT_OFFERED)
        // The recovery key the request was made under, against the pinned card's, before anything is polled (spec 04 §5).
        val k = when (val b = boundToKey(kept0, pin, still)) {
            is KeyBound.Ok -> b.kept
            is KeyBound.Stop -> return b.step
        }
        // The secret travels in the body, never the URL (T2-Rec).
        val r = clientFor(k.origin).call(WireRoute.RECOVERY_REQUEST_POLL, pathParams = mapOf("requestId" to k.requestId),
            bodyJson = WireJson.json.encodeToString(RecoveryPollRequest.serializer(), RecoveryPollRequest(k.pollSecret)),
            decode = { WireJson.json.decodeFromString(RecoveryPollResponse.serializer(), it) })
        if (!still()) return AssistedStep.Stopped(STALE)
        val resp = when (r) {
            is WireResult.Ok -> r.value
            is WireResult.Refused -> return when {
                // The server no longer knows this request: said, and the request kept until its own lifetime ends (a
                // server can lose a row, or lie), so it is neither forgotten silently nor asked about forever.
                r.status == 404 -> AssistedStep.Stopped(REQUEST_UNKNOWN)
                r.status >= 500 -> AssistedStep.Stopped(UNREACHABLE)
                else -> AssistedStep.Stopped(r.code, r.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> return AssistedStep.Stopped(UNREACHABLE)
        }
        val code = requestCode(k.rPub)
        return when (resp.state) {
            RecoveryRequestState.UNVERIFIED -> AssistedStep.Requested(k.origin, code, handle(Ref(k.origin, Stage.REQUESTED, k.requestId)))
            RecoveryRequestState.HOLDING, RecoveryRequestState.AWAITING_OPERATOR ->
                AssistedStep.Waiting(k.origin, resp.state, resp.holdEndsAt, code, handle(Ref(k.origin, Stage.WAITING, k.requestId)))
            RecoveryRequestState.VETOED, RecoveryRequestState.EXPIRED -> { forget(k.origin); AssistedStep.Stopped(resp.state) }
            RecoveryRequestState.READY -> pickUp(k, pin, resp)
            else -> AssistedStep.Stopped(BAD_RESPONSE)
        }
    }

    private sealed class KeyBound {
        class Ok(val kept: KeptAssistRequest) : KeyBound()
        class Stop(val step: AssistedStep.Stopped) : KeyBound()
    }

    /** The unsigned changes the last look at each origin's request found (in memory; a later look that follows replaces it). */
    private val unsignedSeen = HashMap<String, RecoveryKeyChange>()

    override fun recoveryKeyChange(origin: String): RecoveryKeyChange? {
        unsignedSeen[origin]?.let { return it }
        val k = kept.get(origin) ?: return null
        val from = k.keyChangedFrom ?: return null
        return RecoveryKeyChange(k.origin, from, k.recoveryFp!!, signed = true, rotatedAt = k.keyChangedAt)
    }

    /**
     * Spec 04 §5 for a kept request: [pin]'s `recoveryFp` against the one [k] was made under.
     * - The same key: go on.
     * - Another key, and the served rotations link the two, each statement verified here against the key reached so far
     *   (the first signed by the key the request was made under): the request is rebound to the new key, the change and the
     *   newest statement's time are recorded with it ([recoveryKeyChange]), and it goes on. Only answers signed by the new
     *   key are taken from then on (the pick-up is against the pinned card).
     * - Another key with no such rotations (none served, one altered, one signed by any other key): stopped with
     *   [RECOVERY_KEY_CHANGED] before anything is polled, and kept; nothing of an answer is picked up or opened.
     * - A record from before the key was recorded: rebound to the pinned key only when every change of `recoveryFp` along
     *   the whole served chain from card 0 is covered by rotations (the first-consent walk). Otherwise the change cannot be
     *   placed before or after the request, and it is stopped as unsigned: the safe reading.
     * Served chain or rotations that cannot be read: [UNREACHABLE], the request kept, nothing polled.
     */
    private suspend fun boundToKey(k: KeptAssistRequest, pin: CardPin, still: () -> Boolean): KeyBound {
        val made = k.recoveryFp
        if (made == pin.recoveryFp) {
            unsignedSeen.remove(k.origin)
            return KeyBound.Ok(k)
        }
        val served = OperatorRecovery.served(clientFor(k.origin), trust, crypto, k.origin)
        if (!still()) return KeyBound.Stop(AssistedStep.Stopped(STALE))
        // Unreadable, or the card moved on again while this looked: nothing can be judged now; look again later.
        if (served == null || served.pin.hash != pin.hash) return KeyBound.Stop(AssistedStep.Stopped(UNREACHABLE))
        fun unsigned(): KeyBound {
            unsignedSeen[k.origin] = RecoveryKeyChange(k.origin, made, pin.recoveryFp, signed = false, rotatedAt = null)
            return KeyBound.Stop(AssistedStep.Stopped(RECOVERY_KEY_CHANGED))
        }
        if (made == null) {
            if (!served.clean) return unsigned()
            val bound = k.copy(recoveryFp = pin.recoveryFp)
            kept.put(bound)
            unsignedSeen.remove(k.origin)
            return KeyBound.Ok(bound)
        }
        val chain = io.silencelen.andvari.core.trust.RecoveryRotation.chain(crypto, served.rotations, pin.instanceId, made, pin.recoveryFp)
        if (chain.isNullOrEmpty()) return unsigned()
        // Walk it again, link by link, for the newest statement's signed time.
        var reached: String = made
        var at: Long? = null
        for (frame in chain) {
            val link = io.silencelen.andvari.core.trust.RecoveryRotation.verify(crypto, frame, pin.instanceId, reached) as? Checked.Ok ?: return unsigned()
            reached = link.value.fields.toFp
            at = link.value.fields.issuedAt
        }
        if (reached != pin.recoveryFp || at == null) return unsigned()
        // The time the device shows is when the server's card first named the new key (the first card after the last one
        // naming another key), not the rotation statement's own time, which can be earlier.
        val since = served.cards.let { cs ->
            val lastOther = cs.indexOfLast { (it.recoveryFp ?: TrustGrammar.NONE) != pin.recoveryFp }
            cs.getOrNull(lastOther + 1)?.issuedAt
        } ?: at
        val bound = k.copy(recoveryFp = pin.recoveryFp, keyChangedFrom = k.keyChangedFrom ?: made, keyChangedAt = since)
        kept.put(bound)
        unsignedSeen.remove(k.origin)
        return KeyBound.Ok(bound)
    }

    /**
     * §9.3 step 4 through the shared verifiers' [Assisted.openV3], in §2.4's order: `unopenable`; the parse verdicts (an answer of the
     * old version 2 is `bad_statement`); `signer_not_pinned_key` against the recovery key the pinned card's `recoveryFp`
     * names; `bad_signature`; `request_mismatch` (`instanceId`, `requestId`, `requestKey`, and the answer's address against
     * the one this person typed, on a fresh install too; no `userId` on a fresh install); `identity_mismatch`. The commit
     * value the answer carries is held with the delivered key for the commit (spec 03 §18.5). A refusal keeps the request
     * (a later poll asks again) and holds nothing in memory.
     */
    /**
     * True when this device keeps an account at [k]'s origin under the address the person typed, and it is not [userId]:
     * the answer names another account than the one this device keeps for that address ([NOT_THE_KEPT_ACCOUNT]).
     */
    private fun namesAnotherThanKept(k: KeptAssistRequest, userId: String): Boolean {
        val emailNorm = TrustGrammar.emailNorm(k.email) ?: return false
        val kept = sink.keptAccountFor(k.origin, emailNorm) ?: return false
        return kept != userId
    }

    /**
     * [AssistedStep.Stopped.anotherAccountServed] for the keeper's refusal [reason] of [userId]: [userId] where it is the
     * identity refusal for an address tied here to ANOTHER account ([SessionSink.refusalIsAnotherAccount]); else null.
     */
    private fun anotherServed(reason: String, origin: String, emailNorm: String?, userId: String, identityPub: ByteArray?): String? =
        userId.takeIf {
            reason == io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH && emailNorm != null &&
                sink.refusalIsAnotherAccount(origin, emailNorm, userId, identityPub)
        }

    private fun pickUp(k: KeptAssistRequest, pin: CardPin, resp: RecoveryPollResponse): AssistedStep {
        val sealedText = resp.sealed
        val seedText = resp.encryptedIdentitySeed
        val pubText = resp.identityPub
        if (sealedText == null || seedText == null || pubText == null) return AssistedStep.Stopped(BAD_RESPONSE)
        val sealed = Bytes.fromB64Canonical(sealedText) ?: return AssistedStep.Stopped(UNOPENABLE)
        val identityPub = Bytes.fromB64Exact(pubText, 32) ?: return AssistedStep.Stopped(IDENTITY_MISMATCH)
        val rPub = Bytes.fromB64(k.rPub)
        val rSec = Bytes.fromB64(k.rSec)
        val opened = try {
            // Only a version-3 answer, for the address this person typed when asking.
            Assisted.openV3(crypto, rPub, rSec, sealed, pin.recoveryFp, pin.instanceId, k.requestId, k.email, IdentityCheck(seedText, pubText), userId = null)
        } finally {
            rSec.fill(0)
        }
        val ok = when (opened) {
            is Checked.Ok -> opened.value
            is Checked.Refused -> return AssistedStep.Stopped(opened.verdict.code)
        }
        // The account this device keeps for the typed address decides what the answer is held to, never the answer's own id:
        // an answer that names another account (made by whoever holds the operator's recovery key) is refused here, before
        // the person is shown an account to check. What was opened goes, the request stays.
        if (namesAnotherThanKept(k, ok.userId)) {
            ok.wipe()
            return AssistedStep.Stopped(NOT_THE_KEPT_ACCOUNT)
        }
        // The poll's `ready` names the commit hash the server holds for the answer it stored. When
        // it is not the hash of the value inside the answer opened here, the server holds another answer than this one
        // (a damaged or replaced upload): the commit could only be refused, so the person is asked nothing. The request is
        // kept, and what was opened goes. A server that does not send the field is taken as before.
        resp.commitHash?.let { held ->
            val mine = ok.commitB64?.let { Assisted.commitHashOf(crypto, it) }
            val same = TrustGrammar.isHex64(held) && mine != null && Bytes.ctEquals(held.encodeToByteArray(), mine.encodeToByteArray())
            if (!same) {
                ok.wipe()
                return AssistedStep.Stopped(COMMIT_MISMATCH)
            }
        }
        // Spec 01 §7, a recovery on a device that keeps this account: the delivered key must open what the copy holds sealed
        // under the account's key before the person is asked anything. Another key: what was opened goes, the request stays.
        val given = ok.uvk // a copy
        // The answer's identity key is the one its served seed opened to under the delivered key (checked by openV3).
        val keptKey = try {
            KeptAccountCheck.recoveredKeyRefusal(crypto, ok.userId, given, sink.keptForSignIn(k.origin), identityPub)
        } finally {
            given.fill(0)
        }
        if (keptKey != null) {
            ok.wipe()
            return AssistedStep.Stopped(keptKey)
        }
        // A device that knows this account's identity key (it was signed in here once) holds the delivered one to it.
        val known = knownIdentity(ok.userId)
        if (known != null && !Bytes.ctEquals(known, identityPub)) {
            ok.wipe()
            return AssistedStep.Stopped(IDENTITY_MISMATCH)
        }
        // The session keeper is asked before the person is asked anything: a device that keeps another account would refuse
        // the session the commit opens, after the server had taken the new password and ended the request. What was opened
        // goes and the request is kept: once that account is signed out, a later poll picks the answer up again.
        sink.wouldRefuse(k.origin, TrustGrammar.emailNorm(k.email), ok.userId, identityPub)?.let {
            val another = anotherServed(it, k.origin, TrustGrammar.emailNorm(k.email), ok.userId, identityPub)
            ok.wipe()
            return AssistedStep.Stopped(it, anotherAccountServed = another)
        }
        val accountId = Fingerprint.shortForm(Bytes.toHexLower(crypto.sha256(identityPub)))
        delivered.remove(k.origin)?.opened?.wipe()
        delivered[k.origin] = Delivered(k.requestId, ok, accountId, identityPub)
        return AssistedStep.CheckAccount(k.email, pin.name, k.origin, accountId, handle(Ref(k.origin, Stage.CHECK, k.requestId)))
    }

    // ---------------------------------------------------------------------------------------------
    // The account check, step 5 and cancel
    // ---------------------------------------------------------------------------------------------

    /** The delivered payload [ref] stands for, re-derived from this engine's own state. */
    private fun deliveredFor(ref: Ref?): Pair<KeptAssistRequest, Delivered>? {
        val k = keptFor(ref) ?: return null
        val d = delivered[k.origin] ?: return null
        return if (d.requestId == k.requestId) k to d else null
    }

    override suspend fun confirmAccount(step: AssistedStep.CheckAccount, same: Boolean): AssistedStep {
        val ref = refs[step.handle]?.takeIf { it.stage == Stage.CHECK } ?: return AssistedStep.Stopped(STALE)
        val (k, d) = deliveredFor(ref) ?: return AssistedStep.Stopped(STALE)
        if (!same) {
            // "If it is different, stop": nothing more is sent, and the request's secrets go.
            forget(k.origin)
            return AssistedStep.Stopped(ACCOUNT_REJECTED)
        }
        d.confirmed = true
        refs.remove(step.handle)
        return AssistedStep.ChoosePassword(handle(Ref(k.origin, Stage.CHOOSE, k.requestId)))
    }

    override suspend fun commit(step: AssistedStep.ChoosePassword, newPassword: CharArray): AssistedStep {
        try {
            val ref = refs[step.handle]?.takeIf { it.stage == Stage.CHOOSE } ?: return AssistedStep.Stopped(STALE)
            val (k, d) = deliveredFor(ref) ?: return AssistedStep.Stopped(STALE)
            if (!d.confirmed) return AssistedStep.Stopped(ACCOUNT_NOT_CONFIRMED)
            if (!Strength.meetsMasterPasswordFloor(newPassword)) return AssistedStep.Stopped(PASSWORD_TOO_WEAK) // the step stays
            val emailNorm = TrustGrammar.emailNorm(k.email)!!
            if (gate(k.origin, emailNorm) != GateDecision.PROCEED) return AssistedStep.Stopped(TRUST_GATE_FIRST)
            val pin = trust.pinFor(k.origin) ?: return AssistedStep.Stopped(TRUST_GATE_FIRST)
            notTheIssuer(k, pin)?.let { return it }
            if (!OperatorRecovery.offered(pin)) return AssistedStep.Stopped(NOT_OFFERED)
            return send(k, d, pin, emailNorm, newPassword) { still(step.handle, ref) && delivered[k.origin] === d }
        } finally {
            newPassword.fill('\u0000')
        }
    }

    private suspend fun send(k: KeptAssistRequest, d: Delivered, pin: CardPin, emailNorm: String, newPassword: CharArray, still: () -> Boolean): AssistedStep {
        // A flow under way for the address until the commit is answered ([SessionSink.underWay]).
        val done = sink.underWay(k.origin, emailNorm)
        try {
            return sendHeld(k, d, pin, emailNorm, newPassword, still)
        } finally {
            done()
        }
    }

    private suspend fun sendHeld(k: KeptAssistRequest, d: Delivered, pin: CardPin, emailNorm: String, newPassword: CharArray, still: () -> Boolean): AssistedStep {
        val userId = d.opened.userId
        val uvk = d.opened.uvk
        // Asked again before the commit is sent: what the device keeps may have changed since the pick-up (an account kept
        // since for the typed address is the one the answer must name).
        if (namesAnotherThanKept(k, userId)) {
            uvk.fill(0)
            dropDelivered(k.origin)
            return AssistedStep.Stopped(NOT_THE_KEPT_ACCOUNT)
        }
        val kept = sink.keptForSignIn(k.origin)
        KeptAccountCheck.recoveredKeyRefusal(crypto, userId, uvk, kept, d.identityPub)?.let {
            uvk.fill(0)
            dropDelivered(k.origin)
            return AssistedStep.Stopped(it)
        }
        // The new password's cost: never below the server's policy, read through the pinned server now ([RecoveryCost]).
        val cost = RecoveryCost.of(clientFor(k.origin), kdfParams, kept, userId)
        // A wait: a leave (or a newer request) meanwhile dropped what was opened; nothing is derived or sent.
        if (!still()) {
            uvk.fill(0)
            return AssistedStep.Stopped(STALE)
        }
        // Asked again with nothing more to wait for before the commit is sent (another account may have signed in since the
        // pick-up): a no sends nothing, drops what was opened and keeps the request.
        sink.wouldRefuse(k.origin, emailNorm, userId, d.identityPub)?.let {
            val another = anotherServed(it, k.origin, emailNorm, userId, d.identityPub)
            uvk.fill(0)
            dropDelivered(k.origin)
            return AssistedStep.Stopped(it, anotherAccountServed = another)
        }
        val keys = PasswordKeys.derive(crypto, newPassword, crypto.randomBytes(KdfParams.SALT_BYTES), cost, served = false)
        if (keys == null) {
            uvk.fill(0)
            return AssistedStep.Stopped(BAD_RESPONSE)
        }
        val piece = MemberRecovery.generate(crypto, userId, uvk)
        try {
            val device = devices.newDevice(k.origin, emailNorm, platform, deviceName)
            val body = RecoveryRequestCommit(
                pollSecret = k.pollSecret, newAuthKey = keys.authKeyB64, newKdfSalt = Bytes.toB64(keys.salt), newKdfParams = keys.params,
                newWrappedUvk = Envelope.sealB64(crypto, keys.wrapKey, uvk, Ad.uvk(userId)),
                newMemberRecovery = MemberRecoveryBlock(piece.recoveryWrappedUvk, piece.recoveryAuthKey), device = device,
                // Only a device that opened the answer holds this (spec 03 §18.5): a `403 commit_mismatch` (a newer upload
                // replaced the answer) drops what was opened and keeps the request, so the next poll picks up the newer one.
                commit = d.opened.commitB64,
            )
            val r = clientFor(k.origin).call(WireRoute.RECOVERY_REQUEST_COMMIT, pathParams = mapOf("requestId" to k.requestId),
                bodyJson = WireJson.json.encodeToString(RecoveryRequestCommit.serializer(), body),
                decode = { WireJson.json.decodeFromString(SessionResponse.serializer(), it) })
            // Left (or started over) while the commit was in flight: no session is opened for a person who left, and nothing
            // of the flow is kept (the leave forgot it; a newer request owns the origin's state now). The server may have
            // taken the commit: the new password then signs in, and the next sign-in decides, as for an unknown answer. What
            // the answer came to is published once for the first screen (LateRecoveryOutcome), and nothing else of it is used.
            if (!still()) {
                late.publish(LateRecoveryOutcome(k.origin, k.email, LateRecoveryOutcome.Via.OPERATOR, LateRecoveryOutcome.resultOf(r)))
                return AssistedStep.Stopped(STALE)
            }
            val resp = when (r) {
                is WireResult.Ok -> r.value
                is WireResult.Refused -> return when {
                    // Unknown to the server: what was opened goes, the request is kept until its lifetime ends.
                    r.status == 404 -> { dropDelivered(k.origin); AssistedStep.Stopped(REQUEST_UNKNOWN) }
                    r.code == RATE_LIMITED -> AssistedStep.Stopped(r.code, r.retryAfterSeconds) // the step stays
                    // The answer on the server is not the one opened here (a newer or damaged upload): the same outcome as
                    // at the poll. The request is kept and what was opened goes; the operator must upload again.
                    r.code == COMMIT_MISMATCH -> { dropDelivered(k.origin); AssistedStep.Stopped(COMMIT_MISMATCH) }
                    r.status >= 500 -> { dropDelivered(k.origin); AssistedStep.Stopped(UNKNOWN) }
                    // Vetoed meanwhile, or a body the server refused: a later poll says which.
                    else -> { dropDelivered(k.origin); AssistedStep.Stopped(r.code) }
                }
                // The commit may have landed: a later poll answers request_unknown then, and sign-in decides.
                is WireResult.NoAnswer -> { dropDelivered(k.origin); return AssistedStep.Stopped(UNKNOWN) }
            }
            val pieceId = resp.recoveryPieceId
            if (pieceId == null || !TrustGrammar.isB64_32(pieceId)) {
                forget(k.origin)
                // The server has opened a session: a refusal on this device ends exactly that session there.
                sink.notTaken(k.origin, resp.accessToken, resp.refreshToken)
                return AssistedStep.Stopped(BAD_RESPONSE)
            }
            val opened = SessionOpener.open(crypto, k.origin, emailNorm, resp, uvk.copyOf(), userId, pin.instanceId, knownIdentity(userId),
                device.deviceSecret, SessionHow.RECOVERED, devices, sink, KnownKdf(keys.salt, keys.params, body.newWrappedUvk))
            // Committed on the server either way: the request is gone, and so are its secrets here.
            forget(k.origin)
            val (session, notKept) = when (opened) {
                is Opening.Done -> opened.session to opened.notTaken
                is Opening.Fault -> {
                    sink.notTaken(k.origin, resp.accessToken, resp.refreshToken)
                    return AssistedStep.Stopped(opened.reason)
                }
                Opening.Bad -> {
                    sink.notTaken(k.origin, resp.accessToken, resp.refreshToken)
                    return AssistedStep.Stopped(BAD_RESPONSE)
                }
            }
            // A session the keeper refused all the same (what the device keeps changed while the commit was under way): the
            // commit stands at the server and this kit is the only one, so it goes to the caller with the refusal.
            val qr = RecoveryKit.composeQr(k.origin, pin.card0Hash, emailNorm, piece.recoverySecret) ?: return AssistedStep.Stopped(BAD_RESPONSE)
            val kit = RevealedKit(RecoveryKit.groups(piece.recoverySecret), qr, pieceId, session.account.accountId(crypto), piece.recoverySecret.copyOf())
            return AssistedStep.Recovered(userId, kit, notKept)
        } finally {
            keys.wipe()
            uvk.fill(0)
            piece.recoverySecret.fill(0)
        }
    }

    private fun dropDelivered(origin: String) {
        delivered.remove(origin)?.opened?.wipe()
        refs.entries.removeAll { it.value.origin == origin && (it.value.stage == Stage.CHECK || it.value.stage == Stage.CHOOSE) }
    }

    override fun cancel(step: AssistedStep) {
        val h = when (step) {
            is AssistedStep.ConfirmTarget -> step.handle
            is AssistedStep.Requested -> step.handle
            is AssistedStep.Waiting -> step.handle
            is AssistedStep.CheckAccount -> step.handle
            is AssistedStep.ChoosePassword -> step.handle
            else -> return
        }
        val ref = refs.remove(h) ?: return
        targets.remove(h)
        if (ref.stage == Stage.TARGET) return
        // What was opened goes in every case, also when the kept request itself is gone already (it expired, or was
        // forgotten) and so is not found below: the delivered key and commit value never outlive a leave.
        if (ref.stage == Stage.CHECK || ref.stage == Stage.CHOOSE) delivered[ref.origin]?.takeIf { it.requestId == ref.requestId }?.let { dropDelivered(ref.origin) }
        if (keptFor(ref) != null) forget(ref.origin)
    }

    override fun setAside(step: AssistedStep) {
        val h = when (step) {
            // A target not yet confirmed keeps nothing: setting it aside ends it, and with it its hold on the forgetting
            // of the earlier account for that address ([SessionSink.underWayWhileKept]). Before, it stayed in [targets]
            // and the forgetting was refused as under way until the app was started again.
            is AssistedStep.ConfirmTarget -> {
                refs.remove(step.handle)
                targets.remove(step.handle)
                return
            }
            is AssistedStep.Requested -> step.handle
            is AssistedStep.Waiting -> step.handle
            is AssistedStep.CheckAccount -> step.handle
            is AssistedStep.ChoosePassword -> step.handle
            else -> return
        }
        val ref = refs.remove(h) ?: return
        if (ref.stage == Stage.CHECK || ref.stage == Stage.CHOOSE) delivered[ref.origin]?.takeIf { it.requestId == ref.requestId }?.let { dropDelivered(ref.origin) }
    }

    /** For tests: whether a delivered answer (its key and commit value) is held in memory for [origin]. */
    internal fun holdsOpened(origin: String): Boolean = delivered.containsKey(origin)

    companion object {
        const val BAD_ORIGIN = "bad_origin"
        const val INVALID_EMAIL = "invalid_email"
        const val BAD_PLATFORM = "bad_platform"
        const val NOT_OFFERED = "not_offered"
        const val INSTANCE_BLOCKED = "instance_blocked"
        const val TRUST_GATE_FIRST = "trust_gate_first"
        const val PIN_CHANGED = "pin_changed"
        const val ORIGIN_MISMATCH = "origin_mismatch"
        const val UNREACHABLE = "unreachable"
        const val UNKNOWN = "unknown"
        const val STALE = "stale"
        const val BAD_RESPONSE = "bad_response"
        const val BAD_CODE = "bad_code"
        const val RATE_LIMITED = "rate_limited"
        const val MAIL_UNAVAILABLE = "mail_unavailable"
        /**
         * A `404` for a kept request at the code, the poll or the commit: the server no longer knows it (it lost the row,
         * or lies). The request is KEPT until its own lifetime ends (24 hours unverified, 30 days after its hold), so the
         * app says "The server no longer knows this request." with the choice to wait (a later look asks again) or to
         * start again ([AssistedRecovery.cancel], then a new request). Not "expired".
         */
        const val REQUEST_UNKNOWN = "request_unknown"

        /** The server's `409` code at the emailed code's step for a request its account's owner cancelled (spec 03 §18.4). */
        const val REQUEST_STATE = "request_state"

        /**
         * The right code for a request the account's owner cancelled before it was verified: the account's password or
         * recovery setting changed, or the account was recovered, after the request was made. A final stop: the kept
         * request is forgotten. Suggested words: "This request was cancelled: the account's password or recovery setting
         * changed, or the account was recovered, after you asked. If you still need help, start a new request."
         */
        const val REQUEST_CANCELLED = "request_cancelled"
        const val UNOPENABLE = "unopenable"
        const val IDENTITY_MISMATCH = "identity_mismatch"
        /** Not a verdict string any more (design §2.4: one name each): a fault met when the session opens is named by its own verdict. */
        @Deprecated("use the opening's own verdict (identity_mismatch, no_genesis, a genesis verdict)")
        const val IDENTITY_FAULT = "identity_fault"
        const val ACCOUNT_REJECTED = "account_rejected"
        const val ACCOUNT_NOT_CONFIRMED = "account_not_confirmed"
        const val PASSWORD_TOO_WEAK = "password_too_weak"

        /** The mailbox value's symbols (spec 03 §18.1): capital letters without I and O, and the digits 2 to 9. */
        const val MAILBOX_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

        /** A mailbox value is 16 of [MAILBOX_ALPHABET]'s symbols, shown as four groups of four. */
        const val MAILBOX_VALUE_LENGTH = 16

        /**
         * A typed mailbox value that cannot be one (after spaces, tabs and dashes are removed and letters made capitals, not
         * [MAILBOX_VALUE_LENGTH] symbols of [MAILBOX_ALPHABET]): refused on the device before the request is sent, and the
         * step stays. Also the server's own `400` code for a field that is no string or is too long.
         */
        const val BAD_MAILBOX_VALUE = "bad_mailbox_value"

        /**
         * [typed] in its one form, as the server brings it to that form (the rule decided on 2026-11-17): ASCII only;
         * spaces, tabs and dashes removed, the letters a to z raised to capitals; any other character, a letter outside
         * ASCII that a capital form would turn into one of the alphabet's (the long s, the dotless i, a ligature, a
         * full-width letter) included, leaves it not a value. Null when it is not [MAILBOX_VALUE_LENGTH] symbols of
         * [MAILBOX_ALPHABET]. A screen may ask this as the person types.
         */
        fun mailboxValueOf(typed: String): String? {
            val v = StringBuilder(typed.length)
            for (c in typed) {
                when (c) {
                    ' ', '\t', '-' -> {}
                    in 'a'..'z' -> v.append('A' + (c - 'a'))
                    else -> v.append(c)
                }
            }
            return v.toString().takeIf { it.length == MAILBOX_VALUE_LENGTH && it.all { c -> c in MAILBOX_ALPHABET } }
        }

        /** Whether a typed mailbox field holds nothing but spaces and tabs (no value given), as the server reads it. */
        internal fun mailboxFieldEmpty(typed: String): Boolean = typed.all { it == ' ' || it == '\t' }

        /**
         * Spec 01 §7: this device keeps the account, and the delivered key does not open what the copy holds sealed under
         * the account's key (its identity seed, to the identity key kept beside it). Found at the pick-up or again before the
         * commit: nothing was committed, nothing this device keeps was replaced, no session was opened; what was opened goes
         * and the request is kept. The same code as a sign-in's
         * ([io.silencelen.andvari.core.client.onboard.WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE]).
         */
        const val SERVER_KEYS_NOT_KNOWN_HERE = io.silencelen.andvari.core.client.onboard.WireOnboarding.SERVER_KEYS_NOT_KNOWN_HERE

        /**
         * This device keeps another account (or one at another server, or one held as its server's operator): the
         * session the commit opens could not be kept, so the pick-up (and, asked again, the commit) stops before the
         * person is asked anything and before anything is committed. What was opened goes, the request is kept, and the
         * old kit still opens the account; once that account is signed out, a later poll picks the answer up again.
         */
        const val ANOTHER_SESSION_KEPT = io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT

        /**
         * The answer names an account that is not the one this device keeps for the typed address at this server (the
         * account's id differs). Only someone who holds the operator's recovery key can make such an answer. Found at the
         * pick-up, before the person is shown an account to check or asked for a password, or again before the commit:
         * nothing was committed, nothing kept was replaced, no session was opened; what was opened goes and the request
         * is kept. Signing the kept account out is no way out here: the answer is not for it.
         */
        const val NOT_THE_KEPT_ACCOUNT = "not_the_kept_account"

        /** The account kept here is held as its server's operator account, this one included: stopped as [ANOTHER_SESSION_KEPT] is; the way out is to remove it from this device. */
        const val OPERATOR_ACCOUNT_HELD = io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD

        /**
         * Spec 01 §7: this device keeps the account and the delivered key does not open the copy's sealed identity seed,
         * because the copy itself is damaged (the delivered key opens the answer's seed to the identity the copy records, or
         * the copy's records cannot be read). Stopped at the pick-up or before the commit: nothing committed or replaced,
         * the request kept. The way out is to remove this device's copy; a later poll picks the answer up again.
         */
        const val KEPT_COPY_DAMAGED = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED

        /**
         * Spec 03 §18.5: the answer the server holds is not the one this device opened, found at the
         * poll (the `ready` answer's `commitHash` differs from the opened value's hash, before the person is asked anything)
         * or at the commit (`403 commit_mismatch`). The request is KEPT and nothing opened is held. Never "start again" and
         * never "too late": the app says "The answer on the server is not the one this device opened. The operator must
         * upload it again.", and a later poll picks up a corrected upload.
         */
        const val COMMIT_MISMATCH = "commit_mismatch"

        /**
         * Spec 04 §5: the pinned card names another recovery key than the one the request was made under, and no rotation
         * this device verified covers the change. The request is kept and nothing is polled; the app shows the warning
         * ([RecoveryKeyChange], [AssistedRecovery.recoveryKeyChange]).
         */
        const val RECOVERY_KEY_CHANGED = "recovery_key_changed"
    }
}

/**
 * [RecoveryRequests] for a signed-in device (design §9.3 step 2; spec 03 §18.3): `GET /account/recovery-requests`
 * and the veto, a 0x0A frame signed with the account's identity key through the shared verifiers' [RecoveryVeto.sign]. Neither
 * is tried when the pinned card is `public` (variant R: those routes answer 404). The veto is allowed in every
 * state before the commit: the engine does not ask the list first.
 */
class WireRecoveryRequests(
    private val origin: String,
    private val account: OpenedAccount,
    private val client: WireClient,
    private val trust: InstanceTrust,
    private val crypto: CryptoProvider,
    private val clock: () -> Long,
) : RecoveryRequests {
    private fun offered(): Boolean = trust.pinFor(origin)?.kind?.let { it != io.silencelen.andvari.core.trust.InstanceKind.PUBLIC.literal } ?: false

    private companion object {
        /** Spec 03 §18.3: the account's live requests, each of them still cancellable. */
        val LISTED_STATES = setOf(RecoveryRequestState.HOLDING, RecoveryRequestState.AWAITING_OPERATOR, RecoveryRequestState.READY)
    }

    override suspend fun live(): LiveRecoveryRequests {
        if (!offered()) return LiveRecoveryRequests.NotOffered
        // Row by row: one row this device cannot read is dropped and counted, and never hides the
        // others, least of all in the window the veto is kept for. Only a body that is not a list is refused.
        val r = client.call(WireRoute.ACCOUNT_RECOVERY_REQUESTS,
            decode = { WireJson.json.decodeFromString(ListSerializer(kotlinx.serialization.json.JsonElement.serializer()), it) })
        return when (r) {
            is WireResult.Ok -> {
                val rows = r.value.map { row ->
                    runCatching { WireJson.json.decodeFromJsonElement(RecoveryRequestSummary.serializer(), row) }.getOrNull()?.takeIf {
                        TrustGrammar.isB64_16(it.requestId) && TrustGrammar.isPlatform(it.platform) && it.state in LISTED_STATES
                    }
                }
                val kept = rows.filterNotNull()
                LiveRecoveryRequests.Listed(kept, rows.size - kept.size)
            }
            is WireResult.Refused -> if (r.status >= 500) LiveRecoveryRequests.Unreachable else LiveRecoveryRequests.Refused(r.code)
            is WireResult.NoAnswer -> LiveRecoveryRequests.Unreachable
        }
    }

    override suspend fun veto(requestId: String): VetoOutcome {
        if (!offered()) return VetoOutcome.NotOffered
        if (!TrustGrammar.isB64_16(requestId)) return VetoOutcome.Refused(WireAssistedRecovery.REQUEST_UNKNOWN)
        val frame = account.signing.use { RecoveryVeto.sign(crypto, it, VetoFields(requestId, account.userId, clock())) }
        val r = client.call(WireRoute.RECOVERY_REQUEST_VETO, pathParams = mapOf("requestId" to requestId),
            bodyJson = WireJson.json.encodeToString(RecoveryVetoRequest.serializer(), RecoveryVetoRequest(Bytes.toB64(frame))), decode = { })
        return when (r) {
            is WireResult.Ok -> VetoOutcome.Vetoed
            is WireResult.Refused -> if (r.status >= 500) VetoOutcome.Unknown else VetoOutcome.Refused(r.code)
            is WireResult.NoAnswer -> VetoOutcome.Unknown
        }
    }
}
