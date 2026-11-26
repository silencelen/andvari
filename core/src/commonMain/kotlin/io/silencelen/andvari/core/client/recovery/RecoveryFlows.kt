package io.silencelen.andvari.core.client.recovery

import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.pin.CardPin
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.state.RecoveryRecord

/**
 * Recovery (design §4.5, §9.3, §10): the kit format, kit recovery, the escrow consent rules and the
 * own-mirror rule, and operator-assisted recovery on private instances.
 */

/*
 * The kit's text forms (groups, typed parse, the `andvari-kit:2` QR, the three-group confirmation) are
 * the shared verifiers' [io.silencelen.andvari.core.trust.RecoveryKit], graded by `recoverykit.json`; the engine
 * uses them directly.
 */

/** Kit recovery (spec 03 §12, design §10), only from "Forgot your master password? → Scan your recovery kit". */
sealed class KitRecoveryStep {
    /**
     * [anotherAccountServed]: with the session keeper's identity refusal (`self_identity_mismatch`) only, the kit's account
     * id, where the keeper says this device ties the address to ANOTHER account
     * ([io.silencelen.andvari.core.client.onboard.SessionSink.refusalIsAnotherAccount]); null for the same account under
     * another key and for every other stop.
     */
    data class Stopped(val reason: String, val anotherAccountServed: String? = null) : KitRecoveryStep()

    /**
     * "Recover *email* on *name* (*origin*)": nothing sent yet. A SCANNED kit whose `card0Hash` matched the served card 0
     * was already pinned at [KitRecovery.start] (a kit pin, for this account's recovery only), and that pin is dropped
     * again if the person cancels; while [gate] is set, nothing is pinned until [KitRecovery.verify] confirms the gate.
     *
     * [gate] is the Trust Gate the person must pass in the same confirmation (its [FirstPin.NeedsTrustGate.origin],
     * the name the server calls itself and the operator key's 32-hex short form), or null when the server is
     * already pinned for this recovery. It is set (a) for a TYPED kit, which carries no `card0Hash`: the server is
     * pinned through the typed-address root unless this device already holds a pin that serves this recovery (the
     * baked root for the public instance); and (b) for a scanned kit whose `card0Hash` does not match the served
     * card 0, with [kitAnchorMismatch] true: the "This server's identity changed since your kit was made" warning
     * (design §4.4, N2).
     */
    class ConfirmTarget internal constructor(
        val email: String,
        val instanceName: String,
        val origin: String,
        val kitAnchorMismatch: Boolean,
        val gate: FirstPin.NeedsTrustGate?,
        internal val handle: String,
    ) : KitRecoveryStep()

    /**
     * §2.4 pinning: the newest card served at the kit's origin names another origin. Nothing pinned. The app may
     * offer to recover at [mismatch]'s `cardOrigin` instead ([KitRecovery.retargetOrigin]); every check runs again there.
     */
    class OriginMismatch internal constructor(val mismatch: FirstPin.OriginMismatch, internal val handle: String) : KitRecoveryStep()

    /** Under an existing pin the server moved or changed kind: handle [change] first, then start again. */
    class PinChanged internal constructor(val change: FirstPin.PinChanged) : KitRecoveryStep()

    /** The kit verified (phase 1) and the identity hard-fail passed: choose the new master password. */
    class ChoosePassword internal constructor(internal val handle: String) : KitRecoveryStep()

    /**
     * Committed: signed in; the NEW kit must be captured before the vault opens. Two-step sign-in and requireLink are off.
     *
     * [notKept] non-null: committed at the server (the new password is in force and [newKit] is the account's only kit,
     * the old one is dead), but the session keeper refused the session (its reason, such as
     * [WireKitRecovery.ANOTHER_SESSION_KEPT]: what the device keeps changed while the commit was under way) and ended it
     * there. Nothing is signed in: the screen shows [newKit] to be kept all the same, says that the account could not be
     * opened on this device and why, and the person signs in with the new password once the reason is gone. The kit
     * cannot be confirmed at the server without a session.
     */
    class Recovered internal constructor(val userId: String, val newKit: RevealedKit, val notKept: String? = null) : KitRecoveryStep()

    /** The uniform `401`: wrong kit, unknown email, or no kit row. */
    data object Rejected : KitRecoveryStep()
}

/**
 * What a recovery's commit came to when the person had left the flow after its commit request was sent and before its
 * answer arrived (design §9.3 step 5, §10). A leave stays a leave: the late answer opens no session, nothing of it is
 * kept (no token, no key, no request) and nothing more is sent because of it. Only this outcome is published, once, so
 * that the first screen can say what happened:
 * - [Result.RESET]: the server took the commit. The master password of [email] at [origin] is now the one the person
 *   chose, the old kit is dead, and the new kit was never shown: signing in with the new password makes a new kit before
 *   the vault opens (the server's `recoveryConfirmed` is cleared by the commit).
 * - [Result.REFUSED]: the server refused the commit; the reset did not go through and the old password is unchanged.
 * - [Result.UNKNOWN]: no usable answer (a transport failure, a timeout, a 5xx): the reset may or may not have gone
 *   through; the person tries the new password first, then the old one.
 *
 * Held in memory only: if the app has gone by the time the answer arrives, nothing is owed. It names no server text.
 */
class LateRecoveryOutcome internal constructor(val origin: String, val email: String, val via: Via, val result: Result) {
    enum class Via { KIT, OPERATOR }
    enum class Result { RESET, REFUSED, UNKNOWN }

    internal companion object {
        /** The result a commit's answer stands for. */
        fun resultOf(r: io.silencelen.andvari.core.client.net.WireResult<*>): Result = when (r) {
            is io.silencelen.andvari.core.client.net.WireResult.Ok -> Result.RESET
            is io.silencelen.andvari.core.client.net.WireResult.Refused -> if (r.status >= 500) Result.UNKNOWN else Result.REFUSED
            is io.silencelen.andvari.core.client.net.WireResult.NoAnswer -> Result.UNKNOWN
        }
    }
}

/** One flow's late outcome: the newest waits until a host takes it, and is handed out once. */
internal class LateOutcomes {
    private var waiting: LateRecoveryOutcome? = null
    var onPublished: (() -> Unit)? = null

    fun publish(outcome: LateRecoveryOutcome) {
        waiting = outcome
        onPublished?.invoke()
    }

    fun take(): LateRecoveryOutcome? = waiting.also { waiting = null }
}

interface KitRecovery {
    /**
     * The outcome of a commit the person left before its answer arrived ([LateRecoveryOutcome]), handed out once; null
     * when none waits. Nothing else of that commit is kept.
     */
    fun takeLateOutcome(): LateRecoveryOutcome?

    /** Called when a [LateRecoveryOutcome] was published, on the coroutine the answer arrived on; the host then calls [takeLateOutcome]. */
    var onLateOutcome: (() -> Unit)?

    /**
     * Start from the kit screen with a SCANNED kit (a QR, or a pasted `andvari-kit:2:` text, which counts as a scan);
     * pins from the kit's `card0Hash` (a kit pin, this account only). [entry] must be the kit screen
     * ([io.silencelen.andvari.core.client.pin.PasswordGate]); any other entry stops with `wrong_screen_kit`.
     */
    suspend fun start(kit: io.silencelen.andvari.core.trust.RecoveryKit.Kit, entry: io.silencelen.andvari.core.client.pin.GateEntry): KitRecoveryStep

    /**
     * Start from the kit screen with a TYPED kit: the [email], the server's [origin] (checked against the origin
     * grammar first) and the [typedSecret] groups (spaces, CR and LF ignored, design §10). A typed kit has no
     * `card0Hash`, so this never calls `pinFromKit`: the server is pinned through the Trust Gate (typed-address
     * root), or an existing pin that already serves this recovery is used, or the baked root for the public
     * instance. The gate is shown in [KitRecoveryStep.ConfirmTarget.gate].
     */
    suspend fun startTyped(email: String, origin: String, typedSecret: String, entry: io.silencelen.andvari.core.client.pin.GateEntry): KitRecoveryStep

    /** After [KitRecoveryStep.OriginMismatch]: start again at the origin the newest card names, with the same kit. */
    suspend fun retargetOrigin(step: KitRecoveryStep.OriginMismatch): KitRecoveryStep

    /**
     * The person confirmed the target: when [KitRecoveryStep.ConfirmTarget.gate] is set, pin through that Trust Gate now
     * (a scanned kit that matched was pinned at [start]); then phase 1.
     */
    suspend fun verify(step: KitRecoveryStep.ConfirmTarget): KitRecoveryStep

    /** Phase 2 with a fresh kit and the new password. */
    suspend fun commit(step: KitRecoveryStep.ChoosePassword, newPassword: CharArray): KitRecoveryStep

    /**
     * The recovery stopped before it was done: drop the pin this flow made at [start] (the kit pin of a scanned kit, for
     * this account only) and every secret it holds. Sends nothing. A Trust Gate the person confirmed at [verify] (a
     * typed kit) stays pinned once [verify] has answered, as every confirmed Trust Gate does; a leave while [verify] is
     * still waiting (on the gate or on the server) drops the pin that verify's own gate made, as the assisted recovery
     * drops the pin its request's gate made.
     *
     * **A host calls it on EVERY stop after [start] or [startTyped] returned a step that holds a handle**
     * ([KitRecoveryStep.ConfirmTarget], [KitRecoveryStep.OriginMismatch], [KitRecoveryStep.ChoosePassword]), whatever
     * stopped it: the person backing out, the screen going away, or a stop of the host's own (no new password given, a
     * kit it could not capture, a timeout). Not after [KitRecoveryStep.Recovered] (the commit made the pin the account's)
     * nor after a step that holds no handle (the flow already ended and dropped it itself). Without it, a kit pin made
     * for a recovery the person abandoned stays behind, and the flow's secrets stay in memory. Calling it twice, or with a step
     * whose flow already ended, does nothing. As [AssistedRecovery.cancel] for the assisted recovery.
     */
    fun cancel(step: KitRecoveryStep)
}

/**
 * The escrow decisions of design §4.5 as one pure function, pinned by `recovery.json`. No served posture,
 * no served fingerprint and no account-state record alone can make a device seal.
 */
sealed class EscrowDecision {
    /** Nothing to do (private posture, a public card, or the escrow is current). */
    data object None : EscrowDecision()

    /** Seal or re-seal now, without asking: all three conditions hold AND this device's own mirror agrees. [rotations] are the 0x08 frames to send to `PUT /escrow/self` (empty for a first seal through `PUT /account/recovery`). */
    data class SealNow(val toFp: String, val rotations: List<String>) : EscrowDecision()

    /** "Your account lets the operator of *name* (*origin*) restore it. Keep that?" — [Not now] (default), [Keep], [Turn it off]; both changes need the master password. */
    data class AskOwnMirror(val pin: CardPin) : EscrowDecision()

    /** The recovery key changed with no rotation signed by the old key: the takeover warning, default "Turn off operator recovery". */
    data class UnsignedChange(val pin: CardPin, val fromFp: String, val toFp: String) : EscrowDecision()
}

/**
 * Inputs to [EscrowRules.decide]: what the device holds and what the server served, never a conclusion.
 * The rotation facts are computed INSIDE [EscrowRules] from [servedRotations] through the shared verifiers, so no
 * caller can skip the rotation walk.
 */
data class EscrowInputs(
    /** The pinned card (its `kind`, `instanceId` and `recoveryFp` come from verified card frames). */
    val pin: CardPin,
    /** The account-state `recovery` record (the person's consent), or null. */
    val record: RecoveryRecord?,
    /** This device's own mirror of the record (design §4.5, T2-R-e), or null. */
    val mirror: RecoveryRecord?,
    /** The fingerprint the account's current escrow is sealed to, as this device last saw it; null when none. */
    val escrowFp: String?,
    /** Every 0x08 rotation frame served with the chain (`GET /instance`), oldest first. */
    val servedRotations: List<ByteArray>,
    /** `SHA-256` (full length) of the served recovery public key, or null when not fetched. */
    val servedRecoveryKeyFp: String?,
)

/** The engine's port to the shared verifiers' rotation checks ([io.silencelen.andvari.core.trust.RecoveryRotation]). */
interface RotationFacts {
    /** True when [toFp] follows from [fromFp] by valid rotations among [rotations]. */
    fun follows(rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): Boolean

    /** The rotations among [rotations] that chain [fromFp] to [toFp], oldest first, or null when none do. */
    fun chain(rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): List<ByteArray>?
}

/** [RotationFacts] over the shared verifiers' [io.silencelen.andvari.core.trust.RecoveryRotation]. */
class TrustRotationFacts(private val crypto: io.silencelen.andvari.core.crypto.CryptoProvider) : RotationFacts {
    override fun follows(rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): Boolean =
        io.silencelen.andvari.core.trust.RecoveryRotation.follows(crypto, rotations, instanceId, fromFp, toFp)

    /** The shared verifiers' linear path search over the served (unordered) rotations, oldest first; empty when [fromFp] is [toFp]. */
    override fun chain(rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): List<ByteArray>? =
        io.silencelen.andvari.core.trust.RecoveryRotation.chain(crypto, rotations, instanceId, fromFp, toFp)
}

class EscrowRules(private val rotations: RotationFacts) {
    /**
     * Design §4.5, §7.7:
     * - a `public` card: never (variant R), whatever the record or `recoveryFp` say;
     * - no `operator` record, or the card offers no recovery: nothing;
     * - the card's `recoveryFp` neither equals the consented `fp` nor follows from it by signed rotations:
     *   [EscrowDecision.UnsignedChange] (the takeover warning, default off);
     * - the escrow already names the card's `recoveryFp`: nothing;
     * - the served recovery key must hash to it at full length, or nothing is sealed;
     * - seal without asking only when this device's own mirror agrees with the record AND a rotation chain
     *   leads from the current escrow (`PUT /escrow/self`); otherwise ask (the password path).
     */
    fun decide(inputs: EscrowInputs): EscrowDecision {
        val pin = inputs.pin
        if (pin.kind == "public") return EscrowDecision.None
        val record = inputs.record ?: return EscrowDecision.None
        if (record.posture != "operator" || pin.recoveryFp == "none") return EscrowDecision.None
        val target = pin.recoveryFp
        if (target != record.fp && !rotations.follows(inputs.servedRotations, pin.instanceId, record.fp, target)) {
            return EscrowDecision.UnsignedChange(pin, record.fp, target)
        }
        if (inputs.escrowFp == target) return EscrowDecision.None
        if (inputs.servedRecoveryKeyFp != target) return EscrowDecision.None
        val mirror = inputs.mirror
        val ownMirror = mirror != null && mirror.posture == record.posture && mirror.fp == record.fp && mirror.at == record.at
        val chain = inputs.escrowFp?.let { rotations.chain(inputs.servedRotations, pin.instanceId, it, target) }
        return if (ownMirror && !chain.isNullOrEmpty()) EscrowDecision.SealNow(target, chain.map { io.silencelen.andvari.core.crypto.Bytes.toB64(it) })
        else EscrowDecision.AskOwnMirror(pin)
    }

    companion object {
        /**
         * First consent (FS-R2, FC-2): walk the chain from card 0 and require every `recoveryFp` change to be
         * covered by a rotation. The shared verifiers' walk; false means the choice shows the unsigned-change warning with
         * "Only me" preselected.
         */
        fun firstConsentClean(
            crypto: io.silencelen.andvari.core.crypto.CryptoProvider,
            cards: List<io.silencelen.andvari.core.trust.CardFields>,
            rotations: List<ByteArray>,
        ): Boolean = io.silencelen.andvari.core.trust.RecoveryRotation.unsignedChanges(crypto, cards, rotations).isEmpty()
    }
}

/** Operator-assisted recovery on a private instance (design §9.3). */
sealed class AssistedStep {
    /**
     * The flow stopped, or (for `bad_code`, `rate_limited` and `password_too_weak`) this one answer was refused and
     * the step the app holds stays valid. [retryAfterSeconds] comes with `rate_limited`. [anotherAccountServed]: with the
     * session keeper's identity refusal (`self_identity_mismatch`) only, the answer's account id, where the keeper says
     * this device ties the address to ANOTHER account
     * ([io.silencelen.andvari.core.client.onboard.SessionSink.refusalIsAnotherAccount]); null otherwise.
     */
    data class Stopped(val reason: String, val retryAfterSeconds: Long? = null, val anotherAccountServed: String? = null) : AssistedStep()

    /**
     * "Ask the operator of *name* (*origin*) to reset *email*", with §9.3 step 1's copy ("Anyone who gets into your
     * email can ask too. The operator waits 7 days and checks with you, and your other devices can cancel."). Nothing
     * sent yet. [gate] is the Trust Gate to pass in the same confirmation (no pin, or a pin that is not a password pin
     * for this purpose, such as a kit or setup pin, design §4.4), or null when the pin already serves it.
     */
    class ConfirmTarget internal constructor(
        val email: String,
        val instanceName: String,
        val origin: String,
        val gate: FirstPin.NeedsTrustGate?,
        internal val handle: String,
    ) : AssistedStep()

    /**
     * Requested and kept on this device: show [requestCode] (six groups of four) "Read this to the operator when they
     * contact you.", and ask for the 6-digit code the email holds ([AssistedRecovery.verifyCode]).
     */
    class Requested internal constructor(val origin: String, val requestCode: String, internal val handle: String) : AssistedStep()

    /** Waiting: `holding` until [holdEndsAt], then `awaiting_operator`. [requestCode] stays on screen for the operator's call. */
    class Waiting internal constructor(val origin: String, val state: String, val holdEndsAt: Long?, val requestCode: String, internal val handle: String) : AssistedStep()

    /**
     * §9.3 step 4: fulfilled and verified (0x09 signed by the pinned card's recovery key, ids match, the identity
     * seed opens and matches). Nothing ties the delivered account to the address the person typed, so before any
     * new password the app shows [accountId] (the delivered identity's 32-hex short fingerprint, as on a kit and
     * in every notice) with "Check this against the account ID in an earlier andvari email to you. If it is
     * different, stop". Continuing is an explicit choice: [AssistedRecovery.confirmAccount] is the only way to
     * [ChoosePassword], and the engine refuses a commit for a request whose account was not confirmed.
     */
    class CheckAccount internal constructor(val email: String, val instanceName: String, val origin: String, val accountId: String, internal val handle: String) : AssistedStep()

    /** The person confirmed the delivered account ([CheckAccount]): choose a password. */
    class ChoosePassword internal constructor(internal val handle: String) : AssistedStep()

    /**
     * Committed: signed in, and the new kit must be captured before the vault opens. [notKept] non-null: committed at
     * the server all the same (the new password is in force, [newKit] is the only kit, the request is gone), but the
     * session keeper refused the session and ended it there, as for [KitRecoveryStep.Recovered.notKept]: the kit is shown
     * to be kept, and the person signs in with the new password once the reason is gone.
     */
    class Recovered internal constructor(val userId: String, val newKit: RevealedKit, val notKept: String? = null) : AssistedStep()
}

/**
 * The server's recovery key changed while a request this device keeps was open (spec 04 §5, design §9.3). A kept request
 * records the fingerprint of the recovery key the pinned card named when the request was made; each later look compares
 * it with the pinned card's.
 * - [signed] true: the change is covered by rotation statements this device verified, each signed by the outgoing key
 *   (the first by the key the request was made under). The request goes on under the new key; the screen says that the
 *   server's recovery key changed, and since when: [rotatedAt] is the `issuedAt` of the server's card that first named
 *   the new key (the first card after the last one naming another key; the operator's own signed time, ms), not the
 *   rotation statement's. [fromFp] is the key the request was made under.
 * - [signed] false: no verified rotation covers it. The request is stopped at every look ([WireAssistedRecovery.RECOVERY_KEY_CHANGED]):
 *   nothing is polled, picked up or opened, and the app shows the warning of spec 04 §5, "The recovery key for *name*
 *   (*origin*) changed without the old key's signature. This can mean the operator lost the old key. It can also mean
 *   someone has taken over this server's identity.", with the choice to stop the request (default) or to keep waiting
 *   only if the operator has told the person why it changed. The request stays kept until its lifetime ends or the person
 *   stops it ([AssistedRecovery.cancel]); a rotation served later that covers the change lets it go on. [fromFp] is null for
 *   a request kept before devices recorded the key, and [rotatedAt] is null.
 * Fingerprints are `hex64`; the app shows their short form if it shows them at all.
 */
class RecoveryKeyChange internal constructor(val origin: String, val fromFp: String?, val toFp: String, val signed: Boolean, val rotatedAt: Long?)

/** Assisted recovery on a fresh install (design §9.3 steps 1, 2, 4 and 5; spec 03 §18). */
interface AssistedRecovery {
    /**
     * The change of the server's recovery key seen for the request kept for [origin] ([RecoveryKeyChange]), or null when
     * the key is the one the request was made under. A signed change is kept with the request (it outlives a restart); an
     * unsigned one is what the last look at the request found.
     */
    fun recoveryKeyChange(origin: String): RecoveryKeyChange?

    /** As [KitRecovery.takeLateOutcome]: a commit the person left before its answer arrived, handed out once. */
    fun takeLateOutcome(): LateRecoveryOutcome?

    /** As [KitRecovery.onLateOutcome]. */
    var onLateOutcome: (() -> Unit)?

    /**
     * "I lost my master password and my recovery kit" → "Ask the operator for help", for [email] at [origin]. Never
     * offered when the pinned card (or the card the Trust Gate would pin) is `public` or offers no recovery key
     * (`not_offered`). Sends nothing: the answer is [AssistedStep.ConfirmTarget].
     */
    suspend fun start(email: String, origin: String): AssistedStep

    /**
     * The person confirmed (and passed the gate, when set): `POST /recovery/requests`. [AssistedStep.Requested] on `202`.
     *
     * [mailboxValue], optional: the value a mail about a request the person did not make carried ("have a value from a
     * mail about a request you did not make?"). It goes with the request as typed, without spaces, tabs or dashes and in
     * capitals ([WireAssistedRecovery.mailboxValueOf]); one that cannot be a value (not 16 symbols of
     * [WireAssistedRecovery.MAILBOX_ALPHABET]) stops here as [WireAssistedRecovery.BAD_MAILBOX_VALUE] with nothing sent,
     * and the step stays. The answer teaches the device nothing: it is the same with a right value, a wrong one or none,
     * and nothing this flow answers depends on whether one was given. The person learns that it worked by the mail.
     */
    suspend fun request(step: AssistedStep.ConfirmTarget, mailboxValue: String? = null): AssistedStep

    /** The emailed code. A wrong, expired or used-up code is `bad_code` and the step stays. */
    suspend fun verifyCode(step: AssistedStep.Requested, code: String): AssistedStep

    /** Poll a [AssistedStep.Requested] or [AssistedStep.Waiting]; once fulfilled and verified, [AssistedStep.CheckAccount]. */
    suspend fun poll(step: AssistedStep): AssistedStep

    /** The origins for which this device keeps a request (`rSec` and `pollSecret` outlive a restart, N11). */
    fun keptOrigins(): List<String>

    /** After a restart: poll the request kept for [origin]; null when none is kept. */
    suspend fun resume(origin: String): AssistedStep?

    /**
     * The person's answer on [AssistedStep.CheckAccount]: [same] true leads to [AssistedStep.ChoosePassword]; false
     * stops (`account_rejected`), drops `rSec` and `pollSecret`, and sends nothing.
     */
    suspend fun confirmAccount(step: AssistedStep.CheckAccount, same: Boolean): AssistedStep
    suspend fun commit(step: AssistedStep.ChoosePassword, newPassword: CharArray): AssistedStep

    /**
     * The person gave up: drop the kept request, `rSec` and `pollSecret`, any pin this flow made, and what was opened (the
     * delivered key and its commit value). Sends nothing.
     */
    fun cancel(step: AssistedStep)

    /**
     * The person left a screen of the request without giving it up (back from the account check or the password screen,
     * the app closed to the first screen): the step is dead, and what was opened goes (the delivered key and its commit
     * value), so nothing of an answer outlives the screen it was opened for. The request stays kept; the next [poll] or
     * [resume] picks the answer up again and runs every check again. On [AssistedStep.ConfirmTarget], where nothing is
     * kept yet, the target ends (as [cancel] ends it): its hold on the forgetting of the earlier account goes with it.
     * Sends nothing. On a step with no handle it does nothing.
     */
    fun setAside(step: AssistedStep)
}

/** The account's live requests as a signed-in device reads them. */
sealed class LiveRecoveryRequests {
    /**
     * [requests]' `platform` is self-reported: every list that shows it says so. A request's `state` is `holding`,
     * `awaiting_operator` or `ready` (answered by the operator, not yet committed: still cancellable, spec 03 §18.3).
     * [unreadable] counts the rows the server sent that this device could not read (not an object, a field outside its
     * grammar, a state the specification does not name): each was dropped, never the whole list. When it is above zero
     * the app says that the server sent requests this device cannot show, so that an empty list is not read as "nobody
     * asked".
     */
    class Listed internal constructor(
        val requests: List<io.silencelen.andvari.core.model.wire.RecoveryRequestSummary>,
        val unreadable: Int = 0,
    ) : LiveRecoveryRequests()

    /** The pinned card is `public` (variant R) or this device holds no pin: nothing was asked. */
    data object NotOffered : LiveRecoveryRequests()
    data object Unreachable : LiveRecoveryRequests()
    data class Refused(val code: String) : LiveRecoveryRequests()
}

/** What a veto came to. */
sealed class VetoOutcome {
    data object Vetoed : VetoOutcome()
    data object NotOffered : VetoOutcome()

    /** No answer: the request may or may not be cancelled; list again. */
    data object Unknown : VetoOutcome()
    data class Refused(val code: String) : VetoOutcome()
}

/** A signed-in device (design §9.3 step 2): the account's live requests and the veto (0x0A), allowed in every state before the commit. */
interface RecoveryRequests {
    suspend fun live(): LiveRecoveryRequests
    suspend fun veto(requestId: String): VetoOutcome
}
