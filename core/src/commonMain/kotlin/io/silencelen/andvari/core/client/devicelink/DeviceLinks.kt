package io.silencelen.andvari.core.client.devicelink

import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry

/**
 * Device links in both roles (design §8.2), as state machines whose security steps cannot be skipped:
 * each state that lets the flow move on has an internal constructor and is produced only after the
 * checks before it. Nothing here touches the web client (design §13).
 *
 * Existing device E: create → see and fix the claim (mac verified) → post `nonceE` → check N's reveal
 * against `commitN` → the person TYPES N's six digits → approve after a local unlock (outer + bundle +
 * approveMac).
 *
 * New device N: only from "Link from your other device" (or `andvari-cli link-device`) → a password pin
 * for the link's origin first (the gate) → claim → hold the FIRST `nonceE` → reveal → show the code →
 * receive `outer` + `approveMac`, check origin and MAC → only then ask for the master password → pickup →
 * open the bundle under the UVK-derived key, check identity, genesis and the card checkpoint against the
 * pin → import.
 */

/**
 * Why a device-link flow ended without linking (design §2.4 "Device link"). Format verdicts come from
 * the shared verifiers' `DeviceLink` functions; the flow stops (`bad_link`, `claim_changed`, `nonce_changed`,
 * `code_mismatch`) are the engine's, and each cancels the link.
 */
enum class DeviceLinkStop(val code: String) {
    // ---- flow stops ----
    /** The `/d` URL does not parse. */
    BAD_LINK("bad_link"),
    /** A `/d` link that did not come from "Link from your other device" (design §8.2 step 0): nothing starts. */
    WRONG_ENTRY("wrong_entry"),
    TRUST_GATE_DECLINED("trust_gate_declined"),
    /**
     * The link is gone: `404` from the server. For a link made on another device the wire answers `404` both when
     * that device cancelled it and when it was replaced by a newer link of the account (creating a link cancels the
     * others), and the two cannot be told apart, so both are this one stop.
     */
    CANCELLED("cancelled"),
    /** N: `409 link_claimed`, another device claimed this link first. Nothing was sent but the claim; the link is spent. */
    LINK_CLAIMED("link_claimed"),
    EXPIRED("link_expired"),
    /** E: a later poll showed a claim differing in nPub, name, platform or commitN from the one it verified (T2-R-b). */
    CLAIM_CHANGED("claim_changed"),
    /** N: a `nonceE` other than the first it held (T2-R-b). */
    NONCE_CHANGED("nonce_changed"),
    /** The digits typed into E are not the code. */
    CODE_MISMATCH("code_mismatch"),
    BAD_PROOF("bad_proof"),
    UNREACHABLE("unreachable"),
    /**
     * The server refused a step that cannot wait (E's nonce or approval, N's claim or pickup) as one of too many requests
     * (`429`): the link ended there, and the stop carries the wait the server named, when it named one
     * ([ExistingStep.Stopped.retryAfterSeconds], [NewStep.Stopped.retryAfterSeconds]). Never said as "unreachable": the
     * server answered. The steps that can wait within the link's time (the polls, the reveal, the view) wait instead.
     */
    TOO_MANY("rate_limited"),
    /**
     * N: the server refused the pickup's password proof (the uniform 401, before any code was asked for in the link)
     * although the typed password opens this device's kept wrap of the account: not a wrong password, the server holds
     * other keys for the account than this device knows. Within the link's time the link stays and the step is
     * [NewStep.WrongPassword] with `proofRefused`; this stop is that refusal once the link's time is past. Nothing was
     * linked.
     */
    PROOF_REFUSED("reauth_failed"),
    /** The link's origin is blocked here (a forked or damaged pin, design §4.4): nothing claimed. */
    INSTANCE_BLOCKED("instance_blocked"),
    /** The pin step refused (§2.4 pinning, or the served chain's own verdict in [NewStep.Stopped.pinVerdict]): nothing claimed. */
    PIN_REFUSED("pin_refused"),
    /** This device's name is not a `name` (§2.2): no claim can carry it. */
    BAD_NAME("bad_name"),
    /** The served KDF parameters are outside the fence (spec 05 T1): nothing derived. */
    KDF_REFUSED("kdf_refused"),
    /** A step handed back that this engine no longer holds (cancelled, finished, or another engine's). */
    STALE("stale"),
    /** Nothing to do from this side right now (E holds no unlocked account for the link). */
    NO_SESSION("no_session"),

    // ---- E, format verdicts (the shared verifiers') ----
    BAD_CLAIM("bad_claim"),
    BAD_MAC("bad_mac"),
    BAD_REVEAL("bad_reveal"),

    // ---- N before any password prompt (the shared verifiers'), in §2.4's order: BAD_MAC above FIRST (the approveMac over the raw
    // sealed bytes, before anything is opened or parsed), then these three ----
    OUTER_UNOPENABLE("outer_unopenable"),
    BAD_OUTER("bad_outer"),
    ORIGIN_MISMATCH("origin_mismatch"),

    // ---- N after pickup and unlock: the genesis verdicts first (the genesis is verified at the unlock, as at every
    // unlock, and any of them stops here as IDENTITY_MISMATCH), then the shared verifiers' bundle verdicts in this order ----
    BUNDLE_UNOPENABLE("bundle_unopenable"),
    BAD_BUNDLE("bad_bundle"),
    /** The bundle's userId, identityPub or personalVaultId against the session, the seed-derived key and the verified genesis; or a genesis verdict. */
    IDENTITY_MISMATCH("identity_mismatch"),
    /** The bundle's origin, instanceId or card checkpoint disagrees with N's pin: signed out, the step-0 pin removed. */
    PIN_MISMATCH("pin_mismatch"),

    /**
     * Spec 01 §7: N keeps the link's account, and the key the pickup opened is not that account's key as N knows it (no
     * kept wrap the typed password opens holds it, and it does not open the copy's sealed identity seed). The server's new
     * session was ended there, nothing N keeps was replaced, and nothing of the bundle was used. The sign-in's code.
     */
    SERVER_KEYS_NOT_KNOWN_HERE("server_keys_not_known_here"),

    /**
     * The session keeper did not keep the pickup's session: another account (or one at another server) is kept on this
     * device and must be ended first by its own act. Exactly that session was ended at its server; nothing of the bundle
     * was used. (The session keeper's identity refusal for an address bound to another account stops as [IDENTITY_MISMATCH],
     * with [NewStep.Stopped.addressKnownHere] set.)
     */
    ANOTHER_SESSION_KEPT("another_session_kept"),

    /**
     * The session keeper did not keep the pickup's session for a reason of its own that this flow does not know: the
     * keeper's own code is handed through unchanged in [NewStep.Stopped.keeperReason], never turned into another stop.
     * Nothing of the bundle was used; after the pickup, exactly its session was ended at its server.
     */
    KEEPER_REFUSED("keeper_refused"),

    /**
     * The account this device keeps is held here as its server's operator account: no session is kept beside it or over
     * it, not even one of that very account. Stopped before the pickup where the device can tell (nothing picked up), else
     * after it with exactly the new session ended. The way out is to remove the held account from this device.
     */
    OPERATOR_ACCOUNT_HELD("operator_account_held"),

    /**
     * Spec 01 §7: N keeps the link's account, no kept wrap opened with the typed password, and the copy's sealed identity
     * seed does not open because the copy itself is damaged: nothing could be compared, nothing N keeps was replaced, and
     * the pickup's session was ended there. The way out is to remove this device's copy, then link or sign in again.
     */
    KEPT_COPY_DAMAGED("kept_copy_damaged"),

    /**
     * The server refused the pickup after its two-step code was sent. It had asked for the code only after it accepted
     * this password a moment before, and it answers a wrong code and a wrong password alike from then on: never "wrong
     * password"; most likely the code was wrong or already used. Nothing was linked and this pickup's keys are gone:
     * start again with a new link from the other device and the current code.
     */
    REFUSED_AFTER_CODE("refused_after_code"),
}

/** E's side. */
sealed class ExistingStep {
    /** [retryAfterSeconds]: for [DeviceLinkStop.TOO_MANY], the wait the server named, when it named one. */
    data class Stopped(val reason: DeviceLinkStop, val retryAfterSeconds: Long? = null) : ExistingStep()

    /** The link exists: show [url] as a QR with "It links to *name* (*origin*)", counting down from [ttlMs]. */
    class Shown internal constructor(val url: String, val origin: String, val instanceName: String, val ttlMs: Long, internal val token: DeviceLinkToken) : ExistingStep()

    /** A claim arrived and its mac verified; E fixed it and posted `nonceE`. [name] is plain text, [platform] from the claim. */
    class ClaimFixed internal constructor(val name: String, val platform: String, internal val token: DeviceLinkToken) : ExistingStep()

    /** N revealed and the reveal matched `commitN`: "Add *name* (*platform*)? Type the six digits shown on the new device". */
    class TypeDigits internal constructor(val name: String, val platform: String, internal val token: DeviceLinkToken) : ExistingStep()

    /** The typed digits matched: approve after Face ID, fingerprint or the master password. */
    class Approvable internal constructor(val name: String, val platform: String, internal val token: DeviceLinkToken) : ExistingStep()

    /** Approved: the server holds `outer`, `inner` and `approveMac`; N picks up with its password. */
    data class Approved(val name: String) : ExistingStep()
}

/** N's side. */
sealed class NewStep {
    /** [pinVerdict] names the pinning or chain verdict when [reason] is [DeviceLinkStop.PIN_REFUSED]. */
    /** [retryAfterSeconds]: for [DeviceLinkStop.TOO_MANY], the wait the server named, when it named one. */
    /**
     * [addressKnownHere]: with [DeviceLinkStop.IDENTITY_MISMATCH] only, the address the link's account goes by, where the
     * session keeper refused because this device knows that address at the link's server under ANOTHER account (the one
     * it first took there, spec 01 §5): the stop of its own at which the layer above can offer to forget that earlier
     * account, as at a sign-in ([io.silencelen.andvari.core.client.session.SessionKeeper.addressBinding] says where it
     * stands; [io.silencelen.andvari.core.client.session.SessionKeeper.forgetEarlierAccount] forgets it). Null for every
     * other identity fault: an identity key that differs for the same account, a served answer that is not the session
     * it must be, a kept copy whose identity differs. Nothing was picked up where it is set before the pickup; after it,
     * exactly the pickup's session was ended at its server. The keeper decides it
     * ([io.silencelen.andvari.core.client.onboard.SessionSink.refusalIsAnotherAccount]), with the account's key where the
     * stop knows it. [anotherAccountServed]: with [addressKnownHere], and only then, the link's account id (the account the
     * server serves now); null otherwise.
     */
    data class Stopped(
        val reason: DeviceLinkStop, val pinVerdict: String? = null, val retryAfterSeconds: Long? = null, val addressKnownHere: String? = null,
        val anotherAccountServed: String? = null,
        /** For [DeviceLinkStop.KEEPER_REFUSED]: the session keeper's own reason, exactly as the keeper named it. */
        val keeperReason: String? = null,
    ) : NewStep() {
        /**
         * True where the session keeper refused this link BEFORE its pickup was sent: at the approval, once the account is
         * named, or at the ask just before the pickup. Nothing was picked up and the server opened no session for it, so
         * an identity stop with no [addressKnownHere] there is one this device cannot tell apart (the address known here
         * under another account, or a record of the account's key that no served key could be compared with), and offers
         * nothing. False for every other stop: the pickup's own identity checks, and the keeper's refusal of the pickup's
         * session at the take, included. Not part of equality, and not carried by `copy`.
         */
        var keeperBeforePickup: Boolean = false
            private set

        internal constructor(
            reason: DeviceLinkStop, addressKnownHere: String?, anotherAccountServed: String?, keeperReason: String?, keeperBeforePickup: Boolean,
        ) : this(reason, null, null, addressKnownHere, anotherAccountServed, keeperReason) {
            this.keeperBeforePickup = keeperBeforePickup
        }
    }

    /**
     * §2.4 pinning at step 0: the newest card served at the link's origin names another origin. Nothing pinned and
     * nothing claimed; the app shows the dialed origin, whole. A device link is never retargeted: E's QR names the
     * origin, and the person starts again from E.
     */
    class OriginMismatch internal constructor(val mismatch: FirstPin.OriginMismatch) : NewStep()

    /** Under an existing pin the link's server moved or changed kind: handle [change] first, then scan again. Nothing claimed. */
    class PinChanged internal constructor(val change: FirstPin.PinChanged) : NewStep()

    /** N holds no password pin for the link's origin: the device-link Trust Gate ("Is this your server?"). */
    class TrustGate internal constructor(val gate: FirstPin.NeedsTrustGate, internal val token: DeviceLinkToken) : NewStep()

    /** Claimed; waiting for E's nonce. */
    class Claimed internal constructor(val origin: String, internal val token: DeviceLinkToken) : NewStep()

    /** N holds `nonceE` and revealed: show [code] (six digits) for the person to type into E. */
    class ShowCode internal constructor(val code: String, internal val token: DeviceLinkToken) : NewStep()

    /**
     * E approved: `outer` opened under N's key, names the pinned origin, and `approveMac` verified. Now —
     * and only now — ask "Master password for *email* on *name* (*origin*)".
     */
    class PasswordNeeded internal constructor(val email: String, val origin: String, val instanceName: String, internal val token: DeviceLinkToken) : NewStep()

    /** The account has two-step sign-in: ask for the code and pick up again. */
    class TotpNeeded internal constructor(internal val token: DeviceLinkToken) : NewStep()

    /**
     * The pickup was refused with the uniform 401 and the link stays: ask for the password again (and then the code, which
     * the server asks for once it takes the password); the email backoff applies. [afterCode] false: no code had been
     * asked for, so the password was wrong. [afterCode] true: the server refused the pickup after its code step, and from
     * then on it answers a wrong code and a wrong password alike, so this is never said as a wrong password: say a refusal
     * after the code (the server keeps the link approved within its time; the link's time past, the refusal stops as
     * [DeviceLinkStop.REFUSED_AFTER_CODE]). Whether a code was asked for is the flow's, not the call's: once the server
     * has asked for one in this link, every later 401 is [afterCode], also one to a pickup sent without a code.
     *
     * [proofRefused] true (never with [afterCode]): no code had been asked for in this link, and the typed password
     * opens this device's kept wrap of the account, so the server refused a proof of a password this device knows (most
     * often a former password, changed on another device, that still opens this device's copy; or the password of a
     * change from this device whose answer was lost). Never said as a wrong password: say that the server did not take
     * this password although it opens the copy on this device, and ask for the account's current password. The link
     * stays within its time; past it the refusal stops as [DeviceLinkStop.PROOF_REFUSED].
     */
    class WrongPassword internal constructor(
        internal val token: DeviceLinkToken,
        val afterCode: Boolean = false,
        val proofRefused: Boolean = false,
    ) : NewStep()

    /**
     * Linked: the session is live, the bundle verified and imported. Offer quick unlock. [copyUnderOtherPassword] (spec 01
     * §7): this device kept the account, none of its kept wraps opened with the typed password, and the key the pickup
     * opened did open the copy's sealed identity seed: the copy was sealed under another master password and now follows
     * the server's, which a screen says in one line (as after a sign-in). False on every other link.
     */
    data class Linked(val userId: String, val deviceId: String, val copyUnderOtherPassword: Boolean = false) : NewStep()
}

/** The engine's handle on one device link in progress; opaque. */
class DeviceLinkToken internal constructor(internal val id: String)

/** Device links for this device. */
interface DeviceLinks {
    // ---- E ----

    /** Create the link (cancels any other of this account, server-side); requires a signed-in, unlocked account. */
    suspend fun create(): ExistingStep

    /** Advance E: poll for the claim, post the nonce, poll for the reveal. Returns the same step while nothing changed. */
    suspend fun advance(step: ExistingStep): ExistingStep

    /** The person typed N's digits into E. A mismatch cancels the link. */
    suspend fun typeDigits(step: ExistingStep.TypeDigits, digits: String): ExistingStep

    /** Approve after the local unlock the app performed; builds `outer`, the bundle and `approveMac`. */
    suspend fun approve(step: ExistingStep.Approvable): ExistingStep

    // ---- N ----

    /** Start from [text] (a `/d` URL or fragment) on [entry]; only `link_device_screen` and `cli_link_device` start anything. */
    suspend fun start(text: String, entry: GateEntry): NewStep

    /** Continue after the Trust Gate was confirmed (or declined: [confirmed] false). */
    suspend fun afterTrustGate(step: NewStep.TrustGate, confirmed: Boolean): NewStep

    /** Advance N: poll for `nonceE` (holding the first), reveal, poll for the approval. */
    suspend fun advance(step: NewStep): NewStep

    /**
     * Where the server asked this device to wait (a refusal for too many requests, within the link's own time), how many
     * seconds are left of that wait for the link of [step], rounded up; null when nothing holds the link back, or for a
     * step this engine does not hold. [advance] answers such a step as it was, asking nothing, until the wait is over.
     */
    suspend fun waitingSeconds(step: NewStep): Long? = null

    /** Prelogin at the pinned origin, derive `authKey`, pick up, verify and import. [password] is wiped by the caller after. */
    suspend fun pickup(step: NewStep, password: CharArray, totp: String? = null): NewStep

    // ---- both ----

    /** Cancel from either side (E deletes the link; N stops polling and forgets its keys). */
    suspend fun cancel(token: DeviceLinkToken)
}
