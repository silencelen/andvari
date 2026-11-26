package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry

/**
 * Links (design §6) as explicit state machines. Each step returns the next state; the states that let
 * the person act ([RecipientStep.Confirm], [CreatorStep.Processed]) have internal constructors, so a
 * caller can reach them only through every check of design §6.8 in order. A link secret never leaves the
 * creating device's own device state (T-B6). The web client has no code path here (design §13).
 */

/**
 * Why a recipient flow stopped. [code] is the design's verdict string (§2.4 "Opening a link", spec 03 §15.9) where
 * the design names one; each value names its own copy; nothing is sent after a stop.
 */
enum class LinkStop(val code: String) {
    // ---- before the server is asked ----
    /** The text does not parse as an `/l` link (§6.1). */
    BAD_LINK("bad_link"),
    /** A `/d` link or a kit where an invite was expected (design §12.1): start nothing. */
    WRONG_SCREEN_DEVICE_LINK("wrong_screen_device_link"),
    WRONG_SCREEN_KIT("wrong_screen_kit"),
    /** An invite handed to "Link from your other device" or "Scan your recovery kit" (§12.1, FS-B1): start nothing. */
    WRONG_ENTRY("wrong_entry"),

    // ---- the server's answer to GET /links/{linkId} ----
    UNKNOWN("link_unknown"),
    EXPIRED("link_expired"),
    /** `answered` on a link this device did not answer, or `409 link_used` on the answer. */
    ALREADY_USED("link_used"),

    // ---- the offer (the shared verifiers' LinkOffer.open), in §2.4's order ----
    UNOPENABLE("unopenable"),
    UNKNOWN_FORMAT("unknown_format"),
    KIND_MISMATCH("kind_mismatch"),
    BAD_FRAME("bad_frame"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),
    CREATOR_MISMATCH("creator_mismatch"),
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key"),
    BAD_SIGNATURE("bad_signature"),
    LINK_MISMATCH("link_mismatch"),
    /** The offer names another origin than the link, or (pinning, §2.4) the newest card names another origin than the one dialed. */
    ORIGIN_MISMATCH("origin_mismatch"),
    OFFER_EXPIRED("offer_expired"),
    /** `from`/`fromKey` differ from the server-reported creator: an anomaly, nothing sent (T-R5). */
    REPORTED_CREATOR_MISMATCH("reported_creator_mismatch"),

    // ---- the pinning verdicts (§2.4, §4.4) ----
    CARD0_MISMATCH("card0_mismatch"),
    INSTANCE_MISMATCH("instance_mismatch"),
    CARD_NOT_IN_CHAIN("card_not_in_chain"),
    /** The served chain does not extend this device's pin: durable until "Forget this server". */
    FORK("fork"),
    /** The served chain ends below this device's pin (or is empty): nothing pinned, retry later. */
    WITHHELD("withheld"),
    /** This device's pin record for the origin does not decode: the origin is blocked. */
    DAMAGED("damaged"),
    PIN_CONFLICT("pin_conflict"),
    /** The served chain itself failed verification; [RecipientStep.Stopped.cardVerdict] names the shared verifiers' verdict. */
    BAD_CARD("bad_card"),
    /** A store build met the public instance moved or changed: "Update andvari". */
    UPDATE_REQUIRED("update_required"),

    // ---- the kind's own rules ----
    /** A phone app was handed a setup link (design §9.5): "open it on a computer". */
    SETUP_ON_PHONE("setup_on_phone"),
    /** A setup link while the instance already serves cards (§2.4 "Small cases"). */
    ALREADY_SET_UP("already_set_up"),
    /** The link is this account's own (`400 cannot_target_self`, checked before anything is sent). */
    OWN_LINK("cannot_target_self"),
    /** The account holds 1,000 contacts, the most it can (§5.4); nothing sent. */
    TOO_MANY_CONTACTS("too_many_contacts"),
    /** The Trust Gate of an enrol link was declined. */
    DECLINED("declined"),
    /** The account's display name is not a `name` (§2.2): no answer can carry it. */
    BAD_NAME("bad_name"),
    /** The step handed back is no longer this engine's (dismissed, finished, or from another engine). */
    STALE("stale"),

    // ---- after the answer ----
    /** The creator's reveal does not open the offer's commitment (§6.11 pass 3): the link is failed, no code. */
    BAD_REVEAL("bad_reveal"),
    UNREACHABLE("unreachable"),
}

/** The opened, verified offer as the recipient may show it. Names are plain text, always shown with the origin. */
data class OfferView(
    val kind: String,
    val origin: String,
    val instanceName: String,
    /** Connect and register: the creator's chosen name, "(as they call themselves)". Null for host-minted links. */
    val creatorName: String?,
    val creatorUserId: String?,
    val expiresAt: Long,
    /** Enrol links bound to one address: the prefilled, fixed email. */
    val boundEmail: String?,
)

/** The recipient's flow (design §6.8, recipient side). */
sealed class RecipientStep {
    /** [cardVerdict] is the shared verifiers' chain verdict when [reason] is [LinkStop.BAD_CARD]. */
    data class Stopped(val reason: LinkStop, val cardVerdict: String? = null) : RecipientStep()

    /** The instance is not the one this app is signed in to (design §6.7 dead ends): offer to switch. */
    class OtherInstance internal constructor(val offer: OfferView, val currentOrigin: String, internal val token: RecipientToken) : RecipientStep()

    /**
     * §2.4 `origin_mismatch` at the first pin: the newest card the link's server serves names [cardOrigin], not the
     * address the link dialed ([dialedOrigin]). Nothing was pinned or sent; the invite shows both addresses. (A signed
     * offer naming another address than the link's is a [Stopped] with [LinkStop.ORIGIN_MISMATCH].)
     */
    class OriginMismatch internal constructor(val dialedOrigin: String, val cardOrigin: String) : RecipientStep() {
        val reason: LinkStop get() = LinkStop.ORIGIN_MISMATCH
        override fun equals(other: Any?) = other is OriginMismatch && other.dialedOrigin == dialedOrigin && other.cardOrigin == cardOrigin
        override fun hashCode() = dialedOrigin.hashCode() * 31 + cardOrigin.hashCode()
        override fun toString() = "OriginMismatch(dialedOrigin=$dialedOrigin, cardOrigin=$cardOrigin)"
    }

    /** No account and the instance takes none (`links`, `closed`, `full`): its own explanation. */
    data class NotTakingAccounts(val offer: OfferView, val mode: String, val full: Boolean) : RecipientStep()

    /** The instance needs the Trust Gate before anything (an enrol link, design §4.4). */
    class TrustGate internal constructor(val gate: FirstPin.NeedsTrustGate, internal val token: RecipientToken) : RecipientStep()

    /**
     * Under this device's existing pin the link's server moved or changed `kind` (§2.4: "A move met while a link is
     * being opened under an existing pin is handled as a move first, and the link is opened again afterwards").
     * Nothing was pinned or sent; handle [change] through the instance trust, then open the link again.
     */
    class PinChanged internal constructor(val change: FirstPin.PinChanged) : RecipientStep()

    /** A contact for `from` exists with a different key: nothing replaced without a matched code (design §6.8 step 6). */
    class KeyChanged internal constructor(val offer: OfferView, val existingLabel: String, internal val token: RecipientToken) : RecipientStep()

    /**
     * Every check passed and the instance is pinned: show "Connect with *name*?" (or the sign-up form for
     * register/enrol/setup). Only [LinkFlows.confirm] sends anything for a connect link; the other kinds register
     * through [io.silencelen.andvari.core.client.onboard.Onboarding.register] with this step. [replacesKey]: the
     * person acknowledged a key change, and only a matched code will replace the pinned key.
     */
    class Confirm internal constructor(val offer: OfferView, val needsAccount: Boolean, val replacesKey: Boolean, internal val token: RecipientToken) : RecipientStep()

    /** The answer is posted and the creator is pinned with `compared = false`; wait for the reveal. */
    class Answered internal constructor(val contactUserId: String, internal val linkId: String) : RecipientStep()

    /** The reveal matched the commitment: the code can be compared by typing (design §6.11). */
    class CodeReady internal constructor(val contactUserId: String, internal val linkId: String) : RecipientStep()
}

/** The engine's private handle on a recipient flow in progress; opaque to callers. */
class RecipientToken internal constructor(internal val id: String)

/** A link this device created and holds in its own device state (design §6.7 step 2). */
data class CreatedLink(
    val linkId: String,
    val kind: String,
    /** The full `https://andvaripass.com/l#v2.<O>.<S>.<F>` URL, for the QR, share sheet or Copy. */
    val url: String,
    /** Count down from this, never from the device clock against an expiry (spec 03 §15.2). Null when the server's answer is unknown. */
    val ttlMs: Long?,
    val shares: List<LinkShare>,
)

/** A vault attached to a connect link; released only after the codes matched or by a per-vault release (design §6.10). */
data class LinkShare(val vaultId: String, val role: String)

/** The creator's flow, per answered link (design §6.8, creator side). */
sealed class CreatorStep {
    /**
     * The answer was ignored here: no record (expired or revoked, T-R3, `unknown_link`), or a check
     * failed ([reason], a §2.4 "Processing an answer" verdict, or `answer_changed` when a second, different answer
     * was served for a link already answered). The link's record is dropped; nothing was pinned. The answer is
     * acknowledged only when THIS device created the link: an answer to a link of another device of the account
     * (`unknown_link` with no record or tombstone here) is left on the server for the device that made it.
     */
    data class Ignored(val linkId: String, val reason: String) : CreatorStep()

    /**
     * A contact for the answerer exists with a different key: the key-change prompt. Nothing was pinned; the code
     * is ready ([LinkFlows.code]) and only a matched comparison replaces the key (design §6.8 step 6).
     */
    class KeyChanged internal constructor(val linkId: String, val answererUserId: String, val existingLabel: String) : CreatorStep()

    /** Pinned with `compared = false`, reveal posted, secret deleted, acknowledged. Shares wait for the codes. */
    class Processed internal constructor(val linkId: String, val contactUserId: String, val label: String, val pendingShares: List<LinkShare>) : CreatorStep()

    /** Verified and recorded, but the reveal or the acknowledgement had no answer ([reason]): the next run finishes it. */
    data class Deferred(val linkId: String, val reason: String) : CreatorStep()
}

/** What a link creation came to. */
sealed class CreateOutcome {
    data class Created(val link: CreatedLink) : CreateOutcome()

    /**
     * `bad_expiry`, `not_operator`, `quota_exceeded` (open links), `rate_limited`, … from the server, or the engine's
     * own before anything was sent: `no_session`, `bad_kind`, `bad_lifetime`, `shares_on_register`, `no_pin`,
     * `too_many_contacts`, `bad_name`.
     */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : CreateOutcome()

    /** No answer: the record stays and is dropped at expiry if the link never existed. */
    data class Unknown(val link: CreatedLink) : CreateOutcome()
}

/** The typed comparison (design §6.11). Only the person's own correct entry sets `compared = true`. */
sealed class CompareResult {
    data object Matched : CompareResult()

    /** "The codes don't match. Don't share anything with this person until you've talked." */
    data object Mismatch : CompareResult()

    /** A second, different nonce was seen, or no code exists: the link is failed and no code is shown. */
    data object Failed : CompareResult()

    /**
     * The digits matched and this device recorded it, but the account state could not be written yet (no answer, or a
     * refusal): the contact is not compared in the account and no share went out. Typing again retries the write.
     */
    data object Unsaved : CompareResult()
}

/** Where a comparison with one contact stands on this device (the app's `CompareScreen`). */
sealed class CompareState {
    abstract val contactUserId: String

    /** The answerer has not received a reveal that opens the commitment: no code exists yet. */
    class Waiting internal constructor(override val contactUserId: String, val label: String) : CompareState()

    /**
     * Both nonces are fixed; [code] is THIS device's own six digits (§2.3: the creator's code on the creator, the answerer's
     * on the answerer), computed once, for the person to read out. It is not what they type: [LinkFlows.typeCode] accepts
     * only the other side's code, which no object here carries. [replacesKey]: a match replaces the pinned key.
     */
    class Ready internal constructor(override val contactUserId: String, val label: String, val code: String, val replacesKey: Boolean) : CompareState()

    /** A second, different nonce was seen, or the reveal did not open the commitment. No code is shown. */
    class Failed internal constructor(override val contactUserId: String, val label: String) : CompareState()

    /** This device's own entry matched. */
    class Matched internal constructor(override val contactUserId: String, val label: String) : CompareState()
}

/** Link flows for one signed-in account (or, for a recipient without an account, for one origin). */
interface LinkFlows {
    /** Create a connect or register link; the record is written durably before `POST /links`. */
    suspend fun create(kind: String, expiresInMs: Long, shares: List<LinkShare>): CreateOutcome

    /** The links this device made and still holds a record of (dropped at expiry, revocation or processing). */
    fun createdLinks(): List<CreatedLink>

    /** Revoke an open link: its record is dropped first, so a later answer is ignored whatever the server says (T-R3). True when the server confirmed. */
    suspend fun revoke(linkId: String): Boolean

    /** Open [text] (a URL or fragment) from [entry] and run every recipient check (design §6.8). */
    suspend fun open(text: String, entry: GateEntry): RecipientStep

    /**
     * Continue after the Trust Gate (confirmed), the key-change acknowledgement, or an [RecipientStep.OtherInstance]
     * once the app has switched to the link's instance.
     */
    suspend fun proceed(step: RecipientStep): RecipientStep

    /**
     * The person closed [step] (or declined its Trust Gate): the flow ends, and a pin this flow made is dropped unless
     * the flow was [settle]d.
     */
    fun dismiss(step: RecipientStep)

    /**
     * The account now stands on the pin [step]'s flow made (a sign-up or sign-in after the link, design §6.7): from now
     * on the flow keeps that pin, whatever ends it, and holds only what a later [confirm] needs.
     *
     * For a connect link the link's secret is wiped and only its answer key is kept; the answer is the step to hold and
     * pass to [confirm] once the account's vault is open (or to [dismiss], which then ends the flow and keeps the pin).
     * For any other link there is nothing left to confirm: the flow ends, the pin stays, and the answer is null. Call it
     * only after a registration through the link (`LinkRegistrations.resolve`) is done or not wanted. Null as well for a
     * flow that has already ended.
     */
    fun settle(step: RecipientStep.Confirm): RecipientStep.Confirm?

    /** The person confirmed [step]: post the answer (connect), pin `compared = false`. */
    suspend fun confirm(step: RecipientStep.Confirm): RecipientStep

    /** Fetch and check the creator's reveal against the offer's commitment (`bad_reveal`). */
    suspend fun awaitReveal(step: RecipientStep.Answered): RecipientStep

    /** [awaitReveal] for the latest link answered by this device with [contactUserId] (after a restart). */
    suspend fun refreshReveal(contactUserId: String): CompareState?

    /** Process `GET /links/answers` (design §6.8 creator side). */
    suspend fun processAnswers(): List<CreatorStep>

    /**
     * THIS device's own six digits for the contact [contactUserId]'s link (the code its screen shows and its person reads
     * out), once both nonces are fixed; null otherwise. Never the code to type.
     */
    fun code(contactUserId: String): String?

    /** Where the comparison with [contactUserId] stands on this device, or null when this device holds none. */
    fun compareState(contactUserId: String): CompareState?

    /**
     * The person typed [digits], the code the OTHER side's screen shows (§6.11). They are checked in constant time against
     * that code, which this device derives and never displays; this device's own code is refused like any other wrong
     * entry ([CompareResult.Mismatch], nothing changed). Only a match sets `compared`.
     */
    suspend fun typeCode(contactUserId: String, digits: String): CompareResult

    /** Vaults attached to answered links of this device, still waiting for the codes, by contact userId. */
    fun pendingShares(): Map<String, List<LinkShare>>

    /** Release a share to an uncompared contact behind the warning (design §6.7 step 8). */
    suspend fun releaseShare(contactUserId: String, share: LinkShare): Boolean

    /** Drop records past their expiry (design §6.7 step 9). */
    fun expireRecords(nowMs: Long)
}
