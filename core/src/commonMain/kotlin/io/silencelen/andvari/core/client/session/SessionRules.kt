package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.client.EnrollPayload
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.autofill.Idna
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.ClientPolicy
import kotlin.math.abs
import kotlin.math.max
import kotlinx.io.IOException
import kotlinx.serialization.Serializable

// The session rules every native client shares. Each one is a pure function, so the
// security-critical decisions are pinned by unit tests rather than buried in a UI layer.

/**
 * The persisted "an invite-driven server switch is UNCOMMITTED" marker (design 2026-07-15
 * §4.3, breaker B2-6/B2-9). Its mere presence is the source of truth for "pending": while it
 * exists the switch to [origin] is NOT trusted as the new default — enrollment success clears it
 * (the commit, §4.1 rule 3) and a Discard reverts to [previousOrigin] and clears it.
 *
 * Written BEFORE `register` so a crash between register and the commit is reconciled at the next
 * launch ("Finish setting up at <origin> / Discard"). [previousOrigin] is the Android-specific
 * addition to the design's `{origin, email?, ts}` — this app keeps a single global session slot,
 * so a revert needs to know where to return. [email] is captured at register time (the address to
 * sign in as if register already succeeded before the crash).
 */
@Serializable
data class PendingServer(
    val origin: String,
    val previousOrigin: String,
    val email: String? = null,
    val ts: Long,
)

/**
 * The B1-1 auto-lock clamp (design 2026-07-15 §2.3): `autoLockSeconds` arrives from an
 * UNAUTHENTICATED endpoint on an UNTRUSTED server, and it governs THIS device's exposure
 * window — CLIENT-FLOOR-ONLY. Effective value = clamp into `[floor, AUTO_LOCK_MAX_SECONDS]`;
 * a server-supplied 0/negative (which used to mean "never lock") clamps to the CEILING, so a
 * hostile server cannot disable auto-lock. Single source ceiling: core [ClientPolicyClamps].
 */
fun clampAutoLockSeconds(seconds: Int): Int =
    if (seconds <= 0) ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS
    else minOf(seconds, ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS)

/** §F.1 fingerprint-provenance postures (design 2026-07-12) — which human anchor, if any, the
 *  enrollment seals org escrow under. Never "the server said so". */
enum class EnrollPosture { Waived, RequiredAffirm, RequiredTyped }

/**
 * Decide the enrollment posture from the two inputs the client actually has — a local port of the
 * web's unit-pinned pure function (web/src/enroll/enrollposture.ts `enrollPosture`; keep in
 * lockstep — core is frozen this wave, so the port lives app-side):
 *  - [linkRfp]: an rfp on an enroll link ⇒ the invitee scanned an IN-PERSON QR off the admin's
 *    screen ⇒ one-tap eyeball affirmation. **Only an rfp with PROVENANCE may be passed here** —
 *    see [affirmableRfp], which is what the Android form feeds in. Android's invite field is
 *    keyboard/clipboard-only today, so in practice callers still pass null; the parameter keeps
 *    the port faithful and lights up the moment a provenance-bearing channel lands.
 *  - [memberHasSheet]: no rfp — default WAIVED (frictionless, no admin backstop); a member who was
 *    handed a printed recovery SHEET declares it ⇒ the typed-sheet ceremony (the pre-rfp channel).
 * Either "required" branch anchors on a human value; a missing rfp NEVER auto-trusts the server key.
 */
fun enrollPosture(linkRfp: String?, memberHasSheet: Boolean): EnrollPosture = when {
    !linkRfp.isNullOrEmpty() -> EnrollPosture.RequiredAffirm
    memberHasSheet -> EnrollPosture.RequiredTyped
    else -> EnrollPosture.Waived
}

/**
 * The client-effective `signupMode` (design 2026-07-15 §2.1 — the normative enum contract).
 * `"closed"` and `"landing"` render as declared; EVERYTHING else — field absent (old server,
 * `policy == null` / probe failed → the §2.3 conservative default), an unknown value (newer
 * server), and the reserved `"open"` (no open-register UI exists in this client; the server
 * boot-coerces the env anyway, §7.3) — degrades to `"invite-only"`: plain invite-gated enroll,
 * never an open door, no stranger nudge.
 *
 * Trust class (§2.3): TRUSTED as a server-authoritative UI HINT only — it decorates the
 * declaring server's own front door; register success stays server-enforced (invite-ROW gate),
 * so a lying value cannot open anything, and it never gates a client-side protection.
 */
fun effectiveSignupMode(declared: String?): String = when (declared) {
    "closed" -> "closed"
    "landing" -> "landing"
    else -> "invite-only"
}

// ---- endpoint-switch UX + anti-phishing trust gate (design 2026-07-15 §4, Wave-3) ----
//
// Every decision that can be a pure function IS one (the OriginNamespaceTest precedent), so the
// security-critical rules — no-token-replay across a switch, the anti-phishing render, the
// pending commit/revert selection — are pinned by unit tests instead of buried in the ViewModel /
// Compose layers.

/**
 * §4.1 rule 1 (B1-5 — HARD MUST): does a change of server FROM [oldOrigin] TO [newOrigin] drop the
 * active session? True iff it is a REAL origin change (canonical compare) — a real switch drops the
 * old origin's access+refresh tokens and in-memory unlock state, so the rebuilt client for the new
 * origin can never replay the old bearer token. A no-op canonical "switch" (a trailing-slash /
 * case re-entry of your own server) keeps the session — re-probing your own origin must not sign
 * you out. Canonicalization reuses [OriginNamespace] so it agrees with the namespace key.
 */
fun switchDropsSession(oldOrigin: String, newOrigin: String): Boolean =
    OriginCanon.canonicalOrigin(oldOrigin) != OriginCanon.canonicalOrigin(newOrigin)

/** Security review 2026-10, A14 (F8): a stored session's tokens go only to the session's own origin
 *  (the canonical compare [switchDropsSession] uses). Unlock refuses a session saved for another
 *  origin than the one the app dials; a locked sign-out revokes at the session's own origin. */
fun sessionBelongsTo(sessionOrigin: String, liveOrigin: String): Boolean = !switchDropsSession(sessionOrigin, liveOrigin)

/**
 * A14 (F8): may an enroll that built its client for [opOrigin] while [opPending] was the pending
 * invite switch commit its session now? Only while the app still dials that origin, the pending
 * switch is the same one (its email may have been filled in; its origin and restore point may not
 * change), and the probe generation has not moved (a round trip away and back counts as a change).
 */
fun enrollStillBound(
    opOrigin: String,
    opPending: PendingServer?,
    liveOrigin: String,
    livePending: PendingServer?,
    fenceCurrent: Boolean,
): Boolean = fenceCurrent && liveOrigin == opOrigin &&
    opPending?.origin == livePending?.origin && opPending?.previousOrigin == livePending?.previousOrigin

/** A14 (F8): the unlock refusal for a session saved under another origin. */
fun sessionElsewhere(sessionOrigin: String): String =
    "This saved sign-in belongs to $sessionOrigin, not this server. Sign out, then sign in here."

/** A14 review N4: the sign-in whose origin moved while login was in flight. */
fun signInOriginMoved(origin: String): String =
    "The server changed while you were signing in at $origin, so that sign-in was not saved and was ended there. Sign in again."

/** A14 (F8): the enroll whose origin moved while register was in flight. */
fun enrollOriginMoved(origin: String): String =
    "The server changed while your account was being created at $origin, so it was not saved here. Sign in at $origin to finish setting it up."

/**
 * Audit F27 — did the pre-commit probe prove the target is DIALABLE at all?
 *
 * A manual switch is destructive by design (§4.1 rule 1: the old origin's tokens and unlock state
 * must not survive it), and it used to commit before anything was ever sent to the new address.
 * A self-hoster typing `http://192.168.1.9:8080` therefore lost their session and their unlock to
 * an address Android's own network security config forbids the app from ever dialing — and the
 * error blamed their connection and their VPN, so they debugged a network that was never touched.
 * The same address works on desktop, which has no such policy, so the two clients disagree about
 * what a valid server is.
 *
 * The bar is deliberately LOW: a server that ANSWERED — even with a refusal, a 404, or a
 * weakened-KDF policy — is a real endpoint and the switch proceeds, because those are verdicts
 * the user needs to see AT that origin. Only a transport failure means we never reached it, and
 * only then is refusing to commit the kinder outcome: they keep the session they already have.
 */
fun switchProbeReachable(t: Throwable?): Boolean = t !is IOException

/**
 * The tokens a client rebuilt for [newOrigin] may inherit from a session last held against
 * [oldOrigin] (§4.1 rule 1 / B1-5). A real origin switch inherits NOTHING — null — so no
 * `Authorization` header can ever cross a baseUrl change; a no-op switch keeps the tokens. This is
 * the pure model of what [AndvariViewModel.setBaseUrl] enforces on the Context-bound store/api
 * (which a JVM unit test can't touch): the regression test asserts THIS returns null across a switch.
 */
fun inheritedTokensAcrossSwitch(oldOrigin: String, newOrigin: String, oldTokens: Tokens?): Tokens? =
    if (switchDropsSession(oldOrigin, newOrigin)) null else oldTokens

/**
 * What the "Invite code or link" field currently holds (design 2026-07-15 §4.4 Android). The field
 * accepts either a raw invite token (today's behavior) or a full enroll LINK
 * (`<origin>/enroll#a1.…`); the core [EnrollLink.parse] twin (multiplatform, total — null on
 * anything that isn't a link) decides which. Reused, never reimplemented.
 */
sealed interface InviteFieldParse {
    /** The invite token to submit (the verbatim text, or a link's `t`). */
    val token: String

    /** Not a link — the trimmed text is the token; carries no origin/rfp. */
    data class Token(override val token: String) : InviteFieldParse

    /**
     * A parsed enroll link. [gate] is true iff [origin] differs (canonically) from the current
     * baseUrl — a repoint that MUST pass the Trust Gate before enrollment (§4.4). [rfp] drives the
     * `required-affirm` posture ([enrollPosture]); [email] is the invite-bound address.
     */
    data class Link(
        override val token: String,
        val origin: String,
        val email: String,
        val rfp: String?,
        val gate: Boolean,
        // A5: the admin's identity (in-person QR only); with rfp, what the in-person code authenticates.
        val ifp: String? = null,
        val iu: String? = null,
    ) : InviteFieldParse
}

/** Parse the invite field against the current [currentBaseUrl] (design §4.4). Total — a
 *  non-link falls through to [InviteFieldParse.Token]. */
fun parseInviteField(raw: String, currentBaseUrl: String): InviteFieldParse {
    val p = EnrollLink.parse(raw) ?: return InviteFieldParse.Token(raw.trim())
    val gate = OriginCanon.canonicalOrigin(p.o) != OriginCanon.canonicalOrigin(currentBaseUrl)
    return InviteFieldParse.Link(token = p.t, origin = p.o, email = p.e, rfp = p.rfp, gate = gate, ifp = p.ifp, iu = p.iu)
}

/**
 * HOW the enroll link reached this device — the only thing that can make a link's `rfp` mean
 * anything (audit 2026-09-13 H66; owner decision: align Android with desktop).
 *
 * §F.1's required-affirm posture is not "a fingerprint arrived", it is "a human scanned this
 * fingerprint off their admin's screen, in person". Web can claim that because its rfp arrives by
 * NAVIGATION to its own origin — the QR the admin displayed. Desktop refuses the claim outright
 * ("a desktop PASTE has no provenance", `Ui.kt` Enroll / `DesktopState.kt` enrollPosture) and has
 * no affirm leg at all. Android shipped the third answer: it parsed a link out of a text field
 * that only the keyboard and the clipboard write to, and then told the member the code "came from
 * the invite you scanned in person" — a provenance the app cannot know, on a link that may well
 * have been forwarded through chat. Two natives, opposite postures, identical input.
 *
 * So provenance is now explicit and the fail-safe direction is the default: [Typed] yields no
 * affirmable rfp, and enrollment falls back to the typed-sheet / waived ceremony exactly as
 * desktop does. The fail-closed chain is unchanged either way — a missing rfp never auto-trusts a
 * server key, and `Account.enroll` re-checks the served key against whatever was affirmed — but
 * the household now gets ONE ceremony per QR instead of one per native.
 */
enum class InviteProvenance {
    /** The member typed or pasted the field's contents. The only channel Android has today: the
     *  manifest carries MAIN/LAUNCHER only (no `/enroll` app link) and there is no in-app scanner. */
    Typed,

    /** An `/enroll` app link the OS verified against the server's origin and handed us directly —
     *  the invitee opened the admin's link on this device, not a forward of its text. */
    AppLink,

    /** An in-app camera scan of the QR on the admin's screen — the anchor §F.1 actually describes. */
    ScannedQr,
}

/**
 * The rfp the form may ACT on: a link's rfp, but only when [provenance] says something other than
 * a human retyping text into a box (H66). Pure and total so the rule is unit-pinned rather than
 * living inside a composable — the shape [enrollPosture] expects for its `linkRfp` argument.
 */
fun affirmableRfp(rfp: String?, provenance: InviteProvenance): String? =
    if (provenance == InviteProvenance.Typed) null else rfp?.takeIf { it.isNotEmpty() }

/**
 * The required-affirm CHECKER (security review 2026-10, root cause A, A5 — the A2 carry-forward): the link's
 * rfp is a MACHINE value and must equal the server's advertised recovery fingerprint at FULL 64-hex length.
 * Before A5 this leg ran the rfp through the 32-hex HUMAN helper ([Escrow.shortFormMatches]), so a 32-hex
 * prefix passed; a prefix is accepted only from a human. Web twin: enrollposture.ts `escrowGate`.
 */
fun affirmRfpMatches(rfp: String?, serverFullFp: String): Boolean =
    !rfp.isNullOrEmpty() && io.silencelen.andvari.core.crypto.Fingerprint.matchesFull(rfp, serverFullFp)

/**
 * The in-person VERDICT (security review 2026-10, root cause A, A5c — API review LOW item 8), re-asserted at the
 * state layer from the raw inputs rather than taken from the composable as a boolean: the link's in-person code
 * ([EnrollLink.checkCodeMatches]) is an unkeyed hash of the link, so a link plus a correct code — both of which
 * the server that composed the link can supply — is never in-person evidence on its own. In person means all
 * three: a channel that carries provenance ([InviteProvenance], H66 — a typed/pasted link has none), the human's
 * first-person affirmation that they are reading the admin's screen right now, and the code they typed from it.
 * Pure and total (a missing link is simply not in person), the shape [enrollReady] and `enrollOp` both consume.
 */
fun inPersonVerdict(
    crypto: CryptoProvider,
    payload: EnrollPayload?,
    typedCode: String,
    affirmed: Boolean,
    provenance: InviteProvenance,
): Boolean =
    provenance != InviteProvenance.Typed && affirmed && payload != null && EnrollLink.checkCodeMatches(crypto, payload, typedCode)

/**
 * The anti-phishing Trust Gate's render decision (design 2026-07-15 §4.3) — pure so the IDN /
 * plain-http defenses are test-pinned. The gate shows the RAW origin, never a display name.
 */
data class TrustGateRender(
    /** The origin to show — scheme+host+port, monospaced + dominant; a non-ASCII host is rendered
     *  in its punycode (`xn--…`) form so a homograph can't hide. */
    val displayOrigin: String,
    /** The host is an IDN (non-ASCII, or already `xn--` punycode) — show the "international
     *  characters" caution beside the punycode form. */
    val punycodeCaution: Boolean,
    /** An `http://` origin — show the plain-http caution. */
    val httpCaution: Boolean,
    /**
     * An `http://` origin this platform will REFUSE to connect to: any host outside the exempt set
     * the caller passes. Distinct from [httpCaution] because the two http cases are not on a
     * spectrum: an exempt host is permitted, and everything else never connects at all.
     */
    val cleartextBlocked: Boolean,
)

private val ORIGIN_SPLIT = Regex("^(https?)://(\\[[^\\]]*]|[^/:?#]*)(:[0-9]+)?", RegexOption.IGNORE_CASE)

/** §4.3 render rules: punycode a non-ASCII host + caution; caution an already-`xn--` host (the
 *  homograph vector); caution `http://`. */
fun trustGateRender(origin: String, cleartextExemptHosts: Set<String>): TrustGateRender {
    val trimmed = origin.trim()
    val httpCaution = trimmed.startsWith("http://", ignoreCase = true)
    val m = ORIGIN_SPLIT.find(trimmed)
    val scheme = m?.groupValues?.get(1)?.lowercase() ?: ""
    // `.substringAfterLast('@')` drops any userinfo (defense-in-depth: the manual path already
    // canonicalizes, but a raw origin must resolve to the REAL host, never a `real.host@evil` prefix).
    val host = (m?.groupValues?.get(2) ?: "").substringAfterLast('@')
    val port = m?.groupValues?.get(3) ?: ""
    val nonAscii = host.any { it.code > 0x7F }
    // Fail CLOSED: if Idna can't punycode a non-ASCII host, escape its code points rather than
    // rendering the raw homograph the punycode display exists to defeat (§4.3). The caution below still fires.
    val punyHost = if (nonAscii) Idna.toAscii(host) else host
    val safeHost = punyHost ?: host.map { if (it.code > 0x7F) "\\u" + it.code.toString(16).padStart(4, '0') else it.toString() }.joinToString("")
    // A raw non-ASCII host OR a host already encoded as punycode (`xn--`) is an IDN — the
    // homograph vector spec/05 R8 warns about, whether the attacker sent us Unicode or the encoding.
    val idn = nonAscii || safeHost.split('.').any { it.startsWith("xn--", ignoreCase = true) }
    val display = if (m != null && nonAscii) "$scheme://$safeHost$port" else trimmed
    // Matched against the RESOLVED host (post-userinfo-strip, post-punycode), never the raw string:
    // `http://127.0.0.1@evil.example` must be judged on `evil.example`, which is exactly the host
    // the platform will judge it on too.
    val cleartextBlocked = httpCaution && safeHost.lowercase() !in cleartextExemptHosts
    return TrustGateRender(
        displayOrigin = display,
        punycodeCaution = idn,
        httpCaution = httpCaution,
        cleartextBlocked = cleartextBlocked,
    )
}

// §4.3 trust-gate copy — pinned as constants so the phishing wording can't drift. Baseline is
// shown always; the enrollment variant (B2-8) ADDS the new-account/password-reuse warning.
const val TRUST_GATE_TITLE = "Connect to a different server?"
const val TRUST_GATE_BASELINE =
    "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it."
const val TRUST_GATE_ENROLLMENT_EXTRA =
    "Your invite was issued by this server. Enrolling creates a NEW account there — it does not move any existing vault. Choose a master password you don't use anywhere else."

/** §4.3 body paragraphs: baseline always, plus the enrollment warning when [enrollment]. Pure so
 *  the copy selection is test-pinned. */
fun trustGateBody(enrollment: Boolean): List<String> =
    if (enrollment) listOf(TRUST_GATE_BASELINE, TRUST_GATE_ENROLLMENT_EXTRA) else listOf(TRUST_GATE_BASELINE)

/**
 * §4.1 rule 3: the persisted default origin after a pending invite switch resolves. On enroll
 * SUCCESS the pending [PendingServer.origin] commits; on cancel / failure / reconcile-discard the
 * [PendingServer.previousOrigin] is restored. Pure so a refactor can never silently commit a
 * half-finished switch.
 */
fun resolvedDefaultOrigin(pending: PendingServer, enrollSucceeded: Boolean): String =
    if (enrollSucceeded) pending.origin else pending.previousOrigin

/**
 * Security review 2026-10 (A12, q06 — the twin of desktop row 39): the origin a pending invite
 * switch restores on cancel/failure. Captured ONCE: while a switch is already pending,
 * `store.baseUrl` points at that switch's UNVERIFIED target, so a second re-point must inherit the
 * existing marker's restore point rather than record the first unverified origin as "previous".
 * Pure so the rule is test-pinned.
 */
fun pendingSwitchRestorePoint(existing: PendingServer?, currentDefault: String): String =
    existing?.previousOrigin ?: currentDefault

/** A12 review LOW-1: the refusal copy for recover verify / reset while an invite switch is pending
 *  (desktop's `RECOVERY_LOCKED_OUT` twin). */
const val RECOVERY_LOCKED_OUT =
    "Finish or cancel joining the other server first — account recovery here is paused until you do."

/**
 * A12 review LOW-1: the recovery authKey and the reset commit are password-equivalent material, so
 * — like sign-in's sink guard — neither may be sent while an uncommitted invite switch points
 * store.baseUrl at an origin the user has not verified. Returns the refusal copy, or null to go on.
 */
fun recoveryLockout(pending: PendingServer?): String? = if (pending != null) RECOVERY_LOCKED_OUT else null

/**
 * A12 review LOW-2: a policy fetched for an irreversible step is used only if [applied] — i.e. the
 * probe fence still says it belongs to the origin the app dials now. Otherwise the step aborts (an
 * IOException, so the surface maps it to "can't reach the server") — desktop enroll's twin.
 */
fun requireCurrentPolicy(p: ClientPolicy, applied: Boolean): ClientPolicy =
    if (applied) p else throw IOException("server changed during recovery")

/** A12 (row 80): whole-call cap on an unauthenticated policy probe (OkHttp's 10 s defaults bound
 *  each read, not the call). */
const val POLICY_PROBE_TIMEOUT_MS = 15_000L

/** What the Trust Gate's Connect commits to (design §4.3/§4.4). */
sealed interface TrustGateAction {
    /** Manual ServerField switch — Connect commits immediately (the gate IS the gesture, §4.1 rule 3). */
    data class ManualSwitch(val origin: String) : TrustGateAction

    /** Invite-link repoint — Connect enters the PENDING state (commit on enroll success). [email]
     *  seeds the crash marker. */
    data class InviteRepoint(val origin: String, val email: String) : TrustGateAction

    /** Launch-time reconcile "Finish" (§4.3 B2-9) — the raw-origin gate re-shown before repointing. */
    data class ReconcileFinish(val origin: String) : TrustGateAction
}

/**
 * §4.3 B2-6 — what [AndvariViewModel.trustGateCancel] restores. Cancelling a launch-reconcile Finish
 * gate must return to the reconcile CHOICE (the marker): store.baseUrl already points at the
 * UNCOMMITTED foreign origin, so landing on a bare Welcome would re-expose sign-in there (the
 * credential leak — a user who "cancelled" then signs in leaks an offline-crackable authKey). A
 * manual/invite gate never moved store.baseUrl (commit is on Connect), so its Cancel restores nothing.
 * Pure so the "only ReconcileFinish restores the reconcile prompt" rule is test-pinned.
 */
fun reconcileRestoreOnCancel(action: TrustGateAction?, pending: PendingServer?): PendingServer? =
    if (action is TrustGateAction.ReconcileFinish) pending else null

/** The quick-unlock rules of spec 01 §8.1 that do not depend on a platform's key store. */
object QuickUnlockRules {
    /** 30-day periodic-full-password window (spec 01 §8.1). Calendar-shaped, evaluated on the
     *  monotonic high-water wall clock (A2), not raw wall time. */
    const val WINDOW_MS = 30L * 24 * 60 * 60 * 1000

    // (A2's CLOCK_SKEW_MS allowance is gone — security review 2026-10, A12 row 74: a wall clock
    // earlier than the stamp at all is a rollback and fails closed; see [isFreshPure].)

    /** A2: tolerance on the derived boot reference (wall − elapsedRealtime) drift for deciding
     *  "same boot, clock steady" so the extra monotonic-delta guard applies. */
    const val BOOT_SKEW_MS = 60L * 1000

    /** A4: the last-seen client policy must be fresher than this for quick unlock to be eligible;
     *  an admin who flips `offlineCacheAllowed=false` must reach the device within a bounded window
     *  even if only the autofill overlay ever runs. */
    const val POLICY_STALE_MS = 7L * 24 * 60 * 60 * 1000

    /** The org permits durable key material, and the last-seen policy is recent enough to say so (A4). */
    fun policyPermits(cacheAllowed: Boolean, policyFetchedAtMs: Long, nowMs: Long): Boolean =
        cacheAllowed && policyFetchedAtMs > 0L && nowMs - policyFetchedAtMs < POLICY_STALE_MS

    /** Pure inputs for [isFreshPure], extracted so the clock-safety logic is unit-testable
     *  without Android/Keystore. */
    data class FreshnessInputs(
        val nowMs: Long,
        val elapsedNowMs: Long,
        val stampWallMs: Long,
        val stampElapsedMs: Long,
        val stampBootRefMs: Long,
        val highWaterWallMs: Long,
        /** Last SERVER-attested wall time (monotonic). The only clock the device holder can't set. */
        val serverFloorMs: Long,
        /** A12 (row 74): the boot identity now and at the stamp, from a source the device holder
         *  cannot set (Android: `Settings.Global.BOOT_COUNT`); null = unknown (a stamp written before
         *  A12, or a platform that does not expose one). Boot identity comes from HERE, never from
         *  the settable wall clock. */
        val bootIdNow: String? = null,
        val stampBootId: String? = null,
    )

    /**
     * A1: a zero stamp (never a real full-password unlock, or cleared) is NOT fresh.
     * A2: a future stamp fails closed (stale); the window is measured on the highest clock we
     *     have any reason to trust; and within one boot with a steady clock the monotonic
     *     `elapsedRealtime` delta must ALSO be under 30 days (and never regress).
     *
     * Review 2026-07-10 [2] — the cross-boot hole. `highWaterWallMs` only ratchets from the
     * DEVICE clock as this app observes it, so a dormant phone freezes it; a reboot resets
     * `elapsedRealtime`, voiding the monotonic cross-check. An attacker holding the device could
     * then set the clock to a moment INSIDE the window and quick-unlock forever — exactly what
     * A2 exists to prevent. Elapsed time simply CANNOT be bounded from an attacker-settable
     * clock alone. So:
     *   - SAME boot  → the monotonic clock proves duration; trust it (plus the wall-clock guards).
     *   - CROSS boot → require a server-attested anchor taken AFTER the stamp
     *                  (`serverFloorMs > stampWallMs`) and measure the window against THAT.
     *                  With no such anchor we cannot prove how long the device sat powered off,
     *                  so we fail CLOSED: the master password is required.
     * Practical effect: the first unlock after a reboot uses the master password unless the app
     * has since reached the server (the policy fetch on start advances the floor) — the same
     * before-first-unlock posture Android itself takes, for one honest password entry.
     */
    fun isFreshPure(i: FreshnessInputs): Boolean {
        if (i.stampWallMs <= 0L) return false
        // A12 (row 74): a wall clock earlier than the stamp is a rollback — fail closed, no allowance.
        if (i.nowMs < i.stampWallMs) return false
        // `nowMs` is attacker-settable; the floor is not. Never let a rollback shrink the window.
        val effectiveNow = max(max(i.nowMs, i.highWaterWallMs), i.serverFloorMs)
        if (effectiveNow - i.stampWallMs >= WINDOW_MS) return false

        // Security review 2026-10 (A12, row 74): the monotonic check used to be skipped exactly when
        // the wall clock was the problem — "same boot" was derived from `wall − elapsedRealtime`, so
        // stepping the clock back made a same-boot device look rebooted, and the cross-boot branch
        // then accepted any server anchor taken shortly after the stamp, however long ago that was.
        //
        // (1) A belt that holds in EVERY case: if elapsedRealtime has advanced 30 days past the
        //     stamp's, the stamp is at least 30 days old. Same boot, that is the real duration; after
        //     a reboot it means this boot alone has run 30 days, all of it after the stamp. Either way
        //     stale, whatever the wall clock claims.
        if (i.elapsedNowMs >= i.stampElapsedMs && i.elapsedNowMs - i.stampElapsedMs >= WINDOW_MS) return false
        // (2) Boot identity from the boot COUNT when both sides know it; the clock-derived reference
        //     is only the fallback for stamps written before A12.
        val bootKnown = i.bootIdNow != null && i.stampBootId != null
        val sameBoot = if (bootKnown) {
            i.bootIdNow == i.stampBootId
        } else {
            val currentBootRef = i.nowMs - i.elapsedNowMs
            abs(currentBootRef - i.stampBootRefMs) <= BOOT_SKEW_MS
        }
        if (sameBoot) {
            // Same boot, wall clock not stepped: the monotonic clock is authoritative and cheap.
            if (i.elapsedNowMs < i.stampElapsedMs) return false // monotonic went backwards → distrust
            if (i.elapsedNowMs - i.stampElapsedMs >= WINDOW_MS) return false
            return true
        }
        // Cross-boot: the only trustworthy duration evidence is a server contact AFTER the stamp.
        if (i.serverFloorMs <= i.stampWallMs) return false // no anchor → duration unknowable → password
        return i.serverFloorMs - i.stampWallMs < WINDOW_MS
    }

    /** Password unlocks a biometric could have served before the offer returns (design §7.1).
     *  Three, not one: the point is that the user has PAID the cost repeatedly, not merely
     *  that time has passed. */
    const val QU_REOFFER_AFTER = 3

    /** Hard cap on re-offers. Two, so the lifetime worst case is three cards total — the
     *  original one plus two — and a user who declines all three is never asked again. */
    const val QU_REOFFER_MAX = 2

    /** Inputs to [reofferDecision] — the persisted triple, nothing else. */
    data class ReofferInputs(val dismissed: Boolean, val unlocks: Int, val reoffers: Int)

    /** What to persist, and whether the offer re-opens. */
    data class ReofferOutcome(val unlocks: Int, val reoffers: Int, val reoffer: Boolean)

    /**
     * Whether repeated password unlocks have earned the enrollment offer another showing —
     * pure, so [ReofferInputsTest] pins every boundary without SharedPreferences (the
     * [isFreshPure] idiom).
     *
     * The three properties that matter, none of which is obvious from the call site:
     *  - a VISIBLE offer never counts (nothing to re-open, and counting would let a single
     *    ignored card burn the whole budget);
     *  - the counter RESETS on each re-offer, so the cost must be paid again to earn the next;
     *  - past [QU_REOFFER_MAX] it is inert forever — the no-nag-loop property the original
     *    one-and-done design was protecting, kept rather than traded away.
     */
    fun reofferDecision(i: ReofferInputs): ReofferOutcome {
        if (!i.dismissed) return ReofferOutcome(i.unlocks, i.reoffers, false)
        if (i.reoffers >= QU_REOFFER_MAX) return ReofferOutcome(i.unlocks, i.reoffers, false)
        val n = i.unlocks + 1
        return if (n < QU_REOFFER_AFTER) ReofferOutcome(n, i.reoffers, false)
        else ReofferOutcome(0, i.reoffers + 1, true)
    }
}
