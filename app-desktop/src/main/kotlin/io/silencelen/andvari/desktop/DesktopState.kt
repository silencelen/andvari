package io.silencelen.andvari.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.CopyDeniedException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.ItemChangedException
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.MoveGesture
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.AttachmentPlan
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.DeletedVaultInfo
import io.silencelen.andvari.core.client.HeldVaultInfo
import io.silencelen.andvari.core.client.IncomingTransfer
import io.silencelen.andvari.core.client.LifecycleNotice
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupPreflight
import io.silencelen.andvari.core.client.BackupResult
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.CsvPreflight
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.ExportPlanner
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.PlannedAttachment
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PasswordChangeRequest
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import io.silencelen.andvari.core.model.VaultMemberSummary
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

sealed interface DesktopScreen {
    data object Loading : DesktopScreen
    data object Welcome : DesktopScreen
    data class Unlock(val email: String) : DesktopScreen
    data object Vault : DesktopScreen
    data object Sharing : DesktopScreen
    data object Settings : DesktopScreen
    data object Trash : DesktopScreen
    // Shown-once recovery-phrase gate after a fresh enroll (design 2026-07-12 §F.4/§F.7): the
    // per-member self-service piece is MANDATORY, so a member who never SEES it is silently
    // unrecoverable. This screen reveals it once and makes the user type it back before the vault
    // opens. Un-skippable (no back/skip) — the silent-total-loss guard.
    data object RecoverySetup : DesktopScreen
    // (v2 #15) §F.9 vault-entry capture gate, native (mirrors web's RecoveryCaptureGate): reached
    // from unlock/sign-in when the server reports recoveryConfirmed=false — an interrupted reveal
    // (idle lock / quit / crash mid-RecoverySetup destroyed the shown-once phrase before the user
    // typed it back) or a pre-flag migration account. Commits a FRESH piece (PUT /recovery/self-setup,
    // which does NOT flip the flag), then hands off to the same un-skippable RecoverySetup reveal;
    // only the type-back confirm flips recoveryConfirmed. Without this, the "un-skippable" gate was
    // skippable by the app's own idle lock and the next unlock landed straight in the vault with the
    // member's self-recovery silently dead.
    data object RecoveryCapture : DesktopScreen
    // Native self-service recovery (design 2026-07-12 §F.3, the web Recover.tsx mirror): the
    // "forgot my master password" flow for a member holding their saved recovery phrase —
    // verify (email + phrase → single-use ticket) → choose a new master password → commit.
    // Unauthenticated (pre-session), reached from Unlock/Welcome; both /recovery/self routes are
    // server-refused on the public break-glass origin. Confirm-binding §6 scope ruling: verify's
    // password-hash check already binds the caller to the CURRENT piece — no pieceId here.
    data object Recover : DesktopScreen
}

/**
 * §F.1 enrollment posture — the desktop mirror of web `enrollposture.ts` (deliberately LOCAL, not
 * :core: the decision is surface-specific). Web's rule: an in-person-QR `rfp` ⇒ required-affirm;
 * no rfp ⇒ WAIVED by default (frictionless, no admin backstop), or REQUIRED-TYPED when the member
 * declares they were handed a printed recovery SHEET. A desktop PASTE has no provenance (see the
 * Enroll invite-field note in Ui.kt — a pasted link's rfp is deliberately ignored), so the
 * rfp/required-affirm leg is unreachable here and only the two sheet-driven postures exist. The one
 * rule the model rests on holds regardless: a missing sheet NEVER auto-trusts the server key.
 */
enum class EnrollPosture { Waived, RequiredTyped }

fun enrollPosture(memberHasSheet: Boolean): EnrollPosture =
    if (memberHasSheet) EnrollPosture.RequiredTyped else EnrollPosture.Waived

/**
 * §2.3 (B1-1) auto-lock clamp: `ClientPolicy.autoLockSeconds` is CLIENT-FLOOR-ONLY — it comes
 * from an unauthenticated endpoint on an untrusted server, and it governs THIS device's exposure
 * window. Effective = clamp into [1, AUTO_LOCK_MAX_SECONDS]; a server-supplied 0/negative (which
 * meant "never lock") clamps to the CEILING, so a hostile server cannot disable the auto-lock —
 * only shorten it. Applied inside [DesktopState.applyPolicy] (the one write path into policy
 * state) and re-applied on the persisted offline fallback read (belt for pre-clamp prefs).
 */
internal fun clampAutoLockSeconds(v: Int): Int =
    if (v <= 0 || v > ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS) ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS else v

/**
 * §2.3 (B1-1) clipboard clamp: [1, CLIPBOARD_CLEAR_MAX_SECONDS]. 0 still clears after 1 s (the
 * pre-existing floor, never "keep forever" for secrets); an oversized value can no longer pin a
 * copied secret on the clipboard for hours. Applied inside [DesktopState.applyPolicy], so the
 * Ui.kt copy sites read a structurally-clamped `policy.clipboardClearSeconds`.
 */
internal fun clampClipboardClearSeconds(v: Int): Int =
    v.coerceIn(1, ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS)

/** §4.3 anti-phishing trust-gate variant: BASELINE for a manual ServerField repoint, ENROLLMENT for
 *  an invite-driven repoint (adds the new-account/password-reuse note, B2-8). */
enum class TrustGateVariant { Baseline, Enrollment }

/**
 * §4.3 anti-phishing trust-gate display model — computed as a PURE function of the raw origin the
 * client will actually dial + the [variant]. Kept OUT of the composable so the security-critical
 * render DECISIONS (punycode of a non-ASCII host, the plain-http caution, baseline-vs-enrollment
 * copy) are unit-testable without a Compose harness. The composable renders exactly these fields —
 * it invents no copy, and it NEVER substitutes a display name for the raw origin: `instanceName`
 * arrives only after connecting and invite payloads carry only `o`, so attacker-supplied branding
 * is never rendered as verified (§4.3 / spec/05 R8).
 */
data class TrustGateModel(
    val rawOrigin: String,
    // [rawOrigin] with a non-ASCII host rendered in punycode (xn--…) — the dominant line shows THIS,
    // so deceptive lookalike glyphs are never the thing the user eyeballs as the destination.
    val displayOrigin: String,
    val internationalized: Boolean,
    val plainHttp: Boolean,
    val enrollment: Boolean,
) {
    val lead: String get() = "Connect to a different server?"
    val body: String get() =
        "This server will store your encrypted vault and see your account activity " +
            "(email, sign-ins, item counts). Only continue if you trust it."
    // Enrollment variant ADD (B2-8) — verbatim; the password-reuse warning is load-bearing.
    val enrollmentNote: String? get() = if (enrollment)
        "Your invite was issued by this server. Enrolling creates a NEW account there — it does not " +
            "move any existing vault. Choose a master password you don't use anywhere else." else null
    val internationalCaution: String? get() = if (internationalized)
        "This address uses international characters, shown above in their ASCII (punycode) form. " +
            "Lookalike letters are a common phishing trick — confirm it matches exactly what you were given." else null
    val httpCaution: String? get() = if (plainHttp)
        "This is an unencrypted http:// connection — traffic to this server can be read on the " +
            "network. Only continue on a network you trust." else null
}

/** The reg-name/IP host of a stored-baseUrl-shaped origin (`scheme://host[:port]`), tolerant of a
 *  non-ASCII host (which `java.net.URI` may refuse to parse) and IPv6 brackets. Empty when there is
 *  no authority. */
private fun trustGateHost(origin: String): String {
    // `substringAfterLast('@')` drops any userinfo (defense-in-depth: manual input is already
    // canonicalized by canonicalServerOrigin, but a raw origin reaching here must still resolve to the
    // REAL host, never `real.host@evil.example`'s reassuring userinfo prefix).
    val authority = origin.trim().substringAfter("://", "").substringBefore('/').substringAfterLast('@')
    if (authority.isEmpty()) return ""
    return if (authority.startsWith("[")) authority.substring(1).substringBefore(']') // IPv6 literal
    else authority.substringBefore(':')
}

/** §4.3 IDN defense: build the [TrustGateModel] for [origin]. A non-ASCII host is punycoded for the
 *  dominant display + flagged; an `http://` origin is flagged for the plain-transport caution. */
internal fun trustGateModel(origin: String, variant: TrustGateVariant): TrustGateModel {
    val trimmed = origin.trim()
    val plainHttp = trimmed.startsWith("http://", ignoreCase = true)
    val host = trustGateHost(trimmed)
    val nonAscii = host.isNotEmpty() && host.any { it.code > 0x7f }
    val display = if (nonAscii) {
        // §4.3 IDN defense — fail CLOSED: punycode the host; if IDN.toASCII can't (throws → null),
        // escape its non-ASCII code points rather than rendering the raw homograph the punycode display
        // exists to defeat. Either way the `internationalized` caution still fires below.
        val puny = runCatching { java.net.IDN.toASCII(host) }.getOrNull()
        val safeHost = puny ?: host.map { if (it.code > 0x7f) "\\u%04x".format(it.code) else it.toString() }.joinToString("")
        if (trimmed.contains("://"))
            trimmed.substringBefore("://") + "://" + trimmed.substringAfter("://").replaceFirst(host, safeHost)
        else safeHost
    } else trimmed
    return TrustGateModel(
        rawOrigin = trimmed,
        displayOrigin = display,
        internationalized = nonAscii,
        plainHttp = plainHttp,
        enrollment = variant == TrustGateVariant.Enrollment,
    )
}

/** §4.3 (B2-9) launch-time reconcile decision for a persisted pending-switch marker. The switch is
 *  "already committed" (a crash between the `store.baseUrl` commit and the marker clear) iff the
 *  marker's origin canonicalizes to the committed default; otherwise it never committed and the
 *  user must reconcile (Finish/Discard). Pure + canonical-origin-keyed so a trailing-slash/case
 *  difference can't force a spurious Reconcile. */
enum class PendingReconcileDecision { AlreadyCommitted, Reconcile }

internal fun pendingReconcileDecision(markerOrigin: String, committedBaseUrl: String): PendingReconcileDecision =
    if (originKey(markerOrigin) == originKey(committedBaseUrl)) PendingReconcileDecision.AlreadyCommitted
    else PendingReconcileDecision.Reconcile

/** F74: the Settings server-TOTP status fetch as an honest tri-state — Failed must STOP
 *  the spinner and offer Retry, instead of spinning forever beside its own error (the old
 *  shape used totpStatus==null for both "checking" and "check failed"). */
enum class TotpLoad { Pending, Ready, Failed }

/**
 * Plain state holder for the desktop app (no AndroidX ViewModel). Drives the shared
 * :core client (Account + AndvariApi[java engine] + SyncEngine) and exposes Compose
 * state. Mirrors the Android AndvariViewModel.
 */
class DesktopState(
    private val scope: CoroutineScope,
    // Injectable for tests only (the §4.1/§4.3 switch state-machine — token drop, pending
    // commit/revert, marker reconcile — is driven against a temp-dir store); production uses the
    // default ~/.andvari-desktop store.
    private val store: DesktopSessionStore = DesktopSessionStore(),
) {

    init {
        // Wave-4 v2: bump an old LAN|tailnet default server URL to the public default before any state
        // reads it (mirrors Android). MUST run before adoptNamespacesOnce.
        store.migrateDefaultOnce()
        // §4.2 adoption one-shot — MUST stay AFTER migrateDefaultOnce so the legacy unscoped layout
        // adopts under the key of the URL the app will actually dial (now the PUBLIC default).
        // migrateDefaultOnce also carries an already-adopted legacy namespace to the public key as §6.2
        // defense-in-depth (see DesktopSessionStore.carryLegacyNamespaceToPublic).
        store.adoptNamespacesOnce()
        // Inactivity auto-lock watcher (spec 01 §8, 1 s resolution) + the spec 03 §6 poll
        // (every 5 min while unlocked). Both live on the window's scope: they die with it.
        scope.launch {
            while (true) {
                delay(1_000)
                maybeIdleLock()
            }
        }
        scope.launch {
            while (true) {
                delay(POLL_INTERVAL_MS)
                backgroundSync()
            }
        }
    }

    var screen by mutableStateOf<DesktopScreen>(DesktopScreen.Loading)
        private set
    var items by mutableStateOf<List<VaultItem>>(emptyList())
        private set
    // Held envelopes newer than this build can decrypt (fail-closed) — the vault list
    // shows them as a one-line "N items need an app update" banner instead of nothing.
    var needsUpdateCount by mutableStateOf(0)
        private set
    var policy by mutableStateOf<ClientPolicy?>(null)
        private set
    // §3 honesty flag: the last ENROLL-FEEDING policy probe (start / updateServer / Retry)
    // failed — the enroll screen says so + offers Retry instead of claiming "no recovery
    // key configured". ONLY those fetches touch it (B4): the unlocked 5-min background
    // refresh keeps last-known policy for the offline gates (auto-lock) and never writes it.
    var policyFetchFailed by mutableStateOf(false)
        private set
    // §5.3 (B1-4): the one-time per-(device, origin) durable-cache consent prompt is up. Raised
    // on vault landing (toVault) when the current origin's consent was never answered and the org
    // doesn't forbid the cache; lowered by the answer, by dismiss (re-asks at a later landing —
    // consent stays unanswered and nothing persists meanwhile), and with the session teardown.
    var cacheConsentPrompt by mutableStateOf(false)
        private set
    // §6 (F26): why the vault locked — one quiet line on the Unlock screen. Set FRESH per
    // lock event (manual / idle), cleared on successful unlock + sign-in and by signOut
    // (user-initiated — owes no explanation). Desktop has NO 401-driven sign-out path (a
    // 401 during unlock wipes the store but stays on the Unlock screen), so the web
    // "session ended" reason is deliberately unwired here.
    var lockReason by mutableStateOf<String?>(null)
        private set
    var busy by mutableStateOf(false)
        private set
    // Cut O (v2 #17): the SYNC flag, split off the user-op [busy]. One global flag coupled
    // unrelated operations — every 5-minute poll and every window-refocus sync repainted the
    // editor's Save button into an anonymous spinner and greyed Cancel/Trash/Settings for a
    // network round-trip the user never initiated (unbounded when the server black-holed).
    // Background AND manual pulls (timer poll, focus sync, the toolbar Refresh) run under THIS
    // flag only; op() and every user-op UI gate ignore it (the engine's syncMutex already
    // serializes a pull against a save's reconcile, so the overlap is safe by construction).
    // The UI surfaces it on a dedicated toolbar affordance — never by repainting user buttons.
    var syncBusy by mutableStateOf(false)
        private set
    // Cut O (v2 #17): the in-flight attachment download's ref id. The Detail row's "Save"
    // action swaps to a small spinner keyed on THIS id — before the split, a multi-second
    // download over a household link looked frozen (every busy-gated control just greyed,
    // with nothing tying the wait to the file the user clicked).
    var downloadingAttachmentId by mutableStateOf<String?>(null)
        private set
    var error by mutableStateOf<String?>(null)
    /** F71 review: the editor's INLINE save error. Kept apart from the global [error] —
     *  backgroundSync writes that one every 5 min / on focus, and piping it into the editor
     *  painted "sync failed" above Save mid-composition as if the user's edit had failed. */
    var saveError by mutableStateOf<String?>(null)
    /** F71 review: the NEW-item draft id, stable across save retries within one editor
     *  session (attachments committed by a failed attempt are bound to it — a fresh mint
     *  per retry trips the push's attachment_mismatch forever). One editor at a time on
     *  desktop, so one field; cleared on success and on cancel. */
    private var draftItemId: String? = null
        private set
    var notice by mutableStateOf<String?>(null)
        private set
    // The origin the app is CURRENTLY operating against — the server every request dials and every
    // §4.2 namespace read keys off. Normally EQUAL to the persisted default (store.baseUrl); it
    // diverges ONLY during an invite-driven pending switch (dials the pending origin while the
    // persisted default stays on the prior server until enrollment SUCCEEDS — §4.1 rule 3) and
    // transiently through a committed manual switch. Kept a plain observable (read off the UI
    // thread by newApi/originKey is fine — mutableStateOf reads are snapshot-safe).
    var baseUrl by mutableStateOf(store.baseUrl)
        private set
    // §4.1 rule 3 / §4.4 Desktop: an invite-driven repoint held PENDING (uncommitted) — the app
    // dials [PendingServer.origin] once [pendingConnected] flips, but store.baseUrl stays on the
    // prior server until enrollment succeeds. Non-null ⇒ the Welcome UI locks out sign-in (B2-6)
    // and the enroll pane renders the Trust Gate / ceremony against the pending origin.
    var pendingServer by mutableStateOf<PendingServer?>(null)
        private set
    // Two-stage pending: false ⇒ the Trust Gate (enrollment variant) is showing and NOTHING has
    // switched yet (the gate IS the gesture); true ⇒ Connect was pressed, [baseUrl] now dials the
    // pending origin, and the escrow-fingerprint ceremony renders against ITS policy.
    var pendingConnected by mutableStateOf(false)
        private set
    // The persisted default captured when the pending switch was armed — the origin "Cancel and
    // return to <…>" reverts to (store.baseUrl, which a pending switch never moves).
    var pendingReturnOrigin by mutableStateOf<String?>(null)
        private set
    // §4.3 (B2-9): a launch-time reconcile is owed for this crash-window marker (an uncommitted
    // invite switch found at start). Drives the Finish/Discard prompt; null once resolved.
    var pendingReconcile by mutableStateOf<PendingServer?>(null)
        private set
    // §4.3: a MANUAL ServerField repoint awaiting its baseline Trust Gate confirmation. Non-null ⇒
    // the gate dialog is up for this target; Connect commits (the gate is the gesture), Cancel drops it.
    var manualSwitchTarget by mutableStateOf<String?>(null)
        private set
    var updateAvailable by mutableStateOf<String?>(null)
        private set
    // H2 (§M-D5): the QUIET update-channel state — unverified listing or a stale `signedAt`.
    // Rendered as one muted line in Settings, never a banner/nag (a sig-stripping server must not
    // be able to train the household on scary noise). Mutually exclusive with [updateAvailable].
    var updateChannelNotice by mutableStateOf<String?>(null)
        private set
    // UI-audit #26: the Auto/Light/Dark override Main.kt's AndvariDesktopTheme consumes.
    var themeMode by mutableStateOf(ThemeMode.fromStore(store.themeMode))
        private set
    // design 2026-07-13 platform-fit §2 (menu bar): the Vault menu's "Import passwords…" routes
    // through this — the real import flow is a Vault-screen-local `remember` flag the menu can't
    // reach, so the menu sets this and the Vault screen consumes it once ([consumeImportRequested]).
    // The menu item only ENABLES on the Vault screen, so it can only be set while that screen is
    // mounted to observe it; cleared on lock/sign-out as a belt-and-suspenders reset.
    var importRequested by mutableStateOf(false)
        private set
    // design 2026-07-13 platform-fit §2 (menu bar): Help ▸ About andvari visibility. The menu sets
    // it; the About dialog (Ui.kt) renders + dismisses. Pure display — no secret/wire/spec surface.
    var aboutRequested by mutableStateOf(false)
        private set
    // Set when the server 426s this build (minVersion pin) — the UI shows a blocking
    // "update required" screen. Advisory: the gate is a nudge for honest clients.
    var upgradeRequired by mutableStateOf<String?>(null)
        private set
    var signInTotpRequired by mutableStateOf(false)
        private set
    // F58: the sign-in SessionResponse flagged this account "must change password" — an admin
    // recovery left a TEMPORARY password live. Desktop has no change-password screen (deferred),
    // so the UI shows a prominent, non-dismissable root banner directing to the web app.
    // Deliberately survives lock(): the temp password is still what unlocks, and accountKeys()
    // (the unlock path) doesn't carry the flag — so within a run the nag can only clear via
    // sign-out or a fresh sign-in that returns false (i.e. after the change actually happened).
    var mustChangePassword by mutableStateOf(false)
        private set
    // F57: this account's escrow is sealed to a superseded org recovery key (re-ceremony) — the
    // vault screen offers a re-seal. escrowFingerprint is the CURRENT org fingerprint (re-seal
    // target + the value the user verifies against the new printed sheet).
    var escrowStale by mutableStateOf(false)
        private set
    var escrowFingerprint by mutableStateOf("")
        private set
    // Shown-once recovery-phrase reveal (design §F.4/§F.7): the base64url display form
    // (MemberRecovery.displayForm) of a fresh enrollee's self-service recovery secret, held ONLY
    // for the RecoverySetup screen's reveal+confirm gate and nulled the instant the confirm passes.
    // Never persisted (not in DesktopStore/files), never logged. The RAW secret bytes used for the
    // constant-time confirm live in [pendingRecoverySecret] and are zeroed on confirm.
    var recoveryPhrase by mutableStateOf<String?>(null)
        private set
    // §F.4 posture: enroll sealed NO org escrow (waived) → the phrase is the ONLY recovery path
    // (no admin backstop) and the reveal copy is stark about it. Client-derived per §F.1 (see
    // [enrollPosture]) on the enroll path; the capture gate pins it false (posture there is
    // server-unknown — accountKeys deliberately carries no escrow marker).
    var recoverySetupWaived by mutableStateOf(false)
        private set
    // (v2 #15) RecoveryCapture screen state: null = the self-setup commit is in flight ("Preparing
    // your recovery phrase…"); non-null = it failed and the gate offers Retry. The gate NEVER
    // proceeds to the vault on failure (web RecoveryCaptureGate parity — a failed commit keeps the
    // gate closed, never leaves a live secret dangling).
    var recoveryCaptureError by mutableStateOf<String?>(null)
        private set
    // Piece binding (design 2026-07-13 §3): the STATIC replaced-phrase conflict notice — set when a
    // bound confirm 409s `recovery_piece_stale` (another device rotated the piece mid-reveal),
    // rendered on the capture + reveal screens so the user knows to DISCARD the phrase they saved
    // and trust only the fresh one. Static copy only, never interpolated (§F.7); cleared on vault
    // landing and with the session. The enroll path's post-landing 409 uses the global [error] bar
    // instead (this gate-scoped slice has no vault surface).
    var recoveryReplacedNotice by mutableStateOf<String?>(null)
        private set
    // ---- native self-recovery (DesktopScreen.Recover — web Recover.tsx mirror) ----
    // TRUE once phase-1 verify accepted (the reset step renders). The verify RESPONSE (ticket +
    // wrapped-UVK/identity material — all server-issued ciphertext/public values) and the parsed
    // raw phrase bytes live in the private fields below under §F.7 discipline: never persisted,
    // never logged, zeroed at every exit (cancel, commit success, session teardown). The secret
    // survives a FAILED commit on purpose (web parity — a network blip retries without retyping).
    var recoverVerified by mutableStateOf(false)
        private set
    // Static curated copy ONLY (the web verifyErrorMessage/resetErrorMessage twins) — never an
    // exception's own message, never anything interpolated near the phrase (§F.7).
    var recoverError by mutableStateOf<String?>(null)
    // Prefill for the email field when the flow is entered from the Unlock screen.
    var recoverPrefillEmail by mutableStateOf("")
        private set
    private var recoverVerify: RecoveryVerifyResponse? = null
    private var recoverSecret: ByteArray? = null
    // (v2 #15) pre-lock protection: TRUE while the vault screen has an item editor mounted —
    // mirrored in by the UI (the editor's draft is remember-scoped Compose state this holder
    // can't see). While set, maybeIdleLock defers by ONE bounded grace window instead of
    // silently unmounting the editor and destroying the typed draft + picked attachments.
    var editorOpen by mutableStateOf(false)
        private set
    // (v2 #15): the idle window elapsed but the editor grace is holding the lock off — the UI
    // shows a "the vault will lock soon" warning above the editor. Any interaction (touch())
    // resets the idle clock and the next 1 s tick clears this.
    var idleLockImminent by mutableStateOf(false)
        private set
    // (v2 #15): the login authKey (base64url, password-equivalent — treat like web's meta.authKey)
    // held ONLY while the RecoveryCapture gate is unresolved: PUT /recovery/self-setup requires a
    // fresh master-password reauth and the gate's Retry must not re-prompt. Derived from the
    // just-typed password at unlock/sign-in; cleared once the gate RESOLVES — the bound type-back
    // confirm succeeds or fails through to the vault (a 409 conflict instead RE-RUNS the setup
    // with this same proof — piece binding 2026-07-13) — and on lock/sign-out. Never persisted,
    // never logged.
    private var pendingCaptureAuthKey: String? = null
    // Item history (feature): decrypted archived versions of the currently-viewed item, loaded on
    // demand (null = not loaded / loading). Restore a chosen version with saveItem.
    var itemVersions by mutableStateOf<List<DecryptedItemVersion>?>(null)
        private set
    // Item undelete (feature): the Trash screen's deleted items (null = not loaded / loading).
    var deletedItems by mutableStateOf<List<DeletedItemView>?>(null)
        private set
    // F19 move/copy: the running gesture's attachment progress (null unless attachments copy)
    // and an INLINE error kept separate from the global `error` bar so the Detail control can
    // show it beside a Retry button (web MoveCopyControl parity).
    var moveProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var moveError by mutableStateOf<String?>(null)
        private set
    // F71: the in-flight save's per-upload attachment progress (null unless a save with
    // new attachments is running) — the editor shows it while it stays open under `busy`.
    var saveProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var totpStatus by mutableStateOf<TotpStatus?>(null)
        private set
    // F74: tri-state for the status fetch above — totpStatus==null alone can't distinguish
    // "still checking" from "check failed", which left a live spinner beside a stale error.
    var totpLoad by mutableStateOf(TotpLoad.Pending)
        private set
    var totpSetupInfo by mutableStateOf<TotpSetupResponse?>(null)
        private set
    var totpError by mutableStateOf<String?>(null)
        private set
    // CSV import (spec 06 + universal importer): a preview/plan kept across a retry so an
    // interrupted import replays the SAME itemIds idempotently instead of duplicating.
    var importPlan by mutableStateOf<CsvImport.ImportPlan?>(null)
        private set
    var importFormat by mutableStateOf<CsvImport.ImportFormat?>(null)
        private set
    // A10 LastPass mangle heuristic: several parsed values look HTML-entity-encoded
    // (&amp; and friends) — the preview shows a re-export hint. Never auto-decoded.
    var importMangled by mutableStateOf(false)

    /** A9: physical file line → 1-based data-row ordinal, so a row error reads
     *  "row N (file line M)" even when a multi-line quoted note shifts physical lines. */
    var importRowOrdinals by mutableStateOf<Map<Int, Int>>(emptyMap())
        private set
    var importReport by mutableStateOf<CsvImport.ImportReport?>(null)
        private set
    var importError by mutableStateOf<String?>(null)
        private set
    var importProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var importBusy by mutableStateOf(false)
        private set
    var importDone by mutableStateOf(false)
        private set
    // S2: the import's DESTINATION vault. Always assigned WITH importPlan (importFromFile /
    // importSetVault) and read with it in importConfirm — the F75 dedupe fingerprints the
    // plan against this vault, so plan and commit must never name different ones. Survives
    // importDone so the summary can name the vault; cleared on dismiss.
    var importVaultId by mutableStateOf<String?>(null)
        private set
    // S2: the parsed file, retained ONLY while the preview is open — importSetVault re-plans
    // from it against another vault's projections. Plaintext (like importPlan.items, which
    // outlives it anyway); dropped in importDismiss.
    private var importParsed: CsvImport.Parsed? = null
    // Export & backup (spec 07) — preflight dialogs + post-backup summary.
    var backupPreflight by mutableStateOf<BackupPreflight?>(null)
        private set
    var backupResult by mutableStateOf<BackupResult?>(null)
        private set
    var csvPreflight by mutableStateOf<CsvPreflight?>(null)
        private set
    var lastExportAt by mutableStateOf(store.lastExportAt)
        private set
    // Vault lifecycle (spec 03 §11 / N3 design 2026-07-11) — notices banner, verified
    // incoming ownership offers, the Sharing screen's members/deleted/held lists, and
    // rescue-copy progress. Field names mirror Android's UiState 1:1.
    var lifecycleNotices by mutableStateOf<List<LifecycleNotice>>(emptyList())
        private set
    var incomingTransfers by mutableStateOf<List<IncomingTransfer>>(emptyList())
        private set
    /** vaultId → current owner displayName (for the consent card), fetched lazily. */
    var transferOwnerNames by mutableStateOf<Map<String, String>>(emptyMap())
        private set
    /** Owned shared vaultId → members (drives the transfer target picker). */
    var sharingMembers by mutableStateOf<Map<String, List<VaultMemberSummary>>>(emptyMap())
        private set
    var deletedVaults by mutableStateOf<List<DeletedVaultInfo>>(emptyList())
        private set
    var heldVaults by mutableStateOf<List<HeldVaultInfo>>(emptyList())
        private set
    /** DN-1: the vault whose per-vault Settings view the Sharing screen shows (null = the
     *  vault list). Nulled by openSharing (A5: a fresh visit lands on the list), by
     *  lock/sign-out, and ACTIVELY in refreshLifecycle when the id stops resolving (A2 —
     *  a later restore must not resurrect the layer). */
    var sharingSettingsVaultId by mutableStateOf<String?>(null)
        private set
    /** F20: count of shared vaults granted to this account whose grant can't be OPENED on
     *  THIS device (sealed to a key we don't hold, or a newer grant format). Such a grant
     *  is swallowed by hydrate/pull, so the vault is silently absent from [items]/
     *  vaultInfos(); this drives a persistent, non-dismissable warning. Recomputed every
     *  refreshLifecycle; 0 clears it (a later sync opened/revoked the grant). */
    var undecryptableSharedVaultCount by mutableStateOf(0)
        private set
    /** Bulk "copy items to Personal first" progress + its post-copy note. A4: [copyVaultId]
     *  scopes both to the SOURCE vault — DISPLAY state (openSharing/closeSharing/
     *  open-/closeVaultSettings clear it; the in-panel display gates on it, so another
     *  vault's panel never claims the copy). The in-flight OP is guarded by
     *  [copyOpVaultId], never by these. */
    var copyProgress by mutableStateOf<Pair<Int, Int>?>(null)
        private set
    var copiedNote by mutableStateOf<String?>(null)
        private set
    var copyVaultId by mutableStateOf<String?>(null)
        private set
    /** A-tick: bumped at the END of every refreshLifecycle — the UI's memo key for
     *  vault/grant-derived lists (`remember(items, lifecycleTick)`); vaultInfos() shifts on
     *  vault-set-only changes (a new empty grant, a remote delete of an empty vault) that
     *  [items] never reflects. Monotonic — deliberately NOT reset on lock/sign-out. */
    var lifecycleTick by mutableStateOf(0)
        private set
    /** A-copyGate: the rescue copy's NON-display OP guard — the vault whose bulk copy is IN
     *  FLIGHT. Set at copy start, cleared ONLY in the copy's finally; navigation NEVER
     *  touches it (unlike the display [copyVaultId]). While non-null: maybeIdleLock defers,
     *  deleteVault refuses, and the Delete button disables — `busy` alone is not a gate
     *  (any other op finishing mid-copy clears it). */
    var copyOpVaultId by mutableStateOf<String?>(null)
        private set

    private var api: AndvariApi? = null
    private var account: Account? = null
    // F82: raw-row reads (vault rows / envelopes — the spec 07 export enumerates from
    // them) go through the engine's read surface; no carried cache reference here.
    private var engine: SyncEngine? = null
    // F19 gestures memoized per (item|target|mode): a RETRY of a transiently-failed move/copy
    // reuses the SAME gesture (fresh ids were minted ONCE) so the server's mutation dedup
    // converges instead of duplicating. Kept ONLY across a failed attempt of the same
    // UNCHANGED item — a rev change remints (a stale gesture would rebuild attachments from a
    // stale snapshot); Cancel/mode-change discards. Mirrors Android's moveGestures.
    private val moveGestures = mutableMapOf<String, MoveGesture>()

    /**
     * Cut O (v2 #17): every desktop HTTP client is built here, with a CONNECT timeout. The java.net.http
     * engine has NO default timeouts (unlike Android's OkHttp, whose 10 s defaults bound the same
     * calls), so an unreachable-but-not-refusing server (firewall DROP, dead route) hung every call —
     * and through the old shared `busy` flag, the whole UI — indefinitely. Connect-only is deliberate:
     * a request/socket cap on the SHARED client would sever legitimate large attachment transfers
     * (ktor 3 buffers response bodies inside the call, so a 25 MiB download counts against a request
     * cap; a slow-uplink upload likewise). The sync path bounds its whole cycle separately
     * ([SYNC_TIMEOUT_MS] — sync never carries attachment bytes), and the small recovery calls
     * (self-setup / confirm — on the shared core client since the A.3 swap) keep their per-call cap
     * via withTimeoutOrNull([RECOVERY_CALL_TIMEOUT_MS]).
     */
    private fun newHttpClient() = HttpClient(Java) {
        install(HttpTimeout) { connectTimeoutMillis = CONNECT_TIMEOUT_MS }
    }

    private fun newApi(tokens: Tokens? = null) =
        AndvariApi(baseUrl, newHttpClient(), tokens, { store.updateTokens(it) }, platform = desktopPlatform())

    fun start() {
        scope.launch {
            // §4.3 (B2-9): reconcile a crash-window pending marker BEFORE trusting the stored
            // session or probing — an uncommitted invite switch must offer Finish/Discard, never
            // silently boot the unverified origin (store.baseUrl, the prior default, is intact).
            reconcilePendingMarker()
            // §4.2: pin the PROBED origin's key before any await — a policy verdict may only
            // ever touch the declaring origin's own namespace, even if baseUrl moves mid-probe.
            val probedKey = originKey(baseUrl)
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                policyFetchFailed = false
                applyPolicy(p, probedKey) // UI state + persisted offline fallbacks (auto-lock included)
                // Policy may forbid the durable cache; purge any existing file the moment
                // we learn it (spec 02 §8), even before unlock — mirrors the Android client.
                // §4.2 (B2-3): scoped to the DECLARING origin's namespace — a forbidding server
                // can no longer destroy another (home) server's offline data on a mere probe.
                if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(probedKey, it.userId) }
            }.onFailure { policyFetchFailed = true } // §3: never render the no-key lie off a failed probe
            probe.close()
            // UI-audit #24: checkForUpdate is a BLOCKING java.net.http call — it ran directly on
            // this Compose-scope coroutine and froze the whole window for up to ~8 s at startup.
            // Now Dispatchers.IO AND a sibling coroutine: the auth screen must never wait on the
            // nag either (it used to gate `screen =` below even when it didn't freeze). The H2
            // verify flow (signature + seq floor + signedAt) rides the same call; its results
            // land in state whenever they arrive.
            scope.launch {
                runCatching { withContext(Dispatchers.IO) { checkForUpdate(baseUrl, store.lastAcceptedSeq) } }
                    .onSuccess { applyUpdateCheck(it) }
            }
            val session = store.load()
            screen = if (session != null && session.accessToken.isNotEmpty()) DesktopScreen.Unlock(session.email) else DesktopScreen.Welcome
            baseUrl = store.baseUrl
        }
    }

    /**
     * H2 (design 2026-07-13-signed-updates §M): fold one verified-or-refused update check into UI
     * state. Only a VERIFIED manifest may nag ([updateAvailable]) or advance the persisted
     * anti-rollback floor (§D#5); everything unverifiable lands in the QUIET [updateChannelNotice]
     * (§M-D5 — distinct from "up to date", never loud). Disabled (test-key build, §M-D3) shows
     * nothing at all: a hard-off path must not read as a channel problem.
     */
    private fun applyUpdateCheck(result: UpdateCheck) {
        when (result) {
            is UpdateCheck.Available -> { updateAvailable = result.version; updateChannelNotice = null; ratchetAcceptedSeq(result.seq) }
            is UpdateCheck.UpToDate -> { updateAvailable = null; updateChannelNotice = null; ratchetAcceptedSeq(result.seq) }
            is UpdateCheck.Stale -> { updateAvailable = null; updateChannelNotice = UPDATE_STALE_NOTICE; ratchetAcceptedSeq(result.seq) }
            is UpdateCheck.Unverified -> { updateAvailable = null; updateChannelNotice = UPDATE_UNVERIFIED_NOTICE }
            is UpdateCheck.Disabled -> { updateAvailable = null; updateChannelNotice = null }
        }
    }

    /** The floor only ever ratchets UP, and only off a verified manifest (§D#5). */
    private fun ratchetAcceptedSeq(seq: Long) {
        if (seq > store.lastAcceptedSeq) store.lastAcceptedSeq = seq
    }

    /** UI-audit #26: persist + publish the Auto/Light/Dark override. (Named choose…, not set… —
     *  the property's own JVM setter already claims the setThemeMode signature.) */
    fun chooseThemeMode(mode: ThemeMode) {
        themeMode = mode
        store.themeMode = mode.storeValue
    }

    /** design §2 menu bar: the "signed in" gate for Sync now / Lock. Derived from the OBSERVABLE
     *  [screen] (account itself is a plain field, not Compose state, so a menu `enabled =` reading
     *  it would never recompose) — true on exactly the post-unlock screens where a live session is
     *  bound. Lock/Sync are both idempotent no-ops when nothing is bound, so this is a
     *  discoverability gate, not a safety one. */
    val menuSignedIn: Boolean
        get() = screen.let {
            it is DesktopScreen.Vault || it is DesktopScreen.Sharing || it is DesktopScreen.Settings ||
                it is DesktopScreen.Trash || it is DesktopScreen.RecoverySetup || it is DesktopScreen.RecoveryCapture
        }

    /** design §2 menu bar: Import passwords… enables only on the Vault screen (open-question
     *  default: disabled outside Vault, no hidden navigation). Observable via [screen]. */
    val onVaultScreen: Boolean get() = screen is DesktopScreen.Vault

    /** design §2 menu bar: the Vault menu's Import passwords… — the menu can't reach the Vault
     *  screen's local import flag, so set the hoisted request the Vault screen consumes. */
    fun requestImport() { importRequested = true }

    /** design §2: the Vault screen consumes the menu's import request exactly once (LaunchedEffect
     *  keyed on [importRequested]) into the same flow the toolbar icon opens. */
    fun consumeImportRequested() { importRequested = false }

    fun requestAbout() { aboutRequested = true }
    fun dismissAbout() { aboutRequested = false }

    /** design §2 About dialog: the wire platform tag (windows/linux) for display — the same value
     *  [newApi] sends as the X-Andvari-Client platform. */
    val platformLabel: String get() = desktopPlatform()

    /**
     * design 2026-07-13 platform-fit §2, Help ▸ Check for updates: re-run the SAME signed update
     * check [start] runs — on Dispatchers.IO (the UI-audit #24 frozen-startup finding: the blocking
     * java.net.http fetch must never touch the Compose thread) — and fold the verified-or-quiet
     * result into state via [applyUpdateCheck] (surfaces `updateAvailable` as the normal notice /
     * the quiet Settings channel line). Nag-only, no installer is fetched (§M-D1).
     */
    fun checkForUpdatesNow() {
        scope.launch {
            runCatching { withContext(Dispatchers.IO) { checkForUpdate(baseUrl, store.lastAcceptedSeq) } }
                .onSuccess { applyUpdateCheck(it) }
        }
    }

    /**
     * COMMIT a switch to [url] and re-probe — the manual-repoint executor (the baseline Trust Gate's
     * Connect, §4.4 Desktop: "manual ServerField gets the gate too, commit-on-confirm"; the gate IS
     * the gesture, §4.1 rule 3). Drops tokens + in-memory session/unlock and rebuilds BEFORE dialing
     * the new origin (§4.1 rule 1, B1-5) — no bearer token may cross a baseUrl change.
     */
    fun updateServer(url: String) {
        val clean = url.trim().removeSuffix("/")
        // §4.1 rule 1: token isolation FIRST, before any request to the new origin.
        clearSessionForSwitch()
        store.baseUrl = clean // manual repoint commits the persisted default at the gate
        baseUrl = clean
        // B5: a deliberate URL change must re-probe — the OLD server's policy (recovery
        // fingerprint, pins) must not drive the enroll gate until restart. Null the stale
        // policy first (renders the neutral probe-in-flight state, never the no-key text).
        policy = null
        policyFetchFailed = false
        // §4.2: the key of the origin THIS probe interrogates (baseUrl was just committed above).
        probePolicy(originKey(baseUrl))
    }

    /**
     * The enroll-feeding policy probe (start / updateServer / trust-gate Connect / Retry all run
     * it) — fetch the CURRENT origin's [ClientPolicy], apply it under the §2.3 clamps, and purge a
     * forbidding origin's OWN namespace (§4.2, B2-3: never another origin's). [probedKey] is pinned
     * by the caller BEFORE any await so a fast follow-up switch can't re-aim the purge.
     */
    private fun probePolicy(probedKey: String) {
        scope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        policyFetchFailed = false
                        applyPolicy(p, probedKey)
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(probedKey, it.userId) }
                    }
                    .onFailure { policyFetchFailed = true }
            } finally {
                probe.close()
            }
        }
    }

    /**
     * §4.1 rule 1 (B1-5) token isolation — tear down any live session and DROP the persisted
     * access+refresh tokens before the app dials a new origin, so no bearer token ever crosses a
     * baseUrl change. Preserves every origin's at-rest namespace (B2-7): a switch is NOT a sign-out,
     * so [DesktopSessionStore.clearSession] touches session.json only, never any account-keys/cache
     * namespace (a round trip A→B→A keeps A's offline material). Also scrubs the in-memory
     * session/unlock-derived state so nothing bleeds into the new origin.
     */
    private fun clearSessionForSwitch() {
        engine?.close(); api?.close(); api = null; account = null; engine = null
        store.clearSession() // persisted tokens only — no namespace touched (B2-7)
        clearVaultClipboard()
        pendingRecoverySecret?.fill(0); pendingRecoverySecret = null; recoveryPhrase = null // §F.7
        pendingPieceId = null; pendingCaptureAuthKey = null
        signInTotpRequired = false; mustChangePassword = false
        escrowStale = false; escrowFingerprint = ""
        clearSecondary()
    }

    // ---- §4.3 / §4.4 endpoint-switch + anti-phishing trust gate ----

    /**
     * §4.4 Desktop: a pasted invite link targeting a DIFFERENT origin arms a PENDING switch — hold
     * [origin] behind the Trust Gate (enrollment variant) without touching tokens, the persisted
     * default, or the live policy (Cancel must return to the prior server unchanged). The gate's
     * Connect ([trustGateConnect]) is the gesture that actually dials [origin].
     */
    fun beginEnrollSwitch(origin: String, email: String?) {
        val clean = origin.trim().removeSuffix("/")
        if (clean.isBlank()) return
        pendingReturnOrigin = store.baseUrl // the persisted default we revert to on Cancel/failure
        pendingServer = PendingServer(clean, email?.trim()?.ifBlank { null }, System.currentTimeMillis())
        pendingConnected = false
        error = null
    }

    /**
     * §4.4 Desktop: the enrollment Trust Gate's Connect. Drops tokens (§4.1 rule 1) BEFORE dialing
     * the pending origin, points the RUNTIME origin ([baseUrl]) at it, and probes ITS policy so the
     * escrow-fingerprint ceremony renders against that server. The persisted default (store.baseUrl)
     * stays on the prior server — it commits only on enroll SUCCESS ([commitPendingSwitch]).
     */
    fun trustGateConnect() {
        val pend = pendingServer ?: return
        if (pendingConnected) return
        clearSessionForSwitch() // §4.1 rule 1: token isolation before the first request to the new origin
        baseUrl = pend.origin // dial the pending origin — RUNTIME only; store.baseUrl unchanged (uncommitted)
        pendingConnected = true
        policy = null
        policyFetchFailed = false
        probePolicy(originKey(pend.origin))
    }

    /**
     * §4.4 Desktop: "Cancel/failure reverts and re-probes the prior server." Clears the crash marker
     * and pending state and, if the switch had dialed the pending origin, drops tokens, reverts the
     * runtime origin to the persisted default (never moved), and re-probes it. A no-op once the
     * switch has committed (pendingServer already null) — so an enroll failure AFTER register
     * success does NOT wrongly revert a committed account.
     */
    private fun revertPendingSwitch() {
        store.clearPendingServer()
        val hadDialed = pendingConnected && baseUrl != store.baseUrl
        pendingServer = null; pendingConnected = false; pendingReturnOrigin = null
        if (hadDialed) {
            clearSessionForSwitch() // drop anything scoped to the abandoned origin before re-dialing
            baseUrl = store.baseUrl
            policy = null; policyFetchFailed = false
            probePolicy(originKey(baseUrl))
        }
    }

    /** §4.4 Desktop: the user's "Cancel and return to <prior origin>" affordance (Trust Gate Cancel
     *  or the pending-Welcome return button). */
    fun cancelPendingSwitch() {
        if (pendingServer == null) return
        error = null
        revertPendingSwitch()
    }

    /**
     * §4.1 rule 3 / §4.4 Desktop: enrollment SUCCEEDED at the pending origin ⇒ COMMIT it as the
     * persisted default and drop the crash marker + pending state. Ordering is load-bearing (see
     * [reconcilePendingMarker]): store.baseUrl is committed to the origin we enrolled at FIRST, so
     * it and the session about to be saved stay consistent, then the marker clears. Called from the
     * enroll-success path (and shared with its test) — never from Connect, so no switch commits
     * without a successful register.
     */
    internal fun commitPendingSwitch() {
        store.baseUrl = baseUrl
        store.clearPendingServer()
        pendingServer = null; pendingConnected = false; pendingReturnOrigin = null
    }

    /** §4.4 Desktop: a manual ServerField edit arms the BASELINE Trust Gate for [url] (no switch
     *  yet — the gate's Connect commits). Ignores a blank/no-op target. */
    fun beginManualSwitch(url: String) {
        // §4.4 (review 2026-07-16 MEDIUM): a raw ServerField string can carry userinfo/path that spoofs
        // the gate — `https://real.host@evil.example` displays a reassuring host while dialing evil.example
        // (→ authKey phishing on the next sign-in). canonicalServerOrigin REJECTS those and returns the bare
        // origin, so the gate only ever shows + dials a canonical, non-spoofable form.
        val canon = canonicalServerOrigin(url)
        if (canon == null) {
            error = "Enter a server address like https://example.org — no username, path, or query."
            return
        }
        if (canon == baseUrl) return // no-op re-entry of the current origin
        error = null
        manualSwitchTarget = canon
    }

    /** §4.4 Desktop: the manual baseline gate's Connect — commit + re-probe via [updateServer] (which
     *  carries the §4.1 token drop). The gate IS the gesture (§4.1 rule 3). */
    fun manualSwitchConnect() {
        val target = manualSwitchTarget ?: return
        manualSwitchTarget = null
        updateServer(target)
    }

    fun manualSwitchCancel() { manualSwitchTarget = null }

    /** §4.3 (B2-9): at launch, decide whether a persisted pending marker needs reconciliation. An
     *  already-committed straggler is dropped silently; an uncommitted switch raises the Finish/
     *  Discard prompt. store.baseUrl (the prior default) is intact, so nothing has dialed the
     *  unverified origin. */
    internal fun reconcilePendingMarker() {
        val marker = store.loadPendingServer() ?: return
        when (pendingReconcileDecision(marker.origin, store.baseUrl)) {
            PendingReconcileDecision.AlreadyCommitted -> store.clearPendingServer()
            PendingReconcileDecision.Reconcile -> pendingReconcile = marker
        }
    }

    /** §4.3: "Finish setting up at <origin>" — re-show the raw-origin gate (baseline) then repoint.
     *  A committed switch lands on the origin's Welcome (Sign in if register already succeeded
     *  pre-crash, else Enroll), resolving the consumed-single-use-invite strand. */
    fun finishPendingReconcile() {
        val marker = pendingReconcile ?: return
        pendingReconcile = null
        store.clearPendingServer() // the deliberate repoint supersedes the marker
        manualSwitchTarget = marker.origin
    }

    /** §4.3: "Discard" — revert (keep the prior default, never moved) + clear the marker. */
    fun discardPendingReconcile() {
        pendingReconcile = null
        store.clearPendingServer()
    }

    /** §3 Retry: re-run the enroll-feeding policy probe by hand — the enroll screen's
     *  Retry button after a failed fetch. Runs under [busy] (the existing button idiom). */
    fun retryPolicy() {
        if (busy) return
        busy = true
        val probedKey = originKey(baseUrl) // §4.2: see start()/updateServer
        scope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        policyFetchFailed = false
                        applyPolicy(p, probedKey)
                        // Same policy enforcement as start(): a forbidding server purges the cache
                        // (its own origin's namespace only — §4.2).
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(probedKey, it.userId) }
                    }
                    .onFailure { policyFetchFailed = true }
            } finally {
                busy = false
                probe.close()
            }
        }
    }

    /**
     * §5.3 (B1-4): record the one-time per-(device, origin) durable-cache consent answer.
     * Desktops are routinely shared/portable machines, so unlike the phone the offline copy is
     * OPT-IN, default OFF — a fresh install persists nothing at rest until this lands. YES
     * materializes the copy NOW rather than at the next unlock: cache the accountKeys (offline
     * unlock), then rebind the session onto the (now-permitted) durable sqlite cache — empty
     * until the sync below fills it — mirroring exactly what an unlock does. NO just records the
     * decline: nothing was ever persisted pre-answer, so there is nothing to purge. Existing
     * installs never see this — the §4.2 adoption one-shot carried them in as consent=ON
     * (continuity: nobody's offline access silently vanishes).
     */
    fun answerCacheConsent(granted: Boolean) {
        if (busy) return // S2 re-assert: never race an in-flight op with an engine rebind
        cacheConsentPrompt = false
        store.setCacheConsent(originKey(baseUrl), granted)
        if (!granted) return
        val a = api ?: return
        val acct = account ?: return
        op {
            // Offline-unlock material first (persistAccountKeys now passes its consent gate).
            // Best-effort: a blip here self-heals at the next online unlock's persist.
            runCatching { a.accountKeys() }.onSuccess { persistAccountKeys(acct.userId, it) }
            bind(a, acct)
            runCatching { syncNow(engine!!) }.onFailure {
                if (it !is java.io.IOException) throw it
                notice = "Offline — your encrypted offline copy will finish at the next sync."
            }
            refreshItems()
        }
    }

    /** §5.3: close the consent prompt WITHOUT answering — consent stays unanswered (nothing
     *  persists) and the prompt re-asks at a later vault landing. */
    fun dismissCacheConsentPrompt() { cacheConsentPrompt = false }

    fun clearError() { error = null }
    fun clearSaveError() { saveError = null }
    fun clearRecoverError() { recoverError = null }
    /** Editor closed (cancel or success): the next editor session starts a fresh draft.
     *  NOT part of [clearSaveError] — dismissing the inline error must keep the draft id,
     *  or the very next retry re-mints and re-wedges on attachment_mismatch. */
    fun endEditorSession() { saveError = null; draftItemId = null }
    fun clearNotice() { notice = null }

    // #23: sign-in failures map through the shared canon's sign-in ladder (401 → wrong email/
    // password — widened to "…or one-time code" when a code was tried — H1 → the sign-in-context
    // block sentence, `public_login_requires_totp` → the curated break-glass line), never the
    // server's raw message.
    fun signIn(email: String, password: String, totp: String? = null) = op(map = { HouseholdCopy.forSignInError(it, totpTried = totp != null) }) {
        val a = newApi()
        try {
            val pre = a.prelogin(email)
            // Argon2id (64 MiB, twice per sign-in) is CPU-bound — never on the UI thread.
            val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams) }
            val s = try {
                a.login(LoginRequest(email, authKey, Account.deviceInfo(deviceName(), desktopPlatform()), totp = totp))
            } catch (e: ApiException) {
                when (e.code) {
                    // Server-TOTP is enrolled: reveal the code field and let the user retry.
                    "totp_required" -> { signInTotpRequired = true; busy = false; a.close(); return@op }
                    // (The op mapper turns `public_login_requires_totp` and friends into curated copy.)
                    else -> throw e
                }
            }
            val acct = withContext(Dispatchers.Default) { Account.unlock(s.userId, password, s.accountKeys) }
            store.save(DesktopSession(baseUrl, s.userId, email, s.accessToken, s.refreshToken))
            persistAccountKeys(s.userId, s.accountKeys)
            bind(a, acct); syncNow(engine!!)
            escrowStale = s.accountKeys.escrowStale; escrowFingerprint = s.accountKeys.escrowFingerprint
            mustChangePassword = s.mustChangePassword // F58: a recovery temp password forces the banner
            signInTotpRequired = false
            // (v2 #15) §F.9 vault-entry capture gate (web Unlock/SignIn parity): the server says this
            // account's recovery piece was never durably CONFIRMED — an interrupted reveal or a
            // migration account. Route into the capture flow INSTEAD of the vault; the login authKey
            // just derived above is the fresh-reauth proof PUT /recovery/self-setup requires.
            val gate = s.accountKeys.recoveryConfirmed != true
            // F61 (spec 01 §7): a silent KDF re-key rides this ONLINE full-password sign-in, but NEVER
            // under the capture gate — the detached re-key rotates the login verifier, which would
            // strand the gate's stashed reauth proof (self-setup re-verifies it) in a permanent Retry
            // loop; the rare upgrade defers to the next (confirmed) sign-in.
            if (!gate) runKdfUpgrade(s.userId, password, s.accountKeys)
            if (gate) startRecoveryCapture(authKey) else toVault()
        } catch (t: Throwable) {
            // Android-parity leak guard: any PRE-bind failure — incl. the H1 KdfPolicyViolationException
            // (not an ApiException), IdentityMismatch, or a network error — must close the transient
            // OkHttp-backed client. Once bind() ran, `api === a` and it is session-owned; never close it.
            if (api !== a) a.close()
            throw t
        }
    }

    // #23: unlock failures map through the canon's unlock ladder — a crypto throw here IS "Wrong
    // master password." (the sole un-wrapped crypto step), 401 → session expired, IO → unreachable.
    fun unlock(email: String, password: String) = op(map = HouseholdCopy::forUnlockError) {
        val session = store.load() ?: error("no session")
        val a = newApi(session.tokens())
        // Offline unlock (spec 02 §8): cached keys when the network is down; wipe on a
        // definitive auth rejection. (v2 #15): track WHERE the keys came from — the recovery
        // capture gate below keys off the server's recoveryConfirmed flag, and a cached copy is
        // both possibly stale AND useless for the gate (the self-setup PUT needs the network
        // anyway), so an offline unlock deliberately skips the gate rather than stranding
        // offline vault access behind an unreachable server. The flag re-gates next online unlock.
        var freshKeys = true
        // §4.2: this unlock's namespace = the CURRENT origin (the one the session dials).
        val nsKey = originKey(baseUrl)
        val keys = try {
            a.accountKeys().also { persistAccountKeys(session.userId, it) }
        } catch (e: java.io.IOException) {
            freshKeys = false
            store.loadAccountKeys(nsKey, session.userId) ?: throw e
        } catch (e: ApiException) {
            // §4.2: the 401 wipe is scoped to the REJECTING origin's own namespace — a foreign
            // server's rejection must never reach another origin's offline data.
            if (e.status == 401) { purgeOfflineData(nsKey, session.userId); store.clear() }
            throw e
        }
        // KDF off the UI thread (argon2id 64 MiB — the unlock spinner must animate).
        val acct = withContext(Dispatchers.Default) { Account.unlock(session.userId, password, keys) }
        bind(a, acct)
        escrowStale = keys.escrowStale; escrowFingerprint = keys.escrowFingerprint
        runCatching { syncNow(engine!!) }.onFailure {
            if (it is java.io.IOException) notice = "Offline — showing cached data" else throw it
        }
        // (v2 #15) §F.9 vault-entry capture gate — see signIn. Unlock never derived a login
        // authKey (it opens the UVK locally), so derive it here ONLY when the gate actually
        // fires: accountKeys' kdfSalt/kdfParams are the same user-row values prelogin serves,
        // so this authKey verifies against the same server-side login verifier. One extra
        // argon2id pass (off the UI thread), paid only on the rare unconfirmed path.
        val gate = freshKeys && keys.recoveryConfirmed != true
        // F61 (spec 01 §7): the silent KDF re-key is deliberately NOT fired on this returning-session
        // unlock (web parity — Welcome.tsx). Desktop's mustChangePassword is an in-memory flag that
        // resets to false on every app restart, so a re-key on the post-restart unlock path could
        // silently make an admin-issued must-change temp password permanent (server changePassword
        // clears mustChangePassword=0). The re-key rides ONLY the signIn path, where the login response
        // carries the accurate flag; a mid-session org policy raise is picked up at the next full
        // sign-in. (It also must never fire under the capture gate: rotating the login verifier would
        // strand the gate's stashed reauth proof.)
        if (gate) {
            val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams) }
            startRecoveryCapture(authKey)
        } else toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String, typedShortFp: String, hasSheet: Boolean) {
        // State-layer re-assert (mirrors Android; the S2-review race class: a composition-
        // stale submit lambda can fire with live-read fields). Busy first — op() sets busy
        // but never checks it — then the F60 floor (the irreversible leg of this screen).
        if (busy) return
        if (!Strength.meetsMasterPasswordFloor(password)) {
            error = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols."
            return
        }
        enrollOp(invite, email, name, password, typedShortFp, hasSheet)
    }

    private fun enrollOp(invite: String, email: String, name: String, password: String, typedShortFp: String, hasSheet: Boolean) = op(map = ::enrollError) {
        // §F.1 posture, re-derived at the STATE layer from the raw sheet declaration (the same
        // frame-stale-proofing as the strength/fingerprint re-asserts): sheet ⇒ the typed-sheet
        // ceremony seals org escrow; no sheet ⇒ WAIVED (per-member piece only — a backstop is
        // never sealed off a server-trusted fingerprint). The server enforces the INVITE's
        // polarity either way (register-gate refusals land in [enrollError]).
        val posture = enrollPosture(hasSheet)
        // §3 flag audit: this fallback fetch feeds THIS enroll directly (normally dead —
        // the submit gate needs the fingerprint, so policy is already loaded; the waived
        // path still needs the policy's kdfParams, so the fallback serves both postures).
        // Success clears the honesty flag like every enroll-feeding fetch; failure sets it
        // and still throws, so op() surfaces the error as before.
        val pol = policy ?: run {
            // Close the throwaway probe client whether the (now KDF-fenced) policy fetch succeeds or throws.
            val probe = newApi()
            try {
                // B1-1: route through applyPolicy — the ONE policy write path — so this fallback
                // can't seed state with unclamped timers (the raw object is still returned for
                // the enroll's kdfParams/fingerprint reads, which the clamps don't touch).
                probe.clientPolicy().also { applyPolicy(it); policyFetchFailed = false }
            } catch (t: Throwable) {
                policyFetchFailed = true; throw t
            } finally {
                probe.close()
            }
        }
        // Typed-sheet ceremony re-assert at the STATE layer against the policy this enroll
        // actually seals to (review LOW, 4th sighting of the frame-stale class): updateServer
        // can swap the policy mid-screen, and a one-frame-stale submit would otherwise pass
        // the UI gate against the OLD server's fingerprint — spec 04 §2(3)'s attestation
        // must bind to the org being enrolled into (the resealEscrow pattern below).
        // REQUIRED-TYPED only: waived seals nothing, so there is no fingerprint to attest.
        // (#23: an explicit error write, not check() — the curated sentence must reach the user
        // itself, never ride an IllegalStateException's message through a generic mapper.)
        if (posture == EnrollPosture.RequiredTyped && !Escrow.shortFormMatches(typedShortFp, pol.recoveryFingerprint)) {
            busy = false
            error = "The recovery-sheet check no longer matches this server — re-verify the printed sheet's first 16 characters."
            return@op
        }
        val a = newApi()
        try {
            // §F.1/§F.4 escrow decision: required-typed fetches the org key and seals to it under
            // the verified-fingerprint discipline (Account.enroll refuses a pubkey/fingerprint
            // mismatch, so a hostile server can't redirect the escrow past the typed sheet);
            // waived passes null ⇒ NO org escrow blob — the per-member piece is the only path.
            val recoveryPub = if (posture == EnrollPosture.RequiredTyped) Bytes.fromB64(a.recoveryPubkey()) else null
            // Key generation + KDF are CPU-bound (argon2id) — off the UI thread. EnrollResult
            // destructures to (request, account, recoverySecret) — the 3rd is the SHOWN-ONCE piece.
            val (req, acct, recoverySecret) = withContext(Dispatchers.Default) {
                Account.enroll(
                    inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
                    password = password, params = pol.kdfParams,
                    recoveryPublicKey = recoveryPub,
                    recoveryFingerprint = if (recoveryPub != null) pol.recoveryFingerprint else null,
                    deviceName = deviceName(),
                    // CR-20: the device row/audit must record the TRUE OS, not the "android" default,
                    // to match this session's X-Andvari-Client header (desktopPlatform() feeds both).
                    platform = desktopPlatform(),
                )
            }
            // §4.3 (B2-9): persist the crash-window marker BEFORE the irreversible register — a
            // crash between register success and the deferred store.baseUrl commit reconciles at
            // next launch instead of stranding the user on an orphaned account. Written for EVERY
            // enroll (a same-origin enroll's marker just resolves AlreadyCommitted at next launch —
            // marker.origin == store.baseUrl — and clears silently). email is the pre-fill only.
            store.setPendingServer(PendingServer(baseUrl, email, System.currentTimeMillis()))
            val s = a.register(req)
            // §4.1 rule 3 / §4.4 Desktop: register SUCCEEDED ⇒ ENROLL SUCCESS. Commit the persisted
            // default to the origin we enrolled at (baseUrl) and drop the marker + pending state,
            // BEFORE saving the session — so store.baseUrl and the saved session stay consistent
            // (see reconcilePendingMarker) and a pending invite switch commits ONLY here, never on
            // Connect. A same-origin enroll's commit is a no-op (baseUrl already == store.baseUrl).
            commitPendingSwitch()
            store.save(DesktopSession(baseUrl, s.userId, email, s.accessToken, s.refreshToken))
            persistAccountKeys(s.userId, s.accountKeys)
            bind(a, acct); syncNow(engine!!)
            escrowStale = s.accountKeys.escrowStale; escrowFingerprint = s.accountKeys.escrowFingerprint
            mustChangePassword = s.mustChangePassword // F58: never true for a fresh enroll; wired for truth
            // §F.4/§F.7: the recovery piece is MANDATORY and already committed in register(), but a
            // member who never SEES it is silently unrecoverable. Hold it transiently and route to the
            // shown-once reveal+confirm gate (RecoverySetup) instead of the vault; the gate zeroes it
            // once the user types it back.
            pendingRecoverySecret = recoverySecret
            // Piece binding (2026-07-13): the enroll confirm attests the REGISTER-committed piece —
            // register is the only response that populates recoveryPieceId (null ⇒ pre-binding server).
            pendingPieceId = s.recoveryPieceId
            recoveryPhrase = MemberRecovery.displayForm(recoverySecret)
            recoverySetupWaived = posture == EnrollPosture.Waived // §F.4 posture copy on the reveal
            busy = false
            screen = DesktopScreen.RecoverySetup
        } catch (t: Throwable) {
            // Leak guard (Android-parity): a pre-bind failure — incl. the H1 KdfPolicyViolationException
            // from register() — must close the transient client. After bind(), `api === a` (session-owned).
            if (api !== a) a.close()
            // §4.4 Desktop: "Cancel/failure reverts and re-probes the prior server." A pre-register
            // (or register-reject) failure of a PENDING invite switch reverts to the prior origin +
            // clears the marker; a failure AFTER register success is a no-op here (commitPendingSwitch
            // already cleared the pending), so a committed account is never yanked back. A same-origin
            // enroll's revert just drops its (already-current) marker without re-dialing.
            revertPendingSwitch()
            throw t
        }
    }

    // Shown-once recovery secret (design §F.7): the RAW 32 bytes of a fresh enrollee's recovery
    // piece, held transiently between a successful enroll and the confirm gate ONLY for the
    // constant-time confirmMatches. NEVER persisted, NEVER logged; zeroed + dropped the instant the
    // confirm passes (confirmRecoverySaved) or on sign-out. The user-visible base64url form lives in
    // [recoveryPhrase] (also transient) so Compose can render it.
    private var pendingRecoverySecret: ByteArray? = null
    // Piece binding (design 2026-07-13): the opaque, server-minted id of the piece the CURRENT
    // reveal shows — register's recoveryPieceId on the enroll path, the self-setup response's on
    // the capture path (null ⇒ pre-binding server ⇒ the confirm rides the legacy unbound shape).
    // Stashed beside [pendingRecoverySecret] and cleared WITH it everywhere (confirm outcomes,
    // lock, sign-out, the B1 teardown guard) so a confirm can never name a piece whose reveal is
    // gone. Not a secret (an id grants nothing a session couldn't mint itself) — session-scoped
    // all the same.
    private var pendingPieceId: String? = null

    /**
     * The un-skippable "I saved my recovery phrase" gate (design §F.7). Does [typedBack] re-decode
     * to the SAME secret we generated at enroll? Constant-time (core [MemberRecovery.confirmMatches]).
     * On a match: ZERO + DROP the raw secret and its display form, then open the vault. A mistype
     * returns false and the screen shows a STATIC error (never the secret). This is NEVER a KDF
     * source — the piece was already committed at register()/self-setup; this only proves the user
     * saved it.
     *
     * Piece binding (design 2026-07-13 §3): the server confirm names the pieceId this reveal showed
     * ([pendingPieceId]), so it can only flip recoveryConfirmed while that piece is still the
     * CURRENT row. The two reveal paths split on [pendingCaptureAuthKey]:
     *  - ENROLL (null): [markRecoveryConfirmed] is bound but stays best-effort for NAVIGATION —
     *    it never delays the zeroize + toVault below; its one surfaced failure is the 409
     *    replaced-phrase conflict (static notice at vault landing; the cleared flag re-gates).
     *  - CAPTURE GATE (non-null): [confirmCaptureAndEnterVault] AWAITS the bound confirm BEFORE
     *    toVault(); a 409 re-runs the whole setup + reveal with the same stashed reauth proof.
     */
    fun confirmRecoverySaved(typedBack: String): Boolean {
        // State-layer re-assert (the S2 race class, like enroll's): the gate path's awaited
        // confirm runs under [busy] with the secret still live — a second Enter mid-await must
        // not launch a second confirm. `true` = not a mismatch; the first press owns the flow.
        if (busy) return true
        val secret = pendingRecoverySecret ?: return false
        if (!MemberRecovery.confirmMatches(secret, typedBack)) return false
        if (pendingCaptureAuthKey != null) {
            confirmCaptureAndEnterVault(secret)
            return true
        }
        // ENROLL path. §F.9: tell the server this native enrollee saved the register-committed
        // phrase, so the vault-entry gates (web's AND desktop's — v2 #15) never re-nudge the
        // account. Fire this BEFORE we touch the secret: it reads the session creds and launches
        // asynchronously, so a slow/failed ping can never delay or block the zeroize + navigate
        // below (see markRecoveryConfirmed's best-effort note); an interrupted/failed confirm
        // self-heals via the capture gate at the next unlock.
        markRecoveryConfirmed(pendingPieceId)
        secret.fill(0) // best-effort zeroization before dropping the reference
        pendingRecoverySecret = null
        pendingPieceId = null
        toVault() // clears recoveryPhrase too (the display form must not survive landing)
        return true
    }

    /**
     * (v2 #15 → piece binding 2026-07-13) The capture gate's AWAITED confirm: the un-skippable
     * reveal proved the user typed the fresh phrase back — now flip the server flag, but only for
     * the piece THIS gate revealed ([pendingPieceId]). Runs under [busy] (the reveal button spins;
     * the idle lock defers). Outcomes (contract §3):
     *  - 200 → captured: drop the reauth proof, zero + drop the secret, land the vault.
     *  - 409 `recovery_piece_stale` → another device rotated the piece mid-reveal, so the phrase
     *    the user just saved is DEAD. Zero it, surface the static replaced-phrase notice, and
     *    re-run the whole capture (fresh setup + reveal) — which is exactly why
     *    [pendingCaptureAuthKey] survives until a confirm SUCCEEDS (or the session tears down).
     *  - anything else (offline, 5xx, timeout) → proceed to the vault UNCONFIRMED (today's
     *    polarity): the server flag stays 0, so the gate re-fires at the next online unlock and
     *    heals; never strand vault access behind an unreachable server.
     */
    private fun confirmCaptureAndEnterVault(secret: ByteArray) {
        val a = api ?: return
        val acct = account ?: return
        val pieceId = pendingPieceId
        busy = true
        scope.launch {
            try {
                // Bounded like every recovery call (Cut O v2 #17): a black-holed server must not
                // hold [busy] — and with it the idle-lock deferral — open-endedly.
                withTimeoutOrNull(RECOVERY_CALL_TIMEOUT_MS) { a.recoverySelfConfirm(pieceId) }
                    ?: throw java.io.InterruptedIOException("recovery confirm timed out")
                // B1 identity gate: a manual lock / sign-out mid-confirm tore this session down
                // (and already zeroed the pending state) — publish nothing into the next one.
                if (account !== acct) { secret.fill(0); busy = false; return@launch }
                pendingCaptureAuthKey = null // reauth proof served its purpose — drop it
                secret.fill(0)
                pendingRecoverySecret = null
                pendingPieceId = null
                toVault()
            } catch (t: Throwable) {
                if (account !== acct) { secret.fill(0); busy = false; return@launch } // B1, as above
                if (t is ApiException && t.code == "recovery_piece_stale") {
                    // §3: the typed phrase must NEVER be presented as saved. Zero it, say so in
                    // static copy (§F.7 — no interpolation), and re-run the capture: the stashed
                    // reauth proof is still in hand, so the user goes straight to a fresh reveal.
                    secret.fill(0)
                    pendingRecoverySecret = null
                    pendingPieceId = null
                    recoveryPhrase = null // the dead display form must not outlive the conflict
                    recoveryReplacedNotice = RECOVERY_REPLACED_NOTICE
                    busy = false
                    screen = DesktopScreen.RecoveryCapture
                    runRecoveryCapture()
                } else {
                    // IO/other failure: unconfirmed vault entry (flag 0 ⇒ re-gate heals). The
                    // reauth proof is dead weight past the gate — it dies with the secret here.
                    pendingCaptureAuthKey = null
                    secret.fill(0)
                    pendingRecoverySecret = null
                    pendingPieceId = null
                    toVault()
                }
            }
        }
    }

    /**
     * §F.9 best-effort "recovery confirmed" ping — the ENROLL path's confirm, now BOUND (design
     * 2026-07-13): [pieceId] is register's `recoveryPieceId`, so this can never attest a piece a
     * concurrent setup rotated away. Rides the shared core client ([AndvariApi.recoverySelfConfirm]
     * — session bearer + refresh path included; the A.3 swap off the old hand-rolled POST).
     * Deliberately fire-and-forget on [scope] and bounded (a black-holed send must not leak the
     * coroutine — Cut O): a network failure must NEVER strand the enrollee or leave the raw secret
     * un-zeroed — [confirmRecoverySaved] zeroes + navigates regardless, and the flag re-gates at
     * the next unlock. The ONE surfaced failure is the 409 replaced-phrase conflict: the phrase the
     * user just saved is dead, and saying so at vault landing beats letting them trust it (§3 —
     * never present the typed phrase as saved); navigation still proceeds unconfirmed.
     */
    private fun markRecoveryConfirmed(pieceId: String?) {
        val a = api ?: return
        scope.launch {
            try {
                withTimeoutOrNull(RECOVERY_CALL_TIMEOUT_MS) { a.recoverySelfConfirm(pieceId) }
            } catch (t: Throwable) {
                // B1 identity gate: never write a stale session's conflict into the next one.
                if (t is ApiException && t.code == "recovery_piece_stale" && api === a) {
                    error = RECOVERY_REPLACED_NOTICE
                }
                // Every other failure stays swallowed — best-effort by design.
            }
        }
    }

    /**
     * (v2 #15) Enter the §F.9 vault-entry capture gate. [currentAuthKey] is the login authKey
     * derived from the master password the user JUST typed (the fresh-reauth proof the server
     * demands before storing a new recovery block); it is held only until the gate resolves.
     * Kicks the commit immediately — the screen renders "Preparing…" until it lands or fails.
     */
    private fun startRecoveryCapture(currentAuthKey: String) {
        pendingCaptureAuthKey = currentAuthKey
        recoveryCaptureError = null
        busy = false // the op() that routed here is done; the commit runs under its own busy below
        screen = DesktopScreen.RecoveryCapture
        runRecoveryCapture()
    }

    /** (v2 #15) The gate screen's Retry — same commit, same stashed reauth proof. */
    fun retryRecoveryCapture() {
        if (busy) return
        if (screen != DesktopScreen.RecoveryCapture) return // stale click after a lock swapped screens
        runRecoveryCapture()
    }

    /**
     * (v2 #15) The capture gate's commit half (web setupAndCommitRecovery parity): generate a FRESH
     * per-member piece over the in-memory UVK ([Account.setupMemberRecovery]) and PUT it via the
     * shared core [AndvariApi.recoverySelfSetup] (the A.3 swap off the old hand-rolled call) —
     * which stores/rotates the block but deliberately does NOT flip recoveryConfirmed (the flag
     * means "user demonstrably captured" and only the type-back confirm may set it). On success the
     * fresh secret — and the response's pieceId that BINDS the eventual confirm to it (design
     * 2026-07-13; null from a pre-binding server ⇒ legacy unbound confirm) — feeds the SAME
     * un-skippable RecoverySetup reveal the enroll path uses; on any failure the secret is zeroed
     * and the gate stays closed with Retry — never the vault, never a dangling live secret. Runs
     * under [busy] so the idle lock defers while key material is in flight (maybeIdleLock's
     * existing busy gate). A rotation invalidates any previously-written-but-unconfirmed phrase —
     * the screen copy says so.
     */
    private fun runRecoveryCapture() {
        val a = api ?: return
        val acct = account ?: return
        val authKey = pendingCaptureAuthKey ?: return
        recoveryCaptureError = null
        busy = true
        scope.launch {
            try {
                val setup = acct.setupMemberRecovery(authKey)
                var committed = false
                var pieceId: String? = null
                try {
                    // Bounded per call (Cut O v2 #17, kept across the core swap): a black-holed
                    // server must not hold [busy] — and the idle-lock deferral — open-endedly.
                    val resp = withTimeoutOrNull(RECOVERY_CALL_TIMEOUT_MS) { a.recoverySelfSetup(setup.request) }
                        ?: throw java.io.InterruptedIOException("recovery self-setup timed out")
                    pieceId = resp.pieceId
                    committed = true
                } finally {
                    // §F.7 discipline: a failed commit must not leave the raw secret alive.
                    if (!committed) setup.recoverySecret.fill(0)
                }
                // B1 identity gate: a manual lock / sign-out mid-commit tore this session down —
                // the fresh phrase must not leak into whatever session renders next.
                if (account !== acct) { setup.recoverySecret.fill(0); pendingPieceId = null; busy = false; return@launch }
                // NOTE: [pendingCaptureAuthKey] is deliberately KEPT (was dropped here pre-binding):
                // the bound confirm can 409 on a concurrent rotation and the re-run needs the same
                // reauth proof — it drops when a confirm SUCCEEDS (confirmCaptureAndEnterVault) or
                // the session tears down (lock/sign-out).
                pendingRecoverySecret = setup.recoverySecret
                pendingPieceId = pieceId
                recoveryPhrase = MemberRecovery.displayForm(setup.recoverySecret)
                // Posture at the gate is server-unknown (accountKeys deliberately carries no escrow
                // marker), so keep the required copy — imperfect for a waived account that re-gates,
                // but the reveal's load-bearing instruction (save the phrase) is identical.
                recoverySetupWaived = false
                busy = false
                screen = DesktopScreen.RecoverySetup
            } catch (t: Throwable) {
                busy = false
                if (account !== acct) return@launch // torn down mid-flight — nothing to report
                // Static copy only — NEVER interpolate anything near secret material (§F.7).
                recoveryCaptureError = if (t is java.io.IOException) {
                    "Can't reach the server right now — check your connection and try again."
                } else {
                    "Couldn't set up your recovery phrase just now — try again in a moment."
                }
            }
        }
    }

    // ---- native self-recovery (design §F.3 — the web Recover.tsx mirror; DesktopScreen.Recover) ----

    /** Enter the forgot-master-password flow (from Unlock — which knows the email — or Welcome).
     *  Kicks a policy re-probe when none is loaded: the reset step needs `policy.kdfParams`, and
     *  a launch-time probe failure would otherwise dead-end the flow at that step. */
    fun openRecover(prefillEmail: String = "") {
        clearRecoverState()
        recoverPrefillEmail = prefillEmail
        screen = DesktopScreen.Recover
        if (policy == null && !busy) retryPolicy()
    }

    /** Leave the flow (§F.7: zeroes the parsed phrase bytes) — back to Unlock when a stored
     *  session exists, else Welcome. The UI busy-gates its Cancel affordances, so this never
     *  races an in-flight verify/commit. */
    fun cancelRecover() {
        clearRecoverState()
        val session = store.load()
        screen = if (session != null && session.accessToken.isNotEmpty()) DesktopScreen.Unlock(session.email) else DesktopScreen.Welcome
    }

    /**
     * Phase 1 — verify possession of the recovery phrase (web `submitVerify` parity). The typed
     * phrase parses locally ([MemberRecovery.parseSecret] is TOTAL — malformed input is a static
     * user error, not an exception); only the HKDF-derived `recoveryAuthKey` goes to the server,
     * which proves possession without ever seeing the phrase and answers a uniform 401 across
     * unknown-email / no-row / bad-key (anti-enumeration, §F.5). On success the raw secret bytes
     * are stashed for the commit step under §F.7 discipline. Unauthenticated — rides a transient
     * client, bounded like every recovery call (Cut O).
     */
    fun recoverVerifySubmit(email: String, phrase: String) {
        if (busy) return
        val secret = MemberRecovery.parseSecret(phrase)
        if (secret == null || secret.isEmpty()) {
            recoverError = "That doesn't look like a recovery phrase — check it and try again."
            return
        }
        busy = true; recoverError = null
        scope.launch {
            val a = newApi()
            try {
                val authKey = withContext(Dispatchers.Default) { MemberRecovery.deriveAuthKey(createCryptoProvider(), secret) }
                val resp = withTimeoutOrNull(RECOVERY_CALL_TIMEOUT_MS) { a.recoverySelfVerify(email.trim(), authKey) }
                    ?: throw java.io.InterruptedIOException("recovery verify timed out")
                if (screen != DesktopScreen.Recover) { secret.fill(0); return@launch } // left the flow — publish nothing
                recoverSecret?.fill(0) // a re-verify replaces any earlier stash
                recoverSecret = secret
                recoverVerify = resp
                recoverVerified = true
            } catch (t: Throwable) {
                secret.fill(0) // failed verify: the parsed bytes must not linger (§F.7)
                if (screen == DesktopScreen.Recover) recoverError = recoverVerifyError(t)
            } finally {
                busy = false
                a.close()
            }
        }
    }

    /**
     * Phase 2 — commit the reset (web `submitReset` parity). Core [Account.recover] opens the
     * SAME UVK from the phrase, runs the spec 01 §5 identity-pubkey HARD-FAIL (a substituted
     * identity key aborts BEFORE commit — surfaced as the distinct tampering copy, never "wrong
     * phrase"), then re-wraps under the new password (argon2id — off the UI thread). The commit
     * revokes every session server-side, so on success the stored session/keys here are dead
     * weight: drop them and land on Welcome with the sign-in-fresh notice. A FAILED commit keeps
     * the stashed secret so a transient blip retries without retyping (web keeps its secretRef
     * the same way); the single-use ticket path ("start again") exits via Cancel.
     */
    fun recoverCommitSubmit(newPassword: String) {
        if (busy) return
        val v = recoverVerify
        val secret = recoverSecret
        if (v == null || secret == null) {
            recoverError = "Your recovery session expired — start again."
            return
        }
        val pol = policy
        if (pol == null) {
            recoverError = "Couldn't reach the server for its settings — try again in a moment."
            return
        }
        // F60 floor re-assert at the state layer (enroll parity — the UI gate can be a frame stale).
        if (!Strength.meetsMasterPasswordFloor(newPassword)) {
            recoverError = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols."
            return
        }
        busy = true; recoverError = null
        scope.launch {
            val a = newApi()
            try {
                val commit = withContext(Dispatchers.Default) { Account.recover(secret, v, newPassword, pol.kdfParams) }
                withTimeoutOrNull(RECOVERY_CALL_TIMEOUT_MS) { a.recoverySelfCommit(commit) }
                    ?: throw java.io.InterruptedIOException("recovery commit timed out")
                // Success. Sessions are revoked server-side; the persisted tokens + accountKeys
                // (old KDF wrap) are stale — clear them so the next entry is an honest fresh
                // sign-in instead of a doomed unlock. The ciphertext vault cache stays (spec 05
                // T3 posture — the UVK is invariant; a fresh sign-in re-binds it).
                clearRecoverState() // zeroes the secret (§F.7)
                store.clear()
                lockReason = null
                screen = DesktopScreen.Welcome
                notice = "Master password reset — sign in with your new password."
            } catch (t: Throwable) {
                if (screen == DesktopScreen.Recover) recoverError = recoverResetError(t)
            } finally {
                busy = false
                a.close()
            }
        }
    }

    /** §F.7 teardown for the self-recovery slice: zero + drop the parsed phrase bytes and every
     *  flow field. Called at entry, cancel, commit success, and (belt) session teardown. */
    private fun clearRecoverState() {
        recoverSecret?.fill(0)
        recoverSecret = null
        recoverVerify = null
        recoverVerified = false
        recoverError = null
        recoverPrefillEmail = ""
    }

    /** Web Recover.tsx `verifyErrorMessage` twin — static curated copy only (§F.7); the uniform
     *  401 never reveals which of email / phrase / no-recovery-row was wrong (§F.5). */
    private fun recoverVerifyError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION // H1 (spec 05 T1)
        t is ApiException && t.status == 401 -> "We couldn't verify that email and recovery phrase."
        t is ApiException && t.code == "recovery_public_disabled" ->
            "Account recovery isn't available from this public address — connect from inside (VPN/LAN) and try again."
        t is ApiException -> HouseholdCopy.SERVER_PROBLEM
        t is java.io.IOException -> HouseholdCopy.UNREACHABLE
        else -> "Recovery failed. Please try again."
    }

    /** Web Recover.tsx `resetErrorMessage` twin. The identity-mismatch tampering signal (spec 01
     *  §5) keeps its distinct warning — never softened into "wrong phrase" or retry copy. */
    private fun recoverResetError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION // H1 (spec 05 T1)
        t is CryptoException && t.message?.contains("identity key mismatch") == true -> HouseholdCopy.IDENTITY_MISMATCH
        t is ApiException && (t.code == "invalid_ticket" || t.status == 401) -> "Your recovery session expired — start again."
        t is ApiException && t.code == "recovery_account_not_active" ->
            "This account is disabled — self-recovery isn't available. Ask your admin to recover it."
        t is ApiException -> HouseholdCopy.SERVER_PROBLEM
        t is java.io.IOException -> HouseholdCopy.UNREACHABLE
        else -> "Recovery failed. Please try again."
    }

    /**
     * F57: re-seal this account's UVK to the CURRENT org recovery key after a re-ceremony. The user
     * must have TYPED the new recovery fingerprint's short form from their PRINTED sheet (spec 04
     * §2(3)); we re-check it, then [Account.resealEscrowFor] binds the server-fetched recovery pubkey
     * to that verified fingerprint (refusing on mismatch) so a hostile server can't redirect the
     * escrow. Non-blocking: on success the banner clears; a failure surfaces as an error.
     */
    fun resealEscrow(shortFormEntry: String) = op {
        val a = api
        val acct = account
        val fp = escrowFingerprint
        if (a == null || acct == null) { busy = false; return@op }
        if (!Escrow.shortFormMatches(shortFormEntry, fp)) {
            busy = false; error = "That doesn't match this server's recovery key — check your printed recovery sheet."
            return@op
        }
        val pub = withContext(Dispatchers.Default) { a.recoveryPubkey() }
        val upload = withContext(Dispatchers.Default) { acct.resealEscrowFor(pub, fp) }
        a.escrowSelf(upload)
        busy = false; escrowStale = false; notice = "Account re-protected — your recovery is up to date."
    }

    // F18: [vaultId] is honored ONLY for a NEW item (itemId == null) — the core save guard
    // keeps an existing item in its own vault (server enforces vault_mismatch), so a restore
    // (itemId != null) leaves it null and lands the item back where it was.
    // F71: [onSaved] fires ONLY on success — the editor closes there and nowhere else, so a
    // failed save/upload keeps the typed fields + picked attachments editable with the error
    // beside them (the Android op{}+onSaved contract).
    fun saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList(), vaultId: String? = null, onSaved: () -> Unit = {}) = op {
        saveError = null
        if (itemId == null && draftItemId == null) draftItemId = account?.newItemId()
        try {
            // Named: a trailing lambda binds to the LAST parameter (the runGesture rule).
            engine!!.saveWithUploads(
                itemId, doc, uploads, vaultId,
                onProgress = { done, total -> saveProgress = done to total },
                newItemId = if (itemId == null) draftItemId else null,
            )
        } catch (e: UpgradeRequiredException) {
            throw e // the blocking upgrade screen owns 426 — never an inline save error
        } catch (t: Throwable) {
            // Route the failure to the EDITOR's error surface and stop: the editor stays
            // open (F71) and the global bar stays quiet — op's generic catch never sees it.
            // #23: canon save copy (IO → "try saving again when connected", 409 → changed
            // elsewhere, …) — never the exception's raw message beside the Save button.
            busy = false
            saveError = HouseholdCopy.forSaveError(t)
            return@op
        } finally {
            saveProgress = null
        }
        draftItemId = null
        refreshItems()
        onSaved()
    }

    /** Item history (feature): load + decrypt the currently-viewed item's archived versions. */
    fun loadItemVersions(itemId: String, vaultId: String) = op {
        itemVersions = null
        itemVersions = engine!!.itemVersions(itemId, vaultId)
        busy = false
    }

    fun clearItemVersions() { itemVersions = null }
    fun deleteItem(itemId: String) = op { engine!!.remove(itemId); refreshItems() }
    /** Cut O (v2 #17): the toolbar's manual Refresh — the SAME single-flighted sync path as the
     *  poll (it used to run under op{}/busy with no overlap guard, so repeat clicks stacked
     *  concurrent syncs), but `manual = true` so an offline blip answers with an honest notice
     *  instead of the old silence. */
    fun refresh() = runSync(manual = true)
    fun item(itemId: String): VaultItem? = engine?.item(itemId)

    /** Server-declared role for a vault (mirrors web's account.roleFor) — null when unknown. */
    fun roleFor(vaultId: String): String? = account?.roleFor(vaultId)

    /** F81: vaultId → decrypted vault name for every held vault EXCEPT the personal one — the
     *  gold shared-vault badge on rows/detail. Decrypts each vault's metaBlob, so the UI calls
     *  it once per items-change (under remember(items)), never per row recomposition. */
    fun sharedVaultNames(): Map<String, String> {
        val acct = account ?: return emptyMap()
        return engine?.vaultInfos()?.filterNot { it.vaultId == acct.personalVaultId }
            ?.associate { it.vaultId to it.name }.orEmpty()
    }

    /**
     * F18: vaults a NEW item may be created in — the personal vault plus any shared vault we can
     * WRITE to (owner/writer). vaultInfos() is personal-first, so `.first()` is the default the
     * picker starts on. Existing items never move via the editor (the core save guard fences a
     * changed vaultId), so this is a new-item / move-target list only. Each call decrypts vault
     * metadata, so the UI reads it once (under remember), never per recomposition.
     */
    fun newItemVaultChoices(): List<VaultInfo> =
        engine?.vaultInfos()?.filter { it.type == "personal" || it.role == "owner" || it.role == "writer" }.orEmpty()

    /** F19: discard an item's memoized gestures + the inline move state — on Cancel or a
     *  mode switch, so the next gesture is minted fresh (a lingering gesture would replay a
     *  stale snapshot). A transient failure deliberately does NOT call this: the memo must
     *  survive so Retry replays the SAME ids (server dedup converges, never a duplicate). */
    fun clearMoveState(itemId: String) {
        moveGestures.keys.filter { it.startsWith("$itemId|") }.forEach { moveGestures.remove(it) }
        moveError = null
        moveProgress = null
    }

    /**
     * F19 (design §8): move (copy-leg-first, THEN delete source) or copy [itemId] into
     * [targetVaultId]. All gesture logic lives in core [SyncEngine.runGesture] (copy confirmed
     * before any delete, per-gesture idempotent mutationIds) — this only picks/reuses the
     * gesture and maps failures to inline copy. Sets the global [busy] so the idle auto-lock
     * defers (never yanks the engine mid-move). onDone fires ONLY on success (the caller closes
     * the picker + leaves the detail). Mirrors Android's moveOrCopyItem.
     */
    fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean, onDone: () -> Unit) {
        val e = engine ?: return
        val gKey = "$itemId|$targetVaultId|$move"
        busy = true; moveError = null; moveProgress = null
        scope.launch {
            try {
                val current = e.item(itemId)
                    ?: throw ApiException(409, "vault_state_changed", "This item is no longer here — it may have been removed or its vault deleted.")
                // Reuse the memo ONLY while the source content is unchanged — a different rev
                // IS different content, so remint (a stale gesture would rebuild attachments
                // from a stale snapshot). Fresh ids are minted exactly once per gesture.
                val memo = moveGestures[gKey]
                val g = if (memo != null && memo.sourceRev == current.rev) memo
                        else e.newMoveGesture(itemId, targetVaultId, move).also { moveGestures[gKey] = it }
                // Named: a trailing lambda would bind to `finalSync: Boolean`, not onProgress.
                e.runGesture(g, onProgress = { done, total -> moveProgress = done to total })
                moveGestures.remove(gKey)
                val target = e.vaultInfos().find { it.vaultId == targetVaultId }?.name ?: "the other vault"
                refreshItems() // clears busy; a MOVE also empties the detail (source item is gone)
                moveProgress = null
                notice = if (move) "Moved to “$target”." else "Copied to “$target”."
                onDone()
            } catch (t: Throwable) {
                moveProgress = null; busy = false
                when {
                    // Copy denied / source changed / a 403 are TERMINAL — drop the gesture so a
                    // fresh attempt re-reads state (never a blind replay of a doomed gesture).
                    t is CopyDeniedException -> { moveGestures.remove(gKey); moveError = "You don't have permission to add items to that vault — nothing was moved." }
                    t is ItemChangedException -> { moveGestures.remove(gKey); moveError = "This item changed while moving — go back, review it, and try again." }
                    // #23: a server 403 refusal maps through the canon ("You don't have permission
                    // to do that."), never the wire's raw message. The MINTED 409 above (the
                    // curated item-flavored vault_state_changed sentence) deliberately does NOT
                    // route through forError — the shared map would swap it for the generic
                    // vault-flavored row.
                    t is ApiException && t.status == 403 -> { moveGestures.remove(gKey); moveError = HouseholdCopy.forError(t) }
                    // Transient — KEEP the gesture so Retry replays the same ids (no duplicate).
                    else -> moveError = "That didn't finish. Press Retry — it won't create a duplicate."
                }
            }
        }
    }

    // ---- vault lifecycle (spec 03 §11 / N3 design 2026-07-11): sharing + notices ----

    /** Vaults whose key we hold (personal first) — pickers, badges, the Sharing screen. */
    fun vaultInfos(): List<VaultInfo> = engine?.vaultInfos() ?: emptyList()

    /** The pending offer on a vault (owner's "Ownership offer to …" chip), or null. */
    fun pendingTransferFor(vaultId: String): PendingTransfer? = engine?.pendingTransferFor(vaultId)

    /** Not busy-gated: dismissing a notice is a pure engine-side write + re-read. */
    fun dismissNotice(id: String) {
        engine?.dismissNotice(id)
        refreshLifecycle()
    }

    /**
     * F20: count of shared vaults whose grant this device can't OPEN — a grant blob WAS
     * delivered (it's in the engine's grant rows) but addGrant() failed (sealed to an
     * identity we don't hold, or a newer grant format), so [Account.hasVault] is false and
     * the vault is silently absent from vaultInfos()/[items]. Computed app-side from the
     * engine's read surface (F82). Removed/held/deleted vaults are dropVault()'d out of the
     * vault rows, so they never count here; a grant that later opens flips hasVault true
     * and drops out. Mirrors Android's undecryptableSharedCount / web's undecryptableGrants.
     */
    private fun undecryptableSharedCount(): Int {
        val e = engine ?: return 0
        val acct = account ?: return 0
        val grantedIds = e.grants().mapTo(HashSet()) { it.vaultId }
        return e.vaultRows().count {
            it.type == "shared" && it.vaultId in grantedIds && !acct.hasVault(it.vaultId)
        }
    }

    /**
     * Mirror the engine's lifecycle read-surfaces into UI state (cheap in-memory reads),
     * and lazily resolve the owner display name behind any verified incoming offer.
     * A-resolve: ALL slice writes — notices, offers, held list, F20 count, the A2
     * settings-id null, and the lifecycleTick bump — happen in THIS one synchronous,
     * non-suspending block (one recomposition, no torn frame); the owner-name fetch is a
     * SEPARATE launch under the B1 epoch guard.
     */
    private fun refreshLifecycle() {
        val e = engine ?: return
        val incoming = e.incomingTransfers()
        lifecycleNotices = e.notices()
        incomingTransfers = incoming
        heldVaults = e.heldVaultInfos()
        undecryptableSharedVaultCount = undecryptableSharedCount()
        // A2 (DN-1): every sync/refresh funnels through here (reloadSharing after ops, the
        // backgroundSync poll) — a settings id whose vault vanished (deleted/revoked
        // elsewhere) is ACTIVELY cleared, so a later restore/re-grant can't resurrect the
        // settings layer. The screen's null-safe lookup covers the same-frame gap.
        sharingSettingsVaultId = sharingSettingsVaultId?.takeIf { id -> e.vaultInfos().any { it.vaultId == id } }
        lifecycleTick++ // A-tick: LAST slice write — the memo key ticks once per refresh
        val missing = incoming.filter { it.vaultId !in transferOwnerNames }
        if (missing.isNotEmpty()) {
            val a = api ?: return
            scope.launch {
                val names = transferOwnerNames.toMutableMap()
                for (t in missing) {
                    runCatching { a.vaultMembers(t.vaultId).find { it.role == "owner" } }.getOrNull()
                        ?.let { names[t.vaultId] = it.displayName }
                }
                // B1: identity, not null — after a sign-out→sign-in the null check would
                // pass against the NEW engine and leak the old session's owner names.
                if (engine !== e) return@launch
                transferOwnerNames = names
            }
        }
    }

    fun openSharing() {
        // A5 (DN-1): a fresh Sharing visit always lands on the LIST — never inside a
        // stale settings layer left over from the previous visit.
        screen = DesktopScreen.Sharing
        sharingSettingsVaultId = null
        copiedNote = null; copyProgress = null; copyVaultId = null
        reloadSharing()
    }

    fun closeSharing() {
        screen = DesktopScreen.Vault
        copiedNote = null; copyProgress = null; copyVaultId = null
    }

    /** DN-1: open one vault's Settings view inside the Sharing screen. Clears the copy
     *  DISPLAY state per the openSharing convention (A4); an in-flight copy itself
     *  ([copyOpVaultId]) is untouched — its next progress tick republishes, and the
     *  screen-level status line keeps it visible from either branch. */
    fun openVaultSettings(vaultId: String) {
        sharingSettingsVaultId = vaultId
        copiedNote = null; copyProgress = null; copyVaultId = null
    }

    fun closeVaultSettings() {
        sharingSettingsVaultId = null
        copiedNote = null; copyProgress = null; copyVaultId = null
    }

    /**
     * Fetch the Sharing screen's server-side lists: members per owned shared vault (the
     * transfer target picker) and the caller's restorable Recently-deleted vaults. Runs
     * WITHOUT busy (a slow members fetch must not freeze the window). B1: `e`/`a` are the
     * launch-time epoch — every enumeration step is runCatching-wrapped (a mid-flight lock
     * closes the sqlite cache under `e`) and the state writes are identity-gated, so a
     * continuation resuming after a sign-out→sign-in can neither kill the window nor leak
     * account A's member emails / deleted vaults into account B's session.
     */
    fun reloadSharing() {
        val e = engine ?: return
        refreshLifecycle()
        val a = api ?: return
        scope.launch {
            val members = mutableMapOf<String, List<VaultMemberSummary>>()
            val owned = runCatching { e.vaultInfos().filter { it.type == "shared" && it.role == "owner" } }
                .getOrDefault(emptyList())
            for (v in owned) {
                runCatching { members[v.vaultId] = a.vaultMembers(v.vaultId) }
            }
            val deleted = runCatching { e.listDeleted() }.getOrDefault(emptyList())
            if (engine !== e) return@launch // B1: locked/rebound while fetching — publish nothing
            sharingMembers = members
            deletedVaults = deleted
        }
    }

    /** RENAME (owner). stale_meta auto-retries once inside the engine. */
    fun renameVault(vaultId: String, newName: String) = op {
        engine!!.renameVault(vaultId, newName)
        refreshItems(); reloadSharing()
    }

    /** DELETE (soft, 7d grace). The §11 owner toast lands in [notice]. A-copyGate: REFUSED
     *  while the rescue copy runs — `busy` alone is not a gate (any other op finishing
     *  mid-copy clears it), and deleting the source out from under its own rescue is the
     *  one irreversible interleaving. */
    fun deleteVault(vaultId: String, vaultName: String) {
        if (copyOpVaultId != null) return
        op {
            val purgeAt = engine!!.deleteSharedVault(vaultId)
            refreshItems(); reloadSharing()
            notice = "“$vaultName” is deleted. Members lost access immediately. You can restore it until ${fmtDay(purgeAt)} (Sharing → the trash icon)."
        }
    }

    /**
     * Bulk "Copy items to my Personal vault first…" (F19 rider — copy legs ONLY). NOT op{}:
     * busy is set manually and HELD for the whole copy, and the A-copyGate op guard
     * [copyOpVaultId] — set here, cleared ONLY in this finally, never by navigation — is
     * what fences deleteVault + the idle lock for the duration. The engine invokes
     * onProgress inline on this scope's context, so the per-tick write is a plain direct
     * field write. Success keeps [copyVaultId] (A4: the surviving note is named through
     * it); per A-note a completion while the user is off-Sharing also mirrors the note
     * into the global [notice] so it isn't lost. Deliberately NO epoch guard here (design:
     * manual Lock mid-copy stays unguarded — parity; degrades to an error, same as Android).
     */
    fun copyItemsToPersonal(vaultId: String) {
        // Single-flight (review MED): copyOpVaultId is a single slot and the finally below
        // clears it unconditionally — an overlapping second copy would let the FIRST one's
        // finish disarm the gate (delete + idle lock re-enabled) while the second still
        // runs. One rescue at a time; the button mirrors this in its enabled gate.
        if (copyOpVaultId != null) return
        val e = engine ?: return
        busy = true; error = null; copiedNote = null
        copyProgress = 0 to 0; copyVaultId = vaultId; copyOpVaultId = vaultId
        scope.launch {
            try {
                val copied = e.copyAllToPersonal(vaultId) { done, total -> copyProgress = done to total }
                // A4: copyVaultId stays — the surviving note is named through it.
                copyProgress = null
                items = e.items()
                copiedNote = "Copied $copied ${if (copied == 1) "item" else "items"} to your Personal vault. You can still change your mind — deleting won't remove those copies."
                if (screen !is DesktopScreen.Sharing) notice = copiedNote // A-note
            } catch (t: Throwable) {
                copyProgress = null; copyVaultId = null
                error = HouseholdCopy.forError(t) // #23
            } finally {
                // Ownership check (belt on the single-flight guard): only this call's own
                // marker may be cleared — a future re-entry path can never disarm a live copy.
                if (copyOpVaultId == vaultId) copyOpVaultId = null
                busy = false
            }
        }
    }

    fun clearCopiedNote() { copiedNote = null; copyVaultId = null }

    fun offerTransfer(vaultId: String, toUserId: String) = op {
        engine!!.offerTransfer(vaultId, toUserId)
        refreshItems(); reloadSharing()
    }

    /** Owner cancel or target decline. */
    fun cancelTransfer(vaultId: String) = op {
        engine!!.cancelTransfer(vaultId)
        refreshItems(); reloadSharing()
    }

    /** Accept an ownership offer — the engine re-verifies the proof before acting. */
    fun acceptTransfer(vaultId: String) = op {
        engine!!.acceptTransfer(vaultId)
        refreshItems(); reloadSharing()
    }

    fun leaveVault(vaultId: String) = op {
        engine!!.leaveSharedVault(vaultId)
        refreshItems(); reloadSharing()
    }

    fun restoreVault(vaultId: String, deleteId: String) = op {
        engine!!.restoreSharedVault(vaultId, deleteId)
        refreshItems(); reloadSharing()
    }

    // ---- inactivity auto-lock + poll cadence (spec 01 §8 / spec 03 §6) ----

    // Clock choice: wall clock (System.currentTimeMillis). System.nanoTime is monotonic but
    // EXCLUDES time suspended on Linux (CLOCK_MONOTONIC), so a laptop that slept past the
    // window would wake "fresh". Wall time counts sleep — lid-closed-overnight locks on the
    // first tick after wake; an NTP step only shifts the lock by the adjustment, acceptable
    // for a minutes-scale window (and a backwards user clock change can only DELAY, which
    // the manual Lock button still covers).
    private var lastInteractionMs = System.currentTimeMillis()

    /** Record user interaction (pointer/key) — called from the window-level interceptors. */
    fun touch() {
        lastInteractionMs = System.currentTimeMillis()
    }

    /** (v2 #15): the Vault screen mirrors its editor's mounted/unmounted state in (the draft is
     *  remember-scoped Compose state this holder can't see) so [maybeIdleLock] can grant the
     *  bounded grace instead of silently destroying typed work. (Named `note…`, not `set…` —
     *  the property's own JVM setter already claims the setEditorOpen(Z) signature.) */
    fun noteEditorOpen(open: Boolean) {
        editorOpen = open
        if (!open) idleLockImminent = false
    }

    /**
     * Lock if the inactivity window elapsed (policy `autoLockSeconds`; persisted last-known
     * value when the live policy hasn't loaded; 0 disables). Never yanks the engine under an
     * in-flight op ([busy]/import) — the durable queue would survive it, but the op would
     * surface a spurious error; the next 1 s tick re-checks, so the lock is deferred, not
     * skipped.
     *
     * (v2 #15) pre-lock protection — the idle lock used to destroy in-progress work SILENTLY:
     *  - An open editor (typed fields + picked attachments are remember-scoped, unmounted by the
     *    screen swap) gets ONE bounded grace window ([editorGraceMs]) past the policy window,
     *    with [idleLockImminent] raised so the returning user sees WHY the vault hasn't locked
     *    and that the clock is running. Bounded by design: the grace serves the walked-away
     *    editor, it must never become "an open editor disables the security lock".
     *  - RecoverySetup mid-reveal gets NO grace — the shown-once phrase is on screen, and
     *    leaving a secret up longer on an unattended machine is the wrong trade. Instead the
     *    lock is HONEST about what it destroyed (the lockReason below) and the §F.9 capture
     *    gate re-issues a fresh phrase at the next unlock (recoveryConfirmed is still false
     *    server-side), so the interrupted reveal self-heals instead of silently skipping the
     *    "un-skippable" gate.
     */
    private fun maybeIdleLock() {
        if (engine == null) return
        // §2.3 (B1-1): the window is clamped into [1, AUTO_LOCK_MAX_SECONDS] — live policy is
        // pre-clamped by applyPolicy; the per-origin persisted fallback (§4.2) is re-clamped here
        // as the belt (pre-clamp prefs, or a hand-edited file). A 0 that used to mean "auto-lock
        // disabled" now means the CEILING: no server — and no stale fallback — can disable the
        // lock any more; that path is deliberately gone.
        val window = clampAutoLockSeconds(policy?.autoLockSeconds ?: store.originAutoLockSeconds(originKey(baseUrl)))
        // A-copyGate: the rescue copy holds `busy`, but any OTHER op finishing mid-copy
        // clears it — the op guard is what actually keeps the idle lock off the engine
        // for the whole copy (never yank the engine mid-rescue).
        if (busy || importBusy || copyOpVaultId != null) return
        val idleMs = System.currentTimeMillis() - lastInteractionMs
        if (idleMs < window * 1000L) {
            if (idleLockImminent) idleLockImminent = false // interaction reset the clock — stand down
            return
        }
        if (editorOpen && pendingRecoverySecret == null && idleMs < window * 1000L + editorGraceMs(window)) {
            idleLockImminent = true // the editor's grace is holding the lock — warn, don't lock yet
            return
        }
        idleLockImminent = false
        lock(when {
            // §F.7: the phrase (and its raw secret) die with lock() below — say so, and say the
            // recovery, not just "locked". The next unlock lands in the capture gate (v2 #15).
            pendingRecoverySecret != null ->
                "Locked after inactivity. Your recovery phrase was not confirmed — you'll be shown a fresh one after you unlock."
            editorOpen -> "Locked after inactivity — the editor's unsaved changes were discarded."
            else -> "Locked after inactivity."
        })
    }

    /** (v2 #15): the editor's bounded pre-lock grace — one extra policy window, capped at
     *  [EDITOR_LOCK_GRACE_MAX_MS] so a long-window org (30 min) doesn't see its lock double. */
    private fun editorGraceMs(windowSeconds: Int): Long =
        minOf(windowSeconds * 1000L, EDITOR_LOCK_GRACE_MAX_MS)

    /**
     * Quiet poll sync (spec 03 §6: focus regained + every 5 min while unlocked): refresh
     * policy first (so autoLock/clipboard windows track admin changes mid-session), then
     * push-queue + pull. Cut O (v2 #17): runs under [syncBusy], NOT [busy] — see [runSync].
     * Offline blips stay silent; anything else (rev regression, denied writes) surfaces
     * like a manual sync.
     */
    fun backgroundSync() = runSync(manual = false)

    /**
     * Cut O (v2 #17): the ONE sync path behind both the passive pulls (timer poll, focus sync)
     * and the toolbar Refresh. Design points, each fixing a confirmed audit failure:
     *  - Runs under [syncBusy], which op() and every user-op UI gate ignore — a poll/refocus can
     *    no longer repaint the editor's Save into a spinner or grey Cancel/Trash/Settings. The
     *    overlap is engine-safe: SyncEngine.sync() is syncMutex-serialized against a save's
     *    reconcile, so a user op landing mid-pull just queues behind it inside core.
     *  - Single-flight: [syncBusy] is read+set on the UI thread, so repeat Refresh clicks and a
     *    poll tick landing on a running sync are no-ops (they used to STACK concurrent op{} runs).
     *    A sync also never STARTS under a user op / import — their engine writes finish first.
     *  - Bounded: the whole cycle (policy probe + push + pull — never attachment bytes, those
     *    move only inside user-op saves/gestures) lives inside withTimeoutOrNull, so a server
     *    that accepts the connection and then black-holes can wedge the flag — and with it the
     *    single-flight gate — for at most [SYNC_TIMEOUT_MS]. Cancellation is safe by the same
     *    contract as an offline blip: an idempotent push replays, an unfinished pull never
     *    advanced the cursor.
     *  - [manual] only changes the OFFLINE answer: the toolbar Refresh owes feedback ("no
     *    feedback" was the audit finding), the silent 5-min poll does not.
     *  - The idle lock deliberately does NOT defer on [syncBusy] (unlike [busy]): the pull is
     *    teardown-safe by construction (the B1 identity gates below make a mid-sync lock an
     *    expected, silent outcome), and a hung sync must never postpone the security lock.
     */
    private fun runSync(manual: Boolean) {
        val e = engine ?: return
        if (syncBusy || busy || importBusy) return
        // op()-parity for the USER-initiated path: the old op{}-based Refresh opened by clearing
        // the global bars (pressing Refresh to retry after an error must not leave the stale
        // error up over a now-clean sync). The passive poll keeps its hands off them.
        if (manual) { error = null; notice = null }
        syncBusy = true
        scope.launch {
            try {
                val completed = withTimeoutOrNull(SYNC_TIMEOUT_MS) {
                    runCatching { api?.clientPolicy() }.getOrNull()?.let { applyPolicy(it) }
                    syncNow(e)
                }
                // Timed out = the server is reachable-but-unresponsive — same posture as offline
                // (InterruptedIOException IS an IOException, so ONE handling branch below).
                if (completed == null) throw java.io.InterruptedIOException("sync timed out")
                // B1: `syncBusy` alone is no teardown guard — a manual lock (or sign-out→sign-in)
                // mid-sync leaves this continuation holding the OLD engine; identity-gate every
                // post-suspension state write so nothing stale lands in the new session.
                if (engine !== e) { syncBusy = false; return@launch }
                items = e.items()
                needsUpdateCount = e.needsUpdateCount()
                syncBusy = false
                refreshLifecycle() // A-funnel: a background pull may have delivered notices/offers
            } catch (t: Throwable) {
                syncBusy = false
                val torn = engine !== e // locked/rebound mid-sync — an expected teardown, not an error
                if (torn) return@launch
                when {
                    // A 426 mid-poll is not a per-sync error — this build is too old for the
                    // server's pin (op()-parity; the old manual refresh via op{} already did this).
                    t is UpgradeRequiredException ->
                        upgradeRequired = "This andvari server requires a newer desktop app. Download the latest from ${baseUrl}/downloads."
                    // Offline blip: silent for the background poll (by design), an honest one-liner
                    // for the toolbar Refresh the user just clicked (#23: the canon's SYNC_OFFLINE —
                    // byte-equal to the sentence this site always showed).
                    t is java.io.IOException ->
                        if (manual) notice = HouseholdCopy.SYNC_OFFLINE
                    else -> error = HouseholdCopy.forSyncError(t)
                }
                refreshLifecycle() // A-funnel: even a denied/park cycle leaves notices to show
            }
        }
    }

    /** Window regained focus: enforce the idle window FIRST, then catch up (spec 03 §6). */
    fun onWindowFocus() {
        maybeIdleLock()
        backgroundSync()
    }

    // ---- CSV import (spec 06 + universal importer, design 2026-07-11) ----

    /**
     * Bounded read → parse → vault-aware plan, all on-device (nothing is uploaded).
     * Universal importer (design 2026-07-11): there is no source pick — header detection
     * alone decides how the file is read (the parser was always universal). The plan step
     * REFUSES (A8) when the personal vault's projections aren't available rather than
     * silently planning against an empty vault (every duplicate would sail in unflagged).
     */
    fun importFromFile(file: File) {
        importDismiss()
        val eng = engine
        val acct = account
        // A8: the existing-items seam is core-owned and REFUSES rather than degrades —
        // locked, or a personal vault that hasn't hydrated/synced yet, must never plan
        // against an empty `existing` (that would silently disable the dedupe). Mirrors
        // the Android ViewModel's gate exactly.
        if (eng == null || acct == null || eng.vaultInfos().none { it.vaultId == acct.personalVaultId }) {
            importError = "Couldn’t check your vault for items you already have — unlock and sync first, then try the import again."
            return
        }
        // BOUNDED read (mirrors Android's readBounded): the cap is enforced while
        // streaming, so a mislabeled multi-GB pick is rejected without being buffered.
        val bytes = try {
            file.inputStream().use { readBounded(it, CsvImport.MAX_BYTES) }
        } catch (t: Throwable) {
            // #23: local read failure → canon file copy (the bytes never left the device — never
            // network copy, never the raw exception text).
            importError = HouseholdCopy.forImportError(t); return
        }
        if (bytes == null) { importError = friendlyImport("too_large"); return }
        try {
            val parsed = CsvImport.parse(bytes)
            importFormat = parsed.format
            importMangled = looksHtmlMangled(parsed)
            importRowOrdinals = CsvImport.rowOrdinalsByLine(bytes) // A9, same reader as parse
            // Vault-aware plan (F75): `existing` = the DESTINATION vault's light projections,
            // built by the core-owned builder — never raw item lists mapped here (A8).
            // S2: default destination = personal; ONE variable feeds the projections here and
            // (as importVaultId) the eventual importAll. The picker re-plans via importSetVault.
            val dest = acct.personalVaultId
            importParsed = parsed
            importVaultId = dest
            importPlan = CsvImport.plan(parsed, eng.importProjections(dest)) { acct.newItemId() }
        } catch (e: CsvImport.ImportException) {
            importError = friendlyImport(e.code)
        } catch (t: Throwable) {
            importError = HouseholdCopy.forImportError(t) // #23: canon copy, never t.message
        }
    }

    /**
     * Encrypt-and-push the planned items. Reuses plan.items on every call so a mid-import
     * failure is fixed with Retry (idempotent replay of the same itemIds), NOT a re-parse.
     */
    /**
     * S2: switch the import's destination vault — RE-PLANS the parsed file against that
     * vault's projections (the F75 dedupe is per-vault; a plan fingerprinted against one
     * vault must never commit into another). Plan and importVaultId are assigned together
     * after the off-thread plan, and importConfirm reads them together — the invariant is
     * structural. importBusy covers the re-plan: Confirm disables and re-entry no-ops.
     */
    fun importSetVault(vaultId: String) {
        val acct = account ?: return
        val eng = engine ?: return
        val parsed = importParsed ?: return
        // Web importLocked parity: after an import ATTEMPT (error = partial, done = landed)
        // a re-plan would mint new ids — breaking Retry's idempotent replay and duplicating
        // the already-landed rows into the new destination. Only Retry or Dismiss remain.
        if (importBusy || importError != null || importDone || vaultId == importVaultId) return
        // Refuse-not-degrade (A8), now gating the CHOSEN vault: the picker only offers held
        // vaults, but a sync-time removal can race the click — never re-plan against a vault
        // we no longer hold (it would plan as if the vault were empty).
        if (eng.vaultInfos().none { it.vaultId == vaultId }) {
            importPlan = null
            importError = "That vault isn’t available any more — sync and try the import again."
            return
        }
        importBusy = true; importError = null
        scope.launch {
            try {
                val plan = withContext(Dispatchers.Default) {
                    CsvImport.plan(parsed, eng.importProjections(vaultId)) { acct.newItemId() }
                }
                importPlan = plan
                importVaultId = vaultId
                importProgress = null
            } catch (t: Throwable) {
                importError = HouseholdCopy.forImportError(t) // #23; plan/vault unchanged — still a matched pair
            } finally {
                importBusy = false
            }
        }
    }

    fun importConfirm() {
        if (importBusy) return // state-level: the button's enabled flag lags a frame behind a re-plan
        // S2: plan + destination read together — they were assigned together (importFromFile /
        // importSetVault), which is what keeps the F75 invariant (never re-read the picker).
        val plan = importPlan ?: return
        val dest = importVaultId
        importBusy = true; importError = null; importProgress = 0 to plan.items.size
        scope.launch {
            try {
                engine!!.importAll(plan.items, onProgress = { done, total -> importProgress = done to total }, vaultId = dest)
                // The destination can be deleted INTO GRACE mid-import: denials park (F21) and
                // importAll returns normally — success copy telling the user to delete the CSV
                // would then be a lie. A held/gone destination is not a success.
                if (dest != null && engine?.vaultInfos()?.none { it.vaultId == dest } == true) {
                    importBusy = false
                    importError = "The destination vault was removed while importing — the rows are parked and will land only if it is restored. KEEP the CSV file."
                    return@launch
                }
                importReport = plan.report
                importDone = true
                importBusy = false
                items = engine?.items() ?: emptyList()
            } catch (t: Throwable) {
                importBusy = false
                importError = "Import interrupted — press Retry to finish (no duplicates will be created)."
            }
        }
    }

    fun importDismiss() {
        importPlan = null; importFormat = null; importReport = null
        importError = null; importProgress = null; importBusy = false; importDone = false
        importMangled = false; importVaultId = null; importParsed = null
    }

    private fun friendlyImport(code: String): String = when (code) {
        "too_large" -> "That file is larger than 10 MiB — far bigger than any real password export."
        "too_many_rows" -> "That file has more than 10,000 rows. Split it into smaller files and import each."
        // Universal importer: ONE message on all three clients — no pick exists to key a
        // per-source hint on, and the old bespoke 1Password hint is absorbed into it.
        "unrecognized_header" ->
            "This file isn't a recognized password export. Make sure you exported a CSV (not JSON or a zip) — and if it came from 1Password, that you're on 1Password 8 or newer."
        else -> "That file could not be read ($code)."
    }

    /**
     * Read at most [limit] bytes from [input]; return null if the source is larger (so a
     * multi-GB pick is rejected without ever being buffered in memory). Mirrors Android's
     * readBounded and CsvImport's own size cap, so a file that fits here also passes parse().
     */
    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray? {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val r = input.read(buf)
            if (r < 0) break
            total += r
            if (total > limit) return null
            out.write(buf, 0, r)
        }
        return out.toByteArray()
    }

    /** A10: fires when MULTIPLE parsed values carry HTML entities — one legitimate
     *  "&amp;" in a single note shouldn't cry wolf, a file full of them should. */
    private fun looksHtmlMangled(parsed: CsvImport.Parsed): Boolean {
        var hits = 0
        for (row in parsed.rows) {
            for (v in listOf(row.name, row.url, row.username, row.password, row.notes, row.totp ?: "")) {
                if (HTML_ENTITY.containsMatchIn(v) && ++hits >= 2) return true
            }
        }
        return false
    }

    /** Seed-derived identity short code (spec 01 §5) — read out during sharing verification. */
    fun identityCode(): String? = account?.identityFingerprintShort()

    // ---- attachments ----

    /** Mint the SECRET half of a new attachment: fresh id + random per-file key (spec 02 §6). */
    fun newAttachmentRef(name: String, size: Long): AttachmentRef {
        val acct = account ?: throw IllegalStateException("vault is locked")
        return AttachmentRef(id = acct.newItemId(), name = name, size = size, fileKey = Bytes.toB64(acct.newFileKey()))
    }

    /** Download + decrypt an attachment off the UI thread and write it to [dest] via the
     *  same temp-then-atomic-move discipline as the exports ([writeVerifiedAtomically],
     *  F71): a failed write must never leave a torn file — or destroy a pre-existing
     *  one — at [dest]. Cut O (v2 #17): the clicked row's ref id is published for the
     *  duration ([downloadingAttachmentId]) so the Detail row can show a spinner ON the
     *  file being fetched — a many-second download over a household link used to look
     *  frozen (nothing but the global grey-out moved). */
    fun saveAttachmentTo(ref: AttachmentRef, dest: File) = op {
        downloadingAttachmentId = ref.id
        try {
            withContext(Dispatchers.IO) {
                val bytes = engine!!.downloadAttachment(ref)
                try { writeVerifiedAtomically(dest, bytes) } finally { bytes.fill(0) } // attachment plaintext — wipe our copy
            }
        } finally {
            downloadingAttachmentId = null // op()'s catch owns the error surface; the spinner must not outlive the attempt
        }
        busy = false
        notice = "Saved ${ref.name} to ${dest.absolutePath}"
    }

    // ---- settings / server TOTP ----

    fun openSettings() {
        totpSetupInfo = null
        backupPreflight = null; backupResult = null; csvPreflight = null
        lastExportAt = store.lastExportAt
        screen = DesktopScreen.Settings
        loadTotpStatus()
    }

    /** F74: (re)fetch the server-TOTP status — Pending spins, Failed shows the error AND a
     *  Retry that re-runs exactly this, Ready renders the real enrolled/not-enrolled blocks. */
    fun loadTotpStatus() {
        totpLoad = TotpLoad.Pending; totpStatus = null; totpError = null
        scope.launch {
            runCatching { api!!.totpStatus() }
                .onSuccess { totpStatus = it; totpLoad = TotpLoad.Ready }
                .onFailure { totpError = it.message ?: "couldn't load TOTP status"; totpLoad = TotpLoad.Failed }
        }
    }

    fun closeSettings() {
        totpSetupInfo = null; totpError = null
        screen = DesktopScreen.Vault
    }

    /** Item undelete (feature): open the Trash screen and load the deleted items. */
    fun openTrash() {
        deletedItems = null
        screen = DesktopScreen.Trash
        loadDeletedItems()
    }

    fun loadDeletedItems() = op {
        deletedItems = engine!!.deletedItems()
        busy = false
    }

    /** Item undelete (feature): restore a deleted item, then refresh the trash list + the vault. */
    fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc) = op {
        engine!!.restoreDeleted(itemId, vaultId, doc)
        deletedItems = engine!!.deletedItems()
        refreshItems()
        busy = false
    }

    /** Item undelete (F49): "Delete forever" a tombstoned item, then refresh the trash list. */
    fun purgeDeleted(itemId: String) = op {
        engine!!.purgeDeleted(itemId)
        deletedItems = engine!!.deletedItems()
        busy = false
    }

    fun closeTrash() {
        deletedItems = null
        screen = DesktopScreen.Vault
    }

    fun beginTotpSetup() = totpOp { totpSetupInfo = api!!.totpSetup() }

    fun confirmTotp(code: String) = totpOp {
        totpStatus = api!!.totpConfirm(code.trim())
        totpSetupInfo = null
    }

    fun disableTotp(code: String) = totpOp { totpStatus = api!!.totpDisable(code.trim()) }

    private fun totpOp(block: suspend () -> Unit) {
        busy = true; totpError = null
        scope.launch {
            try { block(); busy = false } catch (t: Throwable) {
                busy = false
                totpError = if (t is ApiException && t.code == "bad_totp_code") {
                    "That code isn't right — check your authenticator and try again."
                } else t.message ?: "something went wrong"
            }
        }
    }

    // ---- export & backup (spec 07) ----

    /**
     * "Back up vault…" step 1: sync first (spec 07 — clients MUST sync before
     * snapshotting; offline → proceed with a "vault as of last sync <time>" note), then
     * open the preflight dialog. Runs under [busy], which maybeIdleLock defers on — the
     * auto-lock cannot yank the engine mid-flow.
     */
    fun backupBegin() {
        val e = engine ?: return
        busy = true; error = null; notice = null
        scope.launch {
            val offline = try {
                syncNow(e); false
            } catch (t: java.io.IOException) {
                true // offline is fine — export the cached snapshot, visibly dated
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "sync failed"; return@launch
            }
            val acct = account
            if (acct == null) { busy = false; return@launch }
            items = e.items()
            backupPreflight = BackupPreflight(ExportPlanner.vaultLines(e, acct), offlineNote(offline))
            busy = false
        }
    }

    fun backupDismiss() { backupPreflight = null }
    fun backupResultDismiss() { backupResult = null }

    /** Live §2.5 attachment plan for the preflight dialog's current vault selection
     *  (pure in-memory reads — cheap enough for recomposition). */
    fun attachmentPlan(selected: Set<String>): AttachmentPlan {
        val e = engine ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        val order = backupPreflight?.vaults?.map { it.vaultId }?.filter { it in selected }
            ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        return ExportPlanner.planAttachments(ExportPlanner.orderedItems(e, order))
    }

    /**
     * "Back up vault…" step 2: build → verify → write [dest] via temp-then-atomic-move
     * (see [writeVerifiedAtomically]), all off the UI thread (saveAttachmentTo's
     * pattern). The catch deliberately does NOT touch [dest]: failures before the move
     * happen entirely in the temp file (the helper cleans it up), so a pre-existing
     * backup at [dest] is never destroyed by a failed re-export — the old
     * `dest.delete()` here turned "one good backup" into "zero backups" whenever
     * build/fetch/verify threw before a byte was written. Success records lastExportAt
     * locally and counts as user activity (touch()).
     */
    fun backupRun(selectedVaults: Set<String>, includeAttachments: Boolean, passphrase: String, dest: File) {
        val e = engine ?: return
        val acct = account ?: return
        busy = true; error = null; backupPreflight = null
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    buildAndWriteBackup(e, acct, selectedVaults, includeAttachments, passphrase, dest)
                }
                store.lastExportAt = System.currentTimeMillis()
                lastExportAt = store.lastExportAt
                touch() // export counts as user activity (spec 07 §2.6 / 01 §8)
                busy = false
                backupResult = result
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "backup failed"
            }
        }
    }

    private suspend fun buildAndWriteBackup(
        e: SyncEngine,
        acct: Account,
        selectedVaults: Set<String>,
        includeAttachments: Boolean,
        passphrase: String,
        dest: File,
    ): BackupResult {
        val crypto = acct.cryptoProvider()

        // Snapshot every input up front (cheap in-memory reads): a concurrent manual lock
        // can close the engine's cache underneath a long build, and reads-then-crypto keeps
        // that window to "attachment downloads fail → named skips", never a torn payload.
        val allLines = ExportPlanner.vaultLines(e, acct)
        val lines = allLines.filter { it.vaultId in selectedVaults }
        val exportItems = ExportPlanner.orderedItems(e, lines.map { it.vaultId })
        // Enumerate undecryptable envelopes (missing VK / newer formatVersion) — but not
        // those of a VK-held vault the user explicitly deselected.
        val deselected = allLines.map { it.vaultId }.toSet() - selectedVaults
        val undecryptable = ExportPlanner.undecryptable(e).filter { it.vaultId !in deselected }
        val formatVersions = e.envelopes().associate { it.itemId to it.formatVersion }

        // §2.5: fetch each opted-in attachment plaintext one at a time through the normal
        // client path; ONE retry, then skip BY NAME — never silently, never fatal. The
        // buffers are held until Backup.build consumes (and zeroes) them; the 64 MiB
        // total-plaintext cap keeps the whole set well below any desktop heap.
        val plan = if (includeAttachments) ExportPlanner.planAttachments(exportItems) else AttachmentPlan(emptyList(), 0L, emptyList())
        val fetched = ArrayList<Pair<PlannedAttachment, ByteArray>>()
        val fetchFailed = ArrayList<String>()
        for (p in plan.included) {
            var bytes: ByteArray? = null
            for (attempt in 0 until 2) {
                bytes = runCatching { e.downloadAttachment(p.ref) }.getOrNull()
                if (bytes != null) break
            }
            if (bytes == null) fetchFailed.add(p.ref.name) else fetched.add(p to bytes)
        }

        try {
            // Manifest fileKeys are FRESH per-section keys (spec 07 §2.4); the docs keep
            // their original server-blob fileKeys verbatim inside the payload.
            val freshKeys = fetched.map { acct.newFileKey() }
            val manifest = fetched.mapIndexed { i, (p, bytes) ->
                BackupAttachmentEntry(
                    section = i + 1, attachmentId = p.ref.id, itemId = p.item.itemId,
                    name = p.ref.name, size = bytes.size.toLong(), fileKey = Bytes.toB64(freshKeys[i]),
                )
            }
            val payload = BackupPayload(
                exportedAt = System.currentTimeMillis(), // call-site clock; core takes it as data
                origin = baseUrl,
                userId = acct.userId,
                identityFingerprint = acct.identityFingerprintShort(),
                vaults = lines.map { BackupVault(it.vaultId, it.type, it.name, it.role) },
                items = exportItems.map { BackupItem(it.itemId, it.vaultId, formatVersions[it.itemId] ?: 1, it.updatedAt, it.doc) },
                attachments = manifest,
                skipped = BackupSkipped(undecryptable, plan.overCap, fetchFailed),
            )

            // spec 01 §1 production KDF params (live policy when known), clamped to the
            // §2.2 open() ceilings so the file we produce is always re-openable.
            val policyParams = policy?.kdfParams ?: KdfParams.DEFAULT
            val kdfParams =
                if (policyParams.ops <= Backup.MAX_KDF_OPS && policyParams.memBytes <= Backup.MAX_KDF_MEM_BYTES) policyParams
                else KdfParams.DEFAULT

            // Build to an in-memory buffer, verify, THEN write the file (spec 07 §2.6
            // write-discipline: verify before declaring success, never leave a partial
            // file). In-memory is deliberate: the §2.5 64 MiB attachment-plaintext cap +
            // items keeps the container comfortably below the heap, and it lets us verify
            // the EXACT bytes we are about to persist before the disk sees a single one.
            val out = java.io.ByteArrayOutputStream()
            val sections = fetched.mapIndexed { i, (_, bytes) -> Backup.AttachmentSection(freshKeys[i]) { bytes } }
            Backup.build(
                crypto = crypto, passphrase = passphrase,
                fileId = acct.newItemId(), kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES),
                kdfParams = kdfParams, payload = payload, attachments = sections,
            ) { out.write(it) }
            val file = out.toByteArray()

            // Verify from the produced bytes: re-open section 0 under the same passphrase
            // and decrypt every attachment section's final tag — single pass (§2.6).
            val opened = Backup.open(crypto, passphrase, file)
            if (opened.payload != payload) throw IllegalStateException("backup verification failed — the written payload does not round-trip")
            for (entry in opened.payload.attachments) {
                val plain = opened.readAttachment(entry)
                val ok = plain.size.toLong() == entry.size
                plain.fill(0)
                if (!ok) throw IllegalStateException("backup verification failed — attachment \"${entry.name}\" does not round-trip")
            }

            writeVerifiedAtomically(dest, file)
            return BackupResult(exportItems.size, lines.size, manifest.size, plan.overCap, fetchFailed)
        } finally {
            // Backup.build zeroes each plaintext it consumed; a throw before/during build
            // leaves stragglers — zero them all (idempotent).
            fetched.forEach { it.second.fill(0) }
        }
    }

    /** "Export for another password manager…" step 1: sync (same offline posture as the
     *  backup), then the warning-gated preflight — by NAME, never counts (spec 07 §1). */
    fun csvBegin() {
        val e = engine ?: return
        busy = true; error = null; notice = null
        scope.launch {
            val offline = try {
                syncNow(e); false
            } catch (t: java.io.IOException) {
                true
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "sync failed"; return@launch
            }
            val acct = account
            if (acct == null) { busy = false; return@launch }
            val docs = orderedDocs(e, acct)
            items = e.items()
            csvPreflight = CsvPreflight(ExportCsv.warnings(docs), docs.count { it.type == "login" }, offlineNote(offline))
            busy = false
        }
    }

    fun csvDismiss() { csvPreflight = null }

    /** CSV step 2: write the spec 07 §1 bytes (UTF-8, no BOM) to [dest] via
     *  temp-then-atomic-move (same overwrite safety as the backup: a failure must
     *  never delete a pre-existing file at [dest] — the helper only ever cleans up
     *  its own temp, so no delete in the catch here). */
    fun csvRun(dest: File) {
        val e = engine ?: return
        val acct = account ?: return
        busy = true; error = null; csvPreflight = null
        scope.launch {
            try {
                val count = withContext(Dispatchers.IO) {
                    val docs = orderedDocs(e, acct)
                    val bytes = ExportCsv.write(docs).encodeToByteArray()
                    try { writeVerifiedAtomically(dest, bytes) } finally { bytes.fill(0) } // plaintext passwords — wipe our copy
                    docs.count { it.type == "login" }
                }
                touch()
                busy = false
                notice = "Exported $count logins to ${dest.absolutePath}. Delete the CSV once the other manager has imported it."
            } catch (t: Throwable) {
                busy = false; error = t.message ?: "export failed"
            }
        }
    }

    /**
     * Spec 07 §2.6 write discipline + overwrite safety: write [bytes] to a temp file in
     * [dest]'s OWN directory (same filesystem → rename-able), verify the ON-DISK bytes
     * (byte-equality with the in-memory buffer the callers already verified — this also
     * transfers the Backup.open verification to the persisted bytes), then move the temp
     * over [dest], atomically where the filesystem supports it. The pre-existing file at
     * [dest] is never touched until a fully verified replacement exists, so a failed
     * re-export can no longer destroy a good old backup.
     *
     * Failure handling, two distinct phases:
     * - write/verify failure → delete ONLY the temp (dest untouched);
     * - move failure (rare; e.g. dest locked on Windows after the non-atomic fallback
     *   started) → deliberately KEEP the temp: on that fallback dest may already be
     *   gone, so the temp can be the only surviving verified copy. The surfaced error
     *   names it. A hard crash mid-export can likewise leave a `.tmp` behind
     *   (deleteOnExit covers normal JVM shutdown); a stray temp never masquerades as a
     *   backup and beats a destroyed one.
     */
    private fun writeVerifiedAtomically(dest: File, bytes: ByteArray) {
        val dir = dest.absoluteFile.parentFile ?: File(System.getProperty("user.dir") ?: ".")
        val tmp = File.createTempFile("andvari-", ".tmp", dir)
        tmp.deleteOnExit() // no-op after a successful move (the path no longer exists)
        restrictToOwner(tmp) // exports can hold plaintext (CSV) — same 0600 posture as the cache
        try {
            tmp.writeBytes(bytes)
            val onDisk = tmp.readBytes()
            val ok = onDisk.contentEquals(bytes)
            onDisk.fill(0) // the CSV path passes plaintext — wipe our read-back copy
            if (!ok) throw IllegalStateException("verification failed — the on-disk bytes do not match what was written")
        } catch (t: Throwable) {
            runCatching { tmp.delete() }
            throw t
        }
        try {
            try {
                Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: AtomicMoveNotSupportedException) {
                Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } catch (t: Throwable) {
            throw IllegalStateException("could not replace ${dest.name}: ${t.message} — the verified export was left at ${tmp.name} in the same folder", t)
        }
    }

    /** All VK-held docs in the pinned export order (vault order, then updatedAt). */
    private fun orderedDocs(e: SyncEngine, acct: Account): List<ItemDoc> {
        val order = ExportPlanner.vaultLines(e, acct).map { it.vaultId }
        return ExportPlanner.orderedItems(e, order).map { it.doc }
    }

    /** "July 14"-style day (spec 03 §11 copy — the deleteVault notice). Falls back
     *  gracefully for a missing time. Private MEMBER by design: it must never collide
     *  with a top-level fmtDay the Sharing UI may declare for its own §11 strings. */
    private fun fmtDay(ms: Long?): String {
        if (ms == null || ms <= 0) return "soon"
        return java.text.SimpleDateFormat("MMMM d", java.util.Locale.getDefault()).format(java.util.Date(ms))
    }

    private fun offlineNote(offline: Boolean): String? {
        if (!offline) return null
        val at = store.lastSyncAt
        val stamp = if (at > 0) {
            java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(at))
        } else "(unknown)"
        return "Offline — this exports the vault as of last sync $stamp."
    }

    fun lock(reason: String = "Locked.") {
        // Retain the ciphertext cache on lock (spec 05 T3); close its handle.
        engine?.close(); api?.close(); api = null; account = null; engine = null
        clearVaultClipboard() // a copied secret must not outlive the unlocked session
        pendingRecoverySecret?.fill(0); pendingRecoverySecret = null; recoveryPhrase = null // §F.7
        pendingPieceId = null // piece binding: cleared WITH the secret it names (B1 teardown)
        pendingCaptureAuthKey = null // (v2 #15): password-equivalent — dies with the session; the gate re-derives at next unlock
        clearSecondary()
        // §6: set FRESH per event — the default serves the manual Lock button; the idle
        // watcher passes "Locked after inactivity.". Never carried stale (B6).
        lockReason = reason
        // §3 reset block (review MED, Android parity): clear the probe-failure flag only when
        // a policy is LOADED — a null-policy failure is CURRENT (nothing re-probes on the way
        // to Welcome), and clearing it would strand enroll in "Checking the server…" with no
        // Retry and no probe.
        if (policy != null) policyFetchFailed = false
        importRequested = false // §2: a pending menu import request must not survive into re-unlock
        screen = DesktopScreen.Unlock(store.load()?.email ?: ""); items = emptyList(); needsUpdateCount = 0
    }

    /**
     * design 2026-07-13 platform-fit §2 — Ctrl+L / menu-bar panic lock. No-op unless a session is
     * bound ([account] != null: from Welcome/Unlock/Loading the key does nothing, so a locked app
     * never navigates); otherwise IDENTICAL to the ungated Vault-toolbar Lock button ([lock]) — it
     * fires unconditionally, discarding an open editor's draft (explicit user intent outranks the
     * draft; the idle-lock's editor grace deliberately does NOT apply) and is safe mid-recovery-gate
     * (the v2 #15 capture-gate invariant: the next unlock re-enters the gate with a fresh phrase, and
     * lock() zeroes pendingRecoverySecret §F.7). When an editor was open the reason line reuses
     * maybeIdleLock()'s "the editor's unsaved changes were discarded" wording (minus the false
     * "after inactivity" lead — this is a deliberate command, not a timeout).
     *
     * Idempotent: a second Ctrl+L (or the menu accelerator double-firing alongside onPreviewKeyEvent)
     * lands here with account == null and returns — the design's "one authoritative shortcut site"
     * rests on exactly this no-op.
     */
    fun panicLock() {
        if (account == null) return
        lock(if (editorOpen) "Locked — the editor's unsaved changes were discarded." else "Locked.")
    }

    fun signOut() {
        if (busy) return
        val session = store.load()
        val a = api
        busy = true; error = null
        scope.launch {
            // AWAIT the server-side revocation (bounded) BEFORE close(): the old
            // fire-and-forget launch raced the teardown below, which cancelled the
            // in-flight logout and left the refresh token valid for ~30 days.
            if (a != null) {
                runCatching { withTimeoutOrNull(5_000) { a.logout() } }
            } else if (session != null && session.accessToken.isNotEmpty()) {
                // LOCKED sign-out (the Unlock screen's "Sign out / use a different
                // account"): no live token-holder exists, but the persisted refresh token
                // is still valid server-side — store.clear() alone would leave it live
                // for ~30 days. Build a short-lived holder purely to revoke it.
                val temp = newApi(session.tokens())
                runCatching { withTimeoutOrNull(5_000) { temp.logout() } }
                temp.close()
            }
            // Close the engine (releases the DB handle — Windows won't delete an open file) first.
            engine?.close(); a?.close(); api = null; account = null; engine = null
            clearVaultClipboard()
            pendingRecoverySecret?.fill(0); pendingRecoverySecret = null; recoveryPhrase = null // §F.7
            pendingPieceId = null // piece binding: see lock()
            pendingCaptureAuthKey = null // (v2 #15): see lock()
            // §4.2: explicit sign-out removes the CURRENT origin's cache for this user — other
            // origins' namespaces are out of this gesture's reach (B2-7: wipe only on explicit
            // remove or that origin's own policy-forbid).
            session?.userId?.let { store.deleteCacheDb(originKey(baseUrl), it) }
            store.clear()
            clearSecondary(); signInTotpRequired = false
            importRequested = false // §2: drop any pending menu import request with the session
            mustChangePassword = false // F58: sign-out drops the account; the flag re-arrives at the next sign-in
            lockReason = null // §6: user-initiated sign-out — the Welcome screen owes no explanation
            // §3 reset block (review MED, Android parity): a null-policy probe failure is
            // current, not stale — keep it so Welcome shows the failure + Retry instead of
            // the dead-end "Checking the server…".
            if (policy != null) policyFetchFailed = false
            busy = false
            screen = DesktopScreen.Welcome; items = emptyList(); needsUpdateCount = 0
        }
    }

    private fun clearSecondary() {
        importDismiss() // the parsed CSV + plan hold every password in the file — never outlive the session
        // (v2 #15)/(Cut O v2 #17): per-session UI slices — the capture gate's error + replaced-
        // phrase notice, the editor mirror + its pre-lock warning, and the per-row download marker
        // die with the session. syncBusy is deliberately NOT reset here: its in-flight continuation
        // clears it itself (B1 identity gates), and a blind reset would disarm the single-flight
        // guard under it.
        recoveryCaptureError = null; recoveryReplacedNotice = null; editorOpen = false; idleLockImminent = false; downloadingAttachmentId = null
        cacheConsentPrompt = false // §5.3: an unanswered prompt dies with the session; re-asks at the next landing
        clearRecoverState() // §F.7 belt: the self-recovery stash never outlives a session teardown
        notice = null; totpStatus = null; totpSetupInfo = null; totpError = null
        backupPreflight = null; backupResult = null; csvPreflight = null
        // F19: drop any in-flight move state + memoized gesture ids/fileKeys on lock/sign-out.
        moveError = null; moveProgress = null; moveGestures.clear()
        // §7 teardown (N3): the ENTIRE lifecycle/sharing slice dies with the session — the
        // engine's notice memory does not survive lock, and stale members/deleted lists must
        // not leak across accounts. Only [lifecycleTick] survives (monotonic memo key — a
        // reset to 0 could collide with a remembered key from the previous session).
        lifecycleNotices = emptyList(); incomingTransfers = emptyList(); transferOwnerNames = emptyMap()
        sharingMembers = emptyMap(); deletedVaults = emptyList(); heldVaults = emptyList()
        sharingSettingsVaultId = null; undecryptableSharedVaultCount = 0
        copyProgress = null; copiedNote = null; copyVaultId = null; copyOpVaultId = null
        // A-escrow (P4 parity): the ReSealCard moves to the global AttentionArea — a
        // "Later"-deferred stale flag must not linger past the session (the screen gate is
        // belt; this is the braces). A fresh unlock/sign-in re-reads it from accountKeys.
        escrowStale = false; escrowFingerprint = ""
    }

    /** Last-known org offlineCacheAllowed for the CURRENT origin — live policy first, then that
     *  origin's persisted fallback (spec 02 §8; per-origin per §4.2 — origin A's stance never
     *  governs origin B's cold start). */
    private fun orgCacheAllowed(): Boolean =
        policy?.offlineCacheAllowed ?: store.orgCacheAllowed(originKey(baseUrl))

    /**
     * §5.3 (B1-4): may anything land at rest for the CURRENT origin? Org allowance (tighten-only,
     * §2.3) AND this device's per-origin consent — which is default-OFF (null = never asked ⇒ OFF),
     * so the org's `true` is necessary but never sufficient. Structurally incapable of relaxing:
     * both legs must independently say yes.
     */
    private fun durableCacheEnabled(): Boolean =
        orgCacheAllowed() && store.cacheConsent(originKey(baseUrl)) == true

    /**
     * Record a freshly-fetched policy in UI state + the persisted offline fallbacks. THE one
     * write path into [policy] — §2.3 (B1-1): the device-exposure timers are CLAMPED here, so
     * every downstream consumer (maybeIdleLock, the Ui.kt clipboard copy sites) reads
     * structurally-bounded values and no server can disable the auto-lock or pin the clipboard.
     * [key] names the PROBED origin (§4.2) — async callers capture it before awaiting the fetch
     * so a mid-flight switch can't cross-write another origin's fallbacks.
     */
    private fun applyPolicy(p: ClientPolicy, key: String = originKey(baseUrl)) {
        policy = p.copy(
            autoLockSeconds = clampAutoLockSeconds(p.autoLockSeconds),
            clipboardClearSeconds = clampClipboardClearSeconds(p.clipboardClearSeconds),
        )
        store.setOrgCacheAllowed(key, p.offlineCacheAllowed)
        store.setOriginAutoLockSeconds(key, clampAutoLockSeconds(p.autoLockSeconds))
    }

    /** Persist accountKeys for offline unlock ONLY when the org allows AND this device consented
     *  (spec 02 §8 + §5.3) — into the CURRENT origin's namespace (§4.2). */
    private fun persistAccountKeys(userId: String, keys: io.silencelen.andvari.core.model.AccountKeys) {
        val key = originKey(baseUrl)
        if (durableCacheEnabled()) store.saveAccountKeys(key, userId, keys) else store.clearAccountKeys(key, userId)
    }

    /** Enforce offlineCacheAllowed=false / a definitive auth rejection: drop BOTH the vault DB and
     *  the cached keys — for the NAMED origin's namespace ONLY (§4.2, B2-3: every caller passes
     *  the origin whose verdict triggered the purge; no path wipes globally any more). */
    private fun purgeOfflineData(key: String, userId: String) {
        store.deleteCacheDb(key, userId)
        store.clearAccountKeys(key, userId)
    }

    /**
     * F61 KDF upgrade (spec 01 §7, design 2026-07-10 §4) — the desktop mirror of Android's
     * AndvariViewModel.runKdfUpgrade + KdfReKey.maybeUpgrade (app-android is not shared, so the
     * best-effort re-key is inlined here over the core [KdfUpgrade.shouldUpgrade] gate + core crypto).
     * After a full-master-password unlock WITH server connectivity, if the org policy raised the
     * Argon2id cost, transparently re-key with the password the client just verified (the SAME UVK,
     * new KDF params). DETACHED on [Dispatchers.Default] (two Argon2id derivations — never the UI
     * thread) and best-effort: ANY failure is swallowed, the check re-runs at the next online
     * full-password unlock. ZK-preserving — only the derived authKey + re-wrapped UVK cross the wire,
     * via the existing `PUT /account/password`. Callers MUST have excluded the offline case and the
     * pending recovery-capture gate; [mustChangePassword] (A5), a missing live policy, and the
     * [KdfUpgrade.shouldUpgrade] fence are re-checked here. NEVER on quick-unlock (desktop has none).
     */
    private fun runKdfUpgrade(userId: String, password: String, keys: io.silencelen.andvari.core.model.AccountKeys) {
        // A5: never silently re-key a live admin recovery temp password — the server's changePassword
        // clears mustChangePassword=0, so a re-key would erase the nudge. This is the in-memory F58
        // flag: set from the login response and (like the F58 banner) surviving lock() within a run,
        // so a returning unlock() inside the same session is guarded; it resets on app restart.
        if (mustChangePassword) return
        val pol = policy ?: return // live-fetch-only ([applyPolicy]) — never a stale persisted value
        val a = api ?: return
        val acct = account ?: return
        if (!KdfUpgrade.shouldUpgrade(keys.kdfParams, pol.kdfParams)) return
        scope.launch(Dispatchers.Default) {
            runCatching {
                val crypto = createCryptoProvider()
                val newSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
                val newParams = pol.kdfParams
                val mkNew = Keys.masterKey(crypto, password, newSalt, newParams)
                val authNew = Bytes.toB64(Keys.authKey(crypto, mkNew))
                val wrapNew = Keys.wrapKey(crypto, mkNew)
                // The UVK never changes across a KDF upgrade (spec 01 §4/§7) — re-wrap the SAME UVK
                // under the new wrapKey. The egress copy is zeroed whatever happens.
                val uvk = acct.uvkCopyForPlatformWrap()
                val wrappedUvkNew = try {
                    Envelope.sealB64(crypto, wrapNew, uvk, Ad.uvk(userId))
                } finally {
                    uvk.fill(0)
                }
                val currentAuth = Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams, crypto)
                a.changePassword(
                    PasswordChangeRequest(
                        currentAuthKey = currentAuth,
                        newAuthKey = authNew,
                        newKdfSalt = Bytes.toB64(newSalt),
                        newKdfParams = newParams,
                        newWrappedUvk = wrappedUvkNew,
                    ),
                )
                // design §4 step 3: keep the offline cache in step, or the next offline unlock derives
                // with stale params and fails. Same gate as persistAccountKeys (org allowance AND
                // per-device consent, §5.3) and the same per-origin home (§4.2).
                if (durableCacheEnabled()) {
                    store.saveAccountKeys(
                        originKey(baseUrl), userId,
                        keys.copy(kdfSalt = Bytes.toB64(newSalt), kdfParams = newParams, wrappedUvk = wrappedUvkNew),
                    )
                }
            }
        }
    }

    private fun bind(a: AndvariApi, acct: Account) {
        touch() // spec 01 §8: the auto-lock timer resets on unlock
        engine?.close()
        api = a; account = acct
        val key = originKey(baseUrl) // §4.2: this session's namespace = the current origin
        // §5.3 (B1-4): at-rest cache needs BOTH the org's allowance and this device's per-origin
        // consent (default OFF — null means the one-time prompt hasn't been answered).
        val allowed = (policy?.offlineCacheAllowed ?: store.orgCacheAllowed(key)) && store.cacheConsent(key) == true
        val newCache = if (allowed) {
            val db = store.cacheDbFile(key, acct.userId)
            db.parentFile?.mkdirs() // ns/<originKey>/<userId>/ — first durable cache for this pair
            sqliteVaultCache(db.absolutePath, acct.userId).also {
                // 0600 on POSIX, best-effort on Windows — same handling as session.json.
                for (suffix in listOf("", "-wal", "-shm")) restrictToOwner(File("${db.path}$suffix"))
            }
        } else {
            // Enforcement backstop, scoped to THIS origin (§4.2): an org-forbid (or missing
            // consent) session runs in memory and leaves no stale DB behind for this pair.
            store.deleteCacheDb(key, acct.userId); InMemoryVaultCache()
        }
        engine = SyncEngine(a, acct, newCache).also { it.hydrate() }
    }

    /** Sync + record the wall-clock time of the last SUCCESS — the timestamp the spec 07
     *  offline-export note shows ("vault as of last sync <time>"). */
    private suspend fun syncNow(e: SyncEngine) {
        e.sync()
        store.lastSyncAt = System.currentTimeMillis()
    }

    private fun restrictToOwner(f: File) {
        if (!f.exists()) return
        runCatching { f.setReadable(false, false); f.setReadable(true, true); f.setWritable(false, false); f.setWritable(true, true) }
    }

    private fun refreshItems() {
        items = engine?.items() ?: emptyList()
        needsUpdateCount = engine?.needsUpdateCount() ?: 0
        busy = false; error = null
        refreshLifecycle() // A-funnel: every item refresh re-reads the cheap lifecycle surfaces
    }

    private fun toVault() {
        screen = DesktopScreen.Vault
        items = engine?.items() ?: emptyList()
        needsUpdateCount = engine?.needsUpdateCount() ?: 0
        lockReason = null // §6: successful unlock / sign-in — the line must never carry stale
        recoveryPhrase = null // §F.7: the shown-once display form must not survive landing
        recoveryReplacedNotice = null // gate-scoped (the CURRENT piece was captured) — never follows into the vault
        busy = false; error = null
        // §5.3 (B1-4): the one-time post-first-unlock durable-cache consent prompt — only where
        // this (device, origin) never answered AND the org doesn't forbid the cache (a forbid
        // leaves nothing to consent to). Continuity installs were adopted consent=ON (§4.2
        // one-shot) and never see it.
        if (store.cacheConsent(originKey(baseUrl)) == null && orgCacheAllowed()) cacheConsentPrompt = true
        refreshLifecycle() // A-funnel: offers/notices delivered by the unlock sync show at once
    }

    /**
     * #23: the ENROLL surface's error map. Surface-specific refusal codes keep their per-client
     * phrasing at the surface (the HouseholdCopy contract — web `enrollError` is the twin table;
     * wording adapted to the desktop's sheet toggle where web says "reload"); everything else
     * delegates to the shared canon. The H1 branch pins the SIGN-IN-context sentence (an enroll
     * is a credential ceremony — byte-equal to what this screen always showed); the old desktop
     * `friendlyError` duplicate of the canon's ten lifecycle rows is deleted in favor of
     * [HouseholdCopy.forError] (see [op]).
     */
    private fun enrollError(t: Throwable): String {
        if (t is ApiException) when (t.code) {
            // §F.4 register-gate refusals (posture ≠ invite; reachable now the waived toggle
            // exists). The invitee can't fix a mismatch — the admin re-issues the invite.
            "recovery_required" -> return "This invite needs the admin backstop set up — use your printed recovery sheet (“My admin gave me a printed recovery sheet”), or ask your admin to re-send it as a member-only invite."
            "escrow_not_allowed_when_waived" -> return "This invite is set to “member-only” (no admin backstop) — set up without the recovery-sheet step, or ask your admin for a new invite."
            // Invite/register refusals (web enrollError rows) — these used to fall through as the
            // server's raw message.
            "invalid_invite" -> return "That invite code is not valid."
            "invite_used" -> return "That invite has already been used. Already set up this account? Switch to Sign in."
            "invite_expired" -> return "That invite has expired."
            "email_taken" -> return "An account with that email already exists."
            "invite_email_mismatch" -> return "This invite was created for a different email address — ask your admin for a new invite."
            "escrow_fingerprint_mismatch" -> return "Recovery fingerprint mismatch — do not proceed; contact your admin."
        }
        return if (t is KdfPolicyViolationException) HouseholdCopy.WEAK_KDF_SIGN_IN else HouseholdCopy.forError(t)
    }

    private fun op(map: (Throwable) -> String = HouseholdCopy::forError, block: suspend () -> Unit) {
        busy = true; error = null; notice = null
        scope.launch {
            try {
                block()
            } catch (e: UpgradeRequiredException) {
                // A 426 is not a per-action error — this desktop build is too old for the
                // server's pin. Surface the blocking upgrade screen instead of a toast.
                busy = false
                upgradeRequired = "This andvari server requires a newer desktop app. Download the latest from ${baseUrl}/downloads."
            } catch (t: Throwable) {
                // #23: the shared household canon replaces the deleted desktop friendlyError —
                // its ten vault-lifecycle rows live byte-equal in HouseholdCopy's code map, and
                // the `t.message` fallback is gone for good (the canon NEVER returns raw wire
                // text). Auth-shaped flows pass their context mapper ([HouseholdCopy.forSignInError]
                // / forUnlockError / [enrollError]); everything else takes the general map.
                busy = false; error = map(t)
            }
        }
    }

    private fun deviceName(): String = "${System.getProperty("os.name")} desktop"

    /** Wire platform tag from the JVM OS: "windows" or "linux" (the only jpackage targets). */
    private fun desktopPlatform(): String =
        if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) "windows" else "linux"

    private companion object {
        const val POLL_INTERVAL_MS = 5L * 60 * 1000 // spec 03 §6 poll interval

        // Cut O (v2 #17) timeout tiers — see newHttpClient()/runSync() for the full rationale:
        /** TCP/TLS connect cap on EVERY desktop client (java.net.http ships with none). */
        const val CONNECT_TIMEOUT_MS = 10_000L
        /** Whole-cycle cap on the sync path (poll/focus/Refresh) — it never carries attachment
         *  bytes, so 60 s is generous for a policy probe + queued envelope pushes + a delta pull. */
        const val SYNC_TIMEOUT_MS = 60_000L
        /** Full-request cap for the small recovery calls (self-setup / confirm — small JSON, no
         *  streaming), applied per call via withTimeoutOrNull now that they ride the shared core
         *  client (the Cut O bound, kept across the A.3 swap: a black-holed send must neither
         *  leak a fire-and-forget coroutine nor hold [busy] open-endedly). */
        const val RECOVERY_CALL_TIMEOUT_MS = 30_000L

        /** (v2 #15): ceiling on the editor's pre-lock grace (see editorGraceMs). */
        const val EDITOR_LOCK_GRACE_MAX_MS = 5L * 60 * 1000

        /** Piece binding (design 2026-07-13 §3): the STATIC replaced-phrase conflict copy —
         *  verbatim across all surfaces; never interpolate anything near it (§F.7). */
        const val RECOVERY_REPLACED_NOTICE =
            "This recovery phrase was replaced — a newer one was created, possibly from another device. A fresh phrase will be shown; discard any phrase you saved before it."

        /** A10's pinned pattern — the entities a LastPass in-page export mangles values with. */
        val HTML_ENTITY = Regex("&(amp|lt|gt|quot|#\\d+);")

        // H2 §M-D5 quiet update-channel lines (one muted Settings sentence each — deliberately
        // NOT error-toned, NOT a banner: a sig-stripping server must not get a scary lever).
        const val UPDATE_UNVERIFIED_NOTICE =
            "Updates: the server's update listing couldn't be verified, so no update will be offered from it. Your vault and sync are unaffected."
        const val UPDATE_STALE_NOTICE =
            "Updates: the server's update listing hasn't been re-signed in a while — if you're expecting an update, mention it to your admin."
    }
}
