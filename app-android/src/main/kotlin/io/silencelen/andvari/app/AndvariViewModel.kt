package io.silencelen.andvari.app

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.AttachmentPlan
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupPreflight
import io.silencelen.andvari.core.client.BackupRequest
import io.silencelen.andvari.core.client.BackupResult
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.CopyDeniedException
import io.silencelen.andvari.core.client.CsvPreflight
import io.silencelen.andvari.core.client.ExportPlanner
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.PlannedAttachment
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.DeletedVaultInfo
import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.HeldVaultInfo
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.IncomingTransfer
import io.silencelen.andvari.core.client.ItemChangedException
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LifecycleNotice
import io.silencelen.andvari.core.client.MoveGesture
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.VaultMemberSummary
import java.io.File
import java.io.IOException
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

// P5 (design 2026-07-10): copy for the blocking 426 "Update required" screen. Android updates
// come from the DEVSTORE (not /downloads, which is the desktop/web/extension channel), so the
// wording differs from desktop's. Set into UiState.upgradeRequired from op() and backgroundSync()
// when the server pins minVersion above this build; kept here so both catch sites stay identical.
private const val UPGRADE_REQUIRED_MSG =
    "This andvari server needs a newer version of the app. Update from the devstore, then reopen andvari."

// F26 (N2 design 2026-07-10 §6/B6): the pinned lock/session-end reason strings — web's exact
// copy ("Locked after inactivity." is native-only). The "device revoked" string is unreachable
// on Android (no server-events client — a dead token surfaces as a plain 401), so no revoked
// variant exists here; do not invent one.
private const val REASON_LOCKED = "Locked."
private const val REASON_IDLE = "Locked after inactivity."
private const val REASON_SESSION_ENDED = "Your session ended — sign in again."

// §F.7/§F.9 (desktop v2 #15 parity): the idle-reason variant for a lock that lands mid-reveal —
// the shown-once phrase died unconfirmed, and the vault-entry capture gate re-issues a fresh one
// at the next unlock. Desktop's exact copy; not a new session-end class (the rule above bans a
// REVOKED variant, not this honesty line).
private const val REASON_IDLE_RECOVERY =
    "Locked after inactivity. Your recovery phrase was not confirmed — you'll be shown a fresh one after you unlock."

// Piece-binding (design 2026-07-13 §3): the STATIC replaced-phrase notice — shown when a bound
// confirm is refused `409 recovery_piece_stale` (a concurrent setup, possibly on another device,
// rotated the piece away). No secret material, no interpolation (§F.7). Shared by the capture
// gate (which re-runs setup+reveal under it) and the enroll path (which proceeds unconfirmed —
// the vault-entry gate re-fires at the next entry and heals). Internal so both gate screens in
// MainActivity render the same pinned copy.
internal const val RECOVERY_PHRASE_REPLACED_NOTICE =
    "This recovery phrase was replaced — a newer one was created, possibly from another device. " +
        "A fresh phrase will be shown; discard any phrase you saved before it."

sealed interface Screen {
    data object Loading : Screen
    data object Welcome : Screen
    data class Unlock(val email: String) : Screen
    data object Vault : Screen
    data object Sharing : Screen
    data object Settings : Screen
    data object Trash : Screen
    data object AutofillStatus : Screen
    // Shown-once recovery-phrase gate (design 2026-07-12 §F.4/§F.7): the per-member self-service
    // piece is MANDATORY, so a member who never SEES it is silently unrecoverable. This screen
    // reveals it once — after a fresh enroll, or a fresh piece via the RecoveryCapture gate below —
    // and makes the user type it back before the vault opens. Un-skippable (no back/skip) — the
    // silent-total-loss guard.
    data object RecoverySetup : Screen
    // §F.9 vault-entry capture gate, native (desktop RecoveryCapture / web RecoveryCaptureGate
    // parity): reached from unlock/sign-in when the server reports recoveryConfirmed=false — an
    // interrupted reveal (idle lock / process death mid-RecoverySetup destroyed the shown-once
    // phrase before the user typed it back) or a pre-flag migration account. Commits a FRESH piece
    // (PUT /recovery/self-setup, which does NOT flip the flag), then hands off to the same
    // un-skippable RecoverySetup reveal; only the type-back confirm — BOUND to the pieceId the
    // setup minted and AWAITED (piece-binding design 2026-07-13 §3) — flips recoveryConfirmed.
    // Offline unlocks never gate (the setup PUT needs the network anyway).
    data object RecoveryCapture : Screen
    // Self-service forgot-master-password recovery (design 2026-07-12 §F.3; recovery-cut-2's
    // deferred native half; web Recover.tsx twin): email + saved recovery phrase →
    // POST /recovery/self/verify, then a fresh master password → Account.recover →
    // POST /recovery/self/commit. Pre-session (both endpoints are unauthenticated), reached
    // from the Unlock screen's "Forgot your master password?" signpost — [email] prefills
    // from the stored session, exactly like [Unlock].
    data class Recover(val email: String) : Screen
}

data class UiState(
    val screen: Screen = Screen.Loading,
    val items: List<VaultItem> = emptyList(),
    // Held envelopes newer than this build can decrypt (fail-closed) — the vault list
    // shows them as a one-line "N items need an app update" banner instead of nothing.
    val needsUpdateCount: Int = 0,
    val policy: ClientPolicy? = null,
    // N2 §3 (design 2026-07-10): the last ENROLL-FEEDING policy probe (start / setBaseUrl /
    // retryPolicy) failed — Welcome/Enroll shows the web-parity "couldn't load settings"
    // message + Retry instead of the "no recovery key configured" lie. Deliberately NEVER set
    // by the 5-min background poll: unlike web (which nulls policy on failure), natives keep
    // the last-known policy for the offline gates (cacheAllowed, clipboard windows), so a
    // transient poll failure must not repaint Welcome. Cleared on every fetch success
    // (applyPolicy) and at change time by a deliberate server-URL change (setBaseUrl, which
    // also nulls the old policy → the neutral probe-in-flight state). The lock()/signOut()
    // reset blocks clear it ONLY when a policy is loaded — a null-policy failure is current,
    // not stale, and must keep its Retry affordance on Welcome.
    val policyFetchFailed: Boolean = false,
    // F26 (N2 §6/B6): why the vault locked / the session ended — one quiet secondary line on
    // the Unlock screen (and the sign-in surface for the session-end case). Set fresh by each
    // lock()/session-end path (never carried across events); cleared on successful unlock and
    // sign-in (toVault) and left null by a deliberate, user-initiated sign-out.
    val lockReason: String? = null,
    val busy: Boolean = false,
    // F74: quiet background/periodic sync runs under THIS flag, never `busy` — enable-state
    // of every user affordance (Save, buttons, dialogs) keys off `busy` ONLY, so an offline
    // sync stall can't grey the editor out mid-typing. Not mirrored into the autolock-defer
    // signal either (see the init collector).
    val syncing: Boolean = false,
    // F58: the last login/register response's mustChangePassword — a recovery TEMP password
    // is the live credential. Drives the prominent, NON-dismissable banner (MainActivity)
    // directing the user to change it in the WEB app; persists across nav/lock (backed by
    // SessionStore.mustChangePassword) until a fresh login returns false.
    val mustChangePassword: Boolean = false,
    // P5/A9 (design 2026-07-10): a 426/upgrade_required from ANY server contact (a user op or
    // the 5-min backgroundSync poll) pins this build out. Non-null → AndvariApp swaps the whole
    // app for a blocking "Update required" screen that carries a sign-out escape (A9). Cleared
    // ONLY by signOut() (the escape); never on op/sync success — updating from the devstore +
    // relaunch is the intended exit, so nothing in-session silently dismisses it.
    val upgradeRequired: String? = null,
    val error: String? = null,
    val notice: String? = null,
    val baseUrl: String = SessionStore.DEFAULT_BASE_URL,
    // Wave-3 endpoint switch (design 2026-07-15 §4.3):
    //  - [trustGate]: non-null while the anti-phishing raw-origin gate is shown before ANY serverUrl
    //    change (manual ServerField, invite repoint, or launch-reconcile Finish).
    //  - [pendingSwitch]: non-null while an invite-driven repoint is committed-to-attempt but
    //    enrollment hasn't SUCCEEDED (B2-6) — Welcome hides sign-in + the ServerField and offers only
    //    "complete enrollment" / "cancel and return to the previous origin".
    //  - [pendingReconcile]: non-null at launch when a persisted [PendingServer] marker survived a
    //    restart uncommitted (B2-9) — Welcome shows "Finish setting up at <origin> / Discard".
    val trustGate: TrustGatePrompt? = null,
    val pendingSwitch: PendingSwitchUi? = null,
    val pendingReconcile: PendingServer? = null,
    val loginTotpRequired: Boolean = false,
    val totpStatus: TotpStatus? = null,
    val totpSetup: TotpSetupResponse? = null,
    val totpMessage: String? = null,
    // CSV import (spec 06) — a preview/plan kept across a retry so an interrupted import
    // replays the SAME itemIds idempotently instead of duplicating.
    val importPlan: CsvImport.ImportPlan? = null,
    val importFormat: CsvImport.ImportFormat? = null,
    val importReport: CsvImport.ImportReport? = null,
    val importError: String? = null,
    val importProgress: Pair<Int, Int>? = null,
    val importBusy: Boolean = false,
    val importDone: Boolean = false,
    // S2: the import's DESTINATION vault. Always set in the SAME copy() as importPlan
    // (importParse / importSetVault) and read from one snapshot in importConfirm — the
    // F75 dedupe fingerprints the plan against this vault, so plan and commit must never
    // name different ones. Survives importDone so the summary can name the vault.
    val importVaultId: String? = null,
    // Universal importer (design 2026-07-11): open flag for the ONE import sheet — no
    // source pick exists any more; header detection alone decides how the file is read.
    // The nullable note is the post-parse A10 LastPass HTML-mangle info line, which
    // survives the universal cut because it is content-based, never pick-based (pin 2).
    val importSourceSheet: Boolean = false,
    val importMangleNote: String? = null,
    /** A9: physical file line → 1-based data-row ordinal, so a row error reads "row N
     *  (file line M)" even when a multi-line quoted note shifts the physical lines. */
    val importRowOrdinals: Map<Int, Int> = emptyMap(),
    // Export & backup (spec 07) — preflight dialogs + post-backup summary.
    val backupPreflight: BackupPreflight? = null,
    val backupResult: BackupResult? = null,
    val csvPreflight: CsvPreflight? = null,
    val lastExportAt: Long = 0,
    // Vault lifecycle (spec 03 §11) — notices banner, verified incoming ownership offers,
    // the Sharing screen's members/deleted/held lists, and bulk-copy / move progress.
    val lifecycleNotices: List<LifecycleNotice> = emptyList(),
    val incomingTransfers: List<IncomingTransfer> = emptyList(),
    /** vaultId → current owner displayName (for the consent card), fetched lazily. */
    val transferOwnerNames: Map<String, String> = emptyMap(),
    /** Owned shared vaultId → members (drives the transfer target picker). */
    val sharingMembers: Map<String, List<VaultMemberSummary>> = emptyMap(),
    val deletedVaults: List<DeletedVaultInfo> = emptyList(),
    val heldVaults: List<HeldVaultInfo> = emptyList(),
    /** DN-1: the vault whose per-vault Settings view the Sharing screen shows (null = the
     *  vault list). VM state, not composition state, per the movePicker precedent —
     *  rotation-safe. Nulled by openSharing (A5: a fresh visit lands on the list), by
     *  lock/sign-out, and ACTIVELY in refreshLifecycle when the id stops resolving (A2 —
     *  a later restore must not resurrect the layer). */
    val sharingSettingsVaultId: String? = null,
    /** F20: count of shared vaults granted to this account whose grant can't be OPENED on THIS
     *  device (sealed to a device key we don't hold, or a newer grant format). Such a grant is
     *  swallowed by hydrate/pull (runCatching over addGrant), so the vault is absent from
     *  [items]/vaultInfos(); this drives a persistent, non-dismissable warning on the vault list.
     *  Recomputed every refreshLifecycle; 0 clears the warning (a later sync opened/revoked it). */
    val undecryptableSharedVaultCount: Int = 0,
    /** Bulk "copy items to Personal first" progress + its post-copy note. A4 (DN-1):
     *  [copyVaultId] scopes both to the SOURCE vault — set alongside copyProgress in
     *  copyItemsToPersonal, kept while the note is live (the screen-level status line
     *  names the vault through it), cleared wherever copiedNote/copyProgress both clear.
     *  The in-panel display gates on it, so another vault's panel never claims the copy.
     *  The in-flight OP is guarded by [copyOpVaultId], never by these. */
    val copyProgress: Pair<Int, Int>? = null,
    val copiedNote: String? = null,
    val copyVaultId: String? = null,
    /** A-copyGate: the rescue copy's NON-display OP guard — the vault whose bulk copy is IN
     *  FLIGHT. Set at copy start, cleared ONLY in the copy's finally; navigation NEVER
     *  touches it (unlike the display [copyVaultId]). While non-null: checkIdleLock (and the
     *  autofill idle gate, via the init collector) defers, deleteVault refuses, and the
     *  Delete/rescue-copy buttons disable — `busy` alone is not a gate (any other op
     *  finishing mid-copy clears it). */
    val copyOpVaultId: String? = null,
    /** F19 move/copy attachment re-encryption progress (Detail screen). */
    val moveProgress: Pair<Int, Int>? = null,
    // F57: the account's escrow is sealed to a superseded org recovery key (re-ceremony) — the
    // vault screen offers a re-seal. escrowFingerprint is the CURRENT org fingerprint (the re-seal
    // target + the value the user verifies against the new printed sheet).
    val escrowStale: Boolean = false,
    val escrowFingerprint: String = "",
    // Shown-once recovery-phrase reveal (design §F.4/§F.7): the base64url display form
    // (MemberRecovery.displayForm) of a self-service recovery secret — a fresh enrollee's, or the
    // fresh piece the §F.9 capture gate committed — held ONLY for the RecoverySetup screen's
    // reveal+confirm gate and nulled the instant the confirm passes. Never persisted (not in
    // SessionStore/DataStore/files), never logged. The RAW secret bytes used for the constant-time
    // confirm live OFF UiState (AndvariViewModel.pendingRecoverySecret) and are zeroed on confirm;
    // only this render-only String reaches the composition.
    val recoveryPhrase: String? = null,
    // §F.4 posture: the enroll sealed NO org escrow (waived) → the phrase is the ONLY recovery
    // path (no admin backstop) and the copy is the stark "gone forever" acknowledgment. Set by
    // enrollOp from the client-derived posture (§F.1 [enrollPosture] — waived unless the member
    // declares a printed sheet). The §F.9 capture gate sets false: the posture is unknowable at
    // unlock (AccountKeys deliberately carries none), and fielded gate accounts enrolled required.
    val recoverySetupWaived: Boolean = false,
    // §F.9 RecoveryCapture screen state (desktop parity): null = the self-setup commit is in
    // flight ("Preparing your recovery phrase…"); non-null = it failed and the gate offers Retry.
    // The gate NEVER proceeds to the vault on failure (a failed commit keeps the gate closed,
    // never leaves a live secret dangling).
    val recoveryCaptureError: String? = null,
    // Piece-binding (design 2026-07-13 §3): a bound confirm was refused 409 recovery_piece_stale —
    // the phrase the user just typed back is DEAD (another device's setup rotated it away
    // mid-gate). Both gate screens render [RECOVERY_PHRASE_REPLACED_NOTICE] while set; cleared on
    // vault landing / lock / sign-out.
    val recoveryReplacedNotice: Boolean = false,
    // Forgot-master-password recovery (Screen.Recover), the two-phase wizard flag (web Recover.tsx
    // step parity): false = phase 1 (email + phrase → verify), true = phase 2 (the phrase checked
    // out — choose a new master password). The verify response + raw secret live OFF UiState
    // (AndvariViewModel.pendingRecover*, §F.7); this render-only flag is all the composition needs.
    val recoverVerified: Boolean = false,
    // Item history (feature): decrypted archived versions of the currently-viewed item, loaded on
    // demand (null = not loaded / loading). Restore a chosen version with saveItem.
    val itemVersions: List<DecryptedItemVersion>? = null,
    // Item undelete (feature): the Trash screen's deleted items (null = not loaded / loading).
    val deletedItems: List<DeletedItemView>? = null,
    // Quick unlock (spec 01 §8.1) — derived, recomputed on unlock / Settings / start:
    //  eligible  = strong biometric present + org allows durable key material + policy < 7d old,
    //  enrolled  = a wrapped-UVK blob exists for this user,
    //  fresh     = enrolled AND within the 30-day periodic-full-password window,
    //  offer     = eligible & not enrolled & offer not dismissed (post-unlock one-time card),
    //  message   = Unlock-screen notice ("it's been 30 days…" / "biometrics changed…").
    val quickUnlockEligible: Boolean = false,
    val quickUnlockEnrolled: Boolean = false,
    val quickUnlockFresh: Boolean = false,
    val quickUnlockOffer: Boolean = false,
    val quickUnlockMessage: String? = null,
)

/** Human label for a detected format — the preview's "From … export" line. Stays under
 *  the universal importer (pin 6: it is FORMAT-keyed, not pick-keyed). Keyed on the core
 *  enum's NAME with an else-fallback (the only remaining format is 1Password, whatever
 *  WS-CORE spelled its constant). */
internal fun importFormatLabel(format: CsvImport.ImportFormat): String = when (format.name) {
    "CHROME" -> "Chrome/Chromium"
    "FIREFOX" -> "Firefox"
    "BITWARDEN" -> "Bitwarden"
    "LASTPASS" -> "LastPass"
    else -> "1Password"
}

/** §F.1 fingerprint-provenance postures (design 2026-07-12) — which human anchor, if any, the
 *  enrollment seals org escrow under. Never "the server said so". */
internal enum class EnrollPosture { Waived, RequiredAffirm, RequiredTyped }

/**
 * Decide the enrollment posture from the two inputs the client actually has — a local port of the
 * web's unit-pinned pure function (web/src/enroll/enrollposture.ts `enrollPosture`; keep in
 * lockstep — core is frozen this wave, so the port lives app-side):
 *  - [linkRfp]: an rfp on an enroll link ⇒ the invitee scanned an IN-PERSON QR off the admin's
 *    screen ⇒ one-tap eyeball affirmation. Android has no enroll-link channel today (the invite
 *    token is typed), so callers pass null — the parameter keeps the port faithful.
 *  - [memberHasSheet]: no rfp — default WAIVED (frictionless, no admin backstop); a member who was
 *    handed a printed recovery SHEET declares it ⇒ the typed-sheet ceremony (the pre-rfp channel).
 * Either "required" branch anchors on a human value; a missing rfp NEVER auto-trusts the server key.
 */
internal fun enrollPosture(linkRfp: String?, memberHasSheet: Boolean): EnrollPosture = when {
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
internal fun effectiveSignupMode(declared: String?): String = when (declared) {
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
internal fun switchDropsSession(oldOrigin: String, newOrigin: String): Boolean =
    OriginNamespace.canonicalOrigin(oldOrigin) != OriginNamespace.canonicalOrigin(newOrigin)

/**
 * The tokens a client rebuilt for [newOrigin] may inherit from a session last held against
 * [oldOrigin] (§4.1 rule 1 / B1-5). A real origin switch inherits NOTHING — null — so no
 * `Authorization` header can ever cross a baseUrl change; a no-op switch keeps the tokens. This is
 * the pure model of what [AndvariViewModel.setBaseUrl] enforces on the Context-bound store/api
 * (which a JVM unit test can't touch): the regression test asserts THIS returns null across a switch.
 */
internal fun inheritedTokensAcrossSwitch(oldOrigin: String, newOrigin: String, oldTokens: Tokens?): Tokens? =
    if (switchDropsSession(oldOrigin, newOrigin)) null else oldTokens

/**
 * What the "Invite code or link" field currently holds (design 2026-07-15 §4.4 Android). The field
 * accepts either a raw invite token (today's behavior) or a full enroll LINK
 * (`<origin>/enroll#a1.…`); the core [EnrollLink.parse] twin (multiplatform, total — null on
 * anything that isn't a link) decides which. Reused, never reimplemented.
 */
internal sealed interface InviteFieldParse {
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
    ) : InviteFieldParse
}

/** Parse the invite field against the current [currentBaseUrl] (design §4.4). Total — a
 *  non-link falls through to [InviteFieldParse.Token]. */
internal fun parseInviteField(raw: String, currentBaseUrl: String): InviteFieldParse {
    val p = EnrollLink.parse(raw) ?: return InviteFieldParse.Token(raw.trim())
    val gate = OriginNamespace.canonicalOrigin(p.o) != OriginNamespace.canonicalOrigin(currentBaseUrl)
    return InviteFieldParse.Link(token = p.t, origin = p.o, email = p.e, rfp = p.rfp, gate = gate)
}

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
)

private val ORIGIN_SPLIT = Regex("^(https?)://(\\[[^\\]]*]|[^/:?#]*)(:[0-9]+)?", RegexOption.IGNORE_CASE)

/** §4.3 render rules: punycode a non-ASCII host + caution; caution an already-`xn--` host (the
 *  homograph vector); caution `http://`. */
internal fun trustGateRender(origin: String): TrustGateRender {
    val trimmed = origin.trim()
    val httpCaution = trimmed.startsWith("http://", ignoreCase = true)
    val m = ORIGIN_SPLIT.find(trimmed)
    val scheme = m?.groupValues?.get(1)?.lowercase() ?: ""
    // `.substringAfterLast('@')` drops any userinfo (defense-in-depth: the manual path already
    // canonicalizes, but a raw origin must resolve to the REAL host, never a `real.host@evil` prefix).
    val host = (m?.groupValues?.get(2) ?: "").substringAfterLast('@')
    val port = m?.groupValues?.get(3) ?: ""
    val nonAscii = host.any { it.code > 0x7F }
    // Fail CLOSED: if IDN.toASCII can't punycode a non-ASCII host, escape its code points rather than
    // rendering the raw homograph the punycode display exists to defeat (§4.3). The caution below still fires.
    val punyHost = if (nonAscii) runCatching { java.net.IDN.toASCII(host) }.getOrNull() else host
    val safeHost = punyHost ?: host.map { if (it.code > 0x7F) "\\u%04x".format(it.code) else it.toString() }.joinToString("")
    // A raw non-ASCII host OR a host already encoded as punycode (`xn--`) is an IDN — the
    // homograph vector spec/05 R8 warns about, whether the attacker sent us Unicode or the encoding.
    val idn = nonAscii || safeHost.split('.').any { it.startsWith("xn--", ignoreCase = true) }
    val display = if (m != null && nonAscii) "$scheme://$safeHost$port" else trimmed
    return TrustGateRender(displayOrigin = display, punycodeCaution = idn, httpCaution = httpCaution)
}

// §4.3 trust-gate copy — pinned as constants so the phishing wording can't drift. Baseline is
// shown always; the enrollment variant (B2-8) ADDS the new-account/password-reuse warning.
internal const val TRUST_GATE_TITLE = "Connect to a different server?"
internal const val TRUST_GATE_BASELINE =
    "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it."
internal const val TRUST_GATE_ENROLLMENT_EXTRA =
    "Your invite was issued by this server. Enrolling creates a NEW account there — it does not move any existing vault. Choose a master password you don't use anywhere else."

/** §4.3 body paragraphs: baseline always, plus the enrollment warning when [enrollment]. Pure so
 *  the copy selection is test-pinned. */
internal fun trustGateBody(enrollment: Boolean): List<String> =
    if (enrollment) listOf(TRUST_GATE_BASELINE, TRUST_GATE_ENROLLMENT_EXTRA) else listOf(TRUST_GATE_BASELINE)

/**
 * §4.1 rule 3: the persisted default origin after a pending invite switch resolves. On enroll
 * SUCCESS the pending [PendingServer.origin] commits; on cancel / failure / reconcile-discard the
 * [PendingServer.previousOrigin] is restored. Pure so a refactor can never silently commit a
 * half-finished switch.
 */
internal fun resolvedDefaultOrigin(pending: PendingServer, enrollSucceeded: Boolean): String =
    if (enrollSucceeded) pending.origin else pending.previousOrigin

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
internal fun reconcileRestoreOnCancel(action: TrustGateAction?, pending: PendingServer?): PendingServer? =
    if (action is TrustGateAction.ReconcileFinish) pending else null

/** The Trust Gate prompt held in UI state while shown. */
data class TrustGatePrompt(
    val render: TrustGateRender,
    val enrollment: Boolean,
    val action: TrustGateAction,
)

/** The in-session pending invite switch (design §4.3 B2-6): while set, Welcome hides sign-in +
 *  the ServerField and offers only "complete enrollment" / "cancel and return to [previousOrigin]". */
data class PendingSwitchUi(val origin: String, val previousOrigin: String)

class AndvariViewModel(
    private val store: SessionStore,
    private val cacheDir: File,
    // Application context — used ONLY for the quick-unlock BiometricManager availability check
    // (never held beyond method scope; the ViewModel outlives Activities, so this must be the
    // application context, which MainActivity's factory passes).
    private val appContext: Context,
) : ViewModel() {
    private val _ui = MutableStateFlow(UiState(baseUrl = store.baseUrl, lastExportAt = store.lastExportAt, mustChangePassword = store.mustChangePassword))
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    init {
        // Cold-start fallback: arm the last-known auto-lock window BEFORE the first policy
        // fetch lands (offline starts must still enforce it, spec 01 §8).
        VaultSession.setAutoLockSeconds(store.autoLockSeconds)
        // Idle auto-lock watcher (1 s resolution). Deliberately viewModelScope, NOT a
        // lifecycle-gated scope: an unlocked-but-backgrounded app keeps ticking (while the
        // process isn't cached-frozen) and drops its keys when the window passes instead of
        // holding them all night. A frozen process is covered by the ON_RESUME check in
        // MainActivity (checkIdleLock runs before the first frame is shown).
        viewModelScope.launch {
            while (true) {
                kotlinx.coroutines.delay(1_000)
                checkIdleLock()
            }
        }
        // Mirror the in-flight-op signal (busy || importBusy || the A-copyGate) into the
        // process-wide VaultSession so the AUTOFILL entry point's idle-expiry check
        // (getIfFresh) defers the hard lock exactly like checkIdleLock() does here — an
        // onFillRequest must never close the engine under a running import/export.
        // Single choke point: every op helper flips busy/importBusy through _ui, so
        // collecting _ui catches them all (no unpaired begin/end calls to leak).
        // A-copyGate: copyOpVaultId rides along for the same reason it defers
        // checkIdleLock — another op finishing mid-copy clears busy, and NEITHER idle
        // observer may yank the engine mid-rescue.
        // `syncing` (F74) is deliberately EXCLUDED: a quiet background sync — which can
        // stall for tens of seconds offline — must not hold the auto-lock open past the
        // policy window. A lock landing mid-sync is safe: the durable queue survives it,
        // and backgroundSync swallows the resulting teardown error instead of surfacing it.
        viewModelScope.launch {
            _ui.collect { VaultSession.setOperationInProgress(it.busy || it.importBusy || it.copyOpVaultId != null) }
        }
    }

    override fun onCleared() {
        // The collector above dies with viewModelScope — never leave a stale
        // "operation in progress" latched, or the autofill idle gate would defer
        // locking forever in a process where only the autofill service remains.
        VaultSession.setOperationInProgress(false)
        super.onCleared()
    }

    /** §4.2 layout: `<noBackup>/ns/<originKey>/<userId>/vault-<userId>.db` (userId fragment
     *  path-safe-laundered — it is server-supplied). Writers mkdirs at the use site. */
    private fun cacheFile(originKey: String, userId: String) =
        File(OriginNamespace.dir(cacheDir, originKey, userId), "vault-${OriginNamespace.pathSafe(userId)}.db")

    private fun deleteCache(originKey: String, userId: String) {
        OfflineData.deleteVaultCache(cacheDir, originKey, userId)
    }

    /** Live policy if known, else the persisted last-known value (offline cold start). */
    private fun cacheAllowed(): Boolean = _ui.value.policy?.offlineCacheAllowed ?: store.cacheAllowed

    /** Persist accountKeys for offline unlock ONLY when the policy permits it (spec 02 §8). */
    private fun persistAccountKeys(keys: io.silencelen.andvari.core.model.AccountKeys) {
        if (cacheAllowed()) store.saveAccountKeys(keys) else store.clearAccountKeys()
    }

    /**
     * Enforce offlineCacheAllowed=false (policy flip): drop the vault DB, cached keys AND the
     * quick-unlock blob (A3/A4 shared helper) — the session itself stays valid.
     *
     * §4.2 (design 2026-07-15, B2-3): [originKey] is the namespace of the origin whose POLICY
     * VERDICT is being enforced — captured by the caller beside its probe, BEFORE any await, so
     * a verdict landing after a racing setBaseUrl still purges the origin it came from and a
     * probe of server B can never touch server A's namespace.
     */
    private fun purgeOfflineData(originKey: String, userId: String) {
        OfflineData.purgeCacheForbidden(cacheDir, store, originKey, userId)
    }

    /**
     * Recompute the derived quick-unlock UI flags from disk + the live session. Cheap; called
     * after any unlock, on the Unlock screen (start), and when Settings opens. All reads are
     * scoped to the CURRENT origin's namespace (§4.2).
     */
    private fun refreshQuickUnlockState() {
        val userId = store.load()?.userId
        val eligible = QuickUnlock.isEligible(appContext, store)
        val enrolled = userId != null && QuickUnlock.isEnrolled(cacheDir, store.currentOriginKey(), userId)
        val fresh = enrolled && userId != null && QuickUnlock.isFresh(store, userId)
        _ui.value = _ui.value.copy(
            quickUnlockEligible = eligible,
            quickUnlockEnrolled = enrolled,
            quickUnlockFresh = fresh,
            // Post-unlock one-time offer card: only while an unlocked session exists.
            quickUnlockOffer = eligible && !enrolled && !store.quickUnlockOfferDismissed && VaultSession.get() != null,
        )
    }

    /** F61 (spec 01 §7): kick a silent KDF re-key when ONLINE and the org policy raised the cost.
     *  Detached (two Argon2id derivations off the Main thread); best-effort. Never while
     *  `mustChangePassword` (A5) or without a server-fetched policy this session (design §4). */
    private fun runKdfUpgrade(userId: String, password: String, keys: AccountKeys) {
        if (store.mustChangePassword) return
        val policy = _ui.value.policy ?: return // set only from a live fetch — never a stale persisted value
        val a = api ?: return
        val acct = account ?: return
        viewModelScope.launch(Dispatchers.Default) {
            KdfReKey.maybeUpgrade(a, store, userId, password, keys, policy, acct)
        }
    }

    // ---- quick unlock (spec 01 §8.1) ----

    /** Enroll quick unlock for the current user (biometric consent prompt). A5: refused while a
     *  recovery temp password is live. A1: refused from a QUICK session with no surviving
     *  full-password stamp (would reset the 30-day clock with no password ever typed). */
    fun enrollQuickUnlock(activity: FragmentActivity) {
        val userId = store.load()?.userId ?: return
        if (store.mustChangePassword) {
            _ui.value = _ui.value.copy(error = "Change your master password first, then you can turn on quick unlock.")
            return
        }
        if (!QuickUnlock.isEligible(appContext, store)) {
            _ui.value = _ui.value.copy(error = "This device has no usable fingerprint or face, or your org doesn't allow it.")
            return
        }
        val prov = VaultSession.get()?.provenance
        val stamp = store.lastFullPasswordUnlockAt(userId)
        if (prov != VaultSession.UnlockProvenance.PASSWORD && stamp <= 0L) {
            _ui.value = _ui.value.copy(error = "Unlock with your master password first, then turn quick unlock on.")
            return
        }
        val acct = account ?: return
        viewModelScope.launch {
            when (val r = QuickUnlock.enroll(activity, cacheDir, store.currentOriginKey(), userId, acct)) {
                is QuickUnlock.Enroll.Ok -> {
                    store.quickUnlockOfferDismissed = true // the toggle is now the control surface
                    refreshQuickUnlockState()
                    _ui.value = _ui.value.copy(notice = "Quick unlock is on for this device.")
                }
                is QuickUnlock.Enroll.Cancelled -> refreshQuickUnlockState()
                is QuickUnlock.Enroll.Failed -> _ui.value = _ui.value.copy(error = r.reason ?: "Couldn't turn on quick unlock.")
            }
        }
    }

    /** Disable quick unlock — wipe the CURRENT origin's blob + key. Never gated (reducing
     *  standing secret material must not require auth, spec 01 §8.1). */
    fun disableQuickUnlock() {
        store.load()?.userId?.let { QuickUnlock.wipe(cacheDir, store.currentOriginKey(), it) }
        refreshQuickUnlockState()
    }

    /** Dismiss the one-time post-unlock enrollment offer card (Settings toggle still available). */
    fun dismissQuickUnlockOffer() {
        store.quickUnlockOfferDismissed = true
        _ui.value = _ui.value.copy(quickUnlockOffer = false)
    }

    /**
     * Quick unlock from the Unlock screen: recover the UVK behind BiometricPrompt, then unlock via
     * the UVK path. Same token/mutex skeleton as [unlock] minus the KDF/stamp (a quick unlock is
     * never a full-password unlock, A1/§7). identityPub verification still runs inside
     * `Account.unlockWithUvk` — a mismatch hard-fails; a stale/foreign UVK wipes the blob (§5).
     */
    fun unlockWithBiometric(activity: FragmentActivity) = op {
        val session = store.load() ?: throw IllegalStateException("no session")
        val userId = session.userId
        val originKey = store.currentOriginKey() // §4.2: this unlock's namespace, captured before any await
        val uvk = when (val r = QuickUnlock.recoverUvk(activity, cacheDir, originKey, userId)) {
            is QuickUnlock.Recover.Ok -> r.uvk
            is QuickUnlock.Recover.Fallback -> { _ui.value = _ui.value.copy(busy = false, quickUnlockMessage = r.reason); return@op }
            is QuickUnlock.Recover.Wiped -> { refreshQuickUnlockState(); _ui.value = _ui.value.copy(busy = false, quickUnlockMessage = r.reason); return@op }
        }
        VaultSession.unlockMutex.withLock {
            VaultSession.get()?.let { toVault(); return@op } // adopt a winner instead of a 2nd holder
            val a = newApi(session.tokens())
            val keys = try {
                a.accountKeys().also { persistAccountKeys(it) }
            } catch (e: IOException) {
                store.loadAccountKeys() ?: run { a.close(); throw e }
            } catch (e: ApiException) {
                a.close()
                // F26: a definitive rejection is a session-end — explain it on the Unlock
                // surface (B6: a dead token is a plain 401 here; there is no revoked variant).
                if (e.status == 401) { OfflineData.purgeRevoked(cacheDir, store, originKey, userId); _ui.value = _ui.value.copy(mustChangePassword = false, lockReason = REASON_SESSION_ENDED) }
                throw e
            } catch (t: Throwable) { a.close(); throw t }
            val acct = try {
                withContext(Dispatchers.Default) { Account.unlockWithUvk(userId, uvk, keys) }
            } catch (t: Throwable) {
                a.close()
                // §5: seed won't open under the recovered UVK → wipe (stale/foreign); an identityPub
                // MISMATCH is a security fault — keep the blob (evidence) and hard-fail.
                if (t is CryptoException && t.message?.contains("identity key mismatch") != true) QuickUnlock.wipe(cacheDir, originKey, userId)
                throw t
            }
            try {
                bind(a, acct, VaultSession.UnlockProvenance.QUICK)
                _ui.value = _ui.value.copy(escrowStale = keys.escrowStale, escrowFingerprint = keys.escrowFingerprint)
            } catch (t: Throwable) {
                if (VaultSession.get()?.api !== a) a.close()
                throw t
            }
        }
        runCatching { syncNow(engine!!) }.onFailure {
            if (it is IOException) _ui.value = _ui.value.copy(notice = "Offline — showing cached data")
            else throw it
        }
        refreshQuickUnlockState()
        toVault()
    }

    /**
     * Record a freshly-fetched policy everywhere it's enforced: UI state, the persisted
     * offline fallbacks, and the process-wide auto-lock gate (shared with autofill).
     *
     * [originKey] is REQUIRED (§4.2): the persisted mirrors are per-origin, and every caller
     * captures the key of the origin it PROBED beside the probe itself (before any await) — a
     * probe result landing after a racing setBaseUrl still files under the origin it came from,
     * never under whatever happens to be current. The timer window is CLAMPED (§2.3/B1-1)
     * before it is persisted or armed — a hostile server cannot disable or stretch auto-lock.
     */
    private fun applyPolicy(p: ClientPolicy, originKey: String) {
        _ui.value = _ui.value.copy(policy = p, policyFetchFailed = false) // N2 §3: any fetch success clears the failure flag
        store.setCacheAllowed(originKey, p.offlineCacheAllowed)
        val autoLock = clampAutoLockSeconds(p.autoLockSeconds) // B1-1: [floor, AUTO_LOCK_MAX_SECONDS]
        store.setAutoLockSeconds(originKey, autoLock)
        store.setPolicyFetchedAt(originKey, System.currentTimeMillis()) // A4: quick-unlock eligibility freshness
        store.bumpServerTimeFloor(originKey, p.serverTime) // A2 (review [2]): the one clock the holder cannot set — per-origin
        VaultSession.setAutoLockSeconds(autoLock)
    }

    // Unlocked state (api/account/engine) now lives in the process-wide VaultSession, shared
    // with the autofill service. These are read-only snapshots over it — nothing is stored on
    // the ViewModel; moving where they live is the only change (all call sites keep working).
    private val api: AndvariApi? get() = VaultSession.get()?.api
    private val account: Account? get() = VaultSession.get()?.account
    private val engine: SyncEngine? get() = VaultSession.get()?.engine

    // Pending attachment picks (ref + plaintext bytes) for the OPEN editor session. Held
    // here, not in Compose state: the ViewModel survives rotation/fold-posture recreation
    // and the bytes can never go into SavedState. The editor UI adds/removes;
    // [closeEditor] clears it (plaintext must not outlive the editor session).
    val editorPendingUploads = mutableListOf<PendingUpload>()

    // The OPEN editor session (open flag + target itemId) also lives HERE, not in the
    // composition: a save completing across an Activity recreation must close the editor
    // the user is actually looking at — a composition-captured close callback died with
    // the old Activity and left the restored editor stuck open. On process death the
    // vault relocks to the Unlock screen, so editor session state is moot there.
    var editorOpen by mutableStateOf(false)
        private set
    var editorItemId by mutableStateOf<String?>(null)
        private set

    /** Doc type for a NEW-item session ([editorItemId] == null): "login" | "card". Part of
     *  the editor session for the same reason the id is — a restored editor after an
     *  Activity recreation must rebuild the SAME kind of blank doc. */
    var editorNewType by mutableStateOf("login")
        private set

    fun openEditor(itemId: String?, newType: String = "login") {
        editorPendingUploads.clear() // a fresh editor session never inherits stale picks
        editorItemId = itemId
        editorNewType = newType
        editorOpen = true
    }

    fun closeEditor() {
        editorOpen = false
        editorItemId = null
        editorPendingUploads.clear()
    }

    /** The item under edit vanished (deleted on another device, tombstone synced): close
     *  instead of rebasing a blank doc onto the existing id — a Save would resurrect it
     *  empty in the personal vault, destroying history/extras/attachments. */
    fun editorTargetVanished() {
        closeEditor()
        _ui.value = _ui.value.copy(notice = "This item was removed on another device.")
    }

    /** Server-declared role for a vault (mirrors web's account.roleFor) — null when unknown. */
    fun roleFor(vaultId: String): String? = account?.roleFor(vaultId)

    private fun needsUpdate(): Int = engine?.needsUpdateCount() ?: 0

    private fun newApi(tokens: Tokens? = null): AndvariApi =
        AndvariApi(store.baseUrl, HttpClient(OkHttp), tokens, { store.updateTokens(it) }) // platform defaults to "android"

    fun start() {
        viewModelScope.launch {
            // §4.3 B2-9: a persisted pendingServer marker means a prior invite switch was left
            // UNCOMMITTED (enrollment success clears it) — baseUrl may already point at that
            // foreign origin. Reconcile ("Finish setting up at <origin> / Discard") BEFORE trusting
            // it or offering sign-in there; the reconcile drives the next steps.
            store.pendingServer?.let { pending ->
                _ui.value = _ui.value.copy(screen = Screen.Welcome, baseUrl = store.baseUrl, pendingReconcile = pending)
                return@launch
            }
            // If the vault was already unlocked in this process (autofill unlocked it first,
            // or the activity was recreated while the process lived), show it straight away —
            // but through the auto-lock gate: an idle-expired leftover session must land on
            // the unlock screen, never flash vault content (spec 01 §8).
            val bound = VaultSession.getIfFresh() != null
            if (bound) {
                _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), needsUpdateCount = needsUpdate(), baseUrl = store.baseUrl)
            }
            val session = store.load()
            // §4.2: capture the PROBED origin's key beside the probe (newApi() reads the same
            // baseUrl) — the async verdict below purges/persists under THIS key, so a racing
            // setBaseUrl can never redirect it onto another origin's namespace.
            val originKey = store.currentOriginKey()
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        applyPolicy(p, originKey) // UI state + persisted fallbacks + auto-lock gate
                        // Policy may forbid the durable cache; honor it the moment we learn it,
                        // deleting any existing file (spec 02 §8) — but only when no live engine holds
                        // it (when bound, a later lock/rebind enforces the purge safely). Scoped to
                        // the probed origin's namespace ONLY (§4.2).
                        if (!p.offlineCacheAllowed && session != null && !bound) purgeOfflineData(originKey, session.userId)
                    }
                    // N2 §3: this probe feeds the Welcome/Enroll gate — record the failure
                    // honestly (the policy itself stays last-known for the offline gates).
                    .onFailure { _ui.value = _ui.value.copy(policyFetchFailed = true) }
            } finally {
                probe.close()
            }
            if (!bound) {
                _ui.value = _ui.value.copy(
                    screen = if (session != null && session.accessToken.isNotEmpty()) Screen.Unlock(session.email) else Screen.Welcome,
                    baseUrl = store.baseUrl,
                )
            }
            // Quick-unlock flags for the Unlock screen (biometric button / stale notice) and the
            // post-unlock offer card. Runs after the policy fetch above so eligibility is current.
            refreshQuickUnlockState()
        }
    }

    fun setBaseUrl(url: String) {
        val newUrl = url.trim().removeSuffix("/")
        // §4.1 rule 1 (B1-5 — HARD MUST): a REAL origin change drops the old origin's access+refresh
        // tokens and in-memory unlock state BEFORE the probe below fires, so the client rebuilt for
        // the new origin (newApi() reads the just-changed baseUrl) can never replay the old bearer
        // token — no `Authorization` header crosses a baseUrl change ([inheritedTokensAcrossSwitch]).
        // A no-op canonical re-entry keeps the session. Old-origin NAMESPACED material (cached keys,
        // vault cache, quick-unlock) is PRESERVED (§4.2/B2-7 — a switch is not a wipe); only the
        // single global session slot is cleared, via [SessionStore.clearSessionTokens].
        val drop = switchDropsSession(store.baseUrl, newUrl)
        store.baseUrl = newUrl
        if (drop) {
            VaultSession.lock() // close the old origin's api/engine before any request goes to the new one
            store.clearSessionTokens()
            // In-flight secret material belongs to the old origin's session — it must not survive
            // into the new one (mirrors lock()/signOut()'s zeroize discipline).
            zeroPendingRecovery(); zeroPendingRecover(); pendingCaptureAuthKey = null
        }
        // §3/B4(4) (review MED, desktop-twin parity): a deliberate URL change nulls the OLD
        // server's policy and clears the flag AT CHANGE TIME, so Welcome renders the neutral
        // "Checking the server…" state during the probe — never the old server's ceremony
        // (whose stale fingerprint would die in Account.enroll's cross-check) and never a
        // stale failure whose enabled Retry could race this probe and clobber its result.
        _ui.value = _ui.value.copy(
            baseUrl = store.baseUrl, policy = null, policyFetchFailed = false,
            // A dropped session leaves nothing unlockable on the new origin — land on Welcome
            // (never flash the old origin's Unlock) and clear the session-derived F58 banner.
            screen = if (drop) Screen.Welcome else _ui.value.screen,
            mustChangePassword = if (drop) false else _ui.value.mustChangePassword,
        )
        // Re-fetch policy against the new server so the recovery fingerprint / pins update
        // immediately (no app restart needed).
        // §4.2 — THE call site the namespacing exists for: this probes the JUST-SET origin, so
        // a forbidding answer purges the NEW origin's (empty) namespace and can no longer
        // destroy the previous server's offline data + account keys. The key is captured here,
        // synchronously with the baseUrl write, so a second setBaseUrl racing this in-flight
        // probe still lands the verdict on the origin that produced it.
        val originKey = store.currentOriginKey()
        viewModelScope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        applyPolicy(p, originKey)
                        // Same policy enforcement as start(): a forbidding server purges ITS OWN
                        // namespace for the stored session's user — never another origin's.
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(originKey, it.userId) }
                    }
                    // A deliberate URL change invalidates the old server's policy (null stays
                    // right) — and the probe against the NEW one failed, so say so (N2 §3);
                    // Welcome must never claim the new server has no recovery key.
                    .onFailure { _ui.value = _ui.value.copy(policy = null, policyFetchFailed = true) }
            } finally {
                probe.close()
            }
        }
    }

    // ---- Wave-3 endpoint switch + anti-phishing trust gate (design 2026-07-15 §4) ----

    /** ServerField "Set" (design §4.4 requirement 3): a MANUAL switch shows the Trust Gate
     *  (baseline copy); Connect commits via [setBaseUrl] (the gate IS the gesture). A canonical
     *  no-op is applied straight through — no gate for re-entering your own origin. */
    fun requestManualSwitchGate(url: String) {
        // §4.4 (review 2026-07-16 MEDIUM): reject a userinfo/path-bearing string that would spoof the gate
        // (`https://real.host@evil.example` shows a reassuring host while the HTTP stack dials evil.example
        // → authKey phishing on the next sign-in). canonicalServerOrigin returns the bare canonical origin
        // the gate shows AND dials, or null to refuse.
        val target = OriginNamespace.canonicalServerOrigin(url)
        if (target == null) {
            _ui.value = _ui.value.copy(error = "Enter a server address like https://example.org — no username, path, or query.")
            return
        }
        if (!switchDropsSession(store.baseUrl, target)) { setBaseUrl(target); return }
        _ui.value = _ui.value.copy(
            trustGate = TrustGatePrompt(trustGateRender(target), enrollment = false, action = TrustGateAction.ManualSwitch(target)),
        )
    }

    /** A foreign-origin enroll link was entered (design §4.4): show the Trust Gate (ENROLLMENT
     *  variant, B2-8). Connect enters the PENDING repoint; [email] seeds the crash marker. */
    fun requestInviteTrustGate(origin: String, email: String) {
        _ui.value = _ui.value.copy(
            trustGate = TrustGatePrompt(trustGateRender(origin), enrollment = true, action = TrustGateAction.InviteRepoint(origin, email)),
        )
    }

    /** Trust Gate → Cancel (the safe default, §4.3): dismiss without any server change. A
     *  launch-reconcile Finish gate is special (B2-6): store.baseUrl already points at the uncommitted
     *  marker origin, so Cancel must return to the reconcile CHOICE (Finish/Discard) — landing on a bare
     *  Welcome would re-expose sign-in against the foreign origin. Manual/invite gates never moved
     *  store.baseUrl (commit is on Connect), so their Cancel is a plain dismiss. */
    fun trustGateCancel() {
        _ui.value = _ui.value.copy(
            trustGate = null,
            pendingReconcile = reconcileRestoreOnCancel(_ui.value.trustGate?.action, store.pendingServer),
        )
    }

    /** Trust Gate → Connect: act on the held [TrustGateAction]. */
    fun trustGateConnect() {
        val gate = _ui.value.trustGate ?: return
        when (val a = gate.action) {
            // Manual switch — commit now (the gate is the gesture): setBaseUrl drops tokens + re-probes.
            is TrustGateAction.ManualSwitch -> { _ui.value = _ui.value.copy(trustGate = null); setBaseUrl(a.origin) }
            // Invite repoint — enter the PENDING state; commit only on enroll success (§4.1 rule 3).
            is TrustGateAction.InviteRepoint -> beginPendingSwitch(a.origin, a.email)
            // Launch-reconcile Finish (§4.3 B2-9): baseUrl already points at the origin. If register
            // already succeeded (a session survived the crash) commit + go unlock as that email;
            // otherwise re-enter the pending enroll form. Either way the marker's fate is decided here.
            is TrustGateAction.ReconcileFinish -> {
                _ui.value = _ui.value.copy(trustGate = null, pendingReconcile = null)
                val session = store.load()
                if (session != null && session.accessToken.isNotEmpty()) {
                    store.pendingServer = null // register succeeded — commit the switch
                    _ui.value = _ui.value.copy(pendingSwitch = null, screen = Screen.Unlock(session.email))
                } else {
                    val prev = store.pendingServer?.previousOrigin ?: a.origin
                    _ui.value = _ui.value.copy(pendingSwitch = PendingSwitchUi(a.origin, prev), screen = Screen.Welcome)
                }
                retryPolicy() // re-probe the (still-current) origin so the enroll form / unlock reflects it
            }
        }
    }

    /**
     * §4.1 rule 3 (B2-6): begin a PENDING invite-driven repoint to [origin]. Writes the uncommitted
     * [PendingServer] marker (BEFORE any enrollment, so a crash reconciles at launch), captures
     * [previousOrigin] for a later revert, then switches origin via [setBaseUrl] — which drops the
     * old origin's tokens (§4.1 rule 1) and probes [origin]'s policy so the enroll form renders its
     * fingerprint. Welcome then hides sign-in + the ServerField (driven by [UiState.pendingSwitch]).
     */
    private fun beginPendingSwitch(origin: String, email: String) {
        val previous = store.baseUrl
        store.pendingServer = PendingServer(origin = origin, previousOrigin = previous, email = email.ifBlank { null }, ts = System.currentTimeMillis())
        _ui.value = _ui.value.copy(trustGate = null, pendingSwitch = PendingSwitchUi(origin, previous))
        setBaseUrl(origin)
    }

    /** §4.3 B2-6: "cancel and return to <previous origin>" — revert the uncommitted repoint,
     *  clear the marker, re-probe the previous origin (which re-enables sign-in). */
    fun cancelPendingSwitch() {
        val marker = store.pendingServer ?: run { _ui.value = _ui.value.copy(pendingSwitch = null); return }
        store.pendingServer = null
        _ui.value = _ui.value.copy(pendingSwitch = null, trustGate = null)
        setBaseUrl(resolvedDefaultOrigin(marker, enrollSucceeded = false)) // → previousOrigin, drop + re-probe
    }

    /** §4.3 B2-9 launch reconcile → "Finish setting up at <origin>": re-show the raw-origin gate,
     *  then repoint/commit (see [trustGateConnect]'s ReconcileFinish). */
    fun finishReconcile() {
        val marker = store.pendingServer ?: run { _ui.value = _ui.value.copy(pendingReconcile = null); return }
        _ui.value = _ui.value.copy(
            pendingReconcile = null,
            trustGate = TrustGatePrompt(trustGateRender(marker.origin), enrollment = true, action = TrustGateAction.ReconcileFinish(marker.origin)),
        )
    }

    /** §4.3 B2-9 launch reconcile → "Discard": revert to the previous origin + clear the marker. */
    fun discardReconcile() {
        val marker = store.pendingServer
        store.pendingServer = null
        _ui.value = _ui.value.copy(pendingReconcile = null, pendingSwitch = null)
        if (marker != null) setBaseUrl(resolvedDefaultOrigin(marker, enrollSucceeded = false))
        else _ui.value = _ui.value.copy(screen = Screen.Welcome)
    }

    /** N2 §3 (design 2026-07-10): Welcome/Enroll's Retry for a failed policy probe — the same
     *  fetch + enforcement as [setBaseUrl]'s; sets [UiState.policyFetchFailed] on failure and
     *  clears it on success (via [applyPolicy]). Runs under `busy` so the Retry button can
     *  disable and show "Retrying…" like every other affordance on the screen. */
    fun retryPolicy() {
        if (_ui.value.busy) return
        _ui.value = _ui.value.copy(busy = true)
        val originKey = store.currentOriginKey() // §4.2: captured beside the probe it scopes
        viewModelScope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        applyPolicy(p, originKey)
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(originKey, it.userId) }
                    }
                    .onFailure { _ui.value = _ui.value.copy(policyFetchFailed = true) }
            } finally {
                probe.close()
                _ui.value = _ui.value.copy(busy = false)
            }
        }
    }

    /** #23: every op-failure surfaces through the shared household canon ([HouseholdCopy] —
     *  the Kotlin twin of web errors.ts), NEVER an exception's raw message. The old
     *  android-local friendlyError map is deleted: its ten §11 vault-lifecycle rows + 429
     *  live byte-identical inside [HouseholdCopy.forError]'s code map (that hand-synced
     *  duplication was the finding), and its `t.message ?: …` fallback was the defect.
     *  Context-aware call sites pass the matching mapper ([op]'s parameter). */
    private fun fail(t: Throwable, map: (Throwable) -> String = HouseholdCopy::forError) {
        _ui.value = _ui.value.copy(busy = false, error = map(t))
    }

    /** #23 carve-out for the spec 07 export paths: their [IllegalStateException]s are OUR
     *  curated, user-facing sentences minted app-side ("backup verification failed — …",
     *  openTruncated's destination failure) — never wire text — so they surface verbatim;
     *  everything else routes through the shared canon like any other op. */
    private fun exportError(t: Throwable): String =
        if (t is IllegalStateException && !t.message.isNullOrBlank()) t.message!! else HouseholdCopy.forError(t)

    fun clearError() { _ui.value = _ui.value.copy(error = null) }

    fun clearNotice() { _ui.value = _ui.value.copy(notice = null) }

    /**
     * F57: re-seal this account's UVK to the CURRENT org recovery key after a re-ceremony. The user
     * must have TYPED the new recovery fingerprint's short form from their PRINTED sheet (spec 04
     * §2(3)); we re-check that, then [Account.resealEscrowFor] binds the server-fetched recovery
     * pubkey to that verified fingerprint (refusing on mismatch) so a hostile server can't redirect
     * the escrow. Non-blocking: on success the banner clears; a failure surfaces as an error.
     */
    fun resealEscrow(shortFormEntry: String) = op {
        val fp = _ui.value.escrowFingerprint
        val a = api ?: throw IllegalStateException("not connected")
        val acct = account ?: throw IllegalStateException("locked")
        if (!Escrow.shortFormMatches(shortFormEntry, fp)) {
            _ui.value = _ui.value.copy(busy = false, error = "That doesn't match this server's recovery key — check your printed recovery sheet.")
            return@op
        }
        val pub = withContext(Dispatchers.Default) { a.recoveryPubkey() }
        val upload = withContext(Dispatchers.Default) { acct.resealEscrowFor(pub, fp) }
        a.escrowSelf(upload)
        _ui.value = _ui.value.copy(busy = false, escrowStale = false, notice = "Account re-protected — your recovery is up to date.")
    }

    /** Item history (feature): load + decrypt the currently-viewed item's archived versions. */
    fun loadItemVersions(itemId: String, vaultId: String) = op {
        _ui.value = _ui.value.copy(itemVersions = null)
        val versions = engine!!.itemVersions(itemId, vaultId)
        _ui.value = _ui.value.copy(itemVersions = versions, busy = false)
    }

    fun clearItemVersions() { _ui.value = _ui.value.copy(itemVersions = null) }

    /** Item undelete (feature): open the Trash screen and load the deleted items. */
    fun openTrash() {
        _ui.value = _ui.value.copy(screen = Screen.Trash, deletedItems = null)
        loadDeletedItems()
    }

    fun loadDeletedItems() = op {
        _ui.value = _ui.value.copy(deletedItems = engine!!.deletedItems(), busy = false)
    }

    /** Item undelete (feature): restore a deleted item, then refresh the trash list + the vault. */
    fun restoreDeleted(itemId: String, vaultId: String, doc: ItemDoc) = op {
        engine!!.restoreDeleted(itemId, vaultId, doc)
        _ui.value = _ui.value.copy(deletedItems = engine!!.deletedItems(), items = engine!!.items(), busy = false, notice = "Item restored.")
    }

    /** Item undelete (F49): "Delete forever" a tombstoned item, then refresh the trash list. */
    fun purgeDeleted(itemId: String) = op {
        engine!!.purgeDeleted(itemId)
        _ui.value = _ui.value.copy(deletedItems = engine!!.deletedItems(), busy = false, notice = "Item deleted for good.")
    }

    fun closeTrash() { _ui.value = _ui.value.copy(screen = Screen.Vault, deletedItems = null) }

    fun signIn(email: String, password: String, totp: String? = null) = op(mapError = { HouseholdCopy.forSignInError(it, totpTried = totp != null) }) {
        // §4.3 B2-6 (sink guard — the authoritative backstop for the pending-state sign-in lockout):
        // an uncommitted pendingServer marker means store.baseUrl is OPTIMISTICALLY pointed at an
        // unverified invite origin (enroll-success is what clears the marker). Deriving a master-password
        // authKey (prelogin salt + deriveAuthKey below) against that origin is exactly the offline-crack
        // leak B2-6 exists to stop. The UI hides sign-in in the pending/reconcile states, but this backstops
        // ANY path that leaves the marker set with the controls re-exposed (e.g. reconcile Finish→Cancel) —
        // route back to the reconcile choice instead of signing in against the foreign origin.
        store.pendingServer?.let {
            _ui.value = _ui.value.copy(busy = false, pendingReconcile = it, error = null)
            return@op
        }
        val a = newApi()
        try {
            val pre = a.prelogin(email)
            // Argon2id (64 MiB, twice per sign-in) is CPU-bound — never on Main (ANrs/jank).
            val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams) }
            val s = try {
                a.login(LoginRequest(email, authKey, Account.deviceInfo(android.os.Build.MODEL ?: "android"), totp = totp))
            } catch (e: ApiException) {
                when (e.code) {
                    "totp_required", "bad_totp_code" -> {
                        a.close()
                        _ui.value = _ui.value.copy(
                            busy = false,
                            loginTotpRequired = true,
                            error = if (totp == null) "Enter the 6-digit code from your authenticator." else "That code didn't work — try again.",
                        )
                        return@op
                    }
                    // #23: public_login_requires_totp no longer needs a re-minted message —
                    // op's forSignInError mapper carries the canonical break-glass sentence.
                    else -> throw e
                }
            }
            val acct = withContext(Dispatchers.Default) { Account.unlock(s.userId, password, s.accountKeys) }
            store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
            persistAccountKeys(s.accountKeys)
            bind(a, acct)
            // F58: a recovery TEMP password logs in with mustChangePassword=true — persist it
            // (only a login/register response carries the flag) and raise the blocking banner.
            store.mustChangePassword = s.mustChangePassword
            _ui.value = _ui.value.copy(escrowStale = s.accountKeys.escrowStale, escrowFingerprint = s.accountKeys.escrowFingerprint, mustChangePassword = s.mustChangePassword)
            // A1: stamp the 30-day window on a real full-password unlock; A6/§7: F61 rides online.
            store.stampFullPasswordUnlock(s.userId)
            // §F.9 gate decision: the server says this account's recovery piece was never durably
            // CONFIRMED — an interrupted reveal or a migration account.
            val gate = s.accountKeys.recoveryConfirmed != true
            // F61 re-key NEVER under a pending capture gate: the detached re-key rotates the login
            // verifier, which would strand the gate's stashed reauth proof (PUT /recovery/self-setup
            // re-verifies it) in a permanent 401 Retry loop. The rare upgrade defers to the next
            // (confirmed) sign-in/unlock, like the quick-unlock defer (§F.3).
            if (!gate) runKdfUpgrade(s.userId, password, s.accountKeys)
            syncNow(engine!!)
            // §F.9 vault-entry capture gate (desktop signIn / web SignIn parity): route into the
            // capture flow INSTEAD of the vault; the login authKey derived above is the
            // fresh-reauth proof PUT /recovery/self-setup requires.
            if (gate) startRecoveryCapture(authKey) else toVault()
        } catch (t: Throwable) {
            // F74: no throw path (prelogin/KDF/login/Account.unlock) may leak the transient
            // client. Once bind() succeeded the api is VaultSession-OWNED — never close it
            // here (the success-path token-holder the live session uses).
            if (VaultSession.get()?.api !== a) a.close()
            throw t
        }
    }

    fun unlock(email: String, password: String) = op(mapError = HouseholdCopy::forUnlockError) {
        val session = store.load() ?: throw IllegalStateException("no session")
        val originKey = store.currentOriginKey() // §4.2: the server this unlock talks to

        // §F.9: set when this unlock must land in the capture gate — the FRESH accountKeys said
        // recoveryConfirmed=false. Decided inside the mutex (where the keys are in scope), acted
        // on after the sync below; the gate's authKey derivation (an extra argon2id) deliberately
        // runs OUTSIDE the mutex so the autofill unlock path is never serialized behind it.
        var gateKeys: AccountKeys? = null
        // Serialize with the autofill unlock path: both reuse this session's refresh token,
        // and a concurrent refresh would consume it twice → whole-device revocation.
        VaultSession.unlockMutex.withLock {
            // If autofill (or another tap) already unlocked while we waited, adopt that
            // session instead of building a second token-holder.
            VaultSession.get()?.let { toVault(); return@op }
            val a = newApi(session.tokens())
            // Offline unlock (spec 02 §8): fall back to the cached accountKeys when the
            // network is unreachable; a definitive auth rejection wipes the cache instead.
            var online = false
            val keys = try {
                a.accountKeys().also { online = true; persistAccountKeys(it) }
            } catch (e: IOException) {
                store.loadAccountKeys() ?: run { a.close(); throw e }
            } catch (e: ApiException) {
                a.close()
                // Definitive rejection: this device's session is dead (e.g. the web password
                // change revoked every other session, spec 03 §3) — wipe it, including the
                // persisted F58 flag (store.clear()); mirror the clear into UI state, and say
                // WHY on the Unlock/sign-in surface (F26 session-end reason). §4.2: the 401
                // came from THIS origin — only its namespace is purged.
                if (e.status == 401) { purgeOfflineData(originKey, session.userId); store.clear(); _ui.value = _ui.value.copy(mustChangePassword = false, lockReason = REASON_SESSION_ENDED) }
                throw e
            } catch (t: Throwable) {
                a.close(); throw t // F74: a generic throw must never leak the transient client
            }
            val acct = try {
                // KDF off the Main thread (argon2id 64 MiB — the unlock spinner must animate).
                withContext(Dispatchers.Default) { Account.unlock(session.userId, password, keys) }
            } catch (t: Throwable) { a.close(); throw t }
            // F74 (review [1]): bind() itself can throw — sqliteVaultCache open + SyncEngine
            // hydrate() do raw cache reads, and a corrupt vault-<userId>.db throws there. The
            // ownership guard preserves the never-close-the-adopted-holder invariant: once
            // VaultSession has adopted `a`, it owns it and lock() closes it.
            try {
                bind(a, acct)
                _ui.value = _ui.value.copy(escrowStale = keys.escrowStale, escrowFingerprint = keys.escrowFingerprint)
                // A1: stamp on EVERY full-password unlock, including offline ones.
                store.stampFullPasswordUnlock(session.userId)
                // §F.9 gate decision (desktop unlock parity): only FRESH keys may gate — an
                // offline unlock (cached keys) deliberately skips it rather than stranding
                // offline vault access behind an unreachable server (the self-setup PUT needs
                // the network anyway); the flag re-gates the next online unlock.
                if (online && keys.recoveryConfirmed != true) gateKeys = keys
                // A6/§7: F61 re-key only when this unlock actually reached the server — and NEVER
                // under a pending capture gate: the detached re-key rotates the login verifier,
                // which would strand the gate's stashed reauth proof (self-setup re-verifies it)
                // in a permanent 401 Retry loop. It defers to the next (confirmed) unlock.
                if (online && gateKeys == null) runKdfUpgrade(session.userId, password, keys)
            } catch (t: Throwable) {
                if (VaultSession.get()?.api !== a) a.close()
                throw t
            }
        }
        // Tolerate an offline sync — hydrate() already populated the cached vault.
        runCatching { syncNow(engine!!) }.onFailure {
            if (it is IOException) _ui.value = _ui.value.copy(notice = "Offline — showing cached data")
            else throw it
        }
        // §F.9 vault-entry capture gate — see signIn. Unlock never derived a login authKey (it
        // opens the UVK locally), so derive one ONLY when the gate actually fires: accountKeys'
        // kdfSalt/kdfParams are the same user-row values prelogin serves, so this authKey verifies
        // against the same server-side login verifier. One extra argon2id pass (off the Main
        // thread), paid only on the rare unconfirmed path.
        val gk = gateKeys
        if (gk != null) {
            val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, gk.kdfSalt, gk.kdfParams) }
            startRecoveryCapture(authKey)
        } else toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String, waived: Boolean, typedShortFp: String) {
        // State-layer re-assert (the S2-review race class: a Compose enabled flag lags a
        // frame while onClick reads live fields). Busy first — op() sets busy but never
        // checks it, so a same-frame double-tap would run two registers (second dies
        // invite_used and clobbers the error). Then the F60 floor: a sub-floor master
        // password is the one irreversible outcome of this screen.
        if (_ui.value.busy) return
        if (!Strength.meetsMasterPasswordFloor(password)) {
            _ui.value = _ui.value.copy(error = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols.")
            return
        }
        // CR-06 / spec 04 §2(3) / TM-T10: capture the policy the UI gate just validated the typed
        // sheet against, and thread THIS exact instance into enrollOp. op() schedules enrollOp as a
        // coroutine, so a re-read of _ui.value.policy inside it could see a mid-form policy swap
        // (setBaseUrl re-probe, Activity-recreation re-probe under the rememberSaveable-preserved
        // form). Threading the gate-time snapshot makes the typed-fingerprint re-assert and the
        // escrow seal bind to the SAME policy — the desktop DesktopState.enrollOp guarantee.
        enrollOp(invite, email, name, password, waived, typedShortFp, _ui.value.policy)
    }

    private fun enrollOp(invite: String, email: String, name: String, password: String, waived: Boolean, typedShortFp: String, gatePolicy: ClientPolicy?) = op {
        // F74: the old fallback built a client, closed it UNUSED, then leaked the second one
        // it actually called (`newApi().also { it.close() }.let { newApi().clientPolicy() }`).
        // One probe, closed in finally (AndvariApi has close() but isn't Closeable — no .use).
        // CR-06: use the gate-time policy snapshot threaded from enroll() — NOT a fresh
        // _ui.value.policy re-read — so this same instance backs both the re-assert below and
        // the seal's recoveryFingerprint/kdfParams. The fallback fetch only fires when the gate
        // had none (the waived path still needs the policy's kdfParams; required-typed always has
        // a fingerprint by the UI gate, so gatePolicy is non-null there).
        val policy = gatePolicy ?: run {
            val probe = newApi()
            try { probe.clientPolicy() } finally { probe.close() }
        }
        // Typed-sheet ceremony re-assert at the STATE layer against the policy this enroll actually
        // seals to (CR-06 / spec 04 §2(3); mirrors DesktopState.enrollOp — 4th sighting of the
        // frame-stale class, the TM-T10 escrow-redirect defense): a policy swap between the
        // composition-time UI gate and this seal would otherwise leave a one-frame-stale submit
        // passing the UI gate against the OLD server's fingerprint. The escrow attestation MUST
        // bind to the org being enrolled into. required-typed only — waived (`waived == true`)
        // seals NO org escrow, so there is no fingerprint to attest. An explicit curated error
        // write (not check()) so the sentence reaches the user itself, never via a generic mapper.
        if (!waived && !Escrow.shortFormMatches(typedShortFp, policy.recoveryFingerprint)) {
            _ui.value = _ui.value.copy(busy = false, error = "The recovery-sheet check no longer matches this server — re-verify the printed sheet's first 16 characters.")
            return@op
        }
        val a = newApi()
        // §F.4/§F.7: the per-member recovery piece is generated by enroll() and committed inside
        // register(); it is held here transiently so the shown-once gate (below) can reveal it.
        var recoverySecret: ByteArray? = null
        // Piece-binding (design 2026-07-13): the register-committed piece's opaque id — the enroll
        // path's BOUND confirm presents it (stashed beside the secret below, dropped together).
        var recoveryPieceId: String? = null
        try {
            // §F.1 posture (client-derived, [enrollPosture]): `waived` seals NO org escrow — pass
            // recoveryPublicKey = null and Account.enroll skips the blob entirely (the server
            // rejects escrow on a waived invite; the account gets the self-service piece only, no
            // admin backstop). `required-typed` keeps the verified-fingerprint ceremony exactly as
            // before: the user TYPED the sheet's short form (EnrollForm gate re-checked at submit)
            // and Account.enroll refuses a fetched pubkey whose fingerprint doesn't match the
            // policy value that check anchored. The org key isn't even fetched when waived.
            val recoveryPub = if (waived) null else Bytes.fromB64(a.recoveryPubkey())
            // Key generation + KDF are CPU-bound (argon2id) — off the Main thread. EnrollResult
            // destructures to (request, account, recoverySecret) — the 3rd is the SHOWN-ONCE piece.
            val (req, acct, secret) = withContext(Dispatchers.Default) {
                Account.enroll(
                    inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
                    password = password, params = policy.kdfParams,
                    recoveryPublicKey = recoveryPub,
                    recoveryFingerprint = if (waived) null else policy.recoveryFingerprint,
                    deviceName = android.os.Build.MODEL ?: "android",
                )
            }
            recoverySecret = secret
            // §4.3 B2-9 crash marker: on a PENDING invite switch, capture the enrolling email in the
            // marker BEFORE register — a crash between register success and the commit below is then
            // reconciled at next launch with the address to sign in as. No-op on a same-origin enroll
            // (no marker). baseUrl already points at the pending origin, so register hits the right one.
            store.pendingServer?.let { store.pendingServer = it.copy(email = email) }
            val s = a.register(req)
            recoveryPieceId = s.recoveryPieceId
            store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
            persistAccountKeys(s.accountKeys)
            bind(a, acct)
            // §4.1 rule 3 (B2-6): enrollment SUCCEEDED — COMMIT the pending invite switch. Clearing
            // the uncommitted marker is the commit (baseUrl already points here), and it leaves the
            // pending Welcome state. A same-origin enroll has no marker/pendingSwitch — both no-op.
            if (store.pendingServer != null) store.pendingServer = null
            _ui.value = _ui.value.copy(pendingSwitch = null)
            // F58: symmetric with signIn — a register response carries the flag too (false
            // for a fresh enrollment, but the wire says so, not us).
            store.mustChangePassword = s.mustChangePassword
            _ui.value = _ui.value.copy(escrowStale = s.accountKeys.escrowStale, escrowFingerprint = s.accountKeys.escrowFingerprint, mustChangePassword = s.mustChangePassword)
            // A1: a fresh enrollment typed the master password — stamp the window (already on the
            // policy KDF params, so no F61 re-key is due).
            store.stampFullPasswordUnlock(s.userId)
        } catch (t: Throwable) {
            // F74: same rule as signIn — close the transient client on ANY pre-bind throw,
            // never the VaultSession-owned success-path holder.
            if (VaultSession.get()?.api !== a) a.close()
            throw t
        }
        syncNow(engine!!)
        // §F.4/§F.7: the recovery piece is MANDATORY and already committed in register(), but a
        // member who never SEES it is silently unrecoverable. Hold it transiently and route to the
        // shown-once reveal+confirm gate (RecoverySetup) instead of the vault; the gate zeroes it
        // once the user types it back. (Past the try `recoverySecret` is always non-null; the
        // null-guard keeps this total should a future refactor break that.)
        val secret = recoverySecret
        if (secret == null) { toVault(); return@op }
        pendingRecoverySecret = secret
        pendingRecoveryPieceId = recoveryPieceId
        _ui.value = _ui.value.copy(
            screen = Screen.RecoverySetup,
            recoveryPhrase = MemberRecovery.displayForm(secret),
            recoverySetupWaived = waived, // §F.4 posture copy: stark "gone forever" when waived
            busy = false, error = null,
        )
    }

    // Shown-once recovery secret (design §F.7): the RAW 32 bytes of a recovery piece — a fresh
    // enrollee's, or the fresh one the §F.9 capture gate committed — held transiently between the
    // commit and the confirm gate ONLY for the constant-time confirmMatches. NEVER persisted,
    // NEVER logged; zeroed + dropped the instant the confirm resolves ([zeroPendingRecovery]) and
    // on lock/sign-out. The user-visible base64url form lives in UiState.recoveryPhrase (also
    // transient) so Compose can render it.
    private var pendingRecoverySecret: ByteArray? = null
    // Piece-binding (design 2026-07-13): the opaque server-minted id of the piece
    // [pendingRecoverySecret] holds — register's recoveryPieceId on the enroll path, the self-setup
    // response's pieceId on the capture-gate path. Presented by the BOUND confirm so it can only
    // ever attest the piece THIS device revealed. Not a secret (it rides an authenticated channel
    // and grants nothing a session couldn't get by calling setup itself), but it lives and dies
    // WITH the secret ([zeroPendingRecovery]) — a dangling id must never outlive its phrase.
    private var pendingRecoveryPieceId: String? = null
    // §F.9 (desktop v2 #15 parity): the login authKey (base64url, password-equivalent — treat like
    // the typed master password) held ONLY while the RecoveryCapture gate is unresolved: PUT
    // /recovery/self-setup requires a fresh master-password reauth, and BOTH the gate's Retry and
    // the 409-stale re-run must not re-prompt. Piece-binding §3: held until the BOUND CONFIRM
    // resolves (not just the commit) — a stale confirm re-runs the setup, which needs it. Cleared
    // on the confirm's terminal paths, lock and sign-out. Never persisted, never logged. Doubles
    // as the confirm-route discriminator in [confirmRecoverySaved] (non-null ⇒ capture-gate path).
    private var pendingCaptureAuthKey: String? = null

    /** §F.7 + piece-binding: the raw secret and its pieceId live and die TOGETHER (a dangling id
     *  could bind a confirm to a phrase no longer on screen). The display form is the callers'
     *  (toVault / the explicit screen swaps clear UiState.recoveryPhrase). */
    private fun zeroPendingRecovery() {
        pendingRecoverySecret?.fill(0) // best-effort zeroization before dropping the reference
        pendingRecoverySecret = null
        pendingRecoveryPieceId = null
    }

    /**
     * The un-skippable "I saved my recovery phrase" gate (design §F.7). Does [typedBack] re-decode
     * to the SAME secret we committed (register / self-setup)? Constant-time (core
     * [MemberRecovery.confirmMatches]). A mistype returns false and the screen shows a STATIC error
     * (never the secret); this is NEVER a KDF source — the piece is already committed, this only
     * proves the user saved it. On a match the two reveal paths diverge (piece-binding design
     * 2026-07-13 §3):
     *  - ENROLL (no capture gate in progress): fire the BOUND confirm (register's recoveryPieceId)
     *    without blocking navigation, ZERO + DROP the raw secret + id, open the vault — a 409
     *    surfaces the static replaced-phrase notice and proceeds unconfirmed (the vault-entry gate
     *    re-fires at the next entry and heals).
     *  - CAPTURE GATE ([pendingCaptureAuthKey] held): the bound confirm is AWAITED before the
     *    vault opens — see [confirmCaptureGate].
     */
    fun confirmRecoverySaved(typedBack: String): Boolean {
        val secret = pendingRecoverySecret ?: return false
        if (!MemberRecovery.confirmMatches(secret, typedBack)) return false
        if (pendingCaptureAuthKey != null) {
            // §F.9 capture-gate path: bound + AWAITED (contract §3) — the vault must not open on a
            // phrase the server no longer holds. Runs under `busy` (the reveal's button spins).
            confirmCaptureGate()
            return true
        }
        // ENROLL path. §F.9: tell the server this enrollee saved the register-committed phrase, so
        // the vault-entry gates (web's, desktop's and this app's) never re-nudge the account. Fire
        // this BEFORE we touch the secret: it captures the pieceId and launches asynchronously, so
        // a slow confirm can never delay or block the zeroize + navigate below — best-effort
        // NAVIGATION, but the outcome IS handled (409 ⇒ static notice; markRecoveryConfirmed).
        markRecoveryConfirmed(pendingRecoveryPieceId)
        zeroPendingRecovery()
        toVault() // clears recoveryPhrase too (the display form must not survive landing)
        return true
    }

    /**
     * §F.9 ENROLL-path "recovery confirmed" call, BOUND per the piece-binding contract (design
     * 2026-07-13 §3): presents [pieceId] — register's recoveryPieceId — so the confirm can only
     * ever attest the piece THIS device revealed. Rides the live session's shared
     * [AndvariApi.recoverySelfConfirm] (step-0; the old hand-rolled POST bypassed the shared
     * refresh/error path). Deliberately never blocks navigation ([confirmRecoverySaved] zeroes +
     * lands the vault regardless), but the outcome is handled, not dropped:
     * `409 recovery_piece_stale` ⇒ the static replaced-phrase notice + proceed unconfirmed (the
     * flag stays 0/cleared, so the vault-entry gate re-fires at the next entry and heals); any
     * other failure ⇒ proceed unconfirmed (today's polarity — the flag can be re-set later).
     */
    private fun markRecoveryConfirmed(pieceId: String?) {
        val a = api ?: return
        viewModelScope.launch {
            try {
                a.recoverySelfConfirm(pieceId)
            } catch (e: ApiException) {
                if (e.status == 409 && e.code == "recovery_piece_stale") {
                    // Static copy only (§F.7) — the phrase this enrollee just saved is already
                    // dead (a concurrent setup rotated it). toVault deliberately keeps `notice`.
                    _ui.value = _ui.value.copy(notice = RECOVERY_PHRASE_REPLACED_NOTICE)
                }
                // else: proceed unconfirmed — the vault-entry gate re-fires later and heals.
            } catch (_: Throwable) {
                // Network failure: proceed unconfirmed (the flag can be re-set on a later capture).
            }
        }
    }

    /**
     * §F.9 (desktop v2 #15 parity): enter the vault-entry capture gate. [currentAuthKey] is the
     * login authKey derived from the master password the user JUST typed (the fresh-reauth proof
     * the server demands before storing a new recovery block); held until the gate resolves —
     * including across a 409-stale re-run (piece-binding §3). Kicks the commit immediately — the
     * screen renders "Preparing…" until it lands or fails.
     */
    private fun startRecoveryCapture(currentAuthKey: String) {
        pendingCaptureAuthKey = currentAuthKey
        // The op() that routed here is done; the commit runs under its own busy in runRecoveryCapture.
        _ui.value = _ui.value.copy(screen = Screen.RecoveryCapture, recoveryCaptureError = null, recoveryReplacedNotice = false, busy = false, error = null)
        runRecoveryCapture()
    }

    /** §F.9: the gate screen's Retry — same commit, same stashed reauth proof. */
    fun retryRecoveryCapture() {
        if (_ui.value.busy) return
        if (_ui.value.screen != Screen.RecoveryCapture) return // stale tap after a lock swapped screens
        runRecoveryCapture()
    }

    /**
     * §F.9: the capture gate's commit half (desktop runRecoveryCapture / web setupAndCommitRecovery
     * parity): generate a FRESH per-member piece over the in-memory UVK
     * ([Account.setupMemberRecovery]) and PUT it via the shared [AndvariApi.recoverySelfSetup] —
     * which stores/rotates the block but deliberately does NOT flip recoveryConfirmed (the flag
     * means "user demonstrably captured" and only the type-back confirm may set it). Piece-binding:
     * the response's pieceId is stashed beside the secret — the eventual bound confirm presents it.
     * On success the fresh secret feeds the SAME un-skippable RecoverySetup reveal the enroll path
     * uses; on any failure the secret is zeroed and the gate stays closed with Retry — never the
     * vault, never a dangling live secret. Runs under `busy` so the idle lock defers while key
     * material is in flight (checkIdleLock's busy gate). A rotation invalidates any
     * previously-written-but-unconfirmed phrase — the screen copy says so.
     */
    private fun runRecoveryCapture() {
        val a = api ?: return
        val acct = account ?: return
        val authKey = pendingCaptureAuthKey ?: return
        _ui.value = _ui.value.copy(recoveryCaptureError = null, busy = true)
        viewModelScope.launch {
            try {
                val setup = acct.setupMemberRecovery(authKey)
                var committed = false
                val resp = try {
                    a.recoverySelfSetup(setup.request).also { committed = true }
                } finally {
                    // §F.7 discipline: a failed commit must not leave the raw secret alive.
                    if (!committed) setup.recoverySecret.fill(0)
                }
                // B1 identity gate: a hard lock / sign-out mid-commit tore this session down — the
                // fresh phrase must not leak into whatever session renders next.
                if (account !== acct) { setup.recoverySecret.fill(0); _ui.value = _ui.value.copy(busy = false); return@launch }
                pendingRecoverySecret = setup.recoverySecret
                pendingRecoveryPieceId = resp.pieceId // null on a pre-binding server rollback ⇒ legacy device-scoped confirm
                _ui.value = _ui.value.copy(
                    busy = false,
                    screen = Screen.RecoverySetup,
                    recoveryPhrase = MemberRecovery.displayForm(setup.recoverySecret),
                    // Fielded gate accounts enrolled under `required` (or migration-era with org
                    // escrow), and AccountKeys deliberately carries no posture — the required copy
                    // ("admin can also help") is the honest default here (desktop parity).
                    recoverySetupWaived = false,
                )
            } catch (t: Throwable) {
                if (t is UpgradeRequiredException) {
                    // A8 parity: a 426 mid-gate must raise the blocking upgrade screen — a static
                    // Retry loop against a version-pinned server is a dead end.
                    _ui.value = _ui.value.copy(busy = false, upgradeRequired = UPGRADE_REQUIRED_MSG)
                    return@launch
                }
                if (account !== acct) { _ui.value = _ui.value.copy(busy = false); return@launch } // torn down mid-flight — nothing to report
                // Static copy only — NEVER interpolate anything near secret material (§F.7).
                _ui.value = _ui.value.copy(
                    busy = false,
                    recoveryCaptureError = if (t is IOException) {
                        "Can't reach the server right now — check your connection and try again."
                    } else {
                        "Couldn't set up your recovery phrase just now — try again in a moment."
                    },
                )
            }
        }
    }

    /** [confirmCaptureGate]'s three server verdicts — decided in the coroutine, acted on after the
     *  B1 identity re-check (the decision must never navigate a torn-down session). */
    private enum class ConfirmOutcome { Confirmed, Stale, Failed }

    /**
     * Piece-binding (design 2026-07-13 §3): the capture gate's BOUND + AWAITED confirm — the
     * type-back matched, so present the pieceId this gate's setup minted and only open the vault
     * once the server answers. Outcomes:
     *  - 200 → captured: zero the secret+pieceId, drop the reauth proof, land the vault.
     *  - 409 recovery_piece_stale → the phrase JUST typed is DEAD (another device's setup rotated
     *    it away mid-gate). Zero it, raise the static replaced-phrase notice, and re-run
     *    setup + reveal — the stashed [pendingCaptureAuthKey] is the reauth proof, which is exactly
     *    why it survives the commit. NEVER mark captured, never present the typed phrase as saved.
     *  - anything else (network / server trouble) → proceed to the vault UNCONFIRMED (today's
     *    polarity): the flag stays 0, so the gate re-fires at the next entry and heals — the user
     *    DID type the phrase back, and keeping them out over a blip helps nobody.
     * Runs under `busy` (the reveal's confirm button spins; the idle lock defers).
     */
    private fun confirmCaptureGate() {
        if (_ui.value.busy) return // in-flight confirm; the reveal's button is busy-gated too
        val a = api
        val acct = account
        if (a == null || acct == null) {
            // Session torn down under the reveal (autofill hard-lock): the next checkIdleLock tick
            // locks this screen (zeroing the secret); never navigate a dead session into the vault.
            return
        }
        val pieceId = pendingRecoveryPieceId
        _ui.value = _ui.value.copy(busy = true)
        viewModelScope.launch {
            val outcome = try {
                a.recoverySelfConfirm(pieceId)
                ConfirmOutcome.Confirmed
            } catch (e: ApiException) {
                if (e.status == 409 && e.code == "recovery_piece_stale") ConfirmOutcome.Stale else ConfirmOutcome.Failed
            } catch (_: Throwable) {
                ConfirmOutcome.Failed
            }
            // B1 identity gate: torn down mid-confirm — lock()/signOut() own the cleanup.
            if (account !== acct) { _ui.value = _ui.value.copy(busy = false); return@launch }
            when (outcome) {
                ConfirmOutcome.Stale -> {
                    // §3 stale rule: zero the dead phrase together with its id, say so (statically),
                    // and re-run setup + reveal under the held reauth proof.
                    zeroPendingRecovery()
                    _ui.value = _ui.value.copy(busy = false, screen = Screen.RecoveryCapture, recoveryPhrase = null, recoveryReplacedNotice = true)
                    runRecoveryCapture()
                }
                ConfirmOutcome.Confirmed, ConfirmOutcome.Failed -> {
                    zeroPendingRecovery()
                    pendingCaptureAuthKey = null // the gate is resolved — the reauth proof dies here
                    toVault()
                }
            }
        }
    }

    // ---- forgot-master-password self-recovery (design §F.3; web Recover.tsx twin) ----

    // §F.7: the raw 32 recovery-secret bytes parsed from the typed phrase, held ONLY between a
    // successful verify and the commit (Account.recover consumes them). NEVER persisted, NEVER
    // logged; zeroed + dropped on commit success, cancel, lock and sign-out (web's secretRef +
    // unmount-clear discipline). The verify response beside it is server-public material (ticket +
    // wrapped blobs) but composes nothing, so it stays off UiState with the secret.
    private var pendingRecoverSecret: ByteArray? = null
    private var pendingRecoverVerify: RecoveryVerifyResponse? = null
    // The email the verify proved — decides whether a commit invalidated THIS device's stored
    // session (the commit revokes every session of the recovered account, spec 03 §12).
    private var pendingRecoverEmail: String? = null

    /** The §F.7 zeroize for the recover flow: secret + verify ticket + email die together. */
    private fun zeroPendingRecover() {
        pendingRecoverSecret?.fill(0)
        pendingRecoverSecret = null
        pendingRecoverVerify = null
        pendingRecoverEmail = null
    }

    /** Enter the recover wizard from the Unlock screen's "Forgot your master password?" signpost. */
    fun openRecover() {
        if (_ui.value.busy) return
        zeroPendingRecover() // a fresh entry never inherits a previous attempt's material
        _ui.value = _ui.value.copy(
            screen = Screen.Recover(store.load()?.email ?: ""),
            recoverVerified = false, error = null, notice = null,
        )
    }

    /** Back out of the wizard (either phase): zero the held material, land where start() would.
     *  System back is NOT busy-gated (only the Cancel buttons are), so this can win an in-flight
     *  verify/commit — `busy` resets HERE (the op no longer owns the screen; nothing else can be
     *  busy on Recover), and the screen swap is what the §F.7 cancel fences inside those
     *  continuations key on: they zero their material and die instead of landing. */
    fun cancelRecover() {
        zeroPendingRecover()
        val session = store.load()
        _ui.value = _ui.value.copy(
            screen = if (session != null && session.accessToken.isNotEmpty()) Screen.Unlock(session.email) else Screen.Welcome,
            recoverVerified = false, error = null, busy = false,
        )
    }

    /**
     * Phase 1 (web submitVerify parity): parse the typed phrase (total — a malformed phrase is a
     * user error, not an exception), derive the recovery authKey (HKDF only, no Argon2id — the
     * server proves possession without ever seeing the phrase) and POST /recovery/self/verify.
     * On success the raw secret + response are stashed (§F.7) and the wizard flips to phase 2;
     * the SCREEN keeps its own typed-phrase state and clears it on the flip.
     */
    fun recoverVerify(email: String, phrase: String) {
        if (_ui.value.busy) return
        val wizard = _ui.value.screen as? Screen.Recover ?: return // stale tap after a screen swap
        val secret = MemberRecovery.parseSecret(phrase)
        if (secret == null) {
            _ui.value = _ui.value.copy(error = "That doesn't look like a recovery phrase — check it and try again.")
            return
        }
        _ui.value = _ui.value.copy(busy = true, error = null)
        viewModelScope.launch {
            val a = newApi() // unauthenticated probe — closed in finally (F74)
            try {
                val authKey = withContext(Dispatchers.Default) { MemberRecovery.deriveAuthKey(createCryptoProvider(), secret) }
                // §F.7 cancel fence, re-checked after EVERY await: system back (cancelRecover)
                // isn't busy-gated, so it can win any of these suspensions — and once THIS
                // wizard instance is gone (cancelled, or replaced by a fresh openRecover — the
                // `!== wizard` identity gate, the B1 `account !== acct` idiom) the continuation
                // owns nothing. Zero the parsed bytes and die: landing would stash a raw secret
                // + live single-use ticket that no screen consumes and nothing ever zeroes.
                if (_ui.value.screen !== wizard) { secret.fill(0); return@launch }
                val resp = a.recoverySelfVerify(email.trim(), authKey)
                if (_ui.value.screen !== wizard) { secret.fill(0); return@launch } // cancelled mid-POST: the ticket dies unstashed with this frame
                zeroPendingRecover() // any earlier attempt's bytes die before the fresh stash
                pendingRecoverSecret = secret
                pendingRecoverVerify = resp
                pendingRecoverEmail = email.trim()
                _ui.value = _ui.value.copy(busy = false, recoverVerified = true, error = null)
            } catch (t: Throwable) {
                secret.fill(0) // §F.7: a refused phrase's bytes don't linger
                // Cancelled mid-flight: cancelRecover already reset busy + cleared error — a late
                // failure must not repaint the Unlock/Welcome screen the user backed out to.
                if (_ui.value.screen !== wizard) return@launch
                _ui.value = _ui.value.copy(busy = false, error = recoverVerifyError(t))
            } finally {
                a.close()
            }
        }
    }

    /**
     * Phase 2 (web submitReset parity): floor-check the new master password, then
     * [Account.recover] — which opens the SAME UVK from the phrase and runs the spec 01 §5
     * identity-pubkey HARD-FAIL before producing the commit body (a substituted identity key
     * aborts HERE, before commit) — and POST /recovery/self/commit under the policy KDF params
     * (H1 floor: clientPolicy() already fenced them; when the cold-start probe never landed the
     * policy is re-probed lazily below — the locked side reaches no other probe). Success revokes
     * every session of the account server-side, so when the recovered email is THIS device's
     * stored session the local session dies with it (the unlock-time-401 purge idiom) and the
     * flow lands on sign-in with a success notice. The screen's password fields are composition
     * state and die with the swap.
     */
    fun recoverCommit(newPassword: String) {
        if (_ui.value.busy) return
        val wizard = _ui.value.screen as? Screen.Recover ?: return
        val secret = pendingRecoverSecret
        val verify = pendingRecoverVerify
        if (secret == null || verify == null) {
            _ui.value = _ui.value.copy(error = "Your recovery session expired — start again.", recoverVerified = false)
            return
        }
        // F60 floor, state-layer re-assert (the enabled flag lags a frame): a sub-floor master
        // password is the one irreversible outcome of this screen.
        if (!Strength.meetsMasterPasswordFloor(newPassword)) {
            _ui.value = _ui.value.copy(error = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols.")
            return
        }
        _ui.value = _ui.value.copy(busy = true, error = null)
        val originKey = store.currentOriginKey() // §4.2: newApi() below dials this same origin
        viewModelScope.launch {
            val a = newApi() // unauthenticated — closed in finally (F74)
            try {
                // Captured BEFORE any await: this is the email the verify proved, and a cancel
                // racing this coroutine nulls the field — but a commit that still LANDS revokes
                // that account's sessions regardless, so the same-account purge below must never
                // lose its anchor.
                val recoveredEmail = pendingRecoverEmail
                // Web parity: the KDF params must be the server's fenced policy set, never a
                // guess. But every stored-policy probe (start/setBaseUrl/retryPolicy + the
                // unlocked poll) lives on the Welcome/unlocked side — unreachable from here — so
                // an app that cold-started offline would otherwise dead-end this button forever.
                // Phase 1 just proved the server reachable: re-probe lazily, exactly when phase 2
                // needs the params (enrollOp's idiom). clientPolicy() runs the H1 KDF floor fence
                // (spec 05 T1); a failed probe surfaces through recoverResetError below.
                val policy = _ui.value.policy ?: a.clientPolicy().also { applyPolicy(it, originKey) }
                // §F.7 cancel fence (recoverVerify's twin), re-checked after EVERY await: system
                // back isn't busy-gated, and once THIS wizard instance is gone the continuation
                // must zero its alias and die without touching UI state. The pendingRecover*
                // fields are NOT re-zeroed here — every screen-swapper already did, and by now
                // they may hold a NEWER wizard's material.
                if (_ui.value.screen !== wizard) { secret.fill(0); return@launch }
                // Argon2id (fresh salt under the policy params) — off the Main thread.
                val commit = withContext(Dispatchers.Default) { Account.recover(secret, verify, newPassword, policy.kdfParams) }
                // Cancelled during the derivation (cancelRecover may even have zeroed `secret`
                // mid-read, making `commit` garbage): the reset is abandoned — NEVER post it.
                if (_ui.value.screen !== wizard) { secret.fill(0); return@launch }
                a.recoverySelfCommit(commit)
                // Past the point of no return: the commit LANDED and revoked EVERY session of the
                // recovered account — even when a cancel won the POST race just now. If that
                // account is this device's stored session, its persisted tokens/keys/cache are
                // dead — purge like the definitive-401 path instead of letting the next unlock
                // trip over it (skipping this on cancel would strand a revoked session).
                val cancelled = _ui.value.screen !== wizard
                if (cancelled) secret.fill(0) else zeroPendingRecover()
                val session = store.load()
                if (session != null && recoveredEmail != null && session.email.equals(recoveredEmail, ignoreCase = true)) {
                    // §4.2: the commit ran against the origin captured at entry (newApi() dialed
                    // it), and the stored session it just revoked belongs there — purge that
                    // namespace only.
                    OfflineData.purgeRevoked(cacheDir, store, originKey, session.userId)
                }
                if (cancelled) return@launch // …but the wizard is gone: no screen/notice to paint
                val next = store.load()?.takeIf { it.accessToken.isNotEmpty() }?.let { Screen.Unlock(it.email) } ?: Screen.Welcome
                _ui.value = _ui.value.copy(
                    busy = false, screen = next, recoverVerified = false, lockReason = null,
                    // purgeRevoked dropped the persisted F58 flag with the session — mirror it.
                    mustChangePassword = store.mustChangePassword,
                    notice = "Master password reset — sign in with your new password.",
                )
            } catch (t: Throwable) {
                // Held material survives a failed commit (web parity): a transient failure
                // retries without re-running phase 1; Cancel remains the way out — and when it
                // already WAS the way out (mid-flight), the stash is zeroed and busy reset:
                // never repaint the screen the user backed out to.
                if (_ui.value.screen !== wizard) return@launch
                _ui.value = _ui.value.copy(busy = false, error = recoverResetError(t))
            } finally {
                a.close()
            }
        }
    }

    /**
     * Phase-1 (verify) copy — the native twin of web Recover.tsx `verifyErrorMessage`, pinned
     * sentence-for-sentence. Uniform copy on 401 — the server is anti-enumeration (§F.5); never
     * reveal which of email / phrase / no-recovery-row was wrong. Static strings only, never
     * interpolating anything near secret material (§F.7).
     */
    private fun recoverVerifyError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION // H1 (spec 05 T1)
        t is ApiException -> when {
            t.status == 401 -> "We couldn't verify that email and recovery phrase."
            t.code == "recovery_public_disabled" -> "Account recovery isn't available from this public address — connect from inside (VPN/LAN) and try again."
            else -> HouseholdCopy.SERVER_PROBLEM
        }
        t is IOException -> HouseholdCopy.UNREACHABLE
        else -> "Recovery failed. Please try again."
    }

    /**
     * Phase-2 (reset/commit) copy — web `resetErrorMessage` twin. The identity mismatch is a
     * DISTINCT tampering signal (spec 01 §5) — never softened into "wrong phrase"; an expired/
     * consumed ticket is `invalid_ticket` (the server value, pinned by RecoveryTest.kt).
     */
    private fun recoverResetError(t: Throwable): String = when {
        t is KdfPolicyViolationException -> HouseholdCopy.WEAK_KDF_ACTION // H1 (spec 05 T1)
        t is CryptoException && t.message?.contains("identity key mismatch") == true -> HouseholdCopy.IDENTITY_MISMATCH
        t is ApiException -> when {
            t.code == "invalid_ticket" || t.status == 401 -> "Your recovery session expired — start again."
            t.code == "recovery_account_not_active" -> "This account is disabled — self-recovery isn't available. Ask your admin to recover it."
            else -> HouseholdCopy.SERVER_PROBLEM
        }
        t is IOException -> HouseholdCopy.UNREACHABLE
        else -> "Recovery failed. Please try again."
    }

    fun saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList(), vaultId: String? = null, onSaved: () -> Unit = {}) = op(mapError = HouseholdCopy::forSaveError) {
        // F18: [vaultId] is the NEW-item vault picker's choice. saveWithUploads HONORS it only
        // when itemId == null; for an existing item it re-targets the item's OWN vault (its blob
        // AD binds that vault; the server enforces vault_mismatch), so a stray picker value can
        // never re-home an edited item. The editor also passes null when editing (belt + braces).
        engine!!.saveWithUploads(itemId, doc, uploads, vaultId)
        refreshItems()
        onSaved()
    }

    fun deleteItem(itemId: String) = op {
        engine!!.remove(itemId)
        refreshItems()
    }

    /** Manual sync (the top-bar refresh icon). #24: lands a brief "Synced." notice — the
     *  tap previously gave zero feedback (ui.syncing renders only for the background poll,
     *  and this op's `busy` showed nothing moving on the vault list). */
    fun refresh() = op(mapError = HouseholdCopy::forSyncError) {
        syncNow(engine!!)
        refreshItems()
        _ui.value = _ui.value.copy(notice = "Synced.")
    }

    fun item(itemId: String): VaultItem? = engine?.item(itemId)

    // ---- vault lifecycle (spec 03 §11): sharing screen + notices + F19 move/copy ----

    /** Vaults whose key we hold (personal first) — pickers, badges, the Sharing screen. */
    fun vaultInfos(): List<VaultInfo> = engine?.vaultInfos() ?: emptyList()

    /** The pending offer on a vault (owner's "Ownership offer to …" chip), or null. */
    fun pendingTransferFor(vaultId: String): PendingTransfer? = engine?.pendingTransferFor(vaultId)

    fun dismissNotice(id: String) {
        engine?.dismissNotice(id)
        refreshLifecycle()
    }

    /**
     * F20: count of shared vaults whose grant this device can't OPEN — a grant blob WAS delivered
     * (it's in the engine's grant rows) but addGrant() failed (sealed to an identity we don't
     * hold, or a newer grant format), so [Account.hasVault] is false and the vault is silently
     * absent from vaultInfos()/[items]. Computed app-side from the engine's read surface (F82)
     * because the Kotlin SyncEngine — unlike web's store — tracks no undecryptable-grant set.
     * Removed/held/deleted vaults are dropVault()'d out of the vault rows, so they never count
     * here; a grant that later opens flips hasVault true and drops out. Mirrors web's
     * undecryptableGrants set.
     */
    private fun undecryptableSharedCount(): Int {
        val current = VaultSession.get() ?: return 0
        val acct = current.account
        val grantedIds = current.engine.grants().mapTo(HashSet()) { it.vaultId }
        return current.engine.vaultRows().count {
            it.type == "shared" && it.vaultId in grantedIds && !acct.hasVault(it.vaultId)
        }
    }

    /** Mirror the engine's lifecycle read-surfaces into UI state (cheap in-memory reads),
     *  and lazily resolve the owner display name behind any verified incoming offer (a
     *  SEPARATE launch under the B1 epoch guard). */
    private fun refreshLifecycle() {
        val e = engine ?: return
        val incoming = e.incomingTransfers()
        _ui.value = _ui.value.copy(
            lifecycleNotices = e.notices(),
            incomingTransfers = incoming,
            heldVaults = e.heldVaultInfos(),
            undecryptableSharedVaultCount = undecryptableSharedCount(),
            // A2 (DN-1): every sync/refresh funnels through here (reloadSharing after ops,
            // backgroundSync pulls) — a settings id whose vault vanished (deleted/revoked
            // elsewhere) is ACTIVELY cleared, so a later restore/re-grant can't resurrect
            // the settings layer. The screen's null-safe lookup covers the same-frame gap.
            sharingSettingsVaultId = _ui.value.sharingSettingsVaultId?.takeIf { id -> e.vaultInfos().any { it.vaultId == id } },
        )
        val missing = incoming.filter { it.vaultId !in _ui.value.transferOwnerNames }
        if (missing.isNotEmpty()) {
            val a = api ?: return
            viewModelScope.launch {
                val names = _ui.value.transferOwnerNames.toMutableMap()
                for (t in missing) {
                    runCatching { a.vaultMembers(t.vaultId).find { it.role == "owner" } }.getOrNull()
                        ?.let { names[t.vaultId] = it.displayName }
                }
                // B1: identity, not null — after a sign-out→sign-in a null check would
                // pass against the NEW engine and leak the old session's owner names.
                if (engine !== e) return@launch // locked/rebound while fetching — publish nothing stale
                _ui.value = _ui.value.copy(transferOwnerNames = names)
            }
        }
    }

    fun openSharing() {
        // A5 (DN-1): a fresh Sharing visit always lands on the LIST — never inside a
        // stale settings layer left over from the previous visit.
        _ui.value = _ui.value.copy(screen = Screen.Sharing, sharingSettingsVaultId = null, copiedNote = null, copyProgress = null, copyVaultId = null)
        reloadSharing()
    }

    fun closeSharing() {
        _ui.value = _ui.value.copy(screen = Screen.Vault, copiedNote = null, copyProgress = null, copyVaultId = null)
    }

    /** DN-1: open one vault's Settings view inside the Sharing screen. VM state, not
     *  composition state (the movePicker precedent) — rotation-safe. Clears the copy
     *  progress/note per the openSharing convention (A4); an in-flight copy itself is
     *  untouched — its next progress tick republishes, and the screen-level status line
     *  keeps it visible from either branch. */
    fun openVaultSettings(vaultId: String) {
        _ui.value = _ui.value.copy(sharingSettingsVaultId = vaultId, copiedNote = null, copyProgress = null, copyVaultId = null)
    }

    fun closeVaultSettings() {
        _ui.value = _ui.value.copy(sharingSettingsVaultId = null, copiedNote = null, copyProgress = null, copyVaultId = null)
    }

    /** Fetch the Sharing screen's server-side lists: members per owned shared vault (the
     *  transfer target picker) and the caller's restorable Recently-deleted vaults. Runs
     *  WITHOUT busy (a slow members fetch must not grey the screen out). B1: `e`/`a` are
     *  the launch-time epoch — every enumeration step is runCatching-wrapped (a mid-flight
     *  lock closes the sqlite cache under `e`) and the state write is identity-gated, so a
     *  continuation resuming after a sign-out→sign-in can neither crash the app nor leak
     *  account A's member emails / deleted vaults into account B's session. */
    fun reloadSharing() {
        val e = engine ?: return
        refreshLifecycle()
        val a = api ?: return
        viewModelScope.launch {
            val members = mutableMapOf<String, List<VaultMemberSummary>>()
            val owned = runCatching { e.vaultInfos().filter { it.type == "shared" && it.role == "owner" } }
                .getOrDefault(emptyList())
            for (v in owned) {
                runCatching { members[v.vaultId] = a.vaultMembers(v.vaultId) }
            }
            val deleted = runCatching { e.listDeleted() }.getOrDefault(emptyList())
            if (engine !== e) return@launch // B1: locked/rebound while fetching — publish nothing stale
            _ui.value = _ui.value.copy(sharingMembers = members, deletedVaults = deleted)
        }
    }

    /** RENAME (owner). stale_meta auto-retries once inside the engine. */
    fun renameVault(vaultId: String, newName: String) = op {
        engine!!.renameVault(vaultId, newName)
        refreshItems(); reloadSharing()
    }

    /** DELETE (soft, 7d grace). The §11 owner toast lands in [UiState.notice]. A-copyGate:
     *  REFUSED while the rescue copy runs — `busy` alone is not a gate (any other op
     *  finishing mid-copy clears it), and deleting the source out from under its own
     *  rescue is the one irreversible interleaving. */
    fun deleteVault(vaultId: String, vaultName: String) {
        if (_ui.value.copyOpVaultId != null) return
        op {
            val purgeAt = engine!!.deleteSharedVault(vaultId)
            refreshItems(); reloadSharing()
            _ui.value = _ui.value.copy(
                notice = "“$vaultName” is deleted. Members lost access immediately. You can restore it until ${fmtDay(purgeAt)} (Sharing → the trash icon).",
            )
        }
    }

    /** Bulk "Copy items to my Personal vault first…" (F19 rider — copy legs ONLY). NOT op{}:
     *  busy is set manually and HELD for the whole copy, and the A-copyGate op guard
     *  [UiState.copyOpVaultId] — set here, cleared ONLY in this finally, never by
     *  navigation — is what fences deleteVault + the idle lock for the duration.
     *  Deliberately NO epoch guard here (design: manual Lock mid-copy stays unguarded —
     *  cross-platform parity; it degrades to an error). */
    fun copyItemsToPersonal(vaultId: String) {
        // Single-flight (review MED): copyOpVaultId is a single slot and the finally below
        // clears it unconditionally — an overlapping second copy would let the FIRST one's
        // finish disarm the gate (delete + idle lock re-enabled) while the second still
        // runs. One rescue at a time; the button mirrors this in its enabled gate.
        if (_ui.value.copyOpVaultId != null) return
        val e = engine ?: return
        _ui.value = _ui.value.copy(busy = true, error = null, copiedNote = null, copyProgress = 0 to 0, copyVaultId = vaultId, copyOpVaultId = vaultId)
        viewModelScope.launch {
            try {
                val copied = e.copyAllToPersonal(vaultId) { done, total ->
                    _ui.value = _ui.value.copy(copyProgress = done to total)
                }
                // A4: copyVaultId stays — the surviving note is named through it.
                _ui.value = _ui.value.copy(
                    busy = false, copyProgress = null, items = e.items(),
                    copiedNote = "Copied $copied ${if (copied == 1) "item" else "items"} to your Personal vault. You can still change your mind — deleting won't remove those copies.",
                )
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(copyProgress = null, copyVaultId = null)
                fail(t)
            } finally {
                // Ownership check (belt on the single-flight guard): only this call's own
                // marker may be cleared — a future re-entry path can never disarm a live copy.
                if (_ui.value.copyOpVaultId == vaultId) _ui.value = _ui.value.copy(copyOpVaultId = null)
            }
        }
    }

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

    fun clearCopiedNote() { _ui.value = _ui.value.copy(copiedNote = null, copyVaultId = null) }

    // F19 gestures memoized per (item|target|mode): a RETRY of a transiently-failed
    // move/copy reuses the SAME gesture (fresh ids were minted ONCE) so the server's
    // mutation dedup converges instead of duplicating. Kept ONLY across a failed attempt
    // of the same UNCHANGED item (#5): a rev change remints (a stale gesture would rebuild
    // attachments from a stale snapshot), and Cancel/dismiss discards.
    private val moveGestures = mutableMapOf<String, MoveGesture>()

    // The move/copy picker session lives HERE, not in the composition (#7, same convention
    // as editorOpen): completion across an Activity recreation must close the picker the
    // user is actually looking at, never a dead composition-captured callback.
    var movePickerMode by mutableStateOf<String?>(null) // "move" | "copy"
        private set
    var movePickerItemId by mutableStateOf<String?>(null)
        private set

    fun openMovePicker(itemId: String, mode: String) {
        movePickerItemId = itemId
        movePickerMode = mode
    }

    /** Picker cancel/dismiss: close it and discard the item's memoized gestures (#5). */
    fun closeMovePicker() {
        movePickerItemId?.let { id -> moveGestures.keys.filter { it.startsWith("$id|") }.forEach { moveGestures.remove(it) } }
        movePickerMode = null
        movePickerItemId = null
    }

    /** Move (copy + delete source) or copy [itemId] into [targetVaultId] (design §8). */
    fun moveOrCopyItem(itemId: String, targetVaultId: String, move: Boolean) {
        val e = engine ?: return
        val gKey = "$itemId|$targetVaultId|$move"
        _ui.value = _ui.value.copy(busy = true, error = null, moveProgress = null)
        viewModelScope.launch {
            try {
                val current = e.item(itemId)
                    ?: throw ApiException(409, "vault_state_changed", "This item is no longer here — it may have been removed or its vault deleted.")
                // #5: reuse the memo ONLY while the source content is unchanged — a
                // different rev IS different content (mirror of copyAllToPersonal's memo).
                val memo = moveGestures[gKey]
                val g = if (memo != null && memo.sourceRev == current.rev) memo
                        else e.newMoveGesture(itemId, targetVaultId, move).also { moveGestures[gKey] = it }
                e.runGesture(g, { done, total -> _ui.value = _ui.value.copy(moveProgress = done to total) })
                moveGestures.remove(gKey)
                val target = e.vaultInfos().find { it.vaultId == targetVaultId }?.name ?: "the other vault"
                // Completion is VM state (#7): close the picker + notice, whatever
                // composition is alive. A MOVE also empties the detail view via the item
                // list refresh (the source item is gone).
                movePickerMode = null
                movePickerItemId = null
                refreshItems()
                _ui.value = _ui.value.copy(moveProgress = null, notice = if (move) "Moved to “$target”." else "Copied to “$target”.")
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(moveProgress = null)
                when {
                    t is CopyDeniedException -> {
                        moveGestures.remove(gKey)
                        _ui.value = _ui.value.copy(busy = false, error = "You don't have permission to add items to that vault — nothing was moved.")
                    }
                    t is ItemChangedException -> {
                        moveGestures.remove(gKey)
                        _ui.value = _ui.value.copy(busy = false, error = "This item changed while moving — go back, review it, and try again.")
                    }
                    t is ApiException && t.status == 403 -> {
                        moveGestures.remove(gKey)
                        fail(t)
                    }
                    else -> {
                        // Transient — KEEP the gesture so Retry replays the same ids.
                        _ui.value = _ui.value.copy(busy = false, error = "That didn't finish. Press Retry — it won't create a duplicate.")
                    }
                }
            }
        }
    }

    // ---- inactivity auto-lock + foreground sync cadence (spec 01 §8 / spec 03 §6) ----

    /**
     * Lock if the inactivity window elapsed — or if another holder (the autofill gate in
     * [VaultSession.getIfFresh]) already dropped the session while this UI still shows the
     * vault. Never yanks the engine under an in-flight op ([UiState.busy]/import): the
     * durable queue would survive it, but the op would surface a spurious error — the
     * next 1 s tick re-checks, so the lock is deferred, not skipped.
     */
    fun checkIdleLock() {
        val s = _ui.value
        // §F.7 (desktop v2 #15 parity): a lock that lands mid-reveal destroys the shown-once
        // phrase — the honest reason says so, and that the §F.9 gate re-issues at the next unlock.
        // Mid-reveal gets NO grace: leaving a secret on an unattended screen is the wrong trade.
        val idleReason = if (pendingRecoverySecret != null) REASON_IDLE_RECOVERY else REASON_IDLE
        if (VaultSession.get() == null) {
            // Locked underneath us (autofill gate) — reflect it in the UI. Trash was missing
            // from this list (IA audit): a Trash screen left open must kick to lock like
            // every other unlocked view. Idle-class reason (F26): the autofill gate only
            // drops a session because its idle window expired. The two §F.9 recovery screens
            // are unlocked views too — a reveal over a dead session must die with it.
            if (s.screen is Screen.Vault || s.screen is Screen.Sharing || s.screen is Screen.Settings || s.screen is Screen.AutofillStatus || s.screen is Screen.Trash || s.screen is Screen.RecoverySetup || s.screen is Screen.RecoveryCapture) lock(idleReason)
            return
        }
        // A-copyGate: the rescue copy holds `busy`, but any OTHER op finishing mid-copy
        // clears it — the op guard is what actually keeps the idle lock off the engine
        // for the whole copy (never yank the engine mid-rescue).
        if (s.busy || s.importBusy || s.copyOpVaultId != null) return
        if (VaultSession.idleExpired()) lock(idleReason)
    }

    /**
     * Quiet poll sync (spec 03 §6: on foreground + every 5 min while foregrounded and
     * unlocked): refresh policy first (so autoLock/clipboard windows track admin changes
     * made mid-session), then push-queue + pull. Runs under [UiState.syncing], NEVER
     * [UiState.busy] (F74): busy greys out Save/buttons, and an offline sync can stall for
     * tens of seconds — the user must keep typing/saving through it. Both flags guard the
     * overlap (read and set on the main thread, so they can't interleave with a
     * user-initiated op), and `syncing` deliberately does NOT defer the auto-lock (see the
     * init collector): a mid-sync lock closes the engine under us, which the catch below
     * treats as an expected teardown, not a user-facing error. Transient network failures
     * stay silent (this runs unattended); anything else (rev regression, denied writes)
     * surfaces like a manual sync.
     */
    fun backgroundSync() {
        val current = VaultSession.get() ?: return
        if (_ui.value.busy || _ui.value.importBusy || _ui.value.syncing) return
        _ui.value = _ui.value.copy(syncing = true)
        // §4.2: the poll rides the LIVE session's api, whose origin is the baseUrl the session
        // was unlocked against — unchanged for the session's lifetime today (the ServerField
        // only renders signed-out; wave 3's switch flow tears the session down first).
        val originKey = store.currentOriginKey()
        viewModelScope.launch {
            // N2 §3/B4: deliberately NO onFailure — the poll must never flip policyFetchFailed
            // (that flag belongs to the enroll-feeding fetches; the last-known policy stays
            // live here for the offline gates). Success still clears it via applyPolicy.
            runCatching { current.api.clientPolicy() }.onSuccess { applyPolicy(it, originKey) }
            try {
                syncNow(current.engine)
                if (VaultSession.get() !== current) { // locked/rebound mid-sync — publish nothing stale
                    _ui.value = _ui.value.copy(syncing = false)
                    return@launch
                }
                _ui.value = _ui.value.copy(items = current.engine.items(), needsUpdateCount = current.engine.needsUpdateCount(), syncing = false)
                refreshLifecycle() // a background pull may have delivered notices/offers
            } catch (t: Throwable) {
                // A8: the 5-min foreground poll is the MOST FREQUENT server contact, so a
                // minVersion pin is most likely to surface here first — a 426 must raise the
                // blocking upgrade screen, never get swallowed into the silent background slot
                // below (its whole point is that transient poll failures stay quiet).
                if (t is UpgradeRequiredException) {
                    _ui.value = _ui.value.copy(syncing = false, upgradeRequired = UPGRADE_REQUIRED_MSG)
                    return@launch
                }
                // Locked/rebound mid-sync (auto-lock is NOT deferred for `syncing`): the
                // engine was closed under us — expected teardown, swallow it. #23: what DOES
                // surface (rev regression, denied writes) maps through the sync canon —
                // never `t.message`. IO stays silent here (unattended poll), so forSyncError's
                // SYNC_OFFLINE branch is deliberately unreachable on this path.
                val torn = VaultSession.get() !== current
                _ui.value = _ui.value.copy(syncing = false, error = if (t is IOException || torn) _ui.value.error else HouseholdCopy.forSyncError(t))
                if (!torn) refreshLifecycle() // even a denied/park cycle leaves notices to show
            }
        }
    }

    /** ON_RESUME hook: enforce the idle window FIRST, then catch up if still unlocked. */
    fun onForeground() {
        checkIdleLock()
        backgroundSync()
    }

    // ---- CSV import (spec 06 + universal importer, design 2026-07-11) ----

    // S2: the parsed file, retained ONLY while the preview is open — importSetVault
    // re-plans from it against another vault's projections. Plaintext (exactly like
    // importPlan.items, which outlives it anyway); dropped in importDismiss. Not in
    // UiState: nothing composes off it.
    private var importParsed: CsvImport.Parsed? = null

    /** Open the universal import sheet (the step BEFORE the system file picker). */
    fun importBegin() { _ui.value = _ui.value.copy(importSourceSheet = true) }

    /** "Choose file…" tapped; the UI launches the system file picker. The sheet closes
     *  FIRST, so a bad pick's error dialog renders context-free — which is why
     *  friendlyImport's unrecognized_header copy stays self-contained (A-androidError). */
    fun importChooseFile() { _ui.value = _ui.value.copy(importSourceSheet = false) }

    fun importSheetDismiss() { _ui.value = _ui.value.copy(importSourceSheet = false) }

    /**
     * Parse + plan a browser/manager CSV entirely on-device (no upload). [bytes] is read by
     * the UI. The plan is VAULT-AWARE (F75): `existing` = the personal vault's light
     * projections from the engine's working set, built by the core-owned builder (A8 —
     * never raw item lists mapped at the call site). If the working set is locked or the
     * personal vault isn't hydrated/synced yet, REFUSE with honest copy — never plan
     * against an empty `existing` (that would silently disable the dedupe).
     */
    fun importParse(bytes: ByteArray) {
        try {
            // The pre-flight runs INSIDE the catch: vaultInfos() is a live DB read, and a
            // binder-thread autofill hard-lock can close the cache between the null-check
            // and the query — outside the try that's an uncaught main-thread crash.
            val acct = account
            val eng = engine
            if (acct == null || eng == null || eng.vaultInfos().none { it.vaultId == acct.personalVaultId }) {
                importReject("Couldn’t check your vault for items you already have — unlock and sync first, then try the import again.")
                return
            }
            val parsed = CsvImport.parse(bytes)
            // S2: default destination = personal; ONE variable feeds the projections here
            // and (as importVaultId, set in the same copy) the eventual importAll.
            val dest = acct.personalVaultId
            importParsed = parsed
            _ui.value = _ui.value.copy(
                importFormat = parsed.format,
                importPlan = CsvImport.plan(parsed, eng.importProjections(dest)) { acct.newItemId() },
                importVaultId = dest,
                // A10 LastPass mangle heuristic: multiple HTML-entity hits across values.
                importMangleNote = if (looksHtmlMangled(parsed))
                    "This file looks HTML-mangled — re-export via Advanced → Export and choose the file download." else null,
                importRowOrdinals = CsvImport.rowOrdinalsByLine(bytes), // A9, same reader as parse
                importReport = null, importError = null, importProgress = null, importBusy = false, importDone = false,
            )
        } catch (e: CsvImport.ImportException) {
            _ui.value = _ui.value.copy(importError = friendlyImport(e.code), importPlan = null, importDone = false)
        } catch (t: Throwable) {
            // #23: the bytes never left the device — forImportError says "couldn't read that
            // file", never network copy and never the exception's own message.
            _ui.value = _ui.value.copy(importError = HouseholdCopy.forImportError(t), importPlan = null, importDone = false)
        }
    }

    /** Reject a file without parsing (e.g. the UI's bounded read hit the size cap). */
    fun importReject(message: String) {
        _ui.value = _ui.value.copy(importError = message, importPlan = null, importDone = false)
    }

    /**
     * S2: switch the import's destination vault — RE-PLANS the parsed file against that
     * vault's projections (the F75 dedupe is per-vault; a plan fingerprinted against one
     * vault must never commit into another). The fresh plan and importVaultId land in ONE
     * copy(), so importConfirm's single snapshot can never pair them mismatched.
     * importBusy covers the re-plan: Confirm disables and a second tap here no-ops.
     */
    fun importSetVault(vaultId: String) {
        val acct = account
        val eng = engine
        val parsed = importParsed
        if (acct == null || eng == null || parsed == null) return
        // Web importLocked parity: after an import ATTEMPT (error = partial, done = landed)
        // a re-plan would mint new ids — breaking Retry's idempotent replay and duplicating
        // the already-landed rows into the new destination. Only Retry or Dismiss remain.
        val st = _ui.value
        if (st.importBusy || st.importError != null || st.importDone || vaultId == st.importVaultId) return
        // Refuse-not-degrade (A8), now gating the CHOSEN vault: the picker only offers
        // held vaults, but a sync-time removal can race the tap — never re-plan against
        // a vault we no longer hold (it would plan as if the vault were empty).
        if (eng.vaultInfos().none { it.vaultId == vaultId }) {
            importReject("That vault isn’t available any more — sync and try the import again.")
            return
        }
        _ui.value = _ui.value.copy(importBusy = true, importError = null)
        viewModelScope.launch {
            try {
                val plan = withContext(Dispatchers.Default) {
                    CsvImport.plan(parsed, eng.importProjections(vaultId)) { acct.newItemId() }
                }
                _ui.value = _ui.value.copy(importPlan = plan, importVaultId = vaultId, importBusy = false, importProgress = null)
            } catch (t: Throwable) {
                // plan/vault left unchanged — still a matched pair, so Confirm stays safe.
                // #23: a local re-plan failure is a read failure, never raw exception text.
                _ui.value = _ui.value.copy(importBusy = false, importError = HouseholdCopy.forImportError(t))
            }
        }
    }

    /**
     * Encrypt-and-push the planned items. Reuses plan.items on every call so a mid-import
     * failure is fixed with Retry (idempotent replay of the same itemIds), NOT a re-parse.
     */
    fun importConfirm() {
        // S2: plan + destination from ONE snapshot — they were set together, and reading
        // them together is what keeps the F75 invariant (never re-read the picker).
        val snap = _ui.value
        if (snap.importBusy) return // state-level: the button's enabled flag lags a frame behind a re-plan
        val plan = snap.importPlan ?: return
        val dest = snap.importVaultId
        _ui.value = _ui.value.copy(importBusy = true, importError = null, importProgress = 0 to plan.items.size)
        viewModelScope.launch {
            try {
                engine!!.importAll(plan.items, onProgress = { done, total -> _ui.value = _ui.value.copy(importProgress = done to total) }, vaultId = dest)
                // The destination can be deleted INTO GRACE mid-import: denials park (F21) and
                // importAll returns normally — success copy telling the user to delete the CSV
                // would then be a lie. A held/gone destination is not a success.
                if (dest != null && engine?.vaultInfos()?.none { it.vaultId == dest } == true) {
                    _ui.value = _ui.value.copy(importBusy = false, importError = "The destination vault was removed while importing — the rows are parked and will land only if it is restored. KEEP the CSV file.")
                    return@launch
                }
                _ui.value = _ui.value.copy(importBusy = false, importDone = true, importReport = plan.report, items = engine?.items() ?: emptyList())
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(importBusy = false, importError = "Import interrupted — press Retry to finish (no duplicates will be created).")
            }
        }
    }

    fun importDismiss() {
        importParsed = null
        _ui.value = _ui.value.copy(
            importPlan = null, importFormat = null, importReport = null, importError = null,
            importProgress = null, importBusy = false, importDone = false, importVaultId = null,
            importSourceSheet = false, importMangleNote = null,
        )
    }

    private fun friendlyImport(code: String): String = when (code) {
        "too_large" -> "That file is larger than 10 MiB — far bigger than any real password export."
        "too_many_rows" -> "That file has more than 10,000 rows. Split it into smaller files and import each."
        // A-androidError (universal importer, design 2026-07-11): the sheet closes BEFORE the
        // SAF picker, so this dialog renders context-free — the recognized-source enumeration
        // must live in the message itself, never lean on the sheet's honest line being visible.
        "unrecognized_header" ->
            "This file isn't a recognized password export — andvari reads CSVs from Chrome and other Chromium browsers, Firefox, Bitwarden, 1Password 8 or newer, LastPass, and Safari. Make sure you exported a CSV (not JSON or a zip)."
        else -> "That file could not be read ($code)."
    }

    /** A10 heuristic: a LastPass export copied from the in-page text arrives HTML-escaped.
     *  Fires when MULTIPLE values contain an HTML entity. Never auto-decoded — info only. */
    private fun looksHtmlMangled(parsed: CsvImport.Parsed): Boolean {
        var hits = 0
        for (r in parsed.rows) {
            for (v in listOf(r.name, r.url, r.username, r.password, r.notes, r.totp ?: "")) {
                if (HTML_ENTITY.containsMatchIn(v) && ++hits >= 2) return true
            }
        }
        return false
    }

    private companion object {
        val HTML_ENTITY = Regex("""&(amp|lt|gt|quot|#\d+);""")
    }

    /** Seed-derived identity short code (spec 01 §5) — read out during sharing verification. */
    fun identityCode(): String? = account?.identityFingerprintShort()

    /** Mint the ref for a newly picked file: random id + random per-file key (never logged). */
    fun newAttachmentRef(name: String, size: Long): AttachmentRef? = account?.let {
        AttachmentRef(id = it.newItemId(), name = name, size = size, fileKey = Bytes.toB64(it.newFileKey()))
    }

    /** Download + decrypt [ref], hand the plaintext straight to [write] (no cache, no log), then wipe it. */
    fun saveAttachmentTo(ref: AttachmentRef, write: (ByteArray) -> Unit) {
        _ui.value = _ui.value.copy(busy = true, error = null, notice = null)
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val plain = engine!!.downloadAttachment(ref)
                    try { write(plain) } finally { plain.fill(0) }
                }
                _ui.value = _ui.value.copy(busy = false, notice = "Saved ${ref.name}")
            } catch (t: Throwable) {
                fail(t)
            }
        }
    }

    // ---- export & backup (spec 07) ----

    /**
     * "Back up vault…" step 1: sync first (spec 07 — clients MUST sync before
     * snapshotting; offline → proceed with a "vault as of last sync <time>" note), then
     * open the preflight dialog. Runs under [UiState.busy], which the 1 s idle-check
     * defers on (checkIdleLock) — the auto-lock cannot yank the engine mid-flow.
     */
    fun backupBegin() {
        val e = engine ?: return
        _ui.value = _ui.value.copy(busy = true, error = null, notice = null)
        viewModelScope.launch {
            val offline = try {
                syncNow(e); false
            } catch (t: IOException) {
                true // offline is fine — export the cached snapshot, visibly dated
            } catch (t: Throwable) {
                fail(t); return@launch // rev regression / denied writes: surface, don't export
            }
            val current = VaultSession.get() ?: run { _ui.value = _ui.value.copy(busy = false); return@launch }
            _ui.value = _ui.value.copy(
                busy = false,
                items = current.engine.items(),
                backupPreflight = BackupPreflight(ExportPlanner.vaultLines(current.engine, current.account), offlineNote(offline)),
            )
        }
    }

    fun backupDismiss() { _ui.value = _ui.value.copy(backupPreflight = null) }
    fun backupResultDismiss() { _ui.value = _ui.value.copy(backupResult = null) }

    // Pending backup request across the SAF round-trip. Lives HERE (not `remember`) so a
    // configuration change while the picker is foreground doesn't drop it — see
    // [BackupRequest]. Cleared on lock()/signOut(): a stash must never survive into a
    // different (re)unlock — its vault ids and passphrase belong to the session that
    // created it.
    private var pendingBackupRequest: BackupRequest? = null

    /** Preflight confirmed; hold the request until the SAF picker returns. */
    fun backupRequestStash(req: BackupRequest) { pendingBackupRequest = req }

    /** Consume (and clear) the pending request when the SAF picker returns. */
    fun backupRequestTake(): BackupRequest? = pendingBackupRequest.also { pendingBackupRequest = null }

    /**
     * The SAF picker returned a destination but the request is gone — process death while
     * the picker was foreground (the passphrase is deliberately never saved to SavedState,
     * so this cannot resume), or a lock/sign-out cleared the stash. Discard the created
     * document (best-effort, empty-only — see MainActivity.discardExportDoc) and explain;
     * never leave a silent 0-byte file.
     */
    fun backupRequestMissing(discard: () -> Unit) {
        runCatching { discard() }
        _ui.value = _ui.value.copy(
            busy = false,
            error = "That backup was interrupted (the app restarted or locked) — nothing was saved. Please start the backup again.",
        )
    }

    /** Live §2.5 attachment plan for the preflight dialog's current vault selection
     *  (pure in-memory reads — cheap enough for recomposition). */
    fun attachmentPlan(selected: Set<String>): AttachmentPlan {
        val current = VaultSession.get() ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        val order = _ui.value.backupPreflight?.vaults?.map { it.vaultId }?.filter { it in selected }
            ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        return ExportPlanner.planAttachments(ExportPlanner.orderedItems(current.engine, order))
    }

    /**
     * "Back up vault…" step 2: build → verify → hand bytes to [write] (the SAF stream)
     * → re-read via [readBack] and verify the ON-DISK bytes, all off the UI thread.
     * [discard] removes the destination on failure, but ONLY what this run may own:
     * it receives writeBegan=true iff [write] started (destination opened/truncated) —
     * a failure before that must not delete a pre-existing document the user chose to
     * overwrite (spec 07 §2.6 forbids a partial file, not a preserved old one).
     * Success records lastExportAt locally (never server-side) and counts as user
     * activity for the auto-lock.
     */
    fun backupRun(
        selectedVaults: Set<String>,
        includeAttachments: Boolean,
        passphrase: String,
        write: (ByteArray) -> Unit,
        readBack: () -> ByteArray?,
        discard: (writeBegan: Boolean) -> Unit,
    ) {
        val current = VaultSession.get() ?: run {
            // The idle auto-lock can expire while the user is in the SAF picker: the
            // picker is another app, so no dispatch*Event reaches MainActivity and the
            // 1 s ticker keeps counting (the export hasn't set busy yet). Treat it as a
            // cleanly ABORTED export — nothing was written, so remove the just-created
            // document (empty-only guard inside discard) and say so. Never the old
            // silent return that left a 0-byte file behind. Deliberately NOT fixed by
            // suppressing the idle lock across the picker round-trip: the user is in
            // another app for an unbounded time, and holding keys unlocked past the
            // policy window there would defeat spec 01 §8.
            runCatching { discard(false) }
            _ui.value = _ui.value.copy(
                busy = false, backupPreflight = null,
                error = "The vault locked while choosing where to save — nothing was exported.",
            )
            return
        }
        _ui.value = _ui.value.copy(busy = true, error = null, backupPreflight = null)
        viewModelScope.launch {
            var writeBegan = false
            try {
                val result = withContext(Dispatchers.IO) {
                    buildAndWriteBackup(
                        current, selectedVaults, includeAttachments, passphrase,
                        write = { bytes -> writeBegan = true; write(bytes) },
                        readBack = readBack,
                    )
                }
                store.lastExportAt = System.currentTimeMillis()
                VaultSession.touch() // export counts as user activity (spec 07 §2.6 / 01 §8)
                _ui.value = _ui.value.copy(busy = false, backupResult = result, lastExportAt = store.lastExportAt)
            } catch (t: Throwable) {
                // Failure BEFORE write began (build/fetch/in-memory verify threw): the
                // destination was never touched — discard(false) deletes it only if it
                // is a fresh empty doc, never a pre-existing backup. Failure DURING/
                // AFTER write: content is partial or failed on-disk verification —
                // delete it (§2.6). The success path above never reaches here, so a
                // completed backup is never discarded.
                runCatching { discard(writeBegan) }
                fail(t, ::exportError)
            }
        }
    }

    private suspend fun buildAndWriteBackup(
        current: VaultSession.Unlocked,
        selectedVaults: Set<String>,
        includeAttachments: Boolean,
        passphrase: String,
        write: (ByteArray) -> Unit,
        readBack: () -> ByteArray?,
    ): BackupResult {
        val account = current.account
        val engine = current.engine
        val crypto = account.cryptoProvider()

        // Snapshot every input up front (cheap in-memory reads): a concurrent manual lock
        // can close the engine's cache underneath a long build, and reads-then-crypto keeps
        // that window to "attachment downloads fail → named skips", never a torn payload.
        val allLines = ExportPlanner.vaultLines(engine, account)
        val lines = allLines.filter { it.vaultId in selectedVaults }
        val items = ExportPlanner.orderedItems(engine, lines.map { it.vaultId })
        // Enumerate undecryptable envelopes (missing VK / newer formatVersion) — but not
        // those of a VK-held vault the user explicitly deselected.
        val deselected = allLines.map { it.vaultId }.toSet() - selectedVaults
        val undecryptable = ExportPlanner.undecryptable(engine).filter { it.vaultId !in deselected }
        val formatVersions = engine.envelopes().associate { it.itemId to it.formatVersion }

        // §2.5: fetch each opted-in attachment plaintext one at a time through the normal
        // client path; ONE retry, then skip BY NAME — never silently, never fatal. The
        // buffers are held until Backup.build consumes (and zeroes) them; the 64 MiB
        // total-plaintext cap keeps the whole set far below the Android heap.
        val plan = if (includeAttachments) ExportPlanner.planAttachments(items) else AttachmentPlan(emptyList(), 0L, emptyList())
        val fetched = ArrayList<Pair<PlannedAttachment, ByteArray>>()
        val fetchFailed = ArrayList<String>()
        for (p in plan.included) {
            var bytes: ByteArray? = null
            for (attempt in 0 until 2) {
                bytes = runCatching { current.engine.downloadAttachment(p.ref) }.getOrNull()
                if (bytes != null) break
            }
            if (bytes == null) fetchFailed.add(p.ref.name) else fetched.add(p to bytes)
        }

        try {
            // Manifest fileKeys are FRESH per-section keys (spec 07 §2.4); the docs keep
            // their original server-blob fileKeys verbatim inside the payload.
            val freshKeys = fetched.map { account.newFileKey() }
            val manifest = fetched.mapIndexed { i, (p, bytes) ->
                BackupAttachmentEntry(
                    section = i + 1, attachmentId = p.ref.id, itemId = p.item.itemId,
                    name = p.ref.name, size = bytes.size.toLong(), fileKey = Bytes.toB64(freshKeys[i]),
                )
            }
            val payload = BackupPayload(
                exportedAt = System.currentTimeMillis(), // call-site clock; core takes it as data
                origin = store.baseUrl,
                userId = account.userId,
                identityFingerprint = account.identityFingerprintShort(),
                vaults = lines.map { BackupVault(it.vaultId, it.type, it.name, it.role) },
                items = items.map { BackupItem(it.itemId, it.vaultId, formatVersions[it.itemId] ?: 1, it.updatedAt, it.doc) },
                attachments = manifest,
                skipped = BackupSkipped(undecryptable, plan.overCap, fetchFailed),
            )

            // spec 01 §1 production KDF params (live policy when known), clamped to the
            // §2.2 open() ceilings so the file we produce is always re-openable.
            val policyParams = _ui.value.policy?.kdfParams ?: KdfParams.DEFAULT
            val kdfParams =
                if (policyParams.ops <= Backup.MAX_KDF_OPS && policyParams.memBytes <= Backup.MAX_KDF_MEM_BYTES) policyParams
                else KdfParams.DEFAULT

            // Build to an in-memory buffer, verify, THEN stream to the destination (spec
            // 07 §2.6 write-discipline: verify before declaring success, and a failure
            // must never leave a partial file). In-memory is deliberate: the §2.5 64 MiB
            // attachment-plaintext cap + items keeps the whole container comfortably
            // below the heap on any supported device, and it lets us verify the EXACT
            // bytes we are about to persist before the SAF document sees a single one.
            val out = java.io.ByteArrayOutputStream()
            val sections = fetched.mapIndexed { i, (_, bytes) -> Backup.AttachmentSection(freshKeys[i]) { bytes } }
            Backup.build(
                crypto = crypto, passphrase = passphrase,
                fileId = account.newItemId(), kdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES),
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

            write(file)

            // §2.6 strongest form: verify the ON-DISK bytes, not just our buffer. Re-read
            // the document and require byte-equality with the container we just verified
            // via Backup.open — equality transfers that verification to the persisted
            // bytes without re-running the Argon2id KDF. This is also the safety net for
            // providers that ignore/reject the "wt" truncate mode (stale trailing bytes
            // from a longer pre-existing file fail this check; readBack returns null when
            // the on-disk doc exceeds the spec §2.2 256 MiB cap, which also fails it).
            // Cost: one extra read of ≤ ~70 MiB ciphertext (§2.5 cap) — cheap next to the
            // KDF we already ran for the verify-open.
            val onDisk = readBack()
            if (onDisk == null || !onDisk.contentEquals(file)) {
                throw IllegalStateException("backup verification failed — the saved file does not match the verified backup")
            }
            return BackupResult(items.size, lines.size, manifest.size, plan.overCap, fetchFailed)
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
        _ui.value = _ui.value.copy(busy = true, error = null, notice = null)
        viewModelScope.launch {
            val offline = try {
                syncNow(e); false
            } catch (t: IOException) {
                true
            } catch (t: Throwable) {
                fail(t); return@launch
            }
            val current = VaultSession.get() ?: run { _ui.value = _ui.value.copy(busy = false); return@launch }
            val docs = orderedDocs(current)
            _ui.value = _ui.value.copy(
                busy = false,
                items = current.engine.items(),
                csvPreflight = CsvPreflight(ExportCsv.warnings(docs), docs.count { it.type == "login" }, offlineNote(offline)),
            )
        }
    }

    fun csvDismiss() { _ui.value = _ui.value.copy(csvPreflight = null) }

    /** CSV step 2: write the spec 07 §1 bytes (UTF-8, no BOM) through [write], then
     *  verify the on-disk bytes via [readBack] (backstops providers that ignore the
     *  "wt" truncate mode — a stale tail from a longer pre-existing file must fail
     *  here, not surface as garbage rows in another manager's import). [discard]
     *  follows the same writeBegan discipline as [backupRun]: never delete a
     *  pre-existing document this run hasn't touched. */
    fun csvRun(write: (ByteArray) -> Unit, readBack: () -> ByteArray?, discard: (writeBegan: Boolean) -> Unit) {
        val current = VaultSession.get() ?: run {
            // Same lock-during-SAF-picker abort as backupRun: discard the just-created
            // (empty-only) document and surface the abort — never a silent 0-byte file.
            runCatching { discard(false) }
            _ui.value = _ui.value.copy(
                busy = false, csvPreflight = null,
                error = "The vault locked while choosing where to save — nothing was exported.",
            )
            return
        }
        _ui.value = _ui.value.copy(busy = true, error = null, csvPreflight = null)
        viewModelScope.launch {
            var writeBegan = false
            try {
                val count = withContext(Dispatchers.IO) {
                    val docs = orderedDocs(current)
                    val bytes = ExportCsv.write(docs).encodeToByteArray()
                    try {
                        writeBegan = true
                        write(bytes)
                        val onDisk = readBack()
                        val ok = onDisk != null && onDisk.contentEquals(bytes)
                        onDisk?.fill(0) // plaintext passwords — wipe the read-back copy too
                        if (!ok) throw IllegalStateException("export verification failed — the saved file does not match what was written")
                    } finally {
                        bytes.fill(0) // plaintext passwords — wipe our copy
                    }
                    docs.count { it.type == "login" }
                }
                VaultSession.touch()
                _ui.value = _ui.value.copy(busy = false, notice = "Exported $count logins. Delete the CSV once the other manager has imported it.")
            } catch (t: Throwable) {
                runCatching { discard(writeBegan) }
                fail(t, ::exportError)
            }
        }
    }

    /** All VK-held docs in the pinned export order (vault order, then updatedAt). */
    private fun orderedDocs(current: VaultSession.Unlocked): List<ItemDoc> {
        val order = ExportPlanner.vaultLines(current.engine, current.account).map { it.vaultId }
        return ExportPlanner.orderedItems(current.engine, order).map { it.doc }
    }

    private fun offlineNote(offline: Boolean): String? {
        if (!offline) return null
        val at = store.lastSyncAt
        val stamp = if (at > 0) java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(at)) else "(unknown)"
        return "Offline — this exports the vault as of last sync $stamp."
    }

    /** F26: [reason] names WHY for the Unlock screen — [REASON_LOCKED] (manual, the default)
     *  or [REASON_IDLE] from the idle paths. Set fresh per lock event, never carried. */
    fun lock(reason: String = REASON_LOCKED) {
        // Close the engine (and its cache DB handle) but KEEP the file — the ciphertext
        // cache is retained on lock (spec 05 T3); a relaunch hydrates it.
        VaultSession.lock()
        pendingBackupRequest = null // a stashed export must not survive a lock (see stash docs)
        // §F.7: an interrupted reveal dies with the lock — zero the raw secret + its pieceId; the
        // §F.9 capture gate re-issues a fresh phrase at the next unlock (recoveryConfirmed is
        // still false server-side). The capture reauth proof is password-equivalent — dies too,
        // and so does any half-finished forgot-password attempt's material.
        zeroPendingRecovery()
        zeroPendingRecover()
        pendingCaptureAuthKey = null
        closeEditor() // the editor session (and its picked plaintext bytes) dies with the lock
        importDismiss() // the parsed CSV + plan hold every password in the file — never outlive the lock
        moveGestures.clear() // gestures reference the dead engine's item state
        movePickerMode = null
        movePickerItemId = null
        _ui.value = _ui.value.copy(
            screen = Screen.Unlock(store.load()?.email ?: ""), items = emptyList(), needsUpdateCount = 0,
            notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
            backupPreflight = null, backupResult = null, csvPreflight = null,
            lifecycleNotices = emptyList(), incomingTransfers = emptyList(), transferOwnerNames = emptyMap(),
            sharingMembers = emptyMap(), deletedVaults = emptyList(), heldVaults = emptyList(),
            undecryptableSharedVaultCount = 0, sharingSettingsVaultId = null,
            copyProgress = null, copiedNote = null, copyVaultId = null, copyOpVaultId = null, moveProgress = null,
            // Trash holds DECRYPTED tombstone docs (incl. passwords) + item versions; now that
            // checkIdleLock routinely locks from the Trash screen, they must not outlive the lock.
            deletedItems = null, itemVersions = null,
            // P4: the ReSealCard now lives in the GLOBAL AttentionArea (renders on Unlock too),
            // so escrowStale MUST clear on lock — else a "Later"-deferred re-seal card shows on
            // the lock screen with a dead action (engine torn down). Fresh unlock re-reads it.
            escrowStale = false, escrowFingerprint = "",
            // §F.7/§F.9: the reveal's display form + gate state die with the lock (the raw secret
            // was zeroed above); a fresh unlock re-derives everything.
            recoveryPhrase = null, recoverySetupWaived = false, recoveryCaptureError = null, recoveryReplacedNotice = false,
            recoverVerified = false,
            // N2 §3/§6 (review MED): clear the probe-failure flag only when a policy is
            // LOADED — then it's stale noise. With policy == null the failure is CURRENT
            // (nothing re-probes on the way to Welcome), and clearing it would strand the
            // enroll tab in the probe-in-flight "Checking the server…" text with no Retry
            // and no probe. Web parity: signOut never clears policyError either. The lock
            // reason is THIS event's — fresh, never carried.
            policyFetchFailed = _ui.value.policy == null && _ui.value.policyFetchFailed,
            lockReason = reason,
        )
    }

    /** F26: [reason] is non-null only when a dead session FORCES a sign-out (no such caller
     *  exists today — the unlock-time 401 paths set [REASON_SESSION_ENDED] directly instead);
     *  both live call sites are USER-initiated (Unlock screen, upgrade-screen escape) and take
     *  the default — a deliberate sign-out needs no explanation line on Welcome. */
    fun signOut(reason: String? = null) {
        if (_ui.value.busy) return
        val session = store.load()
        val current = VaultSession.get()
        _ui.value = _ui.value.copy(busy = true, error = null)
        viewModelScope.launch {
            // AWAIT the server-side revocation (bounded) BEFORE tearing the session down.
            // The old fire-and-forget launch raced VaultSession.lock() → api.close(), which
            // cancelled the in-flight logout and left the refresh token valid for ~30 days.
            if (current != null) {
                runCatching { withTimeoutOrNull(5_000) { current.api.logout() } }
            } else if (session != null && session.accessToken.isNotEmpty()) {
                // LOCKED sign-out (the Unlock screen's "Sign out / use a different
                // account"): no live token-holder exists, but the persisted refresh token
                // is still valid server-side — store.clear() alone would leave it live for
                // ~30 days. Build a short-lived holder from the persisted session (same
                // shape as newApi(): updateTokens wired so any rotation persists) purely
                // to revoke it.
                val a = newApi(session.tokens())
                runCatching { withTimeoutOrNull(5_000) { a.logout() } }
                a.close()
            }
            // VaultSession.lock() closes the engine BEFORE we delete the DB (holders), then the api.
            VaultSession.lock()
            pendingBackupRequest = null // never carry a stashed export into a different account
            zeroPendingRecovery() // §F.7: the raw secret + its pieceId never outlive the account
            zeroPendingRecover() // …nor a forgot-password attempt's parsed phrase/ticket
            pendingCaptureAuthKey = null // password-equivalent — dies with the session
            closeEditor()
            importDismiss() // account A's plaintext CSV/plan must never resurface in account B's session
            moveGestures.clear()
            movePickerMode = null
            movePickerItemId = null
            session?.userId?.let {
                // §4.2: a sign-out clears the CURRENT origin's namespace — the session being
                // ended lived there; other origins' material is bounded by their own staleness
                // ceilings and policy flips, never collaterally wiped.
                val originKey = store.currentOriginKey()
                deleteCache(originKey, it)
                // Sign-out always clears the quick-unlock secret + freshness stamp (spec 01 §8.1).
                QuickUnlock.wipe(cacheDir, originKey, it)
                store.clearFullPasswordStamp(originKey, it)
            }
            store.clear()
            _ui.value = _ui.value.copy(
                screen = Screen.Welcome, items = emptyList(), needsUpdateCount = 0, busy = false,
                quickUnlockEnrolled = false, quickUnlockFresh = false, quickUnlockOffer = false, quickUnlockMessage = null,
                mustChangePassword = false, // store.clear() dropped the persisted F58 flag with the account
                upgradeRequired = null, // A9 escape: sign-out must LIFT the 426 block — copy() would otherwise carry it forward and re-brick over Welcome

                notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
                lifecycleNotices = emptyList(), incomingTransfers = emptyList(), transferOwnerNames = emptyMap(),
                sharingMembers = emptyMap(), deletedVaults = emptyList(), heldVaults = emptyList(),
                undecryptableSharedVaultCount = 0, sharingSettingsVaultId = null,
                copyProgress = null, copiedNote = null, copyVaultId = null, copyOpVaultId = null, moveProgress = null,
                escrowStale = false, escrowFingerprint = "", // P4: global ReSealCard must not linger on Welcome
                // §F.7/§F.9: reveal display form + gate state never outlive the account (raw secret zeroed above)
                recoveryPhrase = null, recoverySetupWaived = false, recoveryCaptureError = null, recoveryReplacedNotice = false,
                recoverVerified = false,
                // N2 §3/§6 (review MED): a probe failure with NO policy loaded is current,
                // not stale — keep it so Welcome shows the failure + Retry instead of the
                // dead-end "Checking the server…" (nothing re-probes on this path). With a
                // policy loaded, clear as before. The reason line shows only for a
                // session-end sign-out (user-initiated passes null).
                policyFetchFailed = _ui.value.policy == null && _ui.value.policyFetchFailed,
                lockReason = reason,
            )
        }
    }

    // ---- settings / server TOTP ----

    fun openSettings() {
        _ui.value = _ui.value.copy(
            screen = Screen.Settings, totpStatus = null, totpSetup = null, totpMessage = null,
            backupPreflight = null, backupResult = null, csvPreflight = null, lastExportAt = store.lastExportAt,
        )
        refreshQuickUnlockState() // the quick-unlock toggle reflects current enrollment/eligibility
        viewModelScope.launch {
            try {
                _ui.value = _ui.value.copy(totpStatus = api!!.totpStatus())
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(totpMessage = HouseholdCopy.forTotpError(t)) // #23: never raw wire text
            }
        }
    }

    fun closeSettings() {
        _ui.value = _ui.value.copy(screen = Screen.Vault, totpSetup = null, totpMessage = null)
    }

    // ---- autofill status (diagnostic surface; reached from Settings) ----

    fun openAutofillStatus() {
        _ui.value = _ui.value.copy(screen = Screen.AutofillStatus)
    }

    fun closeAutofillStatus() {
        _ui.value = _ui.value.copy(screen = Screen.Settings)
    }

    fun totpBegin() = totpOp {
        _ui.value = _ui.value.copy(totpSetup = api!!.totpSetup(), busy = false)
    }

    fun totpConfirm(code: String) = totpOp {
        _ui.value = _ui.value.copy(totpStatus = api!!.totpConfirm(code), totpSetup = null, busy = false)
    }

    fun totpDisable(code: String) = totpOp {
        _ui.value = _ui.value.copy(totpStatus = api!!.totpDisable(code), busy = false)
    }

    private fun totpOp(block: suspend () -> Unit) {
        _ui.value = _ui.value.copy(busy = true, totpMessage = null)
        viewModelScope.launch {
            try {
                block()
            } catch (t: Throwable) {
                // #23: the shared canon covers bad_totp_code (its authenticator-hint wording
                // deliberately unifies android's old shorter variant) and never leaks raw text.
                _ui.value = _ui.value.copy(busy = false, totpMessage = HouseholdCopy.forTotpError(t))
            }
        }
    }

    // ---- helpers ----
    private fun bind(a: AndvariApi, acct: Account, provenance: VaultSession.UnlockProvenance = VaultSession.UnlockProvenance.PASSWORD) {
        // Durable cache unless policy forbids it (then delete any existing file). Hydrate
        // the working set from disk BEFORE the first sync so a cold/offline start shows data.
        // Prefer the live policy; fall back to the persisted last-known value when offline
        // (a policy-forbidden device cold-starting offline must NOT recreate the cache).
        val allowed = _ui.value.policy?.offlineCacheAllowed ?: store.cacheAllowed
        val originKey = store.currentOriginKey() // §4.2: the session binds to the current origin's namespace
        val cache = if (allowed) {
            sqliteVaultCache(cacheFile(originKey, acct.userId).apply { parentFile?.mkdirs() }.absolutePath, acct.userId)
        } else {
            deleteCache(originKey, acct.userId); InMemoryVaultCache()
        }
        val newEngine = SyncEngine(a, acct, cache).also { it.hydrate() }
        // VaultSession closes any previously-bound engine/api (defensive: never two conns).
        VaultSession.bind(a, acct, newEngine, provenance)
    }

    /** Sync + record the wall-clock time of the last SUCCESS — the timestamp the spec 07
     *  offline-export note shows ("vault as of last sync <time>"). */
    private suspend fun syncNow(e: SyncEngine) {
        e.sync()
        store.lastSyncAt = System.currentTimeMillis()
    }

    private fun refreshItems() {
        _ui.value = _ui.value.copy(items = engine?.items() ?: emptyList(), needsUpdateCount = needsUpdate(), busy = false, error = null)
        refreshLifecycle()
    }

    private fun toVault() {
        // lockReason clears HERE — the one success landing shared by unlock, sign-in, quick
        // unlock, and enroll (F26: the explanation must not outlive the event it explains).
        // §F.9 gate state clears with it (recoveryPhrase always did; the capture error and the
        // replaced-phrase notice are meaningless once the vault is open).
        _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), needsUpdateCount = needsUpdate(), busy = false, error = null, loginTotpRequired = false, quickUnlockMessage = null, lockReason = null, recoveryPhrase = null, recoveryCaptureError = null, recoveryReplacedNotice = false)
        refreshLifecycle()
        refreshQuickUnlockState() // may surface the one-time enrollment offer card
    }

    /** [mapError] is the #23 context seam: sign-in/unlock/save/sync ops pass their
     *  [HouseholdCopy] mapper so a failure reads right for ITS surface; everything else
     *  takes the general [HouseholdCopy.forError]. */
    private fun op(mapError: (Throwable) -> String = HouseholdCopy::forError, block: suspend () -> Unit) {
        _ui.value = _ui.value.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                block()
            } catch (e: UpgradeRequiredException) {
                // A8: a 426 is not a per-action error — this build is too old for the server's
                // minVersion pin. Raise the blocking upgrade screen (A9), not a dismissable toast.
                _ui.value = _ui.value.copy(busy = false, upgradeRequired = UPGRADE_REQUIRED_MSG)
            } catch (t: Throwable) {
                fail(t, mapError)
            }
        }
    }
}
