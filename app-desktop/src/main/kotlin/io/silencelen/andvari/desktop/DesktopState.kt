package io.silencelen.andvari.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.CopyDeniedException
import io.silencelen.andvari.core.client.ItemChangedException
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
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PendingTransfer
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
}

/** F74: the Settings server-TOTP status fetch as an honest tri-state — Failed must STOP
 *  the spinner and offer Retry, instead of spinning forever beside its own error (the old
 *  shape used totpStatus==null for both "checking" and "check failed"). */
enum class TotpLoad { Pending, Ready, Failed }

/**
 * Plain state holder for the desktop app (no AndroidX ViewModel). Drives the shared
 * :core client (Account + AndvariApi[java engine] + SyncEngine) and exposes Compose
 * state. Mirrors the Android AndvariViewModel.
 */
class DesktopState(private val scope: CoroutineScope) {
    private val store = DesktopSessionStore()

    init {
        // One-time: bump an old LAN-default server URL to the tailnet default before any
        // state reads it (mirrors Android's MainActivity.migrateDefaultOnce).
        store.migrateDefaultOnce()
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
    // §6 (F26): why the vault locked — one quiet line on the Unlock screen. Set FRESH per
    // lock event (manual / idle), cleared on successful unlock + sign-in and by signOut
    // (user-initiated — owes no explanation). Desktop has NO 401-driven sign-out path (a
    // 401 during unlock wipes the store but stays on the Unlock screen), so the web
    // "session ended" reason is deliberately unwired here.
    var lockReason by mutableStateOf<String?>(null)
        private set
    var busy by mutableStateOf(false)
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
    var baseUrl by mutableStateOf(store.baseUrl)
        private set
    var updateAvailable by mutableStateOf<String?>(null)
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
    // (no admin backstop). Native enroll is required-only today, so this is always false; wired for
    // the waived toggle a later cut adds (TODO(recovery-cut-2)).
    var recoverySetupWaived by mutableStateOf(false)
        private set
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

    private fun newApi(tokens: Tokens? = null) =
        AndvariApi(store.baseUrl, HttpClient(Java), tokens, { store.updateTokens(it) }, platform = desktopPlatform())

    fun start() {
        scope.launch {
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                policyFetchFailed = false
                applyPolicy(p) // UI state + persisted offline fallbacks (auto-lock included)
                // Policy may forbid the durable cache; purge any existing file the moment
                // we learn it (spec 02 §8), even before unlock — mirrors the Android client.
                if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
            }.onFailure { policyFetchFailed = true } // §3: never render the no-key lie off a failed probe
            probe.close()
            runCatching { checkForUpdate(store.baseUrl) }.onSuccess { updateAvailable = it }
            val session = store.load()
            screen = if (session != null && session.accessToken.isNotEmpty()) DesktopScreen.Unlock(session.email) else DesktopScreen.Welcome
            baseUrl = store.baseUrl
        }
    }

    fun updateServer(url: String) {
        store.baseUrl = url.trim().removeSuffix("/")
        baseUrl = store.baseUrl
        // B5: a deliberate URL change must re-probe — the OLD server's policy (recovery
        // fingerprint, pins) must not drive the enroll gate until restart. Null the stale
        // policy first (renders the neutral probe-in-flight state, never the no-key text),
        // then mirror Android setBaseUrl: apply + purge-on-forbid on success, flag on failure.
        policy = null
        policyFetchFailed = false
        scope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        policyFetchFailed = false
                        applyPolicy(p)
                        // Same policy enforcement as start(): a forbidding server purges the cache.
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
                    }
                    .onFailure { policyFetchFailed = true }
            } finally {
                probe.close()
            }
        }
    }

    /** §3 Retry: re-run the enroll-feeding policy probe by hand — the enroll screen's
     *  Retry button after a failed fetch. Runs under [busy] (the existing button idiom). */
    fun retryPolicy() {
        if (busy) return
        busy = true
        scope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        policyFetchFailed = false
                        applyPolicy(p)
                        // Same policy enforcement as start(): a forbidding server purges the cache.
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
                    }
                    .onFailure { policyFetchFailed = true }
            } finally {
                busy = false
                probe.close()
            }
        }
    }

    fun clearError() { error = null }
    fun clearSaveError() { saveError = null }
    /** Editor closed (cancel or success): the next editor session starts a fresh draft.
     *  NOT part of [clearSaveError] — dismissing the inline error must keep the draft id,
     *  or the very next retry re-mints and re-wedges on attachment_mismatch. */
    fun endEditorSession() { saveError = null; draftItemId = null }
    fun clearNotice() { notice = null }

    fun signIn(email: String, password: String, totp: String? = null) = op {
        val a = newApi()
        val pre = a.prelogin(email)
        // Argon2id (64 MiB, twice per sign-in) is CPU-bound — never on the UI thread.
        val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams) }
        val s = try {
            a.login(LoginRequest(email, authKey, Account.deviceInfo(deviceName(), desktopPlatform()), totp = totp))
        } catch (e: ApiException) {
            a.close()
            when (e.code) {
                // Server-TOTP is enrolled: reveal the code field and let the user retry.
                "totp_required" -> { signInTotpRequired = true; busy = false; return@op }
                "public_login_requires_totp" ->
                    throw ApiException(e.status, e.code, "this account has no server-TOTP enrolled; public access is blocked")
                else -> throw e
            }
        }
        val acct = withContext(Dispatchers.Default) { Account.unlock(s.userId, password, s.accountKeys) }
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct); syncNow(engine!!)
        escrowStale = s.accountKeys.escrowStale; escrowFingerprint = s.accountKeys.escrowFingerprint
        mustChangePassword = s.mustChangePassword // F58: a recovery temp password forces the banner
        signInTotpRequired = false
        toVault()
    }

    fun unlock(email: String, password: String) = op {
        val session = store.load() ?: error("no session")
        val a = newApi(session.tokens())
        // Offline unlock (spec 02 §8): cached keys when the network is down; wipe on a
        // definitive auth rejection.
        val keys = try {
            a.accountKeys().also { persistAccountKeys(it) }
        } catch (e: java.io.IOException) {
            store.loadAccountKeys() ?: throw e
        } catch (e: ApiException) {
            if (e.status == 401) { purgeOfflineData(session.userId); store.clear() }
            throw e
        }
        // KDF off the UI thread (argon2id 64 MiB — the unlock spinner must animate).
        val acct = withContext(Dispatchers.Default) { Account.unlock(session.userId, password, keys) }
        bind(a, acct)
        escrowStale = keys.escrowStale; escrowFingerprint = keys.escrowFingerprint
        runCatching { syncNow(engine!!) }.onFailure {
            if (it is java.io.IOException) notice = "Offline — showing cached data" else throw it
        }
        toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String, typedShortFp: String) {
        // State-layer re-assert (mirrors Android; the S2-review race class: a composition-
        // stale submit lambda can fire with live-read fields). Busy first — op() sets busy
        // but never checks it — then the F60 floor (the irreversible leg of this screen).
        if (busy) return
        if (!Strength.meetsMasterPasswordFloor(password)) {
            error = "Choose a stronger master password — mix length with upper/lower case, digits, or symbols."
            return
        }
        enrollOp(invite, email, name, password, typedShortFp)
    }

    private fun enrollOp(invite: String, email: String, name: String, password: String, typedShortFp: String) = op {
        // §3 flag audit: this fallback fetch feeds THIS enroll directly (normally dead —
        // the submit gate needs the fingerprint, so policy is already loaded). Success
        // clears the honesty flag like every enroll-feeding fetch; failure sets it and
        // still throws, so op() surfaces the error as before.
        val pol = policy ?: runCatching { newApi().clientPolicy() }
            .onSuccess { policy = it; policyFetchFailed = false }
            .onFailure { policyFetchFailed = true }
            .getOrThrow()
        // Typed-sheet ceremony re-assert at the STATE layer against the policy this enroll
        // actually seals to (review LOW, 4th sighting of the frame-stale class): updateServer
        // can swap the policy mid-screen, and a one-frame-stale submit would otherwise pass
        // the UI gate against the OLD server's fingerprint — spec 04 §2(3)'s attestation
        // must bind to the org being enrolled into (the resealEscrow pattern below).
        check(Escrow.shortFormMatches(typedShortFp, pol.recoveryFingerprint)) {
            "The recovery-sheet check no longer matches this server — re-verify the printed sheet's first 16 characters."
        }
        val a = newApi()
        val recoveryPub = Bytes.fromB64(a.recoveryPubkey())
        // TODO(recovery-cut-2): native enroll is the `required` (org-escrow) path ONLY — it always
        // seals to the org key (recoveryPub non-null), so the account gets BOTH the self-service
        // piece and an admin backstop. Account.enroll now ALSO accepts recoveryPublicKey = null (the
        // `waived` posture: per-member piece only, no backstop), but the waived path needs an
        // admin-set policy toggle + the in-person-QR fingerprint provenance of §F.1 before native can
        // offer it. Until that UI exists, keep required.
        // Key generation + KDF are CPU-bound (argon2id) — off the UI thread. EnrollResult
        // destructures to (request, account, recoverySecret) — the 3rd is the SHOWN-ONCE piece.
        val (req, acct, recoverySecret) = withContext(Dispatchers.Default) {
            Account.enroll(
                inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
                password = password, params = pol.kdfParams,
                recoveryPublicKey = recoveryPub, recoveryFingerprint = pol.recoveryFingerprint, deviceName = deviceName(),
            )
        }
        val s = a.register(req)
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct); syncNow(engine!!)
        escrowStale = s.accountKeys.escrowStale; escrowFingerprint = s.accountKeys.escrowFingerprint
        mustChangePassword = s.mustChangePassword // F58: never true for a fresh enroll; wired for truth
        // §F.4/§F.7: the recovery piece is MANDATORY and already committed in register(), but a
        // member who never SEES it is silently unrecoverable. Hold it transiently and route to the
        // shown-once reveal+confirm gate (RecoverySetup) instead of the vault; the gate zeroes it
        // once the user types it back.
        pendingRecoverySecret = recoverySecret
        recoveryPhrase = MemberRecovery.displayForm(recoverySecret)
        recoverySetupWaived = false // required path today (recoveryPub non-null); TODO(recovery-cut-2)
        busy = false
        screen = DesktopScreen.RecoverySetup
    }

    // Shown-once recovery secret (design §F.7): the RAW 32 bytes of a fresh enrollee's recovery
    // piece, held transiently between a successful enroll and the confirm gate ONLY for the
    // constant-time confirmMatches. NEVER persisted, NEVER logged; zeroed + dropped the instant the
    // confirm passes (confirmRecoverySaved) or on sign-out. The user-visible base64url form lives in
    // [recoveryPhrase] (also transient) so Compose can render it.
    private var pendingRecoverySecret: ByteArray? = null

    /**
     * The un-skippable "I saved my recovery phrase" gate (design §F.7). Does [typedBack] re-decode
     * to the SAME secret we generated at enroll? Constant-time (core [MemberRecovery.confirmMatches]).
     * On a match: ZERO + DROP the raw secret and its display form, then open the vault. A mistype
     * returns false and the screen shows a STATIC error (never the secret). This is NEVER a KDF
     * source — the piece was already committed at register(); this only proves the user saved it.
     */
    fun confirmRecoverySaved(typedBack: String): Boolean {
        val secret = pendingRecoverySecret ?: return false
        if (!MemberRecovery.confirmMatches(secret, typedBack)) return false
        // §F.9: tell the server this native enrollee saved the register-committed phrase, so the
        // (web) vault-entry gate never re-nudges the account. Fire this BEFORE we touch the secret:
        // it reads the session creds and launches asynchronously, so a slow/failed ping can never
        // delay or block the zeroize + navigate below (see markRecoveryConfirmed's best-effort note).
        // TODO(recovery-cut-2): the NATIVE vault-entry capture gate (blocking vault access on
        // recoveryConfirmed==false for migration/interrupted-reveal accounts, mirroring web's
        // Unlock/SignIn gate) is DEFERRED — web covers that cut cross-device via the server flag;
        // native `waived` is off and `required` keeps the escrow backstop, so no native total-loss
        // is reachable. This confirm ping is the only §F.9 native surface for now.
        markRecoveryConfirmed()
        secret.fill(0) // best-effort zeroization before dropping the reference
        pendingRecoverySecret = null
        toVault() // clears recoveryPhrase too (the display form must not survive landing)
        return true
    }

    /**
     * §F.9 best-effort "recovery confirmed" ping. POSTs the current session's bearer to
     * `POST /api/v1/recovery/self/confirm` (session-auth only — no key material or password needed)
     * so the server flips this account's `recoveryConfirmed=true` and the (web) vault-entry gate
     * stops nudging. Deliberately fire-and-forget on [scope] + [Dispatchers.IO] and fully
     * runCatching-swallowed: a network failure must NEVER strand the enrollee or leave the raw
     * secret un-zeroed — [confirmRecoverySaved] zeroes + navigates regardless, and the flag can be
     * re-set on a later capture. Reuses the live [AndvariApi]'s baseUrl + access token via a
     * one-shot client of the same engine the app uses everywhere (the token is seconds old
     * post-enroll, so no 401/refresh is in play; a fresh sign-out mid-flight just no-ops the send).
     */
    private fun markRecoveryConfirmed() {
        val a = api ?: return
        val token = a.currentTokens()?.accessToken ?: return
        val base = a.baseUrl
        val clientTag = "${desktopPlatform()}/$ANDVARI_CLIENT_VERSION"
        scope.launch(Dispatchers.IO) {
            runCatching {
                val client = HttpClient(Java)
                try {
                    client.post("$base/api/v1/recovery/self/confirm") {
                        header("Authorization", "Bearer $token")
                        header("X-Andvari-Client", clientTag)
                    }
                } finally {
                    client.close()
                }
            }
        }
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
            busy = false
            saveError = t.message ?: "save failed"
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
    fun refresh() = op { syncNow(engine!!); refreshItems() }
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
                    t is ApiException && t.status == 403 -> { moveGestures.remove(gKey); moveError = t.message ?: "Move denied — nothing was moved." }
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
                error = friendlyError(t)
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

    /**
     * Lock if the inactivity window elapsed (policy `autoLockSeconds`; persisted last-known
     * value when the live policy hasn't loaded; 0 disables). Never yanks the engine under an
     * in-flight op ([busy]/import) — the durable queue would survive it, but the op would
     * surface a spurious error; the next 1 s tick re-checks, so the lock is deferred, not
     * skipped.
     */
    private fun maybeIdleLock() {
        if (engine == null) return
        val window = policy?.autoLockSeconds ?: store.autoLockSeconds
        if (window <= 0) return
        // A-copyGate: the rescue copy holds `busy`, but any OTHER op finishing mid-copy
        // clears it — the op guard is what actually keeps the idle lock off the engine
        // for the whole copy (never yank the engine mid-rescue).
        if (busy || importBusy || copyOpVaultId != null) return
        if (System.currentTimeMillis() - lastInteractionMs >= window * 1000L) lock("Locked after inactivity.")
    }

    /**
     * Quiet poll sync (spec 03 §6: focus regained + every 5 min while unlocked): refresh
     * policy first (so autoLock/clipboard windows track admin changes mid-session), then
     * push-queue + pull. Reuses [busy] as the overlap guard — read and set on the single
     * UI thread, so it can't interleave with a user-initiated op. Offline blips stay
     * silent; anything else (rev regression, denied writes) surfaces like a manual sync.
     */
    fun backgroundSync() {
        val e = engine ?: return
        if (busy || importBusy) return
        busy = true
        scope.launch {
            runCatching { api?.clientPolicy() }.getOrNull()?.let { applyPolicy(it) }
            try {
                syncNow(e)
                // B1: `busy` alone is no teardown guard — a manual lock (or sign-out→sign-in)
                // mid-sync leaves this continuation holding the OLD engine; identity-gate every
                // post-suspension state write so nothing stale lands in the new session.
                if (engine !== e) { busy = false; return@launch }
                items = e.items()
                needsUpdateCount = e.needsUpdateCount()
                busy = false
                refreshLifecycle() // A-funnel: a background pull may have delivered notices/offers
            } catch (t: Throwable) {
                busy = false
                val torn = engine !== e // locked/rebound mid-sync — an expected teardown, not an error
                if (t !is java.io.IOException && !torn) error = t.message ?: "sync failed"
                if (!torn) refreshLifecycle() // A-funnel: even a denied/park cycle leaves notices to show
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
            importError = "Couldn't read ${file.name}: ${t.message}"; return
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
            importError = t.message ?: "could not read that file"
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
                importError = t.message ?: "could not re-check that file" // plan/vault unchanged — still a matched pair
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
     *  one — at [dest]. */
    fun saveAttachmentTo(ref: AttachmentRef, dest: File) = op {
        withContext(Dispatchers.IO) {
            val bytes = engine!!.downloadAttachment(ref)
            try { writeVerifiedAtomically(dest, bytes) } finally { bytes.fill(0) } // attachment plaintext — wipe our copy
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
                origin = store.baseUrl,
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
        clearSecondary()
        // §6: set FRESH per event — the default serves the manual Lock button; the idle
        // watcher passes "Locked after inactivity.". Never carried stale (B6).
        lockReason = reason
        // §3 reset block (review MED, Android parity): clear the probe-failure flag only when
        // a policy is LOADED — a null-policy failure is CURRENT (nothing re-probes on the way
        // to Welcome), and clearing it would strand enroll in "Checking the server…" with no
        // Retry and no probe.
        if (policy != null) policyFetchFailed = false
        screen = DesktopScreen.Unlock(store.load()?.email ?: ""); items = emptyList(); needsUpdateCount = 0
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
            session?.userId?.let { deleteCache(it) }
            store.clear()
            clearSecondary(); signInTotpRequired = false
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

    private fun cacheFile(userId: String) = File(store.cacheDir, "vault-$userId.db")

    private fun deleteCache(userId: String) {
        for (suffix in listOf("", "-wal", "-shm")) {
            val f = File(store.cacheDir, "vault-$userId.db$suffix")
            // Windows: a straggler handle (AV/indexer) can defeat the unlink — retry at JVM exit.
            if (!f.delete() && f.exists()) f.deleteOnExit()
        }
    }

    private fun cacheAllowed(): Boolean = policy?.offlineCacheAllowed ?: store.cacheAllowed

    /** Record a freshly-fetched policy in UI state + the persisted offline fallbacks. */
    private fun applyPolicy(p: ClientPolicy) {
        policy = p
        store.cacheAllowed = p.offlineCacheAllowed
        store.autoLockSeconds = p.autoLockSeconds
    }

    /** Persist accountKeys for offline unlock ONLY when the policy permits it (spec 02 §8). */
    private fun persistAccountKeys(keys: io.silencelen.andvari.core.model.AccountKeys) {
        if (cacheAllowed()) store.saveAccountKeys(keys) else store.clearAccountKeys()
    }

    /** Enforce offlineCacheAllowed=false: drop BOTH the vault DB and the cached keys. */
    private fun purgeOfflineData(userId: String) { deleteCache(userId); store.clearAccountKeys() }

    private fun bind(a: AndvariApi, acct: Account) {
        touch() // spec 01 §8: the auto-lock timer resets on unlock
        engine?.close()
        api = a; account = acct
        val allowed = policy?.offlineCacheAllowed ?: store.cacheAllowed
        val newCache = if (allowed) {
            val db = cacheFile(acct.userId)
            sqliteVaultCache(db.absolutePath, acct.userId).also {
                // 0600 on POSIX, best-effort on Windows — same handling as session.json.
                for (suffix in listOf("", "-wal", "-shm")) restrictToOwner(File("${db.path}$suffix"))
            }
        } else {
            deleteCache(acct.userId); InMemoryVaultCache()
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
        busy = false; error = null
        refreshLifecycle() // A-funnel: offers/notices delivered by the unlock sync show at once
    }

    /** §11 friendlyError mappings (mirrors Android/web Sharing) — lifecycle codes get honest,
     *  human copy; everything else keeps the raw message the app always showed. Wired into
     *  [op]'s generic catch, deliberately upgrading ALL desktop ops (design §5). */
    private fun friendlyError(t: Throwable): String {
        if (t is ApiException) {
            when (t.code) {
                "owner_must_transfer_or_delete" -> return "You own this vault, so you can't just leave it — make someone else the owner first, or delete it."
                "vault_deleted" -> return "This vault was deleted. The owner can restore it for a few more days."
                "vault_gone" -> return "The restore window has passed — this vault's data has been erased."
                "vault_state_changed" -> return "This vault changed since you tried that — reload and try again."
                "transfer_not_pending" -> return "This ownership offer is no longer active."
                "not_transfer_target" -> return "This ownership offer isn't for you, or it couldn't be verified."
                "stale_meta" -> return "This vault changed somewhere else — reload and try the rename again."
                "not_a_member" -> return "They have to be a member of this vault first."
                "user_inactive" -> return "That account has been disabled — ask your admin to re-enable it first."
                "not_vault_owner" -> return "Only the vault's owner can do that."
            }
            if (t.status == 429) return "Too many requests — please wait a bit and try again."
        }
        return t.message ?: "something went wrong"
    }

    private fun op(block: suspend () -> Unit) {
        busy = true; error = null; notice = null
        scope.launch {
            try {
                block()
            } catch (e: UpgradeRequiredException) {
                // A 426 is not a per-action error — this desktop build is too old for the
                // server's pin. Surface the blocking upgrade screen instead of a toast.
                busy = false
                upgradeRequired = "This andvari server requires a newer desktop app. Download the latest from ${store.baseUrl}/downloads."
            } catch (t: Throwable) {
                busy = false; error = friendlyError(t)
            }
        }
    }

    private fun deviceName(): String = "${System.getProperty("os.name")} desktop"

    /** Wire platform tag from the JVM OS: "windows" or "linux" (the only jpackage targets). */
    private fun desktopPlatform(): String =
        if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) "windows" else "linux"

    private companion object {
        const val POLL_INTERVAL_MS = 5L * 60 * 1000 // spec 03 §6 poll interval

        /** A10's pinned pattern — the entities a LastPass in-page export mangles values with. */
        val HTML_ENTITY = Regex("&(amp|lt|gt|quot|#\\d+);")
    }
}
