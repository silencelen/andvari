package io.silencelen.andvari.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.CopyDeniedException
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.DeletedVaultInfo
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.HeldVaultInfo
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.IncomingTransfer
import io.silencelen.andvari.core.client.ItemChangedException
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LifecycleNotice
import io.silencelen.andvari.core.client.MoveGesture
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.model.PendingTransfer
import io.silencelen.andvari.core.model.VaultMemberSummary
import java.io.File
import java.io.IOException
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
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

sealed interface Screen {
    data object Loading : Screen
    data object Welcome : Screen
    data class Unlock(val email: String) : Screen
    data object Vault : Screen
    data object Sharing : Screen
    data object Settings : Screen
    data object Trash : Screen
    data object AutofillStatus : Screen
}

data class UiState(
    val screen: Screen = Screen.Loading,
    val items: List<VaultItem> = emptyList(),
    // Held envelopes newer than this build can decrypt (fail-closed) — the vault list
    // shows them as a one-line "N items need an app update" banner instead of nothing.
    val needsUpdateCount: Int = 0,
    val policy: ClientPolicy? = null,
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
    val error: String? = null,
    val notice: String? = null,
    val baseUrl: String = SessionStore.DEFAULT_BASE_URL,
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
    // Guided importers (design 2026-07-09): source-picker open flag + the picked source.
    // The source tailors the export instructions and the mismatch hint ONLY — header
    // detection stays authoritative. The two nullable notes are the post-parse info lines
    // (detected-format mismatch; A10 LastPass HTML-mangle heuristic).
    val importSourceSheet: Boolean = false,
    val importSource: ImportSource? = null,
    val importFormatNote: String? = null,
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
    /** Bulk "copy items to Personal first" progress + its post-copy note (delete dialog). */
    val copyProgress: Pair<Int, Int>? = null,
    val copiedNote: String? = null,
    /** F19 move/copy attachment re-encryption progress (Detail screen). */
    val moveProgress: Pair<Int, Int>? = null,
    // F57: the account's escrow is sealed to a superseded org recovery key (re-ceremony) — the
    // vault screen offers a re-seal. escrowFingerprint is the CURRENT org fingerprint (the re-seal
    // target + the value the user verifies against the new printed sheet).
    val escrowStale: Boolean = false,
    val escrowFingerprint: String = "",
    // Item history (feature): decrypted archived versions of the currently-viewed item, loaded on
    // demand (null = not loaded / loading). Restore a chosen version with saveItem.
    val itemVersions: List<DecryptedItemVersion>? = null,
    // Item undelete (feature): the Trash screen's deleted items (null = not loaded / loading).
    val deletedItems: List<DeletedItemView>? = null,
)

/**
 * Guided import sources (design 2026-07-09 §Guided UI): each is a short "how to export"
 * instruction block plus a mismatch hint — NOTHING more. Header detection stays
 * authoritative: a Bitwarden file picked under "Chrome" still imports as Bitwarden, with
 * a calm note. Copy mirrors web's ImportPanel, shortened to fit a dialog. The Chromium
 * four (Chrome/Edge/Brave/Opera) all emit the same CSV and expect the `chrome` format.
 */
enum class ImportSource(val label: String, val steps: List<String>, private val expectedFormats: Set<String>) {
    CHROME(
        "Chrome",
        listOf(
            "Open chrome://settings/passwords (Google Password Manager → Settings).",
            "Export passwords, confirm, and save the CSV.",
        ),
        setOf("CHROME"),
    ),
    EDGE(
        "Edge",
        listOf(
            "Open edge://wallet/passwords.",
            "⋯ (More options) → Export passwords, and save the CSV.",
        ),
        setOf("CHROME"),
    ),
    BRAVE(
        "Brave",
        listOf(
            "Open brave://settings/passwords.",
            "⋯ next to “Saved passwords” → Export passwords, and save the CSV.",
        ),
        setOf("CHROME"),
    ),
    OPERA(
        "Opera",
        listOf(
            "Open opera://settings/passwords.",
            "⋯ next to “Saved passwords” → Export passwords, and save the CSV.",
        ),
        setOf("CHROME"),
    ),
    FIREFOX(
        "Firefox",
        listOf(
            "Open about:logins (Passwords).",
            "⋯ (menu, top right) → Export passwords, and save the CSV.",
        ),
        setOf("FIREFOX"),
    ),
    BITWARDEN(
        "Bitwarden",
        listOf(
            "In the Bitwarden web vault: Tools → Export vault.",
            "File format .csv → Export vault, and save the file.",
        ),
        setOf("BITWARDEN"),
    ),
    ONEPASSWORD(
        "1Password",
        listOf(
            "In the 1Password 8 desktop app: File → Export → your account.",
            "Choose the CSV format and save the file.",
            "Older 1Password versions write a different CSV — use 1Password 8+, or export via Bitwarden as an intermediate.",
        ),
        // Matched by core enum NAME (see [expects]) — tolerate either spelling of the
        // 1password constant until WS-CORE's naming is pinned in this tree.
        setOf("ONEPASSWORD", "ONE_PASSWORD"),
    ),
    LASTPASS(
        "LastPass",
        listOf(
            "In the LastPass vault: Advanced Options → Export.",
            "Choose the CSV FILE download — not the in-page text (copying from the page mangles the file).",
        ),
        setOf("LASTPASS"),
    ),
    ;

    /** Does the detected format match what this source usually produces? Decides ONLY
     *  whether the mismatch info line shows — detection stays authoritative. Compared by
     *  enum NAME string so this file compiles without referencing the new core constants. */
    fun expects(format: CsvImport.ImportFormat): Boolean = format.name in expectedFormats
}

/** Human label for a detected format — the mismatch note + the preview's "From … export"
 *  line. Keyed on the core enum's NAME with an else-fallback (the only remaining format
 *  is 1Password, whatever WS-CORE spelled its constant). */
internal fun importFormatLabel(format: CsvImport.ImportFormat): String = when (format.name) {
    "CHROME" -> "Chrome/Chromium"
    "FIREFOX" -> "Firefox"
    "BITWARDEN" -> "Bitwarden"
    "LASTPASS" -> "LastPass"
    else -> "1Password"
}

class AndvariViewModel(private val store: SessionStore, private val cacheDir: File) : ViewModel() {
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
        // Mirror the in-flight-op signal (busy || importBusy) into the process-wide
        // VaultSession so the AUTOFILL entry point's idle-expiry check (getIfFresh)
        // defers the hard lock exactly like checkIdleLock() does here — an
        // onFillRequest must never close the engine under a running import/export.
        // Single choke point: every op helper flips busy/importBusy through _ui, so
        // collecting _ui catches them all (no unpaired begin/end calls to leak).
        // `syncing` (F74) is deliberately EXCLUDED: a quiet background sync — which can
        // stall for tens of seconds offline — must not hold the auto-lock open past the
        // policy window. A lock landing mid-sync is safe: the durable queue survives it,
        // and backgroundSync swallows the resulting teardown error instead of surfacing it.
        viewModelScope.launch {
            _ui.collect { VaultSession.setOperationInProgress(it.busy || it.importBusy) }
        }
    }

    override fun onCleared() {
        // The collector above dies with viewModelScope — never leave a stale
        // "operation in progress" latched, or the autofill idle gate would defer
        // locking forever in a process where only the autofill service remains.
        VaultSession.setOperationInProgress(false)
        super.onCleared()
    }

    private fun cacheFile(userId: String) = File(cacheDir, "vault-$userId.db")

    private fun deleteCache(userId: String) {
        for (suffix in listOf("", "-wal", "-shm")) File(cacheDir, "vault-$userId.db$suffix").delete()
    }

    /** Live policy if known, else the persisted last-known value (offline cold start). */
    private fun cacheAllowed(): Boolean = _ui.value.policy?.offlineCacheAllowed ?: store.cacheAllowed

    /** Persist accountKeys for offline unlock ONLY when the policy permits it (spec 02 §8). */
    private fun persistAccountKeys(keys: io.silencelen.andvari.core.model.AccountKeys) {
        if (cacheAllowed()) store.saveAccountKeys(keys) else store.clearAccountKeys()
    }

    /** Enforce offlineCacheAllowed=false: drop BOTH the vault DB and the cached keys. */
    private fun purgeOfflineData(userId: String) { deleteCache(userId); store.clearAccountKeys() }

    /**
     * Record a freshly-fetched policy everywhere it's enforced: UI state, the persisted
     * offline fallbacks, and the process-wide auto-lock gate (shared with autofill).
     */
    private fun applyPolicy(p: ClientPolicy) {
        _ui.value = _ui.value.copy(policy = p)
        store.cacheAllowed = p.offlineCacheAllowed
        store.autoLockSeconds = p.autoLockSeconds
        VaultSession.setAutoLockSeconds(p.autoLockSeconds)
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
            // If the vault was already unlocked in this process (autofill unlocked it first,
            // or the activity was recreated while the process lived), show it straight away —
            // but through the auto-lock gate: an idle-expired leftover session must land on
            // the unlock screen, never flash vault content (spec 01 §8).
            val bound = VaultSession.getIfFresh() != null
            if (bound) {
                _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), needsUpdateCount = needsUpdate(), baseUrl = store.baseUrl)
            }
            val session = store.load()
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }.onSuccess { p ->
                    applyPolicy(p) // UI state + persisted fallbacks + auto-lock gate
                    // Policy may forbid the durable cache; honor it the moment we learn it,
                    // deleting any existing file (spec 02 §8) — but only when no live engine holds
                    // it (when bound, a later lock/rebind enforces the purge safely).
                    if (!p.offlineCacheAllowed && session != null && !bound) purgeOfflineData(session.userId)
                }
            } finally {
                probe.close()
            }
            if (!bound) {
                _ui.value = _ui.value.copy(
                    screen = if (session != null && session.accessToken.isNotEmpty()) Screen.Unlock(session.email) else Screen.Welcome,
                    baseUrl = store.baseUrl,
                )
            }
        }
    }

    fun setBaseUrl(url: String) {
        store.baseUrl = url.trim().removeSuffix("/")
        _ui.value = _ui.value.copy(baseUrl = store.baseUrl)
        // Re-fetch policy against the new server so the recovery fingerprint / pins update
        // immediately (no app restart needed).
        viewModelScope.launch {
            val probe = newApi()
            try { // F74: close() in finally — no throw path may leak the transient probe
                runCatching { probe.clientPolicy() }
                    .onSuccess { p ->
                        applyPolicy(p)
                        // Same policy enforcement as start(): a forbidding server purges the cache.
                        if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
                    }
                    .onFailure { _ui.value = _ui.value.copy(policy = null) }
            } finally {
                probe.close()
            }
        }
    }

    private fun fail(t: Throwable) {
        _ui.value = _ui.value.copy(busy = false, error = friendlyError(t))
    }

    /** §11 friendlyError mappings (mirrors web Sharing.tsx) — lifecycle codes get honest,
     *  human copy; everything else keeps the raw message the app always showed. */
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

    fun signIn(email: String, password: String, totp: String? = null) = op {
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
                    "public_login_requires_totp" ->
                        throw ApiException(e.status, e.code, "this account has no server-TOTP enrolled; public access is blocked")
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
        } catch (t: Throwable) {
            // F74: no throw path (prelogin/KDF/login/Account.unlock) may leak the transient
            // client. Once bind() succeeded the api is VaultSession-OWNED — never close it
            // here (the success-path token-holder the live session uses).
            if (VaultSession.get()?.api !== a) a.close()
            throw t
        }
        syncNow(engine!!)
        toVault()
    }

    fun unlock(email: String, password: String) = op {
        val session = store.load() ?: throw IllegalStateException("no session")
        // Serialize with the autofill unlock path: both reuse this session's refresh token,
        // and a concurrent refresh would consume it twice → whole-device revocation.
        VaultSession.unlockMutex.withLock {
            // If autofill (or another tap) already unlocked while we waited, adopt that
            // session instead of building a second token-holder.
            VaultSession.get()?.let { toVault(); return@op }
            val a = newApi(session.tokens())
            // Offline unlock (spec 02 §8): fall back to the cached accountKeys when the
            // network is unreachable; a definitive auth rejection wipes the cache instead.
            val keys = try {
                a.accountKeys().also { persistAccountKeys(it) }
            } catch (e: IOException) {
                store.loadAccountKeys() ?: run { a.close(); throw e }
            } catch (e: ApiException) {
                a.close()
                // Definitive rejection: this device's session is dead (e.g. the web password
                // change revoked every other session, spec 03 §3) — wipe it, including the
                // persisted F58 flag (store.clear()); mirror the clear into UI state.
                if (e.status == 401) { purgeOfflineData(session.userId); store.clear(); _ui.value = _ui.value.copy(mustChangePassword = false) }
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
        toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String) = op {
        // F74: the old fallback built a client, closed it UNUSED, then leaked the second one
        // it actually called (`newApi().also { it.close() }.let { newApi().clientPolicy() }`).
        // One probe, closed in finally (AndvariApi has close() but isn't Closeable — no .use).
        val policy = _ui.value.policy ?: run {
            val probe = newApi()
            try { probe.clientPolicy() } finally { probe.close() }
        }
        val a = newApi()
        try {
            val recoveryPub = Bytes.fromB64(a.recoveryPubkey())
            // Key generation + KDF are CPU-bound (argon2id) — off the Main thread.
            val (req, acct) = withContext(Dispatchers.Default) {
                Account.enroll(
                    inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
                    password = password, params = policy.kdfParams,
                    recoveryPublicKey = recoveryPub, recoveryFingerprint = policy.recoveryFingerprint,
                    deviceName = android.os.Build.MODEL ?: "android",
                )
            }
            val s = a.register(req)
            store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
            persistAccountKeys(s.accountKeys)
            bind(a, acct)
            // F58: symmetric with signIn — a register response carries the flag too (false
            // for a fresh enrollment, but the wire says so, not us).
            store.mustChangePassword = s.mustChangePassword
            _ui.value = _ui.value.copy(escrowStale = s.accountKeys.escrowStale, escrowFingerprint = s.accountKeys.escrowFingerprint, mustChangePassword = s.mustChangePassword)
        } catch (t: Throwable) {
            // F74: same rule as signIn — close the transient client on ANY pre-bind throw,
            // never the VaultSession-owned success-path holder.
            if (VaultSession.get()?.api !== a) a.close()
            throw t
        }
        syncNow(engine!!)
        toVault()
    }

    fun saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList(), onSaved: () -> Unit = {}) = op {
        engine!!.saveWithUploads(itemId, doc, uploads)
        refreshItems()
        onSaved()
    }

    fun deleteItem(itemId: String) = op {
        engine!!.remove(itemId)
        refreshItems()
    }

    fun refresh() = op { syncNow(engine!!); refreshItems() }

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

    /** Mirror the engine's lifecycle read-surfaces into UI state (cheap in-memory reads),
     *  and lazily resolve the owner display name behind any verified incoming offer. */
    private fun refreshLifecycle() {
        val e = engine ?: return
        val incoming = e.incomingTransfers()
        _ui.value = _ui.value.copy(
            lifecycleNotices = e.notices(),
            incomingTransfers = incoming,
            heldVaults = e.heldVaultInfos(),
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
                _ui.value = _ui.value.copy(transferOwnerNames = names)
            }
        }
    }

    fun openSharing() {
        _ui.value = _ui.value.copy(screen = Screen.Sharing, copiedNote = null, copyProgress = null)
        reloadSharing()
    }

    fun closeSharing() {
        _ui.value = _ui.value.copy(screen = Screen.Vault, copiedNote = null, copyProgress = null)
    }

    /** Fetch the Sharing screen's server-side lists: members per owned shared vault (the
     *  transfer target picker) and the caller's restorable Recently-deleted vaults. */
    fun reloadSharing() {
        val e = engine ?: return
        refreshLifecycle()
        val a = api ?: return
        viewModelScope.launch {
            val members = mutableMapOf<String, List<VaultMemberSummary>>()
            for (v in e.vaultInfos().filter { it.type == "shared" && it.role == "owner" }) {
                runCatching { members[v.vaultId] = a.vaultMembers(v.vaultId) }
            }
            val deleted = runCatching { e.listDeleted() }.getOrDefault(emptyList())
            _ui.value = _ui.value.copy(sharingMembers = members, deletedVaults = deleted)
        }
    }

    /** RENAME (owner). stale_meta auto-retries once inside the engine. */
    fun renameVault(vaultId: String, newName: String) = op {
        engine!!.renameVault(vaultId, newName)
        refreshItems(); reloadSharing()
    }

    /** DELETE (soft, 7d grace). The §11 owner toast lands in [UiState.notice]. */
    fun deleteVault(vaultId: String, vaultName: String) = op {
        val purgeAt = engine!!.deleteSharedVault(vaultId)
        refreshItems(); reloadSharing()
        _ui.value = _ui.value.copy(
            notice = "“$vaultName” is deleted. Members lost access immediately. You can restore it until ${fmtDay(purgeAt)} (Sharing → Recently deleted).",
        )
    }

    /** Bulk "Copy items to my Personal vault first…" (F19 rider — copy legs ONLY). */
    fun copyItemsToPersonal(vaultId: String) {
        val e = engine ?: return
        _ui.value = _ui.value.copy(busy = true, error = null, copiedNote = null, copyProgress = 0 to 0)
        viewModelScope.launch {
            try {
                val copied = e.copyAllToPersonal(vaultId) { done, total ->
                    _ui.value = _ui.value.copy(copyProgress = done to total)
                }
                _ui.value = _ui.value.copy(
                    busy = false, copyProgress = null, items = e.items(),
                    copiedNote = "Copied $copied ${if (copied == 1) "item" else "items"} to your Personal vault. You can still change your mind — deleting won't remove those copies.",
                )
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(copyProgress = null)
                fail(t)
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

    fun clearCopiedNote() { _ui.value = _ui.value.copy(copiedNote = null) }

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
        if (VaultSession.get() == null) {
            // Locked underneath us (autofill gate) — reflect it in the UI.
            if (s.screen is Screen.Vault || s.screen is Screen.Sharing || s.screen is Screen.Settings || s.screen is Screen.AutofillStatus) lock()
            return
        }
        if (s.busy || s.importBusy) return
        if (VaultSession.idleExpired()) lock()
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
        viewModelScope.launch {
            runCatching { current.api.clientPolicy() }.onSuccess { applyPolicy(it) }
            try {
                syncNow(current.engine)
                if (VaultSession.get() !== current) { // locked/rebound mid-sync — publish nothing stale
                    _ui.value = _ui.value.copy(syncing = false)
                    return@launch
                }
                _ui.value = _ui.value.copy(items = current.engine.items(), needsUpdateCount = current.engine.needsUpdateCount(), syncing = false)
                refreshLifecycle() // a background pull may have delivered notices/offers
            } catch (t: Throwable) {
                // Locked/rebound mid-sync (auto-lock is NOT deferred for `syncing`): the
                // engine was closed under us — expected teardown, swallow it.
                val torn = VaultSession.get() !== current
                _ui.value = _ui.value.copy(syncing = false, error = if (t is IOException || torn) _ui.value.error else t.message)
                if (!torn) refreshLifecycle() // even a denied/park cycle leaves notices to show
            }
        }
    }

    /** ON_RESUME hook: enforce the idle window FIRST, then catch up if still unlocked. */
    fun onForeground() {
        checkIdleLock()
        backgroundSync()
    }

    // ---- CSV import (spec 06 + guided importers, design 2026-07-09) ----

    /** Open the guided source picker (the step BEFORE the system file picker). */
    fun importBegin() { _ui.value = _ui.value.copy(importSourceSheet = true, importSource = null) }

    /** A source card tapped — show its export instructions. */
    fun importSourcePick(source: ImportSource) { _ui.value = _ui.value.copy(importSource = source) }

    /** "My file is from somewhere else" — back to the source list. */
    fun importSourceBack() { _ui.value = _ui.value.copy(importSource = null) }

    /** Instructions confirmed; the UI launches the system file picker. Close the sheet but
     *  KEEP the picked source — the post-parse mismatch hint compares against it. */
    fun importChooseFile() { _ui.value = _ui.value.copy(importSourceSheet = false) }

    fun importSheetDismiss() { _ui.value = _ui.value.copy(importSourceSheet = false, importSource = null) }

    /**
     * Parse + plan a browser/manager CSV entirely on-device (no upload). [bytes] is read by
     * the UI. The plan is VAULT-AWARE (F75): `existing` = the personal vault's light
     * projections from the engine's working set, built by the core-owned builder (A8 —
     * never raw item lists mapped at the call site). If the working set is locked or the
     * personal vault isn't hydrated/synced yet, REFUSE with honest copy — never plan
     * against an empty `existing` (that would silently disable the dedupe).
     */
    fun importParse(bytes: ByteArray) {
        val acct = account
        val eng = engine
        if (acct == null || eng == null || eng.vaultInfos().none { it.vaultId == acct.personalVaultId }) {
            importReject("Couldn’t check your vault for items you already have — unlock and sync first, then try the import again.")
            return
        }
        try {
            val parsed = CsvImport.parse(bytes)
            val detected = importFormatLabel(parsed.format)
            val source = _ui.value.importSource
            _ui.value = _ui.value.copy(
                importFormat = parsed.format,
                importPlan = CsvImport.plan(parsed, eng.importProjections()) { acct.newItemId() },
                // Mismatch line (calm, informational): the picked source only ever tailored
                // instructions — detection decided what the file IS.
                importFormatNote = if (source != null && !source.expects(parsed.format))
                    "This file looks like a $detected export — imported it as $detected." else null,
                // A10 LastPass mangle heuristic: multiple HTML-entity hits across values.
                importMangleNote = if (looksHtmlMangled(parsed))
                    "This file looks HTML-mangled — re-export via Advanced → Export and choose the file download." else null,
                importRowOrdinals = CsvImport.rowOrdinalsByLine(bytes), // A9, same reader as parse
                importReport = null, importError = null, importProgress = null, importBusy = false, importDone = false,
            )
        } catch (e: CsvImport.ImportException) {
            _ui.value = _ui.value.copy(importError = friendlyImport(e.code), importPlan = null, importDone = false)
        } catch (t: Throwable) {
            _ui.value = _ui.value.copy(importError = t.message ?: "could not read that file", importPlan = null, importDone = false)
        }
    }

    /** Reject a file without parsing (e.g. the UI's bounded read hit the size cap). */
    fun importReject(message: String) {
        _ui.value = _ui.value.copy(importError = message, importPlan = null, importDone = false)
    }

    /**
     * Encrypt-and-push the planned items. Reuses plan.items on every call so a mid-import
     * failure is fixed with Retry (idempotent replay of the same itemIds), NOT a re-parse.
     */
    fun importConfirm() {
        val plan = _ui.value.importPlan ?: return
        _ui.value = _ui.value.copy(importBusy = true, importError = null, importProgress = 0 to plan.items.size)
        viewModelScope.launch {
            try {
                engine!!.importAll(plan.items) { done, total -> _ui.value = _ui.value.copy(importProgress = done to total) }
                _ui.value = _ui.value.copy(importBusy = false, importDone = true, importReport = plan.report, items = engine?.items() ?: emptyList())
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(importBusy = false, importError = "Import interrupted — press Retry to finish (no duplicates will be created).")
            }
        }
    }

    fun importDismiss() {
        _ui.value = _ui.value.copy(
            importPlan = null, importFormat = null, importReport = null, importError = null,
            importProgress = null, importBusy = false, importDone = false,
            importSourceSheet = false, importSource = null, importFormatNote = null, importMangleNote = null,
        )
    }

    private fun friendlyImport(code: String): String = when (code) {
        "too_large" -> "That file is larger than 10 MiB — far bigger than any real password export."
        "too_many_rows" -> "That file has more than 10,000 rows. Split it into smaller files and import each."
        // Per-source hint (design §Format adapters): older 1Password CSV shapes vary wildly.
        "unrecognized_header" ->
            if (_ui.value.importSource == ImportSource.ONEPASSWORD)
                "This doesn’t look like a 1Password 8 CSV. Export from 1Password 8+ as CSV, or use Bitwarden/CSV as an intermediate."
            else
                "This doesn’t look like a password export we recognize — Chrome, Edge, Brave, Opera, Firefox, Bitwarden, 1Password (8+), or LastPass CSV."
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
                backupPreflight = BackupPreflight(ExportPlanner.vaultLines(current.cache, current.account), offlineNote(offline)),
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
        return ExportPlanner.planAttachments(ExportPlanner.orderedItems(current.cache, order))
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
                fail(t)
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
        val cache = current.cache
        val crypto = account.cryptoProvider()

        // Snapshot every input up front (cheap in-memory reads): a concurrent manual lock
        // can close the engine/cache underneath a long build, and reads-then-crypto keeps
        // that window to "attachment downloads fail → named skips", never a torn payload.
        val allLines = ExportPlanner.vaultLines(cache, account)
        val lines = allLines.filter { it.vaultId in selectedVaults }
        val items = ExportPlanner.orderedItems(cache, lines.map { it.vaultId })
        // Enumerate undecryptable envelopes (missing VK / newer formatVersion) — but not
        // those of a VK-held vault the user explicitly deselected.
        val deselected = allLines.map { it.vaultId }.toSet() - selectedVaults
        val undecryptable = ExportPlanner.undecryptable(cache).filter { it.vaultId !in deselected }
        val formatVersions = cache.envelopes().associate { it.itemId to it.formatVersion }

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
                fail(t)
            }
        }
    }

    /** All VK-held docs in the pinned export order (vault order, then updatedAt). */
    private fun orderedDocs(current: VaultSession.Unlocked): List<ItemDoc> {
        val order = ExportPlanner.vaultLines(current.cache, current.account).map { it.vaultId }
        return ExportPlanner.orderedItems(current.cache, order).map { it.doc }
    }

    private fun offlineNote(offline: Boolean): String? {
        if (!offline) return null
        val at = store.lastSyncAt
        val stamp = if (at > 0) java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(at)) else "(unknown)"
        return "Offline — this exports the vault as of last sync $stamp."
    }

    fun lock() {
        // Close the engine (and its cache DB handle) but KEEP the file — the ciphertext
        // cache is retained on lock (spec 05 T3); a relaunch hydrates it.
        VaultSession.lock()
        pendingBackupRequest = null // a stashed export must not survive a lock (see stash docs)
        closeEditor() // the editor session (and its picked plaintext bytes) dies with the lock
        moveGestures.clear() // gestures reference the dead engine's item state
        movePickerMode = null
        movePickerItemId = null
        _ui.value = _ui.value.copy(
            screen = Screen.Unlock(store.load()?.email ?: ""), items = emptyList(), needsUpdateCount = 0,
            notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
            backupPreflight = null, backupResult = null, csvPreflight = null,
            lifecycleNotices = emptyList(), incomingTransfers = emptyList(), transferOwnerNames = emptyMap(),
            sharingMembers = emptyMap(), deletedVaults = emptyList(), heldVaults = emptyList(),
            copyProgress = null, copiedNote = null, moveProgress = null,
        )
    }

    fun signOut() {
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
            closeEditor()
            moveGestures.clear()
            movePickerMode = null
            movePickerItemId = null
            session?.userId?.let { deleteCache(it) }
            store.clear()
            _ui.value = _ui.value.copy(
                screen = Screen.Welcome, items = emptyList(), needsUpdateCount = 0, busy = false,
                mustChangePassword = false, // store.clear() dropped the persisted F58 flag with the account
                notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
                lifecycleNotices = emptyList(), incomingTransfers = emptyList(), transferOwnerNames = emptyMap(),
                sharingMembers = emptyMap(), deletedVaults = emptyList(), heldVaults = emptyList(),
                copyProgress = null, copiedNote = null, moveProgress = null,
            )
        }
    }

    // ---- settings / server TOTP ----

    fun openSettings() {
        _ui.value = _ui.value.copy(
            screen = Screen.Settings, totpStatus = null, totpSetup = null, totpMessage = null,
            backupPreflight = null, backupResult = null, csvPreflight = null, lastExportAt = store.lastExportAt,
        )
        viewModelScope.launch {
            try {
                _ui.value = _ui.value.copy(totpStatus = api!!.totpStatus())
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(totpMessage = t.message ?: "could not load TOTP status")
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
                val msg = if (t is ApiException && t.code == "bad_totp_code") "That code didn't match — try again." else t.message ?: "something went wrong"
                _ui.value = _ui.value.copy(busy = false, totpMessage = msg)
            }
        }
    }

    // ---- helpers ----
    private fun bind(a: AndvariApi, acct: Account) {
        // Durable cache unless policy forbids it (then delete any existing file). Hydrate
        // the working set from disk BEFORE the first sync so a cold/offline start shows data.
        // Prefer the live policy; fall back to the persisted last-known value when offline
        // (a policy-forbidden device cold-starting offline must NOT recreate the cache).
        val allowed = _ui.value.policy?.offlineCacheAllowed ?: store.cacheAllowed
        val cache = if (allowed) {
            sqliteVaultCache(cacheFile(acct.userId).absolutePath, acct.userId)
        } else {
            deleteCache(acct.userId); InMemoryVaultCache()
        }
        val newEngine = SyncEngine(a, acct, cache).also { it.hydrate() }
        // VaultSession closes any previously-bound engine/api (defensive: never two conns).
        VaultSession.bind(a, acct, newEngine, cache)
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
        _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), needsUpdateCount = needsUpdate(), busy = false, error = null, loginTotpRequired = false)
        refreshLifecycle()
    }

    private fun op(block: suspend () -> Unit) {
        _ui.value = _ui.value.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                block()
            } catch (t: Throwable) {
                fail(t)
            }
        }
    }
}
