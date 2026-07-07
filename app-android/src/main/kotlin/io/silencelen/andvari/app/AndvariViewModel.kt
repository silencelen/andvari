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
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.sqliteVaultCache
import java.io.File
import java.io.IOException
import io.silencelen.andvari.core.crypto.Bytes
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
    data object Settings : Screen
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
    // Export & backup (spec 07) — preflight dialogs + post-backup summary.
    val backupPreflight: BackupPreflight? = null,
    val backupResult: BackupResult? = null,
    val csvPreflight: CsvPreflight? = null,
    val lastExportAt: Long = 0,
)

class AndvariViewModel(private val store: SessionStore, private val cacheDir: File) : ViewModel() {
    private val _ui = MutableStateFlow(UiState(baseUrl = store.baseUrl, lastExportAt = store.lastExportAt))
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

    fun openEditor(itemId: String?) {
        editorPendingUploads.clear() // a fresh editor session never inherits stale picks
        editorItemId = itemId
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
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                applyPolicy(p) // UI state + persisted fallbacks + auto-lock gate
                // Policy may forbid the durable cache; honor it the moment we learn it,
                // deleting any existing file (spec 02 §8) — but only when no live engine holds
                // it (when bound, a later lock/rebind enforces the purge safely).
                if (!p.offlineCacheAllowed && session != null && !bound) purgeOfflineData(session.userId)
            }
            probe.close()
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
            runCatching { probe.clientPolicy() }
                .onSuccess { p ->
                    applyPolicy(p)
                    // Same policy enforcement as start(): a forbidding server purges the cache.
                    if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
                }
                .onFailure { _ui.value = _ui.value.copy(policy = null) }
            probe.close()
        }
    }

    private fun fail(t: Throwable) {
        _ui.value = _ui.value.copy(busy = false, error = t.message ?: "something went wrong")
    }

    fun clearError() { _ui.value = _ui.value.copy(error = null) }

    fun clearNotice() { _ui.value = _ui.value.copy(notice = null) }

    fun signIn(email: String, password: String, totp: String? = null) = op {
        val a = newApi()
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
                if (e.status == 401) { purgeOfflineData(session.userId); store.clear() }
                throw e
            }
            val acct = try {
                // KDF off the Main thread (argon2id 64 MiB — the unlock spinner must animate).
                withContext(Dispatchers.Default) { Account.unlock(session.userId, password, keys) }
            } catch (t: Throwable) { a.close(); throw t }
            bind(a, acct)
        }
        // Tolerate an offline sync — hydrate() already populated the cached vault.
        runCatching { syncNow(engine!!) }.onFailure {
            if (it is IOException) _ui.value = _ui.value.copy(notice = "Offline — showing cached data")
            else throw it
        }
        toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String) = op {
        val policy = _ui.value.policy ?: newApi().also { it.close() }.let { newApi().clientPolicy() }
        val a = newApi()
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
            if (s.screen is Screen.Vault || s.screen is Screen.Settings || s.screen is Screen.AutofillStatus) lock()
            return
        }
        if (s.busy || s.importBusy) return
        if (VaultSession.idleExpired()) lock()
    }

    /**
     * Quiet poll sync (spec 03 §6: on foreground + every 5 min while foregrounded and
     * unlocked): refresh policy first (so autoLock/clipboard windows track admin changes
     * made mid-session), then push-queue + pull. Reuses [UiState.busy] as the overlap
     * guard — read and set on the main thread, so it cannot interleave with a
     * user-initiated op. Transient network failures stay silent (this runs unattended);
     * anything else (rev regression, denied writes) surfaces like a manual sync.
     */
    fun backgroundSync() {
        val current = VaultSession.get() ?: return
        if (_ui.value.busy || _ui.value.importBusy) return
        _ui.value = _ui.value.copy(busy = true)
        viewModelScope.launch {
            runCatching { current.api.clientPolicy() }.onSuccess { applyPolicy(it) }
            try {
                syncNow(current.engine)
                _ui.value = _ui.value.copy(items = current.engine.items(), needsUpdateCount = current.engine.needsUpdateCount(), busy = false)
            } catch (t: Throwable) {
                _ui.value = _ui.value.copy(busy = false, error = if (t is IOException) _ui.value.error else t.message)
            }
        }
    }

    /** ON_RESUME hook: enforce the idle window FIRST, then catch up if still unlocked. */
    fun onForeground() {
        checkIdleLock()
        backgroundSync()
    }

    // ---- CSV import (spec 06) ----

    /** Parse + plan a browser CSV entirely on-device (no upload). [bytes] is read by the UI. */
    fun importParse(bytes: ByteArray) {
        val acct = account ?: return
        try {
            val parsed = CsvImport.parse(bytes)
            _ui.value = _ui.value.copy(
                importFormat = parsed.format,
                importPlan = CsvImport.plan(parsed) { acct.newItemId() },
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
        )
    }

    private fun friendlyImport(code: String): String = when (code) {
        "too_large" -> "That file is larger than 10 MiB — far bigger than any real browser password export."
        "too_many_rows" -> "That file has more than 10,000 logins. Split it into smaller files and import each."
        "unrecognized_header" -> "This doesn’t look like a Chrome, Edge, or Firefox password export."
        else -> "That file could not be read ($code)."
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
        _ui.value = _ui.value.copy(
            screen = Screen.Unlock(store.load()?.email ?: ""), items = emptyList(), needsUpdateCount = 0,
            notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
            backupPreflight = null, backupResult = null, csvPreflight = null,
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
            session?.userId?.let { deleteCache(it) }
            store.clear()
            _ui.value = _ui.value.copy(
                screen = Screen.Welcome, items = emptyList(), needsUpdateCount = 0, busy = false,
                notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
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
    }

    private fun toVault() {
        _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), needsUpdateCount = needsUpdate(), busy = false, error = null, loginTotpRequired = false)
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
