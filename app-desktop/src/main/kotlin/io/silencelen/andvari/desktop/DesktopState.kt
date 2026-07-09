package io.silencelen.andvari.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.DeletedItemView
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
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
    data object Settings : DesktopScreen
    data object Trash : DesktopScreen
}

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
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
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
    // F57: this account's escrow is sealed to a superseded org recovery key (re-ceremony) — the
    // vault screen offers a re-seal. escrowFingerprint is the CURRENT org fingerprint (re-seal
    // target + the value the user verifies against the new printed sheet).
    var escrowStale by mutableStateOf(false)
        private set
    var escrowFingerprint by mutableStateOf("")
        private set
    // Item history (feature): decrypted archived versions of the currently-viewed item, loaded on
    // demand (null = not loaded / loading). Restore a chosen version with saveItem.
    var itemVersions by mutableStateOf<List<DecryptedItemVersion>?>(null)
        private set
    // Item undelete (feature): the Trash screen's deleted items (null = not loaded / loading).
    var deletedItems by mutableStateOf<List<DeletedItemView>?>(null)
        private set
    var totpStatus by mutableStateOf<TotpStatus?>(null)
        private set
    var totpSetupInfo by mutableStateOf<TotpSetupResponse?>(null)
        private set
    var totpError by mutableStateOf<String?>(null)
        private set
    // CSV import (spec 06): a preview/plan kept across a retry so an interrupted import
    // replays the SAME itemIds idempotently instead of duplicating.
    var importPlan by mutableStateOf<CsvImport.ImportPlan?>(null)
        private set
    var importFormat by mutableStateOf<CsvImport.ImportFormat?>(null)
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
    // Export & backup (spec 07) — preflight dialogs + post-backup summary.
    var backupPreflight by mutableStateOf<BackupPreflight?>(null)
        private set
    var backupResult by mutableStateOf<BackupResult?>(null)
        private set
    var csvPreflight by mutableStateOf<CsvPreflight?>(null)
        private set
    var lastExportAt by mutableStateOf(store.lastExportAt)
        private set

    private var api: AndvariApi? = null
    private var account: Account? = null
    private var engine: SyncEngine? = null
    // The engine's OWN cache instance, kept for surfaces the engine doesn't re-export
    // (vault rows / envelopes — the spec 07 export enumerates from them).
    private var cache: VaultCache? = null

    private fun newApi(tokens: Tokens? = null) =
        AndvariApi(store.baseUrl, HttpClient(Java), tokens, { store.updateTokens(it) }, platform = desktopPlatform())

    fun start() {
        scope.launch {
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                applyPolicy(p) // UI state + persisted offline fallbacks (auto-lock included)
                // Policy may forbid the durable cache; purge any existing file the moment
                // we learn it (spec 02 §8), even before unlock — mirrors the Android client.
                if (!p.offlineCacheAllowed) store.load()?.let { purgeOfflineData(it.userId) }
            }
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
    }

    fun clearError() { error = null }
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

    fun enroll(invite: String, email: String, name: String, password: String) = op {
        val pol = policy ?: newApi().clientPolicy().also { policy = it }
        val a = newApi()
        val recoveryPub = Bytes.fromB64(a.recoveryPubkey())
        // Key generation + KDF are CPU-bound (argon2id) — off the UI thread.
        val (req, acct) = withContext(Dispatchers.Default) {
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
        toVault()
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

    fun saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList(), onSaved: () -> Unit = {}) =
        op { engine!!.saveWithUploads(itemId, doc, uploads); refreshItems(); onSaved() }

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
        if (busy || importBusy) return
        if (System.currentTimeMillis() - lastInteractionMs >= window * 1000L) lock()
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
                items = e.items()
                needsUpdateCount = e.needsUpdateCount()
                busy = false
            } catch (t: Throwable) {
                busy = false
                if (t !is java.io.IOException) error = t.message ?: "sync failed"
            }
        }
    }

    /** Window regained focus: enforce the idle window FIRST, then catch up (spec 03 §6). */
    fun onWindowFocus() {
        maybeIdleLock()
        backgroundSync()
    }

    // ---- CSV import (spec 06) ----

    /** Length precheck (never read a multi-GB file) → parse + plan a browser CSV on-device. */
    fun importFromFile(file: File) {
        val acct = account ?: return
        importDismiss()
        if (file.length() > CsvImport.MAX_BYTES) { importError = friendlyImport("too_large"); return }
        val bytes = try { file.readBytes() } catch (t: Throwable) { importError = "Couldn't read ${file.name}: ${t.message}"; return }
        try {
            val parsed = CsvImport.parse(bytes)
            importFormat = parsed.format
            importPlan = CsvImport.plan(parsed) { acct.newItemId() }
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
    fun importConfirm() {
        val plan = importPlan ?: return
        importBusy = true; importError = null; importProgress = 0 to plan.items.size
        scope.launch {
            try {
                engine!!.importAll(plan.items) { done, total -> importProgress = done to total }
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
    }

    private fun friendlyImport(code: String): String = when (code) {
        "too_large" -> "That file is larger than 10 MiB — far bigger than any real browser password export."
        "too_many_rows" -> "That file has more than 10,000 logins. Split it into smaller files and import each."
        "unrecognized_header" -> "This doesn’t look like a Chrome, Edge, or Firefox password export."
        else -> "That file could not be read ($code)."
    }

    /** Seed-derived identity short code (spec 01 §5) — read out during sharing verification. */
    fun identityCode(): String? = account?.identityFingerprintShort()

    // ---- attachments ----

    /** Mint the SECRET half of a new attachment: fresh id + random per-file key (spec 02 §6). */
    fun newAttachmentRef(name: String, size: Long): AttachmentRef {
        val acct = account ?: throw IllegalStateException("vault is locked")
        return AttachmentRef(id = acct.newItemId(), name = name, size = size, fileKey = Bytes.toB64(acct.newFileKey()))
    }

    /** Download + decrypt an attachment off the UI thread and write it to [dest]. */
    fun saveAttachmentTo(ref: AttachmentRef, dest: File) = op {
        withContext(Dispatchers.IO) { dest.writeBytes(engine!!.downloadAttachment(ref)) }
        busy = false
        notice = "Saved ${ref.name} to ${dest.absolutePath}"
    }

    // ---- settings / server TOTP ----

    fun openSettings() {
        totpStatus = null; totpSetupInfo = null; totpError = null
        backupPreflight = null; backupResult = null; csvPreflight = null
        lastExportAt = store.lastExportAt
        screen = DesktopScreen.Settings
        scope.launch {
            runCatching { api!!.totpStatus() }
                .onSuccess { totpStatus = it }
                .onFailure { totpError = it.message ?: "couldn't load TOTP status" }
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
            val c = cache; val acct = account
            if (c == null || acct == null) { busy = false; return@launch }
            items = e.items()
            backupPreflight = BackupPreflight(ExportPlanner.vaultLines(c, acct), offlineNote(offline))
            busy = false
        }
    }

    fun backupDismiss() { backupPreflight = null }
    fun backupResultDismiss() { backupResult = null }

    /** Live §2.5 attachment plan for the preflight dialog's current vault selection
     *  (pure in-memory reads — cheap enough for recomposition). */
    fun attachmentPlan(selected: Set<String>): AttachmentPlan {
        val c = cache ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        val order = backupPreflight?.vaults?.map { it.vaultId }?.filter { it in selected }
            ?: return AttachmentPlan(emptyList(), 0L, emptyList())
        return ExportPlanner.planAttachments(ExportPlanner.orderedItems(c, order))
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
        val c = cache ?: return
        busy = true; error = null; backupPreflight = null
        scope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    buildAndWriteBackup(e, acct, c, selectedVaults, includeAttachments, passphrase, dest)
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
        c: VaultCache,
        selectedVaults: Set<String>,
        includeAttachments: Boolean,
        passphrase: String,
        dest: File,
    ): BackupResult {
        val crypto = acct.cryptoProvider()

        // Snapshot every input up front (cheap in-memory reads): a concurrent manual lock
        // can close the engine/cache underneath a long build, and reads-then-crypto keeps
        // that window to "attachment downloads fail → named skips", never a torn payload.
        val allLines = ExportPlanner.vaultLines(c, acct)
        val lines = allLines.filter { it.vaultId in selectedVaults }
        val exportItems = ExportPlanner.orderedItems(c, lines.map { it.vaultId })
        // Enumerate undecryptable envelopes (missing VK / newer formatVersion) — but not
        // those of a VK-held vault the user explicitly deselected.
        val deselected = allLines.map { it.vaultId }.toSet() - selectedVaults
        val undecryptable = ExportPlanner.undecryptable(c).filter { it.vaultId !in deselected }
        val formatVersions = c.envelopes().associate { it.itemId to it.formatVersion }

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
            val c = cache; val acct = account
            if (c == null || acct == null) { busy = false; return@launch }
            val docs = orderedDocs(c, acct)
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
        val acct = account ?: return
        val c = cache ?: return
        busy = true; error = null; csvPreflight = null
        scope.launch {
            try {
                val count = withContext(Dispatchers.IO) {
                    val docs = orderedDocs(c, acct)
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
    private fun orderedDocs(c: VaultCache, acct: Account): List<ItemDoc> {
        val order = ExportPlanner.vaultLines(c, acct).map { it.vaultId }
        return ExportPlanner.orderedItems(c, order).map { it.doc }
    }

    private fun offlineNote(offline: Boolean): String? {
        if (!offline) return null
        val at = store.lastSyncAt
        val stamp = if (at > 0) {
            java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT, java.text.DateFormat.SHORT).format(java.util.Date(at))
        } else "(unknown)"
        return "Offline — this exports the vault as of last sync $stamp."
    }

    fun lock() {
        // Retain the ciphertext cache on lock (spec 05 T3); close its handle.
        engine?.close(); api?.close(); api = null; account = null; engine = null; cache = null
        clearVaultClipboard() // a copied secret must not outlive the unlocked session
        clearSecondary()
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
            engine?.close(); a?.close(); api = null; account = null; engine = null; cache = null
            clearVaultClipboard()
            session?.userId?.let { deleteCache(it) }
            store.clear()
            clearSecondary(); signInTotpRequired = false
            busy = false
            screen = DesktopScreen.Welcome; items = emptyList(); needsUpdateCount = 0
        }
    }

    private fun clearSecondary() {
        notice = null; totpStatus = null; totpSetupInfo = null; totpError = null
        backupPreflight = null; backupResult = null; csvPreflight = null
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
        cache = newCache
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
    }

    private fun toVault() {
        screen = DesktopScreen.Vault
        items = engine?.items() ?: emptyList()
        needsUpdateCount = engine?.needsUpdateCount() ?: 0
        busy = false; error = null
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
                busy = false; error = t.message ?: "something went wrong"
            }
        }
    }

    private fun deviceName(): String = "${System.getProperty("os.name")} desktop"

    /** Wire platform tag from the JVM OS: "windows" or "linux" (the only jpackage targets). */
    private fun desktopPlatform(): String =
        if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) "windows" else "linux"

    private companion object {
        const val POLL_INTERVAL_MS = 5L * 60 * 1000 // spec 03 §6 poll interval
    }
}
