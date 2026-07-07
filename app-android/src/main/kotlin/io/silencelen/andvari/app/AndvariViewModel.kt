package io.silencelen.andvari.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
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

sealed interface Screen {
    data object Loading : Screen
    data object Welcome : Screen
    data class Unlock(val email: String) : Screen
    data object Vault : Screen
    data object Settings : Screen
}

data class UiState(
    val screen: Screen = Screen.Loading,
    val items: List<VaultItem> = emptyList(),
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
)

class AndvariViewModel(private val store: SessionStore, private val cacheDir: File) : ViewModel() {
    private val _ui = MutableStateFlow(UiState(baseUrl = store.baseUrl))
    val ui: StateFlow<UiState> = _ui.asStateFlow()

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

    // Unlocked state (api/account/engine) now lives in the process-wide VaultSession, shared
    // with the autofill service. These are read-only snapshots over it — nothing is stored on
    // the ViewModel; moving where they live is the only change (all call sites keep working).
    private val api: AndvariApi? get() = VaultSession.get()?.api
    private val account: Account? get() = VaultSession.get()?.account
    private val engine: SyncEngine? get() = VaultSession.get()?.engine

    private fun newApi(tokens: Tokens? = null): AndvariApi =
        AndvariApi(store.baseUrl, HttpClient(OkHttp), tokens) { store.updateTokens(it) }

    fun start() {
        viewModelScope.launch {
            // If the vault was already unlocked in this process (autofill unlocked it first,
            // or the activity was recreated while the process lived), show it straight away.
            val bound = VaultSession.get() != null
            if (bound) {
                _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), baseUrl = store.baseUrl)
            }
            val session = store.load()
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                _ui.value = _ui.value.copy(policy = p)
                store.cacheAllowed = p.offlineCacheAllowed // persist for offline cold starts
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
                    _ui.value = _ui.value.copy(policy = p)
                    store.cacheAllowed = p.offlineCacheAllowed
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
        val authKey = Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams)
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
        val acct = Account.unlock(s.userId, password, s.accountKeys)
        store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct)
        engine!!.sync()
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
                Account.unlock(session.userId, password, keys)
            } catch (t: Throwable) { a.close(); throw t }
            bind(a, acct)
        }
        // Tolerate an offline sync — hydrate() already populated the cached vault.
        runCatching { engine!!.sync() }.onFailure {
            if (it is IOException) _ui.value = _ui.value.copy(notice = "Offline — showing cached data")
            else throw it
        }
        toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String) = op {
        val policy = _ui.value.policy ?: newApi().also { it.close() }.let { newApi().clientPolicy() }
        val a = newApi()
        val recoveryPub = Bytes.fromB64(a.recoveryPubkey())
        val (req, acct) = Account.enroll(
            inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
            password = password, params = policy.kdfParams,
            recoveryPublicKey = recoveryPub, recoveryFingerprint = policy.recoveryFingerprint,
            deviceName = android.os.Build.MODEL ?: "android",
        )
        val s = a.register(req)
        store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct)
        engine!!.sync()
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

    fun refresh() = op { engine!!.sync(); refreshItems() }

    fun item(itemId: String): VaultItem? = engine?.item(itemId)

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

    fun lock() {
        // Close the engine (and its cache DB handle) but KEEP the file — the ciphertext
        // cache is retained on lock (spec 05 T3); a relaunch hydrates it.
        VaultSession.lock()
        _ui.value = _ui.value.copy(
            screen = Screen.Unlock(store.load()?.email ?: ""), items = emptyList(),
            notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
        )
    }

    fun signOut() {
        val userId = store.load()?.userId
        val current = VaultSession.get()
        viewModelScope.launch { runCatching { current?.api?.logout() } }
        // VaultSession.lock() closes the engine BEFORE we delete the DB (holders), then the api.
        VaultSession.lock()
        userId?.let { deleteCache(it) }
        store.clear()
        _ui.value = _ui.value.copy(
            screen = Screen.Welcome, items = emptyList(),
            notice = null, loginTotpRequired = false, totpStatus = null, totpSetup = null, totpMessage = null,
        )
    }

    // ---- settings / server TOTP ----

    fun openSettings() {
        _ui.value = _ui.value.copy(screen = Screen.Settings, totpStatus = null, totpSetup = null, totpMessage = null)
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
        VaultSession.bind(a, acct, newEngine)
    }

    private fun refreshItems() {
        _ui.value = _ui.value.copy(items = engine?.items() ?: emptyList(), busy = false, error = null)
    }

    private fun toVault() {
        _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), busy = false, error = null, loginTotpRequired = false)
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
