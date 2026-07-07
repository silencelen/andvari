package io.silencelen.andvari.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.TotpSetupResponse
import io.silencelen.andvari.core.model.TotpStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

sealed interface DesktopScreen {
    data object Loading : DesktopScreen
    data object Welcome : DesktopScreen
    data class Unlock(val email: String) : DesktopScreen
    data object Vault : DesktopScreen
    data object Settings : DesktopScreen
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
    }

    var screen by mutableStateOf<DesktopScreen>(DesktopScreen.Loading)
        private set
    var items by mutableStateOf<List<VaultItem>>(emptyList())
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
    var signInTotpRequired by mutableStateOf(false)
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

    private var api: AndvariApi? = null
    private var account: Account? = null
    private var engine: SyncEngine? = null

    private fun newApi(tokens: Tokens? = null) =
        AndvariApi(store.baseUrl, HttpClient(Java), tokens) { store.updateTokens(it) }

    fun start() {
        scope.launch {
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { p ->
                policy = p
                store.cacheAllowed = p.offlineCacheAllowed // persist for offline cold starts
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
        val authKey = Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams)
        val s = try {
            a.login(LoginRequest(email, authKey, Account.deviceInfo(deviceName()), totp = totp))
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
        val acct = Account.unlock(s.userId, password, s.accountKeys)
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct); engine!!.sync()
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
        val acct = Account.unlock(session.userId, password, keys)
        bind(a, acct)
        runCatching { engine!!.sync() }.onFailure {
            if (it is java.io.IOException) notice = "Offline — showing cached data" else throw it
        }
        toVault()
    }

    fun enroll(invite: String, email: String, name: String, password: String) = op {
        val pol = policy ?: newApi().clientPolicy().also { policy = it }
        val a = newApi()
        val recoveryPub = Bytes.fromB64(a.recoveryPubkey())
        val (req, acct) = Account.enroll(
            inviteToken = invite, email = email, displayName = name.ifBlank { email.substringBefore('@') },
            password = password, params = pol.kdfParams,
            recoveryPublicKey = recoveryPub, recoveryFingerprint = pol.recoveryFingerprint, deviceName = deviceName(),
        )
        val s = a.register(req)
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        persistAccountKeys(s.accountKeys)
        bind(a, acct); engine!!.sync()
        toVault()
    }

    fun saveItem(itemId: String?, doc: ItemDoc, uploads: List<PendingUpload> = emptyList()) =
        op { engine!!.saveWithUploads(itemId, doc, uploads); refreshItems() }
    fun deleteItem(itemId: String) = op { engine!!.remove(itemId); refreshItems() }
    fun refresh() = op { engine!!.sync(); refreshItems() }
    fun item(itemId: String): VaultItem? = engine?.item(itemId)

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

    fun lock() {
        // Retain the ciphertext cache on lock (spec 05 T3); close its handle.
        engine?.close(); api?.close(); api = null; account = null; engine = null
        clearSecondary()
        screen = DesktopScreen.Unlock(store.load()?.email ?: ""); items = emptyList()
    }

    fun signOut() {
        val userId = store.load()?.userId
        scope.launch { runCatching { api?.logout() } }
        // Close the engine (releases the DB handle — Windows won't delete an open file) first.
        engine?.close(); api?.close(); api = null; account = null; engine = null
        userId?.let { deleteCache(it) }
        store.clear()
        clearSecondary(); signInTotpRequired = false
        screen = DesktopScreen.Welcome; items = emptyList()
    }

    private fun clearSecondary() {
        notice = null; totpStatus = null; totpSetupInfo = null; totpError = null
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

    /** Persist accountKeys for offline unlock ONLY when the policy permits it (spec 02 §8). */
    private fun persistAccountKeys(keys: io.silencelen.andvari.core.model.AccountKeys) {
        if (cacheAllowed()) store.saveAccountKeys(keys) else store.clearAccountKeys()
    }

    /** Enforce offlineCacheAllowed=false: drop BOTH the vault DB and the cached keys. */
    private fun purgeOfflineData(userId: String) { deleteCache(userId); store.clearAccountKeys() }

    private fun bind(a: AndvariApi, acct: Account) {
        engine?.close()
        api = a; account = acct
        val allowed = policy?.offlineCacheAllowed ?: store.cacheAllowed
        val cache = if (allowed) {
            val db = cacheFile(acct.userId)
            sqliteVaultCache(db.absolutePath, acct.userId).also {
                // 0600 on POSIX, best-effort on Windows — same handling as session.json.
                for (suffix in listOf("", "-wal", "-shm")) restrictToOwner(File("${db.path}$suffix"))
            }
        } else {
            deleteCache(acct.userId); InMemoryVaultCache()
        }
        engine = SyncEngine(a, acct, cache).also { it.hydrate() }
    }

    private fun restrictToOwner(f: File) {
        if (!f.exists()) return
        runCatching { f.setReadable(false, false); f.setReadable(true, true); f.setWritable(false, false); f.setWritable(true, true) }
    }

    private fun refreshItems() { items = engine?.items() ?: emptyList(); busy = false; error = null }
    private fun toVault() { screen = DesktopScreen.Vault; items = engine?.items() ?: emptyList(); busy = false; error = null }

    private fun op(block: suspend () -> Unit) {
        busy = true; error = null; notice = null
        scope.launch {
            try { block() } catch (t: Throwable) { busy = false; error = t.message ?: "something went wrong" }
        }
    }

    private fun deviceName(): String = "${System.getProperty("os.name")} desktop"
}
