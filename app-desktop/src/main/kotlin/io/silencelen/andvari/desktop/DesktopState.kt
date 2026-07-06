package io.silencelen.andvari.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

sealed interface DesktopScreen {
    data object Loading : DesktopScreen
    data object Welcome : DesktopScreen
    data class Unlock(val email: String) : DesktopScreen
    data object Vault : DesktopScreen
}

/**
 * Plain state holder for the desktop app (no AndroidX ViewModel). Drives the shared
 * :core client (Account + AndvariApi[java engine] + SyncEngine) and exposes Compose
 * state. Mirrors the Android AndvariViewModel.
 */
class DesktopState(private val scope: CoroutineScope) {
    private val store = DesktopSessionStore()

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
    var baseUrl by mutableStateOf(store.baseUrl)
        private set
    var updateAvailable by mutableStateOf<String?>(null)
        private set

    private var api: AndvariApi? = null
    private var account: Account? = null
    private var engine: SyncEngine? = null

    private fun newApi(tokens: Tokens? = null) =
        AndvariApi(store.baseUrl, HttpClient(Java), tokens) { store.updateTokens(it) }

    fun start() {
        scope.launch {
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { policy = it }
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

    fun signIn(email: String, password: String) = op {
        val a = newApi()
        val pre = a.prelogin(email)
        val authKey = Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams)
        val s = a.login(LoginRequest(email, authKey, Account.deviceInfo(deviceName())))
        val acct = Account.unlock(s.userId, password, s.accountKeys)
        bind(a, acct); engine!!.sync()
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        toVault()
    }

    fun unlock(email: String, password: String) = op {
        val session = store.load() ?: error("no session")
        val a = newApi(session.tokens())
        val keys = a.accountKeys()
        val acct = Account.unlock(session.userId, password, keys)
        bind(a, acct); engine!!.sync()
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
        bind(a, acct); engine!!.sync()
        store.save(DesktopSession(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        toVault()
    }

    fun saveItem(itemId: String?, doc: ItemDoc) = op { engine!!.save(itemId, doc); refreshItems() }
    fun deleteItem(itemId: String) = op { engine!!.remove(itemId); refreshItems() }
    fun refresh() = op { engine!!.sync(); refreshItems() }
    fun item(itemId: String): VaultItem? = engine?.item(itemId)

    fun lock() {
        api?.close(); api = null; account = null; engine = null
        screen = DesktopScreen.Unlock(store.load()?.email ?: ""); items = emptyList()
    }

    fun signOut() {
        scope.launch { runCatching { api?.logout() } }
        store.clear(); api?.close(); api = null; account = null; engine = null
        screen = DesktopScreen.Welcome; items = emptyList()
    }

    private fun bind(a: AndvariApi, acct: Account) {
        api = a; account = acct; engine = SyncEngine(a, acct, InMemoryVaultCache())
    }

    private fun refreshItems() { items = engine?.items() ?: emptyList(); busy = false; error = null }
    private fun toVault() { screen = DesktopScreen.Vault; items = engine?.items() ?: emptyList(); busy = false; error = null }

    private fun op(block: suspend () -> Unit) {
        busy = true; error = null
        scope.launch {
            try { block() } catch (t: Throwable) { busy = false; error = t.message ?: "something went wrong" }
        }
    }

    private fun deviceName(): String = "${System.getProperty("os.name")} desktop"
}
