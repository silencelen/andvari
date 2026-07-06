package io.silencelen.andvari.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

sealed interface Screen {
    data object Loading : Screen
    data object Welcome : Screen
    data class Unlock(val email: String) : Screen
    data object Vault : Screen
}

data class UiState(
    val screen: Screen = Screen.Loading,
    val items: List<VaultItem> = emptyList(),
    val policy: ClientPolicy? = null,
    val busy: Boolean = false,
    val error: String? = null,
    val baseUrl: String = SessionStore.DEFAULT_BASE_URL,
)

class AndvariViewModel(private val store: SessionStore) : ViewModel() {
    private val _ui = MutableStateFlow(UiState(baseUrl = store.baseUrl))
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private var api: AndvariApi? = null
    private var account: Account? = null
    private var engine: SyncEngine? = null

    private fun newApi(tokens: Tokens? = null): AndvariApi =
        AndvariApi(store.baseUrl, HttpClient(OkHttp), tokens) { store.updateTokens(it) }

    fun start() {
        viewModelScope.launch {
            val session = store.load()
            val probe = newApi()
            runCatching { probe.clientPolicy() }.onSuccess { _ui.value = _ui.value.copy(policy = it) }
            probe.close()
            _ui.value = _ui.value.copy(
                screen = if (session != null && session.accessToken.isNotEmpty()) Screen.Unlock(session.email) else Screen.Welcome,
                baseUrl = store.baseUrl,
            )
        }
    }

    fun setBaseUrl(url: String) {
        store.baseUrl = url.trim().removeSuffix("/")
        _ui.value = _ui.value.copy(baseUrl = store.baseUrl)
    }

    private fun fail(t: Throwable) {
        _ui.value = _ui.value.copy(busy = false, error = t.message ?: "something went wrong")
    }

    fun clearError() { _ui.value = _ui.value.copy(error = null) }

    fun signIn(email: String, password: String) = op {
        val a = newApi()
        val pre = a.prelogin(email)
        val authKey = Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams)
        val s = a.login(LoginRequest(email, authKey, Account.deviceInfo(android.os.Build.MODEL ?: "android")))
        val acct = Account.unlock(s.userId, password, s.accountKeys)
        bind(a, acct)
        engine!!.sync()
        store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        toVault()
    }

    fun unlock(email: String, password: String) = op {
        val session = store.load() ?: throw IllegalStateException("no session")
        val a = newApi(session.tokens())
        val keys = a.accountKeys()
        val acct = Account.unlock(session.userId, password, keys)
        bind(a, acct)
        engine!!.sync()
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
        bind(a, acct)
        engine!!.sync()
        store.save(Session(store.baseUrl, s.userId, email, s.accessToken, s.refreshToken))
        toVault()
    }

    fun saveItem(itemId: String?, doc: ItemDoc) = op {
        engine!!.save(itemId, doc)
        refreshItems()
    }

    fun deleteItem(itemId: String) = op {
        engine!!.remove(itemId)
        refreshItems()
    }

    fun refresh() = op { engine!!.sync(); refreshItems() }

    fun item(itemId: String): VaultItem? = engine?.item(itemId)

    fun lock() {
        api?.close(); api = null; account = null; engine = null
        _ui.value = _ui.value.copy(screen = Screen.Unlock(store.load()?.email ?: ""), items = emptyList())
    }

    fun signOut() {
        viewModelScope.launch { runCatching { api?.logout() } }
        store.clear(); api?.close(); api = null; account = null; engine = null
        _ui.value = _ui.value.copy(screen = Screen.Welcome, items = emptyList())
    }

    // ---- helpers ----
    private fun bind(a: AndvariApi, acct: Account) {
        api = a; account = acct
        engine = SyncEngine(a, acct, InMemoryVaultCache())
    }

    private fun refreshItems() {
        _ui.value = _ui.value.copy(items = engine?.items() ?: emptyList(), busy = false, error = null)
    }

    private fun toVault() {
        _ui.value = _ui.value.copy(screen = Screen.Vault, items = engine?.items() ?: emptyList(), busy = false, error = null)
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
