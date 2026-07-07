package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.sqliteVaultCache
import io.silencelen.andvari.core.crypto.CryptoException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

/**
 * Translucent activity for the LOCKED autofill path. The platform launches it from the
 * service's `setAuthentication` PendingIntent, injecting EXTRA_ASSIST_STRUCTURE (and, on
 * API 30+, the inline request). It prompts for the master password, unlocks the vault into
 * [VaultSession], rebuilds datasets exactly as the service would, and returns them via
 * EXTRA_AUTHENTICATION_RESULT.
 *
 * Single token-holder invariant (binding blocker): the api is built EXACTLY like
 * AndvariViewModel.newApi — with an HttpClient engine AND the SessionStore.updateTokens
 * persistence callback — and bound into VaultSession so the main app reuses the SAME
 * token-holder. Building a token-carrying api without the onTokens callback would rotate
 * the refresh token in memory only; the next main-app unlock would reuse the consumed token
 * and revoke the whole device. If a session is already bound (a race), we reuse it and never
 * mint a second token-holder.
 */
class AutofillUnlockActivity : ComponentActivity() {

    private var busy by mutableStateOf(false)
    private var errorText by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Default result is CANCELED (back / dismiss returns cleanly with no fill).
        setResult(RESULT_CANCELED)

        val structure = intent.assistStructure()
        if (structure == null) { finish(); return }
        val inlineRequest = intent.inlineRequest()

        // Cold-process safety: arm the auto-lock gate with the persisted policy window
        // before consulting it (this activity never fetches policy itself).
        VaultSession.setAutoLockSeconds(SessionStore(applicationContext).autoLockSeconds)

        // Fast path: already unlocked in this process (e.g. the main app unlocked first) —
        // reuse it, build datasets immediately, no password prompt, no second token-holder.
        // getIfFresh enforces the inactivity window (spec 01 §8): an idle-expired vault is
        // locked and falls through to the master-password prompt below.
        VaultSession.getIfFresh()?.let { unlocked ->
            // Any throwable building the response must degrade to CANCELED, never crash the
            // host app's fill flow (an uncaught throw in this callback path kills the process).
            finishWithResponse(runCatching {
                DatasetBuilder.responseForUnlocked(this, structure, unlocked.engine.items(), inlineRequest)
            }.getOrNull())
            return
        }

        val store = SessionStore(applicationContext)
        val session = store.load()
        if (session == null || session.accessToken.isEmpty()) { finish(); return } // signed out

        setContent {
            AndvariTheme {
                UnlockCard(
                    email = session.email,
                    busy = busy,
                    error = errorText,
                    onUnlock = { pw -> unlockAndFinish(store, session, pw, structure, inlineRequest) },
                    onCancel = { finish() },
                )
            }
        }
        // Exclude the whole overlay (incl. the master-password field) from autofill —
        // belt-and-suspenders with the service self-guard.
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

    private fun unlockAndFinish(
        store: SessionStore,
        session: Session,
        password: String,
        structure: AssistStructure,
        inlineRequest: InlineSuggestionsRequest?,
    ) {
        if (busy) return
        busy = true
        errorText = null
        lifecycleScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) { unlockSession(store, session, password) }
            }
            result.onSuccess { unlocked ->
                // Rebuild datasets exactly as the service would, from the durable cache.
                // Any throwable here degrades to CANCELED rather than crashing the host app.
                finishWithResponse(runCatching {
                    DatasetBuilder.responseForUnlocked(
                        this@AutofillUnlockActivity, structure, unlocked.engine.items(), inlineRequest,
                    )
                }.getOrNull())
            }.onFailure { t ->
                busy = false
                errorText = friendly(t)
            }
        }
    }

    /**
     * Unlock the vault into VaultSession using the single-token-holder api. Mirrors
     * AndvariViewModel.unlock: offline accountKeys fallback, hydrate() from the durable
     * cache, best-effort sync tolerated. The password is used only inside this call.
     */
    private suspend fun unlockSession(store: SessionStore, session: Session, password: String): VaultSession.Unlocked =
        VaultSession.unlockMutex.withLock {
            // Inside the lock: reuse the winner's session if the main app (or a prior fill)
            // unlocked while we waited — never mint a second token-holder that reuses the
            // now-consumed refresh token (→ device revocation). getIfFresh: an idle-expired
            // winner is dropped (its api/token-holder CLOSED by lock()) instead of adopted,
            // and we mint the replacement holder below while still holding the mutex — the
            // single-token-holder invariant is preserved.
            VaultSession.getIfFresh()?.let { return@withLock it }
            unlockLocked(store, session, password)
        }

    private suspend fun unlockLocked(store: SessionStore, session: Session, password: String): VaultSession.Unlocked {
        val api = AndvariApi(store.baseUrl, HttpClient(OkHttp), session.tokens()) { store.updateTokens(it) }
        val keys = try {
            api.accountKeys().also { if (store.cacheAllowed) store.saveAccountKeys(it) else store.clearAccountKeys() }
        } catch (e: IOException) {
            // Offline: fall back to the cached accountKeys (spec 02 §8).
            store.loadAccountKeys() ?: run { api.close(); throw e }
        } catch (t: Throwable) {
            // A definitive auth failure (401 already tried a token refresh inside the api).
            api.close(); throw t
        }
        val acct = try {
            Account.unlock(session.userId, password, keys)
        } catch (t: Throwable) {
            api.close(); throw t // wrong password etc. — never leave the token-holder open unbound
        }

        val cache = if (store.cacheAllowed) {
            sqliteVaultCache(File(applicationContext.noBackupFilesDir, "vault-${acct.userId}.db").absolutePath, acct.userId)
        } else {
            // Policy forbids the durable cache: delete any existing file (spec 02 §8) — the
            // main-app bind() does the same; without this the autofill path would leave a
            // durable ciphertext DB against policy.
            for (s in listOf("", "-wal", "-shm")) File(applicationContext.noBackupFilesDir, "vault-${acct.userId}.db$s").delete()
            InMemoryVaultCache()
        }
        val engine = SyncEngine(api, acct, cache).also { it.hydrate() }
        VaultSession.bind(api, acct, engine, cache) // now THE token-holder; the main app reuses it
        runCatching { engine.sync() } // best-effort; hydrate already gave cached items
        return VaultSession.get() ?: VaultSession.Unlocked(api, acct, engine, cache)
    }

    private fun finishWithResponse(response: android.service.autofill.FillResponse?) {
        if (response != null) {
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
        } else {
            setResult(RESULT_CANCELED) // unlocked, but nothing matched this form
        }
        finish()
    }

    private fun friendly(t: Throwable): String = when {
        t is CryptoException -> t.message ?: "Wrong master password."
        t is ApiException && t.status == 401 -> "Session expired — open andvari and sign in again."
        t is IOException -> "Offline, and no saved keys — open andvari once while online."
        else -> t.message ?: "Couldn't unlock."
    }

    @Suppress("DEPRECATION")
    private fun Intent.assistStructure(): AssistStructure? =
        if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }

    @Suppress("DEPRECATION")
    private fun Intent.inlineRequest(): InlineSuggestionsRequest? {
        if (Build.VERSION.SDK_INT < 30) return null
        return if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST, InlineSuggestionsRequest::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_INLINE_SUGGESTIONS_REQUEST)
        }
    }
}

@androidx.compose.runtime.Composable
private fun UnlockCard(
    email: String,
    busy: Boolean,
    error: String?,
    onUnlock: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
                Text("Unlock andvari", style = MaterialTheme.typography.titleLarge)
                Text(email, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Master password") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
                if (error != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(16.dp))
                Button(
                    onClick = { onUnlock(password) },
                    enabled = password.isNotBlank() && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text("Unlock")
                }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
            }
        }
    }
}
