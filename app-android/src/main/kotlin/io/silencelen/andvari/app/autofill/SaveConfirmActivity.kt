package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
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
import androidx.compose.runtime.Composable
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
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.Session
import io.silencelen.andvari.app.SessionStore
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.CryptoException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * "Save to andvari?" — launched by [AndvariAutofillService.onSaveRequest] via an IntentSender after
 * the platform's save UI dismisses, receiving the submitted form's EXTRA_ASSIST_STRUCTURE. Reads the
 * typed credentials ([SaveExtractor] — the one place autofill touches field VALUES), unlocks the
 * vault if needed (the shared single-token-holder [AutofillUnlock]), shows the user exactly what
 * will be saved, and on confirm creates a login (encrypted client-side, pushed) in the personal
 * vault via the SAME engine the app uses. Values live only in memory here and are never logged.
 * FLAG_SECURE + excluded-from-autofill, mirroring the unlock overlay.
 */
class SaveConfirmActivity : ComponentActivity() {
    private var busy by mutableStateOf(false)
    private var errorText by mutableStateOf<String?>(null)
    private var unlocked by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        setResult(RESULT_CANCELED) // back / dismiss = don't save

        val structure = intent.assistStructure()
        if (structure == null) { finish(); return }
        val creds = SaveExtractor.extract(structure)
        if (!creds.savable) { finish(); return } // no password captured → nothing to save

        VaultSession.setAutoLockSeconds(SessionStore(applicationContext).autoLockSeconds)
        unlocked = VaultSession.getIfFresh() != null

        val store = SessionStore(applicationContext)
        val session = store.load()
        if (session == null || session.accessToken.isEmpty()) { finish(); return } // signed out

        setContent {
            AndvariTheme {
                if (!unlocked) {
                    UnlockToSaveCard(
                        email = session.email, site = creds.title(), busy = busy, error = errorText,
                        onUnlock = { pw -> doUnlock(store, session, pw) }, onCancel = { finish() },
                    )
                } else {
                    SaveCard(
                        site = creds.title(), username = creds.username, busy = busy, error = errorText,
                        onSave = { doSave(creds) }, onCancel = { finish() },
                    )
                }
            }
        }
        // Never let our own save overlay be autofilled (belt-and-suspenders with the service self-guard).
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    }

    private fun doUnlock(store: SessionStore, session: Session, password: String) {
        if (busy) return
        busy = true; errorText = null
        lifecycleScope.launch {
            runCatching { withContext(Dispatchers.IO) { AutofillUnlock.unlock(this@SaveConfirmActivity, store, session, password) } }
                .onSuccess { busy = false; unlocked = true }
                .onFailure { busy = false; errorText = friendly(it) }
        }
    }

    private fun doSave(creds: SavedCredentials) {
        if (busy) return
        // Re-check freshness: an idle auto-lock between unlock and confirm drops us back to the
        // password prompt rather than saving against a stale/closed engine.
        val engine = VaultSession.getIfFresh()?.engine ?: run { unlocked = false; return }
        busy = true; errorText = null
        lifecycleScope.launch {
            runCatching {
                val doc = ItemDoc(
                    type = "login",
                    name = creds.title(),
                    login = LoginData(username = creds.username, password = creds.password, uris = listOf(creds.uri())),
                )
                withContext(Dispatchers.IO) { engine.save(null, doc) } // new item in the personal vault
            }.onSuccess {
                setResult(RESULT_OK)
                finish()
            }.onFailure { busy = false; errorText = friendly(it) }
        }
    }

    private fun friendly(t: Throwable): String = when {
        t is CryptoException -> t.message ?: "Wrong master password."
        t is ApiException && t.status == 401 -> "Session expired — open andvari and sign in again."
        t is IOException -> "Offline — try saving again when you're connected."
        else -> t.message ?: "Couldn't save this login."
    }

    @Suppress("DEPRECATION")
    private fun Intent.assistStructure(): AssistStructure? =
        if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
}

@Composable
private fun SaveCard(
    site: String,
    username: String?,
    busy: Boolean,
    error: String?,
    onSave: () -> Unit,
    onCancel: () -> Unit,
) {
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text("Save to andvari?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(4.dp))
                Text("A new login will be saved to your personal vault.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(16.dp))
                LabeledValue("Site", site)
                if (!username.isNullOrEmpty()) { Spacer(Modifier.height(8.dp)); LabeledValue("Username", username) }
                Spacer(Modifier.height(8.dp))
                LabeledValue("Password", "•••••••• (will be saved)")
                if (error != null) {
                    Spacer(Modifier.height(12.dp))
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(20.dp))
                Button(onClick = onSave, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text("Save to andvari")
                }
                TextButton(onClick = onCancel, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
            }
        }
    }
}

@Composable
private fun UnlockToSaveCard(
    email: String,
    site: String,
    busy: Boolean,
    error: String?,
    onUnlock: (String) -> Unit,
    onCancel: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Text("ᛅ", style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.primary)
                Text("Unlock to save", style = MaterialTheme.typography.titleLarge)
                Text("$email · saving a login for $site", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = password, onValueChange = { password = it }, label = { Text("Master password") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth(), visualTransformation = PasswordVisualTransformation(),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                )
                if (error != null) { Spacer(Modifier.height(8.dp)); Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                Spacer(Modifier.height(16.dp))
                Button(onClick = { onUnlock(password) }, enabled = password.isNotBlank() && !busy, modifier = Modifier.fillMaxWidth()) {
                    if (busy) CircularProgressIndicator(Modifier.height(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                    else Text("Unlock")
                }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Cancel") }
            }
        }
    }
}

@Composable
private fun LabeledValue(label: String, value: String) {
    Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    Text(value, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
}
