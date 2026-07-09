package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.FillResponse
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.Toast
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.app.browserLabel

/**
 * Launched from the autofill dropdown's "Trust {browser} to fill here" row ([DatasetBuilder]). Reads
 * the browser's real on-device signing digest and, on the user's explicit confirm, approves it
 * ([ApprovedBrowsers]). Then — so the dropdown updates without a page reload — it re-runs the fill
 * for THIS form (now that the browser is trusted) and returns it via EXTRA_AUTHENTICATION_RESULT.
 * The explicit tap is the security gate; a malicious app can't self-trust.
 */
class TrustBrowserActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // back / dismiss = trusted nothing, no fill
        val pkg = intent.getStringExtra(EXTRA_PKG)
        if (pkg == null) { finish(); return }
        val digest = TrustedBrowsers.observedCertDigest(applicationContext, pkg)
        if (digest == null) {
            Toast.makeText(applicationContext, "Couldn't read that browser's identity — try again.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        setContent {
            AndvariTheme {
                TrustCard(browser = browserLabel(pkg), onTrust = { approveAndRefill(pkg, digest) }, onCancel = { finish() })
            }
        }
    }

    private fun approveAndRefill(pkg: String, digest: String) {
        ApprovedBrowsers.approve(applicationContext, pkg, digest)
        // Re-run the fill for this form now that the browser is trusted, and hand it back so the
        // dropdown refreshes in place. Only possible when the vault is unlocked (the trust row only
        // shows on the unlocked path) and the platform injected the structure; otherwise we just
        // finish and the toast tells the user to tap the field again.
        val structure = intent.assistStructure()
        val unlocked = VaultSession.getIfFresh()
        val response: FillResponse? = if (structure != null && unlocked != null) {
            runCatching {
                DatasetBuilder.responseForUnlocked(this, structure, unlocked.engine.items(), intent.inlineRequest(), null)
            }.getOrNull()
        } else {
            null
        }
        if (response != null) {
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
            Toast.makeText(applicationContext, "${browserLabel(pkg)} trusted.", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(applicationContext, "${browserLabel(pkg)} trusted — tap the login field again.", Toast.LENGTH_SHORT).show()
        }
        finish()
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

    companion object {
        const val EXTRA_PKG = "pkg"
    }
}

@Composable
private fun TrustCard(browser: String, onTrust: () -> Unit, onCancel: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text("Trust $browser?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text(
                    "andvari will fill and save logins in $browser on this device. Only trust a browser " +
                        "you installed yourself — this lets andvari believe the web address $browser reports.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(20.dp))
                Button(onClick = onTrust, modifier = Modifier.fillMaxWidth()) { Text("Trust $browser") }
                TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
            }
        }
    }
}
