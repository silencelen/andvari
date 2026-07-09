package io.silencelen.andvari.app.autofill

import android.os.Bundle
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
import io.silencelen.andvari.app.browserLabel

/**
 * Launched from the autofill dropdown's "Trust {browser} to fill here" row ([DatasetBuilder]). Reads
 * the browser's real on-device signing digest and, on the user's explicit confirm (seeing WHICH
 * browser), approves it ([ApprovedBrowsers]) so andvari fills + saves there. The explicit tap is the
 * security gate — a malicious app can't get itself trusted without the user choosing to. Fills
 * nothing; after trusting, the user reopens the form (now a trusted browser → it fills).
 */
class TrustBrowserActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // no fill result; the user reopens the form after trusting
        val pkg = intent.getStringExtra(EXTRA_PKG)
        if (pkg == null) { finish(); return }
        // The observed digest is what fill/save will re-verify against on every request.
        val digest = TrustedBrowsers.observedCertDigest(applicationContext, pkg)
        if (digest == null) {
            Toast.makeText(applicationContext, "Couldn't read that browser's identity — try again.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        setContent {
            AndvariTheme {
                TrustCard(
                    browser = browserLabel(pkg),
                    onTrust = {
                        ApprovedBrowsers.approve(applicationContext, pkg, digest)
                        Toast.makeText(applicationContext, "${browserLabel(pkg)} trusted — reopen the login form.", Toast.LENGTH_SHORT).show()
                        finish()
                    },
                    onCancel = { finish() },
                )
            }
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
