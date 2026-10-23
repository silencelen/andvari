package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.autofill.AppFillGate

/**
 * Security review 2026-10, A14 (F7): the one-tap confirm before an `androidapp://` login is released
 * into an app that is neither a system app nor Play-installed (or whose identity could not be read).
 * Launched by the dataset's authentication IntentSender ([DatasetBuilder.confirmDataset]); the
 * dataset itself carried no credential.
 *
 * Root cause G: everything shown and used comes from the service's bake ([AppFillBinding] — the
 * identity PackageManager gave the service; [FillBinding] — the form it parsed), never from the
 * structure or fill-in the host app delivers. Before anything is released the live signer is read
 * again: a package replaced since the request is refused. On confirm the (package, signer) is
 * remembered on this device ([AppSignerBindings]) and the login is returned as the authentication
 * result for exactly the baked fields.
 */
class AppFillConfirmActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // back / dismiss = nothing filled, nothing remembered
        val form = FillBinding.resolve(intent)
        val bake = AppFillBinding.resolve(intent)
        if (form == null || bake == null || form.appPackage != bake.identity.pkg) {
            finish(); return
        }
        val live = AppIdentityLookup.lookup(applicationContext, bake.identity.pkg)
        if (live.signerDigest != bake.identity.signerDigest) {
            Toast.makeText(applicationContext, "That app changed since you tapped — tap the field again.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        setContent {
            AndvariTheme {
                ConfirmCard(
                    bake = bake,
                    onFill = { confirmAndFill(form, bake) },
                    onCancel = { finish() },
                )
            }
        }
    }

    private fun confirmAndFill(form: ParsedForm, bake: AppFillBinding.Bake) {
        // A binding needs a signer to bind to: an unreadable identity confirms again next time.
        bake.identity.signerDigest?.let { digest -> AppSignerBindings.remember(applicationContext, bake.identity.pkg, digest) }
        val unlocked = VaultSession.getIfFresh()
        val item = unlocked?.engine?.items()?.firstOrNull { it.itemId == bake.itemId }
        val dataset = item?.let { runCatching { DatasetBuilder.appLoginResultDataset(it, form) }.getOrNull() }
        if (dataset != null) {
            AutofillHardLock.arm()
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        } else {
            Toast.makeText(applicationContext, "Couldn't fill that login — open andvari and try again.", Toast.LENGTH_SHORT).show()
        }
        finish()
    }
}

@Composable
private fun ConfirmCard(bake: AppFillBinding.Bake, onFill: () -> Unit, onCancel: () -> Unit) {
    val id = bake.identity
    val app = id.label?.takeIf { it.isNotBlank() } ?: id.pkg
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text("Fill a login into $app?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                if (bake.verdict == AppFillGate.Verdict.CONFIRM_SIGNER_CHANGED) {
                    Text(
                        "This app's signer changed since you last allowed it. A real update keeps its signer; " +
                            "a different app installed under the same name does not.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Spacer(Modifier.height(8.dp))
                }
                Text(app, style = MaterialTheme.typography.titleMedium)
                Text(id.pkg, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Text(AppFillGate.installerLine(bake.installerLabel), style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(8.dp))
                Text("Signer (SHA-256)", style = MaterialTheme.typography.labelMedium)
                Text(AppFillGate.signerLine(id.signerDigest), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Spacer(Modifier.height(12.dp))
                Text(
                    "This login is saved for an app with this name, and the name is all it was matched on. Any app " +
                        "can use a name that is free on this phone, so continue only if this is the app you meant.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(20.dp))
                Button(onClick = onFill, modifier = Modifier.fillMaxWidth()) { Text("Fill") }
                TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
        }
    }
}
