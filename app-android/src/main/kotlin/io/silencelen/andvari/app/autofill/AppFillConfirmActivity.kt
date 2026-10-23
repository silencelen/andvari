package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
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
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.VaultSession
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate

/**
 * Security review 2026-10, A14 (F7): the one-tap confirm before an `androidapp://` login is released
 * into an app that is neither a system app nor Play-installed (or whose identity could not be read).
 * Launched by the dataset's authentication IntentSender ([DatasetBuilder.confirmDataset]); the
 * dataset itself carried no credential.
 *
 * Root cause G: everything shown and used comes from the service's bake ([AppFillBinding] — the
 * identity PackageManager gave the service; [FillBinding] — the form it parsed), never from the
 * structure or fill-in the host app delivers. The host does hold the row's IntentSender and can fire
 * it again, so every launch is a fresh confirm and nothing is released without a tap here.
 *
 * Since the A14 review:
 *  - N2: the app label, the installer label and the login's name and username are one escaped,
 *    bounded line each ([AppFillGate.oneLine]), rendered maxLines = 1 with an ellipsis; the installer
 *    line names its PACKAGE and whether it is a system app; the card names the login it would release.
 *  - N6: touches that arrive through another window are dropped (filterTouchesWhenObscured on the
 *    decor view and the compose host), other apps' overlays are hidden on API 31+, and the Fill button
 *    accepts a tap only [ARM_DELAY_MS] after the window gained focus; losing focus disarms it.
 *  - N7: the live identity (signer, installer, installer kind, system flag) is read again at the TAP,
 *    not only at onCreate, and a change refuses the fill; the (package, signer) binding is remembered
 *    only when a fill was actually delivered.
 */
class AppFillConfirmActivity : ComponentActivity() {
    private val armed = mutableStateOf(false)
    private val handler = Handler(Looper.getMainLooper())
    private val arm = Runnable { armed.value = true }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // back / dismiss = nothing filled, nothing remembered
        // N6: before anything is drawn. A touch that passed through another app's window is dropped,
        // and on API 31+ other apps' overlay windows are hidden while this one is shown.
        window.decorView.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        val form = FillBinding.resolve(intent)
        val bake = AppFillBinding.resolve(intent)
        if (form == null || bake == null || form.appPackage != bake.identity.pkg) {
            finish(); return
        }
        if (!AppFillGate.unchangedSince(bake.identity, AppIdentityLookup.lookup(applicationContext, bake.identity.pkg))) {
            Toast.makeText(applicationContext, "That app changed since you tapped — tap the field again.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        // N2: the card names the login it would release; with no unlocked vault nothing could fill, so
        // there is nothing to confirm (and nothing is remembered).
        val item = loginItem(bake)
        if (item == null) {
            Toast.makeText(applicationContext, "Couldn't fill that login — open andvari and try again.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val login = LoginLine(name = item.doc.name, username = item.doc.login?.username)
        setContent {
            AndvariTheme {
                ConfirmCard(
                    bake = bake,
                    login = login,
                    armed = armed.value,
                    onFill = { confirmAndFill(form, bake) },
                    onCancel = { finish() },
                )
            }
        }
    }

    private fun loginItem(bake: AppFillBinding.Bake): VaultItem? =
        VaultSession.getIfFresh()?.engine?.items()?.firstOrNull { it.itemId == bake.itemId && it.doc.type == "login" }

    private fun confirmAndFill(form: ParsedForm, bake: AppFillBinding.Bake) {
        if (!armed.value) return // N6: the state layer refuses an unarmed tap, not only the disabled button
        // N7: the identity at the TAP, not the one onCreate saw.
        if (!AppFillGate.unchangedSince(bake.identity, AppIdentityLookup.lookup(applicationContext, bake.identity.pkg))) {
            Toast.makeText(applicationContext, "That app changed while this was open — nothing was filled.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val item = loginItem(bake)
        val dataset = item?.let { runCatching { DatasetBuilder.appLoginResultDataset(it, form) }.getOrNull() }
        if (dataset != null) {
            // N7: remembered only now, with a fill actually delivered. A binding needs a signer to bind
            // to: an unreadable identity confirms again next time.
            bake.identity.signerDigest?.let { digest -> AppSignerBindings.remember(applicationContext, bake.identity.pkg, digest) }
            AutofillHardLock.arm()
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        } else {
            Toast.makeText(applicationContext, "Couldn't fill that login — open andvari and try again.", Toast.LENGTH_SHORT).show()
        }
        finish()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        // N6: the button arms a moment after the window gains focus, and any loss of focus (a dialog,
        // an overlay, the notification shade) disarms it, so a tap timed to land as the card appears,
        // or as something covering it disappears, does nothing.
        handler.removeCallbacks(arm)
        if (hasFocus) {
            handler.postDelayed(arm, ARM_DELAY_MS)
        } else {
            armed.value = false
        }
    }

    override fun onDestroy() {
        handler.removeCallbacks(arm)
        super.onDestroy()
    }

    companion object {
        /** N6: how long after gaining focus the Fill button starts accepting a tap. */
        const val ARM_DELAY_MS = 500L
    }
}

/** The login a confirm would release, as the vault holds it (escaped for display by the card). */
private data class LoginLine(val name: String, val username: String?)

@Composable
private fun ConfirmCard(bake: AppFillBinding.Bake, login: LoginLine, armed: Boolean, onFill: () -> Unit, onCancel: () -> Unit) {
    // N6: the compose host view filters obscured touches too (the decor view already does).
    val view = LocalView.current
    SideEffect { view.filterTouchesWhenObscured = true }
    val id = bake.identity
    val app = AppFillGate.oneLine(id.label) ?: id.pkg
    Column(
        Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text("Fill this login into an app?", style = MaterialTheme.typography.titleLarge)
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
                Text("Login", style = MaterialTheme.typography.labelMedium)
                Text(AppFillGate.oneLine(login.name) ?: "(no name)", style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                AppFillGate.oneLine(login.username)?.let { user ->
                    Text(user, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Spacer(Modifier.height(12.dp))
                Text("App", style = MaterialTheme.typography.labelMedium)
                Text(app, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                // The package is what the login was matched on: shown whole (package names are plain identifiers).
                Text(id.pkg, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Text(
                    AppFillGate.installerLine(id.installer, bake.installerLabel, id.installerSystem),
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
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
                Button(onClick = onFill, enabled = armed, modifier = Modifier.fillMaxWidth()) { Text("Fill") }
                TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
            }
        }
    }
}
