package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.autofill.FillResponse
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.verticalScroll
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
import io.silencelen.andvari.app.browserLabel
import io.silencelen.andvari.core.client.autofill.AppFillGate

/**
 * Launched from the autofill dropdown's "Trust {browser} to fill here" row ([DatasetBuilder]). Reads the browser's
 * real on-device signing digest and, on the person's explicit confirm, approves exactly that signer
 * ([ApprovedBrowsers]). Then, so the dropdown updates without a page reload, it re-runs the fill for THIS form and
 * returns it via EXTRA_AUTHENTICATION_RESULT.
 *
 * The rules:
 *  - The card shows what the app-fill confirm shows: the package, the installer line and the signer, beside the
 *    browser name andvari knows the id by (a name for an id, not a proof).
 *  - It has the app-fill confirm's three defences: other apps' overlays hidden (API 31+), touches that come through
 *    another window dropped, and the button armed only [AppFillConfirmActivity.ARM_DELAY_MS] after focus.
 *  - An id with a pinned certificate is never approved here: a mismatch is a warning with no Trust button and no fill.
 *  - An approval is kept with its signer; a different signer later is not trusted and asks again, with a warning.
 *  - The signer is read again at the tap; a change refuses.
 *
 * Root cause G: "this form" is the one the service baked into the PendingIntent ([FillBinding]), never the structure
 * that arrives with the launch. A baked form for a different package than [EXTRA_PKG] (also baked) refuses the refill.
 */
class TrustBrowserActivity : ComponentActivity() {
    private val armed = mutableStateOf(false)
    private val handler = Handler(Looper.getMainLooper())
    private val arm = Runnable { armed.value = true }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // back / dismiss = trusted nothing, no fill
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        val pkg = intent.getStringExtra(EXTRA_PKG)
        if (pkg == null) { finish(); return }
        val digest = TrustedBrowsers.observedCertDigest(applicationContext, pkg)
        if (digest == null) {
            Toast.makeText(applicationContext, "Couldn't read that browser's identity — try again.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val offer = ApprovedBrowsers.offer(pkg, digest, ApprovedBrowsers.approvedDigest(applicationContext, pkg))
        val identity = AppIdentityLookup.lookup(applicationContext, pkg)
        val installerLabel = runCatching { AppIdentityLookup.installerLabel(applicationContext, identity.installer) }.getOrNull()
        setContent {
            AndvariTheme {
                TrustCard(
                    browser = browserLabel(pkg),
                    identity = identity,
                    installerLabel = installerLabel,
                    offer = offer,
                    armed = armed.value,
                    onTrust = { approveAndRefill(pkg, digest) },
                    onCancel = { finish() },
                )
            }
        }
    }

    private fun approveAndRefill(pkg: String, digest: String) {
        if (!armed.value) return // the state layer refuses an unarmed tap, not only the disabled button
        // The signer at the TAP: what is approved is what is installed now.
        if (TrustedBrowsers.observedCertDigest(applicationContext, pkg) != digest || !ApprovedBrowsers.approve(applicationContext, pkg, digest)) {
            Toast.makeText(applicationContext, "That browser changed while this was open — nothing was trusted.", Toast.LENGTH_SHORT).show()
            finish(); return
        }
        // Re-run the fill for this form now that the browser is trusted, and hand it back so the dropdown refreshes in
        // place. Only possible when the vault is unlocked (the trust row only shows on the unlocked path) and the
        // baked form checks out; otherwise we just finish and the toast tells the person to tap the field again.
        val form = FillBinding.resolve(intent)?.takeIf { it.appPackage == pkg }
        // The app's own session on the new code, read after the idle lock; only while it is open.
        val open = ContentFillSession.access(applicationContext) as? ContentFillSession.Access.Open
        val response: FillResponse? = if (form != null && open != null) {
            runCatching {
                // Trusted now: the frame domains count, as on the service's trusted path.
                val items = ContentFill.offersFor(open.content, form, TrustedBrowsers.isTrusted(this, form.appPackage))
                DatasetBuilder.responseForUnlocked(this, form, items, intent.inlineRequest(), null) { id -> ContentFill.release(open.content, id) }
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

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        handler.removeCallbacks(arm)
        if (hasFocus) handler.postDelayed(arm, AppFillConfirmActivity.ARM_DELAY_MS) else armed.value = false
    }

    override fun onDestroy() {
        handler.removeCallbacks(arm)
        super.onDestroy()
    }

    private val obscuredTold = BooleanArray(1)

    /** On Android 10 and 11 a touch while the window is partly covered is dropped ([FillWindow]). */
    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean = FillWindow.dispatch(this, ev, obscuredTold) { super.dispatchTouchEvent(it) }

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
internal fun TrustCard(
    browser: String,
    identity: AppFillGate.Identity,
    installerLabel: String?,
    offer: ApprovedBrowsers.Offer,
    armed: Boolean,
    onTrust: () -> Unit,
    onCancel: () -> Unit,
) {
    val view = LocalView.current
    SideEffect { view.filterTouchesWhenObscured = true }
    Column(
        // It scrolls, as the unlock card does: at the largest font Trust and Not now were below the screen's edge.
        Modifier.fillMaxSize().verticalScroll(androidx.compose.foundation.rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                if (offer == ApprovedBrowsers.Offer.PINNED_MISMATCH) {
                    Text("This is not $browser", style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "An app installed under $browser's name is not signed by $browser's maker. andvari will not fill here, " +
                            "and it cannot be trusted on this device.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                } else {
                    Text("Trust $browser?", style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(8.dp))
                    if (offer == ApprovedBrowsers.Offer.SIGNER_CHANGED) {
                        Text(
                            "This browser's signer changed since you trusted it. A real update keeps its signer; a different app " +
                                "installed under the same name does not.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error,
                        )
                        Spacer(Modifier.height(8.dp))
                    }
                }
                Spacer(Modifier.height(8.dp))
                Text("App", style = MaterialTheme.typography.labelMedium)
                Text(AppFillGate.oneLine(identity.label) ?: identity.pkg, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(identity.pkg, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Text(AppFillGate.installerLine(identity.installer, identity.installerSystem), style = MaterialTheme.typography.bodySmall)
                AppFillGate.installerLabelLine(identity.installer, installerLabel)?.let { label ->
                    Text(label, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Spacer(Modifier.height(8.dp))
                Text("Signer (SHA-256)", style = MaterialTheme.typography.labelMedium)
                Text(AppFillGate.signerLine(identity.signerDigest), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Spacer(Modifier.height(12.dp))
                if (offer != ApprovedBrowsers.Offer.PINNED_MISMATCH) {
                    Text(
                        "andvari will believe the web address this app reports for each field and fill that site's logins and " +
                            "your cards in it. Trust it only if you installed this browser yourself and the installer above is " +
                            "the one you used.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(20.dp))
                    Button(onClick = onTrust, enabled = armed, modifier = Modifier.fillMaxWidth()) { Text("Trust $browser") }
                }
                TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text(if (offer == ApprovedBrowsers.Offer.PINNED_MISMATCH) "Close" else "Not now") }
            }
        }
    }
}
