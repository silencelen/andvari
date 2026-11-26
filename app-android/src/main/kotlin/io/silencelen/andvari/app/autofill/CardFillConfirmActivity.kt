package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.WindowManager
import android.view.autofill.AutofillManager
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
import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.UiText
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate

/**
 * Android review 1, ruling 1: the confirm before a payment card fills an app that is not a verified browser. Launched
 * by a card row's authentication IntentSender ([DatasetBuilder]); the row itself carried no value.
 *
 * It names the app (label, package, installer and signer, as [AppFillConfirmActivity] shows them) and the card (its
 * name, brand and last four digits), and returns THAT one card and nothing else ([FillPlan.cardResult]). It has the
 * app-fill confirm's three defences: other apps' overlays hidden (API 31+), touches that come through another window
 * dropped, and the Fill button armed only [AppFillConfirmActivity.ARM_DELAY_MS] after the window gained focus. It is a
 * secure window. It is shown every time: nothing is remembered, and the app-fill gate's SILENT verdict does not apply.
 *
 * Root cause G: everything shown and used comes from the service's bake ([AppFillBinding], [FillBinding]), never from
 * what the host app delivers. The identity is re-read live at onCreate and again at the tap; a change refuses.
 */
class CardFillConfirmActivity : ComponentActivity() {
    private val armed = mutableStateOf(false)
    private val handler = Handler(Looper.getMainLooper())
    private val arm = Runnable { armed.value = true }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // back / dismiss = nothing filled
        // Before anything is drawn: a secure window, touches through another window dropped, overlays hidden.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        val form = FillBinding.resolve(intent)
        val bake = AppFillBinding.resolve(intent)
        if (form == null || bake == null || form.appPackage != bake.identity.pkg) {
            finish(); return
        }
        if (!AppFillGate.unchangedSince(bake.identity, AppIdentityLookup.lookup(applicationContext, bake.identity.pkg))) {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CONFIRM_APP_CHANGED_BEFORE).shown(), Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val item = cardItem(bake)
        if (item == null) {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CONFIRM_CARD_NOT_FILLED).shown(), Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val line = CardLine(name = item.doc.name, masked = CardDisplay.subtitle(item.doc))
        setContent {
            AndvariTheme {
                CardConfirmCard(bake = bake, card = line, armed = armed.value, onFill = { confirmAndFill(form, bake) }, onCancel = { finish() })
            }
        }
    }

    /** The card the confirm would release: only while the app's own session is open, only from the working set. */
    private fun cardItem(bake: AppFillBinding.Bake): VaultItem? =
        (ContentFillSession.access(applicationContext) as? ContentFillSession.Access.Open)
            ?.let { ContentFill.cardById(it.content, bake.itemId) }

    private fun confirmAndFill(form: ParsedForm, bake: AppFillBinding.Bake) {
        if (!armed.value) return // the state layer refuses an unarmed tap, not only the disabled button
        if (!AppFillGate.unchangedSince(bake.identity, AppIdentityLookup.lookup(applicationContext, bake.identity.pkg))) {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CONFIRM_APP_CHANGED).shown(), Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val dataset = cardItem(bake)?.let { runCatching { DatasetBuilder.cardResultDataset(it, form) }.getOrNull() }
        if (dataset != null) {
            // Nothing is remembered: the next card fill in this app asks again.
            ContentFillSession.HardLock.arm(applicationContext)
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        } else {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CONFIRM_CARD_NOT_FILLED).shown(), Toast.LENGTH_SHORT).show()
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
}

/** The card a confirm would release, as shown: its name and "Brand ••1234". Never the number, the date or the code. */
internal data class CardLine(val name: String, val masked: String)

/** Also shown by andvari's own chooser ([FillChooserActivity]) once the person picked a card there. */
@Composable
internal fun CardConfirmCard(bake: AppFillBinding.Bake, card: CardLine, armed: Boolean, onFill: () -> Unit, onCancel: () -> Unit) {
    val view = LocalView.current
    SideEffect { view.filterTouchesWhenObscured = true }
    val id = bake.identity
    val app = AppFillGate.oneLine(id.label) ?: id.pkg
    Column(
        // It scrolls, as the unlock card does: at the largest font Fill and Cancel were below the screen's edge.
        Modifier.fillMaxSize().verticalScroll(androidx.compose.foundation.rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp)) {
                Text("Fill this card into an app?", style = MaterialTheme.typography.titleLarge)
                Spacer(Modifier.height(8.dp))
                Text("Card", style = MaterialTheme.typography.labelMedium)
                Text(AppFillGate.oneLine(card.name) ?: "(no name)", style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(card.masked, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(12.dp))
                Text("App", style = MaterialTheme.typography.labelMedium)
                Text(app, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(id.pkg, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Text(AppFillGate.installerLine(id.installer, id.installerSystem), style = MaterialTheme.typography.bodySmall)
                AppFillGate.installerLabelLine(id.installer, bake.installerLabel)?.let { label ->
                    Text(label, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Spacer(Modifier.height(8.dp))
                Text("Signer (SHA-256)", style = MaterialTheme.typography.labelMedium)
                Text(AppFillGate.signerLine(id.signerDigest), style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
                Spacer(Modifier.height(12.dp))
                Text(
                    "This app is not a browser andvari trusts. It receives this card's number, expiry and security code " +
                        "if you continue. Continue only if this is the app you meant to pay in.",
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
