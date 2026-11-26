package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.AndvariTheme
import io.silencelen.andvari.app.trust.Placeholder
import io.silencelen.andvari.app.trust.UiText
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.AppFillGate
import io.silencelen.andvari.core.client.autofill.BrowserCertPins

/**
 * Andvari's own chooser, opened by the one generic row a result carries for an app
 * that is not a verified browser ([FillRow.Choose], [FillPlan.resultRows]). The result itself named nothing; the names,
 * the user names and how many there are are shown here, in andvari's window, and nowhere the app can read them.
 *
 * The person picks one item here:
 * - a vetted app's own login (the app-fill gate's SILENT verdict) fills at once: the app is entitled to it;
 * - any other login, and every card, shows the app-fill or card confirm in this same window (its three defences, the
 *   armed button, the identity read again at the tap), and only the confirmed item is returned.
 *
 * So there is one way in: the app holds one sender, which opens this list, and cannot raise the confirm for an item
 * of its choosing. Root cause G: the form, the app's identity and the kind come from the service's bake in the base
 * intent ([FillBinding], [AppFillBinding.bakeGate], [bake]); nothing the host app delivers is read. Nothing is released
 * before the pick: the values of the picked item are asked for at the pick ([ContentFill.loginById],
 * [ContentFill.cardById]).
 */
class FillChooserActivity : ComponentActivity() {
    private val armed = mutableStateOf(false)
    private val picked = mutableStateOf<FillRow<AutofillId>?>(null)
    private val handler = Handler(Looper.getMainLooper())
    private val arm = Runnable { armed.value = true }
    private var focused = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED) // back / dismiss = nothing filled
        // Before anything is drawn: a secure window, touches through another window dropped, overlays hidden.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.filterTouchesWhenObscured = true
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        val form = FillBinding.resolve(intent)
        val gate = AppFillBinding.resolveGate(intent)
        val kind = kindOf(intent)
        if (form == null || gate == null || kind == null || form.appPackage != gate.identity.pkg || form.appPackage in BrowserCertPins.TABLE) {
            finish(); return
        }
        if (!AppFillGate.unchangedSince(gate.identity, AppIdentityLookup.lookup(applicationContext, gate.identity.pkg))) {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CHOOSER_APP_CHANGED_BEFORE).shown(), Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val open = ContentFillSession.access(applicationContext) as? ContentFillSession.Access.Open
        // Offers only: the list reads no value; the picked item's values are asked for at the pick.
        val items = open?.let { ContentFill.offersFor(it.content, form, trusted = false) }.orEmpty()
        val cardLines = open?.let { ContentFill.cardLines(it.content) }.orEmpty()
        val rows = FillPlan.chooserRows(items, form, FillPlan.Asker.App(gate.verdict), kind)
        if (rows.isEmpty()) {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CHOOSER_NOTHING).shown(), Toast.LENGTH_SHORT).show()
            finish(); return
        }
        val byId = items.associateBy { it.itemId }
        setContent {
            AndvariTheme {
                val p = picked.value
                BackHandler(enabled = p != null) { back() }
                when (p) {
                    is FillRow.LoginConfirm -> ConfirmCard(
                        bake = AppFillBinding.bakeFor(gate, p.itemId, p.pageDomain),
                        login = LoginLine(name = byId[p.itemId]?.doc?.name.orEmpty(), username = byId[p.itemId]?.doc?.login?.username),
                        armed = armed.value,
                        onFill = { fillLogin(form, gate, p.itemId, p.pageDomain, confirmed = true) },
                        onCancel = { back() },
                    )
                    is FillRow.CardConfirm -> CardConfirmCard(
                        bake = AppFillBinding.bakeFor(gate, p.itemId, null),
                        card = CardLine(name = byId[p.itemId]?.doc?.name.orEmpty(), masked = cardLines[p.itemId].orEmpty()),
                        armed = armed.value,
                        onFill = { fillCard(form, gate, p.itemId) },
                        onCancel = { back() },
                    )
                    else -> ChooserList(kind, gate, rows, byId, cardLines, onPick = { pick(form, gate, it) }, onCancel = { finish() })
                }
            }
        }
    }

    /** A pick in the list: a vetted app's own login fills now; anything else shows its confirm, armed after a delay. */
    private fun pick(form: ParsedForm, gate: AppFillBinding.AppGate, row: FillRow<AutofillId>) {
        when (row) {
            is FillRow.Login -> fillLogin(form, gate, row.itemId, null, confirmed = false)
            is FillRow.LoginConfirm, is FillRow.CardConfirm -> {
                picked.value = row
                rearm()
            }
            else -> Unit
        }
    }

    private fun back() {
        picked.value = null
        rearm()
    }

    /** The confirm's button arms [AppFillConfirmActivity.ARM_DELAY_MS] after it is shown in a focused window. */
    private fun rearm() {
        handler.removeCallbacks(arm)
        armed.value = false
        if (focused) handler.postDelayed(arm, AppFillConfirmActivity.ARM_DELAY_MS)
    }

    private fun identityHolds(gate: AppFillBinding.AppGate): Boolean {
        if (AppFillGate.unchangedSince(gate.identity, AppIdentityLookup.lookup(applicationContext, gate.identity.pkg))) return true
        Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CHOOSER_APP_CHANGED).shown(), Toast.LENGTH_SHORT).show()
        finish()
        return false
    }

    private fun content() = (ContentFillSession.access(applicationContext) as? ContentFillSession.Access.Open)?.content

    /**
     * One login, released now: [confirmed] after the app-fill confirm's armed tap, or without it for a row the gate
     * lets fill silently (a vetted app's own login). Remembered as the app-fill confirm remembers it, only for a
     * confirmed fill into the app itself (never a page inside it).
     */
    private fun fillLogin(form: ParsedForm, gate: AppFillBinding.AppGate, itemId: String, pageDomain: String?, confirmed: Boolean) {
        if (confirmed && !armed.value) return // the state layer refuses an unarmed tap, not only the disabled button
        if (!identityHolds(gate)) return
        val item = content()?.let { ContentFill.loginById(it, itemId) }
        val dataset = item?.let { runCatching { DatasetBuilder.appLoginResultDataset(it, form, pageDomain) }.getOrNull() }
        if (dataset != null && confirmed && pageDomain == null) {
            gate.identity.signerDigest?.let { digest -> AppSignerBindings.remember(applicationContext, gate.identity.pkg, digest) }
        }
        deliver(dataset)
    }

    /** One card, released after the card confirm's armed tap. An app is never remembered for cards. */
    private fun fillCard(form: ParsedForm, gate: AppFillBinding.AppGate, itemId: String) {
        if (!armed.value) return
        if (!identityHolds(gate)) return
        val item: VaultItem? = content()?.let { ContentFill.cardById(it, itemId) }
        deliver(item?.let { runCatching { DatasetBuilder.cardResultDataset(it, form) }.getOrNull() })
    }

    private fun deliver(dataset: Dataset?) {
        if (dataset != null) {
            ContentFillSession.HardLock.arm(applicationContext)
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
        } else {
            Toast.makeText(applicationContext, UiText.ph(Placeholder.FILL_CHOOSER_NOT_FILLED).shown(), Toast.LENGTH_SHORT).show()
        }
        finish()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        focused = hasFocus
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

    companion object {
        private const val EXTRA_KIND = "io.silencelen.andvari.autofill.CHOOSER_KIND"

        /** The kind rides the BASE intent, which a fill-in cannot override (root cause G). */
        fun bake(intent: Intent, kind: ChooserKind): Intent = intent.putExtra(EXTRA_KIND, kind.name)

        internal fun kindOf(intent: Intent): ChooserKind? =
            intent.getStringExtra(EXTRA_KIND)?.let { n -> ChooserKind.entries.firstOrNull { it.name == n } }
    }
}

/** The list in andvari's own window: which app asks, then one line per item the app may be offered. */
@Composable
internal fun ChooserList(
    kind: ChooserKind,
    gate: AppFillBinding.AppGate,
    rows: List<FillRow<AutofillId>>,
    byId: Map<String, VaultItem>,
    cardLines: Map<String, String>,
    onPick: (FillRow<AutofillId>) -> Unit,
    onCancel: () -> Unit,
) {
    val view = LocalView.current
    SideEffect { view.filterTouchesWhenObscured = true }
    val id = gate.identity
    Column(
        Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).verticalScroll(rememberScrollState()).padding(24.dp),
    ) {
        val title = if (kind == ChooserKind.LOGINS) Placeholder.FILL_CHOOSER_LOGINS else Placeholder.FILL_CHOOSER_CARDS
        Text(UiText.ph(title).shown(), style = MaterialTheme.typography.titleLarge)
        Spacer(Modifier.height(8.dp))
        Text(AppFillGate.oneLine(id.label) ?: id.pkg, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Text(id.pkg, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
        Spacer(Modifier.height(16.dp))
        for (row in rows) {
            val item = byId[row.itemId]
            val name = AppFillGate.oneLine(item?.doc?.name) ?: AppFillGate.oneLine(row.title) ?: "(no name)"
            val second = when (row) {
                is FillRow.CardConfirm -> cardLines[row.itemId]
                is FillRow.LoginConfirm -> listOfNotNull(AppFillGate.oneLine(item?.doc?.login?.username), row.pageDomain?.let { FillPlan.pageSubtitle(it) }).joinToString(" · ")
                else -> AppFillGate.oneLine(item?.doc?.login?.username)
            }
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable { onPick(row) }) {
                Column(Modifier.padding(16.dp)) {
                    Text(name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (!second.isNullOrEmpty()) Text(second, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        // The design's own word for it (CopyKey.CANCEL), as every other Cancel of the new path.
        TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text(UiText.of(io.silencelen.andvari.core.app.CopyKey.CANCEL).shown()) }
    }
}
