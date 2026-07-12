package io.silencelen.andvari.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.TextButton
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.autofill.ApprovedBrowsers
import io.silencelen.andvari.app.autofill.AutofillDebugLog
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * "Autofill status" — the screenshot-me diagnostic surface (recon F08). Three sections:
 * platform/service state (with a "Set as autofill service" shortcut), the LAST fill
 * request as recorded by AutofillDebugLog (trust verdict, parsed fields, terminal
 * reason), and the debug ring buffer (24h toggle + copy-to-clipboard). Read-only over
 * the vault: shows only counts/enums/hosts — never item names or values.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AutofillStatusScreen(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContext.current
    BackHandler(onBack = vm::closeAutofillStatus) // back = return to Settings, not background the app
    var tick by remember { mutableIntStateOf(0) } // bump to re-read everything below

    val afm = remember { runCatching { ctx.getSystemService(AutofillManager::class.java) }.getOrNull() }
    val supported = remember(tick) { runCatching { afm?.isAutofillSupported == true }.getOrDefault(false) }
    val enabled = remember(tick) { runCatching { afm?.hasEnabledAutofillServices() == true }.getOrDefault(false) }

    val store = remember { SessionStore(ctx.applicationContext) }
    val signedIn = remember(tick) { store.load()?.accessToken?.isNotEmpty() == true }
    val unlocked = remember(tick) { VaultSession.get() != null }
    val idleSeconds = remember(tick) { VaultSession.idleSeconds() }
    val autoLock = remember(tick) { store.autoLockSeconds }
    val last = remember(tick) { AutofillDebugLog.lastEvent(ctx) }
    var debugUntil by remember { mutableStateOf(store.autofillDebugUntil) }

    // Item URI census (counts only). ui.items is the unlocked working set (empty when locked).
    val census = remember(tick, ui.items) { uriCensus(ui.items.map { it.doc }) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Autofill status", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeAutofillStatus) { Icon(Icons.Default.ArrowBack, "back") } },
                actions = { IconButton(onClick = { tick++ }) { Icon(Icons.Default.Refresh, "refresh") } },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
            // ---- section 1: service + vault state ----
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Service", style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(8.dp))
                    StatusRow("Autofill supported on this device", supported)
                    StatusRow("andvari is the selected autofill service", enabled)
                    if (!enabled) {
                        Spacer(Modifier.height(8.dp))
                        var noPicker by remember { mutableStateOf(false) }
                        Button(
                            onClick = {
                                // Deliberately NOT gated on resolveActivity(): package
                                // visibility (API 30+) filters it and the manifest
                                // <queries> lists only browser <package> entries, so it
                                // can return null even though the Settings picker exists.
                                // Just fire it; if the device truly has no handler the
                                // ActivityNotFoundException lands in runCatching and the
                                // manual-path hint below is shown.
                                val ok = runCatching {
                                    ctx.startActivity(
                                        Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                                            .setData(Uri.parse("package:${ctx.packageName}")),
                                    )
                                }.isSuccess
                                noPicker = !ok
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text("Set as autofill service") }
                        if (noPicker) {
                            Text(
                                "This device offers no picker — enable it under System settings → Passwords & accounts → Autofill service.",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                            )
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    StatusRow("Signed in", signedIn)
                    StatusRow("Vault unlocked", unlocked)
                    Spacer(Modifier.height(8.dp))
                    if (unlocked) {
                        KeyValue("Items", "${census.total} (${census.logins} logins)")
                        KeyValue("Logins with a web address", "${census.web}")
                        KeyValue("Logins with an androidapp:// link", "${census.androidApp}")
                        KeyValue("Logins with NO address (can never match)", "${census.noUri}")
                    } else {
                        Text("Unlock the vault to see item counts.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    KeyValue("Auto-lock window", if (autoLock > 0) "${autoLock}s" else "disabled")
                    if (unlocked) KeyValue("Idle for", "${idleSeconds}s")
                }
            }
            Spacer(Modifier.height(16.dp))

            // ---- section 2: last fill request ----
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Last fill request", style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(8.dp))
                    if (last == null) {
                        Text(
                            "No autofill request seen yet — open a login form in your browser (or an app's sign-in screen) and come back.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        KeyValue("When", formatTs(last.ts))
                        KeyValue("From", "${last.pkg ?: "(unknown)"} · via ${last.origin}")
                        last.trust?.let { KeyValue("Browser trust", it) }
                        KeyValue("Keyboard inline UI requested", if (last.inline) "yes" else "no")
                        KeyValue("Outcome", last.reason + (last.detail?.let { " ($it)" } ?: ""))
                        outcomeHint(last)?.let {
                            Spacer(Modifier.height(4.dp))
                            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        val obsPkg = last.pkg
                        val obsDigest = last.observedDigest
                        if (obsDigest != null && obsPkg != null) {
                            Spacer(Modifier.height(8.dp))
                            val alreadyTrusted = remember(tick) { ApprovedBrowsers.approvedDigest(ctx, obsPkg) == obsDigest }
                            if (alreadyTrusted) {
                                Text(
                                    "✓ You've trusted ${browserLabel(obsPkg)} on this device. Reopen your login form and try autofill again.",
                                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                                )
                            } else {
                                Text(
                                    "andvari doesn't recognize ${browserLabel(obsPkg)}'s app signature yet, so it won't fill web logins there. If this is your real browser, trust it on this device:",
                                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Spacer(Modifier.height(6.dp))
                                Button(onClick = { ApprovedBrowsers.approve(ctx, obsPkg, obsDigest); tick++ }) {
                                    Text("Trust ${browserLabel(obsPkg)} on this device")
                                }
                            }
                            Spacer(Modifier.height(6.dp))
                            Text("Observed signing-cert digest (safe to share):", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            SelectionContainer {
                                Text(obsDigest, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                        if (last.fields.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text("Fields seen (${last.fields.size})", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            last.fields.forEach { f ->
                                Text(
                                    buildString {
                                        append("• ").append(f.kind)
                                        f.host?.let { append(" · ").append(it) }
                                        if (f.signal.isNotEmpty()) append(" · ").append(f.signal)
                                        if (f.matches >= 0) append(" · ").append(f.matches).append(" match(es)")
                                    },
                                    style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace,
                                )
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))

            // ---- section 2b: browsers trusted on this device (self-service pins) ----
            val trusted = remember(tick) { ApprovedBrowsers.all(ctx) }
            if (trusted.isNotEmpty()) {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("Trusted browsers", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Browsers you've trusted for autofill on this device. Revoking one stops andvari filling web logins there until you trust it again.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(8.dp))
                        trusted.keys.sorted().forEach { pkg ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(browserLabel(pkg), Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                                TextButton(onClick = { ApprovedBrowsers.revoke(ctx, pkg); tick++ }) { Text("Revoke") }
                            }
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }

            // ---- section 2c: per-browser reach (2026-07-11 Fold triage: only Brave dispatched natively) ----
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Browser support", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "How login forms in each browser reach andvari. Every browser andvari recognizes is listed, installed or not — if “Last fill request” stays empty after a fill attempt, the fix for that browser is here.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    browserSupportRows().forEach { (name, how) ->
                        Column(Modifier.padding(vertical = 4.dp)) {
                            Text(name, style = MaterialTheme.typography.bodyMedium)
                            Text(how, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            Spacer(Modifier.height(16.dp))

            // ---- section 3: debug ring buffer ----
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Debug log", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Keeps the last ${AutofillDebugLog.RING_MAX} fill events on this device (reasons, counts and hosts only — never passwords or item names). Turns itself off after 24 hours.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    val now = System.currentTimeMillis()
                    val armed = debugUntil > now
                    // AM-4: the whole side-effecting onCheckedChange lambda moves onto the
                    // toggleable row (no enabled guard exists to move); the Switch is inert.
                    Row(
                        Modifier.toggleable(value = armed, role = Role.Switch, onValueChange = { on ->
                            val v = if (on) System.currentTimeMillis() + AutofillDebugLog.DEBUG_WINDOW_MS else 0L
                            // Through the log module, not raw prefs: it refreshes the
                            // fill path's cached armed-check AND purges the ring file
                            // the moment the toggle is disarmed (off = deleted, not kept).
                            AutofillDebugLog.setDebugUntil(ctx, v)
                            debugUntil = v
                        }),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Debug autofill (24h)", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Switch(checked = armed, onCheckedChange = null)
                    }
                    if (armed) {
                        Text(
                            "Recording — expires in ${remainingLabel(debugUntil - now)}.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    Spacer(Modifier.height(8.dp))
                    var copied by remember { mutableStateOf<String?>(null) }
                    OutlinedButton(
                        onClick = {
                            copied = runCatching {
                                val text = AutofillDebugLog.ringText(ctx)
                                if (text.isBlank()) {
                                    "Log is empty — turn the toggle on, reproduce the fill, then copy."
                                } else {
                                    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    cm.setPrimaryClip(ClipData.newPlainText("andvari autofill log", text))
                                    "Copied ${text.lineSequence().count { it.isNotBlank() }} event(s) to the clipboard."
                                }
                            }.getOrElse { "Couldn't read the log." }
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Copy log") }
                    copied?.let {
                        Spacer(Modifier.height(4.dp))
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

// ---- helpers ----

private data class UriCensus(val total: Int, val logins: Int, val web: Int, val androidApp: Int, val noUri: Int)

private fun uriCensus(docs: List<io.silencelen.andvari.core.client.ItemDoc>): UriCensus {
    var logins = 0; var web = 0; var androidApp = 0; var noUri = 0
    for (doc in docs) {
        if (doc.type != "login") continue
        val login = doc.login ?: continue
        logins++
        val parsed = login.uris.mapNotNull { UriMatch.parseSavedUri(it) }
        if (parsed.any { it is SavedUri.Web }) web++
        if (parsed.any { it is SavedUri.AndroidApp }) androidApp++
        if (parsed.isEmpty()) noUri++
    }
    return UriCensus(docs.size, logins, web, androidApp, noUri)
}

/**
 * "Browser support" card rows: display-name → how a fill request reaches andvari there
 * (2026-07-11 Fold triage: of the installed browsers only Brave dispatched to us natively).
 * Derived from [BrowserCertPins.TABLE] so this card can never drift from the trust table;
 * channel packages (Chrome beta/dev/canary, Firefox flavors, Samsung beta) collapse into one
 * row via [browserLabel]. Samsung Internet + Edge must stay in lockstep with the
 * `<compatibility-package>` entries in res/xml/autofill_service.xml.
 */
private fun browserSupportRows(): List<Pair<String, String>> {
    val rows = LinkedHashMap<String, String>()
    for (pkg in BrowserCertPins.TABLE.keys) {
        val name = browserLabel(pkg)
        if (name in rows) continue
        rows[name] = when (name) {
            "Brave" -> "Works out of the box — tap “Trust” the first time you fill there."
            "Chrome" -> "Needs a one-time Chrome setting: Chrome → Settings → Autofill services → “Autofill using another service”, then restart Chrome."
            "Samsung Internet", "Edge" -> "Supported via compatibility mode: suggestions appear as a dropdown under the field, not above the keyboard. Tap “Trust” the first time you fill there."
            else -> "Delegates to Android autofill; tap “Trust” on first use."
        }
    }
    // Lead with the browsers that have a specific state/instruction; the sort is stable, so
    // the generic rows keep their trust-table order.
    val rank = mapOf("Brave" to 0, "Chrome" to 1, "Samsung Internet" to 2, "Edge" to 3)
    return rows.entries.sortedBy { rank[it.key] ?: 4 }.map { it.key to it.value }
}

/** One-line plain-English translation of the terminal reason, for the screenshot. */
/** Friendly name for a browser package id (the raw id is the fallback). `internal` so the autofill
 *  dropdown's "Trust this browser" row + activity show the same label. */
internal fun browserLabel(pkg: String): String = when {
    pkg.startsWith("com.sec.android.app.sbrowser") -> "Samsung Internet"
    pkg == "com.brave.browser" -> "Brave"
    pkg == "com.microsoft.emmx" -> "Edge"
    pkg == "com.opera.browser" || pkg == "com.opera.gx" -> "Opera"
    pkg == "com.vivaldi.browser" -> "Vivaldi"
    pkg == "com.duckduckgo.mobile.android" -> "DuckDuckGo"
    pkg == "com.kiwibrowser.browser" -> "Kiwi"
    pkg == "org.torproject.torbrowser" -> "Tor Browser"
    pkg.startsWith("com.android.chrome") || pkg == "com.google.android.apps.chrome" || pkg.startsWith("com.chrome") -> "Chrome"
    pkg.startsWith("org.mozilla") -> "Firefox"
    else -> pkg
}

private fun outcomeHint(e: AutofillDebugLog.FillEvent): String? = when (e.reason) {
    "NO_STRUCTURE" -> "The system sent no form data — usually a transient platform issue."
    "SELF_FILL" -> "andvari never fills its own screens."
    "SIGNED_OUT" -> "Not signed in on this device, so no suggestions are possible."
    "NO_FIELDS" -> "The screen had no field andvari recognizes as a username or password."
    "LOCKED_ROW_SHOWN" -> "Vault was locked — an “Unlock andvari” row was offered."
    "NO_ITEMS" -> "The vault has no usable logins (username or password required)."
    "NO_URI_MATCH" -> "Logins exist, but none list this site/app — an “Open andvari” row was offered. Add the site's address (or androidapp://package) to the login."
    "DATASETS" -> "Suggestions were offered (${e.detail ?: "?"} match(es))."
    "EXCEPTION" -> "The fill failed with an internal error (class above); enable the debug log and reproduce."
    "UNKNOWN" -> "The fill ended before andvari could tell why — enable the debug log and reproduce."
    else -> null
}

private fun formatTs(ts: Long): String =
    java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.ROOT).format(java.util.Date(ts))

private fun remainingLabel(ms: Long): String {
    val totalMin = ms / 60_000
    return if (totalMin >= 60) "${totalMin / 60}h ${totalMin % 60}m" else "${totalMin}m"
}

@Composable
private fun StatusRow(label: String, ok: Boolean) {
    // a11yand-06: merge the row into one TalkBack stop ("label: yes/no") and drop the
    // decorative colored bullet from the a11y tree (yes/no text keeps it non-color-only).
    Row(Modifier.padding(vertical = 2.dp).semantics(mergeDescendants = true) {}, verticalAlignment = Alignment.CenterVertically) {
        Text(
            "●",
            color = if (ok) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.clearAndSetSemantics {},
        )
        Spacer(Modifier.width(8.dp))
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Text(if (ok) "yes" else "no", style = MaterialTheme.typography.bodyMedium, color = if (ok) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error)
    }
}

@Composable
private fun KeyValue(label: String, value: String) {
    // a11yand-06: one merged TalkBack stop per "label: value" line.
    Row(Modifier.padding(vertical = 2.dp).semantics(mergeDescendants = true) {}) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
    }
}
