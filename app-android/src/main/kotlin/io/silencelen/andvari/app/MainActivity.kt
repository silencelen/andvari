package io.silencelen.andvari.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.BackupPreflight
import io.silencelen.andvari.core.client.DecryptedItemVersion
import io.silencelen.andvari.core.client.BackupRequest
import io.silencelen.andvari.core.client.BackupResult
import io.silencelen.andvari.core.client.CsvPreflight
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.CardDisplay
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.EnrollCeremony
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.ImportHelp
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PendingUpload
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.VaultInfo
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.autofill.CardNormalize
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json

class MainActivity : FragmentActivity() {
    private val vm: AndvariViewModel by viewModels {
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T =
                // Cache DBs live in no_backup/ — the platform keeps that dir out of Auto
                // Backup AND device-to-device transfer on every API level (backup rules
                // can't glob the per-user vault-<userId>.db names, so location does the job).
                AndvariViewModel(SessionStore(applicationContext), applicationContext.noBackupFilesDir, applicationContext) as T
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // If the previous run crashed, show the captured trace using a PLAIN Android view
        // (no Compose/theme), so even a crash in the Compose layer itself is still visible
        // to screenshot. Skips the (possibly still-crashing) normal startup path.
        val crashFile = java.io.File(filesDir, AndvariApplication.CRASH_FILE)
        if (crashFile.exists()) {
            val trace = runCatching { crashFile.readText() }.getOrDefault("(crash file unreadable)")
            showCrash(trace) { crashFile.delete(); recreate() }
            return
        }
        // Block Recents thumbnails / screen recording / casting from capturing revealed
        // secrets (set AFTER the crash-screen early-return above — crash traces must stay
        // screenshot-able). The Autofill Status screen is exempted below: the owner's Fold
        // debugging protocol depends on screenshotting it, and it renders no vault values.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        lifecycleScope.launch {
            vm.ui.map { it.screen is Screen.AutofillStatus }.distinctUntilChanged().collect { exempt ->
                if (exempt) window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                else window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
            }
        }
        // The one-time default-URL migration + §4.2 namespace adoption now run in
        // SessionStore's init (ordering is load-bearing and the autofill entry points build
        // their own stores) — the vm factory's SessionStore construction below triggers them.
        vm.start()
        // Foreground sync cadence (spec 03 §6): sync immediately on EVERY ON_RESUME
        // (onForeground also enforces the idle auto-lock first — a backgrounded app must
        // lock on return if the window passed while it slept), then every 5 min while
        // resumed and unlocked. repeatOnLifecycle cancels the loop off-RESUMED; no
        // WorkManager, no schedule outlives the foreground.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                while (true) {
                    vm.onForeground()
                    delay(FOREGROUND_SYNC_MS)
                }
            }
        }
        setContent { AndvariTheme { AndvariApp(vm) } }
    }

    // Any user interaction resets the inactivity auto-lock window (spec 01 §8: activity =
    // pointer/key/touch, nothing else). Dispatch overrides see every event before Compose.
    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        VaultSession.touch()
        return super.dispatchTouchEvent(ev)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        VaultSession.touch()
        return super.dispatchKeyEvent(event)
    }

    override fun dispatchGenericMotionEvent(ev: MotionEvent?): Boolean {
        VaultSession.touch() // mouse wheel / rotary / hover-scroll on tablets & ChromeOS
        return super.dispatchGenericMotionEvent(ev)
    }

    private companion object {
        const val FOREGROUND_SYNC_MS = 5L * 60 * 1000 // spec 03 §6 poll interval
    }

    /** Deliberately uses only android.widget — no Compose — so a Compose crash still renders. */
    private fun showCrash(trace: String, onClear: () -> Unit) {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setBackgroundColor(0xFF14120E.toInt())
            setPadding(pad, pad, pad, pad)
            // Cut F review: this plain-View fallback bypasses AndvariApp's safeDrawing Column —
            // view-level fitting keeps the header out of the status bar on Android 15+.
            fitsSystemWindows = true
        }
        root.addView(android.widget.TextView(this).apply {
            text = "andvari hit an error — screenshot this and send it"
            setTextColor(0xFFCF6B5A.toInt())
            textSize = 15f
        })
        val scroll = android.widget.ScrollView(this).apply {
            layoutParams = android.widget.LinearLayout.LayoutParams(-1, 0, 1f)
        }
        scroll.addView(android.widget.TextView(this).apply {
            text = trace
            setTextColor(0xFFEDE4D0.toInt())
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
            setPadding(0, pad, 0, pad)
        })
        root.addView(scroll)
        root.addView(android.widget.Button(this).apply {
            text = "Clear & retry"
            setOnClickListener { onClear() }
        })
        setContentView(root)
    }
}

@Composable
fun AndvariApp(vm: AndvariViewModel) {
    val ui by vm.ui.collectAsStateWithLifecycle()
    // P5/A9 (design 2026-07-10): a 426 (server minVersion pin) blocks EVERYTHING — this build is
    // too old, so every server contact throws. Mirror desktop's blocking screen (Ui.kt:57-66),
    // but WITH an escape (A9): unlike desktop's dead-end, the user can sign out and re-point at a
    // different server (signOut does NOT depend on being past the block). No in-app clear — the
    // exit is updating from the devstore + relaunch, or this sign-out escape.
    ui.upgradeRequired?.let { msg ->
        UpgradeRequiredScreen(msg, onSignOut = vm::signOut)
        return
    }
    Surface(Modifier.fillMaxSize()) {
        // UI-audit Cut F (v2 #5): targetSdk 35 forces edge-to-edge — without insets handling the
        // banner stack + non-Scaffold screens (Welcome/Unlock/RecoverySetup) draw under the system
        // bars on Android 15+. safeDrawing (system bars + cutout + IME) is padded ONCE here;
        // windowInsetsPadding consumes what it pads, so the Scaffold screens inside don't double-pad.
        Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
            // F58: sits ABOVE the screen switch so it survives every in-app navigation —
            // no screen can compose it away while the flag is true.
            MustChangePasswordBanner(ui)
            // P4/A7 (design 2026-07-10): break-glass notices live HERE, above the screen switch,
            // so they render ONCE on every screen — no longer duplicated on both the Vault list
            // AND Sharing. Critical items stay direct; only two genuinely-FYI items collapse.
            // §F.9 (desktop Ui parity): the two recovery gate screens get NO attention area — the
            // shown-once reveal must not compete with re-seal/transfer cards (a migration account
            // entering the capture gate can carry several), and every card keeps working after
            // the gate lands the vault.
            if (ui.screen !is Screen.RecoverySetup && ui.screen !is Screen.RecoveryCapture) AttentionArea(vm, ui)
            // One-time quick-unlock enrollment offer, only over the vault list (design §3/§8).
            if (ui.quickUnlockOffer && ui.screen is Screen.Vault) QuickUnlockOfferCard(vm)
            // Cut L (v2 #20): autofill — the product's core daily value — was never offered;
            // it hid behind a diagnostics-framed Settings card. One-time offer over the vault.
            if (ui.screen is Screen.Vault) AutofillOfferCard(vm)
            Box(Modifier.weight(1f)) {
                when (val screen = ui.screen) {
                    // #24/#25: the start-up screen was a lone raw rune — geometry now (tofu-proof),
                    // plus one quiet line in the household voice so the wait reads as alive.
                    is Screen.Loading -> Centered {
                        SigilMark(BrandSigil, 46.dp)
                        Spacer(Modifier.height(12.dp))
                        Text("Waking the keeper…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    is Screen.Welcome -> WelcomeScreen(vm, ui)
                    is Screen.Unlock -> UnlockScreen(vm, ui, screen.email)
                    is Screen.Vault -> VaultScreen(vm, ui)
                    is Screen.Sharing -> SharingScreen(vm, ui)
                    is Screen.Settings -> SettingsScreen(vm, ui)
                    is Screen.Trash -> TrashScreen(vm, ui)
                    is Screen.AutofillStatus -> AutofillStatusScreen(vm, ui)
                    is Screen.RecoverySetup -> RecoverySetupScreen(vm, ui)
                    is Screen.RecoveryCapture -> RecoveryCaptureScreen(vm, ui)
                    is Screen.Recover -> RecoverScreen(vm, ui, screen.email)
                }
            }
        }
    }
}

/**
 * F58: a recovery TEMP password is the live credential (the login response said
 * mustChangePassword=true). Prominent and NON-dismissable — no close affordance, shown on
 * every screen (including Unlock: the user should know BEFORE typing the temp password) —
 * until a fresh login returns false. Full native change-password screens are deliberately
 * deferred; the fix happens in the WEB app (spec 03 §3 then revokes this device's session,
 * forcing the fresh login that clears the flag).
 */
@Composable
private fun MustChangePasswordBanner(ui: UiState) {
    if (!ui.mustChangePassword) return
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error)
            Spacer(Modifier.width(10.dp))
            Column {
                // a11y (Cut B, desktop a11ydesk-01 parity): on errorContainer, TEXT is onErrorContainer
                // (error-on-errorContainer is 4.66:1 dark / 4.43:1 light — the light pair fails AA).
                Text("Temporary password in use", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onErrorContainer)
                Text(
                    "Your password was reset by recovery and the temporary one is still active. Open andvari in your web browser and set a new master password now.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }
    }
}

/**
 * P4 (design 2026-07-10 §P4): the ONE home for break-glass notices, rendered above the screen
 * switch so each shows once on every screen — the Vault-list and Sharing copies were removed
 * (they duplicated, A7). Critical items render directly, always visible: escrow re-seal
 * (recovery is broken until re-sealed, A1), an incoming ownership transfer (a decision only the
 * user can make), lifecycle notices (anomaly kinds render in the danger tone; benign are
 * dismissable), and needsUpdate WHEN it empties the vault (A2 — then it's the only explanation
 * for an apparently-empty list). Only the two genuinely-FYI items — needsUpdate as a minority,
 * and unopenable-vault — collapse, and only when BOTH are present (a 1-item collapse is
 * pointless). Locked/signed-out: every source is cleared by lock(), so this renders nothing.
 */
@Composable
private fun AttentionArea(vm: AndvariViewModel, ui: UiState) {
    val fyiNeedsUpdate = ui.needsUpdateCount > 0 && ui.items.isNotEmpty()
    val fyiUnopenable = ui.undecryptableSharedVaultCount > 0
    val hasAnything = (ui.escrowStale && ui.escrowFingerprint.isNotEmpty()) ||
        ui.incomingTransfers.isNotEmpty() || ui.lifecycleNotices.isNotEmpty() ||
        ui.needsUpdateCount > 0 || fyiUnopenable
    if (!hasAnything) return
    // Capped + scrollable so a pile-up (many lifecycle rows + several simultaneous incoming
    // transfers) can't clip its own lower items or squeeze the vault list below to ~0 — it's a
    // fixed Column above the weight(1f) screen area. Priority order keeps the top-severity items
    // (re-seal, transfers) visible; overflow scrolls instead of clipping.
    Column(Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState()).padding(horizontal = 12.dp)) {
        // Critical-direct — never collapsed.
        if (ui.escrowStale && ui.escrowFingerprint.isNotEmpty()) ReSealCard(vm, ui)
        IncomingTransferCards(vm, ui)
        LifecycleNoticesBanner(ui.lifecycleNotices, vm::dismissNotice)
        if (ui.needsUpdateCount > 0 && ui.items.isEmpty()) { // A2: the "vault looks empty" explanation
            Text(needsUpdateLine(ui.needsUpdateCount), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 6.dp))
        }
        // FYI — collapse the two optional items behind one toggle, only when BOTH are present.
        val fyiCount = (if (fyiNeedsUpdate) 1 else 0) + (if (fyiUnopenable) 1 else 0)
        if (fyiCount >= 2) {
            var open by rememberSaveable { mutableStateOf(false) }
            TextButton(onClick = { open = !open }) {
                Text(if (open) "Hide $fyiCount notices" else "$fyiCount notices — tap to review")
            }
            if (open) {
                if (fyiNeedsUpdate) Text(needsUpdateLine(ui.needsUpdateCount), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 6.dp))
                if (fyiUnopenable) UnopenableVaultWarning(ui.undecryptableSharedVaultCount)
            }
        } else {
            if (fyiNeedsUpdate) Text(needsUpdateLine(ui.needsUpdateCount), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 6.dp))
            if (fyiUnopenable) UnopenableVaultWarning(ui.undecryptableSharedVaultCount)
        }
    }
}

/**
 * F20: a persistent, NON-dismissable warning that a shared vault granted to this account can't be
 * opened on THIS device — its grant was sealed to a device key we don't hold, or it needs a newer
 * app (a newer grant format). Such a grant is silently swallowed on hydrate/pull (runCatching over
 * addGrant), so the vault vanishes from the list; this row makes the absence legible. Sibling of the
 * needsUpdate banner (both "stored safely, can't show it here"), distinct from the dismissable
 * lifecycle notices, and self-clearing once a later sync opens the grant (or it's revoked). No vault
 * name is shown — with no key, nothing about the vault decrypts. Mirrors web's F20 warning.
 */
@Composable
private fun UnopenableVaultWarning(count: Int) {
    Card(
        Modifier.fillMaxWidth().padding(vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error)
            Spacer(Modifier.width(10.dp))
            Column {
                Text(
                    if (count == 1) "Can't open this shared vault on this device" else "Can't open $count shared vaults on this device",
                    style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onErrorContainer,
                )
                Text(
                    "Someone shared a vault with you, but this device can't unlock it — its key was sealed to a different device, or it needs a newer version of andvari. Open andvari on the device you first set up (or update this app); it'll appear here on its own once it can be opened.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }
    }
}

@Composable
private fun Centered(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally, content = content)
}

@Composable
private fun Sigil() {
    // #25: the wordmark rune as geometry (Theme.kt BrandSigil, the web Sigil.tsx port) — the
    // raw ᛅ codepoint rendered as a tofu box wherever no installed font covers the Runic block.
    SigilMark(BrandSigil, 46.dp)
    Spacer(Modifier.height(4.dp))
    Text("andvari", style = MaterialTheme.typography.titleLarge)
    Text("the keeper of the hoard", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/**
 * P5/A9 (design 2026-07-10): the Android port of desktop's 426 blocking screen (Ui.kt:57-66).
 * A server minVersion pin (426/upgrade_required) makes this build unusable — every server
 * contact throws UpgradeRequiredException — so this replaces the whole app. Unlike desktop's
 * dead-end, it carries a "Sign out / change server" escape (A9): a user pinned out of server A
 * can sign out (which does NOT depend on being past the block) and re-point at another server.
 * Android updates ship via the DEVSTORE, so the copy points there, not /downloads. There is no
 * in-app clear — update + relaunch (or the sign-out escape) is the only exit.
 */
@Composable
private fun UpgradeRequiredScreen(message: String, onSignOut: () -> Unit) {
    Surface(Modifier.fillMaxSize()) {
        Centered {
            Sigil()
            Spacer(Modifier.height(24.dp))
            Text("Update required", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.error)
            Text(
                message,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                modifier = Modifier.widthIn(max = 380.dp).padding(top = 8.dp),
            )
            Spacer(Modifier.height(24.dp))
            // Cut D review: the OTHER live signOut site — same one-tap cache/quick-unlock/unsynced
            // wipe as the Unlock screen's, so it gets the same confirm.
            var confirmSignOut by remember { mutableStateOf(false) }
            OutlinedButton(onClick = { confirmSignOut = true }) { Text("Sign out / change server") }
            if (confirmSignOut) {
                AlertDialog(
                    onDismissRequest = { confirmSignOut = false },
                    title = { Text("Sign out of this device?") },
                    text = { Text("This removes the vault copy, quick unlock, and any unsynced changes from this device. You'll need your master password — and a reachable server — to sign back in.") },
                    confirmButton = { TextButton(onClick = { confirmSignOut = false; onSignOut() }) { Text("Sign out") } },
                    dismissButton = { TextButton(onClick = { confirmSignOut = false }) { Text("Stay") } },
                )
            }
        }
    }
}

@Composable
internal fun ErrorBar(msg: String?, onDismiss: () -> Unit) {
    if (msg != null) {
        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Assertive }, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                // a11y (Cut B): onErrorContainer, mirroring desktop's a11ydesk-01 ErrorBar — `error`
                // text on errorContainer fails AA in light (4.43:1); the dismiss button likewise.
                Text(msg, Modifier.weight(1f), color = MaterialTheme.colorScheme.onErrorContainer, style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = onDismiss, colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onErrorContainer)) { Text("dismiss") }
            }
        }
    }
}

@Composable
internal fun NoticeBar(msg: String?, onDismiss: () -> Unit) {
    if (msg != null) {
        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Polite }) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(msg, Modifier.weight(1f), color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall)
                // a11y (Cut B): primary on the default card tone is ~3.7:1 in light — use onSurfaceVariant.
                TextButton(onClick = onDismiss, colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurfaceVariant)) { Text("dismiss") }
            }
        }
    }
}

// ---- auth ----

@Composable
fun WelcomeScreen(vm: AndvariViewModel, ui: UiState) {
    // design 2026-07-15 §4.3: the anti-phishing Trust Gate overlays everything — BOTH the manual
    // ServerField switch and the invite repoint route through it before any serverUrl change.
    ui.trustGate?.let { TrustGateDialog(it, vm) }
    // §4.3 B2-9: a pending invite switch survived a restart uncommitted — reconcile first (its own
    // full-screen prompt), before offering sign-in on a foreign origin.
    ui.pendingReconcile?.let { PendingReconcileScreen(vm, ui, it); return }
    // §4.3 B2-6: while an invite switch is PENDING, the welcome UI is enroll-only — sign-in and the
    // ServerField are hidden so the "I already have an account" reflex can't hand the pending
    // (possibly hostile) server an offline-crackable digest of the real master password.
    val pending = ui.pendingSwitch
    var tab by rememberSaveable { mutableStateOf(0) }
    // design 2026-07-15 §2.1/§7.1: the server-declared signupMode drives which front-door UI
    // renders (a TRUSTED UI hint, §2.3 — register stays invite-gated server-side regardless):
    //  - "closed"      → sign-in only, no enroll UI at all (break-glass twin / sign-in-only instance);
    //  - "landing"     → invite-only + the stranger nudge over the enroll tab;
    //  - anything else → today's invite-only two-tab welcome (incl. policy==null: §2.3's
    //                    conservative default while the probe is in flight / failed).
    val signupMode = effectiveSignupMode(ui.policy?.signupMode)
    val showEnroll = signupMode != "closed"
    // Pending ⇒ force the enroll surface (sign-in is locked out); a remembered Enroll selection
    // can't outlive a closed flip.
    val effTab = if (pending != null) 1 else if (showEnroll) tab else 0
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(40.dp))
        Sigil()
        Spacer(Modifier.height(24.dp))
        if (pending == null && showEnroll) {
            TabRow(selectedTabIndex = effTab) {
                Tab(effTab == 0, { tab = 0 }, text = { Text("Sign in") })
                Tab(effTab == 1, { tab = 1 }, text = { Text("Enroll") })
            }
            Spacer(Modifier.height(20.dp))
        }
        ErrorBar(ui.error, vm::clearError)
        // Success landings that end HERE need a voice too — chiefly the recover flow's
        // "Master password reset — sign in with your new password." (sessions were revoked).
        NoticeBar(ui.notice, vm::clearNotice)
        // §4.3 B2-6 pending notice sits ABOVE the shared enroll form as a separate sibling — so it
        // can appear without disturbing the form's composition identity.
        if (pending != null) PendingSwitchNotice(vm, pending)
        // §7.1 stranger nudge — only in the non-pending enroll-tab landing case.
        if (pending == null && effTab == 1 && signupMode == "landing") LandingNudge(ui.policy?.selfHostDocsUrl)
        // ONE stable call site per auth form: SignInForm only when signed-in entry is allowed, else
        // EnrollForm. Entering the pending state keeps `pending == null && effTab == 0` false on the
        // enroll path (false→false), so the else branch survives — the pasted invite link + typed
        // password are NOT cleared by the repoint (they'd be, if EnrollForm were called from two
        // different branches). The invite field then re-parses as same-origin and the form completes.
        if (pending == null && effTab == 0) SignInForm(vm, ui) else EnrollForm(vm, ui)
        Spacer(Modifier.height(24.dp))
        // §7.1: natives keep the server field — but NOT while a repoint is pending (§4.3 B2-6:
        // finish or cancel the invite first). "Set" opens the Trust Gate, commit-on-Connect (§4.4).
        if (pending == null) ServerField(ui.baseUrl, vm::requestManualSwitchGate)
    }
}

/**
 * The anti-phishing Trust Gate (design 2026-07-15 §4.3), rendered natively (NOT web, §4.4). Shown
 * before EVERY serverUrl change. It displays the RAW origin the client will connect to — scheme+
 * host+port, monospaced + dominant, NEVER a display name (an attacker's branding is never rendered
 * as verified). A non-ASCII host is shown in punycode with an "international characters" caution
 * (IDN homograph defense); an http:// origin gets a plain-http caution. Cancel is the safe default
 * (the dialog's dismiss); there is no "don't ask again". All render/copy decisions are the pure,
 * test-pinned [trustGateRender] / [trustGateBody].
 */
@Composable
private fun TrustGateDialog(gate: TrustGatePrompt, vm: AndvariViewModel) {
    AlertDialog(
        onDismissRequest = vm::trustGateCancel, // dismiss (scrim / back) = Cancel — the safe default
        title = { Text(TRUST_GATE_TITLE) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                // Raw origin — visually dominant, monospaced (R8: never a display name).
                Text(
                    gate.render.displayOrigin,
                    style = MaterialTheme.typography.titleMedium.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurface,
                )
                if (gate.render.punycodeCaution) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "This address uses international characters, shown above in their punycode (xn--) form. Check it is exactly the server you expect — lookalike letters are a known phishing trick.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                    )
                }
                if (gate.render.httpCaution) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "This is an unencrypted http:// address — anyone on the network can read traffic to it.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                    )
                }
                Spacer(Modifier.height(12.dp))
                trustGateBody(gate.enrollment).forEach {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(bottom = 8.dp))
                }
            }
        },
        // Cancel is listed as the dismiss (left/safe) action and dismiss-on-scrim maps to it; there
        // is deliberately no "don't ask again". Compose has no focus-default primitive, so Connect
        // is never auto-activated — the user must deliberately tap it.
        confirmButton = { TextButton(onClick = vm::trustGateConnect) { Text("Connect") } },
        dismissButton = { TextButton(onClick = vm::trustGateCancel) { Text("Cancel") } },
    )
}

/**
 * §4.3 B2-6 pending-state notice: while an invite switch is uncommitted, sign-in is hidden and the
 * user may only complete enrollment (the form below) or cancel and return to the previous origin.
 */
@Composable
private fun PendingSwitchNotice(vm: AndvariViewModel, pending: PendingSwitchUi) {
    Card(
        Modifier.fillMaxWidth().padding(bottom = 12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text("Enrolling at a new server", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onTertiaryContainer)
            Text(pending.origin, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.onTertiaryContainer)
            Text(
                "Signed-in accounts stay on ${pending.previousOrigin} — finish or cancel this invite first. Sign-in is unavailable here until you do.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onTertiaryContainer,
                modifier = Modifier.padding(top = 4.dp),
            )
            TextButton(
                onClick = vm::cancelPendingSwitch,
                colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onTertiaryContainer),
            ) { Text("Cancel and return to ${pending.previousOrigin}") }
        }
    }
}

/**
 * §4.3 B2-9 launch reconcile: a persisted pendingServer marker survived a restart with no committed
 * enrollment. Offer "Finish setting up at <origin>" (re-shows the raw-origin gate, then repoints —
 * register-already-succeeded users land on Unlock, pre-register crashes re-open the enroll form) or
 * "Discard" (revert to the previous origin + clear the marker). Sign-in is not offered here — the
 * origin is still uncommitted.
 */
@Composable
private fun PendingReconcileScreen(vm: AndvariViewModel, ui: UiState, marker: PendingServer) {
    Column(
        Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(40.dp))
        Sigil()
        Spacer(Modifier.height(24.dp))
        Text("Finish setting up?", style = MaterialTheme.typography.titleMedium)
        Text(
            "You started connecting to a different server but didn't finish enrolling. Finish setting up there, or discard it and stay on your previous server.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center, modifier = Modifier.padding(vertical = 12.dp),
        )
        Text(marker.origin, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
        Spacer(Modifier.height(20.dp))
        PrimaryButton("Finish setting up at this server", enabled = !ui.busy, busy = ui.busy) { vm.finishReconcile() }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(onClick = vm::discardReconcile, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) {
            Text("Discard — return to ${marker.previousOrigin}")
        }
    }
}

/**
 * §7.1 stranger landing — a client RENDERING of declared policy, not a server flow: the server
 * still enforces the invite gate on register, and `POST /auth/prelogin` keeps its fake-salt
 * anti-enumeration, so this adds no account oracle. §2.3: `selfHostDocsUrl` is DECORATIVE —
 * rendered as a raw https URL only (R8 rule: never a display name, never verified identity);
 * anything non-https from a hostile or misconfigured server is simply not rendered.
 */
@Composable
private fun LandingNudge(selfHostDocsUrl: String?) {
    Text(
        "This is a private, invite-only server. Have an invite? Paste it below. " +
            "Want your own? andvari is self-hostable — run your own server.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    val url = selfHostDocsUrl?.trim()?.takeIf { it.startsWith("https://") }
    if (url != null) {
        val uriHandler = LocalUriHandler.current
        TextButton(onClick = { runCatching { uriHandler.openUri(url) } }) {
            Text(url, style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace))
        }
    }
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun SignInForm(vm: AndvariViewModel, ui: UiState) {
    // N2 §4 (design 2026-07-10): the master password must never enter rememberSaveable —
    // savedInstanceState is a system-managed PLAINTEXT Bundle that can be persisted to disk
    // for activity recreation. Email stays saveable (rotation / fold-posture change must not
    // wipe it); re-typing the password after a rare mid-form recreation is the accepted trade.
    var email by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var totp by rememberSaveable { mutableStateOf("") } // deliberately saveable: a 30-second-lived code
    Column(Modifier.fillMaxWidth()) {
        // F26: session-end explanation (set by the 401-driven sign-out paths) — one quiet
        // line, cleared on a successful sign-in.
        ui.lockReason?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
        }
        Field("Email", email, { email = it }, keyboard = KeyboardType.Email)
        SecretField("Master password", password) { password = it }
        // design 2026-07-15 §2.3/§2.6: `policy.totpRequired` is a TRUSTED UI HINT — PRE-SHOW the
        // code field so an enrolled user isn't bounced through a failed submit. It never gates
        // submission: on a totpRequired instance a not-yet-enrolled user signs in password-only
        // (the §2.6 restricted-session matrix), so only the REACTIVE server error
        // (ui.loginTotpRequired) makes the 6-digit code mandatory — the authoritative path.
        val showTotp = ui.loginTotpRequired || ui.policy?.totpRequired == true
        if (showTotp) {
            Field("One-time code", totp, { totp = it.filter { c -> c.isDigit() }.take(6) }, mono = true, keyboard = KeyboardType.Number)
            if (!ui.loginTotpRequired) {
                Text(
                    "If you use an authenticator app with this server, enter its code — otherwise leave blank.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(12.dp))
        val ready = email.isNotBlank() && password.isNotBlank() && (!ui.loginTotpRequired || totp.length == 6)
        PrimaryButton("Sign in", enabled = ready && !ui.busy, busy = ui.busy) { vm.signIn(email.trim(), password, totp.ifBlank { null }) }
    }
}

@Composable
private fun EnrollForm(vm: AndvariViewModel, ui: UiState) {
    // N2 §4 (design 2026-07-10): enrollment is the longest form in the app, so the NON-SECRET
    // fields (invite/email/name/typed-fingerprint) stay rememberSaveable — losing them to a
    // fold unfold (Activity recreation) was silent data loss. The password pair is plain
    // `remember`: savedInstanceState is a system-managed plaintext Bundle that can be
    // persisted to disk, and a master password must never land there — a rare mid-form
    // recreation re-types it, but the rest of the long form survives.
    var invite by rememberSaveable { mutableStateOf("") }
    var email by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    var fpOk by rememberSaveable { mutableStateOf(false) }
    // spec 04 §2(3): the user TYPES the first 16 sheet chars; the short form is public
    // (first 16 of a served fingerprint), so rememberSaveable is fold-safe AND safe.
    var shortFp by rememberSaveable { mutableStateOf("") }
    // §F.1 posture (client-derived, web parity): WAIVED by default (frictionless, no admin
    // backstop), required-typed when the member declares a printed sheet, and — new in Wave-3
    // (design §4.4) — required-affirm when a pasted enroll LINK carries an in-person-QR rfp. All
    // flags are non-secret and fold-safe.
    var hasSheet by rememberSaveable { mutableStateOf(false) }
    var waivedAck by rememberSaveable { mutableStateOf(false) }
    var affirmed by rememberSaveable { mutableStateOf(false) }
    // §4.4 Android: the invite field accepts a raw token OR a full enroll LINK. Derive against the
    // CURRENT origin every recomposition (the reused core [EnrollLink.parse] twin; the field is
    // never mutated, so a foreign→pending flip re-parses the same text as same-origin).
    val parsed = parseInviteField(invite, ui.baseUrl)
    val effToken = parsed.token
    val linkRfp = (parsed as? InviteFieldParse.Link)?.rfp
    val linkEmail = (parsed as? InviteFieldParse.Link)?.email
    // A link whose origin differs from the current server must clear the Trust Gate BEFORE enrolling.
    val foreign = (parsed as? InviteFieldParse.Link)?.takeIf { it.gate }
    // Prefill the invite-bound email when the user hasn't typed one (server binds case-insensitively;
    // still editable).
    LaunchedEffect(linkEmail) { if (linkEmail != null && email.isBlank()) email = linkEmail }
    val posture = enrollPosture(linkRfp = linkRfp, memberHasSheet = hasSheet)
    val fp = ui.policy?.recoveryFingerprint ?: ""
    val shortOk = Escrow.shortFormMatches(shortFp, fp)
    // required-affirm: the scanned rfp must match THIS server's advertised recovery fingerprint —
    // the T10 anchor-redirect defense. enrollOp re-asserts it authoritatively before sealing.
    val affirmMatches = !linkRfp.isNullOrEmpty() && Escrow.shortFormMatches(linkRfp, fp)
    // A foreign-origin link blocks submit until the gate repoints (foreign becomes null once we are
    // on its origin). Otherwise the per-posture ceremony legs decide readiness.
    val ready = foreign == null && enrollReady(posture, effToken, email, password, confirm, shortFp, fpOk, waivedAck, affirmed, linkRfp, fp)
    Column(Modifier.fillMaxWidth()) {
        Field("Invite code or link", invite, { invite = it }, mono = true)
        Text(
            "Paste the link from your invite — or just the invite code.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (foreign != null) {
            // §4.4: a foreign-origin invite link. Do NOT auto-repoint — offer the anti-phishing
            // Trust Gate explicitly; only its Connect enters the pending switch (§4.1 rule 3). The
            // rest of the form appears once the gate has repointed us to this server.
            Spacer(Modifier.height(8.dp))
            Text("This invite is for a different server:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(foreign.origin, style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { vm.requestInviteTrustGate(foreign.origin, foreign.email) }, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) {
                Text("Review server and continue")
            }
        } else {
            Field("Email", email, { email = it }, keyboard = KeyboardType.Email)
            Field("Name (optional)", name, { name = it })
            SecretField("Master password", password) { password = it }
            if (password.isNotEmpty()) {
                val score = Strength.estimateStrength(password)
                if (Strength.meetsMasterPasswordFloor(password)) {
                    Text("strength: ${Strength.label(score)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text("Too weak for a master password (${Strength.label(score)}) — mix length with upper/lower case, digits, or symbols.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                if (Strength.masterPasswordHasNonAscii(password)) {
                    Text("contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
                }
            }
            SecretField("Confirm password", confirm) { confirm = it }
            // Routed through InlineError so its Polite liveRegion announces the mismatch (a11yand-01).
            InlineError(if (confirm.isNotEmpty() && confirm != password) "passwords don't match" else null)
            // §F.1 posture UI (web FingerprintProvenance parity): required-affirm shows the scanned
            // rfp + a one-tap eyeball affirmation; waived renders the stark no-backstop ack;
            // required-typed keeps the N2 §3/B4 four honest states, in web's pinned order.
            when {
                // (−1) required-affirm (§4.4): a pasted link carried an in-person-QR rfp. Display it
                // grouped and take a one-tap affirmation — no typing (the scanned QR is the anchor).
                posture == EnrollPosture.RequiredAffirm -> {
                    Spacer(Modifier.height(8.dp))
                    Text("Recovery check — this code came from the invite you scanned in person. Confirm it matches the fingerprint on your admin's screen.", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(groupHex(linkRfp ?: ""), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace), color = MaterialTheme.colorScheme.secondary)
                    if (fp.isNotEmpty() && !affirmMatches) {
                        Text("doesn't match this server's recovery key — if you scanned it correctly, STOP and contact your admin", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    }
                    Row(
                        Modifier.padding(top = 8.dp)
                            .toggleable(value = affirmed, role = Role.Checkbox, onValueChange = { affirmed = it }),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(affirmed, onCheckedChange = null)
                        Text("I scanned this code in person from my household admin and it matches their screen.", style = MaterialTheme.typography.bodySmall)
                    }
                }
                // (0) WAIVED (§F.4): the posture-specific acknowledgment — visually distinct from the
                // backstop ceremony (error-toned; the one irreversible fact of this posture).
                posture == EnrollPosture.Waived -> {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "There is NO admin backstop. Only your recovery phrase can restore this account. Lose both your master password and this phrase and this account is gone forever.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Row(
                        Modifier.padding(top = 8.dp)
                            .toggleable(value = waivedAck, role = Role.Checkbox, onValueChange = { waivedAck = it }),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(waivedAck, onCheckedChange = null)
                        Text("I understand: without my master password AND my recovery phrase, this account cannot be recovered by anyone.", style = MaterialTheme.typography.bodySmall)
                    }
                }
                // (1) Fingerprint known → the enroll ceremony, exactly as before.
                fp.isNotEmpty() -> {
                    Spacer(Modifier.height(8.dp))
                    // Deliberately NOT displayed until typed — showing it above the input would
                    // reduce the check to transcription (spec 04 §2(3); web Enroll parity; the
                    // F57 re-seal card already works this way).
                    // Cut M (v2 #13): the printed sheet belongs to the ADMIN (required posture,
                    // handed over in person) — "your printed recovery sheet" sent an emailed
                    // enrollee hunting for a sheet that was never theirs.
                    Text("Recovery check — type the FIRST 16 characters of the fingerprint on the printed recovery sheet your admin gave you", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Field("From the sheet, not this screen", shortFp, { shortFp = it }, mono = true)
                    if (shortFp.isNotBlank() && !shortOk) {
                        Text("doesn't match this server's recovery key — if you copied the sheet correctly, STOP and contact your admin", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    }
                    if (shortOk) {
                        Text("matches — full fingerprint: ${groupHex(fp)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                    }
                    Row(
                        Modifier.padding(top = 8.dp)
                            .toggleable(value = fpOk, enabled = shortOk, role = Role.Checkbox, onValueChange = { fpOk = it })
                            .semantics { if (!shortOk) stateDescription = "Type the 16 sheet characters above first" },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(fpOk, onCheckedChange = null, enabled = shortOk)
                        Text("This fingerprint matches the recovery sheet. I understand my master password can only be reset with that offline key.", style = MaterialTheme.typography.bodySmall)
                    }
                }
                // (2) The policy probe FAILED — don't claim the ceremony isn't done (it may well
                // be). Web-parity copy (errors.ts POLICY_UNAVAILABLE) + a Retry that re-probes.
                ui.policyFetchFailed -> {
                    Text("Couldn't load the server's settings — it may be briefly unavailable. Try again in a moment.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 8.dp))
                    OutlinedButton(onClick = vm::retryPolicy, enabled = !ui.busy) {
                        Text(if (ui.busy) "Retrying…" else "Retry")
                    }
                }
                // (3) Probe in flight (setBaseUrl's re-probe is async under this shown form) —
                // a neutral line, never the no-key text.
                ui.policy == null -> {
                    Text("Checking the server…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 8.dp))
                }
                // (4) Policy loaded and the fingerprint is genuinely empty → the recovery key
                // really isn't configured on this server yet (waived enrollment still works — the
                // flip below is the way through).
                else -> {
                    Text("This server has no recovery key configured yet — the admin backstop can't be set up.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 8.dp))
                }
            }
            // §F.1 posture flip (web FingerprintProvenance parity): waived ↔ required-typed. HIDDEN
            // when a link rfp is present — required-affirm's posture is fixed by the scanned code,
            // not a sheet declaration (web hides the toggle the same way). Otherwise OUTSIDE the
            // fp-state `when`, so the flip is never hostage to a policy fetch.
            if (linkRfp.isNullOrEmpty()) {
                TextButton(onClick = { hasSheet = posture == EnrollPosture.Waived }) {
                    Text(
                        if (posture == EnrollPosture.Waived) "My admin gave me a printed recovery sheet (add the admin backstop)"
                        else "I don't have a recovery sheet — set up without an admin backstop",
                    )
                }
            }
            Spacer(Modifier.height(12.dp))
            // The onClick RE-EVALUATES the gate from the same live reads it submits: the
            // button's enabled flag reflects the last composition, so a same-frame edit +
            // tap could otherwise submit values `ready` never approved (S2-review race
            // class; web enforces at submit for the same reason). Busy is re-checked in
            // the ViewModel, where the read is live.
            PrimaryButton("Create vault", enabled = ready && !ui.busy, busy = ui.busy) {
                val postureNow = enrollPosture(linkRfp = linkRfp, memberHasSheet = hasSheet)
                // required-affirm feeds the SCANNED rfp as the "typed" fingerprint into the same
                // sealing path required-typed uses; enrollOp re-asserts it against the server's
                // advertised fingerprint (and Account.enroll refuses a mismatched served key) — the
                // T10 defense — before sealing escrow.
                val typedFp = if (postureNow == EnrollPosture.RequiredAffirm) (linkRfp ?: "") else shortFp
                if (enrollReady(postureNow, effToken, email, password, confirm, shortFp, fpOk, waivedAck, affirmed, linkRfp, fp)) {
                    vm.enroll(effToken.trim(), email.trim(), name.trim(), password, waived = postureNow == EnrollPosture.Waived, typedShortFp = typedFp)
                }
            }
        }
    }
}

/** The enroll submit gate per §F.1 posture (design §4.4): the core ceremony legs (EnrollCeremony,
 *  jvm-tested) for required-typed; the invite/email/password legs + a one-tap affirmation for
 *  required-affirm (the scanned rfp must be present — enrollOp does the authoritative match); or
 *  those legs + the §F.4 no-backstop acknowledgment for waived. */
private fun enrollReady(
    posture: EnrollPosture,
    invite: String,
    email: String,
    password: String,
    confirm: String,
    shortFp: String,
    fpOk: Boolean,
    waivedAck: Boolean,
    affirmed: Boolean,
    linkRfp: String?,
    fp: String,
): Boolean = when (posture) {
    EnrollPosture.Waived ->
        invite.isNotBlank() && email.isNotBlank() && Strength.meetsMasterPasswordFloor(password) && password == confirm && waivedAck
    EnrollPosture.RequiredAffirm ->
        invite.isNotBlank() && email.isNotBlank() && Strength.meetsMasterPasswordFloor(password) && password == confirm && affirmed && !linkRfp.isNullOrEmpty()
    EnrollPosture.RequiredTyped ->
        EnrollCeremony.ready(invite, email, password, confirm, shortFp, fpOk, fp)
}

/**
 * Shown-once self-service recovery phrase (design 2026-07-12 §F.4/§F.7). The per-member recovery
 * piece is MANDATORY and was already committed — in register() (enroll path) or by the §F.9
 * capture gate's self-setup ([RecoveryCaptureScreen] hands off here) — but a member who never
 * SEES it is silently unrecoverable — so this un-skippable gate reveals the base64url phrase ONCE
 * and makes the user TYPE IT BACK (constant-time [MemberRecovery.confirmMatches] in the VM) before
 * the vault opens. Shown-once discipline: the phrase is never persisted (FLAG_SECURE blocks
 * screenshots / Recents / casting app-wide, MainActivity), never logged, and is dropped the
 * instant the confirm resolves. There is NO skip/back affordance — the silent-total-loss guard,
 * mirroring the enroll ceremony's fpConfirmed gate. On the capture-gate path the confirm is BOUND
 * + AWAITED in the VM (piece-binding design 2026-07-13 §3) — the button spins under `busy` and a
 * stale verdict routes back through [RecoveryCaptureScreen] with the replaced-phrase notice.
 *
 * Cut M (v2 #7): the fastest path through this gate used to be Copy → paste → confirm — "saved"
 * while the phrase only ever lived on a clipboard the app itself wipes after the policy window.
 * Compose has no per-field paste hook to refuse (web's onPaste deterrent), so the deterrent here
 * is presentation + guidance: the phrase renders GROUPED for transcription, and the type-back
 * says plainly it's about proving a written copy exists. The constant-time match is unchanged.
 *
 * TODO(recovery-cut-2): the native self-recovery flow (POST /recovery/self/verify + commit) — a member using this
 * phrase to reset a forgotten master password — and the native admin fingerprint-confirm-for-QR
 * are deferred; web covers self-recovery for this cut. This screen only SHOWS a piece (at signup,
 * or a fresh one via the §F.9 capture gate) — it never consumes one.
 */
@Composable
private fun RecoverySetupScreen(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContext.current
    // Defensive: recoveryPhrase is set atomically with this screen (enrollOp / runRecoveryCapture)
    // and cleared with the move away (toVault / the stale re-route), so a null here is only the
    // one-frame transition — render nothing rather than a blank form; the next emission lands.
    val phrase = ui.recoveryPhrase ?: return
    var typedBack by remember { mutableStateOf("") }
    var mismatch by remember { mutableStateOf(false) }
    // A "copy phrase" button is a SECRET clipboard write (EXTRA_IS_SENSITIVE + auto-clear after
    // the policy window), never the non-secret setup-material exemption (§F.7). Clamped into
    // [1, CLIPBOARD_CLEAR_MAX_SECONDS] (design 2026-07-15 §2.3/B1-1): a hostile server's policy
    // must not pin a secret on the clipboard for hours.
    val clipClear = (ui.policy?.clipboardClearSeconds ?: 30).coerceIn(1, ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS)
    // Cut M (v2 #7): 4-char groups for transcription — a 43-char unbroken run defeats
    // write-it-down. Visual only: displayForm's contract says confirmMatches strips
    // whitespace, so a grouped type-back still passes; Copy carries the bare phrase.
    val grouped = remember(phrase) { phrase.chunked(4).joinToString(" ") }
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState())) {
        Text("Save your recovery phrase", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        if (ui.recoveryReplacedNotice) {
            // Piece-binding §3: the STATIC replaced-phrase notice (never interpolated, §F.7) — the
            // previous reveal's confirm came back stale; THIS fresh phrase is the one that counts.
            Text(
                RECOVERY_PHRASE_REPLACED_NOTICE,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }
        // Posture copy (§F.4): waived = NO admin backstop (stark, error-toned); required = the
        // household admin can also help. enrollOp sets the flag from the client-derived §F.1
        // posture; the capture gate always uses the required copy (posture unknowable at unlock).
        Text(
            if (ui.recoverySetupWaived)
                "There is NO admin backstop for this account. Only this recovery phrase can restore it. If you lose BOTH your master password AND this phrase, this account is gone forever — no one can recover it. Write it down and keep it somewhere safe and offline."
            else
                "Write this down and keep it somewhere safe and offline. If you ever forget your master password, this phrase lets you recover your account yourself. (Your household admin can also help you recover.)",
            style = MaterialTheme.typography.bodyMedium,
            color = if (ui.recoverySetupWaived) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(16.dp)) {
                SelectionContainer {
                    Text(grouped, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                }
                Spacer(Modifier.height(8.dp))
                // a11y (Cut B): primary on the surfaceVariant card is 3.77:1 in light — use the pair's own ink.
                TextButton(
                    onClick = { copyToClipboard(ctx, "Recovery phrase", phrase, clipClear) },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurfaceVariant),
                ) { Text("Copy phrase") }
            }
        }
        Spacer(Modifier.height(20.dp))
        Text("Type it back to confirm you saved it", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        // NOT a SecretField (no masking — §F.7: a recovery phrase must never be masked-then-
        // password-managed) but KeyboardType.Password so the IME's suggestion strip and personal
        // dictionary never learn it (Cut E precedent: masking and IME secrecy are independent).
        // `mono` kills autocorrect; the typed value is its OWN state, never bound to the secret.
        // A mistype fails the confirm and is discarded — never a KDF input.
        Field("Type your recovery phrase", typedBack, { typedBack = it; mismatch = false }, mono = true, keyboard = KeyboardType.Password)
        // Cut M (v2 #7): guidance is the paste deterrent (see the header note) — the hint
        // names what the type-back is FOR, so the clipboard shortcut reads as self-defeating.
        Text(
            "Type it from your written note — pasting doesn't prove you saved it.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (mismatch) {
            Text(
                "That doesn't match — check the phrase above and type it exactly.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        Spacer(Modifier.height(16.dp))
        PrimaryButton("I've saved it — open my vault", enabled = typedBack.isNotBlank() && !ui.busy, busy = ui.busy) {
            if (!vm.confirmRecoverySaved(typedBack)) mismatch = true
        }
    }
}

/**
 * §F.9 vault-entry capture gate — the working/error half (desktop RecoveryCaptureScreen / web
 * RecoveryCaptureGate parity). Reached from unlock/sign-in when the server reports
 * recoveryConfirmed=false: the VM is committing a FRESH per-member piece (PUT /recovery/self-setup);
 * on success the flow lands in the same un-skippable [RecoverySetupScreen] reveal, on failure this
 * shows the error + Retry and NEVER proceeds to the vault (no skip affordance — the whole point is
 * that the "un-skippable" gate was skippable via idle lock / process death). Offline unlocks never
 * reach this screen (the VM skips the gate when accountKeys came from the offline cache), so vault
 * access without a network is preserved. Also re-entered by a stale bound confirm (piece-binding
 * design 2026-07-13 §3) — then the static replaced-phrase notice explains the re-run.
 */
@Composable
private fun RecoveryCaptureScreen(vm: AndvariViewModel, ui: UiState) {
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState())) {
        Text("Finish protecting your account", style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(12.dp))
        Text(
            "Your recovery phrase was never confirmed as saved — if you forgot your master password " +
                "today, that phrase couldn't help you. A fresh phrase is being prepared now; you'll " +
                "write it down and type it back before the vault opens.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        if (ui.recoveryReplacedNotice) {
            // Piece-binding §3: the STATIC replaced-phrase notice (never interpolated, §F.7) — the
            // confirm was refused recovery_piece_stale (another device rotated the piece mid-gate).
            Text(
                RECOVERY_PHRASE_REPLACED_NOTICE,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        } else {
            // Honesty over comfort: the self-setup ROTATES the stored piece, so a phrase written
            // down during an interrupted reveal (saved but never typed back) stops working the
            // moment the commit lands. Saying so beats a member trusting a dead phrase.
            Text(
                "If you wrote down a phrase before and never finished confirming it, it's replaced by the new one.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(20.dp))
        val err = ui.recoveryCaptureError
        if (err != null) {
            // Static copy from the VM only — never interpolate near secret material (§F.7).
            Text(err, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
            Spacer(Modifier.height(12.dp))
            PrimaryButton("Try again", enabled = !ui.busy, busy = ui.busy) { vm.retryRecoveryCapture() }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Preparing your recovery phrase…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

/**
 * F57: after a recovery-key re-ceremony this account's escrow is sealed to the DEAD key. Offer to
 * re-seal to the current key — but only after the user TYPES the new recovery fingerprint from
 * their PRINTED sheet (spec 04 §2(3): we deliberately do NOT display it, so a compromised server
 * can't win a lazy eyeball-match). The ViewModel binds the fetched pubkey to that verified
 * fingerprint and refuses on mismatch. Non-blocking: "Later" leaves it for the next unlock.
 */
@Composable
private fun ReSealCard(vm: AndvariViewModel, ui: UiState) {
    var open by rememberSaveable { mutableStateOf(false) }
    var entry by rememberSaveable { mutableStateOf("") }
    val ok = Escrow.shortFormMatches(entry, ui.escrowFingerprint)
    Card(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.tertiaryContainer),
    ) {
        Column(Modifier.padding(12.dp)) {
            if (!open) {
                Text(
                    "Your household's recovery key changed — re-protect this account so it stays recoverable.",
                    style = MaterialTheme.typography.bodySmall,
                )
                // a11y (Cut B): primary on tertiaryContainer is 3.75:1 in light — use the pair's own ink.
                TextButton(
                    onClick = { open = true },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onTertiaryContainer),
                ) { Text("Re-protect →") }
            } else {
                Text("Re-protect account", style = MaterialTheme.typography.titleSmall)
                Text(
                    "Confirm the NEW recovery fingerprint from your printed recovery sheet, then re-protect. " +
                        "Your master key never leaves this device except sealed to the recovery key you verify.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(vertical = 6.dp),
                )
                Field("First 16 characters from your printed recovery sheet", entry, { entry = it }, mono = true)
                Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    // a11yand-04 (AM-5): the ReSealCard has no verdict Text/checkbox — the only
                    // gate is this disabled button, so the "why disabled" hint rides its
                    // stateDescription (keeps the visible "Re-protect account" label intact).
                    PrimaryButton(
                        "Re-protect account", enabled = ok && !ui.busy, busy = ui.busy,
                        modifier = Modifier.semantics { if (!ok) stateDescription = "Enter the 16 characters from your recovery sheet first" },
                    ) { vm.resealEscrow(entry) }
                    TextButton(
                        onClick = { open = false },
                        colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onTertiaryContainer),
                    ) { Text("Later") }
                }
            }
        }
    }
}

@Composable
fun UnlockScreen(vm: AndvariViewModel, ui: UiState, email: String) {
    var password by remember { mutableStateOf("") }
    // BiometricPrompt needs a FragmentActivity host (MainActivity is one).
    val activity = LocalContext.current as? FragmentActivity
    val canBiometric = activity != null && ui.quickUnlockEligible && ui.quickUnlockEnrolled && ui.quickUnlockFresh
    // Auto-show the prompt once on entry (spec 01 §8 / design §3). Guarded so a cancel does NOT
    // re-fire it in a loop (each prompt is one explicit gesture); the button below re-offers it.
    var autoShown by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(canBiometric) {
        if (canBiometric && !autoShown && !ui.busy) { autoShown = true; vm.unlockWithBiometric(activity!!) }
    }
    // Cut F (v2 #5): scrollable — a centered fixed column left the Unlock button unreachable
    // with the IME open in landscape / split-screen / half-fold.
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Sigil()
        Spacer(Modifier.height(8.dp))
        Text(email, color = MaterialTheme.colorScheme.onSurfaceVariant)
        // F26: why it locked (manual / idle / session ended) — one quiet line, fresh per
        // lock event, cleared on a successful unlock.
        ui.lockReason?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(24.dp))
        ErrorBar(ui.error, vm::clearError)
        // A recover-flow landing ("Master password reset — sign in…") can arrive here too.
        NoticeBar(ui.notice, vm::clearNotice)
        // Runtime notice from a biometric attempt (temp lockout / cancel / biometrics-changed).
        ui.quickUnlockMessage?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
        }
        // Stale-window notice (design §3): enrolled but past 30 days → password re-stamps it.
        if (ui.quickUnlockEnrolled && !ui.quickUnlockFresh) {
            Text(
                "It's been 30 days — enter your master password to keep quick unlock active.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
        }
        SecretField("Master password", password) { password = it }
        Spacer(Modifier.height(12.dp))
        PrimaryButton("Unlock", enabled = password.isNotBlank() && !ui.busy, busy = ui.busy) { vm.unlock(email, password) }
        // Cut M (v2 #24): the ~6 s Argon2id derivation behind Unlock read as a hang — the
        // button spinner alone has no voice. One honest, motion-free caption (web/extension
        // "Unsealing…" parity); polite live region so reader users hear it too.
        if (ui.busy) {
            Spacer(Modifier.height(8.dp))
            Text(
                "Unsealing your vault — this takes a few seconds.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
        if (canBiometric) {
            OutlinedButton(onClick = { vm.unlockWithBiometric(activity!!) }, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) {
                Text("Use fingerprint / face")
            }
        }
        // Cut H (v2 #6) signposted the WEB #recover flow here; the self-recovery wizard is
        // native now (RecoverScreen, wave-2) — enter it in-app instead of bouncing browsers.
        TextButton(onClick = vm::openRecover, enabled = !ui.busy) {
            Text("Forgot your master password?")
        }
        // Cut D (v2 #3): sign-out clears the local vault cache, quick unlock, and any unsynced
        // edits — it must never be a one-tap action from a screen whose main button is right above.
        var confirmSignOut by remember { mutableStateOf(false) }
        TextButton(onClick = { confirmSignOut = true }) { Text("Sign out / use a different account") }
        if (confirmSignOut) {
            AlertDialog(
                onDismissRequest = { confirmSignOut = false },
                title = { Text("Sign out of this device?") },
                text = { Text("This removes the vault copy, quick unlock, and any unsynced changes from this device. You'll need your master password — and a connection to your server — to sign back in.") },
                confirmButton = { TextButton(onClick = { confirmSignOut = false; vm.signOut() }) { Text("Sign out") } },
                dismissButton = { TextButton(onClick = { confirmSignOut = false }) { Text("Stay signed in") } },
            )
        }
    }
}

/**
 * Forgot-master-password self-recovery (design 2026-07-12 §F.3) — the native twin of web
 * Recover.tsx's two-phase wizard, reached from the Unlock screen's "Forgot your master
 * password?" signpost (the flow used to bounce to the web client's #recover):
 *
 *  1. verify — email + the saved recovery phrase → the VM derives `recoveryAuthKey` (HKDF
 *     only) and POSTs it; the server proves possession WITHOUT ever seeing the phrase.
 *  2. reset  — choose a new master password (F60 strength floor; KDF params = the fenced
 *     server policy); the VM opens the SAME UVK from the phrase, runs the spec 01 §5
 *     identity hard-fail, re-wraps, and commits. All sessions are revoked, so the flow
 *     lands back on sign-in with a success notice.
 *
 * §F.7 hygiene: the typed phrase is plain `remember` (never SavedState), typed under
 * KeyboardType.Password with autocorrect off (the RecoverySetup type-back idiom — the IME's
 * suggestion strip and personal dictionary must not learn it) and cleared from composition
 * state the moment the verify succeeds; the raw secret bytes live only in the VM
 * (zeroized on cancel/commit/lock). Passwords use SecretField (masked + Password IME).
 * System back = Cancel, so leaving the screen always routes through the VM's zeroize.
 */
@Composable
private fun RecoverScreen(vm: AndvariViewModel, ui: UiState, sessionEmail: String) {
    var email by rememberSaveable { mutableStateOf(sessionEmail) } // non-secret; fold-safe
    var phrase by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    BackHandler(onBack = vm::cancelRecover)
    // Web parity (submitVerify): drop the typed phrase from state once the VM holds the
    // parsed bytes — the display string must not linger through phase 2.
    LaunchedEffect(ui.recoverVerified) { if (ui.recoverVerified) phrase = "" }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        SigilMark(BrandSigil, 46.dp)
        Spacer(Modifier.height(4.dp))
        Text("Recover your account", style = MaterialTheme.typography.titleLarge)
        Text(
            if (ui.recoverVerified) "choose a new master password" else "with your saved recovery phrase",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        ErrorBar(ui.error, vm::clearError)
        if (!ui.recoverVerified) {
            Text(
                "Enter the recovery phrase you saved when you set up this account. Your master " +
                    "password is not needed — the phrase alone lets you set a new one.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Field("Email", email, { email = it }, keyboard = KeyboardType.Email)
            // The RecoverySetup type-back idiom: NOT a SecretField (a recovery phrase must never
            // be masked-then-password-managed, §F.7) but Password IME + mono so nothing learns it.
            Field("Recovery phrase", phrase, { phrase = it }, mono = true, keyboard = KeyboardType.Password)
            Text(
                "exactly as you saved it — spaces are ignored",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            PrimaryButton("Continue", enabled = email.isNotBlank() && phrase.isNotBlank() && !ui.busy, busy = ui.busy) {
                vm.recoverVerify(email.trim(), phrase)
            }
            if (ui.busy) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Checking your recovery phrase…",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            TextButton(onClick = vm::cancelRecover, enabled = !ui.busy) { Text("Back to sign in") }
        } else {
            Text(
                "Your recovery phrase checked out. Choose a new master password — it re-locks the " +
                    "same vault; nothing you stored is lost.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            SecretField("New master password", password) { password = it }
            if (password.isNotEmpty()) {
                // The EnrollForm strength block (F60 floor) — same copy, same gate.
                val score = Strength.estimateStrength(password)
                if (Strength.meetsMasterPasswordFloor(password)) {
                    Text("strength: ${Strength.label(score)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text("Too weak for a master password (${Strength.label(score)}) — mix length with upper/lower case, digits, or symbols.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                if (Strength.masterPasswordHasNonAscii(password)) {
                    Text("contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
                }
            }
            SecretField("Confirm new master password", confirm) { confirm = it }
            InlineError(if (confirm.isNotEmpty() && confirm != password) "passwords don't match" else null)
            Spacer(Modifier.height(12.dp))
            val ready = Strength.meetsMasterPasswordFloor(password) && password == confirm
            // onClick re-asserts the gate from live reads (S2-review race class; the VM
            // re-checks the floor + busy too).
            PrimaryButton("Reset master password", enabled = ready && !ui.busy, busy = ui.busy) {
                if (Strength.meetsMasterPasswordFloor(password) && password == confirm) vm.recoverCommit(password)
            }
            if (ui.busy) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Re-locking your vault with the new password — this takes a few seconds.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
            TextButton(onClick = vm::cancelRecover, enabled = !ui.busy) { Text("Cancel") }
        }
    }
}

// ---- vault ----

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(vm: AndvariViewModel, ui: UiState) {
    // rememberSaveable: rotation / fold-posture change recreates the Activity, and plain
    // `remember` state (search, open detail) silently reset — typed work lost. (With the
    // manifest configChanges those events no longer even recreate; this is defense-in-depth.)
    var query by rememberSaveable { mutableStateOf("") }
    var detailId by rememberSaveable { mutableStateOf<String?>(null) }
    val ctx = LocalContextCompat()
    val scope = rememberCoroutineScope()

    // The editor session (open flag + target itemId) lives in the ViewModel — see
    // AndvariViewModel.openEditor/closeEditor. Local snapshot for smart-casts.
    val editorItemId = vm.editorItemId
    // Snapshot the initial doc per editor session (remember, not derived live): edits build
    // on initial.copy(), and the base must not shift under the user mid-session. null with
    // a non-null id = the target item no longer exists.
    val editorInitial = if (!vm.editorOpen) null else remember(editorItemId, vm.editorNewType) {
        when {
            editorItemId != null -> vm.item(editorItemId)?.doc
            vm.editorNewType == "card" -> ItemDoc(type = "card", name = "", card = CardData())
            else -> ItemDoc(type = "login", name = "", login = LoginData(uris = listOf("")))
        }
    }
    if (vm.editorOpen && editorItemId != null && editorInitial == null) {
        // Deleted on another device (tombstone synced) — never rebase a blank doc onto the
        // existing id; the ViewModel closes the session and explains.
        LaunchedEffect(editorItemId) { vm.editorTargetVanished() }
    }
    // System back walks the in-app hierarchy instead of backgrounding the app: detail →
    // list here; editor → discard-confirm (handled inside ItemEditor, which registers its
    // own BackHandler while composed and therefore wins while the editor is open).
    BackHandler(enabled = editorInitial == null && detailId != null) { detailId = null }

    // CSV import: OpenDocument → BOUNDED read (never buffer a multi-GB file) → parse on-device.
    val importPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    // Two distinct nulls: a null STREAM is a read failure (throw), a null from
                    // readBounded means over-cap — that one must reach onSuccess so the
                    // dedicated size message below fires (folding both into one elvis-throw
                    // made the 10 MiB copy dead code).
                    val stream = ctx.contentResolver.openInputStream(uri)
                        ?: throw IllegalStateException("could not read the selected file")
                    stream.use { readBounded(it, CsvImport.MAX_BYTES) }
                }
            }
            result.onSuccess { bytes ->
                if (bytes == null) vm.importReject("That file is larger than 10 MiB — far bigger than any real browser password export.")
                else vm.importParse(bytes)
            }.onFailure { vm.importReject(HouseholdCopy.forImportError(it)) } // #23: local read failure, never raw text
        }
    }

    // Cut K (v2 #19): remembered — this ran on EVERY recomposition (not just query/item
    // changes), and the list below is now lazy so large vaults don't compose every row.
    val filtered = remember(ui.items, query) {
        val q = query.trim().lowercase()
        ui.items.filter {
            // F79 parity with web/desktop: name + username + EVERY uri + notes + card brand/••last4.
            val d = it.doc
            q.isEmpty() ||
                d.name.lowercase().contains(q) ||
                (d.notes ?: "").lowercase().contains(q) ||
                (d.login?.username ?: "").lowercase().contains(q) ||
                (d.login?.uris ?: emptyList()).any { u -> u.lowercase().contains(q) } ||
                (d.type == "card" && CardDisplay.subtitle(d).lowercase().contains(q))
        }
    }
    // Cut K (v2 #20): shared-vault name per item — items never showed WHICH vault they live
    // in, so personal vs shared secrets were indistinguishable in the list (web/desktop have
    // badges; this is the Android twin). Personal stays untagged.
    val vaultTags = remember(ui.items) { vm.vaultInfos().filter { it.type != "personal" }.associate { it.vaultId to it.name } }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    title = { Text("andvari", style = MaterialTheme.typography.titleLarge) },
                    actions = {
                        // Universal importer (design 2026-07-11): the one import sheet first, THEN the file picker.
                        IconButton(onClick = { vm.importBegin() }) { Icon(Icons.Default.FileUpload, "import CSV") }
                        IconButton(onClick = { vm.refresh() }) { Icon(Icons.Default.Refresh, "sync") }
                        IconButton(onClick = { vm.openSharing() }) { Icon(Icons.Default.Group, "sharing") }
                        IconButton(onClick = { vm.openTrash() }) { Icon(Icons.Default.Delete, "trash") }
                        IconButton(onClick = { vm.openSettings() }) { Icon(Icons.Default.Settings, "settings") }
                        IconButton(onClick = { vm.lock() }) { Icon(Icons.Default.Lock, "lock") }
                    },
                )
                // #24: honest motion for the multi-second syncs — ui.syncing (the quiet 5-min /
                // foreground poll) was rendered NOWHERE, and a manual refresh (op → busy) showed
                // nothing moving either. One thin indeterminate line under the bar covers both.
                if (ui.syncing || ui.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
            }
        },
        floatingActionButton = {
            if (editorInitial == null && detailId == null) {
                // Option A rollout gate (design 2026-07-09): card CREATION stays dark until the
                // fielded 0.2.x desktop MSI is retired — the gate const lives in core beside the
                // display helpers. Everything downstream for EXISTING cards renders regardless.
                if (!CardDisplay.CREATE_ENABLED) {
                    ExtendedFloatingActionButton(onClick = { vm.openEditor(null) }, text = { Text("Add") }, icon = { Icon(Icons.Default.Add, null) })
                } else {
                    var addMenu by remember { mutableStateOf(false) }
                    Box {
                        ExtendedFloatingActionButton(onClick = { addMenu = true }, text = { Text("Add") }, icon = { Icon(Icons.Default.Add, null) })
                        DropdownMenu(expanded = addMenu, onDismissRequest = { addMenu = false }) {
                            DropdownMenuItem(text = { Text("Login") }, onClick = { addMenu = false; vm.openEditor(null) })
                            DropdownMenuItem(text = { Text("Card") }, onClick = { addMenu = false; vm.openEditor(null, newType = "card") })
                        }
                    }
                }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            val current = detailId?.let { vm.item(it) }
            when {
                // Completion callbacks capture the STABLE vm, never composition state: a
                // save finishing across an Activity recreation still closes the editor.
                editorInitial != null -> ItemEditor(vm, ui, editorItemId, editorInitial, onSave = { doc, uploads, vId -> vm.saveItem(editorItemId, doc, uploads, vId) { vm.closeEditor() } }, onCancel = { vm.closeEditor() })
                current != null -> ItemDetail(vm, ui, current, onEdit = { vm.openEditor(current.itemId) }, onDelete = { vm.deleteItem(current.itemId); detailId = null }, onBack = { detailId = null })
                // Cut K (v2 #19): LazyColumn — the eager Column composed EVERY row on every
                // keystroke (the 10k-scale freeze class the import dialogs cap against).
                else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp)) {
                    item(key = "toolbar") {
                        Column {
                            OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), placeholder = { Text("Search vault…") }, singleLine = true, leadingIcon = { Icon(Icons.Default.Search, null) })
                            ErrorBar(ui.error, vm::clearError)
                            NoticeBar(ui.notice, vm::clearNotice)
                            // P4/A7: the break-glass banners that used to render here (lifecycle notices,
                            // incoming transfers, re-seal, needsUpdate, unopenable-vault) moved to the
                            // global AttentionArea above the screen switch — rendered once, not duplicated
                            // on the Vault list AND Sharing. ErrorBar/NoticeBar stay (screen-local op feedback).
                            Spacer(Modifier.height(8.dp))
                        }
                    }
                    if (filtered.isEmpty()) {
                        item(key = "empty") {
                            // #25: the empty-hoard ᛝ as geometry (Theme.kt EmptySigil) — see Sigil().
                            Centered { Spacer(Modifier.height(60.dp)); SigilMark(EmptySigil, 40.dp); Spacer(Modifier.height(8.dp)); Text(if (ui.items.isEmpty()) "Your hoard is empty." else "Nothing matches.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        }
                    } else {
                        items(filtered, key = { it.itemId }) { item ->
                            VaultRow(item, vaultTags[item.vaultId]) { detailId = item.itemId }
                            Spacer(Modifier.height(8.dp))
                        }
                    }
                }
            }
            ImportSheet(vm, ui) { importPicker.launch(arrayOf("*/*")) }
            ImportDialogs(vm, ui)
        }
    }
}

/**
 * Universal import sheet (design 2026-07-11): ONE screen for every source — the honest
 * line, the plaintext warning (the same string the preview shows; across Android's
 * sequential dialogs that is how it stays in view before AND after the pick, like web's
 * single panel), and a collapsed-by-default per-source "how to export" help block read
 * from core [ImportHelp] (single-sourced with desktop). "Choose file…" goes STRAIGHT to
 * the SAF picker — the 0.10.1 wildcard path, now the only path (pin 3). No source pick
 * exists: header detection alone decides how the file is read, so the per-source steps
 * screens and the mismatch hint are gone, and the parse-error copy carries its own
 * recognized-source list (A-androidError — this sheet is already closed by error time).
 */
@Composable
private fun ImportSheet(vm: AndvariViewModel, ui: UiState, onChooseFile: () -> Unit) {
    if (!ui.importSourceSheet) return
    AlertDialog(
        onDismissRequest = vm::importSheetDismiss,
        confirmButton = {
            TextButton(onClick = { vm.importChooseFile(); onChooseFile() }) { Text("Choose file…") }
        },
        dismissButton = { TextButton(onClick = vm::importSheetDismiss) { Text("Cancel") } },
        title = { Text("Import passwords (CSV)") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Works with password exports from Chrome, Edge, Brave, Opera, Firefox, Bitwarden, 1Password 8 or newer, LastPass, and Safari — the file itself decides how it's read.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "⚠ This file holds every secret in plaintext. Nothing is uploaded — each item is encrypted on this device. Afterwards, delete the CSV and empty the trash.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                )
                // In-dialog disclosure idiom (ImportBucket's): plain `remember`, so every
                // reopening of the sheet lands collapsed again.
                var helpOpen by remember { mutableStateOf(false) }
                TextButton(onClick = { helpOpen = !helpOpen }) {
                    Text(if (helpOpen) "Hide export steps" else "How do I export from…?")
                }
                if (helpOpen) {
                    ImportHelp.SOURCES.forEach { s ->
                        Text(s.label, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(top = 6.dp))
                        s.steps.forEachIndexed { i, step ->
                            Text("${i + 1}. $step", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 2.dp))
                        }
                        // The 1Password-8 / LastPass safety notes ride inside their entries.
                        s.note?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 2.dp))
                        }
                    }
                }
            }
        },
    )
}

/** The three CSV-import dialogs (parse error → preview/confirm+progress+retry → done). */
@Composable
private fun ImportDialogs(vm: AndvariViewModel, ui: UiState) {
    if (ui.importError != null && ui.importPlan == null && !ui.importDone) {
        AlertDialog(
            onDismissRequest = vm::importDismiss,
            confirmButton = { TextButton(onClick = vm::importDismiss) { Text("OK") } },
            title = { Text("Couldn’t import") },
            text = { Text(ui.importError) },
        )
    }
    ui.importPlan?.let { plan ->
        if (!ui.importDone) {
            val report = plan.report
            // S2: destination choices, the F18 rule verbatim (personal + owner/writer shared
            // — never reader). Read once per preview open: each vaultInfos() call decrypts
            // vault metadata, and the choice list must not shift under an open dialog.
            val vaultChoices = remember {
                vm.vaultInfos().filter { it.type == "personal" || it.role == "owner" || it.role == "writer" }
            }
            AlertDialog(
                onDismissRequest = { if (!ui.importBusy) vm.importDismiss() },
                confirmButton = {
                    if (ui.importError != null) {
                        TextButton(onClick = vm::importConfirm, enabled = !ui.importBusy) { Text("Retry") }
                    } else {
                        TextButton(onClick = vm::importConfirm, enabled = !ui.importBusy && report.imported > 0) { Text("Import ${report.imported}") }
                    }
                },
                dismissButton = { TextButton(onClick = vm::importDismiss, enabled = !ui.importBusy) { Text("Cancel") } },
                title = { Text("Import passwords?") },
                text = {
                    Column(Modifier.verticalScroll(rememberScrollState())) {
                        Text(
                            "⚠ This file holds every secret in plaintext. Nothing is uploaded — each item is encrypted on this device. Afterwards, delete the CSV and empty the trash.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("From ${ui.importFormat?.let { importFormatLabel(it) } ?: "browser"} export:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        // Post-parse info line (calm): the A10 mangle heuristic — content-based,
                        // so it survives the universal importer (the mismatch note did not).
                        ui.importMangleNote?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.secondary, modifier = Modifier.padding(vertical = 2.dp)) }
                        // S2: shown only when there's a choice to make (F18 rule, like the
                        // editor's picker). Selecting RE-PLANS against that vault — every
                        // count/bucket below re-derives, and Confirm is importBusy-disabled
                        // until the fresh plan lands (importSetVault guards re-entry).
                        if (vaultChoices.size > 1) {
                            Spacer(Modifier.height(6.dp))
                            VaultPickerField(vaultChoices, ui.importVaultId) { vm.importSetVault(it) }
                        }
                        Text("• ${report.imported} to import", style = MaterialTheme.typography.bodySmall)
                        if (report.collapsed > 0) Text("• ${report.collapsed} exact duplicates in the file merged", style = MaterialTheme.typography.bodySmall)
                        if (report.skippedEmpty > 0) Text("• ${report.skippedEmpty} empty rows skipped", style = MaterialTheme.typography.bodySmall)
                        // Every bucket enumerates BY NAME (house rule), collapsed when long.
                        ImportBucket("imported as secure notes:", report.noteItems)
                        ImportBucket("already in your vault — skipped:", report.alreadyInVault)
                        ImportBucket("same site + username but a different password — imported separately; review which password is current:", report.passwordDiffers)
                        ImportBucket("same site + username but a different 2FA secret — imported separately; review which is current:", report.totpDiffers)
                        ImportBucket("renamed — the name was already taken:", report.flagged)
                        ImportBucket("archived in the export — not imported:", report.archivedSkipped)
                        ImportBucket("of a type this import doesn’t understand — skipped:", report.unknownTypeSkipped)
                        ImportBucket("with an unsupported one-time-code secret — kept as text in the item’s notes:", report.totpUnsupported)
                        if (report.errors.isNotEmpty()) {
                            Spacer(Modifier.height(6.dp))
                            Text("${report.errors.size} row(s) couldn’t be read:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            // Capped hard: this Column is non-lazy, and a mass-mangled file
                            // yields up to 9,999 error rows — composing them all is a
                            // multi-second main-thread freeze (the one enumeration the
                            // collapseAt house rule missed).
                            report.errors.take(MAX_ERROR_ROWS_SHOWN).forEach { err ->
                                // A9: lead with the data-row ordinal — a multi-line quoted
                                // note makes the physical line unmatchable to the row a
                                // spreadsheet shows (core's rowOrdinalsByLine, same reader).
                                val where = ui.importRowOrdinals[err.line]?.let { "row $it (file line ${err.line})" } ?: "file line ${err.line}"
                                Text("• $where: ${importRowErrorLabel(err.code)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            }
                            if (report.errors.size > MAX_ERROR_ROWS_SHOWN) {
                                Text("…and ${report.errors.size - MAX_ERROR_ROWS_SHOWN} more — fix the export and pick the file again to re-check.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            }
                        }
                        ui.importProgress?.let { (done, total) ->
                            Spacer(Modifier.height(10.dp))
                            LinearProgressIndicator(progress = { if (total > 0) done.toFloat() / total else 0f }, modifier = Modifier.fillMaxWidth())
                            Text("Importing $done / $total", style = MaterialTheme.typography.bodySmall)
                        }
                        ui.importError?.let { Spacer(Modifier.height(8.dp)); Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                    }
                },
            )
        }
    }
    if (ui.importDone) {
        // S2: the summary names the DESTINATION vault — "your vault" hid which vault the
        // rows landed in. Resolved once (vaultInfos decrypts); fallback keeps the old copy.
        val destName = remember(ui.importVaultId) {
            vm.vaultInfos().find { it.vaultId == ui.importVaultId }
                ?.let { it.name + if (it.type == "personal") "" else " (shared)" }
        }
        AlertDialog(
            onDismissRequest = vm::importDismiss,
            confirmButton = { TextButton(onClick = vm::importDismiss) { Text("Done") } },
            title = { Text("Imported") },
            text = { Text("Added ${ui.importReport?.imported ?: 0} item(s) to ${destName ?: "your vault"}. Now delete the CSV file and empty your trash.") },
        )
    }
}

/** Import-report bucket: title (with count) + names, collapsed past [collapseAt] — the
 *  house rule is enumerate-by-name, never a bare count, but a 500-name list must not
 *  swallow the dialog. Empty → renders nothing. */
@Composable
private fun ImportBucket(title: String, names: List<String>, collapseAt: Int = 5) {
    if (names.isEmpty()) return
    var expanded by remember(names) { mutableStateOf(false) }
    Spacer(Modifier.height(6.dp))
    Text("${names.size} $title", style = MaterialTheme.typography.bodySmall)
    // Expansion is capped too: the dialog Column is non-lazy, so "Show all" on a
    // thousands-name bucket would compose them all in one frame (same freeze class as the
    // uncapped error list was).
    val shown = when {
        names.size <= collapseAt -> names
        expanded -> names.take(BUCKET_EXPAND_CAP)
        else -> names.take(collapseAt)
    }
    shown.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    if (names.size > collapseAt) {
        TextButton(onClick = { expanded = !expanded }) { Text(if (expanded) "Show fewer" else "…and ${names.size - collapseAt} more") }
        if (expanded && names.size > BUCKET_EXPAND_CAP) {
            Text("(showing the first $BUCKET_EXPAND_CAP of ${names.size})", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Non-lazy dialog enumerations stop here — past this, composition itself is the bottleneck. */
private const val BUCKET_EXPAND_CAP = 100
private const val MAX_ERROR_ROWS_SHOWN = 8

private fun importRowErrorLabel(code: String): String = when (code) {
    "wrong_field_count" -> "wrong number of fields"
    "bad_quote" -> "broken quoting"
    else -> code
}

/**
 * Read at most [limit] bytes from [input]; return null if the source is larger (so a
 * multi-GB pick is rejected without ever being buffered in memory). Mirrors CsvImport's
 * own size cap so a file that fits here also passes parse().
 */
private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray? {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val r = input.read(buf)
        if (r < 0) break
        total += r
        if (total > limit) return null
        out.write(buf, 0, r)
    }
    return out.toByteArray()
}

@Composable
private fun VaultRow(item: VaultItem, vaultTag: String? = null, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(38.dp), contentAlignment = Alignment.Center) {
                Text((item.doc.name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif)
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(item.doc.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                Text(
                    when (item.doc.type) {
                        "login" -> item.doc.login?.username?.ifBlank { "login" } ?: "login"
                        // Brand + ••last4 (mirrors web) — enough to pick the right card, never the PAN.
                        "card" -> CardDisplay.subtitle(item.doc)
                        else -> "secure note"
                    },
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
                )
            }
            // Cut K (v2 #20): the shared-vault tag (gold, like web's) — personal items stay untagged.
            vaultTag?.let {
                Text(it, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.secondary, maxLines = 1)
                Spacer(Modifier.width(8.dp))
            }
            Text(item.doc.type, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * Item history & restore (feature: "the fat-finger seatbelt"). Loads the archived versions the
 * server keeps (up to the last 10), decrypts each under the held VK, and offers per-version reveal
 * + Restore (a plain put over the live item). Readers view but can't restore. "up to the last 10
 * saves" — never "nothing is ever lost" (spec 02 §7). Mirrors the deployed web panel.
 */
@Composable
private fun ItemHistorySection(vm: AndvariViewModel, ui: UiState, item: VaultItem, readOnly: Boolean, onRestored: () -> Unit) {
    var open by rememberSaveable(item.itemId) { mutableStateOf(false) }
    // Cut D (v2 #3): the pending restore target — Restore was a one-tap unconfirmed overwrite.
    var confirmRestore by remember(item.itemId) { mutableStateOf<DecryptedItemVersion?>(null) }
    confirmRestore?.let { v ->
        AlertDialog(
            onDismissRequest = { confirmRestore = null },
            title = { Text("Restore this version?") },
            text = { Text("The item's current version will be replaced by the one from ${java.time.Instant.ofEpochMilli(v.archivedAt).toString().take(10)}. The replaced version stays in history.") },
            confirmButton = { TextButton(onClick = { confirmRestore = null; vm.saveItem(item.itemId, v.doc) { onRestored() } }) { Text("Restore") } },
            dismissButton = { TextButton(onClick = { confirmRestore = null }) { Text("Cancel") } },
        )
    }
    if (!open) {
        TextButton(onClick = { open = true; vm.loadItemVersions(item.itemId, item.vaultId) }) { Text("Version history") }
        return
    }
    Text("Version history · up to the last 10 saves", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    val versions = ui.itemVersions
    when {
        versions == null -> Text(if (ui.busy) "Loading…" else "", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        versions.isEmpty() -> Text("No earlier versions yet — history starts from the next change.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        else -> versions.forEach { v ->
            var revealed by remember(v.rev) { mutableStateOf(false) }
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
                Text(java.time.Instant.ofEpochMilli(v.archivedAt).toString().take(10), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.width(90.dp))
                val pw = v.doc.login?.password
                Text(
                    when {
                        // Card versions identify by brand + ••last4 (mirrors web) — never the PAN.
                        v.doc.type == "card" -> CardDisplay.subtitle(v.doc)
                        pw == null && v.doc.type == "login" -> "(no password)"
                        pw == null -> "note"
                        revealed -> pw
                        else -> "••••••••"
                    },
                    modifier = Modifier.weight(1f),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
                if (pw != null) TextButton(onClick = { revealed = !revealed }) { Text(if (revealed) "Hide" else "Show") }
                // Cut D (v2 #3): Restore overwrites the LIVE item in one tap — confirm first.
                // (The overwritten version itself lands in history, so the copy says so.)
                if (!readOnly) TextButton(onClick = { confirmRestore = v }) { Text("Restore") }
            }
        }
    }
    TextButton(onClick = { open = false; vm.clearItemVersions() }) { Text("Hide history") }
}

@Composable
private fun ItemDetail(vm: AndvariViewModel, ui: UiState, item: VaultItem, onEdit: () -> Unit, onDelete: () -> Unit, onBack: () -> Unit) {
    val ctx = LocalContextCompat()
    val doc = item.doc
    // Reader-role members get no Edit/Delete affordances (mirrors web): the push would be
    // denied server-side and the denied mutation's typed work destroyed.
    val readOnly = vm.roleFor(item.vaultId) == "reader"
    var pendingDownload by remember { mutableStateOf<AttachmentRef?>(null) }
    val saver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val ref = pendingDownload
        pendingDownload = null
        if (uri != null && ref != null) {
            // "wt": same truncate-on-open contract as the export writes — plain "w"
            // leaves stale trailing bytes when overwriting a longer existing file.
            vm.saveAttachmentTo(ref) { bytes -> openTruncated(ctx, uri).use { it.write(bytes) } }
        }
    }
    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        TextButton(onClick = onBack) { Icon(Icons.Default.ArrowBack, null); Text(" back") }
        ErrorBar(ui.error, vm::clearError)
        NoticeBar(ui.notice, vm::clearNotice)
        Text(doc.name, style = MaterialTheme.typography.headlineMedium)
        // Cards identify themselves by brand + ••last4 (design contract, mirrors web) — the one
        // line that lets the user confirm the right card without revealing the full PAN.
        Text(
            when {
                doc.type == "login" -> "Login"
                doc.type == "card" -> if (doc.card?.number.isNullOrEmpty()) "Card" else CardDisplay.subtitle(doc)
                else -> "Secure note"
            } + (if (readOnly) " · view only" else ""),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(16.dp))
        // Vault-secret copies clear after the org policy window, clamped into
        // [1, CLIPBOARD_CLEAR_MAX_SECONDS] (design 2026-07-15 §2.3/B1-1): a policy of 0 still
        // clears — never "keep forever" for secrets — and an oversized value from a hostile
        // server can't pin the clipboard past the core ceiling. 30 s fallback while the policy
        // hasn't loaded (matches web).
        val clipClear = (ui.policy?.clipboardClearSeconds ?: 30).coerceIn(1, ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS)
        doc.login?.let { login ->
            login.username?.takeIf { it.isNotBlank() }?.let { CopyRow("Username", it, ctx, clipClear) }
            login.password?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Password", it, ctx, clipClear) }
            login.totp?.takeIf { it.isNotBlank() }?.let { TotpRow(it, ctx, clipClear) }
            login.uris.firstOrNull()?.takeIf { it.isNotBlank() }?.let { ReadOnlyRow("Website", it) }
        }
        if (doc.type == "card") doc.card?.let { card ->
            card.cardholderName?.takeIf { it.isNotBlank() }?.let { CopyRow("Cardholder", it, ctx, clipClear) }
            // Reveal shows the grouped form; Copy carries the BARE stored digits (what a
            // checkout field wants) through the same policy-cleared clipboard as passwords.
            card.number?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Card number", it, ctx, clipClear, display = CardDisplay.groupNumber(it)) }
            CardDisplay.expiryLabel(card)?.let { label ->
                val today = java.time.LocalDate.now()
                ExpiryRow(label, CardDisplay.isExpired(card.expMonth, card.expYear, today.year, today.monthValue))
            }
            card.securityCode?.takeIf { it.isNotBlank() }?.let { SecretCopyRow("Security code", it, ctx, clipClear) }
        }
        doc.notes?.takeIf { it.isNotBlank() }?.let { ReadOnlyRow("Notes", it) }
        if (doc.attachments.isNotEmpty()) {
            Spacer(Modifier.height(12.dp))
            Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(4.dp))
            doc.attachments.forEach { ref ->
                AttachmentRow(ref, enabled = !ui.busy) { pendingDownload = ref; saver.launch(ref.name) }
                Spacer(Modifier.height(8.dp))
            }
        }
        Spacer(Modifier.height(16.dp))
        ItemHistorySection(vm, ui, item, readOnly, onRestored = onBack)
        Spacer(Modifier.height(24.dp))
        if (!readOnly) {
            var confirmDelete by remember { mutableStateOf(false) }
            Row {
                Button(onClick = onEdit, modifier = Modifier.weight(1f)) { Text("Edit") }
                Spacer(Modifier.width(12.dp))
                OutlinedButton(onClick = { confirmDelete = true }, colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)) { Text("Delete") }
            }
            if (confirmDelete) {
                AlertDialog(
                    onDismissRequest = { confirmDelete = false },
                    title = { Text("Delete \"${doc.name}\"?") },
                    text = { Text("This removes the item from every device and every family member who can see it.") },
                    confirmButton = { TextButton(onClick = { confirmDelete = false; onDelete() }) { Text("Delete") } },
                    dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Keep") } },
                )
            }
            // F19 (design §8): move/copy into another writable vault. Mirrors web — only for
            // writers/owners of the SOURCE (a reader's delete leg would be denied anyway).
            val moveTargets = vm.vaultInfos().filter {
                (it.type == "personal" || it.role == "owner" || it.role == "writer") && it.vaultId != item.vaultId
            }
            if (moveTargets.isNotEmpty()) {
                Spacer(Modifier.height(8.dp))
                MoveCopyControl(vm, ui, item, moveTargets)
            }
        }
    }
}

@Composable
private fun AttachmentRow(ref: AttachmentRef, enabled: Boolean, onClick: () -> Unit) {
    Card(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.AttachFile, null, tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Text(ref.name, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                Text(humanSize(ref.size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Icon(Icons.Default.FileDownload, "download", tint = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun ItemEditor(vm: AndvariViewModel, ui: UiState, itemId: String?, initial: ItemDoc, onSave: (ItemDoc, List<PendingUpload>, String?) -> Unit, onCancel: () -> Unit) {
    val ctx = LocalContextCompat()
    val isLogin = initial.type == "login"
    val isCard = initial.type == "card"
    // F18 (mirrors web's newItemVaultChoices): a NEW item (itemId == null) may be created in the
    // personal vault or any shared vault this device can WRITE to (owner|writer). An EXISTING item
    // never changes vault — its choice list is empty, so the picker never shows and its value stays
    // null (saveWithUploads ignores it regardless — the HAZARD is closed at both layers).
    val vaultChoices = remember(itemId) {
        if (itemId == null) vm.vaultInfos().filter { it.type == "personal" || it.role == "owner" || it.role == "writer" }
        else emptyList()
    }
    // Default = Personal (vaultInfos() sorts personal first). rememberSaveable keeps the pick across
    // a rotation mid-edit; keyed on itemId so a fresh editor session re-defaults to Personal.
    var targetVaultId by rememberSaveable(itemId) { mutableStateOf(vaultChoices.firstOrNull()?.vaultId) }
    // rememberSaveable: every typed field survives Activity recreation (rotation / fold
    // posture change) — plain `remember` silently wiped them all.
    var name by rememberSaveable { mutableStateOf(initial.name) }
    var username by rememberSaveable { mutableStateOf(initial.login?.username ?: "") }
    var password by rememberSaveable { mutableStateOf(initial.login?.password ?: "") }
    var website by rememberSaveable { mutableStateOf(initial.login?.uris?.firstOrNull() ?: "") }
    var totp by rememberSaveable { mutableStateOf(initial.login?.totp ?: "") }
    // Card fields load VERBATIM (no normalization): merely opening the editor on an old card
    // must never change what a later Save writes back — normalization happens once, inside
    // builtDoc (the TOTP idiom).
    var cardholder by rememberSaveable { mutableStateOf(initial.card?.cardholderName ?: "") }
    var cardNumber by rememberSaveable { mutableStateOf(initial.card?.number ?: "") }
    var cardExpMonth by rememberSaveable { mutableStateOf(initial.card?.expMonth ?: "") }
    var cardExpYear by rememberSaveable { mutableStateOf(initial.card?.expYear ?: "") }
    var cardSecurityCode by rememberSaveable { mutableStateOf(initial.card?.securityCode ?: "") }
    var notes by rememberSaveable { mutableStateOf(initial.notes ?: "") }
    var attachments by rememberSaveable(stateSaver = attachmentListSaver) { mutableStateOf(initial.attachments) }
    // Pending pick BYTES live in the ViewModel (they can't go in SavedState) — see
    // AndvariViewModel.editorPendingUploads.
    val pendingUploads = vm.editorPendingUploads
    var attachError by remember { mutableStateOf<String?>(null) }
    var totpError by remember { mutableStateOf<String?>(null) }
    var confirmDiscard by remember { mutableStateOf(false) }
    val crypto = remember { createCryptoProvider() }
    val scope = rememberCoroutineScope()

    // Process death (not rotation) loses the ViewModel's pending bytes while the saved
    // attachment refs restore: drop any NEW ref whose bytes we no longer hold — saving it
    // would write a dangling attachment pointer.
    LaunchedEffect(Unit) {
        val held = pendingUploads.mapTo(HashSet()) { it.ref.id }
        val preExisting = initial.attachments.mapTo(HashSet()) { it.id }
        attachments = attachments.filter { it.id in preExisting || it.id in held }
    }

    // System back asks before throwing typed work away (it used to background the app).
    BackHandler { confirmDiscard = true }
    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text("Discard changes?") },
            text = { Text("Anything typed in this editor will be lost.") },
            confirmButton = { TextButton(onClick = { confirmDiscard = false; onCancel() }) { Text("Discard") } },
            dismissButton = { TextButton(onClick = { confirmDiscard = false }) { Text("Keep editing") } },
        )
    }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            attachError = null
            val cap = ui.policy?.attachmentMaxBytes ?: DEFAULT_ATTACHMENT_MAX_BYTES
            runCatching {
                withContext(Dispatchers.IO) {
                    val fileName = displayName(ctx, uri)
                    val stream = ctx.contentResolver.openInputStream(uri)
                        ?: throw IllegalStateException("could not read the selected file")
                    // BOUNDED read, mirroring the CSV import path: the cap must be enforced
                    // DURING the read — buffering first (readBytes) OOMed on a mispicked
                    // multi-GB file before the size check ever ran. null = over the cap.
                    val bytes = stream.use { readBounded(it, cap.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()) }
                    val overCapSize = if (bytes == null) documentSize(ctx, uri) else -1L
                    Triple(fileName, bytes, overCapSize)
                }
            }.onSuccess { (fileName, bytes, overCapSize) ->
                when {
                    bytes == null -> attachError =
                        if (overCapSize > 0) "“$fileName” is ${humanSize(overCapSize)} — over the ${humanSize(cap)} limit."
                        else "“$fileName” is over the ${humanSize(cap)} limit."
                    bytes.isEmpty() -> attachError = "“$fileName” is empty — nothing to attach."
                    else -> when (val ref = vm.newAttachmentRef(fileName, bytes.size.toLong())) {
                        null -> attachError = "vault is locked"
                        else -> {
                            pendingUploads += PendingUpload(ref, bytes)
                            attachments = attachments + ref
                        }
                    }
                }
            }.onFailure { attachError = HouseholdCopy.forImportError(it) } // #23: the pick never left the device
        }
    }

    Column(Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
        // Cut D (v2 #3): cancel rides the SAME discard-confirm as system Back — it was the
        // one-tap path that silently threw away typed work.
        TextButton(onClick = { confirmDiscard = true }) { Text("cancel") }
        Text(if (itemId != null) "Edit" else if (isLogin) "New login" else if (isCard) "New card" else "New note", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(8.dp))
        ErrorBar(ui.error, vm::clearError)
        // F18: show the vault picker ONLY for a new item with a real choice (>1 writable vault).
        if (vaultChoices.size > 1) VaultPickerField(vaultChoices, targetVaultId) { targetVaultId = it }
        Field("Name", name, { name = it })
        if (isLogin) {
            Field("Username", username, { username = it }, mono = true)
            Column {
                SecretField("Password", password) { password = it }
                TextButton(onClick = { password = PasswordGenerator.generate(crypto, GeneratorOptions(length = 20)) }) { Icon(Icons.Default.Refresh, null); Text(" Generate") }
            }
            Field("Website", website, { website = it })
            // RAW text while typing — normalizeTotp per keystroke rewrote the field to an
            // otpauth:// URI on the first character, making hand-typing a secret impossible.
            // Normalization + validation happen once, on Save.
            // Cut E review: a TOTP seed is a secret too — Password type keeps it out of the
            // IME's suggestion strip and personal dictionary (usually pasted, but not always).
            Field("TOTP (otpauth:// or base32)", totp, { totp = it; totpError = null }, mono = true, keyboard = KeyboardType.Password)
            InlineError(totpError)
        }
        if (isCard) {
            Field("Cardholder name", cardholder, { cardholder = it })
            // RAW text while typing (separators and all) — digits-only ONCE, on Save, exactly
            // like the TOTP field above. The label badge + warn line read the live digits; the
            // Luhn check WARNS, never blocks: an odd-but-real card must still be savable.
            val cardDigits = CardNormalize.digitsOnly(cardNumber)
            Field(
                "Card number" + (CardDisplay.brandLabel(CardNormalize.brand(cardDigits))?.let { " · $it" } ?: ""),
                cardNumber, { cardNumber = it }, mono = true, keyboard = KeyboardType.Number,
            )
            if (cardDigits.length >= 12 && !CardNormalize.luhnValid(cardDigits)) {
                Text("this number doesn’t pass the usual check — you can still save it", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
            }
            // Free-text expiry (this file has no select idiom) — padMonth/yearTo4 normalize on
            // Save, so "1"/"27" store as "01"/"2027". Every card field is optional. A half that
            // doesn't parse is stored ABSENT (overwriting any stored value), so warn — never
            // block — while it can't be read (desktop Ui.kt parity; web's selects make bad
            // input impossible).
            Field("Expiry month (MM)", cardExpMonth, { cardExpMonth = it }, mono = true, keyboard = KeyboardType.Number)
            Field("Expiry year (YYYY)", cardExpYear, { cardExpYear = it }, mono = true, keyboard = KeyboardType.Number)
            if ((cardExpMonth.isNotBlank() && CardNormalize.padMonth(cardExpMonth) == null) ||
                (cardExpYear.isNotBlank() && CardNormalize.yearTo4(cardExpYear) == null)
            ) {
                Text("expiry wants a month 1–12 and a 2- or 4-digit year — a part that can’t be read won’t be saved", color = MaterialTheme.colorScheme.secondary, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
            }
            // Masked-with-reveal: a CVV is glanceable-short and worth shielding from shoulders
            // by default. Digits-only is applied once, on Save, beside the other normalizations.
            SecretField("Security code", cardSecurityCode) { cardSecurityCode = it }
            Text("Optional — stored encrypted like everything else.", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp))
        }
        Field("Notes", notes, { notes = it }, singleLine = false)
        Spacer(Modifier.height(12.dp))
        Text("Attachments", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        attachments.forEach { ref ->
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.AttachFile, null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(ref.name, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                    Text(humanSize(ref.size), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                TextButton(
                    onClick = {
                        attachments = attachments.filterNot { it.id == ref.id }
                        pendingUploads.removeAll { it.ref.id == ref.id }
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                ) { Text("Remove") }
            }
        }
        attachError?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp)) }
        TextButton(onClick = { picker.launch(arrayOf("*/*")) }) { Icon(Icons.Default.AttachFile, null); Text(" Attach file") }
        Spacer(Modifier.height(16.dp))
        // copy()-based edit, never a field-by-field rebuild: carries favorite, passwordHistory,
        // extra URIs beyond the first, and unknown-field extras (spec 02 §3) through the save.
        fun builtDoc(totpValue: String) = initial.copy(
            name = name.trim(), notes = notes.ifBlank { null },
            login = if (isLogin) (initial.login ?: LoginData()).copy(
                username = username, password = password,
                uris = buildList { if (website.isNotBlank()) add(website); addAll(initial.login?.uris.orEmpty().drop(1)) },
                totp = totpValue.ifBlank { null },
            ) else null,
            // Cards normalize ONCE here (mirrors the web submit): .copy() on the EXISTING
            // CardData so unknown-field extras survive; blanks → null; brand is ALWAYS
            // recomputed from the number — the stored field is display-only, never stale.
            card = if (isCard) (initial.card ?: CardData()).copy(
                cardholderName = cardholder.trim().ifBlank { null },
                number = CardNormalize.digitsOnly(cardNumber).ifBlank { null },
                expMonth = CardNormalize.padMonth(cardExpMonth),
                expYear = CardNormalize.yearTo4(cardExpYear),
                securityCode = CardNormalize.digitsOnly(cardSecurityCode).ifBlank { null },
                brand = CardNormalize.brand(cardNumber),
            ) else initial.card,
            attachments = attachments,
        )
        PrimaryButton("Save", enabled = name.isNotBlank() && !ui.busy, busy = ui.busy) {
            // A5: ONE shared TOTP normalize — core Totp.normalize (the private copy this
            // file carried is deleted). Blank stays blank: normalize is only for values.
            val normalizedTotp = if (isLogin && totp.isNotBlank()) Totp.normalize(totp) else ""
            if (isLogin && totp.isNotBlank() && runCatching { Totp.parseUri(normalizedTotp) }.isFailure) {
                totpError = "TOTP secret isn't valid base32 or an otpauth:// link"
            } else {
                onSave(builtDoc(normalizedTotp), pendingUploads.toList(), targetVaultId)
            }
        }
    }
}

/**
 * F18 vault picker (mirrors web's Editor `<select>`): choose which vault a NEW item is created in.
 * Uses the RadioButton idiom already established for vault selection in MoveCopyControl — Android's
 * house form of web's dropdown. Personal sorts first in vaultInfos(), so it's listed first and is
 * the default. Always enabled, like the editor's other inputs (only Save gates on busy).
 */
@Composable
private fun VaultPickerField(choices: List<VaultInfo>, selectedId: String?, onSelect: (String) -> Unit) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text("Vault", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        choices.forEach { v ->
            Row(
                Modifier.selectable(selected = v.vaultId == selectedId, role = Role.RadioButton, onClick = { onSelect(v.vaultId) }),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(selected = v.vaultId == selectedId, onClick = null)
                Text(v.name + if (v.type == "personal") "" else " (shared)", style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

// ---- TOTP live row ----
@Composable
private fun TotpRow(uri: String, ctx: Context, clearSeconds: Int) {
    val crypto = remember { createCryptoProvider() }
    var code by remember { mutableStateOf("······") }
    var remaining by remember { mutableStateOf(30) }
    LaunchedEffect(uri) {
        val cfg = runCatching { Totp.parseUri(uri) }.getOrNull()
        if (cfg == null) { code = "invalid"; return@LaunchedEffect }
        while (true) {
            val now = System.currentTimeMillis() / 1000
            code = Totp.code(crypto, cfg, now)
            remaining = Totp.secondsRemaining(cfg, now)
            delay(1000)
        }
    }
    Column(Modifier.padding(vertical = 8.dp)) {
        Text("One-time code", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(
                onClick = { copyToClipboard(ctx, "code", code, clearSeconds) },
                modifier = Modifier.semantics { contentDescription = "One-time code, double-tap to copy" },
            ) {
                Text(code.chunked(3).joinToString(" "), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.headlineMedium, color = MaterialTheme.colorScheme.secondary)
            }
            // Re-computed every second; clearAndSetSemantics stops TalkBack re-announcing it on every tick (a11yand-05).
            Text("${remaining}s", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.clearAndSetSemantics {})
        }
    }
}

// ---- settings / server TOTP ----

/**
 * Item undelete (feature): "Recently deleted" — the tombstoned items the user can recover. Each is
 * named from its last archived version (a tombstone's own blob is null); Restore re-creates it live
 * via the dedicated route (clean un-tombstone). Attachments are not restored (blobs gone at delete).
 * Mirrors the web Trash view.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(vm: AndvariViewModel, ui: UiState) {
    BackHandler(onBack = vm::closeTrash)
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Trash", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeTrash) { Icon(Icons.Default.ArrowBack, "back") } },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
            ErrorBar(ui.error, vm::clearError)
            NoticeBar(ui.notice, vm::clearNotice)
            var confirmPurgeId by remember { mutableStateOf<String?>(null) }
            Text(
                "Deleted items are kept for 30 days, then removed automatically. Restore brings one back to its vault on every device; \"Delete forever\" removes it now.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            confirmPurgeId?.let { id ->
                AlertDialog(
                    onDismissRequest = { confirmPurgeId = null },
                    title = { Text("Delete forever?") },
                    text = { Text("This permanently removes the item and its history from every device. It can't be undone.") },
                    confirmButton = { TextButton(onClick = { vm.purgeDeleted(id); confirmPurgeId = null }) { Text("Delete forever", color = MaterialTheme.colorScheme.error) } },
                    dismissButton = { TextButton(onClick = { confirmPurgeId = null }) { Text("Keep") } },
                )
            }
            val deleted = ui.deletedItems
            when {
                deleted == null -> Text(if (ui.busy) "Loading…" else "", color = MaterialTheme.colorScheme.onSurfaceVariant)
                deleted.isEmpty() -> Text("Nothing here — deleted items you can recover will show up in this list.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                else -> deleted.forEach { d ->
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                d.doc?.name ?: "(unrecoverable — no readable version)",
                                style = MaterialTheme.typography.bodyLarge,
                                color = if (d.doc != null) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                "deleted ${java.time.Instant.ofEpochMilli(d.deletedAt).toString().take(10)}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        val docToRestore = d.doc
                        if (docToRestore != null) {
                            TextButton(enabled = !ui.busy, onClick = { vm.restoreDeleted(d.itemId, d.vaultId, docToRestore) }) { Text("Restore") }
                        }
                        TextButton(enabled = !ui.busy, onClick = { confirmPurgeId = d.itemId }) {
                            Text("Delete forever", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContextCompat()
    var code by remember { mutableStateOf("") }
    BackHandler(onBack = vm::closeSettings) // back = the top-bar arrow, not "background the app"
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings", style = MaterialTheme.typography.titleLarge) },
                navigationIcon = { IconButton(onClick = vm::closeSettings) { Icon(Icons.Default.ArrowBack, "back") } },
            )
        },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState())) {
            vm.identityCode()?.let { idCode ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("My identity code", style = MaterialTheme.typography.titleLarge)
                        Text(
                            "Someone sharing a vault with you will ask you to read this out (in person or by phone) before they send you the key.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(8.dp))
                        SelectionContainer {
                            Text(
                                idCode.chunked(4).joinToString(" "),
                                style = MaterialTheme.typography.titleMedium, fontFamily = FontFamily.Monospace,
                            )
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Server", style = MaterialTheme.typography.titleLarge)
                    Spacer(Modifier.height(8.dp))
                    SelectionContainer {
                        Text(ui.baseUrl, style = MaterialTheme.typography.bodyMedium, fontFamily = FontFamily.Monospace)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text("Sign out to connect to a different server.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Spacer(Modifier.height(16.dp))
            AppearanceCard()
            Spacer(Modifier.height(16.dp))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Vault backup", style = MaterialTheme.typography.titleLarge)
                    Text(lastBackupLine(ui.lastExportAt), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (backupNudge(ui.lastExportAt)) {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            if (ui.lastExportAt <= 0) {
                                "You've never backed up this vault — an offline backup is the only copy that survives losing the server and its backups."
                            } else {
                                "It's been over 90 days — consider taking a fresh backup."
                            },
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = vm::backupBegin, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Back up vault…") }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = vm::csvBegin, enabled = !ui.busy, modifier = Modifier.fillMaxWidth()) { Text("Export for another password manager…") }
                }
            }
            Spacer(Modifier.height(16.dp))
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Autofill", style = MaterialTheme.typography.titleLarge)
                    Text(
                        "Is autofill working? See what the last fill request looked like and why it did (or didn't) offer anything — screenshot-friendly.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedButton(onClick = vm::openAutofillStatus, modifier = Modifier.fillMaxWidth()) { Text("Autofill status") }
                }
            }
            Spacer(Modifier.height(16.dp))
            QuickUnlockSettingsCard(vm, ui)
            Spacer(Modifier.height(16.dp))
            ErrorBar(ui.error, vm::clearError)
            NoticeBar(ui.notice, vm::clearNotice)
            ExportDialogs(vm, ui)
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Two-factor sign-in (server)", style = MaterialTheme.typography.titleLarge)
                    Text("A second factor the server checks — protects break-glass/public logins.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.height(12.dp))
                    val status = ui.totpStatus
                    val setup = ui.totpSetup
                    when {
                        status == null -> {
                            if (ui.totpMessage != null) {
                                InlineError(ui.totpMessage)
                            } else {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                    Spacer(Modifier.width(10.dp))
                                    Text("Checking status…", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                            }
                        }
                        setup != null -> {
                            Text("Add this secret to your authenticator app, then confirm with a code.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            SelectableCopyRow("Setup URI (otpauth)", setup.otpauthUri, ctx)
                            SelectableCopyRow("Secret (base32)", setup.secretBase32, ctx)
                            Spacer(Modifier.height(4.dp))
                            Field("6-digit code", code, { code = it.filter { c -> c.isDigit() }.take(6) }, mono = true, keyboard = KeyboardType.Number)
                            InlineError(ui.totpMessage)
                            Spacer(Modifier.height(8.dp))
                            PrimaryButton("Confirm", enabled = code.length == 6 && !ui.busy, busy = ui.busy) { vm.totpConfirm(code); code = "" }
                        }
                        status.enrolled -> {
                            Text("Enrolled — one-time codes are active for this account.", style = MaterialTheme.typography.bodyMedium)
                            Spacer(Modifier.height(8.dp))
                            Field("6-digit code", code, { code = it.filter { c -> c.isDigit() }.take(6) }, mono = true, keyboard = KeyboardType.Number)
                            InlineError(ui.totpMessage)
                            Spacer(Modifier.height(8.dp))
                            OutlinedButton(
                                onClick = { vm.totpDisable(code); code = "" },
                                enabled = code.length == 6 && !ui.busy,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                            ) { Text("Disable") }
                        }
                        else -> {
                            Text(
                                if (status.pendingSetup) "A previous setup was never confirmed — enable to restart it." else "Not enrolled.",
                                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            InlineError(ui.totpMessage)
                            Spacer(Modifier.height(8.dp))
                            PrimaryButton("Enable", enabled = !ui.busy, busy = ui.busy) { vm.totpBegin() }
                        }
                    }
                }
            }
        }
    }
}

// ---- export & backup (spec 07) ----

/** The spec 07 export dialogs + their SAF launchers (backup preflight → CreateDocument →
 *  build/verify/write/verify-on-disk; CSV preflight → CreateDocument → write/verify;
 *  backup success summary). The pending [BackupRequest] is stashed in the ViewModel —
 *  NOT `remember` — so a Fold unfold / rotation / split-screen resize while the SAF
 *  picker is foreground doesn't drop it (a `remember` came back null and the result
 *  no-op'd, leaving a silent empty file). */
@Composable
internal fun ExportDialogs(vm: AndvariViewModel, ui: UiState) {
    val ctx = LocalContextCompat()

    // ---- backup (.andvari) ----
    val backupSaver = rememberLauncherForActivityResult(
        // MIME octet-stream is deliberate (spec 07 §2.6): a JSON MIME makes SAF mangle the
        // .andvari extension. Restore sniffs the magic bytes, never the extension.
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri ->
        // uri == null → picker cancelled; the request is dropped (take() below) and the
        // preflight dialog stays open for another go (re-confirming re-stashes it).
        val req = vm.backupRequestTake()
        when {
            uri == null -> {}
            req == null ->
                // Process death while the picker was foreground (ViewModel gone; the
                // passphrase is never persisted, so the flow cannot resume), or a
                // lock/sign-out cleared the stash: remove the created doc (empty-only)
                // and explain — never a silent 0-byte file.
                vm.backupRequestMissing { discardExportDoc(ctx, uri, writeBegan = false) }
            else -> vm.backupRun(
                req.vaults, req.includeAttachments, req.passphrase,
                write = { bytes -> openTruncated(ctx, uri).use { it.write(bytes) } },
                // On-disk verification read (spec 07 §2.6): bounded by the §2.2 256 MiB
                // open() cap — larger (a provider that kept a giant stale tail) reads
                // back null, which the ViewModel treats as verification failure.
                readBack = { ctx.contentResolver.openInputStream(uri)?.use { readBounded(it, EXPORT_READBACK_LIMIT) } },
                discard = { writeBegan -> discardExportDoc(ctx, uri, writeBegan) },
            )
        }
    }
    ui.backupPreflight?.let { pre ->
        BackupPreflightDialog(vm, ui, pre) { selected, includeAttachments, passphrase ->
            vm.backupRequestStash(BackupRequest(selected, includeAttachments, passphrase))
            backupSaver.launch("andvari-backup-${exportDateSuffix()}.andvari")
        }
    }
    ui.backupResult?.let { BackupResultDialog(it, vm::backupResultDismiss) }

    // ---- CSV ----
    val csvSaver = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        if (uri != null) {
            vm.csvRun(
                write = { bytes -> openTruncated(ctx, uri).use { it.write(bytes) } },
                readBack = { ctx.contentResolver.openInputStream(uri)?.use { readBounded(it, EXPORT_READBACK_LIMIT) } },
                discard = { writeBegan -> discardExportDoc(ctx, uri, writeBegan) },
            )
        }
    }
    ui.csvPreflight?.let { pre ->
        CsvPreflightDialog(vm, ui, pre) { csvSaver.launch("andvari-export-${exportDateSuffix()}.csv") }
    }
}

/** Bound for the post-export verification read-back = the spec 07 §2.2 total-file cap.
 *  Anything larger on disk is by definition not the file we wrote. */
private const val EXPORT_READBACK_LIMIT = 256 * 1024 * 1024

/**
 * Open [uri] for writing with TRUNCATION ("wt"). Plain "w" ([android.content.ContentResolver.openOutputStream]'s
 * default) does NOT truncate on many DocumentsProviders, so overwriting a longer
 * pre-existing file would leave stale trailing bytes — a corrupt export. "wt" is the
 * documented truncate-on-open contract; SAF offers no channel-level truncate to force
 * the issue on a provider that rejects the mode, so those fall back to "w" and the
 * export paths rely on their on-disk read-back verification to refuse any
 * non-truncated result.
 */
private fun openTruncated(ctx: Context, uri: Uri): java.io.OutputStream =
    runCatching { ctx.contentResolver.openOutputStream(uri, "wt") }.getOrNull()
        ?: ctx.contentResolver.openOutputStream(uri)
        ?: throw IllegalStateException("could not open the chosen destination")

/**
 * Best-effort discard of an export destination — deleting ONLY bytes this run may own.
 * [writeBegan] = the write lambda ran (the destination was opened with truncation): its
 * content is now partial/corrupt, so deleting satisfies spec 07 §2.6 (never leave a
 * partial file). When the failure happened BEFORE any write, delete only if the doc is
 * still EMPTY: CreateDocument usually mints a fresh 0-byte doc (delete = clean abort),
 * but a user confirming an overwrite gets the PRE-EXISTING document back — deleting
 * that on a build/verify failure would turn one good backup into zero. Unknown size
 * (provider won't say) → leave it alone: a stray empty file beats a destroyed backup.
 */
private fun discardExportDoc(ctx: Context, uri: Uri, writeBegan: Boolean) {
    runCatching {
        if (writeBegan || documentSize(ctx, uri) == 0L) {
            DocumentsContract.deleteDocument(ctx.contentResolver, uri)
        }
    }
}

/** SIZE column of a document, or -1 when the provider won't report it. */
private fun documentSize(ctx: Context, uri: Uri): Long {
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            val i = c.getColumnIndex(OpenableColumns.SIZE)
            if (i >= 0 && !c.isNull(i)) return c.getLong(i)
        }
    }
    return -1L
}

@Composable
private fun BackupPreflightDialog(
    vm: AndvariViewModel,
    ui: UiState,
    pre: BackupPreflight,
    onChooseDestination: (Set<String>, Boolean, String) -> Unit,
) {
    var selected by remember(pre) { mutableStateOf(pre.vaults.map { it.vaultId }.toSet()) }
    var includeAttachments by remember(pre) { mutableStateOf(false) }
    var passphrase by remember(pre) { mutableStateOf("") }
    var confirm by remember(pre) { mutableStateOf("") }
    val plan = remember(pre, selected) { vm.attachmentPlan(selected) }
    val score = Strength.estimateStrength(passphrase)
    val ready = selected.isNotEmpty() && passphrase.isNotEmpty() && passphrase == confirm &&
        score >= Strength.BACKUP_FLOOR && !ui.busy
    AlertDialog(
        onDismissRequest = { if (!ui.busy) vm.backupDismiss() },
        confirmButton = {
            TextButton(onClick = { onChooseDestination(selected, includeAttachments, passphrase) }, enabled = ready) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = vm::backupDismiss, enabled = !ui.busy) { Text("Cancel") } },
        title = { Text("Back up vault") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                pre.offlineNote?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    "Exporting is private — other members and the server are not notified.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(8.dp))
                pre.vaults.forEach { v ->
                    if (v.type == "personal") {
                        Text("• ${v.name} — ${v.itemCount} item(s), personal", style = MaterialTheme.typography.bodySmall)
                    } else {
                        Row(
                            Modifier.toggleable(value = v.vaultId in selected, role = Role.Checkbox, onValueChange = { on -> selected = if (on) selected + v.vaultId else selected - v.vaultId }),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(v.vaultId in selected, onCheckedChange = null)
                            Text("${v.name} — ${v.itemCount} item(s), shared (${v.role})", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                Row(
                    Modifier.toggleable(value = includeAttachments, role = Role.Checkbox, onValueChange = { includeAttachments = it }),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(includeAttachments, onCheckedChange = null)
                    Text("Include attachments (${humanSize(plan.totalBytes)})", style = MaterialTheme.typography.bodySmall)
                }
                if (includeAttachments && plan.overCap.isNotEmpty()) {
                    Text("Skipped — over the 64 MiB total cap:", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    plan.overCap.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                }
                Spacer(Modifier.height(8.dp))
                SecretField("Backup passphrase", passphrase) { passphrase = it }
                SecretField("Confirm passphrase", confirm) { confirm = it }
                if (passphrase.isNotEmpty()) {
                    val ok = score >= Strength.BACKUP_FLOOR
                    Text(
                        "Strength: ${Strength.label(score)}" + if (ok) "" else " — needs at least “good”",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (ok) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.error,
                    )
                }
                if (confirm.isNotEmpty() && confirm != passphrase) {
                    Text("Passphrases don't match.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                if (passphrase.any { it.code > 127 }) {
                    Text(
                        "Heads-up: non-ASCII characters are used exactly as typed — you must type them identically to restore.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    "Tip: your master password is a fine choice — the backup is then exactly as protected as your vault. A different passphrase belongs on your printed recovery sheet.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

@Composable
private fun BackupResultDialog(r: BackupResult, onDone: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDone,
        confirmButton = { TextButton(onClick = onDone) { Text("Done") } },
        title = { Text("Backup saved") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    "Backed up ${r.items} item(s) across ${r.vaults} vault(s)" +
                        (if (r.attachments > 0) " with ${r.attachments} attachment(s)." else "."),
                    style = MaterialTheme.typography.bodySmall,
                )
                NamedSkips("Skipped (over the 64 MiB attachment cap):", r.attachmentsOverCap)
                NamedSkips("Skipped (download failed twice):", r.attachmentFetchFailed)
                Spacer(Modifier.height(8.dp))
                Text(
                    "If you change your master password later, this file still opens with the passphrase you just set.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Restore is for total server loss only — via the offline backup-cli today, in-app in a future release.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

@Composable
private fun CsvPreflightDialog(vm: AndvariViewModel, ui: UiState, pre: CsvPreflight, onChooseDestination: () -> Unit) {
    AlertDialog(
        onDismissRequest = { if (!ui.busy) vm.csvDismiss() },
        confirmButton = {
            TextButton(onClick = onChooseDestination, enabled = !ui.busy && pre.loginCount > 0) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = vm::csvDismiss, enabled = !ui.busy) { Text("Cancel") } },
        title = { Text("Export for another password manager?") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                pre.offlineNote?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    "⚠ The CSV holds every password in PLAINTEXT. Anyone who reads the file reads your vault — and your Downloads folder may auto-sync to cloud storage. Delete it (and empty the trash) as soon as the other manager has imported it.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error,
                )
                Spacer(Modifier.height(8.dp))
                Text("${pre.loginCount} login(s) will be written.", style = MaterialTheme.typography.bodySmall)
                NamedSkips("Not exported (secure notes):", pre.warnings.noteItems)
                NamedSkips("Cards can't go in a CSV — back up the vault to include them:", pre.warnings.cardItems)
                NamedSkips("Attachments can't be represented in CSV:", pre.warnings.withAttachments)
                NamedSkips("Only the first website is kept:", pre.warnings.extraUris)
                NamedSkips("Written, but a reimport would skip them (no username or password):", pre.warnings.emptyUsernameAndPassword)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Reimporting a CSV collapses exact duplicates.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}

/** Named enumeration (spec 07 §1: by item name, never by count). Empty → renders nothing. */
@Composable
private fun NamedSkips(title: String, names: List<String>) {
    if (names.isEmpty()) return
    Spacer(Modifier.height(6.dp))
    Text(title, style = MaterialTheme.typography.bodySmall)
    names.forEach { Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
}

private fun exportDateSuffix(): String =
    java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.ROOT).format(java.util.Date())

private fun lastBackupLine(lastExportAt: Long): String {
    if (lastExportAt <= 0) return "Last backup: never"
    return when (val days = ((System.currentTimeMillis() - lastExportAt) / 86_400_000L).toInt()) {
        0 -> "Last backup: today"
        1 -> "Last backup: yesterday"
        else -> "Last backup: $days days ago"
    }
}

private fun backupNudge(lastExportAt: Long): Boolean =
    lastExportAt <= 0 || System.currentTimeMillis() - lastExportAt > 90L * 86_400_000L

@Composable
private fun InlineError(msg: String?) {
    // Polite liveRegion so TalkBack speaks validation/error text on change (a11yand-01). NOTE
    // (AM-6): this node is conditionally composed (null→text is first appearance) — the §4
    // TalkBack smoke must confirm the null→text case is spoken, not only text-to-text.
    if (msg != null) Text(msg, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(vertical = 4.dp).semantics { liveRegion = LiveRegionMode.Polite })
}

/** Copy row for setup material (not vault secrets): selectable text, copy WITHOUT auto-clear. */
@Composable
private fun SelectableCopyRow(label: String, value: String, ctx: Context) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            SelectionContainer(Modifier.weight(1f)) {
                Text(value, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
            TextButton(onClick = { copyToClipboard(ctx, label, value, 0) }) { Text("Copy") }
        }
    }
}

// ---- quick unlock (spec 01 §8.1) ----

/** Settings toggle: enroll (biometric consent) / disable quick unlock for this device. Disable is
 *  never auth-gated (reducing standing secret material); enroll is A5/A1-gated inside the VM. */
@Composable
private fun QuickUnlockSettingsCard(vm: AndvariViewModel, ui: UiState) {
    val activity = LocalContext.current as? FragmentActivity
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Quick unlock", style = MaterialTheme.typography.titleLarge)
            when {
                ui.mustChangePassword -> Text(
                    "Change your master password first, then you can turn on quick unlock.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                !ui.quickUnlockEligible && !ui.quickUnlockEnrolled -> Text(
                    "Add a fingerprint or face in your device settings (and make sure your organization allows it) to unlock andvari with biometrics.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                else -> {
                    Text(
                        "Unlock this device with your fingerprint or face instead of your master password. You'll still enter the password at least every 30 days.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    // AM-4: the toggle carries a real side effect (enroll/disable quick unlock),
                    // so the ENTIRE onCheckedChange lambda AND the enabled guard move onto the
                    // toggleable row; the Switch keeps enabled only for its greyed-out visual.
                    Row(
                        Modifier.toggleable(
                            value = ui.quickUnlockEnrolled,
                            enabled = activity != null && !ui.busy,
                            role = Role.Switch,
                            onValueChange = { on -> if (on) activity?.let { vm.enrollQuickUnlock(it) } else vm.disableQuickUnlock() },
                        ),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Fingerprint / face unlock", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        Switch(
                            checked = ui.quickUnlockEnrolled,
                            enabled = activity != null && !ui.busy,
                            onCheckedChange = null,
                        )
                    }
                }
            }
        }
    }
}

/** #26: device-local Auto/Light/Dark appearance pref (ThemePref, SharedPreferences
 *  "andvari-ui"). Selecting recomposes every AndvariTheme in the process live — including
 *  the autofill overlays. The two color schemes themselves are untouched (token lockstep);
 *  only the theme's selection expression reads this. */
@Composable
private fun AppearanceCard() {
    val ctx = LocalContextCompat()
    val mode = ThemePref.mode(ctx)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text("Appearance", style = MaterialTheme.typography.titleLarge)
            Text(
                "Auto follows this device's light/dark setting.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(4.dp))
            ThemeMode.entries.forEach { m ->
                Row(
                    Modifier.fillMaxWidth()
                        .selectable(selected = mode == m, role = Role.RadioButton, onClick = { ThemePref.set(ctx, m) })
                        .padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = mode == m, onClick = null)
                    Spacer(Modifier.width(10.dp))
                    Text(
                        when (m) {
                            ThemeMode.Auto -> "Auto (match device)"
                            ThemeMode.Light -> "Light"
                            ThemeMode.Dark -> "Dark"
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

/** One-time post-unlock offer card (design §8 default). "Not now" dismisses for good; the Settings
 *  toggle remains the durable control. */
@Composable
private fun AutofillOfferCard(vm: AndvariViewModel) {
    val ctx = LocalContext.current
    val prefs = remember { ctx.getSharedPreferences("andvari-ui", Context.MODE_PRIVATE) }
    var dismissed by remember { mutableStateOf(prefs.getBoolean("autofill_offer_dismissed", false)) }
    // Checked once per composition of the vault screen — enabling via the offer navigates
    // away, so a stale `false` can't stick around after setup.
    val afm = remember { ctx.getSystemService(android.view.autofill.AutofillManager::class.java) }
    val active = remember { runCatching { afm?.hasEnabledAutofillServices() == true }.getOrDefault(false) }
    if (dismissed || active || afm?.isAutofillSupported != true) return
    Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Text("Fill passwords everywhere", style = MaterialTheme.typography.titleSmall)
            Text(
                "Turn on andvari autofill and your logins appear right in apps and browsers — no copy-paste.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row {
                TextButton(onClick = { vm.openAutofillStatus() }) { Text("Set up") }
                TextButton(
                    onClick = { prefs.edit().putBoolean("autofill_offer_dismissed", true).apply(); dismissed = true },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurfaceVariant),
                ) { Text("Not now") }
            }
        }
    }
}

@Composable
private fun QuickUnlockOfferCard(vm: AndvariViewModel) {
    val activity = LocalContext.current as? FragmentActivity ?: return
    Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text("Unlock with fingerprint next time?", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(4.dp))
            Text(
                "Skip typing your master password on this device. You'll still enter it at least every 30 days.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(12.dp))
            Row {
                TextButton(onClick = { vm.dismissQuickUnlockOffer() }) { Text("Not now") }
                Spacer(Modifier.weight(1f))
                Button(onClick = { vm.enrollQuickUnlock(activity) }) { Text("Turn on") }
            }
        }
    }
}

// ---- small building blocks ----

@Composable private fun LocalContextCompat(): Context = androidx.compose.ui.platform.LocalContext.current

@Composable
private fun Field(label: String, value: String, onChange: (String) -> Unit, mono: Boolean = false, singleLine: Boolean = true, keyboard: KeyboardType = KeyboardType.Text) {
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = singleLine,
        // mono fields hold verbatim strings (invite token, typed fingerprint) — an IME
        // "correcting" a hex chunk to a dictionary word can only ever FAIL the check,
        // but the user gets a scary mismatch for keyboard noise. Kill autocorrect there.
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, autoCorrectEnabled = if (mono) false else null),
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium)
}

@Composable
private fun SecretField(label: String, value: String, onChange: (String) -> Unit) {
    var show by remember { mutableStateOf(false) }
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        // Cut E (v2 #4): a masking transformation alone does NOT tell the IME the field is a
        // secret — without KeyboardType.Password the keyboard's suggestion strip and personal
        // dictionary learn master passwords, item passwords, and backup passphrases.
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = { IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (show) "Hide $label" else "Show $label") } })
}

@Composable
private fun CopyRow(label: String, value: String, ctx: Context, clearSeconds: Int) {
    // Cut J (v2 #10): copying is the core daily action, and it gave zero in-app feedback —
    // worse, the auto-wipe (a real safety feature) was undisclosed, so a late paste read as
    // a random failure. A short flash names both.
    var copied by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(value, Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            TextButton(onClick = { copyToClipboard(ctx, label, value, clearSeconds); copied = true }) { Text(if (copied) "Copied ✓" else "Copy") }
        }
        if (copied) {
            CopiedNote(clearSeconds) { copied = false }
        }
    }
}

/** Cut J: the shared "Copied — clears in Ns" disclosure line (polite live region, ~3.5 s). */
@Composable
private fun CopiedNote(clearSeconds: Int, onExpire: () -> Unit) {
    Text(
        if (clearSeconds > 0) "Copied — clears from the clipboard in ${clearSeconds}s" else "Copied",
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    )
    LaunchedEffect(Unit) { delay(3500); onExpire() }
}

/** [display] lets the reveal show a formatted view (e.g. a grouped card number) while Copy
 *  still carries the bare stored [value]. */
@Composable
private fun SecretCopyRow(label: String, value: String, ctx: Context, clearSeconds: Int, display: String = value) {
    var show by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(if (show) display else "••••••••••", Modifier.weight(1f), fontFamily = FontFamily.Monospace)
            IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (show) "Hide $label" else "Show $label") }
            TextButton(onClick = { copyToClipboard(ctx, label, value, clearSeconds); copied = true }) { Text(if (copied) "Copied ✓" else "Copy") }
        }
        if (copied) {
            CopiedNote(clearSeconds) { copied = false }
        }
    }
}

/** Read-only expiry line with the "expired" marker — flagged strictly AFTER the last moment
 *  of the printed month (a card is good THROUGH it); absent/garbled halves never flag. */
@Composable
private fun ExpiryRow(label: String, expired: Boolean) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text("Expiry", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(label, fontFamily = FontFamily.Monospace)
            if (expired) {
                Spacer(Modifier.width(8.dp))
                Text("expired", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
            }
        }
    }
}

@Composable
private fun ReadOnlyRow(label: String, value: String) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value)
    }
}

@Composable
private fun ServerField(baseUrl: String, onSet: (String) -> Unit) {
    var url by remember(baseUrl) { mutableStateOf(baseUrl) }
    Column(Modifier.fillMaxWidth()) {
        OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("Server") }, singleLine = true,
            textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            trailingIcon = { if (url != baseUrl) TextButton(onClick = { onSet(url) }) { Text("Set") } })
    }
}

@Composable
private fun PrimaryButton(text: String, enabled: Boolean, busy: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, modifier = modifier.fillMaxWidth()) {
        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary) else Text(text)
    }
}

// ---- non-composable helpers ----

private const val DEFAULT_ATTACHMENT_MAX_BYTES = 25L * 1024 * 1024

private val attachmentJson = Json { ignoreUnknownKeys = true }

/** SavedState Saver for the editor's attachment list — JSON via the spec serializer so
 *  unknown-field extras survive the recreation round-trip too. Restore failures fall
 *  back to re-initialization (null) rather than crashing the restore. */
private val attachmentListSaver = listSaver<List<AttachmentRef>, String>(
    save = { list -> list.map { attachmentJson.encodeToString(AttachmentRef.serializer(), it) } },
    restore = { list -> runCatching { list.map { attachmentJson.decodeFromString(AttachmentRef.serializer(), it) } }.getOrNull() },
)

private fun needsUpdateLine(n: Int): String =
    if (n == 1) "1 item needs an app update to display." else "$n items need an app update to display."

private fun groupHex(hex: String): String = hex.chunked(4).joinToString(" ")

private fun humanSize(bytes: Long): String = when {
    bytes >= 1024L * 1024 * 1024 -> "%.1f GB".format(bytes / (1024.0 * 1024 * 1024))
    bytes >= 1024L * 1024 -> "%.1f MB".format(bytes / (1024.0 * 1024))
    bytes >= 1024L -> "%.1f KB".format(bytes / 1024.0)
    else -> "$bytes B"
}

private fun displayName(ctx: Context, uri: Uri): String {
    ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
        if (c.moveToFirst()) {
            val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (i >= 0) c.getString(i)?.let { return it }
        }
    }
    return uri.lastPathSegment ?: "file"
}

private fun copyToClipboard(ctx: Context, label: String, value: String, clearSeconds: Int) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    // <=0 is reserved for NON-secret setup material (e.g. the TOTP setup URI) — no auto-clear.
    // Vault-secret call sites always pass max(1, policy.clipboardClearSeconds), mirroring web.
    if (clearSeconds <= 0) {
        cm.setPrimaryClip(ClipData.newPlainText(label, value))
        return
    }
    // Secret copy: EXTRA_IS_SENSITIVE keeps the value out of the Android 13+ clipboard
    // preview overlay (and tells sync'd clipboards to leave it alone).
    val clip = ClipData.newPlainText(label, value)
    clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    cm.setPrimaryClip(clip)
    // Auto-clear after the policy window — ONLY when we can confirm the clipboard still
    // holds OUR secret. On API 29+ a backgrounded read returns null (and a non-text clip
    // reads null even in foreground), so a null read means "can't verify ownership" — NOT
    // "still ours". Clearing on null would silently wipe whatever the user copied from
    // another app after pasting (a URL, a 2FA code, an image). For the background case the
    // real mitigation is EXTRA_IS_SENSITIVE (set above), which lets the OS auto-expire and
    // hide the value on Android 13+; on older versions the secret may linger until
    // overwritten — a platform limitation we cannot fix without clobbering user data.
    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
        val cur = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (cur == value) runCatching { cm.clearPrimaryClip() }
    }, clearSeconds * 1000L)
}
