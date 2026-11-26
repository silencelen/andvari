package io.silencelen.andvari.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.os.PersistableBundle
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.client.Strength
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The one activity. Since the onboarding and trust overhaul it renders the new path only: the engine-backed
 * app API ([io.silencelen.andvari.app.trust.TrustSeam]) and its screens ([io.silencelen.andvari.app.trust.TrustApp]).
 * The old controller's screens and its router were deleted once their replacements landed; the old controller
 * ([AndvariViewModel]) stays for the autofill service, which keeps its own path, unreachable from here.
 */
class MainActivity : FragmentActivity() {
    private val model: io.silencelen.andvari.app.trust.TrustModel by lazy {
        io.silencelen.andvari.app.trust.TrustSeam.model(applicationContext)
    }

    /** True once the crash screen took over onCreate — the normal startup path never ran. Read by [onDestroy]. */
    private var crashScreenShown = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // If the previous run crashed, show the captured trace using a PLAIN Android view
        // (no Compose/theme), so even a crash in the Compose layer itself is still visible
        // to screenshot. Skips the (possibly still-crashing) normal startup path. H56: the
        // report lives in no_backup/ (out of Auto Backup and device transfer) and carries class
        // names + frames only — showing it screenshot-able is safe only in that scrubbed form.
        val crashFile = java.io.File(noBackupFilesDir, AndvariApplication.CRASH_FILE)
        if (crashFile.exists()) {
            val trace = runCatching { crashFile.readText() }.getOrDefault("(crash file unreadable)")
            crashScreenShown = true // the normal startup never ran on this path — see onDestroy
            showCrash(trace) { crashFile.delete(); recreate() }
            return
        }
        // Block Recents thumbnails / screen recording / casting from capturing revealed secrets (set AFTER the
        // crash-screen early return above: crash traces must stay screenshot-able). The new path has no exempt screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // Other apps' overlay windows are hidden while andvari is shown (API 31+), so none can
        // cover the Trust Gate's origin, the master password, the device-link digits or "Forget this server".
        if (android.os.Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        // No autofill service (andvari's own or another) is shown this window's fields; Compose
        // past 1.7 exposes text fields to whichever service is selected.
        window.decorView.importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        // §12.4: the first-launch wipe runs inside start(), before any screen. Idempotent: a later onCreate of the
        // same process finds the app already started.
        io.silencelen.andvari.app.trust.isDebugBuild = (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        // Quick unlock's prompt is shown over this activity (the engine's PlatformKeyWrap must know it).
        io.silencelen.andvari.app.trust.TrustSeam.keyWrap(applicationContext).attach(this)
        model.start()
        // Note 11: the launch intent's link is taken once. A task reopened from Recents (or an activity restored after
        // the process died) carries the same old intent, and must not open the old link again.
        launchLink(intent?.dataString, restored = savedInstanceState != null, fromHistory = ((intent?.flags ?: 0) and android.content.Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0)
            ?.let(model::openLink)
        // R17: the activity's RESUMED entry is the only foreground hook a dialog-style picker fires.
        lifecycleScope.launch { repeatOnLifecycle(Lifecycle.State.RESUMED) { ExternalExcursion.clear() } }
        // The idle auto-lock window (spec 01 §8): the app's to run (IF-3 AppApi.lock), and a kit's own limit, its warning
        // and the end of the screen-on hold. Ticks while the activity is visible (started), the focus or not: beside
        // another app in split screen, under another app's dialog. A backgrounded app has already locked (TrustApp's
        // process observer).
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (true) {
                    model.tick()
                    delay(1_000)
                }
            }
        }
        setContent { AndvariTheme { io.silencelen.andvari.app.trust.TrustApp(model) } }
    }

    /**
     * §12.1: a tapped `https://andvaripass.com/l` link reaching the running activity. The manifest's filter takes `/l`
     * only; the model drops anything else and keeps the link until a person can see what it opens.
     */
    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (!crashScreenShown) intent.dataString?.let(model::openLink)
    }

    // Any user interaction resets the inactivity auto-lock window (spec 01 §8: activity =
    // pointer/key/touch, nothing else). Dispatch overrides see every event before Compose.
    override fun dispatchTouchEvent(ev: MotionEvent?): Boolean {
        if (!crashScreenShown) model.touched()
        return super.dispatchTouchEvent(ev)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (!crashScreenShown) model.touched()
        return super.dispatchKeyEvent(event)
    }

    override fun dispatchGenericMotionEvent(ev: MotionEvent?): Boolean {
        if (!crashScreenShown) model.touched() // mouse wheel / rotary / hover-scroll on tablets & ChromeOS
        return super.dispatchGenericMotionEvent(ev)
    }

    /**
     * The Back-button hole in lock-on-background (leaving by Back could leave the vault open), kept for the new path: a FINISHING activity
     * can be destroyed inside ProcessLifecycleOwner's 700 ms ON_STOP delay, so the composition's observer never hears
     * the stop. Locking here closes that hole. Never on the crash-screen path, where the app was never started.
     */
    override fun onDestroy() {
        if (isFinishing && !crashScreenShown) model.backgrounded()
        if (!crashScreenShown) io.silencelen.andvari.app.trust.TrustSeam.keyWrap(applicationContext).detach(this)
        super.onDestroy()
    }

    /** Deliberately uses only android.widget — no Compose — so a Compose crash still renders. */
    private fun showCrash(trace: String, onClear: () -> Unit) {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setBackgroundColor(0xFF14120E.toInt())
            setPadding(pad, pad, pad, pad)
            // Cut F review: this plain-View fallback bypasses the Compose tree's safe-drawing insets —
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

// The old controller's screens (AndvariApp and its Screen router, the attention area, the vault list, item detail and
// editor, trash, settings, import and export dialogs, and their helpers) were deleted in the overhaul: the new path's
// screens in trust/ replace them. What follows is shared with the new path.

/**
 * The width the pre-unlock family is allowed to grow to (audit 2026-09-13 H129).
 *
 * Web caps its auth card at 440px inside a centring shell and desktop bounds its whole tree at
 * 760dp (its Cut I note: "a maximized window stretched every field … edge-to-edge"). Android had
 * no cap at all: every screen before the vault opens was a `fillMaxSize().padding(24.dp)` column
 * of `fillMaxWidth` fields, and the manifest handles the fold posture in-process, so the SAME
 * composable renders on a 6.2" cover screen and a ~7.6" inner display. Unfolded, the sign-in and
 * master-password fields became a single ~800dp line of input with the button under it, and the
 * recovery-phrase type-back — already a transcription task — became one very long line to track
 * across. Legible, but visibly un-designed beside the web card, on the owner's own device.
 *
 * 480dp (owner decision), a little wider than web's 440px because a Compose text field carries its
 * own inset and the phrase field wants the room. Applied to the PRE-UNLOCK family only: the vault
 * list, health and settings are list surfaces that genuinely use a tablet's width.
 *
 * **This is the house cap for BOTH natives** (R18): desktop declares the same 480dp literal at
 * `Ui.kt`'s `AUTH_MAX_WIDTH` and applies it with the same top-centred shell, and
 * `app-desktop`'s `SurfacePinsTest` reads THIS declaration to keep the two numbers identical.
 * Changing it here without changing desktop turns "the auth cap" back into two opinions.
 */
private val AUTH_MAX_WIDTH = 480.dp

/**
 * The shared shell for that family (H129) — a full-bleed, scrollable, top-CENTRED column capped at
 * [AUTH_MAX_WIDTH].
 *
 * Scrollable is not optional here and predates the cap (Cut F, v2 #5): a centred fixed column left
 * the Unlock button unreachable with the IME open in landscape, split-screen and half-fold. The
 * min-height constraint survives the scroll modifier, which is what still lets
 * [verticalArrangement] centre a short form vertically inside the viewport.
 */
@Composable
internal fun AuthColumn(
    verticalArrangement: Arrangement.Vertical = Arrangement.Top,
    horizontalAlignment: Alignment.Horizontal = Alignment.Start,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            Modifier.widthIn(max = AUTH_MAX_WIDTH).fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = verticalArrangement,
            horizontalAlignment = horizontalAlignment,
            content = content,
        )
    }
}

@Composable
internal fun Centered(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally, content = content)
}

@Composable
internal fun Sigil() {
    // The brand's rune and the drawn name (Theme.kt BrandSigil and Wordmark), as geometry: the raw ᛅ codepoint
    // rendered as a tofu box wherever no installed font covers the Runic block, and no font ships for the name. The
    // name takes the size of the title text it stands in for.
    SigilMark(BrandSigil, 46.dp)
    Spacer(Modifier.height(4.dp))
    Wordmark(MaterialTheme.typography.titleLarge.fontSize)
    Text("the keeper of the hoard", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** The F60 master-password floor feedback — strength label, the too-weak refusal, the F31
 *  pattern caveat, and the non-ASCII caution. ONE copy for every form that chooses a master
 *  password. Renders nothing while the field is empty. */
@Composable
internal fun MasterPasswordStrengthHints(password: String) {
    if (password.isEmpty()) return
    val score = Strength.estimateStrength(password)
    // F31: the pattern penalty is already inside `score`, but a bare "strength: good" beside a
    // doubled block still reads as an endorsement of the block — the estimate and the caveat
    // contradicted each other on screen. Where the collapse cost a score, the label says so and
    // the shared sentence below explains WHY; the affirmative (uncaveated) line is reserved for
    // passwords that earn it. It never gates: the floor is [Strength.meetsMasterPasswordFloor].
    val pattern = Strength.patternWarning(password)
    when {
        !Strength.meetsMasterPasswordFloor(password) ->
            Text("Too weak for a master password (${Strength.label(score)}) — mix length with upper/lower case, digits, or symbols.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        pattern != null ->
            Text("strength: ${Strength.label(score)} — weaker than it looks", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
        else ->
            Text("strength: ${Strength.label(score)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    if (pattern != null) {
        Text(pattern, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
    }
    if (Strength.masterPasswordHasNonAscii(password)) {
        Text("contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
    }
}

/** The launch intent's link, taken only on a fresh launch: never when restored or reopened from Recents (note 11). */
internal fun launchLink(dataString: String?, restored: Boolean, fromHistory: Boolean): String? =
    dataString?.takeIf { !restored && !fromHistory }

/** The one spelling of "which build is this". */
internal val VERSION_LINE = "andvari $ANDVARI_CLIENT_VERSION · android"

/** The IME action a field actually declares. Pure so the multi-line drop and the
 *  "onDone implies Done" contract are unit-testable. */
internal fun imeActionFor(singleLine: Boolean, imeAction: ImeAction, onDone: (() -> Unit)?): ImeAction = when {
    !singleLine -> ImeAction.Default
    imeAction != ImeAction.Default -> imeAction
    onDone != null -> ImeAction.Done
    else -> ImeAction.Default
}

/** The masked secret field (the master password's, and every other secret's): hidden until the person shows it.
 *  [revealed] hoists the reveal toggle for callers that must force it open (the editor's Generate
 *  shows what will be saved — web F78 parity); null keeps the toggle field-local. */
@Composable
internal fun SecretField(
    label: String,
    value: String,
    imeAction: ImeAction = ImeAction.Default,
    onDone: (() -> Unit)? = null,
    revealed: MutableState<Boolean>? = null,
    digits: Boolean = false,
    onChange: (String) -> Unit,
) {
    val showState = revealed ?: remember { mutableStateOf(false) }
    val show = showState.value
    val effAction = imeActionFor(singleLine = true, imeAction = imeAction, onDone = onDone)
    OutlinedTextField(value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp), label = { Text(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        // Cut E (v2 #4): a masking transformation alone does NOT tell the IME the field is a
        // secret — without KeyboardType.Password the keyboard's suggestion strip and personal
        // dictionary learn master passwords, item passwords, and backup passphrases. [digits]
        // (a card's number and code) keeps that promise with the secret number pad.
        keyboardOptions = KeyboardOptions(keyboardType = if (digits) KeyboardType.NumberPassword else KeyboardType.Password, autoCorrectEnabled = false, imeAction = effAction),
        keyboardActions = KeyboardActions(onDone = if (effAction == ImeAction.Done && onDone != null) ({ onDone() }) else null),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = { IconButton(onClick = { showState.value = !show }) { Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (show) "Hide $label" else "Show $label") } })
}

@Composable
internal fun PrimaryButton(text: String, enabled: Boolean, busy: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    Button(onClick = onClick, enabled = enabled, modifier = modifier.fillMaxWidth()) {
        // a11yand-08 (the desktop a11ydesk-08 twin): while busy the label is replaced by a bare
        // spinner — name the spinner with the button's text (+ "working" state) so a screen reader
        // still announces the action instead of an unlabeled button.
        if (busy) CircularProgressIndicator(Modifier.size(18.dp).semantics { contentDescription = text; stateDescription = "working" }, strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary) else Text(text)
    }
}

// ---- the clipboard ----

/**
 * Copy [value]; a secret ([clearSeconds] > 0) is marked sensitive and cleared after [clearSeconds] whether or not
 * andvari is in front then ([ClipboardClear]). ux-parity--5 still holds: only the NEWEST copy owns the clear,
 * so a first copy's timer never wipes the window a second copy just disclosed.
 */
internal fun copyToClipboard(ctx: Context, label: String, value: String, clearSeconds: Int) {
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
    // The clear runs in front or not, from a timer that survives a lock and a background stay (and an
    // alarm for a process the system ended); in the background it clears without reading the clipboard.
    ClipboardClear.scheduled(ctx, cm, value, clearSeconds * 1000L)
}
