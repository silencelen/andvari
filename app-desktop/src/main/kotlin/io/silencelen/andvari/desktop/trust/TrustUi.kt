package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.VerticalScrollbar
import androidx.compose.foundation.border
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.width
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.rememberScrollbarAdapter
import androidx.compose.ui.unit.Dp
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ButtonDefaults
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.foundation.focusable
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.desktop.BrandRune
import io.silencelen.andvari.desktop.Wordmark

// The small pieces every screen of the new path is made of, in the desktop's existing visual language (Material 3
// with the andvari treasury theme, the old app's 480 dp auth column, its Enter-to-submit fields). No accent bars;
// state marks in the app's own quiet tones.

/** The house cap for the signed-out family: the same 480 dp as the old desktop's `AUTH_MAX_WIDTH` and Android's. */
internal val TRUST_AUTH_MAX_WIDTH = 480.dp

/** A signed-out (or lock, or kit) screen: top-centred, capped at [TRUST_AUTH_MAX_WIDTH], scrolling when tall. */
@Composable
internal fun AuthColumn(
    verticalArrangement: Arrangement.Vertical = Arrangement.Top,
    horizontalAlignment: Alignment.Horizontal = Alignment.Start,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            // The current app's sign-in margin.
            Modifier.widthIn(max = TRUST_AUTH_MAX_WIDTH).fillMaxSize().verticalScroll(rememberScrollState()).padding(28.dp),
            verticalArrangement = verticalArrangement,
            horizontalAlignment = horizontalAlignment,
            content = content,
        )
    }
}

@Composable
internal fun Centered(content: @Composable ColumnScope.() -> Unit) =
    Column(Modifier.fillMaxSize(), verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally, content = content)

/**
 * The brand mark, the name and the line under it, as the desktop app's sign-in and lock screens show them. The name is
 * the drawing ([Wordmark]) at the size of the title text it stands in for; the line stays text.
 */
@Composable
internal fun Sigil() {
    BrandRune()
    Wordmark(MaterialTheme.typography.titleLarge.fontSize)
    Text(BRAND_LINE, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/** The brand head over a left-aligned sign-in screen, centred, as the current app's sign-in opens. */
@Composable
internal fun BrandHead() {
    Column(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 20.dp), horizontalAlignment = Alignment.CenterHorizontally) { Sigil() }
}

/** The line under the name, carried over word for word from the current desktop app. */
internal const val BRAND_LINE = "the keeper of the hoard"

/**
 * The head of a window that stands alone, as the current desktop app draws its recovery window: the brand mark, the
 * window's own title in the large style, and quiet lines under it (the server it is about, a line of its own), all
 * centred over a left-aligned form.
 */
@Composable
internal fun WindowHead(title: UiText?, instance: InstanceLabel? = null, line: UiText? = null) {
    Column(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        BrandRune()
        title?.let { Say(it, Modifier.fillMaxWidth(), MaterialTheme.typography.titleLarge.copy(textAlign = TextAlign.Center)) }
        instance?.let { QuietInstance(it) }
        line?.let { Say(it, Modifier.fillMaxWidth().padding(top = 4.dp), MaterialTheme.typography.bodySmall.copy(textAlign = TextAlign.Center), MaterialTheme.colorScheme.onSurfaceVariant) }
    }
}

/** An instance named quietly under a head, centred: its name, its origin beside it always (§4.4), the self-named mark. */
@Composable
internal fun QuietInstance(label: InstanceLabel) {
    val tone = MaterialTheme.colorScheme.onSurfaceVariant
    val centred = MaterialTheme.typography.bodyMedium.copy(textAlign = TextAlign.Center)
    if (label.name.isNotEmpty()) Text(label.name, Modifier.fillMaxWidth(), color = tone, style = centred)
    Text(label.origin, Modifier.fillMaxWidth(), color = tone, style = centred.copy(fontFamily = FontFamily.Monospace))
    if (label.selfNamed) Say(CopyKey.AS_THE_SERVER_NAMES_ITSELF, Modifier.fillMaxWidth(), MaterialTheme.typography.bodySmall.copy(textAlign = TextAlign.Center), tone)
}

/**
 * The current app's card for something to write down or read out (its recovery phrase card): the surface-variant
 * container with a 16 dp margin. Nothing at its edge marks a state.
 */
@Composable
internal fun CodeCard(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), content = content)
    }
}

/**
 * The current app's gate buttons: the way out as a text button first (so the focus reaches it before the action), then
 * the filled action taking the rest of the row.
 */
@Composable
internal fun WayOutThenMain(wayOut: UiText, wayOutEnabled: Boolean, onWayOut: () -> Unit, main: UiText, enabled: Boolean, busy: Boolean, onMain: () -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Quieter(wayOut, enabled = wayOutEnabled, onClick = onWayOut)
        Spacer(Modifier.width(8.dp))
        Box(Modifier.weight(1f)) { Main(main, enabled = enabled, busy = busy, onClick = onMain) }
    }
}

/**
 * Where a test can see the focus walk: each control with a focus mark adds its words here when the focus reaches it.
 * Null (nothing kept) everywhere but in a test.
 */
internal val LocalFocusLog = staticCompositionLocalOf<MutableList<String>?> { null }

/**
 * The visible focus mark of every control of the path: a 2 dp outline in the text tone around the control while the
 * keyboard's focus is on it (Material's own focus tint is too faint to follow on a filled or a text button). Returns the
 * source to hand to the control, and the modifier that draws the mark.
 */
@Composable
internal fun focusMark(words: String, shape: Shape = ButtonDefaults.shape): Pair<MutableInteractionSource, Modifier> {
    val source = remember { MutableInteractionSource() }
    // The focus as the focus system itself reports it, at the moment it moves: not the control's interaction stream,
    // which only a coroutine started after the control was composed listens to, and which drops what came before it
    // listened; and not an effect run after a later frame, which a quick second Tab cancels before it ran. Through
    // either, a control composed a moment ago (an operator's account panel just opened) could take the focus and show
    // no mark, and the walk below missed it once on a loaded machine.
    var focused by remember { mutableStateOf(false) }
    val log = LocalFocusLog.current
    val seen = Modifier.onFocusChanged { f ->
        if (f.isFocused && !focused) log?.add(words)
        focused = f.isFocused
    }
    val mark = if (focused) seen.border(FOCUS_MARK_WIDTH, MaterialTheme.colorScheme.onSurface, shape) else seen
    return source to mark
}

/** The width of the focus mark. */
internal val FOCUS_MARK_WIDTH = 2.dp

/**
 * A kit's idle warning line. Compose for desktop hands no live region to the platform's accessibility, so the line is
 * not announced by a mark. Where the window has the focus when the line comes, the line takes the keyboard's focus,
 * which the toolkit reports to assistive technology (a screen reader reads a control that gains the focus); nothing is
 * being typed then, as the warning comes only after the whole idle time. Once each time the line comes: a click or a
 * key puts it away, and the next warning takes the focus again. The operating system's own signals (the taskbar, the
 * alert sound) come from the model ([KitWarningSignal]).
 */
@Composable
internal fun KitIdleWarningLine(text: UiText) {
    val (_, mark) = focusMark(text.shown(), RectangleShape)
    val requester = remember { FocusRequester() }
    val windowFocused = LocalWindowInfo.current.isWindowFocused
    Say(text, Modifier.fillMaxWidth().then(mark).focusRequester(requester).focusable(), color = MaterialTheme.colorScheme.error)
    LaunchedEffect(Unit) { if (windowFocused) requester.requestFocus() }
}

/** Text of the new path. A placeholder is italic, in the tertiary tone, and bracketed, so it reads as unfinished. */
@Composable
internal fun Say(
    text: UiText,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
    color: Color = Color.Unspecified,
) {
    if (text.isPlaceholder) {
        Text(text.shown(), modifier, style = style.copy(fontStyle = FontStyle.Italic), color = MaterialTheme.colorScheme.tertiary)
    } else {
        Text(text.shown(), modifier, style = style, color = color)
    }
}

@Composable
internal fun Say(key: CopyKey, modifier: Modifier = Modifier, style: TextStyle = MaterialTheme.typography.bodyMedium, color: Color = Color.Unspecified) =
    Say(UiText.of(key), modifier, style, color)

@Composable
internal fun Say(line: CopyLine, modifier: Modifier = Modifier, style: TextStyle = MaterialTheme.typography.bodyMedium, color: Color = Color.Unspecified) =
    Say(UiText.of(line), modifier, style, color)

@Composable
internal fun Say(p: Placeholder, vararg args: String, style: TextStyle = MaterialTheme.typography.bodyMedium) =
    Say(UiText.Ph(p, args.toList()), style = style)

@Composable
internal fun Title(text: UiText) = Say(text, Modifier.padding(bottom = 8.dp), MaterialTheme.typography.titleLarge)

@Composable
internal fun Quiet(text: UiText) = Say(text, Modifier.padding(vertical = 4.dp), MaterialTheme.typography.bodySmall, MaterialTheme.colorScheme.onSurfaceVariant)

/** An origin, always whole and monospaced (§4.4: never a display name alone). */
@Composable
internal fun Origin(origin: String, style: TextStyle = MaterialTheme.typography.bodyMedium) =
    Text(origin, style = style.copy(fontFamily = FontFamily.Monospace))

/** [line] with the last [origin] in it monospaced, as an origin is everywhere; the words are unchanged. */
internal fun monospacedOrigin(line: String, origin: String): AnnotatedString = buildAnnotatedString {
    append(line)
    val at = line.lastIndexOf(origin)
    if (origin.isNotEmpty() && at >= 0) addStyle(SpanStyle(fontFamily = FontFamily.Monospace), at, at + origin.length)
}

/**
 * An instance as the design names it (§4.4, T-R8): the card's name with its origin beside it, always, and the
 * self-named mark where nobody but the server vouches for the name.
 */
@Composable
internal fun InstanceName(label: InstanceLabel, style: TextStyle = MaterialTheme.typography.titleMedium, centered: Boolean = false) {
    // Centred under a centred head (the lock screen), as the current app centres what it names there.
    val place = if (centered) Modifier.fillMaxWidth() else Modifier
    Column(place.padding(vertical = 4.dp), horizontalAlignment = if (centered) Alignment.CenterHorizontally else Alignment.Start) {
        if (label.name.isNotEmpty()) Text(label.name, style = style)
        Origin(label.origin)
        if (label.selfNamed) Say(CopyKey.AS_THE_SERVER_NAMES_ITSELF, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/**
 * The name a screen reader says for the eye button beside a secret ([shown]: the field is shown, so it hides): the
 * field's name is part of it, on a key of its own, so it is not dropped once "Show" and "Hide" hold their words.
 */
internal fun eyeButtonName(shown: Boolean, field: UiText): UiText =
    UiText.ph(if (shown) Placeholder.HIDE_FIELD_NAMED else Placeholder.SHOW_FIELD_NAMED, field.shown())

/**
 * What the last intent answered on this screen, in place (polite live region). A refusal because another account is
 * kept here names that account and offers to sign it out ([KeptAccountRefusal]).
 */
@Composable
internal fun SaidHere(model: TrustModel, s: AppSnapshot) {
    // Read the state here, so a new answer recomposes this very place: a screen whose own inputs did not change (the
    // lock screen, when a lock overtook work and said so after the screen was drawn) is otherwise skipped, and the
    // sentence would wait for the next keystroke there (found in a run against a local server).
    model.said.collectAsState().value
    val said = saidDrawn(model, s)
    if (said != null) {
        // A refusal with a way out on this computer (the kept account's sign-out, the removal of a damaged copy) offers it,
        // except while a kit this computer did not keep is on show: that would go with the sign-out unsaid.
        val way = wayOutOf(said.result, said.text, s)
        if (way != null) KeptAccountRefusal(model, s, way, offered = !showsNotKeptKit(s)) else ErrorBar(said.text) { model.clearSaid() }
    }
    // Under the refused answer's line: "Forget the earlier account on this device", where the shared code offers it on this screen.
    EarlierAccountOffer(model, s)
}

/**
 * The answer [SaidHere] draws: none where it is a result without wording and the shared code's offer to forget an earlier
 * account stands on the screen, since the offer's own lines say the refusal ([EarlierAccountOffer]).
 */
internal fun saidDrawn(model: TrustModel, s: AppSnapshot): TrustModel.Said? =
    model.saidOn(s)?.takeUnless { s.earlierAccount != null && (it.text as? UiText.Ph)?.placeholder == Placeholder.REFUSAL }

/**
 * The current desktop app's error bar: a card in the error container with the sentence and "dismiss" in its own tone
 * (the readable pair; the plain error tone on that container is not). It is marked as an assertive live region, which
 * this version of Compose for desktop hands to no platform's accessibility: nothing announces it.
 */
@Composable
internal fun ErrorBar(text: UiText, onDismiss: () -> Unit) {
    val tone = MaterialTheme.colorScheme.onErrorContainer
    Card(
        Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Assertive },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            // A placeholder keeps its italics and brackets, in the bar's own tone so it can be read there.
            val style = MaterialTheme.typography.bodySmall.let { if (text.isPlaceholder) it.copy(fontStyle = FontStyle.Italic) else it }
            Text(text.shown(), Modifier.weight(1f), style = style, color = tone)
            TextButton(onClick = guarded(onClick = onDismiss), colors = ButtonDefaults.textButtonColors(contentColor = tone)) {
                Text(UiText.ph(Placeholder.DISMISS).shown(), style = MaterialTheme.typography.labelLarge.copy(fontStyle = FontStyle.Italic))
            }
        }
    }
}

/**
 * The current desktop app's notice bar: a card in the surface's own tone with the sentence in the secondary tone and
 * "dismiss", marked as a polite live region (which, as for [ErrorBar], nothing on the desktop announces). Never for a
 * warning: that is the [ErrorBar].
 */
@Composable
internal fun NoticeBar(text: UiText, onDismiss: () -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Polite }) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            val style = MaterialTheme.typography.bodySmall.let { if (text.isPlaceholder) it.copy(fontStyle = FontStyle.Italic) else it }
            Text(text.shown(), Modifier.weight(1f), style = style, color = MaterialTheme.colorScheme.secondary)
            TextButton(onClick = guarded(onClick = onDismiss), colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.onSurfaceVariant)) {
                Text(UiText.ph(Placeholder.DISMISS).shown(), style = MaterialTheme.typography.labelLarge.copy(fontStyle = FontStyle.Italic))
            }
        }
    }
}

/** The screen's main action: filled, full width, a named spinner while busy (the old desktop's `Primary`). */
@Composable
internal fun Main(text: UiText, enabled: Boolean, busy: Boolean, onClick: () -> Unit) {
    // Every control of the path is guarded: what the shared code throws in its click is said in place.
    val (source, mark) = focusMark(text.shown())
    Button(onClick = guarded(onClick = onClick), enabled = enabled, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).then(mark), interactionSource = source) {
        if (busy) {
            CircularProgressIndicator(
                Modifier.size(18.dp).semantics { contentDescription = text.shown(); stateDescription = "working" },
                strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary,
                // A faint full ring under the arc, as the opening page's: a still frame caught it as a dot on the
                // unlock button (seen on the virtual display).
                trackColor = LocalContentColor.current.copy(alpha = 0.3f),
            )
        } else if (text.isPlaceholder) {
            // On the filled button a placeholder keeps its italics and brackets but takes the button's own content tone:
            // the tertiary green on gold could not be read (the first run under a virtual display).
            Text(text.shown(), style = MaterialTheme.typography.bodyMedium.copy(fontStyle = FontStyle.Italic), color = LocalContentColor.current)
        } else {
            Say(text)
        }
    }
}

/**
 * A group of buttons side by side that wraps onto the next line when the window is narrow. A plain Row squeezed the
 * last button into a column one letter wide at the window's 480 dp (the first run under a virtual display).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun Actions(content: @Composable () -> Unit) =
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) { content() }

@Composable
internal fun Second(text: UiText, enabled: Boolean = true, onClick: () -> Unit) {
    val (source, mark) = focusMark(text.shown())
    OutlinedButton(onClick = guarded(onClick = onClick), enabled = enabled, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp).then(mark), interactionSource = source) { Say(text) }
}

@Composable
internal fun Quieter(text: UiText, enabled: Boolean = true, onClick: () -> Unit) {
    val (source, mark) = focusMark(text.shown())
    TextButton(onClick = guarded(onClick = onClick), enabled = enabled, modifier = mark, interactionSource = source) { Say(text) }
}

/** A dialog's text button (its way out, its confirm), with the focus mark every control of the path has. */
@Composable
internal fun DialogButton(text: UiText, enabled: Boolean = true, onClick: () -> Unit) {
    val (source, mark) = focusMark(text.shown())
    TextButton(onClick = guarded(onClick = onClick), enabled = enabled, modifier = mark, interactionSource = source) { Say(text) }
}

/** Enter (key-down) in the field runs [submit], as the old desktop's fields did. */
internal fun Modifier.submitOnEnter(submit: (() -> Unit)?): Modifier =
    if (submit == null) this else onPreviewKeyEvent { e ->
        if (e.type == KeyEventType.KeyDown && (e.key == Key.Enter || e.key == Key.NumPadEnter)) { submit(); true } else false
    }

/** The notes editor's height in lines (it grows past it). */
internal const val NOTES_LINES = 4

/**
 * A field: one line unless [lines] asks for more, when Enter makes a new line (and [onEnter] must be null). Nothing is
 * focused by itself: the first screen's rule (§12.1) holds on every screen of the path.
 */
@Composable
internal fun Field(
    label: UiText, value: String, mono: Boolean = false, onEnter: (() -> Unit)? = null, lines: Int = 1, maxLines: Int = Int.MAX_VALUE,
    modifier: Modifier = Modifier,
    onChange: (String) -> Unit,
) {
    val enter = onEnter?.let { guarded(onClick = it) }
    OutlinedTextField(
        value, guardedChange(onChange = onChange), modifier.fillMaxWidth().padding(vertical = 4.dp).submitOnEnter(if (lines > 1) null else enter),
        label = { Say(label) }, singleLine = lines == 1, minLines = lines, maxLines = if (lines == 1) 1 else maxOf(lines, maxLines),
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium,
    )
}

/**
 * A field a recovery kit's groups are typed back into ([Field], monospaced): what is typed there cannot be copied out of
 * it. Ctrl+C, Ctrl+X, Ctrl+Insert and Shift+Delete do nothing ([isCopyOrCut]); the field's context menu offers no Copy and
 * no Cut ([withoutCopyOrCut]); and should anything in the field still ask for a copy, the clipboard it is given takes
 * nothing ([TakesNoCopy]). Typing, pasting and selecting work as in any field. (The check of 2026-11-18: three groups the
 * person typed could be copied, and stayed on the clipboard after the lock took the kit.)
 */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
internal fun KitGroupField(label: UiText, value: String, onEnter: (() -> Unit)? = null, onChange: (String) -> Unit) {
    val board = androidx.compose.ui.platform.LocalClipboardManager.current
    val menu = androidx.compose.foundation.text.LocalTextContextMenu.current
    val noCopy = remember(board) { TakesNoCopy(board) }
    val noCopyMenu = remember(menu) { withoutCopyOrCut(menu) }
    androidx.compose.runtime.CompositionLocalProvider(
        androidx.compose.ui.platform.LocalClipboardManager provides noCopy,
        androidx.compose.foundation.text.LocalTextContextMenu provides noCopyMenu,
    ) {
        Field(label, value, mono = true, onEnter = onEnter, modifier = Modifier.onPreviewKeyEvent { isCopyOrCut(it) }, onChange = onChange)
    }
}

/** A copy or a cut by the keyboard, as Compose's text fields read them on every platform (Ctrl or ⌘ with C or X, Ctrl+Insert, Shift+Delete). */
internal fun isCopyOrCut(e: androidx.compose.ui.input.key.KeyEvent): Boolean =
    isCopyOrCut(e.key, e.isCtrlPressed, e.isMetaPressed, e.isShiftPressed)

internal fun isCopyOrCut(key: Key, ctrl: Boolean, meta: Boolean, shift: Boolean): Boolean =
    ((ctrl || meta) && (key == Key.C || key == Key.X || key == Key.Insert)) || (shift && key == Key.Delete) || key == Key.Copy || key == Key.Cut

/** The clipboard as a kit's group field sees it: a copy puts nothing there; a paste reads it as usual. */
internal class TakesNoCopy(private val base: androidx.compose.ui.platform.ClipboardManager) : androidx.compose.ui.platform.ClipboardManager {
    override fun setText(annotatedString: AnnotatedString) {}

    override fun getText(): AnnotatedString? = base.getText()

    override fun hasText(): Boolean = base.hasText()
}

/** [menu] with no Copy and no Cut: the text manager it is handed drops both; Paste and Select all stay. */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
internal fun withoutCopyOrCut(menu: androidx.compose.foundation.text.TextContextMenu): androidx.compose.foundation.text.TextContextMenu =
    object : androidx.compose.foundation.text.TextContextMenu {
        @Composable
        override fun Area(
            textManager: androidx.compose.foundation.text.TextContextMenu.TextManager,
            state: androidx.compose.foundation.ContextMenuState,
            content: @Composable () -> Unit,
        ) = menu.Area(noCopyOrCut(textManager), state, content)
    }

/** [manager] without its copy and cut. */
@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
internal fun noCopyOrCut(manager: androidx.compose.foundation.text.TextContextMenu.TextManager): androidx.compose.foundation.text.TextContextMenu.TextManager =
    object : androidx.compose.foundation.text.TextContextMenu.TextManager by manager {
        override val cut: (() -> Unit)? get() = null
        override val copy: (() -> Unit)? get() = null
    }

/**
 * A secret field: hidden until its own toggle shows it; the toggle names the field it belongs to. [revealed], when
 * given, is the shown state's holder, so a caller can show what it filled in (the generator).
 */
/**
 * Design point 6 (§4.4): the line above every field that asks for the master password, naming the account, the
 * instance and its origin ([CopyKey.MASTER_PASSWORD_FOR]). Null only before any instance is on show, which no signed-in
 * prompt is; the field then still names nothing it does not know.
 */
internal fun masterPasswordFor(s: AppSnapshot): UiText? {
    val label = s.instance?.label ?: return null
    return UiText.Plain(fillCopy(CopyKey.MASTER_PASSWORD_FOR, s.account?.email.orEmpty(), label.name, label.origin))
}

/** The master-password field of a signed-in prompt, with the line that names whose password it is ([masterPasswordFor]). */
@Composable
internal fun MasterPasswordField(s: AppSnapshot, value: String, onEnter: (() -> Unit)? = null, onChange: (String) -> Unit) {
    masterPasswordFor(s)?.let { Say(it, style = MaterialTheme.typography.bodySmall) }
    SecretField(UiText.ph(Placeholder.PASSWORD_FIELD), value, onEnter = onEnter, onChange = onChange)
}

@Composable
internal fun SecretField(
    label: UiText,
    value: String,
    onEnter: (() -> Unit)? = null,
    revealed: MutableState<Boolean>? = null,
    onChange: (String) -> Unit,
) {
    val own = remember { mutableStateOf(false) }
    var show by (revealed ?: own)
    val enter = onEnter?.let { guarded(onClick = it) }
    OutlinedTextField(
        value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp).submitOnEnter(enter),
        label = { Say(label) }, singleLine = true,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        trailingIcon = {
            IconButton(onClick = { show = !show }) {
                Icon(
                    if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    eyeButtonName(show, label).shown(),
                )
            }
        },
    )
}

@Composable
internal fun Tick(label: UiText, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    val (source, mark) = focusMark(label.shown(), MaterialTheme.shapes.small)
    Row(
        Modifier.fillMaxWidth().then(mark).toggleable(checked, source, LocalIndication.current, enabled = enabled, role = Role.Checkbox, onValueChange = guardedChange(onChange = onChange)).padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked, onCheckedChange = null, enabled = enabled)
        Say(label, Modifier.padding(start = 8.dp))
    }
}

@Composable
internal fun Choice(label: UiText, detail: UiText, selected: Boolean, enabled: Boolean, onSelect: () -> Unit) {
    val (source, mark) = focusMark(label.shown(), MaterialTheme.shapes.small)
    Row(
        Modifier.fillMaxWidth().then(mark).selectable(selected, source, LocalIndication.current, enabled = enabled, role = Role.RadioButton, onClick = guarded(onClick = onSelect)).padding(vertical = 6.dp),
        verticalAlignment = Alignment.Top,
    ) {
        RadioButton(selected, onClick = null, enabled = enabled)
        Column(Modifier.padding(start = 8.dp)) {
            Say(label)
            Say(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/**
 * The old desktop's strength line under a new master password, carried over word for word (it never gates; the floor
 * is core's [Strength.meetsMasterPasswordFloor]). In a slot of a fixed height, empty or not, so the field under it
 * does not move while the first one is typed in.
 */
@Composable
internal fun MasterPasswordStrengthHints(password: String) {
    FixedSlot(STRENGTH_SLOT) { StrengthLines(password) }
}

@Composable
private fun StrengthLines(password: String) {
    if (password.isEmpty()) return
    val score = Strength.estimateStrength(password)
    val pattern = Strength.patternWarning(password)
    when {
        !Strength.meetsMasterPasswordFloor(password) ->
            Text("Too weak for a master password (${Strength.label(score)}) — mix length with upper/lower case, digits, or symbols.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        pattern != null ->
            Text("strength: ${Strength.label(score)} — weaker than it looks", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
        else ->
            Text("strength: ${Strength.label(score)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
    if (pattern != null) Text(pattern, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
    if (Strength.masterPasswordHasNonAscii(password)) {
        Text("contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
    }
}

@Composable
internal fun Gap(h: Int = 12) = Spacer(Modifier.height(h.dp))

/**
 * The head of a page of its own, as the current desktop app draws Settings, Sharing and the trash: "back" with its arrow,
 * then the page's name as a large heading.
 */
@Composable
internal fun PageHeader(title: UiText, enabled: Boolean = true, onBack: () -> Unit) {
    val (source, mark) = focusMark(UiText.ph(Placeholder.BACK).shown())
    TextButton(onClick = guarded(onClick = onBack), enabled = enabled, modifier = mark, interactionSource = source) {
        Icon(Icons.AutoMirrored.Filled.ArrowBack, null)
        Say(UiText.ph(Placeholder.BACK), Modifier.padding(start = 4.dp))
    }
    Say(title, Modifier.padding(bottom = 8.dp), MaterialTheme.typography.headlineMedium)
}

/**
 * One section of a page, as the current desktop app draws each part of Settings and Sharing: a card of the page's
 * width, its content inside a 16 dp margin, and 16 dp before the next. Nothing at its edge marks a state.
 */
@Composable
internal fun SectionCard(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.fillMaxWidth().padding(16.dp), content = content)
    }
    Spacer(Modifier.height(16.dp))
}

/** A section's title inside a [SectionCard], in the current app's large serif style. */
@Composable
internal fun SectionTitle(p: Placeholder) = Say(UiText.ph(p), style = MaterialTheme.typography.titleLarge)

/** A page of its own below its header: the signed-in column's width, scrolling when tall. */
@Composable
internal fun PageColumn(content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 12.dp), content = content)
}

/**
 * A slot of a fixed [height] for lines that come and go (a strength line while typing, a line a read adds): what is in
 * it never moves what is below it, so nothing moves under a control a person is about to use (a line that grew under
 * a password field once put an operator's master password into the wrong field). Longer content scrolls inside.
 */
@Composable
internal fun FixedSlot(height: Dp, content: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxWidth().height(height).verticalScroll(rememberScrollState())) {
        Column(Modifier.fillMaxWidth(), content = content)
    }
}

/**
 * A slot for lines that come and go that is as tall as what stands in it, and at most [max]: past it, its lines scroll
 * inside. Unlike [FixedSlot] it keeps no room for lines that are not there.
 */
@Composable
internal fun CappedSlot(max: Dp, content: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxWidth().heightIn(max = max).verticalScroll(rememberScrollState())) {
        Column(Modifier.fillMaxWidth(), content = content)
    }
}

/**
 * A panel inside a list (an account's actions under its row in the console), as the current app draws a vault's
 * settings: a card of its own with a 16 dp margin, in the page's own tone so it stands out from the card around the
 * list. Nothing at its edge marks a state.
 */
@Composable
internal fun PanelCard(content: @Composable ColumnScope.() -> Unit) {
    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(16.dp), content = content)
    }
}

/**
 * A list in a scroll box of a fixed [height], outlined and with its own scroll bar: a read that adds or drops rows
 * changes nothing below the box. Focus moving into a row brings it into view inside the box.
 */
@Composable
internal fun ListBox(height: Dp, content: @Composable ColumnScope.() -> Unit) {
    val scroll = rememberScrollState()
    Box(Modifier.fillMaxWidth().height(height).border(1.dp, MaterialTheme.colorScheme.outlineVariant, MaterialTheme.shapes.small)) {
        Column(Modifier.fillMaxWidth().verticalScroll(scroll).padding(start = 8.dp, end = 16.dp, top = 4.dp, bottom = 4.dp), content = content)
        VerticalScrollbar(rememberScrollbarAdapter(scroll), Modifier.align(Alignment.CenterEnd).fillMaxHeight())
    }
}

/** The height of the slot under a new master password for its strength lines (three lines of small text, and room to wrap). */
internal val STRENGTH_SLOT = 72.dp

/** The slot under the unlock button for "unlocking" and what the unlock answered (the error bar, two lines and its dismiss). */
internal val UNLOCK_SAID_SLOT = 104.dp

/** The slot under a sign-in button for the line that names the wait while the password is checked. */
internal val BUSY_LINE_SLOT = 28.dp

/**
 * A row as the current app draws a vault in its Vaults card and an item in its list: the name's first letter in the
 * brand colour and a serif face, the name, and a quieter second line.
 */
@Composable
internal fun LetterHead(name: String, second: UiText?) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text((name.firstOrNull() ?: '?').uppercase(), color = MaterialTheme.colorScheme.primary, fontFamily = FontFamily.Serif, modifier = Modifier.padding(end = 12.dp))
        Column(Modifier.weight(1f)) {
            Text(name, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
            second?.let { Say(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
    }
}

/**
 * A section that opens on request, drawn as the current app draws every section of Settings and Sharing: its title in
 * the card, then the button that opens it (it reads from the server, so it is not opened by itself).
 */
@Composable
internal fun ClosedSection(title: Placeholder, enabled: Boolean, onOpen: () -> Unit) {
    SectionTitle(title)
    Gap(4)
    Second(UiText.ph(Placeholder.OPEN_SECTION), enabled = enabled) { onOpen() }
}

/** The slot under a card number for its warning (two lines). */
internal val CARD_WARNING_SLOT = 44.dp
