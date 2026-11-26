package io.silencelen.andvari.app.trust

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.app.PrimaryButton
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.InstanceLabel
import io.silencelen.andvari.core.app.SignInAnswer

// The small pieces every screen of the new path is made of, in the app's existing visual language (Material 3 with
// the andvari theme; no accent bars, state marks in the app's own quiet tones).

/** Text of the new path. A placeholder is italic, in the tertiary tone, and bracketed, so it reads as unfinished. */
@Composable
internal fun Say(
    text: UiText,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.bodyMedium,
    color: Color = Color.Unspecified,
) {
    if (text.isPlaceholder) {
        Text(addressBreaks(text.shown()), modifier, style = style.copy(fontStyle = FontStyle.Italic), color = MaterialTheme.colorScheme.tertiary)
    } else {
        Text(addressBreaks(text.shown()), modifier, style = style, color = color)
    }
}

/** U+200B, written as a number so the source shows it. */
internal val ZERO_WIDTH_SPACE: Char = Char(0x200B)

/** A web address inside shown text: the scheme, then everything up to a space or a closing bracket or quote. */
private val WEB_ADDRESS = Regex("""https?://[^\s)\]”"'⟧]+""")

/**
 * [text] with a break opportunity (a zero-width space) before each `.` and `/` of every web address after its scheme,
 * so an address too long for its line breaks between its own parts ("https://vault" / ".family" / ".example") rather
 * than inside a word ("vault.family.exampl" / "e"), which hides which server it names (as the drawn screens
 * showed; the extension made the same fix). Only what is drawn changes: the text itself, and what is read
 * aloud, are the same.
 */
internal fun addressBreaks(text: String): String = WEB_ADDRESS.replace(text) { m ->
    val a = m.value
    val start = a.indexOf("://") + 3
    buildString(a.length + 8) {
        append(a, 0, start)
        for (i in start until a.length) {
            val ch = a[i]
            if ((ch == '.' || ch == '/') && i > start) append(ZERO_WIDTH_SPACE)
            append(ch)
        }
    }
}

/**
 * A row of buttons that wraps onto the next line when they do not fit, instead of squeezing the last ones until their
 * words stand one letter a line and push the rest of the screen out of sight (the vault's own
 * home screen showed no items on a small phone).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun ButtonRow(spacing: Int = 8, content: @Composable () -> Unit) =
    FlowRow(horizontalArrangement = Arrangement.spacedBy(spacing.dp)) { content() }

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

/** The largest font sizes (1.5 and up), where a small phone has room for little above a field. */
@Composable
internal fun largeFont(): Boolean = LocalDensity.current.fontScale >= LARGE_FONT_SCALE

internal const val LARGE_FONT_SCALE = 1.5f

/**
 * A password step's title, which names the account, the server and its address (§4.4), once: the server is not named
 * again under it, only marked as self-named where nobody but the server vouches for its name. At the largest font
 * sizes the title is smaller, so that the password field is on the first screen of a small phone. Without a title the
 * server is named as everywhere else ([InstanceName]).
 */
@Composable
internal fun PasswordStepTitle(title: UiText?, label: InstanceLabel) {
    if (title == null) return InstanceName(label)
    Say(title, Modifier.padding(bottom = 4.dp), if (largeFont()) MaterialTheme.typography.titleSmall else MaterialTheme.typography.titleLarge)
    if (label.selfNamed) Say(CopyKey.AS_THE_SERVER_NAMES_ITSELF, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
}

/**
 * An instance as the design names it (§4.4, T-R8): the card's name with its origin beside it, always, and the
 * self-named mark where nobody but the server vouches for the name.
 */
@Composable
internal fun InstanceName(label: InstanceLabel, style: TextStyle = MaterialTheme.typography.titleMedium) {
    Column(Modifier.padding(vertical = 4.dp)) {
        if (label.name.isNotEmpty()) Text(label.name, style = style)
        Text(addressBreaks(label.origin), style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace))
        if (label.selfNamed) Say(CopyKey.AS_THE_SERVER_NAMES_ITSELF, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** What the last intent answered on this screen, in place (polite live region). */
@Composable
internal fun SaidHere(model: TrustModel, s: AppSnapshot) {
    // An answer a section shows in place ([SaidIn]) is not repeated here.
    val said = model.saidOn(s)?.takeIf { it.section == null }
    if (said != null) {
        Say(
            said.text,
            Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Polite },
            MaterialTheme.typography.bodyMedium,
            MaterialTheme.colorScheme.error,
        )
        // The server's keys are not this account's as this phone knows them: the way out is said under the sentence.
        if (said.result == SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE) Say(Placeholder.SIGN_IN_KEYS_WAY_OUT)
        // A stop offers its way out here: a kept-account refusal names that account (its words, above) and offers to sign
        // it out; this phone's own copy in the way, its removal; a held operator account, its removal on the first screen.
        WayOutOffer(model, s, wayOutFor(said.result))
    }
    // A refusal because this phone knows the address under an earlier account: under the refused result's line, on the
    // screen it was raised on, the shared code's offer to forget it (only as the snapshot hands it).
    s.earlierAccount?.let { EarlierAccountOffer(model, s, it) }
}

/**
 * §4.4: "Master password for *email* on *name* (*origin*)", the line every master-password field of an existing
 * account shows above it. Null when the account or the server is not known on the screen.
 */
internal fun masterPasswordLine(email: String?, label: io.silencelen.andvari.core.app.InstanceLabel?): UiText? =
    if (email.isNullOrEmpty() || label == null) null
    else UiText.Plain(fillCopy(io.silencelen.andvari.core.app.CopyKey.MASTER_PASSWORD_FOR, email, label.name, label.origin))

/**
 * The master-password field of the signed-in screens: the account, the server's name and
 * its address above the field ([masterPasswordLine]), always, from the open account and the server on show.
 */
@Composable
internal fun MasterPasswordField(s: AppSnapshot, value: String, onChange: (String) -> Unit) {
    masterPasswordLine(s.account?.email, s.instance?.label)?.let { Say(it, style = MaterialTheme.typography.bodySmall) }
    io.silencelen.andvari.app.SecretField(UiText.ph(Placeholder.PASSWORD_FIELD).shown(), value) { onChange(it) }
}

/** What the last intent of [section] ([TrustModel.runIn]) answered, in place in that section. */
@Composable
internal fun SaidIn(model: TrustModel, s: AppSnapshot, section: String) {
    val said = model.saidIn(s, section) ?: return
    Say(
        said.text,
        Modifier.fillMaxWidth().padding(vertical = 8.dp).semantics { liveRegion = LiveRegionMode.Polite },
        MaterialTheme.typography.bodyMedium,
        MaterialTheme.colorScheme.error,
    )
}

@Composable
internal fun Main(text: UiText, enabled: Boolean, busy: Boolean, onClick: () -> Unit) {
    PrimaryButton(text.shown(), enabled = enabled, busy = busy, onClick = onClick)
}

@Composable
internal fun Second(text: UiText, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) { Say(text) }
}

@Composable
internal fun Quieter(text: UiText, enabled: Boolean = true, onClick: () -> Unit) {
    TextButton(onClick = onClick, enabled = enabled) { Say(text) }
}

@Composable
internal fun Field(label: UiText, value: String, keyboard: KeyboardType = KeyboardType.Text, mono: Boolean = false, modifier: Modifier = Modifier, onChange: (String) -> Unit) {
    OutlinedTextField(
        value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp).then(modifier),
        label = { Say(label) }, singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, autoCorrectEnabled = false),
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium,
    )
}

/**
 * A field labelled by the sentence shown above it ([line]): no floating label (a sentence does not fit one), and
 * [line] is what a screen reader names the field by.
 */
@Composable
internal fun LineLabelledField(line: UiText, value: String, keyboard: KeyboardType = KeyboardType.Text, mono: Boolean = false, onChange: (String) -> Unit) {
    val name = line.shown()
    OutlinedTextField(
        value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp).semantics { contentDescription = name },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, autoCorrectEnabled = false),
        textStyle = if (mono) MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace) else MaterialTheme.typography.bodyMedium,
    )
}

/**
 * A field that holds lines (an item's notes): not single-line, so the keyboard's Enter adds a line, at least
 * [NOTES_MIN_LINES] tall and growing to [NOTES_MAX_LINES] before it scrolls. It asks the keyboard not to learn what is
 * typed ([notesKeyboard]: the password input type with autocorrect off, which Compose still lets hold lines).
 */
@Composable
internal fun LinesField(label: UiText, value: String, onChange: (String) -> Unit) {
    OutlinedTextField(
        value, onChange, Modifier.fillMaxWidth().padding(vertical = 4.dp),
        label = { Say(label) }, singleLine = false, minLines = NOTES_MIN_LINES, maxLines = NOTES_MAX_LINES,
        keyboardOptions = notesKeyboard,
        textStyle = MaterialTheme.typography.bodyMedium,
    )
}

/** The notes field's keyboard: not learned (password type, no autocorrect), and Enter left to add a line (ImeAction.Default). */
internal val notesKeyboard = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = ImeAction.Default)
internal const val NOTES_MIN_LINES = 3
internal const val NOTES_MAX_LINES = 12

@Composable
internal fun Gap(h: Int = 12) = Spacer(Modifier.height(h.dp))

/** True inside a [SettingsCard]: a section there has the card for its frame, not a divider. */
internal val LocalInSettingsCard = staticCompositionLocalOf { false }

/**
 * One section of Settings as the current app draws it: a full-width card with 16 dp inside, its title in titleLarge,
 * and 16 dp to the next card. No accent bar.
 */
@Composable
internal fun SettingsCard(content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            CompositionLocalProvider(LocalInSettingsCard provides true) { content() }
        }
    }
    Spacer(Modifier.height(16.dp))
}

/** A section's top: a divider, except inside a [SettingsCard], whose frame divides it. */
@Composable
internal fun SectionDivider() {
    if (!LocalInSettingsCard.current) HorizontalDivider()
}

/** A section's title style: titleLarge in a [SettingsCard], as the current app's cards have it; titleSmall elsewhere. */
@Composable
internal fun sectionTitleStyle(): TextStyle =
    if (LocalInSettingsCard.current) MaterialTheme.typography.titleLarge else MaterialTheme.typography.titleSmall
