package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.desktop.DESKTOP_VERSION
import io.silencelen.andvari.desktop.UpdateCheck
import io.silencelen.andvari.desktop.UpdateReport
import io.silencelen.andvari.desktop.WORDMARK_BASELINE_SHARE
import io.silencelen.andvari.desktop.Wordmark
import io.silencelen.andvari.desktop.openFolder
import java.io.File
import kotlin.math.roundToInt
import java.text.DateFormat
import java.util.Date

/** The platform tag the old About showed: "windows" or "linux" (the only desktop targets). */
internal fun desktopPlatform(): String =
    if (System.getProperty("os.name").orEmpty().lowercase().contains("win")) "windows" else "linux"

/**
 * Help ▸ About andvari, carried over from the old desktop word for word (design 2026-07-13 platform-fit §2, audit
 * H126): the version, the platform, the server on show ([origin], whole), a found update, and the diagnostic log's
 * path (selectable) with Open folder. It makes no network call of its own.
 */
/**
 * About's update lines: where and when a verified list last came, and the two quiet
 * states, "could not check since …" and "could not verify", plus a list too old to prove the channel fresh. [last] is
 * the persisted (time, source) of the last verified list (0 = never).
 */
internal fun updateStatusLines(report: UpdateReport?, last: Pair<Long, String>, format: (Long) -> String = ::aboutTime, signedAt: String = ""): List<UiText> = buildList {
    val (lastAt, lastFrom) = last
    // Three things: the source, the date the list itself was signed, and when it was last
    // checked; a list held back shows an old signed date under a fresh check.
    if (lastAt > 0) add(UiText.ph(Placeholder.UPDATE_LAST_CHECKED, lastFrom, signedDate(signedAt, format), format(lastAt)))
    when (val c = report?.check) {
        UpdateCheck.NotAsked -> add(UiText.ph(Placeholder.UPDATE_NOT_ASKED))
        UpdateCheck.Unreachable -> add(UiText.ph(Placeholder.UPDATE_COULD_NOT_CHECK_SINCE, if (lastAt > 0) format(lastAt) else UiText.ph(Placeholder.UPDATE_NEVER).shown()))
        UpdateCheck.Unverified -> add(UiText.ph(Placeholder.UPDATE_COULD_NOT_VERIFY, report.from?.shown.orEmpty()))
        is UpdateCheck.Stale -> add(UiText.ph(Placeholder.UPDATE_STALE, report.from?.shown.orEmpty()))
        else -> {}
    }
}

/** The list's `signedAt` as a date: formatted when it reads as an instant, shown as signed otherwise, a placeholder when absent. */
internal fun signedDate(signedAt: String, format: (Long) -> String): String {
    if (signedAt.isBlank()) return UiText.ph(Placeholder.UPDATE_SIGNED_NOT_GIVEN).shown()
    return runCatching { format(java.time.Instant.parse(signedAt.trim()).toEpochMilli()) }.getOrElse { printableSigned(signedAt) }
}

/** A signed date that does not parse is still the list's own words: shown cut short, with no control characters. */
private fun printableSigned(s: String): String = s.filter { !it.isISOControl() }.take(40)

private fun aboutTime(ms: Long): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(ms))

@Composable
internal fun AboutDialog(origin: String?, updateAvailable: String?, logPath: String, updateLines: List<UiText> = emptyList(), onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("About andvari") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                // The name drawn at the size of this line's text, its baseline on the line's; the line stays text.
                Row {
                    Wordmark(
                        MaterialTheme.typography.bodyMedium.fontSize,
                        modifier = Modifier.alignBy { (it.measuredHeight * WORDMARK_BASELINE_SHARE).roundToInt() },
                    )
                    Text(" — $BRAND_LINE", Modifier.alignByBaseline(), style = MaterialTheme.typography.bodyMedium)
                }
                Spacer(Modifier.height(12.dp))
                Text("Version $DESKTOP_VERSION", style = MaterialTheme.typography.bodySmall)
                Text("Platform: ${desktopPlatform()}", style = MaterialTheme.typography.bodySmall)
                origin?.let {
                    Spacer(Modifier.height(4.dp))
                    Text("Server", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
                updateAvailable?.let {
                    Spacer(Modifier.height(12.dp))
                    Text("Version $it is available.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary)
                }
                if (updateLines.isNotEmpty()) Spacer(Modifier.height(8.dp))
                for (line in updateLines) Say(line, style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(12.dp))
                Text("Diagnostic log", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                SelectionContainer {
                    Text(logPath, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
                Text(
                    "Errors this app couldn't explain on screen are recorded here — error types and where in the app they happened, " +
                        "never anything from your vault. It's kept small, safe to delete, and safe to send to whoever is helping you.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // Secondary to the selectable path, never a replacement for it: Desktop.open fails on some Linux sessions.
                var openFailed by remember { mutableStateOf(false) }
                File(logPath).absoluteFile.parentFile?.let { dir ->
                    TextButton(onClick = { openFailed = !openFolder(dir) }) { Text("Open folder") }
                }
                if (openFailed) {
                    Text(
                        "Couldn't open a file manager on this machine — copy the path above instead.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
    )
}
