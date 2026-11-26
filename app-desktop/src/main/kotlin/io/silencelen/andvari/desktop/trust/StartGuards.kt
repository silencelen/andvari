package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.WindowExceptionHandler
import androidx.compose.ui.window.WindowExceptionHandlerFactory
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.desktop.DesktopDiagnostics
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File

/**
 * An uncaught error in a screen shows an error card with "Quit", never a closed window with
 * a raw message. What failed goes to the redacting log ([DesktopDiagnostics.logThrowable]), never to the screen or to
 * standard error with its message.
 *
 * [failed] turns true once and stays: the window that failed is replaced by the card ([ScreenFailedCard]). [onFailure]
 * runs first, so the open vault is locked and a copied secret cleared before the card shows.
 */
@OptIn(ExperimentalComposeUiApi::class)
class ScreenFailure(
    private val log: (String, Throwable) -> Unit = DesktopDiagnostics::logThrowable,
) {
    private val state = MutableStateFlow(false)
    val failed: StateFlow<Boolean> = state

    /** What to do the moment something failed (lock, clear the clipboard). Its own failure is logged and passed. */
    @Volatile
    var onFailure: () -> Unit = {}

    fun caught(where: String, t: Throwable) {
        runCatching { log(where, t) }
        runCatching { onFailure() }.onFailure { e -> runCatching { log("while handling a failure", e) } }
        state.value = true
    }

    /** The handler a window's composition calls instead of Compose's default dialog (which shows the raw message). */
    fun handler(): WindowExceptionHandler = WindowExceptionHandler { t -> caught("a screen failed", t) }

    /** For `LocalWindowExceptionHandlerFactory`: every window of the app reports to this one. */
    fun factory(): WindowExceptionHandlerFactory = WindowExceptionHandlerFactory { handler() }
}

/**
 * A state file that does not parse at start gives a screen that says which file, keeps it
 * under a new name, and asks before starting fresh on this computer. It is never read as empty, and nothing loops: the
 * engine is not built over it until the person has answered.
 */
object StateFiles {
    private val json = Json { ignoreUnknownKeys = true }
    private val codec = MapSerializer(String.serializer(), String.serializer())

    /**
     * The files the engine reads at start that are there but do not read as its map ([JsonDeviceState]'s shape):
     * `device-state.json` always, `secure-state.json` only while the sign-in is kept here (otherwise it is never read,
     * and [DesktopHome] has already removed it unread).
     */
    fun damaged(home: DesktopHome): List<File> =
        listOfNotNull(File(home.dir, JsonDeviceState.FILE_NAME), home.secureStateFile.takeIf { home.keepAtStart == Keep.ON })
            .filter { !readsAsMap(it) }

    /** True when [f] is absent or holds a JSON object of strings. A file that cannot be read at all is damaged too. */
    fun readsAsMap(f: File): Boolean {
        if (!SafeDelete.exists(f)) return true
        return runCatching { json.decodeFromString(codec, f.readText()) }.isSuccess
    }

    /** Keeps each file under a new name (`<name>.unreadable-<time>`), unread. True when every one moved. */
    fun setAside(files: List<File>): Boolean = files.map { OwnerOnlyFile(it).setAside() }.all { it }
}

/** The card a failed window turns into: what happened, where the log is, and Quit. */
@Composable
fun ScreenFailedCard(logPath: String, quit: () -> Unit) {
    Surface(Modifier.fillMaxSize()) {
        AuthColumn {
            Sigil()
            Gap()
            Say(Placeholder.SCREEN_FAILED, logPath)
            Gap()
            Main(UiText.ph(Placeholder.QUIT), enabled = true, busy = false) { quit() }
        }
    }
}

/**
 * The screen a damaged state file gives at start: which file, what starting fresh means, and the two answers. Nothing
 * is moved until the person picks [startFresh]; Quit leaves the file as it is.
 */
@Composable
fun StateFileScreen(files: List<File>, startFresh: () -> Boolean, quit: () -> Unit) {
    var failed by remember(files) { mutableStateOf(false) }
    Surface(Modifier.fillMaxSize()) {
        AuthColumn {
            Sigil()
            Gap()
            for (f in files) Say(Placeholder.STATE_FILE_UNREADABLE, f.absolutePath)
            Gap(8)
            Say(UiText.ph(Placeholder.STATE_FILE_FRESH_WHAT), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (failed) for (f in files) Say(Placeholder.STATE_FILE_ASIDE_FAILED, f.absolutePath)
            Gap()
            Second(UiText.ph(Placeholder.QUIT)) { quit() }
            Main(UiText.ph(Placeholder.STATE_FILE_FRESH), enabled = true, busy = false) { failed = !startFresh() }
        }
    }
}
