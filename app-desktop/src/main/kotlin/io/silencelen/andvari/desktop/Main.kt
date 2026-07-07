package io.silencelen.andvari.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import java.awt.event.WindowEvent
import java.awt.event.WindowFocusListener

// Treasury/gold palette — matches the web + Android clients.
private val Gold = Color(0xFFD0A94A)
private val Ink = Color(0xFFEDE4D0)
private val Bg = Color(0xFF14120E)
private val BgRaised = Color(0xFF1E1B15)

private val DarkColors = darkColorScheme(
    primary = Gold, onPrimary = Color(0xFF1A1509), secondary = Color(0xFFE8C66A),
    background = Bg, onBackground = Ink, surface = BgRaised, onSurface = Ink,
    surfaceVariant = Color(0xFF262119), onSurfaceVariant = Color(0xFFA79C85),
    outline = Color(0xFF38311F), error = Color(0xFFCF6B5A),
)
private val LightColors = lightColorScheme(
    primary = Color(0xFF9A7420), onPrimary = Color.White, secondary = Color(0xFF7D5E14),
    background = Color(0xFFF4EFE4), onBackground = Color(0xFF2C2517), surface = Color(0xFFFBF8F1),
    onSurface = Color(0xFF2C2517), outline = Color(0xFFE0D8C5), error = Color(0xFFB3402C),
)
private val AndvariType = Typography(
    headlineMedium = TextStyle(fontFamily = FontFamily.Serif, fontWeight = FontWeight.SemiBold, fontSize = 26.sp),
    titleLarge = TextStyle(fontFamily = FontFamily.Serif, fontWeight = FontWeight.SemiBold, fontSize = 22.sp),
)

@Composable
fun AndvariDesktopTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        typography = AndvariType,
        content = content,
    )
}

fun main() = application {
    // The state holder must exist before Window's key-event callback references it, so
    // hoist scope+state to the application scope (the window IS the app lifetime here).
    val scope = rememberCoroutineScope()
    val state = remember { DesktopState(scope).also { it.start() } }
    Window(
        onCloseRequest = ::exitApplication,
        title = "andvari",
        state = rememberWindowState(width = 480.dp, height = 720.dp),
        // Every hardware key press counts as user activity for the inactivity auto-lock
        // (spec 01 §8). Window-level preview sees keys regardless of what has focus; never
        // consumes.
        onPreviewKeyEvent = { state.touch(); false },
    ) {
        // Sync (and enforce the idle lock) whenever the window regains OS focus (spec 03 §6).
        DisposableEffect(Unit) {
            val focus = object : WindowFocusListener {
                override fun windowGainedFocus(e: WindowEvent?) = state.onWindowFocus()
                override fun windowLostFocus(e: WindowEvent?) {}
            }
            window.addWindowFocusListener(focus)
            onDispose { window.removeWindowFocusListener(focus) }
        }
        AndvariDesktopTheme {
            Surface {
                // Root pointer interceptor: PointerEventPass.Initial observes every pointer
                // event (press/move/scroll) before children consume it — any of them resets
                // the auto-lock window. Purely observational; nothing is consumed.
                Box(
                    Modifier.fillMaxSize().pointerInput(Unit) {
                        awaitPointerEventScope {
                            while (true) {
                                awaitPointerEvent(PointerEventPass.Initial)
                                state.touch()
                            }
                        }
                    },
                ) { DesktopApp(state) }
            }
        }
    }
}
