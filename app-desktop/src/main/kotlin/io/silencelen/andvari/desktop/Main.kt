package io.silencelen.andvari.desktop

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState

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
    Window(
        onCloseRequest = ::exitApplication,
        title = "andvari",
        state = rememberWindowState(width = 480.dp, height = 720.dp),
    ) {
        val scope = rememberCoroutineScope()
        val state = remember { DesktopState(scope).also { it.start() } }
        AndvariDesktopTheme {
            Surface { DesktopApp(state) }
        }
    }
}
