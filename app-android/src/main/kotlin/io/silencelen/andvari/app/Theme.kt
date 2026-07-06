package io.silencelen.andvari.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// Treasury/gold palette — matches the web client (aged gold on deep charcoal).
private val Gold = Color(0xFFD0A94A)
private val GoldBright = Color(0xFFE8C66A)
private val Ink = Color(0xFFEDE4D0)
private val InkDim = Color(0xFFA79C85)
private val Bg = Color(0xFF14120E)
private val BgRaised = Color(0xFF1E1B15)
private val Edge = Color(0xFF38311F)
private val Danger = Color(0xFFCF6B5A)

private val AndvariDark = darkColorScheme(
    primary = Gold,
    onPrimary = Color(0xFF1A1509),
    secondary = GoldBright,
    background = Bg,
    onBackground = Ink,
    surface = BgRaised,
    onSurface = Ink,
    surfaceVariant = Color(0xFF262119),
    onSurfaceVariant = InkDim,
    outline = Edge,
    error = Danger,
)

private val AndvariLight = lightColorScheme(
    primary = Color(0xFF9A7420),
    onPrimary = Color.White,
    secondary = Color(0xFF7D5E14),
    background = Color(0xFFF4EFE4),
    onBackground = Color(0xFF2C2517),
    surface = Color(0xFFFBF8F1),
    onSurface = Color(0xFF2C2517),
    outline = Color(0xFFE0D8C5),
    error = Color(0xFFB3402C),
)

private val serif = FontFamily.Serif
private val AndvariType = Typography(
    headlineMedium = TextStyle(fontFamily = serif, fontWeight = FontWeight.SemiBold, fontSize = 26.sp),
    titleLarge = TextStyle(fontFamily = serif, fontWeight = FontWeight.SemiBold, fontSize = 22.sp),
)

@Composable
fun AndvariTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) AndvariDark else AndvariLight,
        typography = AndvariType,
        content = content,
    )
}
