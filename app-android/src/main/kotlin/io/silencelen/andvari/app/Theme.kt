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
// UI-audit 2026-07 (Cut B): BOTH schemes now declare every Material3 color role the app
// renders. Before this, only the ~11 legacy base roles were themed, so M3 1.3 painted
// Cards, dialogs, the FAB, and error/tertiary surfaces from BASELINE (lavender/mauve) —
// the generic-Material look the brand exists to avoid. Every on-X/X pair below was
// contrast-computed (WCAG 2.x): text pairs ≥ 4.5:1, UI/boundary pairs ≥ 3:1. Values are
// kept in lockstep with web/src/ui/styles.css + the desktop twin by
// web/src/ui/token-lockstep.test.ts — change them THERE first.
private val Gold = Color(0xFFD0A94A)
private val GoldBright = Color(0xFFE8C66A)
private val Ink = Color(0xFFEDE4D0)
private val InkDim = Color(0xFFA79C85)
private val Bg = Color(0xFF14120E)
private val BgRaised = Color(0xFF1E1B15)
private val Edge = Color(0xFF38311F)
// a11y (Cut A parity): web dark --danger was lifted #CF6B5A → #D97F6F so danger text
// clears AA on tinted error plates; native error follows in lockstep.
private val Danger = Color(0xFFD97F6F)

private val AndvariDark = darkColorScheme(
    primary = Gold,
    onPrimary = Color(0xFF1A1509),
    primaryContainer = Color(0xFF4A3A12),
    onPrimaryContainer = Color(0xFFECD9A0),
    secondary = GoldBright,
    onSecondary = Color(0xFF1A1509),
    secondaryContainer = Edge,
    onSecondaryContainer = Ink,
    tertiary = Color(0xFF7FA86A), // the web --ok green
    onTertiary = Color(0xFF10200B),
    tertiaryContainer = Color(0xFF2A3A22),
    onTertiaryContainer = Color(0xFFC8DDB8),
    background = Bg,
    onBackground = Ink,
    surface = BgRaised,
    onSurface = Ink,
    surfaceVariant = Color(0xFF262119),
    onSurfaceVariant = InkDim,
    surfaceTint = Gold,
    inverseSurface = Ink,
    inverseOnSurface = Color(0xFF2C2517),
    inversePrimary = Color(0xFF9A7420),
    error = Danger,
    onError = Color(0xFF1A0F0B),
    errorContainer = Color(0xFF4A231C),
    onErrorContainer = Color(0xFFF2C0B5), // 8.38:1 on errorContainer — error-surface TEXT uses this
    // M3 outline borders text fields (OutlinedTextField) — must clear 3:1 vs surface
    // (was Edge #38311F ≈ 1.3:1, near-invisible). Dividers keep the old subtle tone
    // via outlineVariant (M3's Divider default).
    outline = Color(0xFF80714F),
    outlineVariant = Edge,
    scrim = Color(0xFF000000),
    surfaceBright = Color(0xFF3A332A),
    surfaceDim = Bg,
    surfaceContainerLowest = Color(0xFF0F0D0A),
    surfaceContainerLow = Color(0xFF1A1712),
    surfaceContainer = BgRaised,
    surfaceContainerHigh = Color(0xFF262119),
    surfaceContainerHighest = Color(0xFF2E2820), // default filled Card / Switch track
)

private val AndvariLight = lightColorScheme(
    // Light primary darkened #9A7420 → #8F6B16 (web --gold-hi parity): white button
    // labels were 4.29:1 (< AA); on #8F6B16 they're 4.90:1, primary-as-text 4.62:1.
    primary = Color(0xFF8F6B16),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFECDCAE),
    onPrimaryContainer = Color(0xFF3A2B05),
    secondary = Color(0xFF7D5E14),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFECE2C8),
    onSecondaryContainer = Color(0xFF2C2517),
    tertiary = Color(0xFF4F7A3A),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFD7E6CB),
    onTertiaryContainer = Color(0xFF1C2F12),
    background = Color(0xFFF4EFE4),
    onBackground = Color(0xFF2C2517),
    surface = Color(0xFFFBF8F1),
    onSurface = Color(0xFF2C2517),
    surfaceVariant = Color(0xFFE9E1CF), // pair was silently MISSING → Material grey leaked
    onSurfaceVariant = Color(0xFF6B6047),
    surfaceTint = Color(0xFF8F6B16),
    inverseSurface = Color(0xFF2C2517),
    inverseOnSurface = Color(0xFFEDE4D0),
    inversePrimary = Gold,
    error = Color(0xFFB3402C),
    onError = Color.White,
    errorContainer = Color(0xFFF6DED7),
    onErrorContainer = Color(0xFF5C1F12), // 9.85:1 — error-surface TEXT uses this (error itself is 4.43, < AA)
    outline = Color(0xFF857857), // 4.11:1 vs surface — text-field borders visible (was #E0D8C5 ≈ 1.3:1)
    outlineVariant = Color(0xFFE0D8C5),
    scrim = Color(0xFF000000),
    surfaceBright = Color(0xFFFBF8F1),
    surfaceDim = Color(0xFFD8D2C2),
    surfaceContainerLowest = Color.White,
    surfaceContainerLow = Color(0xFFFBF8F1),
    surfaceContainer = Color(0xFFF4EFE4),
    surfaceContainerHigh = Color(0xFFEFE9DB),
    surfaceContainerHighest = Color(0xFFE9E1CF), // secondary #7D5E14 on this = 4.63:1 — do not darken
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
