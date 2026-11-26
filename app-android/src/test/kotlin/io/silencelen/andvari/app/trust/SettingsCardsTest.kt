package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Settings follows the current app (0.30.0's SettingsScreen): one full-width card per section with 16 dp inside and
 * between, the title in titleLarge, the backups first, then autofill, quick unlock and two-step sign-in; the sections
 * the current app has no card for come after them, drawn the same way. No accent bar.
 */
class SettingsCardsTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun everySectionIsACardInTheCurrentAppsOrder() {
        val settings = src("SettingsScreens.kt").substringAfter("internal fun SettingsSections(").substringBefore("\n}\n")
        val order = listOf(
            "VaultBackupSection(model)", "StorageSection(model)", "SettingsCard { AutofillTrustSection() }",
            "SettingsCard { QuickUnlockSection(", "SettingsCard { TwoStepSection(", "SettingsCard { DevicesSection(",
            "SettingsCard { RecoverySection(", "SettingsCard { ChangePasswordSection(", "SettingsCard { PolicySection(",
            "SettingsCard { DeleteAccountSection(",
        )
        val at = order.map { settings.indexOf(it) }
        assertTrue(at.all { it >= 0 }, "every section is there: ${order.zip(at)}")
        assertEquals(at.sorted(), at, "in the current app's order")
        // The backup and the storage meters make their own card, only when they have something to show.
        val home = src("VaultHome.kt")
        for (fn in listOf("internal fun VaultBackupSection(", "internal fun StorageSection(")) {
            assertTrue(home.substringAfter(fn).substringBefore("\n}\n").contains("SettingsCard {"), fn)
        }
        // The card: full width, 16 dp inside and after it, titleLarge inside; and no accent bar on it.
        val ui = src("TrustUi.kt").substringAfter("internal fun SettingsCard(").substringBefore("\n}\n")
        assertTrue(ui.contains("Card(Modifier.fillMaxWidth())") && ui.contains("Column(Modifier.padding(16.dp))") && ui.contains("Spacer(Modifier.height(16.dp))"))
        assertFalse(ui.contains("border") || ui.contains("drawBehind") || ui.contains("width(4"), "no accent bar")
        assertTrue(src("TrustUi.kt").contains("if (LocalInSettingsCard.current) MaterialTheme.typography.titleLarge else MaterialTheme.typography.titleSmall"))
        // Inside a card, no section draws its own divider or a small title any more.
        for ((file, fn) in listOf(
            "SettingsScreens.kt" to "internal fun QuickUnlockSection(", "SettingsScreens.kt" to "internal fun TwoStepSection(",
            "SettingsScreens.kt" to "internal fun ChangePasswordSection(", "SettingsScreens.kt" to "internal fun DeleteAccountSection(",
            "SettingsScreens.kt" to "internal fun AutofillTrustSection(", "DevicesScreens.kt" to "internal fun DevicesSection(",
            "RecoverySettingsScreens.kt" to "internal fun RecoverySection(",
        )) {
            val body = src(file).substringAfter(fn).substringBefore("\n}\n")
            assertTrue(body.contains("SectionDivider()"), fn)
            assertFalse(body.lines().take(16).any { it.trim() == "HorizontalDivider()" }, "$fn: no divider of its own at the top")
            assertTrue(body.contains("style = sectionTitleStyle()"), fn)
        }
    }
}
