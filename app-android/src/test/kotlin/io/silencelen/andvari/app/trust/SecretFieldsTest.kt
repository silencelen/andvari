package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * No secret is typed in the clear by default: the backup passphrase, the editors' password, one-time-code key, card
 * number and card code, and the kit's text and groups all use the master password's field (masked, with its show
 * control, and a keyboard that learns nothing).
 */
class SecretFieldsTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/app/"

    private fun src(name: String) = File(dir + name).readText()

    @Test
    fun theEditorsSecretsAreMaskedAndGenerateShowsWhatWillBeSaved() {
        val editor = src("trust/VaultItemsScreens.kt").substringAfter("private fun ItemEditor(").substringBefore("\n@Composable")
        for (p in listOf("ITEM_PASSWORD", "ITEM_TOTP", "ITEM_CARD_CODE")) {
            assertTrue(editor.contains("MaskedField(UiText.ph(Placeholder.$p).shown()"), "$p is masked")
            assertFalse(Regex("""(?<![A-Za-z])Field\(UiText\.ph\(Placeholder\.$p\)""").containsMatchIn(editor), "$p is no plain field")
        }
        // The card number's label also names the brand while it is typed; the field is masked as before.
        assertTrue(editor.contains("MaskedField(cardNumberLabel(c, number), number, digits = true)"))
        assertFalse(Regex("""(?<![A-Za-z])Field\((UiText\.ph\(Placeholder\.ITEM_CARD_NUMBER\)|cardNumberLabel)""").containsMatchIn(editor), "the card number is no plain field")
        assertTrue(src("trust/VaultItemsScreens.kt").contains("UiText.ph(Placeholder.ITEM_CARD_NUMBER).shown() + (c.cardBrandOf(typed)"))
        assertTrue(editor.contains("passwordShown.value = true"), "Generate shows the password it made")
        assertTrue(src("trust/VaultItemsScreens.kt").contains("import io.silencelen.andvari.app.SecretField as MaskedField"))
    }

    @Test
    fun theBackupPassphraseAndTheKitAreMasked() {
        val transfer = src("trust/VaultTransferScreens.kt")
        assertTrue(transfer.contains("SecretField(UiText.ph(Placeholder.EXPORT_PASSPHRASE).shown(), passphrase)"))
        assertTrue(transfer.contains("SecretField(UiText.ph(Placeholder.EXPORT_PASSPHRASE_AGAIN).shown(), confirm)"))
        assertFalse(Regex("""(?<![A-Za-z])Field\(UiText\.ph\(Placeholder\.EXPORT_PASSPHRASE""").containsMatchIn(transfer), "no plain field")
        val kit = src("trust/LinkAndRecoveryScreens.kt")
        assertTrue(kit.contains("SecretField(UiText.ph(Placeholder.KIT_TEXT_FIELD).shown(), pasted)"))
        assertTrue(kit.contains("SecretField(UiText.ph(Placeholder.KIT_GROUPS_FIELD).shown(), groups)"))
    }

    @Test
    fun theSharedFieldMasksByDefaultAndKeepsTheKeyboardFromLearning() {
        val field = src("MainActivity.kt").substringAfter("internal fun SecretField(").substringBefore("\n}\n")
        assertTrue(field.contains("remember { mutableStateOf(false) }"), "hidden until the person shows it")
        assertTrue(field.contains("PasswordVisualTransformation()"))
        assertTrue(field.contains("if (digits) KeyboardType.NumberPassword else KeyboardType.Password"))
        assertTrue(field.contains("autoCorrectEnabled = false"))
        assertTrue(field.contains("Icons.Default.Visibility"), "its show and hide control")
    }
}
