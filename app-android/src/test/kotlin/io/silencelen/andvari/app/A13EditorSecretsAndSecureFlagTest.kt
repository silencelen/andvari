package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A13.
 *
 *  - q27: the item editor's secret fields (password, TOTP seed, card number, security code) never go into
 *    `rememberSaveable` — the saved-instance Bundle is held by system_server, outside the app's lock and zeroization.
 *    They live in the ViewModel's editor session instead, cleared when a session opens or closes (and so on lock).
 *  - q30: FLAG_SECURE is cleared for the whole window on the Autofill Status screen, so nothing that shows vault
 *    values (the attention area) may be composed there.
 */
class A13EditorSecretsAndSecureFlagTest {
    private fun src(name: String): String =
        listOf(File("src/main/kotlin/io/silencelen/andvari/app/$name"), File("app-android/src/main/kotlin/io/silencelen/andvari/app/$name"))
            .first { it.isFile }.readText()

    private val editor by lazy { src("MainActivity.kt").substringAfter("private fun ItemEditor(").substringBefore("\n@Composable") }
    private val vm by lazy { src("AndvariViewModel.kt") }

    @Test
    fun theEditorsSecretFieldsAreNeverSaveable() {
        for (seed in listOf("initial.login?.password", "initial.login?.totp", "initial.card?.number", "initial.card?.securityCode")) {
            assertTrue(editor.contains(seed), "the editor still seeds from $seed (pin moved?)")
            val line = editor.lines().single { it.trimStart().startsWith("var ") && it.contains(seed) }
            assertFalse(line.contains("rememberSaveable"), "$seed is held in rememberSaveable (saved-instance state): $line")
            assertTrue(line.contains("vm.editorSecretState("), "$seed must live in the ViewModel's editor session: $line")
        }
    }

    @Test
    fun theEditorSecretsDieWithTheEditorSession() {
        for (fn in listOf("fun openEditor(", "fun closeEditor(")) {
            val body = vm.substringAfter(fn).substringBefore("\n    }")
            assertTrue(body.contains("editorSecrets.clear()"), "$fn must clear the editor's secrets")
        }
        assertTrue(vm.substringAfter("fun lock(").substringBefore("\n    }").contains("closeEditor()"), "lock closes the editor session")
    }

    @Test
    fun noScreenThatClearsFlagSecureComposesTheAttentionArea() {
        val screens = listOf(
            Screen.Loading, Screen.Welcome, Screen.Unlock("a@b.c"), Screen.Vault, Screen.Sharing, Screen.Settings,
            Screen.Trash, Screen.Health, Screen.AutofillStatus, Screen.RecoverySetup,
        )
        assertTrue(flagSecureExempt(Screen.AutofillStatus), "the Autofill Status screen stays screenshot-able")
        for (s in screens) {
            if (flagSecureExempt(s)) assertFalse(showsAttentionArea(s), "$s clears FLAG_SECURE but composes the attention area")
        }
        assertTrue(showsAttentionArea(Screen.Vault))
        assertFalse(showsAttentionArea(Screen.RecoverySetup))
        val main = src("MainActivity.kt")
        assertTrue(main.contains("vm.ui.map { flagSecureExempt(it.screen) }"), "the window flag follows the same predicate")
        assertTrue(main.contains("if (showsAttentionArea(ui.screen)) AttentionArea(vm, ui)"), "the attention area follows the predicate")
    }
}
