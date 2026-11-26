package io.silencelen.andvari.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Where an item editor keeps its secrets, and which screens may be captured, as far as it still applies after the
 * overhaul deleted the old screens.
 *
 *  - The old item editor kept its secrets in the ViewModel's editor session, never in `rememberSaveable`. The old
 *    editor is gone; the session rules it relied on stay with the ViewModel the autofill service still uses. The new
 *    editor's fields are `remember`, keyed to the content instance (pinned in trust/SecretFieldsTest and below).
 *  - The new path has no screen that clears FLAG_SECURE.
 */
class A13EditorSecretsAndSecureFlagTest {
    private fun src(name: String): String =
        listOf(File("src/main/kotlin/io/silencelen/andvari/app/$name"), File("app-android/src/main/kotlin/io/silencelen/andvari/app/$name"))
            .first { it.isFile }.readText()

    private val vm by lazy { src("AndvariViewModel.kt") }

    @Test
    fun theEditorSecretsDieWithTheEditorSession() {
        for (fn in listOf("fun openEditor(", "fun closeEditor(")) {
            val body = vm.substringAfter(fn).substringBefore("\n    }")
            assertTrue(body.contains("editorSecrets.clear()"), "$fn must clear the editor's secrets")
        }
        assertTrue(vm.substringAfter("fun lock(").substringBefore("\n    }").contains("closeEditor()"), "lock closes the editor session")
    }

    @Test
    fun theNewEditorKeepsNoSecretInSavedInstanceState() {
        val editor = src("trust/VaultItemsScreens.kt").substringAfter("private fun ItemEditor(").substringBefore("\n@Composable")
        assertFalse(editor.contains("rememberSaveable"), "no field of the editor goes into the saved-instance Bundle")
    }

    @Test
    fun theWindowIsSecureAndTheNewPathClearsItNowhere() {
        val main = src("MainActivity.kt")
        assertTrue(main.contains("window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)"), "the window is secure")
        val trust = File("src/main/kotlin/io/silencelen/andvari/app/trust").takeIf { it.isDirectory } ?: File("app-android/src/main/kotlin/io/silencelen/andvari/app/trust")
        for (f in listOf(main) + (trust.listFiles()?.map { it.readText() } ?: emptyList())) {
            assertFalse(f.contains("clearFlags(WindowManager.LayoutParams.FLAG_SECURE)"), "the new path clears it nowhere")
        }
    }
}
