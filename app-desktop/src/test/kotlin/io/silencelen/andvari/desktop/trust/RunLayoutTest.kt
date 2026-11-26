package io.silencelen.andvari.desktop.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** What the first run under a virtual display found in the window's layout at its 480 dp width, pinned. */
class RunLayoutTest {
    private val mainSources: List<File> =
        listOf(File("src/main/kotlin"), File("app-desktop/src/main/kotlin")).first { it.isDirectory }
            .walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()

    private fun src(name: String) = mainSources.single { it.name == name }.readText()

    private fun codeLines(name: String): List<String> =
        mainSources.single { it.name == name }.readLines().map { it.trim() }.filterNot { it.startsWith("//") || it.startsWith("*") }

    /** A plain Row of buttons squeezed the last one into a column one letter wide at 480 dp: groups of buttons wrap. */
    @Test
    fun groupsOfButtonsWrap() {
        assertTrue("FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp))" in src("TrustUi.kt"))
        for (name in listOf("VaultItemsScreens.kt", "VaultHealthScreens.kt", "VaultTransferScreens.kt", "VaultScreens.kt")) {
            val rows = codeLines(name).filter { it.startsWith("Row(horizontalArrangement = Arrangement.spacedBy(8.dp)") }
            assertEquals(emptyList(), rows, name)
            // The transfer screens' buttons are full width, one under the other (the current app's backup card).
            if (name != "VaultTransferScreens.kt") assertTrue("Actions {" in src(name), name)
        }
    }

    /** A placeholder on the filled main button takes the button's content tone (green on gold could not be read). */
    @Test
    fun aPlaceholderOnTheMainButtonIsReadable() {
        val main = src("TrustUi.kt").substringAfter("internal fun Main(").substringBefore("internal fun Actions(")
        assertTrue("text.isPlaceholder" in main)
        assertTrue("color = LocalContentColor.current" in main)
    }

    /** A note takes more than one line: Enter in the notes editor is a new line, never a submit. */
    @Test
    fun theNotesEditorTakesLines() {
        assertTrue("Field(UiText.ph(Placeholder.ITEM_NOTES), notes, lines = NOTES_LINES)" in src("VaultItemsScreens.kt"))
        assertTrue(NOTES_LINES > 1)
        val field = src("TrustUi.kt").substringAfter("internal fun Field(").substringBefore("internal fun SecretField(")
        assertTrue("singleLine = lines == 1" in field)
        // Enter's action is guarded (what the shared code throws in it is said, never a crash).
        assertTrue("submitOnEnter(if (lines > 1) null else enter)" in field && "val enter = onEnter?.let { guarded(onClick = it) }" in field)
    }
}
