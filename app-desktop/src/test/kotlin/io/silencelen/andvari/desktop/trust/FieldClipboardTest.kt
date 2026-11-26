package io.silencelen.andvari.desktop.trust

import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.text.AnnotatedString
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** A text field's own copy goes through the app's one secret clipboard. */
class FieldClipboardTest {
    private class Base : ClipboardManager {
        var set: String? = null

        override fun setText(annotatedString: AnnotatedString) {
            set = annotatedString.text
        }

        override fun getText(): AnnotatedString? = AnnotatedString("pasted")
    }

    @Test
    fun aFieldsCopyIsMarkedAndClearedNotPutThereBare() {
        val base = Base()
        val copies = ArrayList<Pair<String, Int>>()
        val m = SensitiveClipboardManager(base, { 17 }) { v, s -> copies += v to s; true }
        m.setText(AnnotatedString("the revealed password"))
        assertEquals(listOf("the revealed password" to 17), copies, "through the secret clipboard, with the policy's window")
        assertEquals(null, base.set, "never the platform's plain copy")
        assertEquals("pasted", m.getText()?.text, "a paste reads the platform's clipboard")
    }

    @Test
    fun theWindowProvidesItAtTheRootAndEveryCopyInTheAppGoesThroughOneFunction() {
        val main = File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt").readText()
        assertTrue(main.contains("CompositionLocalProvider(LocalClipboardManager provides sensitiveClipboard)"))
        assertTrue(main.indexOf("CompositionLocalProvider(LocalClipboardManager provides sensitiveClipboard)") < main.indexOf("TrustApp(model,"))
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        for (f in sources) {
            val t = f.readText()
            if (f.name != "Platform.kt" && f.name != "SensitiveClipboard.kt") {
                assertTrue(!t.contains("systemClipboard") && !t.contains("setContents("), "${f.name} touches the clipboard itself")
            }
            assertTrue(!t.contains("LocalClipboardManager.current.setText"), f.name)
        }
    }
}
