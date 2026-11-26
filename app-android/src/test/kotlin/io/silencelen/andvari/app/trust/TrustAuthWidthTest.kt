package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The width cap of the screens before an unlock, for the new path (map §7.2: AuthWidthCapTest's screen list becomes the entry screens): every screen composable
 * of the new path renders inside the one capped shell, [io.silencelen.andvari.app.AuthColumn].
 */
class TrustAuthWidthTest {
    @Test
    fun everyScreenOfTheNewPathUsesTheSharedShell() {
        val dir = File("src/main/kotlin/io/silencelen/andvari/app/trust")
        var checked = 0
        for (f in dir.listFiles()!!.filter { it.name.endsWith(".kt") }) {
            val code = f.readText()
            for (m in Regex("""internal fun (\w+Screen\w*)\(""").findAll(code)) {
                val name = m.groupValues[1]
                val body = code.substring(m.range.first).let { rest -> rest.substring(0, rest.indexOf("\n@Composable").let { if (it < 0) rest.length else it }) }
                // A screen either renders the shell itself or delegates whole to one that does.
                val delegates = Regex("""^\s*(\w+Screen\w*|KitScreenView|NotBuilt)\(""", RegexOption.MULTILINE).containsMatchIn(body.substringAfter("{"))
                assertTrue(body.contains("AuthColumn") || delegates || name == "EntryScreens", "$name in ${f.name} must render inside AuthColumn")
                checked++
            }
        }
        assertTrue(checked >= 25, "found the new path's screens ($checked)")
    }
}
