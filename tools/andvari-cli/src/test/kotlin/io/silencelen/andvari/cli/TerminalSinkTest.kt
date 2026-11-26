package io.silencelen.andvari.cli

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * No string a server sent reaches the terminal as itself. The tool has one sink ([Term]), and every
 * line goes through one function ([Shown.text]). This test pins both: on the shipped classes, nothing but [Term] prints,
 * reads the console or reaches standard output or error; and the function escapes every character a terminal acts on.
 */
class TerminalSinkTest {
    private val cli = "io/silencelen/andvari/cli/"

    @Test fun nothingButTheSinkPrintsOrReachesTheConsole() {
        assertTrue(ShippedClasses.classes.size > 20 && ShippedClasses.classes.keys.any { it.startsWith("${cli}Term") }, ShippedClasses.classes.keys.toString())
        val printing = setOf("print", "println", "printf", "format", "write", "append", "flush")
        val bypass = ShippedClasses.users { r ->
            (r.owner == "java/io/PrintStream" && r.name in printing) ||
                (r.owner == "java/io/PrintWriter" && r.name in printing) ||
                (r.owner == "java/io/Console" && r.name in setOf("printf", "format", "readLine", "readPassword", "writer", "reader")) ||
                (r.owner == "java/lang/System" && r.name in setOf("out", "err", "console", "setOut", "setErr")) ||
                (r.owner == "kotlin/io/ConsoleKt" && r.name in setOf("print", "println")) ||
                (r.owner == "java/lang/Throwable" && r.name == "printStackTrace")
        }
        assertEquals(setOf("${cli}Term"), bypass.keys, "only the sink prints; the others: ${bypass.filterKeys { it != "${cli}Term" }}")
    }

    @Test fun theOneFunctionEscapesEveryCharacterATerminalActsOn() {
        val esc = Char(0x1b)
        val cases = mapOf(
            "a${esc}[2Jb" to "a\\u{001B}[2Jb",
            "line\nforged" to "line\\nforged",
            "back\rover" to "back\\rover",
            "tab\there" to "tab\\there",
            "csi" + Char(0x9b) + "31m" to "csi\\u{009B}31m",
            "bell" + Char(7) to "bell\\u{0007}",
            "del" + Char(0x7f) to "del\\u{007F}",
            "nul" + Char(0) to "nul\\u{0000}",
            "rlo" + Char(0x202e) + "txt.exe" to "rlo\\u{202E}txt.exe",
            "isolate" + Char(0x2066) + "x" + Char(0x2069) to "isolate\\u{2066}x\\u{2069}",
            "mark" + Char(0x200f) to "mark\\u{200F}",
            "zero" + Char(0x200b) + "width" + Char(0x200d) + Char(0xfeff) to "zero\\u{200B}width\\u{200D}\\u{FEFF}",
            "word" + Char(0x2060) + "joiner" + Char(0x00ad) to "word\\u{2060}joiner\\u{00AD}",
            "sep" + Char(0x2028) + Char(0x2029) to "sep\\u{2028}\\u{2029}",
            "filler" + Char(0x3164) to "filler\\u{3164}",
            "tag" + String(Character.toChars(0xE0041)) to "tag\\u{E0041}",
            "lone" + Char(0xd800) to "lone\\u{D800}",
        )
        for ((raw, shown) in cases) {
            assertEquals(shown, Shown.text(raw), raw)
            assertTrue(Shown.text(raw).none { Shown.harmful(it.code) }, raw)
        }
        // Text a terminal draws plainly is left as it is.
        for (plain in listOf("Família “Casa” — 7 items", "日本語のメモ", "emoji 🔑 key", "back\\slash", "")) assertEquals(plain, Shown.text(plain))
    }

    @Test fun aValueToPasteIsOneShellWord() {
        assertEquals("alice@example.org", Shown.arg("alice@example.org"))
        assertEquals("1b4e28ba-2fa1-4d3b-8e5b-9f2c3a4d5e6f", Shown.arg("1b4e28ba-2fa1-4d3b-8e5b-9f2c3a4d5e6f"))
        assertEquals("https://vault.example.org", Shown.arg("https://vault.example.org"))
        assertEquals("'a`id`\$x|y&z@example.org'", Shown.arg("a`id`\$x|y&z@example.org"))
        assertEquals("'o'\\''brien@example.org'", Shown.arg("o'brien@example.org"))
        assertEquals("'x; rm -rf ~'", Shown.arg("x; rm -rf ~"))
        assertEquals("''", Shown.arg(""))
    }

    @Test fun aJsonDocumentMeansTheSameAndHoldsNothingATerminalActsOn() {
        val esc = Char(0x1b)
        val value = "a${esc}[2J" + Char(0x202e) + Char(0x9b) + Char(0x2028) + String(Character.toChars(0xE0041)) + "\n\"z"
        val doc = buildJsonObject { put("name", JsonPrimitive(value)) }.toString()
        val safe = Shown.json(doc)
        assertTrue(safe.none { Shown.harmful(it.code) }, safe)
        assertEquals(value, Json.parseToJsonElement(safe).jsonObject.getValue("name").jsonPrimitive.content)
        assertEquals("{\n  \"a\": 1\n}", Shown.json("{\n  \"a\": 1\n}"), "a pretty document's own line breaks stay")
    }
}
