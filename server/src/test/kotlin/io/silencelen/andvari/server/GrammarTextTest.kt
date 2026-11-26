package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.builtins.serializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec 03 §0.1 `text`: a display name and a device's name refuse direction overrides,
 * zero-width characters and line and paragraph separators, exactly as the `name` type of an instance's or a
 * device link's name does. Before, `text` refused only the controls.
 */
class GrammarTextTest {
    private fun cp(n: Int) = String(Character.toChars(n))
    private fun json(s: String) = WireJson.json.encodeToString(String.serializer(), s)

    @Test
    fun text_refusesExactlyWhatNameRefuses_onEveryCodePoint() {
        val differ = ArrayList<String>()
        for (n in 0..0x10FFFF) {
            if (n in 0xD800..0xDFFF || n == 0x20) continue // surrogates are not code points; a lone space is a name's edge rule
            val s = cp(n)
            if (Grammar.isText(s) != (TrustGrammar.encodeName(s) != null)) differ += "U+%04X".format(n)
            if (differ.size > 20) break
        }
        assertEquals(emptyList(), differ)
        assertTrue(Grammar.isText(" ")) // `text` has no edge rule
    }

    @Test
    fun text_theNamedCharacters_andLoneSurrogates() {
        for (n in listOf(0x202E, 0x202D, 0x2066, 0x2069, 0x200E, 0x200F, 0x061C, 0x200B, 0x200D, 0xFEFF, 0x2060, 0x2028, 0x2029, 0x00AD, 0x0A, 0x7F, 0x85)) {
            assertFalse(Grammar.isText("Eve${cp(n)}gnp.exe"), "U+%04X".format(n))
        }
        assertFalse(Grammar.isText("a\uD800"), "a lone high surrogate")
        assertFalse(Grammar.isText("\uDC00a"), "a lone low surrogate")
        assertFalse(Grammar.isText("a\uDC00\uD800"), "a reversed pair")
        assertFalse(Grammar.isText(""))
        assertFalse(Grammar.isText("x".repeat(257)))
        for (ok in listOf("Jo's Pixel 8", "Søren's MacBook ✓", "Работа", "مكتب", "家のパソコン", "laptop ${cp(0x1F4BB)}", "x".repeat(256))) {
            assertTrue(Grammar.isText(ok), ok)
        }
    }

    @Test
    fun theRoutes_refuseSuchANameForAnAccountOrADevice() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val post = HttpMethod.Post
        val rlo = "Eve${cp(0x202E)}gnp.exe"
        val zw = "my${cp(0x200B)}laptop"
        val ls = "line${cp(0x2028)}break"
        // Register: the display name, then the device's name.
        for ((field, bad, code) in listOf(Triple("displayName", rlo, "bad_display_name"), Triple("name", zw, "bad_device"), Triple("name", ls, "bad_device"))) {
            val me = Me("r${field.length}${bad.length}@example.com")
            val from = if (field == "displayName") "\"displayName\":\"Me\"" else "\"name\":\"my laptop\""
            val plain = me.register(s, Flow.enrolAuth(s))
            val body = plain.replace(from, "\"$field\":${json(bad)}")
            assertTrue(body != plain, "the name was put in")
            val r = c.call(post, "/api/v1/auth/register", body)
            assertEquals(400, r.status.value, r.bodyAsText()); assertEquals(code, r.errorCode(), field)
        }
        // Sign-in on a new device.
        val me = Flow.member(c, s, "me@example.com")
        for (bad in listOf(rlo, zw, ls)) {
            val r = c.call(post, "/api/v1/auth/login", me.loginBody().replace("\"name\":\"other laptop\"", "\"name\":${json(bad)}"))
            assertEquals(400, r.status.value, r.bodyAsText()); assertEquals("bad_device", r.errorCode())
        }
        // A plain name in any script is still taken.
        val r = c.call(post, "/api/v1/auth/login", me.loginBody().replace("\"name\":\"other laptop\"", "\"name\":${json("Søren's 家のパソコン ${cp(0x1F4BB)}")}"))
        assertEquals(200, r.status.value, r.bodyAsText())
    }
}
