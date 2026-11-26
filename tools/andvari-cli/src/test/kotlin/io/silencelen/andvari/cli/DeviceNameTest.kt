package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A device name given on the command line is checked with the shared code's own
 * test ([io.silencelen.andvari.core.trust.TrustGrammar.isText]) before anything is sent, with a sentence that says which
 * kind of character is refused, never the server's `400 bad_device`. A name of visible characters and spaces is taken.
 */
class DeviceNameTest {
    @Test fun aDeviceNameIsCheckedBeforeAnythingIsSent() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val email = "dana@example.org"
            val refused = listOf(
                "my" + Char(0x202e) + "enohp" to "a character that changes the direction of text (U+202E)",
                "tab" + Char(0x09) + "here" to "a control character (such as a line break or a tab) (U+0009)",
                "zero" + Char(0x200b) + "width" to "an invisible character",
                "line" + Char(0x2028) + "two" to "a line or paragraph separator (U+2028)",
                "x".repeat(257) to "is longer than 256 characters",
            )
            ConnectionCounter().use { counter ->
                for ((name, kind) in refused) {
                    val r = w.run(w.home(email), "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", w.kit(email).path,
                        "--trust-card", w.card0, "--device-name", name, dial = counter.address)
                    assertEquals(2, r.code, r.out + r.err)
                    assertTrue(r.err.contains("--device-name is not a name andvari can use") && r.err.contains(kind) && r.err.contains("Nothing was sent"), r.err)
                    assertFalse(r.err.contains(Char(0x202e)) || r.err.contains("bad_device"), r.err)
                }
                assertEquals(0, counter.settled(), "nothing was sent for any of them")
            }
            // Spaces, punctuation and letters of any script are a name.
            val ok = w.run(w.home(email), "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", w.kit(email).path,
                "--trust-card", w.card0, "--device-name", " Dana's phone, été ")
            assertEquals(0, ok.code, ok.out + ok.err)
        }
    }
}
