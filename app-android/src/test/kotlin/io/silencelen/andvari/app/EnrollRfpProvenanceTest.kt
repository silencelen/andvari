package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.session.*
import io.silencelen.andvari.core.client.EnrollLink
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H66 — owner decision: **align Android with desktop.** A pasted enroll link's
 * `rfp` is ignored until a channel with real provenance (an `/enroll` app link, an in-app QR
 * scan) delivers it, and the affirm copy stops asserting a provenance the app cannot know.
 *
 * What was wrong: Wave-3 gave Android link parsing and fed `p.rfp` straight into the
 * required-affirm posture — the posture web reaches only by NAVIGATION to its own origin — while
 * desktop, on the identical input, refuses it ("a desktop PASTE has no provenance"). Two natives
 * took opposite security postures on one QR, and the Android copy told a member who pasted a link
 * out of a chat message that they had "scanned it in person".
 *
 * The fail-safe polarity was never the hole (a missing rfp never auto-trusts, and `Account.enroll`
 * re-checks the served key against the affirmed value); the ceremony and the honesty of the
 * sentence were. These pin both, plus the seam in the form — the pure rule is worthless if the
 * composable stops calling it.
 */
class EnrollRfpProvenanceTest {

    private companion object {
        const val ORIGIN = "https://vault.example.org"
        // A5: the in-person QR carries the FULL 64-hex fingerprint (a 16-hex rfp no longer parses).
        const val RFP = "14f1bf4220e132f3aa00bb11cc22dd33ee44ff5566778899aabbccddeeff0011"
    }

    private val mainSource =
        File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText()

    /** Comment-stripped, so a rule written down in prose cannot satisfy a pin about the code. */
    private val mainCode = mainSource
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    // ---- the rule ----

    /** THE DECISION: typed/pasted text yields no affirmable rfp, however well-formed the link. */
    @Test
    fun aPastedLinksRfpIsNotAffirmable() {
        assertNull(affirmableRfp(RFP, InviteProvenance.Typed), "a paste has no provenance — desktop's rule")
        assertNull(affirmableRfp(null, InviteProvenance.Typed))
    }

    /** …and the leg is not deleted, only unreachable: a real channel still lights it up. */
    @Test
    fun aProvenanceBearingChannelStillCarriesTheRfp() {
        assertEquals(RFP, affirmableRfp(RFP, InviteProvenance.AppLink))
        assertEquals(RFP, affirmableRfp(RFP, InviteProvenance.ScannedQr))
        // An empty rfp is the same as none — never an "affirm nothing" posture.
        assertNull(affirmableRfp("", InviteProvenance.ScannedQr))
        assertNull(affirmableRfp(null, InviteProvenance.AppLink))
    }

    /** End to end over a REAL composed link: the posture a pasted invite reaches is the
     *  sheet-driven one, exactly as on desktop — never required-affirm. */
    @Test
    fun aPastedLinkFallsBackToTheDesktopCeremony() {
        val link = EnrollLink.compose(origin = ORIGIN, token = "tok", email = "m@example.org", rfp = RFP)!!
        val parsed = parseInviteField(link, currentBaseUrl = ORIGIN)
        assertTrue(parsed is InviteFieldParse.Link)
        assertEquals(RFP, (parsed as InviteFieldParse.Link).rfp, "the parse still SEES the rfp…")

        val affirmable = affirmableRfp(parsed.rfp, InviteProvenance.Typed)
        assertEquals(EnrollPosture.Waived, enrollPosture(linkRfp = affirmable, memberHasSheet = false))
        assertEquals(EnrollPosture.RequiredTyped, enrollPosture(linkRfp = affirmable, memberHasSheet = true))
        // …and with provenance, the affirm leg is exactly what it was.
        assertEquals(
            EnrollPosture.RequiredAffirm,
            enrollPosture(linkRfp = affirmableRfp(parsed.rfp, InviteProvenance.ScannedQr), memberHasSheet = false),
        )
    }

    /** The link's OTHER fields are untouched — this row was never about distrusting the token,
     *  the origin (which still gates) or the invite-bound email. */
    @Test
    fun ignoringTheRfpDoesNotDisarmTheTrustGateOrThePrefill() {
        val foreign = EnrollLink.compose(origin = "https://elsewhere.example", token = "t9", email = "m@b.example", rfp = RFP)!!
        val parsed = parseInviteField(foreign, currentBaseUrl = ORIGIN) as InviteFieldParse.Link
        assertTrue(parsed.gate, "a foreign origin must still face the Trust Gate")
        assertEquals("t9", parsed.token)
        assertEquals("m@b.example", parsed.email)
    }

    // The seam tests (EnrollForm's provenance routing, its affirm copy, its submit anchor) and the enrollReady
    // gate went with the old EnrollForm. The pure rules above stay pinned while they exist.

    // ---- A5: the affirm leg compares the rfp at FULL length (the A2 carry-forward) ----

    /** A machine value is compared whole: a 16-hex (the pre-A5 id) or 32-hex (the human form) prefix of
     *  the server's fingerprint never passes; only the exact 64 lowercase hex does. */
    @Test
    fun affirmRfpComparesTheFullFingerprint() {
        assertTrue(affirmRfpMatches(RFP, RFP))
        assertFalse(affirmRfpMatches(RFP.take(16), RFP), "the retired 16-hex short id")
        assertFalse(affirmRfpMatches(RFP.take(32), RFP), "the 32-hex HUMAN form is not a machine match")
        assertFalse(affirmRfpMatches(RFP.uppercase(), RFP))
        assertFalse(affirmRfpMatches(null, RFP))
    }
}
