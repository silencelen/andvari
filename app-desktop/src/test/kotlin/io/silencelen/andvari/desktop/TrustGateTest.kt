package io.silencelen.andvari.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * §4.3 anti-phishing Trust Gate render DECISIONS + §4.3 (B2-9) launch reconcile decision, as PURE
 * functions (design 2026-07-15-multi-tenant-endpoints §4.3/§4.4). The Compose gate renders exactly
 * [TrustGateModel]'s fields, so pinning the decision here pins the gate: raw origin never a display
 * name, non-ASCII host → punycode + caution, http → caution, enrollment-vs-baseline copy verbatim.
 */
class TrustGateTest {
    // Raw origin is shown as-is (monospaced/dominant in the composable) and is NEVER a display name;
    // an ASCII origin needs no punycode and raises no caution.
    @Test
    fun asciiHttpsOriginRendersRawWithNoCautions() {
        val m = trustGateModel("https://vault.example.org", TrustGateVariant.Baseline)
        assertEquals("https://vault.example.org", m.rawOrigin)
        assertEquals("https://vault.example.org", m.displayOrigin)
        assertFalse(m.internationalized)
        assertFalse(m.plainHttp)
        assertNull(m.internationalCaution)
        assertNull(m.httpCaution)
    }

    // §4.3 IDN defense: a non-ASCII host renders in punycode (xn--…) for the DOMINANT line, so the
    // user never eyeballs the deceptive glyphs as the destination — with the "international
    // characters" caution.
    @Test
    fun nonAsciiHostPunycodedWithCaution() {
        // "аndvari" leads with a Cyrillic а (U+0430) — a classic homograph of ASCII 'a'.
        val m = trustGateModel("https://аndvari.example", TrustGateVariant.Enrollment)
        assertTrue(m.internationalized, "a non-ASCII host must be flagged")
        assertTrue(m.displayOrigin.contains("xn--"), "the dominant line must render punycode, got ${m.displayOrigin}")
        assertFalse(m.displayOrigin.contains("а"), "the deceptive glyph must NOT be the dominant line")
        assertTrue(m.internationalCaution!!.contains("international characters"))
        // the raw origin is preserved verbatim (for the record), separate from the punycoded display
        assertEquals("https://аndvari.example", m.rawOrigin)
    }

    // A non-default port and IPv6-safe host extraction don't false-trigger the IDN path.
    @Test
    fun asciiHostWithPortIsNotInternationalized() {
        val m = trustGateModel("https://vault.example.org:8443", TrustGateVariant.Baseline)
        assertFalse(m.internationalized)
        assertEquals("https://vault.example.org:8443", m.displayOrigin)
    }

    // §4.3 plain-http caution — the transport warning fires for http:// only.
    @Test
    fun httpOriginRaisesPlainHttpCaution() {
        val http = trustGateModel("http://192.168.1.5:8080", TrustGateVariant.Baseline)
        assertTrue(http.plainHttp)
        assertTrue(http.httpCaution!!.contains("unencrypted"))
        assertFalse(http.internationalized) // an IP literal is ASCII

        val https = trustGateModel("https://192.168.1.5:8080", TrustGateVariant.Baseline)
        assertFalse(https.plainHttp)
        assertNull(https.httpCaution)
    }

    // §4.3 copy selection: BASELINE (manual repoint) has no enrollment note; ENROLLMENT adds the
    // B2-8 new-account/password-reuse warning verbatim. Both share the lead + body.
    @Test
    fun baselineVsEnrollmentCopySelection() {
        val baseline = trustGateModel("https://example.org", TrustGateVariant.Baseline)
        assertFalse(baseline.enrollment)
        assertNull(baseline.enrollmentNote)

        val enroll = trustGateModel("https://example.org", TrustGateVariant.Enrollment)
        assertTrue(enroll.enrollment)
        val note = enroll.enrollmentNote!!
        assertTrue(note.contains("Enrolling creates a NEW account"))
        assertTrue(note.contains("Choose a master password you don't use anywhere else"))
        // lead + body are identical across variants (only the note differs)
        assertEquals(baseline.lead, enroll.lead)
        assertEquals(baseline.body, enroll.body)
        assertTrue(baseline.body.contains("store your encrypted vault"))
    }

    // §4.3 (B2-9) reconcile: a marker whose origin canonicalizes to the committed default is an
    // already-committed straggler (silent clear); a different origin is uncommitted ⇒ reconcile.
    @Test
    fun reconcileDecisionByCommitState() {
        assertEquals(
            PendingReconcileDecision.Reconcile,
            pendingReconcileDecision("https://invite.example", "https://home.example"),
        )
        assertEquals(
            PendingReconcileDecision.AlreadyCommitted,
            pendingReconcileDecision("https://home.example", "https://home.example"),
        )
        // canonical-origin keyed: a trailing-slash / case difference is NOT a spurious reconcile
        assertEquals(
            PendingReconcileDecision.AlreadyCommitted,
            pendingReconcileDecision("https://Home.example/", "https://home.example"),
        )
    }

    // §4.4 (review 2026-07-16 MEDIUM) manual-switch canonicalization: a userinfo/path input is the
    // authKey-phishing vector (the gate would show a reassuring host while the HTTP stack dials
    // another) — REJECT it so it can never arm the gate or reach the dialer.
    @Test
    fun canonicalServerOriginRejectsTheUserinfoAndPathPhishingVectors() {
        assertNull(canonicalServerOrigin("https://andvari.monahanhosting.com@evil.example")) // dials evil.example
        assertNull(canonicalServerOrigin("https://user:pass@evil.example"))
        assertNull(canonicalServerOrigin("https://evil.example/andvari.monahanhosting.com")) // reassuring path
        assertNull(canonicalServerOrigin("https://evil.example?x=1"))
        assertNull(canonicalServerOrigin("https://evil.example#frag"))
        assertNull(canonicalServerOrigin("ftp://x.example"))
        assertNull(canonicalServerOrigin("javascript:alert(1)"))
        assertNull(canonicalServerOrigin("not a url"))
        assertNull(canonicalServerOrigin(""))
    }

    @Test
    fun canonicalServerOriginAcceptsAndCanonicalizesCleanOrigins() {
        assertEquals("https://vault.example.org", canonicalServerOrigin("https://vault.example.org"))
        assertEquals("https://vault.example.org", canonicalServerOrigin("https://Vault.Example.ORG/")) // case + trailing slash
        assertEquals("https://vault.example.org", canonicalServerOrigin("https://vault.example.org:443")) // default port stripped
        assertEquals("https://vault.example.org:8443", canonicalServerOrigin("https://vault.example.org:8443"))
        assertEquals("http://192.168.1.9:8080", canonicalServerOrigin("http://192.168.1.9:8080")) // LAN self-host
    }

    // §4.3 IDN defense fail-CLOSED: when IDN.toASCII CANNOT punycode a non-ASCII host (it throws on a
    // label too long to encode), the display must NOT fall back to the raw homograph glyphs.
    @Test
    fun idnDisplayFailsClosedWhenPunycodeThrows() {
        val overlong = "а".repeat(70) + ".example" // 70 Cyrillic а → xn-- label > 63 chars → IDN.toASCII throws
        val m = trustGateModel("https://$overlong", TrustGateVariant.Baseline)
        assertTrue(m.internationalized, "still flagged international so the caution fires")
        assertFalse(m.displayOrigin.any { it.code > 0x7f }, "the display must carry NO raw non-ASCII glyph, got ${m.displayOrigin}")
    }
}
