package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.client.Tokens
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Wave-3 (design 2026-07-15-multi-tenant-endpoints §4) Android decision-function suite. Everything
 * security-critical about the endpoint switch + anti-phishing trust gate is a PURE function (the
 * [OriginNamespaceTest] precedent), so this pins it under `testDebugUnitTest` with no Android
 * framework: no-token-replay across a switch (§4.1 rule 1 / B1-5), the enroll-link→gate decision
 * (§4.4), the required-affirm posture from a link rfp, the pending commit/revert selection
 * (§4.1 rule 3), and the trust-gate render + copy rules (§4.3). The Context/Compose wiring around
 * these (the [TrustGateDialog], the pending Welcome UI, the [SessionStore] side effects) is
 * inspection-only and noted in the lane report.
 */
class Wave3EndpointSwitchTest {

    private val A = "https://a.example"
    private val B = "https://b.example"
    private val RFP = "b26efdd3eafc9dad" // a 16-hex org recovery short fingerprint

    // ---- §4.1 rule 1 (B1-5): NO token/session replay across a real origin switch ----

    @Test
    fun switchDropsSessionOnlyOnRealOriginChange() {
        assertTrue(switchDropsSession(A, B), "a different origin is a real switch → drop")
        // canonicalization agrees with OriginNamespace: trailing slash / default port / case are no-ops
        assertFalse(switchDropsSession(A, "$A/"))
        assertFalse(switchDropsSession("https://a.example", "https://a.example:443"))
        assertFalse(switchDropsSession("https://a.example", "HTTPS://A.EXAMPLE"))
        assertTrue(switchDropsSession("https://a.example", "https://a.example:8443"), "a non-default port is a distinct origin")
        assertTrue(switchDropsSession("https://a.example", "http://a.example"), "a distinct scheme is a distinct origin")
    }

    @Test
    fun noAuthorizationHeaderCrossesABaseUrlChange() {
        // The pure model of what setBaseUrl enforces on the Context-bound store/api: a client
        // rebuilt for the NEW origin inherits NO token from the old one — so no Authorization
        // header can ever cross a baseUrl change (the §4.1 rule 1 regression the brief demands).
        val old = Tokens("access-A", "refresh-A")
        assertNull(inheritedTokensAcrossSwitch(A, B, old), "a real switch inherits no token")
        // …but a no-op canonical re-entry of your own origin keeps the session (must not sign you out).
        assertEquals(old, inheritedTokensAcrossSwitch(A, "$A/", old))
        assertNull(inheritedTokensAcrossSwitch(A, B, null))
    }

    // ---- §4.4: enroll-link field parse → gate decision + rfp → required-affirm posture ----

    @Test
    fun plainTokenIsNotALinkAndNeverGates() {
        val p = parseInviteField("PLAIN-INVITE-TOKEN", A)
        assertIs<InviteFieldParse.Token>(p)
        assertEquals("PLAIN-INVITE-TOKEN", p.token)
        // a plain token drives no posture change (no rfp)
        assertEquals(EnrollPosture.Waived, enrollPosture(linkRfp = null, memberHasSheet = false))
    }

    @Test
    fun sameOriginLinkDoesNotGateAndUnpacksTokenAndEmail() {
        val link = EnrollLink.compose(origin = A, token = "tok123", email = "m@a.example", rfp = null)!!
        val p = parseInviteField(link, currentBaseUrl = A)
        assertIs<InviteFieldParse.Link>(p)
        assertFalse(p.gate, "p.o == baseUrl ⇒ no gate")
        assertEquals("tok123", p.token)
        assertEquals("m@a.example", p.email)
        assertNull(p.rfp)
    }

    @Test
    fun foreignOriginLinkGatesAndCarriesOrigin() {
        val link = EnrollLink.compose(origin = B, token = "tok9", email = "m@b.example", rfp = null)!!
        val p = parseInviteField(link, currentBaseUrl = A)
        assertIs<InviteFieldParse.Link>(p)
        assertTrue(p.gate, "p.o != baseUrl ⇒ gate")
        assertEquals(B, p.origin)
        // a trailing-slash baseUrl is canonically the same origin — still no gate for our own server
        val same = parseInviteField(EnrollLink.compose(A, "t", "m@a.example")!!, "$A/")
        assertFalse((same as InviteFieldParse.Link).gate)
    }

    @Test
    fun linkRfpDrivesRequiredAffirmPosture() {
        val link = EnrollLink.compose(origin = A, token = "t", email = "m@a.example", rfp = RFP)!!
        val p = parseInviteField(link, currentBaseUrl = A)
        assertIs<InviteFieldParse.Link>(p)
        assertEquals(RFP, p.rfp)
        // the brief's pin: an rfp on the link ⇒ required-affirm (Android gains the posture)
        assertEquals(EnrollPosture.RequiredAffirm, enrollPosture(linkRfp = p.rfp, memberHasSheet = false))
        assertEquals(EnrollPosture.RequiredAffirm, enrollPosture(linkRfp = p.rfp, memberHasSheet = true), "rfp wins over a sheet declaration")
        // no rfp ⇒ posture stays waived/required-typed as before (no regression)
        assertEquals(EnrollPosture.Waived, enrollPosture(linkRfp = null, memberHasSheet = false))
        assertEquals(EnrollPosture.RequiredTyped, enrollPosture(linkRfp = null, memberHasSheet = true))
    }

    // ---- §4.1 rule 3: pending invite switch commits on success, reverts otherwise ----

    @Test
    fun pendingSwitchCommitsOnSuccessRevertsOtherwise() {
        val pending = PendingServer(origin = B, previousOrigin = A, email = "m@b.example", ts = 0L)
        assertEquals(B, resolvedDefaultOrigin(pending, enrollSucceeded = true), "enroll success commits the new origin")
        assertEquals(A, resolvedDefaultOrigin(pending, enrollSucceeded = false), "cancel / failure / discard reverts")
    }

    // ---- §4.3: trust-gate render rules (punycode, plain-http) + copy selection ----

    @Test
    fun trustGateRenderCleanAsciiHttpsHasNoCautions() {
        val r = trustGateRender("https://example.org")
        assertEquals("https://example.org", r.displayOrigin)
        assertFalse(r.punycodeCaution)
        assertFalse(r.httpCaution)
        // port preserved, still no caution
        assertEquals("https://vault.example.org:8443", trustGateRender("https://vault.example.org:8443").displayOrigin)
    }

    @Test
    fun trustGateRenderCautionsPlainHttp() {
        val r = trustGateRender("http://192.168.1.9:8080")
        assertTrue(r.httpCaution, "http:// gets the plain-http caution")
        assertFalse(r.punycodeCaution)
        assertEquals("http://192.168.1.9:8080", r.displayOrigin)
    }

    @Test
    fun trustGateRenderPunycodesNonAsciiHost() {
        // a non-ASCII (IDN homograph) host renders in punycode with the caution
        val r = trustGateRender("https://例え.jp") // 例え.jp
        assertTrue(r.punycodeCaution, "non-ASCII host ⇒ caution")
        assertTrue(r.displayOrigin.startsWith("https://xn--"), "shown as punycode, got ${r.displayOrigin}")
        assertTrue(r.displayOrigin.all { it.code <= 0x7F }, "the shown origin is pure ASCII punycode")
    }

    @Test
    fun trustGateRenderCautionsAlreadyEncodedPunycode() {
        // an attacker who sends the xn-- form directly still trips the IDN caution
        val r = trustGateRender("https://xn--r8jz45g.example")
        assertTrue(r.punycodeCaution)
        assertFalse(r.httpCaution)
    }

    @Test
    fun trustGateCopySelectsBaselineVsEnrollment() {
        val baseline = trustGateBody(enrollment = false)
        assertEquals(1, baseline.size)
        assertEquals(TRUST_GATE_BASELINE, baseline[0])
        assertTrue(baseline[0].contains("encrypted vault"))

        val enrollment = trustGateBody(enrollment = true)
        assertEquals(2, enrollment.size)
        assertEquals(TRUST_GATE_BASELINE, enrollment[0])
        assertEquals(TRUST_GATE_ENROLLMENT_EXTRA, enrollment[1])
        // B2-8: the enrollment variant carries the password-reuse warning verbatim
        assertTrue(enrollment[1].contains("Choose a master password you don't use anywhere else"))
        assertTrue(enrollment[1].contains("NEW account"))
    }

    // §4.4 (review 2026-07-16 MEDIUM) manual-switch canonicalization: reject the userinfo/path
    // authKey-phishing vector so the gate can never show a reassuring host while dialing another.
    @Test
    fun canonicalServerOriginRejectsUserinfoAndPathVectors() {
        assertNull(OriginNamespace.canonicalServerOrigin("https://andvari.monahanhosting.com@evil.example")) // dials evil.example
        assertNull(OriginNamespace.canonicalServerOrigin("https://user:pass@evil.example"))
        assertNull(OriginNamespace.canonicalServerOrigin("https://evil.example/andvari.monahanhosting.com")) // reassuring path
        assertNull(OriginNamespace.canonicalServerOrigin("https://evil.example?x=1"))
        assertNull(OriginNamespace.canonicalServerOrigin("https://evil.example#frag"))
        assertNull(OriginNamespace.canonicalServerOrigin("ftp://x.example"))
        assertNull(OriginNamespace.canonicalServerOrigin("not a url"))
        assertNull(OriginNamespace.canonicalServerOrigin(""))
    }

    @Test
    fun canonicalServerOriginCanonicalizesCleanOrigins() {
        assertEquals("https://vault.example.org", OriginNamespace.canonicalServerOrigin("https://Vault.Example.ORG/")) // case + trailing slash
        assertEquals("https://vault.example.org", OriginNamespace.canonicalServerOrigin("https://vault.example.org:443")) // default port stripped
        assertEquals("https://vault.example.org:8443", OriginNamespace.canonicalServerOrigin("https://vault.example.org:8443"))
        assertEquals("http://192.168.1.9:8080", OriginNamespace.canonicalServerOrigin("http://192.168.1.9:8080")) // LAN self-host
    }

    // §4.3 IDN fail-CLOSED: a non-ASCII host that IDN.toASCII can't encode must NOT render as raw
    // homograph glyphs (the caution still fires).
    @Test
    fun trustGateRenderIdnFailsClosedWhenPunycodeThrows() {
        val overlong = "а".repeat(70) + ".example" // 70 Cyrillic а → xn-- label > 63 chars → IDN.toASCII throws
        val r = trustGateRender("https://$overlong")
        assertTrue(r.punycodeCaution, "still flagged international")
        assertFalse(r.displayOrigin.any { it.code > 0x7F }, "no raw non-ASCII glyph in the display, got ${r.displayOrigin}")
    }

    // §4.3 B2-6: ONLY a launch-reconcile Finish gate's Cancel restores the reconcile prompt (store.baseUrl
    // is on the uncommitted foreign origin — a bare Welcome would re-expose sign-in there); a manual/invite
    // gate never moved store.baseUrl, so its Cancel restores nothing.
    @Test
    fun reconcileRestoreOnCancelOnlyForReconcileFinish() {
        val marker = PendingServer("https://b.example", "https://a.example", null, 1L)
        assertEquals(marker, reconcileRestoreOnCancel(TrustGateAction.ReconcileFinish("https://b.example"), marker))
        assertNull(reconcileRestoreOnCancel(TrustGateAction.ManualSwitch("https://b.example"), marker))
        assertNull(reconcileRestoreOnCancel(TrustGateAction.InviteRepoint("https://b.example", "e@x"), marker))
        assertNull(reconcileRestoreOnCancel(null, marker))
        assertNull(reconcileRestoreOnCancel(TrustGateAction.ReconcileFinish("https://b.example"), null))
    }
}
