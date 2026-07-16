import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { EnrollMismatchNotice, LandingNudge, freshStartAffordances, landingModeFor, type FreshStartState, type LandingMode } from "./Welcome";

/**
 * Wave-3 WEB (design 2026-07-15-multi-tenant-endpoints §7.1 reference-instance landing + §4.4
 * REJECT-on-mismatch, B2-2). The landing is a pure CLIENT RENDERING of the server-declared
 * `signupMode` (§2.1) — no server flow, no account oracle — so the decision is a pure function and
 * the two banners are pure presentational components, proven statically (house pattern:
 * Devices.test.ts / Field.test.ts — renderToStaticMarkup runs no effects, so the emitted markup is
 * a pure function of props). The full FreshStart card reads window.location + module singletons and
 * cannot render in the node env, so the affordance-by-mode contract is pinned on landingModeFor
 * (the exact function the card branches on).
 */

describe("landingModeFor — the reference-instance landing decision, keyed on the DECLARED signupMode (§2.1/§7.1)", () => {
  it('"landing" is the reference-instance stranger landing', () => {
    expect(landingModeFor("landing")).toBe("landing");
  });
  it('"closed" is sign-in only (the per-origin break-glass overlay, §2.2)', () => {
    expect(landingModeFor("closed")).toBe("closed");
  });
  it('"invite-only" is today\'s plain sign-in + invite-gated enroll', () => {
    expect(landingModeFor("invite-only")).toBe("invite-only");
  });
  it('"open" is RESERVED — treated as landing until the open-register path ships (§7.3)', () => {
    expect(landingModeFor("open")).toBe("landing");
  });
  it("absent (old server / a failed policy fetch ⇒ policy null) degrades to invite-only (§2.3 conservative default)", () => {
    expect(landingModeFor(undefined)).toBe("invite-only");
    expect(landingModeFor(null)).toBe("invite-only");
  });
  it("an unknown value from a NEWER server degrades to invite-only — NEVER an open-register surface (§2.1)", () => {
    expect(landingModeFor("some-future-mode")).toBe("invite-only");
    expect(landingModeFor("")).toBe("invite-only");
  });
});

describe("landing affordances per mode — the exact booleans FreshStart branches on (§7.1)", () => {
  // enrollAvailable = mode !== "closed"; nudge = mode === "landing"; default tab = enroll iff landing.
  const enrollAvailable = (m: string | null | undefined) => landingModeFor(m) !== "closed";
  const showsNudge = (m: string | null | undefined) => landingModeFor(m) === "landing";

  it('ONLY "closed" hides the enroll surface (sign-in only); every other mode keeps enroll available', () => {
    expect(enrollAvailable("closed")).toBe(false);
    for (const m of ["landing", "open", "invite-only", undefined, null, "weird"]) {
      expect(enrollAvailable(m)).toBe(true);
    }
  });
  it('ONLY "landing"/"open" show the stranger self-host nudge (invite-only shows none — no stranger nudge)', () => {
    expect(showsNudge("landing")).toBe(true);
    expect(showsNudge("open")).toBe(true); // open → landing for now
    for (const m of ["invite-only", "closed", undefined, null, "weird"]) {
      expect(showsNudge(m)).toBe(false);
    }
  });
});

describe("freshStartAffordances — the security-relevant mode→affordance WIRING FreshStart calls (§2.1/§7.1/§4.4)", () => {
  // FreshStart reads window.location + module singletons and cannot render in the node env, so the
  // seam that connects landingModeFor + the link/consent/blocking state to the exposed surfaces is
  // pinned HERE, on the exact pure function the card destructures. A future mis-wire (enroll exposed
  // on a "closed" break-glass origin, or the tab not forced to sign-in) would fail these — where 17
  // render-blind tests would not. `base` = everything neutral; `aff` overrides one axis at a time.
  const base: FreshStartState = { hasPendingLink: false, hasValidPrefill: false, tab: "signin", consented: false, dismissed: false, blocking: false };
  const aff = (mode: LandingMode, over: Partial<FreshStartState> = {}) => freshStartAffordances(mode, { ...base, ...over });

  it('enrollAvailable is TRUE for every mode EXCEPT "closed" (the §2.2 break-glass origin exposes NO enroll surface)', () => {
    expect(aff("closed").enrollAvailable).toBe(false);
    expect(aff("landing").enrollAvailable).toBe(true);
    expect(aff("invite-only").enrollAvailable).toBe(true);
  });

  it('effectiveTab is FORCED to "signin" whenever enroll is unavailable — even if `tab` is stale on "enroll" (a landing→closed refresh)', () => {
    // "closed": the enroll tab is never honoured, whatever the current selection.
    expect(aff("closed", { tab: "enroll" }).effectiveTab).toBe("signin");
    expect(aff("closed", { tab: "signin" }).effectiveTab).toBe("signin");
    // enroll available: the user's selection is honoured verbatim (no forcing).
    expect(aff("invite-only", { tab: "enroll" }).effectiveTab).toBe("enroll");
    expect(aff("invite-only", { tab: "signin" }).effectiveTab).toBe("signin");
    expect(aff("landing", { tab: "enroll" }).effectiveTab).toBe("enroll");
  });

  it("showConsentCard needs enroll available AND a valid same-origin prefill AND neither consented nor dismissed (consume-semantics rule 4)", () => {
    const armed = { hasPendingLink: true, hasValidPrefill: true };
    expect(aff("invite-only", armed).showConsentCard).toBe(true);
    // consenting or dismissing closes the gate…
    expect(aff("invite-only", { ...armed, consented: true }).showConsentCard).toBe(false);
    expect(aff("invite-only", { ...armed, dismissed: true }).showConsentCard).toBe(false);
    // …no valid prefill → nothing to consent to…
    expect(aff("invite-only", { hasPendingLink: true, hasValidPrefill: false }).showConsentCard).toBe(false);
    // …and "closed" NEVER shows it, even for a (crafted) valid same-origin link (§2.1).
    expect(aff("closed", armed).showConsentCard).toBe(false);
  });

  it('showTabBar hides while a child reveal blocks (escape-hatch guard §F.7/§F.9) AND whenever enroll is unavailable ("closed" ⇒ sign-in only)', () => {
    expect(aff("invite-only").showTabBar).toBe(true);
    expect(aff("landing").showTabBar).toBe(true);
    expect(aff("invite-only", { blocking: true }).showTabBar).toBe(false); // reveal up → no escape hatch
    expect(aff("closed").showTabBar).toBe(false); // no enroll surface → no tab bar
  });

  it('showNudge is the stranger self-host nudge — ONLY "landing", and never while a child reveal blocks', () => {
    expect(aff("landing").showNudge).toBe(true);
    expect(aff("landing", { blocking: true }).showNudge).toBe(false);
    expect(aff("invite-only").showNudge).toBe(false);
    expect(aff("closed").showNudge).toBe(false);
  });

  it("showMismatch is the §4.4 terminal reject — a captured link present but NOT valid for this origin, independent of mode", () => {
    // pending link that did not validate for this origin → the mismatch notice (even on "closed").
    expect(aff("invite-only", { hasPendingLink: true, hasValidPrefill: false }).showMismatch).toBe(true);
    expect(aff("closed", { hasPendingLink: true, hasValidPrefill: false }).showMismatch).toBe(true);
    // a valid prefill is NOT a mismatch; and no captured link is not a mismatch.
    expect(aff("invite-only", { hasPendingLink: true, hasValidPrefill: true }).showMismatch).toBe(false);
    expect(aff("invite-only", { hasPendingLink: false }).showMismatch).toBe(false);
  });

  it('composes with landingModeFor: a reserved "open" server resolves to the landing surface (nudge shown, enroll available)', () => {
    const a = freshStartAffordances(landingModeFor("open"), base);
    expect(a.enrollAvailable).toBe(true);
    expect(a.showNudge).toBe(true);
    expect(a.effectiveTab).toBe("signin"); // base tab honoured (enroll available ⇒ no forcing)
  });
});

describe("LandingNudge — §7.1 self-host nudge (selfHostDocsUrl a RAW link, only when present; no account oracle)", () => {
  it("renders the invite-only landing copy and the self-host nudge", () => {
    const html = renderToStaticMarkup(createElement(LandingNudge, { selfHostDocsUrl: null }));
    expect(html).toContain("private, invite-only server");
    expect(html).toContain("Have an invite?");
    expect(html).toContain("self-hostable");
    expect(html).toContain("run your own server");
  });

  it("renders selfHostDocsUrl as a RAW anchor whose TEXT is the exact URL when present (§2.3 R8 rule)", () => {
    const url = "https://andvari.monahanhosting.com/selfhost";
    const html = renderToStaticMarkup(createElement(LandingNudge, { selfHostDocsUrl: url }));
    expect(html).toContain(`href="${url}"`);
    expect(html).toContain(`>${url}</a>`); // the raw URL is the link TEXT — never dressed-up branding
  });

  it("accepts an http self-host URL too (LAN self-host, §3 https-required carve-out for local hosts)", () => {
    const url = "http://192.168.1.9:8080/selfhost";
    const html = renderToStaticMarkup(createElement(LandingNudge, { selfHostDocsUrl: url }));
    expect(html).toContain(`href="${url}"`);
  });

  it("renders NO link when selfHostDocsUrl is absent/empty (a decorative field a hostile server may omit)", () => {
    for (const v of [null, undefined, ""] as (string | null | undefined)[]) {
      const html = renderToStaticMarkup(createElement(LandingNudge, { selfHostDocsUrl: v }));
      expect(html).not.toContain("<a ");
    }
  });

  it("REFUSES a non-http(s) selfHostDocsUrl — a hostile server cannot inject a javascript:/data: href", () => {
    for (const bad of ["javascript:alert(1)", "data:text/html,<script>x</script>", "vbscript:x", "not a url"]) {
      const html = renderToStaticMarkup(createElement(LandingNudge, { selfHostDocsUrl: bad }));
      expect(html).not.toContain("<a "); // link omitted entirely
      expect(html).not.toContain("javascript:");
      expect(html).not.toContain("data:");
    }
  });

  it("adds NO account/enumeration surface — no input, no email probe, no 'account exists' oracle (§7.1)", () => {
    const html = renderToStaticMarkup(createElement(LandingNudge, { selfHostDocsUrl: "https://x.example/selfhost" }));
    expect(html).not.toContain("<input");
    expect(html.toLowerCase()).not.toContain("email");
  });
});

describe("EnrollMismatchNotice — §4.4 reject-on-mismatch is TERMINAL and NON-ACTIONABLE (B2-2)", () => {
  const FOREIGN = "https://evil.example";

  it("states the invite's true origin and tells the user to open the original link", () => {
    const html = renderToStaticMarkup(createElement(EnrollMismatchNotice, { origin: FOREIGN }));
    expect(html).toContain("This invite belongs to");
    expect(html).toContain(FOREIGN);
    expect(html).toContain("Open the original link you were given");
  });

  it("shows the foreign origin as PLAIN TEXT — never a link or a button (no escort to attacker turf)", () => {
    const html = renderToStaticMarkup(createElement(EnrollMismatchNotice, { origin: FOREIGN }));
    expect(html).not.toContain("<a "); // no anchor at all…
    expect(html).not.toContain("href="); // …so nothing hrefs the foreign origin
    expect(html).not.toContain("<button"); // no continue/switch affordance
  });

  it("carries no 'continue'/'switch'/'connect'/'proceed' affordance toward the foreign origin", () => {
    const html = renderToStaticMarkup(createElement(EnrollMismatchNotice, { origin: FOREIGN })).toLowerCase();
    for (const word of ["continue", "switch", "connect to", "go to", "proceed"]) {
      expect(html).not.toContain(word);
    }
  });
});
