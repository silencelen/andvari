import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  INSECURE_CONTEXT_DETAIL,
  INSECURE_CONTEXT_MESSAGE,
  InsecureContextCard,
  webCryptoUnavailable,
} from "./securecontext";

/**
 * Audit F06: on a plain-http self-host (docs/self-hosting.md's third TLS story) the web vault is
 * 100% non-functional at first contact — `crypto.subtle` is `[SecureContext]`, so keys.ts's first
 * `importKey` throws, and enrollment/sign-in landed on "Enrollment failed." / "Sign-in failed.
 * Please try again." Retrying can never work; the native clients keep working against the same
 * server, so nothing pointed at the origin's scheme. There was no `isSecureContext` check
 * anywhere in web/src or extension/src. This is that check, plus the terminal card it renders.
 */
describe("webCryptoUnavailable — the boot precondition", () => {
  it("a secure context with a real subtle crypto boots normally", () => {
    expect(webCryptoUnavailable({ isSecureContext: true, crypto: { subtle: {} } })).toBe(false);
  });

  it("an explicitly non-secure context is refused (the http://192.168.x.x case)", () => {
    expect(webCryptoUnavailable({ isSecureContext: false, crypto: { subtle: {} } })).toBe(true);
  });

  it("a missing crypto.subtle is refused whatever the context flag says", () => {
    expect(webCryptoUnavailable({ isSecureContext: true, crypto: {} })).toBe(true);
    expect(webCryptoUnavailable({ isSecureContext: true })).toBe(true);
    expect(webCryptoUnavailable({})).toBe(true);
  });

  it("a browser that simply does not expose isSecureContext is NOT locked out of a working vault", () => {
    // Fail-open on the FLAG only: the capability itself (subtle) is present, so the app works.
    expect(webCryptoUnavailable({ crypto: { subtle: {} } })).toBe(false);
  });
});

describe("InsecureContextCard — what the operator is told instead", () => {
  const html = renderToStaticMarkup(createElement(InsecureContextCard));

  it("names the real cause and the two things that actually work", () => {
    expect(html).toContain("plain http");
    expect(html).toContain("https");
    expect(html).toContain("http://localhost");
    expect(INSECURE_CONTEXT_MESSAGE).toContain("desktop or mobile app");
  });

  it("does not blame the password, the account, or the network", () => {
    for (const wrong of ["Sign-in failed", "try again", "Wrong master password", "Enrollment failed"]) {
      expect(html, `the old non-diagnostic copy must not reappear: ${wrong}`).not.toContain(wrong);
    }
    expect(INSECURE_CONTEXT_DETAIL).toContain("Nothing is wrong with your account");
  });

  it("announces itself — a terminal failure is an alert, not a quiet paragraph", () => {
    expect(html).toContain('role="alert"');
  });
});

describe("main.tsx wiring", () => {
  const mainTsx = readFileSync(fileURLToPath(new URL("../main.tsx", import.meta.url)), "utf8");

  it("checks before mounting the app", () => {
    expect(mainTsx).toContain("if (webCryptoUnavailable())");
    expect(mainTsx).toContain("<InsecureContextCard />");
  });

  it("does NOT strip the enroll fragment on an origin that cannot use it", () => {
    // captureEnrollFromLocation() consumes the invite link from the URL. Running it here would
    // burn a one-time invite on an origin where enrollment can never complete.
    const gate = mainTsx.indexOf("if (webCryptoUnavailable())");
    const capture = mainTsx.indexOf("captureEnrollFromLocation()");
    expect(gate).toBeGreaterThan(-1);
    expect(capture).toBeGreaterThan(gate);
    expect(mainTsx.slice(gate, capture)).toContain("} else {");
  });
});
