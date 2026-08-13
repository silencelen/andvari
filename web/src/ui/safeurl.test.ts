import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { safeHttpHref, safeHttpUrl } from "./safeurl";

/**
 * Audit F14: §2.3 R8 says a SERVER-DECLARED url is untrusted and may only be rendered as a raw
 * link when it is a real http(s) URL. Welcome enforced it for the landing's `selfHostDocsUrl`;
 * the Devices card took five hrefs straight out of /downloads/manifest.json with no scheme check
 * at all, leaving the safety entirely to a CSP nobody re-checks when that component changes. One
 * shared module, so the rule cannot be applied in one place and skipped in five again.
 */
describe("safeHttpUrl — absolute http(s) only (the landing's docs link)", () => {
  it("passes a real http(s) URL through verbatim", () => {
    expect(safeHttpUrl("https://andvari.example/self-host")).toBe("https://andvari.example/self-host");
    expect(safeHttpUrl("http://andvari.example/self-host")).toBe("http://andvari.example/self-host");
  });

  it("refuses every other scheme", () => {
    for (const bad of ["javascript:alert(1)", "data:text/html,x", "vbscript:x", "file:///etc/passwd", "blob:https://x/y"]) {
      expect(safeHttpUrl(bad), bad).toBeNull();
    }
  });

  it("refuses the empty, the absent and the unparseable (a relative path is not a docs link)", () => {
    expect(safeHttpUrl("")).toBeNull();
    expect(safeHttpUrl(null)).toBeNull();
    expect(safeHttpUrl(undefined)).toBeNull();
    expect(safeHttpUrl("not a url")).toBeNull();
    expect(safeHttpUrl("/downloads/x.msi")).toBeNull();
  });
});

describe("safeHttpHref — the downloads manifest, whose own artifacts are same-origin paths", () => {
  it("keeps a relative path exactly as written (the href must stay relative)", () => {
    expect(safeHttpHref("/downloads/andvari-0.21.0.apk")).toBe("/downloads/andvari-0.21.0.apk");
    expect(safeHttpHref("downloads/andvari-0.21.0.apk")).toBe("downloads/andvari-0.21.0.apk");
  });

  it("keeps an absolute http(s) url (a store listing)", () => {
    expect(safeHttpHref("https://chromewebstore.google.com/detail/andvari/x")).toBe(
      "https://chromewebstore.google.com/detail/andvari/x",
    );
  });

  it("still refuses a scheme that is not http(s) — the whole point of the rule", () => {
    for (const bad of ["javascript:alert(1)", "data:text/html,<script>x</script>", "blob:https://x/y", "vbscript:msgbox"]) {
      expect(safeHttpHref(bad), bad).toBeNull();
    }
    expect(safeHttpHref("")).toBeNull();
    expect(safeHttpHref(undefined)).toBeNull();
  });
});

describe("the rule is applied where it was skipped", () => {
  const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

  it("Devices routes its manifest urls through the shared check, not `typeof v === 'string'`", () => {
    const devices = readFileSync(here("./Devices.tsx"), "utf8");
    expect(devices).toContain('import { safeHttpHref } from "./safeurl"');
    expect(devices).toContain("safeHttpHref(build.url)");
    expect(devices).toContain("safeHttpHref(v)");
  });

  it("Welcome imports the shared one instead of keeping a private copy", () => {
    const welcome = readFileSync(here("./Welcome.tsx"), "utf8");
    expect(welcome).toContain('import { safeHttpUrl } from "./safeurl"');
    expect(welcome).not.toContain("function safeHttpUrl(");
  });
});
