import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { detailUris } from "./Vault";

/**
 * H53 (audit 2026-09-13): the web item Detail rendered the website as a read-only text box — no
 * "open site" link, no Copy, only uris[0] — while the extension detail (popup.ts site-link rows),
 * the Staleness run card and the Duplicates checker all link through safeSiteHref. The rows now
 * list every saved uri as a safeSiteHref link (a click is a genuine use, recorded like Staleness
 * does) with the raw text shown inert when the href is rejected, plus the row Copy button. The
 * list derivation is pure; the render wiring is pinned on the source (Detail is a closure with no
 * render seam in this node env).
 */
describe("detailUris", () => {
  it("lists EVERY non-blank saved uri in stored order — the search matches on all of them (F79)", () => {
    expect(detailUris(["netflix.com", " ", "https://www.netflix.com/login", ""])).toEqual(["netflix.com", "https://www.netflix.com/login"]);
  });

  it("no uris → no row", () => {
    expect(detailUris(undefined)).toEqual([]);
    expect(detailUris([])).toEqual([]);
  });
});

describe("Vault.tsx Detail website rows (source pin)", () => {
  const src = readFileSync(fileURLToPath(new URL("./Vault.tsx", import.meta.url)), "utf8");
  const start = src.indexOf("{detailUris(doc.login.uris).length > 0 && (");
  const block = src.slice(start, src.indexOf("<HealthLine", start));

  it("renders each uri through safeSiteHref — a navigable one is a link that records a use, a rejected one is inert text", () => {
    expect(start, "the website block moved — update the pin").toBeGreaterThan(-1);
    expect(block).toContain("const href = safeSiteHref(uri);");
    expect(block).toContain('<a className="link site-uri" href={href} target="_blank" rel="noreferrer" onClick={onUsed}>{uri} ↗</a>');
    expect(block).toContain('<span className="site-uri">{uri}</span>');
  });

  it("carries the row Copy button, for parity with username / password / TOTP", () => {
    expect(block).toContain('onClick={() => copy("website", uri)}>Copy</button>');
  });

  it("the read-only text box is gone and the heading pluralises with the count", () => {
    expect(src).not.toContain("<input readOnly value={doc.login.uris[0]} />");
    expect(block).toContain('=== 1 ? "Website" : "Websites"');
  });
});
