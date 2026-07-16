import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { coerceManifest, DevicesCard, extensionRowState, platformRowState, windowsRowState } from "./Devices";

describe("coerceManifest (fetch-parse → state, review finding web-correctness-2)", () => {
  it("a JSON body of literal null (or any non-object) is 'error', NEVER the loading state", () => {
    expect(coerceManifest(null)).toBe("error"); // would otherwise wedge on "Checking…" forever
    expect(coerceManifest("null")).toBe("error");
    expect(coerceManifest(42)).toBe("error");
    expect(coerceManifest([])).toBe("error");
    expect(coerceManifest(undefined)).toBe("error");
  });

  it("a plain object passes through", () => {
    const m = { windows: { version: "0.5.0", url: "/downloads/x.msi" } };
    expect(coerceManifest(m)).toBe(m);
    expect(coerceManifest({})).toEqual({});
  });
});

/**
 * The manifest→state decision path is pure (coerceManifest + windowsRowState) and
 * tested exhaustively here. The useEffect fetch itself is NOT executed in this suite
 * (node environment, no jsdom, static markup runs no effects) — accepted per review
 * test-adequacy-4: since the endpoint-agnostic pivot (design 2026-07-15 §5.4.4) it is
 * an unconditional same-origin manifest fetch with no gate left to pin.
 */
describe("windowsRowState (downloads manifest → Windows row)", () => {
  it("null = still fetching", () => {
    expect(windowsRowState(null)).toEqual({ kind: "loading" });
  });

  it('404 / network ("error") = unpublished — the steady state today, never shown as an error', () => {
    expect(windowsRowState("error")).toEqual({ kind: "unpublished" });
  });

  it("a manifest with no windows build = unpublished", () => {
    expect(windowsRowState({})).toEqual({ kind: "unpublished" });
    expect(windowsRowState({ windows: null })).toEqual({ kind: "unpublished" });
    expect(windowsRowState({ linux: { version: "0.5.0", url: "/downloads/x.deb" } })).toEqual({ kind: "unpublished" });
  });

  it("a windows build missing url OR version = unpublished (never a dead link)", () => {
    expect(windowsRowState({ windows: { version: "0.5.0" } })).toEqual({ kind: "unpublished" });
    expect(windowsRowState({ windows: { url: "/downloads/andvari-0.5.0.msi" } })).toEqual({ kind: "unpublished" });
    expect(windowsRowState({ windows: { version: "", url: "" } })).toEqual({ kind: "unpublished" });
  });

  it("a complete windows build = available link", () => {
    expect(windowsRowState({ windows: { version: "0.5.0", url: "/downloads/andvari-0.5.0.msi" } })).toEqual({
      kind: "available",
      version: "0.5.0",
      url: "/downloads/andvari-0.5.0.msi",
    });
  });

  it("the linux column reads the same manifest independently", () => {
    const m = { linux: { version: "0.6.0", url: "/downloads/andvari-desktop-0.6.0.deb" } };
    expect(platformRowState(m, "linux")).toEqual({
      kind: "available",
      version: "0.6.0",
      url: "/downloads/andvari-desktop-0.6.0.deb",
    });
    expect(platformRowState(m, "windows")).toEqual({ kind: "unpublished" });
    expect(platformRowState(null, "linux")).toEqual({ kind: "loading" });
    expect(platformRowState("error", "linux")).toEqual({ kind: "unpublished" });
  });
});

describe("extensionRowState (downloads manifest → browser-extension row)", () => {
  it("null = still fetching; error/absent/null entry = unpublished", () => {
    expect(extensionRowState(null)).toEqual({ kind: "loading" });
    expect(extensionRowState("error")).toEqual({ kind: "unpublished" });
    expect(extensionRowState({})).toEqual({ kind: "unpublished" });
    expect(extensionRowState({ browserExtension: null })).toEqual({ kind: "unpublished" });
  });

  it("needs a version AND at least one browser url — never a dead row", () => {
    expect(extensionRowState({ browserExtension: { version: "0.6.0" } })).toEqual({ kind: "unpublished" });
    expect(extensionRowState({ browserExtension: { chromeUrl: "/downloads/x.zip" } })).toEqual({
      kind: "unpublished",
    });
    expect(extensionRowState({ browserExtension: { version: "", chromeUrl: "/downloads/x.zip" } })).toEqual({
      kind: "unpublished",
    });
  });

  it("either browser alone or both together = available with only the real links", () => {
    expect(
      extensionRowState({ browserExtension: { version: "0.6.0", chromeUrl: "/downloads/andvari-extension-chrome-0.6.0.zip" } }),
    ).toEqual({ kind: "available", version: "0.6.0", chromeUrl: "/downloads/andvari-extension-chrome-0.6.0.zip", firefoxUrl: undefined });
    expect(
      extensionRowState({
        browserExtension: {
          version: "0.6.0",
          chromeUrl: "/downloads/andvari-extension-chrome-0.6.0.zip",
          firefoxUrl: "/downloads/andvari-extension-firefox-0.6.0.zip",
        },
      }),
    ).toEqual({
      kind: "available",
      version: "0.6.0",
      chromeUrl: "/downloads/andvari-extension-chrome-0.6.0.zip",
      firefoxUrl: "/downloads/andvari-extension-firefox-0.6.0.zip",
    });
  });
});

describe("DevicesCard — endpoint-agnostic (design 2026-07-15 §5.4.4: no origin gate, no baked hostnames)", () => {
  const TAILNET = "https://andvari.example.net";
  const PUBLIC = "https://vault.example.com";

  it("renders the same manifest-driven rows on ANY origin — the old private/public fork is gone", () => {
    const a = renderToStaticMarkup(createElement(DevicesCard, { origin: TAILNET }));
    const b = renderToStaticMarkup(createElement(DevicesCard, { origin: PUBLIC }));
    for (const html of [a, b]) {
      expect(html).toContain("Checking…"); // no effect under static markup → manifest null → loading rows
      expect(html).toContain("Windows");
      expect(html).toContain("Linux");
      expect(html).toContain("Browser extension");
      expect(html).not.toContain("home network"); // the public-origin "hidden" copy is deleted
    }
    // The "any browser" row shows the CURRENT address — origin is just an address now.
    expect(a).toContain(TAILNET);
    expect(b).toContain(PUBLIC);
  });

  it("bakes no tailnet hostname and ships no devstore QR (§5.5 tailnet-leak removal)", () => {
    // TODO Wave 3 (§5.4.4, gated on the Gate-1 artifact publish): when the manifest-driven Android
    // row lands, pin here that an `android` manifest entry — and ONLY that — renders it (with QR).
    const html = renderToStaticMarkup(createElement(DevicesCard, { origin: PUBLIC }));
    expect(html).not.toContain("devserv");
    expect(html).not.toContain("ts.net");
    expect(html).not.toContain("<svg");
    expect(html).not.toContain("Show QR code");
    expect(html).not.toContain("Android"); // nothing honest to render for phones until the artifact publish
  });
});
