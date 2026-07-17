import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  coerceManifest,
  DevicesCard,
  ExtensionRowView,
  extensionRowState,
  platformRowState,
  windowsRowState,
} from "./Devices";

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

  it("a store listing alone is a real install surface — available with just chromeStoreUrl", () => {
    expect(
      extensionRowState({
        browserExtension: { version: "0.16.1", chromeStoreUrl: "https://chromewebstore.google.com/detail/andvari/x" },
      }),
    ).toEqual({
      kind: "available",
      version: "0.16.1",
      chromeStoreUrl: "https://chromewebstore.google.com/detail/andvari/x",
      chromeUrl: undefined,
      firefoxUrl: undefined,
    });
  });

  it("store + zips + xpi all pass through together", () => {
    expect(
      extensionRowState({
        browserExtension: {
          version: "0.16.1",
          chromeStoreUrl: "https://chromewebstore.google.com/detail/andvari/x",
          chromeUrl: "/downloads/andvari-extension-chrome-0.16.1.zip",
          firefoxUrl: "/downloads/andvari-extension-firefox-0.16.1.xpi",
        },
      }),
    ).toEqual({
      kind: "available",
      version: "0.16.1",
      chromeStoreUrl: "https://chromewebstore.google.com/detail/andvari/x",
      chromeUrl: "/downloads/andvari-extension-chrome-0.16.1.zip",
      firefoxUrl: "/downloads/andvari-extension-firefox-0.16.1.xpi",
    });
  });
});

describe("ExtensionRowView — store buttons replace the zip flow when a better surface exists", () => {
  const STORE = "https://chromewebstore.google.com/detail/andvari/ndhkgfgkbnfieehncjgegcjhfdbhmmbn";
  const XPI = "/downloads/andvari-extension-firefox-0.16.1.xpi";
  const ZIP_C = "/downloads/andvari-extension-chrome-0.16.1.zip";
  const ZIP_F = "/downloads/andvari-extension-firefox-0.16.1.zip";

  it("store + signed xpi → two install buttons, NO unzip instructions (zip suppressed even if present)", () => {
    const html = renderToStaticMarkup(
      createElement(ExtensionRowView, {
        state: { kind: "available", version: "0.16.1", chromeStoreUrl: STORE, chromeUrl: ZIP_C, firefoxUrl: XPI },
      }),
    );
    expect(html).toContain(`href="${STORE}"`);
    expect(html).toContain('target="_blank"'); // store opens in a new tab…
    expect(html).toContain(`href="${XPI}"`); // …the xpi installs in place (no _blank)
    expect(html).toContain("update automatically");
    expect(html).toContain("Mozilla-signed");
    // Review 2026-07-17 (copy-honesty HIGH): the xpi has no update_url — the card must say so
    // right next to Chrome's auto-update claim, never imply parity.
    expect(html).toContain("can’t update itself");
    expect(html).toContain("install it again from this button");
    expect(html).not.toContain("unzip"); // the packaged-file flow is gone when buttons exist
    expect(html).not.toContain(ZIP_C); // chrome zip suppressed by the store listing
  });

  it("zips only (self-host without a store listing) keeps the honest load-unpacked flow", () => {
    const html = renderToStaticMarkup(
      createElement(ExtensionRowView, {
        state: { kind: "available", version: "0.6.0", chromeUrl: ZIP_C, firefoxUrl: ZIP_F },
      }),
    );
    expect(html).not.toContain("getbtns");
    expect(html).toContain("unzip");
    expect(html).toContain("INSTALL.txt");
    expect(html).toContain(`href="${ZIP_C}"`);
    expect(html).toContain(`href="${ZIP_F}"`);
    // Review 2026-07-17 (copy-honesty MED): the update nag ships un-armed (§M-D3 sentinel key) —
    // the popup can never flag an update, so the card must not promise one. "Check back here."
    expect(html).not.toContain("will flag");
    expect(html).toContain("check back here");
  });

  it("mixed: store listing + firefox ZIP → chrome button, firefox falls back to the zip flow", () => {
    const html = renderToStaticMarkup(
      createElement(ExtensionRowView, {
        state: { kind: "available", version: "0.16.1", chromeStoreUrl: STORE, firefoxUrl: ZIP_F },
      }),
    );
    expect(html).toContain(`href="${STORE}"`);
    expect(html).toContain("Or download");
    expect(html).toContain(`href="${ZIP_F}"`);
    expect(html).not.toContain("Mozilla-signed"); // a zip is not the signed build — never claim it is
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
