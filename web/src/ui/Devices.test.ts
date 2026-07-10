import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { isExportOriginAllowed } from "../export/plan";
import { coerceManifest, DevicesCard, extensionRowState, platformRowState, windowsRowState } from "./Devices";
import { isPrivateOrigin } from "./origin";

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
 * tested exhaustively here. The useEffect fetch itself and its private-origin guard
 * are NOT executed in this suite (node environment, no jsdom, static markup runs no
 * effects) — accepted per review test-adequacy-4: the effect is a one-line guard over
 * the same isPrivateOrigin predicate pinned below and in export/plan tests.
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

describe("DevicesCard origin suppression", () => {
  const PRIVATE = "https://andvari.taila2dff2.ts.net";
  const PUBLIC = "https://vault.example.com";

  it("shares its private-origin predicate with export-button suppression", () => {
    expect(isPrivateOrigin(PRIVATE)).toBe(true);
    expect(isPrivateOrigin(PUBLIC)).toBe(false);
    // isExportOriginAllowed now delegates to the same primitive — one source of truth.
    expect(isExportOriginAllowed(PRIVATE)).toBe(isPrivateOrigin(PRIVATE));
    expect(isExportOriginAllowed(PUBLIC)).toBe(isPrivateOrigin(PUBLIC));
  });

  it("on a private origin advertises the devstore install; the QR is behind a default-off toggle", () => {
    const html = renderToStaticMarkup(createElement(DevicesCard, { origin: PRIVATE }));
    expect(html).toContain("devserv.taila2dff2.ts.net");
    // Owner dev-note 2026-07-10: the install QR is DEFAULT HIDDEN behind a toggle button —
    // pin the default (no svg) and the affordance that reveals it.
    expect(html).not.toContain("<svg");
    expect(html).toContain("Show QR code");
    expect(html).toContain("Checking…"); // no effect under static markup → manifest null → loading
    expect(html).toContain(PRIVATE); // the "any browser" row shows the current address
  });

  it("on the public break-glass origin hides device pointers (no devstore, no QR)", () => {
    const html = renderToStaticMarkup(createElement(DevicesCard, { origin: PUBLIC }));
    expect(html).not.toContain("devserv.taila2dff2.ts.net");
    expect(html).not.toContain("<svg");
    expect(html).toContain("home network");
  });
});
