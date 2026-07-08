import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { isExportOriginAllowed } from "../export/plan";
import { DevicesCard, windowsRowState } from "./Devices";
import { isPrivateOrigin } from "./origin";

/**
 * The manifest→Windows-row decision is pure and tested exhaustively here; the fetch
 * itself is not mount-tested (the web suite runs in node, no jsdom), but every OUTCOME
 * of that fetch (null / "error" / parsed) is covered below, so the branching is fully
 * exercised without a DOM.
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

  it("on a private origin advertises the devstore install + a QR", () => {
    const html = renderToStaticMarkup(createElement(DevicesCard, { origin: PRIVATE }));
    expect(html).toContain("devserv.taila2dff2.ts.net");
    expect(html).toContain("<svg"); // the devstore install QR
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
