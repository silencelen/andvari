import "fake-indexeddb/auto"; // webCacheEnabled()'s idbSupported() gate needs a live indexedDB global
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { confirmQueueLoss, OfflineCopyBody, offlineCopyModel, type OfflineCopyModel } from "./Settings";
import { OfflineCopyUnlockLine } from "./Welcome";

/**
 * S5 (design 2026-07-13-web-offline-cache §E.3.4/§B.5/§D.1): the settings "Offline copy" card and
 * the Unlock transparency line, proven statically (house pattern: Field.test.ts / Devices.test.ts —
 * renderToStaticMarkup runs no effects, so the body is a pure function of the injected model; the
 * async model ASSEMBLY is tested separately against a stub store + stubbed navigator.storage).
 */

const g = globalThis as { window?: { location: { origin: string } } };

const PRIVATE_ORIGIN = "https://andvari.taila2dff2.ts.net";

/** Map-backed localStorage for the node test environment. */
function fakeStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

const model = (over: Partial<OfflineCopyModel> = {}): OfflineCopyModel => ({
  privateOrigin: true,
  enabled: true,
  orgDisallowed: false,
  durable: true,
  demoted: false,
  lastSyncAt: 1_720_900_000_000,
  persisted: true,
  usageBytes: 2048,
  queued: 0,
  ...over,
});

const render = (m: OfflineCopyModel): string =>
  renderToStaticMarkup(
    createElement(OfflineCopyBody, { model: m, busy: false, notice: "", onToggle: () => {}, onWipe: () => {} }),
  );

describe("OfflineCopyBody — state rendering", () => {
  it("PUBLIC origin + not opted in renders NOTHING (hidden on the break-glass origin, §E.3.3)", () => {
    expect(render(model({ privateOrigin: false, enabled: false }))).toBe("");
  });

  it("PUBLIC origin + opted in renders the card (controls exist once a copy was chosen)", () => {
    const html = render(model({ privateOrigin: false, enabled: true }));
    expect(html).toContain("Offline copy");
    expect(html).toContain("Keep an offline copy on this device");
  });

  it("org-disallowed explains the policy and offers NO toggle (§E.4 — the wipe already ran)", () => {
    const html = render(model({ orgDisallowed: true }));
    expect(html).toContain("household");
    expect(html).not.toContain("Keep an offline copy on this device");
    expect(html).not.toContain("Remove the offline copy now");
  });

  it("demoted shows the §D.1 storage-error state", () => {
    const html = render(model({ demoted: true, durable: false }));
    expect(html).toContain("Offline copy unavailable — storage error");
  });

  it("enabled + durable shows last-synced, eviction protection, size, and wipe-now", () => {
    const html = render(model());
    expect(html).toContain("Last synced");
    expect(html).toContain("Protected from eviction");
    expect(html).toContain("yes");
    expect(html).toContain("2.0 KiB"); // humanSize(2048) — display only (§B.5)
    expect(html).toContain("Remove the offline copy now");
  });

  it("best-effort persistence is stated honestly (§B.5 surfaced result)", () => {
    expect(render(model({ persisted: false }))).toContain("best-effort");
  });

  it("the queued count row appears only with unsynced edits, pluralized", () => {
    expect(render(model({ queued: 0 }))).not.toContain("waiting to sync");
    expect(render(model({ queued: 1 }))).toContain("1 change waiting to sync");
    expect(render(model({ queued: 3 }))).toContain("3 changes waiting to sync");
  });

  it("enabled but not (yet) durable points at the next unlock (toggle just flipped / degraded session)", () => {
    const html = render(model({ durable: false }));
    expect(html).toContain("next unlock");
    expect(html).not.toContain("Last synced");
  });

  it("toggle checkbox reflects the gate state", () => {
    expect(render(model({ enabled: true, durable: false }))).toContain("checked");
    expect(render(model({ enabled: false }))).not.toContain("checked");
  });
});

describe("offlineCopyModel — assembly from the frozen store surface + navigator.storage", () => {
  beforeEach(() => {
    g.window = { location: { origin: PRIVATE_ORIGIN } };
    vi.stubGlobal("localStorage", fakeStorage());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    delete g.window;
  });

  const stubStore = (over: Partial<{ cacheDurable: boolean; cacheDemoted: boolean; lastSyncAt: number | null; queued: number }> = {}) => {
    const s = { cacheDurable: true, cacheDemoted: false, lastSyncAt: 123, queued: 2, ...over };
    return {
      cacheDurable: s.cacheDurable,
      cacheDemoted: s.cacheDemoted,
      lastSyncAt: s.lastSyncAt,
      queuedMutationCount: async () => s.queued,
    };
  };

  it("maps store state + storage estimates into the model", async () => {
    vi.stubGlobal("navigator", {
      storage: { persisted: async () => true, estimate: async () => ({ usage: 4096, quota: 10_000_000 }) },
    });
    const m = await offlineCopyModel(stubStore());
    expect(m).toMatchObject({
      privateOrigin: true,
      enabled: true, // private origin, no markers
      orgDisallowed: false,
      durable: true,
      demoted: false,
      lastSyncAt: 123,
      persisted: true,
      usageBytes: 4096,
      queued: 2,
    });
  });

  it("degrades to unknown when navigator.storage is missing — never a broken card", async () => {
    vi.stubGlobal("navigator", {});
    const m = await offlineCopyModel(stubStore());
    expect(m.persisted).toBeNull();
    expect(m.usageBytes).toBeNull();
  });

  it("a failing queued count reads 0 (display-only, session.pendingSyncCount posture)", async () => {
    vi.stubGlobal("navigator", {});
    const m = await offlineCopyModel({
      cacheDurable: true,
      cacheDemoted: false,
      lastSyncAt: null,
      queuedMutationCount: async () => {
        throw new Error("closed handle");
      },
    });
    expect(m.queued).toBe(0);
  });

  it("reflects the org pin and the opt-out marker (the card's WHY rows)", async () => {
    vi.stubGlobal("navigator", {});
    localStorage.setItem("andvari.orgCacheOff", "1");
    const m = await offlineCopyModel(stubStore());
    expect(m.orgDisallowed).toBe(true);
    expect(m.enabled).toBe(false);
  });
});

describe("confirmQueueLoss — the breaker-#9 gate re-reads the LIVE count (S5 review F2)", () => {
  it("a queue that GREW after mount is respected — the confirm carries the live count and blocks on decline", async () => {
    // Mount-time model said 0 (which alone would SKIP the confirm); a concurrent tab queued 3
    // edits since — the live store reads the shared per-account DB and must see them.
    const ask = vi.fn(() => false);
    const ok = await confirmQueueLoss({ queuedMutationCount: async () => 3 }, 0, ask);
    expect(ask).toHaveBeenCalledWith(expect.stringContaining("3 unsynced changes"));
    expect(ok).toBe(false); // declined ⇒ toggle/wipe abort, the queue survives
  });

  it("live count 0 proceeds without asking (edits synced since mount — nothing to lose)", async () => {
    const ask = vi.fn(() => false);
    expect(await confirmQueueLoss({ queuedMutationCount: async () => 0 }, 2, ask)).toBe(true);
    expect(ask).not.toHaveBeenCalled();
  });

  it("accepting the confirm proceeds — singular copy for one change", async () => {
    const ask = vi.fn(() => true);
    expect(await confirmQueueLoss({ queuedMutationCount: async () => 1 }, 0, ask)).toBe(true);
    expect(ask).toHaveBeenCalledWith(expect.stringContaining("1 unsynced change on this device"));
  });

  it("a failing re-read falls back to the mount-time count (a stale confirm beats a skipped one)", async () => {
    const ask = vi.fn(() => true);
    const failing = {
      queuedMutationCount: async (): Promise<number> => {
        throw new Error("closed handle");
      },
    };
    expect(await confirmQueueLoss(failing, 2, ask)).toBe(true);
    expect(ask).toHaveBeenCalledWith(expect.stringContaining("2 unsynced changes"));
  });

  it("confirm-less environments proceed (historical non-browser fall-through)", async () => {
    // No `ask` injected and no window.confirm in the node env — must not throw, must not block.
    expect(await confirmQueueLoss({ queuedMutationCount: async () => 5 }, 0)).toBe(true);
  });
});

describe("OfflineCopyUnlockLine — §E.3.4 transparency (shows ONLY with a cache)", () => {
  it("renders nothing for a null stamp (no cache on this device)", () => {
    expect(renderToStaticMarkup(createElement(OfflineCopyUnlockLine, { stamp: null }))).toBe("");
  });

  it("renders the line with the sync stamp when a cache exists", () => {
    const html = renderToStaticMarkup(
      createElement(OfflineCopyUnlockLine, { stamp: { lastSyncAt: 1_720_900_000_000 } }),
    );
    expect(html).toContain("Offline copy on this device — last synced");
    expect(html).not.toContain("not yet");
  });

  it("a cache that never synced reads 'not yet'", () => {
    const html = renderToStaticMarkup(createElement(OfflineCopyUnlockLine, { stamp: { lastSyncAt: null } }));
    expect(html).toContain("last synced not yet");
  });
});
