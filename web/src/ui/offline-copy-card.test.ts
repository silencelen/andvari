import "fake-indexeddb/auto"; // webCacheEnabled()'s idbSupported() gate needs a live indexedDB global
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
import { OfflineCopyBody, offlineCopyModel, queueLossQuestion, type OfflineCopyModel } from "./Settings";
import { OfflineCopyUnlockLine } from "./Welcome";
import { fill, OFFLINE_COPY_LIMIT, OFFLINE_COPY_OFFER, UNSENT_LOST_MANY, UNSENT_LOST_ONE, UNSENT_SEND_FIRST, UNSENT_UNKNOWN } from "./copy";
import { VaultStore } from "../vault/store";

/**
 * S5 (design 2026-07-13-web-offline-cache §E.3.4/§B.5/§D.1) as amended by the endpoint-agnostic
 * pivot (design 2026-07-15 §5.4.3): the settings "Offline copy" card — now ALWAYS rendered, on
 * every origin, as the standing consent entry point — and the Unlock transparency line, proven
 * statically (house pattern: Field.test.ts / Devices.test.ts — renderToStaticMarkup runs no
 * effects, so the body is a pure function of the injected model; the async model ASSEMBLY is
 * tested separately against a stub store + stubbed navigator.storage).
 */

const UID = "user-card";
const OPT_IN_KEY = `andvari.cacheOptIn.${UID}`;

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

const render = (m: OfflineCopyModel, pendingConfirm: { question: string; verb: string } | null = null): string =>
  renderToStaticMarkup(
    createElement(OfflineCopyBody, {
      model: m,
      busy: false,
      notice: "",
      pendingConfirm,
      onToggle: () => {},
      onWipe: () => {},
      onConfirm: () => {},
      onCancelConfirm: () => {},
    }),
  );

describe("OfflineCopyBody — state rendering", () => {
  it("NOT enabled still renders the card with the unchecked opt-in toggle — the §5.4.1 consent entry point on every origin", () => {
    const html = render(model({ enabled: false, durable: false }));
    expect(html).toContain("Offline copy");
    expect(html).toContain("Keep an offline copy on this device");
    expect(html).not.toContain("checked");
    // The old public-origin blank render is gone: the body never returns nothing anymore.
    expect(html).not.toBe("");
  });

  it("enabled renders the card with its controls", () => {
    const html = render(model({ enabled: true }));
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
    vi.stubGlobal("localStorage", fakeStorage());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
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

  it("maps store state + storage estimates into the model (opted-in device — the gate reads THIS user's marker)", async () => {
    vi.stubGlobal("navigator", {
      storage: { persisted: async () => true, estimate: async () => ({ usage: 4096, quota: 10_000_000 }) },
    });
    localStorage.setItem(OPT_IN_KEY, "1"); // §5.4.1: consent is the ONLY way enabled goes true
    const m = await offlineCopyModel(stubStore(), UID);
    expect(m).toMatchObject({
      enabled: true,
      orgDisallowed: false,
      durable: true,
      demoted: false,
      lastSyncAt: 123,
      persisted: true,
      usageBytes: 4096,
      queued: 2,
    });
  });

  it("no opt-in marker ⇒ enabled false — default OFF on every origin (§5.4.1)", async () => {
    vi.stubGlobal("navigator", {});
    const m = await offlineCopyModel(stubStore(), UID);
    expect(m.enabled).toBe(false);
  });

  it("degrades to unknown when navigator.storage is missing — never a broken card", async () => {
    vi.stubGlobal("navigator", {});
    const m = await offlineCopyModel(stubStore(), UID);
    expect(m.persisted).toBeNull();
    expect(m.usageBytes).toBeNull();
  });

  it("a failing queued count reads 0 (display-only, session.pendingSyncCount posture)", async () => {
    vi.stubGlobal("navigator", {});
    const m = await offlineCopyModel(
      {
        cacheDurable: true,
        cacheDemoted: false,
        lastSyncAt: null,
        queuedMutationCount: async () => {
          throw new Error("closed handle");
        },
      },
      UID,
    );
    expect(m.queued).toBe(0);
  });

  it("reflects the org pin (the card's WHY row) — beating even an explicit opt-in", async () => {
    vi.stubGlobal("navigator", {});
    localStorage.setItem("andvari.orgCacheOff", "1");
    localStorage.setItem(OPT_IN_KEY, "1");
    const m = await offlineCopyModel(stubStore(), UID);
    expect(m.orgDisallowed).toBe(true);
    expect(m.enabled).toBe(false);
  });
});

describe("queueLossQuestion — the breaker-#9 gate re-reads the LIVE count (S5 review F2)", () => {
  it("a queue that GREW after mount is respected — the question carries the live count", async () => {
    // A concurrent tab queued 3 edits since mount — the live store reads the shared per-account DB and must see them.
    expect(await queueLossQuestion({ unsentChangeCount: async () => 3 })).toEqual({ question: fill(UNSENT_LOST_MANY, "3"), unsent: 3 });
  });

  it("live count 0 asks nothing (edits synced since mount — nothing to lose)", async () => {
    expect(await queueLossQuestion({ unsentChangeCount: async () => 0 })).toBeNull();
  });

  it("its own line for one change", async () => {
    expect(await queueLossQuestion({ unsentChangeCount: async () => 1 })).toEqual({ question: UNSENT_LOST_ONE, unsent: 1 });
  });

  it("a failing re-read still asks, and says that this browser cannot tell (never a number it did not read)", async () => {
    const failing = {
      unsentChangeCount: async (): Promise<number> => {
        throw new Error("closed handle");
      },
    };
    expect(await queueLossQuestion(failing)).toEqual({ question: UNSENT_UNKNOWN, unsent: null });
  });
});

/**
 * Design §4.4 (decided on 2026-11-17): turning the copy off or removing it, with changes not sent, offers to try sending
 * them first (the vault is open here) and acts only on the second click over the count it said; the count includes the
 * vaults held back, as the shared code counts them.
 */
describe("the offline copy's confirm over unsent changes", () => {
  it("offers to try sending them first where sending is possible, and not where it is not", () => {
    const armed = { question: fill(UNSENT_LOST_MANY, "2"), verb: "Remove it and lose them" };
    const withSend = renderToStaticMarkup(
      createElement(OfflineCopyBody, { model: model({ enabled: true, durable: true, queued: 2 }), busy: false, notice: "", pendingConfirm: armed, onToggle: () => {}, onWipe: () => {}, onConfirm: () => {}, onCancelConfirm: () => {}, onSendFirst: () => {} }),
    );
    expect(withSend).toContain(UNSENT_SEND_FIRST);
    expect(render(model({ enabled: true, durable: true, queued: 2 }), armed)).not.toContain(UNSENT_SEND_FIRST);
  });

  it("the card wires it: the button only over a count it read and a vault whose traffic runs; the second click counts again", () => {
    const settings = readFileSync(here("./Settings.tsx"), "utf8");
    expect(settings).toContain("onSendFirst={pendingConfirm && pendingConfirm.unsent !== null && !store.isReadOnlyCopy() ? () => void sendFirst() : undefined}");
    const confirm = settings.slice(settings.indexOf("onConfirm={() => {"), settings.indexOf("onCancelConfirm={() => setPendingConfirm(null)}"));
    expect(confirm).toContain("void queueLossQuestion(store).then((now) => {");
    expect(confirm).toContain("unsentArmStep({ text: armed.question, unsent: armed.unsent }");
  });

  it("the store counts every change parked with a held vault with the queue (not the held vaults), and sending first counts again after one sync", async () => {
    const calls: string[] = [];
    const fake = {
      unsentChangeCount: VaultStore.prototype.unsentChangeCount,
      // One vault held back with one change parked, one with none: one change, not two vaults.
      holding: new Map([["v9", { parked: [{ mutationId: "m1" }] }], ["v8", { parked: [] }]]),
      queuedMutationCount: async () => (calls.includes("sync") ? 0 : 2),
      sync: async () => {
        calls.push("sync");
        throw new Error("offline"); // a failed send is not thrown on: what remains is counted
      },
    };
    expect(await VaultStore.prototype.unsentChangeCount.call(fake as never)).toBe(3);
    expect(await VaultStore.prototype.sendBeforeDelete.call(fake as never)).toBe(1);
    expect(calls).toEqual(["sync"]);
  });
});

/**
 * H135: the wipe/turn-off confirm is the house INLINE two-step arm, not `window.confirm`. The
 * native dialog was the only unthemed, tab-blocking, Announcer-less surface left in the app, and
 * it sat on the one action that destroys unsynced work. These pin the replacement: the row exists,
 * it names the loss, it offers a way out, and Settings.tsx raises no native dialog at all.
 */
/**
 * H48 (audit 2026-09-13): both offline-copy surfaces promised "you can open it even when the
 * server can't be reached" — which on WEB is true only inside a tab that is already loaded. The
 * app ships no service-worker shell (design 2026-07-13-web-offline-cache D1; its F.4 defers the
 * shell), so a cold tab opened during the outage the copy exists for gets the browser's own
 * "site can't be reached" and andvari never renders to explain itself. The member most likely to
 * be reading that sentence is the one about to lose their server. These pin the qualification on
 * both surfaces; if the D1 shell ever ships, this is the test that says what to un-qualify.
 */
describe("H48 — the offline-copy promise is qualified to what the web client can do", () => {
  it("the card promises a tab you already have open, and says a fresh tab still needs the server", () => {
    const html = render(model({ enabled: true, durable: true }));
    expect(html).toContain("in a tab you already have open");
    expect(html).toContain("A fresh tab still needs the server");
    // The unqualified promise is the defect — it must not come back.
    expect(html).not.toMatch(/open it even when the server/);
    // R04: while the web manifest declares `display: standalone`, an installed home-screen copy of
    // THIS app is the same code with the same limitation — so the qualification must be stated by
    // mechanism, not by form factor, or it reads as false to the member who installed it.
    const manifest = JSON.parse(readFileSync(here("../../public/manifest.webmanifest"), "utf8")) as { display?: string };
    if (manifest.display && manifest.display !== "browser") {
      expect(html, "an installable web app must not be told a home-screen copy opens cold").toContain(
        "a home-screen shortcut for this site included",
      );
      expect(html, "…and 'apps for your computer and phone' must name the INSTALLED natives").toContain(
        "The andvari apps you install for your computer and phone do open offline from cold",
      );
    }
  });

  it("the unlock-time nudge carries the same qualification (one claim, two surfaces)", () => {
    const app = readFileSync(here("./App.tsx"), "utf8");
    expect(app).toContain("const CACHE_NUDGE_OFFER = OFFLINE_COPY_OFFER;");
    expect(OFFLINE_COPY_OFFER).toContain("a tab you already have open can unlock it");
    expect(OFFLINE_COPY_OFFER).not.toContain("You could open your vault even when");
  });

  it("the one-time question says when the copy is made: at the next unlock or sign-in, as the note after “Keep a copy” does", () => {
    expect(OFFLINE_COPY_OFFER).toContain("It is made the next time you unlock or sign in here");
    expect(readFileSync(here("./App.tsx"), "utf8")).toContain("it will be created at your next unlock or sign-in");
  });

  it("every sentence about the copy says a reload without the server cannot load the page", () => {
    const html = render(model({ enabled: true, durable: true }));
    expect(html).toContain("so does a reload: without the server the page itself can"); // "can't", escaped in the markup
    expect(OFFLINE_COPY_OFFER).toContain("A reload or a fresh tab still needs the server: without it, the page itself can't load.");
    expect(OFFLINE_COPY_LIMIT).toContain("keeps only a tab that is already open working");
    // No sentence of the web app promises that a reload or a fresh tab opens the copy without the server.
    const sources = ["./App.tsx", "./Settings.tsx", "./Welcome.tsx", "./copy.ts"].map((f) => readFileSync(here(f), "utf8")).join("\n");
    expect(sources).not.toMatch(/(reload|fresh tab)[^."]*\b(opens?|unlocks?)\b[^."]*(without the server|offline)/i);
  });
});

describe("H135 — the offline-copy confirm is inline, not a native dialog", () => {
  const armed = { question: fill(UNSENT_LOST_MANY, "3"), verb: "Remove it and lose them" };

  it("renders the armed confirm row under the toggle, with the destructive verb and a way out", () => {
    const html = render(model({ enabled: true, durable: true, queued: 3 }), armed);
    expect(html).toContain("confirm-row");
    expect(html).toContain(fill(UNSENT_LOST_MANY, "3").replace(/'/g, "&#x27;"));
    expect(html).toContain("Remove it and lose them");
    expect(html).toContain("Keep it");
  });

  it("nothing armed renders no confirm row (the card is not permanently shouting)", () => {
    expect(render(model({ enabled: true, durable: true, queued: 3 }))).not.toContain("confirm-row");
  });

  it("Settings.tsx CALLS no window.confirm — house style, no native dialogs", () => {
    // The prose above the code may name the retired dialog; only a call site fails this.
    expect(readFileSync(here("./Settings.tsx"), "utf8")).not.toMatch(/window\.confirm\s*\(/);
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

  it("the unlock card shows it (the 2026-11-16 walk found it rendered nowhere): probed per account, on both copy cards", () => {
    const welcome = readFileSync(here("./Welcome.tsx"), "utf8");
    const unlock = welcome.slice(welcome.indexOf("function Unlock("), welcome.indexOf("// ---- Sign up"));
    // The probe is offlineCopyStamp's, read through unlockCopyStamp (which says a copy it cannot read as that).
    expect(unlock).toContain("void unlockCopyStamp(session.userId).then(");
    expect(welcome).toContain("stampOf: (userId: string) => Promise<{ lastSyncAt: number | null } | null> = offlineCopyStamp,");
    expect(unlock.match(/<OfflineCopyUnlockLine stamp=\{copyStamp\} \/>/g)).toHaveLength(2);
    // The hooks run before the card's early returns.
    expect(unlock.indexOf("useState<CopyStamp | null>(null)")).toBeLessThan(unlock.indexOf("if (endedByServer(session)) {"));
  });
});
