import assert from "node:assert/strict";
import { test } from "node:test";
import vm from "node:vm";
import * as esbuild from "esbuild";

// A smoke test of popup.ts itself, as the Safari bundle, against a stand-in DOM. The state-machine tests drive
// AppVault and never load the popup; a popup that throws at start, or renders nothing, would pass them all.

/** An element stand-in: it keeps what is set on it and accepts every DOM call the popup makes. */
function fakeElement(id = ""): Record<string, unknown> {
  const listeners: Record<string, ((e: unknown) => unknown)[]> = {};
  const noop = (): undefined => undefined;
  const base: Record<string, unknown> = {
    id,
    hidden: true,
    textContent: "",
    value: "",
    disabled: false,
    className: "",
    title: "",
    dataset: {},
    children: [],
    style: new Proxy({ cssText: "" } as Record<string, unknown>, { get: (t, p) => (p === "setProperty" || p === "removeProperty" ? noop : t[p as string]), set: (t, p, v) => ((t[p as string] = v), true) }),
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    addEventListener: (type: string, fn: (e: unknown) => unknown) => void (listeners[type] ??= []).push(fn),
    removeEventListener: noop,
    dispatch: (type: string) => Promise.all((listeners[type] ?? []).map((fn) => fn({ preventDefault: noop, stopPropagation: noop, target: base }))),
    getAttribute: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    closest: () => null,
    contains: () => false,
    matches: () => false,
    getBoundingClientRect: () => ({ top: 0, left: 0, width: 0, height: 0, bottom: 0, right: 0 }),
  };
  return new Proxy(base, { get: (t, p) => (p in t ? t[p as string] : typeof p === "string" ? noop : undefined), set: (t, p, v) => ((t[p as string] = v), true) });
}

type Answer = (msg: { type: string }) => unknown;

/** Load the Safari popup bundle into a fresh page whose worker answers with [answer]. */
async function loadPopup(answer: Answer) {
  const out = await esbuild.build({
    entryPoints: [new URL("./popup.ts", import.meta.url).pathname],
    bundle: true,
    format: "iife",
    target: "es2022",
    write: false,
    logLevel: "silent",
    define: { __ANDVARI_TARGET__: JSON.stringify("safari") },
  });
  const elements = new Map<string, Record<string, unknown>>();
  const byId = (id: string): Record<string, unknown> => {
    if (!elements.has(id)) elements.set(id, fakeElement(id));
    return elements.get(id)!;
  };
  const sent: string[] = [];
  const errors: unknown[] = [];
  // The page's timers, so the test can stop them all (the popup polls once a second for as long as it is open).
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const pageTimeout = (fn: () => void, ms?: number) => { const t = setTimeout(fn, ms); timers.add(t); return t; };
  const pageInterval = (fn: () => void, ms?: number) => { const t = setInterval(fn, ms); timers.add(t); return t; };
  const dispose = (): void => { for (const t of timers) { clearTimeout(t); clearInterval(t); } };
  const windowListeners: Record<string, ((e: unknown) => unknown)[]> = {};
  const document = {
    getElementById: (id: string) => (id === "server-details" || id === "other-site-confirm" ? null : byId(id)),
    createElement: () => fakeElement(),
    createElementNS: () => fakeElement(),
    createTextNode: () => fakeElement(),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    visibilityState: "visible",
    body: fakeElement("body"),
    head: fakeElement("head"),
    documentElement: fakeElement("html"),
    activeElement: null,
  };
  const chrome = {
    runtime: {
      sendMessage: async (msg: { type: string }) => {
        sent.push(msg.type);
        return answer(msg);
      },
      sendNativeMessage: async () => ({ ok: true, type: "appServer", url: null }),
      getURL: (p: string) => `safari-web-extension://x/${p}`,
      getManifest: () => ({ version: "0.0.0" }),
      onMessage: { addListener: () => undefined },
      openOptionsPage: () => undefined,
      connect: () => {
        throw new Error("the popup opens no port");
      },
    },
    tabs: { query: async () => [{ id: 1, url: "https://login.example.com/x" }], create: async () => ({}) },
    permissions: { contains: async () => true, request: async () => true },
  };
  const window: Record<string, unknown> = {
    addEventListener: (type: string, fn: (e: unknown) => unknown) => void (windowListeners[type] ??= []).push(fn),
    removeEventListener: () => undefined,
    setTimeout: pageTimeout,
    clearTimeout,
    setInterval: pageInterval,
    clearInterval,
    close: () => undefined,
    matchMedia: () => ({ matches: false, addEventListener: () => undefined }),
    location: { href: "safari-web-extension://x/popup.html", search: "" },
  };
  const context = vm.createContext({
    window, document, chrome, console, setTimeout: pageTimeout, clearTimeout, setInterval: pageInterval, clearInterval, URL, TextEncoder, TextDecoder, crypto: globalThis.crypto,
    navigator: { clipboard: { writeText: async () => undefined }, userAgent: "smoke", credentials: undefined },
    requestAnimationFrame: (fn: () => void) => pageTimeout(fn, 0),
    location: window.location,
    PublicKeyCredential: undefined,
  });
  process.on("unhandledRejection", (e) => errors.push(e));
  try {
    vm.runInContext(out.outputFiles[0]!.text, context, { filename: "popup.safari.js" });
  } catch (e) {
    errors.push(e);
  }
  const settle = (ms = 60): Promise<void> => new Promise((r) => setTimeout(r, ms));
  return { byId, sent, errors, settle, windowListeners, dispose };
}

const lockedStatus = { unlocked: false, count: 0, email: null, mustChangePassword: false, lockNotice: null, quickUnlock: { enrolled: false, armed: false, attemptsRemaining: 0, offerDismissed: true, kind: null }, totpPending: null, personalChange: false, personalChangeText: null, personalProposal: false, waitingGrants: 0, wrongVault: 0, rememberedEmail: null };

test("the Safari popup shows its unlock view at once, before any message is answered, and never throws at start", async () => {
  const never: Answer = () => new Promise(() => {}); // a worker that answers nothing
  const page = await loadPopup(never);
  assert.deepEqual(page.errors, []);
  assert.equal(page.byId("locked").hidden, false, "something is on screen");
  assert.equal(page.byId("app-locked").hidden, false, "the Face ID view");
  assert.equal(page.byId("unlocked").hidden, true);
  assert.equal(page.byId("qu-master-form").hidden, true, "no sign-in form in this build");
  page.dispose();
});

test("it prompts once on open, shows the list after the unlock whatever the cards answer, and closes nothing when it goes away", async () => {
  let unlocked = false;
  let unlockAsks = 0;
  const item = { itemId: "i1", name: "Example", username: "fam", uris: ["https://login.example.com/x"], siteMatch: false, hasTotp: true, readOnly: true };
  const answer: Answer = (msg) => {
    switch (msg.type) {
      case "appServer": return { app: "set" };
      case "serverInfo": return { url: "https://home.example", trustedStore: true, block: null };
      case "status": return { ...lockedStatus, unlocked, count: unlocked ? 1 : 0 };
      case "appUnlock": unlockAsks++; unlocked = true; return { ok: true, state: "open" };
      case "matches": return { locked: !unlocked, matches: unlocked ? [{ ...item, siteMatch: true }] : [] };
      case "allItems": return { locked: !unlocked, items: unlocked ? [item] : [] };
      case "cardItems": return { locked: !unlocked, items: [] }; // the app's vault has no cards: an empty list, not "locked"
      case "cardFillOffers": return { fillable: false, origin: null, crossOriginFormsOnly: false };
      case "ping": return { ok: true };
      case "updateStatus": return { current: "0", latest: null, chromeUrl: null, firefoxUrl: null, quietReason: null };
      default: return undefined;
    }
  };
  const page = await loadPopup(answer);
  await page.settle(900); // two frames and the 400 ms the sheet gets to finish presenting, then the prompt
  assert.deepEqual(page.errors, []);
  assert.equal(unlockAsks, 1, "Face ID is asked for once, by itself");
  assert.equal(page.byId("unlocked").hidden, false, "the list is up");
  assert.equal(page.byId("locked").hidden, true);
  // The view stays put: later status polls do not ask again and do not flip it.
  await page.settle(1200);
  assert.equal(unlockAsks, 1);
  assert.equal(page.byId("unlocked").hidden, false);
  // The page going away (the Face ID sheet dismisses the popup on iOS) locks nothing.
  for (const type of ["pagehide", "visibilitychange", "beforeunload", "unload"]) for (const fn of page.windowListeners[type] ?? []) fn({});
  await page.settle(50);
  assert.ok(!page.sent.includes("lock"), "no lock is sent when the popup's page is hidden or unloaded");
  page.dispose();
});

test("a popup opened again inside the unlock's lifetime shows the list without asking for Face ID", async () => {
  let unlockAsks = 0;
  const answer: Answer = (msg) => {
    switch (msg.type) {
      case "appServer": return { app: "set" };
      case "serverInfo": return { url: "https://home.example", trustedStore: true, block: null };
      case "status": return { ...lockedStatus, unlocked: true, count: 0 };
      case "appUnlock": unlockAsks++; return { ok: true, state: "open" };
      case "matches": return { locked: false, matches: [] };
      case "allItems": return { locked: false, items: [] };
      case "cardItems": return { locked: false, items: [] };
      case "cardFillOffers": return { fillable: false, origin: null, crossOriginFormsOnly: false };
      default: return undefined;
    }
  };
  const page = await loadPopup(answer);
  await page.settle(900);
  assert.deepEqual(page.errors, []);
  assert.equal(unlockAsks, 0);
  assert.equal(page.byId("unlocked").hidden, false);
  page.dispose();
});
