// The desktop popup (popup.ts as the Chrome bundle) drawn against a stand-in DOM, driven as a person drives it: its
// buttons pressed (a pointer down, a key down, a click), its fields filled, and its worker a function of the test's. The
// stand-in keeps what the popup sets on each element (text, hidden, focus) so a test reads the screen as drawn.
import vm from "node:vm";
import * as esbuild from "esbuild";

export type Answer = (msg: { type: string; [k: string]: unknown }) => unknown;

/** An element stand-in: it keeps what is set on it, its listeners, and the text of what is put in it. */
function fakeElement(page: { active: unknown }, id = ""): Record<string, unknown> {
  const listeners: Record<string, ((e: unknown) => unknown)[]> = {};
  const noop = (): undefined => undefined;
  const kids: Record<string, unknown>[] = [];
  const base: Record<string, unknown> = {
    id,
    hidden: true,
    textContent: "",
    value: "",
    disabled: false,
    className: "",
    title: "",
    tabIndex: 0,
    dataset: {},
    children: kids,
    style: new Proxy({ cssText: "" } as Record<string, unknown>, { get: (t, p) => (p === "setProperty" || p === "removeProperty" ? noop : t[p as string]), set: (t, p, v) => ((t[p as string] = v), true) }),
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    addEventListener: (type: string, fn: (e: unknown) => unknown) => void (listeners[type] ??= []).push(fn),
    removeEventListener: noop,
    /** Fires [type] with [props] on the event (`repeat`, `key`), as the browser would. */
    fire: (type: string, props: Record<string, unknown> = {}) => Promise.all((listeners[type] ?? []).map((fn) => fn({ preventDefault: noop, stopPropagation: noop, target: proxy, ...props }))),
    focus: () => void (page.active = proxy),
    blur: () => void (page.active === proxy ? (page.active = null) : undefined),
    append: (...n: Record<string, unknown>[]) => void kids.push(...n),
    appendChild: (n: Record<string, unknown>) => (kids.push(n), n),
    replaceChildren: (...n: Record<string, unknown>[]) => void kids.splice(0, kids.length, ...n),
    ownerDocument: { createElement: () => fakeElement(page) },
    getAttribute: () => null,
    setAttribute: noop,
    removeAttribute: noop,
    querySelector: () => null,
    querySelectorAll: () => [],
    closest: () => null,
    contains: () => false,
    matches: () => false,
    getBoundingClientRect: () => ({ top: 0, left: 0, width: 0, height: 0, bottom: 0, right: 0 }),
  };
  const proxy: Record<string, unknown> = new Proxy(base, { get: (t, p) => (p in t ? t[p as string] : typeof p === "string" ? noop : undefined), set: (t, p, v) => ((t[p as string] = v), true) });
  return proxy;
}

/** Every text in [e] and what was put in it, in order. */
export function textOf(e: Record<string, unknown>): string {
  const own = String(e.textContent ?? "");
  const kids = (e.children as Record<string, unknown>[] | undefined) ?? [];
  return [own, ...kids.map(textOf)].filter(Boolean).join(" ");
}

/** Loads the desktop popup into a fresh page whose worker answers with [answer]. The page's clock is [clock].now. */
export async function drawPopup(answer: Answer) {
  const out = await esbuild.build({
    entryPoints: [new URL("../popup.ts", import.meta.url).pathname],
    bundle: true,
    format: "iife",
    target: "es2022",
    write: false,
    logLevel: "silent",
    define: { __ANDVARI_TARGET__: JSON.stringify("chrome") },
  });
  const page = { active: null as unknown };
  const clock = { now: 1_000 };
  const elements = new Map<string, Record<string, unknown>>();
  const byId = (id: string): Record<string, unknown> => {
    if (!elements.has(id)) elements.set(id, fakeElement(page, id));
    return elements.get(id)!;
  };
  const sent: { type: string; [k: string]: unknown }[] = [];
  const errors: unknown[] = [];
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const pageTimeout = (fn: () => void, ms?: number) => {
    const t = setTimeout(fn, ms);
    timers.add(t);
    return t;
  };
  /** Every interval the page set, with its period and its function, and whether it was cleared since. */
  const intervals: { t: ReturnType<typeof setInterval>; ms: number | undefined; fn: () => void; cleared: boolean }[] = [];
  const pageInterval = (fn: () => void, ms?: number) => {
    const t = setInterval(fn, ms);
    timers.add(t);
    intervals.push({ t, ms, fn, cleared: false });
    return t;
  };
  const pageClearInterval = (t: ReturnType<typeof setInterval> | undefined) => {
    for (const i of intervals) if (i.t === t) i.cleared = true;
    clearInterval(t);
  };
  const dispose = (): void => {
    for (const t of timers) {
      clearTimeout(t);
      clearInterval(t);
    }
  };
  const document = {
    getElementById: (id: string) => (id === "server-details" || id === "other-site-confirm" ? null : byId(id)),
    createElement: () => fakeElement(page),
    createElementNS: () => fakeElement(page),
    createTextNode: (t: string) => Object.assign(fakeElement(page), { textContent: t }),
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    visibilityState: "visible",
    body: fakeElement(page, "body"),
    head: fakeElement(page, "head"),
    documentElement: fakeElement(page, "html"),
    get activeElement() {
      return page.active;
    },
  };
  const chrome = {
    runtime: {
      sendMessage: async (msg: { type: string }) => {
        sent.push(msg);
        return answer(msg);
      },
      getURL: (p: string) => `chrome-extension://x/${p}`,
      getManifest: () => ({ version: "0.0.0" }),
      onMessage: { addListener: () => undefined },
      openOptionsPage: () => undefined,
      connect: () => ({ onMessage: { addListener: () => undefined }, onDisconnect: { addListener: () => undefined }, postMessage: () => undefined, disconnect: () => undefined }),
    },
    tabs: { query: async () => [{ id: 1, url: "https://login.example.com/x" }], create: async () => ({}) },
    permissions: { contains: async () => true, request: async () => true },
  };
  const window: Record<string, unknown> = {
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    setTimeout: pageTimeout,
    clearTimeout,
    setInterval: pageInterval,
    clearInterval: pageClearInterval,
    close: () => undefined,
    matchMedia: () => ({ matches: false, addEventListener: () => undefined }),
    location: { href: "chrome-extension://x/popup.html", search: "" },
  };
  const context = vm.createContext({
    window, document, chrome, console, setTimeout: pageTimeout, clearTimeout, setInterval: pageInterval, clearInterval: pageClearInterval, URL, TextEncoder, TextDecoder, crypto: globalThis.crypto,
    performance: { now: () => clock.now },
    navigator: { clipboard: { writeText: async () => undefined }, userAgent: "drawn", credentials: undefined },
    requestAnimationFrame: (fn: () => void) => pageTimeout(fn, 0),
    location: window.location,
    PublicKeyCredential: undefined,
  });
  const onRejection = (e: unknown) => errors.push(e);
  process.on("unhandledRejection", onRejection);
  try {
    vm.runInContext(out.outputFiles[0]!.text, context, { filename: "popup.js" });
  } catch (e) {
    errors.push(e);
  }
  const settle = (ms = 60): Promise<void> => new Promise((r) => setTimeout(r, ms));
  return {
    byId,
    sent,
    errors,
    settle,
    clock,
    page,
    /** The page's intervals still running. */
    liveIntervals: () => intervals.filter((i) => !i.cleared),
    dispose: () => {
      dispose();
      process.off("unhandledRejection", onRejection);
    },
  };
}

/** The worker's answers for a locked popup at a server in force, with nothing else under way. */
export const lockedStatus = { unlocked: false, count: 0, email: null, mustChangePassword: false, lockNotice: null, quickUnlock: { enrolled: false, armed: false, attemptsRemaining: 0, offerDismissed: true, kind: null }, totpPending: null, personalChange: false, personalChangeText: null, personalProposal: false, waitingGrants: 0, wrongVault: 0, rememberedEmail: null };
