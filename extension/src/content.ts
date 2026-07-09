/**
 * Content script — thin wiring between the pure detection engine (detect.ts), the shadow-DOM
 * UI layer (content-ui.ts), and the service worker (messages.ts contract). Runs in every
 * http(s) frame (all_frames); srcdoc/about:blank frames have an empty hostname and are skipped
 * entirely. The SW holds the decrypted vault and enforces the reveal rules — a secret reaches
 * this frame only host-bound, popup-granted, or via an explicit search-all pick (ZK).
 */
import { findLoginForms, isSubmitLike, type LoginForm } from "./detect";
import {
  closeDropdown,
  openDropdown,
  showLinkOffer,
  showSaveBanner,
  showToast,
  type DropdownState,
} from "./content-ui";
import { send, type MatchItem, type PendingSave, type Req, type RevealedSecret, type Res, type TabMsg } from "./messages";

const isTop = window.self === window.top;

/** sendMessage rejects while the SW restarts or after an extension reload orphans this script —
 *  every caller degrades to "do nothing" instead of throwing into the page's console. */
function safeSend<T extends Req["type"]>(req: Extract<Req, { type: T }>): Promise<Res<T> | undefined> {
  return send(req).catch(() => undefined);
}

// ---- form scan, cached per animation frame (focusin/input storms reuse one scan) ----

let formsCache: LoginForm[] | null = null;
function scanForms(): LoginForm[] {
  if (!formsCache) {
    formsCache = findLoginForms(document);
    requestAnimationFrame(() => {
      formsCache = null;
    });
  }
  return formsCache;
}

function formFor(input: HTMLInputElement): LoginForm | null {
  return (
    scanForms().find((f) => f.username === input || f.password === input || f.newPasswords.includes(input)) ?? null
  );
}

// ---- fill ----

const nativeValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;

/** React/Vue value tracking swallows direct `.value=` writes (the state stays empty while the
 *  text looks filled) — write through the native prototype setter, then dispatch the composed
 *  event pair frameworks listen for. */
function setValue(input: HTMLInputElement, value: string): void {
  input.focus();
  nativeValueSetter.call(input, value);
  input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, data: value, inputType: "insertReplacementText" }));
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}

/** Suppresses focusin→dropdown while OUR setValue calls input.focus() (those events are trusted). */
let filling = false;

/** Between dropdown-open and the user's pick, an SPA can swap the form subtree, detaching the
 *  captured field refs — filling would write into orphan nodes that never reach the page. If the
 *  refs are gone, re-scan and re-resolve to the live form of the same kind; null → skip the fill. */
function liveForm(f: LoginForm): LoginForm | null {
  const ref = f.password ?? f.username;
  if (ref && ref.isConnected) return f;
  formsCache = null; // force a fresh scan past the per-frame cache
  const all = scanForms();
  return all.find((x) => x.kind === f.kind) ?? all.find((x) => x.kind === "login") ?? all[0] ?? null;
}

function fillForm(f: LoginForm, s: RevealedSecret): void {
  const live = liveForm(f);
  if (!live) return;
  filling = true;
  try {
    if (live.username && s.username) setValue(live.username, s.username);
    if (live.password && s.password) setValue(live.password, s.password);
  } finally {
    filling = false;
  }
  updateSnapshot(live); // our dispatched events are !isTrusted — feed the capture engine directly
  if (s.totpCode) void copyTotp(s.totpCode);
}

async function copyTotp(code: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(code);
    showToast("2FA code copied — paste when asked");
  } catch {
    showToast(`2FA code: ${code}`); // clipboard needs document focus — surface the code instead
  }
}

// ---- dropdown ----

let lastOpen: { input: HTMLInputElement; t: number } | null = null;

function maybeOpen(target: EventTarget | null): void {
  if (filling || !(target instanceof HTMLInputElement)) return;
  const f = formFor(target);
  if (!f) return;
  const now = Date.now();
  if (lastOpen && lastOpen.input === target && now - lastOpen.t < 400) return; // focusin+click pair
  lastOpen = { input: target, t: now };
  void openFor(target, f);
}

async function openFor(anchor: HTMLInputElement, f: LoginForm): Promise<void> {
  // Raw hostname on the wire — the SW runs urimatch.normalizeHost, one normalizer fleet-wide.
  const res = await safeSend({ type: "matches", host: location.hostname });
  if (!res) return;
  const state: DropdownState = {
    kind: res.locked ? "locked" : res.matches.length > 0 ? "matches" : "empty",
    host: location.hostname,
    matches: res.locked ? [] : res.matches,
    isSignup: f.isSignup,
  };
  openDropdown(anchor, state, {
    onPick: (m) => void fillItem(m.itemId, f, false),
    onStrongPassword: () => void useStrongPassword(f),
    onSearch: async (query) => {
      const r = await safeSend({ type: "allItems", query });
      return r && !r.locked ? r.items : [];
    },
    onSearchPick: (m) => void fillExplicit(m, f),
  });
}

async function fillItem(itemId: string, f: LoginForm, explicit: boolean): Promise<void> {
  const r = await safeSend({ type: "reveal", itemId, host: location.hostname, explicit });
  closeDropdown();
  if (r?.ok && r.secret) fillForm(f, r.secret);
}

/** Search-all pick: explicit reveal (user chose it in OUR closed-shadow UI), then offer the
 *  one-tap URI backfill so the item matches this site next time. */
async function fillExplicit(m: MatchItem, f: LoginForm): Promise<void> {
  const r = await safeSend({ type: "reveal", itemId: m.itemId, host: location.hostname, explicit: true });
  closeDropdown();
  if (!r?.ok || !r.secret) return;
  fillForm(f, r.secret);
  if (!m.siteMatch) {
    showLinkOffer(
      m.name,
      location.hostname,
      async () => (await safeSend({ type: "linkUri", itemId: m.itemId, host: location.hostname }))?.ok === true,
    );
  }
}

async function useStrongPassword(f: LoginForm): Promise<void> {
  const r = await safeSend({ type: "generate" });
  closeDropdown();
  if (!r) return;
  const live = liveForm(f);
  if (!live) return;
  const targets = live.newPasswords.length > 0 ? live.newPasswords : live.password ? [live.password] : [];
  filling = true;
  try {
    for (const t of targets) setValue(t, r.password);
  } finally {
    filling = false;
  }
  updateSnapshot(live); // the generated secret must reach the save banner, not just the page
}

// ---- capture engine ----

interface Snapshot {
  username: string;
  password: string;
}

/** Keyed by form ?? container: SPA re-renders replace nodes (old keys GC away), and reading
 *  only at trigger time loses values on sites that clear fields before navigating — so keep
 *  the last non-empty value seen per field. */
const snapshots = new WeakMap<object, Snapshot>();

function snapKey(f: LoginForm): object {
  return f.form ?? f.container;
}

function updateSnapshot(f: LoginForm): void {
  const key = snapKey(f);
  const s = snapshots.get(key) ?? { username: "", password: "" };
  const u = f.username?.value ?? "";
  const p = f.password?.value ?? "";
  if (u !== "") s.username = u;
  if (p !== "") s.password = p;
  snapshots.set(key, s);
}

let lastSent: { u: string; p: string; t: number } | null = null;
/** A recent step-1 capture arms the password-page auto-open (multi-step logins). */
let usernameStepAt = 0;

function captureNow(f: LoginForm): void {
  updateSnapshot(f);
  const s = snapshots.get(snapKey(f)) ?? { username: "", password: "" };
  const username = s.username;
  const password = f.kind === "username-step" ? "" : s.password; // step 1 sends password:"" per contract
  if (f.kind === "username-step" ? username === "" : password === "") return;
  const now = Date.now();
  // Enter + form submit + button click routinely ALL fire for one login attempt.
  if (lastSent && lastSent.u === username && lastSent.p === password && now - lastSent.t < 1500) return;
  lastSent = { u: username, p: password, t: now };
  if (f.kind === "username-step") usernameStepAt = now;
  // The send happens NOW, before the page can unload — the SW keeps it as the tab's pending
  // save; the banner only appears if this document survives long enough to hear back.
  void (async () => {
    const res = await safeSend({ type: "capturedCredential", url: location.href, username, password });
    if (res?.pending) offerBanner(res.pending);
  })();
}

function offerBanner(pending: PendingSave): void {
  showSaveBanner(
    pending,
    async () => {
      const r = await safeSend({ type: "resolvePendingSave", action: "save" });
      if (r?.ok) return { ok: true, text: "Saved to the hoard." };
      return { ok: false, text: r?.error ?? "Could not save — unlock andvari and try again." };
    },
    () => void safeSend({ type: "resolvePendingSave", action: "dismiss" }),
  );
}

// ---- wiring ----

function init(): void {
  document.addEventListener(
    "focusin",
    (e) => {
      if (e.isTrusted) maybeOpen(e.target);
    },
    true,
  );

  document.addEventListener(
    "input",
    (e) => {
      if (!e.isTrusted || !(e.target instanceof HTMLInputElement)) return;
      const f = formFor(e.target);
      if (f) updateSnapshot(f);
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e) => {
      if (!e.isTrusted || e.key !== "Enter" || !(e.target instanceof HTMLInputElement)) return;
      const f = formFor(e.target);
      if (!f) return;
      if (e.target.type === "password" || (f.kind === "username-step" && f.username === e.target)) captureNow(f);
    },
    true,
  );

  // Deliberately not isTrusted-gated: requestSubmit()-driven submits are real logins too.
  document.addEventListener(
    "submit",
    (e) => {
      const t = e.target;
      if (!(t instanceof HTMLFormElement)) return;
      const f = scanForms().find((x) => x.form === t);
      if (f) captureNow(f);
    },
    true,
  );

  document.addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted) return;
      if (e.target instanceof HTMLInputElement) maybeOpen(e.target); // reopen after dismissal
      const control = e.composedPath().find((n): n is Element => n instanceof Element && isSubmitLike(n));
      if (!control) return;
      const all = scanForms();
      // "Near the form": a formless group's button can sit outside the fields' container —
      // when the page has exactly one login form, any submit-shaped click belongs to it.
      const f = all.find((x) => (x.form ?? x.container).contains(control)) ?? (all.length === 1 ? all[0]! : null);
      if (f) captureNow(f);
    },
    true,
  );

  // SPA route changes: an open dropdown is anchored to nodes that may be on their way out.
  window.addEventListener("popstate", closeDropdown);
  window.addEventListener("hashchange", closeDropdown);

  let mutateTimer = 0;
  new MutationObserver(() => {
    window.clearTimeout(mutateTimer);
    mutateTimer = window.setTimeout(() => {
      formsCache = null;
      // Multi-step: step 1 was captured and the password page/fragment just rendered with
      // focus already on the password field — offer without another user gesture.
      if (Date.now() - usernameStepAt < 120_000) {
        const a = document.activeElement;
        if (a instanceof HTMLInputElement && a.type === "password") {
          lastOpen = null;
          maybeOpen(a);
        }
      }
    }, 150);
  }).observe(document.documentElement, { childList: true, subtree: true });

  chrome.runtime.onMessage.addListener((msg: TabMsg) => {
    if (msg.type === "fillItem") {
      // Popup-granted fill: the SW minted a one-shot grant, so the normal host-bound reveal
      // path clears it — single secret-egress path. Frames without a form stay silent.
      const all = scanForms();
      const f = all.find((x) => x.kind === "login") ?? all[0];
      if (f) void fillItem(msg.itemId, f, false);
    } else if (msg.type === "offerPendingSave" && isTop) {
      offerBanner(msg.pending);
    }
  });

  void safeSend({ type: "pageInfo", host: location.hostname });

  // Post-navigation re-offer — top frame only, or every iframe would grow a banner.
  if (isTop) {
    void (async () => {
      const r = await safeSend({ type: "pendingSave" });
      if (r?.pending) offerBanner(r.pending);
    })();
  }

  // Autofocus bootstrap: the page put the cursor in a login field before we loaded.
  maybeOpen(document.activeElement);
}

if (location.hostname !== "") init();
