/**
 * Content script — thin wiring between the pure detection engine (detect.ts), the shadow-DOM
 * UI layer (content-ui.ts), and the service worker (messages.ts contract). Runs in every
 * http(s) frame (all_frames); srcdoc/about:blank frames have an empty hostname and are skipped
 * entirely. The SW holds the decrypted vault and enforces the reveal rules — a secret reaches
 * this frame only host-bound, popup-granted, or via an explicit search-all pick (ZK).
 */
import {
  closeDropdown,
  dropdownWillConsumeEnter,
  openDropdown,
  showLinkOffer,
  showSaveBanner,
  showToast,
  type DropdownState,
} from "./content-ui";
import { findCardForms, findLoginForms, isSubmitLike, type CardFieldKind, type CardForm, type LoginForm } from "./detect";
import { fillErrorCopy, saveErrorCopy } from "./errors";
import {
  send,
  type CardFillFields,
  type CardFillOutcome,
  type FillOutcome,
  type MatchItem,
  type PendingSave,
  type Req,
  type RevealedSecret,
  type Res,
  type TabMsg,
} from "./messages";

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

/** Cut M (v2 #14): fill is truthful — answers exactly which parts landed in the page's fields
 *  (the old void return swallowed every miss: dead form refs, mismatched fields, empty items).
 *  The TOTP side-copy runs only when a credential actually landed — a failed fill must not
 *  half-succeed into the clipboard while the caller reports failure. */
function fillForm(f: LoginForm, s: RevealedSecret): FillOutcome {
  const live = liveForm(f);
  if (!live) return { filled: "nothing", code: "no_form" };
  if (!s.username && !s.password) return { filled: "nothing", code: "no_secret" };
  let wroteUser = false;
  let wrotePass = false;
  filling = true;
  try {
    if (live.username && s.username) {
      setValue(live.username, s.username);
      wroteUser = true;
    }
    if (live.password && s.password) {
      setValue(live.password, s.password);
      wrotePass = true;
    }
  } finally {
    filling = false;
  }
  if (!wroteUser && !wrotePass) return { filled: "nothing", code: "no_fields" };
  updateSnapshot(live); // our dispatched events are !isTrusted — feed the capture engine directly
  if (s.totpCode) void copyTotp(s.totpCode);
  return { filled: wroteUser && wrotePass ? "both" : wroteUser ? "username" : "password" };
}

async function copyTotp(code: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(code);
    showToast("2FA code copied — paste when asked");
    await scheduleClipboardClear(); // E1-4: clear this post-fill 2FA copy on the policy window
  } catch {
    // a11y 6d (AM-7): assertive — the code is shown ONLY in this 5 s toast (safety-critical path).
    showToast(`2FA code: ${code}`, true); // clipboard needs document focus — surface the code instead
  }
}

/** The ONE pending clipboard-clear timer for this frame (AM2, content half): copyTotp is the
 *  only in-page copy site, so a single slot suffices — a newer copy clearTimeout's the previous,
 *  mirroring the popup slot and the SW alarm's "last copy through us wins". */
let clipClearTimer = 0;

/** E1-4 clipboard auto-clear, content half — mirrors popup's scheduleClipboardClear: arm the SW
 *  alarm backstop (it outlives this frame) whose reply carries the effective policy seconds, plus
 *  a local precise timer (web useCopy parity — blind clear, `Math.max(1, s)` clamp, policy 0 still
 *  clears). SW unreachable → 30 s default. Never a user-facing error: every path is a silent no-op. */
async function scheduleClipboardClear(): Promise<void> {
  const r = await safeSend({ type: "scheduleClipboardClear" });
  const s = r?.clearSeconds ?? 30;
  window.clearTimeout(clipClearTimer); // AM2: single slot — the newest copy owns the clear
  clipClearTimer = window.setTimeout(() => void navigator.clipboard.writeText("").catch(() => {}), Math.max(1, s) * 1000);
}

// ---- S3 in-page card fill (design 2026-07-10-extension-card-fill) ----
// Detection is passive per frame: findCardForms reports metadata-only kinds to the SW, which binds
// this frame's identity to browser-set sender.origin. Fill is a targeted round-trip: the SW sends
// {fillCard} to THIS frame only, we redeem via revealCardForFill (the value round-trip), and the
// revealed card fields stay strictly function-local — never snapshotted, never save-bannerable ([A6]).

/** The current frame's card form (first one found), cached for the fill round-trip. */
let cardForm: CardForm | null = null;
/** Last reported kind signature — skip redundant cardFormInfo sends on quiet mutations. */
let lastCardSig = "";

/** Re-scan and report this frame's card form to the SW (metadata only). Empty ⇒ the form went
 *  away and the SW clears our record. Idempotent: a stable kind-set never re-sends. */
function reportCardForm(): void {
  cardForm = findCardForms(document)[0] ?? null;
  const kinds: CardFieldKind[] = cardForm ? cardForm.fields.map((f) => f.kind) : [];
  const sig = kinds.join(",");
  if (sig === lastCardSig) return;
  lastCardSig = sig;
  void safeSend({ type: "cardFormInfo", fields: kinds });
}

/** Re-resolve to the live card form (an SPA may have swapped the subtree since detection). */
function liveCardForm(): CardForm | null {
  if (cardForm && cardForm.fields.length > 0 && cardForm.fields.every((f) => f.input.isConnected)) return cardForm;
  cardForm = findCardForms(document)[0] ?? null;
  return cardForm;
}

/** Map a detected card kind to its fill value. Split MM/YY feeds standalone month/year inputs. */
function cardValueFor(kind: CardFieldKind, v: CardFillFields): string | null {
  switch (kind) {
    case "cardnumber":
      return v.number ?? null;
    case "cardexpiry":
      return v.expiry ?? null;
    case "cardexpmonth":
      return v.expiry ? v.expiry.slice(0, 2) : null; // "MM" of "MM/YY"
    case "cardexpyear":
      return v.expiry ? v.expiry.slice(3) : null; //    "YY" of "MM/YY"
    case "cardname":
      return v.name ?? null;
    case "cardcvv":
      return v.cvv ?? null;
  }
}

/** Write the revealed card fields into the form's inputs, CVV LAST (some checkouts validate CVV
 *  against the entered PAN). [A6]: NEVER updateSnapshot / touch `snapshots` — the values are used
 *  synchronously inside this call frame and implicitly cleared with it. */
function applyCardFill(form: CardForm, values: CardFillFields): CardFillOutcome {
  let wrote = false;
  filling = true;
  try {
    for (const { kind, input } of form.fields) {
      if (kind === "cardcvv") continue; // CVV last
      const val = cardValueFor(kind, values);
      if (val !== null && input.isConnected) {
        setValue(input, val);
        wrote = true;
      }
    }
    for (const { kind, input } of form.fields) {
      if (kind !== "cardcvv") continue;
      const val = cardValueFor(kind, values);
      if (val !== null && input.isConnected) {
        setValue(input, val);
        wrote = true;
      }
    }
  } finally {
    filling = false;
  }
  return wrote ? { filled: "card" } : { filled: "nothing", code: "no_fields" };
}

/** Popup-granted card fill: redeem the one-shot grant (the SW verifies frameId + origin + live
 *  top-origin), then write the returned fields. The card values never persist past this call. */
async function fillCardIntoForm(itemId: string): Promise<CardFillOutcome> {
  const form = liveCardForm();
  if (!form) return { filled: "nothing", code: "no_form" };
  const r = await safeSend({ type: "revealCardForFill", itemId });
  if (!r) return { filled: "nothing", code: "unreachable" };
  if (!r.ok || !r.fields) return { filled: "nothing", code: "not_allowed" };
  return applyCardFill(form, r.fields);
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
    onPick: (m) => void fillFromDropdown(m.itemId, f, false),
    onStrongPassword: () => void useStrongPassword(f),
    onSearch: async (query) => {
      const r = await safeSend({ type: "allItems", query });
      return r && !r.locked ? r.items : [];
    },
    onSearchPick: (m) => void fillExplicit(m, f),
  });
}

async function fillItem(itemId: string, f: LoginForm, explicit: boolean): Promise<FillOutcome> {
  const r = await safeSend({ type: "reveal", itemId, host: location.hostname, explicit });
  closeDropdown();
  if (!r) return { filled: "nothing", code: "unreachable" };
  if (!r.ok || !r.secret) return { filled: "nothing", code: r.code ?? "not_allowed" };
  return fillForm(f, r.secret);
}

/** Cut M (v2 #14): dropdown picks surface their verdict in-page — the old path closed the
 *  dropdown and did nothing visible either way, leaving the user to guess from the fields.
 *  Success names exactly what landed (a username-step fill is NOT "Login filled"); failures
 *  render the canon line. A TOTP side-copy toast may follow and supersede the success one —
 *  the 2FA instruction is the more urgent of the two. */
async function fillFromDropdown(itemId: string, f: LoginForm, explicit: boolean): Promise<FillOutcome> {
  const o = await fillItem(itemId, f, explicit);
  if (o.filled === "nothing") showToast(fillErrorCopy(o.code));
  else showToast(o.filled === "both" ? "Login filled" : o.filled === "username" ? "Username filled" : "Password filled");
  return o;
}

/** Search-all pick: explicit reveal (user chose it in OUR closed-shadow UI), then offer the
 *  one-tap URI backfill so the item matches this site next time — but only after a REAL fill
 *  (Cut M: linking a site the fill never reached would compound the silent failure). */
async function fillExplicit(m: MatchItem, f: LoginForm): Promise<void> {
  const o = await fillFromDropdown(m.itemId, f, true);
  if (o.filled === "nothing") return;
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
  // Cut M (v2 #14): every dead end here used to be silent — the dropdown just vanished.
  if (!r) {
    showToast(fillErrorCopy("unreachable"));
    return;
  }
  const live = liveForm(f);
  if (!live) {
    showToast(fillErrorCopy("no_form"));
    return;
  }
  const targets = live.newPasswords.length > 0 ? live.newPasswords : live.password ? [live.password] : [];
  if (targets.length === 0) {
    showToast(fillErrorCopy("no_fields"));
    return;
  }
  filling = true;
  try {
    for (const t of targets) setValue(t, r.password);
  } finally {
    filling = false;
  }
  updateSnapshot(live); // the generated secret must reach the save banner, not just the page
  showToast("Strong password filled"); // Cut M (v2 #14): success is visible too, not just failure
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
  // CVV-negative rule (cards design 2026-07-09): the form's lone password-typed field is a
  // checkout security code — never raise save/update for it (an "update" would overwrite the
  // stored merchant password with a CVV). Fill/dropdown behavior stays untouched.
  if (f.suppressSave) return;
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
      // E1-5: map the SW's code to human copy — NEVER render r.error (the old `?? fallback` only
      // fired on undefined, so the SW's internal "locked"/"save failed (conflict)" strings leaked
      // straight into the red result line). saveErrorCopy: locked → unlock-and-retry, conflict →
      // open-in-web-vault, failed/undefined → generic retry.
      return { ok: false, text: saveErrorCopy(r?.code) };
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
      // Cut N review: when the dropdown is about to consume this Enter as a row pick, it is NOT a
      // login submit — snapshotting the (possibly junk partial) field here would offer to overwrite
      // the stored password. This listener runs BEFORE the dropdown's Enter handler, so the flag is
      // still accurate. (Enter with no active row still submits the page form → capture stays valid.)
      if (dropdownWillConsumeEnter()) return;
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
      reportCardForm(); // S3: a checkout card form may have just rendered (or gone away)
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

  chrome.runtime.onMessage.addListener(
    (msg: TabMsg, _sender, sendResponse: (o: FillOutcome | CardFillOutcome) => void) => {
      if (msg.type === "fillItem") {
        // Popup-granted fill: the SW minted a one-shot grant, so the normal host-bound reveal
        // path clears it — single secret-egress path. Cut M (v2 #14): the REAL outcome goes back
        // via sendResponse (the SW relays it to the popup, whose ok used to mean mere delivery) —
        // a form-less page answers no_form instead of staying silent.
        const all = scanForms();
        const f = all.find((x) => x.kind === "login") ?? all[0];
        if (!f) {
          sendResponse({ filled: "nothing", code: "no_form" });
          return undefined;
        }
        void fillItem(msg.itemId, f, false).then(sendResponse);
        return true; // keep the channel open for the async outcome
      }
      if (msg.type === "fillCard") {
        // S3: the SW sent this to THIS frame only (frameId-targeted). We redeem the one-shot card
        // grant and write the returned fields; the SW re-verifies frameId + origin + top origin.
        void fillCardIntoForm(msg.itemId).then(sendResponse);
        return true; // keep the channel open for the async outcome
      }
      if (msg.type === "offerPendingSave" && isTop) offerBanner(msg.pending);
      return undefined;
    },
  );

  void safeSend({ type: "pageInfo", host: location.hostname });
  reportCardForm(); // S3: report any card form present at load (metadata only)

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
