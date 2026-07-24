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
  isOwnUiHost,
  openDropdown,
  showLinkOffer,
  showSaveBanner,
  showToast,
  type DropdownState,
} from "./content-ui";
import { deriveCardWrite, radioIndexFor, splitPan, verifyLanded, verifySplitPanLanded, type CardTargetMeta, type CardWrite } from "./cardfill";
import { bumpLabelGeneration, findCardForms, findLoginForms, isSubmitLike, labelSourcesOf, type CardFieldKind, type CardForm, type CardFormFieldRef, type FillableControl, type LoginForm } from "./detect";
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

// ---- §3 shadow DOM (Tier 2, F14) ----
// Open AND closed roots join the scan scopes: chrome.dom.openOrClosedShadowRoot (Chrome) /
// el.openOrClosedShadowRoot (Firefox content scripts) / el.shadowRoot. OPEN-shadow logins get
// dropdown + fill + input capture; CLOSED-shadow gets popup-driven fill only (composedPath
// truncates at closed boundaries — our own dropdown host relies on exactly that).

const SHADOW_MAX_DEPTH = 8;
const SHADOW_MAX_ROOTS = 64;
const SHADOW_MAX_VISITED = 20_000;

/** The cached root list. [U16]: re-swept ONLY on childList-bearing mutation ticks (attribute
 *  toggles cannot create shadow roots; the walk is ~130k API calls/s worst case if run per
 *  attribute tick). `attachShadow` on an existing element stays invisible until the next
 *  childList tick — accepted residual. Pin: shadow-free pages stay byte-identical (roots=[]). */
let shadowRoots: ShadowRoot[] = [];

/** [U16] one observer PER root (a shared observer has no per-root unobserve), reconciled each
 *  sweep, hard-capped at SHADOW_MAX_ROOTS live. */
const shadowObservers = new Map<ShadowRoot, MutationObserver>();

function shadowRootOf(el: Element): ShadowRoot | null {
  try {
    const sr = chrome.dom?.openOrClosedShadowRoot?.(el as HTMLElement);
    if (sr) return sr;
  } catch {
    /* chrome.dom unavailable / detached element — fall through to the standard probes */
  }
  const ff = (el as Element & { openOrClosedShadowRoot?: ShadowRoot | null }).openOrClosedShadowRoot;
  return ff ?? el.shadowRoot;
}

/** Recursive root discovery via TreeWalker. Caps are per sweep and stop DISCOVERY while keeping
 *  everything already found ([U16] — partial beats nothing). Roots land in document order, so
 *  the first-64 are the page's first-64. */
function sweepShadowRoots(): void {
  const roots: ShadowRoot[] = [];
  let visited = 0;
  let stopped = false;
  const walk = (scope: Document | ShadowRoot, depth: number): void => {
    const w = document.createTreeWalker(scope, NodeFilter.SHOW_ELEMENT);
    for (let n = w.nextNode(); n !== null && !stopped; n = w.nextNode()) {
      if (++visited > SHADOW_MAX_VISITED) {
        stopped = true;
        return;
      }
      // Our own closed-shadow UI host is opaque to the scan: chrome.dom pierces closed roots, so
      // without this the sweep would observe our dropdown/toast root and every render would loop
      // back through onMutations. Skip the host AND its subtree (never descend into our own UI).
      if (isOwnUiHost(n as Element)) continue;
      const sr = shadowRootOf(n as Element);
      if (sr === null) continue;
      if (roots.length >= SHADOW_MAX_ROOTS) {
        stopped = true;
        return;
      }
      roots.push(sr);
      if (depth < SHADOW_MAX_DEPTH) walk(sr, depth + 1);
    }
  };
  walk(document, 1);
  shadowRoots = roots;
  reconcileShadowObservers();
}

/** The §7 observer options, shared by the document observer and every per-root observer — the
 *  attributeFilter literal is PINNED verbatim (extension-pins): a CSS-toggle reveal (class/style/
 *  hidden flip on a pre-rendered checkout) must re-scan; attribute ticks reuse the cached root
 *  list and label cache under the same 150 ms debounce; the sig guard stops redundant sends. */
const OBSERVE_OPTS: MutationObserverInit = { childList: true, subtree: true, attributes: true, attributeFilter: ["class", "style", "hidden"] };

function reconcileShadowObservers(): void {
  const live = new Set(shadowRoots);
  for (const [root, ob] of shadowObservers) {
    if (!live.has(root) || !root.host.isConnected) {
      ob.disconnect(); // per-observer disconnect — the reconcile IS the unobserve
      shadowObservers.delete(root);
    }
  }
  for (const root of shadowRoots) {
    if (shadowObservers.size >= SHADOW_MAX_ROOTS) break; // hard cap on LIVE observers
    if (shadowObservers.has(root)) continue;
    const ob = new MutationObserver(onMutations);
    ob.observe(root, OBSERVE_OPTS);
    shadowObservers.set(root, ob);
  }
}

/** Every scan scope, document first then roots in discovery (document) order — findLoginForms/
 *  findCardForms run per scope and concatenate, keeping document-order semantics. */
function scanScopes(): (Document | ShadowRoot)[] {
  return [document, ...shadowRoots];
}

// ---- form scan, cached per animation frame (focusin/input storms reuse one scan) ----

let formsCache: LoginForm[] | null = null;
function scanForms(): LoginForm[] {
  if (!formsCache) {
    formsCache = scanScopes().flatMap((s) => findLoginForms(s));
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
const nativeSelectedIndexSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "selectedIndex")!.set!;

/** React/Vue value tracking swallows direct `.value=` writes (the state stays empty while the
 *  text looks filled) — write through the native prototype setter, dispatched inside the [U18]
 *  event envelope (shared with the login fill DELIBERATELY — the fidelity gap bites logins too;
 *  Bitwarden ships the same pattern): focus → keydown → write → input (insertReplacementText) →
 *  keyup → change. Key events carry NO key identity; they are synthetic (!isTrusted), and every
 *  capture listener of ours is isTrusted-gated so our own events never self-trigger. [U18]: NO
 *  blind re-assert — ONE re-assert only when the read-back is EMPTY (a masker's reformat is
 *  success under the [T7] canonical verify; a masker that re-clears after the single re-assert
 *  ends as a truthful miss, accepted). */
function setValue(input: HTMLInputElement, value: string): void {
  input.focus();
  input.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, composed: true }));
  nativeValueSetter.call(input, value);
  input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, data: value, inputType: "insertReplacementText" }));
  input.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, composed: true }));
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  if (input.value === "") {
    nativeValueSetter.call(input, value);
    input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, data: value, inputType: "insertReplacementText" }));
  }
}

/** [T8] Selects are written BY INDEX through the native prototype setter — a `.value=` write
 *  binds to the FIRST option with a duplicate value (tripping the read-back verify), and React's
 *  change-event path for selects reads `target.value` at event time, so unlike inputs there is no
 *  value-tracker to bypass. Same composed input/change pair as setValue. */
function setSelectedIndex(sel: HTMLSelectElement, index: number): void {
  sel.focus();
  nativeSelectedIndexSetter.call(sel, index);
  sel.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  sel.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}

/** [W9] V3 radio card-type write — the ONLY card write that never goes through setValue: a radio's
 *  `.value` is its brand token, so setValue + a text verifyLanded would bless an UNSELECTED group.
 *  Select the winner via `.checked` (the read-back verify reads `.checked === true`, [W9]), then
 *  dispatch the events a real pick fires — `click` (its default action + PAGE listeners, which need
 *  no isTrusted), `input`, `change`. Called INSIDE the filling bracket ([A6]-safe: our own selection
 *  never reopens the dropdown). [W11]: the caller runs this LAST — a click may submit/navigate. */
function setRadioChecked(group: HTMLInputElement[], index: number): HTMLInputElement {
  const winner = group[index]!;
  winner.checked = true;
  winner.dispatchEvent(new MouseEvent("click", { bubbles: true, composed: true }));
  winner.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  winner.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  return winner;
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

/** Last reported registry signature — skip redundant cardFormInfo sends on quiet mutations. NULL
 *  (not "") until the first report (§7): the first reportCardForm after injection ALWAYS sends,
 *  even empty, clearing the SW's stale record for the new document in this frame slot. [U13]:
 *  the idempotence sig is JSON.stringify(forms) — a join(",") over nested arrays would alias
 *  [[a,b]] ≡ [[a],[b]] and swallow structural changes. */
let lastCardSig: string | null = null;

/** Re-scan and report ALL of this frame's card forms to the SW (metadata only, document order
 *  across [document, …shadowRoots] — §2 [U13]). Empty ⇒ every form went away and the SW clears
 *  our record. Idempotent: a stable structure never re-sends. */
function reportCardForm(): void {
  const forms: CardFieldKind[][] = scanScopes()
    .flatMap((s) => findCardForms(s))
    .map((f) => f.fields.map((x) => x.kind));
  const sig = JSON.stringify(forms);
  if (sig === lastCardSig) return;
  lastCardSig = sig;
  void safeSend({ type: "cardFormInfo", forms });
}

/** The live control → the metadata surface cardfill.ts derives against (§4). The caller-side DOM
 *  mappings the pure leaf must never see: `maxLength === -1` is the DOM's "undeclared" → null;
 *  select options read `opt.value` (its native attr-absent→text fallback is wanted — [T8]: it
 *  makes the value pass ≡ the text pass on label-only options). */
function cardTargetOf(el: FillableControl): CardTargetMeta {
  if (el instanceof HTMLSelectElement) {
    return { tag: "select", type: el.type, maxLength: null, placeholder: null, options: [...el.options].map((o) => ({ value: o.value, text: o.text })) };
  }
  return { tag: "input", type: el.type, maxLength: el.maxLength === -1 ? null : el.maxLength, placeholder: el.placeholder === "" ? null : el.placeholder, options: null };
}

/** [U12] grant-redemption targeting: a FRESH scan (the SPA may have swapped subtrees since the
 *  popup click), then the FIRST form (document order) whose CURRENT kind-signature equals the
 *  grant's — kinds drift only when the form structurally changed, and filling a changed form is
 *  "wrong beats nothing"; NO index fallback, no match → the caller answers no_form.
 *  Identical-sig twins go document-order-first (a reorder among identical-sig forms is a
 *  harmless retarget — accepted + documented). */
function cardFormBySig(sig: string): CardForm | null {
  const forms = scanScopes().flatMap((s) => findCardForms(s));
  return forms.find((f) => f.fields.map((x) => x.kind).join(",") === sig) ?? null;
}

/** Drive cardfill.ts per field ref (§4/§5), CVV LAST (some checkouts validate CVV against the
 *  entered PAN): derive the ONE faithful write (null = fit-guard/no-value skip → file missed),
 *  write it (inputs via setValue, selects BY INDEX via the native setter — [T8]), then
 *  verifyLanded on an immediate read-back (F16/[T7]) — a mismatch leaves the page's residue in
 *  place (never auto-clear, it may be user-typed) and files the kind missed. [A6]: the card path
 *  NEVER feeds the capture engine / save-banner store — the values are used synchronously inside
 *  this call frame and implicitly cleared with it (pin-anchored, §11). */
function applyCardFill(form: CardForm, values: CardFillFields): CardFillOutcome {
  const filledKinds: CardFieldKind[] = [];
  const missedKinds: CardFieldKind[] = [];
  const file = (list: CardFieldKind[], kind: CardFieldKind): void => {
    if (!list.includes(kind)) list.push(kind);
  };
  let lastWritten: FillableControl | null = null;
  filling = true;
  try {
    // §4 [U19] split-PAN pre-pass: >1 cardnumber INPUT → cardfill.splitPan chunks when every box
    // declares maxLength 1..8 and the boxes jointly fit the PAN; otherwise the whole PAN goes to
    // the FIRST box ONLY, under the ordinary fit-guard (a declared-but-insufficient box nulls the
    // write there → truthful miss; the fallback only ever lands for undeclared-maxLength shapes).
    const panBoxes = form.fields.flatMap((f) => (f.kind === "cardnumber" && f.input instanceof HTMLInputElement && f.input.isConnected ? [f.input] : []));
    const splitRan = panBoxes.length > 1;
    if (splitRan) {
      const chunks = splitPan(values.number, panBoxes.map((b) => (b.maxLength === -1 ? null : b.maxLength)));
      if (chunks !== null) {
        for (let i = 0; i < panBoxes.length; i++) {
          // A PAN shorter than the boxes' joint capacity leaves trailing chunks empty — don't
          // write "" into them (a no-op that would still aim the closing blur/[U18] re-assert at
          // an untouched box); lastWritten stays on the last box that actually received digits.
          if (chunks[i] === "") continue;
          setValue(panBoxes[i]!, chunks[i]!);
          lastWritten = panBoxes[i]!;
        }
        // [U19] landed-ness = the CONCATENATION of every box's digitsOnly vs the full PAN —
        // auto-advance maskers redistribute digits across boxes, so per-box equality would
        // fail a successful fill. Mismatch leaves the residue in place (never auto-clear).
        file(verifySplitPanLanded(values.number ?? "", panBoxes.map((b) => b.value)) ? filledKinds : missedKinds, "cardnumber");
      } else {
        const first = panBoxes[0]!;
        const write = deriveCardWrite("cardnumber", cardTargetOf(first), values);
        if (write !== null && write.kind === "text") {
          setValue(first, write.value);
          lastWritten = first;
          file(verifyLanded("cardnumber", write, { kind: "text", value: first.value }) ? filledKinds : missedKinds, "cardnumber");
        } else {
          file(missedKinds, "cardnumber");
        }
      }
    }
    // [W9] cardtype RADIO refs are held back from this text/select loop entirely — deriveCardWrite
    // would hand a cardtype/input target a text write, setValue would stamp the radio's `.value`,
    // and a text verifyLanded would falsely report "filled" on an unselected group. They fill LAST,
    // via the `.checked` branch below ([W11]).
    const isRadioRef = (f: CardFormFieldRef): boolean => f.input instanceof HTMLInputElement && f.input.type === "radio";
    const nonRadio = form.fields.filter((f) => !isRadioRef(f));
    for (const { kind, input } of [...nonRadio.filter((f) => f.kind !== "cardcvv"), ...nonRadio.filter((f) => f.kind === "cardcvv")]) {
      if (splitRan && kind === "cardnumber") continue; // the pre-pass owned the PAN verdict
      if (!input.isConnected) {
        file(missedKinds, kind);
        continue;
      }
      const write = deriveCardWrite(kind, cardTargetOf(input), values);
      if (write === null) {
        file(missedKinds, kind);
        continue;
      }
      let observed: CardWrite;
      if (write.kind === "index" && input instanceof HTMLSelectElement) {
        setSelectedIndex(input, write.index);
        observed = { kind: "index", index: input.selectedIndex };
        lastWritten = input;
      } else if (write.kind === "text" && input instanceof HTMLInputElement) {
        setValue(input, write.value);
        observed = { kind: "text", value: input.value };
        lastWritten = input;
      } else {
        file(missedKinds, kind); // write/control shape mismatch — unreachable by construction, but never guess
        continue;
      }
      file(verifyLanded(kind, write, observed) ? filledKinds : missedKinds, kind);
    }
    // [W9][W10][W11][W12] cardtype RADIO groups LAST — a synthetic click fires PAGE listeners (no
    // isTrusted needed) and runs the radio's default action, which may advance/submit/navigate and
    // DETACH unfilled PAN/expiry inputs, so this runs only after every text/select field is written.
    // Synthetic options come from THIS form's own collected group members ([W10] never a
    // document-wide `name` re-query — a colliding name in another block must stay unreachable);
    // buildCardForm already collapsed same-name members to ONE ref ([W12]), so each group fills once.
    // NO setValue: radioIndexFor picks the winner, `.checked` writes it, `.checked === true` verifies.
    // lastWritten is left on the last DATA field so the closing blur validates that, not the radio.
    for (const ref of form.fields.filter(isRadioRef)) {
      const live = (ref.group ?? [ref.input as HTMLInputElement]).filter((r) => r.isConnected);
      if (live.length === 0) {
        file(missedKinds, ref.kind);
        continue;
      }
      const idx = radioIndexFor(
        live.map((r) => ({ value: r.value, text: labelSourcesOf(r).join(" ") })),
        values.brand,
      );
      if (idx === null) {
        file(missedKinds, ref.kind);
        continue;
      }
      const winner = setRadioChecked(live, idx);
      file(winner.checked ? filledKinds : missedKinds, ref.kind);
    }
    // §4 card path only: end with blur + focusout on the last-written field, INSIDE the
    // filling bracket — validate-on-blur checkouts must run their checks NOW, while our own
    // focusin suppression still holds (blur does not bubble; focusout does).
    if (lastWritten !== null) {
      lastWritten.dispatchEvent(new FocusEvent("blur", { composed: true }));
      lastWritten.dispatchEvent(new FocusEvent("focusout", { bubbles: true, composed: true }));
    }
  } finally {
    filling = false;
  }
  // Truthful verdict (F9): card = EVERY declared kind landed; partial = both lists non-empty.
  // Duplicate same-kind refs (twin expiry boxes, multi-block forms): a KIND counts filled when
  // ANY of its instances landed — "partial" must mean a whole kind is missing from the page,
  // not that one of two twins missed while its sibling filled.
  const missed = missedKinds.filter((k) => !filledKinds.includes(k));
  if (filledKinds.length === 0) return { filled: "nothing", filledKinds, missedKinds: missed, code: "no_fields" };
  return { filled: missed.length === 0 ? "card" : "partial", filledKinds, missedKinds: missed };
}

/** Popup-granted card fill: redeem the one-shot grant (the SW verifies frameId + origin + live
 *  top-origin), then write the returned fields. The card values never persist past this call.
 *  [U12]/[A3]: `sig` is the grant's kind-signature — a non-string (a mid-update mixed-version
 *  SW) refuses rather than guesses, same fail-closed law as the SW side. */
async function fillCardIntoForm(itemId: string, sig: unknown): Promise<CardFillOutcome> {
  const form = typeof sig === "string" ? cardFormBySig(sig) : null;
  if (!form) return { filled: "nothing", filledKinds: [], missedKinds: [], code: "no_form" };
  const r = await safeSend({ type: "revealCardForFill", itemId });
  if (!r) return { filled: "nothing", filledKinds: [], missedKinds: [], code: "unreachable" };
  if (!r.ok || !r.fields) return { filled: "nothing", filledKinds: [], missedKinds: [], code: "not_allowed" };
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

/** The ONE mutation sink — the document observer and every per-root shadow observer feed it.
 *  §7: attributes join the childList triggers (OBSERVE_OPTS) — a CSS-toggle reveal re-scans
 *  under the same 150 ms debounce; the sig guard stops redundant sends. Bounded: the attribute
 *  path re-walks findCardForms at most ~6×/s. [U16]: ONLY childList-bearing ticks re-sweep the
 *  shadow roots and bump detect.ts's label-cache generation (attribute toggles can create
 *  neither shadow roots nor label restructures the cache key survives; without the bump the
 *  label WeakMap would serve stale text forever on dynamic pages). */
let mutateTimer = 0;
let sweepPending = false;
function onMutations(records: MutationRecord[]): void {
  if (records.some((r) => r.type === "childList")) sweepPending = true;
  window.clearTimeout(mutateTimer);
  mutateTimer = window.setTimeout(() => {
    if (sweepPending) {
      sweepPending = false;
      bumpLabelGeneration();
      sweepShadowRoots();
    }
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
}

// [U17] retargeting: `e.composedPath()[0]` replaces `e.target` in FOUR paths — focusin,
// click-reopen, the input listener (capture), and the keydown Enter-capture. Events crossing an
// OPEN shadow boundary retarget to the host, leaving instanceof gates silently dead for shadow
// fields; composedPath()[0] is the real innermost target (and truncates back to the host at
// CLOSED boundaries — popup-driven fill only there, which is also what keeps our own
// closed-shadow dropdown host opaque). DOCUMENTED RESIDUALS: the `submit` listener (submit does
// not compose — shadow form submits stay uncaptured) and the mutation auto-open's
// `document.activeElement` (= host).

function init(): void {
  document.addEventListener(
    "focusin",
    (e) => {
      if (e.isTrusted) maybeOpen(e.composedPath()[0] ?? null);
    },
    true,
  );

  document.addEventListener(
    "input",
    (e) => {
      const t = e.composedPath()[0] ?? e.target;
      if (!e.isTrusted || !(t instanceof HTMLInputElement)) return;
      const f = formFor(t);
      if (f) updateSnapshot(f);
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (e) => {
      const t = e.composedPath()[0] ?? e.target;
      if (!e.isTrusted || e.key !== "Enter" || !(t instanceof HTMLInputElement)) return;
      // Cut N review: when the dropdown is about to consume this Enter as a row pick, it is NOT a
      // login submit — snapshotting the (possibly junk partial) field here would offer to overwrite
      // the stored password. This listener runs BEFORE the dropdown's Enter handler, so the flag is
      // still accurate. (Enter with no active row still submits the page form → capture stays valid.)
      if (dropdownWillConsumeEnter()) return;
      const f = formFor(t);
      if (!f) return;
      if (t.type === "password" || (f.kind === "username-step" && f.username === t)) captureNow(f);
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
      const t = e.composedPath()[0];
      if (t instanceof HTMLInputElement) maybeOpen(t); // reopen after dismissal
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

  new MutationObserver(onMutations).observe(document.documentElement, OBSERVE_OPTS);

  chrome.runtime.onMessage.addListener(
    (msg: TabMsg, _sender, sendResponse: (o: FillOutcome | CardFillOutcome | { ok: true }) => void) => {
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
        // [U12]: msg.sig picks the form — first current-sig match in document order, else no_form.
        void fillCardIntoForm(msg.itemId, msg.sig).then(sendResponse);
        return true; // keep the channel open for the async outcome
      }
      if (msg.type === "rescanCardForms") {
        // §7 [T4]: reset the sig sentinel FIRST — bfcache restores this script's JS state on a
        // back-navigation, so without the reset the rescan's own report would be swallowed by its
        // own sig guard and the offer lost for the document's life. formsCache drops too (the SPA
        // that warranted a rescan invalidated the login scan as well).
        lastCardSig = null;
        formsCache = null;
        reportCardForm();
        sendResponse({ ok: true });
        return undefined;
      }
      if (msg.type === "offerPendingSave" && isTop) offerBanner(msg.pending);
      return undefined;
    },
  );

  void safeSend({ type: "pageInfo", host: location.hostname });
  sweepShadowRoots(); // §3: roots present at load join the very first scan/report
  reportCardForm(); // S3: report any card forms present at load (metadata only)

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
