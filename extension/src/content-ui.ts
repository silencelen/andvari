/**
 * In-page UI layer: fill dropdown, save/update banner, link-offer banner, toast. Pure DOM —
 * no chrome.* — the content script wires actions in via handlers.
 *
 * Strict-CSP hardening (carried over from 0.6.0): all UI lives in a CLOSED shadow root, styled
 * by a constructed CSSStyleSheet via adoptedStyleSheets — encapsulated from the page's CSS AND
 * immune to the page's `style-src` (unlike inline <style>/style="" attributes). Dynamic position
 * is set via CSSOM (el.style.*), which is not gated by CSP.
 *
 * Theming trap the token layout answers: `all: initial` does NOT reset custom properties, and
 * the page can out-cascade :host rules on the host element — so the full --anv-* token set is
 * defined ON the component roots (.dropdown/.banner/.toast), never :host, making each surface
 * self-sealed on any site. The ᛅ+wordmark header doubles as anti-spoof attribution: a
 * distinctive treasury surface is harder for a page to convincingly fake — so the mark is
 * drawn as SVG geometry (sigilSpan), never a runic codepoint that tofus on font-poor hosts.
 */
import type { MatchItem, PendingCardSave, PendingSave } from "./messages";

const UI_CSS = `
:host { all: initial; }

.dropdown, .banner, .toast, .chip { all: initial; }
.dropdown, .banner, .toast, .chip {
  --anv-bg: #1e1b15;
  --anv-bg-deep: #14120e;
  --anv-bg-input: #262119;
  --anv-edge: #38311f;
  --anv-edge-strong: #4a3f28;
  --anv-ink: #ede4d0;
  --anv-ink-dim: #a79c85;
  --anv-ink-faint: #8d8370;
  --anv-gold: #d0a94a;
  --anv-gold-bright: #e8c66a;
  /* Cut A (web parity): normal-size gold TEXT darkens in light for AA; dark equals gold. */
  --anv-gold-text: #d0a94a;
  --anv-btn-ink: #1a1509;
  --anv-danger: #d97f6f;
  --anv-ok: #7fa86a;
  --anv-serif: "Iowan Old Style", Palatino, Georgia, serif;
  --anv-sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --anv-mono: "SF Mono", "JetBrains Mono", ui-monospace, monospace;
  --anv-radius: 10px;
  --anv-shadow: 0 18px 50px -20px rgba(0, 0, 0, .7);
}
@media (prefers-color-scheme: light) {
  .dropdown, .banner, .toast, .chip {
    --anv-bg: #fbf8f1;
    --anv-bg-deep: #f4efe4;
    --anv-bg-input: #fff;
    --anv-edge: #e0d8c5;
    --anv-edge-strong: #c9bfa2;
    --anv-ink: #2c2517;
    --anv-ink-dim: #6b6047;
    --anv-ink-faint: #786c50;
    --anv-gold: #9a7420;
    --anv-gold-bright: #7d5e14;
    --anv-gold-text: #7d5e14;
    --anv-btn-ink: #fdf9f0;
    --anv-danger: #b3402c;
    --anv-ok: #4f7a3a;
    --anv-shadow: 0 18px 50px -24px rgba(70, 55, 20, .35);
  }
}

@keyframes anv-in { from { opacity: 0; } }
@media (prefers-reduced-motion: reduce) { .dropdown, .banner, .toast, .chip { animation: none; } }

/* a11y 6d: off-screen live-region carrier — visually hidden but in the AT tree (a closed
   shadow root still reaches AT). Toast text is mirrored here so it is spoken. */
.anv-sr { position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; border: 0; overflow: hidden; clip: rect(0 0 0 0); clip-path: inset(50%); white-space: nowrap; }

.dropdown {
  position: fixed; z-index: 2147483647;
  display: block; box-sizing: border-box;
  min-width: 260px; max-width: 380px;
  background: var(--anv-bg);
  border: 1px solid var(--anv-edge);
  border-radius: var(--anv-radius);
  box-shadow: var(--anv-shadow);
  color: var(--anv-ink);
  font: 13px/1.45 var(--anv-sans);
  overflow: hidden;
  user-select: none;
  animation: anv-in .16s ease-out;
}

.hdr {
  display: flex; align-items: baseline; gap: 6px;
  padding: 8px 12px;
  background: var(--anv-bg-deep);
  border-bottom: 1px solid var(--anv-edge);
  font-family: var(--anv-serif);
  font-size: 13.5px; font-weight: 600; letter-spacing: .02em;
  color: var(--anv-ink);
  cursor: default;
}
/* The mark is inline SVG (see sigilSpan) — centered against the baseline-flex text, and the
   old text-shadow glow restated as a drop-shadow (shadows can't reach SVG strokes). */
.hdr .sigil { color: var(--anv-gold); align-self: center; display: inline-flex; }
.hdr .sigil svg { filter: drop-shadow(0 1px 12px rgba(208, 169, 74, .4)); }
.hdr .a-mark { color: var(--anv-gold); }

.list { max-height: 300px; overflow-y: auto; overscroll-behavior: contain; scrollbar-width: thin; }
.list > * + * { border-top: 1px solid var(--anv-edge); }

.row {
  display: flex; align-items: baseline; gap: 7px;
  padding: 9px 12px;
  cursor: pointer;
  white-space: nowrap; overflow: hidden;
}
.row .name { color: var(--anv-ink); overflow: hidden; text-overflow: ellipsis; min-width: 0; }
.row .user { font-family: var(--anv-mono); font-size: 12px; color: var(--anv-ink-dim); overflow: hidden; text-overflow: ellipsis; }
.row:hover, .row.active { background: var(--anv-bg-deep); box-shadow: inset 2px 0 0 var(--anv-gold); }
.row:hover .name, .row.active .name { color: var(--anv-gold-bright); }
.row.action { color: var(--anv-gold-text); font-size: 12.5px; }
.row.action:hover, .row.action.active { color: var(--anv-gold-bright); }
/* Cut N (v2 #18): the keyboard-active row mirrors hover and adds a gold ring — a focus-visible
   equivalent, since real focus stays in the page's own field and :focus can never land here. */
.row.active { outline: 2px solid var(--anv-gold); outline-offset: -2px; }

.state { padding: 14px 12px; color: var(--anv-ink-dim); font-size: 12.5px; cursor: default; }

.search { padding: 10px 12px; }
.search-input {
  width: 100%; box-sizing: border-box;
  font: 13px var(--anv-sans);
  color: var(--anv-ink);
  background: var(--anv-bg-input);
  border: 1px solid var(--anv-edge);
  border-radius: 7px;
  padding: 7px 9px;
  outline: none;
  user-select: text;
}
.search-input:focus { border-color: var(--anv-gold); }
.search-input::placeholder { color: var(--anv-ink-dim); }

.banner {
  position: fixed; top: 16px; right: 16px; z-index: 2147483647;
  display: block; box-sizing: border-box;
  width: 330px; max-width: calc(100vw - 32px);
  background: var(--anv-bg);
  border: 1px solid var(--anv-edge);
  border-radius: var(--anv-radius);
  box-shadow: var(--anv-shadow);
  color: var(--anv-ink);
  font: 13px/1.5 var(--anv-sans);
  overflow: hidden;
  animation: anv-in .16s ease-out;
}
.banner .body { padding: 12px; }
.banner .hl { font-family: var(--anv-mono); font-size: 12px; color: var(--anv-gold-bright); }
.banner .actions { display: flex; gap: 8px; margin-top: 11px; }

button.primary {
  font: 600 12.5px var(--anv-sans);
  color: var(--anv-btn-ink);
  background: linear-gradient(180deg, var(--anv-gold-bright), var(--anv-gold));
  border: 0; border-radius: 8px;
  padding: 7px 16px;
  cursor: pointer;
  box-shadow: 0 6px 18px -8px rgba(208, 169, 74, .6);
}
button.primary:hover { filter: brightness(1.06); }
button.primary:disabled { opacity: .5; cursor: default; filter: none; }
button.ghost {
  font: 12.5px var(--anv-sans);
  color: var(--anv-ink-dim);
  background: transparent;
  border: 1px solid var(--anv-edge);
  border-radius: 8px;
  padding: 7px 13px;
  cursor: pointer;
}
button.ghost:hover { color: var(--anv-ink); border-color: var(--anv-edge-strong); }
button.ghost:disabled { opacity: .5; cursor: default; }

.result { display: block; margin-top: 11px; font-size: 12.5px; }
.result.ok { color: var(--anv-ok); }
.result.err { color: var(--anv-danger); }

.toast {
  position: fixed; left: 50%; bottom: 24px; transform: translateX(-50%);
  z-index: 2147483647;
  display: flex; align-items: baseline; gap: 7px;
  box-sizing: border-box; max-width: calc(100vw - 32px);
  padding: 9px 16px;
  background: var(--anv-bg);
  border: 1px solid var(--anv-edge-strong);
  border-radius: 999px;
  box-shadow: var(--anv-shadow);
  color: var(--anv-ink);
  font: 12.5px/1.4 var(--anv-sans);
  animation: anv-in .16s ease-out;
}
.toast .sigil { color: var(--anv-gold); align-self: center; display: inline-flex; }

/* C1 chip — [S3] ONE fixed width, identical in both states (rationale on showCardChip). This
   block is inside a template literal esbuild does NOT minify: every byte ships to every page. */
.chip {
  position: fixed; z-index: 2147483647;
  box-sizing: border-box;
  width: 372px; max-width: calc(100vw - 16px);
  display: flex; align-items: center; justify-content: center; gap: 7px;
  padding: 7px 13px;
  background: var(--anv-bg);
  border: 1px solid var(--anv-edge-strong);
  border-radius: 999px;
  box-shadow: var(--anv-shadow);
  color: var(--anv-ink);
  font: 12.5px/1.4 var(--anv-sans);
  cursor: pointer;
  user-select: none;
  /* Review #5: the locked sentence is the anti-phishing payload ("…click the andvari toolbar
     icon"). With nowrap+ellipsis it truncated to "…click the andva…" under a user MINIMUM FONT
     SIZE (14-16px is common for low-vision users), deleting the instruction. It wraps instead, on
     a FIXED two-line height so the box stays byte-identical between the locked and unlocked
     states — [S3]'s hit-test indistinguishability is a property of the BOX, not the text.
     The height must actually HOLD those two lines under border-box: 2 × (12.5px × 1.4) = 35px of
     text + 14px vertical padding + 2px border = 51px (the shipped 46px spilled the sentence
     outside the pill). overflow:hidden is the [S3] backstop: whatever a user minimum font size or
     a wide font fallback does to the text, the page-observable painted region — elementFromPoint
     retargets every shadow descendant to the host — can never exceed this fixed box. */
  height: 52px;
  overflow: hidden;
  animation: anv-in .16s ease-out;
}
.chip:hover { border-color: var(--anv-gold); }
.chip .sigil { color: var(--anv-gold); display: inline-flex; flex: none; }
.chip .label { min-width: 0; overflow: hidden; }
`;

export interface DropdownState {
  kind: "matches" | "locked" | "empty";
  host: string;
  matches: MatchItem[];
  isSignup: boolean;
}

export interface DropdownHandlers {
  onPick(item: MatchItem): void;
  onStrongPassword(): void;
  onSearch(query: string): Promise<MatchItem[]>;
  onSearchPick(item: MatchItem): void;
}

let shadow: ShadowRoot | null = null;
let hostEl: HTMLElement | null = null;

/** True for the div that hosts our own closed-shadow UI. The Tier-2 shadow sweep (content.ts)
 *  probes every element with `chrome.dom.openOrClosedShadowRoot`, which PIERCES closed roots —
 *  so without this exclusion the sweep would discover our own dropdown/banner/toast root, observe
 *  it, and every UI render (an open, a row .active toggle, a live-region announce) would re-enter
 *  onMutations: a self-sustaining re-render loop in the multi-step auto-open window. The scan must
 *  treat our host as opaque, exactly as the pre-Tier-2 document observer did. */
export function isOwnUiHost(el: Element): boolean {
  return hostEl !== null && el === hostEl;
}
let dropdownEl: HTMLElement | null = null;
let anchorEl: HTMLElement | null = null;
/** C1: the ONE live chip and its anchor — a module slot, cleared like closeDropdown. [K6] it
 *  shares hostEl's single closed root: a SECOND attachShadow host would be pierced by
 *  chrome.dom.openOrClosedShadowRoot, join content.ts's `shadowRoots`, get an observer, and —
 *  since OBSERVE_OPTS filters on ["class","style","hidden"] — turn every re-anchor style write
 *  into an observed mutation (isOwnUiHost is an IDENTITY test against the one hostEl). */
let chipEl: HTMLElement | null = null;
let chipAnchor: HTMLElement | null = null;
/** [K7] one re-anchor per scroll burst — a getBoundingClientRect()+offsetWidth read per scroll
 *  event is a forced layout on every frame of a momentum scroll. */
let chipRafPending = false;
let bannerEl: HTMLElement | null = null;
let toastEl: HTMLElement | null = null;
let toastTimer = 0;
/** a11y 6d (AM-7): persistent live regions on the ui() root — a role/aria-live on the FRESH
 *  per-toast node is populated-on-mount (polite is unreliable). Two static regions so the
 *  safety-critical 2FA-clipboard fallback is assertive and routine toasts stay polite. */
let politeLive: HTMLElement | null = null;
let assertiveLive: HTMLElement | null = null;
/** Cut N (v2 #18): keyboard model — the pickable rows in render order + the roving highlight.
 *  Rebuilt on every render; -1 = no selection (a plain Enter falls through to the page). Real
 *  focus STAYS in the page's own input the dropdown anchors to — a closed shadow root cannot be
 *  referenced by aria-activedescendant from the page DOM — so arrows move this highlight and the
 *  polite live region speaks each move. */
let listRows: { el: HTMLElement; act: () => void }[] = [];
let activeIdx = -1;
/** Cut N (v2 #18): Escape returns focus to the origin field, which fires a TRUSTED focusin —
 *  content.ts would instantly reopen the dropdown it just closed. A short suppression window
 *  keeps Escape meaning closed (a fresh click/refocus after it reopens normally). */
let suppressOpenUntil = 0;

/** a11y 6d (AM-7) / Cut N: clear-then-set into a persistent off-screen region so a repeated
 *  message re-announces; assertive is reserved for the safety-critical 2FA-clipboard fallback. */
function announceLive(text: string, assertive = false): void {
  const live = assertive ? assertiveLive : politeLive;
  if (!live) return;
  live.textContent = "";
  window.setTimeout(() => {
    live.textContent = text;
  }, 50);
}

function resetRows(): void {
  listRows = [];
  activeIdx = -1;
}

/** Spoken form of a row for the live region: "name, username" or the action label. */
function rowLabel(el: HTMLElement): string {
  const name = el.querySelector(".name")?.textContent;
  const user = el.querySelector(".user")?.textContent;
  return name ? (user ? `${name}, ${user}` : name) : (el.textContent ?? "");
}

/** Move the roving highlight (wraps at both ends). The active row mirrors the hover treatment
 *  (treasury gold inset + ring) and is announced with its position. */
function setActive(i: number): void {
  const n = listRows.length;
  if (n === 0) return;
  const idx = ((i % n) + n) % n;
  const prev = listRows[activeIdx];
  if (prev) {
    prev.el.classList.remove("active");
    prev.el.setAttribute("aria-selected", "false");
  }
  activeIdx = idx;
  const cur = listRows[idx]!;
  cur.el.classList.add("active");
  cur.el.setAttribute("aria-selected", "true");
  cur.el.scrollIntoView({ block: "nearest" });
  announceLive(`${rowLabel(cur.el)}, ${idx + 1} of ${n}`);
}

// ---- C1 in-page card chip (design 2026-07-26) ----
// Declared ABOVE ui() (which forward-references it, exactly as it already forward-references
// positionDropdown/closeDropdown) so that the pinned showCardChip→closeCardChip span is the
// function body and nothing else: an indexOf-based span anchor would otherwise latch onto ui()'s
// own closeCardChip() call and invert.

/** C1: the field-anchored card affordance. It carries ZERO data — no card identity, no item name,
 *  no count, no origin, and no "recognized"/"saved for this site" framing (cards are NOT uri-bound,
 *  so the chip appears identically on a phishing checkout and on the real one; any copy implying
 *  verification is a lie the extension cannot back). Its ONLY action is "open the popup" — which is
 *  precisely why spoofing and clickjacking it buy an attacker nothing: the popup is trusted chrome
 *  the page can neither draw, read, nor script.
 *  [S3] `.chip` carries ONE fixed width, identical in both states and never intrinsically sized:
 *  document.elementFromPoint() RETARGETS to our closed-shadow host, so a page can hit-test the
 *  anchor's neighbourhood and, by scanning x-coordinates, read our width. A content-sized pill
 *  would make locked/unlocked distinguishable — and since page script can force
 *  HTMLElement.focus() (which fires TRUSTED focus events) at frame rate, that is not a one-shot
 *  disclosure but a CONTINUOUS vault-state monitor: a hostile merchant could detect the instant
 *  the user unlocks and time a fake overlay to it. The box is sized for the LONGER (locked)
 *  sentence so it never ellipses away its anti-phishing payload; the short unlocked label centres
 *  in the same box, and the max-width clamp is state-independent too. */
export function showCardChip(anchor: HTMLElement, state: { locked: boolean }, handlers: { onActivate: () => void }): void {
  const root = ui();
  chipEl?.remove(); // one live chip at a time — the module slot, cleared like closeDropdown
  chipAnchor = anchor;
  const chip = document.createElement("div");
  chip.className = "chip";
  // [K10] role=button but NEVER tabbable: real focus stays in the page's own field (the dropdown's
  // shipped discipline), so there is no tabindex and activation is mousedown + preventDefault.
  chip.setAttribute("role", "button");
  // [S6] both sentences are VERBATIM and load-bearing. The locked line mirrors the shipped
  // locked-dropdown announcement and teaches that unlocking happens in browser chrome, NEVER
  // in-page: "Unlock to fill card" teaches the opposite, and since the page controls the anchor
  // position it could butt the REAL chip flush against a page-drawn master-password box.
  // [K-label]: neither string matches detect.ts's SUBMIT_TEXT_RX — a label like "Continue with
  // saved card" would turn our own chip into a G2 submit gesture.
  const text = state.locked ? "andvari is locked — click the andvari toolbar icon" : "Fill card with andvari";
  chip.append(sigilSpan(12), span("label", text));
  // [S5] the listener binds to the CHIP inside the closed root, never to hostEl — hostEl is a
  // page-reachable node, so a host-bound listener would fire on hostEl.click(). isTrusted first,
  // matching every shipped activation path.
  const activate = (e: Event): void => {
    if (!e.isTrusted) return;
    e.preventDefault(); // keep focus in the page field — the chip must never take it
    closeCardChip(); // [K9] the surface goes before the action: the popup is about to cover the page
    handlers.onActivate();
  };
  chip.addEventListener("mousedown", activate);
  // Review #4: AT activation dispatches a CLICK, not a mousedown. Without this the chip is
  // announced as a button to a screen-reader user who then has no way to trigger it. Same in-root
  // element and same isTrusted gate, so [S5] is unchanged; the mousedown path already closed the
  // surface, making this a no-op for pointer users (closeCardChip clears chipEl).
  chip.addEventListener("click", activate);
  root.appendChild(chip);
  chipEl = chip;
  positionChip();
  announceLive(text); // focus never enters the chip — without this it is invisible to AT
}

/** Review #13: re-anchor a live chip from the content script's mutation tick — layout shifts that
 *  fire neither scroll nor resize (inline validation inserted above the field) would otherwise
 *  leave the fixed-position chip overlapping its own anchor. No-op when no chip is live. */
export function repositionCardChip(): void {
  if (chipEl) positionChip();
}

export function closeCardChip(): void {
  chipEl?.remove();
  chipEl = null;
  chipAnchor = null;
}

/** [K3]/[K4] the chip's Escape sentinel is CHIP-PRIVATE state owned by content.ts; this is its
 *  read-only liveness probe (same contract shape as dropdownWillConsumeEnter). */
export function cardChipIsOpen(): boolean {
  return chipEl !== null;
}

/** [K11] a pill, not the dropdown: anchored to the field's inline-END edge (inline-START under
 *  `direction: rtl`), clamped into the viewport with an 8 px gutter, and preferring ABOVE the
 *  field — below collides with both the browser's native autofill list and the site's own
 *  suggestion popup. Deliberately does NOT inherit positionDropdown's min-width:260px/left-clamp:
 *  the width is FIXED in CSS ([S3]) and only read back here, never derived from the anchor.
 *  [K8]: an anchor that left the DOM, or scrolled out of the viewport, ends the chip — a fixed
 *  pill floating over an off-screen field is worse than no chip at all. */
function positionChip(): void {
  if (!chipEl || !chipAnchor) return;
  if (!chipAnchor.isConnected) {
    closeCardChip();
    return;
  }
  const r = chipAnchor.getBoundingClientRect();
  if (r.bottom < 0 || r.top > window.innerHeight || r.right < 0 || r.left > window.innerWidth) {
    closeCardChip();
    return;
  }
  const w = chipEl.offsetWidth;
  const edge = getComputedStyle(chipAnchor).direction === "rtl" ? r.left : r.right - w;
  chipEl.style.left = `${Math.min(Math.max(edge, 8), Math.max(8, window.innerWidth - w - 8))}px`;
  // Review #12: the below-fallback needs its own clamp — a tall or near-bottom anchor would
  // otherwise place the chip partly off-screen, where it reads as broken rather than absent.
  const h = chipEl.offsetHeight;
  const above = r.top - 4 - h;
  const top = above > 8 ? above : r.bottom + 4;
  chipEl.style.top = `${Math.min(Math.max(top, 8), Math.max(8, window.innerHeight - h - 8))}px`;
}

function ui(): ShadowRoot {
  if (shadow) return shadow;
  hostEl = document.createElement("div");
  (document.documentElement || document.body).appendChild(hostEl);
  const root = hostEl.attachShadow({ mode: "closed" });
  const sheet = new CSSStyleSheet();
  sheet.replaceSync(UI_CSS);
  root.adoptedStyleSheets = [sheet];
  shadow = root;

  // a11y 6d (AM-7): persistent live regions, present in the AT tree before any toast text lands.
  politeLive = document.createElement("div");
  politeLive.className = "anv-sr";
  politeLive.setAttribute("aria-live", "polite");
  assertiveLive = document.createElement("div");
  assertiveLive.className = "anv-sr";
  assertiveLive.setAttribute("aria-live", "assertive");
  root.append(politeLive, assertiveLive);

  // Outside-close: composedPath() at document level is truncated at the CLOSED shadow
  // boundary, so inner nodes never appear in it — test for the HOST element (which is in
  // the retargeted path for any click inside our UI). Each surface's own anchor is exempt so
  // clicking the field again refreshes it rather than close-then-reopen.
  // [K9] that hostEl test is necessarily SHARED: closed-root truncation makes a chip click and a
  // dropdown click indistinguishable here, so this handler can only ever say "inside our UI" —
  // each surface dismisses itself from its own in-root handler.
  document.addEventListener("mousedown", (e) => {
    if ((!dropdownEl && !chipEl) || !e.isTrusted) return;
    const path = e.composedPath();
    if (hostEl && path.includes(hostEl)) return;
    if (dropdownEl && !(anchorEl && path.includes(anchorEl))) closeDropdown();
    if (chipEl && !(chipAnchor && path.includes(chipAnchor))) closeCardChip();
  });
  // Cut N (v2 #18): keyboard operability, on document-level CAPTURE so the keys are seen while
  // focus sits in the page's own input (or in our shadow search box, whose stopPropagation runs
  // later at target phase). Keys are swallowed ONLY while a surface is live — Escape while either
  // is, everything else only for the dropdown, and Enter only while a row is active, so a plain
  // Enter still submits the page's form. isTrusted-gated like
  // every activation path here (anti-spoof: a page-synthesized KeyboardEvent cannot fill).
  document.addEventListener(
    "keydown",
    (e) => {
      if ((!dropdownEl && !chipEl) || !e.isTrusted) return;
      // [K9] Escape is the ONE key both surfaces answer (hoisted so a co-live chip on another
      // anchor is not left floating when the dropdown consumes the key). Everything past the
      // chip-only early return reads or writes DROPDOWN state — decisively closeDropdown() and
      // suppressOpenUntil, which [K4] forbids the chip from touching: an Esc'd chip must never
      // gag a real login dropdown for 400 ms.
      if (e.key === "Escape") {
        closeCardChip();
        // Review #2: a chip-only Escape must NOT be consumed. The chip renders on every card-field
        // focus, so swallowing the key would eat the first Escape on any checkout whose card form
        // lives in a modal/drawer — the page never sees it and the modal never closes. Only the
        // DROPDOWN (a focus-trapping surface with its own row state) earns preventDefault.
        if (!dropdownEl) return;
        e.preventDefault();
        e.stopPropagation();
        const origin = anchorEl;
        closeDropdown();
        // Return focus to the origin field; the suppression window keeps the trusted focusin
        // this fires (content.ts focusin → openDropdown) from instantly reopening.
        suppressOpenUntil = Date.now() + 400;
        if (origin?.isConnected) origin.focus();
        return;
      }
      if (!dropdownEl) return; // a lone chip owns no other key — never trap the page's keys
      if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        if (listRows.length === 0) return;
        e.preventDefault();
        e.stopPropagation();
        const down = e.key === "ArrowDown";
        setActive(activeIdx < 0 ? (down ? 0 : listRows.length - 1) : activeIdx + (down ? 1 : -1));
      } else if (e.key === "Enter") {
        if (activeIdx < 0) return; // no selection — the page's own submit proceeds untouched
        e.preventDefault();
        e.stopPropagation();
        listRows[activeIdx]?.act();
      } else if (e.key === "Tab") {
        closeDropdown(); // never trap — the Tab itself proceeds (a login-field target reopens naturally)
      }
    },
    true,
  );
  const reanchor = (): void => {
    if (dropdownEl) positionDropdown();
    // [K7] the chip joins THIS handler (never its own listener pair), coalesced into ONE rAF per
    // burst. Without a re-anchor a position:fixed chip stays pinned to the viewport while the
    // field scrolls away — worse than not showing it at all.
    if (chipEl && !chipRafPending) {
      chipRafPending = true;
      requestAnimationFrame(() => {
        chipRafPending = false;
        if (chipEl) positionChip();
      });
    }
  };
  document.addEventListener("scroll", reanchor, { capture: true, passive: true });
  window.addEventListener("resize", reanchor, { passive: true });
  return root;
}

function span(className: string, text: string): HTMLSpanElement {
  const s = document.createElement("span");
  s.className = className;
  s.textContent = text;
  return s;
}

/** The ᛅ brand mark as a span-wrapped inline SVG (web Sigil.tsx geometry, verbatim): the raw
 *  runic codepoint renders as tofu wherever no installed font covers the Runic block — fatal
 *  for a header whose whole job is anti-spoof attribution on arbitrary sites. The stroke
 *  inherits currentColor from the .sigil gold. */
function sigilSpan(size: number): HTMLSpanElement {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("aria-hidden", "true");
  for (const d of ["M12 3v18", "M5.5 8.5l13 6"]) { // a stave crossed by one falling stroke (long-branch ár)
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  const s = span("sigil", "");
  s.append(svg);
  return s;
}

function brandHeader(): HTMLElement {
  const hdr = document.createElement("div");
  hdr.className = "hdr";
  const brand = document.createElement("span");
  brand.append(span("a-mark", "and"), document.createTextNode("vari"));
  hdr.append(sigilSpan(14), brand);
  return hdr;
}

function stateCard(text: string): HTMLElement {
  const d = document.createElement("div");
  d.className = "state";
  d.textContent = text;
  // Cut N review: a state message is NOT a listbox option — hide it from AT so it never appears
  // as an invalid listbox child. Its content is spoken via the live region on open / search-run.
  d.setAttribute("aria-hidden", "true");
  return d;
}

/** Cut N (v2 #18): every pickable row joins the keyboard model — listbox option semantics plus
 *  registration for the arrow-key highlight (keyboard Enter runs the same handler as mousedown). */
function registerRow(row: HTMLElement, act: () => void): void {
  row.setAttribute("role", "option");
  row.setAttribute("aria-selected", "false");
  listRows.push({ el: row, act });
}

function matchRow(m: MatchItem, pick: () => void): HTMLElement {
  const row = document.createElement("div");
  row.className = "row";
  row.appendChild(span("name", m.name));
  if (m.username) row.appendChild(span("user", m.username));
  row.addEventListener("mousedown", (e) => {
    if (!e.isTrusted) return;
    e.preventDefault(); // keep focus on the page field so it stays fillable
    pick();
  });
  registerRow(row, pick);
  return row;
}

function actionRow(label: string, act: () => void): HTMLElement {
  const row = document.createElement("div");
  row.className = "row action";
  row.textContent = label;
  row.addEventListener("mousedown", (e) => {
    if (!e.isTrusted) return;
    e.preventDefault();
    act();
  });
  registerRow(row, act);
  return row;
}

/** Placed via CSSOM (not CSP-gated); position:fixed → viewport coords, so scroll/resize
 *  re-anchoring reads the anchor's LIVE rect each time. Closes if the anchor left the DOM. */
function positionDropdown(): void {
  if (!dropdownEl || !anchorEl) return;
  if (!anchorEl.isConnected) {
    closeDropdown();
    return;
  }
  const r = anchorEl.getBoundingClientRect();
  const w = Math.min(Math.max(r.width, 260), 380);
  const left = Math.min(Math.max(r.left, 8), Math.max(8, window.innerWidth - w - 8));
  dropdownEl.style.width = `${w}px`;
  dropdownEl.style.left = `${left}px`;
  const h = dropdownEl.offsetHeight;
  const below = r.bottom + 4;
  const top = below + h > window.innerHeight - 8 && r.top - 4 - h > 8 ? r.top - 4 - h : below;
  dropdownEl.style.top = `${top}px`;
}

function renderMain(body: HTMLElement, state: DropdownState, h: DropdownHandlers): void {
  body.textContent = "";
  resetRows();
  // Cut N review: only mark the container a listbox when it actually holds option rows — the
  // locked state is a lone (aria-hidden) message with no options, so it stays role-less there.
  body.removeAttribute("role");
  body.removeAttribute("aria-label");
  if (state.kind === "locked") {
    body.appendChild(stateCard("Locked — click the andvari toolbar icon to unlock"));
    return;
  }
  // From here on the container always carries at least the "Search all logins…" option.
  body.setAttribute("role", "listbox");
  body.setAttribute("aria-label", `andvari — saved logins for ${state.host}`);
  if (state.kind === "empty") body.appendChild(stateCard(`No saved login for ${state.host}`));
  else for (const m of state.matches) body.appendChild(matchRow(m, () => h.onPick(m)));
  if (state.isSignup) body.appendChild(actionRow("Use a strong password", () => h.onStrongPassword()));
  body.appendChild(actionRow("Search all logins…", () => renderSearch(body, h)));
}

function renderSearch(body: HTMLElement, h: DropdownHandlers): void {
  body.textContent = "";
  resetRows();
  // Cut N (v2 #18): in search mode the listbox is the RESULTS container (the search box is not
  // an option) — move the role off the body it sat on in renderMain.
  body.removeAttribute("role");
  body.removeAttribute("aria-label");
  const wrap = document.createElement("div");
  wrap.className = "search";
  const inp = document.createElement("input");
  inp.className = "search-input";
  inp.type = "text";
  inp.placeholder = "Search all logins…";
  inp.setAttribute("aria-label", "Search all logins"); // a11y 1b: placeholder is not a name
  wrap.appendChild(inp);
  const results = document.createElement("div");
  results.setAttribute("role", "listbox");
  results.setAttribute("aria-label", "andvari — matching logins");
  body.append(wrap, results);

  // Key/input events are composed — without this, page-level listeners see every
  // keystroke typed into OUR search box. (Capture-phase snooping remains possible;
  // our own Escape-close is capture too, so it still runs.)
  for (const type of ["keydown", "keyup", "keypress", "input"] as const) {
    inp.addEventListener(type, (e) => e.stopPropagation());
  }

  let seq = 0;
  const run = async (query: string): Promise<void> => {
    const mine = ++seq;
    const items = await h.onSearch(query);
    if (mine !== seq || !dropdownEl) return; // stale response, or closed while in flight
    results.textContent = "";
    resetRows(); // Cut N: the keyboard model tracks the freshly rendered result set
    if (items.length === 0) results.appendChild(stateCard("No logins found"));
    else for (const m of items) results.appendChild(matchRow(m, () => h.onSearchPick(m)));
    // Cut N (v2 #18): result counts are invisible to a screen reader otherwise (focus stays in
    // the search box and options never take focus).
    announceLive(items.length === 0 ? "No logins found" : `${items.length} login${items.length === 1 ? "" : "s"} found, arrows to browse`);
    positionDropdown(); // result list changes our height
  };
  inp.addEventListener("input", () => void run(inp.value));
  void run("");
  inp.focus();
  positionDropdown();
}

/** Cut N review: content.ts's Enter-capture hook (a document-capture keydown registered at load,
 *  BEFORE this file's lazy one) would snapshot the focused field as a "typed credential" on the
 *  same Enter that we consume as a row pick — offering to overwrite the stored password with the
 *  junk partial. content.ts gates its captureNow on this so a dropdown-pick Enter is never a
 *  credential capture. Registration order guarantees the flag is still accurate when it reads it. */
export function dropdownWillConsumeEnter(): boolean {
  return dropdownEl !== null && activeIdx >= 0;
}

export function openDropdown(anchor: HTMLElement, state: DropdownState, handlers: DropdownHandlers): void {
  if (Date.now() < suppressOpenUntil) return; // Cut N: just Escape-closed — the refocus must not reopen
  const root = ui();
  closeDropdown();
  anchorEl = anchor;
  const box = document.createElement("div");
  box.className = "dropdown";
  box.appendChild(brandHeader());
  const body = document.createElement("div");
  body.className = "list";
  box.appendChild(body);
  renderMain(body, state, handlers);
  root.appendChild(box);
  dropdownEl = box;
  positionDropdown();
  // Cut N (v2 #18): announce availability on open — focus never enters the dropdown, so without
  // this a screen-reader user cannot know the listbox exists at all.
  const n = state.matches.length;
  announceLive(
    state.kind === "locked"
      ? "andvari is locked — click the andvari toolbar icon to unlock"
      : state.kind === "empty"
        ? `No saved login for ${state.host}, arrows to browse`
        : `${n} login${n === 1 ? "" : "s"} available, arrows to browse`,
  );
}

export function closeDropdown(): void {
  dropdownEl?.remove();
  dropdownEl = null;
  anchorEl = null;
  resetRows(); // Cut N: no highlight survives a close — Enter must never fire on a gone row
}

function bannerShell(): { bar: HTMLElement; body: HTMLElement } {
  const root = ui();
  bannerEl?.remove(); // one banner at a time — newest wins
  const bar = document.createElement("div");
  bar.className = "banner";
  bar.appendChild(brandHeader());
  const body = document.createElement("div");
  body.className = "body";
  bar.appendChild(body);
  root.appendChild(bar);
  bannerEl = bar;
  return { bar, body };
}

function closeBanner(which: HTMLElement): void {
  which.remove();
  if (bannerEl === which) bannerEl = null;
}

/** Save/update offer. Never shows the password itself — only host/name (ZK: the secret stays
 *  in the SW's pending slot). onSave resolves to the honest result line to display. */
export function showSaveBanner(
  pending: PendingSave,
  onSave: () => Promise<{ ok: boolean; text: string }>,
  onDismiss: () => void,
): void {
  const { bar, body } = bannerShell();
  const msg = document.createElement("div");
  msg.className = "msg";
  if (pending.updatesItemId) {
    // Show the existing item's username too — auto-saved items are named after the host, so the
    // name alone can't distinguish a password change from a wrong-account merge (2b guard).
    msg.append("Update the password for ", span("hl", pending.updatesItemName ?? "this login"));
    if (pending.updatesItemUsername) msg.append(" (", span("hl", pending.updatesItemUsername), ")");
    msg.append("?");
  } else msg.append("Save this login for ", span("hl", pending.host), " to andvari?");
  const actions = document.createElement("div");
  actions.className = "actions";
  const primary = document.createElement("button");
  primary.className = "primary";
  primary.textContent = pending.updatesItemId ? "Update" : "Save";
  const ghost = document.createElement("button");
  ghost.className = "ghost";
  ghost.textContent = "Not now";
  actions.append(primary, ghost);
  body.append(msg, actions);
  // Cut N (v2 #18): banners appear without any focus change and auto-dismiss — announce the
  // offer (and, below, its verdict) or a screen-reader user never knows it existed.
  announceLive(`andvari: ${msg.textContent ?? ""}`);

  const idle = window.setTimeout(() => closeBanner(bar), 30_000);
  primary.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    window.clearTimeout(idle);
    primary.disabled = true;
    ghost.disabled = true;
    void onSave().then((r) => {
      actions.remove();
      body.appendChild(span(r.ok ? "result ok" : "result err", r.text));
      announceLive(r.text); // Cut N: the verdict is spoken, not just painted (the banner auto-closes)
      window.setTimeout(() => closeBanner(bar), r.ok ? 4000 : 8000);
    });
  });
  ghost.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    window.clearTimeout(idle);
    closeBanner(bar);
    onDismiss();
  });
}

/** G2 save-card offer (design 2026-07-23 §G2). Shows ONLY the masked `cardSubtitle` ("Visa
 *  ••4242") — never the PAN/expiry/CVV (the raw values stay in the SW's pendingCardSave slot).
 *  Mirrors showSaveBanner's structure; onSave resolves to the honest result line. */
export function showCardSaveBanner(
  pending: PendingCardSave,
  onSave: () => Promise<{ ok: boolean; text: string }>,
  onDismiss: () => void,
): void {
  const { bar, body } = bannerShell();
  const msg = document.createElement("div");
  msg.className = "msg";
  if (pending.updatesItemId) {
    msg.append("Update the card ", span("hl", pending.updatesItemName ?? pending.cardSubtitle));
    msg.append(" (", span("hl", pending.cardSubtitle), ")?");
  } else msg.append("Save this card ", span("hl", pending.cardSubtitle), " to andvari?");
  const actions = document.createElement("div");
  actions.className = "actions";
  const primary = document.createElement("button");
  primary.className = "primary";
  primary.textContent = pending.updatesItemId ? "Update" : "Save";
  const ghost = document.createElement("button");
  ghost.className = "ghost";
  ghost.textContent = "Not now";
  actions.append(primary, ghost);
  body.append(msg, actions);
  announceLive(`andvari: ${msg.textContent ?? ""}`);

  const idle = window.setTimeout(() => closeBanner(bar), 30_000);
  primary.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    window.clearTimeout(idle);
    primary.disabled = true;
    ghost.disabled = true;
    void onSave().then((r) => {
      actions.remove();
      body.appendChild(span(r.ok ? "result ok" : "result err", r.text));
      announceLive(r.text);
      window.setTimeout(() => closeBanner(bar), r.ok ? 4000 : 8000);
    });
  });
  ghost.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    window.clearTimeout(idle);
    closeBanner(bar);
    onDismiss();
  });
}

/** Post-fill URI backfill offer for an out-of-match (search-all) fill. */
export function showLinkOffer(itemName: string, host: string, onLink: () => Promise<boolean>): void {
  const { bar, body } = bannerShell();
  const msg = document.createElement("div");
  msg.className = "msg";
  msg.append("Link ", span("hl", itemName), " to ", span("hl", host), "?");
  const actions = document.createElement("div");
  actions.className = "actions";
  const primary = document.createElement("button");
  primary.className = "primary";
  primary.textContent = "Link";
  const ghost = document.createElement("button");
  ghost.className = "ghost";
  ghost.textContent = "No";
  actions.append(primary, ghost);
  body.append(msg, actions);
  announceLive(`andvari: ${msg.textContent ?? ""}`); // Cut N (v2 #18): see showSaveBanner

  const idle = window.setTimeout(() => closeBanner(bar), 20_000);
  primary.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    window.clearTimeout(idle);
    primary.disabled = true;
    ghost.disabled = true;
    void onLink().then((ok) => {
      actions.remove();
      const text = ok ? "Linked." : "Could not link.";
      body.appendChild(span(ok ? "result ok" : "result err", text));
      announceLive(text); // Cut N: spoken verdict
      window.setTimeout(() => closeBanner(bar), ok ? 3000 : 6000);
    });
  });
  ghost.addEventListener("click", (e) => {
    if (!e.isTrusted) return;
    window.clearTimeout(idle);
    closeBanner(bar);
  });
}

export function showToast(text: string, assertive = false): void {
  const root = ui();
  toastEl?.remove();
  const t = document.createElement("div");
  t.className = "toast";
  t.append(sigilSpan(12), document.createTextNode(text));
  root.appendChild(t);
  toastEl = t;
  // a11y 6d (AM-7): mirror the text into the PERSISTENT region so it is spoken (the fresh toast
  // node above is populated-on-mount → polite is unreliable). `assertive` is the safety-critical
  // 2FA-clipboard fallback, where the code is shown only in this 5 s toast.
  announceLive(text, assertive);
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    t.remove();
    if (toastEl === t) toastEl = null;
  }, 5000);
}
