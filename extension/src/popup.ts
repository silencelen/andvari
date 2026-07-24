/**
 * Popup — the themed vault surface. Locked: email + master password → SW `unlock` (the ~6 s
 * Argon2id shows the animated "Unsealing…" state). Unlocked: current-site matches + search-all
 * rows — a row click fills via the SW's one-shot grant (`fillFromPopup`); hover copy buttons
 * (password via explicit `reveal`, written straight to the clipboard, never rendered); live
 * TOTP chips re-polled each second. The SW holds all key material — this page only messages it.
 * External module only (MV3 CSP forbids inline); vault strings land via textContent only.
 */
import type { CardFieldKind } from "./detect";
import { bioUnlockErrorCopy, CARD_COPY_FAILED, CLIPBOARD_FAILED, enrollBioErrorCopy, enrollErrorCopy, fillErrorCopy, lockNoticeCopy, pinUnlockErrorCopy, revealErrorCopy, UNREACHABLE, unlockErrorCopy } from "./errors";
import { send, type CardItem, type MatchItem, type Req, type Res } from "./messages";
import { getServerUrl, middleTruncateOrigin, originMatchPattern } from "./serverurl";
import { BROAD_ORIGIN_PATTERN, shouldRouteToOptions } from "./grantflow";
import { displaySite, safeSiteUrl } from "./siteurl";

const FLASH_MS = 1200;
const TOTP_PERIOD_S = 30; // ring denominator (web Vault parity)

const el = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(`#${id} missing`);
  return e as T;
};

/** send() that survives a mid-flight SW restart ("receiving end does not exist") as undefined. */
async function ask<T extends Req["type"]>(req: Extract<Req, { type: T }>): Promise<Res<T> | undefined> {
  try {
    return await send(req);
  } catch {
    return undefined;
  }
}

let tabHost: string | null = null;
/** S3: whether the active tab has a same-origin card form we may Fill into, and to which origin.
 *  Fetched once per unlocked render — the active tab can't change while the popup is open.
 *  `crossOriginFormsOnly` (Tier 2 §6 [U21]) drives the PSP explainer; mutually exclusive with
 *  `fillable` (SW-computed), so the explainer state can never also render a Fill button. */
let cardFill: { fillable: boolean; origin: string | null; crossOriginFormsOnly: boolean } = { fillable: false, origin: null, crossOriginFormsOnly: false };
let totpTimer: number | undefined;
let searchTimer: number | undefined;
let searchSeq = 0;
/** The ONE pending clipboard-clear timer (AM2): every copy funnels through toClipboard(),
 *  and a newer copy replaces the pending clear — so an earlier timer can never wipe a
 *  later secret mid-window. */
let clipClearTimer: number | undefined;
/** Monotonic id source for per-chip TOTP "seconds left" descriptions (a11y 5b). */
let totpSeq = 0;
/** Quick-unlock (spec 01 §8.4): when the user picks "use your master password instead" on the armed
 *  locked screen, show the full form instead of the PIN field for the rest of this popup opening. */
let pinFallback = false;
/** TOTP challenge (0.16.3): consecutive wrong codes this challenge. After 3 we abandon it (clear the
 *  SW keys) and drop to the full form — self-healing the edge where the password changed server-side
 *  mid-window (every fresh code would 401 forever otherwise). */
let totpBadCount = 0;
/** 0.17.0: whether this platform reports a user-verifying platform authenticator (Windows Hello /
 *  Touch ID / device PIN). Probed once per popup open; gates the biometric ENROLL shortcuts only. The
 *  locked bio view is driven by the SW's committed `kind`, not this — a device that enrolled bio then
 *  lost its authenticator still shows the button and degrades to the master-password fallback. */
let bioCapable = false;

/** Cosmetic platform label for the biometric buttons — the ceremony itself works regardless. */
function bioLabel(): string {
  const ua = navigator.userAgent;
  if (/Mac|iPhone|iPad|iPod/.test(ua)) return "Touch ID";
  if (/Windows/.test(ua)) return "Windows Hello";
  return "your device";
}

async function probeBioCapable(): Promise<void> {
  try {
    bioCapable =
      typeof PublicKeyCredential !== "undefined" &&
      typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function" &&
      (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch {
    bioCapable = false;
  }
  const label = bioLabel();
  el("qu-bio-unlock").textContent = label === "your device" ? "Unlock with your device" : `Unlock with ${label}`;
}

function showMsg(kind: "err" | "info", text: string): void {
  const m = el("msg");
  m.className = `msg ${kind}`;
  // a11y 2a — ORDER MATTERS (the static-read caveat): the region must be in the a11y tree
  // (unhidden) with its live role set BEFORE its text mutates, or the first message is dropped.
  // unhide → role → text. Errors are assertive (role=alert), info is polite (role=status).
  m.hidden = false;
  m.setAttribute("role", kind === "err" ? "alert" : "status");
  m.textContent = text;
}

function clearMsg(): void {
  const m = el("msg");
  m.textContent = "";
  m.hidden = true;
}

function setConn(ok: boolean): void {
  const dot = el("conn");
  dot.className = `dot ${ok ? "on" : "off"}`;
  dot.title = ok ? "server reachable" : "server unreachable";
  el("conn-status").textContent = ok ? "Server reachable" : "Server unreachable"; // a11y 5a twin
}

/** a11y 2d — one polite announcer for copy confirmations. The visible feedback (button ✓, TOTP
 *  "copied", generator flash) never becomes an accessible name (the buttons keep a stable
 *  aria-label), so the confirmation is spoken from here. Clear-then-set so repeats re-announce. */
function announce(text: string): void {
  const live = el("copy-live");
  live.textContent = "";
  window.setTimeout(() => {
    live.textContent = text;
  }, 50);
}

function showView(unlocked: boolean): void {
  // The detail view is a transient overlay of the unlocked list — only openDetail() shows it,
  // so any list/lock transition drops it (and any revealed password rendered inside it).
  el("detail").hidden = true;
  el("detail-body").replaceChildren();
  el("totp-challenge").hidden = true; // reset the 0.16.3 code view; refresh() re-shows it iff totpPending
  setTotpKeepalive(false); // stop the challenge SW-keepalive on any view change (refresh re-arms it if needed)
  el("locked").hidden = unlocked;
  el("unlocked").hidden = !unlocked;
  el("lock").hidden = !unlocked;
  el("sign-out").hidden = !unlocked; // spec 01 §8.4 — full sign-out, distinct from Lock
  el("count").hidden = !unlocked;
  if (!unlocked) {
    stopTotp();
    el("must-change").hidden = true; // unlocked-session chrome — refresh() re-derives it
    el("qu-offer").hidden = true; // quick-unlock offer/enroll are unlocked-only chrome (spec 01 §8.4)
    el("qu-enroll").hidden = true;
    el("qu-settings").hidden = true;
    // Drop rendered vault rows/codes on lock — nothing lingers in the DOM.
    el("site-list").replaceChildren();
    el("all-list").replaceChildren();
    renderCards([]); // empties AND hides the Cards group
    el<HTMLInputElement>("search").value = "";
    el("gen-pass").textContent = "";
    el("generator").hidden = true;
    el("gen-toggle").classList.remove("on");
    el("gen-toggle").setAttribute("aria-expanded", "false"); // a11y 5c: collapsed on lock
  }
}

async function refresh(): Promise<void> {
  const s = await ask({ type: "status" });
  if (!s) {
    showView(false);
    showMsg("err", "Extension backend not responding — try reloading the extension.");
    return;
  }
  showView(s.unlocked);
  renderQuickUnlock(s.quickUnlock, s.unlocked); // spec 01 §8.4 — PIN entry (locked) / offer+settings (unlocked)
  // E1-6: rescue-issued temporary password — a persistent, non-dismissable strip for the
  // whole unlocked session; it clears only via a fresh unlock whose response drops the flag.
  el("must-change").hidden = !(s.unlocked && s.mustChangePassword);
  if (s.unlocked) {
    await loadUnlocked();
    // a11y 2c: on a recovery-password session, move focus onto the critical notice so a screen
    // reader announces it (loadUnlocked otherwise leaves focus on #search). It IS a button — the
    // last focus wins, so this beats the focus race rather than relying on an appears-populated
    // role=alert. No-op if the strip is hidden (e.g. a mid-load relock).
    if (s.mustChangePassword) el("must-change").focus();
    return;
  }
  // 0.16.3: a live TOTP challenge (popup reopened mid-code-entry — the common case, since copying a
  // code from an authenticator app closed the popup) OUTRANKS both the armed-PIN view and the master
  // form. renderQuickUnlock already ran; enterTotpChallenge overrides those two hidden.
  if (s.totpPending) {
    enterTotpChallenge(true);
    return;
  }
  // F26 (E1-7): say WHY the vault is locked — recorded for idle autolock only (manual lock
  // renders no reason line, web useAutoLock parity); verbatim web copy via lockNoticeCopy.
  if (s.lockNotice) showMsg("info", lockNoticeCopy(s.lockNotice.seconds));
  // Armed quick unlock (and not falling back) → the PIN field (or the bio button) owns the focus; else
  // the master form.
  if (s.quickUnlock.armed && !pinFallback) {
    el(s.quickUnlock.kind === "biometric" ? "qu-bio-unlock" : "qu-pin").focus();
    return;
  }
  const email = el<HTMLInputElement>("email");
  if (!email.value) {
    const remembered = s.email ?? (await rememberedEmail());
    if (remembered) email.value = remembered;
  }
  (email.value ? el("password") : email).focus();
}

/** Render the self-update banner from the SW's SW-validated verdict. `latest` is non-null only
 *  when a strictly-newer build is published, so we show the banner iff it is present. The SW
 *  answers whether locked or not, so the banner surfaces on the unlock screen too. */
async function renderUpdate(): Promise<void> {
  const banner = el("update");
  const quiet = el("update-quiet");
  const link = el<HTMLAnchorElement>("update-link");
  const r = await ask({ type: "updateStatus" });
  if (!r || !r.latest) {
    banner.hidden = true;
    // M-D4b (compliance UQUIET-read): when there is no offer, the SW's fail-closed-QUIET
    // update-channel reason (unverified/stale/…) shows as ONE muted, non-modal line —
    // distinct from the gold "update available" banner AND from silence. A sig-stripping
    // server must not be able to train the household on scary noise, so never a banner/nag.
    const reason = r?.quietReason ?? null;
    quiet.textContent = reason ? updateQuietCopy(reason) : "";
    quiet.hidden = !reason;
    return;
  }
  quiet.hidden = true; // an offer supersedes the quiet note (mutually exclusive)
  el("update-text").textContent = `Update available — andvari ${r.latest}. `;
  // Firefox gets the Firefox zip; everything else (Chrome/Edge/Brave) the Chrome zip. Fall back
  // to whichever URL exists so a single-target publish still links somewhere real.
  const isFirefox = /firefox/i.test(navigator.userAgent);
  const url = (isFirefox ? r.firefoxUrl : r.chromeUrl) ?? r.chromeUrl ?? r.firefoxUrl;
  if (url) {
    link.href = url;
    link.textContent = "Download & reload";
    link.hidden = false;
  } else {
    link.hidden = true; // a version with no usable link: still tell them one exists
  }
  banner.hidden = false;
}

/** M-D4b muted update-channel copy (surface owns the sentences; the seam carries only a reason
 *  code). Mirrors the desktop's two quiet Settings lines (DesktopState UPDATE_*_NOTICE). */
function updateQuietCopy(reason: string): string {
  return reason === "stale"
    ? "Updates: the server’s update listing hasn’t been re-signed in a while — if you’re expecting an update, mention it to your admin."
    : "Updates: the server’s update listing couldn’t be verified, so no update will be offered from it. Your vault and sync are unaffected.";
}

/** Email is deliberately non-secret (remembered for convenience) — the ZK line is the master
 *  password and keys, which never touch chrome.storage.local. */
async function rememberedEmail(): Promise<string | null> {
  try {
    const st = (await chrome.storage.local.get("lastEmail")) as Record<string, unknown>;
    const v = st["lastEmail"];
    return typeof v === "string" && v ? v : null;
  } catch {
    return null;
  }
}

function relocked(): void {
  pinFallback = false; // a fresh relock re-offers the quick-unlock PIN if the SW armed one
  showView(false);
  // a11y 4a: a mid-session relock hid the unlocked view under focus — move focus to a real
  // element (#email) instead of letting it fall to <body>. showMsg is a live region (2a) so
  // the reason is announced.
  el("email").focus();
  showMsg("info", "Session locked — unlock to continue.");
  // Re-query status so an armed quick-unlock (an idle autolock ARMS it — spec 01 §8.4) shows its PIN
  // field; refresh() refines the focus + lock-notice (an idle notice supersedes the message above).
  void refresh();
}

async function loadUnlocked(): Promise<void> {
  const host = await activeTabHost();
  tabHost = host;
  const siteLabel = el("site-label");
  const siteList = el("site-list");
  if (host) {
    siteLabel.hidden = false;
    siteList.hidden = false;
    siteLabel.textContent = `This site — ${host}`;
    const r = await ask({ type: "matches", host });
    if (!r || r.locked) return relocked();
    renderList(siteList, r.matches, `No login saved for ${host}`, true);
  } else {
    // No usable page URL (chrome://, new tab, detached popup) — nothing to match against.
    siteLabel.hidden = true;
    siteList.hidden = true;
  }
  const all = await ask({ type: "allItems" });
  if (!all || all.locked) return relocked();
  const n = all.items.length;
  el("count").textContent = `${n} login${n === 1 ? "" : "s"} in the hoard`;
  renderList(el("all-list"), all.items, "The hoard is empty");
  const cards = await ask({ type: "cardItems" });
  if (!cards || cards.locked) return relocked();
  // S3: may we offer in-page card fill for this tab? (popup-only query; the SW derives the
  // origin). The SW answers off its registry IMMEDIATELY and fires a rescan broadcast; the one
  // delayed re-query below is what picks up a form the rescan just surfaced (CSS-revealed step,
  // bfcache return) — freshness without an inline wait on the popup's critical path.
  const offer = await ask({ type: "cardFillOffers" });
  cardFill = offer
    ? { fillable: offer.fillable, origin: offer.origin, crossOriginFormsOnly: offer.crossOriginFormsOnly === true }
    : { fillable: false, origin: null, crossOriginFormsOnly: false };
  renderCards(cards.items);
  window.setTimeout(() => {
    void (async () => {
      const o2 = await ask({ type: "cardFillOffers" });
      // [U21] pinned: the re-query diffs crossOriginFormsOnly too — a late PSP-frame report
      // must surface the explainer, not just a late same-origin form the Fill button.
      if (o2 && (o2.fillable !== cardFill.fillable || o2.origin !== cardFill.origin || (o2.crossOriginFormsOnly === true) !== cardFill.crossOriginFormsOnly)) {
        cardFill = { fillable: o2.fillable, origin: o2.origin, crossOriginFormsOnly: o2.crossOriginFormsOnly === true };
        const c2 = await ask({ type: "cardItems" });
        if (c2 && !c2.locked) renderCards(c2.items);
      }
    })();
  }, 350);
  startTotp();
  el<HTMLInputElement>("search").focus();
}

/** activeTab (granted by opening the popup) exposes the page URL on http/https only. */
async function activeTabHost(): Promise<string | null> {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const u = new URL(tabs[0]?.url ?? "");
    return (u.protocol === "https:" || u.protocol === "http:") && u.hostname ? u.hostname : null;
  } catch {
    return null;
  }
}

/** F80 port (web Sigil.tsx, geometry verbatim): the ᛅ/ᛝ marks as inline SVG — the runic
 *  codepoints render as tofu wherever no installed font covers the Runic block, and the CSP
 *  posture (self-contained, nothing loads over the network) bars shipping one. Strokes inherit
 *  currentColor, so the existing .sigil/.glyph color tokens keep working in both themes.
 *  Duplicated from web because no build path from extension/ to web/src exists (the errors.ts
 *  UNREACHABLE idiom); popup.html carries the same geometry statically. */
const SVG_NS = "http://www.w3.org/2000/svg";
function sigilSvg(mark: "brand" | "empty", size: number): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  if (mark === "empty") svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  // ᛅ (long-branch ár) = a stave crossed by one falling stroke; ᛝ (Ingwaz) = its enclosing diamond.
  for (const d of mark === "brand" ? ["M12 3v18", "M5.5 8.5l13 6"] : ["M12 4.5 19 12l-7 7.5L5 12Z"]) {
    const p = document.createElementNS(SVG_NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return svg;
}

function renderList(list: HTMLElement, items: MatchItem[], emptyText: string, slim = false): void {
  list.replaceChildren();
  if (items.length === 0) {
    const empty = document.createElement("div");
    empty.className = slim ? "empty slim" : "empty";
    if (!slim) {
      const sigil = document.createElement("div");
      sigil.className = "sigil";
      sigil.append(sigilSvg("empty", 30)); // ᛝ, the empty-hoard mark (web Vault parity) — was a tofu-prone ᛅ
      empty.append(sigil);
    }
    empty.append(emptyText);
    list.append(empty);
    return;
  }
  for (const it of items) list.append(row(it));
}

/** Row = open the item's detail on click (nested copy/TOTP buttons stop propagation, so the
 *  row can't be a <button> itself — divs with button semantics instead). Fill moved INTO the
 *  detail as an explicit action: a blind row-click fill fails on every non-fillable tab. */
function row(it: MatchItem): HTMLElement {
  const r = document.createElement("div");
  r.className = "item";
  r.setAttribute("role", "button");
  r.tabIndex = 0;
  r.title = "View details";

  const glyph = document.createElement("span");
  glyph.className = "glyph";
  const initial = it.name.trim().charAt(0).toUpperCase();
  if (initial) glyph.textContent = initial;
  else glyph.append(sigilSvg("brand", 15)); // a nameless login falls back to the mark, not a tofu rune

  const body = document.createElement("div");
  body.className = "body";
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = it.name;
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = it.username ?? "no username";
  body.append(name, sub);

  r.append(glyph, body);
  if (it.hasTotp) r.append(totpChip(it.itemId));

  const acts = document.createElement("span");
  acts.className = "acts";
  if (it.username) acts.append(actBtn("user", "Copy username", (btn) => void copyUsername(it, btn)));
  acts.append(actBtn("pass", "Copy password", (btn) => void copyPassword(it, btn)));
  r.append(acts);

  const open = () => openDetail(it);
  r.addEventListener("click", open);
  r.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      open();
    }
  });
  return r;
}

// ---- item detail: the item's data + a site link, instead of a blind active-tab fill ----

/** Show the detail overlay for [it]. openDetail is the ONLY caller that reveals #detail;
 *  showView() hides it on every list/lock transition (and clears any revealed password). */
function openDetail(it: MatchItem): void {
  renderDetail(it);
  clearMsg();
  el("unlocked").hidden = true;
  el("detail").hidden = false;
  el<HTMLButtonElement>("detail-back").focus();
}

function closeDetail(): void {
  el("detail").hidden = true;
  el("detail-body").replaceChildren(); // drop any revealed password from the DOM
  el("unlocked").hidden = false;
  el<HTMLInputElement>("search").focus(); // return focus to the list (hiding #detail-back would strand it on <body>)
}

/** One labelled detail row: a value cell + a right-aligned actions cell. */
function detailField(label: string): { field: HTMLElement; value: HTMLElement; acts: HTMLElement } {
  const field = document.createElement("div");
  field.className = "detail-field";
  const lab = document.createElement("div");
  lab.className = "detail-label";
  lab.textContent = label;
  const rowEl = document.createElement("div");
  rowEl.className = "detail-row";
  const value = document.createElement("span");
  value.className = "detail-value";
  const acts = document.createElement("span");
  acts.className = "acts";
  rowEl.append(value, acts);
  field.append(lab, rowEl);
  return { field, value, acts };
}

/** Reveal toggles the password INTO the DOM on an explicit click (cleared on Back/lock);
 *  copy keeps sending it straight to the clipboard. Same explicit-reveal path as the list. */
async function toggleReveal(it: MatchItem, value: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (value.dataset["shown"] === "1") {
    value.textContent = "••••••••••";
    delete value.dataset["shown"];
    btn.textContent = "show";
    return;
  }
  const r = await ask({ type: "reveal", itemId: it.itemId, host: tabHost ?? "", explicit: true });
  if (!r?.ok || r.secret?.password == null) {
    // #23: canon copy, never the SW's raw `error` debug detail (the messages.ts contract).
    showMsg("err", r?.ok ? "No password on this item." : revealErrorCopy(r?.code));
    return;
  }
  value.textContent = r.secret.password;
  value.dataset["shown"] = "1";
  btn.textContent = "hide";
}

function renderDetail(it: MatchItem): void {
  el("detail-name").textContent = it.name || "Login";
  const body = el("detail-body");
  body.replaceChildren();

  if (it.username) {
    const { field, value, acts } = detailField("Username");
    value.textContent = it.username;
    acts.append(actBtn("copy", "Copy username", (btn) => void copyUsername(it, btn)));
    body.append(field);
  }

  {
    const { field, value, acts } = detailField("Password");
    value.classList.add("secret");
    value.textContent = "••••••••••";
    acts.append(
      actBtn("show", "Reveal password", (btn) => void toggleReveal(it, value, btn)),
      actBtn("copy", "Copy password", (btn) => void copyPassword(it, btn)),
    );
    body.append(field);
  }

  if (it.hasTotp) {
    const field = document.createElement("div");
    field.className = "detail-field";
    const lab = document.createElement("div");
    lab.className = "detail-label";
    lab.textContent = "One-time code";
    field.append(lab, totpChip(it.itemId)); // joins the list's 1 s ticker (queried by class)
    body.append(field);
  }

  // Saved sites — each uri sanitized to an http(s) link (a saved uri could be javascript:/
  // data:; those render as inert text, never a clickable target).
  const sites = document.createElement("div");
  sites.className = "detail-field";
  const sitesLabel = document.createElement("div");
  sitesLabel.className = "detail-label";
  sitesLabel.textContent = it.uris.length > 1 ? "Sites" : "Site";
  sites.append(sitesLabel);
  if (it.uris.length === 0) {
    const none = document.createElement("div");
    none.className = "detail-value muted";
    none.textContent = "no site saved";
    sites.append(none);
  } else {
    for (const raw of it.uris) {
      const href = safeSiteUrl(raw);
      if (href) {
        const a = document.createElement("a");
        a.className = "site-link";
        a.href = href;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        a.textContent = displaySite(raw);
        sites.append(a);
      } else {
        const span = document.createElement("div");
        span.className = "detail-value muted";
        span.textContent = raw; // shown, never linked
        sites.append(span);
      }
    }
  }
  body.append(sites);

  // Fill: the old row-click action, now explicit. On failure the user still has the copy
  // buttons + the link above, so a non-fillable tab is no longer a dead end.
  const fill = document.createElement("button");
  fill.type = "button";
  fill.className = "primary detail-fill";
  fill.textContent = "Fill this page";
  fill.title = "Type this login into the current tab";
  fill.addEventListener("click", () => void fillItem(it.itemId));
  body.append(fill);
}

function actBtn(label: string, title: string, onClick: (btn: HTMLButtonElement) => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "fill-btn";
  b.textContent = label;
  b.title = title;
  b.setAttribute("aria-label", title); // a11y 3a: the terse glyph text ("user"/"pass"/"num"…)
  b.dataset["label"] = label; //          is not a usable name — the title is the real one.
  b.addEventListener("click", (e) => {
    e.stopPropagation(); // the row itself fills
    onClick(b);
  });
  return b;
}

function flash(btn: HTMLElement): void {
  announce("Copied — it clears from your clipboard soon"); // a11y 2d + Cut J (v2 #10): disclose the auto-wipe
  btn.textContent = "✓";
  btn.classList.add("did");
  window.setTimeout(() => {
    btn.textContent = btn.dataset["label"] ?? "";
    btn.classList.remove("did");
  }, FLASH_MS);
}

async function toClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    showMsg("err", CLIPBOARD_FAILED); // #23: household copy, never the raw exception text
    return false;
  }
  await scheduleClipboardClear();
  return true;
}

/** E1-4 clipboard auto-clear, popup half — runs after every successful copy. Layer 2 first:
 *  arm the SW's alarm backstop (it outlives this popup — Chrome closes us on focus loss);
 *  its reply carries the effective policy seconds, so no separate plumbing. Layer 1: one
 *  precise local timer, web useCopy parity — blind clear, `Math.max(1, s)` clamp (policy 0
 *  still clears). SW unreachable → default 30 s (clearing is safety-positive regardless).
 *  Never a user-facing error: every failure path is a silent no-op. */
async function scheduleClipboardClear(): Promise<void> {
  const r = await ask({ type: "scheduleClipboardClear" });
  const s = r?.clearSeconds ?? 30;
  window.clearTimeout(clipClearTimer); // AM2: single slot — the newest copy owns the clear
  clipClearTimer = window.setTimeout(() => void navigator.clipboard.writeText("").catch(() => {}), Math.max(1, s) * 1000);
}

async function fillItem(itemId: string): Promise<void> {
  const r = await ask({ type: "fillFromPopup", itemId });
  // Cut M (v2 #14): ok is now the FILL outcome (the content script's ground truth), not message
  // delivery — close only when something actually landed in the page; otherwise stay open and
  // render the canon sentence for the seam code (never the SW's raw `error` debug string).
  if (r?.ok) {
    window.close(); // the fill really landed in the page
  } else {
    showMsg("err", fillErrorCopy(r?.code));
  }
}

/** The list payload already carries the username (safe subset) — no reveal round-trip. */
async function copyUsername(it: MatchItem, btn: HTMLElement): Promise<void> {
  if (it.username && (await toClipboard(it.username))) flash(btn);
}

async function copyPassword(it: MatchItem, btn: HTMLElement): Promise<void> {
  const r = await ask({ type: "reveal", itemId: it.itemId, host: tabHost ?? "", explicit: true });
  if (!r?.ok || r.secret?.password == null) {
    // #23: canon copy, never the SW's raw `error` debug detail (the messages.ts contract).
    showMsg("err", r?.ok ? "No password on this item." : revealErrorCopy(r?.code));
    return;
  }
  if (await toClipboard(r.secret.password)) flash(btn); // just the one field, straight to clipboard
}

/* ---- live TOTP chips: 1 s re-poll while the unlocked view is up; click = copy ---- */

function totpChip(itemId: string): HTMLElement {
  const chip = document.createElement("button");
  chip.type = "button";
  chip.className = "totp-chip";
  chip.dataset["item"] = itemId;
  chip.title = "Copy one-time code";
  // a11y 3b: a STABLE name (the live 6-digit code as the name would re-announce every second).
  chip.setAttribute("aria-label", "Copy one-time code");
  const ring = document.createElement("span");
  ring.className = "ring";
  ring.setAttribute("aria-hidden", "true"); // decorative countdown visual (5b conveys it as text)
  const code = document.createElement("span");
  code.className = "code";
  code.textContent = "······";
  code.setAttribute("aria-hidden", "true"); // a11y 3b: digits out of the accessible name
  // a11y 5b: seconds-left as a described-by description (read on focus, not per-tick) so the
  // countdown is available to AT without re-announcing and without polluting the button name.
  const secs = document.createElement("span");
  secs.className = "visually-hidden";
  secs.id = `totp-secs-${++totpSeq}`;
  chip.setAttribute("aria-describedby", secs.id);
  chip.append(ring, code, secs);
  chip.addEventListener("click", (e) => {
    e.stopPropagation();
    void copyTotp(itemId, code);
  });
  return chip;
}

async function copyTotp(itemId: string, codeEl: HTMLElement): Promise<void> {
  const r = await ask({ type: "totp", itemId });
  if (!r?.ok || !r.code) return;
  if (await toClipboard(r.code)) {
    announce("One-time code copied"); // a11y 2d (the chip's "copied" text is aria-hidden)
    codeEl.textContent = "copied";
    codeEl.dataset["hold"] = String(Date.now() + FLASH_MS); // ticker restores the live code after
  }
}

function startTotp(): void {
  stopTotp();
  totpTimer = window.setInterval(() => void tickTotp(), 1000);
  void tickTotp();
}

function stopTotp(): void {
  if (totpTimer !== undefined) {
    window.clearInterval(totpTimer);
    totpTimer = undefined;
  }
}

async function tickTotp(): Promise<void> {
  // The 1 s ticker is also the popup's liveness check: if the session locked while the popup was
  // open (idle autolock, or a Lock from another surface), flip to the locked view instead of
  // leaving a stale — and now unusable — vault list on screen. Distinct from a per-chip {ok:false}
  // (a malformed TOTP), which must NOT relock the whole popup.
  const st = await ask({ type: "status" });
  if (!st) return; // SW mid-restart — retry next tick
  if (!st.unlocked) {
    relocked();
    return;
  }
  for (const chip of document.querySelectorAll<HTMLElement>(".totp-chip")) {
    const itemId = chip.dataset["item"];
    const code = chip.querySelector<HTMLElement>(".code");
    const ring = chip.querySelector<HTMLElement>(".ring");
    if (!itemId || !code || !ring) continue;
    const r = await ask({ type: "totp", itemId });
    if (r?.ok && r.code) {
      if (Date.now() >= Number(code.dataset["hold"] ?? 0)) {
        code.textContent = r.code.replace(/^(\d{3})(\d{3})$/, "$1 $2");
      }
      ring.style.setProperty("--p", String(((r.secondsLeft ?? 0) / TOTP_PERIOD_S) * 100));
      const secsId = chip.getAttribute("aria-describedby"); // a11y 5b: refresh seconds-left desc
      const secs = secsId ? document.getElementById(secsId) : null;
      if (secs) secs.textContent = `${r.secondsLeft ?? 0} seconds left`;
    } else {
      chip.hidden = true; // locked mid-poll / item no longer carries a code
    }
  }
}

/* ---- cards: copy group beneath the logins (cards design 2026-07-09; S3 in-page fill 2026-07-10)
 * Rows reuse the login-row styling. The row shows the masked identity line only; number/expiry/CVV
 * go straight from the SW to the clipboard (copyPassword's exact path), never into this DOM. When
 * the active tab has a same-origin card form (cardFillOffers), each row also offers a Fill button
 * that shows the target origin — the trusted, unspoofable surface for the egress grant ([A2]/R1). */

const cardsLabel = document.createElement("div");
cardsLabel.className = "section-label";
cardsLabel.textContent = "Cards";
cardsLabel.hidden = true;
const cardsList = document.createElement("div");
cardsList.className = "list";
cardsList.hidden = true;
/** Tier 2 §6 [U21] PSP explainer — capability-framed NEUTRAL copy, EXACT design sentence (never
 *  "this checkout…": the signal is attacker-assertable by any embedded frame and must not vouch
 *  the page is a checkout). Shown only while the SW reports crossOriginFormsOnly; the Fill
 *  button never renders in that state (the SW computes the two flags mutually exclusive, and
 *  cardRow gates Fill on `fillable` alone). */
const cardsPspNote = document.createElement("div");
cardsPspNote.className = "empty slim";
cardsPspNote.textContent = "Andvari can't auto-fill payment forms embedded from another site. Use the copy buttons instead.";
cardsPspNote.hidden = true;
el("all-list").after(cardsLabel, cardsPspNote, cardsList);

/** Empty = hidden: login-only hoards see no Cards group at all. */
function renderCards(items: CardItem[]): void {
  cardsLabel.hidden = items.length === 0;
  cardsList.hidden = items.length === 0;
  // The explainer needs rows to point at ("use the copy buttons") — a cardless hoard stays bare.
  cardsPspNote.hidden = items.length === 0 || !cardFill.crossOriginFormsOnly;
  cardsList.replaceChildren();
  for (const it of items) cardsList.append(cardRow(it));
}

/** Card row = copy-only: no click-to-fill (unlike login rows), just per-field copy buttons
 *  gated on the SW's has* flags. The subtitle is the SW's masked line ("Visa ••4242"). */
function cardRow(it: CardItem): HTMLElement {
  const r = document.createElement("div");
  r.className = "item";
  r.title = "Copy card details";

  const glyph = document.createElement("span");
  glyph.className = "glyph";
  const initial = it.name.trim().charAt(0).toUpperCase();
  if (initial) glyph.textContent = initial;
  else glyph.append(sigilSvg("brand", 15)); // a nameless card falls back to the mark, not a tofu rune

  const body = document.createElement("div");
  body.className = "body";
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = it.name;
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = it.subtitle;
  body.append(name, sub);
  // S3: show exactly where the card will go — the browser-provided origin, under the row body.
  if (cardFill.fillable && cardFill.origin) {
    const dest = document.createElement("div");
    dest.className = "card-fill-dest";
    dest.textContent = `Fill → ${cardFill.origin}`;
    body.append(dest);
  }

  const acts = document.createElement("span");
  acts.className = "acts";
  if (cardFill.fillable) {
    acts.append(
      actBtn("fill", `Fill this card into ${cardFill.origin ?? "the page"}`, (btn) => void fillCardRow(it.itemId, btn)),
    );
  }
  if (it.hasNumber) acts.append(actBtn("num", "Copy card number", (btn) => void copyCardField(it.itemId, "number", btn)));
  if (it.hasExpiry) acts.append(actBtn("exp", "Copy expiry (MM/YY)", (btn) => void copyCardField(it.itemId, "expiry", btn)));
  // Tier 2 §6 copy parity: every surface copies number/expiry/name/CVV.
  if (it.hasName) acts.append(actBtn("name", "Copy name on card", (btn) => void copyCardField(it.itemId, "name", btn)));
  if (it.hasCvv) acts.append(actBtn("cvv", "Copy security code", (btn) => void copyCardField(it.itemId, "cvv", btn)));

  r.append(glyph, body, acts);
  return r;
}

/** §5 partial-outcome copy: human labels per detected kind. The three expiry kinds deliberately
 *  share ONE label — "couldn't fill expiry, expiry" would read as a stutter, and the user's
 *  remedy (the expiry copy button) is the same for all three. */
const CARD_KIND_LABEL: Record<CardFieldKind, string> = {
  cardnumber: "number",
  cardexpiry: "expiry",
  cardexpmonth: "expiry",
  cardexpyear: "expiry",
  cardname: "name on card",
  cardcvv: "security code",
  cardtype: "card type",
};

function cardLabels(kinds: CardFieldKind[]): string[] {
  const labels: string[] = [];
  for (const k of kinds) {
    const l = CARD_KIND_LABEL[k];
    if (!labels.includes(l)) labels.push(l);
  }
  return labels;
}

/** S3: mint the SW's one-shot card grant for the active tab's detected card form and fill it.
 *  [T11]: the verdict is `r.outcome.filled`, NOT `r.ok` — "card" (everything landed) closes like
 *  the login fill; "partial" keeps the popup OPEN and names what's missing (the row's copy
 *  buttons, right beneath, are the remedy); anything else renders the canon seam copy. */
async function fillCardRow(itemId: string, btn: HTMLButtonElement): Promise<void> {
  btn.disabled = true;
  const r = await ask({ type: "fillCardFromPopup", itemId });
  btn.disabled = false;
  const filled = r?.outcome?.filled;
  if (filled === "card") {
    window.close(); // the card fill really landed in the page, in full
  } else if (filled === "partial" && r?.outcome) {
    // A label can appear on BOTH sides (month filled, year missed → both read "expiry") —
    // "Filled expiry — couldn't fill expiry" is nonsense, so the missed side owns shared labels.
    const missed = cardLabels(r.outcome.missedKinds);
    const landed = cardLabels(r.outcome.filledKinds).filter((l) => !missed.includes(l));
    showMsg(
      "info",
      landed.length > 0
        ? `Filled ${landed.join(", ")} — couldn't fill ${missed.join(", ")}. Copy instead:`
        : `Couldn't fill ${missed.join(", ")}. Copy instead:`,
    );
  } else {
    showMsg("err", fillErrorCopy(r?.code));
  }
}

/** Same secret-clipboard path as copyPassword: the SW answers exactly one field, it goes
 *  straight to the clipboard, the button flashes — the value is never rendered. */
async function copyCardField(itemId: string, field: "number" | "expiry" | "name" | "cvv", btn: HTMLElement): Promise<void> {
  const r = await ask({ type: "revealCardField", itemId, field });
  if (!r?.ok || r.value == null) {
    // #23: the card seam carries no code — one canon sentence, never the SW's raw `error`.
    showMsg("err", CARD_COPY_FAILED);
    return;
  }
  if (await toClipboard(r.value)) flash(btn);
}

/* ---- search-all (debounced; out-of-order responses dropped) ---- */

async function runSearch(): Promise<void> {
  const q = el<HTMLInputElement>("search").value.trim();
  const seq = ++searchSeq;
  const query = q || undefined;
  const [r, c] = await Promise.all([ask({ type: "allItems", query }), ask({ type: "cardItems", query })]);
  if (seq !== searchSeq) return; // a newer query superseded this response
  if (!r || r.locked) return relocked();
  renderList(el("all-list"), r.items, q ? `Nothing in the hoard matches “${q}”` : "The hoard is empty");
  renderCards(c && !c.locked ? c.items : []);
}

el<HTMLInputElement>("search").addEventListener("input", () => {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => void runSearch(), 150);
});

/* ---- generator: one collapsible section; every Regenerate is a fresh SW `generate` ---- */

async function regenerate(): Promise<void> {
  const r = await ask({ type: "generate" });
  el("gen-pass").textContent = r?.password ?? "";
}

el("gen-toggle").addEventListener("click", () => {
  const g = el("generator");
  g.hidden = !g.hidden;
  el("gen-toggle").classList.toggle("on", !g.hidden);
  el("gen-toggle").setAttribute("aria-expanded", String(!g.hidden)); // a11y 5c
  if (!g.hidden && !el("gen-pass").textContent) void regenerate();
});

el("gen-again").addEventListener("click", () => void regenerate());

el("gen-pass").addEventListener("click", async () => {
  const pw = el("gen-pass").textContent;
  if (pw && (await toClipboard(pw))) {
    announce("Password copied"); // a11y 2d
    const f = el("gen-flash");
    f.hidden = false;
    window.setTimeout(() => {
      f.hidden = true;
    }, FLASH_MS);
  }
});

/* ---- unlock ---- */

function setUnsealing(busy: boolean): void {
  const btn = el<HTMLButtonElement>("unlock");
  btn.disabled = busy;
  btn.textContent = busy ? "Unsealing…" : "Unlock";
  el("kdf").hidden = !busy;
}

async function unlock(): Promise<void> {
  if (el<HTMLButtonElement>("unlock").disabled) return; // Enter while a KDF is already running
  const email = el<HTMLInputElement>("email").value.trim();
  const pw = el<HTMLInputElement>("password");
  if (!email || !pw.value) return;
  clearMsg();
  setUnsealing(true);
  try {
    const r = await ask({ type: "unlock", email, password: pw.value });
    if (r?.ok) {
      pw.value = "";
      try {
        await chrome.storage.local.set({ lastEmail: email }); // the email only — never the password
      } catch {
        /* remembering is best-effort */
      }
      await refresh();
    } else if (r?.code === "totp_required") {
      // 0.16.3: password verified server-side + keys derived (SW memory) — collect the code, no
      // second KDF. Clear the password field (a "start over" is a fresh full sign-in).
      pw.value = "";
      totpBadCount = 0;
      // The email is proven correct here (server accepted the authKey, only the code is left) — remember
      // it now, else TOTP-enrolled accounts (exactly this seam's users) never get it stored.
      try {
        await chrome.storage.local.set({ lastEmail: email });
      } catch {
        /* best-effort */
      }
      enterTotpChallenge(true);
    } else if (r?.code === "aborted") {
      // A server switch / lock landed mid-sign-in — the SW installed nothing; just re-render silently.
      await refresh();
    } else {
      // E1-3: render the coded ladder (errors.ts), never the SW's raw `error` debug detail.
      showMsg("err", unlockErrorCopy(r?.code));
      // AM5: on a 426, the copy points at the update banner — but renderUpdate() ran at popup
      // open BEFORE the SW's 426-triggered checkForUpdate(true) could land its verdict. Re-render
      // now and once more after the SW round-trip (single retry, no loop) so the banner is present
      // when it exists (it only does if a strictly-newer build is actually published).
      if (r?.code === "upgrade_required") {
        void renderUpdate();
        window.setTimeout(() => void renderUpdate(), 2000);
      }
      pw.select();
    }
  } finally {
    setUnsealing(false);
  }
}

/* ---- TOTP challenge (0.16.3): the code step after a totp_required sign-in ---- */

/** Keep the SW alive while the code view is up (MV3 has no popup "port" keepalive, and the challenge
 *  keys live in SW memory — a ~30 s idle eviction would drop them mid-entry, forcing a full re-sign-in
 *  and re-creating the very friction this fixes). A `status` ping every 15 s (< the ~30 s idle window)
 *  is passive — PASSIVE_MSGS, so it never re-arms autolock. Stops when the challenge leaves the screen. */
let totpKeepalive: ReturnType<typeof setInterval> | undefined;
function setTotpKeepalive(on: boolean): void {
  if (totpKeepalive !== undefined) {
    clearInterval(totpKeepalive);
    totpKeepalive = undefined;
  }
  if (on) totpKeepalive = setInterval(() => void ask({ type: "status" }), 15_000);
}

/** Show the one-time-code field, hiding both the master form and the armed-PIN view (a live challenge
 *  outranks them). `withInstruction` posts the polite instruction (info, not an error role). */
function enterTotpChallenge(withInstruction: boolean): void {
  el("totp-challenge").hidden = false;
  el("qu-master-form").hidden = true;
  el("qu-locked").hidden = true;
  setTotpKeepalive(true);
  const code = el<HTMLInputElement>("totp-code");
  code.value = "";
  if (withInstruction) showMsg("info", unlockErrorCopy("totp_required"));
  code.focus(); // explicit — unhiding a section does not move focus in this popup
}

/** Leave the challenge (success, "start over", or the bad-code cap); the caller then refresh()es. */
function exitTotpChallenge(): void {
  el("totp-challenge").hidden = true;
  el<HTMLInputElement>("totp-code").value = "";
  totpBadCount = 0;
  setTotpKeepalive(false);
}

function setTotpVerifying(busy: boolean): void {
  const b = el<HTMLButtonElement>("totp-verify");
  b.disabled = busy; // single-flight the Verify click/Enter — a double-submit burns the login backoff
  b.textContent = busy ? "Verifying…" : "Verify";
  el<HTMLButtonElement>("totp-startover").disabled = busy; // don't let "start over" race an in-flight verify
}

async function verifyTotp(): Promise<void> {
  const input = el<HTMLInputElement>("totp-code");
  const code = input.value.replace(/\D/g, ""); // paste "123 456" → "123456" (maxlength would truncate first)
  if (el<HTMLButtonElement>("totp-verify").disabled) return;
  if (code.length < 6) {
    showMsg("info", "Enter all 6 digits of the code."); // not a silent no-op (a11y: SR announces it)
    input.focus();
    return;
  }
  clearMsg();
  setTotpVerifying(true);
  try {
    const r = await ask({ type: "unlockTotp", code });
    if (r?.ok || r?.code === "aborted") {
      // ok → unlocked; aborted → a switch/lock re-rendered us. Either way just re-render (no error).
      totpBadCount = 0;
      input.value = "";
      exitTotpChallenge();
      await refresh();
      return;
    }
    if (r?.code === "totp_bad_code" && ++totpBadCount < 3) {
      showMsg("err", unlockErrorCopy("totp_bad_code"));
      input.select();
      return;
    }
    // Bad-code cap, expiry, rate-limit, enroll-required, or a transport error: end the challenge
    // (drop the SW keys) and drop to the full form with the honest reason.
    const capped = totpBadCount >= 3;
    await ask({ type: "cancelTotp" });
    exitTotpChallenge();
    await refresh();
    showMsg("err", capped ? "Too many wrong codes — sign in again." : unlockErrorCopy(r?.code));
  } finally {
    setTotpVerifying(false);
  }
}

/** "Start over" — abandon the challenge and return to the master form (the user was in a password
 *  flow, so pin over the PIN view with pinFallback before re-rendering); clear the stale instruction. */
async function totpStartOver(): Promise<void> {
  await ask({ type: "cancelTotp" });
  pinFallback = true;
  exitTotpChallenge();
  clearMsg(); // the "Enter the 6-digit code" instruction must not linger over the master form
  await refresh();
}

el<HTMLButtonElement>("unlock").addEventListener("click", () => void unlock());
el<HTMLInputElement>("email").addEventListener("keydown", (e) => {
  if (e.key === "Enter") el("password").focus();
});
el<HTMLInputElement>("password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") void unlock();
});
el<HTMLButtonElement>("totp-verify").addEventListener("click", () => void verifyTotp());
el<HTMLInputElement>("totp-code").addEventListener("input", (e) => {
  const t = e.target as HTMLInputElement; // keep the field digits-only as they type/paste
  const digits = t.value.replace(/\D/g, "").slice(0, 6);
  if (t.value !== digits) t.value = digits;
});
el<HTMLInputElement>("totp-code").addEventListener("keydown", (e) => {
  if (e.key === "Enter") void verifyTotp();
});
el("totp-startover").addEventListener("click", () => void totpStartOver());

/* ---- quick unlock Tier B (spec 01 §8.4): PIN entry (locked) + offer / enroll / settings (unlocked) ---- */

/** Drive the quick-unlock chrome from the SW's status sub-state. Locked: the PIN field iff `armed` and
 *  the user hasn't chosen the master-password fallback. Unlocked: the Settings on/off row always, plus
 *  the one-time offer card when not enrolled + not dismissed (and the enroll form isn't already open). */
function renderQuickUnlock(qu: Res<"status">["quickUnlock"], unlocked: boolean): void {
  const armedView = !unlocked && qu.armed && !pinFallback;
  const bioView = armedView && qu.kind === "biometric"; // the SW's committed method drives which view
  const pinView = armedView && qu.kind !== "biometric";
  el("qu-locked").hidden = !pinView;
  el("qu-bio-locked").hidden = !bioView;
  el("qu-master-form").hidden = armedView;
  if (!unlocked) return; // showView already hid the unlocked-only offer/enroll/settings chrome

  el("qu-settings").hidden = false;
  el("qu-settings-state").textContent = qu.enrolled ? "Quick unlock is on" : "Quick unlock is off";
  el("qu-toggle").textContent = qu.enrolled ? "Turn off" : "Set up";
  const enrollOpen = !el("qu-enroll").hidden;
  el("qu-offer").hidden = qu.enrolled || qu.offerDismissed || enrollOpen;
  // Biometric enroll shortcuts render only where the platform supports it (bioCapable): one in the
  // offer card (when the offer shows), one inside the open enroll form.
  el("qu-offer-bio-wrap").hidden = el("qu-offer").hidden || !bioCapable;
  el("qu-enroll-bio-wrap").hidden = !enrollOpen || !bioCapable;
}

async function quUnlock(): Promise<void> {
  const pinEl = el<HTMLInputElement>("qu-pin");
  if (!pinEl.value || el<HTMLButtonElement>("qu-unlock").disabled) return;
  const pin = pinEl.value;
  const btn = el<HTMLButtonElement>("qu-unlock");
  btn.disabled = true;
  clearMsg();
  try {
    const r = await ask({ type: "unlockWithPin", pin });
    pinEl.value = ""; // never leave the PIN in the field
    if (r?.ok) {
      await refresh();
      return;
    }
    showMsg("err", pinUnlockErrorCopy(r?.code, r?.attemptsRemaining));
    // A wrong PIN keeps the field for a retry; anything that WIPED or invalidated the blob (exhausted /
    // expired / corrupt / revoked / hard fault) drops us to the master password (re-render clears #qu-locked).
    if (r && (r.code === "wrong_pin" || r.code === "network" || r.code === "server_error")) {
      pinEl.focus();
    } else {
      pinFallback = true;
      await refresh();
    }
  } finally {
    btn.disabled = false;
  }
}
el("qu-unlock").addEventListener("click", () => void quUnlock());
el<HTMLInputElement>("qu-pin").addEventListener("keydown", (e) => {
  if (e.key === "Enter") void quUnlock();
});
el("qu-use-master").addEventListener("click", () => {
  pinFallback = true;
  el("qu-locked").hidden = true;
  el("qu-master-form").hidden = false;
  const email = el<HTMLInputElement>("email");
  (email.value ? el("password") : email).focus();
});

/** Biometric redeem (0.17.0). The SW opens the WebAuthn connector WINDOW; this popup usually loses focus
 *  and CLOSES the moment it does (so the `await` below rarely resolves here — the connector shows its own
 *  progress and the vault is unlocked when the popup is reopened). The branch runs only where the popup
 *  survived or the redeem failed before the window opened; it renders a fallback message then. */
async function quBioUnlock(): Promise<void> {
  const btn = el<HTMLButtonElement>("qu-bio-unlock");
  if (btn.disabled) return;
  btn.disabled = true;
  clearMsg();
  showMsg("info", "Opening your device’s unlock prompt…");
  try {
    const r = await ask({ type: "unlockWithBio" });
    if (r?.ok) {
      clearMsg();
      await refresh();
      return;
    }
    if (!r) return; // popup context surviving without a response (rare) — the connector owns the outcome
    showMsg("err", bioUnlockErrorCopy(r.code));
    // A benign/transient outcome keeps the bio view for a retry; anything that WIPED or invalidated the
    // blob (expired / corrupt / stale_uvk / revoked / hard fault) drops us to the master password.
    if (r.code === "not_armed" || r.code === "bio_cancelled" || r.code === "network" || r.code === "server_error") {
      el("qu-bio-unlock").focus();
    } else {
      pinFallback = true;
      await refresh();
    }
  } finally {
    btn.disabled = false;
  }
}
el("qu-bio-unlock").addEventListener("click", () => void quBioUnlock());
el("qu-bio-use-master").addEventListener("click", () => {
  pinFallback = true;
  el("qu-bio-locked").hidden = true;
  el("qu-master-form").hidden = false;
  const email = el<HTMLInputElement>("email");
  (email.value ? el("password") : email).focus();
});

/** Biometric enroll (0.17.0). Like quBioUnlock, the connector window usually closes this popup — the
 *  status on the next open reflects the result. When the popup survives, we render the outcome. */
async function quEnrollBio(): Promise<void> {
  clearMsg();
  showMsg("info", "Opening your device’s setup prompt…");
  const r = await ask({ type: "enrollQuickUnlockBio" });
  if (!r) return; // popup closed when the connector opened — the reopened popup shows the result
  if (r.ok) {
    el("qu-enroll").hidden = true;
    showMsg("info", "Device quick unlock is on for this browser.");
    await refresh();
  } else {
    showMsg("err", enrollBioErrorCopy(r.code));
    await refresh();
  }
}
el("qu-offer-bio").addEventListener("click", () => void quEnrollBio());
el("qu-enroll-bio").addEventListener("click", () => void quEnrollBio());

function openEnroll(): void {
  el("qu-offer").hidden = true;
  el("qu-offer-bio-wrap").hidden = true;
  el("qu-enroll").hidden = false;
  el("qu-enroll-bio-wrap").hidden = !bioCapable; // reveal the biometric alternative where supported
  el<HTMLInputElement>("qu-new-pin").value = "";
  el("qu-new-pin").focus();
}

async function quEnrollSave(): Promise<void> {
  const pinEl = el<HTMLInputElement>("qu-new-pin");
  if (!pinEl.value || el<HTMLButtonElement>("qu-enroll-save").disabled) return;
  const pin = pinEl.value;
  const btn = el<HTMLButtonElement>("qu-enroll-save");
  btn.disabled = true;
  clearMsg();
  try {
    const r = await ask({ type: "enrollQuickUnlock", pin });
    if (r?.ok) {
      pinEl.value = "";
      el("qu-enroll").hidden = true;
      showMsg("info", "Quick unlock is on for this browser.");
      await refresh();
    } else {
      pinEl.select();
      showMsg("err", enrollErrorCopy(r?.code, r?.reason));
    }
  } finally {
    btn.disabled = false;
  }
}
el("qu-offer-setup").addEventListener("click", openEnroll);
el("qu-offer-dismiss").addEventListener("click", async () => {
  await ask({ type: "dismissQuickUnlockOffer" });
  el("qu-offer").hidden = true;
});
el("qu-enroll-save").addEventListener("click", () => void quEnrollSave());
el<HTMLInputElement>("qu-new-pin").addEventListener("keydown", (e) => {
  if (e.key === "Enter") void quEnrollSave();
});
el("qu-enroll-cancel").addEventListener("click", () => {
  el<HTMLInputElement>("qu-new-pin").value = "";
  el("qu-enroll").hidden = true;
  void refresh();
});
el("qu-toggle").addEventListener("click", async () => {
  if (el("qu-settings-state").textContent === "Quick unlock is on") {
    await ask({ type: "disableQuickUnlock" }); // wipe — no auth gate (§8.1 parity)
    showMsg("info", "Quick unlock turned off.");
    await refresh();
  } else {
    openEnroll();
  }
});
el("sign-out").addEventListener("click", async () => {
  await ask({ type: "signOut" }); // full wipe: blob + co-key + tokens + session (spec 01 §8.4)
  clearMsg();
  pinFallback = false;
  await refresh();
});

/* ---- footer ---- */

el("lock").addEventListener("click", async () => {
  await ask({ type: "lock" });
  clearMsg();
  await refresh();
});

/** Open a page on the configured server (design §5.1 — the origin is read fresh from
 *  storage.local via serverurl.ts on every click, never cached in the popup). window.close() only
 *  AFTER tabs.create resolves: a closed popup's pending promise continuations never run. */
async function openServerPage(path = ""): Promise<void> {
  const base = await getServerUrl();
  try {
    await chrome.tabs.create({ url: base + path });
  } catch {
    /* tab creation refused — leave the popup open rather than silently doing nothing */
    return;
  }
  window.close();
}

el("open-vault").addEventListener("click", () => void openServerPage());

// Cut H (v2 #6): forgotten master password — the self-recovery flow lives in the web app
// (#recover deep link); the locked popup was a dead end.
el("forgot").addEventListener("click", () => void openServerPage("/#recover"));

// E1-6: the rescue-nudge strip IS the affordance — the extension can't change the master
// password itself, so clicking anywhere on it opens the web vault (same action as open-vault).
el("must-change").addEventListener("click", () => void openServerPage());

el("ping").addEventListener("click", async () => {
  showMsg("info", "…");
  const r = await ask({ type: "ping" });
  setConn(r?.ok === true);
  // #23: the conn-status twin's sentence — the old line leaked a raw epoch (`t=1752…`).
  if (r?.ok) showMsg("info", "Server reachable.");
  // E1-3/extux-05: the one canonical unreachable sentence — never the raw exception text. (A
  // mid-restart SW → undefined shares this copy, mildly conflating SW death with the network;
  // accepted per design.)
  else showMsg("err", UNREACHABLE);
});

el("detail-back").addEventListener("click", closeDetail);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el("detail").hidden) {
    e.preventDefault();
    closeDetail();
  }
});

/** Persistent anti-phishing origin display (design §5.1): render the RAW configured origin in the
 *  header, middle-truncated to fit, with the FULL origin on title + aria-label (hover/focus). Read
 *  fresh from storage.local every open — never cached — so it always reflects the real switch target. */
async function renderServerOrigin(): Promise<void> {
  const origin = await getServerUrl();
  const node = el("server-origin");
  node.textContent = middleTruncateOrigin(origin);
  node.title = origin;
  node.setAttribute("aria-label", `Connected server: ${origin}`);
}

/** Wave-3 route (design §5.1): Firefox MV3 grants NO host permissions at install (optional-by-
 *  default), so a first run lacks the grant for the configured origin — every fetch then fails as
 *  "unreachable". Detect the missing grant and ROUTE to the options page (the only place a
 *  permissions.request can run under a user gesture, which also lights up the dynamic autofill
 *  registration via background.permissions.onAdded). `granted===false` (not null/unknown) is the
 *  only trigger, so a permissions-API-less engine never shows a false route (grantflow decision). */
async function detectMissingHostGrant(): Promise<void> {
  let granted: boolean | null = null;
  try {
    const pattern = originMatchPattern(await getServerUrl());
    if (pattern) granted = await chrome.permissions.contains({ origins: [pattern] });
  } catch {
    /* permissions API unavailable — granted stays null (no detection, no false route) */
  }
  document.body.dataset.missingHostGrant = granted === false ? "true" : "false";
  if (shouldRouteToOptions(granted)) el("host-grant-cta").hidden = false;
}

el("host-grant-cta").addEventListener("click", () => {
  try {
    chrome.runtime.openOptionsPage();
  } catch {
    /* openOptionsPage unavailable — fall back to a tab on the options page */
    void chrome.tabs.create({ url: chrome.runtime.getURL("options.html") });
  }
  window.close();
});

/** F3 fresh-install grant banner (card autofill Tier 1 §10): Chrome grants NO optional host
 *  permission at install, so the dynamic autofill script injects nowhere and every card/login
 *  in-page surface is silently dormant. When the broad grant is missing, un-hide the banner; the
 *  probe failing (permissions API absent) shows nothing — a false banner whose button can't work
 *  is worse than staying quiet (the grantflow null discipline). */
async function detectMissingBroadGrant(): Promise<void> {
  try {
    el("autofill-grant").hidden = await chrome.permissions.contains({ origins: [BROAD_ORIGIN_PATTERN] });
  } catch {
    /* permissions API unavailable — banner stays hidden (no false CTA) */
  }
}

el("autofill-grant").addEventListener("click", () => {
  // permissions.request MUST be the first async call — this popup click is the user gesture it
  // needs (§10). On grant, just hide the banner: the background permissions.onAdded listener does
  // the content-script re-registration (NO SW plumbing here — one reconcile path, not two).
  void (async () => {
    try {
      const granted = await chrome.permissions.request({ origins: [BROAD_ORIGIN_PATTERN] });
      if (granted) el("autofill-grant").hidden = true;
    } catch {
      /* dismissed / not requestable — the banner stays as the retry affordance */
    }
  })();
});

void renderServerOrigin();
// Probe biometric capability BEFORE the first status render so the bio enroll shortcuts appear on the
// first paint (not only after an interaction re-renders). The probe is fast and never throws out.
void probeBioCapable().finally(() => void refresh());
void renderUpdate();
// Passive connectivity dot — quiet ping on open, result only in the header dot.
void ask({ type: "ping" }).then((r) => setConn(r?.ok === true));
void detectMissingHostGrant();
void detectMissingBroadGrant();
