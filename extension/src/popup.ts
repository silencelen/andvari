/**
 * Popup — the themed vault surface. Locked: email + master password → SW `unlock` (the ~6 s
 * Argon2id shows the animated "Unsealing…" state). Unlocked: current-site matches + search-all
 * rows — a row click fills via the SW's one-shot grant (`fillFromPopup`); hover copy buttons
 * (password via explicit `reveal`, written straight to the clipboard, never rendered); live
 * TOTP chips re-polled each second. The SW holds all key material — this page only messages it.
 * External module only (MV3 CSP forbids inline); vault strings land via textContent only.
 */
import type { CardFieldKind } from "./detect";
import { drawWordmarks, runeSvg } from "./brand";
import { CARD_MOVE_NOT_FOLLOWED_TITLE, CARD_RECORD_DAMAGED_TITLE, CARD_REFUSED_KEPT, CARD_WITHHELD, cardRecordDamagedCopy, chooseServerCopy, chooseServerMessage, FORGET_DELETES_COPY, GATE_TITLE_KIND_CHANGE, moveNotFollowedCopy, RECOVER_IN_APP, SERVER_CHANGED_UPDATE, serverEndedNotice, SERVER_FORK, sessionNotConfirmedNotice, SIGN_OUT_NOT_CONFIRMED, unlockErrorMessage } from "./errors";
import { bioUnlockErrorCopy, CARD_COPY_FAILED, CARD_DUPLICATE_FIELDS, cardFillOffLine, CARD_MIXED_FORMS, CARD_NO_FRAME_ORIGIN, CARD_PAGE_FORM, cardFillErrorCopy, cardProviderNotAllowedCopy, CLIPBOARD_FAILED, CONFIRM_SERVER_FIRST, enrollBioErrorCopy, enrollErrorCopy, fillErrorCopy, lockNoticeCopy, pinUnlockErrorCopy, QUICK_UNLOCK_NOT_CONFIRMED, QUICK_UNLOCK_NOT_UPDATED, revealErrorCopy, SESSION_NOT_SAVED, timerNoticeLine, TOTP_ADDED, totpAddErrorCopy, UNREACHABLE, unlockErrorCopy, waitingGrantsLine } from "./errors";
import * as T from "./copy";
import { fillApproved } from "./errors";
import { ACCOUNT_REMEMBERED, FORGET_EARLIER_CONFIRM, FORGET_EARLIER_CONFIRM_BUTTON, FORGET_EARLIER_DONE, FORGET_EARLIER_FAILED, FORGET_EARLIER_NOT_OFFERED, FORGET_EARLIER_OFFER, FORGET_EARLIER_OPEN, FORGET_EARLIER_READ_FIRST } from "./errors";
import { capturesLostLine, COUNT_UNKNOWN, forgetUnsavedLine, unsavedArmStep, unsavedCapturesLine } from "./unsavedarm";
import { wrongVaultLine } from "./itemhome";
import { clearLiveMsg, messageBlocks, renderBlocks, setLiveMsg, setLiveMsgBlocks } from "./livemsg";
import { send, type CardItem, type MatchItem, type Req, type Res, type ServerBlockWire, type UnlockNotice } from "./messages";
import type { OtherSiteQuestion } from "./othersite";
import { middleTruncateOrigin, originMatchPattern } from "./serverurl";
import { PUBLIC_INSTANCE } from "./publicinstance";
import { masterPasswordLabel } from "./trustgate";
import { offerDownloadUrl } from "./updateoffer";
import { BROAD_ORIGIN_PATTERN, shouldRouteToOptions } from "./grantflow";
import { BUILD_TARGET } from "./buildtarget";
import { CARD_FILL } from "./cardfillflag";
import { fillDestination } from "./cardrelease";
import { askAppServerDetailed, nativeSender } from "./appserver";
import { displaySite, safeSiteUrl } from "./siteurl";
import { tabPageOf } from "./senderorigin";
import { reuseWarning } from "./reusealert";

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

/** The active tab's origin, as the worker is told it (F4: its scheme decides which addresses match). */
let tabPage: string | null = null;
/** S3: whether the active tab has a payment provider's card form we may Fill into, and to which origin (owner decision
 *  2026-11-14: andvari fills a card only there). Fetched once per unlocked render — the active tab can't change while
 *  the popup is open. When it is not fillable, `allowOrigin` (a provider's form, shown by the page, on a site andvari may
 *  not run on), `pageFormOnly` (the page takes the card in its own fields) or `allowEverywhere` (Safari: andvari is not
 *  running on this page) gives the one line that says why the rows copy instead. */
let cardFill: {
  fillable: boolean;
  origin: string | null;
  /** The provider frames a Fill reaches, with the card details it fills there: shown as the Fill's destination (the
   *  details by name, round-12 review), and sent back with it. */
  frames: { frameId: number; origin: string; kinds: CardFieldKind[]; ancestors?: readonly string[] | null }[];
  pageFormOnly: boolean;
  allowOrigin?: string;
  allowEverywhere?: boolean;
  doubled?: boolean;
  noFrameOrigin?: boolean;
  /** This build has no in-page card fill (cardfillflag.ts). */
  fillOff?: boolean;
  /** The person tapped card fields in two different payment forms (round-13 review): Start over. */
  mixed?: boolean;
} = { fillable: false, origin: null, frames: [], pageFormOnly: false };
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

/** The connector's RP-ID claim rides the manifest's install-time host permission for the reference
 *  instance (design 2026-07-18 §3), which the browser can withhold at runtime. Same pattern the SW
 *  broker probes — kept as one derivation from PUBLIC_INSTANCE.origin rather than a second literal.
 *  A missing permissions API answers TRUE (never hide a working button on an unaskable engine). */
async function bioRpPermissionHeld(): Promise<boolean> {
  try {
    return await chrome.permissions.contains({ origins: [`${PUBLIC_INSTANCE.origin}/*`] });
  } catch {
    return true;
  }
}

/** Cosmetic platform label for the biometric buttons — the ceremony itself works regardless. */
function bioLabel(): string {
  const ua = navigator.userAgent;
  if (/Mac|iPhone|iPad|iPod/.test(ua)) return "Touch ID";
  if (/Windows/.test(ua)) return "Windows Hello";
  return T.YOUR_DEVICE;
}

/** bug-ext-gating--4: this probed ONLY for a platform authenticator, and that single boolean both
 *  reveals and hides the enroll/unlock buttons. Two things it said nothing about, each of which
 *  makes the ceremony impossible rather than merely likely to fail — and both of which surfaced as
 *  "Setup was cancelled — try again when you're ready.", forever, on every retry:
 *   - extension-page WebAuthn support (Firefox needs 150+, while manifest.firefox.json admits 121);
 *   - the RP host permission, which can be runtime-withheld (Chrome "site access: on click",
 *     Firefox optional-by-default) and which the SW's ceremony broker now probes for the same
 *     reason. A capability that cannot work must not be offered. */
async function probeBioCapable(): Promise<void> {
  try {
    bioCapable =
      typeof PublicKeyCredential !== "undefined" &&
      typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function" &&
      typeof navigator.credentials?.create === "function" &&
      (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) &&
      (await bioRpPermissionHeld());
  } catch {
    bioCapable = false;
  }
  const label = bioLabel();
  el("qu-bio-unlock").textContent = label === T.YOUR_DEVICE ? T.UNLOCK_WITH_YOUR_DEVICE : fillApproved(T.UNLOCK_WITH, label);
}

function showMsg(kind: "err" | "info", text: string, title: string | null = null): void {
  // a11y 2a — ORDER MATTERS (the static-read caveat); the rule and its rationale live in
  // livemsg.ts now, because two other copies of this idiom had it inverted. Errors are assertive
  // (role=alert), info is polite (role=status).
  // A title, or a paragraph break in the words, takes the message's parts: a title above, one paragraph per line, each
  // set as text (livemsg.ts renderBlocks), never as markup.
  if (title !== null || text.includes("\n")) setLiveMsgBlocks(el("msg"), `msg ${kind}`, kind === "err" ? "alert" : "status", title, text);
  else setLiveMsg(el("msg"), `msg ${kind}`, kind === "err" ? "alert" : "status", text);
}

/** A message with its title (the owner's approved words come as a title and a body). */
function showTitled(kind: "err" | "info", m: { title: string | null; body: string }): void {
  showMsg(kind, m.body, m.title);
}

function clearMsg(): void {
  clearLiveMsg(el("msg"));
}

function setConn(ok: boolean, noServer = false): void {
  const dot = el("conn");
  dot.className = `dot ${ok ? "on" : "off"}`;
  // A15 review F1: while a server is pending nothing was dialed, so "unreachable" would be the wrong word.
  dot.title = ok ? T.SERVER_DOT_REACHABLE : noServer ? T.SERVER_DOT_NONE : T.SERVER_DOT_UNREACHABLE;
  el("conn-status").textContent = ok ? T.SERVER_REACHABLE : noServer ? T.SERVER_NONE_CONFIRMED : T.SERVER_UNREACHABLE; // a11y 5a twin
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
    el("grants-waiting").hidden = true; // unlocked-session chrome — refresh() re-derives it
    el("wrong-vault").hidden = true; // A1b: likewise
    el("qu-offer").hidden = true; // quick-unlock offer/enroll are unlocked-only chrome (spec 01 §8.4)
    el("qu-enroll").hidden = true;
    el("qu-settings").hidden = true;
    // Drop rendered vault rows/codes on lock — nothing lingers in the DOM.
    el("site-list").replaceChildren();
    el("all-list").replaceChildren();
    renderCards([]); // empties AND hides the Cards group
    el<HTMLInputElement>("search").value = "";
    setGeneratedPassword(""); // a11y-webext--10 owns this node's content — never write it raw
    el("generator").hidden = true;
    el("gen-toggle").classList.remove("on");
    el("gen-toggle").setAttribute("aria-expanded", "false"); // a11y 5c: collapsed on lock
  }
}

/** The captures-lost line this popup said (popup life only; Res<"status">.capturesLost is taken by the read). */
let capturesLostShown: string | null = null;

async function refresh(): Promise<void> {
  // A15 review F1: while a server is pending the worker signs in nowhere, so the popup leads with the confirm route
  // INSTEAD of any sign-in form (and opens no server page). Asked first, on every render.
  const info = await ask({ type: "serverInfo" });
  passwordLabelServer = info && !info.block && typeof info.url === "string" && info.url !== "" ? { name: info.name ?? null, origin: info.url } : null;
  if (info?.block) {
    // §4.4 "A fork stops traffic, not reading": an unlocked vault stays readable under a fork, with the warning and
    // "Forget this server" in view (the card notice below); a locked one cannot be opened (that needs the server).
    const readable = info.block.kind === "fork" ? (await ask({ type: "status" }))?.unlocked === true : false;
    if (!readable) {
      showConfirmServer(info.block, info.trustedStore === true);
      return;
    }
  }
  el("confirm-server").hidden = true;
  el("open-vault").hidden = false;
  // takeLost: this render says the captures a lock nobody was asked about deleted unsaved, once (the read takes them).
  const s = await ask({ type: "status", takeLost: true });
  // Design §4.4 (decided on 2026-11-17): kept for this popup's life while it stays locked, in its own line, so an error
  // the popup shows meanwhile (a refused PIN unlock) is not replaced by it.
  const lostNow = capturesLostLine(s?.capturesLost ?? 0);
  if (lostNow !== null) capturesLostShown = lostNow;
  if (s?.unlocked) capturesLostShown = null;
  el("captures-lost").hidden = capturesLostShown === null;
  el("captures-lost").textContent = capturesLostShown ?? "";
  if (!s) {
    showView(false);
    showMsg("err", T.BACKEND_NOT_RESPONDING);
    return;
  }
  showView(s.unlocked);
  renderQuickUnlock(s.quickUnlock, s.unlocked); // spec 01 §8.4 — PIN entry (locked) / offer+settings (unlocked)
  if (BUILD_TARGET === "safari") renderAppLocked(s.unlocked);
  renderCardNotice(s.cardNotice);
  // §4.4: the server ended this session — readable here, nothing sent or saved, with the notice in view.
  if (s.unlocked && s.serverEnded) {
    // Never advises the lock where it would delete logins or cards caught and not saved.
    // A session the extension could not confirm in time ended here, not at the server: said as that end.
    const unsaved = typeof s.unsavedCaptures === "number" ? s.unsavedCaptures : null;
    showMsg("info", s.serverEndedUnconfirmed ? sessionNotConfirmedNotice(unsaved) : serverEndedNotice(unsaved));
    // Quick unlock cannot be enrolled while it stands (the worker refuses it): the popup does not offer it.
    el("qu-offer").hidden = true;
    el("qu-enroll").hidden = true;
    el("qu-settings").hidden = true;
  }
  // §12.2 rule 1: the count of served shared vaults whose key this session does not hold: a grant that waits for a
  // full client, or a vault closed in this session and served again, which opens at the next unlock here.
  const waiting = s.unlocked ? s.waitingGrants ?? 0 : 0;
  el("grants-waiting").hidden = waiting <= 0;
  el("grants-waiting").textContent = waitingGrantsLine(waiting);
  // A1b (§5.1 INV-HOME): the last snapshot sent rows under the wrong vault; they were not applied.
  const wrong = s.unlocked ? s.wrongVault ?? 0 : 0;
  el("wrong-vault").hidden = wrong <= 0;
  el("wrong-vault").textContent = wrongVaultLine(wrong);
  // An alarm the browser refused (twice); for the auto-lock's, the deadline still keeps the lock's time.
  const timerLine = s.unlocked ? timerNoticeLine(s.timerNotice) : "";
  el("timer-notice").hidden = timerLine === "";
  el("timer-notice").textContent = timerLine;
  if (s.unlocked) {
    await loadUnlocked();
    // Security review 2026-10: the signup reuse warning lives here (and on the badge), never in
    // the page — an in-page toast was readable by the page, one membership bit per guess.
    const reuse = await ask({ type: "reuseNotice" });
    const warning = reuse ? reuseWarning(reuse.count) : null;
    if (warning) showMsg("info", warning);
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
  if (s.lockNotice?.kind === "idle") showMsg("info", lockNoticeCopy(s.lockNotice.seconds));
  else if (s.lockNotice?.kind === "operator") showMsg("err", unlockErrorCopy("operator_account")); // §12.2 rule 7, by the card
  // A quick unlock that found this browser's session unconfirmed: said at every locked render until the next unlock.
  else if (s.lockNotice?.kind === "not_confirmed") showMsg("info", QUICK_UNLOCK_NOT_CONFIRMED);
  // Armed quick unlock (and not falling back) → the PIN field (or the bio button) owns the focus; else
  // the master form.
  if (s.quickUnlock.armed && !pinFallback) {
    el(s.quickUnlock.kind === "biometric" ? "qu-bio-unlock" : "qu-pin").focus();
    return;
  }
  const email = el<HTMLInputElement>("email");
  if (!email.value) {
    const remembered = s.email ?? s.rememberedEmail ?? null; // A15: kept by the worker, not in storage.local
    if (remembered) email.value = remembered;
  }
  renderPasswordLabel();
  (email.value ? el("password") : email).focus();
}

/** The server the password label names (§4.4), from the last serverInfo; null while none is in effect. */
let passwordLabelServer: { name: string | null; origin: string } | null = null;

/** §4.4: "Master password for *email* on *name* (*origin*)". */
function renderPasswordLabel(): void {
  const s = passwordLabelServer;
  el("password-label").textContent =
    s === null || s.origin === "" ? T.MASTER_PASSWORD_LABEL : masterPasswordLabel(el<HTMLInputElement>("email").value, s.name, s.origin);
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
    // a11y 2a (livemsg.ts): these two role="status" containers were populated WHILE HIDDEN and
    // unhidden afterwards — the inverted order, so the update-channel note was announced to
    // nobody. Unhide first here too; the text is a child write, so the shared helper doesn't fit.
    quiet.hidden = !reason;
    quiet.textContent = reason ? updateQuietCopy(reason) : "";
    return;
  }
  quiet.hidden = true; // an offer supersedes the quiet note (mutually exclusive)
  banner.hidden = false; // a11y 2a: in the tree before its text lands (see above)
  el("update-text").textContent = fillApproved(T.UPDATE_AVAILABLE, String(r.latest));
  // Firefox gets the Firefox zip; everything else (Chrome/Edge/Brave) the Chrome zip. Fall back
  // to whichever URL exists so a single-target publish still links somewhere real.
  // A15 step 0: the popup re-checks the link itself before it becomes an href — only
  // `${UPDATE_ORIGIN}/downloads/<basename>`, and only while the current server is the public instance.
  const isFirefox = /firefox/i.test(navigator.userAgent);
  const server = (await currentServer()) ?? ""; // no answer / pending: no link (offerDownloadUrl needs the default)
  const url = [isFirefox ? r.firefoxUrl : r.chromeUrl, r.chromeUrl, r.firefoxUrl].map((u) => offerDownloadUrl(u, server)).find((u) => u !== null) ?? null;
  if (url) {
    link.href = url;
    link.textContent = T.UPDATE_DOWNLOAD_RELOAD;
    link.hidden = false;
  } else {
    link.hidden = true; // a version with no usable link: still tell them one exists
  }
}

/** M-D4b muted update-channel copy (surface owns the sentences; the seam carries only a reason
 *  code). Mirrors the desktop's two quiet Settings lines (DesktopState UPDATE_*_NOTICE). */
function updateQuietCopy(reason: string): string {
  return reason === "stale"
    ? T.UPDATE_LISTING_STALE
    : T.UPDATE_LISTING_UNVERIFIED;
}

/** A15: the configured server origin, from the worker (the only reader of its trusted store) — asked on every use,
 *  never cached in the popup. Null when there is no server to use: the worker did not answer (A15 review S3 — before,
 *  that read as the default, and a click opened the reference instance), or a server is pending (F1). */
async function currentServer(): Promise<string | null> {
  const r = await ask({ type: "serverInfo" });
  return r && typeof r.url === "string" && r.url && !r.block ? r.url : null;
}

/** A15 review F1: the pending-server card, shown instead of the sign-in form. The origin is the worker's (display
 *  only — confirming it is the Trust Gate's job, in Options); every string here is textContent. A block that cannot be
 *  confirmed (`keepable` false) is one of two cases: no store here at all ([storeKept] false), or (A16 review R3) the
 *  update could not confirm the old setting although a choice can be kept — then the user enters the address. */
function showConfirmServer(block: ServerBlockWire, storeKept: boolean): void {
  showView(false); // drops any unlocked chrome (and the master form's state)
  el("locked").hidden = true;
  el("open-vault").hidden = true; // no server page opens while a server is pending
  const box = el("confirm-server");
  box.hidden = false;
  const notMine = el<HTMLButtonElement>("confirm-server-not-mine");
  const open = el<HTMLButtonElement>("confirm-server-open");
  const pub = el<HTMLButtonElement>("confirm-server-public");
  pub.hidden = true;
  if (BUILD_TARGET === "safari") {
    // The server is the andvari app's, and only the app changes it: nothing to confirm here, no Options, no default.
    el("confirm-server-h").textContent = T.NO_SERVER_YET;
    el("confirm-server-lead").hidden = true;
    el("confirm-server-origin").hidden = true;
    el("confirm-server-body").textContent = appAnswered === "none" ? T.APP_SERVER_NONE : T.APP_SERVER_UNKNOWN;
    open.hidden = true;
    notMine.hidden = true;
    return;
  }
  if (block.kind === "unsettled") {
    el("confirm-server-h").textContent = T.SETTINGS_NOT_LOADED_TITLE;
    el("confirm-server-lead").hidden = true;
    el("confirm-server-origin").hidden = true;
    el("confirm-server-body").textContent = T.SETTINGS_NOT_LOADED;
    open.hidden = true;
    notMine.hidden = true;
    return;
  }
  const origin = el("confirm-server-origin");
  if (block.kind === "no_store" || !storeKept) {
    el("confirm-server-h").textContent = T.NO_STORE_TITLE;
    el("confirm-server-lead").hidden = true;
    origin.hidden = true;
    el("confirm-server-body").textContent = T.NO_STORE;
    open.hidden = true;
    notMine.hidden = true;
    return;
  }
  if (block.kind === "fork" || block.kind === "pin_damaged") {
    // §4.4: a fork is durable and stops everything; a damaged record blocks the origin. "Forget this server" only.
    el("confirm-server-h").textContent = block.kind === "fork" ? T.FORK_TITLE : CARD_RECORD_DAMAGED_TITLE;
    el("confirm-server-lead").hidden = true;
    origin.hidden = false;
    origin.textContent = block.origin;
    // Entry 12's two paragraphs stay two paragraphs: one element per line, each set as text.
    if (block.kind === "fork") el("confirm-server-body").textContent = `${SERVER_FORK} ${FORGET_DELETES_COPY}`;
    else renderBlocks(el("confirm-server-body"), messageBlocks(null, cardRecordDamagedCopy(block.origin)));
    open.hidden = true;
    notMine.hidden = false;
    notMine.textContent = T.FORGET_THIS_SERVER;
    forgetArms.delete(notMine); // a fresh render starts unarmed
    // Rendered run: not focused at open (it drew a heavy ring at rest, and Enter would have deleted this
    // browser's copy of the vault: the first screen's no-preselection rule). Tab still reaches it.
    return;
  }
  // `no_server`: the first popup (§12.2) — the public instance, or the person's own server behind the Trust Gate.
  el("confirm-server-h").textContent = T.CHOOSE_YOUR_SERVER;
  el("confirm-server-lead").hidden = false;
  el("confirm-server-lead").textContent = T.PUBLIC_SERVER_LEAD;
  origin.hidden = false;
  origin.textContent = PUBLIC_INSTANCE.origin;
  el("confirm-server-body").textContent = T.OWN_SERVER_BODY;
  pub.hidden = false;
  pub.textContent = PUBLIC_INSTANCE.name;
  open.hidden = false;
  open.textContent = T.YOUR_OWN_SERVER;
  notMine.hidden = true;
  // Rendered run 2026-11-16: neither choice is preselected (§12.1's first-screen rule, the safer reading for this one):
  // a focused "andvari" made Enter pick the public server.
  if (document.activeElement === pub) pub.blur();
}

/** §4.4: the card notice beside a working server. Names are plain text, always beside their origin. */
function renderCardNotice(n: Res<"status">["cardNotice"]): void {
  const box = el("card-notice");
  const text = el("card-notice-text");
  const follow = el<HTMLButtonElement>("card-notice-follow");
  const title = el("card-notice-title");
  const later = el<HTMLButtonElement>("card-notice-later");
  follow.hidden = true;
  title.hidden = true;
  later.hidden = true;
  if (!n) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  delete follow.dataset["forget"];
  if (n.kind === "fork") {
    text.textContent = `${n.origin}: ${SERVER_FORK} ${FORGET_DELETES_COPY}`;
    follow.hidden = false;
    follow.textContent = T.FORGET_THIS_SERVER;
    forgetArms.delete(follow); // a fresh render starts unarmed
    follow.dataset["forget"] = "1";
    delete follow.dataset["to"];
    delete follow.dataset["hash"];
    return;
  }
  if (n.kind === "withheld") text.textContent = CARD_WITHHELD;
  else if (n.kind === "invalid") text.textContent = CARD_REFUSED_KEPT;
  else if (n.kind === "changed") text.textContent = SERVER_CHANGED_UPDATE;
  else if (n.kind === "move") {
    text.textContent = fillApproved(T.SERVER_MOVED_NOTICE, n.name, n.from, n.to);
    follow.hidden = false;
    follow.textContent = fillApproved(T.MOVE_TO, n.to);
    follow.dataset["to"] = n.to;
    follow.dataset["hash"] = n.hash;
  } else {
    // The kind change gate (§12.3; approved wording, entry 10): the title, §12.3's sentence, Continue and Not now.
    title.hidden = false;
    title.textContent = GATE_TITLE_KIND_CHANGE;
    text.textContent = fillApproved(T.KIND_CHANGE_NOTICE, n.name, n.origin, n.to);
    follow.hidden = false;
    follow.textContent = T.CONTINUE;
    delete follow.dataset["to"];
    follow.dataset["hash"] = n.hash;
    later.hidden = false;
    later.textContent = T.NOT_NOW;
    later.dataset["hash"] = n.hash;
  }
}

// Entry 10: "Not now" closes the kind change notice until the next unlock; the old kind stays in force.
el("card-notice-later").addEventListener("click", async () => {
  const hash = el<HTMLButtonElement>("card-notice-later").dataset["hash"] ?? "";
  await ask({ type: "deferServerChange", hash });
  await refresh();
});

// §12.3 "Forget this server" on the popup's own stop card and fork notice, as on the options page (design §4.4, decided
// on 2026-11-17): it deletes the logins and cards this browser captured on pages and has not saved, so with any waiting,
// or when the worker does not answer the count, the first click says how many (or that andvari cannot tell) and the
// second forgets; with none it forgets at once. Leaving the button cancels a half-armed Forget (the first click's own
// move of the focus to its line excepted).
// The second step has the guard of "Forget the earlier account" (FORGET_SECOND_STEP_AFTER_MS): it is taken only from a
// press (or a click that came with no press, as assistive technology sends it) begun a moment after the first step's
// line stood, and the first step moves the focus off the button, so two clicks in one turn, a double click or a held key
// never pass both steps; a click not taken says to read the line first, which stays.
/** Each armed button: the count its first click said, and when that line stood. */
const forgetArms = new Map<HTMLButtonElement, { count: number; at: number }>();
/** The press under way on each button (its start, or `repeat` for a held key's repeat); each click takes it. */
const forgetServerPress = new Map<HTMLButtonElement, number | "repeat">();
async function popupCapturesNow(): Promise<number> {
  try {
    const s = await ask({ type: "status" });
    return typeof s?.unsavedCaptures === "number" ? s.unsavedCaptures : COUNT_UNKNOWN;
  } catch {
    return COUNT_UNKNOWN;
  }
}
/** True when this click forgets; otherwise it armed [b] and said the count. */
async function forgetSecondClick(b: HTMLButtonElement): Promise<boolean> {
  // Read before anything is awaited: the click's own press, and its time.
  const press = forgetServerPress.get(b) ?? null;
  forgetServerPress.delete(b);
  const began = press ?? performance.now();
  const armed = forgetArms.get(b);
  if (armed !== undefined && (began === "repeat" || began < armed.at + FORGET_SECOND_STEP_AFTER_MS)) {
    showMsg("info", `${T.FORGET_SERVER_READ_FIRST}\n${forgetUnsavedLine(armed.count) ?? ""}`);
    return false;
  }
  const now = await popupCapturesNow();
  const step = unsavedArmStep(armed?.count ?? null, now, false);
  if (step.act) {
    forgetArms.delete(b);
    return true;
  }
  forgetArms.set(b, { count: step.armed!, at: performance.now() });
  b.textContent = T.FORGET_CONFIRM;
  showMsg("info", forgetUnsavedLine(now) ?? "");
  // The focus leaves the button for the line, so a key still held does not press it again.
  const msg = el("msg");
  msg.tabIndex = -1;
  msg.focus();
  return false;
}
function disarmForget(b: HTMLButtonElement): void {
  if (!forgetArms.has(b)) return;
  forgetArms.delete(b);
  b.textContent = T.FORGET_THIS_SERVER;
  clearMsg();
}
for (const id of ["card-notice-follow", "confirm-server-not-mine"]) {
  const b = el<HTMLButtonElement>(id);
  b.addEventListener("pointerdown", () => void forgetServerPress.set(b, performance.now()));
  b.addEventListener("keydown", (e: KeyboardEvent) => void forgetServerPress.set(b, e.repeat ? "repeat" : performance.now()));
  // Leaving the button cancels a half-armed Forget, except for the first click's own move to its line.
  b.addEventListener("blur", (e: FocusEvent) => {
    if (e.relatedTarget !== el("msg")) disarmForget(b);
  });
}

// §4.4: one tap follows a move (the browser's access to the new address is asked first, in this gesture) or a kind change.
el("card-notice-follow").addEventListener("click", async () => {
  const b = el<HTMLButtonElement>("card-notice-follow");
  if (b.dataset["forget"] === "1") {
    if (!(await forgetSecondClick(b))) return;
    const r = await ask({ type: "forgetServer" });
    if (!r?.ok) showMsg("err", T.FORGET_FAILED);
    await renderServerOrigin();
    await refresh();
    return;
  }
  const to = b.dataset["to"];
  const hash = b.dataset["hash"] ?? "";
  if (to) {
    const pattern = originMatchPattern(to);
    let granted = false;
    try {
      granted = pattern !== null && (await chrome.permissions.request({ origins: [pattern] }));
    } catch {
      granted = false;
    }
    if (!granted) {
      showMsg("err", chooseServerCopy("no_permission"));
      return;
    }
  }
  const r = await ask({ type: "followServerChange", hash });
  // A move this browser can't follow because it already knows the new address says so in the approved words, naming it.
  if (!r?.ok) {
    if (r?.code === "pin_conflict" && to) showMsg("err", moveNotFollowedCopy(to), CARD_MOVE_NOT_FOLLOWED_TITLE);
    else showMsg("err", chooseServerCopy(r?.code));
  }
  await renderServerOrigin();
  await refresh();
});

// §12.2: "andvari" — the public instance, pinned from its baked card. The browser's access is asked in this gesture.
el("confirm-server-public").addEventListener("click", async () => {
  let granted = false;
  try {
    granted = await chrome.permissions.request({ origins: [`${PUBLIC_INSTANCE.origin}/*`] });
  } catch {
    granted = false;
  }
  if (!granted) {
    showMsg("err", chooseServerCopy("no_permission"));
    return;
  }
  showMsg("info", T.CHECKING_CARD);
  const r = await ask({ type: "chooseServer", choice: "public" });
  if (!r?.ok) showTitled("err", chooseServerMessage(r, PUBLIC_INSTANCE.origin));
  else clearMsg();
  await renderServerOrigin();
  await refresh();
});

function relocked(): void {
  pinFallback = false; // a fresh relock re-offers the quick-unlock PIN if the SW armed one
  showView(false);
  // a11y 4a: a mid-session relock hid the unlocked view under focus — move focus to a real
  // element (#email) instead of letting it fall to <body>. showMsg is a live region (2a) so
  // the reason is announced. (Safari has no email field: its one button takes the focus.)
  if (BUILD_TARGET === "safari") renderAppLocked(false);
  el(BUILD_TARGET === "safari" ? "app-unlock" : "email").focus();
  showMsg("info", T.SESSION_LOCKED);
  // Re-query status so an armed quick-unlock (an idle autolock ARMS it — spec 01 §8.4) shows its PIN
  // field; refresh() refines the focus + lock-notice (an idle notice supersedes the message above).
  void refresh();
}

async function loadUnlocked(): Promise<void> {
  const tab = await activeTabPage();
  tabPage = tab?.page ?? null;
  const siteLabel = el("site-label");
  const siteList = el("site-list");
  if (tab) {
    const host = tab.host;
    siteLabel.hidden = false;
    siteList.hidden = false;
    siteLabel.textContent = fillApproved(T.THIS_SITE_FOR, host);
    const r = await ask({ type: "matches", host: tab.page });
    if (!r || r.locked) return relocked();
    renderList(siteList, r.matches, fillApproved(T.NO_LOGIN_FOR, host), true);
  } else {
    // No usable page URL (chrome://, new tab, detached popup) — nothing to match against.
    siteLabel.hidden = true;
    siteList.hidden = true;
  }
  const all = await ask({ type: "allItems" });
  if (!all || all.locked) return relocked();
  const n = all.items.length;
  el("count").textContent = fillApproved(n === 1 ? T.LOGINS_IN_HOARD_ONE : T.LOGINS_IN_HOARD, String(n));
  renderList(el("all-list"), all.items, T.HOARD_EMPTY);
  const cards = await ask({ type: "cardItems" });
  if (!cards || cards.locked) return relocked();
  // S3: may we offer in-page card fill for this tab? (popup-only query; the SW derives the
  // origin). The SW answers off its registry IMMEDIATELY and fires a rescan broadcast; the one
  // delayed re-query below is what picks up a form the rescan just surfaced (CSS-revealed step,
  // bfcache return) — freshness without an inline wait on the popup's critical path.
  // A build without in-page card fill (cardfillflag.ts) asks nothing: its rows copy, and one line says where cards are
  // filled from.
  if (!CARD_FILL) {
    cardFill = { fillable: false, origin: null, frames: [], pageFormOnly: false, fillOff: true };
    renderCards(cards.items);
    startTotp();
    if (BUILD_TARGET !== "safari") el<HTMLInputElement>("search").focus();
    return;
  }
  const offer = await ask({ type: "cardFillOffers" });
  cardFill = cardFillOf(offer);
  renderCards(cards.items);
  window.setTimeout(() => {
    void (async () => {
      const o2 = cardFillOf(await ask({ type: "cardFillOffers" }));
      // [U21] pinned: the re-query diffs the reasons too — a late report from a provider's frame must surface its Fill,
      // and a late one from the page's own form the line that says why the rows copy instead.
      if (o2.fillable !== cardFill.fillable || o2.origin !== cardFill.origin || JSON.stringify(o2.frames) !== JSON.stringify(cardFill.frames) || o2.pageFormOnly !== cardFill.pageFormOnly || o2.allowOrigin !== cardFill.allowOrigin || o2.allowEverywhere !== cardFill.allowEverywhere || o2.doubled !== cardFill.doubled || o2.noFrameOrigin !== cardFill.noFrameOrigin || o2.mixed !== cardFill.mixed) {
        cardFill = o2;
        const c2 = await ask({ type: "cardItems" });
        if (c2 && !c2.locked) renderCards(c2.items);
      }
    })();
  }, 350);
  startTotp();
  // Safari on iOS: no focus on the search field. It would raise the keyboard over the list the moment it appears.
  if (BUILD_TARGET !== "safari") el<HTMLInputElement>("search").focus();
}

/** The worker's card offer for the active tab, as the popup keeps it (nothing fillable when it did not answer). */
function cardFillOf(offer: Res<"cardFillOffers"> | undefined | null): typeof cardFill {
  if (!offer) return { fillable: false, origin: null, frames: [], pageFormOnly: false };
  const frames = Array.isArray(offer.frames)
    ? offer.frames
        .filter((f) => typeof f?.frameId === "number" && typeof f?.origin === "string" && Array.isArray(f?.kinds))
        .map((f) => ({
          frameId: f.frameId, origin: f.origin, kinds: f.kinds.filter((k): k is CardFieldKind => typeof k === "string" && k in CARD_DETAIL_WORDS),
          ancestors: Array.isArray(f.ancestors) && f.ancestors.every((a) => typeof a === "string") ? f.ancestors : null,
        }))
    : [];
  return {
    fillable: offer.fillable,
    origin: offer.origin,
    frames,
    pageFormOnly: offer.pageFormOnly === true,
    ...(typeof offer.allowOrigin === "string" ? { allowOrigin: offer.allowOrigin } : {}),
    ...(offer.allowEverywhere === true ? { allowEverywhere: true } : {}),
    ...(offer.doubled === true ? { doubled: true } : {}),
    ...(offer.noFrameOrigin === true ? { noFrameOrigin: true } : {}),
    ...(offer.fillOff === true ? { fillOff: true } : {}),
    ...(offer.mixed === true ? { mixed: true } : {}),
  };
}

/** activeTab (granted by opening the popup) exposes the page URL on http/https only. The worker is told the page's
 *  ORIGIN (`page`), scheme included, because a plain-http page matches only an address saved as http (spec 05
 *  autofill (e)); `host` is what the popup shows. */
async function activeTabPage(): Promise<{ host: string; page: string } | null> {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabPageOf(tabs[0]?.url);
  } catch {
    return null;
  }
}

/** F80 port (web Sigil.tsx): the ᛅ/ᛝ marks as inline SVG — the runic codepoints render as tofu
 *  wherever no installed font covers the Runic block, and the CSP posture (self-contained, nothing
 *  loads over the network) bars shipping one. Both draw in currentColor, so the existing
 *  .sigil/.glyph color tokens keep working in both themes. The rune is the brand's (brand.ts,
 *  assets/brand/andvari-rune.svg); the empty-hoard diamond is drawn here, as web's EmptySigil. */
const SVG_NS = "http://www.w3.org/2000/svg";
function sigilSvg(mark: "brand" | "empty", size: number): SVGSVGElement {
  if (mark === "brand") return runeSvg(size);
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  // ᛝ (Ingwaz), reduced to its enclosing diamond.
  const p = document.createElementNS(SVG_NS, "path");
  p.setAttribute("d", "M12 4.5 19 12l-7 7.5L5 12Z");
  svg.append(p);
  return svg;
}

/** H133 (audit 2026-09-13): `emptyText` is a SENTENCE — the web empties ("Your hoard is empty.
 *  Add your first secret.", "Nothing matches that search.") all carry terminal punctuation and the
 *  popup's three dropped it, which is the drift a reader notices when they use both surfaces in the
 *  same session. copy.test.ts fails if a caller passes an unpunctuated empty back in. */
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
 *  row can't be a <button> itself). a11y-webext--5: the container is no longer a role="button"
 *  either — that recreated the same invalid structure semantically, since ARIA's `button` role is
 *  Children-Presentational and this row CONTAINS the TOTP chip and the copy buttons. The named
 *  open-control is now the `.body` block (glyph aside, chip and copies as siblings), so the tab
 *  order reads open → chip → copy, each a valid control, and the row's accessible name is the item
 *  name + username instead of a button that swallows its own children. Fill moved INTO the detail
 *  as an explicit action: a blind row-click fill fails on every non-fillable tab. */
function row(it: MatchItem): HTMLElement {
  const r = document.createElement("div");
  r.className = "item";

  const glyph = document.createElement("span");
  glyph.className = "glyph";
  const initial = it.name.trim().charAt(0).toUpperCase();
  if (initial) glyph.textContent = initial;
  else glyph.append(sigilSvg("brand", 15)); // a nameless login falls back to the mark, not a tofu rune

  const body = document.createElement("div");
  body.className = "body";
  body.setAttribute("role", "button"); // the row's ONE named control — nothing interactive inside it
  body.tabIndex = 0;
  body.title = T.VIEW_DETAILS;
  const name = document.createElement("div");
  name.className = "name";
  name.textContent = it.name;
  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = it.username ?? T.NO_USERNAME;
  body.append(name, sub);

  r.append(glyph, body);
  if (it.hasTotp) r.append(totpChip(it.itemId));

  const acts = document.createElement("span");
  acts.className = "acts";
  if (it.username) acts.append(actBtn(T.BTN_USER, T.COPY_USERNAME, (btn) => void copyUsername(it, btn)));
  if (copiesLongLivedSecrets()) acts.append(actBtn(T.BTN_PASS, T.COPY_PASSWORD, (btn) => void copyPassword(it, btn)));
  r.append(acts);

  const open = () => openDetail(it);
  r.addEventListener("click", open); // the whole row stays a pointer target (the glyph, the padding)
  body.addEventListener("keydown", (e) => {
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
    btn.textContent = T.BTN_SHOW;
    return;
  }
  const r = await ask({ type: "reveal", itemId: it.itemId, host: tabPage ?? "", explicit: true });
  if (!r?.ok || r.secret?.password == null) {
    // #23: canon copy, never the SW's raw `error` debug detail (the messages.ts contract).
    showMsg("err", r?.ok ? T.NO_PASSWORD_ON_ITEM : revealErrorCopy(r?.code));
    return;
  }
  value.textContent = r.secret.password;
  value.dataset["shown"] = "1";
  btn.textContent = T.BTN_HIDE;
}

function renderDetail(it: MatchItem): void {
  el("detail-name").textContent = it.name || T.LOGIN_UNNAMED;
  const body = el("detail-body");
  body.replaceChildren();

  if (it.username) {
    const { field, value, acts } = detailField(T.USERNAME_LABEL);
    value.textContent = it.username;
    acts.append(actBtn(T.BTN_COPY, T.COPY_USERNAME, (btn) => void copyUsername(it, btn)));
    body.append(field);
  }

  {
    const { field, value, acts } = detailField(T.PASSWORD_LABEL);
    value.classList.add("secret");
    value.textContent = "••••••••••";
    acts.append(actBtn(T.BTN_SHOW, T.REVEAL_PASSWORD, (btn) => void toggleReveal(it, value, btn)));
    if (copiesLongLivedSecrets()) acts.append(actBtn(T.BTN_COPY, T.COPY_PASSWORD, (btn) => void copyPassword(it, btn)));
    body.append(field);
  }

  if (it.hasTotp) {
    const field = document.createElement("div");
    field.className = "detail-field";
    const lab = document.createElement("div");
    lab.className = "detail-label";
    lab.textContent = T.ONE_TIME_CODE_LABEL;
    field.append(lab, totpChip(it.itemId)); // joins the list's 1 s ticker (queried by class)
    body.append(field);
  } else if (!it.readOnly) {
    // TOTP-add (design 2026-08-12): only a code-LESS login gets the affordance — the seam is
    // ADD-ONLY (setTotp answers `exists` regardless of what a surface renders), so replacing or
    // removing an existing code stays a web-vault edit and this branch never shows beside a chip.
    // G21: and only for a login this user can WRITE — a reader-role shared vault refuses the push
    // (SW setTotp is the honest backstop), so don't offer a paste-add that can only dead-end.
    body.append(totpAddField(it));
  }

  // Saved sites — each uri sanitized to an http(s) link (a saved uri could be javascript:/
  // data:; those render as inert text, never a clickable target).
  const sites = document.createElement("div");
  sites.className = "detail-field";
  const sitesLabel = document.createElement("div");
  sitesLabel.className = "detail-label";
  sitesLabel.textContent = it.uris.length > 1 ? T.SITES_LABEL : T.SITE_LABEL;
  sites.append(sitesLabel);
  if (it.uris.length === 0) {
    const none = document.createElement("div");
    none.className = "detail-value muted";
    none.textContent = T.NO_SITE_SAVED;
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
  fill.textContent = T.FILL_THIS_PAGE;
  fill.title = T.FILL_THIS_PAGE_TITLE;
  fill.addEventListener("click", () => void fillItem(it.itemId));
  body.append(fill);
}

/** The login detail's button that adds a one-time code, in the design's term (it said "(2FA)" before 2026-11-17). */
const ADD_TOTP_LABEL = T.ADD_TOTP_LABEL;

/** TOTP-add paste row (design 2026-08-12). The input accepts whatever the enrollment page
 *  offers — the full otpauth:// link or the bare "can't scan?" setup key — and the SW runs the
 *  shared normalize + parse-accept gate on the write (this surface validates nothing; rendering
 *  the honest code copy is its whole error story). On success the SW's session copy is already
 *  updated (putExisting mutates in place), so re-rendering the detail immediately shows the
 *  live code chip. */
function totpAddField(it: MatchItem): HTMLElement {
  const { field, value, acts } = detailField(T.ONE_TIME_CODE_LABEL);
  value.classList.add("muted");
  value.textContent = T.TOTP_NONE;
  const add = actBtn(T.BTN_ADD, ADD_TOTP_LABEL, () => {
    const row = value.parentElement;
    if (!row) return;
    const form = document.createElement("div");
    form.className = "totp-add";
    const input = document.createElement("input");
    input.type = "text";
    input.className = "mono";
    input.placeholder = T.TOTP_SECRET_HINT;
    input.setAttribute("aria-label", T.TOTP_SECRET_LABEL);
    const save = document.createElement("button");
    save.type = "button";
    save.className = "fill-btn";
    save.textContent = T.TOTP_SAVE_BUTTON;
    save.title = T.TOTP_ADD_TITLE;
    save.setAttribute("aria-label", save.title);
    const submit = async (): Promise<void> => {
      const raw = input.value.trim();
      if (raw === "") {
        input.focus();
        return;
      }
      save.disabled = true;
      input.disabled = true;
      const r = await ask({ type: "setTotp", itemId: it.itemId, totp: raw });
      if (r?.ok) {
        input.value = ""; // never leave the secret sitting in the DOM
        it.hasTotp = true; // the SW's session copy already carries it (putExisting mutates in place)
        renderDetail(it); // the row becomes the live code chip
        showMsg("info", TOTP_ADDED); // polite, not alert — the chip appearing is the real confirmation
        return;
      }
      save.disabled = false;
      input.disabled = false;
      showMsg("err", totpAddErrorCopy(r?.code));
      input.focus();
    };
    save.addEventListener("click", () => void submit());
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void submit();
    });
    form.append(input, save);
    row.replaceWith(form); // one-shot swap; Back/reopen renders the detail fresh
    input.focus();
  });
  acts.append(add);
  return field;
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
  announce(T.COPIED_CLEARS_SOON); // a11y 2d + Cut J (v2 #10): disclose the auto-wipe
  btn.textContent = "✓";
  btn.classList.add("did");
  window.setTimeout(() => {
    btn.textContent = btn.dataset["label"] ?? "";
    btn.classList.remove("did");
  }, FLASH_MS);
}

/**
 * Whether this popup copies a password, a card number or a security code (round-5 review C4). Not in the Safari build:
 * a copy from a web page goes to the general pasteboard, which Universal Clipboard carries to the person's other
 * devices, and nothing clears it (the popup's timer dies with the sheet, and the worker cannot write the clipboard
 * there). Apple's documentation does not say that the extension's native handler may write the pasteboard (where the
 * app's own copies are local-only and expire), so there is no safe copy here: those are filled, or copied in the app.
 * The username, a one-time code (valid for seconds), the expiry and the name on a card are still copied.
 */
function copiesLongLivedSecrets(): boolean {
  return BUILD_TARGET !== "safari";
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

async function fillItem(itemId: string, confirmedOtherSite?: string): Promise<void> {
  // The page this popup showed rides along: the worker fills only while the tab is still on it (the tab may have moved).
  const page = tabPage ?? undefined;
  const r = await ask(confirmedOtherSite === undefined ? { type: "fillFromPopup", itemId, page } : { type: "fillFromPopup", itemId, confirmedOtherSite, page });
  if (r?.needsConfirm) {
    confirmOtherSite(itemId, r.needsConfirm);
    return;
  }
  // Cut M (v2 #14): ok is now the FILL outcome (the content script's ground truth), not message
  // delivery — close only when something actually landed in the page; otherwise stay open and
  // render the canon sentence for the seam code (never the SW's raw `error` debug string).
  if (r?.ok) {
    window.close(); // the fill really landed in the page
  } else {
    showMsg("err", fillErrorCopy(r?.code));
  }
}

/**
 * Every build: a login saved for one site is about to be filled on another. Nothing has been filled yet; this names both
 * sites as the worker named them (the schemes where the hosts are the same, a plain-http page as not secure) and, under a
 * long host, the site the page belongs to, and fills only on a second, explicit tap. Every string is textContent; the
 * box lets a host with no break point wrap (popup.css).
 */
function confirmOtherSite(itemId: string, q: OtherSiteQuestion): void {
  document.getElementById("other-site-confirm")?.remove();
  const box = document.createElement("div");
  box.id = "other-site-confirm";
  box.setAttribute("role", "alertdialog");
  box.style.cssText = "margin:8px 0;padding:10px;border:1px solid currentColor;border-radius:8px";
  const text = document.createElement("p");
  text.style.margin = "0 0 8px";
  text.textContent = fillApproved(T.FILL_OTHER_SITE, q.savedFor, q.page);
  const lines: HTMLElement[] = [text];
  if (q.domain !== null) {
    const site = document.createElement("p");
    site.style.margin = "0 0 8px";
    site.textContent = fillApproved(T.FILL_OTHER_SITE_DOMAIN, q.domain);
    lines.push(site);
  }
  const fill = document.createElement("button");
  fill.type = "button";
  fill.className = "primary";
  fill.textContent = fillApproved(T.FILL_ON, q.page);
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "link dim";
  cancel.textContent = T.CANCEL;
  cancel.addEventListener("click", () => box.remove());
  fill.addEventListener("click", () => {
    box.remove();
    void fillItem(itemId, q.confirm); // the yes is for this login on this page, and the worker holds it to both
  });
  box.append(...lines, fill, cancel);
  el("msg").insertAdjacentElement("afterend", box);
  cancel.focus();
}

/** The list payload already carries the username (safe subset) — no reveal round-trip. */
async function copyUsername(it: MatchItem, btn: HTMLElement): Promise<void> {
  if (it.username && (await toClipboard(it.username))) flash(btn);
}

async function copyPassword(it: MatchItem, btn: HTMLElement): Promise<void> {
  const r = await ask({ type: "reveal", itemId: it.itemId, host: tabPage ?? "", explicit: true });
  if (!r?.ok || r.secret?.password == null) {
    // #23: canon copy, never the SW's raw `error` debug detail (the messages.ts contract).
    showMsg("err", r?.ok ? T.NO_PASSWORD_ON_ITEM : revealErrorCopy(r?.code));
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
  chip.title = T.COPY_TOTP;
  // a11y 3b: a STABLE name (the live 6-digit code as the name would re-announce every second).
  chip.setAttribute("aria-label", T.COPY_TOTP);
  const ring = document.createElement("span");
  ring.className = "ring";
  ring.setAttribute("aria-hidden", "true"); // decorative countdown visual (5b conveys it as text)
  const code = document.createElement("span");
  code.className = "code";
  // Safari: no live code is shown (it is released only on a copy), so the chip says what a tap does.
  code.textContent = BUILD_TARGET === "safari" ? T.COPY_CODE_CHIP : "······";
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
  // `forCopy` (H69, 2026-09-13 audit): this send is the user's click, not the ticker's render, so
  // the SW counts it as a use of the item — the G37 rule desktop, Android and web already follow.
  // tickTotp's poll deliberately omits the flag; see the messages.ts contract for why.
  const r = await ask({ type: "totp", itemId, forCopy: true });
  if (!r?.ok || !r.code) return;
  if (await toClipboard(r.code)) {
    announce(T.TOTP_COPIED); // a11y 2d (the chip's "copied" text is aria-hidden)
    codeEl.textContent = T.COPIED_FLASH;
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
  // Safari: a code is released only when the person copies it (appvault.ts), so there is nothing to tick. Asking
  // anyway got "no code" every second and hid each chip a second after it was drawn — the popup's flicker.
  if (BUILD_TARGET === "safari") return;
  // quality-perf--4: the asks go out CONCURRENTLY. Serially awaiting one message per chip made the
  // codes flip visibly staggered across the second at double-digit chip counts, and stretched the
  // popup⇄SW round-trips over the whole tick. No protocol change — same N messages, in flight at
  // once — so the SW's per-item handler is untouched.
  const chips = [...document.querySelectorAll<HTMLElement>(".totp-chip")];
  const answers = await Promise.all(
    chips.map(async (chip) => {
      const itemId = chip.dataset["item"];
      return itemId ? await ask({ type: "totp", itemId }) : undefined;
    }),
  );
  chips.forEach((chip, i) => {
    const code = chip.querySelector<HTMLElement>(".code");
    const ring = chip.querySelector<HTMLElement>(".ring");
    if (!chip.dataset["item"] || !code || !ring) return;
    const r = answers[i];
    if (r?.ok && r.code) {
      if (Date.now() >= Number(code.dataset["hold"] ?? 0)) {
        code.textContent = r.code.replace(/^(\d{3})(\d{3})$/, "$1 $2");
      }
      ring.style.setProperty("--p", String(((r.secondsLeft ?? 0) / TOTP_PERIOD_S) * 100));
      const secsId = chip.getAttribute("aria-describedby"); // a11y 5b: refresh seconds-left desc
      const secs = secsId ? document.getElementById(secsId) : null;
      if (secs) secs.textContent = fillApproved(T.SECONDS_LEFT, String(r.secondsLeft ?? 0));
    } else {
      chip.hidden = true; // locked mid-poll / item no longer carries a code
    }
  });
}

/* ---- cards: copy group beneath the logins (cards design 2026-07-09; S3 in-page fill 2026-07-10)
 * Rows reuse the login-row styling. The row shows the masked identity line only; number/expiry/CVV
 * go straight from the SW to the clipboard (copyPassword's exact path), never into this DOM. When
 * the active tab holds a payment provider's card form (cardFillOffers; owner decision 2026-11-14),
 * each row also offers a Fill button that shows the provider's origin — the trusted, unspoofable
 * surface for the egress grant ([A2]/R1). */

const cardsLabel = document.createElement("div");
cardsLabel.className = "section-label";
cardsLabel.textContent = T.CARDS_LABEL;
cardsLabel.hidden = true;
const cardsList = document.createElement("div");
cardsList.className = "list";
cardsList.hidden = true;
/** The one line that says why the rows copy instead of filling (owner decision 2026-11-14): a payment provider's form
 *  the page shows, on a site andvari may not run on (its origin, to allow); the page takes the card in its own fields;
 *  or (Safari) andvari is not running on the page at all (allow it on Every Website). Shown only while the SW reports
 *  one of them; the Fill button never renders then (cardRow gates Fill on `fillable` alone). */
const cardsPspNote = document.createElement("div");
cardsPspNote.className = "empty slim";
cardsPspNote.hidden = true;
/** Round-13 review: card fields tapped in two payment forms fill neither; Start over lets every choice go, and the person
 *  taps the one form they mean. */
const cardsStartOver = document.createElement("button");
cardsStartOver.type = "button";
cardsStartOver.className = "link";
cardsStartOver.textContent = T.START_OVER;
cardsStartOver.hidden = true;
cardsStartOver.addEventListener("click", () => {
  void (async () => {
    cardsStartOver.disabled = true;
    await ask({ type: "clearCardChoices" });
    cardFill = cardFillOf(await ask({ type: "cardFillOffers" }));
    const cards = await ask({ type: "cardItems" });
    cardsStartOver.disabled = false;
    if (cards && !cards.locked) renderCards(cards.items);
  })();
});
el("all-list").after(cardsLabel, cardsPspNote, cardsStartOver, cardsList);

/** What to do instead of a fill: the copy buttons, or in the Safari build (which copies no card number or code) the app. */
function cardCopyRemedy(): string {
  return copiesLongLivedSecrets() ? T.CARD_USE_COPY_BUTTONS : T.CARD_COPY_IN_APP;
}

/** The one line that says why the rows copy instead of filling; null while they fill. */
function cardCopyReason(safari: boolean): string | null {
  if (cardFill.fillOff === true) return cardFillOffLine(safari);
  if (cardFill.mixed === true) return CARD_MIXED_FORMS;
  if (cardFill.fillable) return null;
  if (cardFill.doubled === true) return CARD_DUPLICATE_FIELDS;
  if (cardFill.noFrameOrigin === true) return CARD_NO_FRAME_ORIGIN;
  if (cardFill.allowOrigin !== undefined) return cardProviderNotAllowedCopy(cardFill.allowOrigin, safari);
  if (cardFill.pageFormOnly) return CARD_PAGE_FORM;
  if (cardFill.allowEverywhere === true) return cardProviderNotAllowedCopy(undefined, safari);
  return null;
}

/** Empty = hidden: login-only hoards see no Cards group at all. */
function renderCards(items: CardItem[]): void {
  cardsLabel.hidden = items.length === 0;
  cardsList.hidden = items.length === 0;
  // The line needs rows to point at ("use the copy buttons") — a cardless hoard stays bare.
  const why = cardCopyReason(BUILD_TARGET === "safari");
  cardsPspNote.hidden = items.length === 0 || why === null;
  // Without card fill in the build, the line is the remedy itself; so it is for two forms, whose remedy is Start over.
  if (why !== null) cardsPspNote.textContent = cardFill.fillOff === true || cardFill.mixed === true ? why : `${why} ${cardCopyRemedy()}`;
  cardsStartOver.hidden = items.length === 0 || cardFill.mixed !== true;
  cardsList.replaceChildren();
  for (const it of items) cardsList.append(cardRow(it));
}

/** Card row = copy-only: no click-to-fill (unlike login rows), just per-field copy buttons
 *  gated on the SW's has* flags. The subtitle is the SW's masked line ("Visa ••4242"). */
function cardRow(it: CardItem): HTMLElement {
  const r = document.createElement("div");
  r.className = "item";
  r.title = T.COPY_CARD_DETAILS;

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
    // Where the card goes, and exactly which details (round-12 review): the provider origin of the frames where the
    // person chose a field, and the details the fill writes there, by name; or the provider's own origin when none is
    // chosen yet (the Fill then asks for a tap).
    const dest = document.createElement("div");
    dest.className = "card-fill-dest";
    // Round-13 review: and the documents a frame sits in below the top one ("js.stripe.com inside rewards.example").
    dest.textContent =
      cardFill.frames.length > 0
        ? fillApproved(T.FILL_DESTINATION_DETAILS, fillDestination(cardFill.frames), cardDetailNames(cardFill.frames.flatMap((f) => f.kinds)))
        : fillApproved(T.FILL_DESTINATION, String(cardFill.origin));
    body.append(dest);
  }

  const acts = document.createElement("span");
  acts.className = "acts";
  if (cardFill.fillable) {
    acts.append(
      actBtn(
        T.BTN_FILL,
        cardFill.frames.length > 0
          ? fillApproved(T.FILL_CARD_DETAILS_INTO, cardDetailNames(cardFill.frames.flatMap((f) => f.kinds)), cardFill.origin ?? T.THE_PAGE)
          : fillApproved(T.FILL_CARD_INTO, cardFill.origin ?? T.THE_PAGE),
        (btn) => void fillCardRow(it.itemId, btn),
      ),
    );
  }
  if (it.hasNumber && copiesLongLivedSecrets()) acts.append(actBtn(T.BTN_NUM, T.COPY_CARD_NUMBER, (btn) => void copyCardField(it.itemId, "number", btn)));
  if (it.hasExpiry) acts.append(actBtn(T.BTN_EXP, T.COPY_CARD_EXPIRY, (btn) => void copyCardField(it.itemId, "expiry", btn)));
  // Tier 2 §6 copy parity: every surface copies number/expiry/name/CVV.
  if (it.hasName) acts.append(actBtn(T.BTN_NAME, T.COPY_CARD_NAME, (btn) => void copyCardField(it.itemId, "name", btn)));
  if (it.hasCvv && copiesLongLivedSecrets()) acts.append(actBtn(T.BTN_CVV, T.COPY_CARD_CVV, (btn) => void copyCardField(it.itemId, "cvv", btn)));

  r.append(glyph, body, acts);
  return r;
}

/** The card details a fill writes, by name, for the line that says where a Fill goes (round-12 review). */
const CARD_DETAIL_WORDS: Record<CardFieldKind, string> = {
  cardnumber: T.CARD_DETAIL_NUMBER,
  cardexpiry: T.CARD_DETAIL_EXPIRY,
  cardexpmonth: T.CARD_DETAIL_EXPIRY,
  cardexpyear: T.CARD_DETAIL_EXPIRY,
  cardcvv: T.CARD_DETAIL_CVV,
  cardname: T.CARD_DETAIL_NAME,
  cardtype: T.CARD_DETAIL_TYPE,
  cardpostal: T.CARD_DETAIL_POSTAL,
};

/** "card number, expiry date, security code": each detail once, in that order. */
function cardDetailNames(kinds: readonly CardFieldKind[]): string {
  const order: CardFieldKind[] = ["cardnumber", "cardexpiry", "cardexpmonth", "cardexpyear", "cardcvv", "cardname", "cardpostal", "cardtype"];
  return [...new Set(order.filter((k) => kinds.includes(k)).map((k) => CARD_DETAIL_WORDS[k]))].join(", ");
}

/** §5 partial-outcome copy: human labels per detected kind. The three expiry kinds deliberately
 *  share ONE label — "couldn't fill expiry, expiry" would read as a stutter, and the user's
 *  remedy (the expiry copy button) is the same for all three. */
const CARD_KIND_LABEL: Record<CardFieldKind, string> = {
  cardnumber: T.CARD_KIND_NUMBER,
  cardexpiry: T.CARD_KIND_EXPIRY,
  cardexpmonth: T.CARD_KIND_EXPIRY,
  cardexpyear: T.CARD_KIND_EXPIRY,
  cardname: T.CARD_DETAIL_NAME,
  cardcvv: T.CARD_DETAIL_CVV,
  cardtype: T.CARD_DETAIL_TYPE,
  cardpostal: T.CARD_DETAIL_POSTAL, // G3: a missed billing postal (no copy button — postal isn't a stored copy field)
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
  // Round-11 review: the fill goes to exactly the frames this popup showed, or to none.
  const r = await ask({ type: "fillCardFromPopup", itemId, frames: cardFill.frames });
  btn.disabled = false;
  const filled = r?.outcome?.filled;
  if (filled === "card") {
    window.close(); // the card fill really landed in the page, in full
  } else if (filled === "partial" && r?.outcome) {
    // A label can appear on BOTH sides (month filled, year missed → both read "expiry") —
    // "Filled expiry — couldn't fill expiry" is nonsense, so the missed side owns shared labels.
    const missed = cardLabels(r.outcome.missedKinds);
    const landed = cardLabels(r.outcome.filledKinds).filter((l) => !missed.includes(l));
    const remedy = copiesLongLivedSecrets() ? T.CARD_COPY_INSTEAD : T.CARD_COPY_MISSING_IN_APP;
    // Round-6 review H1: a field that can't be seen is left empty, never filled; scrolling it into view and filling
    // again is the first remedy.
    const unseen = cardLabels(r.outcome.unseenKinds ?? []);
    const why = unseen.length > 0 ? ` ${fillApproved(T.CARD_FIELDS_UNSEEN, unseen.join(", "))}` : "";
    const head = landed.length > 0 ? fillApproved(T.CARD_FILLED_SOME, landed.join(", "), missed.join(", ")) : fillApproved(T.CARD_FILLED_NONE, missed.join(", "));
    showMsg("info", `${head}${why} ${why ? remedy.charAt(0).toLowerCase() + remedy.slice(1) : remedy}`);
  } else {
    const code = r?.outcome?.code ?? r?.code;
    const remedy = code === "page_form" || code === "provider_not_allowed" || code === "duplicate_fields" || code === "no_frame_origin" ? ` ${cardCopyRemedy()}` : "";
    showMsg("err", cardFillErrorCopy(code, r?.allowOrigin, BUILD_TARGET === "safari") + remedy);
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
  renderList(el("all-list"), r.items, q ? fillApproved(T.NOTHING_MATCHES, q) : T.HOARD_EMPTY);
  renderCards(c && !c.locked ? c.items : []);
}

el<HTMLInputElement>("search").addEventListener("input", () => {
  window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => void runSearch(), 150);
});

/* ---- generator: one collapsible section; every Regenerate is a fresh SW `generate` ---- */

/** a11y-webext--10: #gen-pass is the button whose CONTENT is the generated password, and it carried
 *  aria-label="Copy generated password" — an aria-label REPLACES the content in the accessible
 *  name, so browse-mode and focus both announced only the label and the password itself was not in
 *  the a11y tree at all. A blind user could copy it but never review or transcribe it (to type on
 *  another device), and got no signal that Regenerate had changed anything. A visually-hidden
 *  PREFIX instead: the name computes as "Generated password: <pw>", per-character review works,
 *  the visible pill is unchanged, and the secrets-in-DOM posture is untouched (the password was
 *  already the button's text). The value is kept here rather than re-read from textContent, which
 *  now carries the prefix — the copy path must never ship the label with it.
 *  The static aria-label in popup.html is removed here for the same reason it is written here. */
let generatedPw = "";
function setGeneratedPassword(pw: string): void {
  const btn = el("gen-pass");
  generatedPw = pw;
  btn.removeAttribute("aria-label");
  btn.textContent = "";
  if (pw === "") return;
  const prefix = document.createElement("span");
  prefix.className = "visually-hidden";
  prefix.textContent = T.GENERATED_PASSWORD;
  btn.append(prefix, document.createTextNode(pw));
}

async function regenerate(): Promise<void> {
  const r = await ask({ type: "generate" });
  setGeneratedPassword(r?.password ?? "");
  if (generatedPw) announce(T.NEW_PASSWORD_GENERATED); // a11y 2d: Regenerate is otherwise silent
}

el("gen-toggle").addEventListener("click", () => {
  const g = el("generator");
  g.hidden = !g.hidden;
  el("gen-toggle").classList.toggle("on", !g.hidden);
  el("gen-toggle").setAttribute("aria-expanded", String(!g.hidden)); // a11y 5c
  if (!g.hidden && !generatedPw) void regenerate();
});

el("gen-again").addEventListener("click", () => void regenerate());

el("gen-pass").addEventListener("click", async () => {
  const pw = generatedPw; // NOT textContent — that now carries the visually-hidden name prefix
  if (pw && (await toClipboard(pw))) {
    announce(T.PASSWORD_COPIED); // a11y 2d
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
  btn.textContent = busy ? T.UNSEALING : T.UNLOCK;
  el("kdf").hidden = !busy;
}

async function unlock(): Promise<void> {
  if (el<HTMLButtonElement>("unlock").disabled) return; // Enter while a KDF is already running
  const email = el<HTMLInputElement>("email").value.trim();
  const pw = el<HTMLInputElement>("password");
  if (!email || !pw.value) return;
  clearMsg();
  hideForgetEarlier();
  setUnsealing(true);
  try {
    const r = await ask({ type: "unlock", email, password: pw.value });
    if (r?.ok) {
      pw.value = ""; // (A15: the worker remembers the email itself — the popup writes no storage)
      await refresh();
      showSignInNotice(r.notice);
    } else if (r?.code === "totp_required") {
      // 0.16.3: password verified server-side + keys derived (SW memory) — collect the code, no
      // second KDF. Clear the password field (a "start over" is a fresh full sign-in).
      pw.value = "";
      totpBadCount = 0;
      // The email is proven correct here (server accepted the authKey, only the code is left); the worker
      // remembered it on this answer (A15), so TOTP-enrolled accounts get it stored too.
      enterTotpChallenge(true);
    } else if (r?.code === "aborted") {
      // A server switch / lock landed mid-sign-in — the SW installed nothing; just re-render silently.
      await refresh();
    } else if (r?.code === "confirm_server") {
      // A15 review F1: a server is pending — nothing was sent. Clear the password and show the confirm route.
      pw.value = "";
      await refresh();
      showMsg("info", unlockErrorCopy(r.code));
    } else {
      // E1-3: render the coded ladder (errors.ts), never the SW's raw `error` debug detail.
      showTitled("err", unlockErrorMessage(r?.code, email));
      // Another account under a known address, and only that refusal: the offer to forget the earlier account.
      if (r?.code === "remade_account") offerForgetEarlier(email);
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

/** What a sign-in that opened the vault could not do, said after the vault is shown (the vault is open:
 *  said, not an error). */
function showSignInNotice(notice: UnlockNotice | undefined): void {
  if (notice === "session_not_saved") showMsg("info", SESSION_NOT_SAVED);
  else if (notice === "quick_unlock_not_updated") showMsg("info", QUICK_UNLOCK_NOT_UPDATED);
  else if (notice === "account_remembered") showMsg("info", ACCOUNT_REMEMBERED);
}

/* ---- "Forget the earlier account on this device" (decided on 2026-11-17): at the refusal, two steps ---- */

/**
 * The second step is taken only from a press (or, where no press came with the click, a click) this long after the
 * confirmation stood on the screen: a double click, two clicks in one turn or a held key never pass both steps before the
 * confirmation could be read, and a click from assistive technology, which comes with no press, still can.
 */
const FORGET_SECOND_STEP_AFTER_MS = 1000;
/** The worker is pinged this often while the confirmation stands, so the offer, kept in its memory, is not lost while the
 *  person reads (an idle worker is stopped after about thirty seconds); the ping is the passive `status`. */
const FORGET_KEEPALIVE_MS = 15_000;

/** The address the offer stands for; when its first step (the confirmation's text) was shown, or null before it. */
let forgetEarlier: { email: string; armedAt: number | null } | null = null;
/** The press under way on the offer's button: when it began (a pointer down, or a key down), `repeat` for a held key's
 *  repeat, null for none (the click then comes with no press). Each click takes it. */
let forgetPress: number | "repeat" | null = null;
let forgetKeepalive: ReturnType<typeof setInterval> | undefined;
function setForgetKeepalive(on: boolean): void {
  if (forgetKeepalive !== undefined) clearInterval(forgetKeepalive);
  forgetKeepalive = on ? setInterval(() => void ask({ type: "status" }), FORGET_KEEPALIVE_MS) : undefined;
}
function hideForgetEarlier(): void {
  forgetEarlier = null;
  setForgetKeepalive(false);
  el("forget-earlier").hidden = true;
}
function offerForgetEarlier(email: string): void {
  forgetEarlier = { email, armedAt: null };
  el("forget-earlier").textContent = FORGET_EARLIER_OFFER;
  el("forget-earlier").hidden = false;
}
el("forget-earlier").addEventListener("pointerdown", () => void (forgetPress = performance.now()));
el("forget-earlier").addEventListener("keydown", (e: KeyboardEvent) => {
  forgetPress = e.repeat ? "repeat" : performance.now();
});
el("forget-earlier").addEventListener("click", async () => {
  const f = forgetEarlier;
  const press = forgetPress;
  forgetPress = null;
  if (f === null) return;
  if (f.armedAt === null) {
    // The second confirmation: what goes, that it cannot be undone, and what it means if the account was not remade.
    f.armedAt = performance.now();
    showMsg("info", fillApproved(FORGET_EARLIER_CONFIRM, f.email));
    el("forget-earlier").textContent = FORGET_EARLIER_CONFIRM_BUTTON;
    // The worker stays awake while it is read (until the step is taken, the offer goes, or the popup closes).
    setForgetKeepalive(true);
    // The focus leaves the button for the confirmation, so a key still held does not press it again.
    const msg = el("msg");
    msg.tabIndex = -1;
    msg.focus();
    return;
  }
  // Only a press (or a click with no press) that began after the confirmation stood for a moment takes the second step;
  // any other click is not taken, and the popup says to read the confirmation first (which stays on the screen).
  const began = press ?? performance.now();
  if (began === "repeat" || began < f.armedAt + FORGET_SECOND_STEP_AFTER_MS) {
    showMsg("info", `${FORGET_EARLIER_READ_FIRST}\n${fillApproved(FORGET_EARLIER_CONFIRM, f.email)}`);
    return;
  }
  hideForgetEarlier();
  const r = await ask({ type: "forgetEarlierAccount", email: f.email });
  if (r?.ok) showMsg("info", FORGET_EARLIER_DONE);
  else showMsg("err", r?.code === "open" ? FORGET_EARLIER_OPEN : r?.code === "failed" ? FORGET_EARLIER_FAILED : FORGET_EARLIER_NOT_OFFERED);
});

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
  b.textContent = busy ? T.VERIFYING : T.VERIFY;
  el<HTMLButtonElement>("totp-startover").disabled = busy; // don't let "start over" race an in-flight verify
}

async function verifyTotp(): Promise<void> {
  const input = el<HTMLInputElement>("totp-code");
  const code = input.value.replace(/\D/g, ""); // paste "123 456" → "123456" (maxlength would truncate first)
  if (el<HTMLButtonElement>("totp-verify").disabled) return;
  if (code.length < 6) {
    showMsg("info", T.ENTER_ALL_DIGITS); // not a silent no-op (a11y: SR announces it)
    input.focus();
    return;
  }
  clearMsg();
  hideForgetEarlier();
  setTotpVerifying(true);
  try {
    const r = await ask({ type: "unlockTotp", code });
    if (r?.ok || r?.code === "aborted") {
      // ok → unlocked; aborted → a switch/lock re-rendered us. Either way just re-render (no error).
      totpBadCount = 0;
      input.value = "";
      exitTotpChallenge();
      await refresh();
      if (r?.ok) showSignInNotice(r.notice);
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
    if (capped) showMsg("err", T.TOO_MANY_WRONG_CODES);
    else {
      showTitled("err", unlockErrorMessage(r?.code, el<HTMLInputElement>("email").value.trim()));
      const email = el<HTMLInputElement>("email").value.trim();
      // The same refusal at the code step: the same offer to forget the earlier account (the worker raised it there too).
      if (r?.code === "remade_account") offerForgetEarlier(email);
    }
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
el<HTMLInputElement>("email").addEventListener("input", () => renderPasswordLabel());
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
  el("qu-settings-state").textContent = qu.enrolled ? T.QUICK_UNLOCK_IS_ON : T.QUICK_UNLOCK_IS_OFF;
  el("qu-toggle").textContent = qu.enrolled ? T.TURN_OFF : T.SET_UP;
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
      if (r.notice === "quick_unlock_not_updated") showMsg("info", QUICK_UNLOCK_NOT_UPDATED); // the vault is open: said, not an error
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
  showMsg("info", T.OPENING_UNLOCK_PROMPT);
  try {
    const r = await ask({ type: "unlockWithBio" });
    if (r?.ok) {
      clearMsg();
      await refresh();
      if (r.notice === "quick_unlock_not_updated") showMsg("info", QUICK_UNLOCK_NOT_UPDATED); // the vault is open: said, not an error
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
  showMsg("info", T.OPENING_SETUP_PROMPT);
  const r = await ask({ type: "enrollQuickUnlockBio" });
  if (!r) return; // popup closed when the connector opened — the reopened popup shows the result
  if (r.ok) {
    el("qu-enroll").hidden = true;
    showMsg("info", T.DEVICE_QUICK_UNLOCK_ON);
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
      showMsg("info", T.QUICK_UNLOCK_ON_HERE);
      await refresh();
    } else if (r?.code === "switched_off") {
      // Switched off in another window while this was set up: nothing is on, said plainly (not an error).
      pinEl.value = "";
      el("qu-enroll").hidden = true;
      await refresh();
      showMsg("info", enrollErrorCopy(r.code));
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
  if (el("qu-settings-state").textContent === T.QUICK_UNLOCK_IS_ON) {
    await ask({ type: "disableQuickUnlock" }); // wipe — no auth gate (§8.1 parity)
    showMsg("info", T.QUICK_UNLOCK_TURNED_OFF);
    await refresh();
  } else {
    openEnroll();
  }
});
/** ux-parity--1: sign-out was a ONE-CLICK unconfirmed wipe here while every other surface confirms
 *  (desktop and Android both raise a dialog; web confirms on unsynced changes) — and a mis-click in
 *  this footer, one button away from "Lock", destroys the browser's quick-unlock enrollment, so the
 *  user has to re-run the PIN or biometric setup to get back to where they were. The popup has no
 *  dialog surface and shouldn't grow one for this, so the confirm is the house's OWN inline idiom:
 *  the options page's two-click arm, disarmed on blur, with the consequence stated in the live
 *  message region (which the SR user hears, per a11y 2a). */
// Design §4.4 (decided on 2026-11-17): both say first how many captured logins and cards were not saved, which they
// delete (unsavedarm.ts), and a count that moved between the two clicks arms again with the new number.
let signOutArmed: number | null = null;
const signOutLabel = T.SIGN_OUT;
function disarmSignOut(): void {
  if (signOutArmed === null) return;
  signOutArmed = null;
  el("sign-out").textContent = signOutLabel;
}
/** What is at stake now: the captures not saved, and whether they can still be saved (an open vault, its session live). */
async function unsavedNow(): Promise<{ count: number; canSave: boolean }> {
  const st = await ask({ type: "status" });
  return { count: st?.unsavedCaptures ?? 0, canSave: st?.unlocked === true && st.serverEnded !== true };
}
el("sign-out").addEventListener("click", async () => {
  const now = await unsavedNow();
  const step = unsavedArmStep(signOutArmed, now.count, true);
  if (!step.act) {
    signOutArmed = step.armed;
    el("sign-out").textContent = T.SIGN_OUT_CONFIRM;
    const line = unsavedCapturesLine("signout", now.count, now.canSave);
    showMsg("info", line === null ? T.SIGN_OUT_EXPLAINED : `${T.SIGN_OUT_EXPLAINED} ${line}`);
    return;
  }
  disarmSignOut();
  const out = await ask({ type: "signOut" }); // full wipe: blob + co-key + tokens + session (spec 01 §8.4)
  clearMsg();
  pinFallback = false;
  await refresh();
  // A session of that account whose end the server could not confirm: said at this moment, with how to end it.
  if (out?.notice === "session_not_confirmed") showMsg("info", SIGN_OUT_NOT_CONFIRMED);
});
el("sign-out").addEventListener("blur", disarmSignOut); // any move away cancels a half-armed confirm

/* ---- footer ---- */

let lockArmed: number | null = null;
function disarmLock(): void {
  if (lockArmed === null) return;
  lockArmed = null;
  el("lock").textContent = T.LOCK;
}
// The button's word is the LOCK line's, filled at load: popup.html carries the same word only until this runs.
el("lock").textContent = T.LOCK;
el("lock").addEventListener("click", async () => {
  const now = await unsavedNow();
  const step = unsavedArmStep(lockArmed, now.count, false);
  if (!step.act) {
    lockArmed = step.armed;
    el("lock").textContent = T.LOCK_CONFIRM;
    showMsg("info", unsavedCapturesLine("lock", now.count, now.canSave) ?? "");
    return;
  }
  disarmLock();
  await ask({ type: "lock" });
  clearMsg();
  await refresh();
});
el("lock").addEventListener("blur", disarmLock);

/** Open a page on the configured server (design §5.1 — the origin is asked of the worker on
 *  every click, never cached in the popup). window.close() only
 *  AFTER tabs.create resolves: a closed popup's pending promise continuations never run. */
async function openServerPage(path = ""): Promise<void> {
  const base = await currentServer();
  if (base === null) {
    // A15 review S3 / F1: no answer from the worker, or a server pending — open nothing (never a guessed default).
    showMsg("err", T.CANT_TELL_SERVER);
    return;
  }
  try {
    await chrome.tabs.create({ url: base + path });
  } catch {
    /* tab creation refused — leave the popup open rather than silently doing nothing */
    return;
  }
  window.close();
}

el("open-vault").addEventListener("click", () => void openServerPage());

// Cut H (v2 #6): a forgotten master password — the locked popup is not a dead end. The
// extension recovers nothing (design §12.2, §10: recovery runs in a full client), so the link says where to go instead
// of opening the web app's old recovery route.
el("forgot").addEventListener("click", () => showMsg("info", RECOVER_IN_APP));

el("ping").addEventListener("click", async () => {
  showMsg("info", "…");
  const r = await ask({ type: "ping" });
  setConn(r?.ok === true, r?.code === "confirm_server");
  // #23: the conn-status twin's sentence — the old line leaked a raw epoch (`t=1752…`).
  if (r?.ok) showMsg("info", T.SERVER_REACHABLE_DONE);
  else if (r?.code === "confirm_server") showMsg("err", CONFIRM_SERVER_FIRST); // A15 review F1: nothing was dialed
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
 *  header, middle-truncated to fit, with the FULL origin on title + aria-label (hover/focus). Asked
 *  of the worker every open — never cached — so it shows the origin the worker actually dials. */
async function renderServerOrigin(): Promise<void> {
  const info = await ask({ type: "serverInfo" });
  const node = el("server-origin");
  // A15 review F1 / S3: the header names the server in effect only when there is one. A pending server (the card below
  // says why) or a worker that did not answer is said in words — never shown as the default, which would be a lie on
  // an anti-phishing display.
  const origin = info && typeof info.url === "string" && info.url && !info.block ? info.url : null;
  if (origin === null) {
    const why =
      BUILD_TARGET === "safari" || info?.block?.kind === "no_server"
        ? T.NO_SERVER_YET
        : info?.block?.kind === "fork" || info?.block?.kind === "pin_damaged"
          ? T.SERVER_STOPPED
          : T.SERVER_UNKNOWN;
    node.textContent = why;
    node.title = why;
    node.setAttribute("role", "note");
    node.setAttribute("aria-label", why);
    if (BUILD_TARGET === "safari") void renderServerDetails(node, info === undefined);
    return;
  }
  // Safari: the Details stay reachable (collapsed) while the app-backed vault is being proven on devices; they show
  // whether the native handler's process survived between the unlock and a fill.
  if (BUILD_TARGET === "safari") void renderServerDetails(node, false);
  else document.getElementById("server-details")?.remove();
  node.textContent = middleTruncateOrigin(origin);
  node.title = origin;
  // a11y-webext--5: the element is a bare <span> (role=generic), and aria-label is PROHIBITED on a
  // generic role — some AT drops it, which would silently defeat the whole point of exposing the
  // untruncated origin to a screen-reader user on an anti-phishing display. `note` is a labelable
  // role that says what this is (an aside about the current state), so the name lands.
  node.setAttribute("role", "note");
  node.setAttribute("aria-label", fillApproved(T.CONNECTED_SERVER, origin));
}

/**
 * Safari on iOS: nobody can attach a debugger there, so when no server is in effect the header carries a Details
 * disclosure that says why. Nothing in it is secret: where the worker's start is, the kind of block, whether the store
 * opened, how the ask of the app ended, and what the app answers this popup directly. Every string is textContent.
 */
async function renderServerDetails(after: HTMLElement, serverInfoSilent: boolean): Promise<void> {
  // Built once and filled only when opened. Rebuilding it on every header render (each refresh re-renders the header)
  // redrew this block and sent the app a native message every time: part of the popup's flicker.
  const existing = document.getElementById("server-details");
  if (existing?.dataset["silent"] === String(serverInfoSilent)) return;
  existing?.remove();
  const box = document.createElement("details");
  box.id = "server-details";
  box.dataset["silent"] = String(serverInfoSilent);
  box.style.cssText = "font-size:11px;margin-top:4px;word-break:break-word";
  const summary = document.createElement("summary");
  summary.textContent = T.DETAILS;
  const body = document.createElement("div");
  body.style.whiteSpace = "pre-wrap";
  box.append(summary, body);
  after.insertAdjacentElement("afterend", box);
  box.addEventListener("toggle", () => {
    if (box.open) void fillServerDetails(body, serverInfoSilent);
  });
}

/** The Details' lines, gathered when the disclosure is opened (and again each time it is reopened). */
async function fillServerDetails(body: HTMLElement, serverInfoSilent: boolean): Promise<void> {
  const lines: string[] = [`Worker answered serverInfo: ${serverInfoSilent ? "no" : "yes"}`];
  const show = (): void => {
    body.textContent = lines.join("\n");
  };
  show();
  const d = await ask({ type: "serverDiag" });
  if (!d) {
    lines.push("Worker diagnostics: no answer");
    lines.push(...(await backgroundBootLines()));
  } else {
    lines.push(
      `Worker start: ${d.stage}${d.migration ? ` (migration: ${d.migration})` : ""}`,
      `Block: ${d.block ?? "none"}`,
      `Store opened: ${d.store ? "yes" : "no"}`,
      `Worker's server: ${d.url}`,
      `App ask (worker): ${d.native}${d.nativeError ? ` — ${d.nativeError}` : ""}`,
      `App answered: ${d.app ?? "–"}`,
      `Adoption: ${d.adopt ?? "–"}`,
      `Handler at unlock: ${d.vaultOpen ?? "–"}`,
      `Handler at last fill or copy: ${d.vaultSecret ?? "–"}`,
      `Page origin: ${d.pageOrigin ?? "no page has asked yet"}`,
      `Payment frame origin: ${d.providerFrame ?? "no payment frame has reported yet"}`,
    );
  }
  show();
  const own = await askAppServerDetailed(nativeSender(globalThis as Parameters<typeof nativeSender>[0], "com.silencelen.andvari"));
  const said = own.answer.kind === "set" ? own.answer.url : own.answer.kind;
  lines.push(`App ask (popup): ${own.call}${own.error ? ` — ${own.error}` : ""}; answer: ${said}`);
  show();
}

/**
 * What the background page recorded about its own load (safari-boot.js), read by safari-diag.js: a classic script
 * loaded on demand, because this page itself never touches storage. Display only.
 */
async function backgroundBootLines(): Promise<string[]> {
  type Boot = { readError?: string; "diag.backgroundLoadedAt"?: unknown; "diag.backgroundReadyAt"?: unknown; "diag.backgroundErrors"?: unknown };
  try {
    await new Promise<void>((resolve, reject) => {
      const tag = document.createElement("script");
      tag.src = "safari-diag.js";
      tag.onload = () => resolve();
      tag.onerror = () => reject(new Error("safari-diag.js did not load"));
      document.head.append(tag);
    });
    const read = (globalThis as { __andvariBackgroundDiag?: () => Promise<Boot> }).__andvariBackgroundDiag;
    if (!read) return ["Background record: reader missing"];
    const got = await Promise.race([read(), new Promise<Boot>((r) => setTimeout(() => r({ readError: "timed out" }), 3000))]);
    if (got.readError) return [`Background record: ${got.readError}`];
    const out = [
      `Background loaded at: ${String(got["diag.backgroundLoadedAt"] ?? "never")}`,
      `Background finished loading at: ${String(got["diag.backgroundReadyAt"] ?? "never")}`,
    ];
    const errors = Array.isArray(got["diag.backgroundErrors"]) ? (got["diag.backgroundErrors"] as Record<string, unknown>[]) : [];
    if (errors.length === 0) out.push("Background errors: none recorded");
    for (const e of errors.slice(0, 5)) {
      out.push(`Background ${String(e.kind)}: ${String(e.message)}${e.where ? ` @ ${String(e.where)}` : ""}`);
      if (e.stack) out.push(String(e.stack).slice(0, 1500));
    }
    return out;
  } catch (e) {
    return [`Background record: ${String(e)}`];
  }
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
    const server = await currentServer();
    const pattern = server === null ? null : originMatchPattern(server);
    if (pattern) granted = await chrome.permissions.contains({ origins: [pattern] });
  } catch {
    /* permissions API unavailable — granted stays null (no detection, no false route) */
  }
  document.body.dataset.missingHostGrant = granted === false ? "true" : "false";
  if (shouldRouteToOptions(granted)) el("host-grant-cta").hidden = false;
}

// §12.2: "Your own server" — typed in Options, behind the Trust Gate (Connect is the only commit); "Forget this server"
// (§12.3) is the way out of a fork or a damaged record.
el("confirm-server-open").addEventListener("click", () => {
  try {
    chrome.runtime.openOptionsPage();
  } catch {
    void chrome.tabs.create({ url: chrome.runtime.getURL("options.html") });
  }
  window.close();
});
el("confirm-server-not-mine").addEventListener("click", async () => {
  const b = el<HTMLButtonElement>("confirm-server-not-mine");
  if (b.textContent === T.FORGET_THIS_SERVER || b.textContent === T.FORGET_CONFIRM) {
    if (!(await forgetSecondClick(b))) return;
  }
  const r = await ask({ type: "forgetServer" });
  if (!r?.ok) showMsg("err", T.FORGET_FAILED);
  await renderServerOrigin();
  await refresh();
});

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

/**
 * Safari on iOS: the locked view is one button. There is no sign-in in this build (the vault is the andvari app's),
 * so the master-password form, the PIN and the WebAuthn views never show, and neither does Sign out.
 */
function renderAppLocked(unlocked: boolean): void {
  for (const id of ["qu-locked", "qu-bio-locked", "qu-master-form"]) el(id).hidden = true;
  el("app-locked").hidden = unlocked;
  el("sign-out").hidden = true;
}

/** An unlock is in flight: Face ID is up, or its answer is on its way. */
let appUnlockPending = false;

/**
 * Face ID in the app's handler, then the list. The button is the retry after a cancel or a failure.
 *
 * iOS puts the system's Face ID sheet over Safari, and may suspend this page while it is up (how far is not
 * documented for an extension's popup: the page may be hidden, frozen with its timers and message answers held, or
 * the popup dismissed outright, which is what a device showed). So nothing here depends on the answer to this one
 * message arriving: while the unlock is pending the popup also asks the worker for its status once a second and
 * whenever the page becomes visible again, and whichever says "unlocked" first ends the wait. A hide or an unload in
 * between closes nothing, and a popup opened afresh finds the worker unlocked and shows the list.
 */
async function appUnlock(): Promise<void> {
  if (appUnlockPending) return; // one prompt at a time
  appUnlockPending = true;
  const button = el<HTMLButtonElement>("app-unlock");
  button.disabled = true;
  button.textContent = T.WAITING_FOR_FACE_ID;
  clearMsg();
  let poll: number | undefined;
  let onVisible: (() => void) | undefined;
  try {
    const answered = ask({ type: "appUnlock" });
    const seenUnlocked = new Promise<"unlocked">((resolve) => {
      const check = (): void => void ask({ type: "status" }).then((s) => (s?.unlocked ? resolve("unlocked") : undefined));
      poll = window.setInterval(check, 1000);
      onVisible = () => {
        if (document.visibilityState === "visible") check();
      };
      document.addEventListener("visibilitychange", onVisible);
    });
    const gaveUp = new Promise<"timeout">((resolve) => window.setTimeout(() => resolve("timeout"), 70_000));
    const r = await Promise.race([answered, seenUnlocked, gaveUp]);
    if (r !== "unlocked" && r !== "timeout") {
      if (r?.state === "openApp") showMsg("info", r.message ?? T.OPEN_APP_AND_UNLOCK);
      else if (r?.state === "unavailable" || r === undefined) showMsg("err", T.APP_NOT_REACHED);
    }
  } finally {
    if (poll !== undefined) window.clearInterval(poll);
    if (onVisible) document.removeEventListener("visibilitychange", onVisible);
    appUnlockPending = false;
    button.disabled = false;
    button.textContent = T.UNLOCK_WITH_FACE_ID;
  }
  await refresh();
}
el("app-unlock").addEventListener("click", () => void appUnlock());

/** Once per popup open: Face ID comes up by itself. A relock while the popup stays open (the 90 s window) does not
 *  prompt again on its own; the button does. */
let appUnlockOffered = false;
async function appUnlockOnOpen(): Promise<void> {
  if (BUILD_TARGET !== "safari" || appUnlockOffered) return;
  appUnlockOffered = true;
  const s = await ask({ type: "status" });
  const info = await ask({ type: "serverInfo" });
  // A page asked for this popup (not a tap on the toolbar item): Face ID waits for the button.
  if (!s || s.unlocked || s.pageSummoned === true || !info || info.block) return;
  // The popup is painted before the prompt is asked for: two animation frames put the unlock view on screen, and
  // 400 ms more lets Safari finish presenting the sheet (its presentation animation is about a third of a second).
  // A system sheet raised while Safari is still presenting ours is the surest way to have ours dropped.
  await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
  await new Promise<void>((resolve) => window.setTimeout(resolve, 400));
  await appUnlock();
}

if (BUILD_TARGET === "safari") {
  // Something is on screen from the first frame, before any message has been answered: the unlock view.
  showView(false);
  renderAppLocked(false);
  // Nothing fails silently into a blank popup: an error anywhere in this page is shown, over the unlock view.
  const showFailure = (what: unknown): void => {
    try {
      el("locked").hidden = false;
      el("app-locked").hidden = false;
      showMsg("err", fillApproved(T.UNEXPECTED_PROBLEM, String(what instanceof Error ? `${what.name}: ${what.message}` : what).slice(0, 300)));
    } catch {
      /* the page is too broken to say so */
    }
  };
  window.addEventListener("error", (e) => showFailure(e.error ?? e.message));
  window.addEventListener("unhandledrejection", (e) => showFailure(e.reason));
  // Nothing is closed when this page goes away. On iOS the system's Face ID sheet DISMISSES the popup (build 15 on a
  // device: Face ID came up, and afterwards there was no popup): if the popup's going away locked the vault, the
  // unlock it had just asked for would be thrown away, and opening the popup again would only ask again. The unlock
  // belongs to the worker and lasts its 90 seconds; opening the popup again within them shows the list. Lock, in the
  // popup, ends it at once.
}

/** Safari on iOS: the server comes from the andvari app (copy.ts APP_SERVER_NONE / APP_SERVER_UNKNOWN). */
const APP_SERVER_NONE = T.APP_SERVER_NONE;

/** Safari: what the app said about its server at this open (the worker's ask, else the popup's own). */
let appAnswered: "set" | "none" | "unavailable" | null = null;

/**
 * Safari: have the worker adopt the app's server before anything shows a server; whether the app has none. The worker
 * asks the app itself; when that ask got no answer (on a device it timed out while this page's, a moment later,
 * resolved), this page asks the app and relays what it said, which the worker adopts the same way.
 */
async function adoptAppServer(): Promise<boolean> {
  if (BUILD_TARGET !== "safari") return false;
  const r = await ask({ type: "appServer" });
  appAnswered = r?.app ?? "unavailable";
  if (appAnswered === "unavailable") {
    const askedAt = Date.now();
    const own = await askAppServerDetailed(nativeSender(globalThis as Parameters<typeof nativeSender>[0], "com.silencelen.andvari"));
    if (own.answer.kind === "set") {
      const relayed = await ask({ type: "appServerAnswer", url: own.answer.url, nativeSave: own.nativeSave, askedAt });
      appAnswered = relayed?.app ?? "unavailable";
    } else if (own.answer.kind === "none") {
      // Relayed too: the worker then forgets a server it still keeps from the app (an account deleted in the app leaves
      // the device with none).
      await ask({ type: "appServerAnswer", url: null, nativeSave: own.nativeSave, askedAt });
      appAnswered = "none"; // the app said so itself, whatever the worker made of it
    }
  }
  return appAnswered === "none";
}

drawWordmarks(document); // the drawn name in the header and the lock screen (brand.ts)
void adoptAppServer().then((appHasNone) => {
  void renderServerOrigin();
  // Probe biometric capability BEFORE the first status render so the bio enroll shortcuts appear on the
  // first paint (not only after an interaction re-renders). The probe is fast and never throws out.
  void probeBioCapable().finally(() => void refresh().finally(() => {
    if (appHasNone && el("confirm-server").hidden) showMsg("info", APP_SERVER_NONE); // the card says it when it is up
    else void appUnlockOnOpen();
  }));
  void renderUpdate();
  if (BUILD_TARGET === "safari") {
    // The Safari build never contacts the server (the andvari app does), so there is no connection to show or test,
    // and no host grant for it to finish setting up. Its access to web pages is Safari's per-site permission, which the
    // andvari app explains (Settings › Safari): the all-sites banner would offer a grant the page cannot make here.
    el("conn").hidden = true;
    el("conn-status").textContent = "";
    el("ping").hidden = true;
    return;
  }
  // Passive connectivity dot — quiet ping on open, result only in the header dot.
  void ask({ type: "ping" }).then((r) => setConn(r?.ok === true, r?.code === "confirm_server"));
  void detectMissingHostGrant();
  void detectMissingBroadGrant();
});
