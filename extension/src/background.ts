import { AndvariApi, ApiError, type MutationResult, type SyncResponse } from "./api";
import { cardSubtitle, composeShortExpiry, digitsOnly } from "./card";
import {
  adIdkey,
  adItem,
  adUvk,
  adVk,
  authKey,
  assertServerKdfParams,
  KdfPolicyError,
  boxKeypairFromSeed,
  deriveMasterKey,
  fromB64,
  open,
  seal,
  sealOpen,
  toB64,
  wrapKey,
  type KdfParams,
} from "./crypto";
import { startEvents, type EventsHandle, type WsLike } from "./events";
import { LOGIN_FORMAT_VERSION, MAX_ITEM_FORMAT_VERSION } from "./format";
import { isNewerVersion } from "./version";
import { evaluateSignedManifest, MIN_SEQ, updatesEnabled } from "./updateverify";
import { DEFAULT_GENERATOR, generatePassword } from "./generator";
import type { CardFieldKind } from "./detect";
import type {
  CardFillFields,
  CardFillOutcome,
  CardItem,
  FillOutcome,
  MatchItem,
  PendingSave,
  Req,
  Res,
  SaveErrorCode,
  TabMsg,
  UnlockCode,
} from "./messages";
import { currentCode } from "./totp";
import { matchLogins, normalizeHost, parseSavedUri, type FillTarget } from "./urimatch";
import { pslResolve } from "./psl"; // A8: the SW is the ONLY bundle that carries the PSL blob
import { resolveSaveAction, saveTargetFor } from "./savetarget";

/**
 * MV3 background service worker — sole custodian of unlocked vault material. Chrome kills an idle
 * SW (~30 s), so the session ALSO lives in chrome.storage.session: memory-backed browser storage —
 * never disk, cleared on browser exit, trusted extension contexts only — lazily restored on wake.
 * ZK holds: the master password and mk exist only transiently inside unlock(); what persists is
 * session-scoped custody (tokens, unwrapped vault keys b64, decrypted docs) — the same posture as
 * SW RAM. chrome.storage.local NEVER holds secrets. (storage.session: Chrome 102+/Firefox 115+,
 * where `chrome` aliases `browser`.)
 *
 * Message protocol = src/messages.ts (THE CONTRACT). Secret egress is `reveal` only, gated on
 * host-match ∨ a one-shot popup fill grant ∨ an explicit user pick — see the contract's trust
 * model. Lock policy: chrome.alarms "autolock" re-armed by every message answered with a live
 * session (client-policy autoLockSeconds; 0 disables), "resync" refreshes items every 5 min —
 * the alarm floor under the live dirty-bell WebSocket (events.ts), which nudges the same resync
 * within ~1–2 s of a peer write while a session exists.
 *
 * Unlock flow (mirrors web Account.unlock): prelogin → Argon2id → login (authKey) → unwrap UVK
 * from accountKeys → sync → unwrap each vault key from its grant → decrypt items under the VK.
 */
const SERVER_URL = "https://andvari.taila2dff2.ts.net";

const SKEY = "session"; // storage.session: SessionSnapshot
const TKEY = "tabs"; //    storage.session: Record<tabId, TabState>
const NKEY = "lockNotice"; // storage.session: { kind:"idle"; seconds } — F26 reason line (E1-7)
const UKEY = "updateInfo"; // storage.local (non-secret): UpdateInfo while a newer build is live
const ULAST = "updateCheckedAt"; // storage.local: epoch ms of the last COMPLETED update fetch
const USEQ = "updateAcceptedSeq"; // storage.local: highest signed-manifest seq ever accepted (§B anti-rollback)
const UQUIET = "updateChannelQuiet"; // storage.local: { reason } — H2 fail-closed-QUIET state (§M-D5), never a nag
// M-D4b: ONLY these quiet reasons are ACTIONABLE and may surface a muted popup line. `seq_regression`
// (already-accepted manifest re-polled — the normal steady state) and `disabled` are benign and must
// NEVER render as "couldn't be verified" (permanent false alarm = the alert-fatigue failure M-D4b exists
// to prevent). The write path also refuses to stamp seq_regression; this Set is the belt-and-suspenders.
const SURFACEABLE_QUIET_REASONS = new Set(["unverified", "malformed", "stale", "manifest_fetch_failed"]);
const DEFAULT_AUTOLOCK_SECONDS = 15 * 60; // policy fetch failed/absent — never "no lock at all"
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 30; // spec 01 §8 policy default; clearing is safety-positive
const CLIPBOARD_CLEAR_ALARM = "clipboardclear"; // SW backstop clear (E1-4); survives idle doLock
const RESYNC_PERIOD_MIN = 5;
const UPDATE_ALARM = "updatecheck";
const UPDATE_PERIOD_MIN = 1440; // ~daily; the SW also opportunistically checks on wake (throttled)
const UPDATE_MIN_GAP_MS = 20 * 60 * 60 * 1000; // floor between real fetches — SWs wake constantly
const GRANT_TTL_MS = 30_000; // popup fill grant: covers the content script's reveal round-trip
const BADGE_BG = "#d0a94a"; //  aged gold on…
const BADGE_INK = "#1a1509"; // …treasury charcoal (web --gold / --btn-ink)
// formatVersion discipline lives in format.ts (MAX_ITEM_FORMAT_VERSION read ceiling;
// LOGIN_FORMAT_VERSION new-login seal fv) — chrome-free so the web pin suite imports it.
// Automated (non-user) messages that must NOT re-arm the idle lock — else a page auto-reloading
// (pageInfo) or the popup's 1 s status/TOTP poll would defer autolock forever while the user is
// away. `status` is here too: merely leaving the popup open (it polls status every second for
// liveness) is not activity; real interaction (matches/reveal/search/save/…) still re-arms.
const PASSIVE_MSGS = new Set<Req["type"]>(["pageInfo", "totp", "ping", "status", "cardFormInfo"]);

/** Local sentinel for the spec 01 §5 identityPub derive-and-compare hard-fail (E1-1, web
 *  account.ts:40 parity). The unlock mapper carries it to the popup as code "identity_mismatch" —
 *  a distinct class so it can NEVER be softened into "wrong password". The message is debug-only
 *  detail; the popup renders the canonical sentence from errors.ts. */
class IdentityMismatchError extends Error {
  constructor() {
    super("Server identity key mismatch — possible tampering. Do not proceed; contact your admin.");
    this.name = "IdentityMismatchError";
  }
}

interface LoginData {
  username?: string;
  password?: string;
  uris?: string[];
  totp?: string;
}
/** Card fields (spec 02 §3, fv 2 docs) — read-only here: the extension lists/copies cards but
 *  never creates or edits them. Field names mirror web api/types CardData / core CardData. */
interface CardData {
  cardholderName?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  securityCode?: string;
  brand?: string;
}
/** Parsed plaintext doc. Unknown fields (notes, favorite, passwordHistory, …) survive re-encrypts
 *  via object spread; `attachments` is typed because a put's wire attachmentIds must mirror it —
 *  an update that sent [] would orphan the item's attachment blobs server-side. */
interface ItemDoc {
  type: string;
  name: string;
  login?: LoginData;
  card?: CardData;
  attachments?: { id: string }[];
}
interface DecryptedItem {
  itemId: string;
  vaultId: string;
  rev: number;
  /** The fv this item was decrypted (or last sealed) at — every re-seal AD-binds and rewires
   *  this same value (monotonic client rule, web Account.itemFv parity; format.ts has the law). */
  formatVersion: number;
  doc: ItemDoc;
}

interface Session {
  userId: string;
  email: string;
  items: DecryptedItem[];
  vaultKeys: Map<string, Uint8Array>;
  personalVaultId: string;
  /** Rescue-issued temporary password in effect (E1-6) — surfaced in `status` for the popup nudge. */
  mustChangePassword: boolean;
}

/** What survives SW death (JSON-safe: keys as b64 — Uint8Array doesn't cross chrome.storage). */
interface SessionSnapshot {
  access: string;
  refresh: string | null;
  userId: string;
  email: string;
  personalVaultId: string;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  mustChangePassword: boolean;
  vaultKeys: Record<string, string>;
  items: DecryptedItem[];
}

interface TabState {
  /** Username-only capture (multi-step step 1), merged into the password page's capture. */
  lastUsername?: string;
  /** The tab's pending save. The password stays SW-side — content only ever sees PendingSave.
   *  `frameId` is the frame that captured it: a DIFFERENT frame may not overwrite a live pending,
   *  so a hostile sub-frame can't silently redirect the top frame's Save banner to its own login. */
  pending?: (PendingSave & { password: string; frameId: number }) | undefined;
  /** S3 per-frame card-form registry: frameId → { the frame's browser-set origin, the card-field
   *  kinds it declared }. METADATA ONLY (never card values). `origin` is `sender.origin` ([A2]);
   *  every card offer/redemption re-derives the tab's top origin and compares against it, so a
   *  stale record can never leak a fill across origins. Cleared with the tab (onRemoved / lock). */
  cardForms?: Record<number, { origin: string; fields: CardFieldKind[] }>;
}

let session: Session | null = null;
let autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
let clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
let tabs = new Map<number, TabState>();
/** One-shot popup fill grants, tabId → item+expiry. In-memory only: minted and consumed within
 *  one message exchange, so a SW death in between simply voids the grant (fill re-clicks). The
 *  grant is consumed ONLY by the tab's TOP frame (fillFromPopup targets frameId 0) — a
 *  broadcast-to-all-frames grant would let a hostile cross-origin sub-frame claim the secret. */
const grants = new Map<number, { itemId: string; expiresMs: number }>();
/** S3 CARD fill grants — a store SEPARATE from login `grants` ([A5]). `grants` is single-slot per
 *  tab, so sharing it would let a card grant clobber a live login grant (and let one path's
 *  redemption consume the other's). A card grant carries the two extra bindings the contract needs
 *  — the frame that detected the form (`frameId`) and its browser-set `origin` — and is consumed
 *  ONLY by `revealCardForFill` (never the login `reveal()`, nor the reverse). One-shot, 30 s. */
const cardGrants = new Map<number, { itemId: string; frameId: number; origin: string; expiresMs: number }>();
/** In-flight write count — resync must not replace session.items out from under a landing put. */
let writesInFlight = 0;
let loadPromise: Promise<void> | null = null;
/** Live dirty-bell socket handle (events.ts) — held ONLY while a session exists; locked or
 *  logged out = no socket (doLock tears it down first thing). Dies with the SW; T1/T3 revive. */
let events: EventsHandle | null = null;

const api = new AndvariApi(SERVER_URL, chrome.runtime.getManifest().version);
// Awaited on every pair mutation — the consumed refresh token must reach the snapshot BEFORE the
// refresh POST (a stale persisted pair resurrected on SW wake = revoked device). persistSession
// returns its storage.set promise so doRefresh can await it.
api.onTokensChanged = () => persistSession();
// A 426 min-version pin (spec 03 §1) surfaces via checkForUpdate → the existing update banner is
// the download surface. checkForUpdate hits the static /downloads route (not api.ts), so it can
// never itself 426 — no re-entry loop (AM4).
api.onUpgradeRequired = () => void checkForUpdate(true);

// ---- one-time per SW life; listeners MUST register synchronously (MV3 wake requirement) ----

void chrome.action.setBadgeBackgroundColor({ color: BADGE_BG });
void chrome.action.setBadgeTextColor({ color: BADGE_INK });
try {
  // Explicit though it IS the default: the snapshot is readable from trusted contexts only.
  void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
} catch {
  /* not implemented on this browser — the default is trusted-only anyway */
}

chrome.runtime.onMessage.addListener((msg: Req, sender, sendResponse) => {
  handle(msg, sender)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: String(e) }));
  return true; // keep the channel open for the async response
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "autolock") void doLock("idle");
  else if (alarm.name === "resync") {
    void resync(); // the ≤5-min staleness floor…
    void ensureSocket(true); // …and the guaranteed live-socket revival after SW death (T3)
  } else if (alarm.name === UPDATE_ALARM) void checkForUpdate();
  else if (alarm.name === CLIPBOARD_CLEAR_ALARM) void clearClipboardBackstop();
});

// The self-update check runs on its OWN daily schedule, independent of lock state (it reads only
// the public downloads manifest — no vault, no session). A reload/update fires onInstalled, which
// re-checks against the NEW installed version and so clears a now-satisfied signal immediately.
chrome.runtime.onInstalled.addListener(() => void checkForUpdate(true));
chrome.runtime.onStartup.addListener(() => void checkForUpdate(true));
void (async () => {
  // Survive SW recycling without resetting the period on every wake (that would starve a
  // 1440-min alarm): create it only when absent. The wake-path check is throttled by ULAST.
  try {
    if (!(await chrome.alarms.get(UPDATE_ALARM))) {
      await chrome.alarms.create(UPDATE_ALARM, { periodInMinutes: UPDATE_PERIOD_MIN });
    }
  } catch {
    /* alarms.get unsupported here — the throttled wake check below still yields ~daily coverage */
  }
  void checkForUpdate();
})();

// T1: EVERY SW start (browser startup, install, popup/content-message/alarm wake) re-establishes
// the live dirty-bell socket if a restorable session exists — no-op when locked or logged out.
void ensureSocket();

// Re-offer a pending save once the post-login navigation lands. Belt: the content script also
// polls pendingSave on load; braces: this reaches SPAs that "complete" without a fresh script.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "complete") return;
  void (async () => {
    await ensureLoaded();
    const pending = tabs.get(tabId)?.pending;
    if (!pending) return;
    const msg: TabMsg = { type: "offerPendingSave", pending: publicPending(pending) };
    try {
      await chrome.tabs.sendMessage(tabId, msg);
    } catch {
      /* content not injected in that tab (yet) — its own pendingSave poll covers it */
    }
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  grants.delete(tabId);
  cardGrants.delete(tabId);
  void (async () => {
    await ensureLoaded();
    if (tabs.delete(tabId)) persistTabs();
  })();
});

// ---- session custody ----

/** Lazy wake path: one storage.session read per SW life hydrates session + tab state. */
function ensureLoaded(): Promise<void> {
  loadPromise ??= (async () => {
    const got = await chrome.storage.session.get([SKEY, TKEY]);
    const snap = got[SKEY] as SessionSnapshot | undefined;
    if (snap && !session) {
      api.setTokens(snap.access || null, snap.refresh);
      session = {
        userId: snap.userId,
        email: snap.email,
        personalVaultId: snap.personalVaultId,
        // mustChangePassword joined the snapshot in 0.10.0 — a ≤0.9.0 snapshot lacks it; false is
        // the safe default (a real rescue re-nudges on the next fresh login anyway).
        mustChangePassword: snap.mustChangePassword ?? false,
        vaultKeys: new Map(Object.entries(snap.vaultKeys).map(([id, b]) => [id, fromB64(b)])),
        // formatVersion joined the snapshot in 0.7.0 — a session persisted by ≤0.6.1 lacks it,
        // and that client's read gate only admitted fv≤1, so defaulting 1 is exact, not a guess.
        items: snap.items.map((i) => ({ ...i, formatVersion: i.formatVersion ?? 1 })),
      };
      autoLockSeconds = snap.autoLockSeconds;
      clipboardClearSeconds = snap.clipboardClearSeconds ?? DEFAULT_CLIPBOARD_CLEAR_SECONDS;
    }
    const t = got[TKEY] as Record<string, TabState> | undefined;
    if (t) tabs = new Map(Object.entries(t).map(([id, st]) => [Number(id), st]));
  })();
  return loadPromise;
}

/** Persist the live session to storage.session. RETURNS the storage.set promise so
 *  api.onTokensChanged can AWAIT the snapshot write before spending a refresh token (a consumed
 *  pair must be persisted before the POST — see AndvariApi.doRefresh). The `!session` guard is
 *  safe for that path: unlock sets tokens before session exists (setTokens vs the session
 *  assignment), but no refresh can run mid-login, so onTokensChanged never fires session-less
 *  there — the guard must NOT be "fixed" by reordering unlock. Fire-and-forget callers ignore it. */
function persistSession(): Promise<void> {
  if (!session) return Promise.resolve();
  const t = api.getTokens();
  const snap: SessionSnapshot = {
    access: t.access ?? "",
    refresh: t.refresh,
    userId: session.userId,
    email: session.email,
    personalVaultId: session.personalVaultId,
    autoLockSeconds,
    clipboardClearSeconds,
    mustChangePassword: session.mustChangePassword,
    vaultKeys: Object.fromEntries([...session.vaultKeys].map(([id, vk]) => [id, toB64(vk)])),
    items: session.items,
  };
  return chrome.storage.session.set({ [SKEY]: snap });
}

function persistTabs(): void {
  void chrome.storage.session.set({ [TKEY]: Object.fromEntries([...tabs].map(([id, st]) => [String(id), st])) });
}

/** Full lock: memory + storage.session (pending saves hold plaintext passwords — they lock too).
 *  `reason` records WHY for the F26 unlock-form line (E1-7): idle → write a notice; manual → clear
 *  any stale one. The "clipboardclear" backstop alarm deliberately SURVIVES (a secret copied just
 *  before an idle lock still clears on schedule, E1-4). */
async function doLock(reason: "idle" | "manual" = "manual"): Promise<void> {
  events?.close(); // live socket + all its timers die FIRST — locked means no bell traffic at all
  events = null;
  const secondsAtLock = autoLockSeconds; // capture before the reset below (web App.tsx:209 parity)
  session = null;
  autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
  clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  tabs.clear();
  grants.clear();
  cardGrants.clear();
  api.setTokens(null, null);
  await chrome.storage.session.remove([SKEY, TKEY]);
  // Write the reason AFTER the [SKEY,TKEY] remove so it survives it (a notice only from the idle
  // path — web parity); manual lock renders no reason line. storage.session clears on browser exit.
  if (reason === "idle") {
    await chrome.storage.session.set({ [NKEY]: { kind: "idle", seconds: secondsAtLock } });
  } else {
    await chrome.storage.session.remove(NKEY);
  }
  void chrome.alarms.clear("autolock");
  void chrome.alarms.clear("resync");
  try {
    // Quiet toolbar while locked — stale counts would claim matches we can no longer serve.
    for (const t of await chrome.tabs.query({})) {
      if (t.id !== undefined) chrome.action.setBadgeText({ tabId: t.id, text: "" }).catch(() => {});
    }
  } catch {
    /* tab enumeration unavailable — badges refresh on each page's next pageInfo */
  }
}

/** Re-arm the policy idle lock. chrome.alarms floors at ~30 s; 0 = policy-disabled (web parity). */
function armAutoLock(): void {
  if (autoLockSeconds <= 0) return;
  void chrome.alarms.create("autolock", { delayInMinutes: Math.max(autoLockSeconds / 60, 0.5) });
}

/** Periodic refresh while unlocked — new/changed items under keys we already hold. A grant to a
 *  brand-new vault needs uvk/identity (never persisted), so it lands at the next real unlock.
 *  Failures are silent by design: offline now, the next alarm retries. */
async function resync(): Promise<void> {
  await ensureLoaded();
  if (!session || writesInFlight > 0) return; // a save is landing — don't race its rev
  try {
    const sync = await api.sync(0);
    if (writesInFlight > 0 || !session) return; // a write started mid-sync — its result would be clobbered
    session.items = decryptItems(sync, session.vaultKeys);
    persistSession();
  } catch {
    /* tolerated */
  }
}

// ---- live change-push (dirty-bell WebSocket — design 2026-07-13-ext-live-sync.md) ----
// A peer edit reaches this SW in ~1–2 s via the server's rev bell instead of the 5-min alarm.
// The bell only NUDGES the existing resync() pull — no new decrypt path, no new secret egress —
// and nothing here may ever call armAutoLock() (bells are not user activity, PASSIVE_MSGS law).

/** Ticket-mint glue for events.ts. A definitive auth refusal folds to null (stop the cycle
 *  quietly — the vault STAYS unlocked serving offline fills, exactly like a failing alarm sync;
 *  a mint 401 must NEVER doLock, or laptop-asleep expiry would punish the user). Anything else
 *  (offline, 5xx) stays a throw = transient → events.ts backs off. The ticket is single-use,
 *  deviceId-bound server-side, and never persisted or logged. */
async function mintTicket(): Promise<string | null> {
  try {
    return (await api.eventsTicket()).ticket;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return null;
    throw e;
  }
}

/** Open (or prod) the live socket — ONLY while a session exists in the SW; locked or logged out
 *  means no socket (doLock cleared the tokens, so no ticket could be minted anyway). Every
 *  trigger funnels here: T1 SW-wake bootstrap (module scope), T2 unlock, T3 resync alarm —
 *  `reset` collapses a pending backoff so those known-good moments reconnect immediately. */
async function ensureSocket(reset = false): Promise<void> {
  await ensureLoaded(); // session may not be hydrated yet on a fresh SW wake
  if (!session) return;
  if (!events || events.closed) {
    events = startEvents({
      wsUrl: SERVER_URL.replace(/^http/, "ws") + "/api/v1/events",
      mintTicket,
      // The DOM WebSocket satisfies WsLike at runtime; TS's strict property variance on the on*
      // slots blocks the structural check — bridge it here, at the one real-socket seam.
      makeSocket: (u) => new WebSocket(u) as WebSocket & WsLike,
      onBell: () => void resync(), // debounced in events.ts; the EXISTING pull, nothing else
      onRevoked: () => void doLock("manual"), // explicit server frame — web-parity sign-out
    });
  } else {
    events.kick(reset);
  }
}

// ---- self-update signal (tier 1: NOTIFY only) ----
// Unpacked extensions cannot self-install, so the SW never rewrites itself — it only records
// that a newer build sits at /downloads and lets the popup + web hub point the user to it.

interface UpdateInfo {
  latest: string;
  chromeUrl: string | null;
  firefoxUrl: string | null;
}

/** Absolute a downloads URL. The manifest stores relative paths ("/downloads/…"); the popup is a
 *  chrome-extension:// page, so a relative href would resolve against the EXTENSION origin. Prefix
 *  the server origin unless the manifest already gave an absolute URL. */
function downloadUrl(u: unknown): string | null {
  if (typeof u !== "string" || !u) return null;
  return /^https?:\/\//i.test(u) ? u : SERVER_URL + u;
}

/**
 * H2 signed-update check (design 2026-07-13-signed-updates §D/§M). Fetch the manifest as RAW BYTES
 * plus its detached `manifest.json.sig`, verify the Ed25519 signature over the EXACT bytes against
 * the pinned key SET (updateverify.ts), and ONLY THEN parse + enforce the anti-rollback `seq` and
 * the `signedAt` staleness window. On a strictly-newer build it records an [UpdateInfo]; on an
 * equal-or-older build it clears any stale signal.
 *
 * FAIL-CLOSED QUIET (§M-D5/D6): any fetch/verify/seq/staleness failure records a distinct quiet
 * reason and NEVER fabricates or refreshes a nag — an existing previously-VERIFIED signal is left
 * intact (only a clean verified read supersedes it), so a T1 server stripping the sig can DoS the
 * fetch but never conjure a scary banner. Records no vault state, so it is safe to run locked.
 * [force] bypasses the wake throttle. Never throws.
 */
async function checkForUpdate(force = false): Promise<void> {
  try {
    if (!force) {
      const seen = (await chrome.storage.local.get(ULAST))[ULAST];
      if (typeof seen === "number" && Date.now() - seen < UPDATE_MIN_GAP_MS) return;
    }
    // §M-D3: a build pinning only the placeholder sentinel has NO update path — do not even fetch.
    if (!updatesEnabled()) return;

    const base = SERVER_URL + "/downloads/manifest.json";
    let mResp: Response;
    let sResp: Response;
    try {
      // §M-D6: the sig is a SECOND request over the same raw bytes — either fetch failing → quiet.
      [mResp, sResp] = await Promise.all([fetch(base, { cache: "no-store" }), fetch(base + ".sig", { cache: "no-store" })]);
    } catch {
      return; // network (offline / DNS) — transient; keep any prior signal, don't stamp ULAST
    }
    if (!mResp.ok || !sResp.ok) {
      // Reachable server but the manifest or its detached sig errored (404/5xx) — a misconfigured or
      // tampering server, NOT offline. Fail-closed QUIET and STAMP ULAST so the wake-throttle floors it
      // (§M-D5): otherwise, once ULAST ages past UPDATE_MIN_GAP_MS, every SW wake (content message,
      // popup, alarm) would re-hammer two no-store fetches indefinitely. A genuine network reject is
      // caught above and left un-stamped for prompt retry when connectivity returns.
      await chrome.storage.local.set({ [UQUIET]: { reason: "manifest_fetch_failed" }, [ULAST]: Date.now() });
      return;
    }

    const raw = new Uint8Array(await mResp.arrayBuffer()); // EXACT bytes — never resp.json() (§M-D6)
    const sigText = await sResp.text();
    const storedSeq = (await chrome.storage.local.get(USEQ))[USEQ];
    // §M-D4(a) anti-rollback FLOOR: a fresh install (or a wiped USEQ) starts at MIN_SEQ, not 0, so a
    // T1 server can't steer it to any validly-signed-but-older (known-vuln) manifest below the floor.
    const lastAcceptedSeq = Math.max(typeof storedSeq === "number" ? storedSeq : 0, MIN_SEQ);
    const decision = evaluateSignedManifest(raw, sigText, { lastAcceptedSeq, now: Date.now() });

    // A completed fetch stamps ULAST regardless of verdict (the throttle floors real fetches, §M-D5
    // — a tampering/stale server must not be hammered on every SW wake).
    if (decision.kind === "quiet") {
      if (decision.reason === "seq_regression") {
        // NOT a failure: the fetch verified a genuine, signature-valid, well-formed manifest that is
        // simply not newer than one we already accepted (the normal steady state after every accept).
        // Treat it like a clean verified read — CLEAR any prior quiet marker (healthy channel) and stamp
        // ULAST. Surfacing this as "couldn't be verified" would be a permanent false alarm, and stamping
        // it would also clobber a real prior `unverified`/`stale` signal (fail-open). Leave [UKEY] alone.
        await chrome.storage.local.remove(UQUIET);
        await chrome.storage.local.set({ [ULAST]: Date.now() });
        return;
      }
      // Fail-closed QUIET (unverified/malformed/stale): record the distinct ACTIONABLE reason; leave any
      // prior VERIFIED [UKEY] signal alone.
      await chrome.storage.local.set({ [UQUIET]: { reason: decision.reason }, [ULAST]: Date.now() });
      return;
    }

    // Fully verified, seq-monotonic, fresh — this read supersedes the stored verdict.
    const ext = decision.ext;
    const latest = typeof ext.version === "string" ? ext.version : null;
    const current = chrome.runtime.getManifest().version;
    await chrome.storage.local.remove(UQUIET); // a clean verified read clears the quiet marker
    if (latest && isNewerVersion(latest, current)) {
      const info: UpdateInfo = { latest, chromeUrl: downloadUrl(ext.chromeUrl), firefoxUrl: downloadUrl(ext.firefoxUrl) };
      await chrome.storage.local.set({ [UKEY]: info, [USEQ]: decision.seq, [ULAST]: Date.now() });
    } else {
      await chrome.storage.local.remove(UKEY); // up to date (or unreadable version) → no signal
      await chrome.storage.local.set({ [USEQ]: decision.seq, [ULAST]: Date.now() });
    }
  } catch {
    /* unexpected — any existing signal stands until a clean verified read supersedes it */
  }
}

/** Popup query: the stored signal, RE-VALIDATED against the currently-installed version so a
 *  signal recorded before an in-place reload can never linger as a false "update available". When
 *  there is no offer, surface the fail-closed-QUIET update-channel reason from [UQUIET] (M-D4b /
 *  compliance UQUIET-read) so the popup can render ONE muted line — an offer supersedes it
 *  (mutually exclusive, mirroring the desktop's `updateAvailable` vs `updateChannelNotice`). */
async function updateStatus(): Promise<Res<"updateStatus">> {
  const current = chrome.runtime.getManifest().version;
  const info = (await chrome.storage.local.get(UKEY))[UKEY] as UpdateInfo | undefined;
  if (info && typeof info.latest === "string" && isNewerVersion(info.latest, current)) {
    return { current, latest: info.latest, chromeUrl: info.chromeUrl ?? null, firefoxUrl: info.firefoxUrl ?? null, quietReason: null };
  }
  const quiet = (await chrome.storage.local.get(UQUIET))[UQUIET] as { reason?: unknown } | undefined;
  // Surface ONLY actionable reasons (M-D4b): a benign seq_regression — or any marker a pre-fix build
  // may have persisted — must never render as a scary "couldn't be verified" line.
  const rawReason = quiet && typeof quiet.reason === "string" ? quiet.reason : null;
  const quietReason = rawReason && SURFACEABLE_QUIET_REASONS.has(rawReason) ? rawReason : null;
  return { current, latest: null, chromeUrl: null, firefoxUrl: null, quietReason };
}

// ---- message dispatch ----

async function handle(msg: Req, sender: chrome.runtime.MessageSender): Promise<unknown> {
  await ensureLoaded();
  const res = await dispatch(msg, sender);
  // Policy idle window: only genuine user activity re-arms the lock. Automated traffic
  // (pageInfo on every load, the popup's 1 s TOTP poll) must not defer autolock while away.
  if (session && msg.type !== "lock" && !PASSIVE_MSGS.has(msg.type)) armAutoLock();
  return res;
}

async function dispatch(msg: Req, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (msg.type) {
    case "ping": {
      const p = await api.clientPolicy(); // host_permissions + reachability
      return { ok: true, serverTime: p.serverTime } satisfies Res<"ping">;
    }
    case "status": {
      // The F26 reason line only matters while locked (it sits above the unlock form).
      const lockNotice = session ? null : await readLockNotice();
      return {
        unlocked: session !== null,
        count: loginItems().length,
        email: session?.email ?? null,
        mustChangePassword: session?.mustChangePassword ?? false,
        lockNotice,
      } satisfies Res<"status">;
    }
    case "lock": {
      await doLock("manual");
      return { ok: true } satisfies Res<"lock">;
    }
    case "unlock":
      return unlockWithMapping(msg.email, msg.password);
    case "scheduleClipboardClear":
      return scheduleClipboardClear();
    case "matches": {
      if (!session) return { locked: true, matches: [] } satisfies Res<"matches">;
      return { locked: false, matches: matchesFor(msg.host).map((i) => toMatchItem(i, true)) } satisfies Res<"matches">;
    }
    case "allItems": {
      if (!session) return { locked: true, items: [] } satisfies Res<"allItems">;
      const q = (msg.query ?? "").trim().toLowerCase();
      const items = loginItems()
        .filter(
          (i) =>
            !q ||
            i.doc.name.toLowerCase().includes(q) ||
            (i.doc.login?.username ?? "").toLowerCase().includes(q) ||
            (i.doc.login?.uris ?? []).some((u) => u.toLowerCase().includes(q)),
        )
        .map((i) => toMatchItem(i, false));
      return { locked: false, items } satisfies Res<"allItems">;
    }
    case "cardItems": {
      if (!session) return { locked: true, items: [] } satisfies Res<"cardItems">;
      const q = (msg.query ?? "").trim().toLowerCase();
      const items = cardItems()
        .map(toCardItem)
        .filter((c) => !q || c.name.toLowerCase().includes(q) || c.subtitle.toLowerCase().includes(q));
      return { locked: false, items } satisfies Res<"cardItems">;
    }
    case "reveal":
      return reveal(msg, sender);
    case "revealCardField":
      return revealCardField(msg, sender);
    case "fillFromPopup":
      return fillFromPopup(msg.itemId);
    case "capturedCredential":
      return capturedCredential(msg, sender);
    case "pendingSave": {
      const tabId = await contextTabId(sender);
      const p = tabId === undefined ? undefined : tabs.get(tabId)?.pending;
      return { pending: p ? publicPending(p) : null } satisfies Res<"pendingSave">;
    }
    case "resolvePendingSave":
      return resolvePendingSave(msg.action, sender);
    case "linkUri":
      return linkUri(msg.itemId, msg.host);
    case "generate":
      return { password: generatePassword(DEFAULT_GENERATOR) } satisfies Res<"generate">;
    case "totp": {
      const uri = session?.items.find((i) => i.itemId === msg.itemId)?.doc.login?.totp;
      if (!uri) return { ok: false } satisfies Res<"totp">;
      try {
        const { code, secondsLeft } = currentCode(uri, Date.now());
        return { ok: true, code, secondsLeft } satisfies Res<"totp">;
      } catch {
        return { ok: false } satisfies Res<"totp">; // malformed stored totp
      }
    }
    case "pageInfo": {
      const locked = session === null;
      const matchCount = locked ? 0 : matchesFor(msg.host).length;
      const tabId = sender.tab?.id;
      // Badge from the top frame only — an iframe's count must not repaint the tab's signal.
      if (tabId !== undefined && (sender.frameId === undefined || sender.frameId === 0)) {
        chrome.action.setBadgeText({ tabId, text: !locked && matchCount > 0 ? String(matchCount) : "" }).catch(() => {});
      }
      return { matchCount, locked } satisfies Res<"pageInfo">;
    }
    case "updateStatus":
      return updateStatus();
    case "cardFormInfo":
      return cardFormInfo(msg, sender);
    case "cardFillOffers":
      return cardFillOffers(sender);
    case "fillCardFromPopup":
      return fillCardFromPopup(msg.itemId, sender);
    case "revealCardForFill":
      return revealCardForFill(msg, sender);
  }
}

// ---- unlock ----

/**
 * Derive the master key in a dedicated Web Worker so the SW event loop stays free during the ~5.8 s
 * Argon2id (fill/save messages keep flowing). Falls back to inline (blocks the SW) if the host won't
 * let the SW spawn a worker (older Chrome / some MV3 runtimes). mk stays inside the extension.
 */
function deriveMasterKeyAsync(password: string, params: KdfParams, salt: Uint8Array): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const inline = () => {
      try {
        resolve(deriveMasterKey(password, params, salt));
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    };
    let worker: Worker;
    try {
      worker = new Worker(chrome.runtime.getURL("kdf-worker.js"), { type: "module" });
    } catch {
      inline(); // nested workers not supported here → run inline
      return;
    }
    worker.onmessage = (e: MessageEvent<{ ok: boolean; mk?: Uint8Array; error?: string }>) => {
      worker.terminate();
      if (e.data.ok && e.data.mk) resolve(e.data.mk);
      else reject(new Error(e.data.error ?? "kdf worker failed"));
    };
    worker.onerror = () => {
      worker.terminate();
      inline(); // worker execution failed → don't block unlock, run inline
    };
    worker.postMessage({ password, params, salt });
  });
}

async function unlock(email: string, password: string): Promise<Res<"unlock">> {
  const pre = await api.prelogin(email);
  assertServerKdfParams(pre.kdfParams); // H1 (spec 05 T1): refuse a weakened/absurd KDF before deriving (also blocks a 4 GiB SW OOM)
  const mk = await deriveMasterKeyAsync(password, pre.kdfParams, fromB64(pre.kdfSalt));
  const s = await api.login(email, toB64(authKey(mk)));
  api.setTokens(s.accessToken, s.refreshToken);

  const uvk = open(wrapKey(mk), fromB64(s.accountKeys.wrappedUvk), adUvk(s.userId));
  // Identity keypair — for member (shared-vault) grants sealed to us.
  const identity = boxKeypairFromSeed(open(uvk, fromB64(s.accountKeys.encryptedIdentitySeed), adIdkey(s.userId)));

  // spec 01 §5 (web account.ts:157-174 / core parity): the seed-derived identity key is the one the
  // server cannot forge — a server-sent identityPub that doesn't equal it is a substitution attempt.
  // Hard-fail with a DISTINCT sentinel BEFORE any vault material is synced/decrypted/persisted,
  // including when the field is malformed (garbage where the identity key belongs IS the tampering
  // this names). No ctEquals in extension crypto.ts; a length + byte loop is fine (the comparand is
  // server-supplied, so timing is not load-bearing).
  let serverIdentityPub: Uint8Array | null = null;
  try {
    serverIdentityPub = fromB64(s.accountKeys.identityPub);
  } catch {
    /* undecodable → treated as a mismatch below */
  }
  if (
    serverIdentityPub === null ||
    serverIdentityPub.length !== identity.publicKey.length ||
    !identity.publicKey.every((b, i) => b === serverIdentityPub![i])
  ) {
    throw new IdentityMismatchError();
  }

  const sync = await api.sync(0);

  const vaultKeys = new Map<string, Uint8Array>();
  for (const g of sync.grants) {
    try {
      let vk: Uint8Array;
      if (g.sealedVk) {
        // Member grant: crypto_box_seal to our identity key; payload {v,vaultId,vk} bound to the row.
        const p = JSON.parse(
          new TextDecoder().decode(sealOpen(identity.publicKey, identity.privateKey, fromB64(g.sealedVk))),
        ) as { v: number; vaultId: string; vk: string };
        if (p.v !== 1 || p.vaultId !== g.vaultId) continue; // reject a reseated/forged grant
        vk = fromB64(p.vk);
      } else if (g.wrappedVk) {
        vk = open(uvk, fromB64(g.wrappedVk), adVk(g.vaultId, s.userId)); // owner / personal
      } else {
        continue;
      }
      vaultKeys.set(g.vaultId, vk);
    } catch {
      /* wrong key / not ours — skip */
    }
  }

  const items = decryptItems(sync, vaultKeys);
  // The personal vault (save target) = the type="personal" vault we hold a key for (web store.ts parity).
  const personalVaultId = sync.vaults.find((v) => v.type === "personal" && vaultKeys.has(v.vaultId))?.vaultId ?? "";
  session = { userId: s.userId, email, items, vaultKeys, personalVaultId, mustChangePassword: s.mustChangePassword ?? false };

  // Policy fetch — a failed fetch must never mean "no idle lock at all" (web resolveAutoLockSeconds
  // falls back to a persisted value; here the conservative defaults stand in). Also captures the
  // clipboard-clear window (E1-4): finite ≥ 0 else default 30.
  try {
    const p = await api.clientPolicy();
    autoLockSeconds =
      typeof p.autoLockSeconds === "number" && Number.isFinite(p.autoLockSeconds)
        ? Math.max(0, p.autoLockSeconds)
        : DEFAULT_AUTOLOCK_SECONDS;
    clipboardClearSeconds =
      typeof p.clipboardClearSeconds === "number" && Number.isFinite(p.clipboardClearSeconds) && p.clipboardClearSeconds >= 0
        ? p.clipboardClearSeconds
        : DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  } catch {
    autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
    clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  }

  await persistSession();
  void chrome.storage.session.remove(NKEY); // a fresh unlock clears the F26 idle-lock notice (E1-7)
  void chrome.alarms.create("resync", { periodInMinutes: RESYNC_PERIOD_MIN });
  void ensureSocket(true); // T2: live bell up within ~1 s of unlock
  armAutoLock();

  // E1-5: re-offer any save captured while locked the moment we unlock — otherwise the pending
  // stays invisible until a navigation (its only other re-offer paths). Same uninjected-tab
  // try/catch as the tabs.onUpdated listener.
  for (const [tabId, st] of tabs) {
    if (!st.pending) continue;
    const m: TabMsg = { type: "offerPendingSave", pending: publicPending(st.pending) };
    chrome.tabs.sendMessage(tabId, m).catch(() => {
      /* content not injected in that tab — its own pendingSave poll covers it */
    });
  }
  return { ok: true };
}

/** Wrap unlock() so its throws cross the seam as a coded Res<"unlock"> (design decision 4): the SW
 *  never ships user-facing sentences — the popup renders copy from errors.ts keyed on `code`. The
 *  raw String(e) rides `error` as debug detail the surfaces never render. */
async function unlockWithMapping(email: string, password: string): Promise<Res<"unlock">> {
  try {
    return await unlock(email, password);
  } catch (e) {
    return { ok: false, code: mapUnlockError(e), error: String(e) };
  }
}

function mapUnlockError(e: unknown): UnlockCode {
  if (e instanceof KdfPolicyError) return "kdf_policy"; // H1 (spec 05 T1): server tried to weaken/DoS the KDF
  if (e instanceof IdentityMismatchError) return "identity_mismatch";
  if (e instanceof ApiError) {
    if (e.code === "upgrade_required") return "upgrade_required"; // 426 min-version pin (any status)
    if (e.status === 401) return e.code === "totp_required" ? "totp_required" : "bad_credentials";
    return "server_error"; // 429/500/… fold here (strict Welcome-ladder parity, decision 5)
  }
  if (e instanceof TypeError) return "network"; // fetch rejection (web errors.ts:26-33 convention)
  return "unknown";
}

/** The F26 idle-lock reason, read from its own storage.session key (E1-7). Not part of the session
 *  snapshot — it must outlive the [SKEY,TKEY] removal doLock does. */
async function readLockNotice(): Promise<{ kind: "idle"; seconds: number } | null> {
  try {
    const n = (await chrome.storage.session.get(NKEY))[NKEY] as { kind?: unknown; seconds?: unknown } | undefined;
    if (n && n.kind === "idle" && typeof n.seconds === "number") return { kind: "idle", seconds: n.seconds };
  } catch {
    /* storage.session unavailable — no notice */
  }
  return null;
}

// ---- clipboard auto-clear backstop (spec 01 §8 / E1-4) ----
// The surface schedules a precise local timer at each copy (web-parity), but Chrome closes the
// popup on focus loss so that timer nearly never survives the dominant copy-in-popup flow. This SW
// alarm is the backstop that outlives the popup. The SW has no document, so the actual clipboard
// write is delegated to a context that does: an offscreen document on Chrome, the event page's own
// navigator on Firefox.

/** Arm the single backstop clear alarm. chrome.alarms floors at 0.5 min, so a sub-30 s policy
 *  clears at ~30 s once the copying document is gone (AM7 — honest + deterministic on packed
 *  builds; layer-1 covers sub-30 s while that document survives). Same-name create REPLACES, so the
 *  last copy through us wins (AM2). Answers the effective seconds; locked/absent → default 30. */
async function scheduleClipboardClear(): Promise<Res<"scheduleClipboardClear">> {
  const s = clipboardClearSeconds;
  try {
    await chrome.alarms.create(CLIPBOARD_CLEAR_ALARM, { delayInMinutes: Math.max(s / 60, 0.5) });
  } catch {
    /* alarms unavailable here — the surface's own local timer is the only clear */
  }
  return { ok: true, clearSeconds: s };
}

/** Fire the backstop clear. B1: the write is a SINGLE SPACE (an empty-selection execCommand copy is
 *  a silent no-op) and runs on EVERY alarm fire. Best-effort — every failure is swallowed. */
async function clearClipboardBackstop(): Promise<void> {
  if (typeof chrome.offscreen === "undefined") {
    // Firefox: background.js runs as an EVENT PAGE (a real document) and the clipboardWrite
    // permission lifts the gesture/focus gate — clear directly, execCommand-of-a-space as fallback.
    try {
      await navigator.clipboard.writeText("");
      return;
    } catch {
      /* fall through to the execCommand fallback */
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = " ";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    } catch {
      /* nothing more this context can do */
    }
    return;
  }
  // Chrome: the async Clipboard API refuses unfocused documents (offscreen docs are never focused),
  // so offscreen.ts does a textarea + execCommand copy at top level. Close-then-recreate guarantees
  // the clear runs on EVERY fire (never clear-on-load behind a create-if-absent guard — B1).
  try {
    await closeOffscreenIfPresent();
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: [chrome.offscreen.Reason.CLIPBOARD],
      justification: "clear a copied secret from the clipboard",
    });
    await closeOffscreenIfPresent(); // the clear ran at document load — tear it back down
  } catch {
    /* offscreen unavailable — the surface's local timer was the only best-effort clear */
  }
}

async function closeOffscreenIfPresent(): Promise<void> {
  try {
    const has = typeof chrome.offscreen.hasDocument === "function" ? await chrome.offscreen.hasDocument() : true;
    if (has) await chrome.offscreen.closeDocument();
  } catch {
    /* none open, or a close race — nothing to do */
  }
}

function decryptItems(sync: SyncResponse, vaultKeys: Map<string, Uint8Array>): DecryptedItem[] {
  const items: DecryptedItem[] = [];
  for (const it of sync.items) {
    if (it.deleted || !it.blob) continue;
    // Fail closed above the read ceiling (web account.ts parity): an fv this client doesn't
    // understand may carry doc semantics an edit would corrupt. Items we CAN read carry their
    // fv onto the session item, and every re-seal AD-binds + rewires that SAME fv (the server
    // refuses per-item fv downgrades) — so nothing we touch can ever downgrade or upgrade.
    if (it.formatVersion > MAX_ITEM_FORMAT_VERSION) continue;
    const vk = vaultKeys.get(it.vaultId);
    if (!vk) continue;
    try {
      const doc = JSON.parse(
        new TextDecoder().decode(open(vk, fromB64(it.blob), adItem(it.vaultId, it.itemId, it.formatVersion))),
      ) as ItemDoc;
      items.push({ itemId: it.itemId, vaultId: it.vaultId, rev: it.rev, formatVersion: it.formatVersion, doc });
    } catch {
      /* undecryptable — skip */
    }
  }
  return items;
}

// ---- matching ----

function loginItems(): DecryptedItem[] {
  return session ? session.items.filter((i) => i.doc.type === "login") : [];
}

/** Login items whose saved uris match the page host — canonical urimatch (spec 02 §3.1) over a
 *  browser FillTarget. The host is normalized here (location.host may carry a port); saved
 *  androidapp:// entries classify kind:"app" and correctly never match a web target. */
function matchesFor(host: string): DecryptedItem[] {
  const webHost = normalizeHost(host);
  if (!webHost) return [];
  const target: FillTarget = { webHost, packageName: "" };
  return loginItems().filter((it) => matchLogins(it.doc.login?.uris ?? [], target, pslResolve));
}

function toMatchItem(it: DecryptedItem, siteMatch: boolean): MatchItem {
  return {
    itemId: it.itemId,
    name: it.doc.name,
    username: it.doc.login?.username ?? null,
    uris: it.doc.login?.uris ?? [],
    siteMatch,
    hasTotp: Boolean(it.doc.login?.totp),
  };
}

// ---- cards (popup copy-only group — the fill/save paths above stay login-only by design) ----

function cardItems(): DecryptedItem[] {
  return session ? session.items.filter((i) => i.doc.type === "card") : [];
}

/** Masked, list-safe projection — the number/expiry/CVV never ride a list (messages contract). */
function toCardItem(it: DecryptedItem): CardItem {
  const c = it.doc.card;
  return {
    itemId: it.itemId,
    name: it.doc.name,
    subtitle: cardSubtitle(c?.number),
    hasNumber: digitsOnly(c?.number ?? "") !== "",
    hasExpiry: composeShortExpiry(c?.expMonth ?? "", c?.expYear ?? "") !== null,
    hasCvv: (c?.securityCode ?? "") !== "",
  };
}

// ---- reveal + popup fill (the ZK egress gate) ----

/** Contract reveal rules: host-match ∨ one-shot popup grant (consumed) ∨ explicit user pick.
 *  Cut M (v2 #14): failures carry a seam `code` so the fill surfaces render canon copy — the
 *  raw `error` strings here are debug detail and must never reach a user. */
function reveal(msg: Extract<Req, { type: "reveal" }>, sender: chrome.runtime.MessageSender): Res<"reveal"> {
  if (!session) return { ok: false, code: "locked", error: "locked" };
  const it = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "login");
  if (!it) return { ok: false, code: "not_allowed", error: "unknown item" };

  const webHost = normalizeHost(msg.host);
  let allowed =
    msg.explicit === true || (webHost !== null && matchLogins(it.doc.login?.uris ?? [], { webHost, packageName: "" }, pslResolve));
  const tabId = sender.tab?.id;
  // A popup fill grant is redeemable ONLY by the tab's TOP frame (fillFromPopup targets frameId 0).
  // Without this, a host-matched top frame leaves the grant armed and a hostile cross-origin
  // sub-frame — which reveal() would otherwise NOT host-match — claims the secret from it.
  const isTopFrame = sender.frameId === undefined || sender.frameId === 0;
  if (!allowed && tabId !== undefined && isTopFrame) {
    const g = grants.get(tabId);
    if (g && g.itemId === msg.itemId && g.expiresMs > Date.now()) {
      grants.delete(tabId); // one-shot
      allowed = true;
    }
  }
  if (!allowed) return { ok: false, code: "not_allowed", error: "not allowed for this site" };

  let totpCode: string | null = null;
  const totp = it.doc.login?.totp;
  if (totp) {
    try {
      totpCode = currentCode(totp, Date.now()).code;
    } catch {
      /* malformed stored totp — the credential fill still proceeds */
    }
  }
  return {
    ok: true,
    secret: { username: it.doc.login?.username ?? null, password: it.doc.login?.password ?? null, totpCode },
  };
}

/** Card copy egress — POPUP ONLY (a sender with a tab is a content script ⇒ refused): the
 *  in-page path must have NO route to card data until the frame-origin egress contract ships
 *  (cards design 2026-07-09). Cards are deliberately not uri-bound, so there is no host gate —
 *  the gate is the explicit click on a copy button in OUR popup plus the unlocked session.
 *  ONE field per request: the popup receives exactly what lands on the clipboard, no more. */
function revealCardField(
  msg: Extract<Req, { type: "revealCardField" }>,
  sender: chrome.runtime.MessageSender,
): Res<"revealCardField"> {
  if (sender.tab !== undefined) return { ok: false, error: "not allowed from a page" };
  if (!session) return { ok: false, error: "locked" };
  const c = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "card")?.doc.card;
  if (!c) return { ok: false, error: "unknown item" };
  switch (msg.field) {
    case "number": {
      const d = digitsOnly(c.number ?? "");
      return d !== "" ? { ok: true, value: d } : { ok: false, error: "no number on this card" };
    }
    case "expiry": {
      const e = composeShortExpiry(c.expMonth ?? "", c.expYear ?? "");
      return e !== null ? { ok: true, value: e } : { ok: false, error: "no expiry on this card" };
    }
    case "cvv": {
      const s = c.securityCode ?? "";
      return s !== "" ? { ok: true, value: s } : { ok: false, error: "no security code on this card" };
    }
  }
}

/** Cut M (v2 #14): shape-check the content script's sendResponse before trusting it as an
 *  outcome — an old/orphaned script (or a frame answering nothing) yields undefined, which must
 *  read as "no verdict", never as success. */
function asFillOutcome(v: unknown): FillOutcome | null {
  if (typeof v !== "object" || v === null) return null;
  const f = (v as { filled?: unknown }).filled;
  return f === "both" || f === "username" || f === "password" || f === "nothing" ? (v as FillOutcome) : null;
}

/** Explicit popup pick → mint the tab's one-shot grant, then tell the tab to run its normal
 *  reveal round-trip. Single secret-egress path: the SW never pushes a secret at a tab.
 *  Cut M (v2 #14): `ok` used to mean sendMessage DELIVERY, so the popup closed over a fill
 *  that wrote nothing — now the content script answers its real FillOutcome and ok is true
 *  only when something actually landed in a field. */
async function fillFromPopup(itemId: string): Promise<Res<"fillFromPopup">> {
  if (!session) return { ok: false, code: "locked", error: "locked" };
  if (!session.items.some((i) => i.itemId === itemId && i.doc.type === "login")) {
    return { ok: false, code: "not_allowed", error: "unknown item" };
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { ok: false, code: "unreachable", error: "no active tab" };
  grants.set(tab.id, { itemId, expiresMs: Date.now() + GRANT_TTL_MS });
  const msg: TabMsg = { type: "fillItem", itemId };
  let raw: unknown;
  try {
    // Top frame ONLY — both the message and the grant (redeemed in reveal()) are frame-0-bound so
    // a cross-origin sub-frame can neither receive the fill request nor consume the grant.
    raw = await chrome.tabs.sendMessage(tab.id, msg, { frameId: 0 });
  } catch {
    grants.delete(tab.id);
    return { ok: false, code: "unreachable", error: "page not reachable — reload the tab and retry" };
  }
  // The fill round-trip is over — void any unconsumed grant (e.g. the content answered no_form
  // before its reveal ran) rather than leaving it armed for the 30 s TTL.
  grants.delete(tab.id);
  const outcome = asFillOutcome(raw);
  if (!outcome) return { ok: false, code: "unreachable", error: "no fill outcome from the page" };
  if (outcome.filled === "nothing") {
    return { ok: false, outcome, code: outcome.code ?? "no_fields", error: `fill wrote nothing (${outcome.code ?? "no_fields"})` };
  }
  return { ok: true, outcome };
}

// ---- S3 in-page card fill (the frame-origin egress contract — design 2026-07-10) ----
// Card data leaves the SW ONLY via revealCardForFill, one field-set per explicit popup click,
// bound to the exact frame that detected the form (frameId + sender.origin + a live top-origin
// recheck), one-shot, in a store SEPARATE from login grants. The popup-only messages refuse tab
// senders; the content path can neither mint a grant nor enumerate offers.

/** The tab's CURRENT top-level origin, read from `tab.url` under the popup-open `activeTab` window
 *  ([A4] — the manifest has NO `tabs` permission; needing `tab.url` outside this window would be a
 *  permission bump + a re-review). Fail-closed ([A3]): null on an unreadable/empty/opaque URL — a
 *  missing URL is NEVER a match, and `null === null` never passes an eligibility check below. */
async function topOrigin(tabId: number): Promise<string | null> {
  try {
    const t = await chrome.tabs.get(tabId);
    if (typeof t.url !== "string" || t.url === "") return null;
    const o = new URL(t.url).origin;
    return o === "null" ? null : o; // opaque/sandboxed top → never eligible ([A1])
  } catch {
    return null;
  }
}

/** Content (per frame): record/clear this frame's card form. [A2]/[A3]: identity binds to
 *  browser-set `sender.origin` ONLY (no page-controlled host), fail-closed on any undefined. */
async function cardFormInfo(
  msg: Extract<Req, { type: "cardFormInfo" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"cardFormInfo">> {
  const tabId = sender.tab?.id;
  const frameId = sender.frameId;
  if (tabId === undefined || frameId === undefined || typeof sender.origin !== "string" || sender.origin === "" || sender.origin === "null") {
    return { ok: false };
  }
  const st = tabs.get(tabId) ?? {};
  const forms = st.cardForms ?? {};
  if (msg.fields.length === 0) delete forms[frameId];
  else forms[frameId] = { origin: sender.origin, fields: msg.fields };
  st.cardForms = forms;
  tabs.set(tabId, st);
  persistTabs();
  return { ok: true };
}

/** Popup ONLY: is the active tab fillable, and to which origin? Fillable iff a recorded card
 *  form's origin equals the tab's current top-level origin (SW-derived). Refuses tab senders. */
async function cardFillOffers(sender: chrome.runtime.MessageSender): Promise<Res<"cardFillOffers">> {
  if (sender.tab !== undefined) return { fillable: false, origin: null }; // popup-only guard
  if (!session) return { fillable: false, origin: null };
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { fillable: false, origin: null };
  const top = await topOrigin(tab.id);
  if (top === null) return { fillable: false, origin: null };
  const forms = tabs.get(tab.id)?.cardForms ?? {};
  const eligible = Object.values(forms).some((f) => f.origin === top);
  return { fillable: eligible, origin: eligible ? top : null };
}

/** Shape-check the granted frame's sendResponse before trusting it (mirrors asFillOutcome). */
function asCardFillOutcome(v: unknown): CardFillOutcome | null {
  if (typeof v !== "object" || v === null) return null;
  const f = (v as { filled?: unknown }).filled;
  return f === "card" || f === "nothing" ? (v as CardFillOutcome) : null;
}

/** Popup ONLY: mint the tab's one-shot CARD grant for the eligible frame, then send `fillCard` to
 *  THAT frame only. The frame redeems via revealCardForFill (the value round-trip) — the SW never
 *  pushes card values at a tab. Refuses tab senders. */
async function fillCardFromPopup(itemId: string, sender: chrome.runtime.MessageSender): Promise<Res<"fillCardFromPopup">> {
  if (sender.tab !== undefined) return { ok: false, code: "not_allowed", error: "not allowed from a page" };
  if (!session) return { ok: false, code: "locked", error: "locked" };
  if (!session.items.some((i) => i.itemId === itemId && i.doc.type === "card")) {
    return { ok: false, code: "not_allowed", error: "unknown item" };
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { ok: false, code: "unreachable", error: "no active tab" };
  const top = await topOrigin(tab.id);
  if (top === null) return { ok: false, code: "not_allowed", error: "no top origin" };
  // The eligible frame = a recorded card form whose origin equals the current top origin. Prefer
  // the top frame (0) when it qualifies; else the first eligible frame.
  const forms = tabs.get(tab.id)?.cardForms ?? {};
  const eligible = Object.entries(forms).filter(([, f]) => f.origin === top).map(([fid]) => Number(fid));
  if (eligible.length === 0) return { ok: false, code: "no_form", error: "no eligible card form" };
  const frameId = eligible.includes(0) ? 0 : eligible[0]!;
  cardGrants.set(tab.id, { itemId, frameId, origin: top, expiresMs: Date.now() + GRANT_TTL_MS });
  const msg: TabMsg = { type: "fillCard", itemId };
  let raw: unknown;
  try {
    raw = await chrome.tabs.sendMessage(tab.id, msg, { frameId });
  } catch {
    cardGrants.delete(tab.id);
    return { ok: false, code: "unreachable", error: "frame not reachable — reload the tab and retry" };
  }
  // Round-trip over — void any unconsumed grant rather than leaving it armed for the TTL.
  cardGrants.delete(tab.id);
  const outcome = asCardFillOutcome(raw);
  if (!outcome) return { ok: false, code: "unreachable", error: "no fill outcome from the page" };
  if (outcome.filled === "nothing") {
    return { ok: false, outcome, code: outcome.code ?? "no_fields", error: `card fill wrote nothing (${outcome.code ?? "no_fields"})` };
  }
  return { ok: true, outcome };
}

/** Content (S3 redemption): return the declared card fields to the granted frame ONCE. Every
 *  check fails CLOSED on undefined ([A3]); success consumes the grant, any failure consumes
 *  nothing. This is a store SEPARATE from login `grants` — it can ONLY match a card grant, never a
 *  login one ([A5]). PAN/CVV are composed here and never touch `snapshots`/the save path ([A6]). */
async function revealCardForFill(
  msg: Extract<Req, { type: "revealCardForFill" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"revealCardForFill">> {
  if (!session) return { ok: false, error: "locked" };
  const tabId = sender.tab?.id;
  if (tabId === undefined) return { ok: false, error: "not a page sender" };
  const grant = cardGrants.get(tabId);
  if (!grant || grant.itemId !== msg.itemId || grant.expiresMs <= Date.now()) return { ok: false, error: "no card grant" };
  // Frame + origin: fail-closed on undefined (first-ever sender.origin reliance in the extension),
  // then the positive equality binding.
  const frameOk = sender.frameId === grant.frameId;
  const originOk = sender.origin === grant.origin;
  if (sender.frameId === undefined || !frameOk) return { ok: false, error: "frame mismatch" };
  if (sender.origin === undefined || !originOk) return { ok: false, error: "origin mismatch" };
  // A navigation between the click and this redemption voids the fill: the grant's origin must
  // still equal the tab's CURRENT top-level origin (re-fetched from tab.url).
  const top = await topOrigin(tabId);
  const topOk = grant.origin === top;
  if (top === null || !topOk) return { ok: false, error: "top-origin changed" };

  const item = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "card");
  const c = item?.doc.card;
  if (!c) return { ok: false, error: "unknown item" }; // consumes nothing
  // Compose ONLY the kinds the detected form declared ("CVV only if a CVV field was detected").
  const declared = new Set(tabs.get(tabId)?.cardForms?.[grant.frameId]?.fields ?? []);
  const fields: CardFillFields = {};
  if (declared.has("cardnumber")) {
    const n = digitsOnly(c.number ?? "");
    if (n !== "") fields.number = n;
  }
  if (declared.has("cardexpiry") || declared.has("cardexpmonth") || declared.has("cardexpyear")) {
    const e = composeShortExpiry(c.expMonth ?? "", c.expYear ?? "");
    if (e !== null) fields.expiry = e;
  }
  if (declared.has("cardname")) {
    const nm = c.cardholderName ?? "";
    if (nm !== "") fields.name = nm;
  }
  if (declared.has("cardcvv")) {
    const s = c.securityCode ?? "";
    if (s !== "") fields.cvv = s;
  }
  cardGrants.delete(tabId); // one-shot: success consumes the grant
  return { ok: true, fields };
}

// ---- capture → pending save → resolve ----

/** Page host from a captured URL (content sends location.href), normalized like a match target. */
function hostOfUrl(url: string): string | null {
  try {
    return normalizeHost(new URL(url).host);
  } catch {
    return normalizeHost(url);
  }
}

/** The password (and the owning frameId) NEVER ride a pending-save answer — metadata only. */
function publicPending(p: PendingSave & { password: string }): PendingSave {
  return { host: p.host, username: p.username, updatesItemId: p.updatesItemId, updatesItemName: p.updatesItemName, updatesItemUsername: p.updatesItemUsername };
}

/** Content senders carry their tab; the popup asks about the active tab. */
async function contextTabId(sender: chrome.runtime.MessageSender): Promise<number | undefined> {
  if (sender.tab?.id !== undefined) return sender.tab.id;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.id;
}

async function capturedCredential(
  msg: Extract<Req, { type: "capturedCredential" }>,
  sender: chrome.runtime.MessageSender,
): Promise<Res<"capturedCredential">> {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return { ok: false }; // captures come from pages only
  const frameId = sender.frameId ?? 0;
  const host = hostOfUrl(msg.url);
  if (!host) return { ok: false };
  const st = tabs.get(tabId) ?? {};

  // A live pending belongs to the frame that captured it. Reject an overwrite from a DIFFERENT
  // frame (a hostile sub-frame firing a synthetic submit to hijack the top frame's Save banner);
  // the owning frame may still update its own capture (user corrects the password).
  if (msg.password && st.pending && st.pending.frameId !== frameId) return { ok: true };

  if (!msg.password) {
    // Username-only page (multi-step step 1) — remember it for the password page. Sticky for
    // the tab's life so a wrong-password retry still has it; newer captures overwrite.
    if (msg.username) {
      st.lastUsername = msg.username;
      tabs.set(tabId, st);
      persistTabs();
    }
    return { ok: true };
  }

  const username = msg.username || st.lastUsername || "";
  // Save-vs-update target (capture-time). A username picks the exact (host ∧ username) match; a
  // password-only submit (username "") falls back to a password-equal item (2a — a re-login) or a
  // lone host login (2b — a password change), else a new item (2c). Locked ⇒ matchesFor() is empty
  // ⇒ records save-new; resolve re-checks post-unlock with a STRICTER rule (no silent 2b clobber).
  const existing = saveTargetFor(matchesFor(host), username, msg.password);
  if (existing && (existing.doc.login?.password ?? "") === msg.password) {
    // Unchanged password (a re-login of a known item — 2a) — every successful re-login would banner otherwise.
    if (st.pending) {
      st.pending = undefined;
      tabs.set(tabId, st);
      persistTabs();
    }
    return { ok: true };
  }

  const pending: PendingSave & { password: string; frameId: number } = {
    host,
    username,
    updatesItemId: existing?.itemId ?? null,
    updatesItemName: existing?.doc.name ?? null,
    updatesItemUsername: existing?.doc.login?.username ?? null,
    password: msg.password,
    frameId,
  };
  st.pending = pending;
  tabs.set(tabId, st);
  persistTabs();
  return { ok: true, pending: publicPending(pending) };
}

async function resolvePendingSave(
  action: "save" | "dismiss",
  sender: chrome.runtime.MessageSender,
): Promise<Res<"resolvePendingSave">> {
  const tabId = await contextTabId(sender);
  const st = tabId === undefined ? undefined : tabs.get(tabId);
  const pending = st?.pending;
  if (tabId === undefined || !st || !pending) return { ok: false, error: "nothing pending" };

  if (action === "dismiss") {
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
    return { ok: true };
  }

  // Pending survives a locked failure so unlock → save can still land it. The surface maps the
  // CODE to copy — the SW's raw "locked" string must never reach the banner (extux-03).
  if (!session || !session.personalVaultId) return { ok: false, code: "locked", error: "locked" };

  // Re-decide save-vs-update NOW (the capture-time decision is stale if the vault was LOCKED then —
  // matchesFor was empty ⇒ updatesItemId null). resolveSaveAction only auto-updates on UNAMBIGUOUS
  // same-account signals: it NEVER runs the ambiguous "lone host login" (2b) fallback here (a
  // locked-at-capture password-only submit for a DIFFERENT account would otherwise clobber the
  // host's single login — data loss), and it suppresses ONLY a password-only re-login (never drops
  // a username-present new account that reuses a password).
  const decision = resolveSaveAction(
    pending.updatesItemId ? session.items.find((i) => i.itemId === pending.updatesItemId) : undefined,
    matchesFor(pending.host),
    pending.username,
    pending.password,
  );
  if (decision.kind === "suppress") {
    // 2a re-login of a known item (reachable via the locked-at-capture path, where the :967
    // unchanged-password suppress couldn't run) — nothing to save; don't mint a duplicate.
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
    return { ok: true };
  }
  let result: Res<"resolvePendingSave">;
  if (decision.kind === "update") {
    // Update = the same doc with ONLY the password swapped — uris tail, totp, notes, favorite,
    // attachments all ride the spread — put against the rev we decrypted (server 409s a racer).
    const doc: ItemDoc = { ...decision.target.doc, login: { ...decision.target.doc.login, password: pending.password } };
    result = await putExisting(decision.target, doc);
  } else {
    // New login — the frozen/username target vanished, or a locked-2b / 2c ambiguity (recoverable New).
    result = await putNewLogin(pending.host, pending.username, pending.password);
  }
  if (result.ok) {
    st.pending = undefined;
    tabs.set(tabId, st);
    persistTabs();
  }
  return result;
}

// ---- writes (seal → push → confirm) ----

/** Seal + push one put over the existing envelope path; answers the per-mutation result.
 *  `formatVersion` is computed ONCE by the caller and used for BOTH the AD binding and the
 *  wire field (web ItemUpload pattern) — restating it anywhere would let the two diverge
 *  into an AD mismatch. */
async function putItem(
  itemId: string,
  vaultId: string,
  doc: ItemDoc,
  baseItemRev: number,
  formatVersion: number,
): Promise<MutationResult | undefined> {
  const vk = session?.vaultKeys.get(vaultId);
  if (!vk) return undefined;
  const blob = toB64(seal(vk, new TextEncoder().encode(JSON.stringify(doc)), adItem(vaultId, itemId, formatVersion)));
  writesInFlight++; // hold off resync's wholesale session.items replace until this rev lands
  try {
    const resp = await api.push([
      {
        mutationId: crypto.randomUUID(),
        op: "put",
        itemId,
        vaultId,
        baseItemRev,
        // attachmentIds mirrors the doc (web putMutation parity) — [] on an update would orphan blobs.
        item: { formatVersion, attachmentIds: doc.attachments?.map((a) => a.id) ?? [], blob },
      },
    ]);
    return resp.results[0];
  } finally {
    writesInFlight--;
  }
}

/** Map a non-applied push status to the seam SaveErrorCode (E1-5): `conflict` is the one distinct
 *  case; denied/duplicate/no-vault-key/undefined all fold to "failed". The `error` string is
 *  debug-only detail the surface never renders (it maps the CODE to copy). */
function saveFailure(status: MutationResult["status"] | undefined): { ok: false; code: SaveErrorCode; error: string } {
  const code: SaveErrorCode = status === "conflict" ? "conflict" : "failed";
  return { ok: false, code, error: `save failed (${status ?? "no vault key"})` };
}

async function putExisting(target: DecryptedItem, doc: ItemDoc): Promise<{ ok: boolean; code?: SaveErrorCode; error?: string }> {
  // Monotonic re-seal: never below the fv the item arrived at (web Account.itemFv parity —
  // the server refuses fv downgrades). The extension's per-doc floor is constant
  // LOGIN_FORMAT_VERSION: every putExisting caller filters type==="login", and the extension
  // never writes card docs (a card's floor would be 2).
  const fv = Math.max(LOGIN_FORMAT_VERSION, target.formatVersion);
  const r = await putItem(target.itemId, target.vaultId, doc, target.rev, fv);
  if (r?.status !== "applied") return saveFailure(r?.status);
  target.doc = doc;
  target.rev = r.newItemRev ?? target.rev + 1;
  target.formatVersion = fv; // what this write actually sealed at (web store.ts parity)
  persistSession();
  return { ok: true };
}

async function putNewLogin(host: string, username: string, password: string): Promise<{ ok: boolean; code?: SaveErrorCode; error?: string }> {
  if (!session || !session.personalVaultId) return { ok: false, code: "locked", error: "locked or no personal vault" };
  const itemId = crypto.randomUUID();
  const doc: ItemDoc = { type: "login", name: host, login: { username, password, uris: [`https://${host}`] } };
  // NEW items seal at the login doc floor — the extension only ever creates logins (format.ts).
  const r = await putItem(itemId, session.personalVaultId, doc, 0, LOGIN_FORMAT_VERSION);
  if (r?.status !== "applied") return saveFailure(r?.status);
  const rev = r.newItemRev ?? 1; // matchable immediately:
  session.items.push({ itemId, vaultId: session.personalVaultId, rev, formatVersion: LOGIN_FORMAT_VERSION, doc });
  persistSession();
  return { ok: true };
}

/** One-tap URI backfill for legacy items: append https://<host>, keep the real tail, shed the
 *  unmatchable "" entries the web editor leaves on untouched items. Idempotent per host. */
async function linkUri(itemId: string, host: string): Promise<Res<"linkUri">> {
  if (!session) return { ok: false, error: "locked" };
  const it = session.items.find((i) => i.itemId === itemId && i.doc.type === "login");
  if (!it) return { ok: false, error: "unknown item" };
  const webHost = normalizeHost(host);
  if (!webHost) return { ok: false, error: "bad host" };
  const kept = (it.doc.login?.uris ?? []).filter((u) => u.trim() !== "");
  const already = kept.some((u) => {
    const p = parseSavedUri(u);
    return p?.kind === "web" && p.host === webHost;
  });
  if (already) return { ok: true }; // nothing to push
  const doc: ItemDoc = { ...it.doc, login: { ...it.doc.login, uris: [...kept, `https://${webHost}`] } };
  return putExisting(it, doc);
}
