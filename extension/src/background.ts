import { AndvariApi, ApiError, clampAutoLockSeconds, clampClipboardClearSeconds, type MutationResult, type SessionResponse, type SyncResponse } from "./api";
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
  EnrollCode,
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
import { QuickUnlock, PIN_KDF_MIN_MEM_BYTES, PIN_KDF_MIN_OPS, type QuCoKey, type QuRecord, type QuStore } from "./quickunlock";
import { DEFAULT_SERVER_URL, getServerUrl, nsKey, originKeyFor, originMatchPattern, SERVER_URL_KEY } from "./serverurl";
import { armGate, withRedeemInFlight } from "./locksequence";
import { applyServerSwitch, purgeServerDataFor } from "./serverswitch";

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
// ---- server endpoint + per-origin namespace (design 2026-07-15 §5.1/§4.2) ----
// The baked tailnet constant is GONE: the origin is a per-device choice in storage.local
// (serverurl.ts), preconfigured for DEFAULT_SERVER_URL. `serverReady` below loads it before any
// network/namespace use; a storage change of SERVER_URL_KEY is an origin-clean switch (§4.1).
let serverUrl = DEFAULT_SERVER_URL;
let currentOriginKey = originKeyFor(DEFAULT_SERVER_URL);
/** A storage key under the CURRENT origin's namespace (§4.2/B2-7): quick-unlock/PIN co-key
 *  material and cached per-origin state live under `ns.<originKey>.<key>`, so a server switch can
 *  never read, mint, or wipe another origin's material. Computed at CALL time — the switch path
 *  locks under the OLD key, then flips `currentOriginKey`. */
const nsk = (key: string): string => nsKey(currentOriginKey, key);

const SKEY = "session"; // storage.session: SessionSnapshot
const TKEY = "tabs"; //    storage.session: Record<tabId, TabState>
const NKEY = "lockNotice"; // storage.session: { kind:"idle"; seconds } — F26 reason line (E1-7)
// Extension quick-unlock Tier B (spec 01 §8.4). QKEY is a DISTINCT storage.session key (breaker B3):
// ensureLoaded MUST NOT hydrate `session` from it, so a locked-armed record leaves every `!session`
// gate reporting fully locked. DKEY is the durable, NON-secret offer-card dismissed-once flag (breaker
// B7). The non-extractable co-key lives in IndexedDB (below) — wiped on every QKEY wipe (breaker A1).
// The five keys below are PER-ORIGIN state and are stored under `nsk(...)` (§4.2/B2-7): the
// quick-unlock record + offer flag belong to the account/server they were minted against, and the
// update-channel state describes ONE origin's /downloads channel (an unscoped USEQ would let one
// origin's seq numbering poison another's anti-rollback). Every read/write goes through nsk().
const QKEY = "quickUnlock"; // storage.session, namespaced: QuRecord (blob + counter + locked-token stash)
const DKEY = "quOfferDismissed"; // storage.local, namespaced (non-secret): the offer card was dismissed once
const UKEY = "updateInfo"; // storage.local, namespaced (non-secret): UpdateInfo while a newer build is live
const ULAST = "updateCheckedAt"; // storage.local, namespaced: epoch ms of the last COMPLETED update fetch
const USEQ = "updateAcceptedSeq"; // storage.local, namespaced: highest signed-manifest seq ever accepted (§B anti-rollback)
const UQUIET = "updateChannelQuiet"; // storage.local, namespaced: { reason } — H2 fail-closed-QUIET (§M-D5), never a nag
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
  /** UVK custody, MEMORY-ONLY (breaker B1) — retained for the unlocked lifetime so quick-unlock enroll
   *  can wrap it; NEVER written to storage.session/local. Absent on a snapshot-restored session (SW was
   *  evicted) → enroll must trigger a fresh full unlock. */
  uvk?: Uint8Array;
  /** How this session was opened. `enroll` COPIES the surviving full-password stamp regardless, but the
   *  provenance makes the "never mint `now` from a QUICK session" invariant (breaker A4) explicit. */
  provenance: "PASSWORD" | "QUICK";
  /** The last full-master-password unlock time. A quick unlock carries the blob's COPIED stamp (never
   *  `now`), so re-enrolling from a QUICK session cannot extend the 24 h quick-unlock window (breaker A4). */
  lastFullUnlockAt: number;
}

/** What survives SW death (JSON-safe: keys as b64 — Uint8Array doesn't cross chrome.storage). The UVK
 *  is deliberately NOT here (breaker B1 — memory-only custody); provenance + lastFullUnlockAt ride so
 *  the quick-unlock 24 h-window invariant (breaker A4) survives a wake. */
interface SessionSnapshot {
  /** The server origin this snapshot's tokens belong to (§4.1 rule 1). ensureLoaded refuses to
   *  hydrate a snapshot minted against a DIFFERENT origin — e.g. the server was switched while the
   *  SW was dead — so persisted tokens can never replay across a serverUrl change. */
  origin: string;
  access: string;
  refresh: string | null;
  userId: string;
  email: string;
  personalVaultId: string;
  autoLockSeconds: number;
  clipboardClearSeconds: number;
  mustChangePassword: boolean;
  provenance: "PASSWORD" | "QUICK";
  lastFullUnlockAt: number;
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

/** Build the api client for [url] with its custodial handlers attached. A server switch swaps in a
 *  FRESH instance (never a mutated baseUrl — §4.1 rule 1/B1-5: a new instance holds no tokens, so
 *  an Authorization header can never cross a baseUrl change; the old instance becomes garbage). */
function makeApi(url: string): AndvariApi {
  const a = new AndvariApi(url, chrome.runtime.getManifest().version);
  // Awaited on every pair mutation — the consumed refresh token must reach the snapshot BEFORE the
  // refresh POST (a stale persisted pair resurrected on SW wake = revoked device). While unlocked it
  // lands in the full SessionSnapshot; DURING a quick-unlock redeem (session still null) it lands in the
  // locked-token stash so a mid-refresh SW death never resurrects a spent token (breaker A5, AM1 parity).
  a.onTokensChanged = () => persistTokens();
  // A 426 min-version pin (spec 03 §1) surfaces via checkForUpdate → the existing update banner is
  // the download surface. checkForUpdate hits the static /downloads route (not api.ts), so it can
  // never itself 426 — no re-entry loop (AM4).
  a.onUpgradeRequired = () => void checkForUpdate(true);
  return a;
}
let api = makeApi(serverUrl);

/** Resolves once the persisted server origin is loaded and `serverUrl`/`currentOriginKey`/`api`
 *  reflect it (plus the §4.2 one-shot legacy-key adoption). EVERY path that touches the api, the
 *  per-origin namespace, or the network awaits this first (ensureLoaded, doLock, checkForUpdate) —
 *  the module-eval placeholders above exist only so the symbols are never undefined. */
const serverReady: Promise<void> = (async () => {
  try {
    const url = await getServerUrl();
    if (url !== serverUrl) {
      serverUrl = url;
      currentOriginKey = originKeyFor(url);
      api = makeApi(url);
    }
  } catch {
    /* storage unavailable — stay on the baked default (getServerUrl already folds most failures) */
  }
  await adoptLegacyNamespaceOnce();
})();

// ---- quick-unlock Tier B engine (spec 01 §8.4) ----
// The non-extractable co-key (breaker A1) persists in IndexedDB — a service worker CAN open IDB, and
// IDB round-trips a non-extractable CryptoKey via structured clone without ever exposing its bytes.
const IDB_NAME = "andvari-qu";
const IDB_STORE = "cokey";
const IDB_KEY = "k_nonexp";

function idbOpen(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("idb open failed"));
  });
}
function idbRun<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest | null): Promise<T> {
  return idbOpen().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const tx = db.transaction(IDB_STORE, mode);
        let result: T;
        const r = fn(tx.objectStore(IDB_STORE));
        if (r) r.onsuccess = () => (result = r.result as T);
        tx.oncomplete = () => {
          db.close();
          resolve(result);
        };
        tx.onerror = () => {
          db.close();
          reject(tx.error ?? new Error("idb tx failed"));
        };
        tx.onabort = () => {
          db.close();
          reject(tx.error ?? new Error("idb tx aborted"));
        };
      }),
  );
}

// Both quick-unlock stores key by the CURRENT origin's namespace at CALL time (§4.2/B2-7): a
// server switch leaves the old origin's record + co-key standing under its own keys — redeemable
// again on return, bounded by the staleness ceiling — and every wipe-class event (sign-out,
// exhausted attempts, policy-forbid) erases ONLY the origin it happened under.
const quCoKey: QuCoKey = {
  async generate() {
    const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, /* extractable */ false, ["encrypt", "decrypt"]);
    await idbRun<void>("readwrite", (s) => s.put(k, nsk(IDB_KEY)));
    return k;
  },
  async get() {
    try {
      return (await idbRun<CryptoKey | undefined>("readonly", (s) => s.get(nsk(IDB_KEY)))) ?? null;
    } catch {
      return null; // IDB unavailable / co-key gone → treated as a corrupt blob at redeem
    }
  },
  async delete() {
    try {
      await idbRun<void>("readwrite", (s) => s.delete(nsk(IDB_KEY)));
    } catch {
      /* nothing to delete / IDB unavailable */
    }
  },
};

/** The DISTINCT storage.session record slot (breaker B3). `remove` deletes the key DIRECTLY (breaker
 *  A7/A10/B7) — never via persistSession, which early-returns when session===null. */
const quStore: QuStore = {
  async read() {
    const key = nsk(QKEY);
    const got = await chrome.storage.session.get(key);
    return (got[key] as QuRecord | undefined) ?? null;
  },
  write: (rec) => chrome.storage.session.set({ [nsk(QKEY)]: rec }),
  remove: () => chrome.storage.session.remove(nsk(QKEY)),
};

/** §4.2 adoption one-shot: pre-namespacing builds kept this material under BARE keys. Move it into
 *  the CURRENT origin's namespace once — for every fielded install the current origin IS the new
 *  default, and the tailnet front + the public origin are two fronts of the SAME instance (§6.4),
 *  so the adopted quick-unlock blob/co-key stay redeemable. Idempotent + retried: the flag is
 *  stamped only after all moves succeed; a partial move re-runs and no-ops the already-moved keys. */
const NS_ADOPTED_KEY = "nsAdoptedOnce";
async function adoptLegacyNamespaceOnce(): Promise<void> {
  try {
    if ((await chrome.storage.local.get(NS_ADOPTED_KEY))[NS_ADOPTED_KEY] === true) return;
    // storage.local: the offer-dismissed flag + the update-channel state.
    const legacyLocal = [DKEY, UKEY, ULAST, USEQ, UQUIET];
    const got = await chrome.storage.local.get(legacyLocal);
    const moved: Record<string, unknown> = {};
    for (const k of legacyLocal) if (got[k] !== undefined) moved[nsk(k)] = got[k];
    if (Object.keys(moved).length > 0) await chrome.storage.local.set(moved);
    await chrome.storage.local.remove(legacyLocal);
    // storage.session: a quick-unlock record armed by the pre-update build (present only if the
    // browser session survived the update).
    try {
      const rec = (await chrome.storage.session.get(QKEY))[QKEY];
      if (rec !== undefined) {
        await chrome.storage.session.set({ [nsk(QKEY)]: rec });
        await chrome.storage.session.remove(QKEY);
      }
    } catch {
      /* storage.session unavailable — nothing to adopt */
    }
    // IndexedDB: the non-extractable co-key moves to its per-origin record key.
    try {
      const k = await idbRun<CryptoKey | undefined>("readonly", (s) => s.get(IDB_KEY));
      if (k) {
        await idbRun<void>("readwrite", (s) => s.put(k, nsk(IDB_KEY)));
        await idbRun<void>("readwrite", (s) => s.delete(IDB_KEY));
      }
    } catch {
      /* IDB unavailable — a missing co-key reads as a corrupt blob at redeem and self-wipes */
    }
    await chrome.storage.local.set({ [NS_ADOPTED_KEY]: true });
  } catch {
    /* best-effort: legacy keys + unset flag remain, so the next SW start retries the adoption */
  }
}

/** One-shot enroll bench (breaker B8). Pure-JS Argon2id is ~linear in memBytes at fixed ops (and 64 MiB
 *  is multi-second), so a 4-candidate scan would cost ~15 s. Instead: measure ONE derive at the FLOOR
 *  (32 MiB / ops 2), then scale memory linearly toward the ~1 s target, capped at 64 MiB and never below
 *  the floor. So a fast machine gets stronger params (toward 64 MiB) while a slow one uses the honest
 *  floor (accepting > 1 s rather than dropping below 32 MiB). Enroll-time only; the result is re-checked
 *  by assertPinKdfParams before it is ever persisted (2 derives total: this measure + the real K_pin). */
async function benchPinParams(): Promise<KdfParams> {
  const targetMs = 1000;
  const CAP_MEM_BYTES = 67_108_864; // 64 MiB — the master floor; never pick PIN params stronger than that
  const STEP = 16 * 1024 * 1024; // round memory to a 16 MiB step
  const floor: KdfParams = { v: 1, alg: "argon2id13", ops: PIN_KDF_MIN_OPS, memBytes: PIN_KDF_MIN_MEM_BYTES };
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const t0 = Date.now();
  try {
    await deriveMasterKeyAsync("andvari-quick-unlock-bench", floor, salt);
  } catch {
    return floor; // couldn't even bench the floor — use it (never go below)
  }
  const floorMs = Math.max(1, Date.now() - t0);
  if (floorMs >= targetMs) return floor; // even the floor is at/over the target — use the floor
  // time ∝ memBytes at fixed ops → the memory that lands ~targetMs, capped + floored + step-rounded.
  const budget = Math.floor((PIN_KDF_MIN_MEM_BYTES * targetMs) / floorMs);
  const memBytes = Math.max(PIN_KDF_MIN_MEM_BYTES, Math.min(CAP_MEM_BYTES, Math.floor(budget / STEP) * STEP));
  return { v: 1, alg: "argon2id13", ops: PIN_KDF_MIN_OPS, memBytes };
}

const quickUnlock = new QuickUnlock({
  store: quStore,
  coKey: quCoKey,
  deriveKPin: (pin, params, salt) => deriveMasterKeyAsync(pin, params, salt),
  benchPinParams,
  now: () => Date.now(),
  randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
});

/** True only while a quick-unlock redeem is between its forced refresh and the session rebuild — the
 *  window where api token mutations must land in the locked-token stash, not the (absent) session. */
let redeemInFlight = false;
/** Single-flight for the quick-unlock redeem (mirrors AndvariApi.refreshInFlight) — two racing popups
 *  submitting a PIN must not each start a redeem and double-spend the attempt counter (breaker A5⊕B4). */
let pinUnlockInFlight: Promise<Res<"unlockWithPin">> | null = null;
/** TOTP unlock seam (0.16.3): a TOTP-enrolled login returns 401 totp_required — we hold the ALREADY-
 *  DERIVED {authKey, wrapKey} so the code retry needs no second ~6 s Argon2id, and let the popup
 *  render a code field. This lives in SW MEMORY ONLY, NEVER storage.session: breaker B1 keeps the
 *  UVK (and UVK-equivalent wrapKey) out of at-rest storage, and while quick-unlock is armed the
 *  storage compartment already holds the plaintext token pair — persisting wrapKey there too would
 *  let a storage-read alone recover the UVK with no PIN and no TOTP. Memory-only means its lifetime
 *  (SW alive — held by the open popup port) exactly matches when the retry can succeed: if the SW is
 *  evicted (popup closed >~30 s while grabbing the code), it's gone → status reports no challenge →
 *  the popup shows the full form → a fresh sign-in. Origin-bound + 5-min fused; every read re-checks. */
const PENDING_TOTP_TTL_MS = 5 * 60 * 1000;
let pendingTotp: { origin: string; email: string; authKey: Uint8Array; wrapKey: Uint8Array; expiresAt: number } | null = null;
let totpUnlockInFlight: Promise<Res<"unlockTotp">> | null = null;
/** Read the live challenge, dropping it if it has expired or the server was switched under it (the
 *  §4.1 origin guard, applied at READ like ensureLoaded does for the session snapshot). */
function livePendingTotp(): typeof pendingTotp {
  if (pendingTotp && (pendingTotp.origin !== serverUrl || Date.now() >= pendingTotp.expiresAt)) pendingTotp = null;
  return pendingTotp;
}
/** Drop the challenge (and its in-memory authKey/wrapKey). Called on every transition to a live
 *  session (full unlock, TOTP redeem, PIN redeem), on sign-out, on server switch, and on cancel. */
function clearPendingTotp(): void {
  pendingTotp = null;
}
/** owns() generation (breaker A5⊕B4): bumped by every lock / sign-out / full unlock. A redeem that
 *  reads a different value after its async KDF/network discards itself rather than clobber new state. */
let redeemGen = 0;

/** onTokensChanged custodian. Unlocked → the full SessionSnapshot. Mid-redeem (session still null) →
 *  the quick-unlock locked-token stash (breaker A5/AM1). Otherwise (locked, not redeeming) → nothing:
 *  there is no live session to attach a stray mutation to. */
function persistTokens(): Promise<void> {
  if (session) return persistSession();
  if (redeemInFlight) return quickUnlock.setLockedTokens(api.getTokens());
  return Promise.resolve();
}
// ---- one-time per SW life; listeners MUST register synchronously (MV3 wake requirement) ----

void chrome.action.setBadgeBackgroundColor({ color: BADGE_BG });
void chrome.action.setBadgeTextColor({ color: BADGE_INK });
// A9⊕B5: storage.session TRUSTED_CONTEXTS is a HARD precondition for quick unlock — the armed record
// is a crackable UVK blob + a LIVE refresh token, so content scripts MUST NOT be able to read it. Both
// Chrome and Firefox MV3 DEFAULT storage.session to TRUSTED_CONTEXTS (content scripts excluded); this
// call re-affirms it. `quCompartmentTrusted` explicitly gates arm below; enroll is IMPLICITLY gated
// (it requires an unlocked `session`, which only exists when storage.session does — the same condition
// that makes quCompartmentTrusted true), and if we can neither call setAccessLevel NOR even see
// storage.session we refuse to arm and fall back to full erase — NEVER a storage.local fallback for the
// blob (that is the rejected durable Tier C, breaker A9).
let quCompartmentTrusted = false;
try {
  void chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  quCompartmentTrusted = true;
} catch {
  // setAccessLevel unimplemented here — the documented default for storage.session is still
  // TRUSTED_CONTEXTS on both engines, so the compartment is trusted-only as long as it EXISTS.
  quCompartmentTrusted = typeof chrome.storage.session?.get === "function";
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
// Both hooks also reconcile the dynamic autofill registration (B2-5) — install/update is exactly
// when a stale or missing registration is most likely.
chrome.runtime.onInstalled.addListener(() => {
  void checkForUpdate(true);
  void serverReady.then(registerAutofillScripts);
});
chrome.runtime.onStartup.addListener(() => {
  void checkForUpdate(true);
  void serverReady.then(registerAutofillScripts);
});
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

// ---- dynamic autofill registration (design §5.1, B2-5 — security-critical) ----
// The static manifest `content_scripts` entry is GONE from both manifests: a static entry's
// exclude_matches is immutable at runtime, so keeping it would inject the autofill UI into every
// SELF-HOSTED vault origin (and adding a dynamic twin would double-inject everywhere else).
// Autofill registers dynamically instead, excludeMatches recomputed from the configured server
// origin + the shipped default. Effective injection is additionally bounded by GRANTED host
// permissions (Chrome: optional_host_permissions granted at runtime; Firefox MV3: all host
// permissions are optional-by-default) — the wave-3 options/grant flow widens the effective set,
// and permissions.onAdded below re-reconciles the moment a grant lands.
const AUTOFILL_SCRIPT_ID = "autofill";

/** Reconcile the registered autofill content script with the current serverUrl. Runs on every SW
 *  start, on install/update, on every server switch, and on every host-permission grant — a
 *  registration that failed (or predates a switch) is detected and self-healed here (§5.1
 *  corollary: a failure means no autofill until the SW next runs, never a mis-scoped injection). */
async function registerAutofillScripts(): Promise<void> {
  const excludeMatches: string[] = [];
  for (const origin of new Set([serverUrl, DEFAULT_SERVER_URL])) {
    const p = originMatchPattern(origin);
    if (p === null) {
      // The vault origin cannot be expressed as a match pattern (e.g. an IPv6-literal host), so it
      // cannot be EXCLUDED — fail CLOSED to "no autofill anywhere" rather than inject into a vault.
      await unregisterAutofillScripts();
      return;
    }
    if (!excludeMatches.includes(p)) excludeMatches.push(p);
  }
  const desired: chrome.scripting.RegisteredContentScript = {
    id: AUTOFILL_SCRIPT_ID,
    matches: ["http://*/*", "https://*/*"],
    excludeMatches,
    js: ["content.js"],
    runAt: "document_idle",
    allFrames: true,
    persistAcrossSessions: true, // survives browser restarts; the SW-start reconcile covers the rest
  };
  try {
    const existing = (await chrome.scripting.getRegisteredContentScripts({ ids: [AUTOFILL_SCRIPT_ID] }))[0];
    if (!existing) {
      await chrome.scripting.registerContentScripts([desired]);
    } else if (!sameStringSet(existing.excludeMatches ?? [], excludeMatches)) {
      await chrome.scripting.updateContentScripts([desired]);
    }
  } catch {
    // Fail CLOSED (review 2026-07-16 D1): a failed register/update must NOT leave a STALE registration
    // whose excludeMatches are the OLD origin while serverUrl has moved to a new (un-excluded) vault
    // origin — that would inject content.js into the new vault's own UI (content.ts has no self-guard).
    // Drop to "no autofill anywhere"; the next SW-start / permissions.onAdded reconcile retries.
    await unregisterAutofillScripts();
  }
}

async function unregisterAutofillScripts(): Promise<void> {
  try {
    await chrome.scripting.unregisterContentScripts({ ids: [AUTOFILL_SCRIPT_ID] });
  } catch {
    /* not registered */
  }
}

function sameStringSet(a: string[], b: string[]): boolean {
  return a.length === b.length && [...a].sort().join("\n") === [...b].sort().join("\n");
}

// B2-5: every SW start reconciles the registration (module scope runs on install, browser
// startup, and every wake — including after a serverUrl change landed while this worker was dead).
void serverReady.then(registerAutofillScripts);
// A runtime host-permission grant (the wave-3 options flow; Firefox's first-run grant) can land
// while the SW is alive — reconcile immediately so autofill starts without a browser restart.
try {
  chrome.permissions.onAdded.addListener(() => void serverReady.then(registerAutofillScripts));
} catch {
  /* permissions events unavailable on this engine — the SW-start reconcile covers it */
}

// ---- server switch (§4.1 origin-clean rules) ----
// The ONLY writer of SERVER_URL_KEY is serverurl.setServerUrl (the wave-3 options page commits
// through the Trust Gate); the SW reacts to the persisted change so the api/WS/namespace/autofill
// all rebuild no matter which surface wrote it. Serialized: two rapid switches apply in order,
// each locking under ITS old namespace first.
let switchChain: Promise<void> = Promise.resolve();
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local" || !(SERVER_URL_KEY in changes)) return;
  switchChain = switchChain.then(applyServerChange).catch(() => {});
});

/** Apply a persisted serverUrl change. Order is the whole story (§4.1): lock under the OLD origin
 *  first — the armed branch stashes the live token pair into the OLD origin's quick-unlock record
 *  (PRESERVED per B2-7, never wiped: an A→B→A round trip keeps A's PIN, bounded by the staleness
 *  ceiling) — then swap in a FRESH api (a new instance carries no tokens, so no Authorization
 *  header can cross the change) + the new namespace key, then recompute the autofill exclusions.
 *  Old-origin namespaces are wiped ONLY via that origin's own policy-forbid or the explicit
 *  wave-3 "remove data for this server" action (purgeOriginNamespace). */
async function applyServerChange(): Promise<void> {
  await ensureLoaded();
  clearPendingTotp(); // a challenge belongs to the OLD origin — never carry its authKey across a switch
  // The §4.1 origin-clean swap ORDER (bump redeemGen → lock-under-OLD → adopt new origin → swap in a
  // FRESH api for it → re-register autofill) lives in the serverswitch leaf, so serverswitch.test.ts
  // drives it with a real AndvariApi and proves no Authorization header crosses the change (B1-5).
  // background wires the chrome-coupled dependencies; the no-op-when-unchanged check is inside the leaf.
  await applyServerSwitch<AndvariApi>({
    nextUrl: await getServerUrl(),
    currentUrl: serverUrl,
    hasSession: session !== null,
    bumpRedeemGen: () => {
      redeemGen++; // an in-flight PIN redeem belongs to the old origin — it discards itself (owns() guard)
    },
    lock: () => doLock("manual"), // still under the OLD originKey: the stash lands in the old namespace
    makeApi,
    installApi: (a) => {
      api = a;
    },
    setOrigin: (u) => {
      serverUrl = u;
      currentOriginKey = originKeyFor(u);
    },
    registerAutofill: registerAutofillScripts,
  });
}

/** Wave-3 hook (§4.2): the ONLY destructive per-origin path. The options page's explicit "remove
 *  data for this server" action — and an origin's own policy-forbid — call this with THAT origin's
 *  key. Removes that origin's namespaced keys everywhere (storage.local + storage.session + the
 *  IDB co-key) and touches nothing else; safe for current and non-current origins alike. */
export async function purgeOriginNamespace(originKey: string): Promise<void> {
  const keys = [QKEY, DKEY, UKEY, ULAST, USEQ, UQUIET].map((k) => nsKey(originKey, k));
  try {
    await chrome.storage.local.remove(keys);
  } catch {
    /* best-effort */
  }
  try {
    await chrome.storage.session.remove(keys);
  } catch {
    /* storage.session unavailable */
  }
  try {
    await idbRun<void>("readwrite", (s) => s.delete(nsKey(originKey, IDB_KEY)));
  } catch {
    /* IDB unavailable */
  }
}

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
    await serverReady; // api/originKey/namespace reflect the persisted origin before any state hydrates
    const got = await chrome.storage.session.get([SKEY, TKEY]);
    let snap = got[SKEY] as SessionSnapshot | undefined;
    // §4.1 rule 1 (no token replay across a serverUrl change): a snapshot minted against another
    // origin is DROPPED, not hydrated — the user re-unlocks at the new server. A pre-0.16 snapshot
    // (no `origin` field) fails the same check: fail closed, never guess.
    if (snap && snap.origin !== serverUrl) {
      snap = undefined;
      await chrome.storage.session.remove(SKEY);
    }
    if (snap && !session) {
      api.setTokens(snap.access || null, snap.refresh);
      session = {
        userId: snap.userId,
        email: snap.email,
        personalVaultId: snap.personalVaultId,
        // mustChangePassword joined the snapshot in 0.10.0 — a ≤0.9.0 snapshot lacks it; false is
        // the safe default (a real rescue re-nudges on the next fresh login anyway).
        mustChangePassword: snap.mustChangePassword ?? false,
        // uvk is intentionally absent here (breaker B1 — never persisted): a snapshot-restored session
        // has no UVK, so enroll on it must trigger a fresh full unlock.
        provenance: snap.provenance ?? "PASSWORD",
        lastFullUnlockAt: typeof snap.lastFullUnlockAt === "number" ? snap.lastFullUnlockAt : 0,
        vaultKeys: new Map(Object.entries(snap.vaultKeys).map(([id, b]) => [id, fromB64(b)])),
        // formatVersion joined the snapshot in 0.7.0 — a session persisted by ≤0.6.1 lacks it,
        // and that client's read gate only admitted fv≤1, so defaulting 1 is exact, not a guess.
        items: snap.items.map((i) => ({ ...i, formatVersion: i.formatVersion ?? 1 })),
      };
      // Re-clamp on restore (§2.3/B1-1 defense-in-depth): a snapshot persisted by a pre-clamp
      // build could carry a server value the ceilings would have refused.
      autoLockSeconds = clampAutoLockSeconds(snap.autoLockSeconds, DEFAULT_AUTOLOCK_SECONDS);
      clipboardClearSeconds = clampClipboardClearSeconds(snap.clipboardClearSeconds, DEFAULT_CLIPBOARD_CLEAR_SECONDS);
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
    origin: serverUrl, // binds the persisted tokens to their server (§4.1 rule 1 — see ensureLoaded)
    access: t.access ?? "",
    refresh: t.refresh,
    userId: session.userId,
    email: session.email,
    personalVaultId: session.personalVaultId,
    autoLockSeconds,
    clipboardClearSeconds,
    mustChangePassword: session.mustChangePassword,
    provenance: session.provenance,
    lastFullUnlockAt: session.lastFullUnlockAt,
    vaultKeys: Object.fromEntries([...session.vaultKeys].map(([id, vk]) => [id, toB64(vk)])),
    items: session.items,
  };
  return chrome.storage.session.set({ [SKEY]: snap });
}

function persistTabs(): void {
  void chrome.storage.session.set({ [TKEY]: Object.fromEntries([...tabs].map(([id, st]) => [String(id), st])) });
}

/** Lock: drop in-memory vault material + the full storage.session snapshot (pending saves hold
 *  plaintext passwords — they lock too). `reason` records WHY for the F26 unlock-form line (E1-7).
 *  The "clipboardclear" backstop alarm deliberately SURVIVES (a secret copied just before an idle lock
 *  still clears on schedule, E1-4).
 *
 *  Quick-unlock Tier B (spec 01 §8.4): an idle/manual lock ARMS if a fresh, non-exhausted blob exists —
 *  it stashes the token pair (breaker B3 armed branch) and KEEPS the slim `{blob, counter, tokens}`
 *  record under the DISTINCT QKEY, erasing everything else exactly as today, so the next unlock can be
 *  a PIN. `signout` (an explicit user action / revocation) NEVER arms and full-wipes the blob + co-key.
 *  When quick unlock is not enrolled, an idle/manual lock stays byte-identical to today's full erase. */
async function doLock(reason: "idle" | "manual" | "signout" = "manual"): Promise<void> {
  // D3: armGate AWAITS ensureLoaded (hydrates the persisted token pair) BEFORE it samples api.getTokens()
  // for the arm decision, returning both the sampled pair (the armed branch stashes it) and the verdict.
  // An idle-autolock alarm can fire into a COLD SW whose `api` holds no tokens yet; sampling before
  // hydration would see {access:null} and WIPE the enrolled quick-unlock instead of arming it — so the
  // ordering lives in the locksequence leaf (locksequence.test.ts pins that reverting to a non-hydrating
  // load re-wipes). ensureLoaded awaits serverReady first, so the arm/wipe lands in the CURRENT origin's
  // namespace (§4.2), and it is idempotent — every other doLock caller (applyServerChange, handle(),
  // onRevoked) already ran it. It restores session too, but every write below is a CLEAR (session=null,
  // tabs.clear, SKEY remove), so a briefly-rehydrated session is immediately re-locked — never resurrected.
  const { tokens: toks, attempt: attemptArm } = await armGate({
    hydrate: ensureLoaded,
    readTokens: () => api.getTokens(),
    isSignout: reason === "signout",
    compartmentTrusted: quCompartmentTrusted,
  });
  redeemGen++; // any lock invalidates an in-flight quick-unlock redeem (owns() guard, breaker A5⊕B4)
  events?.close(); // live socket + all its timers die FIRST — locked means no bell traffic at all
  events = null;
  const secondsAtLock = autoLockSeconds; // capture before the reset below (web App.tsx:209 parity)
  session = null; // in-memory vault material — INCLUDING the memory-only uvk (breaker B1) — is dropped
  clearPendingTotp(); // and any in-flight TOTP challenge (covers sign-out; a normal lock has none)
  autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
  clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  tabs.clear();
  grants.clear();
  cardGrants.clear();

  // Arm decision (attemptArm, computed by armGate above). `signout` skips arming and forces a full wipe;
  // idle/manual attempt to arm — but ONLY when the storage.session compartment is trusted-only (breaker
  // A9⊕B5: without that guarantee we must NOT retain a crackable UVK blob + a live refresh token, so we
  // fall back to today's full erase + wipe). arm() fails CLOSED to "declined" if reading the flag throws
  // (breaker B3). On "armed" the record now holds the token stash; "not-enrolled" leaves nothing
  // (byte-identical to today); SKEY+TKEY are erased below in ALL cases so a locked SW reports locked.
  if (attemptArm) {
    // .catch → "declined": arm() must NEVER throw past the [SKEY,TKEY] erase below (review F1 — an
    // unexpected throw, e.g. a malformed record, would otherwise skip the erase and leave the just-
    // locked session snapshot on disk, rehydratable into an unlocked vault on the next SW wake).
    // toks.access is non-null here (attemptArm ⇒ shouldAttemptArm required it); the `!` restates that
    // the extracted gate can't narrow across the armGate call the way an inline `&& toks.access` would.
    const armed = await quickUnlock.arm({ access: toks.access!, refresh: toks.refresh }).catch(() => "declined" as const);
    if (armed === "declined") {
      await quickUnlock.wipe(); // stale/ineligible/fail-closed → erase the residue
    }
  } else {
    // signout, no live token, OR an untrusted compartment → full wipe (never leave standing material).
    await quickUnlock.wipe();
  }

  api.setTokens(null, null); // the api forgets the pair; while armed it lives ONLY in QKEY.lockedTokens
  await chrome.storage.session.remove([SKEY, TKEY]); // full vault snapshot always erased — locked reports locked
  // Write the reason AFTER the [SKEY,TKEY] remove so it survives it (a notice only from the idle
  // path — web parity); manual/signout renders no reason line. storage.session clears on browser exit.
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

/** Explicit sign-out / definitive revocation → a FULL wipe of the quick-unlock blob + co-key + tokens,
 *  never the armed-retaining lock (breaker A3⊕B2). Routed here from onRevoked, the popup "Sign out"
 *  action, and every definitive-401 during a quick-unlock redeem. */
function doSignOut(): Promise<void> {
  return doLock("signout");
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
      wsUrl: serverUrl.replace(/^http/, "ws") + "/api/v1/events",
      mintTicket,
      // The DOM WebSocket satisfies WsLike at runtime; TS's strict property variance on the on*
      // slots blocks the structural check — bridge it here, at the one real-socket seam.
      makeSocket: (u) => new WebSocket(u) as WebSocket & WsLike,
      onBell: () => void resync(), // debounced in events.ts; the EXISTING pull, nothing else
      // Explicit server revocation frame — a FULL sign-out (wipes the quick-unlock blob + co-key too),
      // never the armed-retaining lock: revocation is wipe-class in every path (breaker A3⊕B2).
      onRevoked: () => void doSignOut(),
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
  return /^https?:\/\//i.test(u) ? u : serverUrl + u;
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
    await serverReady; // the channel state below is per-origin (nsk) and the fetch needs serverUrl
    const kInfo = nsk(UKEY);
    const kLast = nsk(ULAST);
    const kSeq = nsk(USEQ);
    const kQuiet = nsk(UQUIET);
    if (!force) {
      const seen = (await chrome.storage.local.get(kLast))[kLast];
      if (typeof seen === "number" && Date.now() - seen < UPDATE_MIN_GAP_MS) return;
    }
    // §M-D3: a build pinning only the placeholder sentinel has NO update path — do not even fetch.
    if (!updatesEnabled()) return;

    const base = serverUrl + "/downloads/manifest.json";
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
      await chrome.storage.local.set({ [kQuiet]: { reason: "manifest_fetch_failed" }, [kLast]: Date.now() });
      return;
    }

    const raw = new Uint8Array(await mResp.arrayBuffer()); // EXACT bytes — never resp.json() (§M-D6)
    const sigText = await sResp.text();
    const storedSeq = (await chrome.storage.local.get(kSeq))[kSeq];
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
        await chrome.storage.local.remove(kQuiet);
        await chrome.storage.local.set({ [kLast]: Date.now() });
        return;
      }
      // Fail-closed QUIET (unverified/malformed/stale): record the distinct ACTIONABLE reason; leave any
      // prior VERIFIED [UKEY] signal alone.
      await chrome.storage.local.set({ [kQuiet]: { reason: decision.reason }, [kLast]: Date.now() });
      return;
    }

    // Fully verified, seq-monotonic, fresh — this read supersedes the stored verdict.
    const ext = decision.ext;
    const latest = typeof ext.version === "string" ? ext.version : null;
    const current = chrome.runtime.getManifest().version;
    await chrome.storage.local.remove(kQuiet); // a clean verified read clears the quiet marker
    if (latest && isNewerVersion(latest, current)) {
      const info: UpdateInfo = { latest, chromeUrl: downloadUrl(ext.chromeUrl), firefoxUrl: downloadUrl(ext.firefoxUrl) };
      await chrome.storage.local.set({ [kInfo]: info, [kSeq]: decision.seq, [kLast]: Date.now() });
    } else {
      await chrome.storage.local.remove(kInfo); // up to date (or unreadable version) → no signal
      await chrome.storage.local.set({ [kSeq]: decision.seq, [kLast]: Date.now() });
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
  const kInfo = nsk(UKEY);
  const kQuiet = nsk(UQUIET);
  const info = (await chrome.storage.local.get(kInfo))[kInfo] as UpdateInfo | undefined;
  if (info && typeof info.latest === "string" && isNewerVersion(info.latest, current)) {
    return { current, latest: info.latest, chromeUrl: info.chromeUrl ?? null, firefoxUrl: info.firefoxUrl ?? null, quietReason: null };
  }
  const quiet = (await chrome.storage.local.get(kQuiet))[kQuiet] as { reason?: unknown } | undefined;
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
      // Quick-unlock sub-state (spec 01 §8.4) — `armed` drives the LOCKED popup's PIN field vs the
      // master-password field; `enrolled`/`offerDismissed` drive the unlocked Settings toggle + offer.
      // TOTP challenge in progress (0.16.3): read from the SW memory var — its lifetime IS "the retry
      // can still succeed", so a cold-woken SW correctly reports none and the popup shows the full form.
      // Outranks the quick-unlock PIN view (a live challenge is the most-recent intent — see popup).
      const tp = livePendingTotp();
      return {
        unlocked: session !== null,
        count: loginItems().length,
        email: session?.email ?? null,
        mustChangePassword: session?.mustChangePassword ?? false,
        lockNotice,
        quickUnlock: await quStateForStatus(),
        totpPending: tp ? { email: tp.email, expiresAt: tp.expiresAt } : null,
      } satisfies Res<"status">;
    }
    case "lock": {
      await doLock("manual");
      return { ok: true } satisfies Res<"lock">;
    }
    case "signOut": {
      await doSignOut(); // explicit full sign-out — wipes the quick-unlock blob + co-key too (breaker A3⊕B2)
      return { ok: true } satisfies Res<"signOut">;
    }
    case "unlock":
      return unlockWithMapping(msg.email, msg.password);
    case "unlockTotp":
      return unlockTotp(msg.code);
    case "cancelTotp":
      clearPendingTotp(); // popup "start over" / bad-code cap → drop the in-memory challenge
      return { ok: true } satisfies Res<"cancelTotp">;
    case "unlockWithPin":
      return unlockWithPin(msg.pin);
    case "enrollQuickUnlock":
      return enrollQuickUnlock(msg.pin);
    case "disableQuickUnlock":
      return disableQuickUnlock();
    case "dismissQuickUnlockOffer":
      return dismissQuickUnlockOffer();
    case "purgeServerData":
      // §4.2/B2-7 — the ONLY destructive per-origin path (the options page's explicit "Remove data for
      // this server"). The popup-only sender guard + canonicalize + originKey derivation live in the
      // serverswitch leaf (serverswitch.test.ts drives them, incl. the tab-sender rejection): a sender
      // WITH a tab is a content script ⇒ refused (parity with revealCardField / fillCardFromPopup);
      // a non-origin string yields no key ⇒ no-op; safe for the current origin, never touches another's.
      return purgeServerDataFor(msg.origin, sender.tab !== undefined, purgeOriginNamespace) satisfies Promise<Res<"purgeServerData">>;
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

/** spec 01 §5 (web account.ts / core parity): the seed-derived identity key is the one the server
 *  cannot forge — a server-sent identityPub that doesn't equal it is a substitution attempt. Hard-fail
 *  with a DISTINCT sentinel (E1-1), including when the field is malformed (garbage where the identity
 *  key belongs IS the tampering this names). No ctEquals in extension crypto.ts; a length + byte loop
 *  is fine (the comparand is server-supplied, so timing is not load-bearing). Shared by the full unlock
 *  AND the quick-unlock redeem — the redeem re-verifies exactly as strictly (design §1 fail-closed table). */
function verifyServerIdentity(localPub: Uint8Array, identityPubB64: string): void {
  let serverIdentityPub: Uint8Array | null = null;
  try {
    serverIdentityPub = fromB64(identityPubB64);
  } catch {
    /* undecodable → treated as a mismatch below */
  }
  if (serverIdentityPub === null || serverIdentityPub.length !== localPub.length || !localPub.every((b, i) => b === serverIdentityPub![i])) {
    throw new IdentityMismatchError();
  }
}

/** Open every grant we hold a key for (owner via UVK, member via the identity-sealed box). Shared by
 *  the full unlock and the quick-unlock redeem — the redeem holding the UVK + identity again is what
 *  lets a brand-new shared-vault grant open on a quick unlock (design §1). */
function buildVaultKeys(sync: SyncResponse, uvk: Uint8Array, identity: { publicKey: Uint8Array; privateKey: Uint8Array }, userId: string): Map<string, Uint8Array> {
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
        vk = open(uvk, fromB64(g.wrappedVk), adVk(g.vaultId, userId)); // owner / personal
      } else {
        continue;
      }
      vaultKeys.set(g.vaultId, vk);
    } catch {
      /* wrong key / not ours — skip */
    }
  }
  return vaultKeys;
}

/** Policy fetch — a failed fetch must never mean "no idle lock at all" (web resolveAutoLockSeconds
 *  falls back to a persisted value; here the conservative defaults stand in). Also captures the
 *  clipboard-clear window (E1-4). Shared by unlock + redeem (breaker B6 re-fetches autoLockSeconds
 *  on a quick unlock). Values pass the §2.3/B1-1 CEILINGS (api.ts clamps): with the server now an
 *  arbitrary self-host endpoint, a hostile policy's 0/oversized timer clamps into range — it can
 *  tighten the lock/clear windows but never disable them. */
async function fetchPolicyInto(): Promise<void> {
  try {
    const p = await api.clientPolicy();
    autoLockSeconds = clampAutoLockSeconds(p.autoLockSeconds, DEFAULT_AUTOLOCK_SECONDS);
    clipboardClearSeconds = clampClipboardClearSeconds(p.clipboardClearSeconds, DEFAULT_CLIPBOARD_CLEAR_SECONDS);
  } catch {
    autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
    clipboardClearSeconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  }
}

/** E1-5: re-offer any save captured while locked the moment we unlock — otherwise the pending stays
 *  invisible until a navigation. Same uninjected-tab try/catch as the tabs.onUpdated listener. */
function reofferPendingSaves(): void {
  for (const [tabId, st] of tabs) {
    if (!st.pending) continue;
    const m: TabMsg = { type: "offerPendingSave", pending: publicPending(st.pending) };
    chrome.tabs.sendMessage(tabId, m).catch(() => {
      /* content not injected in that tab — its own pendingSave poll covers it */
    });
  }
}

async function unlock(email: string, password: string): Promise<Res<"unlock">> {
  redeemGen++; // a full unlock supersedes any in-flight quick-unlock redeem (owns() guard)
  clearPendingTotp(); // a fresh sign-in supersedes any prior TOTP challenge
  const gen = redeemGen; // owns() token: a server switch / lock mid-sign-in bumps this → we abort
  const pre = await api.prelogin(email);
  assertServerKdfParams(pre.kdfParams); // H1 (spec 05 T1): refuse a weakened/absurd KDF before deriving (also blocks a 4 GiB SW OOM)
  const mk = await deriveMasterKeyAsync(password, pre.kdfParams, fromB64(pre.kdfSalt));
  const ak = authKey(mk);
  const wk = wrapKey(mk); // needed by hydrateSession to open wrappedUvk; mk is otherwise done
  let s: SessionResponse;
  try {
    s = await api.login(email, toB64(ak));
  } catch (e) {
    // Enrolled second factor: stash the ALREADY-DERIVED {authKey, wrapKey} (no second Argon2id) so
    // the code retry (unlockTotp) can finish; the popup renders a code field. Memory-only — see the
    // pendingTotp declaration for the B1 custody reason. Rethrow → unlockWithMapping → "totp_required".
    // Only if still current (a mid-sign-in switch / lock owns the outcome — never strand foreign keys).
    if (e instanceof ApiError && e.status === 401 && e.code === "totp_required" && gen === redeemGen && !session) {
      pendingTotp = { origin: serverUrl, email, authKey: ak, wrapKey: wk, expiresAt: Date.now() + PENDING_TOTP_TTL_MS };
    }
    throw e;
  }
  return hydrateSession(email, s, wk, gen);
}

/** Phase C — shared by the password unlock and the TOTP retry: open the UVK with the derived
 *  wrapKey, verify server identity, sync + decrypt, install the session, arm the session chrome.
 *  `gen` is the caller's owns()-token: a server switch (applyServerChange bumps redeemGen) or a lock
 *  landing during the sign-in must NOT let this install the OLD origin's tokens/vault under the NEW
 *  origin — so we abort on a gen change, before any token/vault material is installed or POSTed.
 *  A throw here (identity mismatch, restricted-session 403, network) crosses to the caller's mapper;
 *  on ANY non-install exit the freshly-minted token pair is cleared so it never lingers while locked. */
async function hydrateSession(email: string, s: SessionResponse, wk: Uint8Array, gen: number): Promise<Res<"unlock">> {
  if (gen !== redeemGen || session) return { ok: false, code: "aborted" }; // superseded before we touched `api`
  api.setTokens(s.accessToken, s.refreshToken);
  try {
    const uvk = open(wk, fromB64(s.accountKeys.wrappedUvk), adUvk(s.userId));
    // Identity keypair — for member (shared-vault) grants sealed to us.
    const identity = boxKeypairFromSeed(open(uvk, fromB64(s.accountKeys.encryptedIdentitySeed), adIdkey(s.userId)));
    verifyServerIdentity(identity.publicKey, s.accountKeys.identityPub); // before ANY vault material is synced/persisted

    const sync = await api.sync(0);
    if (gen !== redeemGen || session) {
      api.setTokens(null, null); // a switch/lock landed during sync — drop the tokens, install nothing
      return { ok: false, code: "aborted" };
    }
    const vaultKeys = buildVaultKeys(sync, uvk, identity, s.userId);
    const items = decryptItems(sync, vaultKeys);
    // The personal vault (save target) = the type="personal" vault we hold a key for (web store.ts parity).
    const personalVaultId = sync.vaults.find((v) => v.type === "personal" && vaultKeys.has(v.vaultId))?.vaultId ?? "";
    // uvk RETAINED in memory (breaker B1) so enroll can wrap it; provenance PASSWORD + a fresh
    // lastFullUnlockAt stamp — the only place that mints `now` (breaker A4).
    session = {
      userId: s.userId,
      email,
      items,
      vaultKeys,
      personalVaultId,
      mustChangePassword: s.mustChangePassword ?? false,
      uvk,
      provenance: "PASSWORD",
      lastFullUnlockAt: Date.now(),
    };
    clearPendingTotp(); // a live session exists — the challenge (if any) is spent

    await fetchPolicyInto();
    // breaker A6 + A11: a full unlock as a DIFFERENT user strands any prior quick-unlock blob → wipe;
    // a surviving same-user blob gets its 24 h window re-stamped to now (the fail-closed "a successful
    // full unlock re-stamps" rule) and its attempt budget refreshed to full.
    await quickUnlock.onFullUnlock(s.userId, session.lastFullUnlockAt);

    await persistSession();
    void chrome.storage.session.remove(NKEY); // a fresh unlock clears the F26 idle-lock notice (E1-7)
    void chrome.alarms.create("resync", { periodInMinutes: RESYNC_PERIOD_MIN });
    void ensureSocket(true); // T2: live bell up within ~1 s of unlock
    armAutoLock();
    reofferPendingSaves();
    return { ok: true };
  } catch (e) {
    if (!session) api.setTokens(null, null); // never leave live tokens in the api while locked (doUnlockWithPin:1597 parity)
    throw e;
  }
}

/** Single-flight for the TOTP code retry (mirrors pinUnlockInFlight): two racing popups / an
 *  Enter+click double-fire must not each POST /login and burn the server's login backoff. */
function unlockTotp(code: string): Promise<Res<"unlockTotp">> {
  totpUnlockInFlight ??= doUnlockTotp(code).finally(() => {
    totpUnlockInFlight = null;
  });
  return totpUnlockInFlight;
}

async function doUnlockTotp(code: string): Promise<Res<"unlockTotp">> {
  await ensureLoaded();
  if (session) return { ok: true }; // a concurrent full unlock already won — nothing to do
  const p = livePendingTotp();
  if (!p) return { ok: false, code: "totp_expired" }; // SW evicted / switched origin / 5-min fuse blew
  redeemGen++; // ONLY once a real challenge exists (a dead no-op must not abort an in-flight PIN redeem)
  const gen = redeemGen;
  let s: SessionResponse;
  try {
    s = await api.login(p.email, toB64(p.authKey), code);
  } catch (e) {
    if (session) return { ok: true }; // lost the race but the vault is open — not an error
    if (e instanceof ApiError) {
      // 401 here is NOT the authKey (proven at stash time) — it's the code (wrong/replayed) or, in a
      // 5-min-window edge, a server-side password change; the popup caps consecutive bad codes and
      // falls back to a full sign-in, which self-heals the edge. 429 gets its own copy; 403 = enroll.
      if (e.status === 401) return { ok: false, code: "totp_bad_code" };
      if (e.status === 429) return { ok: false, code: "totp_rate_limited" };
      return { ok: false, code: mapUnlockError(e) };
    }
    return { ok: false, code: mapUnlockError(e) };
  }
  if (session) return { ok: true }; // a full unlock landed while we were on the wire
  // A server switch during the login POST would have bumped redeemGen AND cleared pendingTotp (both
  // via applyServerChange) — hydrateSession's gen guard is the backstop, but bail early + explicitly.
  if (gen !== redeemGen || !livePendingTotp()) return { ok: false, code: "aborted" };
  try {
    return await hydrateSession(p.email, s, p.wrapKey, gen); // clears pendingTotp on success
  } catch (e) {
    return { ok: false, code: mapUnlockError(e), error: String(e) };
  }
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
    // Restricted session (server §2.6 row 4): a totpRequired instance let an un-enrolled user's
    // login succeed, then every authed route 403s until they enroll in the web vault. Route there
    // honestly instead of the server_error dead-end (moot on the reference instance — TOTP off).
    if (e.status === 403 && (e.code === "totp_enrollment_required" || e.code === "public_login_requires_totp")) return "totp_enroll_required";
    if (e.status === 401) return e.code === "totp_required" ? "totp_required" : "bad_credentials";
    return "server_error"; // 429/500/… fold here (strict Welcome-ladder parity, decision 5)
  }
  if (e instanceof TypeError) return "network"; // fetch rejection (web errors.ts:26-33 convention)
  return "unknown";
}

// ---- quick-unlock Tier B: enroll / redeem / disable / status (spec 01 §8.4) ----

/** Enroll a PIN over the in-memory UVK. Gated: unlocked, uvk present (breaker B1 — a snapshot-restored
 *  session has none → a fresh full unlock is required first), and NOT mustChangePassword (breaker A4 /
 *  §8.1-A5 — never let a rescue-issued temp password's UVK get armed). `enroll` COPIES the session's
 *  surviving full-password stamp (breaker A4) — a QUICK session carries the ORIGINAL stamp, so it can
 *  never mint a fresh 24 h window. The blob double-wraps the UVK under Argon2id(PIN) ⊕ a fresh
 *  non-extractable co-key (breaker A1). */
async function enrollQuickUnlock(pin: string): Promise<Res<"enrollQuickUnlock">> {
  if (!session) return { ok: false, code: "locked" };
  if (session.mustChangePassword) return { ok: false, code: "must_change_password" };
  if (!session.uvk) return { ok: false, code: "need_full_unlock" };
  const r = await quickUnlock.enroll({
    uvk: session.uvk,
    userId: session.userId,
    email: session.email,
    pin,
    lastFullUnlockAt: session.lastFullUnlockAt, // COPIED — never Date.now() from a QUICK session (breaker A4)
    autoLockSeconds,
  });
  if (!r.ok) return { ok: false, code: r.code as EnrollCode, reason: r.reason };
  return { ok: true };
}

/** Quick-unlock redeem (spec 01 §8.4). Single-flight (breaker A5). The engine's beginRedeem does the
 *  reserve-then-open; this does the server dance: forced refresh FIRST (breaker A3⊕B2), re-assert the
 *  master-KDF floor + re-verify identity + re-fetch policy (breaker B6), then sync + rebuild + persist. */
function unlockWithPin(pin: string): Promise<Res<"unlockWithPin">> {
  pinUnlockInFlight ??= doUnlockWithPin(pin).finally(() => {
    pinUnlockInFlight = null;
  });
  return pinUnlockInFlight;
}

async function doUnlockWithPin(pin: string): Promise<Res<"unlockWithPin">> {
  await ensureLoaded();
  if (session) return { ok: true }; // already unlocked (a race) — nothing to redeem
  const gen = redeemGen;
  const begin = await quickUnlock.beginRedeem(pin);
  if (!begin.ok) {
    return begin.code === "wrong_pin"
      ? { ok: false, code: "wrong_pin", attemptsRemaining: begin.attemptsRemaining }
      : { ok: false, code: begin.code };
  }
  // owns() guard: a lock / sign-out / full unlock intervened during the PIN KDF → discard silently.
  if (gen !== redeemGen || session) return { ok: false, code: "aborted" };

  api.setTokens(begin.tokens.access, begin.tokens.refresh);
  // withRedeemInFlight sets redeemInFlight for the server dance and GUARANTEES it clears on EVERY exit
  // (success / owns()-abort return / throw) — a mid-redeem switch/lock that bumps redeemGen and aborts
  // here can never STRAND the flag true (which would later misroute a full unlock's initial setTokens
  // into the QKEY locked-token stash). While set, api token mutations route to that stash (persistTokens).
  // The inner try/catch stays INSIDE the body so the catch runs with the flag still set (unchanged); the
  // `if (!session) setTokens(null,null)` cleanup sits in the OUTER finally so it runs AFTER the flag is
  // cleared — the exact order the prior single finally used. locksequence.test.ts pins the guaranteed clear.
  try {
    return await withRedeemInFlight(
      (v) => {
        redeemInFlight = v; // true → token mutations land in QKEY.lockedTokens (persistTokens), not a session
      },
      async (): Promise<Res<"unlockWithPin">> => {
        try {
          // A3⊕B2: forced rotation is the FIRST server contact. It is also the account-state read that
          // catches a rescue (which revokes all sessions, spec 03) — a revoked/rotated refresh → 401.
          const rot = await api.forceRefresh();
          if (gen !== redeemGen) return { ok: false, code: "aborted" };
          if (rot === "revoked") {
            await doSignOut(); // definitive-401 → FULL wipe (blob + co-key + tokens) → full sign-in
            return { ok: false, code: "revoked" };
          }
          if (rot === "transient") {
            api.setTokens(null, null); // offline / 5xx — blob KEPT; the master password needs the network too
            return { ok: false, code: "network" };
          }

          const keys = await api.getAccountKeys();
          assertServerKdfParams(keys.kdfParams); // breaker B6: re-assert the H1 master-KDF floor on redeem
          // The seed open throwing = stale/foreign UVK (→ wipe); the compare failing = IdentityMismatchError
          // (→ HARD FAIL, blob KEPT). Same strictness as the full unlock (verifyServerIdentity).
          const identity = boxKeypairFromSeed(open(begin.uvk, fromB64(keys.encryptedIdentitySeed), adIdkey(begin.userId)));
          verifyServerIdentity(identity.publicKey, keys.identityPub);

          const sync = await api.sync(0);
          await fetchPolicyInto(); // breaker B6: re-fetch autoLockSeconds — done BEFORE the final owns-check so
          if (gen !== redeemGen) return { ok: false, code: "aborted" }; // no network await follows the session build
          const vaultKeys = buildVaultKeys(sync, begin.uvk, identity, begin.userId);
          const items = decryptItems(sync, vaultKeys);
          const personalVaultId = sync.vaults.find((v) => v.type === "personal" && vaultKeys.has(v.vaultId))?.vaultId ?? "";
          // Provenance QUICK + the COPIED stamp (breaker A4). mustChangePassword is false by construction —
          // a rescue would have revoked the session and the forced refresh above would have 401'd (breaker B6).
          session = {
            userId: begin.userId,
            email: begin.email,
            items,
            vaultKeys,
            personalVaultId,
            mustChangePassword: false,
            uvk: begin.uvk, // UVK retained in memory (breaker B1) so a re-enroll from this QUICK session works
            provenance: "QUICK",
            lastFullUnlockAt: begin.blob.lastFullUnlockAt,
          };
          redeemInFlight = false; // a session exists now → persistTokens routes to the full snapshot again
          // From here only LOCAL storage awaits remain (no doLock is UI-reachable during a redeem — the popup
          // shows the locked PIN screen, whose Lock/Sign-out buttons are unlocked-only; the gen checks above
          // are defense-in-depth). completeRedeem clears the token stash and keeps the blob for the next lock.
          clearPendingTotp(); // a PIN redeem opened the vault → any stale TOTP challenge is spent
          await persistSession();
          await quickUnlock.completeRedeem(autoLockSeconds);
          void chrome.storage.session.remove(NKEY);
          void chrome.alarms.create("resync", { periodInMinutes: RESYNC_PERIOD_MIN });
          void ensureSocket(true);
          armAutoLock();
          reofferPendingSaves();
          return { ok: true };
        } catch (e) {
          if (e instanceof IdentityMismatchError) return { ok: false, code: "identity_mismatch" }; // blob KEPT (evidence)
          if (e instanceof KdfPolicyError) {
            await doSignOut(); // the server tried to weaken the master KDF on redeem — wipe, force full sign-in
            return { ok: false, code: "kdf_policy" };
          }
          if (e instanceof ApiError) {
            if (e.status === 401 || e.status === 403) {
              await doSignOut(); // definitive-401 survived the inner refresh → FULL wipe
              return { ok: false, code: "revoked" };
            }
            return { ok: false, code: "server_error" }; // transient server — blob kept
          }
          if (e instanceof TypeError) return { ok: false, code: "network" }; // fetch rejection — blob kept
          // Generic Error — encryptedIdentitySeed would not open under the recovered UVK: stale/foreign UVK.
          await quickUnlock.wipe();
          return { ok: false, code: "stale_uvk" };
        }
      },
    );
  } finally {
    if (!session) api.setTokens(null, null); // a failed redeem must never leave tokens live in the api while locked
  }
}

/** Disable quick unlock — a full wipe, NO auth gate (breaker A6 / §8.1 parity: reducing standing secret
 *  material is never gated). */
async function disableQuickUnlock(): Promise<Res<"disableQuickUnlock">> {
  await quickUnlock.wipe();
  return { ok: true };
}

/** The quick-unlock sub-state the popup needs in BOTH views (folded into `status`): `armed`
 *  (locked-armed → show the PIN field), `enrolled` + `offerDismissed` (unlocked → Settings toggle +
 *  the one-time offer card). Every read is fail-closed. */
async function quStateForStatus(): Promise<{ enrolled: boolean; armed: boolean; attemptsRemaining: number; offerDismissed: boolean }> {
  const st = await quickUnlock.status();
  let offerDismissed = false;
  try {
    const dk = nsk(DKEY);
    offerDismissed = (await chrome.storage.local.get(dk))[dk] === true;
  } catch {
    /* storage.local unavailable — treat as not-dismissed (the offer is best-effort chrome) */
  }
  return { enrolled: st.enrolled, armed: st.armed, attemptsRemaining: st.attemptsRemaining, offerDismissed };
}

/** Remember the offer card was dismissed once (breaker B7 — durable, storage.local, NON-secret). */
async function dismissQuickUnlockOffer(): Promise<Res<"dismissQuickUnlockOffer">> {
  try {
    await chrome.storage.local.set({ [nsk(DKEY)]: true });
  } catch {
    /* best-effort */
  }
  return { ok: true };
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
