import { AndvariApi, type MutationResult, type SyncResponse } from "./api";
import { cardSubtitle, composeShortExpiry, digitsOnly } from "./card";
import {
  adIdkey,
  adItem,
  adUvk,
  adVk,
  authKey,
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
import { LOGIN_FORMAT_VERSION, MAX_ITEM_FORMAT_VERSION } from "./format";
import { DEFAULT_GENERATOR, generatePassword } from "./generator";
import type { CardItem, MatchItem, PendingSave, Req, Res, TabMsg } from "./messages";
import { currentCode } from "./totp";
import { matchLogins, normalizeHost, parseSavedUri, type FillTarget } from "./urimatch";

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
 * session (client-policy autoLockSeconds; 0 disables), "resync" refreshes items every 5 min.
 *
 * Unlock flow (mirrors web Account.unlock): prelogin → Argon2id → login (authKey) → unwrap UVK
 * from accountKeys → sync → unwrap each vault key from its grant → decrypt items under the VK.
 */
const SERVER_URL = "https://andvari.taila2dff2.ts.net";

const SKEY = "session"; // storage.session: SessionSnapshot
const TKEY = "tabs"; //    storage.session: Record<tabId, TabState>
const DEFAULT_AUTOLOCK_SECONDS = 15 * 60; // policy fetch failed/absent — never "no lock at all"
const RESYNC_PERIOD_MIN = 5;
const GRANT_TTL_MS = 30_000; // popup fill grant: covers the content script's reveal round-trip
const BADGE_BG = "#d0a94a"; //  aged gold on…
const BADGE_INK = "#1a1509"; // …treasury charcoal (web --gold / --btn-ink)
// formatVersion discipline lives in format.ts (MAX_ITEM_FORMAT_VERSION read ceiling;
// LOGIN_FORMAT_VERSION new-login seal fv) — chrome-free so the web pin suite imports it.
// Automated (non-user) messages that must NOT re-arm the idle lock — else a page auto-reloading
// (pageInfo) or the popup's 1 s status/TOTP poll would defer autolock forever while the user is
// away. `status` is here too: merely leaving the popup open (it polls status every second for
// liveness) is not activity; real interaction (matches/reveal/search/save/…) still re-arms.
const PASSIVE_MSGS = new Set<Req["type"]>(["pageInfo", "totp", "ping", "status"]);

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
}

/** What survives SW death (JSON-safe: keys as b64 — Uint8Array doesn't cross chrome.storage). */
interface SessionSnapshot {
  access: string;
  refresh: string | null;
  userId: string;
  email: string;
  personalVaultId: string;
  autoLockSeconds: number;
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
}

let session: Session | null = null;
let autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
let tabs = new Map<number, TabState>();
/** One-shot popup fill grants, tabId → item+expiry. In-memory only: minted and consumed within
 *  one message exchange, so a SW death in between simply voids the grant (fill re-clicks). The
 *  grant is consumed ONLY by the tab's TOP frame (fillFromPopup targets frameId 0) — a
 *  broadcast-to-all-frames grant would let a hostile cross-origin sub-frame claim the secret. */
const grants = new Map<number, { itemId: string; expiresMs: number }>();
/** In-flight write count — resync must not replace session.items out from under a landing put. */
let writesInFlight = 0;
let loadPromise: Promise<void> | null = null;

const api = new AndvariApi(SERVER_URL);
api.onTokensRotated = () => persistSession(); // single-use refresh: a stale persisted pair = revoked device

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
  if (alarm.name === "autolock") void doLock();
  else if (alarm.name === "resync") void resync();
});

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
        vaultKeys: new Map(Object.entries(snap.vaultKeys).map(([id, b]) => [id, fromB64(b)])),
        // formatVersion joined the snapshot in 0.7.0 — a session persisted by ≤0.6.1 lacks it,
        // and that client's read gate only admitted fv≤1, so defaulting 1 is exact, not a guess.
        items: snap.items.map((i) => ({ ...i, formatVersion: i.formatVersion ?? 1 })),
      };
      autoLockSeconds = snap.autoLockSeconds;
    }
    const t = got[TKEY] as Record<string, TabState> | undefined;
    if (t) tabs = new Map(Object.entries(t).map(([id, st]) => [Number(id), st]));
  })();
  return loadPromise;
}

function persistSession(): void {
  if (!session) return;
  const t = api.getTokens();
  const snap: SessionSnapshot = {
    access: t.access ?? "",
    refresh: t.refresh,
    userId: session.userId,
    email: session.email,
    personalVaultId: session.personalVaultId,
    autoLockSeconds,
    vaultKeys: Object.fromEntries([...session.vaultKeys].map(([id, vk]) => [id, toB64(vk)])),
    items: session.items,
  };
  void chrome.storage.session.set({ [SKEY]: snap });
}

function persistTabs(): void {
  void chrome.storage.session.set({ [TKEY]: Object.fromEntries([...tabs].map(([id, st]) => [String(id), st])) });
}

/** Full lock: memory + storage.session (pending saves hold plaintext passwords — they lock too). */
async function doLock(): Promise<void> {
  session = null;
  autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
  tabs.clear();
  grants.clear();
  api.setTokens(null, null);
  await chrome.storage.session.remove([SKEY, TKEY]);
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
    case "status":
      return {
        unlocked: session !== null,
        count: loginItems().length,
        email: session?.email ?? null,
      } satisfies Res<"status">;
    case "lock": {
      await doLock();
      return { ok: true } satisfies Res<"lock">;
    }
    case "unlock":
      return unlock(msg.email, msg.password);
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
  const mk = await deriveMasterKeyAsync(password, pre.kdfParams, fromB64(pre.kdfSalt));
  const s = await api.login(email, toB64(authKey(mk)));
  api.setTokens(s.accessToken, s.refreshToken);

  const uvk = open(wrapKey(mk), fromB64(s.accountKeys.wrappedUvk), adUvk(s.userId));
  // Identity keypair — for member (shared-vault) grants sealed to us.
  const identity = boxKeypairFromSeed(open(uvk, fromB64(s.accountKeys.encryptedIdentitySeed), adIdkey(s.userId)));
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
  session = { userId: s.userId, email, items, vaultKeys, personalVaultId };

  // Policy idle lock — a failed fetch must never mean "no lock at all" (web resolveAutoLockSeconds
  // falls back to a persisted value; here the conservative default stands in).
  try {
    const p = await api.clientPolicy();
    autoLockSeconds =
      typeof p.autoLockSeconds === "number" && Number.isFinite(p.autoLockSeconds)
        ? Math.max(0, p.autoLockSeconds)
        : DEFAULT_AUTOLOCK_SECONDS;
  } catch {
    autoLockSeconds = DEFAULT_AUTOLOCK_SECONDS;
  }

  persistSession();
  void chrome.alarms.create("resync", { periodInMinutes: RESYNC_PERIOD_MIN });
  armAutoLock();
  return { ok: true };
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
  return loginItems().filter((it) => matchLogins(it.doc.login?.uris ?? [], target));
}

function toMatchItem(it: DecryptedItem, siteMatch: boolean): MatchItem {
  return {
    itemId: it.itemId,
    name: it.doc.name,
    username: it.doc.login?.username ?? null,
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

/** Contract reveal rules: host-match ∨ one-shot popup grant (consumed) ∨ explicit user pick. */
function reveal(msg: Extract<Req, { type: "reveal" }>, sender: chrome.runtime.MessageSender): Res<"reveal"> {
  if (!session) return { ok: false, error: "locked" };
  const it = session.items.find((i) => i.itemId === msg.itemId && i.doc.type === "login");
  if (!it) return { ok: false, error: "unknown item" };

  const webHost = normalizeHost(msg.host);
  let allowed =
    msg.explicit === true || (webHost !== null && matchLogins(it.doc.login?.uris ?? [], { webHost, packageName: "" }));
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
  if (!allowed) return { ok: false, error: "not allowed for this site" };

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

/** Explicit popup pick → mint the tab's one-shot grant, then tell the tab to run its normal
 *  reveal round-trip. Single secret-egress path: the SW never pushes a secret at a tab. */
async function fillFromPopup(itemId: string): Promise<Res<"fillFromPopup">> {
  if (!session) return { ok: false, error: "locked" };
  if (!session.items.some((i) => i.itemId === itemId && i.doc.type === "login")) {
    return { ok: false, error: "unknown item" };
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id === undefined) return { ok: false, error: "no active tab" };
  grants.set(tab.id, { itemId, expiresMs: Date.now() + GRANT_TTL_MS });
  const msg: TabMsg = { type: "fillItem", itemId };
  try {
    // Top frame ONLY — both the message and the grant (redeemed in reveal()) are frame-0-bound so
    // a cross-origin sub-frame can neither receive the fill request nor consume the grant.
    await chrome.tabs.sendMessage(tab.id, msg, { frameId: 0 });
  } catch {
    grants.delete(tab.id);
    return { ok: false, error: "page not reachable — reload the tab and retry" };
  }
  return { ok: true };
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
  return { host: p.host, username: p.username, updatesItemId: p.updatesItemId, updatesItemName: p.updatesItemName };
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
  // Save-vs-update: an existing login on this host with this exact username is an UPDATE target.
  // Locked ⇒ matchesFor() is empty ⇒ pending records as save-new; resolve re-checks post-unlock.
  const existing = matchesFor(host).find((i) => (i.doc.login?.username ?? "") === username);
  if (existing && (existing.doc.login?.password ?? "") === msg.password) {
    // Unchanged password — every successful re-login would banner otherwise.
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

  // Pending survives a locked failure so unlock → save can still land it.
  if (!session || !session.personalVaultId) return { ok: false, error: "locked" };

  // Re-decide save-vs-update NOW: the capture-time decision is stale if the vault was LOCKED then
  // (matchesFor was empty ⇒ updatesItemId null ⇒ this would duplicate an existing login). Prefer
  // the frozen target, but fall back to a fresh host+username match before creating a new item.
  let target = pending.updatesItemId ? session.items.find((i) => i.itemId === pending.updatesItemId) : undefined;
  if (!target) {
    target = matchesFor(pending.host).find((i) => (i.doc.login?.username ?? "") === pending.username);
  }
  let result: Res<"resolvePendingSave">;
  if (target) {
    // Update = the same doc with ONLY the password swapped — uris tail, totp, notes, favorite,
    // attachments all ride the spread — put against the rev we decrypted (server 409s a racer).
    const doc: ItemDoc = { ...target.doc, login: { ...target.doc.login, password: pending.password } };
    result = await putExisting(target, doc);
  } else {
    // New login — also the fallback when an update target vanished between capture and resolve.
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

async function putExisting(target: DecryptedItem, doc: ItemDoc): Promise<{ ok: boolean; error?: string }> {
  // Monotonic re-seal: never below the fv the item arrived at (web Account.itemFv parity —
  // the server refuses fv downgrades). The extension's per-doc floor is constant
  // LOGIN_FORMAT_VERSION: every putExisting caller filters type==="login", and the extension
  // never writes card docs (a card's floor would be 2).
  const fv = Math.max(LOGIN_FORMAT_VERSION, target.formatVersion);
  const r = await putItem(target.itemId, target.vaultId, doc, target.rev, fv);
  if (r?.status !== "applied") return { ok: false, error: `save failed (${r?.status ?? "no vault key"})` };
  target.doc = doc;
  target.rev = r.newItemRev ?? target.rev + 1;
  target.formatVersion = fv; // what this write actually sealed at (web store.ts parity)
  persistSession();
  return { ok: true };
}

async function putNewLogin(host: string, username: string, password: string): Promise<{ ok: boolean; error?: string }> {
  if (!session || !session.personalVaultId) return { ok: false, error: "locked or no personal vault" };
  const itemId = crypto.randomUUID();
  const doc: ItemDoc = { type: "login", name: host, login: { username, password, uris: [`https://${host}`] } };
  // NEW items seal at the login doc floor — the extension only ever creates logins (format.ts).
  const r = await putItem(itemId, session.personalVaultId, doc, 0, LOGIN_FORMAT_VERSION);
  if (r?.status !== "applied") return { ok: false, error: `save failed (${r?.status ?? "no vault key"})` };
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
