import { AndvariApi } from "./api";
import { adItem, adUvk, adVk, authKey, deriveMasterKey, fromB64, open, seal, toB64, wrapKey } from "./crypto";

/**
 * MV3 background service worker — the ONLY holder of unlocked vault material, in memory only (never
 * chrome.storage; ZK). MV3 kills the worker aggressively → on death the session is gone and the user
 * re-unlocks (spike doc Unknown 3). Content script + popup talk to it via chrome.runtime messages.
 *
 * Unlock flow (mirrors web Account.unlock): prelogin → Argon2id → login (authKey) → unwrap UVK from
 * the returned accountKeys → sync → unwrap each vault key from its grant → decrypt items under the VK.
 */
const SERVER_URL = "https://andvari.taila2dff2.ts.net";

interface LoginData {
  username?: string;
  password?: string;
  uris?: string[];
  totp?: string;
}
interface ItemDoc {
  type: string;
  name: string;
  login?: LoginData;
}
interface DecryptedItem {
  itemId: string;
  vaultId: string;
  doc: ItemDoc;
}

interface Session {
  userId: string;
  items: DecryptedItem[];
  vaultKeys: Map<string, Uint8Array>;
  personalVaultId: string;
}
let session: Session | null = null;
const api = new AndvariApi(SERVER_URL);

type Msg =
  | { type: "ping" }
  | { type: "status" }
  | { type: "lock" }
  | { type: "unlock"; email: string; password: string }
  | { type: "matches"; host: string }
  | { type: "reveal"; itemId: string }
  | { type: "save"; url: string; username: string; password: string };

chrome.runtime.onMessage.addListener((msg: Msg, _sender, sendResponse) => {
  handle(msg)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: String(e) }));
  return true; // keep the channel open for the async response
});

async function handle(msg: Msg): Promise<unknown> {
  switch (msg.type) {
    case "ping": {
      const p = await api.clientPolicy(); // host_permissions + reachability
      return { ok: true, serverTime: p.serverTime };
    }
    case "status":
      return { ok: true, unlocked: session !== null, count: session?.items.length ?? 0 };
    case "lock": {
      session = null;
      api.setToken(null);
      return { ok: true };
    }
    case "unlock":
      return unlock(msg.email, msg.password);
    case "matches":
      return { ok: true, matches: matchesFor(msg.host) };
    case "reveal":
      return { ok: true, secret: revealItem(msg.itemId) };
    case "save":
      return saveLogin(msg.url, msg.username, msg.password);
  }
}

async function unlock(email: string, password: string): Promise<unknown> {
  const pre = await api.prelogin(email);
  const mk = deriveMasterKey(password, pre.kdfParams, fromB64(pre.kdfSalt)); // ~5–6 s; TODO: Web Worker
  const s = await api.login(email, toB64(authKey(mk)));
  api.setToken(s.accessToken);

  const uvk = open(wrapKey(mk), fromB64(s.accountKeys.wrappedUvk), adUvk(s.userId));
  const sync = await api.sync(0);

  const vaultKeys = new Map<string, Uint8Array>();
  for (const g of sync.grants) {
    if (!g.wrappedVk) continue; // member grants use sealedVk — TODO(extension): crypto_box_seal_open
    try {
      vaultKeys.set(g.vaultId, open(uvk, fromB64(g.wrappedVk), adVk(g.vaultId, s.userId)));
    } catch {
      /* wrong key / not ours — skip */
    }
  }

  const items: DecryptedItem[] = [];
  for (const it of sync.items) {
    if (it.deleted || !it.blob) continue;
    const vk = vaultKeys.get(it.vaultId);
    if (!vk) continue;
    try {
      const doc = JSON.parse(
        new TextDecoder().decode(open(vk, fromB64(it.blob), adItem(it.vaultId, it.itemId, it.formatVersion))),
      ) as ItemDoc;
      items.push({ itemId: it.itemId, vaultId: it.vaultId, doc });
    } catch {
      /* undecryptable / newer formatVersion — skip */
    }
  }
  // The personal vault (save target) = the type="personal" vault we hold a key for (web store.ts parity).
  const personalVaultId = sync.vaults.find((v) => v.type === "personal" && vaultKeys.has(v.vaultId))?.vaultId ?? "";
  session = { userId: s.userId, items, vaultKeys, personalVaultId };
  return { ok: true, unlocked: true, count: items.length };
}

/** Reveal a chosen login's secret to fill (only on the user's explicit selection). */
function revealItem(itemId: string): { username: string | null; password: string | null } | null {
  const it = session?.items.find((i) => i.itemId === itemId);
  if (!it) return null;
  return { username: it.doc.login?.username ?? null, password: it.doc.login?.password ?? null };
}

/** Save flow: create a new login in the personal vault (client-encrypted) and push it. */
async function saveLogin(url: string, username: string, password: string): Promise<unknown> {
  if (!session || !session.personalVaultId) return { ok: false, error: "locked or no personal vault" };
  const vk = session.vaultKeys.get(session.personalVaultId);
  if (!vk) return { ok: false, error: "no personal vault key" };
  const host = hostOf(url);
  const itemId = crypto.randomUUID();
  const doc: ItemDoc = { type: "login", name: host, login: { username, password, uris: [`https://${host}`] } };
  const blob = toB64(seal(vk, new TextEncoder().encode(JSON.stringify(doc)), adItem(session.personalVaultId, itemId, 1)));
  await api.push([
    { mutationId: crypto.randomUUID(), op: "put", itemId, vaultId: session.personalVaultId, baseItemRev: 0, item: { formatVersion: 1, attachmentIds: [], blob } },
  ]);
  session.items.push({ itemId, vaultId: session.personalVaultId, doc }); // matchable immediately
  return { ok: true };
}

/** Logins whose stored URI host matches the page host (exact or a registrable-domain suffix). */
function matchesFor(host: string): { itemId: string; name: string; username: string | null }[] {
  if (!session) return [];
  const page = normHost(host);
  return session.items
    .filter((it) => it.doc.type === "login" && (it.doc.login?.uris ?? []).some((u) => hostMatch(normHost(hostOf(u)), page)))
    .map((it) => ({ itemId: it.itemId, name: it.doc.name, username: it.doc.login?.username ?? null }));
}

function hostOf(uri: string): string {
  try {
    return new URL(uri).host;
  } catch {
    return uri;
  }
}
function normHost(h: string): string {
  return h.trim().toLowerCase().replace(/^www\./, "").replace(/:\d+$/, "");
}
function hostMatch(saved: string, page: string): boolean {
  if (!saved || !page) return false;
  return saved === page || (saved.includes(".") && page.endsWith("." + saved));
}
