import { AndvariApi } from "./api";
import { adIdkey, adItem, adUvk, adVk, authKey, boxKeypairFromSeed, deriveMasterKey, fromB64, open, seal, sealOpen, toB64, wrapKey, type KdfParams } from "./crypto";

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
      api.setTokens(null, null);
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

async function unlock(email: string, password: string): Promise<unknown> {
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
