import { AndvariApi } from "./api";
import { authKey, deriveMasterKey, fromB64, type KdfParams } from "./crypto";

/**
 * MV3 background service worker — the ONLY holder of the unlocked vault material, in memory only
 * (never chrome.storage; ZK). MV3 kills the worker aggressively, so on death the session is gone and
 * the user re-unlocks from the popup (spike doc Unknown 3). Content script + popup talk to it via
 * chrome.runtime messages.
 */
const SERVER_URL = "https://andvari.taila2dff2.ts.net";

interface Session {
  masterKey: Uint8Array;
  // TODO(extension): vaultKeys (unwrapped VKs per vault) + the decrypted item working set, mirroring
  // the web/Android durable cache. Populated after login → accountKeys → unwrap → sync.
}
let session: Session | null = null;
const api = new AndvariApi(SERVER_URL);

type Msg =
  | { type: "ping" }
  | { type: "status" }
  | { type: "unlock"; password: string; kdfParams: KdfParams; saltB64: string };

chrome.runtime.onMessage.addListener((msg: Msg, _sender, sendResponse) => {
  handle(msg)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: String(e) }));
  return true; // keep the channel open for the async response
});

async function handle(msg: Msg): Promise<unknown> {
  switch (msg.type) {
    case "ping": {
      // Proves host_permissions + server reachability (no CORS): spike verification step 3.
      const p = await api.clientPolicy();
      return { ok: true, serverTime: p.serverTime };
    }
    case "status":
      return { ok: true, unlocked: session !== null };
    case "unlock": {
      // The ~5–6 s Argon2id — TODO: move to a Web Worker so this doesn't block (spike doc).
      const mk = deriveMasterKey(msg.password, msg.kdfParams, fromB64(msg.saltB64));
      void authKey(mk); // exercises HKDF; TODO: authKey → login → accountKeys → unwrap VK → sync items
      session = { masterKey: mk };
      return { ok: true, unlocked: true };
    }
  }
}
