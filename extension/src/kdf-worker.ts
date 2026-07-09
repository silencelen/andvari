import { deriveMasterKey, type KdfParams } from "./crypto";

/**
 * Dedicated Web Worker for the ~5.8 s Argon2id, so the service worker's event loop stays free during
 * unlock (fill/save messages keep flowing; no long synchronous block). Pure-JS @noble → no WASM/eval,
 * fine under the extension CSP. Receives {password, params, salt}, returns the 32-byte master key
 * (transferred). The master key stays inside the extension's own worker — never the page.
 */
self.onmessage = (e: MessageEvent<{ password: string; params: KdfParams; salt: Uint8Array }>) => {
  const { password, params, salt } = e.data;
  try {
    const mk = deriveMasterKey(password, params, salt);
    (self as DedicatedWorkerGlobalScope).postMessage({ ok: true, mk }, { transfer: [mk.buffer] });
  } catch (err) {
    (self as DedicatedWorkerGlobalScope).postMessage({ ok: false, error: String(err) });
  }
};
