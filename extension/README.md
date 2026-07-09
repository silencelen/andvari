# andvari browser extension (MV3 scaffold)

PC autofill. **Status: buildable scaffold** — build tooling, the pure-JS `@noble` crypto (proven
byte-identical to the fleet — `web/src/crypto/noble-extension-poc.test.ts`), and the
service-worker/content/popup message spine are wired. Unlock (account-key unwrap) and fill/save UI
are the next port (clearly `TODO(extension)` in the source, pointing at the web modules to reuse).
Full design + go/no-go: [`docs/design/2026-07-08-browser-extension-spike.md`](../docs/design/2026-07-08-browser-extension-spike.md).

## Build

```bash
cd extension
npm install
npm run build        # → dist/ (esbuild bundles TS; @noble bundled in — 0 wasm, 0 eval)
npm run typecheck    # tsc --noEmit
```

## Load + verify (on a real Chromium — I can't here)

1. `chrome://extensions` → Developer mode → **Load unpacked** → select `extension/dist`.
2. Open the popup → **Test server connection**. Expect "server reachable (t=…)" — proves
   `host_permissions` reaches the tailnet server with **no CORS** (be on Tailscale).
3. Service-worker console (chrome://extensions → "service worker"): **no CSP violation** — confirms
   the bundled `@noble` crypto loads (the spike's whole premise: no WASM, no eval).
4. Open a login page (e.g. https://fill.dev) → the content script logs "login form detected".

## What's wired vs next

- **Wired:** manifest (host_permissions + `'wasm-unsafe-eval'` CSP), esbuild build, `src/crypto.ts`
  (@noble: Argon2id / HKDF / XChaCha20-Poly1305 envelope, vector-parity proven), `src/api.ts`
  (Bearer JSON client + `clientPolicy` smoke test), `src/background.ts` (SW session + message
  router + KDF-in-SW), `src/content.ts` (DOM login-form detection), `src/popup.ts` + `popup.html`.
- **Next (`TODO(extension)`):** port login → accountKeys → unwrap VK → sync from
  `web/src/api/client.ts` + `web/src/vault/account.ts`; run the KDF in a Web Worker (the ~5.8 s
  Argon2id, spike doc); the fill dropdown + "Save to andvari?" content-script UI; a real unlock form
  in the popup; then Firefox MV3.
