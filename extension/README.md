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

- **Wired — the extension unlocks and decrypts for real:**
  - `src/crypto.ts` — @noble Argon2id / HKDF / XChaCha20-Poly1305 envelope + the item/UVK/VK
    **associated-data** constructions (byte-exact vs core `Ad.kt`; vector-parity proven).
  - `src/api.ts` — prelogin / login / sync (+ `clientPolicy` smoke test), Bearer JSON, no CORS.
  - `src/background.ts` — the full **unlock flow**: prelogin → Argon2id → login (authKey) → unwrap
    UVK from the returned accountKeys → sync → unwrap each vault key from its grant → **decrypt items
    under the VK**. Holds the decrypted set in memory only (ZK). `matches` returns host-matching
    logins (name + username, never the password until a fill).
  - `src/popup.ts` + `popup.html` — a real unlock form (email + master password) showing the login
    count + Lock.
  - `src/content.ts` — **the in-page autofill UI**: on login-field focus, a fill dropdown of matching
    logins → click → SW `reveal` → the username/password are set in the fields; on submit, a "Save to
    andvari?" banner → SW `save` (client-encrypts a new login under the personal vault key + pushes).
    So the extension now **fills and saves** end to end.
- **Next (`TODO(extension)`):** a shadow-root + injected stylesheet so the UI survives strict-CSP
  sites (the spike uses inline styles); run the ~5.8 s Argon2id in a Web Worker so the popup doesn't
  block; member (shared-vault) grants via `sealedVk` (crypto_box_seal_open — identity key + `@noble`
  X25519); token refresh; then Firefox MV3.
