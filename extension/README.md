# andvari browser extension (MV3)

PC autofill for Chromium (Chrome/Edge/Brave) + Firefox. **Status: functional (v0.6.1).** Real
unlock (pure-JS `@noble` crypto, byte-identical to the fleet: `web/src/crypto/noble-extension-poc.test.ts`),
member grants, Web-Worker KDF, token refresh — plus the 0.6.1 rework: a session that survives the
MV3 service-worker (chrome.storage.session custody + alarm autolock), a real detection engine
(delegated focusin + MutationObserver, multi-step, all_frames iframes, React-safe fill), save AND
update prompts that survive navigation, a themed functional popup, and treasury theming throughout.
Design + go/no-go: [`docs/design/2026-07-08-browser-extension-spike.md`](../docs/design/2026-07-08-browser-extension-spike.md);
rework audit + plan: [`docs/design/2026-07-09-extension-rework-plan.md`](../docs/design/2026-07-09-extension-rework-plan.md).

## Build

```bash
cd extension
npm install
npm run build        # → dist/ dev build (readable, sourcemaps; esbuild — 0 wasm, 0 eval; copies popup.html/popup.css/icons/INSTALL.txt)
npm run typecheck    # tsc --noEmit
npm run package      # → artifacts/andvari-extension-{chrome,firefox}-<ver>.zip (minified release)
```

## Distribute (household — no store listing)

`npm run package`, then publish both zips to CT 122 `/opt/andvari/downloads/` and **merge** a
`browserExtension` entry into `manifest.json` there (merge — never overwrite; the windows/linux
desktop entries live in the same file, see `ops/windows-build.md`):

```json
"browserExtension": {
  "version": "0.6.1",
  "chromeUrl": "/downloads/andvari-extension-chrome-0.6.1.zip",
  "firefoxUrl": "/downloads/andvari-extension-firefox-0.6.1.zip"
}
```

The web app's **Settings → Devices** hub reads that entry and shows the download row (private
origin only). Each zip carries a tester-facing `INSTALL.txt`; Firefox loads are session-temporary
(`about:debugging`) until we sign an .xpi.

## Load + verify (on a real Chromium — I can't here)

1. `chrome://extensions` → Developer mode → **Load unpacked** → select `extension/dist`.
2. Open the popup → **Test server connection**. Expect "server reachable (t=…)" — proves
   `host_permissions` reaches the tailnet server with **no CORS** (be on Tailscale).
3. Service-worker console (chrome://extensions → "service worker"): **no CSP violation** — confirms
   the bundled `@noble` crypto loads (the spike's whole premise: no WASM, no eval).
4. Open a login page (e.g. https://fill.dev), unlock in the popup, then click a username/password
   field → the andvari fill dropdown appears; submit an unknown login → the "Save to andvari?" bar.

## What's wired vs next

- **Wired — the extension unlocks and decrypts for real:**
  - `src/crypto.ts` — @noble Argon2id / HKDF / XChaCha20-Poly1305 envelope + the item/UVK/VK
    **associated-data** constructions (byte-exact vs core `Ad.kt`; vector-parity proven).
  - `src/api.ts` — prelogin / login / sync (+ `clientPolicy` smoke test), Bearer JSON, no CORS.
  - `src/background.ts` — the full **unlock flow**: prelogin → Argon2id → login (authKey) → unwrap
    UVK from the returned accountKeys → sync → unwrap each vault key from its grant → **decrypt items
    under the VK**. Holds the decrypted set in memory only (ZK). `matches` returns host-matching
    logins (name + username, never the password until a fill).
  - `src/popup.ts` + `popup.html` + `popup.css` — the **functional, treasury-themed vault surface**:
    current-site matches + search-all, per-row copy username/password + live TOTP, a password
    generator, open-web-vault, Lock. The unlock form shows the "Unsealing…" KDF state.
  - `src/content.ts` + `src/detect.ts` + `src/content-ui.ts` — the **detection engine + in-page UI**:
    delegated focusin + a MutationObserver re-scan catch SPA/late-rendered/multi-step forms; fill uses
    the native value setter (React/Vue-safe); a fill dropdown (matches / search-all / strong-password)
    → SW `reveal` → fields set; captured logins raise a "Save to andvari?" / "Update password?" banner
    that survives the post-login navigation. The UI renders in a **closed shadow root** styled by a
    constructed `CSSStyleSheet` (`adoptedStyleSheets`) — page-CSS-isolated AND immune to the site's
    `style-src`, so it works on strict-CSP sites (github.com, banks), not just fill.dev.
  - `src/background.ts` session custody: the unlocked vault survives MV3 SW death via
    `chrome.storage.session` (memory-backed, never disk); `chrome.alarms` drive policy autolock +
    periodic resync. Secret egress stays `reveal`-only, host-bound or by an explicit gesture in our UI.
  - **KDF in a Web Worker** (`src/kdf-worker.ts`) — the ~5.8 s Argon2id runs off the SW event loop,
    with an inline fallback where nested workers aren't allowed.
  - **Member (shared-vault) grants** — `sealedVk` opened via `crypto_box_seal_open` reconstructed
    from **tweetnacl** (box) + `@noble` blake2b (nonce), verified byte-identical to libsodium
    (`web/src/crypto/noble-extension-poc.test.ts`). Shared-vault logins fill too now.
  - **Token refresh** — a 401 rotates the single-use token pair and retries once.
- **Manifests (both):** branded icons (`icons/icon{16,32,48,128}.png` — the treasury coin + ᛅ rune),
  content script in **all frames** (`"all_frames": true` — iframe logins) with the vault app's own
  origin excluded (`exclude_matches` — never run the PM UI inside andvari itself), extension-page
  CSP without `'wasm-unsafe-eval'` (nothing loads wasm).
- **Firefox:** `manifest.firefox.json` + `TARGET=firefox npm run build` (background event page instead
  of the SW; `browser_specific_settings`). The `chrome.*` calls work on both.
- **Next:** more item types beyond logins, a signed Firefox `.xpi` (temporary `about:debugging` loads
  vanish on restart), and continued on-browser verification on both Chromium and Firefox (a
  headless-Chromium harness already exercises unlock / save / fill / multi-step / iframe / SPA / SW-kill).
