# andvari browser extension (MV3)

Desktop autofill for Chromium (Chrome/Edge/Brave) + Firefox — logins and payment cards.
**Status: shipping.** The version lives in `manifest.json` (0.19.0 as of this writing);
`package.mjs` refuses to package if `manifest.json`, `manifest.firefox.json`, and
`package.json` disagree, so that one file is the answer. Per-release detail is in the repo-root
[`CHANGELOG.md`](../CHANGELOG.md).

It is a full client, not a shim: pure-JS `@noble` crypto (no WASM, no `eval`) byte-identical to
the fleet, member (shared-vault) grants, a Web-Worker KDF, a session that survives MV3
service-worker death, and a detection + fill engine for logins and checkout card forms. It talks
only to the one andvari server you configure — your own instance or the shipped default — and
holds decrypted items in service-worker memory only.

Design record: the go/no-go spike
[`docs/design/2026-07-08-browser-extension-spike.md`](../docs/design/2026-07-08-browser-extension-spike.md),
the rework plan [`docs/design/2026-07-09-extension-rework-plan.md`](../docs/design/2026-07-09-extension-rework-plan.md),
the endpoint-agnostic model [`docs/design/2026-07-15-multi-tenant-endpoints.md`](../docs/design/2026-07-15-multi-tenant-endpoints.md),
and the card-fill chain (`2026-07-10-extension-card-fill`, `2026-07-23-card-autofill-*`,
`2026-07-26-in-page-card-chip`).

## Build

```bash
cd extension
npm install
npm run build        # → dist/ dev build (readable, sourcemaps; esbuild — 0 wasm, 0 eval; copies popup.html/popup.css/icons/INSTALL.txt)
npm run typecheck    # tsc --noEmit
npm run test         # node --test over src/**/*.test.ts
npm run package      # → artifacts/andvari-extension-{chrome,firefox}-<ver>.zip (minified release)
```

## Tests — where they actually live

There is **no browser harness in this tree** (no puppeteer, no playwright). On-browser behaviour
is verified by hand, per the procedure in "Load + verify" and the B2-10 section below. What *is*
automated:

- **`extension/src/*.test.ts`** — `npm test`, Node's built-in runner (`node --test`, native
  type-stripping). The security-critical logic is deliberately factored into chrome-free **leaf
  modules** (`serverurl`, `locksequence`, `quickunlock`, `serverswitch`, `grantflow`, `trustgate`,
  `updateverify`, `card`, `cardfill`, `detect`, `urimatch`, `totp`, `errors`, …) so the real
  enforcement is driven under plain node instead of a hand-rolled mirror. The `*.vectors.test.ts`
  files in that set read `spec/test-vectors/` directly — the same bytes the Kotlin and web engines
  are graded against (provenance: `spec/test-vectors/README.md`).
- **`web/src/extension-pins.test.ts`** — the house pattern, stated at that file's top: because the
  extension has no suite of its own for cross-engine values, its safety-critical constants
  (`format.ts` format-version ceiling/floor, `card.ts` derivations, `detect.ts` CVV classification,
  `messages.ts` card-target choice) are pinned **from the web vitest suite**, alongside
  `web/src/crypto/noble-extension-poc.test.ts`, which proves the `@noble` + `tweetnacl` crypto is
  byte-identical to libsodium.
- **`extension/package.mjs`** self-defends before it zips: refuses on manifest version drift, runs
  the same test glob, and caps `content.js` size so the ~144 KB PSL blob can never leak into the
  per-page bundle.

`scripts/verify.sh` at the repo root runs the extension typecheck + tests together with both
engines' suites; that is the gate for every ship.

## Release & distribution

`npm run package` produces both zips, then `scripts/publish-extension.sh` uploads them:

- **Chrome Web Store**, *unlisted* — installable by link, absent from search/browse. Updates
  auto-install like any store extension.
- **Firefox AMO self-distribution** — `web-ext sign` returns a Mozilla-signed `.xpi`. The Firefox
  manifest bakes `browser_specific_settings.gecko.update_url` → the reference instance's
  `/downloads/firefox-updates.json`, which the publish script emits alongside the signed `.xpi`,
  so signed installs self-update (Firefox verifies the signature on every update).
- **Sideload zips** remain the fallback; each carries `INSTALL.txt`. Any instance can host builds
  in its `/downloads` dir: the web app's **Settings → Devices** hub reads that dir's
  `manifest.json` and renders whatever a `browserExtension` entry declares, preferring
  `chromeStoreUrl` and a signed `firefoxUrl` `.xpi` over plain zips. Merge that entry, never
  overwrite it — the desktop installer entries live in the same file. There is no origin gate:
  a self-host instance advertises its own `/downloads` exactly like the reference instance does.

Both stores review every update, even unlisted ones. Credentials and the full field kit live in
[`docs/runbooks/extension-store-publishing.md`](../docs/runbooks/extension-store-publishing.md).

## Load + verify (manual, on a real browser)

1. `chrome://extensions` → Developer mode → **Load unpacked** → select `extension/dist`.
2. Open the popup → **Test server connection**. Expect "Server reachable." — proves the granted
   host permission reaches the configured server with **no CORS** (preconfigured:
   `https://andvari.monahanhosting.com`; on Firefox grant the host permission first — see
   "Host permissions" below).
3. Service-worker console (chrome://extensions → "service worker"): **no CSP violation** — confirms
   the bundled `@noble` crypto loads (the spike's whole premise: no WASM, no eval).
4. Open a login page (e.g. https://fill.dev), unlock in the popup, then click a username/password
   field → the andvari fill dropdown appears; submit an unknown login → the "Save to andvari?" bar.

## What's wired

- **The extension unlocks and decrypts for real:**
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
  - **Cards** — the popup lists `type:"card"` items in a "Cards" group beneath the logins as a
    masked identity line only ("Visa ••4242"; the full number/CVV never enter the popup DOM), with
    copy buttons for number / expiry / security code behind the same explicit-reveal path as
    passwords (`revealCardField`, popup-only — the SW refuses it from pages). **In-page fill** of
    merchant-hosted checkout forms is wired too (`src/cardfill.ts` + `src/content.ts`), including
    `<select>` expiry/type dropdowns, split-PAN boxes, radio card types, and billing ZIP. Every
    card value crosses into page DOM only through a **one-shot `revealCardForFill` grant minted by
    a popup click and redeemable by the exact frame that detected the form** — the frame-origin
    egress contract. Cross-origin PSP iframes (Stripe Elements et al.) are **deliberately not
    filled**: nothing can distinguish a merchant's PSP frame from an attacker's, so copy stays the
    posture there. The C1 in-page chip carries zero data and mints no grant — it is a signpost that
    opens the popup (design `2026-07-26-in-page-card-chip`). Item read ceiling is fv 2 with
    per-item carried re-seal fv; new logins still seal at fv 1 (`src/format.ts`, pinned by
    `web/src/extension-pins.test.ts`). A lone password-typed field whose name/id token-matches
    `cvv`/`cvc`/`csc` suppresses the save/update banner, so a checkout security code can't be
    offered as an overwrite of a stored login password (the id is consulted only when the name is
    empty).
  - **Any server, safely (`src/options.ts`, `serverurl`, `serverswitch`, `trustgate`)** — the
    options page repoints the extension at any andvari origin behind an anti-phishing Trust Gate
    that shows the **raw origin only**, never a server-supplied display name. A switch is
    origin-clean: locks, clears tokens, and namespaces storage per origin.
  - **Quick unlock (`src/quickunlock.ts`)** — an optional PIN (or platform passkey) that turns the
    idle relock's full sign-in + multi-second Argon2id into a short one. The UVK is **double**-wrapped:
    a PIN-derived key over a non-extractable WebCrypto key held in IndexedDB, so the blob alone is
    not offline-crackable. Session-scoped; never persisted to disk.
  - **Signed update channel (`src/updateverify.ts`)** — the SW checks a detached-signed
    `/downloads/manifest.json` with an anti-rollback sequence floor, fails closed and quiet, and
    runs **only** against the shipped default origin (the pinned key signs that instance's
    `/downloads` alone). A custom origin gets no fetch at all. Per-instance keys are later work.
- **Manifests (both):** branded icons (`icons/icon{16,32,48,128}.png` — the treasury coin + ᛅ rune),
  extension-page CSP without `'wasm-unsafe-eval'` (nothing loads wasm). The autofill content script
  is **registered dynamically by the service worker** (`chrome.scripting.registerContentScripts`,
  all frames, `document_idle`) — there is deliberately **no static `content_scripts` entry**: a
  static entry's `exclude_matches` is immutable at runtime, so it would inject the autofill UI into
  every *self-hosted* vault origin (design 2026-07-15 §5.1/B2-5). The SW recomputes
  `excludeMatches` (configured server origin + the shipped default) on every start, install, and
  server change, and reconciles on every host-permission grant.

## Host permissions & the install-warning strategy (B2-10 — read before ANY host change)

- **Chrome (`manifest.json`):** `host_permissions` carries ONLY the reference instance
  (`https://andvari.monahanhosting.com/*`); the broad patterns (`https://*/*`,
  `http://localhost/*`, `http://127.0.0.1/*`) live in `optional_host_permissions` and are granted
  **at runtime, per user gesture** (the wave-3 options page's Trust-Gate → `permissions.request`).
  Install shows only the reference-instance warning; autofill *injects* only on granted origins —
  until the broad grant, the dynamic registration is effective nowhere (the vault origins are
  excluded anyway).
- **Firefox (`manifest.firefox.json`):** MV3 host permissions are **optional-by-default**, and
  `optional_host_permissions` isn't supported at our `strict_min_version` (121), so ALL patterns —
  including the default origin — sit in `host_permissions` as user-grantable toggles. First run
  may hold NO grant at all: the popup detects this (`data-missing-host-grant` hook) and the wave-3
  options page routes the grant.
- **Why this is release-gated:** the 0.15.0→0.16.0 update *removes* the static all-URLs content
  script and *adds* new host patterns in the same release — a changed install-time warning set can
  **disable the extension on update**. Per design §5.1 (B2-10) this must be **observed, never
  reasoned**: before shipping any release that touches `host_permissions`/
  `optional_host_permissions`/content-script registration, load the previous store build in real
  Chrome + Firefox profiles, apply the new build as an in-place update, and assert it stays
  enabled, fetch works, and the Firefox first-run grant flow triggers.
- **Firefox:** `manifest.firefox.json` + `TARGET=firefox npm run build` (background event page instead
  of the SW; `browser_specific_settings`). The `chrome.*` calls work on both.

## Next

- More item types in-page beyond logins and cards.
- Per-instance signing keys for the update channel, so a self-host origin can have one too.
- A real browser harness. On-browser behaviour is manual today; the B2-10 procedure above is the
  only thing standing between a host-permission change and a silently disabled extension, and it
  deserves automation.
