# Extension store publishing (H2, item 1) — submission package

Goal: get **genuine store-signed auto-updates** for the browser extension (the real H2 fix for the
extension — self-hosted zips have no integrity). Keep it **out of public search** via *unlisted*
(Chrome) / *self-distribution* (Firefox). Safe for andvari because it's zero-knowledge: no secrets in
the code, the only host permission is your Tailscale server URL, and it collects/transmits nothing to
anyone but your own server.

**Artifacts to upload** (already built, byte-verified, version 0.14.0):
- Chrome: `extension/artifacts/andvari-extension-chrome-0.14.0.zip`
- Firefox: `extension/artifacts/andvari-extension-firefox-0.14.0.zip`

---

## A. Firefox — AMO self-distribution (do this first: free, unlisted, signs in seconds)

Firefox refuses to install unsigned extensions on release builds, so AMO signing is required anyway.
Self-distribution signs your XPI **without any public listing**.

1. Sign in at **https://addons.mozilla.org/developers/** (create an account if needed).
2. **Submit a New Add-on** → distribution choice **"On your own site"** (this is self-distribution / unlisted).
3. Upload `andvari-extension-firefox-0.13.0.zip`. Automated validation runs; on pass, AMO **signs it in seconds**.
4. Download the **signed `.xpi`** and host it at `CT122:/opt/andvari/downloads/` (same place the deb/zip live) — or wherever the extension's update check points. Users install the *signed* XPI; Firefox verifies Mozilla's signature.
5. (optional) For future releases you can automate this with `web-ext sign` + AMO API credentials.

---

## B. Chrome — Web Store, **Unlisted** ($5 one-time) — COMPLETE FIELD KIT (2026-07-14)

Account is registered + fee paid; the 0.14.0 chrome zip is uploaded as the draft package. The
dashboard has four tabs to complete before **Submit for review**: **Package · Store listing ·
Privacy · Distribution** (plus one-time Account items). Everything below is paste-ready.

### One-time Account items (dashboard → Account)
- **Contact email:** set + **verify** (publish is blocked until verified).
- **Trader declaration (EU DSA):** declare **Non-trader** — household/hobby distribution, no
  commerce. (Moot if distribution is US-only, but set it anyway; the field is account-level.)

### Package tab
- Draft package = `andvari-extension-chrome-0.14.0.zip`. The **Summary** ("description" in
  `manifest.json`) and the item name come from the package, not the form: *"Zero-knowledge password
  manager — fill and save logins. Requires the andvari server on your Tailscale network."* (110
  chars — fits the 132 limit.) Nothing to do here unless a newer version ships before submission.

### Store listing tab
- **Title (from package):** andvari
- **Summary (from package):** see above — edit `manifest.json` + repackage if it ever needs changing.
- **Category:** **Privacy & Security** (what 1Password/Bitwarden use; the old "Productivity" draft
  predates the CWS category rework).
- **Language:** English (United States)
- **Detailed description** (paste verbatim):

```
andvari is the browser companion for the andvari password manager — a self-hosted, zero-knowledge vault for one household. The extension connects ONLY to your own andvari server over your private Tailscale network. There is no account to create here and no cloud service behind it: without a running andvari server, the extension does nothing.

WHAT IT DOES
• Fills logins — detects username/password fields (multi-step sign-ins, iframes, and single-page apps included) and offers the matching entries from your vault.
• Saves and updates — after you sign in on a site, offers to save the new login or update a changed password.
• Popup vault — search your entries, copy usernames/passwords, live two-factor (TOTP) codes, and copy card details (shown masked; full numbers are never rendered in the UI).
• Strong password generator.
• Auto-lock, clipboard auto-clear, and a session that survives browser restarts of the extension's service worker — secrets live in memory only, never on disk.

HOW YOUR DATA IS HANDLED
• End-to-end encrypted: entries are encrypted and decrypted only on your devices. Your master password and keys never leave your browser.
• Your server, your data: the extension talks exclusively to the single andvari server address built into it (a private Tailscale hostname). No third-party servers, no analytics, no telemetry.
• The content script reads only form structure to detect login fields; page content is never collected or transmitted.

REQUIREMENTS
• A running andvari server reachable over your Tailscale network. This extension is distributed unlisted for household use and will not work without one — it is a companion client, not a standalone product.

Privacy policy: https://monahanhosting.com/andvari/privacy/
```

- **Store icon (128×128):** upload `extension/icons/icon128.png` (the treasury coin + ᛅ rune).
- **Screenshots (≥1 required, up to 5, 1280×800 PNG):** use the generated set in
  `extension/store-assets/` (popup vault + in-page fill dropdown + save banner). Must show the item
  in actual use — no pure marketing frames.
- **Small promo tile (440×280, optional):** `extension/store-assets/promo-tile-440x280.png` if
  present; safe to skip for an unlisted item.
- **Additional fields:** Homepage URL `https://andvari.monahanhosting.com` · Support URL the same ·
  skip "Official URL" (needs a Search-Console-verified domain — unnecessary) · Mature content: **No**
  · no Google Analytics ID.

### Privacy tab (this is what review actually reads — answer exactly)
- **Single purpose** (paste):

```
andvari is a password manager. Its single purpose is giving the user access to their own encrypted credential vault — filling and saving logins on websites, and showing/copying vault entries (passwords, two-factor codes, payment cards) from the user's own self-hosted andvari server. Every permission requested serves that one purpose.
```

- **Permission justifications** (one field per permission):
  - **storage** — `Holds the unlocked session in chrome.storage.session (memory-backed, cleared when the browser closes) so the vault survives Manifest V3 service-worker restarts, plus non-secret bookkeeping (update-check state, UI preferences). Secrets are never written to persistent storage.`
  - **activeTab** — `Lets the popup read the URL of the tab it was opened on so it can list the vault entries that match the current site, without requesting broad tabs access.`
  - **alarms** — `Schedules the vault auto-lock timeout, the clipboard auto-clear, and the periodic background sync/update check. No user data is involved.`
  - **offscreen** — `Creates a minimal offscreen document for exactly one job: clearing the system clipboard after the auto-clear timeout (an MV3 service worker cannot access the clipboard directly).`
  - **Host permission justification** (covers `https://andvari.taila2dff2.ts.net/*` AND the content
    scripts on `http://*/*` / `https://*/*`) — `The single host permission is the user's own self-hosted andvari server on their private Tailscale network — the only network endpoint the extension ever contacts, used to fetch and store the user's end-to-end-encrypted vault. The content scripts run on ordinary web pages because a password manager must detect login/registration forms on whatever site the user visits in order to offer autofill and save; they read form structure only, and nothing from the page is sent anywhere except to the extension itself.`
- **Remote code:** **"No, I am not using remote code."** (Everything is bundled by esbuild; no
  eval, no WASM, extension-page CSP is `script-src 'self'`.)
- **Data usage — check exactly two** (Bitwarden-precedent, accurate for us):
  - ☑ **Personally identifiable information** (usernames are typically email addresses)
  - ☑ **Authentication information** (passwords, TOTP seeds — the product's purpose)
  - Everything else unchecked. Cards are NOT "collected" by the extension (it only downloads +
    decrypts them locally and copies to clipboard; it never creates/edits/transmits card data).
- **Certifications — check all three:** not sold to third parties; not used/transferred for
  purposes unrelated to the single purpose; not used/transferred to determine creditworthiness or
  for lending.
- **Privacy policy URL:** `https://monahanhosting.com/andvari/privacy/` (the hosted copy of
  `docs/legal/privacy-extension.md` — deployed to monahanhosting.com's static docroot).

### Test instructions tab (fill it — credentials NO, instructions YES)

Do **not** provide test credentials: the only backend the extension can reach is the private
Tailscale hostname pinned in the manifest, so any account would fail from Google's review
environment anyway — and the household vault is not something to hand out. Instead, paste this so
the reviewer knows WHY sign-in can't work and what they can still verify:

```
andvari is the companion client to a SELF-HOSTED password manager. The only backend it can talk to is the single host in its manifest — a private Tailscale (VPN) hostname on the developer's home network. It is not reachable from the public internet, so no test account can work from your environment: sign-in will fail with a network error by design. There is no public or demo server; pinning that single host permission is the product's security model (the extension can never talk to any other endpoint).

What you can verify without a server:
1. Install and open the popup — the locked screen renders (email + master password + "Test server connection").
2. Click "Test server connection" — it reports the server unreachable (expected outside the private network) and sends no other traffic.
3. Visit any login page (for example https://fill.dev) — the content script reads form structure only; with the vault locked it fills nothing and transmits nothing.
4. Observe network traffic: every request goes exclusively to the single manifest host. There are no analytics and no third-party endpoints anywhere in the code.

This extension is distributed UNLISTED and installed only by the developer's own household, whose members run the matching self-hosted server. The listing screenshots show the unlocked experience.
```

### Distribution tab
- **Payments:** Free of charge.
- **Visibility:** **Unlisted** (installable by link, absent from search/browse).
- **Regions:** **United States only** (household use; also sidesteps the EU-DSA trader-labeling
  surface entirely). All-regions would also be fine as a declared non-trader.

### Submit + expectations
- Content scripts on all sites = **broad host permissions** → expect the in-depth review track
  (typically 1–7 days for a first submission; the justifications above are exactly what reviewers
  check). Unlisted items get the same review as public ones.
- After approval, Chrome installs/auto-updates it **store-signed** — that's the H2 fix for Chrome.
  Record the **item ID + store URL here** when granted.
- **Future releases:** bump the 3 lockstep version files → `npm run package` → Package tab →
  upload the new chrome zip → Submit. Each upload must have a strictly higher `version`.

---

## C. Privacy policy — **LIVE** at `https://monahanhosting.com/andvari/privacy/`

Deployed 2026-07-14: `docs/legal/privacy-extension.md` rendered as a static, theme-aware HTML page
on monahanhosting.com (CT 121 hermod, `/var/www/monahanhosting.com/andvari/privacy/index.html`;
mirrored in netplan `nginx-configs/webroot/monahanhosting.com/andvari/privacy/`). Verified 200
through Cloudflare. If the markdown policy changes, re-render + redeploy both copies.

## D. Store assets (generated 2026-07-14 — `extension/store-assets/`)

3× 1280×800 screenshots (real popup UI driven by a chrome-API shim + fixture data, headless
capture) + optional 440×280 promo tile. Owner-facing submission kit with every field paste-ready +
downloadable assets: **https://claude.ai/code/artifact/74b32e72-dded-46f3-a746-4556b6f96031**

---

## After publishing
- Point the extension's update surface at the store/signed artifact (Chrome auto-updates from CWS; Firefox installs the AMO-signed XPI). The self-hosted `/downloads` zip then becomes a fallback only.
- Record the CWS item id + the AMO listing in this runbook for future releases.
  - **CWS item id:** `ndhkgfgkbnfieehncjgegcjhfdbhmmbn` (unlisted) — https://chromewebstore.google.com/detail/andvari/ndhkgfgkbnfieehncjgegcjhfdbhmmbn
  - **AMO addon id:** `andvari@monahanhosting.com` (self-distribution / unlisted)

---

## E. Automated publishing (both stores) — `scripts/publish-extension.sh`

Once the sections above are done manually the *first* time, every subsequent release is one command
from huginn: **`scripts/publish-extension.sh`** (no args → both browsers, version from
`extension/manifest.json`). It uploads + submits to Chrome (Publish API) and signs on AMO
(`web-ext sign`, unlisted). **Local-publish only — never CI** (this account's Actions billing is broken),
matching `ship.sh`/`publish-image.sh`.

**Honest caveat:** both stores still *review* every update (even unlisted) — Chrome minutes-to-days,
AMO usually seconds-to-minutes. The script automates the upload + submit, not the review wait.

### One-time credential setup (owner-gated — needs your Google / Mozilla accounts)
Fill these into `~/.andvari/store-publish.env` (chmod 600 — **outside the repo**; template at
`scripts/store-publish.env.template`):

**Chrome (OAuth2 refresh token):**
1. Google Cloud Console → new project → **APIs & Services → Enable APIs → "Chrome Web Store API"**.
2. **OAuth consent screen** (External; add yourself as a test user) → **Credentials → Create OAuth client → Desktop app** → copy the **client id + secret**.
3. Mint a refresh token on a machine with a browser (the loopback OAuth flow — the old copy/paste
   `oob` flow is deprecated). Easiest: `npx chrome-webstore-upload-keys` → paste the client id/secret →
   it opens the consent page → outputs `CWS_CLIENT_ID` / `CWS_CLIENT_SECRET` / `CWS_REFRESH_TOKEN`.

**Firefox (AMO API key):**
- addons.mozilla.org → **Developer Hub → Manage API Keys → Generate new credentials** → copy the
  **JWT issuer** (`user:…:…`) into `AMO_JWT_ISSUER` and the secret into `AMO_JWT_SECRET`. No browser dance.

### Run
```
cd extension && node package.mjs && cd ..    # build the versioned zips first
scripts/publish-extension.sh --dry-run       # confirm creds + zips resolve, no upload
scripts/publish-extension.sh                 # push BOTH stores at the manifest version
# scripts/publish-extension.sh --chrome --version 0.16.0   # one browser / pinned version
```
Chrome auto-updates installed users once review passes. For Firefox, host the resulting signed
`.xpi` (printed by the script) at the instance's `ANDVARI_DOWNLOADS_DIR` — along with the
`firefox-updates.json` the script emits — so release-Firefox installs the Mozilla-signed build and
auto-updates via the baked `update_url`.

**Then RE-SIGN the downloads manifest (H2 — armed 2026-07-18).** Any release that changes
`/downloads/manifest.json` (new ext version/urls, new deb/msi) must bump `seq` to max(published)+1,
refresh `signedAt` (ISO-8601 UTC), and sign the EXACT final bytes with the ceremony key on the owner
workstation — per-release step + key locations in `docs/runbooks/release-signing-keys.md` §1.
Publish `manifest.json` + `manifest.json.sig` together, byte-identical to what was signed. Skipping
this leaves armed (0.18+) reference-origin installs showing the muted "update listing couldn't be
verified" line — fielded sentinel builds (≤0.17.0 ext / ≤0.19.0 desktop) never fetch and don't care.

### Releases faster than Chrome reviews — the push queue (standard process 2026-07-17)

Chrome refuses a new upload while a prior version is still in review (`ITEM_NOT_UPDATABLE`), and
reviews can take days. When that happens the script does NOT fail: it writes the version to
`~/.andvari/cws-push-queue` (single line, **newest wins** — releasing again before the store frees
up simply overwrites the queue, and the superseded version is never pushed). An operator-side cron
watcher drains the queue by re-running `publish-extension.sh --chrome --version <queued>` until the
store accepts it; on the reference deployment that's `andvari-cws-watch.sh` (every 6 h, notifies on
success or on a non-review failure, silent while waiting). Firefox never queues — AMO signs
unlisted submissions in seconds.

**BATCH releases — Chrome review is per-submission time-to-live (limitation, 2026-07-18).** Every
Chrome Web Store submission is independently reviewed (minutes → days) before it reaches users, and a
new version can't even upload while the prior one is still pending. So each version you push adds a
full review cycle of latency. When several fixes are landing close together, **hold them and ship one
combined version** rather than a rapid 0.16.x drip — one review, not N. (Firefox has no such tax —
AMO signs in seconds and auto-updates immediately, so the asymmetry is worth remembering: a fix can be
live on Firefox the same minute while its Chrome twin waits in review.) Example: the 0.16.4 unlocked-
list layout fix was deliberately held and folded into the 0.17.0 biometric release for this reason.
