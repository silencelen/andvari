# Extension store publishing (H2, item 1) — submission package

Goal: get **genuine store-signed auto-updates** for the browser extension (the real H2 fix for the
extension — self-hosted zips have no integrity). Keep it **out of public search** via *unlisted*
(Chrome) / *self-distribution* (Firefox). Safe for andvari because it's zero-knowledge: no secrets in
the code, the only host permission is your Tailscale server URL, and it collects/transmits nothing to
anyone but your own server.

**Artifacts to upload** (already built, byte-verified, version 0.13.0):
- Chrome: `extension/artifacts/andvari-extension-chrome-0.13.0.zip`
- Firefox: `extension/artifacts/andvari-extension-firefox-0.13.0.zip`

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

## B. Chrome — Web Store, **Unlisted** ($5 one-time)

1. Go to **https://chrome.google.com/webstore/devconsole**. If not registered, pay the **one-time $5** developer fee.
2. **Add new item** → upload `andvari-extension-chrome-0.13.0.zip`.
3. Fill the listing (draft copy below), set **Visibility: Unlisted**, and **Submit for review** (hours→days; a password manager's permissions draw scrutiny — the justifications below are what they ask for).
4. Once approved, Chrome **auto-updates it from the store, store-signed** — that's the H2 fix for Chrome.

### Listing copy (draft)
- **Name:** andvari
- **Summary (≤132 chars):** Autofill and save logins for your self-hosted, zero-knowledge andvari password manager. Requires the andvari server on your Tailscale network.
- **Category:** Productivity
- **Description:** andvari is the browser companion for the self-hosted, end-to-end-encrypted andvari password manager. It detects login forms and fills/saves credentials from your own andvari server. Your vault is encrypted on your devices; the extension talks only to your andvari server over your private Tailscale network and sends no data to anyone else. Requires a running andvari server.

### Permission justifications (Chrome asks for each)
- **host_permissions `https://andvari.taila2dff2.ts.net/*`** — the extension connects only to the user's own andvari server (their Tailscale MagicDNS address) to fetch/save the encrypted vault. No other host.
- **content_scripts (`http://*/*`, `https://*/*`, all_frames)** — a password manager must detect login/registration forms on the sites the user visits to offer autofill and save. It reads only form structure; it never sends page content anywhere.
- **storage** — holds the session (in `storage.session`, memory-only) and non-secret update-check state; never persists secrets to disk.
- **activeTab** — act on the tab the user is on when they invoke fill.
- **alarms** — schedule the clipboard auto-clear and the update check.
- **offscreen** (Chrome) — a minimal offscreen document used solely to clear the clipboard after the auto-clear timeout.

### Data-use disclosures
- Personally/sensitive data handled: **authentication information** (the user's own credentials), used **only** to fill/save on the user's own server. **Not** sold, **not** transferred to third parties, **not** used for anything beyond the single purpose. The design is zero-knowledge (the server never sees plaintext or keys).
- **Privacy policy URL** (Chrome requires one for this category): host the draft in `docs/legal/privacy-extension.md` (below) at a public URL (e.g. `https://monahanhosting.com/andvari/privacy`) and paste that URL here.

---

## C. Privacy policy (draft to host — see `docs/legal/privacy-extension.md`)

A short, accurate policy is enough: the extension collects no analytics, stores no data off-device
except the encrypted vault on the user's own andvari server, and shares nothing with third parties.

---

## After publishing
- Point the extension's update surface at the store/signed artifact (Chrome auto-updates from CWS; Firefox installs the AMO-signed XPI). The self-hosted `/downloads` zip then becomes a fallback only.
- Record the CWS item id + the AMO listing in this runbook for future releases.
