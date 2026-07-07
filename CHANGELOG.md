# andvari — changelog

## 0.3.0 — family sharing, offline cache, CSV import, autofill

- **Family sharing.** Create shared vaults and add household members. Each member grant
  seals the vault key to that member's identity key (`crypto_box_seal`); before sending it
  you verify their short **identity code** out of band (in person / by phone) — that code is
  derived from a key the server can't forge. Web has a full Sharing screen (create, add by
  email with the fingerprint check, change role, remove); native apps open shared vaults and
  show your own identity code. Removing a member is revocation-only in v1 (they keep anything
  they already saw; key rotation is a later release).
- **Durable offline cache** (native). Android/desktop keep an encrypted on-device copy of the
  vault, so the app opens instantly and works **offline** (read + queue edits) until it
  reconnects. Only ciphertext is stored; the master password is still required to unlock.
- **CSV import.** Import from Chrome/Edge or Firefox password exports (web + native). Parsing
  is fully on-device; the file never leaves your machine. Handles quoting/dedupe/rename and
  warns that the export holds plaintext — delete it after. An interrupted import resumes
  without creating duplicates.
- **Android autofill** (fill-only). andvari can fill logins in Chrome and other apps. Matching
  is strict (exact host or a true subdomain — never a look-alike or a whole TLD) and honors a
  web domain only from a trusted browser. Locked → tap to unlock in place. Enable it in
  Settings → Passwords & autofill.
- **Security hardening.** Real client IPs behind the proxy for rate-limits/audit; per-user
  upload caps; WebSocket auth via a single-use ticket (no token in URLs); no emails in audit
  logs; tighter CSP. Desktop now defaults to the tailnet URL (auto-migrates once).
- Fielded 0.2.4 (Android) / 0.2.0 (desktop) clients keep working against the upgraded server.

## 0.2.4 — default to the tailnet server

- Default server URL is now https://andvari.taila2dff2.ts.net (reachable from any
  Tailscale device; the old .2.122 LAN IP isn't, from off-VLAN-2). Existing installs
  on the old default auto-migrate once. Changing the server now reloads the recovery
  key immediately (no restart).

## 0.2.3 — boot crash FIXED

- Fixed the ClassNotFoundException that crashed the app on launch since v0.1.0: the
  manifest referenced MainActivity/Application by relative name (resolved against the
  `com.silencelen.andvari` namespace) while the classes live in package
  `io.silencelen.andvari.app`. Now fully-qualified. The app launches to the Welcome
  screen (verified on-device). Crash reporter + ProfileInstaller changes from 0.2.1–0.2.2 kept.

## 0.2.2 (Android boot-crash diagnostic)

- Disable ProfileInstaller auto-init (a pre-Application startup step that can crash on
  some Android 15/OEM builds) — perf-only, safe to drop.
- Crash reporter now renders with a plain Android view (no Compose), so a crash in the
  Compose layer itself is still shown on the next launch to screenshot.

## 0.2.1 (Android diagnostic)

- On-screen crash reporter: if the app hits an unhandled error, the next launch shows
  the stack trace to screenshot (no adb needed). Diagnostic aid; no feature changes.

## 0.2.0

- Encrypted file attachments on items: attach from the editor, download+decrypt from
  the detail view. Per-file keys; the server only ever stores ciphertext chunks.
- Server-TOTP (Settings): enroll an authenticator as the second factor that
  break-glass/public logins require. Sign-in now prompts for a code when the server
  asks for one.
- Matches server/web 0.2.0 (admin console, password health, password change live in
  the web app).

## 0.1.0 (first release)

First Android client for the in-house andvari password manager.

- Sign in and enroll (invite + recovery-fingerprint confirmation) against the
  andvari server (default CT 122, `192.168.2.122`; configurable in the sign-in
  screen).
- Zero-knowledge: your master password derives all keys on-device; the server only
  ever sees ciphertext. A relaunch re-prompts for the master password (the vault key
  is never stored).
- Vault: search, logins and secure notes, per-item detail with copy-to-clipboard
  (auto-clears after 30s), live rolling TOTP codes, and a strong password generator.

**Note:** enrollment needs the server's escrow recovery key configured first (the
one-time offline ceremony). Until then the server disables new-account creation.
