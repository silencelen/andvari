# andvari — changelog

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
