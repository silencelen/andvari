# andvari browser extension — Privacy Policy

_Last updated: 2026-07-27_

The andvari browser extension is the companion client to the andvari password manager — an
end-to-end-encrypted vault you or someone you trust runs. The extension talks to **one** andvari
server: the one configured in its Options page. That is your own self-hosted instance if you run
one, or the reference instance the shipped build defaults to
(`https://andvari.monahanhosting.com`). This policy describes what the extension does and does not
do with your data.

## What the extension accesses

- **Your vault items** (logins and payment cards), to fill and save them. They travel to and from
  your configured server as ciphertext only. Decryption happens in your browser, in memory, while
  the vault is unlocked — the keys are derived from your master password on your device.
- **Web page form structure**, to detect sign-in, registration, and checkout fields. The extension
  looks at whether fields exist and what kind they are (username, password, card number, expiry,
  and so on). It does not read, store, or transmit page content.
- **A credential you type into a form**, when you submit one the vault does not yet know, so it can
  offer to save it. That offer is in-memory until you accept it.

## What leaves your device

Everything below goes to the single server you configured, over HTTPS, and nowhere else:

- your **email address**, to begin sign-in and to look up your key-derivation parameters;
- a **derived authentication value** — never your master password, never your keys — plus your
  one-time code if you have two-factor enabled;
- **encrypted vault data** in both directions (sync), plus session tokens;
- a header naming the client and its version, so the server can refuse an incompatible build.

One exception, and it is narrow: when — and only when — the configured server is the shipped
default, the extension fetches that server's signed update manifest to notice a new version. If
you point the extension at any other origin, it makes no such request at all.

## What the extension does NOT do

- It does **not** collect analytics, telemetry, or usage data.
- It does **not** send anything to the extension's authors, to any third party, or to any server
  other than the one you configured.
- Your server never receives your master password, your keys, or any plaintext. It stores
  ciphertext it cannot read.
- It writes **no** vault secrets to disk. Unlocked vault data lives in memory-backed session
  storage, cleared when the vault locks or the browser closes. What it does keep on disk is
  non-secret: the server address you chose, the email you last signed in with, and interface
  preferences.
- The **context-menu item** and the **keyboard shortcut** only open the extension's popup. Neither
  reads the page.

## Permissions, and why

- **Site access** for the sites you visit: required to detect fields and fill them. On Chrome it is
  requested at runtime, by your explicit action, not at install; on Firefox it is a toggle you
  grant. Without it the extension does nothing on a page.
- **Site access for your andvari server**: required to reach it at all.
- **Storage / alarms / scripting / offscreen / context menus**: local session custody, the idle
  auto-lock and clipboard-clear timers, injecting the autofill helper into pages you granted, and
  the "andvari" entry in the right-click menu.

## Data sharing and sale

**None.** No data is sold, rented, or shared with any third party.

## Contact

Questions: the operator of your andvari server. For the software itself, see the project's
repository at <https://github.com/silencelen/andvari> — security reports go through the private
channel described in its `SECURITY.md`.
