# andvari browser extension — Privacy Policy

_Last updated: 2026-07-13_

The andvari browser extension is the companion to the self-hosted, end-to-end-encrypted andvari
password manager. This policy describes what the extension does and does not do with your data.

## What the extension accesses
- **Your login credentials**, to fill and save them — only on the sites you use them on, and only
  to/from **your own andvari server** (the Tailscale address you configure). Credentials are
  encrypted end-to-end; they are decrypted only in your browser, in memory, while your vault is
  unlocked.
- **Web page form structure**, to detect login and registration fields for autofill. The extension
  reads only whether fields are present and their type; it does not read or transmit page content.

## What the extension does NOT do
- It does **not** collect analytics, telemetry, or usage data.
- It does **not** send any data to the extension's authors or to any third party.
- It communicates **only** with the andvari server you configure, over your private Tailscale
  network, using end-to-end encryption. The server never receives your master password, your keys,
  or any plaintext.
- It stores **no** secrets on disk; session data lives in memory and is cleared when the browser
  closes or the vault locks.

## Data sharing and sale
- **None.** No data is sold, rented, or shared with any third party.

## Contact
Questions: the operator of your andvari server.
