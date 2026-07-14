# Release-signing keys (H2) — public record

_Ceremony run 2026-07-14 on the owner's Windows workstation (PRESTIGE). All PRIVATE keys stay on that
machine, ACL/file-perm locked, uncommitted and un-uploaded. Only the PUBLIC material below leaves it._
Sibling to the escrow/recovery-ceremony record (`docs/drills/escrow-genesis-ceremony.md`).

## 1. Update-manifest signing — Ed25519 (H2 §F / core `UpdateVerify.PINNED`)
- **Public key (base64url):** `e_2TpyoQG4ygtbdVO9RUWbUW4MTHGPO8eXL7Jqc_tHI`
- Pinned in `core/.../client/UpdateVerify.kt` `PINNED` (the client verifies the `/downloads` manifest
  signature against it). Sign a manifest with `tools/update-signer sign … --key <privkey>` on the
  workstation.
- Private key: `~/.andvari/update-signing.key` on PRESTIGE (ACL: `PRESTIGE\silence:(R)`).
- Loss/rotation: mint a new keypair, add the new pubkey to `PINNED` (a key SET — keep the old one
  during the overlap so fielded clients don't brick), rebuild clients, then retire the old.

## 2. Windows MSI code-signing — Authenticode (self-signed, household)
- **Certificate:** `CN=andvari household releases`
- **Thumbprint:** `35DFD21A…` (full value in the workstation cert store `Cert:\CurrentUser\My`)
- **Expires:** 2031. **Public cert:** `~/.andvari/andvari-codesign-pub.cer` on PRESTIGE.
- **Trust step:** import the `.cer` into **Trusted Publishers** on each household Windows machine →
  Windows then shows the andvari MSI as a known publisher and warns on anyone else's. SmartScreen may
  still warn on first run until reputation builds.
- **Follow-on:** a CA-issued **OV** code-signing cert (now needs org validation + a hardware token) or
  **Azure Trusted Signing** (~$10/mo) removes the self-signed/SmartScreen caveat. Not done this run.
- 0.16.0 MSI is signed (SHA256, RFC-3161 timestamped via DigiCert) and published; its sha256
  `45026161b555082234e80c51c5bdc50ee8c2f3ac44b32805c43b92ba44f2b081` is in `/downloads/manifest.json`.

## 3. Linux deb signing — GPG (detached `.asc`)
- **Key:** `andvari releases <releases@monahanhosting.com>` (ed25519, sign-only)
- **Fingerprint:** `03B3437A126C5C534CA0E9687514033356FDB4BF` · **Expires:** 2028 · machine-local, no passphrase.
- 0.16.0 deb signed → `andvari-0.16.0.deb.asc` published to `/downloads`. Users verify with:
  `gpg --import <this key> && gpg --verify andvari-0.16.0.deb.asc andvari-0.16.0.deb`
- **Public key block:**
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEalWpyRYJKwYBBAHaRw8BAQdAKTzFOgMaG1MOH2khZ6h/5UK0fXBjnjEIx+ku
sDHZMeW0LmFuZHZhcmkgcmVsZWFzZXMgPHJlbGVhc2VzQG1vbmFoYW5ob3N0aW5n
LmNvbT6IlgQTFgoAPhYhBAOzQ3oSbFxTTKDpaHUUAzNW/bS/BQJqVanJAhsDBQkD
wmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEHUUAzNW/bS/xYgA/2C8gliT
gNwuByi91u4o7pgD/VoZzh/N/hSiYNzHBX9UAP9JXVBhYc5GOokigvadNSG+olfm
7AVDYZbgQ42FROmTBw==
=mgP5
-----END PGP PUBLIC KEY BLOCK-----
```

## Status (2026-07-14)
- **Load-bearing OS-signing DONE for desktop:** MSI Authenticode + deb GPG live on CT122. That closes
  the H2 §M-D1 "trojaned installer → RCE" path for the .msi/.deb the user runs (the bytes are now
  OS-verifiable, independent of the server).
- **Secondary manifest-sig:** pubkey pinned; the client verify wiring (desktop + extension) is the
  remaining code; each release's manifest must be signed on the workstation with `update-signer sign`.
- **Extension:** still needs store-signing (CWS/AMO, `docs/runbooks/extension-store-publishing.md`) —
  the only real integrity for a browser extension; that's H2 for the extension.
