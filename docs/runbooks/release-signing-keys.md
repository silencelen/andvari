# Release-signing keys (H2) — public record

_Ceremony run 2026-07-14 on the owner's Windows workstation (PRESTIGE). All PRIVATE keys stay on that
machine, ACL/file-perm locked, uncommitted and un-uploaded. Only the PUBLIC material below leaves it._
Sibling to the escrow/recovery-ceremony record (`docs/drills/escrow-genesis-ceremony.md`).

## 1. Update-manifest signing — Ed25519 (H2 §F / core `UpdateVerify.PINNED`)
- **Public key (base64url):** `e_2TpyoQG4ygtbdVO9RUWbUW4MTHGPO8eXL7Jqc_tHI`
- **ARMED 2026-07-18**, pinned in `core/.../client/UpdateVerify.kt` `PINNED` + the extension's
  `updateverify.ts PINNED_UPDATE_KEYS` (byte-locked by `updateverify.test.ts`). The channel is
  **reference-instance-scoped** (multi-tenant §9): desktop `Platform.checkForUpdate` and extension
  `background.checkForUpdate` run it ONLY when the configured server is the shipped default origin —
  a self-host/custom origin never fetches the manifest (quiet "disabled", exactly the un-armed
  posture), so this single key never renders anyone else's `/downloads` "unverified".
- Private key: `~/.andvari/update-signing.key` on PRESTIGE (ACL: `PRESTIGE\silence:(R)`).
- **Per-release step (every time `/downloads/manifest.json` changes):** bump `seq` to
  max(published)+1 (§D8; first signed manifest = seq 1, 2026-07-18), refresh `signedAt` (ISO-8601
  UTC; clients treat > 30–45 d as a stale channel), then on PRESTIGE:
  `java -jar tools\update-signer\build\libs\andvari-update-signer.jar sign manifest.json --key %USERPROFILE%\.andvari\update-signing.key`
  and publish `manifest.json` + `manifest.json.sig` to CT122 `/opt/andvari/downloads/` TOGETHER
  (the sig is over the exact bytes — any re-serialization breaks it). Anti-rollback floors:
  core `MIN_SEQ = 1` (desktop refuses `seq < floor`) / extension `MIN_SEQ = 0` (refuses
  `seq <= lastAccepted`) — the SAME semantic floor, deliberately different numbers.
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
- **CURRENT key (rotated 2026-07-23):** **Fingerprint `741CF143A5E1EDF3B9CBE923D1CC699A598417FC`** ·
  **Expires 2028-07-22** · machine-local, no passphrase, plus an offline-keyring backup so a keyring
  reset can't lose it again (the 2026-07-14 key was lost exactly that way — see rotation note).
- Signed releases: `andvari-0.19.1.deb.asc` (this key) · `andvari-0.16.0.deb.asc` (RETIRED key below).
  0.17.0–0.19.0 debs shipped **unsigned** (the signing lapse the rotation closes). Users verify with:
  `gpg --import <this key> && gpg --verify andvari-<ver>.deb.asc andvari-<ver>.deb`
- **Public key block (CURRENT, 741CF143…):**
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEamKObhYJKwYBBAHaRw8BAQdAfCGQuARf7aOAXl8V53q0fWcSh+Fvk20iAqWU
gB0QhJ60LmFuZHZhcmkgcmVsZWFzZXMgPHJlbGVhc2VzQG1vbmFoYW5ob3N0aW5n
LmNvbT6ImQQTFgoAQRYhBHQc8UOl4e3zucvpI9HMaZpZhBf8BQJqYo5uAhsDBQkD
wmcABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJENHMaZpZhBf8MtcA/jWH
9GMDbm9s8MfTLi/Cr/U57aIsdZp5swZI2X7Ja4zbAP9G2+wLeFWkIvv+8u74hAKw
qW2MjPc7z9lVeWr3ilciCQ==
=j6ly
-----END PGP PUBLIC KEY BLOCK-----
```
- **ROTATION NOTE (2026-07-23):** the 2026-07-14 key (`03B3437A126C5C534CA0E9687514033356FDB4BF`)
  was lost in a build-host keyring reset (~2026-07-16) with no backup — it signed only
  `andvari-0.16.0.deb.asc`, which stays verifiable against its block below. No compromise is
  suspected (loss, not leak); the old key simply can't sign again.
- **Public key block (RETIRED 2026-07-23, 03B3437A… — verifies 0.16.0 only):**
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

## Status (2026-07-18)
- **Load-bearing OS-signing DONE for desktop:** MSI Authenticode + deb GPG live on CT122. That closes
  the H2 §M-D1 "trojaned installer → RCE" path for the .msi/.deb the user runs (the bytes are now
  OS-verifiable, independent of the server). (0.19.0's MSI shipped UNSIGNED — re-run the Authenticode
  step at the next Windows build.)
- **Secondary manifest-sig: ARMED 2026-07-18** — ceremony pubkey pinned in core + extension,
  reference-instance-scoped (see §1); first signed manifest = seq 1. Fielded ≤0.17.0-ext /
  ≤0.19.0-desktop builds pin the sentinel and stay quiet; builds from the arming commit onward
  verify. Each manifest change re-signs on PRESTIGE per the §1 per-release step.
- **Extension store-signing DONE** (CWS + AMO live since 0.16.x, `extension-store-publishing.md`) —
  the load-bearing integrity for the extension; the signed manifest is the belt for zip installs.
