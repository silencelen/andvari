# Release-signing keys (H2) — public record

_Ceremony run 2026-07-14 on the owner's Windows workstation (PRESTIGE). All PRIVATE keys stay on that
machine, ACL/file-perm locked, uncommitted and un-uploaded. Only the PUBLIC material below leaves it._
Sibling to the escrow/recovery-ceremony record (`docs/drills/escrow-genesis-ceremony.md`).

## 0. The ceremony is one command (`signandvari`, 2026-08-20)

Everything the signing box does for a release — fetch tags, check out the tag, find `signtool`,
build and sign the MSI, mint the manifest at the next `seq`, sign it, and deliver the bundle —
runs as **`scripts/signandvari.ps1`**, installed *outside* the repo (`%USERPROFILE%\bin` plus a
`$PROFILE` function) because step 3 checks out the release tag and would otherwise replace the
script underneath its own execution.

```powershell
signandvari 0.25.0 -DryRun     # preflight, seq arithmetic and manifest preview; signs nothing
signandvari 0.25.0             # checkout + preflight -> ceremony -> ordered drop
signandvari 0.25.0 -SkipDrop   # produce the bundle, deliver it by hand
```

Configuration is **environment-only**, so nothing instance-specific lives in this public repo:
`ANDVARI_REPO` (the checkout), `ANDVARI_RELEASE_DROP` (`user@host:/path/`), optionally
`ANDVARI_SIGNTOOL`. It reimplements none of the ceremony — `prestige-release.ps1` remains the
single source of truth for signing, `seq` arithmetic and manifest assembly. What it adds is the
handling *around* those, every step of which had cost a release at least once.

The delivery order is the part worth understanding: **payload files first, then every payload
re-hashed by `ssh sha256sum` on the build host, and only then `manifest.json.sig`, alone, last.**
The build-host watcher treats the `.sig` as the completion signal, so a single recursive copy
gives no ordering guarantee against a ~117 MB MSI. Any hash mismatch aborts *before* the
signature, so a torn drop can never be published.

**A wedge or failure after signing is never re-signed** — a fresh signature burns a new
`signedAt`. Verify the produced bundle against its `bundle.json`, confirm the published channel's
`seq` is unchanged, and deliver by hand in payload → sig order.

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
  and publish `manifest.json` + `manifest.json.sig` to the instance's downloads dir TOGETHER
  (the sig is over the exact bytes — any re-serialization breaks it). **In practice this is one
  command now — see §0 — and running it by hand is the fallback, not the path.** Anti-rollback floors:
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
- Every MSI from 0.20.0 onward is signed (SHA256, RFC-3161 timestamped via DigiCert) and its
  sha256 published in `/downloads/manifest.json`. 0.19.0's shipped unsigned — a lapse, not a
  policy — and 0.16.0's was the first signed one.
- **Known-benign:** `signtool verify` exits 1 with an `UnknownError` chain status, because the
  household cert is self-signed and not in the signing box's Trusted Root. `signandvari`
  classifies this itself (signature present, correct cert, timestamped). It is not a signing
  failure; do not "fix" the chain.

## 3. Linux deb signing — GPG (detached `.asc`)
- **Key:** `andvari releases <releases@monahanhosting.com>` (ed25519, sign-only)
- **CURRENT key (rotated 2026-07-23):** **Fingerprint `741CF143A5E1EDF3B9CBE923D1CC699A598417FC`** ·
  **Expires 2028-07-22** · machine-local, no passphrase, plus an offline-keyring backup so a keyring
  reset can't lose it again (the 2026-07-14 key was lost exactly that way — see rotation note).
- Signed releases: **every deb from 0.19.1 onward** carries a `.deb.asc` under this key ·
  `andvari-0.16.0.deb.asc` under the RETIRED key below. 0.17.0–0.19.0 debs shipped **unsigned**
  (the signing lapse the rotation closes). Users verify with:
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

## Status (2026-08-23)
- **Load-bearing OS-signing DONE for desktop:** MSI Authenticode + deb GPG, live on the reference
  instance. That closes the H2 §M-D1 "trojaned installer → RCE" path for the `.msi`/`.deb` the
  user runs — the bytes are OS-verifiable, independent of the server. Both have run every release
  since 0.20.0.
- **Secondary manifest-sig: ARMED 2026-07-18, and signing every release since** — ceremony pubkey
  pinned in core + extension, reference-instance-scoped (see §1); first signed manifest = seq 1
  (0.19.1). Fielded ≤0.17.0-ext / ≤0.19.0-desktop builds pin the sentinel and stay quiet; builds
  from the arming commit onward verify.
- **Open at 0.25.0:** the reference instance's channel is at **seq 7 (0.24.0)** and the 0.25.0 MSI
  is not yet on `/downloads`. Both are the same PRESTIGE step — `signandvari 0.25.0` (§0). The deb,
  both extension packages and the web bundle are already live at 0.25.0, so this is a channel that
  is behind, not one that is wrong: armed clients correctly report 0.24.0 as latest.
- **Extension store-signing DONE** (CWS + AMO live since 0.16.x, `extension-store-publishing.md`) —
  the load-bearing integrity for the extension; the signed manifest is the belt for zip installs.

## Signing-box preflight (learned on the 0.22.0 ceremony, 2026-08-14)

Four things cost time on a run that was otherwise clean. None is a script defect; all are host
state, so they recur on a fresh box or after a long gap.

1. **`signtool` is usually not on PATH.** Launch from a Developer Command Prompt / Windows SDK
   shell, or pass `-SignToolPath "C:\Program Files (x86)\Windows Kits\10\bin\<ver>\x64\signtool.exe"`.
   The script preflights for it and stops early rather than failing after the MSI build.
2. **Check out the TAG, not `main`.** `main` moves on after a release; an MSI built from it would
   carry dependencies no other artifact of that version has, so Windows would silently diverge from
   the deb, APK and extension already in users' hands. `-Ref v<version>` pins it.
3. **A stale clone is fine to update, but only if it postdates 2026-07-16.** Anything older predates
   the `git-filter-repo` rewrite and the repo recreation, and will not reconcile — take a fresh
   clone instead. A clean `git fetch --all --tags` succeeding is the signal that yours is fine.
4. **`ANDVARI_RELEASE_DROP` is worth setting.** Unset, the bundle stays on the signing box and the
   ~117 MB MSI needs a manual copy to the build host before it can be verified and published.

### Handing the bundle back

Report the MSI's sha256 and size, the manifest **verbatim plus its own sha256**, and the signature
last. That manifest hash is what makes a pasted handover safe: the signature covers exact bytes, so
without it a mangled newline or a BOM is indistinguishable from a bad key. State the byte facts too
(UTF-8, no BOM, LF, exactly one trailing newline) and note that the `.sig` is **unpadded base64url**
— a strict base64 decoder rejects it. Done that way, a 687-byte manifest reconstructs byte-exactly
on the first attempt.
