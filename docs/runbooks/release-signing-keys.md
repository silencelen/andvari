# Release-signing keys (H2) — public record

_Ceremony run 2026-07-14 on the owner's Windows workstation (PRESTIGE). All PRIVATE keys stay on that
machine, ACL/file-perm locked, uncommitted and un-uploaded. Only the PUBLIC material below leaves it._
Sibling to the escrow/recovery-ceremony record (`docs/drills/escrow-genesis-ceremony.md` — **recorded elsewhere**: `docs/drills/` was never part of this repository, it is the reference instance's private, out-of-tree operational area, so read that as a pointer and not a broken link; same note as `CHANGELOG.md` and `docs/ROADMAP.md` carry).

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

## 4. The GitHub release — `scripts/gh-release.sh` (added 2026-09-13, audit H102/H104)

The GitHub release page is the one download surface a stranger lands on, and until this script it
was the only published surface with no script behind it: assembled by hand with
`gh release create` / `gh release upload`, so its asset layout was retyped every release and
drifted apart from itself.

- `v0.26.3` shipped `andvari_0.26.3-1_amd64.deb` (Debian's build-output name) next to
  `andvari-0.26.3.deb.asc` (a signature named for the SERVED file) — a visitor cannot tell that
  those two pair up.
- `v0.26.2` shipped the opposite pairing (`andvari_0.26.2-1_amd64.deb` +
  `andvari_0.26.2-1_amd64.deb.asc`).
- §3's verify line, `gpg --verify andvari-<ver>.deb.asc andvari-<ver>.deb`, matched **neither**
  release page. (The bytes were fine throughout: `SHA256SUMS-0.26.3.txt` lists both names against
  the same digest `c0a32424…`.)

**One convention now: the SERVED names**, the same ones `/downloads` uses, the same ones §3 tells
users to verify, and the same ones `release-spec.sh` puts in the signed manifest. Run it on the
build host after the deb is signed:

```
scripts/gh-release.sh --version 0.26.3 --ext-version 0.26.0     --msi /path/to/andvari-0.26.3.msi   # handed back from the signing workstation, optional
```

What it guarantees, and why each one is here:

1. **`SHA256SUMS-<ver>.txt` is generated over exactly the asset set being uploaded** — never
   hand-maintained. `SHA256SUMS-0.26.2.txt` listed the two extension `.zip`s and omitted
   `andvari-extension-firefox-0.26.0.xpi` (sha `a704497…`, 191 892 B), which is the **only**
   Firefox install artifact and the one the live manifest's `browserExtension.firefoxUrl` points
   at: it shipped with no published digest anywhere. It was omitted because the AMO signing
   round-trip returns the `.xpi` *after* the rest is packaged and nothing re-emitted the file.
   Generating SUMS at upload time makes "in the release" and "in SUMS" the same event.
2. **`SHA256SUMS-<ver>.txt.asc`** — signed with the same GPG release key as the deb (§3,
   `741CF143…`). Unsigned checksums served from the same page as the artifacts prove nothing.
3. **Never different bytes under a filename that already exists.** 0.26.2 published two
   byte-different MSIs as `andvari-0.26.2.msi` (manifest seq 10 `windows.sha256` `1b8a94cd…`, then
   a seq 11 re-cut `93a7b7f5…`, same URL). Clients were never at risk — they verify the signed
   manifest's hash — but anyone who wrote down the seq-10 digest from the publish notification was
   left with an unexplained mismatch, and nothing in the tree said a re-cut had happened. The
   script refuses the overwrite at both the staging and the upload step. **A re-cut gets a new
   filename** (`andvari-<ver>-2.msi`, or the next version) **and a line in the release notes.**
4. **The deb is cross-checked against `release-spec.json`** when it is on the host, so the release
   page and `/downloads` cannot end up describing two different builds of one version.

`--dry-run` stages, hashes and prints the plan without gpg, `gh` or any network — use it to check
an asset set before publishing.


## Status (2026-09-13)
- **Channel state: signed manifest at seq 12** — linux **0.26.3**, windows **0.26.3**, browserExtension
  0.26.0; `signedAt 2026-09-05T22:56:25Z`, bundle ref `v0.26.3` / commit `39bf5944`. Recorded here from
  the archive on huginn (`~/.andvari/manifest-archive/seq12-20260905T230007Z/`) and re-verified for the
  2026-09-13 audit, because the publish itself left **no line in the watcher log and no PUBLISHED
  telegram** (audit H47): it was run by hand from an interactive tmux session at 16:00:07 local, about
  three minutes after the bundle landed (every bundle file mtime 15:57) and one minute before the
  cron tick would have taken it — against this runbook's own "do NOT run it by hand" rule. Hashes of
  record: `manifest.json` sha256 `bb94611b…0501be` (688 B), `manifest.json.sig` sha256
  `4ec672d9…8d1cd0`, `andvari-0.26.3.msi` sha256 `9d2831bb…680111` (117 235 712 B, matches
  `windows.sha256`), deb `c0a32424…cc9e77`; every file in the archive re-hashes to the bundle.json it
  was signed with. **Fix landed in the watcher's mirror of record** (netplan
  `scripts/active/andvari-manifest-watch.sh`): the script now opens its own log, refuses a real
  publish from a tty unless `--interactive-ok` AND the log is writable, and names the supported hand
  path (`systemd-run --wait --pipe --collect …`, which has a writable /var/log for both logs).
  **Operator step outstanding: redeploy it to `/usr/local/bin/andvari-manifest-watch.sh`** — the
  deployed copy still has the hole until then.
- **(2026-08-31)** entries follow.
- **Load-bearing OS-signing DONE for desktop:** MSI Authenticode + deb GPG, live on the reference
  instance. That closes the H2 §M-D1 "trojaned installer → RCE" path for the `.msi`/`.deb` the
  user runs — the bytes are OS-verifiable, independent of the server. Both have run every release
  since 0.20.0.
- **Secondary manifest-sig: ARMED 2026-07-18**, and every manifest change since has been signed —
  though 0.26.0 shipped without ever reaching the manifest (see the channel-state note) — ceremony pubkey
  pinned in core + extension, reference-instance-scoped (see §1); first signed manifest = seq 1
  (0.19.1). Fielded ≤0.17.0-ext / ≤0.19.0-desktop builds pin the sentinel and stay quiet; builds
  from the arming commit onward verify.
- **Channel-behind-fleet, twice, and the tripwire that now exists.** The 0.25.0 lag this section
  once recorded cleared with its ceremony, and the condition recurred immediately: **0.26.0 was
  published on every channel and never signed** — 0.26.1 superseded it before the ceremony ran, so
  the manifest went seq 8 → 9 with exactly one signing. Both times the only detection was a
  hand-typed paragraph in this file, which is stale the moment the next ceremony runs — and this
  paragraph itself then rotted two releases behind for the third time (audit H110). Two changes
  close it. **(1)** `signandvari.ps1` now ends with a **post-publish read-back** (§9): after the
  drop it polls the public `/downloads/manifest.json`, cache-busted, until the watcher has
  published, then fails hard unless the served manifest carries the seq this run minted, names the
  tag just signed on `linux` and `windows`, and matches the MSI digest this run hashed. It also
  dies immediately if another publish overtook the ceremony (a seq past ours can never be
  published — clients refuse a non-increasing seq) or if nothing appears within 12 minutes.
  `scripts/ci/powershell-gate.sh`, run by `verify.sh`, asserts that step is still there and still
  fatal. **(2)** No file in this repo states the current channel state as prose any more. Ask the
  wire:

  ```
  curl -s 'https://andvari.monahanhosting.com/downloads/manifest.json?cb=1' \
    | jq '{seq, signedAt, linux: .linux.version, windows: .windows.version, ext: .browserExtension.version}'
  ```

  The dated per-release blocks above and in `docs/ROADMAP.md` stay as they are: they are records of
  what was published *then*, verified at the time, and they are allowed to be historical. What is
  not allowed back is a sentence claiming to describe the channel *now*.
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
