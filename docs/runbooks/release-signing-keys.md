# Release-signing keys (H2) — public record

_Ceremony run 2026-07-14 on the owner's Windows workstation (PRESTIGE). All PRIVATE keys stay on that
machine, ACL/file-perm locked, uncommitted and un-uploaded. Only the PUBLIC material below leaves it._
Sibling to the escrow/recovery-ceremony record (`docs/drills/escrow-genesis-ceremony.md` — **recorded elsewhere**: `docs/drills/` was never part of this repository, it is the reference instance's private, out-of-tree operational area, so read that as a pointer and not a broken link; same note as `CHANGELOG.md` and `docs/ROADMAP.md` carry).

## 0. The ceremony is one command (`signandvari`, 2026-08-20)

Everything the signing box does for a release — fetch the release tag, check out the tag, find
`signtool`, build and sign the MSI, mint the manifest at the next `seq`, sign it, and deliver the
bundle — runs as **`scripts/signandvari.ps1`**, installed *outside* the repo (`%USERPROFILE%\bin`
plus a `$PROFILE` function) because step 3 checks out the release tag and would otherwise replace
the script underneath its own execution.

```powershell
signandvari 0.25.0 -Commit <sha> -DryRun     # signs nothing; still stops at the typed confirm, then runs the tree's prestige-release.ps1
signandvari 0.25.0 -Commit <sha>             # verify tag -> review -> checkout -> typed confirm -> ceremony -> ordered drop
signandvari 0.25.0 -Commit <sha> -SkipDrop   # produce the bundle, deliver it by hand
```

**`-DryRun` is not a run in which no tree code runs** (A14 review R2-6). It signs nothing and
drops nothing, but it goes through the same review and typed confirmation, and once you confirm it
runs the release tree's own `prestige-release.ps1` on this account, beside `update-signing.key`
(with `-DryRun`, which that tree's script is trusted to honour). Confirm a dry run only for a tree
you would confirm a real run for.

**One-time, before the first ceremony that uses `-Commit`** (security review 2026-10). The box runs
the INSTALLED copy, so the reviewed script has to be installed before it can protect anything. An
older copy rejects `-Commit` ("A parameter cannot be found that matches parameter name 'Commit'").
**If it does, STOP and install first; never drop `-Commit`**: the old script force-fetches tags and
then runs whatever tree the tag names, and the pin checks inside that tree's own
`prestige-release.ps1` are that tree's code. It is two separate steps, and the second is never
pasted together with the first (A14 review R2-5).

*Step 1 - fetch the reviewed copy beside the installed one and read the diff.* This replaces
nothing:

```powershell
git -C $env:ANDVARI_REPO fetch origin main
git -C $env:ANDVARI_REPO show <reviewed-sha>:scripts/signandvari.ps1 | Set-Content -Encoding Ascii "$HOME\bin\signandvari.new.ps1"
git diff --no-index --ignore-cr-at-eol -- "$HOME\bin\signandvari.ps1" "$HOME\bin\signandvari.new.ps1"
```

*Step 2 - only once you have read that diff and it is the change you reviewed,* install it:

```powershell
Move-Item -Force "$HOME\bin\signandvari.new.ps1" "$HOME\bin\signandvari.ps1"
```

If the diff is not what you reviewed, delete `signandvari.new.ps1` and stop. (`signandvari.ps1`
is pure ASCII, which the PowerShell gate enforces, so `Set-Content -Encoding Ascii` is
byte-faithful apart from line endings.) Repeat both steps whenever a release changes
`scripts/signandvari.ps1`: the tree never updates the installed copy, by design.

**Where `<reviewed-sha>` and `<sha>` come from** (A14 review R2-5). Not from the handoff alone:
the handoff is written by the build host, and a value it supplies would become the installed
verifier or the release pin. Read each one off GitHub's web UI yourself and compare it with the
handoff value; stop if they differ. `<reviewed-sha>` is the merge commit (or pull request head)
you approved there; `<sha>` is the commit GitHub's page for the release tag `v<ver>` names. What
that does: GitHub is a second view of what was pushed, served by a party the build host does not
control, so it catches a handoff value that was mistyped, altered on its way to you, or names a
commit that was never published, and it ties `<reviewed-sha>` to the review you actually did rather
than to whatever the build host says you reviewed. What it does not do: the build host can push to
that repository, so a commit it pushed and tagged there itself appears on GitHub exactly as it
handed it over. Against that, what remains is your own review of the merge, the stat and commit
list `signandvari` prints since the last release you signed (below), and GitHub's record of who
pushed what.

**Do not `git pull` or run a plain `git fetch` in the signing checkout before the first ceremony
on this version of `signandvari`** (A14 review R2-3). Step 1's `git fetch origin main` is the only
fetch it needs (a fetch that names a branch does not pull tags in with it), and `signandvari`
fetches the release tag itself. A pull checks an unreviewed tree out into the very checkout the
ceremony runs in, and a plain fetch brings in every new tag on the remote.

**`-Commit <sha>` is required** (security review 2026-10): the full 40-hex commit the release tag
was cut at, copied from the handover line the build host prints
(`scripts/gh-release.sh` ends with `signandvari <ver> -Commit <sha>`). The signing box runs the
tag's tree — its scripts and its gradle build — with the update-signing key openable by the same
account, and a tag is a mutable ref on a remote the build host can write to. So before anything is
checked out, the tag must resolve to exactly that commit; HEAD must equal it after the checkout and
again right before `prestige-release.ps1` starts (which takes the same `-Commit` and records it as
`bundle.json.commit`). Only the release tag is fetched (`refs/tags/v<ver>`, `--no-tags`), and
**never with `--force`**: a remote release tag that differs from the local one stops the run and
names both commits, instead of silently replacing it, and any *other* tag that moved on the remote
is not fetched, so it cannot block a ceremony. A mismatch is a reason to ask the build host what
happened, never to re-run with the tag's commit.

**What the pin does and does not do.** The handover line reads the build host's own local tag, so
the pin closes a tag moved by anyone other than the build host, a tag moved after the handover line
was printed, and an accidental re-tag. It does **not** close a compromised build host: that host
chooses both the tag and the pin. The layer aimed at that is the workstation's own record:

**The last signed commit.** `signandvari` keeps the commit of its last *successful* ceremony in
`%LOCALAPPDATA%\andvari\signandvari-last-signed.json`, outside the repo. Before any of the tree's
code runs (dry runs included) it:

1. refuses unless the release commit **descends** from that commit
   (`git merge-base --is-ancestor <last> <commit>`) — merge a release branch back before the next
   ceremony;
2. refuses a release tree in which two paths are **one file on a case-insensitive disk** (NTFS
   compares names case-insensitively and ignores a trailing dot or space, so
   `Scripts/prestige-release.ps1` beside `scripts/prestige-release.ps1` would be written one over
   the other);
3. prints a `git diff --stat <last>..<commit>` of the code that runs beside the key, **first**, and
   then `git log` of the commits in that range, every line taken from git escaped (C0, DEL, C1 and the
   bidi controls print as `\u001B`-style text, so a commit subject cannot move the cursor or redraw
   the stat on a VT console; A14 review R2-2). The stat matches these paths in any case:
   `core/` (ALL of it), `tools/update-signer/`, `scripts/`, `gradlew*`, `gradle/`,
   `*gradle.properties`, `settings.gradle.kts`, every `*.gradle.kts` and `*.gradle`, `buildSrc/`,
   `build-logic/`, and `.gradle/`, `.kotlin/`, `local.properties` should a tree ever track them. That
   is what the ceremony builds and runs here: its scripts, the whole gradle build, and the
   update-signer, which is handed the key's path and is a shadowJar of `tools/update-signer` plus
   all of `:core`. **All** of core, not its crypto (A14 review R2-1): Kotlin resolves an
   unqualified call to a declaration in the caller's own package ahead of its default imports, from
   any module on the classpath, so one core file that declares the signer's package and a
   same-named function replaces the signer's own key read, and a stat over core's crypto
   directories printed "(no changes)" over exactly that. Not covered: the third-party artifacts
   gradle downloads (only the catalog that names them), the JDK, and the sources compiled into the
   MSI but never run here (`app-desktop/src`), which the commit list names. The stat is names and
   counts; the line under it gives the `git diff` command to read the change in full;
4. checks the tree out, and refuses unless `git status --porcelain` is then empty (what is on disk
   must be exactly the commit that was reviewed);
5. asks the operator to **type the version** being released. Anything else stops the run and puts
   HEAD back where it was. A run with no human at a console — `-NonInteractive`, piped or redirected
   input, a service — stops before anything is checked out; there is no flag that skips it.

The record moves only after `prestige-release.ps1` exited 0 **and** `bundle.json` records the
pinned commit. A dry run, a refused run or a failed ceremony leaves it where it was. This is a review
aid that rests on the operator reading the diff, not a proof: a compromised build host can still cut
a descendant commit, but it can no longer swap the tree silently or rewrite history under the last
release, and a change to the build is in front of a human before it runs.

**First run** (no record yet, e.g. the first ceremony after this change; A14 review R2-3): the
baseline is the commit in **this box's own most recent signed bundle**:
`dist\release-bundle-<version>\bundle.json` in the checkout, beside its `manifest.json.sig`.
`prestige-release.ps1` writes both only after a signature it verified (the `.sig` last), `dist\` is
gitignored so no checkout replaces it, and the highest `seq` wins; a `bundle.json` that git tracks
is the tree's content, not this box's, and is skipped. The output says FIRST RUN, names the bundle,
and prints the baseline commit's date and subject — check that it is the release you last signed.
**A tag is never the seed**: a plain `git fetch` or `git pull` brings in new tags, so a planted
intermediate tag would become the baseline and hide every change up to it. With no signed bundle
(a new checkout, a cleaned `dist\`) the run stops and asks for `-Baseline <40-hex>`: a commit you
reviewed yourself, such as the last release you signed — never one read off the build host. It may
also be passed on any first run to choose the comparison, it must be a **strict** ancestor of
`-Commit` (`-Baseline` equal to `-Commit` would compare the release with itself and show nothing;
A14 review R2-4), and it is refused once a record exists. **Reset:** deleting the record on purpose
(history rewritten, a new checkout) makes the next run a first run again.

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

## 0.1 Before the ceremony — the pre-cut checks `verify.sh` cannot make

`scripts/verify.sh` is the gate for everything that runs on the build host. Two things do not,
and they are the two that have historically shipped broken. Both are **blocking**: do not tag,
do not sign, do not upload until they have passed for the exact commit being released.

1. **Android crypto, graded on a real device (audit H94) — blocks the APK.** Every byte-locked
   vector suite (`VectorsTest`, `MemberRecoveryVectorTest`, `UsageKeyVectorTest`,
   `LifecycleProofVectorTest`) lives in `jvmTest` and links **lazysodium-java**. The phone links
   **lazysodium-android**, a different artifact with a different bundled libsodium and a different
   loader, and no test in the tree executes it. Byte-identity is expected by construction — same
   algorithms, same parameters — so what this catches is not a maths error but the class of defect
   that actually happens: an ABI/loader mismatch, a stale or missing `.so`, a `jna` packaging
   change, a `lazysodium-android` bump. That class is not theoretical here; it is exactly how the
   0.26.3 desktop libsodium loader defect surfaced, and the only detector was a user who could not
   sign in.

   Run the instrumented vector suite on a physical device or an emulator image
   (`./gradlew :app-android:connectedDebugAndroidTest`) and require it green **with a non-zero
   test count** — an empty `androidTest` source set makes that task succeed having run nothing,
   so read the count, not the exit code. It drives the same `spec/test-vectors` through
   `createCryptoProvider()` on-device — at minimum the `kdf.json` chain, `wrap.json`, `seal.json`
   and `usagekey.json`. **A JVM-suite pass is not a substitute**: it grades a different native
   binary. This lives in the release checklist rather than the PR gate because CI has no emulator
   (see docs/ROADMAP.md "CI posture").

   The suite is
   `app-android/src/androidTest/kotlin/io/silencelen/andvari/app/crypto/AndroidCryptoVectorsTest.kt`
   (added for this audit); it reads the shared `spec/test-vectors` files rather than carrying
   copies, so it cannot drift from the JVM and web suites. It needs a connected device or a running
   emulator — nothing on the build host can stand in for it.

   > **If no device is available for a cut**, the honest options are to ship no APK and say so
   > (`scripts/gh-release.sh --no-android`, which also stops devstore warning about it) or to record
   > in the release notes that the phone's crypto was graded only by proxy this time. "Assume it is
   > fine" is not one of them — it is what shipped the 0.26.3 desktop loader defect.

2. **The manual on-device smoke** the P5 design records: sign in, airplane mode, force-stop,
   relaunch → the cached vault unlocks offline; create an item offline → relaunch → network on →
   it syncs. Desktop equivalent under `~/.andvari-desktop`.

## 0.2 Provenance — what ties a shipped installer to a commit (audit H103)

**The artifact hashes are not reproducible.** Rebuilding `v0.26.3` on another box, or on this box
next week, does not reproduce the MSI's or the deb's sha256: the jar embeds timestamps and entry
order, jlink/jpackage bake in the JDK and host layout, and the MSI wraps all of it with its own
timestamps. Nothing about that is wrong, but it has a consequence people keep re-deriving the hard
way — **a hash mismatch between two builds of the same tag proves nothing**, and on 2026-09-01 a
day went into reading exactly that as "different code". Do not treat a rebuild as a verification
step, and do not ask anyone else to.

So the provenance chain is deliberately made of things that *are* checkable:

1. **`bundle.json`** — written by the ceremony next to the artifacts, recording `version`, `seq`,
   `ref`, the `commit` that was checked out, and every file's sha256 and size. This is the only
   statement of what was built from where.
2. **The signed manifest** — `manifest.json` + `manifest.json.sig` over the exact published bytes,
   verified against the pinned key by every armed client (§1).
3. **The tag check, enforced.** The build-host watcher (netplan
   `scripts/active/andvari-manifest-watch.sh`, CHECK 2b) refuses to publish unless
   `bundle.json.commit` equals the commit of `v<version>` in huginn's own checkout, and unless
   `bundle.json.version` is the version the dropped manifest names. A mismatch **quarantines** the
   bundle with `off-tag-build` and telegrams; nothing reaches `/downloads`. **There is no off-tag
   flag, by design** — a build from a branch is precisely the artifact nobody can audit later. If
   you need to ship a fix, tag the commit you built and re-drop. A tag huginn's clone has not
   fetched yet is a *transient* stop, not a rejection: `git fetch --tags origin` and the next tick
   proceeds.

Which is why `-Ref v<version>` in the ceremony (§Signing-box preflight item 2) is not a
convenience: it is now the difference between a publish and a quarantine. `-Commit <sha>` is the
other half: the watcher checks the bundle against the tag, and the pin checks the tag against the
commit the build host says it cut, before the signing box runs a line of the tree.

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

## 3. Linux package signing — GPG (detached `.asc`): the `.deb` AND the Arch `.pkg.tar.zst`
- **Both Linux packages, one key, one treatment (2026-10-13).** `scripts/build-linux.sh` builds the
  `.deb` and the Arch pacman package `andvari-<ver>-x86_64.pkg.tar.zst` from ONE gradle build
  (it proves the two carry the same application jar), then detach-signs both with the key below.
  The signed manifest carries the Arch package as the additive `linuxArch` entry
  (`{version,url,sha256}`), emitted by `release-spec.sh` beside `linux` and listed in its
  `intendedKeys`; `prestige-release.ps1` proves the SERVED package hashes to the spec exactly as it
  does for the deb. Users verify both the same way:
  `gpg --verify andvari-<ver>-x86_64.pkg.tar.zst.asc andvari-<ver>-x86_64.pkg.tar.zst`
- **ARMORED `.asc`, never a binary `.sig`, for the Arch package** — this is load-bearing, not
  style. `pacman -U` auto-verifies a `<pkg>.sig` sidecar sitting beside the file against **pacman's
  own keyring**, and the household release key is deliberately not in it, so a `.sig` would make
  every install fail with "invalid or corrupted package (PGP signature)". The `.asc` is for a human
  running `gpg --verify`, exactly like the deb's; installing stays `sudo pacman -U <file>` by hand,
  as `dpkg -i` is for the deb (no Linux client runs an installer).
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


## 5. `/downloads` retention — what stays reachable (audit H107)

`/downloads` is a **public directory with guessable filenames**, and until 2026-09-13 nothing ever
removed anything from it: every publish step only added. It had reached 4.6 GB on a 16 GB rootfs,
holding every deb since 0.6.0 (including unsigned pre-0.19.1 ones), the known-broken 0.26.2 MSI,
two still-valid signed manifest pairs from seq 3-4, and `manifest.json.*` backups made in place.
Nothing forced a cleanup because the signed-update clients are immune to the clutter — fixed paths
plus anti-rollback floors — which is exactly why it needed a written rule instead of a habit.

**The rule.** Everything the LIVE `manifest.json` and `firefox-updates.json` reference is
untouchable, and beyond that the **current and previous release's installers stay reachable**;
older ones are pruned. Fleet artifacts (`andvari-<ver>.deb/.msi/.apk` and their `.asc`) and
extension artifacts (`andvari-extension-*-<ver>.zip/.xpi`) are counted on **separate tracks** — the
extension version legitimately sits several fleet releases back, and one shared count would prune
the live extension. A release is kept or dropped **whole**, so the directory can never offer a deb
without its signature. Anything not matching a known artifact name is reported and left alone.

**Manifest backups leave the web root.** `manifest.json.<anything>` / `manifest.json.sig.<anything>`
are *moved* to `/opt/andvari/manifest-backups` (not served), never deleted — the durable archive is
`~/.andvari/manifest-archive` on huginn, and an older but still validly-signed manifest pair sitting
publicly beside the live one is not something this directory should offer.

**How it reaches the instance: `ANDVARI_DOWNLOADS_EXEC`, and there is no default** (R29). The
prefix names one household's host, and this repo is public, so `--downloads` refuses to run until
you export it — the same shape as `signandvari.ps1`'s `$env:ANDVARI_RELEASE_DROP`. This runbook is
the place that may name the real one, because it is the exempt operator document that already
names the machines the ceremony runs on:

```
export ANDVARI_DOWNLOADS_EXEC='ssh -o BatchMode=yes -o ConnectTimeout=15 root@192.168.7.131 pct exec 122 --'
```

(The generic shapes, for any other instance: `ssh you@host docker exec -i andvari`, or
`ssh you@host pct exec <ctid> --`.)

```
scripts/prune-artifacts.sh --downloads                 # dry run: prints the plan, touches nothing
scripts/prune-artifacts.sh --downloads --apply         # move the backups, delete the old installers
scripts/prune-artifacts.sh --downloads --keep-releases 3 --apply
```

It reads the live manifest from the container and **aborts rather than guessing** if it cannot: a
directory whose live references are unknown does not get pruned. `scripts/ci/prune-downloads.test.sh`
(run by `verify.sh`) exercises the whole rule against a fake `/downloads`, including the case that
would hurt most — an old `.xpi` that `firefox-updates.json` still points at must survive.

## Status (2026-09-13)
- **Publish record — seq 12 (0.26.3), signed 2026-09-05** (history, not a current claim — see (2) below): linux **0.26.3**, windows **0.26.3**, browserExtension
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
   the deb, APK and extension already in users' hands. `-Ref v<version>` names it and
   `-Commit <sha>` pins it (signandvari passes both).
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
