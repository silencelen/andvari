# andvari

A zero-knowledge household password manager you can host yourself. Named for the dwarf
who guards the treasure hoard.

The server only ever stores ciphertext: every encryption key derives from a user's master
password **on the device**, and account recovery goes through an offline escrow key the
server never holds. A hostile or compromised server can deny you service; it cannot read
your vault. Clients apply the instance's declared policy under one hard rule — **a server
can make a client safer, never laxer** (`spec/03` §1.1) — so a server also cannot disable
a device's auto-lock or talk it into weaker crypto.

Every client works with **any** andvari server: point it at yours under *Settings →
Server*, or open an invite link from it. `https://andvari.monahanhosting.com` is the
reference instance the shipped builds default to; it is not privileged in the protocol.

## What it does

- **Logins, notes and payment cards**, with attachments — every field sealed on the device,
  the server holding bytes it cannot read.
- **Shared household vaults.** A vault is granted to a member under their own identity key, so
  sharing never means handing anyone a password; membership changes re-key without a re-import.
- **Autofill where you actually type**: the browser extension fills and saves logins and
  checkout card forms on Chromium and Firefox, and the Android client is a system autofill
  service. Both offer to save what you submit, and both know when they already have it.
- **Built-in TOTP** — second-factor codes live beside the login they belong to, and can be added
  from the extension.
- **Vault health** — weak and reused passwords, a breach check against Have I Been Pwned's
  k-anonymity range API, duplicate groups with a guided merge, and a **Staleness** view that
  ranks logins by how long it has been since anyone confirmed one still works. Checking is
  guided but never automated: andvari opens the site and you say what happened. **A client that
  quietly probed sites with your credentials would be doing something you never asked for.**
- **Last used, across every device.** Copying a password on the phone, filling one in the
  browser, opening a site from a check — all of it feeds one sealed per-account record, so a
  login you rely on stops looking neglected just because you last edited it a year ago. One blob
  rather than a row per login, written occasionally rather than per use: the server learns
  neither which login you used nor when you were awake.
- **Quick unlock** — an optional PIN, biometric or platform passkey instead of a full Argon2id
  sign-in at every idle relock, with the vault key double-wrapped so the stored blob alone is
  not offline-crackable.
- **Offline-first** — native clients cache to SQLite, the web vault to IndexedDB, both under the
  same key-derivation floor enforced at cache read.
- **Import and export** — browser and password-manager CSV import (spec 06), CSV export and an
  encrypted `.andvari` backup container readable by an offline CLI (spec 07).
- **Recovery without a server that can help you** — an offline escrow key and a printed
  recovery sheet are the answer to "forgot my master password". The server holds sealed blobs it
  cannot open.
- **Deleted items and password history** — a 30-day trash on every client, and a merge that
  loses a duplicate keeps its password in the survivor's history rather than destroying it.
- **A signed update channel** — clients verify a detached-signed `/downloads/manifest.json`
  against a pinned key with an anti-rollback floor, and fail closed and quiet.

## Clients

| Client | Stack | Distribution |
|---|---|---|
| **Web** | TypeScript + React (Vite) — an independent implementation of the spec | served by every server at its own origin |
| **Android** | Kotlin / Jetpack Compose, on `:core` | an APK you build, serve from your instance's `/downloads` (`ANDVARI_DOWNLOADS_DIR`) **and list in `/downloads/manifest.json`** |
| **Desktop** | Compose for Desktop, on `:core` — `.msi` (Windows), `.deb` (Linux) | as above |
| **Browser extension** | MV3, Chromium + Firefox, pure-JS `@noble` crypto (no WASM, no `eval`) | Chrome Web Store (unlisted) + a Mozilla-signed `.xpi` with a self-hosted update channel |

Dropping a build into the downloads directory publishes nothing on its own: the file is
served, but the clients' "get andvari on your other devices" hub reads
`/downloads/manifest.json` and shows a platform as unpublished until that file names it.
Each platform key — `android`, `windows`, `linux` — wants a `version` **and** a `url`;
with either missing the row stays "isn't published yet". A same-origin path is fine (it
inherits the page's scheme; only an http(s) result is ever rendered as a link). This is
the phone-shaped half of audit F09: the `android` key did not exist at all before 0.21.0,
so an APK served exactly as this table documented could never appear in any client.

```jsonc
{ "android": { "version": "0.25.0", "url": "/downloads/andvari-0.25.0.apk" },
  "linux":   { "version": "0.25.0", "url": "/downloads/andvari_0.25.0_amd64.deb" } }
```

Two independent crypto implementations — Kotlin (`core/`) and TypeScript (`web/src/crypto`
plus the extension's `extension/src/crypto.ts`) — are held in byte-lockstep by the shared
vector files in `spec/test-vectors/`. Neither is the other's oracle; both are checked
against the vectors.

## Self-hosting

The distribution channel is the public container image **`ghcr.io/silencelen/andvari`**.
The full walkthrough — TLS options, the escrow ceremony, the policy variables, backup and
updates — is **[`docs/self-hosting.md`](docs/self-hosting.md)**, which every running
instance also serves at `<your-origin>/selfhost` alongside downloadable copies of
`deploy/docker-compose.yml`, `deploy/andvari.env.template`, and `deploy/bringup.sh`.

## Layout

| Path | What |
|---|---|
| `spec/` | **Normative** protocol + crypto spec (00–07) and `test-vectors/` — code follows spec, never the reverse |
| `core/` | Kotlin Multiplatform (android + jvm): crypto, models, sync engine, client cache |
| `server/` | ktor JVM sync server (depends on `:core`) |
| `app-android/` | Android client |
| `app-desktop/` | Compose for Desktop client (Windows `.msi`, Linux `.deb`) |
| `web/` | Independent TypeScript implementation of the spec (Vite + React) |
| `extension/` | MV3 browser extension, Chromium + Firefox — in-browser fill/save (pure-JS @noble crypto) |
| `deploy/` | The self-host bundle: `docker-compose.yml`, the caddy overlay, `andvari.env.template`, `bringup.sh` |
| `tools/vector-gen` | Emits most of `spec/test-vectors/*.json` from the Kotlin reference implementation (six are hand-authored — see below) |
| `tools/recovery-cli` / `tools/backup-cli` | Offline escrow ceremony/recovery + offline `.andvari` backup reader (verify/dump/extract) |
| `tools/update-signer` | Signs the `/downloads` update manifest the extension's update channel verifies |
| `scripts/` | `verify.sh` (the every-ship gate — see Build), `build.sh`, `e2e.sh`, `publish-image.sh`, `publish-extension.sh`, and the Windows release ceremony (`build-windows.ps1`, `prestige-release.ps1`, `signandvari.ps1`) |

Six vector files — `card`, `cardfill`, `cardform`, `enrolllink`, `import-foreign`,
`urimatch-etld1` — are hand-authored fixtures rather than `vector-gen` output. Both
engines still consume them, so the lockstep holds either way.

## Build

JDK 17, Node ≥ 22, and — for `:app-android` — an Android SDK, located via `ANDROID_HOME`
or an `sdk.dir` line in `local.properties`. `gradle.properties` is tuned for a small
(8–12 GB) build host; raise the heaps if yours is bigger. Serialize concurrent Gradle
invocations with `flock /tmp/andvari-gradle.lock`.

```sh
bash scripts/verify.sh   # the ship gate: release-version consistency across the clients,
                         # then the Kotlin suites (:core, :server, :app-desktop,
                         # recovery-cli), :app-android unit tests + compile gate, web
                         # vitest + tsc, and the extension typecheck + tests — Kotlin and
                         # TS crypto both graded off spec/test-vectors
```

`scripts/e2e.sh` adds a live end-to-end run (real server, real WebSocket, crash
idempotency across a `SIGKILL`). **[`CONTRIBUTING.md`](CONTRIBUTING.md)** walks the
clone → verify path and says what each suite proves.

## Accessibility

Screen-reader support differs by client — see **[`docs/accessibility.md`](docs/accessibility.md)**
for the dated, CMP-version-pinned support matrix. Short version: **the web vault is the
accessible path**; the Linux desktop app does not currently expose an accessibility tree, and
Windows requires the Java Access Bridge (`jabswitch /enable`). (The desktop app does have full
keyboard access, including `Ctrl+L` to lock and a native menu bar.)

## More

- **[`CHANGELOG.md`](CHANGELOG.md)** — what shipped, per release
- **[`SECURITY.md`](SECURITY.md)** — how to report a vulnerability (privately, please)
- **[`LICENSING.md`](LICENSING.md)** — AGPLv3 server, GPLv3 clients/core/tools; the split
  is deliberate
- **[`spec/00-overview.md`](spec/00-overview.md)** — the protocol and key hierarchy
- **[`spec/05-threat-model.md`](spec/05-threat-model.md)** — what andvari does and does
  not defend against
