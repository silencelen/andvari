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

## Clients

| Client | Stack | Distribution |
|---|---|---|
| **Web** | TypeScript + React (Vite) — an independent implementation of the spec | served by every server at its own origin |
| **Android** | Kotlin / Jetpack Compose, on `:core` | an APK you build and serve from your instance's `/downloads` (`ANDVARI_DOWNLOADS_DIR`) |
| **Desktop** | Compose for Desktop, on `:core` — `.msi` (Windows), `.deb` (Linux) | as above |
| **Browser extension** | MV3, Chromium + Firefox, pure-JS `@noble` crypto (no WASM, no `eval`) | Chrome Web Store (unlisted) + a Mozilla-signed `.xpi` with a self-hosted update channel |

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
| `scripts/` | `verify.sh` (the every-ship gate — see Build), `build.sh`, `e2e.sh`, `publish-image.sh`, `publish-extension.sh` |

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
