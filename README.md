# andvari

In-house zero-knowledge password manager for the homelab fleet. Named for the dwarf
who guards the treasure hoard.

Three clients — Android (Jetpack Compose, shipped via devstore), Windows (Compose for
Desktop), and a browser web app — plus an MV3 browser extension (Chromium + Firefox)
sync through a central ktor server (CT 122 on heimdall, Tailscale-only with a
break-glass public tunnel). The server only ever
stores ciphertext: encryption keys derive from each user's master password on-device,
and recovery goes through an offline escrow key, never the server.

## Layout

| Path | What |
|---|---|
| `spec/` | **Normative** protocol + crypto spec (00–07) and `test-vectors/` — code follows spec, never the reverse |
| `core/` | Kotlin Multiplatform (android + jvm): crypto, models, sync engine, client cache |
| `server/` | ktor JVM sync server (depends on `:core`) |
| `app-android/` | Android client |
| `app-desktop/` | Compose for Desktop Windows client |
| `web/` | Independent TypeScript implementation of the spec (Vite + React) |
| `extension/` | MV3 browser extension, Chromium + Firefox — in-browser fill/save (pure-JS @noble crypto) |
| `tools/vector-gen` | Emits `spec/test-vectors/*.json` from the Kotlin reference implementation |
| `tools/recovery-cli` / `tools/backup-cli` | Offline escrow ceremony/recovery + offline `.andvari` backup reader (verify/dump/extract) |
| `ops/` | LXC bring-up runbook, systemd units, deploy + backup scripts |
| `scripts/` | `verify.sh` (the every-ship gate — see Build), `build.sh`, `ship.sh` (devstore) |

## Build (huginn)

JDK 17, Android SDK at `/opt/android-sdk`, Node ≥ 22. Gradle heaps are tuned for the
8–12 GB LXC in `gradle.properties`; serialize concurrent Gradle invocations with
`flock /tmp/andvari-gradle.lock`.

```sh
bash scripts/verify.sh   # the ship gate: 4-way client version-lockstep check, then
                         # :core/:server/recovery-cli tests, :app-android compile gate,
                         # web vitest + tsc, extension typecheck + tests — Kotlin and
                         # TS crypto both off spec/test-vectors
```

The two crypto implementations (Kotlin `core/`, TypeScript `web/src/crypto`) must pass
the **same** vector files; `verify.sh` is the gate for every ship.
