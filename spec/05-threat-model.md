# andvari spec 05 — threat model

## Assets
A1 vault plaintext (credentials, TOTP seeds, notes, attachments). A2 master
passwords. A3 UVKs/VKs/identity keys. A4 the org recovery seed. A5 account
availability (lockout = losing access to everything). A6 metadata (who has how many
items, sizes, timing). A7 the at-rest quick-unlock secret (Android: the
Keystore-wrapped UVK blob + its non-exportable hardware key, spec 01 §8.1) — the
only durable on-device artifact that, combined with a live authenticator, opens a
vault without the master password.

## Adversaries & guarantees

| # | Adversary | Outcome (by design) |
|---|---|---|
| T1 | **Server compromise (CT 122 root)** — reads DB, blobs, memory, logs | Sees only spec 02 §5 plaintext + traffic patterns. No item content, no keys, no master passwords (authKey is one-way; verifier re-hashed). CAN: serve stale data, drop writes, swap ciphertexts *between* slots — blocked by AD binding; roll back the DB — mitigated by client caches noticing rev regression (clients warn, never delete local newer state). CAN corrupt/deny service → availability handled by offline caches + PBS. |
| T2 | **Passive network (tailnet/LAN/CF)** | TLS everywhere (tailscale serve / cloudflared terminate; LAN fallback is plain HTTP to .2.122 and is OFF by default in clients — enabling it is an explicit per-device choice, VLAN-2-internal only). |
| T3 | **Stolen/lost device, locked** | At-rest cache is ciphertext (the native offline cache persists only §5-table ciphertext + metadata in SQLite, spec 02 §8; keys only in memory or hardware-wrapped quick-unlock per spec 01 §8). Offline unlock accepts the master password current at last online contact; **remote device revocation / password change take effect only at next connectivity** (then the client wipes the cache + cached accountKeys). Local data remains ciphertext without the master password; a stolen locked device with a known-old master password can read the last-synced cached vault until it reconnects — an accepted narrowing in exchange for offline availability. |
| T4 | **Stolen device, UNLOCKED with vault open** | Out of scope: an open vault is an open vault. The window is bounded by the inactivity auto-lock (`autoLockSeconds`, enforced by all three clients incl. the Android autofill path — spec 01 §8 "Auto-lock") + policy clipboard clearing (min 1 s clamp). |
| T5 | **Malware on a client device** | Out of scope (keylogger gets the master password). This is the boundary every password manager shares. |
| T6 | **Malicious/compromised web origin** (server serving hostile JS) | Accepted gap of the web client: page-load-time trust. Mitigations: CSP `default-src 'self'`, SRI, immutable versioned bundles, no third-party origins, no CDN; native apps are the trust anchor; break-glass public mode additionally forces CF Access + server-TOTP. High-value operations (escrow ceremony) never run in the web client. |
| T7 | **B2 / PBS / backup theft** | Backups contain only what T1 sees (ciphertext + metadata). Neutralized by design. |
| T8 | **DB leak → offline cracking** | authKey verifier is argon2id-hashed server-side; vault security rests on Argon2id(master password) at ≥64 MiB — weak master passwords remain the user's risk (policy enforces minimum strength at enrollment). |
| T9 | **Recovery-sheet thief** | Holds A4 ⇒ can decrypt every escrowed UVK **given the sealed blobs** (needs server data too). Physical security of the two sheets + USB is the control; annual drill verifies presence. Compromise response: re-ceremony + full re-escrow + item re-key (manual runbook). |
| T10 | **Malicious server during enrollment** (pubkey substitution) | Blocked by triple pinning + human fingerprint check (spec 04 §2). |
| T11 | **User enumeration / credential stuffing** | Deterministic fake prelogin salts, uniform 401s, per-IP+per-account rate limits, public-origin lockdown (TOTP + tighter limits + registration disabled). |

## Accepted risks (signed off by owner at hardening gate)
R1 JVM/JS cannot guarantee secret zeroization (GC copies) — industry-standard gap.
R2 Web client page-load trust (T6). R3 Escrow key holder can decrypt all (deliberate
— the recovery feature). R4 Server metadata visibility (A6) — includes a residual
prelogin oracle: after a KDF-policy change, an account whose stored params differ
from the current default answers prelogin with diverged params (existence confirmed)
until it re-keys via password change; unknown emails always answer the current
org-default params. R5 Single server on
heimdall — availability via offline-first + PBS/shadow-2122, not HA. R6 TOTP seeds
co-located with passwords (accepted eggs-in-one-basket, user decision). R7 removed
shared-vault member retains decryption capability for ciphertext they held while granted
(and future leaks of *unchanged* items) until P6 VK rotation + lazy re-encryption —
removal in v1 is server-side revocation only; future-secrecy loss only, the server itself
still holds only ciphertext. **R7 extended (vault lifecycle, spec 03 §11):** vault deletion
removes the server's copies after a 7-day grace and triggers fleet-wide client purge, but is
NOT cryptographic erasure toward ex-members — anyone granted while the vault lived may retain
ciphertext + the VK they already held, and encrypted server backups (PBS/B2) keep copies
until their own retention expires (~30 d); the ex-owner after a transfer retains VK likewise.
True erasure needs P6 VK rotation. **Lifecycle threat posture (T1):** lifecycle ops on
existing vaults are member-verifiable — the server never holds VK and cannot mint proofs; it
can still WITHHOLD, delay, or serve stale state (availability-class, accepted). Replay is
bounded by expiry+seq binding and by soft-hide-until-purgeAt; residuals: a device offline
since before the newest verified seq may be shown stale-but-genuine older state; proofs are
keyholder-forgeable (server authz is the gate). Grant injection for NEW vaults (F16) remains
an accepted residual until P6 owner-signed grants — the "you were added to <vault>" notice is
transparency for honest servers only and is NOT an F16 defense. Shared-vault membership
topology (which userId holds which role on which vaultId) is server-visible metadata,
subsumed by A6/R4.

## Quick-unlock at-rest secret (A7, Android — spec 01 §8.1)

Enabling quick unlock changes the at-rest story of exactly one asset: a
Keystore-wrapped copy of the UVK now persists on the device. What each attacker
gets:

| Attacker | Outcome |
|---|---|
| **Device in hand, UNLOCKED, vault app locked** | Can *see* the biometric-unlock offer but cannot pass `BiometricPrompt` (BIOMETRIC_STRONG / Class 3 — spoof-resistance per the Android CDD; screen PIN/pattern deliberately NOT accepted, spec 01 §8.1). The honest **narrowing vs T3**: where a stolen device previously required the master password, it now falls to the owner's biometric — a sleeping/coerced owner or a Class-3 sensor bypass is the new (accepted, opt-in) exposure. Coercion is out of scope, same as for the master password. An OPEN vault remains T4. |
| **Device powered off / locked (thief, border search of hardware)** | The blob is AES-256-GCM ciphertext under a non-exportable TEE/StrongBox key with `setUnlockedDeviceRequired(true)` — unusable before first device unlock. No offline brute-force surface exists: the wrapping key never leaves hardware, and the blob without it is just 32 random-looking bytes plus tag. Chip-level key extraction is nation-state class (Non-goals). |
| **Malicious app on the device (non-root)** | App-sandbox private file (`noBackupFilesDir`); Keystore keys are per-UID — another app can neither read the blob nor request the cipher. Fake-overlay biometric phishing yields nothing: the prompt is bound to OUR key's `CryptoObject`. Root/accessibility malware is T5, out of scope — and quick unlock does not *worsen* T5 (unlocked-process memory already holds the UVK; a keylogger already gets the master password). |
| **ADB / backup extraction** | `android:allowBackup="false"` + the blob and cache both under `noBackupFilesDir` ⇒ neither `adb backup` nor cloud backup carries the blob; a leaked blob alone is useless without the hardware key (above). ADB shell as the app's uid implies a compromised/debug device — T5. |
| **The server** | Learns nothing — quick unlock is wire-invisible (spec 01 §8); the server story is unchanged (T1 unaffected). |

Residual accepted: the `lastFullPasswordUnlockAt` freshness stamp is advisory
plaintext — resettable only by an attacker already inside the app sandbox (T5),
who still cannot use the Keystore key. The A5 risk of *forgetting* the master
password behind a working biometric is bounded by the normative 30-day periodic
full-password rule (spec 01 §8.1).

## Autofill (client-side, Android)

The autofill service honors a fill request's web domain only from a browser it verifies by
**signing certificate** (package name alone is spoofable — an app can install under an
absent browser's package id). A package that is not pinned, not installed, or whose cert
does not match its pin **fails closed**: no web-domain trust → only `androidapp://<pkg>`
URIs match it, never web items. Residual: a browser whose release cert we have not pinned
won't offer autofill until its digest is added (safe, functionality-only); and the match
rule is label-boundary suffix, not eTLD+1/PSL (strictly safer, misses sibling subdomains).
Digital Asset Links verification + PSL are the P6 loosening. The service never reads field
values and never logs field content, item names, or URIs.

## Non-goals
Nation-state adversaries; side-channel resistance beyond libsodium's own; protection
of an unlocked session from its own OS; multi-org tenancy; plausible deniability.
