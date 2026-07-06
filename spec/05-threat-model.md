# andvari spec 05 — threat model

## Assets
A1 vault plaintext (credentials, TOTP seeds, notes, attachments). A2 master
passwords. A3 UVKs/VKs/identity keys. A4 the org recovery seed. A5 account
availability (lockout = losing access to everything). A6 metadata (who has how many
items, sizes, timing).

## Adversaries & guarantees

| # | Adversary | Outcome (by design) |
|---|---|---|
| T1 | **Server compromise (CT 122 root)** — reads DB, blobs, memory, logs | Sees only spec 02 §5 plaintext + traffic patterns. No item content, no keys, no master passwords (authKey is one-way; verifier re-hashed). CAN: serve stale data, drop writes, swap ciphertexts *between* slots — blocked by AD binding; roll back the DB — mitigated by client caches noticing rev regression (clients warn, never delete local newer state). CAN corrupt/deny service → availability handled by offline caches + PBS. |
| T2 | **Passive network (tailnet/LAN/CF)** | TLS everywhere (tailscale serve / cloudflared terminate; LAN fallback is plain HTTP to .2.122 and is OFF by default in clients — enabling it is an explicit per-device choice, VLAN-2-internal only). |
| T3 | **Stolen/lost device, locked** | At-rest cache is ciphertext (SQLDelight stores envelopes; keys only in memory or hardware-wrapped quick-unlock per spec 01 §8). Remote device revocation kills sync; local data remains ciphertext without biometric/PIN+DPAPI/master password. |
| T4 | **Stolen device, UNLOCKED with vault open** | Out of scope: an open vault is an open vault. Auto-lock policy + clipboard clearing bound the window. |
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
— the recovery feature). R4 Server metadata visibility (A6). R5 Single server on
heimdall — availability via offline-first + PBS/shadow-2122, not HA. R6 TOTP seeds
co-located with passwords (accepted eggs-in-one-basket, user decision).

## Non-goals
Nation-state adversaries; side-channel resistance beyond libsodium's own; protection
of an unlocked session from its own OS; multi-org tenancy; plausible deniability.
