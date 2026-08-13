# andvari spec 05 — threat model

## Assets
A1 vault plaintext (credentials, TOTP seeds, notes, attachments). A2 master
passwords. A3 UVKs/VKs/identity keys. A4 the org recovery seed. A5 account
availability (lockout = losing access to everything). A6 metadata (who has how many
items, sizes, timing). A7 the at-rest quick-unlock secret — the on-device artifact
that, combined with a live unlocking factor, opens a vault without the master
password. Two variants with **different at-rest posture**: **A7-android** (the
Keystore-wrapped UVK blob + its non-exportable hardware key, spec 01 §8.1) is
*durable* but *hardware-gated*; **A7-extension** (the PIN-wrapped, session-scoped UVK
blob double-wrapped under a non-extractable WebCrypto co-key, spec 01 §8.4) is
*non-durable* (browser-session-scoped, dies at browser exit) but *hardware-less*.

## Adversaries & guarantees

| # | Adversary | Outcome (by design) |
|---|---|---|
| T1 | **Server compromise (root on the instance host)** — reads DB, blobs, memory, logs | Sees only spec 02 §5 plaintext + traffic patterns. No item content, no keys, no master passwords (authKey is one-way; verifier re-hashed). CAN: serve stale data, drop writes, swap ciphertexts *between* slots — blocked by AD binding; roll back the DB — mitigated by client caches noticing rev regression (clients warn, never delete local newer state). CAN corrupt/deny service → availability handled by offline caches + the operator's backups. |
| T2 | **Passive network (anything between a client and its instance)** | TLS everywhere: the operator's front terminates it (reverse proxy, tunnel, or the bundled caddy overlay — `docs/self-hosting.md`), and the server emits HSTS where the operator has said TLS is the only way in (an armed break-glass twin origin, or `ANDVARI_FORCE_HSTS=1` on a single-origin TLS instance) — deliberately NOT by default, since an HSTS pin on a plain-http dev origin bricks it. A **plain-http LAN/dev origin is a supported but explicit choice** — never a default, never silently adopted. Every client that lets a user *type* a server address carries a plain-http caution on that screen (Android, desktop, and the extension's trust gate), and an operator who picks it accepts an on-path attacker within that LAN. |
| T3 | **Stolen/lost device, locked** | At-rest cache is ciphertext (the native offline cache persists only §5-table ciphertext + metadata in SQLite, and the **web client persists the same set in per-account IndexedDB inside the browser profile** — spec 02 §8/§8.1; keys only in memory or hardware-wrapped quick-unlock per spec 01 §8). Offline unlock accepts the master password current at last online contact; **remote device revocation / password change take effect only at next connectivity** (then the client wipes the cache + cached accountKeys). Local data remains ciphertext without the master password; a stolen locked device with a known-old master password can read the last-synced cached vault until it reconnects — an accepted narrowing in exchange for offline availability. Web deltas (spec 02 §8.1): the browser profile cannot be excluded from OS backup, so OS backups may carry the ciphertext DB (⊆ T7); the Unlock screen discloses an existing copy ("Offline copy on this device — last synced <t>") so a borrowed-machine user can see and remove it. **Durable-cache consent record (2026-07-15 pivot, B1-4 — the origin gate is replaced by declared policy + per-device consent):** **web** persists at rest only after an explicit per-device opt-in, default OFF on *every* origin (the walk-up browser is the T3 case; a one-time boot migration keeps existing private-origin users' caches). **Desktop** likewise moves to per-device consent default OFF — desktops are routinely shared/portable/work machines, closer to web's borrowed-machine case than to a phone; an existing install that already holds a cache adopts consent=ON during the namespacing one-shot so nobody's offline access silently vanishes. **Android stays policy-driven default-ON — the exemption justified on the record:** installing an APK on one's own phone *is* the device-consent act, and the cache is at-rest encrypted, gated by the hardware quick-unlock co-key (A7-android), bounded by the 7-day staleness ceiling, protected by the KDF cache-read floor (T8), and purged on policy-`false`. In every case `offlineCacheAllowed=false` remains a forbid + wipe of that origin's own namespace (R11). |
| T4 | **Stolen device, UNLOCKED with vault open** | Out of scope: an open vault is an open vault. The window is bounded by the inactivity auto-lock (`autoLockSeconds`, enforced by all three clients incl. the Android autofill path — spec 01 §8 "Auto-lock") + policy clipboard clearing. **Both timers are clamped on the client since the 2026-07-15 pivot (B1-1):** effective auto-lock ∈ `[floor, 900 s]` and clipboard-clear ∈ `[1 s, 300 s]` — a server-supplied 0/absent/oversized value clamps into range, so a hostile or misconfigured server can neither disable auto-lock nor pin secrets on the clipboard (spec 03 §1.1; core `ClientPolicyClamps` constants with byte-pinned web/ext mirrors, clamp-down tested on all four clients). |
| T5 | **Malware on a client device** | Out of scope (keylogger gets the master password). This is the boundary every password manager shares. |
| T6 | **Malicious/compromised web origin** (server serving hostile JS) | Accepted gap of the web client: page-load-time trust. Mitigations: CSP `default-src 'self'`, immutable versioned bundles, no third-party origins, no CDN; native apps are the trust anchor; an armed break-glass twin origin additionally refuses any sign-in without server-TOTP, and whatever access control the operator puts in front of that origin is theirs to add — andvari does not assume one. High-value operations (escrow ceremony) never run in the web client. The durable web cache (spec 02 §8.1) sharpens T6's **timing**, not its ceiling: hostile same-origin script can now exfiltrate persistent ciphertext + the wrapped accountKeys from a LOCKED/idle tab — an offline-cracking surface, floored by T8's KDF math and client-enforced at cache read (a planted weak-KDF payload refuses offline unlock) — where previously it had to wait for the next unlock. That next unlock still hands hostile JS the master password itself, which strictly dominates ciphertext theft; controls unchanged. **Correction on the record (2026-07-15, B1-2):** a web cross-origin enroll affordance would enable **full existing-account compromise**, not merely exposure of a new vault — an actionable "switch to this server" prompt escorts the user onto attacker-controlled origin, where post-navigation JS (this row's page-load trust) phishes the plaintext master password and replays it against the victim's REAL server. Both link composers mint authority == `payload.o`, so genuine web links land same-origin by construction; a web-visible mismatch's only real-world trigger is a crafted URL. The web client therefore REJECTS a mismatched invite link terminally — origin rendered as plain text, no link, no button, no continue affordance (design 2026-07-15 §4.4 / B2-2). |
| T7 | **Backup theft** (the operator's snapshots, and any offsite copy of them) | Backups contain only what T1 sees (ciphertext + metadata). Neutralized by design. |
| T8 | **DB leak → offline cracking** | authKey verifier is argon2id-hashed server-side; vault security rests on Argon2id(master password) at ≥64 MiB — weak master passwords remain the user's risk (policy enforces minimum strength at enrollment). The client offline caches (native SQLite / web IndexedDB, spec 02 §8/§8.1) widen **where** this sentence applies — a stolen device, a browser-profile leak, or an OS backup of one is the same offline-cracking surface as a server DB leak — not its math: the identical H1 floor is enforced server-side, client-side at every unlock, and at cache READ (a cached sub-floor `kdfParams` payload refuses offline unlock outright, so the cache can never become a floor bypass). **Pattern-aware strength estimate (0.21.0, audit F31):** "minimum strength" is a class-diversity × length proxy, and length used to be the raw one — so `Password1!Password1!` scored as twice its real entropy and a 40-character run of one letter cleared the floor, exactly the shapes a cracking rig tries first. The estimator now collapses a repeated block (charged once, `period + 1`) and a ±1 run (charged 2) before the length term — spec 07 §2.3 `effectiveLength`, vector-pinned so both impls collapse identically. Deliberately asymmetric: the **enrollment / change-password floor still scores the pre-collapse proxy**, so the sharper estimate lowers what the meter *displays* but never what it *refuses* — a floor that gates a password change must not tighten under a user who is mid-way through fixing a weak password. The residual is unchanged and owned by the user: a weak-but-non-repetitive master password is still accepted, and this row's Argon2id cost is what stands behind it. |
| T9 | **Recovery-sheet thief** | Holds A4 ⇒ can decrypt every escrowed UVK **given the sealed blobs** (needs server data too). Physical security of the two sheets + USB is the control; annual drill verifies presence. Compromise response: re-ceremony + full re-escrow + item re-key (manual runbook). |
| T10 | **Malicious server during enrollment** (pubkey substitution) | Blocked by triple pinning + human fingerprint check (spec 04 §2). **Per-member recovery (spec 04 §6):** `waived` members carry no org escrow ⇒ no pubkey to substitute ⇒ T10 N/A to them; for `required` members the fingerprint reaches the invitee out-of-band via the **client-composed** in-person QR (or the typed-sheet fallback), never a server-stamped pin (`rfp=null` on the server-composed emailed link — spec 04 §6.5). The symmetric member-recovery blob has no pubkey and is T10-immune by construction. |
| T11 | **User enumeration / credential stuffing** | Deterministic fake prelogin salts, uniform 401s, per-IP rate limits, and — since the 2026-07-15 pivot — **email-keyed exponential backoff on LOGIN only** (5 consecutive failures → `2^(n-5)` s capped 900 s, applied **uniformly to existing and unknown emails** so throttling is not an account oracle). `/recovery/self/*` deliberately keeps **per-IP fixed-window only, NO per-account backoff** (§F.8: never lock a victim out of last-resort recovery; the 256-bit recovery secret makes per-IP sufficient — review 2026-07-16 D1). Break-glass twin-origin lockdown (TOTP + register/refresh disabled) applies only where that opt-in origin is configured; login rate is a flat 5/min per IP on every origin (R12). |

## Accepted risks (signed off by owner at hardening gate)
R1 JVM/JS cannot guarantee secret zeroization (GC copies) — industry-standard gap.
R2 Web client page-load trust (T6). R3 Escrow key holder can decrypt all (deliberate
— the recovery feature). **Amended for per-member recovery (spec 04 §6):** under the
Hybrid default the admin backstop **persists** for `escrowPolicy=required` members (the
admin can still decrypt them — R3 stands); for a **`waived`** member R3 is **retired** (no
org escrow blob exists ⇒ private from admin) at the cost of **no backstop** — losing both
the master password and the generated recovery piece ⇒ permanent data loss (the accepted
hard-loss trade, R9). R4 Server metadata visibility (A6) — includes a residual
prelogin oracle: after a KDF-policy change, an account whose stored params differ
from the current default answers prelogin with diverged params (existence confirmed)
until it re-keys via password change; unknown emails always answer the current
org-default params. R5 Single server per
instance — availability comes from offline-first clients plus the operator's own backups,
never from HA. R6 TOTP seeds
co-located with passwords (accepted eggs-in-one-basket, user decision). R7 removed
shared-vault member retains decryption capability for ciphertext they held while granted
(and future leaks of *unchanged* items) until P6 VK rotation + lazy re-encryption —
removal in v1 is server-side revocation only; future-secrecy loss only, the server itself
still holds only ciphertext. **R7 extended (vault lifecycle, spec 03 §11):** vault deletion
removes the server's copies after a 7-day grace and triggers fleet-wide client purge, but is
NOT cryptographic erasure toward ex-members — anyone granted while the vault lived may retain
ciphertext + the VK they already held, and the operator's server backups keep copies
until their own retention expires (~30 d); the ex-owner after a transfer retains VK likewise.
True erasure needs P6 VK rotation. **R8 (cut 4 email-invite — INERT unless the owner configures
it):** with `ANDVARI_SMTP_*` + `ANDVARI_INVITE_BASE_URL` set, a **bearer invite token transits the
operator's mail relay and rests in the invitee's inbox** — bounded by a forced ≤60-min TTL,
private-origin-only links (an emailed public-origin link dies at `register`), and `register` still
needing reach to the private enroll origin; a real widening of R3-adjacent out-of-band delivery.
**T1 widens with it:** a server compromise reading `andvari.env` now also gains the stored
`ANDVARI_SMTP_PASS` = send-as the operator's mail domain (phishing) + a new outbound
internet egress — capabilities the T1 row above ("sees only spec 02 §5 plaintext + traffic
patterns") otherwise excludes. **Lifecycle threat posture (T1):** lifecycle ops on
existing vaults are member-verifiable — the server never holds VK and cannot mint proofs; it
can still WITHHOLD, delay, or serve stale state (availability-class, accepted). Replay is
bounded by expiry+seq binding and by soft-hide-until-purgeAt; residuals: a device offline
since before the newest verified seq may be shown stale-but-genuine older state; proofs are
keyholder-forgeable (server authz is the gate). Grant injection for NEW vaults (F16) remains
an accepted residual until P6 owner-signed grants — the "you were added to <vault>" notice is
transparency for honest servers only and is NOT an F16 defense. Shared-vault membership
topology (which userId holds which role on which vaultId) is server-visible metadata,
subsumed by A6/R4.
**R8 extended (per-member recovery `rfp`, spec 04 §6.5):** the emailed enroll link is
**server-composed**, so any org recovery fingerprint it carried would be server-attested
(TOFU-from-server, T1-bounded) rather than out-of-band — which is exactly why the
server-composed emailed link carries **no authoritative `rfp` (`rfp=null`)** and emailed
invites **default to `escrowPolicy=waived`** (no fingerprint needed → frictionless and
safe). A required-backstop invite that needs a genuine org pubkey uses the
client-composed in-person QR (fingerprint out-of-band via the admin's screen) or the
typed-sheet fallback; a missing `rfp` fails safe to typed-sheet, never to server
auto-trust. No new server capability beyond the existing R8 email relay.
**R8 delta (endpoint-agnostic pivot 2026-07-15):** R8's containment claim — that an
emailed link is private-origin-only and a leaked inbox still can't reach the enroll
origin (also asserted in `docs/design/2026-07-12-email-invite.md`) — is **superseded on
single-origin instances**, which are now the DEFAULT topology (`ANDVARI_PUBLIC_HOSTNAME`
unset — the reference instance and the self-host default): emailed invites legitimately
carry the public canonical origin (`ANDVARI_CANONICAL_ORIGIN`, replacing the deprecated
`ANDVARI_INVITE_BASE_URL`), so the invite token in a leaked inbox CAN reach `register`.
This is a deliberate, accepted trade; compensating controls: the forced ≤60-min TTL,
single-use token, invite-row-bound escrow policy (read server-side, never from the
client body), register rate limits, **https now required for the minting origin on
non-local hosts** (with private-origin containment gone, transport secrecy is the
remaining control on the bearer link), and `signupMode` gating — a leaked token still
only creates the one account the admin intended, redeemable solely at its issuing
server (invite-ROW gate). Dual-origin deployments keep the old A5 guard verbatim:
emailed links must never point at the break-glass twin origin.
**R9 (per-member recovery piece — a member holds a UVK-equivalent secret, spec 01 §2.1 /
spec 04 §6).** The generated `recoverySecret` wraps that member's own UVK, so possession
of the piece is UVK-equivalent **for that one account** (never the fleet). Two faces:
(1) **LOSS** — a `waived` member who loses **both** master password and piece has **no
backstop ⇒ permanent data loss** (accepted; the register-time posture acknowledgment,
spec 04 §6.3, makes the trade explicit and un-skippable); a `required` member is covered
by the admin escrow backstop (R3), so their loss is recoverable. (2) **THEFT** — the piece
is the self-held analogue of the org recovery-sheet thief (T9): whoever holds it can, *with
server data*, decrypt/reset that one account. Controls: physical/digital custody of the
member's sheet/QR (same class as T9's sheet custody); and the online reset is gated by the
phase-1 **verifier** (a thief still needs the piece), the **per-IP rate-limit** (per-IP
fixed-window ONLY — deliberately NO per-account backoff, §F.8: a targeted flood can never
lock a victim out of their own recovery; the 256-bit recovery secret makes per-IP
sufficient), and the **single-use replay-bound ticket** (spec 03 §12), so the stolen piece alone is not a remote
reset/lockout oracle. The recovery unlock **preserves the identity-pubkey hard-fail
linchpin** (spec 01 §5): `recover()` routes through the shared UVK-unlock tail, so a server
substituting an identity pubkey is caught during recovery exactly as on every normal unlock
(spec 04 §6.2) — untouched by this change. The **opt-out authorization** (who may waive) is
**server-trusted state with admin-visible, non-silent reconciliation — NOT tamper-proof**:
the admin UI distinguishes "waived (intended)" from "escrow missing/failed"
(`escrowFingerprint == null` on a `required` invite), so a hostile-server policy flip is
*visible* on reconciliation but not *prevented* (acceptable under T1 for the household
model; spec 04 §6.5).
**R10 (hostile endpoint / endpoint-agnostic operation — 2026-07-15 pivot,
`docs/design/2026-07-15-multi-tenant-endpoints.md`).** Clients are endpoint-agnostic: any
client may be pointed at ANY server, including a hostile one, at any time — including
mid-enrollment, since the invite carries its issuing server's origin. What holds the line:
(1) **The policy-trust boundary** (spec 03 §1.1) — the client-side hostname trust
heuristic (`*.ts.net`/RFC1918 ⇒ trusted) is deleted; device posture derives from
server-declared policy fetched from an unauthenticated endpoint on an untrusted server,
applied under the invariant *trusted-as-declared iff the field governs the server's own
behavior; client-floor-only iff it touches the device's at-rest posture, factor floors, or
timer windows; decorative otherwise — a hostile server may make a client safer, never
laxer* (see R11 for the monotonicity consequences). (2) **Origin-clean switching** — a
`serverUrl` change drops access+refresh tokens before the first request to the new origin
(no `Authorization` header ever crosses a baseUrl change — test-gated on all four
clients); native/extension data is namespaced by `(origin, userId)` so a foreign origin's
policy can neither read nor wipe another origin's material; the raw-origin anti-phishing
trust gate (punycode-rendered IDN, plain-http caution, no server-supplied branding)
precedes every switch; while an invite-driven switch is pending, sign-in is hidden so a
hostile pending server cannot harvest an offline-crackable authKey digest of the user's
REAL master password; web gets no cross-origin affordance at all (T6 correction above).
(3) **Blast radius is stated conditionally (B2-8):** enrolling at a hostile server exposes
what the user gives THAT server — a new vault there plus the email/activity metadata of
one account; it does not move or expose any existing vault **provided the master password
is unique**, which is why the enrollment trust-gate copy instructs "choose a master
password you don't use anywhere else" (reuse would hand the hostile server a crackable
digest of the real one). (4) **Recovery endpoints** (`/recovery/self/*`), LAN-only in
practice before the pivot, are **internet-reachable on single-origin instances**: kept at
per-IP 5/min with **NO per-account backoff** (§F.8 — never lock a victim out of last-resort
recovery; the 256-bit recovery secret makes per-IP sufficient, review 2026-07-16 D1), and a
build-time confirmation asserts the recovery secret's ≥128-bit (verified 256-bit) entropy and
a constant-time verify comparison; the residual —
reachability itself — is accepted (the phase-1 verifier gate and single-use replay-bound
ticket stand, R9). Decorative fields (`instanceName`, `canonicalOrigin`,
`selfHostDocsUrl`, `recoveryFingerprint`) are never rendered as verified identity; the
human-anchored escrow fingerprint ceremony remains the only cryptographic anchor (T10).
**R11 (policy monotonicity — forbid-only fields and clamped timers).** Clients treat
`offlineCacheAllowed` as **forbid-only**: `false` ⇒ prohibition + immediate wipe of the
declaring origin's own namespace (never another origin's); `true` is **necessary but
never sufficient** — at-rest persistence additionally requires per-device consent on web
and desktop (Android's default-ON exemption is on the record in T3), so a hostile
`offlineCacheAllowed=true` alone can never switch a device to durable storage. Oversized
or absent `autoLockSeconds`/`clipboardClearSeconds` clamp into the client-side ceilings
(T4/B1-1). `kdfParams` floors — including the cache-read sub-floor (T8) — are unchanged
and remain the backstop that makes even a consent-granted cache non-catastrophic under a
weak-params-planting server. A monotonicity test suite asserts a hostile policy object
can never leave any client laxer than its floors/ceilings.
**R12 (online guessing with TOTP optional — B1-3/B1-6).** With mandatory TOTP retired
from the reference instance (`totpRequired` is per-instance, default false), online
password guessing is resisted by: the flat per-IP login limit
(`ANDVARI_LOGIN_RATE_PER_MIN`, default 5/min — the old private-origin 10/min relaxation
is **revoked**, spec 03 §8), the email-keyed exponential backoff (5 consecutive failures
→ `2^(n-5)` s capped 900 s, uniform across existing and unknown emails, reset on
success — per-IP alone is botnet-bypassable), and the score ≥ 3 master-password floor at
enrollment (T8's own estimator, spec 07 §2.3 — andvari ships no zxcvbn; this line named one
for years). An **accepted, compensated risk**; enrolled TOTP is now verified on EVERY
origin (closing the latent gap that an enrolled secret was only ever checked on the
public origin). Residual: distributed low-rate guessing below both rate keys — bounded by
the password-strength floor (T8's math applies online too, one attempt at a time).

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

## Quick-unlock at-rest secret (A7-extension — spec 01 §8.4)

The MV3 extension's quick unlock (spec 01 §8.4) has a **different** A7 posture than
Android's: **non-durable but hardware-less**. Enabling it puts a PIN-wrapped,
session-scoped UVK blob (`ct = AEAD(K_pin, AEAD(K_nonexp, UVK))`) **plus a live
refresh token** in `chrome.storage.session` (memory-backed, `TRUSTED_CONTEXTS`,
gone at browser exit), and the non-extractable co-key `K_nonexp` in IndexedDB. What
each attacker gets:

| Attacker | Outcome |
|---|---|
| **Device powered off / browser closed (thief, border search)** | Nothing quick-unlock-specific: `chrome.storage.session` is memory-backed and **evaporates at browser exit**, so the blob, counter, and retained token are simply gone. **Strictly better than A7-android vs a powered-off device** (no durable blob at all). Residual: OS **swap / hibernation** may page a memory image (blob + token) to disk — the co-key mitigates data-exfil of the blob alone but not a full RAM/swap image; ⊆ T7 for a disk that also holds the swapfile. |
| **Human-at-keyboard opportunist, browser running, extension locked-armed** | The in-scope delta. Where a locked extension previously required the master password, it now falls to a **6+-char PIN, 5 attempts, then wipe**. This is the accepted, opt-in narrowing. The attempt counter is same-compartment and **attacker-resettable** (below), so against a *sophisticated* local attacker it is theater; against the opportunist it holds, and the PIN entropy floor + session scoping are the real bounds. |
| **Malware / debugger reading the browser process or `storage.session`** | **T5, out of scope** for every client (a keylogger already gets the master password; unlocked-process memory already holds `vaultKeys`). Such an attacker gets a **PIN-crackable blob (double-wrapped: ~32 MiB+ Argon2id over a ≥6-char / ≥10-digit PIN ≈ GPU-hours for a floor PIN, more for a word) *plus* a live refresh token** — but note the blob alone is useless without the **non-extractable co-key** (A1): a pure `storage.session` dump cannot open it. **Per-extension storage isolation is a PLUS**: a co-installed extension cannot read another extension's `storage.session` except via a `chrome.debugger` grant or OS access (both T5). |
| **Co-installed page / content script** | No access: the PIN UI and enroll are **popup-only** (`chrome-extension://`), there is no `externally_connectable`, and the `TRUSTED_CONTEXTS` access level is a hard precondition to arming at all (if it can't be guaranteed, the client does NOT arm — spec 01 §8.4). A page can neither send the PIN nor read the blob. |
| **The server** | Learns nothing — quick unlock is wire-invisible (spec 01 §8); no new endpoint/header/field. The one wire *interaction* is that a redeem forces a `POST /auth/refresh` FIRST, so revocation / a rescue (which revokes sessions) takes effect at the next redeem (T1 unaffected). |

Residuals accepted (A7-extension): (a) **memory-backed ≠ never-on-disk** — OS
swap/hiberfil can page the blob + token; the co-key defends data-exfil of the blob,
not a full RAM/swap image. (b) The **attempt counter, freshness stamp, and pinParams
are same-compartment and attacker-resettable** by a `storage.session`/DevTools write
(= T5) — they defend only the unsophisticated opportunist; a **pinParams ceiling**
still bounds a planted-params OOM, and a sub-range set is treated as corrupt → wipe.
(c) The whole in-scope delta reduces to the **human-at-keyboard opportunist on an
unlocked machine with the browser running**; a machine that is unlocked with the
browser running is already adjacent to T4/T5. The A5 risk of forgetting the master
password behind a working PIN is bounded by the **min(browser session, 24 h)**
periodic-full-password rule (spec 01 §8.4).

## Autofill (client-side, Android)

The autofill service honors a fill request's web domain only from a browser it verifies by
**signing certificate** (package name alone is spoofable — an app can install under an
absent browser's package id). A package that is not pinned, not installed, or whose cert
does not match its pin **fails closed**: no web-domain trust → only `androidapp://<pkg>`
URIs match it, never web items. Residual: a browser whose release cert we have not pinned
won't offer autofill until its digest is added (safe, functionality-only). The match rule
(2026-07-10 amendment — spec 02 §3.1, `docs/design/2026-07-10-etld1-psl-matching.md`) is
registrable-domain (eTLD+1) equality against the vendored PSL snapshot (explicit rules
only): sibling subdomains of the same registrable domain fill each other, bare-public-suffix
and cross-registrable fills are refused, and hosts the snapshot cannot positively resolve
(`.lan`/`.local`/unknown TLDs) degrade fail-safe to the pre-amendment label-boundary suffix
rule. Digital Asset Links verification is the P6 loosening. The service never reads field
values and never logs field content, item names, or full URIs; local fill diagnostics
persist host-only frame domains + the calling package in app-private storage (last-event
summary always; a ring buffer only while the 24 h debug toggle is armed, purged on disarm).

## Non-goals
Nation-state adversaries; side-channel resistance beyond libsodium's own; protection
of an unlocked session from its own OS; multi-org tenancy; plausible deniability.
