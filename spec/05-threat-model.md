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
| T10 | **Malicious server during enrollment** (pubkey substitution) | Blocked by triple pinning + human fingerprint check (spec 04 §2). **Per-member recovery (spec 04 §6):** `waived` members carry no org escrow ⇒ no pubkey to substitute ⇒ T10 N/A to them; for `required` members the fingerprint reaches the invitee out-of-band via the **client-composed** in-person QR (or the typed-sheet fallback), never a server-stamped pin (`rfp=null` on the server-composed emailed link — spec 04 §6.5). Since security review 2026-10 (A5) the QR's `rfp` is the FULL fingerprint, compared at full length, and honoured only after the invitee types the in-person code from the admin's screen, so a server-composed link carrying an `rfp` cannot pass either. The symmetric member-recovery blob has no pubkey and is T10-immune by construction. |
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
keyholder-forgeable (server authz is the gate). **Forged or replayed removal attribution** (the removal
half of F16; security review 2026-10, root cause A §6, review A-6: a removal proof replayed after a
re-add, or a `left` the server simply asserted, suppressed the "server may be misbehaving" warning) is
closed by removal proofs v2 (branch A7; spec 01 §6): every removal and leave carries a MAC over a
16-byte nonce and the actor's clock, each device of the target consumes the nonce (device set ∪
account state) and checks it against its OWN `liveSince` window, and neither the window nor the
consumed set ever comes from the server. It remains open, as a bounded residual, only through the
compatibility window's legacy rows (a v1 removal proof is "valid (legacy)" iff its nonce is unconsumed;
a `left` with no proof is shown as "You left" plus "Didn't do this? Tell your admin"); branch A8
retires both with the window. **Cross-vault re-seal (review A-4, the campaign HIGH "web conflict-sync
re-seal", and its core twin) — CLOSED (branch A1b; spec 02 §7.2):** a served row can no longer move an item
this device holds into another vault, so a conflict row the server flags under a vault it (or a colluding
co-member) keys can no longer make a client re-seal another vault's plaintext under that key and push it.
Every client records each item's home vault (INV-HOME), seals plaintext only under its provenance vault
(INV-SEAL), builds conflict copies from the flagged envelope itself (INV-CONFLICT), binds an editor to the
vault it opened on (INV-EDIT), and never seals under a legacy-read-only key or one that contradicts the
device's vouch / held-key memory (INV-WRITE-KEY); residuals in R17. Grant injection for NEW vaults (F16) is closed for
v2 grants by owner-signed grants (security review 2026-10, root cause A, branch A6; spec 01 §6): a
key is adopted only from a grant signed by the identity this account PINNED for the sender it names,
and "You were added to <vault> by <contact>" names that verified contact. It remains open, as a
bounded residual, only through the compatibility window's v1 seals (R15); it is retired when branch
A8 closes the window. Shared-vault membership
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
heuristic (a tailnet or private-range hostname ⇒ trusted) is deleted; device posture derives from
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

**R13 (unanchored org recovery — escrow v2, security review 2026-10, root cause A).** Admin recovery
(spec 04 §4) is anchored by the member's identity fingerprint, which must come from outside the
server. When no anchor exists (the admin never pinned the member and the member lost their sheet),
`recovery-cli recover --no-identity-anchor` runs after a typed acknowledgment (owner decision Q2): it
still refuses a blob swapped in from another member, but cannot detect a wholesale server-minted
identity (a forged UVK with a forged, self-consistent identity seed). The bundle is marked UNANCHORED,
and every device that unlocked the account before refuses the forged identity at the next unlock
(spec 01 §5 self-identity backstop); a member with no such device has no backstop. v1 escrow blobs
remain recoverable indefinitely (Q3), but only through the mandatory identity check.

**R14 (personal vault, contact pins and account state — security review 2026-10, root cause A §4, §7.2;
branch A5).** "Personal" is the UVK-authenticated `personalWrap` (spec 01 §6), so a server can no longer
make a shared vault personal by relabelling it (or by stripping a seal and relabelling `role=owner`, the
A1 residue); it can only withhold the wrap, which fails closed (no default destination, no usage
ledger). Residuals accepted: (a) **designation is a human choice** (spec 02 §4, A5 review H-1): an account that
predates the wrap, or a fresh device the server withholds the wrap from, is ASKED which vault is personal;
the server's label never picks or orders the choices and nothing is minted without the answer. A human who
picks a vault co-members can read gets exactly that; re-designation (fresh password reauth, Q9) repairs it.
A device that cached a wrap reports a withheld one as an anomaly and keeps its cache; that cache outlives the
offline cache on every client (A5b). Every choice shows its co-holders and whether it was created here or
received by transfer, and a designation mints only after a confirmation naming the vault and its co-holders.
A served wrap naming another vault than the device's (a change elsewhere, or an older wrap replayed) is a
notice the human confirms, never a silent switch; a junk wrap never displaces a valid cached one. The
co-holder list is server-reported: a server that hides a member shortens the list, which is why the
confirmation, not the list, is the control. (b) **account-state availability**: the account-state
blob (contact pins, the verified org fingerprint, consumed nonces) is UVK-sealed, so the server cannot
add to it, but it can withhold it or roll it back; each device keeps a high-water seq and its own sealed
copy and refuses the rollback, but a device that never held a newer copy cannot tell, and loses pins
(fail safe: re-verify). (c) **pins are pairwise** (owner decision Q4): a household of N people needs a
verification per pair; no admin-signed introductions. (d) The enrolment pin rests on two human acts
(spec 04 §6.5): typing the in-person code from the admin's screen, and affirming, under the stop warning,
that the admin's screen is in front of them (A5c). The code is an unkeyed hash of the link, and nothing
the invitee's client could verify instead is beyond the reach of the server that composed the link, so no
keyed code would change this; the control is the human assertion, re-checked by the client from the raw
inputs, and a navigated link plus a code on its own leaves the admin a pending verification, never a pin.
A member who ticks the affirmation and types a code read to them by someone other than the admin, in
person or, despite the warning, from an email, gives that person the admin's slot. (e) **The designation rides
the account state (branch A9, the second API-review pass, MEDIUM):** the server keeps every wrap the account ever
minted and chooses which to serve, and a device with no cached wrap (new, reinstalled, wiped) had nothing to
contradict a superseded wrap for a co-held vault, so every default save there landed where co-holders read it.
Now the account's own designation (`personal`, spec 03 §3: UVK-sealed, newest wins, written on register, on the
migration choice, on a re-designation and on an accepted change) vouches for a served wrap on any device; a
served wrap it does not name, or one served to a device with no cache and no designation (a fresh account, or
account state withheld), is a PROPOSAL: nothing is in force (no default destination), the human sees the vault's
server-reported co-holders and origin and confirms it, or re-designates with the password. An established device
whose cached wrap the server keeps serving is unchanged. The "never switch silently" rule also holds inside the
account type itself: a second apply while a wrap is in force is a notice, never a switch. **A9 review (LOW-4,
MEDIUM-1): the fresh-device replay is CLOSED by a one-time confirmation.** On a device that never confirmed a
personal vault (no cached wrap) a served wrap is a proposal even when the account's designation names it: on such a
device the account state is as replayable as the wrap (no high-water mark can tell an older authentic blob from the
current one), so a matching designation proves nothing, and the human confirms once (co-holders shown). A device that
merged account state before and holds a cached wrap follows the designation (a rollback there is detectable). The
extension holds the same line without reading account state: a served wrap on a browser with no cached wrap is a
proposal, it has no capture destination until the popup's describe/accept confirms it (captures and TOTP adds answer
"Open andvari to confirm your personal vault."), and the cached-wrap path is unchanged. Cost: every fresh device of
an account asks exactly once; the registering device never does. What remains: a default save while a proposal is
pending is refused ("Choose a vault for this item."), never redirected.

**R15 (signed grants and the compatibility window — security review 2026-10, root cause A §1.4–§1.7, §8.2;
branch A6).** Residuals accepted: (a) **legacy keys** (spec 01 §6): while the window is open a client still
READS a vault whose key only a v1 seal vouches for (anyone holding the member's public key, the server
included, can mint one), but writes nothing under it, and self-wraps it only with pre-upgrade evidence on
that device (the trust on first use the household already had) or after the human accepts it on the review
card. "Accept" is trust on first use and the copy says so; a member who accepts a server-forged vault reads
what the server put there, and anything they then save into it is readable by the server. (b) **pin currency is per device**:
a pin skips verification only on a device where a human made or re-confirmed it; a synced pin does not, so a
replayed older blob (in any order) cannot bring back a removed pin as trusted. The cost is one re-verification
per contact per device. A tombstone in the merged state removes the pin everywhere; a device that never saw the
tombstone (offline across the removal, and served only older blobs since) still trusts the pin IT confirmed:
the stale-but-genuine residual. On a host whose client state is in memory only (no durable device state),
confirmations are lost at every restart and pins are never current there until re-confirmed in that session:
this fails closed (grants go pending, the add-member check runs) and is accepted. A tombstone written on
ANOTHER device does not clear this device's own confirmation record, so if the SAME key is later re-pinned (on
any device) it is current here again without a new ceremony here: accepted, because a human on this device
verified exactly that key. (c) **pending invitations** name a sender the server reports (display name
and key); the human compares codes before anything is adopted, and the vault's name stays hidden until then.
(d) **the extension** (owner decision Q8) never opens a grant: a member's new shared vault appears in the
extension only after a full client verified the grant and posted the self-wrap. (e) **the owner's re-issue**
— as built in A6 it trusted the server for more than "whom to list": see (h), which corrects it. (f) **grant authority is not bound to the vault**: a verified grant proves which PINNED contact signed
it, not that the signer owns or may share the vault; any pinned household member who holds a vault's key can
grant it. A verified grant naming a different key than a held one is refused as `vk_mismatch` (never a silent
switch); binding grants to the vault's owner is an open design follow-up. (g) **per-vault key memory —
CLOSED on any device that held the vault (branch A7)**: every device now records SHA-256 of the first key it
adopted for each vault, by any rule, beside the §8.2 vouches (spec 01 §6, "Held-key memory"), and a later
different key for that vault meets the vouch gate (never adopted, promoted, self-wrapped, owner-wrapped or
signed onward; the caller's own UVK wrap is still used but flagged). No step of root cause A re-keys a vault,
so no legitimate path changes a held key. The memory (and the §8.2 vouch) survives EVERY server-driven drop
— any removal verdict, the resync drop, holding expiry — so a server cannot reset it and re-add the vault
under a key it chose (A7 review MEDIUM-1); only the user's own leave or delete on that device clears it,
which is the recovery path for a `vk_mismatch` ("leave it and ask its owner to add you again"). Only
trusted sources record a tag (own UVK wrap, verified v2 grant, a vouched legacy key, a vault the device
created; never an unvouched read-only v1 seal, A7 review LOW-1), so a server-forged seal served first does
not block the genuine key. Residuals: a **fresh device** (or one whose client state was wiped) has no
memory and adopts whatever verified key it is served first, which is the R15(f) authority question again;
the first TRUSTED key a device adopted is trusted on first use; and a future VK rotation (P6) must move the
tag in the same step that installs the new key. (h) **re-issue authority — CLOSED (branch A6b; the HIGH from
the security review 2026-10 API pass)**: A6 re-issued legacy grants automatically on every sync, to every
member the SERVER listed as legacy on every vault the SERVER labelled `owner`, gated only by "the member is
pinned here". A pin proves who a member is, not that this owner ever gave them this vault, so a server
colluding with one verified member could list that member on any vault the owner's device held and get the
key signed and sealed to them with no human action. Now (spec 01 §6 "Grant authority"): nothing is re-issued
by sync; a key is signed or sealed to a user only after a human on the device confirmed that (vault, user)
pair, or for a pair in the UVK-authenticated issued-grants record for the same identity key; and add member,
re-issue and transfer offer require the account's own owned-vaults record, never the role label. Residuals
accepted: a vault created before A6b needs one "You own <vault>?" confirmation (password reauth) on first
owner action, and a human who confirms ownership of, or a re-share to, something they never shared is not
stopped (the copy says the list comes from the server); a pre-A6b member must be confirmed once per vault;
and a forged transfer completion (a co-member holding the key can mint the MAC, R16(a)) can only REMOVE the
ownership record, which costs a re-confirmation, never a grant. Review residuals (A6b review): (i) **a member
claiming a vault** it holds through its self-wrap is no longer one confirm away: a vault this device first
adopted as a member needs the explicit "This vault's owner transferred it to me" on top of the password, and
the dialog shows the server-reported owner, transfer and co-holders; a member on a FRESH device whose served
row the server has stripped to an owner shape has no such provenance and gets only the single confirm (still
a password reauth, an assertion worded "Only confirm if you created this vault, or its owner transferred it to
you", and the server-reported co-holders on screen). **Narrowed in branch A1b (A6b review LOW-R):** the
"received as a member" provenance now also rides the account state (`memberReceived`, spec 03 §3: UVK-sealed,
union-merged, add-only), and `receivedAsMember` is the device record OR the account-state record, so a fresh
device of a member still needs the transfer acknowledgement when ANY device of the account ever recorded member
provenance. What remains: a member none of whose devices ever saw a member-shaped row (every row it was ever
served was already stripped to an owner shape), and a fresh device the server withholds or rolls back the
account state from (R14(b): it can remove the record from what that device sees, never add one). (ii) **a fresh device adopting an older authentic
account-state blob** (no local copy, no high-water mark yet) can bring back an issued-grant or ownership entry
that a later tombstone removed, until it merges with a newer copy; the entry is genuine (this account wrote
it) and a resurrected issued-grant entry only renews a grant this owner once signed to that same key. The
optional "prompt-only on a device that never wrote account state" hardening was not built: a device that has
written once may still hold the resurrected entry from its first merge, so it would not close the window.
(iii) **transfer accept records ownership** for an offer a colluding vault-key holder could have minted (the
offer is a MAC, R16(a)); it still needs the target's explicit "Become the owner", and the vault key it then
owns is one the target already held, so it adds a sharing authority, not a key. (iv) the reauth is refused
on a session whose unlock salt is unknown or stale (after an in-session password change or a KDF upgrade)
until the next unlock: fail closed. Since branch A1b the refusal says how to recover, "Lock and unlock andvari,
then try again", byte-identical on every client, instead of "That master password isn't right". (v) **Rule (b)
removed (branch A9, the second API-review pass, MEDIUM; owner-review item recorded in the private plan):** the
prompt-free renewal of a pair in the issued-grants record trusted the record's presence on the signing device,
but the record is relayed by the server, which can withhold the removal tombstone from a device that never saw
it (its high-water mark sits below the tombstone, so no rollback is detectable) and then list the removed
member as legacy; `recordIssued` after the renewal would then outrank the owner's tombstone on every device.
Every signing of a VK to a member is now the owner's per-row tap; the record only annotates the row ("you
shared this vault with them on …"), and the removing device keeps its own durable tombstone so it never shows
the removed pair as previously shared whatever account state it is later served. The cost is one tap per
member per key-format migration. What remains: a device that never saw the tombstone still SHOWS the hint for
a removed member (display only; no authority follows from it), and a human who re-shares with someone they
removed is not stopped (the copy says the list comes from the server). (vi) **The member-granted bit is
provenance, not shape (A9, LOW):** it is set only when the key was ADOPTED through a v1 seal or a verified v2
grant, when a VERIFIED v2 grant from a pinned sender sits beside the account's own self-wrap, or when the row
is not an owner row and no UVK wrap of the account's own opened — never from a seal or grant field the server
attached beside the account's own UVK wrap (ignored, as A1 requires) or from a relabelled role, which would
otherwise become add-only durable evidence that makes the genuine creator answer a false "its owner
transferred it to me" forever. What remains: a member whose devices never verified the owner (an unpinned
sender beside a self-wrap) records no provenance on that device and relies on the account state's
`memberReceived`, written by the device that adopted the key through the grant. (vii) **A pinned co-member who holds
the VK can mark the creator's own vault "received as a member" (A9 review LOW-4, documented only):** any pinned
household member holding a vault's key can sign a v2 grant for it (R15(f)), and a VERIFIED grant from a pinned sender
beside the account's own self-wrap is authenticated member provenance (vi), so a colluding co-member can have the
genuine creator asked for the "This vault's owner transferred it to me" acknowledgement once on the next "You own
<vault>?". A nuisance, not an authority: the acknowledgement is the creator's own statement, nothing is signed or
sealed by it, and it is asked once per device. Closing it is the R15(f) owner-binding follow-up.

**R16 (removal proofs v2 — security review 2026-10, root cause A §6, §10; branch A7).** Residuals accepted:
(a) **lifecycle MACs are forgeable by any VK holder colluding with the server** (owner decision Q11 keeps
delete, restore, transfer, remove and leave proofs as MACs, not signatures): a co-member who holds the
vault key can mint a valid removal or leave proof for anyone, and the server can deliver it. Server-side
owner authorisation stays the real gate; signing them is revisited with VK rotation. (b) **a device
offline across the whole remove → re-add → replay cycle**, when no other device of that user consumed
the nonce, never saw the vault go not-live, so its `liveSince` predates the proof and the replayed
proof verifies: the existing stale-but-genuine residual. It changes only the banner's wording, never the
data handling (holding area, 30 days, either way). (c) **another of the user's devices consumed it first**
(A7 review MEDIUM-2, a refinement of design §6.3 step 5): a nonce found only in the account-state set, with
an `issuedAt` inside THIS device's window, is shown calmly as "already recorded on another of your devices"
rather than as a replay (only this device's own consumed set raises `replay-denied`). The window is checked
first, so a proof replayed after a re-add this device saw still fails as an anomaly; a replay this device
did not see the re-add for is the (b) residual, now worded calmly when another device recorded the nonce.
(d) **older clients in the window — OWNER REVIEW ITEM for the A8 checkpoint**: removals and leaves are sent
v2-ONLY, with no v1 dual-send (a deviation from design §8.3, decided because a replayable v1 proof with no
time window would be a downgrade). An N−1 member's client cannot read a v2 proof and shows the anomaly
warning for every genuine removal or leave during the window; an N client shows "Didn't do this? Tell your
admin" for a leave an N−1 device made (it carried no proof). Both resolve as the household upgrades. An N
client that accepts a v1 proof in-window shows it qualified, "(sent by an older app version)" (A7 review
LOW-3): MAC-verified and single-use, but with no time window. (e) The server's `removal_nonces` refusal is hygiene for an
honest server only; a hostile server ignores it, which is why the clients' consumed sets decide. (f) **a
device's first `liveSince` is set at upgrade** (A7 review LOW-4): a device that held a vault before running
a release with removal proofs v2 stamps `liveSince` at its first run of that release, so a genuine v2 removal
issued while that device was offline before its upgrade (more than 10 minutes before the upgrade) shows the
anomaly warning instead of the attributed notice. Wording only, fail-closed.

**R17 (item home — security review 2026-10, root cause A §5; branch A1b; spec 02 §7.2).** Closes review A-4.
Residuals accepted: (a) **the home is device-local**, so the server chooses the FIRST home of an itemId on a
fresh device (or one whose cache was wiped: sign-out, a policy purge, a demoted web cache), exactly as it
already chooses which rows a fresh device sees; from then on no served row moves the item. **Narrowed in
branch A9 (LOW, every engine):** the first home is the vault of the first row this device APPLIED (live, blob
present, key held, envelope opened), never of a row it merely saw: a blob-less tombstone or a row under a
vault this device holds no key for, served first, records nothing (`skip`), so the server's choice is only
among rows the device can actually apply, and it can no longer home an item away from its genuine row (and
quarantine that row for good) with a row it needs no key to mint. A ciphertext row kept for a key that arrives
later homes the item when it is applied then, if the item still has no home. The same holds for
every SESSION of a client with no durable cache: cache-less web (`NullCache`, the default until the per-device
opt-in, spec 02 §8.1) and a native host on the in-memory cache (desktop before cache consent, org-forbid mode)
hold their homes in memory only, so each unlock starts fresh and the server picks the first home of every item
in each such session. Confidentiality holds there as well: a served row under the server's vault that wins the
first-home race leaves the genuine row QUARANTINED, never decrypted into the working set, so no plaintext of the
genuine vault is ever sealed under the server's key; what the user sees is the server's own plaintext, and the
wrong-vault notice is raised on that pull. A server that serves
a fresh device an item ONLY under a vault it keys reads nothing new (the plaintext it serves is its own). (b)
**the extension keeps its homes per server origin and user in browser storage** and rebuilds them from the
first snapshot after that storage is cleared. (c) **quarantined rows are kept as ciphertext** for diagnosis
only (native: the newest 256; web: one per item), never decrypted into a list, search, export, fill or capture
target. (d) **one notice per pull**, however many rows were refused, so a server that keeps re-serving the
same row raises the notice again on each pull (it is never silent). (e) a capture or editor that opened BEFORE
an item's home was recorded on this device (an upgrade mid-session) binds to the vault the item showed then,
which is the item's recorded home from that point on.

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
URIs match it, never web items — and never for a KNOWN browser package (2026-10 security
review): a browser shows every web origin, so `androidapp://<browser>` matches nothing, and an
untrusted known browser gets no login fill at all. Residual: a browser whose release cert we have not pinned
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
