# andvari — multi-tenant / self-hostable / endpoint-agnostic pivot (design, 2026-07-15)

> Status: DRAFT for owner ratification. Breaker-vetted (2 adversarial passes, both GO-WITH-AMENDMENTS; 1 blocking + 10 required + 6 recommended, all folded). Workflow wf_46f6e9d9-4b1. Owner decisions locked 2026-07-15: self-hostable + endpoint-agnostic; default reference instance andvari.monahanhosting.com (landing/self-host-nudge, no open signup); server-declared policy replaces the hostname heuristic; TOTP optional (per-instance); un-arm the update-check.

## 1. Model & goals

andvari becomes a **self-hostable, endpoint-agnostic product**: published clients (APK/deb/extension/web) bake **no tailnet hostnames** and ship preconfigured for the **default reference instance `https://andvari.monahanhosting.com`**, which acts as an invite-only landing + self-host nudge for strangers rather than an open service; the client-side hostname trust heuristic (`web/src/ui/origin.ts` — `*.ts.net`/RFC1918 ⇒ "private/trusted") is **deleted** and replaced by **explicit server-declared per-instance policy** (`signupMode`, `totpRequired`, `offlineCacheAllowed`, …) fetched pre-login, applied under a strict trust boundary ("a server may make a client safer, never laxer"); clients can repoint at any endpoint at any time — including mid-enrollment, since the invite carries its issuing server's origin — behind an anti-phishing trust gate showing the raw origin; the extension/desktop update-check is un-armed (placeholder key re-pin), and a one-command docker-compose self-host path with published artifacts is in scope. Origin becomes just an address; posture becomes declared policy plus per-device consent. Verified against HEAD `1bf8432` (fleet 0.18.0 / ext 0.15.0).

## Breaker amendments (binding)

Every blocking/required amendment is folded into the body as binding; recommended amendments are adopted as binding too. IDs follow the verdict order (B1 = threat breaker, B2 = coherence breaker).

| ID | Severity | Amendment (gist) | Disposition | Folded at |
|---|---|---|---|---|
| B1-1 | required | `autoLockSeconds`/`clipboardClearSeconds` have **no upper clamp in code**; hostile server can disable auto-lock / pin clipboard for hours | **Adopted** — client-side ceilings ADDED (new, not "unchanged"): autoLock ≤ 900 s, clipboard ≤ 300 s; server-supplied 0/oversize clamps into range; tests added | §2.3 |
| B1-2 | required | Web cross-origin enroll navigation enables **full existing-account compromise** (post-navigation master-password phishing, T6), not just new-vault exposure; one-click ferry too soft | **Adopted** — (a) threat-model text corrected in spec/05; (b) UI half **superseded by the stronger B2-2**: web gets NO cross-origin affordance at all | §4.4, §10 DOCS |
| B1-3 | required | Unsetting `ANDVARI_PUBLIC_HOSTNAME` drops mandatory TOTP **and** doubles login rate 5→10/min with per-IP-only limiting | **Adopted** — login/recovery rate limits decoupled from origin, kept at 5/min; per-account (email-keyed) backoff added; spec/05 records residual online-guessing posture | §2.5, §7.2 |
| B1-4 | required | Desktop granted default-ON durable cache under the Android "install = consent" rationale without analysis | **Adopted, first branch for desktop** — desktop moves to per-device consent default-OFF (with continuity adoption); Android exemption justified on the record in spec/05 | §5.3, §5.2 |
| B1-5 | recommended | Token non-replay across baseUrl change is stated but violated by live code (`DesktopState.updateServer`, `setBaseUrl`) | **Adopted as hard, test-gated MUST** | §4.1 |
| B1-6 | recommended | Recovery endpoints go LAN-only → internet-reachable unexamined | **Adopted** — per-IP limit kept, email-keyed backoff added, entropy/constant-time confirmation task + spec/05 accepted-risk record | §2.5, §7.2 |
| B2-1 | **blocking** | Lenses disagree on `signupMode` enum, env names, per-origin resolution; bringup writes env the server rejects; client reads a field the server never emits | **Adopted** — one normative contract table (§2.1); server enum `closed\|invite-only\|landing\|open`; per-origin overlay via `policy(publicOrigin)`; single wire name `offlineCacheAllowed`; env names fixed; bringup runs `ANDVARI_STRICT_ENV=1` so bad env kills boot | §2.1, §2.2, §2.4, §8.2 |
| B2-2 | required | Web prompt-to-switch on invite mismatch is adversarial-only and turns the trusted origin into an escort to the attacker | **Adopted** — web keeps REJECT-on-mismatch, softened copy, no actionable affordance; `enrollSwitchProposalFor` deleted from the design; switch flow scoped to desktop/Android/ext options | §4.4 |
| B2-3 | required | Native (origin,userId) namespacing has no design section/owner/rollout slot; purge paths are origin-blind and globally destructive | **Adopted** — full namespacing section with mechanism, owners, adoption one-shot; every purge site origin-scoped; **hard prerequisite of the repoint wave** | §4.2, §10 |
| B2-4 | required | Self-host path dead-ends: private repo, no public artifacts, compose-build vs `docker compose pull` contradiction, `selfHostDocsUrl` swallowed by SPA fallback, no public APK channel | **Adopted** — public GHCR image is the distribution channel; `/selfhost` becomes a real static route registered before the SPA fallback; APK/deb/ext publish to reference `/downloads` promoted to a numbered rollout step **gating** the Devices-card rework; update story = pull-from-registry | §8, §10 |
| B2-5 | required | Static `content_scripts` cannot have `exclude_matches` updated at runtime → injection into self-host vault UIs or double injection | **Adopted** — static entry removed from both manifests; dynamic registration only (`persistAcrossSessions`), excludeMatches computed from `serverUrl`; e2e asserts absent-on-vault / exactly-once-elsewhere | §5.1 |
| B2-6 | required | During a pending invite repoint, sign-in is one tap away → hostile server harvests a KDF digest of the REAL master password | **Adopted** — pending state hides/disables sign-in (only "complete enrollment" / "cancel and return"); foreign-origin sign-in requires a deliberate manual ServerField switch | §4.3 |
| B2-7 | required | Ext §C5 wipe-on-switch contradicts the no-cross-namespace-wipe invariant; A→B→A round trip loses PIN/cache | **Adopted** — C0 rule 2 applied uniformly: switches preserve old-origin namespaces (bounded by the 7-day quick-unlock staleness ceiling); wipe only on explicit remove or that origin's own policy-forbid | §4.2, §5.1 |
| B2-8 | recommended | Trust-gate enrollment copy overpromises ("does not expose any existing vault") given password reuse | **Adopted** — copy adds "choose a master password you don't use anywhere else"; spec/05 blast-radius claim stated conditionally | §4.3, §10 DOCS |
| B2-9 | recommended | Crash between register success and deferred baseUrl commit strands the user; "abandoned" undefined | **Adopted** — persisted `pendingServer` marker written before register; launch-time reconcile prompt; "abandoned" defined | §4.3 |
| B2-10 | recommended | Ext manifest warning-set change across the update may disable-on-update; must be observed, not reasoned | **Adopted** — release gate: install 0.15.0 in Chrome+Firefox, update in place, assert enabled + fetch works + Firefox first-run grant flow | §5.1, §10 gates |
| B2-11 | recommended | Web origin move silently loses durable cache; tailnet front lifetime for old clients unstated | **Adopted** — one-time offline-copy nudge fires per (origin,device); tailnet `tailscale serve` front lifetime recorded as a rollout constraint | §5.4, §6.4 |

---

## 2. Server-declared policy

### 2.1 Normative contract (binding for every lane — resolves B2-1)

This table is THE contract. All lanes cite it verbatim; no lane invents synonyms.

| Item | Normative value |
|---|---|
| Wire field | `ClientPolicy.signupMode: String` (default `"invite-only"`) |
| Enum | `"closed"` \| `"invite-only"` \| `"landing"` \| `"open"` |
| `closed` | Sign-in only; client renders no invite/enroll UI. Emitted per-origin for a break-glass twin origin (§2.2); operator-settable for sign-in-only instances. |
| `invite-only` | Sign-in + invite-gated enroll, no stranger nudge (self-host household default). |
| `landing` | `invite-only` + the stranger landing: "invite-only — enter an invite, point at your own server, or self-host" (**reference-instance value**). |
| `open` | Registration without invite. **Reserved**: server boot-coerces env `open` → `landing` with a warning until the open-register path ships (§7.3). |
| Old server (field absent) | Client treats as `invite-only` (today's universal truth — every register is invite-gated). |
| Unknown value (newer server) | Client treats as `invite-only`: plain invite-gated enroll, **never** open-register UI, no nudge. |
| Durable-cache field | **One wire name: `offlineCacheAllowed`** (`Wire.kt:579`, existing). The owner-decision term "durableCacheAllowed" IS this field; no parallel field exists anywhere. Client reads only `offlineCacheAllowed`. |
| Env vars | `ANDVARI_SIGNUP_MODE` (`closed\|invite-only\|landing\|open`, default `invite-only`), `ANDVARI_TOTP_REQUIRED` (bool, default false), `ANDVARI_OFFLINE_CACHE_ALLOWED` (tighten-only floor, default true), `ANDVARI_INSTANCE_NAME`, `ANDVARI_CANONICAL_ORIGIN` (falls back to deprecated `ANDVARI_INVITE_BASE_URL` with boot warning), `ANDVARI_SELFHOST_DOCS_URL` (default `<canonicalOrigin>/selfhost`), `ANDVARI_FORCE_HSTS` (default false), `ANDVARI_LOGIN_RATE_PER_MIN` (default 5), `ANDVARI_STRICT_ENV` (default false). |
| Env lint | Server boot warns on unknown/invalid `ANDVARI_*`; under `ANDVARI_STRICT_ENV=1` it **exits**. `bringup.sh` sets strict mode so a typo'd/renamed var fails the healthz wait (B2-1). |

### 2.2 Schema, endpoint, sourcing

**Endpoint: reuse `GET /api/v1/client-policy`** (`App.kt:419-422`, unauthenticated, already fetched pre-login by all four clients — web `App.tsx:69-92`, ext `background.ts:783,986`, desktop `DesktopState.kt:475,584`, android policy probe). No new route. Add a per-IP rate bucket (~60/min) — it becomes the most-hammered anonymous route on a public instance.

**`ClientPolicy` additions** (`core/.../model/Wire.kt:573-588`; mirrors: `web/src/api/types.ts:306-320`, `extension/src/api.ts:88-93`) — all defaulted, old-server/old-client pairings degrade to today's behavior (the `AdminStatus.emailConfigured` precedent, `Wire.kt:556-559`):

```kotlin
// appended to ClientPolicy — existing fields unchanged
val signupMode: String = "invite-only",   // §2.1 enum
val totpRequired: Boolean = false,        // per-instance login-factor stance (§2.6)
val instanceName: String? = null,         // decorative label — NEVER a verified identity
val canonicalOrigin: String? = null,      // server-claimed own origin — diagnostic only, never an anchor
val selfHostDocsUrl: String? = null,      // rendered as a raw https URL only (R8 rule)
```

Plus `SessionResponse.mustEnrollTotp: Boolean = false` (§2.6).

**Sourcing — operator env overlay, per-origin resolved, stripped on persist.** The instance stance belongs to the operator (env), not the in-app admin: a compromised admin session must not open the front door or disable instance TOTP. `Service.policy()` (`Service.kt:96-99`) gains a `publicOrigin: Boolean` parameter, passed by the route as `call.isPublicOrigin(config)` — the same pattern `login()` already uses (`App.kt:469-474`):

```kotlin
fun policy(publicOrigin: Boolean): ClientPolicy {
    val stored = repo.policyJson()?.let { json.decodeFromString(ClientPolicy.serializer(), it) } ?: ClientPolicy()
    return stored.copy(
        recoveryFingerprint = config.recoveryFingerprint,
        serverTime = now(),
        signupMode = if (publicOrigin) "closed" else config.signupMode,   // break-glass twin always answers closed
        totpRequired = config.totpRequired,
        instanceName = config.instanceName,
        canonicalOrigin = config.canonicalOrigin,
        selfHostDocsUrl = config.selfHostDocsUrl ?: config.canonicalOrigin?.plus("/selfhost"),
        offlineCacheAllowed = stored.offlineCacheAllowed && config.offlineCacheAllowedFloor,  // env floor, tighten-only
    )
}
```

The per-origin overlay is how the dual-origin duality folds into declared policy: on a self-hoster keeping the break-glass topology, the twin origin serves `signupMode="closed"` (client renders sign-in only, admin QR suppressed) while the primary serves the configured mode — the client never sniffs hostnames (resolves B2-1's per-origin fork via the amendment's first branch). `setPolicy()` (`Service.kt:101-106`) widens the existing `serverTime` strip to ALL overlay fields, so an old admin client's `PUT /api/v1/admin/policy` (`App.kt:870-878`) round-trips losslessly and can never clobber operator stance. `offlineCacheAllowed` stays admin-settable (household knob) with the env floor tighten-only. New `Config.kt` params are defaulted trailing args — the ~15 positional test constructions compile unchanged.

Reference-instance response (canonical origin):

```json
{ "...existing fields...": "unchanged",
  "signupMode": "landing", "totpRequired": false,
  "instanceName": "andvari (reference instance)",
  "canonicalOrigin": "https://andvari.monahanhosting.com",
  "selfHostDocsUrl": "https://andvari.monahanhosting.com/selfhost" }
```

### 2.3 POLICY-TRUST BOUNDARY table (normative; goes into `spec/03` beside lines 15-17 and `spec/05` as an R-row)

The client reads this object from an **unauthenticated endpoint on an untrusted server**. Governing invariant (generalizing `session.ts:143`'s `offlineCacheAllowed=false ⇒ never cache` polarity): *a field is trusted-as-declared iff it governs the server's own behavior; it is client-floor-only iff it touches the client device's at-rest posture, factor floors, or timer windows. A hostile server may always make the client safer, never laxer.* Each client implements one `applyPolicy()` whose tighten-only branches are structurally incapable of relaxing.

| Field | Class | Rule |
|---|---|---|
| `signupMode` | **TRUSTED** (server-authoritative UI hint) | Drives which landing/enroll UI renders; register success stays server-enforced (invite gate, `Service.kt:126-133`). A lie only mis-decorates the liar's own front door. |
| `totpRequired` | **TRUSTED** (UI hint) | Pre-shows the TOTP input. Authoritative path stays the reactive server errors (`totp_required` / `public_login_requires_totp` — `Welcome.tsx:388-394`, `AndvariViewModel.kt:185`, `DesktopState.kt:236`), which win over any declared value. Never gates a client-side protection. |
| `sessionAccessTtlSeconds`, `sessionRefreshTtlDays`, attachment quotas, `serverTime` | **TRUSTED** (informational) | Describe the server's own enforcement; never security anchors. |
| `offlineCacheAllowed` | **CLIENT-FLOOR-ONLY** (tighten-only) | `false` ⇒ prohibition + force-wipe of the **declaring origin's own namespace only** (§4.2; existing machinery `session.ts:222-229`, native purge paths, now origin-scoped). `true` ⇒ **necessary but never sufficient**: at-rest persistence additionally requires per-device consent on web + desktop (§5.3/§5.4); Android's exemption is recorded (§5.2). |
| `kdfParams` | **CLIENT-FLOOR-ONLY** | Existing floors unchanged, incl. the cache-read sub-floor (below-floor params ⇒ refuse offline unlock, spec/05 T8) — the backstop that makes even a mis-enabled cache non-catastrophic. |
| `autoLockSeconds` | **CLIENT-FLOOR-ONLY** (clamp — **ADDED by this design, B1-1**) | No upper clamp exists today (`useAutoLock.ts:114-116` applies only `Math.max(0, fetched)`). New: effective = clamp into `[floor, AUTO_LOCK_MAX_SECONDS=900]`; a server-supplied 0/absent that would mean "never lock" clamps to the ceiling — **a server cannot disable auto-lock**. Constants live in core (new `ClientPolicyClamps`) with byte-pinned web/ext mirrors; applied at `useAutoLock.ts:114-116`, `AndvariViewModel.kt:551-554`, `DesktopState.kt:2416`, ext `api.ts:88-93` consumers. Tests assert oversized values clamp down on all four clients. |
| `clipboardClearSeconds` | **CLIENT-FLOOR-ONLY** (clamp — **ADDED, B1-1**) | Today only `Math.max(1, …)` (`Welcome.tsx:917`, `Vault.tsx:923,929`). New: clamp into `[1, CLIPBOARD_CLEAR_MAX_SECONDS=300]`, same constant/mirror/test discipline. |
| `minVersion` | **CLIENT-FLOOR-ONLY** | Force-upgrade-only (fail-safe); unchanged. |
| `recoveryFingerprint` | **DECORATIVE** | A value to check against the human-anchored sheet; never itself an anchor (`enrollposture.ts:3-13`). Now stated explicitly in spec. |
| `instanceName`, `canonicalOrigin`, `selfHostDocsUrl` | **DECORATIVE** | Never rendered as verified identity; never in the trust gate; `selfHostDocsUrl` rendered as a raw URL only; `canonicalOrigin` used only as a proxy-misconfig diagnostic and for server-side invite minting (§3). |

**Policy fetch failure ⇒ conservative defaults:** render sign-in + manual invite entry, treat `signupMode` as `invite-only`, `totpRequired=false` (server re-prompts authoritatively), durable cache OFF; keep the native retry affordance (`AndvariViewModel.kt:687`).

### 2.4 Fetch cadence

Boot, every unlock (existing), immediately after every trust-gate-confirmed switch (native probes already do this: `DesktopState.kt:584`, `AndvariViewModel.kt:661-671`), and before rendering the landing.

### 2.5 Rate limiting & online-guessing posture (B1-3, B1-6 — binding, origin-independent)

With mandatory TOTP retired from the reference instance, online-guessing resistance must not simultaneously relax:

1. **Login bucket decoupled from origin and kept tight:** `App.kt:471`'s `if (publicOrigin) 5 else 10` becomes a flat `ANDVARI_LOGIN_RATE_PER_MIN` (default **5**) per IP. The 5→10 relaxation the old design waved through is revoked.
2. **Per-account backoff added (per-IP alone is botnet-bypassable):** after 5 consecutive failures keyed on the **normalized submitted email** (existing or not — extending the prelogin fake-salt anti-enumeration discipline, `Service.kt:109-123`, so throttling is not an account oracle), an exponential delay `2^(n-5)` s capped at 900 s applies uniformly; reset on success.
3. **Recovery endpoints** (`/recovery/self/*`, `App.kt:723-752`) — now internet-reachable on single-origin instances — keep their unconditional per-IP 5/min and **deliberately get NO per-account backoff** (CORRECTION, review 2026-07-16 D1; overrides the original B1-6 amendment, which wrongly copied login's backoff here). §F.8 "do NOT regress" forbids a per-account counter there — it would be a targeted last-resort-recovery lockout DoS — and the recovery secret is **256-bit CSPRNG** (`core MemberRecovery`), so per-IP 5/min already makes online guessing computationally unreachable; email-keyed backoff would add ~zero resistance for that DoS. **Build-time confirmation task (binding):** assert recovery-secret entropy meets target (≥128-bit — verified 256-bit) and the verify comparison is constant-time; document both in spec/05.
4. **spec/05 records** (R-row): with TOTP optional, online-guessing resistance = rate limit + backoff + zxcvbn ≥ 3 password entropy — an accepted, compensated risk; plus the recovery LAN-only→internet delta in R8/T10.

### 2.6 TOTP as per-instance policy

Fixes the latent gap that an enrolled TOTP secret is only ever verified on the public origin (`Service.kt:222-244`). New matrix for `Service.login(req, ip, publicOrigin)`:

| user enrolled? | instance `totpRequired` | break-glass origin? | result |
|---|---|---|---|
| yes | any | any | **TOTP verified, always** (origin-independent; reuse verify + `totpLastStep` atomic anti-replay, `Service.kt:230-243`) |
| no | false | no | password-only login (reference default) |
| no | false | yes | `403 public_login_requires_totp` (break-glass unchanged, `Service.kt:225-227`) |
| no | true | no | login succeeds → **restricted session**: `mustEnrollTotp=true`; all authenticated routes except TOTP setup/confirm + logout answer `403 totp_enrollment_required` (single enforcement point near `requirePrincipal`) |
| no | true | yes | `403 public_login_requires_totp` (no restricted-session hatch on the emergency origin) |

Client contract: `policy.totpRequired` is a pre-prompt hint only; reactive errors stay authoritative. CHANGELOG must announce "enrolled TOTP is now enforced on every origin" (visible to household members logging in via tailnet).

---

## 3. Invite = endpoint carrier; retiring the private-origin guard

The enroll link (`<origin>/enroll#a1.<b64url({v,o,t,e,rfp?})>`; twin composers `EnrollLink.kt:90-101` / `enrolllink.ts:93-104`, vector-pinned) already carries its issuing server's origin `o`, scheme-safe-validated (`ORIGIN` regex, `EnrollLink.kt:59-61` — http(s) canonical lowercase host[:port] only). The parser stays endpoint-agnostic; only the consumers change (§4).

**`ANDVARI_CANONICAL_ORIGIN` replaces `ANDVARI_INVITE_BASE_URL` as the minting origin** (`App.kt:794,805` reads `config.canonicalOrigin`); the old var remains a deprecated fallback alias. Web admin QR minting is untouched — `window.location.origin` (`Admin.tsx:459`) IS the canonical origin on a single-origin instance.

**`Config.inviteBaseUrlIssue()` (`Config.kt:84-100`) → `canonicalOriginIssue()`:**

| Check | Fate |
|---|---|
| Unset ⇒ email invites inert (`emailConfigured`, `Config.kt:78-79`) | keep (fail-safe) |
| Default-port strip (`:443`/`:80` dead-on-arrival, `Config.kt:87-88`) | keep (correctness) |
| **A5** (host == `publicHostname` ⇒ refuse, `Config.kt:89-92`) | **keep, topology-conditional by construction** — it only fires in the dual-origin break-glass topology, where "emailed bearer links must not point at the emergency hatch" stays right (register is refused there, `App.kt:464`). Single-origin instances (`publicHostname` unset — the reference instance and default self-host) never trip it; emailed invites legitimately carry the public canonical origin. Reword the message: "…must point at the primary origin, not the break-glass origin." |
| B2 round-trip pin (compose→parse ⇒ `parsed.o == base`, `Config.kt:93-98`) | keep — guarantees the web `payload.o === location.origin` match can succeed |
| **NEW: https required for non-local hosts** | add — an emailed enroll link is a bearer credential (`docs/design/2026-07-12-email-invite.md:79-90`); with private-origin containment gone, transport secrecy is the remaining control. Refuse `http://` unless loopback/RFC1918/`.local`-class (dev/LAN parity). |

**No replacement needed for cross-server validity:** an invite token is only redeemable at its issuing server (invite-ROW gate, `Service.kt:126-133`) — a token at the wrong server fails as today. **Accepted-risk delta for spec/05 R8:** the "leaked inbox still can't reach the private enroll origin" containment is deliberately traded on single-origin instances; compensating controls = short TTL, single-use, invite-row-bound escrow policy, register rate limits, https transport, and `signupMode=landing` (a leaked token still only creates the account the admin intended).

---

## 4. Endpoint-switch + anti-phishing trust gate

### 4.1 Origin-clean switch rules (binding, test-gated)

1. **No token replay (B1-5 — hard MUST).** Any `serverUrl` change drops access+refresh tokens and in-memory session state and rebuilds the client BEFORE the first request to the new origin. Today's code violates this — `DesktopState.updateServer` (`DesktopState.kt:572-596`) and `AndvariViewModel.setBaseUrl` (`:654-681`) clear stale policy but not tokens, and the shipping desktop enroll auto-repoint (`Ui.kt:456`) reaches `updateServer`; web `makeClient(session, baseUrl)` (`session.ts:363-372`) would hand tokens to any baseUrl. **Regression test on all four clients: a header-capturing fake server asserts no `Authorization` header crosses a baseUrl change.**
2. **Namespace isolation (§4.2).** A switch never reads, mints, or wipes another origin's namespace.
3. **Enrollment-scoped switch.** An invite-driven repoint is PENDING until enrollment succeeds; it commits as the persisted default only on success, reverts on cancel/failure/reconcile-discard. Manual repoints commit at the gate (the gate is the gesture).

### 4.2 (origin, userId) namespacing — the missing section (B2-3, B2-7; owners: android/desktop/ext lanes)

Without this, the gated repoint ships today's **origin-blind global purge**: merely probing a server whose policy says `offlineCacheAllowed=false` destroys the home server's offline data and account keys (`AndvariViewModel.kt:671,696` → `OfflineData.purgeCacheForbidden(cacheDir, store, userId)`; `DesktopState.kt:589,611` → `deleteCache(userId); store.clearAccountKeys()` at `:2425`, global). **Binding: the repoint UI (wave 3) must not ship in any release where purge paths are unscoped.**

- **Key:** `originKey = hex(sha256(canonicalized origin)).take(16)` (canonical = lowercase `scheme://host[:non-default port]`) — stable, path-safe.
- **Android:** cache under `cacheDir/ns/<originKey>/<userId>/`; per-origin SharedPreferences via `ns.<originKey>.` key prefix (`cacheAllowed`, cached policy, quick-unlock meta); Android Keystore alias scheme `andvari.<originKey>.<userId>.qk`; `QuickUnlock.kt` (staleness ceiling `:66`, gate `:109-115`, purge `:458-528`) and the autofill process (`AutofillUnlock.kt:110-154`) read the scoped paths; `purgeOfflineData`/`purgeCacheForbidden` gain an `originKey` param and every call site (`AndvariViewModel.kt:410,634,671,696`) passes the **current** origin's key.
- **Desktop:** `~/.andvari-desktop/ns/<originKey>/<userId>/`; `prefs.json` gains `origins: { "<originKey>": { cacheConsent, accountKeys, … } }`; `clearAccountKeys` becomes per-origin; purge sites (`DesktopState.kt:480,589,611`) scoped.
- **Extension (B2-7 resolution — rule 2 applied uniformly):** `storage.local` keys prefixed `ns.<originKey>.` for quick-unlock/PIN co-key material and cached state. **Switching servers preserves the old origin's namespace** (the existing 7-day quick-unlock staleness ceiling bounds its lifetime); a namespace is wiped only on (a) that origin's own policy-forbid, or (b) an explicit "remove data for this server" action in options. An A→B→A round trip keeps A's PIN/cache.
- **Web:** browser IndexedDB is origin-partitioned — namespacing by construction; no work.
- **Adoption one-shot:** new flag (`nsAdoptedOnce`); on first run of the new build, AFTER `migrateDefaultOnce` (§6), move the legacy unscoped layout into `ns/<originKey(current baseUrl)>/`. This is also the mechanism §6 uses to carry offline data across the tailnet→public default rewrite (same instance, two fronts). Extension pre-update material adopts into the new default origin's namespace.
- **Tests:** repoint to a forbidding origin leaves all other namespaces intact; A→B→A preserves A's material (android, desktop, ext).

### 4.3 Trust Gate (one spec, rendered on desktop/Android/ext — NOT web, §4.4)

Shown before **every** `serverUrl` change (sole exception: the §6 constant→constant migration).

- Displays the **raw origin** the client will actually connect to — scheme+host+port, monospaced, visually dominant. Never a display name: `instanceName` arrives only after connecting and invite payloads carry no self-description (`o` only) — attacker-supplied branding is never rendered as verified (R8 template, spec/05:72-80).
- **IDN defense:** non-ASCII hosts render in punycode (`xn--…`) with an "international characters" caution. **Plain-http caution** for `http://` origins.
- Copy (baseline): *"Connect to a different server? **`https://example.org`** — This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it."* Enrollment variant adds (B2-8): *"Your invite was issued by this server. Enrolling creates a NEW account there — it does not move any existing vault. **Choose a master password you don't use anywhere else.**"*
- Buttons: `Cancel` (default focus) / `Connect`. No "don't ask again."
- **Pending-state sign-in lockout (B2-6, binding):** while an invite-driven switch is pending (uncommitted), the welcome UI offers ONLY "complete enrollment" and "cancel and return to `<previous origin>`" — sign-in controls are hidden/disabled (copy: "Signed-in accounts stay on `<previous origin>` — finish or cancel this invite first"). Sign-in against a foreign origin is available only after a deliberate manual ServerField switch (which commits at the gate). Prevents the "I already have an account" reflex from handing a hostile pending server an offline-crackable authKey digest of the real master password. Tests: pending state has no login controls; cancel restores the prior origin, re-probes its policy, re-enables sign-in.
- **Crash-window marker (B2-9, binding):** persist a `pendingServer` record `{origin, email?, ts}` BEFORE calling register. At next launch, if the marker exists with no committed enrollment, reconcile: "Finish setting up at `<origin>` / Discard" ("finish" re-shows the raw-origin gate, then repoints; register-already-succeeded users sign in with the password they just set; pre-register crashes re-open the enroll form there). **"Abandoned" is defined:** leaving the enroll flow or an app restart without a committed enrollment ⇒ reconcile prompt; discard ⇒ revert + clear marker. Covers the consumed-single-use-invite strand.

### 4.4 Mid-enrollment case, per surface

**Web — REJECT on mismatch (B2-2 binding; supersedes B1-2's UI half).** `enrollPrefillFor` keeps its exact-match contract (`enrolllink.ts:285-287`); the mismatch branch (`Welcome.tsx:291-295`) stays a terminal state with softened copy: *"This invite belongs to `{pending.o}`. Open the original link you were given."* — origin rendered as plain text, **no link, no button, no continue affordance**. `enrollSwitchProposalFor` does not exist. `App.tsx:107-108`'s "never repoint the session's server from a link" invariant stays. Rationale (recorded in spec/05 per B1-2a): both composers mint authority == `payload.o`, so genuine web links land same-origin by construction — a web mismatch's only real-world trigger is a crafted URL (any hostile page can set `location = "https://household-server/enroll#a1.<o=evil>"`), and an actionable prompt would turn the trusted origin's own UI into an escort to attacker turf where post-navigation JS (T6) can phish the plaintext master password and replay it against the user's REAL server — full existing-account compromise. The owner decision "invite carries its origin; client switches" is satisfied on web by navigation itself: **the link IS the switch** (opening it lands on the issuing server, which serves its own SPA; the existing same-origin consent card `Welcome.tsx:258-277` then runs).

**Desktop** — today's silent auto-repoint (`Ui.kt:451-461`, esp. `:456 state.updateServer(p.o)`) becomes: parse → hold `pendingServer` → Trust Gate (enrollment variant) inline in the enroll pane → on Connect, probe `p.o`'s policy, render the escrow fingerprint ceremony against that server (`Ui.kt:442-445`, unchanged — it remains the cryptographic anchor); commit `prefs.baseUrl` on enroll success only; Cancel/failure reverts and re-probes the prior server. Manual `ServerField` (`Ui.kt:348`) gets the gate too, commit-on-confirm.

**Android** — closes the "no enroll-link channel" gap (`MainActivity.kt:523-529`): the invite field becomes "Invite code or link", every edit runs `EnrollLink.parse` (core, multiplatform); on a link with `p.o != store.baseUrl` → Trust Gate → pending repoint (commit-on-enroll-success). `enrollPosture(linkRfp = p.rfp, …)` finally receives a real `linkRfp` — Android gains desktop's `required-affirm` posture. Camera-QR intake reuses the identical path later; field paste is the MVP.

**Extension** — account enrollment stays a non-goal (`messages.ts:161-163`); it inherits endpoint-agnosticism via the options page (§5.1).

---

## 5. Client changes per surface

### 5.1 Extension (the hard case: no setter, no options page, manifest-pinned origin)

- **`extension/src/serverurl.ts`** (new leaf module, node-test loadable like `updateverify.ts`): `DEFAULT_SERVER_URL = "https://andvari.monahanhosting.com"`, `getServerUrl()` (`storage.local.serverUrl ?? default`), `setServerUrl()`, canonicalization reusing the enroll-link origin rules. **`storage.local`, not `storage.sync`** — the server choice is a per-device trust decision; sync would let one phished device repoint every synced browser. Consumers derive: `background.ts:225` (api construction; SW rebuilds api/WS on storage change), `:632` (WS URL), `:662,687` (downloads), `popup.ts:964,971,978` (`tabs.create`). The two `const SERVER_URL`s (`background.ts:66`, `popup.ts:13`) are deleted.
- **Options page** (net-new `options.html`/`options.ts`, `options_ui` in both manifests): Server field + current-origin display; submit shows the Trust Gate, whose Connect click is the **user gesture** for `chrome.permissions.request({origins:[origin+"/*"]})`. Grant dismissed ⇒ no change. On success: origin-clean switch (§4.1 — tokens dropped; **old namespace preserved** per §4.2/B2-7; explicit "remove data for this server" button is the only destructive path), persist, rebuild.
- **Manifest permission model:** Chrome MV3 — `host_permissions: ["https://andvari.monahanhosting.com/*"]` + `optional_host_permissions: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"]` (self-host origins granted per-origin at runtime; the CORS-less fetch of `api.ts:4-6` requires the grant). Firefox MV3 — host permissions are optional-by-default: the popup detects a missing default-origin grant on first run and routes to options (the options page is mandatory on Firefox, not cosmetic). Store-listing notes flag the optional broad pattern for CWS/AMO review.
- **Content scripts (B2-5, binding):** the static `content_scripts` entry (`manifest.json:26-33`, firefox `:31` area) is **removed from both manifests entirely** (a static script's `exclude_matches` is immutable at runtime; keeping it means autofill injects into every self-host vault UI, and adding a dynamic twin double-injects everywhere). Autofill registers **dynamically only**: `chrome.scripting.registerContentScripts([{id:"autofill", matches:["http://*/*","https://*/*"], excludeMatches:[serverUrl+"/*", DEFAULT_SERVER_URL+"/*"], js:["content.js"], runAt:"document_idle", allFrames:true, persistAcrossSessions:true}])` on install/startup and updated on every `serverUrl` change; SW start checks `getRegisteredContentScripts` and re-registers (corollary: a registration failure means no autofill until the SW next runs — detected and self-healed). **e2e asserts:** script absent on the configured vault origin; present exactly once on an ordinary page; Firefox parity.
- **Popup origin display:** header shows the raw current origin (middle-truncated, full on hover/focus) — persistent anti-phishing visibility.
- **Copy:** manifest `description` (`manifest.json:5`, firefox `:5`) drops "Requires the andvari server on your Tailscale network" → "Works with any andvari server — preconfigured for andvari.monahanhosting.com; point it at your own in Options."
- **Update-in-place release gate (B2-10, binding):** removing the static all-URLs content script changes the install-time warning set in the same release that adds new host permissions — behavior must be observed: load ext 0.15.0 in Chrome and Firefox profiles, apply the new build as an in-place update, assert it stays enabled, fetch works to both origins, and the Firefox first-run grant flow triggers. The chosen warning-set strategy is documented in the ext README so future host changes re-run the check.

### 5.2 Android

Default swap (`Session.kt:248`); enroll-link channel + gate + pending flow (§4.4); namespacing + adoption + purge scoping (§4.2); clamps (§2.3); `ServerField` (`MainActivity.kt:475,2696-2701`) gains the gate; token-clear in `setBaseUrl`. **Durable cache stays policy-driven default-ON** — the exemption is justified **on the record in spec/05** (B1-4 second branch): installing an APK on one's own phone is the device-consent act; the cache is at-rest encrypted, gated by the quick-unlock co-key, bounded by the 7-day staleness ceiling (`Session.kt:68`), protected by the kdf cache-read floor, and purged on policy-`false`.

### 5.3 Desktop

Default swap (`DesktopSession.kt:147`); gate at `Ui.kt:348`/`:456` + pending flow; namespacing + purge scoping; clamps; token-clear in `updateServer`. **Durable cache moves to per-device consent, default OFF (B1-4 first branch):** desktops are routinely shared/portable/work machines — closer to web's borrowed-machine T3 than to a phone. Fresh installs persist nothing at rest until the user answers a one-time post-first-unlock prompt ("Keep an encrypted offline copy on this device?", shown only when `offlineCacheAllowed !== false`). **Continuity adoption:** an existing install that already holds a cache adopts consent=ON during the §4.2 adoption one-shot — nobody's offline access silently vanishes.

### 5.4 Web

- **`web/src/ui/origin.ts` is deleted** (with tests). Its six consumers re-home:
  1. `webCacheEnabled()` (`session.ts:141-148`) → `idbUsable && !orgCacheOff && !deviceOptOut && deviceOptIn(userId)` — explicit per-device opt-in, default OFF, on every origin (walk-up browsers are the T3 case; browser IDB partitioning supplies (origin,user) namespacing). `setOfflineCopyEnabled` (`session.ts:200-211`) writes the opt-in marker unconditionally (`:209` loses its `!isPrivateOrigin` guard). **Continuity:** one-time boot migration — an existing cache DB with no opt-out marker writes the opt-in marker (current private-origin users keep their cache). **Origin-move nudge (B2-11):** the one-time "keep an encrypted offline copy?" nudge fires on first unlock at **any** (origin, device) where policy allows and no per-device marker exists — so a member following the household to the new origin re-gains offline access with one tap instead of silently losing it; a line goes in the member migration note.
  2. Export buttons (`plan.ts:32-34`): `isExportOriginAllowed` deleted; export renders whenever the vault is unlocked (was SHOULD-level advertising; the page already holds plaintext).
  3. Offline-copy Settings card (`Settings.tsx:104-106,150`): `privateOrigin` field deleted; card always renders (org-disallowed explanation kept via `orgOfflineCacheDisallowed`, `session.ts:153-155`).
  4. Devices card (`Devices.tsx:151-166`): origin gate deleted; the card is purely manifest-driven — fetch same-origin `/downloads/manifest.json`, render exactly the artifacts listed (Android QR entry included iff an `android` artifact exists). `DEVSTORE_URL` (`Devices.tsx:30`) deleted. **Gated on the §8 artifact publish** (B2-4) so the Android entry doesn't silently vanish.
  5. Invite QR (`Admin.tsx:308-310` `shouldOfferQr`, `inviteResultView :328-332`): re-keyed to `policy.signupMode !== "closed"` — the per-origin-resolved policy (§2.2) makes a break-glass twin answer `closed` ⇒ token-only, with no hostname sniffing. QR links keep embedding `window.location.origin` (`Admin.tsx:459`).
  6. Cache opt-in pinning: folded into (1).
- **Landing** (§7) keyed on `signupMode`; **reject-on-mismatch** per §4.4; clamps per §2.3; no in-app repoint (`defaultBaseUrl()` stays `""`, `session.ts:340-343`; the `andvari.baseUrl` localStorage key stays dev-only).
- **Tests** (rewrite/new): `onboarding-decisions.test.ts` (mismatch stays rejected, copy asserted non-actionable), `plan/export/Devices/offline-copy-card/session.cache/unlock` suites for the new formulas, policy-monotonicity suite (hostile `offlineCacheAllowed=true` alone never enables; `false` always wipes own namespace; oversized timers clamp), trust-gate render rules (native), token-clear-on-switch, pending commit/revert/reconcile, old-server tolerance.

### 5.5 Baked-default swap + tailnet-leak removal (release-gated)

| File:line | Change |
|---|---|
| `app-android/.../app/Session.kt:248` | `DEFAULT_BASE_URL` → `"https://andvari.monahanhosting.com"` |
| `app-desktop/.../DesktopSession.kt:147` | same |
| `extension/src/background.ts:66`, `popup.ts:13` | consts deleted → `serverurl.ts` |
| `extension/manifest.json:8,29` + `manifest.firefox.json:10,31` | host_permissions → monahanhosting + optional perms; static content_scripts/exclude_matches removed (§5.1) |
| `web/src/ui/Devices.tsx:30` | `DEVSTORE_URL` deleted (manifest-driven card) |
| `Session.kt:249` / `DesktopSession.kt:148` | `LEGACY_LAN_DEFAULT` kept only as migration match-target; add `LEGACY_DEFAULT_TAILNET = "https://andvari.taila2dff2.ts.net"` — match-targets, never dialed |

Non-shipped tailnet literals swept as P2 hygiene (repo mirrors to GitHub): `tools/vector-gen/.../Main.kt:763`, `tools/backup-cli/.../TestBackups.kt:53`, `tools/recovery-cli/.../CliHardeningTest.kt:23-29` + `Main.kt:81` (extend the network-arg matcher to any https origin), `spec/03-wire-protocol.md:3`, `spec/07-export.md:137`. **Test vectors** (`spec/test-vectors/enrolllink.json:20,23`, `export.json:148`) are regenerated via vector-gen with `example.com` origins in the same change that touches vector-gen — never hand-edited (import.json lesson). **Release gates:** `grep -rnE "taila2dff2|192.168.2.122" app-android/src/main app-desktop/src/main extension/src web/src` must return **ONLY** the two `LEGACY_LAN_DEFAULT` / `LEGACY_DEFAULT_TAILNET` match-target constants (Session.kt + DesktopSession.kt) — nothing else. **Do NOT "clean up" those constants to zero the grep**: they are the never-dialed targets `migrateDefaultOnce` v2 rewrites FROM, and deleting them silently disables tailnet→public migration (tailnet installs would keep dialing tailnet). The Kotlin **test** dirs (`app-*/src/test`) legitimately reference the same literals as migration/carry fixtures (they exercise the match-targets) — that is expected, not a leak, since the same string already ships in the constant. Published APK/deb/ext zips are additionally string-scanned (`strings | grep ts.net`) — a binary match is acceptable only as those match-target constants, never as a dialed default.

---

## 6. Migration of existing installs

Clone the `migrateDefaultOnce` precedent (`Session.kt:239-245`, `DesktopSession.kt:67-71`) as **v2 with a NEW flag**:

```kotlin
fun migrateDefaultOnce() {
    if (prefs.getBoolean("baseUrlMigratedPublic", false)) return
    val cur = prefs.getString("baseUrl", null)
    if (cur == LEGACY_DEFAULT_LAN || cur == LEGACY_DEFAULT_TAILNET)      // ONLY the exact shipped defaults
        prefs.edit().putString("baseUrl", DEFAULT_BASE_URL).apply()      // → https://andvari.monahanhosting.com
    prefs.edit().putBoolean("baseUrlMigratedPublic", true).apply()
}
```

1. **Custom URLs untouched** — matches only the two historical shipped defaults; a self-hoster's deliberate URL passes through. v2 collapses the LAN→tailnet chain in one boot; the old `baseUrlMigratedTailnet` code is deleted. Call sites unchanged (`MainActivity.kt:124` in `onCreate`; `DesktopState.kt:135-138` in `init{}`), before first state read.
2. **Trust-Gate exemption (explicit):** a build-shipped constant→constant rewrite between two owner-controlled fronts of the SAME instance (CT122 via tailscale serve vs the always-on CF tunnel); no attacker input on either side ⇒ no gate, no token/cache clear. The §4.2 adoption one-shot runs immediately after, moving unscoped offline data into `ns/<originKey(current baseUrl)>/` so the rename doesn't orphan native offline data.
3. **Hard sequencing gate:** the migration (and the default swap for fresh installs) MUST NOT ship until the reference public origin is promoted to full service — otherwise members land on the origin that today refuses refresh/recovery/sharing and demands TOTP (`App.kt:478,723-752,977`). Release gate: live probe `curl https://andvari.monahanhosting.com/api/v1/client-policy` returns the new fields with `signupMode="landing"`.
4. **Web:** no migration (same-origin); the §5.4 nudge covers the origin move. **Extension:** no stored URL today ⇒ post-update `serverUrl` falls back to the new default (same-instance argument); pre-update quick-unlock material adopts into the default origin's namespace; a tailnet-preferring member sets the tailnet origin once in options (grant flow) — and gets it back losslessly thanks to §4.2 namespace preservation.
5. **Tailnet front lifetime (B2-11, rollout constraint):** the `tailscale serve` front stays active until fleet-min versions (or observed traffic) show no pre-migration clients (0.17/0.18 native, 0.14/0.15 ext point at it forever if un-updated); retirement is a deliberate owner step, never a side effect.

---

## 7. Reference-instance landing / self-host nudge

### 7.1 Behavior

`signupMode="landing"` is a **client rendering of declared policy, not a server flow**: a stranger's client boots against `andvari.monahanhosting.com`, fetches `/client-policy`, and renders — *"This is a private, invite-only server. Have an invite? Paste it here. Want your own? andvari is self-hostable — run your own server"* — with the invite field, the server field (native), and `selfHostDocsUrl` as a raw link. Server enforcement is unchanged: register without a valid invite fails exactly as today (invite-ROW gate); `POST /auth/prelogin` keeps its fake-salt anti-enumeration (`Service.kt:109-123`) — the landing adds no account oracle. `closed` renders sign-in only; `open` is reserved (§7.3). Native welcome screens mirror the same states from their policy probe.

### 7.2 What stays hardened with `ANDVARI_PUBLIC_HOSTNAME` unset

- **HSTS** re-homed: gate becomes `isPublicOrigin(config) || config.forceHsts` (`App.kt:338-340`); reference sets `ANDVARI_FORCE_HSTS=1`.
- **Login/recovery limits stay tight + backoff** per §2.5 (the 5→10/min relaxation is revoked; B1-3).
- **Recovery endpoints** now internet-reachable — controls + confirmation task per §2.5/B1-6.
- `isPublicOrigin` (`Auth.kt:112-115`) hygiene: tighten the `host.contains(...)` substring match to exact host equality after stripping `:port` (a crafted Host header must not select a régime). The whole break-glass bundle stays in the code, inert when the env is unset — dual-origin self-hosters get today's régime verbatim (documented as "hardened emergency origin", not "your public face"). `AdminStatus.breakGlassConfigured` (`AdminService.kt:160`) flips false; admin UI copy says "single-origin instance", not misconfiguration.
- **robots.txt** Disallow-all kept (owner knob, §11).
- Public-traffic metric (`App.kt:307-320`) left keyed to `isPublicOrigin` (inert on single-origin; no replacement).

### 7.3 `open` mode (reserved)

When implemented: register with absent/blank invite accepted; server synthesizes the invite-ROW inputs (`isAdmin=false`, instance-default escrow policy). Until then, env `open` boot-coerces to `landing` with a warning — never silently open an unwired door.

### 7.4 Reference env flip (one maintenance window, **explicit owner OK** per house rule)

Unset `ANDVARI_PUBLIC_HOSTNAME`; set `ANDVARI_SIGNUP_MODE=landing`, `ANDVARI_CANONICAL_ORIGIN=https://andvari.monahanhosting.com`, `ANDVARI_INSTANCE_NAME="andvari (reference instance)"`, `ANDVARI_TOTP_REQUIRED=false`, `ANDVARI_FORCE_HSTS=1`. Smoke: `/client-policy` shows the stance; register-with-invite, refresh, sharing, recovery all work via the public origin; an enrolled-TOTP account is prompted on every origin.

---

## 8. Self-hosting packaging

### 8.1 Distribution channel (B2-4 — binding; strangers must be able to actually get it)

- **Public container image `ghcr.io/silencelen/andvari:<version>`** (+`:latest`), multi-arch amd64/arm64, containing the shadowJar + built web assets + `recovery-cli` as a subcommand. GHCR package visibility is public even while the source repo stays private (owner decision recorded in §11; recommended default = private repo + public image + server-served docs). GH Actions billing is broken → images are built and pushed from huginn/devserv.
- **`selfHostDocsUrl` must resolve:** the server gains a real static route **`GET /selfhost`**, registered BEFORE the SPA fallback (`App.kt:929-945` currently swallows any path into index.html), serving a bundled HTML render of `docs/self-hosting.md` plus downloadable `docker-compose.yml` / `andvari.env.template` / `bringup.sh`. Every instance thereby carries its own self-host docs.
- **Client artifacts:** APK, desktop deb, and ext zips are published to the reference instance's `/downloads` with `manifest.json` updated — a **numbered rollout step that gates the §5.4 Devices-card rework**.
- **Update story reconciled:** compose references the image; updates = `docker compose pull && docker compose up -d`. `bringup.sh --build` remains for source checkouts; the docs describe exactly one default path (pull).

### 8.2 `deploy/` + bringup (env names per §2.1 — B2-1)

```
deploy/
  docker-compose.yml        # image: ghcr.io/silencelen/andvari:<ver>; ./data volume; env_file; healthcheck /healthz
  docker-compose.caddy.yml  # optional TLS overlay (auto-HTTPS sidecar)
  andvari.env.template      # from ops/andvari.env.example, self-host defaults
  bringup.sh                # THE one command (idempotent; refuses to overwrite an existing env)
docs/self-hosting.md
```

`bringup.sh`: (1) prompt for the instance origin → writes `ANDVARI_CANONICAL_ORIGIN` (boot self-test `canonicalOriginIssue()` catches `:443`/trailing-slash/http mistakes) + `ANDVARI_SIGNUP_MODE=invite-only`, `ANDVARI_TOTP_REQUIRED=false`, `ANDVARI_OFFLINE_CACHE_ALLOWED=true`, `ANDVARI_INSTANCE_NAME=<prompted>`, **`ANDVARI_STRICT_ENV=1`** (a rejected env kills boot and fails the healthz wait), `ANDVARI_PUBLIC_HOSTNAME` left unset (single-origin default — `isPublicOrigin` never fires); (2) generate `ANDVARI_ENUM_SECRET` (server refuses to start without it, `Config.kt:121-123`); (3) **escrow ceremony** — `docker compose run --rm andvari recovery-cli keygen`, print-the-sheet instructions, write `ANDVARI_RECOVERY_PUBKEY`/`_FINGERPRINT` (enrollment is refused until present — bringup must not skip past a dead instance); (4) mint `ANDVARI_BOOTSTRAP_TOKEN`, `up -d`, wait `/healthz`, smoke `GET /api/v1/client-policy` asserting the declared fields round-trip (pattern: `scripts/migration-rehearsal.sh:44,143,497`), print the first-admin enroll URL + "point any andvari app at `<origin>` (Settings → Server)".

`docs/self-hosting.md` covers: requirements (compose, DNS, TLS via caddy overlay OR own proxy/cloudflared/tailscale-serve + `ANDVARI_TRUSTED_IP_HEADERS`, `andvari.env.example:26-29`); backup = SQLite db + blob dir (adapt `ops/nightly-db-backup.sh`); the policy envs and what each declares (incl. the monotonicity note: clients treat `offlineCacheAllowed` as forbid-only); invites/email; updates (`compose pull`); explicit non-promise: client update-check is disabled by design (§9), per-instance signed updates are future work.

**CI gate:** build the image, run `bringup.sh` non-interactively against localhost, assert healthz + client-policy + a scripted enroll.

---

## 9. Un-arm the update-check (owner decision)

Two-constant re-pin back to the placeholder sentinel: `core/.../client/UpdateVerify.kt:32` `PINNED` and `extension/src/updateverify.ts:28` `PINNED_UPDATE_KEYS` (currently the real ceremony key `e_2Tpy…tHI`) → the TEST_PUBKEY placeholder. The pair is byte-locked by `updateverify.test.ts` — **change together, same wave**. Effect is total and quiet by existing §M-D3 design: `updatesEnabled()` → false ⇒ the SW never fetches the manifest (`background.ts:684`) and desktop is compile-time disabled (`Platform.kt:110`); no nag, fail-closed. `/downloads` + manifest keep serving as plain pull distribution (`App.kt:434-454`). `MIN_SEQ` parks at 0; the owner item "run `update-signer sign` for `manifest.json.sig`" becomes **moot** — drop it from the pickup queue (signer + real key stay on the owner workstation). Rationale on record: under endpoint-agnostic, a single owner-pinned key makes every self-host `/downloads` unverifiable-by-construction while keeping a live verification path aimed at untrusted servers — un-arming is security-neutral-to-positive. **Per-instance signed updates (key discovery/pinning/rotation, TOFU vs invite-carried pins) are explicitly a separate later design.** Store/OS installer signing remains the load-bearing H2 control.

---

## 10. Build-lane breakdown (module-disjoint, house parallel-campaign shape)

Seven lanes (core / server / web / ext / android / desktop / docs+deploy), four waves, ~25 slices — the 0.17.0-s6 shape. Two-reviewer bar per slice; gate-batching per wave.

| Wave | Lane | Slices | Notes |
|---|---|---|---|
| **1 — foundations** | CORE | 1. `ClientPolicy` fields + `SessionResponse.mustEnrollTotp` + `ClientPolicyClamps` constants. 2. `UpdateVerify.kt` re-pin | slice 2 is a **coordinated pair** with EXT-1 (byte-locked equality test) |
| | SERVER | 1. `policy(publicOrigin)` overlay/strip + Config envs + env-lint/strict. 2. Login TOTP matrix + restricted session. 3. Rate decoupling + email-keyed backoff + client-policy bucket + `isPublicOrigin` exact-match + HSTS `forceHsts`. 4. `canonicalOriginIssue()` + https check + `/selfhost` static route | all inert until envs set — deploy-safe |
| | EXT | 1. `updateverify.ts` re-pin | pairs with CORE-2 |
| | DOCS/DEPLOY | 1. spec/03 + spec/05 deltas (trust table normative; T3/T6/T8 per-device consent; hostile-endpoint row incl. **web T6 existing-account correction** + conditional blast radius; R8 delta + recovery exposure; monotonicity R-row; Android cache exemption; online-guessing note; email-invite design superseding note; ops/breakglass re-doc; CHANGELOG TOTP announce). 2. Dockerfile + compose + bringup + GHCR publish script + self-hosting.md | |
| **Gate 1** | | server suite + vectors + bringup CI green → **reference env flip (§7.4, explicit owner OK)** → **publish APK/deb/ext to reference `/downloads` + GHCR** (numbered step; gates WEB Devices rework and wave-4 swaps) | |
| **2 — policy consumption + namespacing** | WEB | 1. `origin.ts` deletion + six-consumer re-home. 2. Cache consent + continuity + origin-move nudge + clamps + monotonicity tests | |
| | ANDROID | 1. **Namespacing + adoption + purge scoping (§4.2)**. 2. Policy consumption + clamps | namespacing = hard prerequisite of wave 3 (B2-3) |
| | DESKTOP | 1. Namespacing + adoption + purge scoping. 2. Per-device cache consent + clamps | same prerequisite |
| | EXT | 2. `serverurl.ts` + storage namespacing + **dynamic content scripts** + manifest permission model | |
| **Gate 2** | | monotonicity suite + namespace A→B→A round-trip tests + **ext update-in-place check (Chrome+Firefox, B2-10)** | |
| **3 — switch UX** | DESKTOP | 3. Trust gate (ServerField + invite pending) + sign-in lockout + `pendingServer` marker + token-clear | |
| | ANDROID | 3. Enroll-link channel + gate + pending + lockout + marker + token-clear | |
| | EXT | 3. Options page + `permissions.request` flow + popup origin display; store submissions prepared (supersede pending CWS/AMO items, §11) | |
| | WEB | 3. Landing + reject-on-mismatch copy + Devices manifest-gated rework (requires Gate-1 artifact publish) | |
| **Gate 3** | | cross-client switch e2e + no-Authorization-crosses-baseUrl test (all four) + tailnet-string scan on artifacts | |
| **4 — defaults + migration + release** | ANDROID+DESKTOP | 4. `DEFAULT_BASE_URL` swap + `migrateDefaultOnce` v2 | **gated on the live `/client-policy` probe (§6.3)** |
| | EXT | 4. Default swap ships in the store build | |
| | DOCS | 3. Member migration note + tailnet-front lifetime constraint recorded | |
| **Release gates** | | live probe; tailnet scan; bringup CI; monotonicity suite; ext update-in-place; Devices-card artifact gate | |

---

## 11. Open questions (recommended defaults)

1. **Source visibility vs distribution.** Recommend: **repo stays private; GHCR image public; docs served at `/selfhost`** — self-hosting works without publishing source. Making the repo public is a separate owner call (B2-4 owner decision).
2. **robots.txt on the landing.** Recommend: keep Disallow-all (household privacy over product marketing); revisit only if the landing should be discoverable.
3. **`offlineCacheAllowed` governance.** Recommend: stays admin-settable (household knob) with `ANDVARI_OFFLINE_CACHE_ALLOWED` as a tighten-only operator floor (§2.2).
4. **Backoff parameters.** Recommend: threshold 5 consecutive failures, `2^(n-5)` s capped 900 s, reset on success, email-keyed uniformly (existing + nonexistent accounts) — tune after observing reference-instance metrics.
5. **Clamp ceilings.** Recommend: `AUTO_LOCK_MAX=900 s`, `CLIPBOARD_CLEAR_MAX=300 s`; owner may raise, but any raise ships as a client build constant, never a server value.
6. **Tailnet front retirement criterion.** Recommend: keep `tailscale serve` ≥ 90 days AND until fleet clients ≥ the migration-carrying versions; retire as a deliberate owner step.
7. **Extension store timing.** Recommend: **supersede** the pending CWS/AMO 0.14/0.15 submissions with the endpoint-agnostic build (single review instead of two; the manifest permission change forces re-review anyway).
8. **Android camera-QR invite intake.** Recommend: defer — field paste is the MVP; camera reuses the identical parse+gate path later.
