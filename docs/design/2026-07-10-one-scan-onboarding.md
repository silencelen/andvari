# One-scan household onboarding (S4) — design v2 (breaker-amended)

**Status:** breaker-passed (2 adversaries, `wf_bbda3fe8`, 1 fatal + 11 serious + 12 minor,
all folded in below or explicitly parked). **Origin:** exploration walk P1
(`docs/assess/2026-07-exploration.md`), ratified as S4 in `PLAN-autonomous-2026-07b.md`.
**Cycle note:** S4 is built AHEAD of S3 — see §Reorder rationale.

> **v1→v2 (what the breakers changed):** dropped `f` (the fp commitment) from the QR — it is a
> PUBLIC echoable value that stops no real attacker and is a ceremony-collapse foot-gun; made
> the transient-origin rule NORMATIVE (the v1 draft's aspirational safety note was a FATAL as
> written — eager `setBaseUrl` persistence + a ceremony-free Sign-in tab = a phishing setup);
> **scoped S4 to CO-LOCATED enrollment** (the sheet ceremony needs the physical sheet, so remote
> one-scan was never real); and pinned the honest trust model (origin authenticity = network
> trust, NOT anything in the QR).

## What it is, honestly

A **convenience** that removes the hand-typing of server origin + invite token + email from a
new household member's enrollment. It is **not** a new security mechanism and it is **not** a
remote-onboarding tool. The owner and the new member are **physically together** (the normal
case — a new phone at the kitchen table); the owner hands over the printed recovery sheet in
person. After S4, "add a member" is: owner clicks **Add family member** → a QR fills the screen
→ member scans it with the **system camera** (no in-app scanner, no camera permission, no new
dependency) → lands on a **prefilled** enrollment → member chooses a master password and types
the first 16 characters of the fingerprint **from the physical sheet in their hand**.

**What it removes:** typing a `ts.net` URL, a 43-char token, and an email on a phone keyboard —
the three most error-prone steps of the ~7-step ceremony the persona walk flagged.
**What it deliberately keeps:** the typed-sheet fingerprint ceremony (spec 04 §2(3)), master
password entry. **What it does NOT solve** (unchanged): tailnet joining, extension install, the
guest inversion (P3), warm escrow (P2), and **remote** enrollment (out of scope — no safe
screen-free fp channel exists for an absent member; see Trust model).

## The trust model (rewritten honestly — this is the load-bearing section)

andvari is zero-knowledge; enrollment is where a NEW member's device first trusts a server. The
question S4 must answer: *can the one-scan convenience let a member enroll against the wrong
(hostile) server, or seal their escrow to the wrong key?*

**The guarantee that holds (both breakers confirmed sound):** a member who types the fingerprint
from a **genuine printed sheet** cannot have their escrow redirected. `Account.enroll` computes
`fingerprint(recoveryPublicKey)` from the server's `/recovery-pubkey` and **refuses to seal the
UVK unless it equals the fingerprint the member verified** (account.ts:110-113, Account.kt:227-241;
F57 re-seal too). So a hostile server either serves the REAL recovery pubkey (→ escrow seals to
the household key it cannot decrypt) or its own (→ `computedFp ≠ verifiedFp` → enroll refuses).
Escrow integrity does not depend on the QR at all.

**What the QR does NOT establish: server identity.** The `f` fingerprint-commitment idea from v1
is DROPPED. `GET /api/v1/client-policy` serves the org `recoveryFingerprint` **unauthenticated**
(App.kt:270-273) — it is a public value. A competent hostile origin simply serves the real
fingerprint, so a QR-carried `f` would match the enrollee's live `/client-policy` fp AND the
member's sheet-16 would match the echoed value — both "checks" pass while the server is the
attacker's. `f` therefore stops only a *lazy/misconfigured* substitution; against a real attacker
it is theater, and it is a foot-gun (one "prefill everything" refactor would auto-seed the
sheet-typing field from `f`, collapsing the ceremony into verifying the QR against itself — the
exact failure the exploration doc warned of). It is also the second-largest payload field. Gone.

**So where does origin authenticity come from? Network trust.** The member's device reaches the
correct server because it is on the **household tailnet/LAN** and the QR encodes that private
origin. A member NOT on the household network cannot reach the private origin at all (register is
private-origin-only server-side, App.kt:315) — the flow simply fails closed rather than enrolling
somewhere wrong. The residual risk the design accepts and states plainly: if a member is tricked
into enrolling a **new** account against a hostile origin they can reach (e.g. a public
attacker origin, with a real co-located sheet echoing the real fp), the attacker gains that
member's `authKey` + `wrappedUvk` (an offline master-password oracle) and hosts their future
secrets — **but not their escrow, and not any existing account** (a fresh device has none). This
is a network-trust failure, not a QR failure; S4's job is to make the target origin **visible and
consented**, never silent (see Consume semantics).

**Remote members (out of scope, stated so the owner doesn't improvise):** the sheet ceremony
needs the physical sheet. For an absent member the owner would have to read the fingerprint off
their **mint screen** — and a compromised-later server shows the *attacker's* fingerprint there,
which the member would then dutifully "verify," sealing escrow to the attacker. The only safe
remote path is the owner reading the fingerprint from the **printed paper** over an independent
channel (a phone call), which S4 does not automate. **Do not build remote onboarding on this.**

## The link format (v2) — one artifact, three consumers

```
https://<private-origin>/enroll#a1.<b64url(payload-json)>
```
payload JSON (compact): `{"v":1,"o":"https://<private-origin>","t":"<invite-token>","e":"<bound-email>"}`

- **No `f`.** No key material, no password, no seeds. The only secret is `t` (43-char b64url of
  256 random bits; server stores only its sha256), exactly as secret as today's hand-delivered
  token.
- **`t` rides ONLY in the fragment** — never sent to the server, never in Referer/proxy logs. The
  web consumer strips it via `history.replaceState` the instant it is captured.
- **`o`** is the owner's `location.origin` at mint (verbatim; no trailing slash — matches
  `location.origin` exactly). Web cross-checks `payload.o === location.origin` and refuses on
  mismatch. Native uses it as the transient enroll origin (see Consume semantics) — never
  persisted until success.
- **`e`** is the server-BOUND email (`invite_email_mismatch` if register disagrees,
  Service.kt:101, case-insensitive) → prefilled **read-only**, with "wrong address? ask for a new
  invite" copy.

**Parser contract — TOTAL and byte-identical across the core-Kotlin and web-TS twins**
(`EnrollLink.compose`/`parse`, pinned to `spec/vectors/enrolllink.json`):
- Any malformed input returns null (never throws) — this runs in UI layers on three platforms; a
  throwing parser is a crash primitive (the BUG-0 lesson, applied up front).
- **Normalization before decode (breaker impl-1):** strip ALL whitespace from the fragment body
  (chat apps hard-wrap; b64url never legitimately contains whitespace), then strip any `=`
  padding, then decode. Both twins do the identical strip so a padded or wrapped link parses the
  same on all three clients. (Core `Bytes` decode accepts padded-or-unpadded; web libsodium
  `URLSAFE_NO_PADDING` rejects `=` — the strip removes the divergence.)
- **`ignoreUnknownKeys = true` on the Kotlin twin** (kotlinx `Json` defaults to false → throws on
  a forward-compat extra key while JS `JSON.parse` ignores it — a silent twin divergence).
  Duplicate keys: JS last-wins, kotlinx rejects → the vectors pin a duplicate-key row and both
  MUST agree (simplest: both reject → parse null).
- Vector rows: round-trips + hostile (bad prefix, bad b64, truncated JSON, **padded b64url**,
  **unknown key**, **duplicate key**, **internal whitespace**, non-https origin — with the http
  LAN-cleartext exception, oversized fields, unicode/Turkish-İ email, empty token). Parse returns
  null on every hostile row, both impls. (fp length is moot now — `f` is gone.)

## Consume semantics (the FATAL fix — NORMATIVE, not aspirational)

The v1 draft said "call `setBaseUrl(payload.o)`" — which **eagerly persists** `store.baseUrl` and
**overwrites process policy** (autolock/serverTime/cache) from the link's server. Combined with
the ceremony-free Sign-in tab, that is a drive-by phishing setup (breaker trust-FATAL). The rules
below are mandatory on all clients:

1. **Transient origin only.** A link's origin lives ONLY in a transient `pendingEnrollLink`
   (UiState on natives, module singleton on web). It is used solely as the base URL for THIS
   enrollment's probe + register. **`store.baseUrl` / persisted prefs are written ONLY inside the
   successful `register()` path.** On dismiss/abandon/failure, nothing was persisted, so nothing
   needs restoring. Do NOT call the eager `setBaseUrl`/`updateServer` on arrival.
2. **No policy mutation from a link.** The link path must NOT run `applyPolicy`/`purgeOfflineData`
   against process state. Fetch the link origin's `/client-policy` into a **transient** holder
   used only to render the fingerprint for the typed gate and to supply kdf params to
   `Account.enroll` — never write it over the live user's `autoLockSeconds`/`serverTimeFloor`/
   cache. (Desktop MUST do this fetch explicitly — `updateServer` never refetched policy, so the
   typed gate would otherwise compare the sheet against a STALE server's fp; breaker impl-3.)
3. **Session-absence gate at CONSUME time, not screen.** Honor a link ONLY when
   `store.load() == null` (no persisted session), evaluated AFTER `start()` resolves (a cold
   start THROUGH the intent is in `Screen.Loading`, not `Welcome`, when the intent arrives — a
   screen check is racy; breaker trust-3). If a session exists: drop the link with **zero side
   effects** and show "signed in as X — sign out to enroll a new account." Never process a link
   while an enrollment is already in progress without explicit re-consent.
4. **Explicit origin consent.** The link does not auto-advance into a prefilled form. It shows a
   confirm step naming the origin — **"Set up a new andvari account at `<origin>`?"** — and only
   an explicit tap proceeds. A silent `andvari://` navigation from a hostile page thus cannot
   stage anything the user didn't see and accept.
5. **One-shot (Android stale-intent, breaker impl-5).** After consuming an intent, call
   `setIntent(Intent())` so a process-death recreation's `getIntent()` is a no-op — else an
   abandoned/spent link resurrects on every relaunch. Consume in BOTH `onCreate` and
   `onNewIntent`. `pendingEnrollLink` is consume-once in UiState (clear on first apply) so a
   re-firing `LaunchedEffect` can't re-clobber user edits or re-force the Enroll tab (breaker
   minor).
6. **Prefilled token is non-saveable (breaker minor).** Read token/email directly from
   `pendingEnrollLink`; do not copy the single-use token into `rememberSaveable` (it serializes
   into the Activity's saved-instance Bundle held by system_server).

## Android reality (system-camera + scheme, no in-app scanner)

- Private origin is tailnet/LAN-only; verified App Links can't auto-verify against it (the
  verifier can't fetch assetlinks from a tailnet host). **v1 declares NO autoVerify https
  filter** — only the `andvari` scheme (`VIEW`+`DEFAULT`+`BROWSABLE`). Path: system camera →
  https link opens in browser → Welcome shows **Open in the andvari app** (`andvari://`, same
  payload) → app opens. One scan + one tap, zero permissions, zero deps, every Android version.
  We still ship `assetlinks.json` (future public hostname), just no https filter yet.
- `launchMode`: use **`singleTop`** (delivers `onNewIntent` when the instance is on top — the
  deep-link case — without `singleTask`'s task-affinity/Recents surprises next to the autofill
  activities; breaker minor). Add `getIntent()` handling in `onCreate` + an `onNewIntent`
  override (neither exists today).
- assetlinks.json: `package_name` **`com.silencelen.andvari`** (the applicationId,
  build.gradle.kts:24 — NOT the source package `io.silencelen.andvari.app`), cert SHA-256
  `DB:89:12:87:8E:19:A5:46:80:76:47:FE:DE:95:E8:19:1B:95:DF:76:C2:F3:0D:3E:07:70:30:4C:BF:0E:A2:F6`
  (v2-signed, alias `andvari-release`).
- Prefill has no VM channel today (enroll fields are local `rememberSaveable`) — hoist
  `pendingEnrollLink` into UiState and force the Welcome tab to Enroll (defaults to Sign-in).

## Server work (small)

1. **Short-TTL invites for QR minting** — `createInvite` hardcodes 72 h (`inviteTtlMs`,
   AdminService.kt:13). Add optional `ttlMinutes` to `InviteRequest`; server clamps to
   **[5 min, 72 h]**; absent → 72 h (existing button unchanged). **QR TTL = 60 min** (breaker
   minor: 15 min is shorter than a real install-APK + join-network + scan + set-password +
   type-sheet flow → owners would flee to the 72 h button and lose the containment; 60 fits the
   co-located flow with margin). There is NO invite list/revoke surface — TTL is the only
   containment for a photographed QR. **v1 surfaces the lifetime as copy** ("valid for about 60
   minutes (expires …)") next to the QR rather than a live ticking countdown — a co-located
   enrollment completes in minutes, so a static lifetime + the absolute expiry is honest and
   adequate; a serverTime-anchored ticking countdown is a deferred polish (would thread the live
   policy into `InviteForm`).
2. **Block minting a QR on the public origin (breaker impl-4).** `requireAdmin` (App.kt:717) has
   NO public-origin guard (unlike `sharingPrincipal`, App.kt:707), so a break-glass admin CAN
   mint — and the QR would encode the public origin, which `register` refuses at the LAST step
   (a fully-completed-then-rejected ceremony). Cheapest correct fix: the mint UI refuses to
   compose a QR when `location.origin` is the public hostname ("mint from the private/LAN
   address"). (Optionally also add the guard to the admin route; client block is sufficient for
   v1 since the QR is the only new surface.)
3. **`/.well-known/assetlinks.json`** — no route: the SPA catch-all serves any real file under
   `webDir` with the right content-type (absent → index.html **HTTP 200**, never 404). Ship the
   file in the bundle. **Build assertion (breaker minor):** dot-directories are skipped by some
   copy globs — add an e2e/route check that `/.well-known/assetlinks.json` returns
   `application/json`, not index.html. Non-blocking for v1 (no https filter) but cheap.
4. **Riding fix:** map `invite_email_mismatch` to friendly copy (web Welcome.tsx:380-389 misses
   it; natives equivalent).
5. Register/enroll wire format UNCHANGED. `/enroll` already serves the SPA (catch-all).

## Client work

- **Web Admin** (extend `InviteForm`, Admin.tsx:255-314): after mint (dropping `f` means no
  policy/fingerprint is needed here at all),
  compose the link from `location.origin`+`result.inviteToken`+`result.email` → render `QrSvg`
  (`qrModules(url,"M")`, the TOTP/devstore pattern) + copy-link + the 60-min lifetime copy + the
  co-located ceremony line ("hand them the printed sheet in person — the app asks for its first
  16 characters"). **Wrap `qrModules` in try/catch (breaker minor):** the vendored encoder
  `throw`s a bare string on overflow → white-screens Admin; fall back to copy-link-only. Refuse
  to compose on the public origin (§Server 2).
- **Web Welcome:** capture the fragment at **main.tsx module load** into a module singleton, call
  `replaceState` exactly once, guarded (breaker impl-7 — a component `useEffect` double-fires
  under StrictMode and the second pass reads an already-wiped hash → prefill lost; and a
  has-session boot goes straight to Unlock, never mounting FreshStart, silently dropping the
  payload). If a payload was captured but a session exists → notice, don't silently drop. Origin
  consent step → `payload.o===location.origin` check → force enroll tab → prefill token + email
  (read-only) → unchanged password + **typed-sheet** steps.
- **Android:** `andvari` scheme intent-filter + `singleTop` + `getIntent`/`onNewIntent` + one-shot
  `setIntent` → core parse → `pendingEnrollLink` in UiState (consume-once) → session-absence gate
  → origin-consent → transient-origin enroll (persist baseUrl only on register success). **Fold
  in the layer-2 fix:** replace the display+checkbox fingerprint with the web's **typed
  short-form gate** (`Escrow.shortFormMatches`, already used by F57 re-seal cards). **Raise the
  master-password floor to F60 score≥3** (natives accept length≥8 today — the weakest link under
  this threat model; breaker minor). **This platform must not merge prefill without its typed
  gate in the same cut** (breaker impl-8 — easier-enroll + checkbox-theater is strictly worse
  than today).
- **Desktop:** paste-link box on Welcome (above the tabs; flips to Enroll on valid parse) → strip
  whitespace → shared core parser → **explicitly refetch `/client-policy` for `payload.o` and
  disable submit until it resolves** (breaker impl-3) → transient-origin enroll. Same typed-gate
  fold-in + F60 floor + atomic coupling as Android.
- **invite_used is NOT an alarm (breaker minor):** a second family device scanning the same QR is
  benign; on `invite_used` from a link-driven enroll, offer "Already set up this account? Use Sign
  in," not a security warning.
- **Cut from S4** (recorded): the Admin per-member setup checklist (P1's second half) — that is
  the Steward-panel horizon (ROADMAP:230), its own cycle. S4 is the enrollment artifact only.

## Tests & gates

- `spec/vectors/enrolllink.json` (above) — the divergence tripwire, both impls.
- Web: module-load capture unit test (pure fn); Admin compose test (incl. public-origin refusal +
  qr-overflow fallback); origin-mismatch refusal; has-session-drops-with-notice.
- Android/desktop: parse unit test; session-absence + one-shot-intent guard test; **per-platform
  welcome-enroll test asserting the create button stays disabled until
  `shortFormMatches(entry,fp)` is true** (the atomic-coupling tripwire).
- Server: `ttlMinutes` clamp bounds + single-use atomicity **regression test** (the property is
  sound — Db.tx serializes — but untested); assetlinks content-type route test; invite_email_
  mismatch copy.
- Gates: verify.sh (file-logged exits) + `:app-desktop:classes` by hand + e2e.sh (server changed).

## Scope split — v1 is WEB-ONLY (the risk/value call)

The breaker pass made the shape of the risk clear: the native `andvari://` handler carries the
ENTIRE drive-by attack surface (the FATAL, all the consume-semantics machinery, a new exported
deep-link on a currently-clean single-activity app) and is the THINNEST-value part — a member who
scans the QR lands in a prefilled **web** Welcome, and the web client is a full client over the
tailnet, so the native app is not needed to enroll; its value (autofill/biometric) comes after
enrollment via ordinary sign-in. The native handler would only save typing the server URL into
ServerField once. So:

- **v1 (this cut, WEB + SERVER only, deploys to CT122):** Admin QR + copy-link + 60-min TTL;
  web Welcome module-load capture + prefill (read-only email) + origin-consent + has-session
  notice; the core+web **parser twins + shared vectors** (format pinned now so the future native
  consumer is pure UI wiring); server `ttlMinutes` clamp + `assetlinks.json` in the bundle +
  `invite_email_mismatch` copy. **No native code, no manifest change, no version bump** (web
  `CLIENT_VERSION` stays 0.10.0 — additive, no wire/behavior change to the native contract).
- **DEFERRED (designed here, not built): native `andvari://` deep-link consumption** — build it
  only if the web slice proves the value warrants the surface; the consume-semantics section
  above is its spec. **Also deferred: the native typed-sheet fingerprint fix + F60 floor** — a
  real spec-04-§2(3) security improvement, but INDEPENDENT of the web slice (web already has the
  typed gate, so shipping web prefill does not raise any native layer-2 load). It deserves its
  own focused, separately-reviewed native cut; flagged as the next security item, not smuggled
  into an onboarding cut.

## Known-divergence, deferred to the native-mint cut (not reachable in web-only v1)

`EnrollLink.compose` (the Kotlin twin) and `composeEnrollLink` (web) diverge on ONE pathological
input: an email carrying an unpaired UTF-16 surrogate. Kotlin's `encodeToByteArray` replaces it
with `?` (mint corrupts the email); web's `JSON.stringify` emits a `\uXXXX` escape that
round-trips. This is **unreachable in v1** — minting is web-only, and the email is server-bound
(the server never issues a lone-surrogate email). It MUST be pinned before native minting ships
(both twins refuse, or both document a well-formed-UTF-16 precondition + a parity vector). Filed
here so the native-mint cut can't forget it. Found by the S4 review (LOW), verified by an
independent JVM repro against the compiled artifact.

## Ship shape (v1)

Web + server only → **no version bump**; deploy at the checkpoint snapshot-first (real script
scp'd, `VACUUM INTO`+integrity_check; **vzdump — the server jar changes** for `ttlMinutes`);
served-bytes verification (local `web/dist` bundle hash == served; item count survives). The
BUG-0 fix batch (`df1092f`) is native-and-web — its web part (the errors-table cap) rides this
web deploy; its native part waits for the next native cut.

## Reorder rationale (S4 before S3) — for the plan doc

S3 (extension in-page card fill) has **zero exercisable value today**: card-create is dark on
every client (`CARD_CREATE_ENABLED=false` web/src/vault/card.ts:24, `CardDisplay.CREATE_ENABLED=false`
core .../CardDisplay.kt:27, both test-pinned) until the owner retires the 0.2.x MSI (an owner
step, no ETA), so the household can hold no card items for the extension to fill; the S3 design
further excludes cross-origin PSP iframes (most real checkouts). S4's value is live the day it
ships and is needed BEFORE the family enrolls at the real-secrets migration. S3 is not cancelled —
next after S4; its design doc + breaker discipline carry unchanged (its version note is stale:
extension is 0.9.0 now).
