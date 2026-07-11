# E1 — extension hardening (design, 2026-07-11) → extension 0.10.0

> Input: 13 adversarially-verified findings (2026-07-11 recon, refuter-confirmed at HEAD
> `7edfdb0`), folded into 10 work items (extux-02+exttech-1 = one clipboard item;
> extux-04+extux-05+exttech-5 = one taxonomy item). Scope: `extension/` + doc truth fixes.
> **Zero server changes, zero web/core/native code changes.** The extension versions
> independently: this cut is 0.9.0 → 0.10.0.

## Ground truth

The extension predates three fleet-wide hardening waves and missed all of them: the 2026-07-09
TOTP determinism fixes (web+core only), the F26/F31/error-taxonomy UX canon (web+natives), and
the spec-03 client-identification contract (it sends no `X-Andvari-Client` at all — the server
files it as `unknown/0.0.0`, so the 426 min-version control structurally cannot reach it, and
`docs/drills/426-min-version-drill.md:64-66` even asserts header-less callers don't exist).
It also never clears the clipboard (spec 01 §8 :357-359 is a MUST "on every client"), never
runs the spec 01 §5 identityPub derive-and-compare (spec/01:76-85; core and web both hard-fail),
and kills its refresh-token pair on transient failures where web keeps it (client.ts:215-221).

## Work items

### E1-1 — identityPub derive-and-compare (spec01-ext-idpub-check, P2)

- **Now:** `background.ts` unlock() derives the identity keypair from the UVK-sealed seed
  (:504) and never reads `s.accountKeys.identityPub` (typed api.ts:19, zero usages).
- **Target:** immediately after :504, decode the server value defensively and hard-fail on any
  mismatch — mirror `web/src/vault/account.ts:157-174` exactly, including malformed-b64 →
  treated as mismatch (garbage where the identity key belongs IS the tampering this names).
  No `ctEquals` in extension crypto.ts; a length check + byte loop is fine (client-side, the
  compared value is server-supplied — timing is not load-bearing). Throw a local
  `IdentityMismatchError` sentinel; unlock aborts BEFORE sync/decrypt and never persists a
  session. The dispatch mapping (E1-3) carries it to the popup as code `identity_mismatch` —
  it must NEVER render as wrong-password.
- **Reference copy** (web account.ts:42, rendered verbatim by the popup):
  *"Server identity key mismatch — possible tampering. Do not proceed; contact your admin."*

### E1-2 — X-Andvari-Client + minimal 426 surface (extux-01, P2)

- **Now:** api.ts builds only content-type/authorization (:109-116 json(), :144-148
  doRefresh) — no client header anywhere; login registers device platform `"web"` (:174);
  a 426 would render as raw JSON (E1-3's problem) and can't even be targeted (unknown/0.0.0,
  Auth.kt:28; pins key on the header platform, Auth.kt:104-107).
- **Target:** both fetch sites send `X-Andvari-Client: extension/<version>`. Version comes
  from `chrome.runtime.getManifest().version` passed INTO the client
  (`new AndvariApi(SERVER_URL, chrome.runtime.getManifest().version)`) so api.ts stays
  chrome-free and node-testable. **Platform token = `extension`** (decision 2). The device
  row keeps `platform:"web"` (decision 3).
- **426 surface (minimal, mirrors web App.tsx:211-226 semantics):** api.ts gains
  `onUpgradeRequired` fired from the new error parse when body code = `upgrade_required`
  (web client.ts:252 parity); the refused call still throws unchanged. background.ts wires it
  to `void checkForUpdate(true)` — the EXISTING self-update banner (popup.ts:100-121, SW-side
  checkForUpdate :326-348) is the download surface, and a pin should only ever name a
  published build, so the banner materializes with the right zip link. The popup additionally
  maps unlock-time code `upgrade_required` to its own sentence (E1-3 table) so the user is
  told even before the banner lands. No new persistent state (decision 4).
- **Doc fixes (same item):** spec/03-wire-protocol.md:9-10 enum gains `extension`
  (doc-only — Auth.kt already accepts any token, see decision 2);
  docs/drills/426-min-version-drill.md:64-66 footgun rewritten (the "no shipped client is
  header-less" claim is false for ≤0.9.0 extensions; pinning `extension` gates 0.10.0+,
  pinning `unknown` bans ≤0.9.0 installs outright) and the drill gains an extension step
  ([breaker-corrected] pin `extension` above current → the gate fires at the next UNLOCK
  (lock first, or use a locked profile — a live unlocked session keeps syncing/saving,
  see decision 3); popup shows the upgrade sentence; the update BANNER additionally appears
  only if a strictly-newer build is actually published to /downloads; unpin → recovers).

### E1-3 — error taxonomy: codes in the engine, copy in the surfaces (extux-04 + exttech-5 + extux-05, P2)

- **Now:** ApiError message = `andvari api <status>: <raw body>` (api.ts:121, :191-198); the
  dispatch catch stringifies (background.ts:157-161); popup unlockError() special-cases only
  `/fetch|network/i` (popup.ts:622-626) — a typoed master password renders raw JSON, and
  426/429/500 are indistinguishable; the ping button prints `server: Error: TypeError: …`
  (popup.ts:679-681).
- **Target, three layers:**
  1. **api.ts** parses the server's `{error, message}` body on !ok and constructs
     `ApiError(status, code, message)` — web `throwApiError` parity (client.ts:242-254),
     including the `http_<status>` / statusText fallbacks for non-JSON bodies.
  2. **background.ts** wraps the `unlock` dispatch in a mapper → `Res<"unlock">` gains
     `code` (contract below): ApiError 401 → `bad_credentials` (except body code
     `totp_required` → `totp_required`); body code `upgrade_required` → `upgrade_required`;
     other ApiError → `server_error`; `IdentityMismatchError` → `identity_mismatch`;
     `TypeError` (fetch rejection — web errors.ts:26-33 convention) → `network`; anything
     else → `unknown`. The raw `String(e)` may ride `error` as debug detail; surfaces never
     render it (decision 6).
  3. **popup.ts** maps codes to web's exact FreshStart ladder (Welcome.tsx:207-227 — the
     extension flow is a full sign-in, not the unlock-gate): `bad_credentials` → *"Wrong
     email or master password."*; `server_error` → *"The server had a problem answering —
     your details may be fine. Try again in a moment."*; `network` → UNREACHABLE (verbatim
     web errors.ts:36: *"Can't reach the andvari server — check you're on the home network
     or VPN, then try again."* — duplicated as a const, no build path to web/src exists);
     `identity_mismatch` → the E1-1 sentence; `upgrade_required` → [breaker-corrected]
     *"Your server requires a newer extension — get the update from the web vault or the
     link above."* (the banner exists only when a strictly-newer build is PUBLISHED —
     isNewerVersion vs /downloads — so copy must not hard-promise it; see amendment AM5);
     `totp_required` → *"This account
     requires a one-time code — sign in from the web vault."* (the popup has no TOTP field;
     decision 7); `unknown`/absent → *"Sign-in failed. Please try again."*. The ping
     failure branch (popup.ts:680) and the network branch drop raw exception text and use
     UNREACHABLE. Copy + mapping live in a NEW chrome-free `extension/src/errors.ts` so
     node --test pins every string (test plan).

### E1-4 — clipboard auto-clear (extux-02 + exttech-1, P2, the one M-sized item)

- **Now:** no clear anywhere. popup toClipboard (:399-407) serves password (:423-430), TOTP
  (:453-460), card number/expiry/CVV (:559-566), generated pw (:602-611), username;
  content copyTotp (:88-95) is the post-fill 2FA copy. `clipboardClearSeconds` is typed
  (api.ts:85) and never read. Spec 01 §8 (:357-359): auto-clear after policy seconds, clamp
  min 1 s, policy 0 still clears, on every client. Web reference: Vault.tsx:821-833 useCopy —
  `setTimeout(() => clipboard.writeText("").catch(...), Math.max(1, clearSeconds) * 1000)`,
  an unconditional (blind) clear; the ==value-guarded clear is the desktop JVM variant only.
- **MV3 honesty:** the dominant flow is copy-in-popup → click into the page → **Chrome closes
  the popup** → paste. A popup-local timer therefore almost never survives to perform the
  clear. The SW cannot touch the clipboard (no document; `navigator.clipboard` is
  Window-scoped). The mechanism must live where a document exists:
- **Target — layered best-effort clear:**
  1. **Local precise timer at each copy site** (web-parity semantics): popup toClipboard()
     and content copyTotp() schedule `setTimeout(writeText(""), Math.max(1, s) * 1000)` after
     a successful copy. Covers popup-still-open and the common in-page case (the target page
     holds focus after the paste). All `.catch(() => {})` — never a user-facing error.
  2. **SW backstop that survives popup close:** after every successful clipboard write, the
     copying surface sends the new `scheduleClipboardClear` message; the SW arms a single
     `"clipboardclear"` alarm (`delayInMinutes: Math.max(s / 60, 0.5)` — same 30 s floor
     pattern as armAutoLock :282; [breaker-corrected] a sub-30 s policy is covered by
     layer 1 only while the copying document survives — once the popup closes, the backstop
     clears at ~30 s, later than policy; see amendment AM7). On
     fire, the SW clears via the platform path:
     - **Chrome:** an offscreen document (`chrome.offscreen.createDocument`, reason
       `CLIPBOARD`, justification "clear copied secret") — the async Clipboard API refuses
       unfocused documents and offscreen docs are never focused, so the clear is a
       textarea + `document.execCommand("copy")` write. [breaker-corrected] The write is a
       SINGLE SPACE, not the empty string, and executes on EVERY alarm fire (message-driven
       or close-then-recreate — never clear-on-load behind a create-if-absent guard): see
       BLOCKER B1. SW closes the document after the clear completes. New files
       `extension/src/offscreen.ts` + `extension/offscreen.html`, new build entry.
     - **Firefox:** no offscreen API — but `manifest.firefox.json` runs background.js as an
       EVENT PAGE (a real document): clear directly with `navigator.clipboard.writeText("")`
       (the new `clipboardWrite` permission lifts the gesture/focus requirement), execCommand
       fallback. Branch on `chrome.offscreen` availability.
     The alarm deliberately survives doLock (:267-268 clears only autolock/resync) — a
     secret copied just before an idle lock still clears on schedule.
  3. **Policy plumbing:** unlock()'s existing clientPolicy fetch (:536-544) also captures
     `clipboardClearSeconds` (finite ≥ 0, else default 30) into module state + the
     SessionSnapshot (:111-120, :242-253, restore :231). `Res<"scheduleClipboardClear">`
     returns the effective seconds so surfaces need no separate plumbing; locked/absent →
     default 30 (clearing is safety-positive regardless).
- **Blind clear, no ==value guard** (decision 9). Uniform for ALL copies including username —
  web clears uniformly through its one useCopy path.
- **Doc fix (same item):** docs/design/2026-07-09-cards-wallet.md:149 falsely claims the
  extension copy path has a clear-timer — amend with a dated correction note pointing here.

### E1-5 — locked-save banner copy + re-offer after unlock (extux-03, P2)

- **Now:** the save banner's red result line literally renders the SW's internal strings —
  `"locked"` (background.ts:807) and `` `save failed (conflict)` `` (:876, :890) — because
  content.ts:229's friendly `??` fallback only fires on undefined. After unlock, the pending
  save survives SW-side but nothing re-offers it: the only paths are tabs.onUpdated
  "complete" (:190-203) and the content-script init poll (:331-336), both requiring
  navigation.
- **Target:** `Res<"resolvePendingSave">` gains `code: "locked" | "conflict" | "failed"`
  (locked :807; MutationResult status "conflict"; everything else — denied/duplicate/no-vk/
  thrown push — "failed"). content.ts offerBanner maps codes and NEVER renders `r.error`:
  locked → the existing *"Could not save — unlock andvari and try again."*; conflict →
  *"This login changed elsewhere — open it in the web vault."*; failed/undefined →
  *"Could not save — try again."*. content-ui.ts is untouched (it already takes the text).
  And at the end of background unlock() (after persistSession :546), iterate `tabs` entries
  holding a pending save and `chrome.tabs.sendMessage(tabId, { type: "offerPendingSave",
  pending: publicPending(p) })` with the same try/catch-uninjected pattern as :196-201 — the
  banner returns without a reload.

### E1-6 — mustChangePassword nudge (extux-06, P2)

- **Now:** the login response carries `mustChangePassword` (Service.kt:1045; set by rescue,
  cleared only by a password change :247) — the extension's SessionResponse omits it
  (api.ts:21-27), so a rescued member re-logging in with the admin-known temporary password
  gets a nudge-free session. Web classifies this CRITICAL-DIRECT (always-visible banner,
  Vault.tsx:394-399; ia-cut2 doc :99).
- **Target:** api.ts SessionResponse gains `mustChangePassword?: boolean`; background unlock()
  captures it (:499), it joins Session + SessionSnapshot (survives SW death) and the `status`
  reply. Popup: a persistent NON-dismissable strip in the unlocked view (the update-banner
  idiom, popup.html), copy adapted from web Vault.tsx:396 because the extension cannot change
  the password itself: *"Recovery sign-in — set a new master password in the web vault."*,
  click → the existing open-vault action (popup.ts:670-673). Cleared only by a fresh unlock
  whose response no longer carries the flag.

### E1-7 — F26 lock-reason line (extux-07, P3)

- **Now:** a popup opened after an idle autolock shows the bare unlock form (refresh()
  :77-95); only the live-popup relock path shows a reason-free line (:135-138). doLock
  (:260-277) records nothing.
- **Target:** doLock takes a reason (`"idle"` from the autolock alarm :165, `"manual"`
  otherwise). Idle lock writes `{ kind: "idle", seconds: autoLockSeconds-at-lock }` to
  storage.session under its own key AFTER the :266 remove; manual lock clears it (web parity:
  App.tsx:209 passes a notice only from useAutoLock). `Res<"status">` gains
  `lockNotice: { kind: "idle"; seconds: number } | null`; popup refresh() renders it via
  showMsg("info", …) above the unlock form — no popup.html change — using a verbatim port of
  web `inactivityNotice` (format.ts:21-28: *"Locked after N minutes of inactivity."*;
  [breaker-corrected] the seconds form appears ONLY below 60 s — anything ≥ 60 s renders as
  `Math.round(seconds/60)` whole minutes, so 90 s → "2 minutes"; see amendment AM3), living
  in the new errors.ts. Cleared on successful unlock
  (key removed in unlock()); browser exit clears storage.session anyway, so no stale notice.

### E1-8 — TOTP determinism backport (exttech-2, P2)

- **Now:** extension/src/totp.ts is the pre-0.8.0 port (untouched since 0.6.1) and diverges
  from web/core on five 2026-07-09 fixes — same stored URI, different outcome per client:
  `\s` base32 stripping (:21), partial-parse percent hex (:106-107, `%1G` → 0x01),
  `fatal:true` label decode (:115, throws where twins accept — hides the chip via
  background.ts:441-443 and drops totpCode from reveal :650-653), `parseInt(x)||default`
  digits/period (:144-145, `digits=8x` → 8 here vs 6 on web/Android), no empty-secret gate.
- **Target:** backport web/src/crypto/totp.ts (post-863a0e2) mechanically:
  `BASE32_IGNORED = /[= \t\n\v\f\r]/g` (web :13); `toIntOrNull`/`hexOrNull` ports (web
  :95-106), hexOrNull in percentDecode; lenient `TextDecoder` (web :130); strict
  digits/period = `toIntOrNull(...) ?? default` + explicit range throws (web :185-188);
  empty-secret rejection after base32Decode (web :181-182). `totpCode`/`base32Encode`/
  `currentCode` are already parity — untouched. The extension gains its own execution of
  `spec/test-vectors/totp.json` (test plan) — the same vectors web/core run, closing "all
  impls run totp.json" (totp.ts:8 header claim, currently false for this port).

### E1-9 — refresh: transient failures keep the pair (exttech-3, P3)

- **Now:** doRefresh (api.ts:139-158) nulls the refresh token pre-flight and returns false on
  ANY failure with no restore and no persist — a 503/network blip dead-ends the SW life
  (silent resync stall, saves 401), while the storage.session snapshot (persisted only via
  onTokensRotated, background.ts:144) still holds the CONSUMED pair and resurrects it on the
  next SW wake — if the failed rotation actually landed server-side, that replay is
  `refresh_reuse` and revokes the whole device. Web kills the pair only on definitive 401/403
  (client.ts:215-221).
- **Target:** web's transient-keep semantics, adapted to snapshot reality (we deliberately
  EXCEED web here because the SW has a persistence layer web's in-memory client doesn't):
  1. replace `onTokensRotated` with ONE awaited callback
     `onTokensChanged: (() => void | Promise<void>) | null`, fired on every pair mutation;
  2. doRefresh consumes the token, then `await onTokensChanged?.()` BEFORE the POST — a SW
     death mid-refresh can no longer resurrect a spent token;
  3. on 401/403: clear BOTH tokens, notify (web :220 parity — the pair is dead);
  4. on any other !ok or a thrown fetch: RESTORE `this.refreshToken = rt`, notify — one blip
     no longer dead-ends the session;
  5. on success: set pair, notify (as today).
  background.ts wires `api.onTokensChanged = () => persistSession()` (persistSession returns
  its storage.set promise; existing callers keep ignoring it). Note persistSession's
  `if (!session) return` guard: during unlock the tokens are set before session exists
  (:500 vs :532), but no refresh can run mid-login, so the guard is safe — state this in a
  comment rather than reordering unlock.

### E1-10 — drop the unused "scripting" permission (exttech-4, P3)

- **Now:** both manifests request `"scripting"` (manifest.json:6, manifest.firefox.json:9);
  zero `chrome.scripting` calls in src or dist. Content scripts are statically declared
  (manifest.json:25-33).
- **Target:** delete it from both permission arrays. **Load-time effect: none** — static
  content-script injection, storage/alarms/activeTab usage, and the popup are all independent
  of "scripting"; removal cannot break load or runtime (verified: the other three permissions
  are each used). Net permission delta for 0.10.0: `-scripting` (both), `+offscreen`
  (Chrome, E1-4), `+clipboardWrite` (Firefox, E1-4).

## Decisions

1. **Platform token = `extension`, not `web`.** Auth.kt clientId() (:27-31) parses ANY
   `<platform>/<semver>` — no enum validation — and enforceMinVersion (:104-107) is
   `policy.minVersion[client.platform] ?: return`: an unknown platform simply has no pin
   until the owner sets `minVersion["extension"]`. Zero server changes. Riding `web` is
   broken by construction: web is at 0.14.x while the extension is at 0.10.x — any honest web
   pin would permanently 426 every extension. spec/03 §1's enum is amended as a doc edit.
2. **Device row keeps `platform:"web"`** (api.ts:174). Pins read the header, not the device
   row; renaming the row is a server-visible behavior change (and possible enum validation)
   this cycle forbids. Recorded as a known cosmetic mismatch.
3. **426 state is derived, never stored.** `onUpgradeRequired` → `checkForUpdate(true)`; the
   existing update banner is the surface; [breaker-corrected] the pin re-manifests on every
   GATED call — the fielded server runs `enforceVersion` only on register + login
   (App.kt:317, :327) and the §10/§11 sharing/lifecycle preamble (App.kt sharingPrincipal),
   NONE of which the extension calls except login — so for the extension the pin manifests
   exactly at unlock; sync/push/refresh are ungated and a live unlocked session sails on
   under a pin until its next unlock (see amendment AM4). A stored flag would still only add
   staleness. Mirrors web's side-channel-nudge posture (client.ts:120,
   App.tsx:211-226) with "download and reload the unpacked build" standing in for web's
   one-click Reload.
4. **Codes cross the message seam; copy lives only in the surfaces.** background.ts never
   ships user-facing sentences (its current `"locked"` leak is exactly this bug); popup.ts +
   content.ts render from `extension/src/errors.ts`. The `error` field survives as debug
   detail that surfaces never render.
5. **429 folds into `server_error`** — strict Welcome-ladder parity; bespoke rate-limit copy
   would be a new cross-client drift class. Accepted artifact.
6. **`totp_required` gets copy, not a field.** Cannot fire on the tailnet origin today
   (spec 03 §2 makes server-TOTP mandatory only via the public origin) but the code exists on
   the wire and server-TOTP enrollment is the migration blocker — the popup must not render
   raw JSON the day it fires. A TOTP input in the popup is out of scope (A1 territory).
7. **identityPub mismatch is a hard security fault**: abort before any vault material is
   decrypted, distinct code + web's exact sentence, never softened into wrong-password —
   including the malformed-identityPub case (account.ts:161-174 semantics).
8. **Clipboard clear mechanism under SW eviction** = local timers (web-exact semantics) + SW
   alarm backstop with offscreen-doc (Chrome) / event-page-direct (Firefox) writes — see
   E1-4. The popup-only timer was rejected as dishonest: Chrome closes the popup on focus
   loss, so it nearly never survives to clear.
9. **Blind clear, no ==value guard.** Reading the clipboard to guard the clear needs the
   `clipboardRead` permission — strictly worse privilege than the guard is worth (this cycle
   REMOVES excess permissions). Web's shipped behavior (Vault.tsx:830) is the same blind
   clear; desktop's guarded variant stays a JVM luxury. Cost: a clear at t+N may wipe an
   unrelated later copy — accepted, same as web.
10. **Clamps:** clipboard `Math.max(1, s)` (policy 0 still clears — spec 01 §8); the SW
    backstop alarm floors at 30 s (chrome.alarms minimum is 0.5 min — sub-minimum values are
    NOT honored on packed builds, so the self-imposed floor is the deterministic choice),
    [breaker-corrected] covered below 30 s by the local timers only while the copying
    document survives (amendment AM7 states the honest behavior).
11. **F26 records `idle` only.** Manual lock renders no reason line (web parity: the notice
    exists only on the useAutoLock path); the live-popup relocked() line stays as-is.
12. **api.ts stays chrome-free** — the manifest version is injected via the constructor, so
    the refresh/header/error tests run under plain node --test with a mocked `fetch`.
13. **The update-check fetch** (background.ts:332, static `/downloads/manifest.json`) carries
    no header — spec 03 governs `/api/v1`, and the downloads manifest is a public static file.

## Builder split (exactly 2, disjoint files)

**Builder A — ENGINE** (api/SW/wire/build/docs):
- `extension/src/api.ts` — header, ApiError(status, code, message), onUpgradeRequired,
  onTokensChanged + doRefresh semantics, SessionResponse.mustChangePassword
- `extension/src/background.ts` — identityPub check + IdentityMismatchError sentinel, unlock
  code mapping, mustChange/lockNotice/clipboardClearSeconds plumbing + snapshot, doLock
  reason, scheduleClipboardClear handler + "clipboardclear" alarm + clear dispatch, unlock-end
  pending-save re-offer, resolvePendingSave codes, onUpgradeRequired → checkForUpdate(true)
- `extension/src/messages.ts` — the contract changes (pinned below)
- `extension/src/totp.ts` — E1-8 backport
- `extension/src/offscreen.ts` + `extension/offscreen.html` — NEW (Chrome clear path)
- `extension/manifest.json`, `extension/manifest.firefox.json` — version, permission deltas
- `extension/build.mjs` — offscreen entry + html copy
- `extension/package.json` — version
- Tests: `extension/src/totp.vectors.test.ts` (NEW), `extension/src/api.test.ts` (NEW),
  `extension/src/version.test.ts` (lockstep addition)
- Docs: `spec/03-wire-protocol.md` §1, `docs/drills/426-min-version-drill.md`,
  `docs/design/2026-07-09-cards-wallet.md` correction note, `CHANGELOG.md` entry

**Builder B — SURFACES** (popup/content/copy):
- `extension/src/popup.ts` — unlockError → code mapping via errors.ts, ping copy, clipboard
  local timer + scheduleClipboardClear calls, mustChange strip render, F26 info line,
  426 unlock copy
- `extension/popup.html` — mustChange strip element; `extension/popup.css` — its styling
- `extension/src/content.ts` — offerBanner code mapping (never render r.error), copyTotp
  local clear + scheduleClipboardClear
- `extension/src/content-ui.ts` — expected zero changes (owned by B in case a result-line
  class tweak is needed)
- `extension/src/errors.ts` — NEW: UNREACHABLE + unlockErrorCopy + saveErrorCopy +
  lockNoticeCopy (the inactivityNotice port)
- Tests: `extension/src/errors.test.ts` (NEW)

**Pinned name contract (the seam — B builds against these exact shapes; A implements):**

```ts
// messages.ts (A owns the file)
export type UnlockCode =
  | "bad_credentials" | "totp_required" | "upgrade_required"
  | "identity_mismatch" | "server_error" | "network" | "unknown";
export type SaveErrorCode = "locked" | "conflict" | "failed";
// Res<"unlock">             = { ok: boolean; code?: UnlockCode; error?: string }
// Res<"status">             = { unlocked: boolean; count: number; email: string | null;
//                               mustChangePassword: boolean;
//                               lockNotice: { kind: "idle"; seconds: number } | null }
// Res<"resolvePendingSave"> = { ok: boolean; code?: SaveErrorCode; error?: string }
// Req                      += { type: "scheduleClipboardClear" }   // arm the SW backstop
// Res<"scheduleClipboardClear"> = { ok: boolean; clearSeconds: number } // effective policy s

// errors.ts (B owns the file; A never imports it)
export const UNREACHABLE: string; // verbatim web/src/ui/errors.ts:36
export function unlockErrorCopy(code: UnlockCode | undefined): string;
export function saveErrorCopy(code: SaveErrorCode | undefined): string;
export function lockNoticeCopy(seconds: number): string; // verbatim web format.ts:21-28 port

// api.ts (A-internal, pinned for the tests)
// new AndvariApi(baseUrl, clientVersion?)  → header `extension/${clientVersion ?? "0.0.0"}`
// class ApiError { status: number; code: string }  (message = server message | body slice)
// onTokensChanged: (() => void | Promise<void>) | null   // replaces onTokensRotated
// onUpgradeRequired: (() => void) | null
```

Both builders run `npm test` + `npm run typecheck` in `extension/` before handing back;
neither touches web/, core/, server/, app-*/.

## Test plan (all under extension `npm test` = node --test, unless noted)

- **E1-8** `totp.vectors.test.ts`: every `spec/test-vectors/totp.json` case →
  `totpCode({secret: base32Decode(c.secretBase32), …}, c.timeSec) === c.expected` (the
  urimatch.vectors.test.ts fileURLToPath pattern). Plus the determinism pins the vectors
  don't cover (parse-level, asserting the WEB outcome): `Caf%E9` label → parses (lenient);
  `%1G` → throws; `digits=8x` → 6; `digits=0` → throws; `period=30x` → 30; `period=0` →
  throws; `secret=` and all-padding secret → throw; U+FEFF/NBSP inside the secret → throw;
  `digits=8` → 8 sanity.
- **E1-9 + E1-2 + E1-3(api)** `api.test.ts` (mock `globalThis.fetch`): header
  `extension/1.2.3` on a json() call AND on the refresh POST; 401 → single rotation → retry
  with fresh access (+ onTokensChanged fired); refresh 503 → refresh token RESTORED +
  onTokensChanged fired + a later refresh retries with the SAME token; refresh fetch throw →
  same restore; refresh 401 → both tokens null + notified; the consume-persist ordering —
  onTokensChanged observes `refresh === null` BEFORE the refresh POST starts (capture
  getTokens() in the callback, assert against fetch-call order); ApiError body
  `{"error":"invalid_credentials","message":"authentication failed"}` → code/message parsed;
  non-JSON body → `http_<status>` fallback; body `upgrade_required` → onUpgradeRequired
  fired AND the ApiError still throws.
- **E1-3/5/7 copy** `errors.test.ts`: pins every sentence verbatim — UNREACHABLE (byte-equal
  to the web string, stated in a comment), the seven unlock codes, the three save codes,
  `lockNoticeCopy(900) === "Locked after 15 minutes of inactivity."`,
  [breaker-corrected] `lockNoticeCopy(90) === "Locked after 2 minutes of inactivity."`
  (web format.ts rounds ≥ 60 s to whole minutes — Math.round(90/60)=2; a seconds-form case
  is `lockNoticeCopy(45) === "Locked after 45 seconds of inactivity."`),
  `lockNoticeCopy(60)` singular-minute form.
- **Version lockstep** `version.test.ts` gains one test reading `../manifest.json`,
  `../manifest.firefox.json`, `../package.json` and asserting the three versions are equal
  (package.mjs :8-17 already refuses drift at package time; this catches it at test time).
  No `version.ts` change — it holds only `isNewerVersion`, already covered.
- **E1-1/4/6 (chrome-bound, no node harness — established posture):** logic that can be
  chrome-free IS (errors.ts, totp.ts, api.ts); the rest is pinned by the builder's
  load-unpacked smoke on the live server: wrong password → the canonical sentence; idle-lock
  (set a short policy) → reopen popup → the F26 line; copy password → close popup → clipboard
  empty at ~30 s (Chrome offscreen path) and again on Firefox; locked save → banner sentence
  → unlock → banner re-offers without reload; rescue-flagged account → strip; identityPub
  tamper is exercised by inverting the comparison locally (one-line flip) and observing the
  distinct sentence — then flipping back.
- `npm run typecheck` (tsc, chrome types incl. chrome.offscreen) + `npm run package` (A7
  runs the full test glob and the A8 content.js size cap — offscreen must not disturb either).

## Version bump + ship (0.9.0 → 0.10.0)

Every place 0.9.0 lives (verified by grep — exactly three, all hand-edited):
1. `extension/manifest.json:4`
2. `extension/manifest.firefox.json:4`
3. `extension/package.json:3`

(`version.ts` carries no constant — runtime version = `getManifest().version`, which is why
the manifests are the source of truth for the new header too.)

**CHANGELOG.md stub** (top of file, the "### browser extension" voice of the 0.8.0 entry):

> ### browser extension 0.10.0 — hardening round: the fleet's safety canon reaches the extension
>
> - **Copied secrets now clear themselves.** Passwords, one-time codes, and card fields
>   copied from the extension wipe from the clipboard after the same org-policy window the
>   other apps honor (30 s default) — even after the popup closes.
> - **Errors speak human now.** A mistyped master password says "Wrong email or master
>   password." instead of raw server JSON; can't-reach-the-server uses the same sentence as
>   the web vault; a save attempted while locked explains itself — and after you unlock, the
>   save offer comes back on its own instead of silently dying with the page.
> - **The extension now identifies itself to the server** (`extension/0.10.0`), so the
>   server-side minimum-version safety net can actually reach it, and it tells you when your
>   server requires a newer build. It also verifies the server-sent identity key against the
>   one your own sealed seed derives — the same tampering tripwire web and the apps run.
> - Two-factor codes now compute identically to every other client on edge-case setups
>   (the 2026-07-09 determinism fixes, backported); a recovery sign-in now nags you to set a
>   new master password; the popup says why it locked ("Locked after 15 minutes of
>   inactivity."); a transient server blip no longer signs the extension out; and the unused
>   "scripting" permission is gone (the clear-timer adds narrow clipboard permissions in its
>   place).

**Ship steps delta** (the 0.8.x procedure plus nothing new): `npm run package` →
`artifacts/andvari-extension-{chrome,firefox}-0.10.0.zip` → scp to heimdall → `pct push 122`
both zips into `/opt/andvari/downloads/` (user/group andvari) → **MERGE, never overwrite**,
the `browserExtension` key into `/opt/andvari/downloads/manifest.json` via the
ops/windows-build.md:59-68 python3 pattern (read-modify-write preserves the `linux` and
`windows` keys — the house gotcha): `m['browserExtension'] = {'version': '0.10.0',
'chromeUrl': '/downloads/andvari-extension-chrome-0.10.0.zip', 'firefoxUrl':
'/downloads/andvari-extension-firefox-0.10.0.zip'}` → chown → verify
`https://andvari.taila2dff2.ts.net/downloads/manifest.json` shows all three keys → installed
0.9.0 popups begin showing the update banner within a day (or immediately on browser
restart). Owner installs remain manual load-unpacked (unchanged posture).

## Out of scope (E1 does NOT do)

- **Server changes of any kind** — no enum validation, no device-platform rename, no new
  endpoints. The `extension` platform token works against the fielded server as-is.
- **A TOTP input in the popup** (totp_required gets copy only) and any popup IA/a11y work —
  that is A1.
- **In-page card fill** — still gated on the frame-origin egress contract (cards design
  2026-07-09).
- **==value-guarded clipboard clear** (needs clipboardRead) and any clipboard history/
  ClipboardItem work.
- **web-side residue**: web parseErr copy alignment and extending
  `web/src/extension-pins.test.ts` to totp — the extension now executes the shared vector
  file natively, which IS the cross-client parity anchor; a web-suite duplicate adds nothing.
- **Device-row dedup (F28 installId)** for the extension.
- **Firefox strict_min_version bump** — 121 already covers everything used (no offscreen on
  the Firefox path).
- **normalizeTotp backport** — the extension never writes/normalizes TOTP fields (read-only
  consumer of stored URIs); only the parse side must agree.

## Breaker amendments (BINDING, 2026-07-11)

Adversarial review at HEAD `7edfdb0`; every mechanism below re-verified against
extension/web/server source (citations inline). The architecture stands — nothing here
changes the item set, the two-builder split, or the 0.10.0 scope. One BLOCKER-class
mechanism fix (B1) and eight binding amendments (AM1–AM8); design text corrected in place is
marked `[breaker-corrected]` above (E1-4 backstop ×2, E1-7 notice format, E1-3 upgrade copy,
E1-2 drill step, decision 3, decision 10, test-plan lockNotice row).

### B1 — Chrome offscreen clear, as originally written, silently never clears (BLOCKER)

Two independent defects, one mechanism:

1. **Empty-string execCommand is a no-op.** `document.execCommand("copy")` copies the
   current SELECTION; `select()` on an empty textarea yields an empty selection and the
   copy command is refused — clipboard untouched, no error. The flagship backstop would
   fire on schedule and clear nothing, forever, with every test green.
2. **Clear-on-load behind a create-if-absent guard skips the clear.** Chrome allows ONE
   offscreen document per extension (createDocument rejects while one exists). If
   closeDocument ever fails/races, the guarded create SKIPS creation — and a clear that
   runs only on load never runs again.

**Bound fix:** the offscreen clear writes a SINGLE SPACE (`" "`), never `""`; and the clear
must execute on EVERY alarm fire — either message-driven (SW ensures the document exists →
sends a clear message → offscreen script clears on receipt and replies → SW closes; the
documented Chrome offscreen-clipboard pattern) or close-then-recreate (closeDocument if
present → createDocument → top-level sync execCommand runs before the create promise
resolves → closeDocument). The Firefox event-page path may keep async
`navigator.clipboard.writeText("")` (the async API accepts an empty string); its
execCommand FALLBACK also writes the space. The load-unpacked smoke asserts "clipboard no
longer contains the secret" (a lone space is a pass), never "clipboard is empty".
**Failure prevented:** E1-4's entire point — spec 01 §8 — lost invisibly on the dominant
copy-in-popup flow.

### AM1 — refresh: the exact persisted state machine, plus an outcome guard

The persisted state = the storage.session snapshot, written by the awaited
`onTokensChanged` → `persistSession()` (which must return its storage.set promise). Bound
sequence for doRefresh:

1. **Consume:** `this.refreshToken = null`; capture `atConsume = this.accessToken`;
   `await onTokensChanged?.()` — the snapshot now holds `{access: old, refresh: null}`.
2. **POST** `/api/v1/auth/refresh`.
3. **Outcome guard (NEW, binding):** apply the outcome ONLY if the pair is untouched since
   consume (`this.refreshToken === null && this.accessToken === atConsume`); otherwise
   DISCARD it entirely — no set, no clear, no restore, no notify. A concurrent
   `setTokens` (doLock :265, unlock :500) owns the pair now.
4. **Outcomes:** success → set pair, notify. 401/403 → clear BOTH, notify. Any other !ok
   or thrown fetch → restore `this.refreshToken = rt`, notify.
5. **Resurrection rule:** a woken SW that finds `{access, refresh: null}` attempts NO
   recovery — it runs on the access token until a 401, whose failed tryRefresh (null rt)
   surfaces normally (resync stays silent, saves answer code `failed`, popup re-unlock is
   the recovery). It never re-derives or replays anything.

Failure matrix (task-verified): **(a)** SW evicted after the server consumed, before the
response persisted → snapshot `refresh:null` → forced re-login and NO replay — correct,
because replay is whole-device revocation (Service.kt:261-283, CAS-guarded `refresh_reuse`).
**(b)** marker persisted but the POST never reached the server: SW survived → step-4
restore re-persists the still-valid token, nothing strands; SW died mid-POST →
indistinguishable from (a), strands to re-login — UNAVOIDABLE (a possibly-sent single-use
token can never be safely retried) and accepted. **(c)** concurrent refresh → AM6.
**Failure prevented by the guard:** a transient-failing refresh spanning a lock→unlock
would restore the OLD session's dead token over the fresh pair (or a late success/definitive
clear would clobber it) → the NEW session strands at its first access expiry.

### AM2 — local clear timers are single-slot; blind-clear ruling bound

Each copying surface holds ONE pending clear timer (popup: module slot serving
toClipboard(); content: module slot serving copyTotp()); every new successful copy
`clearTimeout`s the previous before scheduling. This matches the backstop, where
`chrome.alarms.create` with the same name REPLACES the alarm — "last copy through us wins"
on every layer. (Web's useCopy declares and checks `timer.current` but never assigns it —
Vault.tsx:821-833 — so its cancel is dead code; parity is owed to web's evident intent, not
its bug.) **Failure prevented:** copy username → copy password 10 s later → the username
timer wipes the password mid-window; the user pastes an empty clipboard (the Android B8
clobber class, entirely inside our own app).

**Blind-clear ruling (binding):** the backstop STAYS (without it the dominant popup flow
never clears — the popup dies on focus loss); blind clear STAYS (a ==value guard needs
`clipboardRead`, strictly worse privilege in the cycle that removes excess permissions);
the "skip if a later copy went through us" guard IS AM2 + the alarm replace semantics.
External copies inside the final window remain clobber-able — web-identical exposure,
accepted. Also accepted: chrome.alarms persistence across BROWSER RESTART is documented
unpredictable pre-Chrome-150, so copy-then-quit inside the window can leave the secret —
unreachable without a persistent process; do not over-claim in the smoke.

### AM3 — lockNoticeCopy ports web format.ts:21-28 EXACTLY

Web renders seconds ONLY below 60 s; anything ≥ 60 s renders `Math.round(seconds/60)` whole
minutes (90 s → "2 minutes"); the seconds branch clamps `Math.max(1, Math.round(s))`. The
original test plan pinned `lockNoticeCopy(90)` to a seconds form NO web client produces —
a builder following it would ship a divergent string or a red test against a "verbatim
port". Test plan corrected in place. **Failure prevented:** cross-client copy drift in the
very item that exists to close copy drift.

### AM4 — 426 gate scope: login-only for the extension (server truth)

`enforceVersion` runs ONLY at register/login (App.kt:317, :327) and the §10/§11
sharingPrincipal preamble — never on sync/push/refresh/client-policy. Bound consequences:
(i) the drill step expects the upgrade sentence at the next UNLOCK, not on a live session
(corrected inline); (ii) checkForUpdate structurally cannot 426 (raw fetch, background.ts:332,
against the static /downloads route which has no version gate — and not via api.ts) so
`onUpgradeRequired → checkForUpdate(true)` has NO re-entry/loop path — verified safe;
(iii) refresh is ungated → no 426×E1-9 interaction exists. **Failure prevented:** a drill
recorded as a false failure ("pinned but the extension keeps syncing") and a shipped doc
claim that misstates the fielded server.

### AM5 — popup re-renders the update banner on an upgrade_required unlock

renderUpdate() runs once at popup open (popup.ts:692) — BEFORE the SW's 426-triggered
`checkForUpdate(true)` can land its signal, so the upgrade copy would point at a banner
that is not there. **Binding:** when rendering the `upgrade_required` unlock error, the
popup calls `renderUpdate()` immediately and once more after ~2 s (single retry, no loop).
The copy is corrected inline to not hard-promise the link: with a pin naming an unpublished
build — and in the drill itself, which pins above the newest build — `isNewerVersion`
yields no banner. **Failure prevented:** the one moment the min-version control fires, the
user is pointed at a nonexistent element.

### AM6 — tryRefresh single-flight survives the E1-9 rewrite verbatim

api.ts:125-135 already coalesces concurrent 401s onto ONE rotation; the design rewrites
doRefresh without ever naming the mutex. It is the only thing preventing two concurrent
401s (the resync alarm racing a user save) from double-spending the single-use refresh
token — which the server punishes with whole-device revocation (Service.kt:261-283).
**Binding:** the shared-promise coalescing stays; api.test.ts adds one case — two
concurrent 401-triggered calls produce exactly ONE refresh POST. **Failure prevented:**
`refresh_reuse` device revocation manufactured by our own client.

### AM7 — sub-30 s honesty; the alarm floor stays

chrome.alarms minimum is 0.5 min; sub-minimum values are "not honored" (with a warning) on
packed builds and unlimited on unpacked. The self-imposed `Math.max(s/60, 0.5)` is bound
AS-IS — deterministic on both load modes — and the honest statement (now inline) is: with
the popup closed, a sub-30 s policy clears at ~30 s, later than policy; layer 1 covers
sub-30 s only while the copying document survives. Household policy default is 30 s — the
fleet is unaffected today. **Failure prevented:** a builder "improving" fidelity by passing
raw `s/60` ships an alarm packed Chrome may simply never fire.

### AM8 — Chrome manifest gains `"minimum_chrome_version": "109"`

The `offscreen` permission is unknown to Chrome < 109, and an unknown permission entry is a
manifest LOAD error — E1-10's "load-time effect: none" claim covers the scripting removal,
not this addition. One line makes the real floor explicit and the failure mode a clear
version message instead of a cryptic permission error. (Firefox manifest: `clipboardWrite`
only, no offscreen; `strict_min_version: 121` already present and sufficient.)

### Attacked and held (no amendment)

- **E1-1 placement:** the extension has NO cached/offline unlock — ensureLoaded
  (background.ts:216-237) restores an already-unlocked session and never touches
  accountKeys; unlock() always runs prelogin→login fresh (:496-505), so the compare can
  never block a legitimate unlock on stale data. Malformed-b64→mismatch mirrors web
  account.ts:157-174; crypto.ts has no ctEquals — the byte loop stands (server-supplied
  comparand, timing not load-bearing).
- **Platform token end-to-end:** Auth.kt:27-31 parses any token (no enum); :104-107
  unpinned → no gate; rate-limit keys are IP/userId only (App.kt:312-546), never platform;
  issueSession INSERTs the BODY platform verbatim (Service.kt:1022-1027) with no validation
  and no join to the header (service.login never receives it) — decisions 1-3 stand.
  `totp_required` is a 401 (Service.kt:157), so the 401-with-code-exception mapping shape
  is right; `public_login_requires_totp` is a 403 (:155) → server_error copy, structurally
  unreachable on the tailnet-only SERVER_URL. The extension has no WebSocket; the server's
  WS route version-gates nothing — no other header parse site exists for it.
- **Consume-persist pre-POST is required, not optional:** the snapshot-resurrection replay
  it prevents is whole-device revocation; web's alternative protections (Web Locks +
  persisted re-read, client.ts:159-226) do not exist in a SW.
- **persistSession's `!session` guard during unlock:** no authed call sits between
  setTokens (:500) and session assignment (:532) except the login-path sync, and a
  sync-401→rotation with a skipped persist is safely captured by :546 reading live
  getTokens(). Comment-don't-reorder stands.
- **E1-5 seam:** TabMsg `offerPendingSave` already exists (messages.ts:156) and content's
  listener (content.ts:323-325, isTop-gated) already renders it — the unlock-end re-offer
  needs zero new contract; linkUri's error string is never rendered anywhere (content.ts:149
  consumes `.ok` only) — no escaped raw-string surface remains after E1-3/E1-5.
- **Permissions delta:** zero chrome.scripting references in src or dist; storage/alarms/
  activeTab each verified load-bearing — the removal is load-safe.
- **Builder seam:** simulated both builders blind — every cross-file symbol is pinned; no
  file is touched by both; errors.ts needs no build.mjs entry (esbuild bundles imports);
  the offscreen entry cannot disturb the A8 content.js size cap (separate entry point).
- **Test plan:** spec/test-vectors/totp.json exists with exactly the fields used
  (secretBase32/algorithm/digits/period/timeSec/expected); the fileURLToPath pattern
  (urimatch.vectors.test.ts:14) resolves `../../spec/test-vectors/` from src;
  api.getTokens() (api.ts:105-107) exists for the consume-order assertion and doRefresh
  uses global fetch (mockable); the version-lockstep test's three files are the verified
  complete set of hand-edited 0.9.0 sites; node v22.23.1 runs the .ts test glob today.
  All E1-8 parse-level expectations verified against web totp.ts's actual behavior.

### Non-binding observations (file for later cycles — NOT E1 work)

- Definitive refresh death (401/403 → both tokens cleared) leaves an "unlocked" session
  whose writes all fail until a manual lock/unlock; web drops to its lock screen via
  events()/onRevoked. Pre-existing, outside exttech-3's scope. Candidate follow-up: doLock
  on definitive death (a new lock reason — F26 currently records `idle` only).
- web useCopy's dead `timer.current` check (Vault.tsx:823-827) is a one-line web bug worth
  fixing in a web cycle (the AM2 rationale documents it).
- `ask()` → undefined (SW mid-restart) sharing the UNREACHABLE copy at the ping surface
  mildly misattributes SW death to the network — today's conflation, accepted.
