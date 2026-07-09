# Extension rework — audit synthesis + v0.6.1 implementation plan (2026-07-09)

**Trigger (owner, verbatim):** "the extension installed. and i can log in with it. but its very
basic, no functionality right now other than the basic popup. not consistent with our theme and
style. and it does not autofill or save fills" — plus an explicit ask for a deep multi-agent
audit → plan → implement pass.

**Method:** 5-lens parallel audit (autofill mechanics, product parity, theme/design,
security/permissions, architecture/reuse) + synthesis, verified against a headless-Chromium
regression harness that proves the 0.6.0 spine (unlock → save → persist → fill) works on a
static form — i.e. the field failures are detection/lifecycle, not crypto.

## Root causes — "does not autofill or save" is overdetermined

Five independent mechanisms, each alone sufficient:

1. **MV3 service-worker death (~30 s idle) wipes the in-memory session.** Unlock → browse →
   SW killed → every `matches` returns `[]`, silently. `storage` + `alarms` are declared in the
   manifest but never called. Fix: **`chrome.storage.session` key custody** (memory-backed,
   never disk, cleared on browser exit — the sanctioned MV3 pattern; ZK-compatible: wraps the
   session under a session-scoped custody, never the master password) + `chrome.alarms` for the
   policy auto-lock (client-policy `autoLockSeconds`) and periodic re-sync.
2. **One-shot field detection at `document_idle`.** No MutationObserver, no focusin delegation,
   no SPA-routing handling → late-rendered/React/modal/multi-step forms never seen; detached-node
   listener bugs on re-render. Fix: delegated `focusin` + MutationObserver re-scan + per-tab
   multi-step memory (username page → password page), using the **canonical, vector-tested
   `classify()` from web/src/vault/urimatch.ts** (written "for the future browser extension").
3. **Save fires only on literal `submit`/Enter and races navigation.** JS-click logins missed;
   banner injected into an unloading page; no pending-save re-offer after the redirect; no
   update-existing flow. Fix: credential snapshotting on input + submit-ish triggers (submit,
   Enter, submit-button click) + **SW-side pending-save** re-offered on the next page load +
   "Update password for …?" when the username already exists.
4. **Naive `.value=` fill.** React-controlled forms revert it (visible text, empty state). Fix:
   native `HTMLInputElement.prototype.value` setter + full event sequence.
5. **Legacy data can't match.** Web editor leaves `uris:[""]`; Android app-saves write
   `androidapp://`; the hand-rolled host matcher diverges from canonical `urimatch.ts`
   (scheme-less/path entries like `netflix.com/login` never match). Fix: port `urimatch.ts`
   verbatim (+ shared vectors), popup/dropdown "Search all logins…" fallback, and
   **"Link this login to this site"** one-tap URI backfill.

Also: no `all_frames` (iframe logins invisible — ships together with SW-side, host-bound
`reveal` authorization so widening frames doesn't widen the secret surface), and locked /
zero-match / broken states all render identically (nothing) — every failure needs a visible,
themed state.

## v0.6.1 scope (all P0 + selected P1)

**P0** — session custody + auto-lock; detection engine rework (delegated focusin, observer,
multi-step, all_frames + frame-origin guards); snapshot save/update engine surviving navigation;
native-setter fill; canonical urimatch + classify port; SW-side host-bound reveal (one-shot
grant for explicit popup fills); functional popup (site matches, search-all, copy user/pw,
open-vault, lock, diagnostics); treasury theming for popup + in-page UI (component-scoped
`--anv-*` tokens — `all:initial` doesn't reset custom properties; max z-index) with
`prefers-color-scheme` light variant; branded icons (16/32/48/128); microcopy canon
("Unsealing…", "the keeper of the hoard").

**P1 pulled in:** state-aware empty/locked dropdown UI; URI backfill on out-of-match fill;
TOTP auto-copy on fill + live code in popup (port web `totp.ts`); password generator popup view +
new-password suggestion (port web `generator.ts`); per-tab match-count badge.

**Deferred:** context-menu fill (only item needing a new permission), Firefox AMO signing,
keyboard nav polish, arrow-key dropdown nav. **Do-not-build (household):** multi-account,
passkeys, card/identity types, offline cache, auto-submit, in-field icon overlays, store
distribution.

**Invariants:** zero new permissions; zero server/wire changes; ZK — secrets to a page only on
explicit user gesture (row click in page, or item click in popup = the gesture); nothing
plaintext ever in `chrome.storage.local`/disk; 0 eval / 0 wasm.

## Implementation structure

Shared typed `src/messages.ts` contract pinned first; then four parallel workstreams over
disjoint files: **A** background/session/api + ported libs (urimatch/totp/generator),
**B** content script (detect.ts / ui.ts / index.ts), **C** popup (html/css/ts),
**D** manifests/build/icons/INSTALL. Integration gate: typecheck + build + the headless harness
extended with SPA/late-render, JS-click, multi-step, iframe, React-controlled, and
SW-kill-survival fixtures + adversarial review workflow before packaging 0.6.1.

Raw audit payloads (incl. full CSS deliverables consumed by B/C): session scratch
`tasks/wkdxdqxj1.output` (not committed; distilled here).

## Post-implementation adversarial review (2026-07-09)

A 4-lens review + per-finding refutation over the rework diff confirmed **16 findings, all fixed
before packaging** (2 rejected on refutation). The two HIGH ones were real:

1. **Popup-fill grant broadcast to all frames** (`background.ts`) — `fillFromPopup` sent `fillItem`
   to every frame and the reveal grant was keyed by tabId only, so a hostile cross-origin iframe in
   a tab where the user popup-filled a login could redeem the still-armed grant and exfiltrate the
   secret. Fix: target `{frameId: 0}` and require `sender.frameId === 0` to consume the grant.
2. **Non-fillable controls classified as fields** (`detect.ts`) — a `show password` checkbox or a
   submit named `login` classified as password/username, breaking real detection. Fix: a
   `NON_FILLABLE_TYPES` gate before `classify()`.

Others fixed: locked-capture always-new (resolve re-checks update target), passive `pageInfo`/`totp`/
`status` defeating idle autolock (passive-message set), `formatVersion` fail-closed guard, resync
clobbering an in-flight save (write counter), `tryRefresh` single-use-token race (in-flight
coalescing), formless-group over-merge + stray-field username-step (bounded ancestor climb),
detached-node fill after SPA re-render (`liveForm` re-resolve), sub-frame pending-save hijack
(frame-owned pending), popup wedged-on-lock (ticker liveness check), popup >600px overflow, stale
docs. Two dedicated headless harnesses gate it: `verify-extension-2.js` (8 functional scenarios) +
`verify-security.js` (frame-isolation + field-trap regressions).
