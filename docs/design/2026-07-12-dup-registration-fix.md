# Cut 2 — Fix the dup-registration bug (dev-note BUG) — 2026-07-12

> Owner dev-note (ROADMAP §Onboarding & reach, 2026-07-12, reproduced live): on a re-login form
> that shows ONLY a password field, the owner autofills the password from an andvari suggestion and
> submits; andvari's save-offer then asks to "save this login?" as if new, and accepting creates a
> SECOND (password-only) item beside the original. P2 data hygiene. Fix BOTH surfaces (owner hit it
> via a browser fill → extension; Android has the same class of gap).

## Root cause (verified by the cut-2 investigator, file:line)

Both surfaces decide "new vs update" using a signal a password-only re-login **zeroes out**:

- **Extension** (`extension/src/background.ts:966` + resolve mirror `:1016`): the update-target
  lookup is `matchesFor(host).find(i => (i.doc.login?.username ?? "") === username)`. A password-only
  submit sends `username === ""` (`content.ts` only sets username when a field has one), so the real
  item (username `jacob@…`) never matches → `existing = undefined` → `updatesItemId = null` → the
  unchanged-password suppress branch (`:967`) is skipped → `putNewLogin` → **duplicate**. The
  content-ui banner ALREADY renders an "Update the password for X?" variant when `updatesItemId` is
  set (`content-ui.ts`), so the fix is purely in the decision logic.
- **Android** (`app-android/.../autofill/SaveConfirmActivity.kt:285`): `doSave` unconditionally calls
  `engine.save(null, doc)` = **always create**. There is NO login dedup at all — only *cards* dedup
  (`cardPlanFor` :156 → `CardPlan.Update/New`). Every accepted login save is a create; the platform's
  "submitted == the dataset that filled" suppression usually hides it, but a password-only re-login of
  an item whose username the form never showed is exactly where that slips.

Neither surface has a durable autofill-provenance signal ("this fill came from item X") — the
extension's popup grants are one-shot / 30 s / frame-0 only; Android's `AutofillUnlock.provenance` is
*unlock* provenance. So the fix keys on **content match** (host + username/password), not provenance.

## The dedup decision (shared logic, one per surface — pinned pure)

Given the host's existing login items `matches` (already host-filtered via urimatch), the submitted
`username`, and the submitted `password`, pick the update target:

1. **`username` non-empty** → `matches.find(username exact)` (today's behavior, unchanged).
2. **`username` empty (password-only)** →
   - **a.** `matches.find(password equal)` → that item is the SAME login being re-entered → its
     password is unchanged by definition → **suppress the offer** (no banner / nothing to save).
     *This is the owner's exact bug: an autofilled password equals the stored one → no dup.*
   - **b.** else if `matches.length === 1` → the host's single login, password differs → **offer
     Update** of it (a password change). The prompt NAMES the item, so a user who realizes it's a
     genuinely new account can decline (→ nothing saved) — no silent wrong-merge.
   - **c.** else (multiple host logins, none password-equal) → **New** (ambiguous; never silently
     overwrite the wrong account — a dup is recoverable, a clobbered password is not).
3. **No `matches`** → **New** (genuinely first credential for the host).

Unchanged-password on the username path (step 1) already suppresses today; step 2a extends the same
"a re-login is a no-op" rule to the password-only case.

## Extension implementation (`extension/src/background.ts`)

Add a pinned pure helper (near `matchesFor`):

```ts
/** Save-vs-update target. With a username, an exact (host ∧ username) match is the target (v1).
 *  A password-only submit (username === "") has no username to key on → fall back to the host's
 *  login items: a password-equal item is the SAME login being re-entered (→ its unchanged-password
 *  path suppresses the banner, never a dup); a lone host login is the update target (password
 *  change); an ambiguous multi-login host with no password match stays a NEW item (never overwrite
 *  the wrong account). Fixes the dup-registration bug. Pure over the passed matches → unit-pinned. */
export function saveTargetFor(matches: DecryptedItem[], username: string, password: string): DecryptedItem | undefined {
  if (username !== "") return matches.find((i) => (i.doc.login?.username ?? "") === username);
  const byPassword = matches.find((i) => (i.doc.login?.password ?? "") === password);
  if (byPassword) return byPassword;
  return matches.length === 1 ? matches[0] : undefined;
}
```

- `capturedCredential` `:966`: `const existing = saveTargetFor(matchesFor(host), username, msg.password);`
  Then the existing `:967` unchanged-password suppress branch fires for step-2a (password-equal), and
  for step-2b (single login, password differs) `existing` drives `updatesItemId`/`updatesItemName` →
  the banner shows "Update the password for X?".
- `resolvePendingSave` `:1016`: `target = saveTargetFor(matchesFor(pending.host), pending.username, pending.password);`
  (post-unlock re-decision — same helper; a locked-at-capture re-login now resolves to Update, not a
  dup). If the target's password already equals `pending.password`, `putExisting` writes an idempotent
  no-op rev (harmless; only reachable via the locked path where suppression couldn't run at capture).
- **No UI change** — the update banner already exists; the token/secret egress rules are untouched.

## Android implementation (`app-android/.../autofill/SaveConfirmActivity.kt`)

Mirror the `CardPlan` / `cardPlanFor` pattern exactly (proven 0.7.0 code):

- Add `sealed interface LoginPlan { data class Update(itemId, name); object New }`.
- `loginPlanFor(creds): LoginPlan?` — `engine.items().filter { type=="login" && UriMatch.matchLogins(it.doc.login?.uris ?: [], FillTarget(webHost=creds.webDomain, packageName=creds.appPackage), pslResolve) }`
  then the step 1–3 decision above (username `creds.username`; password `creds.password`). Returns
  **null** for step 2a (password-equal re-login → nothing to save) so the login stage is skipped —
  the Android analogue of the extension's suppress.
- Wire into `resolveStages`: also compute `loginPlan = if (creds.savable) loginPlanFor(creds) else null`;
  return `cardPlan != null || loginPlan != null` (so a pure unchanged re-login with no card → `finish()`,
  no banner). Compute post-unlock (needs the decrypted working set), exactly like `cardPlanFor`; ensure
  `doUnlock` → `resolveStages` sets it (it already calls resolveStages).
- Render: replace `creds.savable -> SaveCard(...)` with `loginPlan != null -> SaveCard(plan=loginPlan, …)`
  where `SaveCard` shows an **Update** variant ("Update login?" / "The password for <name> will be
  updated; its username stays.") when `plan is LoginPlan.Update`, else the current create copy.
- `doSave` uses the plan: `Update` → materialize from the existing doc (`.copy` the stored `LoginData`,
  swap only `password`; keep username/uris/totp/notes) and `engine.save(itemId, doc)`; `New` →
  `engine.save(null, doc)` (today's path).
- **Create is NOT gated** here (unlike cards' Option-A `CREATE_ENABLED`) — logins have always been
  creatable; only card *creation* was dark. Update touches an existing item only.

## Parity + tests

- No wire/byte contract (this is local autofill UX) → each impl carries its own pinned test, NOT a
  shared vector; note the parity in-doc.
- **Extension:** `node --test` case for `saveTargetFor` — username-match; password-only password-equal
  (→ returns the item, drives suppress); password-only single-login differing password (→ that item);
  password-only multi-login no match (→ undefined/New); no matches (→ undefined/New).
- **Android:** a `loginPlanFor`-logic unit test (pure decision over a fake item set) mirroring the same
  five cases; run desktop-free (`app-android` has minimal test deps — if none, gate via a small pure
  `LoginPlanDecider` object testable without Android, matching the card-normalize test style).

## Scope / ship

- **extension** (bump ext 0.11.0 → **0.12.0**) + **Android APK** (versionName STAYS 0.15.0 — an
  additive bugfix, versionCode auto-bumps by time; no fleet lockstep change; web/desktop/core
  untouched). Two ships, one cut.
- Gates: `verify.sh` (web+extension+kotlin) EXIT=0 file-logged; `:app-android:compileDebugKotlin` +
  the two new unit tests. Extension ship = `npm run package` → /downloads zips + manifest MERGE
  (`browserExtension` key; preserve `linux`/`windows`). APK = `scripts/ship.sh release` → devstore.
  **No vzdump / no server touch** (zero server/jar/schema change). Byte-verify served zip shas +
  manifest; APK vc on devstore. Telegram statement.

## Breaker amendments (2026-07-12) — BINDING (fold before build)

The breaker found **2 BLOCKERs + 6 amendments**. These override the sections above where they conflict.

**BLOCKER 1 — extension RESOLVE must NOT run the ambiguous 2b branch (data-loss).** Applying
`saveTargetFor` (with 2b "single host login, password differs → Update") at resolve time
(`:1016`) silently clobbers the wrong account: locked-at-capture, host has ONE login (alice/P_A),
user submits a password-only login for a *different* unsaved account (bob/P_B) → capture (locked,
matchesFor empty) records **New** → user unlocks, sees "Save new", clicks Save → resolve picks
alice (single login) → `putExisting(alice, {password:P_B})` → **alice's P_A is overwritten, no
Update prompt ever shown**. `saveTargetFor`'s 2b is fine at CAPTURE (`:966`, the Update banner
mediates consent) but resolve must use an ordered rule that only auto-updates on UNAMBIGUOUS
same-account signals (hoist `const hostMatches = matchesFor(pending.host)`):
1. frozen `pending.updatesItemId` (user saw the Update banner) → `putExisting`;
2. else `pending.username !== "" && hostMatches.find(username exact)` → `putExisting` (same account);
3. else `hostMatches.some(password === pending.password)` → **skip the write** (2a re-login of a
   known item, reachable only via the locked-at-capture path) — clear pending, return ok;
4. else → `putNewLogin` (recoverable New for locked-2b / 2c — matches today's safety).

**BLOCKER 2 — Android stage-advance must gate on `loginPlan`, not `creds.savable`.** A card+login
submit where the login is an unchanged re-login (`loginPlan == null`) strands a blank screen:
`doSaveCard.onSuccess` (`:258`) and `advancePastCard` (`:182`) set `cardStageDone=true` without
`finish()`, and the login branch (`loginPlan != null`) is false → `else -> {}` hangs. Store
`loginPlan` in a `mutableStateOf` field (like `cardPlan`); in BOTH `doSaveCard.onSuccess` and
`advancePastCard` replace `if (creds.savable)` with `if (loginPlan != null)`.

**A — show the existing item's USERNAME in the 2b Update confirm (both surfaces).** Auto-saved
items are named after the host (`putNewLogin` name=host), so "Update the password for example.com?"
can't distinguish a password change from a wrong-account merge — the guard 2b leans on. Carry
`updatesItemUsername` through `PendingSave` + `publicPending` → the banner (`content-ui.ts:428`),
and `LoginPlan.Update(itemId, name, username)` → the Android Update card. Usernames already egress
via the match dropdown — no new secret boundary.

**C — Android step-1 suppress parity.** When `creds.username` is non-empty and the username-exact
match's password EQUALS the submitted password, `loginPlanFor` returns **null** (unchanged
re-login), mirroring the extension `:967` suppress — no pointless "Update login?" / no-op write.

**D — Android Update re-reads + `.copy()`-materializes (never field-rebuild — the 0.2.x loss
class, `SaveConfirmActivity.kt:77`).** `LoginPlan.Update` carries only `(itemId, name, username)`
— NO doc — which forces `doSave` to re-read by `itemId` at save time and build
`existing.doc.copy(login = (existing.doc.login ?: LoginData()).copy(password = creds.password))`,
preserving username/uris/totp/passwordHistory/notes/favorite/extras/attachments (mirror
`doSaveCard` :225-236). Do NOT close over the resolve-time doc.

**E — Kotlin signature fixes (design snippets won't compile as written).**
`UriMatch.matchLogins(uris, target)` takes **no** `pslResolve` arg (it calls `Psl.resolve`
internally — `DatasetBuilder.kt:171/199` calls it 2-arg). **CORRECTED by the cut-2 review (Finding
1, security):** `creds.webDomain` is ATTACKER-CONTROLLED (any app populates its own
`AssistStructure`; `SaveExtractor` reads `node.webDomain` raw — it does NOT null it for
non-browsers, so my "already mirrors the trust gate" premise was FALSE). The fill side gates it
(`DatasetBuilder.targetFor:296-297` → `TrustedBrowsers.isTrusted`); the save side MUST too, or a
malicious non-browser app can set `webDomain="github.com"` and drive an Update that clobbers the
real github login. Build:
`FillTarget(webHost = if (TrustedBrowsers.isTrusted(this, creds.appPackage)) creds.webDomain else null, packageName = creds.appPackage)`.

**F — honest oracle note (correct the design's "no oracle" claim).** The suppress-on-password-equal
branch is a password-**confirmation** side channel: a page controlling host H can submit guesses via
a password-only form and detect a hit by the Save banner's *absence* (observable via the page-visible
shadow host). This oracle ALREADY exists on the username path (`:967`); the fix WIDENS it to
password-only. No secret egresses (ZK holds) → not a blocker, but document it as pre-existing +
marginally-widened, not "no oracle."

**Confirmed sound (no change):** 2c (multi-login → New) beats a guess-update; username-present path
bit-identical to today; frame-safety holds; the 2a shared-password residual (a third unsaved account
sharing a stored password is suppressed) is a rare, non-destructive accepted residual; Android
computes the plan post-unlock in both the already-unlocked and unlock-then-resolve paths.

## Breaker seeds (probe before build)

1. Extension: does `saveTargetFor` at resolve time (`:1016`) ever pick a target whose password ==
   pending, causing a redundant no-op `putExisting`? Is that harmful (rev churn / 409)? Should resolve
   short-circuit when target.password == pending.password?
2. The multi-login ambiguous case (2c): is "New" really safer than "suppress"? (A dup vs. a missed
   password-change.) Confirm New (recoverable) beats a silent miss.
3. Android: `loginPlanFor` returning null when unchanged — does `resolveStages` correctly `finish()`
   with no card AND no login, and not strand a blank screen? Interaction with the card-first staging
   (card present + login unchanged).
4. Android Update: does `.copy`-materializing the existing doc preserve unknown fields / totp / uris
   (the 0.2.x field-rebuild data-loss class the cards fix warns about)? Must NOT field-rebuild.
5. Both: username present but the site ALSO has a password-only variant — no regression to the working
   username-match path.
6. Extension frame-safety: the fix runs inside the existing frame-owned `pending` guard (`:950`) — no
   new cross-frame hijack surface.
7. Does matching by password leak timing/existence? (Local, in-memory over already-decrypted items —
   no oracle to the server or page.) Confirm no secret crosses a boundary.
