# Cut 1 — Unify the invite button (dev-note B) — 2026-07-12

> Owner dev-note (ROADMAP §Onboarding & reach, 2026-07-12): collapse "Invite" + "Invite with
> QR" into ONE "Invite" button that shows the QR by default (with the token). Size S, web-only.
> **The one real decision is invite-TTL policy.** Freshest signal: the owner minted TWO invites
> for the same family member (`traxis@`) ~2 h before this session — a plain 72 h invite (still
> pending) and a QR invite (short TTL, expired) — the exact dual-path friction this note targets.

## Goal

One `Invite` action on the Admin invite form (`web/src/ui/Admin.tsx` `InviteForm`, currently
two buttons: plain `Invite` → `mint(false)`, and `Invite with QR` → `mint(true)`). Its result
view always shows the one-time token **and**, when the origin supports it, the enroll QR + link
together — so the admin hands over whichever is convenient in one flow.

## The TTL decision (the crux — CORRECTED by the breaker)

Today: a **plain** invite gets the server-default **72 h** TTL (`inviteTtlMs`); a **QR** invite
gets a short **60 min** TTL (`QR_INVITE_TTL_MINUTES`). If *every* invite now shows a QR, *every*
invite is photographable, so the TTL default matters.

**The security model (breaker BLOCKER 1 — my first rationale was FALSE, corrected here):** the
invite token is a **pure bearer credential**, and per `AdminService.kt:37-38` the **TTL is the
SOLE containment** for a photographed/leaked QR. The "printed-sheet fingerprint gate" does NOT
bind a capable holder: the fingerprint is `policy.recoveryFingerprint`, served *unauthenticated*
at `GET /client-policy` (`App.kt:273`); the org recovery **public** key is public
(`/recovery-pubkey`); `register` enforces only `escrow.fingerprint == config.recoveryFingerprint`
(equality against that public value, `Service.kt:88`) + an escrow-blob size check. A token holder
can read the public fingerprint, seal a self-generated escrow blob to the public key, and register
with their own master password — **no printed sheet needed**. The sheet is anti-wrong-server +
casual-finder friction, not a control over a capable holder. (Reaching `register` still requires
the attacker to reach the private enroll origin — tailnet/LAN — which bounds, but does not remove,
the threat.)

**Decision: make TTL an explicit, visible choice** (the dev-note's blessed alternative),
**secure-by-default-SHORT**:

- Add an **"Invite expires in"** `<select>`: **1 hour / 1 day / 3 days**. **Default 1 hour**
  (AM-5 renamed the label from "Link expires in" — the TTL governs the token, which is on screen
  even in the states with no link).
- **Why 1 hour default:** it preserves today's 60-min photographable-QR containment window
  (unifying must not silently 24×/72× the bearer-credential exposure the project deemed
  appropriate). 1 day / 3 days are **conscious admin opt-ins** for hand-delivery ("set it up
  tonight" / slow handoff) — the control is right there and its help copy states the tradeoff, so
  a longer window is a deliberate, informed act, not a hidden default.
- Server already clamps `ttlMinutes` to `[5, 4320]` (`AdminService.kt:39`), so `{60, 1440, 4320}`
  are all in range; we now **always** pass an explicit value (never `undefined`).
- The **non-revocable warning** renders whenever the enroll **link** is shown (AM-3: a sibling of
  the whole link block, so it also shows on the QR-overflow-link case — NOT nested in the
  QR-success branch): "Anyone who photographs this can use it until it expires — it can't be
  revoked. Hand over the printed recovery sheet in person, and keep the window short."

> **Owner-flag:** this reverts my earlier off-hand "1 day" to a 1-hour default on the breaker's
> corrected security model. The owner's live 72 h hand-delivery flow is preserved as a one-click
> opt-in (pick "3 days"). Flagged in the ship note so the owner can override the default if they'd
> rather trade exposure for cadence.

## Behavior by origin (preserve the public-origin containment)

`shouldOfferQr(origin)` (= `isPrivateOrigin`) stays the gate — **unchanged, still unit-pinned**:

- **Private origin** (tailnet / LAN / localhost): one `Invite` button → mint with the chosen TTL →
  result shows **token + QR + link + warning**.
- **Public origin** (`andvari.monahanhosting.com`): one `Invite` button → mint with the chosen TTL
  → result shows **token only** (a QR embedding the public origin dies at `register`, which is
  server-refused there). Keep the existing "a token minted anywhere is redeemed wherever the
  member actually enrolls" note. The TTL selector still applies.

So on the public origin the UI is effectively unchanged except for the new TTL selector; the QR
button never existed there and still doesn't.

## Edge cases + the four result states (breaker BLOCKER 2 + AMs — binding)

The result view is a **pure decision over `(qrAvailable, linkComposed, modulesOk)`** — pin it as
`inviteResultView(...)` (AM-4) so a refactor can't reintroduce BLOCKER 2:

| qrAvailable | link composed | modules ok | → view | renders |
|---|---|---|---|---|
| false | — | — | `"token-only"` | token only (public origin) |
| true | yes | yes | `"qr"` | token + QR image + link + warning |
| true | yes | no  | `"overflow-link"` | token + "QR too dense" note + link + warning |
| true | no (null) | — | `"compose-note"` | token + "couldn't encode a QR" note (NO link) |

- **BLOCKER 2:** the compose-failure note and the link block are **gated behind `qrAvailable`**;
  `mint` only calls `composeEnrollLink` when `qrAvailable`. NEVER gate the note on bare
  `!resultLink` — on the public origin `resultLink` is null too, and that would paint a false
  "couldn't encode a QR" on every public break-glass invite (leaking a QR affordance where
  `shouldOfferQr` is false). `inviteResultView(false, …)` MUST be `"token-only"`, asserted in the
  test.
- **Edge — `composeEnrollLink` → null:** the OLD code (`Admin.tsx:313-318`) cleared the result and
  told the user *"mint again with the plain Invite button instead"* — **that button no longer
  exists.** NEW (`"compose-note"`): keep the token, skip only the QR/link, show "Couldn't encode a
  QR for this address; hand over the token above." Never hide the token; never name a removed
  control.
- **Edge — `tryQrModules` → null** (`"overflow-link"`): render "QR too dense — use the link below"
  + the link + the warning (AM-3: warning is a sibling of the link block, so overflow keeps it).
- **AM-1 — kill the hardcoded minutes copy:** the old caption *"Valid for about
  {QR_INVITE_TTL_MINUTES} minutes"* (`Admin.tsx:386`) is now WRONG (a 3-day invite would read "60
  minutes"). Show only the server-authoritative `expires {fmtDate(result.expiresAt)}`; delete the
  phrase and the now-dead `QR_INVITE_TTL_MINUTES` constant (N-1).
- **State between mints:** clear `email` + `isAdmin` on success (as today); **keep** the TTL
  selection (admins mint several with the same delivery method).
- **One button**, disabled when `busy || !email.trim()`; Enter (form submit) mints with the current
  TTL. The `busy` guard + self-disable closes the double-submit window (breaker-verified clean).

## A11y (must not regress the just-shipped 0.15.0 / A1)

- New **"Invite expires in"** select → wrap in `<Field label=…>` (a `<select>` is labelable, so
  Field's `cloneElement` id-association lands correctly — breaker-verified).
- **AM-2 — the Announcer must be mounted UNCONDITIONALLY** (a sibling of the form body, like
  `Admin.tsx:539`), NOT inside `{result && …}` — a region that mounts already-populated is silent
  (BL-1). Drive it from `result?.email` (`mint` nulls `result` at start, sets it on success), so it
  announces "Invite created for <email>" AND re-announces on a same-email repeat (the `traxis@`
  two-invites scenario). Errors already go through `<Msg kind="err">`.
- Keep `QrSvg ariaLabel`.

## Scope / ship

- **web only.** One file (`Admin.tsx`) + a pinned pure-helper test. **No** server / wire / core /
  crypto change (the server already takes `ttlMinutes`). **No version bump** — additive web UI
  (QW1 / S2 precedent: a web-only additive change ships at the current fleet version, 0.15.0).
- Ship: `verify.sh` green → `ops/deploy.sh` → byte-verify the served web bundle sha == build →
  (no vzdump — zero server/jar/schema touch) → CHANGELOG line under the 0.15.0 era → push →
  Telegram statement.

## Tests

- **Keep** `onboarding-decisions.test.ts` (shouldOfferQr / tryQrModules) unchanged — still valid.
- **Add** pinned pure helpers in `Admin.tsx`, tested in `onboarding-decisions.test.ts` (its home
  for the invite gates):
  - `inviteTtlMinutes(choice)` mapping `{"1h","1d","3d"} → {60,1440,4320}`; assert every value is
    within the server's `[5, 4320]` clamp AND that the default choice maps to 60 (a refactor that
    adds an out-of-range or wrong-default choice trips the test).
  - `inviteResultView(qrAvailable, linkComposed, modulesOk)` → the 4-state table above; assert
    `inviteResultView(false, false, false) === "token-only"` and `(false, true, true)` too — i.e.
    **public origin is ALWAYS token-only** (locks BLOCKER 2), plus the three private states.
- Component stays node-vitest-untestable (no jsdom) → house pattern: pin the decision logic as pure
  functions, not a mount.

## Explicitly NOT in this cut

- The **tunnel-DOWN Grafana monitor** (item G) — different domain (ops/VM112); owner said "each
  broken its own part," so it rides separately if time permits, not bundled here.
- **Email-this-invite** (cut 4) — same form, but net-new server SMTP + a threat-model sign-off;
  its own cut, gated on owner approval.
