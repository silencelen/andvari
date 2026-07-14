# Recovery-confirm piece binding — BINDING build contract (2026-07-13)

**Status:** BINDING. Three parallel lanes (server, web, natives) implement EXACTLY this.
**Fixes:** the cross-device self-service-recovery race (silent-total-loss class for waived members).
**Verified at HEAD `6e0d638`.** Amends design `2026-07-12-auth-secret-recovery-review.md` §F.3/§F.9;
where this doc and §F differ, THIS doc wins for the confirm/setup binding only. All §F crypto,
anti-enumeration, origin-refusal, rate-limit, and shown-once rules are UNCHANGED.
`spec/test-vectors/member-recovery.json` stays **byte-identical** — there is NO crypto change.

---

## 0. The defect (two orderings, both must die)

Code facts (server `Service.kt`): `recoverySelfSetup` fresh-reauths then UPSERTs
`member_recovery(recoveryWrappedUvk, recoveryVerifier, updatedAt)` and deliberately does not flip
`users.recoveryConfirmed`; `recoverySelfConfirm` is a separate tx that sets `recoveryConfirmed=1`
unconditionally (`Repo.setRecoveryConfirmed`). Both web `RecoveryCaptureGate` (run-on-mount →
`setupAndCommitRecovery`) and desktop `startRecoveryCapture`/`runRecoveryCapture` call setup **on
gate mount**, before any reveal. Nothing binds a confirm to the piece the confirming client revealed.

- **Ordering 1 (confirm-after-rotate):** device A setup(pieceA) → device B setup(pieceB, rotating A
  away) → A type-backs pieceA locally (`MemberRecovery.confirmMatches` is CLIENT-side) → A's confirm
  sets `recoveryConfirmed=1`. Server row = pieceB (possibly never revealed to anyone who kept it);
  user's saved pieceA is dead at `/recovery/self/verify` (verifier = pieceB's). Silent total loss for
  a waived member who later forgets the master password.
- **Ordering 2 (rotate-after-confirm):** A setup(pieceA) → A confirms (flag=1) → B (whose
  `accountKeys` fetch predated A's confirm) mounts the gate → B's mount-time setup rotates to pieceB
  → B abandons. Flag=1, row=pieceB, nobody captured pieceB. Same loss class — and it needs no
  type-back on B at all; merely OPENING the gate on a second device strands the first phrase.

A token binding alone kills ordering 1 but NOT ordering 2. The contract therefore has two legs:
**(i) a server-minted opaque piece id presented at confirm**, and **(ii) every rotation clears
`recoveryConfirmed` back to 0**. Leg (ii) does not violate the F.9 invariant (constraint 4): the flag
still flips **to 1** only at demonstrated type-back; clearing to 0 at rotation is the complementary
safety direction (flag=1 ⇒ the CURRENT piece was captured).

---

## 1. (a) Endpoint + DTO contract

### 1.1 Schema (server `Db.kt`) — coordinate: ONE shared v8 block

`member_recovery` gains two nullable columns. The concurrent server lane adds `users.escrowPolicy`
in the same bump. **BINDING: a single `if (version < 8)` migration block containing all v8 ALTERs
and one `UPDATE meta SET value='8'`. Do NOT mint v8 and v9 separately** (prod CT122 is at v7 and
both changes ship in one release; the server builder owns the merge).

```sql
ALTER TABLE member_recovery ADD COLUMN pieceId TEXT        -- opaque id of the CURRENT piece; NULL = pre-v8 row
ALTER TABLE member_recovery ADD COLUMN setupDeviceId TEXT  -- deviceId whose setup/register committed it; NULL = pre-v8 row
```

**No backfill** — no fielded client ever received an id for a pre-v8 piece; NULL drives the legacy
branch (§4). `updatedAt` keeps its current write-only behavior.

**Why a new column and not `updatedAt`-as-token (constraint 5):** (1) `now()` is millisecond-grained;
two setups in the same ms (fully possible — txs are serialized by `Db`'s single-connection lock but
not spaced) would mint IDENTICAL tokens for DIFFERENT pieces, letting a stale confirm false-match —
the very bug, in a narrower window. (2) It overloads an ops timestamp with protocol semantics,
freezing it against future migrations/backfills. (3) A guessable/monotonic value invites clients to
fabricate one instead of threading it. Cost of the explicit column ≈ zero inside an already-open v8.

### 1.2 Piece id mint

`val pieceId = ServerCrypto.newToken()` (32 random bytes → b64, the existing ticket idiom in
`WsTicketStore.mint`). Minted server-side at **every** `member_recovery` INSERT/UPSERT — in
`register` and in `recoverySelfSetup`. It is an opaque handle, not a secret credential (it rides an
authenticated channel and grants nothing a session couldn't get by calling setup itself); plain
string equality at compare time is acceptable — constant-time compare is NOT load-bearing here.
It is not consumed on use: confirm is idempotent while the row is unrotated (retry-safe); a rotation
is what invalidates it. ("One-time" = one per piece, not consume-on-first-confirm.)

### 1.3 Wire DTOs (core `Wire.kt` + web `types.ts` twins) — ALL additive-with-defaults

| DTO | Change |
|---|---|
| `SessionResponse` | `+ val recoveryPieceId: String? = null` — populated **ONLY by register** (the id of the register-committed piece). Login/refresh MUST leave it null. |
| `RecoverySelfSetupResponse` | **NEW**: `data class RecoverySelfSetupResponse(val pieceId: String? = null)` — the setup route's response body (replaces text `"ok"`). |
| `RecoverySelfConfirmRequest` | **NEW**: `data class RecoverySelfConfirmRequest(val pieceId: String? = null)` — optional body on the confirm POST. |
| `AccountKeys` | **UNCHANGED — MUST NOT carry `pieceId`.** Every session fetches keys; handing out the current id would let a client "confirm" a piece it never revealed, hollowing out the flag's meaning ("demonstrably captured"). |
| `RegisterRequest`, `MemberRecoveryBlock`, `RecoverySelfSetupRequest`, verify/commit DTOs | UNCHANGED. |

Compat audit (verified): core client `AndvariApi`'s Json has `ignoreUnknownKeys = true`
(`AndvariApi.kt`, `private val json`), so fielded 0.15/0.16 natives parse a `SessionResponse` with
the new field; web JSON parsing ignores extras natively. Fielded desktop `putRecoverySelfSetup`
checks `resp.status.isSuccess()` only and discards the body (verified in `DesktopState.kt`), and no
fielded client parses the setup response text — so `"ok"` → JSON is safe. Fielded confirms send NO
body; the route must therefore tolerate an empty body (§2.2).

### 1.4 Routes (server `App.kt`) — guards unchanged (public-origin refusal + 5/min per-IP limiter)

- `PUT /api/v1/recovery/self-setup` — request unchanged; response becomes
  `200 RecoverySelfSetupResponse{ pieceId }` (JSON) instead of `"ok"`.
- `POST /api/v1/recovery/self/confirm` — body now OPTIONAL `RecoverySelfConfirmRequest`.
  Body parse rule (BINDING): read `call.receiveText()`; blank/absent ⇒ `pieceId = null` (legacy);
  non-blank ⇒ decode `RecoverySelfConfirmRequest` (decode failure ⇒ `400 bad_request`).
  Response `"ok"` unchanged. New failure: **`409 {"error":"recovery_piece_stale","message":"conflict"}`**
  via the existing `Conflict("recovery_piece_stale")` exception (`Auth.kt` → StatusPages mapping).
- `POST /auth/register` — response gains `recoveryPieceId` (§1.3).
- `/recovery/self/verify` + `/recovery/self/commit` — **UNTOUCHED** (§6 scope).

### 1.5 Core client API (`AndvariApi`, added this wave per step-0)

- `recoverySelfSetup(req): RecoverySelfSetupResponse` — on a pre-fix server whose body is not
  decodable JSON (`"ok"`), return `RecoverySelfSetupResponse(pieceId = null)`; never throw on body
  shape alone when status is 2xx.
- `recoverySelfConfirm(pieceId: String?)` — `pieceId != null` ⇒ JSON body `{"pieceId":"…"}`;
  `null` ⇒ empty body (legacy wire shape).

---

## 2. (b) Server tx pseudocode (BINDING semantics; `Db` single-connection lock totally serializes txs)

### 2.1 `recoverySelfSetup(p, req, ip): String` — returns the minted pieceId

```
verify currentAuthKey against login verifier          // UNCHANGED, outside tx, audit _fail on 401
block = requireMemberRecovery(req.memberRecovery)     // UNCHANGED
pieceId = ServerCrypto.newToken()
tx { c ->
    UPSERT member_recovery(userId, recoveryWrappedUvk, recoveryVerifier, updatedAt,
                           pieceId = pieceId, setupDeviceId = p.deviceId)   // stamp BOTH on insert AND on-conflict update
    c.exec("UPDATE users SET recoveryConfirmed=0 WHERE userId=?", p.userId) // LEG (ii): reset-on-rotate
    auditOn(c, "recovery_self_setup", p.userId, p.deviceId, ip)
}
return pieceId   // route responds RecoverySelfSetupResponse(pieceId)
```

### 2.2 `recoverySelfConfirm(p, pieceId: String?, ip)`

Everything — row read, comparison, flag write, audit — in ONE tx so no setup can interleave between
decision and write. The stale path must COMMIT its audit row, so decide inside, throw after:

```
val stale = repo.db.tx { c ->
    row = SELECT pieceId, setupDeviceId FROM member_recovery WHERE userId = p.userId
    when {
        row == null -> { auditOn(c,"recovery_self_confirm_stale",p.userId,p.deviceId,ip,"no_row"); true }
        pieceId != null ->                                    // BOUND (post-fix clients)
            if (row.pieceId != null && pieceId == row.pieceId)
                 { setRecoveryConfirmed(c,p.userId); auditOn(c,"recovery_self_confirm",p.userId,p.deviceId,ip); false }
            else { auditOn(c,"recovery_self_confirm_stale",p.userId,p.deviceId,ip,"bound"); true }
        else ->                                               // UNBOUND (fielded 0.15/0.16 natives)
            if (row.setupDeviceId == null || row.setupDeviceId == p.deviceId)
                 { setRecoveryConfirmed(c,p.userId); auditOn(c,"recovery_self_confirm_unbound",p.userId,p.deviceId,ip); false }
            else { auditOn(c,"recovery_self_confirm_stale",p.userId,p.deviceId,ip,"unbound"); true }
    }
}
if (stale) throw Conflict("recovery_piece_stale")
```

### 2.3 `register(...)`

Inside the existing register tx: mint `pieceId`; the `member_recovery` INSERT carries
`pieceId` + `setupDeviceId = <the deviceId of the session this register mints>` (reorder the insert
after `issueSession`, or precompute the deviceId — builder's choice, semantics binding).
`recoveryConfirmed` stays 0 (column default, unchanged). Response carries `recoveryPieceId = pieceId`.

**Repo:** extend `MemberRecoveryRow` with `pieceId: String?`, `setupDeviceId: String?` and add them
to the `memberRecoveryRow` SELECT list (`recoverySelfVerify` ignores them — harmless). Audit types
added: `recovery_self_confirm_unbound`, `recovery_self_confirm_stale` (meta: `no_row`/`bound`/`unbound`).

---

## 3. (c) Client obligations per surface

**Universal post-fix confirm rule (BINDING, all surfaces):** every confirm is **bound** (send the
pieceId you hold) and **awaited** (no fire-and-forget in NEW code). Outcomes:
- **200** → captured; proceed.
- **409 `recovery_piece_stale`** → the phrase on screen / just typed is DEAD. Zero the secret, show
  the STATIC notice (no secret material, no interpolation, §F.7):
  *"This recovery phrase was replaced — a newer one was created, possibly from another device.
  A fresh phrase will be shown; discard any phrase you saved before it."*
  Then: if the surface holds a fresh reauth proof (`currentAuthKey` — both gate paths do) →
  **re-run setup + reveal + type-back** (fresh piece, new pieceId). If it does not (enroll path,
  password already dropped) → proceed WITHOUT confirming; the flag is 0 (or was cleared by the
  rotation), so the vault-entry gate re-fires at next entry and heals. **Never mark captured, never
  present the typed phrase as saved.**
- **Network / other failure** → proceed unconfirmed (today's polarity): flag stays 0 → re-gate heals.

**Web (gate = `Welcome.tsx` `RecoveryCaptureGate` + seams in `recovery-capture.ts`, api `client.ts`):**
- `client.recoverySelfSetup` parses `RecoverySelfSetupResponse`; non-JSON 2xx body (pre-fix server
  rollback) ⇒ `pieceId = null`. `client.recoverySelfConfirm(pieceId?: string | null)` sends
  `{pieceId}` when non-null, empty body when null (then the server's legacy deviceId rule applies —
  correct, since the committing web session IS the confirming session).
- `setupAndCommitRecovery` returns `{ recoverySecret, pieceId }`; gate stores pieceId in a ref beside
  `secretRef`. Zero/clear both together (unmount + confirm + stale paths).
- Gate `onConfirmed`: **await** `recoverySelfConfirm(pieceId)`; 409 ⇒ stale rule above (auto re-run
  `run()` → fresh setup/reveal; the tab-bar stays disabled; gate remains un-skippable); other
  failure ⇒ `onReady(...)` as today.
- Enroll happy path (`Welcome.tsx` enroll `onConfirmed`): thread `recoveryPieceId` from the register
  `SessionResponse` into the ready state; **await** `recoverySelfConfirm(recoveryPieceId)`; 409 ⇒
  static notice + proceed unconfirmed (no reauth in hand); other failure ⇒ proceed (unchanged).
- `recovery-capture.test.ts`: cover the stale-retry seam (409 → secret zeroed → re-setup invoked →
  onReady NOT called on the stale pass).

**Desktop (`DesktopState.kt`):**
- `putRecoverySelfSetup` parses the JSON body → pieceId (tolerate `"ok"` ⇒ null); stash
  `pendingPieceId` beside `pendingRecoverySecret`; clear together (B1 teardown guard included).
- Gate path: on `confirmRecoverySaved` type-back match arriving from the capture gate, **await** the
  bound confirm BEFORE `toVault()`; 409 ⇒ static notice + re-run `runRecoveryCapture()` (the stashed
  `pendingCaptureAuthKey` is the reauth proof — do not drop it until confirm succeeds or the gate is
  torn down); IO failure ⇒ `toVault()` (re-gates later).
- Enroll path: `markRecoveryConfirmed(pieceId?)` gains the id from register's `recoveryPieceId`;
  send bound; keep best-effort *navigation* (never block zeroize+navigate on network), but a
  **409 must surface the static replaced-phrase notice** before/at vault landing; proceed unconfirmed.
- Builder may split the shared enroll/gate confirm seam; the behaviors above are what's binding.

**Android (gate being built this wave):** implement bound+awaited from day one — NO unbound calls in
new code. Gate: setup → reveal → type-back → bound confirm → vault; 409 ⇒ stale rule (re-run setup;
the gate holds `currentAuthKey` like desktop). Enroll (`AndvariViewModel.markRecoveryConfirmed`):
bound via register's `recoveryPieceId`, 409 ⇒ static notice + proceed unconfirmed. Offline-unlock
skip semantics mirror desktop (`freshKeys` gating) — an offline unlock never gates.

**Extension:** NO obligations — it has no recovery UI and never calls setup/confirm (verified: the
only `recovery` hits in `extension/src/popup.ts` are a11y copy + a pointer to the web flow).

---

## 4. (d) Enforcement / compat posture — the implementable rule

> **R1 (bound):** confirm with `pieceId` ⇒ accept iff the current `member_recovery.pieceId` is
> non-null and equal. Else `409 recovery_piece_stale`. No exceptions, no grace.
> **R2 (unbound, fielded 0.15/0.16):** confirm without a body ⇒ accept iff a row exists AND
> (`setupDeviceId IS NULL` — pre-v8 piece — OR `setupDeviceId == principal.deviceId`), audited
> `recovery_self_confirm_unbound`. Else `409` + `recovery_self_confirm_stale`.
> **R3:** no `member_recovery` row ⇒ `409`.

**Why this resolves the constraint-3 dilemma — both desiderata hold simultaneously, no least-harm
trade needed:**
- **No fielded lockout, provably:** both fielded confirm call sites are fire-and-forget and
  swallowed — desktop `markRecoveryConfirmed` ("fully runCatching-swallowed… zeroes + navigates
  regardless") and android `AndvariViewModel.markRecoveryConfirmed` (same pattern). A 409 can never
  block any fielded flow; the fielded capture gate remains passable each unlock regardless.
- **No perpetual re-gate for fielded desktops:** the common single-device case satisfies R2
  (the gate's own setup stamped `setupDeviceId` = this device; native apps are single-instance, and
  desktop's retry overwrites `pendingRecoverySecret` with the newest committed piece — verified in
  `runRecoveryCapture` — so an accepted unbound confirm always attests the piece that device
  actually revealed, which IS the current row). So fielded gates converge: confirm accepted → flag=1
  → gate stops.
- **Never attests a rotated piece:** the only rejected unbound confirms are exactly the
  cross-device-rotated ones (`setupDeviceId` differs), and rejection is safe (previous bullet).
  The `setupDeviceId IS NULL` acceptance covers only pre-v8 rows, which by definition have had NO
  post-deploy rotation (any post-deploy setup stamps the row); the residual — a pre-deploy rotation
  whose loser confirms post-deploy — is a one-time, vanishing window, accepted as least-harm and
  visible in the `recovery_self_confirm_unbound` audit.
- **Sunset (non-binding note):** once the fleet min-version pin reaches the first bound-confirm
  release, R2 may be tightened to reject `setupDeviceId IS NULL`; not in this cut.

Residual accepted risk (documented): a fielded device whose unbound confirm 409s reaches the vault
believing its phrase saved; the cleared/unset flag re-gates every device at next entry, and the
dead phrase is only load-bearing if the user also forgets the master password inside that window on
a waived account. This is the floor achievable without shipping new native binaries retroactively.

---

## 5. (e) Spec diffs (exact old → new)

### 5.1 `spec/03-wire-protocol.md` §12 — intro sentence

**OLD:** `**Two-phase**, so the server hands out no pre-auth UVK blob,\nexposes no enumeration oracle, and binds the reset to one replay-bound ticket. **All three\nroutes are refused on the public break-glass origin** (\`403\`, same guard as register) and`

**NEW:** `**Two-phase**, so the server hands out no pre-auth UVK blob,\nexposes no enumeration oracle, and binds the reset to one replay-bound ticket. **All four\nroutes (verify, commit, self-setup, self-confirm) are refused on the public break-glass origin**\n(\`403\`, same guard as register) and`

### 5.2 `spec/03` §12 — self-setup bullet, append after "Audited \`recovery_self_setup\`."

```
  Every setup (and every register) mints a fresh, opaque, server-side **`pieceId`**
  (random, `ServerCrypto.newToken`) stored on the `member_recovery` row together with the
  committing **`setupDeviceId`**; the response is `200 { pieceId }` (was `"ok"` — no
  fielded client parses that body). Because a setup ROTATES the piece, it also clears
  `users.recoveryConfirmed` to 0: the flag always describes the CURRENT piece.
```

### 5.3 `spec/03` §12 — new bullet after self-setup (documents the confirm endpoint, previously a spec gap)

```
- **`POST /recovery/self/confirm` (authenticated) `{ pieceId? }`** — flips the durable,
  cross-device `users.recoveryConfirmed` flag to 1 after the user demonstrably typed the
  revealed phrase back (design §F.9). The flag flips ONLY here — never at register, setup,
  or commit. **Piece binding:** a confirm carrying `pieceId` is accepted iff it equals the
  CURRENT row's `pieceId`; otherwise `409 recovery_piece_stale` — the client must discard
  the shown phrase as invalid and re-run setup + reveal. A body-less confirm (fielded
  pre-binding natives) is accepted only when the current row's `setupDeviceId` is the
  caller's device (or the row predates the columns), so a legacy confirm can never attest
  a piece rotated in from another device; rejected legacy confirms are fail-open for
  availability (fielded confirm calls are fire-and-forget) and the cleared flag re-gates.
  Audited `recovery_self_confirm` / `recovery_self_confirm_unbound` /
  `recovery_self_confirm_stale`. An empty body parses as `pieceId = null`; register's
  response carries the register-committed piece's id as `recoveryPieceId` for the enroll
  path's bound confirm.
```

### 5.4 `spec/03` §12 — errors paragraph

**OLD:** `**Errors:** \`recovery_required\`, \`escrow_not_allowed_when_waived\` (register gate, §7);\n\`recovery_account_not_active\` (commit); an invalid/consumed ticket and all verify failures\nare the uniform \`401\`. New audit types: \`recovery_self_commit\`, \`recovery_self_setup\`.\nNew stored surface: table \`member_recovery\` + column \`invites.escrowPolicy\` (ZK contract:\nspec 02 §5).`

**NEW:** `**Errors:** \`recovery_required\`, \`escrow_not_allowed_when_waived\` (register gate, §7);\n\`recovery_account_not_active\` (commit); \`recovery_piece_stale\` (\`409\`, confirm — stale or\nforeign-device piece); an invalid/consumed ticket and all verify failures are the uniform\n\`401\`. New audit types: \`recovery_self_commit\`, \`recovery_self_setup\`,\n\`recovery_self_confirm\`, \`recovery_self_confirm_unbound\`, \`recovery_self_confirm_stale\`.\nNew stored surface: table \`member_recovery\` (+ v8 \`pieceId\`, \`setupDeviceId\`) + columns\n\`invites.escrowPolicy\`, \`users.recoveryConfirmed\` (ZK contract: spec 02 §5).`

### 5.5 `spec/03` §2 — accountKeys line (pre-existing gap-fix rider, REQUIRED)

**OLD:** `escrowFingerprint, recoverySetupNeeded }\`. \`recoverySetupNeeded\` (additive, default`
**NEW:** `escrowFingerprint, recoverySetupNeeded, recoveryConfirmed }\`. \`recoveryConfirmed\`\n  (additive, default \`false\`) is the §12 capture-confirmation flag — \`false\` ⇒ the client\n  MUST run the vault-entry capture gate before granting vault access; \`accountKeys\` never\n  carries the piece id itself. \`recoverySetupNeeded\` (additive, default`

### 5.6 `spec/03` §7 — register response line

**OLD:** `grant + first device + session; response = the login response).`
**NEW:** `grant + first device + session; response = the login response **plus\n  \`recoveryPieceId\`** — the register-committed recovery piece's opaque id, presented by the\n  enroll path's \`POST /recovery/self/confirm\` (§12); login/refresh never populate it).`

### 5.7 `spec/04-escrow-recovery.md` §6.2 — first bullet, append at its END (after "…is build-contract §F.7.")

```
  The register response returns the committed piece's opaque `recoveryPieceId`; the
  type-back confirm presents it to `POST /recovery/self/confirm`, which flips the durable
  `recoveryConfirmed` flag only when the id still names the CURRENT `member_recovery` row
  (spec 03 §12) — a confirm can never attest a piece that a concurrent setup rotated away.
```

### 5.8 `spec/04` §6.6 — append at end of the section

```
Because `PUT /recovery/self-setup` ROTATES the piece, every setup also clears
`recoveryConfirmed` to 0 and mints a fresh `pieceId` (returned in its response); the
vault-entry capture gate on any device therefore re-fires until the CURRENT piece is
type-backed, and a stale confirm (an interleaved rotation from another device) is refused
`409 recovery_piece_stale` — the client discards the shown phrase and re-runs
setup + reveal. Two devices racing the gate converge on whichever completes
reveal → type-back → confirm against the newest piece; no ordering can leave
`recoveryConfirmed = 1` attesting an uncaptured piece.
```

### 5.9 `spec/02-vault-format.md` — storage table `member_recovery` row (line ~221): append to the column list

`, **pieceId** (opaque random id of the current piece — rotation/confirm binding, spec 03 §12; not a secret), **setupDeviceId** (which device committed it — legacy-confirm scoping), updatedAt`
(replacing the bare `updatedAt` tail), and the ladder note: **OLD** `This table describes **schema v7 exactly**` … **NEW** `This table describes **schema v8 exactly**` + append `v8 = users.escrowPolicy (admin posture reconciliation) + member_recovery.pieceId/setupDeviceId (confirm piece-binding, design 2026-07-13).` — merge this line with the escrowPolicy lane's edit.

---

## 6. Scope rulings

- **`/recovery/self/verify` + `/recovery/self/commit` (forgot-password): OUT OF SCOPE — no binding.**
  Reasoning: verify's `crypto_pwhash_str_verify(recoveryVerifier, recoveryAuthKey)` already binds the
  caller cryptographically to the CURRENT piece — strictly stronger than any token. Commit touches
  `users.verifier/wrappedUvk/kdf*`, never `member_recovery`. A rotation between verify and commit is
  benign: the ticket holder proved possession of the then-current piece; post-commit the (rotated)
  row's cleared flag re-gates capture of the new piece at next unlock. Adding tokens there is scope
  creep and would create a new availability failure (a mid-recovery rotation bricking a valid ticket).
- **No client ever receives another piece's id:** ids travel ONLY in the register response and the
  setup response — never in `AccountKeys`, login, refresh, or admin surfaces.
- **`spec/test-vectors/member-recovery.json`, `MemberRecovery` crypto, `Ad.recovery`, HKDF infos,
  sheet format: UNTOUCHED.** Any lane whose diff touches them is out of contract.

---

## 7. (f) Server test list (`RecoveryTest`, house style; helpers: extend `confirm(vc)` with an optional `pieceId`, add a `selfSetup(vc, …): RecoverySelfSetupResponse`)

New:
1. `recovery_confirm_bound_setsConfirmed` — setup → confirm(pieceId) → 200; `accountKeys.recoveryConfirmed == true`.
2. `recovery_twoDevice_interleaving_confirmNeverAttestsOtherPiece` — **the repro**: device A setup(idA) → device B setup(idB) → confirm A(idA) ⇒ `409 recovery_piece_stale` AND flag stays `false`; confirm B(idB) ⇒ 200, flag `true`. (Assert the 409 body's `error` field.)
3. `recovery_confirm_staleAfterRotation_409` — setup(id1) → setup(id2) same device → confirm(id1) ⇒ 409, flag false; confirm(id2) ⇒ 200.
4. `recovery_setup_rotation_clearsConfirmed` — confirm ⇒ flag true → setup again ⇒ flag back to **false** (leg ii); fresh keys + fresh login both report false.
5. `recovery_confirm_unbound_sameDevice_accepted` — bodyless confirm from the device whose setup committed the current row ⇒ 200 + audit `recovery_self_confirm_unbound`.
6. `recovery_confirm_unbound_afterForeignRotation_409` — device A setup, device B setup, bodyless confirm as A ⇒ 409 (audit `recovery_self_confirm_stale` meta `unbound`); bodyless as B ⇒ 200.
7. `recovery_confirm_unbound_preV8Row_accepted` — direct SQL `UPDATE member_recovery SET pieceId=NULL, setupDeviceId=NULL` → bodyless confirm ⇒ 200 (migration compat).
8. `recovery_confirm_boundAgainstPreV8Row_409` — NULL-id row + confirm(anyId) ⇒ 409.
9. `recovery_register_returnsPieceId_boundEnrollConfirm` — register response `recoveryPieceId` non-null; confirm with it from the register session ⇒ 200.
10. `recovery_confirm_emptyBody_noContentType_parses` — the exact fielded wire shape (POST, no body, no content-type) does not 400/500.
11. `recovery_confirm_malformedBody_400` — non-blank garbage body ⇒ `400 bad_request`, flag untouched.
12. `recovery_selfSetup_responseCarriesPieceId` — JSON `RecoverySelfSetupResponse.pieceId` non-null and equals the id the next bound confirm accepts.
13. `recovery_confirm_noRow_409` — user with `member_recovery` row deleted ⇒ 409 (not 500).

Update (behavior intentionally changed — do not "fix" back):
- `recovery_selfConfirm_setsConfirmed_reflectedOnKeysAndLogin` — its bodyless `confirm(vc)` now rides R2; keep it same-device (register session) or switch to bound.
- `recovery_selfSetup_commits_butDoesNotConfirm` — additionally assert setup CLEARS a previously-true flag.
- Any assertion on the setup route's `"ok"` body → JSON shape.

Web: `recovery-capture.test.ts` stale-seam test (§3). Native lanes: mirror gate tests per their harnesses.

---

## 8. (g) Refutations of the task framing (evidence-anchored)

1. **"Whichever confirms LAST sets recoveryConfirmed=1" — imprecise.** ANY confirm sets it (the
   write is an unconditional idempotent `=1`, `Repo.setRecoveryConfirmed`); order is irrelevant. The
   loss condition is: at least one confirm landed ∧ the FINAL row's piece was never retained by the
   user. Matters because a fix targeting only "last confirm" would under-fix.
2. **Binding alone does NOT close the class.** Ordering 2 (§0: setup A → confirm A → setup B →
   abandon B) leaves flag=1 over an uncaptured piece with zero stale confirms — reachable by merely
   MOUNTING the gate on a second device (both gates call setup on mount: web `RecoveryCaptureGate`
   `useEffect`-run, desktop `startRecoveryCapture`). Hence leg (ii) reset-on-rotate is REQUIRED and
   is inside this contract even though the task framed the fix as token-only.
3. **"Hard-rejecting unbound confirms makes the fielded desktop capture gate UNPASSABLE = vault
   lockout" — overstated.** Both fielded confirm call sites are fire-and-forget and exception-
   swallowed (desktop `markRecoveryConfirmed`, android `AndvariViewModel.markRecoveryConfirmed`), and
   desktop's gate navigates to the vault independent of the confirm's fate (`confirmRecoverySaved`
   zeroes + `toVault()` unconditionally). The true hazard of hard-reject-all is a PERPETUAL RE-GATE
   (flag never flips ⇒ every unlock rotates + re-reveals + re-types ⇒ phrase churn that silently
   invalidates previously saved sheets) — bad enough to justify R2, but it is not a lockout. No
   availability/never-attest deadlock exists (§4), so the constraint's "if both are impossible" fork
   is refuted: both are achievable simultaneously.
4. **"recoverySelfConfirm (near 420) is a separate tx" — confirmed**, but note the deeper fact: `Db`
   is a single-connection, `ReentrantLock`-serialized SQLite, so NO txs ever interleave; the race is
   purely BETWEEN txs at flow level. Builders must not "fix" this with DB isolation levels — the fix
   is the semantic binding above, with compare+write in one tx (§2.2) only to keep the decision
   atomic against an adjacent setup tx.
5. **Pre-existing spec gap:** `POST /recovery/self/confirm` and `AccountKeys.recoveryConfirmed` are
   in shipped code but absent from `spec/03` §2/§12 (grep: no `self/confirm` hit in spec/). §5.3/§5.5
   fix this as riders; without them the §12 diff would document a binding for an endpoint the spec
   doesn't have.
6. **The type-back is client-side** (`MemberRecovery.confirmMatches` on natives, web mirror) — the
   server never validates the typed phrase and this contract does NOT change that (doing so would
   ship the secret to the server, violating ZK). The binding attests "the client that revealed piece
   X confirms X", not "the server checked the phrase" — the honest scope of `recoveryConfirmed`.
