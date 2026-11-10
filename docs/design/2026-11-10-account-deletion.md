# Account deletion — server, specs, web (2026-11-10)

**Status:** design and build record for branch `account-deletion` (cut from the 0.29.1 release). The server, the
normative specs (spec 03 §13 and the amendments listed in §10) and the web client land here. The native clients
(Android, desktop, iOS) follow on another branch against the same wire contract (§3); nothing in it is web-specific.

---

## 1. Why, and the owner decisions

Google Play's User Data policy and Apple's App Store guideline 5.1.1(v) both require that an app which creates accounts
lets the user delete the account from inside the app, and Google also wants a web route for it. andvari had no account
deletion at all — not on the server, not in any client. An admin could only *disable* an account (spec 03 §7), which
keeps every row, every key wrap and every audit line forever.

Owner decisions, binding for this design:

| # | Decision |
|---|---|
| D1 | Deletion is **refused** while the account owns a shared vault that still has other members. The member first deletes that vault or transfers its ownership, then retries. |
| D2 | The same refusal applies to the **last admin** of a household or organisation that has other members, and the refusal names exactly which vaults or roles block. |
| D3 | Vaults the account owns that have **no other members** are deleted with it. Where the account is a member but not the owner, its grant is removed **as if it had left**. |
| D4 | Security audit events (sign-ins, revocations, the deletion itself) are **kept for 90 days with the email removed**, under a pseudonymous id that cannot be reversed to the email. |
| D5 | The request needs a **fresh master-password proof** — the reauth the server already uses for sensitive operations — **plus the TOTP code** when the account has one. |

"Household or organisation" maps onto one thing in andvari: the **instance**. There is no household entity separate
from the set of accounts on a server, and admin is an instance-wide role (`users.isAdmin`).

## 2. What deletion does, in one table

| What | Outcome |
|---|---|
| Sessions and devices | Every row deleted. Deleting them **is** the revocation: `authenticate`, `POST /auth/refresh` and the WebSocket live-session re-check all find nothing. Every open socket of the account gets `{"type":"revoked"}` and is closed. |
| Personal vault, and every vault only the account holds | **Purged now**, with the janitor's own statements (shared code, §6.2): items become ciphertext-free tombstones, archived versions and attachment rows go, every grant's key material on the vault is blanked, the blob files are unlinked from disk. The vault row stays as a purged tombstone (a vaultId is never recycled). |
| A shared vault the account soft-deleted and is still in grace | Purged now too: nobody else can restore it (restore is the deleting owner's alone), so there is nothing to wait for. |
| Memberships in other people's vaults | Grant row removed — the leave. Items the account wrote there stay: they belong to the vault. |
| Transfer offers naming the account | Cleared, vault rev bumped, audited as a system action (`vault_transfer_cancel`, meta `<vault>:target_deleted`). |
| Escrow + retained escrow, recovery piece, usage ledger, account state, personal wrap | Rows deleted. Admin recovery and self-service recovery of the account become impossible, by intent. |
| Invites | Every invite row naming the account's address (pending ones it received and the one it registered with — each carries the email in plaintext), and every **unused** invite it minted as an admin. |
| Audit | Re-keyed to a fresh random pseudonym (security types) or deleted (activity types); the account's id is replaced by the pseudonym in every other row's meta; the janitor deletes the pseudonym's rows 90 days after the deletion (§9). |
| The user row | Deleted, last. The email can register again — as a brand-new account, through a new invite (registration is invite-only). |
| The ids it leaves behind | Retired for good: the SHA-256 of the deleted userId and of the audit pseudonym go into `retired_ids` (schema v16), and register refuses both as `user_id_taken` — the client chooses its userId, so without this the old id could be registered again (reviving lookups of it), or the pseudonym (whose rows the 90-day purge would then erase from the new account). |

It is **one database transaction**: either every row above changes or none does (§6). The blob files follow the commit
(§6.3).

## 3. The wire contract (normative text: spec 03 §13)

### 3.1 `GET /api/v1/account/delete/preview` → `200 AccountDeletePreview`

```jsonc
{ "blockers": [ { "kind": "shared_vault", "vaultId": "…", "others": 2 },
                { "kind": "last_admin", "others": 5 } ],
  "deletedVaults": [ "…" ],   // personal + solely held + soft-deleted-in-grace, sorted
  "leftVaults":    [ "…" ],   // memberships dropped, sorted
  "totpRequired": true }      // the deletion must carry the current code
```

A snapshot for the UI, so a client can show the blockers (with links) and the consequences **before** asking for the
master password. Read-only, refused on the break-glass origin like the deletion itself (§4.4). The deletion re-checks
everything inside its own transaction.

### 3.2 `POST /api/v1/account/delete { confirmEmail, currentAuthKey, totp? }` → `200 { deletedAt }`

- `confirmEmail` — the address the human typed to confirm, compared trimmed and lowercased with the account's. The UI's
  "type your email" guard is therefore binding for **every** client, not only for the polite ones.
- `currentAuthKey` — the fresh master-password proof (§4.2).
- `totp` — the current code, required when the account has server TOTP enrolled.

POST, not `DELETE /account`: the house's destructive lifecycle routes are POSTs with a body (`POST /vaults/{id}/delete`),
and a DELETE with a body is fragile through proxies.

### 3.3 Errors

| Status | `error` | When | Audited |
|---|---|---|---|
| 400 | `confirm_email_mismatch` | `confirmEmail` is not the account's address | no (a UX guard) |
| 400 | `totp_code_required` | TOTP enrolled, no code sent | no |
| 400 | `bad_totp_code` | wrong code, or a step already used | `totp_verify_fail` meta `account_delete` / `account_delete_replay` |
| 403 | `reauth_failed` | `currentAuthKey` does not verify | `account_delete_reauth_fail` |
| 401 | `credential_changed` | the password changed, or this session was revoked, between the verify and the commit | `account_delete_reauth_fail` meta `credential_changed` |
| 403 | `account_delete_public_disabled` | the request came through the break-glass twin origin | no |
| 403 | `totp_enrollment_required` | a §2.6 restricted session (instance requires TOTP, account not enrolled) | no (the existing single gate) |
| 409 | `account_delete_blocked` + `blockers` | a refusal rule holds (§5) | `account_delete_denied` meta = the kinds |
| 429 | `rate_limited` | the hourly bucket, or the live-factor bucket | no |
| 426 | `upgrade_required` | min-version pin | no |

The 409 body is the house `ApiError` shape plus an additive `blockers` array (`AccountDeleteBlockedError` in core), so a
client that decodes only `ApiError` still reads the code. A blocker kind a client does not know MUST be shown as a
blocker it cannot explain, never skipped.

## 4. The gate

### 4.1 Order

All of it OUTSIDE the writer lock, in this order, the first failure deciding:

1. route: authenticated (`requirePrincipal`, so a §2.6 restricted session is refused like everywhere else) →
   `enforceVersion` → **break-glass refusal** → the `account_delete:{userId}` bucket → body;
2. typed email;
3. **TOTP, before the password** (when enrolled);
4. master-password reauth;
5. then the transaction (§6), whose first act re-checks the credential epoch.

### 4.2 Reauth: the existing mechanism

`currentAuthKey` is verified against the login verifier exactly as `PUT /account/password`, `PUT /recovery/self-setup`,
the personal-wrap re-designation and the first-TOTP-enrollment gate verify it — the same Argon2id string verify. The web
client derives it through `Account.reauthAuthKey`, the one fenced in-session derivation (KDF floor, and only the salt
this session unlocked with — A9 M-1), which also PROVES the password locally (the wrap key must open the served
`wrappedUvk` to this session's UVK) before anything leaves the browser.

A miss is `403 reauth_failed`, the code of the newest reauth gate (first TOTP enrollment), **not** the password change's
`401`: an authenticated route answering 401 sends every web client into a token refresh and a retry.

### 4.3 TOTP: before the password, consumed in the transaction

When the account has server TOTP enrolled, a missing code is `400 totp_code_required` and a wrong one `400 bad_totp_code`
— the authenticated rotation gate's codes (spec 03 §2), not login's 401s. The code is checked **before** the password on
purpose: a stolen session without the factor never reaches the password verify, so this route cannot be used to confirm
a guessed master password (the spec 05 T11 / F7 "password before the second factor" class). With the factor, a wrong
password answers `403 reauth_failed` as above.

The step is verified outside the lock and **consumed inside the transaction** (`UPDATE users SET totpLastStep=? WHERE
… AND totpLastStep<?` must hit one row, else the replay answer): a wrong password burns nothing, two racing requests
with one code cannot both pass, and a refused (409) attempt commits the consumed step with its audit row.

A code draws on the shared live-factor bucket `totp_verify:{userId}` (5/min) like `/totp/disable` and the rotation
gate — the keys are cut by which secret a call checks.

### 4.4 The break-glass origin: refused

Both routes answer `403 account_delete_public_disabled` on the opt-in break-glass twin origin, before any work. Nothing
in the specs argues for allowing it, and everything argues against: the emergency origin exists to READ a vault from
somewhere hostile with TOTP; spec 03 refuses sharing administration (§10), every lifecycle route (§11), registration,
refresh and the recovery routes there as "sit-at-home operations", and account deletion is the most destructive of
them. A member reaches the deletion from the household's usual origin with the same session. Single-origin instances —
the default topology — are unaffected.

### 4.5 Rate limits

`account_delete:{userId}`, **5 per hour**. Each attempt is a memory-hard verify, and every reauth route a session holder
can reach is another password guess per window (password change, recovery setup and personal-wrap re-designation are
each 5/min). An account is deleted once; five typos in an hour is already a bad day, and the hourly window keeps the
added guessing surface at 120/day. The preview is a cheap read and carries no bucket (like `GET /vaults/{id}/members`).

## 5. Refusal rules (blockers)

Evaluated inside the deletion transaction (and, as a snapshot, by the preview), stable order:

| Kind | Holds when | What the member does |
|---|---|---|
| `shared_vault` (one per vault, `vaultId`, `others`) | the account holds an **active owner** grant to a vault and `others ≥ 1` other accounts hold active grants to it | delete the vault (spec 03 §11, soft delete) or transfer it (offer → accept); a vault in grace no longer blocks, and is purged with the account |
| `last_admin` (`others`) | the account is an active admin, **no other account is an active admin**, and `others ≥ 1` other accounts exist (any status) | invite a new account as admin, or recover a disabled admin (admin recovery reactivates it) |

Why `last_admin` counts disabled accounts: a disabled account comes back only through an admin's recovery upload, so an
instance with disabled accounts and no admin strands them exactly as one with active members would. An instance whose
**only** account deletes itself is left empty, not stranded: its operator re-bootstraps it (`ANDVARI_BOOTSTRAP_TOKEN`,
seeded at the next start). For that to hold, the deletion of the LAST account also deletes every remaining invite row —
the used `*` row it registered through would otherwise count, for `seedBootstrap`, as "an invite exists" and block the
re-mint silently until the janitor pruned it (~33 days) — and `seedBootstrap` itself now clears every invite row when it
finds no account, before minting (the belt for a database emptied any other way, or by an older build).

Known limitation, recorded here and in the report: andvari has **no "promote to admin" route** — admin is set only on
the invite — and an existing member's address cannot be invited (`email_taken`). So the last-admin blocker is resolved
only by a NEW admin account (or a recovered disabled admin). A promote route is a natural follow-up; it is out of scope
(it is a new admin power with its own threat model).

The refusal is audited `account_delete_denied` (meta: the kinds, ids-free), written inside the transaction, which then
**commits** (with the consumed TOTP step) before the `409` is thrown — the `disableUser` pattern, so the audit row
cannot be rolled back by its own refusal.

## 6. The deletion transaction

### 6.1 Every table

In `AccountDeletion.deleteRows` (server), inside the caller's `db.tx`, after the gate and an empty blocker list:

| Table | Change |
|---|---|
| `users` | the row is deleted **last**, after every row that references it (FK); `check(removed == 1)` |
| `sessions` | every row of the account (and of its devices) deleted — before `devices` (FK) |
| `devices` | every row of the account deleted |
| `mutations` | the idempotency rows of the account's devices deleted (journal of devices that no longer exist) |
| `grants` | (a) on each purged vault: every row's key material blanked (`wrappedVk=''`, `sealedVk=NULL`, `signedGrant=NULL`) — other accounts' revoked rows are retained, as at a janitor purge; (b) every row whose `userId` is the account deleted (owner rows of purged vaults, member rows elsewhere — the leave —, revoked rows) |
| `vaults` | purged vaults: `metaBlob=''`, `deletedAt`/`purgeAt` set if unset, `purgedAt=now`, `deletedBy=NULL` (it named the account), pending-offer fields cleared. Vaults whose pending offer names the account: offer cleared, rev bumped. Every OTHER vault whose `deletedBy` names the account (one it deleted that the janitor already purged, or one it deleted, restored — restore keeps the column — and handed over): `deletedBy=NULL`; nothing reads the column. A test scans every TEXT column of every table for the deleted userId and address afterwards |
| `items` | purged vaults: skeletal tombstones (`deleted=1`, `blob=NULL`, `blobSize=0`, `attachmentIds='[]'`, `conflict=0`, `updatedAt=now`, **no rev bump**); they age out through the 30-day tombstone rule. Items the account wrote into other vaults: untouched |
| `item_versions` | purged vaults' rows deleted |
| `attachments` | purged vaults' rows deleted (ids collected for the post-commit unlink) |
| `changes` | one row per membership dropped (as a leave records one, so the co-members' bell carries a fresh rev) and one per offer cleared; otherwise untouched |
| `escrow`, `escrow_legacy`, `member_recovery`, `usage_ledger`, `account_state`, `personal_wrap` | the account's row deleted (each a FK child of `users`: a new per-account table not added to the list fails the user delete on its foreign key and rolls everything back — loud, never a silent leftover) |
| `invites` | rows with the account's email deleted; unused rows it minted deleted (below); when it was the instance's last account, every row (§5) |
| `audit` | §9 |
| `retired_ids` (schema v16) | one row each for the SHA-256 of the deleted userId and of the pseudonym (`INSERT OR IGNORE`); register checks it beside `users` |
| `removal_nonces`, `policies`, `meta` | untouched (vault-keyed random nonces; instance config) |

**Invites the account minted.** Invites have no issuer column. The issuer's `invite_create` row — written in the same
transaction as the invite, meta = the token-hash prefix — is the record, and it outlives every invite (365-day audit
retention vs a ≤ 72 h invite), so `DELETE FROM invites WHERE usedAt IS NULL AND substr(tokenHash,1,12) IN (SELECT meta
FROM audit WHERE type='invite_create' AND userId=?)` is complete. It runs before the audit pass re-keys those rows. No
column was added for it (a `createdBy` column would have needed a spec 02 §5 row and its own scrubbing); the one schema
change of this feature is v16's `retired_ids` table.

### 6.2 One purge, shared with the janitor

The destructive statements of a vault purge now live in one function, `Repo.purgeVaultContents`, called by the janitor's
post-grace purge (with its in-transaction due-check as an `EXISTS` guard on every statement, exactly as before) and by
account deletion (which has already decided inside its own transaction). The janitor's comment "a new key-carrier column
must be added HERE too" (q43) now protects both paths by construction.

### 6.3 Files on disk

Attachment blobs (`blobDir/{attachmentId}`) are unlinked **after** the commit — a rollback must leave every file in
place — in chunks of 50, each chunk inside one short DB read that re-checks the row is still absent (the push path's
TOCTOU guard: an idempotent re-upload of the same id that committed meanwhile keeps its file). A crash between the
commit and the unlink leaves rowless files, which the hourly orphan sweep deletes once they pass its 24 h TTL. After the
commit the WAL is checkpointed and truncated (`secure_delete` is on): verifier, wrapped UVK, escrow blobs, the recovery
piece, grant key material and item ciphertext were destroyed in place (server scan F5).

### 6.4 After the commit

1. WAL `checkpoint(TRUNCATE)`; 2. blob unlinks; 3. `onChange` bells the co-members (§8); 4. the route sends `revoked` to
every socket of the account and closes it (`Notifier.notifyRevokedUser`). In-memory state that still names the account
is inert: a WebSocket ticket minted ≤ 30 s earlier is refused by the live-session re-check at connect; a self-recovery
ticket finds no user at commit (`400 no_such_user`); the rate-limiter and backoff entries age out.

## 7. Concurrency

The gate runs outside the lock; the blockers and every write run in one transaction; SQLite on one connection serialises
write transactions totally. Each race therefore resolves one of two ways, and both are safe:

| Racing operation | Commits before the deletion tx | Runs after it |
|---|---|---|
| A share of a vault the account owns (its other device) | the tx sees the new member → `409 shared_vault` | `requireOwnerOfShared` finds no grant → 403 |
| Someone adds the account to their vault | its grant is dropped with the rest | target lookup → `404 no_such_user` |
| A transfer accept making the account an owner of a shared vault | `409 shared_vault` | `no_grant` |
| A push / restore into a vault the account alone holds | purged with the rest | no grant → `denied` (audited without the id, below) |
| An attachment upload | row collected and the file unlinked | the upload's commit re-checks the grant → `403 no_grant`, its part file deleted |
| A sync pull | a consistent snapshot | `401` (its session is gone) |
| A password change / recovery / admin recovery | the epoch check fails → `401 credential_changed` | finds no user |
| A second deletion (another device) | — | finds no user → `401` |

A request that authenticated before the commit and writes an audit row after it (a queued push's `push_denied`, a racing
sign-out) would re-introduce the raw userId into the trail the deletion just scrubbed. `Repo.auditOn` therefore stores a
row naming a user the table no longer holds with `userId NULL` and meta prefixed `deleted_account` — the event is kept,
the id is not. One primary-key lookup per audit row; every live caller names an existing user or none. The deletion's
own row is written through the one exempt writer, `auditPseudonymOn`.

The test seam `Service.accountDeletePreTxProbe` sits exactly in the window between the gate and the transaction, so the
tests drive these interleavings deterministically rather than hoping for them (AccountDeletionRaceTest).

## 8. What everyone else sees afterwards

| Who | Sees |
|---|---|
| Co-members of a vault the account was a member of | The account is gone from the members list (`GET /vaults/{id}/members` joins active grants). Items it wrote stay. A rev bell; their next pull carries nothing new for them (a leave behaves the same). |
| Members of a vault whose transfer offer named the account | The offer banner clears (the vault row re-delivers with `pendingTransfer` absent). |
| Ex-members of a vault the account alone held | Nothing: they lost access before; a purge bumps no rev and sends no row. |
| Members of a vault the account soft-deleted | Nothing new: they hold it in the holding area until `purgeAt` (client-side), restore was only ever the deleting owner's. |
| Admins | The account is gone from the users list. The audit view shows its retained events under the pseudonym and one `account_delete` row. |
| Anyone looking the account up | `POST /users/lookup` and `GET /users/{id}/identity` answer `404 no_such_user`; adding the old userId answers `404 no_such_user`. |
| Contact pins of the account's identity key | They live only inside other accounts' UVK-sealed account state (spec 03 §3); the server cannot read or edit them, and does not. They are inert: a pin authorizes nothing by itself and the old userId can never be granted again. If the address registers again, it is a NEW account with a new identity key, and spec 01 §6's add-member identity rule refuses to add it while a pin records that email for the old userId — the owner verifies the person again (unpin, re-verify), which is exactly the fail-closed outcome a new key deserves. No spec text asks the server to remove pins; a client MAY offer to drop a pin whose userId the server reports gone. Not built here. |

## 9. Audit: kept, pseudonymised, purged

**The pseudonym** is a fresh random UUIDv4 minted at deletion. It is never derived from the userId or the email, and the
mapping is not stored anywhere, so nothing on the server reverses it. It is shaped like a userId on purpose: every
client checks served ids against the UUID grammar (spec 05 R18), so a differently shaped value would make the admin
audit view drop the rows. It names no account.

**Kept for 90 days, re-keyed to the pseudonym** (`AccountDeletion.RETAINED_AUDIT_TYPES`) — the owner's "sign-ins,
revocations, the deletion itself", read as the account's security record:

- sign-in and sessions: `register`, `login`, `login_fail`, `login_fail_totp`, `logout`, `refresh_reuse`;
- credentials and the second factor: `password_change(_fail)`, `personal_wrap_reauth_fail`, `escrow_self_upload`,
  `totp_enroll`, `totp_rotate`, `totp_disable`, `totp_verify_fail`, `totp_setup_reauth_fail`;
- self-service recovery: `recovery_self_verify(_fail)`, `recovery_self_commit`, `recovery_self_setup(_fail)`;
- intrusion signals: `push_denied`, `attachment_cross_vault`;
- the deletion: `account_delete`, `account_delete_denied`, `account_delete_reauth_fail`;
- the account's admin actions on the instance: `invite_create`, `user_disable(_denied)`, `device_revoke(_denied)`,
  `recovery_apply`, `escrow_admin_read`, `escrow_legacy_dropped`, `escrow_legacy_purged`, `policy_update`.

**Deleted with the account** (`DROPPED_AUDIT_TYPES`): its vault, item and sharing activity (`vault_*`, `attachment_upload`,
`item_restore`, `item_purge`), the personal-wrap designation, lookups (`user_lookup`, `user_identity_lookup`) and the
recovery-capture confirmations — activity about data that no longer exists.

A type in neither set fails the build: `AccountDeletionTest.everyAuditTypeTheServerWrites_isClassifiedRetainedOrDropped`
reads every audit type out of the server sources.

**Other accounts' rows** that name the account in meta (an admin's `user_disable`, an owner's `vault_member_add`, a
`user_lookup` that found it) keep their ordinary 365-day retention with the userId replaced by the pseudonym
(`replace(meta, userId, pseudonym)`): they are those accounts' history.

**No row ever held the email** (spec 02 §5: audit rows carry no emails of existing users; `register` and `invite_create`
carry a token-hash prefix). The invite rows that did hold it are deleted (§6.1).

**The 90-day purge** is janitor rule (i): `DELETE FROM audit WHERE userId IN (SELECT userId FROM audit WHERE
type='account_delete' AND at < now − 90 d)`. The deletion's own row is the clock (it carries the pseudonym and the
instant) and goes with the rest. The window runs from the **deletion**, not from each event: an incident review that
starts from a deletion needs the events just before it.

**Outside the database**: every audit line also went to stdout → journald → the operator's log pipeline with the raw
userId (never the email). Those copies follow the operator's log retention; the server cannot recall them. Recorded as a
residual (spec 05 R19).

## 10. Spec conflicts and how they are resolved

| Spec text | Conflict | Resolution |
|---|---|---|
| spec 02 §4 "vault rows are NEVER hard-deleted; `vaultId` is never recycled" and §7 "Vault tombstone rows and all grant rows are retained indefinitely" | the account's own grant rows must go (FK to `users`, and they name the account) | Vault rows are kept (purged tombstones), so `vaultId` is still never recycled. **Grant rows are retained indefinitely except a deleted account's own rows.** The property they protect still holds: a push against the purged vault needs an authenticated session of an existing account; the deleted account has none, and every other account's rows are retained. Amended in spec 02 §4/§7. |
| spec 02 §7 "Vault deletion: a soft-delete with a 7-day grace" | an account's vaults are purged immediately | Account deletion is not a vault delete: there is nobody left who could restore. Amended (§7 names the second purge path). |
| spec 01 §5 self-identity backstop: "an account deleted and re-registered under the same email on the same origin is refused on a device that unlocked the old one, until that device's record is removed by hand" | conflicts with "the email can register again" on the deleting device | The deleting device removes its own records (the userId-keyed pin, and the email binding only where it names the deleted userId) when the deletion succeeds. Any OTHER device that unlocked the old account keeps refusing a re-registered account under that email until its record is removed by hand — the backstop is doing its job (the server cannot prove the new account is the same human), so it stays, documented as residual R19(c). |
| spec 02 §5 audit row: "userId … never … emails of existing users" | a userId column can now hold a pseudonym that names no user | Amended: a deleted account's retained rows carry a random pseudonym; a row written for a user that no longer exists carries none (`deleted_account`). |
| spec 03 §6 WS frames "exhaustively `rev` and `revoked`" | — | No new frame: the deletion uses `revoked`. |
| spec 03 §11 "Admin succession: no admin lifecycle route exists BY DESIGN" | — | Unchanged: deletion is self-service only. There is no admin route that deletes another account (it would be a server power to destroy members' vaults); disable stays the admin tool. |
| spec 04 §4 "Escrow ⊥ vault lifecycle … recovery doubles as vault succession" | a deleted account has no escrow | Amended: deletion removes escrow, retained escrow and the recovery piece; neither recovery path survives it. That is the point, and the UI says so. |
| spec 03 §2 login TOTP answers (`401 totp_required`) | the deletion answers `400 totp_code_required` / `bad_totp_code` | Not a conflict: the deletion is an authenticated route and uses the authenticated rotation gate's codes (§4.3). |
| Audit retention (365 days, janitor rule (g), not in any spec) | a 90-day rule for deleted accounts | Written into spec 03 §13 and spec 05 R19; the 365-day rule is restated there for context. |

## 11. Web client flow

**Settings → Delete account** (the last card; a danger card in the house idiom):

1. **Collapsed**: one paragraph — what deleting means — and "Delete my account…".
2. **Opened**: the preview is fetched. The card lists what goes (the account, its personal vault and the N vaults only it
   holds — by NAME, decrypted locally from the store's vault list —, every device signed in, the recovery phrase and the
   household recovery backup, invites it sent that nobody used) and the M vaults it will leave (what it saved there stays
   for the others), "This can't be undone", and a "Back up first" link.
3. **Blockers**, when the preview has any: each on its own line with a link — "Open “Family” settings →" (Sharing, the
   vault's settings, where Transfer and Delete live) or "Open Administration →" for `last_admin` — and the form is not
   shown. An unknown kind is listed as a blocker this version cannot explain ("Reload to update, or ask whoever runs your
   server"), and a refusal that named nothing still reads as blocked; neither offers the form.
4. **The form**, when there are none: "Type your email" (must match the session's address, trimmed and case-folded; the
   server re-checks), the master password, the authenticator code when `totpRequired`, and "Delete my account
   permanently", enabled only when all are filled and the email matches.
5. **Submit**: `client.accountKeys()` → `account.reauthAuthKey(password, keys)` (a wrong password is caught LOCALLY and
   never sent) → `POST /account/delete`. Errors map to one sentence each (`ui/account-delete.ts`); a 409 re-renders the
   blockers from the response; a network failure says the outcome is unknown.
6. **Success**: `App.onAccountDeleted` wipes this browser's state for the account — the session and the tab's token
   slot, the offline copy (IndexedDB), every `andvari.*` key scoped to the userId (client state, the cache opt-in, the
   auto-lock and last-export stamps), the in-session breach cache, and the self-identity records (§10) — and lands on the
   sign-in card with "Your andvari account was deleted…". Other tabs follow through the session key's `storage` event.
   Device-wide preferences (theme, install id, server address, the device's cache opt-out) are not account data and stay.

Logic lives in pure, tested modules (`ui/account-delete.ts`, `session.wipeLocalAccountState`,
`selfidentity.forgetSelfIdentity`, the API client methods); the card body is a pure render of its model, tested with
`renderToStaticMarkup` (the repository's node-environment UI test posture).

## 12. Non-goals and residuals

- **No grace period.** Deletion is immediate and irreversible. A grace window would have to keep the escrow, the
  recovery piece and the credentials alive — the opposite of D3/D5's intent — and the store policies want the deletion
  to actually happen. The UI asks for a typed email, the password and the code, and offers a backup first.
- **No admin-initiated deletion** (§10). Disable remains the admin tool.
- **Backups.** The operator's backups keep everything until they rotate out (spec 05 T7; R7's ~30-day note). Deletion is
  not cryptographic erasure towards anyone who already held a vault key (R7 extended).
- **Logs.** The journald/log-pipeline copies of audit lines keep the raw userId under the operator's retention (§9).
- **Other devices.** Co-members' clients may hold the account's email and display name in memory from earlier members
  lists; the account's own other devices keep their self-identity record (§10) and, until they next reach the server,
  their offline copy (spec 05 T3: revocation takes effect at the next connectivity, which here answers 401).
- **Native clients**: not on this branch. They need the same flow and the same local wipe; the wire contract is final.

## 13. Tests

Server (`AccountDeletionTest`, `AccountDeletionRaceTest`): the full deletion (every table, the blob file gone from disk,
the household's vault and its members untouched, every token dead, the vaultId not recyclable, the email registering
again as a new account with a new salt); both refusal kinds, their audit rows and their resolutions (transfer, delete,
a second admin; the only account deleting itself); the gate (typed email, a wrong proof, TOTP before the password, a
replayed code after a refused attempt, the hourly bucket, the break-glass origin); the WebSocket `revoked` frame and the
co-member's bell; the offer clear; the pseudonymised trail and its 90-day purge; the straggler belt; invites; the
audit-type classification tripwire; and the races — a share, a push + upload and a password change landing between the
gate and the transaction, plus pushes, pulls and a second deletion racing for real. Web (vitest): the client methods and
their wire shapes, the blocked-response parsing, the flow logic and error sentences, the card's static render, the local
wipe and the self-identity forget.
