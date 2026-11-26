# andvari spec 03 — wire protocol

HTTPS JSON API under `/api/v1`, served on **one origin per instance**: the instance's canonical
origin (`ANDVARI_CANONICAL_ORIGIN`), which is also the `origin` its instance card names (§17). There
is no second origin with other rules. Store builds are baked to the public instance
`https://vault.andvaripass.com` (`spec/public-instance.json`); every client can be pointed at any
other instance, behind the Trust Gate (spec 05 R22).

Every binary field is unpadded base64url unless its row says otherwise. Request bodies over
**256 KiB** are refused (`413 body_too_large`), except attachment uploads (streamed and
quota-checked, §9) and these per-route ceilings: `POST /sync/push` and `POST /items/{id}/restore`
**8 MiB** (a CSV import batch arrives as one body; a restore re-uploads that item's blob, which push
accepted at up to 8 MiB); `PUT /usage` **512 KiB plus framing headroom**, so an oversized ledger
reaches §3's `bad_usage_blob` check; `PUT /account/state` and `PUT /account/recovery` **1 MiB plus
64 KiB of framing headroom**, so a full account-state blob (§3) reaches its own check;
`POST /account/delete` **1 MiB** (up to 500 leave frames, §13).

## 0. Route index

### 0.1 Conventions used by every route

**Field presence.** Every field a message lists is present in its JSON with its value, also when that
value is one a library would call a default: `kdfParams` always carries `v`, `alg`, `ops` and
`memBytes`, a `false` is written as `false`, an empty list as `[]`. A field marked optional (`?`) is
absent when it has no value; `null` is sent only where a row gives `null` a meaning of its own. This
binds both directions, and a receiver may refuse a message with a listed field missing. No engine's
serialisation defaults decide what a message means: the server once left out the `kdfParams` fields
equal to its own defaults, a client in another language had to guess them, and a later change of
those defaults would have made every sign-in there look like a wrong password.

**Field types.** The statement grammar of spec 01 §5.1 defines `uuid`, `b64_16`, `b64_32`, `hex64`,
`ms`, `int`, `origin`, `name`, `role`, `hex64n` and `email_b64n`; this document uses the same names
for JSON fields. In addition:

| Type | Meaning |
|---|---|
| `b64` | unpadded base64url of some bytes; the row gives the cap, in characters of the encoded string unless it says "decoded" |
| `frame` | a `b64` holding one signed-statement frame (spec 01 §5.1); the row names the purpose |
| `envelope` | a `b64` holding one AEAD envelope (spec 02 §2) |
| `sealed` | a `b64` holding one `crypto_box_seal` ciphertext |
| `emailText` | the address as the person typed it; the server derives `emailNorm` (§0.3) and refuses an address that has none |
| `platform` | one of `android`, `ios`, `windows`, `macos`, `linux`, `web`, `cli`, `extension` |
| `text` | a JSON string of 1 to 256 UTF-16 characters, well formed (no lone surrogate), with none of the code points the `name` type refuses (spec 01 §5.1: the controls, U+00AD, U+061C, U+180E, U+200B–U+200F, U+2028–U+202E, U+2060–U+2064, U+2066–U+206F, U+FEFF, U+FFF9–U+FFFB), so no direction override, zero-width character or line or paragraph separator; no normalisation, and unlike `name` a leading or trailing space is allowed (device names, display names; rule of 2026-11-16). A refusal is the field's `400 bad_<field>` (`bad_device`, `bad_display_name`). Clients draw it as plain text |
| `head` | `{seq: int, hash: hex64, at: ms}`, a log head (§10) |
| `ok` | the plain-text body `ok` (`text/plain`), as every existing write route that returns nothing else |

Field names are lowerCamelCase. **Numeric widths:** millisecond times (`ms`, `expiresAt`,
`createdAt` and the like), byte counts and quotas, `seq`, `rev` and `ttlMs` are 64-bit integers.
**Codes people type** — the sign-up code, two-step (TOTP) codes, the recovery-request email code and
the request code — are JSON **strings**, never numbers, so leading zeros survive. **Expiry is
exclusive everywhere:** a link, an offer, a code or a ticket is valid while `now < expiresAt` and has
expired at `now = expiresAt`. A client MUST
ignore response fields it does not know. A server
refuses request fields a route does not take only where the route says so; otherwise it ignores them.

**Redirects.** No route answers with a redirect: a client follows none and reads a `3xx` as no answer
(never a refusal, an empty result or a wrong password), so a `Location` cannot make it send a request,
a credential or a password proof anywhere, or dial an address the origin grammar refuses.

**What the browser may say of a commit's answer** (rules of 2026-11-17; the web client keeps them
since 2026-11-17). A commit here is a kit recovery's commit (§12), a registration (§14.3), and any
other request after which the person holds a new password or a new kit. Three outcomes, each with
its own words:
- **"The server stored it"** is said only of an answer that only this server could have given: a
  `2xx` with the JSON content type, no redirect followed, whose body parses to a JSON object with
  no `error` member that names the account this browser sent. Any other `2xx` (an empty body, a
  page from a proxy or a captive portal, a front's own JSON, an object that names another account)
  is "cannot be told".
- **"Nothing was sent, nothing changed"** is said only where nothing was: the browser's own traffic
  gate states at every place it is raised whether anything had been sent, and a stop before
  sending is this outcome (the old kit and the old password are as before). Its line says the way
  on, which is to load the page again: the browser has forgotten the server, so trying again in the
  same form would send nothing.
- **"Cannot be told"** is everything else: a request sent whose answer did not arrive, an answer
  whose status arrived and whose body could not be read to its end (never "the server didn't
  answer", which is said only when it did not), a stop by the gate after an answer was dropped, and
  every answer above that is not the server's own. After a recovery the screen shows the new kit as
  the stored case does and says: keep both kits; try the new password first; if it is refused,
  nothing was changed and the old kit and the old password are as before. After a registration it
  shows the kit and says: try to sign in; if there is no such account, nothing was made.

**Error envelope.** Every refusal is `{ "error": "<code>", "message": "<human>" }` with the status in
the index. Clients key on `error`, never on the status alone or on `message`. A few refusals carry
extra fields **beside** `error` and `message`, at the top level, and the index writes them in braces:
`409 log_head_moved {seq, hash, at}` is `{"error":"log_head_moved","message":…,"seq":…,"hash":…,"at":…}`.

**Who may call** (the index's third column):

| Mark | Meaning |
|---|---|
| none | unauthenticated; a capability in the body or path (a link token, a device-link proof, a poll secret) may still be required, as the row says |
| session | `Authorization: Bearer <accessToken>` of a live session of an `active` account (§2) |
| session† | a session plus a fresh `currentAuthKey` in the JSON body, verified against the login verifier exactly as `PUT /account/password` verifies it (§3) |
| operator | a session of the instance's operator account (`role = operator`, §7) |
| operator† | an operator session plus a fresh `currentAuthKey`, as session† |
| host | not reachable from the network (`/metrics`), or not an HTTP route at all (`andvari admin`, §7.4) |

A **V** after the mark means the route is version-checked (§1): a caller below
`minVersion[platform]` gets `426 upgrade_required`.

**Generic refusals.** These apply to every route of the kind named and are **not** repeated in the
index:

| Applies to | Refusals |
|---|---|
| every route | `400 bad_request` (the body is not JSON of the route's shape); `400 bad_<field>` (a field fails its type or limit; `<field>` is the field's name in snake_case, for example `bad_vault_id`, and the first failing field in body order decides); `413 body_too_large`; `429 rate_limited` with `Retry-After` (seconds) when the route's bucket (§0.2) is spent; `500 internal` |
| session, session†, operator, operator† | `401 missing_token` (no bearer); `401 invalid_credentials` (an unknown, expired or revoked token, or an account that is not `active`); `403 totp_enrollment_required` (a restricted session, §2, on any route but TOTP setup, confirm and logout) |
| session†, operator† | `403 reauth_failed` (a wrong `currentAuthKey`; audited), on **every** re-authenticated route (`PUT /account/password`, `PUT /account/recovery`, `PUT /recovery/self-setup`, the device revoke, `PUT /account/require-link`, `POST /account/delete`, `POST /account/totp/disable` and the operator's † routes; the same answer on `POST /account/totp/setup`, row 14): a `401` on a live session would read as an expired session to the client's refresh logic. That is also why `401 credential_changed` (rows 21 and 31) stays a `401`: it means the session itself is no longer valid, because the credential was changed or recovered elsewhere, so the client must sign in again, which is exactly what a `401` tells the refresh logic. Routes with no session keep the uniform `401`: login, device-link pickup, and `POST /recovery/self/verify` and `/commit`, which run on a recovery ticket. On a † route a refusal for the request's own shape or size (a body that does not parse, an empty or oversized blob such as `400 bad_account_state`) may come before the password is checked. So may a refusal that tells the session only what that session can read for itself: `POST /account/totp/disable` says `400 totp_not_enrolled` (two-step sign-in is not set up, which `GET /account/totp` says too, §2), and `POST /account/delete` says `400 confirm_email_mismatch` (the typed address is not this account's, §13). Every other refusal that depends on what the server stores comes after the password is checked. Every † route has a bucket of 5 per minute per device, with the ceiling per account of the rate buckets' rule below (each verify is a memory-hard hash), unless its row names another. **Every proof also draws on its device's own proof back-off (§8: per device), never the sign-in's**, on every route that takes one (the † routes and `currentAuthKey` on row 14), the operator's and an ordinary account's alike: a wrong proof is counted on it, and while it is in force the proof is refused before it is checked with `429 rate_limited`, whose `Retry-After` is its own device's real remaining wait (§8, "The waits a refusal names"). It has the sign-in back-off's curve, so the routes together give a session no more guesses than the sign-in gives, and no number of wrong sign-ins refuses a signed-in account's proof |
| operator, operator† | `403 not_operator` (the caller is not the operator account); `403 operator_web_refused` (the session was minted by a request whose `X-Andvari-Client` platform was `web`, §7) |
| V | `426 upgrade_required` |
| marked **R** in the index | on an instance whose `ANDVARI_INSTANCE_KIND` is `public`, the route answers `404 not_found` before anything else, and does nothing (§18.6: variant R) |

**Rate buckets.** Every `/api/v1` route has one. Unauthenticated routes are bucketed per IP, with the
numbers in the index; the recovery-request verify (row 69) has a bucket per IP of its own,
`recovery_request_verify`, beside its per-request limit (§18.2; rule of 2026-11-16).
An IPv6 client is keyed on its /64 (§8). **A bucket's name is its budget** (rule of 2026-11-17): each
name has one limit and one window, and routes share a budget only by naming the same bucket
(`totp_verify`: rows 16 and 31; `device_link_poll`: rows 63 and 64; `vault_destructive`: §10.5 and
row 50; `recovery_commit`: rows 33 and 72; `login`: rows 10 and 66). No route takes another's name by
accident: the kit's verify (row 32) is `recovery_verify` and the request's verify (row 69)
`recovery_request_verify`. A test of the server's pins this.

**Routes that need a session are bucketed per device** (rule of 2026-11-17, which replaces "per
account"): a session spends only its own device's budget (the device row its sessions carry, which a
refresh keeps), and beside it every such bucket has a ceiling per account of four times the device's
limit, in the same window, on every session bucket alike, the breach-check relay's (row 87) included.
A call the device's budget refuses spends nothing of the ceiling, and a call the ceiling refuses is
given back to the device. A `429` from a session bucket names the longer wait: when the device's
budget refuses while the account's ceiling is full too, `Retry-After` is the later of the two
windows' ends. A removed device (by its account, by the operator, or with its account)
takes its budgets with it; the ceiling keeps what it spent. Why: kept per account, a session held
without the password could spend a route's budget and so keep the owner from that route on every
device (five requests an hour kept the owner from deleting the account). The ceiling stays because
every sign-in with the password makes a device and an account has no cap on its devices, so without
it the password's holder could multiply any budget, the memory-hard proofs' included; a held session
cannot make a device, so the ceiling never bounds a thief, only the password's holder. One device
puts at most twice its limit into one window of the ceiling (the windows are fixed), so a held session
leaves the account's other devices at least two devices' budgets. Where the index names no bucket, a
read (`GET`) gets **read 60/min** and a write **write 60/h**; device-link create gets 10 an hour;
every re-authenticated route 5 a minute. The read and write defaults are one bucket per route, not
shared. The two buckets keyed by the typed address (`signup_start_address`, `recovery_request_address`,
5 per window of 24 hours each), and the mailbox value's own ceiling beside the second
(`recovery_request_mailbox`, §18.1), are not session buckets and are unchanged. **The refresh** (row 11) is drawn from the
device's budget (`refresh_session`, 30 a minute, with the ceiling per account) when its token names a
live session (not revoked, not consumed, not expired, of an active account and a device not
removed); a consumed token of such a session (the reuse, which revokes every session of its device)
draws nothing and is never refused by a bucket, since drawn on the device whoever holds the rotated
chain could keep that budget spent and so keep the reuse from ever revoking it; a replaced token that
the sixty-second grace answers (§2) is no reuse and draws the caller's address (`refresh`), so that the
grace is an answer and not a free door; every other refresh
(a body that is not the shape, an empty, unknown, revoked or expired token, an inactive account or a
removed device) draws the caller's address (`refresh`, 30 a minute) (rule of 2026-11-17): a live
token is served once and rotates, and its reuse already revokes, so an address bucket protects
nothing there, and drawn per address for everyone it let anyone behind one address (a household, an
office, a mobile network) keep everyone else behind it from refreshing.

**Idempotency.** Where a route is idempotent the row says how. Every other write is not, and a
client that loses the answer re-reads state before it retries.

### 0.2 The index

Statuses are the success status unless the success column says otherwise. "→ §n" names the section
that defines the route's fields, checks and effects; where the two disagree, the section wins and the
index is a defect.

| # | Method and path (under `/api/v1` unless shown) | Who | Request body | Success | Route-specific refusals | Rate bucket | § |
|---|---|---|---|---|---|---|---|
| **Instance and policy** |
| 1 | `GET /client-policy` | none | — | `200 ClientPolicy` | — | `client_policy` 60/min per IP | §1.1 |
| 2 | `GET /instance` (`If-None-Match` honoured) | none | — | `200 {cards, rotations}`, or `200 {cards: [], setup}` before card 0; `304` on a matching ETag | — | `instance` 60/min per IP | §17.1 |
| 3 | `PUT /instance/card` | operator† | `{card, currentAuthKey}` | `200 {seq, hash}` | `400 bad_card`; `409 card_head_moved {seq, hash}`; `409 handover_target_invalid` | † | §17.2 |
| 4 | `PUT /instance/rotation` | operator†, **R** | `{statement, currentAuthKey}` | `200 ok` | `400 bad_rotation` | † | §17.3 |
| 5 | `GET /recovery-pubkey` | none, **R** | — | `200` text: the recovery public key, `b64` | `404 not_found` (no recovery key) | `recovery_pubkey` 60/min per IP | §17.4 |
| **Sign-up and registration** |
| 6 | `POST /signup/start` | none | `{email, ageConfirmed, pow?}` | `202 {status: "sent"}` | `403 signup_closed`; `403 signup_full`; `400 invalid_email`; `400 email_domain_blocked`; `400 age_confirm_required`; `400 pow_required`; `400 bad_pow`; `503 mail_unavailable` | `signup_start_ceiling` 30/h per IP, never given back (§14.1); `signup_start` 3/h and 10/day per IP; 5 per 24-hour window per address (`signup_start_address`, which names its real wait, §8) | §14.1 |
| 7 | `POST /signup/verify` | none | `{email, code}` | `200 {signupTicket, expiresAt}` | `400 bad_code` | `signup_verify` 20/h per IP | §14.2 |
| 8 | `POST /auth/register` | none, V | Register (§14.3) | `200` SessionResponse + `recoveryPieceId` | §14.3's table, by step: `403 signup_closed`, `403 setup_done`, `409 setup_incomplete`, `400 bad_ticket`, `404 link_unknown`, `410 link_expired`, `409 link_used`, `409 kind_mismatch`, `403 email_mismatch`, `400 age_confirm_required`, `403 signup_full`, `429 signup_daily_max`, `409 email_taken`, `409 user_id_taken`, `409 vault_id_taken`, `400 bad_genesis`, `400 escrow_not_allowed`, `400 operator_recovery_unavailable`, `400 bad_escrow`, `400 escrow_wrong_form`, `400 personal_vault_mismatch`, `400 kdf_too_weak`, `400 kdf_mem_not_kib_multiple`, `400 bad_kdf_salt`, `400 recovery_required` | `register` 10/h per IP | §14.3 |
| **Sessions** |
| 9 | `POST /auth/prelogin` | none | `{email}` | `200 {kdfSalt, kdfParams}` | — | `prelogin` 10/min per IP | §2 |
| 10 | `POST /auth/login` | none, V | `{email, authKey, device, totp?, replacesRefreshToken?}` | `200` SessionResponse | `401 invalid_credentials`; `401 totp_required`; `403 link_required` | `login` per IP (`ANDVARI_LOGIN_RATE_PER_MIN`, default 5/min); email backoff (§8) | §2 |
| 11 | `POST /auth/refresh` | none | `{refreshToken}` | `200 {accessToken, refreshToken}` | `401 invalid_refresh`; `401 session_revoked`; `401 refresh_reuse`; `401 refresh_expired`; `401 invalid_credentials` (account not active, or device revoked) | `refresh_session` 30/min per device (with the ceiling of §0.1) when the token names a live session; `refresh` 30/min per IP when it names none; the reuse of a consumed token draws neither (§0.1); a replaced token the grace answers (§2) draws `refresh` 30/min per IP | §2 |
| 12 | `POST /auth/logout` | session | — | `200 ok` | — | write 60/h | §2 |
| 93 | `POST /auth/end-session` | none (the refresh token is the proof) | `{refreshToken}` | `200 ok`, whatever the token | — (`400 bad_request` only for a body that is not that shape) | `end_session` 30/min per IP, drawn only when the token names no live session (a live one is always served) | §2 |
| 13 | `GET /account/totp` | session | — | `200 {enrolled, pendingSetup}` | — | read 60/min | §2 |
| 14 | `POST /account/totp/setup` | session | `{currentAuthKey, code?}` (an account with two-step sign-in sends both, §2) | `200 {secretBase32, otpauthUri}` | `403 reauth_required`; `403 reauth_failed`; `400 bad_totp_code` | `totp_setup` 5/min; the proofs' back-off and the codes' back-off (§8) | §2 |
| 15 | `POST /account/totp/confirm` | session | `{code}` | `200 ok` | `400 no_pending_totp`; `400 bad_totp_code` | `totp_confirm` 5/min; the codes' back-off (§8) | §2 |
| 16 | `POST /account/totp/disable` | session† | `{code, currentAuthKey}` (the proof before the code, §2) | `200 ok` | `400 totp_not_enrolled`; `403 reauth_required`; `403 reauth_failed`; `400 bad_totp_code` | `totp_verify` 5/min; the codes' back-off (§8) | §2 |
| **Account** |
| 17 | `GET /account/keys` | session | — | `200 AccountKeys` | — | read 60/min | §3 |
| 18 | `GET /account/state` | session | — | `200 {sealedState, seq}` | — | read 60/min | §3 |
| 19 | `PUT /account/state` | session, V | `{sealedState, baseSeq}` | `200 {sealedState, seq}` | `409 stale_state`; `400 bad_account_state` | `account_state` 60/min | §3 |
| 20 | — (retired: `PUT /account/personal-wrap` is deleted; row numbers are kept stable) | — | — | — | — | — | — |
| 21 | `PUT /account/password` | session†, V | `{currentAuthKey, newAuthKey, newKdfSalt, newKdfParams, newWrappedUvk}` | `200 ok` | `401 credential_changed`; `400 kdf_too_weak`; `400 kdf_mem_not_kib_multiple`; `400 bad_kdf_salt` | `password_change` 5/min | §3 |
| 22 | `PUT /account/recovery` | session†, V | `{posture, escrow?, currentAuthKey, accountState}` | `200 {sealedState, seq}` | `400 escrow_not_allowed`; `400 operator_recovery_unavailable`; `400 bad_escrow`; `400 escrow_wrong_form`; `400 bad_account_state`; `409 stale_state` | † | §3.1 |
| 23 | `PUT /escrow/self` | session, V, **R** | `{sealed, fingerprint, rotations}` (at most 64 rotations) | `200 ok` | `400 escrow_not_allowed`; `400 bad_escrow`; `400 escrow_wrong_form`; `409 escrow_not_due` (also over 64 rotations) | `escrow_self` 10/min | §3.2 |
| 24 | `GET /usage` | session | — | `200 {sealedUsage, updatedAt}` | — | read 60/min | §3 |
| 25 | `PUT /usage` | session, V | `{sealedUsage}` | `200 ok` | `400 bad_usage_blob` | `usage` 60/min | §3 |
| 26 | `GET /account/devices?after=` | session | — | `200 [Device]`, one page of at most 500 | `400 bad_request` (an `after` that names no device of the account) | read 60/min | §16.7 |
| 27 | `POST /account/devices/{deviceId}/revoke` | session† | `{currentAuthKey}` | `200 ok` | `404 no_such_device`; `400 cannot_target_self` | † | §16.7 |
| 28 | `PUT /account/require-link` | session† | `{enabled, currentAuthKey}` | `200 ok` | — | † | §16.8 |
| 29 | `GET /account/recovery-requests` | session, **R** | — | `200 [RecoveryRequestSummary]` | — | read 60/min | §18.3 |
| 30 | `GET /account/delete/preview` | session, V | — | `200 AccountDeletePreview` | — | read 60/min | §13 |
| 31 | `POST /account/delete` | session†, V | `{confirmEmail, currentAuthKey, totp?, leaves}` | `200 {deletedAt}` | `400 confirm_email_mismatch`; `403 reauth_failed`; `401 credential_changed`; `400 totp_code_required`; `400 bad_totp_code` (the proof before the code, §13); `409 account_delete_blocked {blockers}`; `409 account_delete_log_stale {vaultIds}`; `400 at_ahead`; `400 bad_leaves` | `account_delete` 5/h; `totp_verify` 5/min when a code is sent; the codes' back-off (§8) | §13 |
| **Recovery with the kit** |
| 32 | `POST /recovery/self/verify` | none | `{email, recoveryAuthKey}` | `200 {recoveryTicket, userId, recoveryWrappedUvk, encryptedIdentitySeed, identityPub}` | `401 invalid_credentials` (uniform) | `recovery_verify` 5/min per IP | §12 |
| 33 | `POST /recovery/self/commit` | none, V | `{recoveryTicket, newAuthKey, newKdfSalt, newKdfParams, newWrappedUvk, newMemberRecovery, device}` | `200` SessionResponse + `recoveryPieceId` | `401 invalid_ticket`; `400 recovery_account_not_active`; `400 kdf_too_weak`; `400 kdf_mem_not_kib_multiple`; `400 bad_kdf_salt`; `400 recovery_required` | `recovery_commit` 5/min per IP | §12 |
| 34 | `PUT /recovery/self-setup` | session† | `{currentAuthKey, memberRecovery}` | `200 {pieceId}` | `400 recovery_required` | `recovery_setup` 5/min per device | §12 |
| 35 | `POST /recovery/self/confirm` | session | `{pieceId?}` | `200 ok` | `409 recovery_piece_stale` | `recovery_confirm` 5/min per device | §12 |
| **Sync, items, attachments, events** |
| 36 | `GET /sync?since=<rev>` | session, V | — | `200 SyncResponse`, with the caller's own `quota` (§14.4) | `410 resync_required` | read 60/min | §4 |
| 37 | `POST /sync/push` | session, V | `{mutations}` | `200 {rev, results}` (per-mutation status) | `400 batch_too_large`; `400 bad_op`; `400 put_without_item` | `sync_push` (`ANDVARI_PUSH_RATE_PER_MIN`, default 120/min) | §5 |
| 38 | `GET /items/{itemId}/versions` | session | — | `200 {itemId, versions}` | `403 no_grant` | read 60/min | §4 |
| 39 | `GET /items/deleted?after=` | session | — | `200 {items}`, one page of at most 65,536 | `400 bad_request` (an `after` that is not `<deletedAt>:<itemId>`) | read 60/min | §5.1 |
| 40 | `POST /items/{itemId}/restore` | session, V | `{formatVersion, attachmentIds, blob}` | `200 {rev}` | `403 no_grant`; `400 item_not_deleted`; `400 fv_downgrade`; `400 unknown_attachment`; `400 attachment_mismatch`; `400 too_many_attachments`; `400 duplicate_attachment`; `400 bad_attachment_id`; `413 item_attachment_quota`; `413 item_too_large`; `413 quota_exceeded {quota}` | `item_recovery` 400/h | §5.1 |
| 41 | `POST /items/{itemId}/purge` | session | — | `200 {rev}` | `403 no_grant`; `400 item_not_deleted` | `item_destructive` 200/h | §5.1 |
| 42 | `POST /attachments/{attachmentId}?vaultId=&itemId=` | session, V | raw bytes (§9) | `200 AttachmentMeta` | `403 no_write_grant`; `403 no_grant`; `400 attachment_id_taken`; `400 attachment_truncated` (a body shorter than its header says); `413 attachment_too_large`; `413 quota_exceeded {quota}`; `429 rate_limited` (concurrent uploads) | `attachment_upload` 600/h per device, and the concurrent-upload cap | §9 |
| 43 | `GET /attachments/{attachmentId}` | session | — | `200` raw bytes | `403 no_grant` | read 60/min | §9 |
| 44 | `POST /events/ticket` | session | — | `200 {ticket, expiresInSeconds}` | — | `ws_ticket` 60/min | §6 |
| 45 | `GET /events` (WebSocket upgrade) | `?ticket=` or bearer | — | `101`, then frames | close `1008` (unauthorized; or the device's oldest socket, past 8), `1009` (frame too big), `1013` (bearer upgrade over its bucket) | a bearer upgrade: `ws_bearer` 60/min per device; a ticket: none (the ticket is single-use; `ws_ticket` bounds minting) | §6 |
| **Shared vaults and the vault log** |
| 46 | `POST /vaults/{vaultId}/log` | session, V | `{entry, grant?, wrappedVk?, metaBlob?}` | `200 {rev, head, deleted?}` | §10.4's table: `400 bad_frame`, `400 non_canonical`, `400 bad_statement`, `400 wrong_vault`, `400 bad_signer`, `400 bad_signature`, `403 no_grant`, `403 not_vault_owner`, `400 not_shared_vault`, `409 vault_id_taken`, `409 log_head_moved {seq, hash, at}`, `400 precondition`, `400 at_ahead`, `400 bad_expiry`, `409 member_limit`, `409 not_connected`, `409 offer_expired`, `413 quota_exceeded {quota}` | by kind (§10.5): `vault_create` 10/h, `vault_destructive` 10/h, `vault_membership` 60/h, `vault_recovery` 30/h | §10.3 |
| 47 | `GET /vaults/{vaultId}/log?after=<seq>` | session, V | — | `200 {entries, head, purged?, deleted?}` | `403 no_grant`; `400 bad_after` | read 60/min | §10.6 |
| 48 | `GET /vaults/{vaultId}/members` | session, V | — | `200 [VaultMemberSummary]` | `403 no_grant` | read 60/min | §10.7 |
| 49 | `GET /vaults/deleted` | session, V | — | `200 [DeletedVaultSummary]` | — | read 60/min | §11.2 |
| 50 | `PUT /vaults/{vaultId}/meta` | session, V | `{metaBlob, baseVaultRev?}` | `200 {rev}` | `403 not_vault_owner`; `400 not_shared_vault`; `400 vault_deleted`; `409 stale_meta` | `vault_destructive` 10/h | §11.3 |
| 51 | `PUT /vaults/{vaultId}/grant/self-wrap` | session, V | `{wrappedVk}` | `200 {rev}` | `403 no_grant`; `403 owner_wrap_immutable` | `vault_self_wrap` 60/h | §11.4 |
| **Links** |
| 52 | `POST /links` | session, V | `{linkId, kind, offer, expiresAt, tokenHash?}` | `201 {expiresAt, ttlMs}` | `400 bad_kind`; `400 bad_expiry`; `400 bad_token_hash`; `403 not_operator`; `409 link_id_taken`; `413 quota_exceeded {quota}` | `link_create` 30/day | §15.2 |
| 53 | `GET /links/{linkId}` | none | — | `200 {kind, offer, expiresAt, state, creatorUserId, creatorIdentityPub, reveal}` (open) or `200 {kind, state, reveal}` (answered) | `410 link_expired`; `404 link_unknown` | `link_fetch` 30/min per IP | §15.3 |
| 54 | `POST /links/{linkId}/answer` | session, V | `{answer}` | `200 ok` | `404 link_unknown`; `410 link_expired`; `409 link_used`; `409 kind_mismatch`; `400 cannot_target_self` | write 60/h | §15.4 |
| 55 | `POST /links/{linkId}/reveal` | session, V | `{nonce}` | `200 ok` | `404 link_unknown`; `409 link_state` | write 60/h | §15.5 |
| 56 | `GET /links/answers` | session, V | — | `200 [LinkAnswer]` | — | read 60/min | §15.6 |
| 57 | `POST /links/{linkId}/ack` | session, V | — | `200 ok` | `404 link_unknown`; `409 link_state` | write 60/h | §15.6 |
| 58 | `DELETE /links/{linkId}` | session, V | — | `200 ok` | `404 link_unknown`; `409 link_state` | write 60/h | §15.7 |
| **Device links** |
| 59 | `POST /device-links` | session, V | `{linkId, expiresAt}` | `201 {expiresAt, ttlMs}` | `400 bad_expiry`; `409 link_id_taken` | `device_link_create` 10/h | §16.2 |
| 60 | `GET /device-links/{linkId}` | session, V | — | `200 {state, expiresAt, claim?, nonceE?, nonceN?}` | `404 link_unknown`; `410 link_expired` | read 60/min | §16.3 |
| 61 | `POST /device-links/{linkId}/claim` | none, V | `{nPub, name, platform, commitN, mac}` | `200 ok` | `404 link_unknown`; `410 link_expired`; `409 link_claimed` | `device_link_claim` 10/min per IP | §16.4 |
| 62 | `POST /device-links/{linkId}/nonce` | session, V | `{nonceE, proofHash}` | `200 ok` | `404 link_unknown`; `410 link_expired`; `409 link_state` | write 60/h | §16.5 |
| 63 | `POST /device-links/{linkId}/poll` | none, V | `{proof}` | `200 {state}`, `{state, nonceE}` or `{state, nonceE, outer, approveMac}` | `404 link_unknown`; `410 link_expired`; `403 bad_proof` | `device_link_poll` 60/min per IP | §16.5 |
| 64 | `POST /device-links/{linkId}/reveal` | none, V | `{nonceN, proof}` | `200 ok` | `404 link_unknown`; `410 link_expired`; `403 bad_proof`; `409 link_state` | `device_link_poll` | §16.5 |
| 65 | `POST /device-links/{linkId}/approve` | session, V | `{outer, inner, approveMac}` | `200 ok` | `404 link_unknown`; `410 link_expired`; `409 link_state` | write 60/h | §16.6 |
| 66 | `POST /device-links/{linkId}/pickup` | none, V | `{proof, authKey, totp?, device}` | `200 {inner, session: SessionResponse}` | `404 link_unknown`; `410 link_expired`; `403 bad_proof`; `409 link_state`; `401 invalid_credentials`; `401 totp_required` | `login` per IP; email backoff (§8) | §16.6 |
| 67 | `DELETE /device-links/{linkId}` | session, V | — | `200 ok` | `404 link_unknown` | write 60/h | §16.2 |
| **Operator-assisted recovery** |
| 68 | `POST /recovery/requests` | none, **R** | `{email, rPub, pollHash, platform, mailboxValue?}` | `202 {requestId}` | `400 bad_mailbox_value`; `400 invalid_email`; `503 mail_unavailable` | `recovery_request` 5/h per IP; 5 per 24-hour window per address, silent (still `202`); past it, with a mailbox value, 5 more per window (`recovery_request_mailbox`, §18.1) | §18.1 |
| 69 | `POST /recovery/requests/{requestId}/verify` | none, **R** | `{code}` | `200 {state, holdEndsAt}` | `400 bad_code`; `409 request_state` (the right code of a request its owner cancelled) | 5 per request; `recovery_request_verify` 20/h per IP | §18.2 |
| 70 | `POST /recovery/requests/{requestId}/veto` | session, **R** | `{statement}` | `200 ok` | `404 request_unknown`; `400 bad_frame`; `400 non_canonical`; `400 bad_statement`; `400 bad_signer`; `400 bad_signature` | write 60/h | §18.3 |
| 71 | `POST /recovery/requests/{requestId}/poll` | none, **R** | `{pollSecret}` | `200 {state, holdEndsAt?}` or `200 {state: "ready", sealed, encryptedIdentitySeed, identityPub, commitHash}` | `404 request_unknown` | `recovery_poll` 60/min per IP | §18.4 |
| 72 | `POST /recovery/requests/{requestId}/commit` | none, V, **R** | `{pollSecret, commit, newAuthKey, newKdfSalt, newKdfParams, newWrappedUvk, newMemberRecovery, device}` | `200` SessionResponse + `recoveryPieceId` | `404 request_unknown`; `409 request_state`; `400 bad_commit`; `403 commit_mismatch` (audited each time, and never cancels the request: rule of 2026-11-16); `400 recovery_account_not_active`; `400 kdf_too_weak`; `400 kdf_mem_not_kib_multiple`; `400 bad_kdf_salt`; `400 recovery_required` | `recovery_commit` 5/min per IP | §18.5 |
| **Operator** |
| 73 | `GET /admin/accounts` | operator | — | `200 [AccountSummary]`, each with its account's `quota` (§14.4) | — | read 60/min | §7.1 |
| 74 | `POST /admin/accounts/{userId}/disable` | operator† | `{reason, currentAuthKey}` | `200 ok` | `400 no_such_user`; `400 cannot_target_self` | † | §7.1 |
| 75 | `POST /admin/accounts/{userId}/enable` | operator† | `{currentAuthKey}` | `200 ok` | `400 no_such_user` | † | §7.1 |
| 76 | `POST /admin/accounts/{userId}/delete` | operator† | `{currentAuthKey, reason?}` | `200 {deletedAt}` | `400 no_such_user`; `400 cannot_target_self`; `400 bad_reason`; `409 not_disabled_long_enough {disabledAt}`; `409 account_delete_blocked {blockers}` | † | §7.1 |
| 77 | `GET /admin/accounts/{userId}/devices?after=` | operator | — | `200 [Device]`, one page of at most 500 | `400 no_such_user`; `400 bad_request` (an `after` that names no device of the account) | read 60/min | §7.1 |
| 78 | `POST /admin/devices/{deviceId}/revoke` | operator† | `{currentAuthKey}` | `200 ok` | `404 no_such_device` | † | §7.1 |
| 79 | `PUT /admin/accounts/{userId}/quota` | operator† | `{accountBytes, items, ownedSharedVaults, openLinks, currentAuthKey}` | `200 Quota` | `400 no_such_user` | † | §7.1 |
| 80 | `GET /admin/policy` | operator | — | `200 AdminPolicy` | — | read 60/min | §7.2 |
| 81 | `PUT /admin/policy` | operator† | AdminPolicy + `currentAuthKey` | `200 AdminPolicy` | `400 kdf_too_weak`; `400 kdf_mem_not_kib_multiple`; `400 not_tighter` | † | §7.2 |
| 82 | `GET /admin/audit?since=&type=&userId=&after=` | operator | — | `200 [AuditRow]`, one page of at most 500, newest first | `400 bad_since`; `400 bad_type`; `400 bad_user_id`; `400 bad_request` (an `after` that is not a positive integer) | read 60/min | §7.3 |
| 83 | `GET /admin/status` | operator | — | `200 AdminStatus` | — | read 60/min | §7.3 |
| 84 | `GET /admin/recovery-requests` | operator, **R** | — | `200 [AdminRecoveryRequest]` | — | read 60/min | §18.6 |
| 85 | `POST /admin/accounts/{userId}/escrow` | operator†, **R** | `{currentAuthKey}` | `200 {userId, sealed, encryptedIdentitySeed, identityPub}` | `400 no_such_user`; `404 no_escrow` | † | §18.6 |
| 86 | `POST /admin/recovery-requests/{requestId}/fulfil` | operator†, **R** | `{sealed, requestKey, commitHash, currentAuthKey}` | `200 ok` (repeatable until the commit) | `400 bad_sealed`; `400 bad_request_key`; `400 bad_commit_hash`; `404 request_unknown`; `409 request_state`; `400 request_key_mismatch` | † | §18.6 |
| **Misc** |
| 87 | `GET /api/v1/hibp/range/{prefix}` | session | — | `200` text | `400 bad_prefix`; `502 hibp_timeout` (HIBP did not answer in time or could not be reached at all: a refused or failed connection); `502 hibp_upstream_<status>` | `hibp` 600/min | §8 |
| 88 | `GET /healthz` (at the origin's root, not under `/api/v1`) | none | — | `200 ok`, or `503` | — | — (not an API route) | §8 |
| 89 | `GET /metrics` (at the origin's root, not under `/api/v1`) | host | — | `200` Prometheus text | — | — (not an API route) | §8 |
| 90 | `GET /robots.txt` (at the origin's root, not under `/api/v1`) | none | — | `200` text | — | — (not an API route) | §8 |
| 91 | at the root, not under `/api/v1`: `GET /downloads/manifest.json`, `GET /downloads/manifest.json.sig`, `GET /downloads/{file}` | none | — | `200` bytes | `404` | — (not an API route) | §8 |
| 92 | `GET /selfhost`, `GET /selfhost/{file}` (at the root, not under `/api/v1`) | none | — | `200` | `404` | — (not an API route) | §8 |

The twelve routes 4, 5, 23, 29, 68–72 and 84–86 (**R**) exist on private instances and answer `404 not_found` on
a public one (§18.6). Every route not in this table answers `404` (an unknown `/api/v1` path) or the
web client (any other path, served by the SPA fallback). The SPA fallback also answers `HEAD` on those
paths exactly as it answers `GET` (the same status and headers, `Content-Length` included), with no
body; no other route answers `HEAD`. **Without a downloads directory** (`ANDVARI_DOWNLOADS_DIR` unset, so row 91
is absent) the SPA fallback answers every path under `/downloads/` with `404`, for `GET` and `HEAD`, never the web
client's page: a client asking for `/downloads/manifest.json` or its `.sig` learns that this server serves no
update list (the desktop app then falls back to its other source) instead of reading an HTML page as a list that
failed its check. With a downloads directory set, row 91 answers as before. A blank `ANDVARI_DOWNLOADS_DIR` is
unset. Row 91 serves every regular file directly inside that directory to anyone, so the server refuses to boot
when it is the directory that holds the database (and its `-wal` and `-shm`) or the blob directory, by any spelling
or through a link: that would hand out the instance itself.

### 0.3 Shared encodings

These are spec 01 §5.1's and the design's encoding rules, repeated here because the server applies
them at the wire:

- **`emailNorm`** (spec 01 §5.5): strip ASCII white space (space, tab, CR, LF) from both ends;
  lowercase ASCII `A–Z` only, with no Unicode case folding and no locale. An address that, **after the
  strip**, is shorter than 3 or longer than 254 octets, contains any byte outside `0x21–0x7E` (an
  interior space, a tab, a control character, DEL, any non-ASCII byte), or does not have exactly one
  `@` with non-empty parts, is refused `400 invalid_email` wherever an address is taken. The server stores and compares `emailNorm`.
- **Token hashes**: a link's register token is stored as `b64url(SHA-256(ASCII(token)))` over the
  43-character token string (the server's `hashToken`). A sign-up ticket is stored the same way,
  `b64url(SHA-256(ASCII(ticket)))` over its text as sent. Access and refresh tokens, tickets and poll secrets are stored
  only as hashes.
- **`deviceSecret`**: 32 CSPRNG bytes, `b64_32`, generated by the device and kept in its device state.
  The server stores the lowercase hex SHA-256 of the **32 decoded bytes** (not of the base64url text)
  with the device row and never returns it (§16.8).
- **`platform`** (§0.1) in a device object is checked against the closed list (`400 bad_platform`).

### 0.4 Answer caps: how much of an answer a client reads

A client does not trust a server to keep its answers small, before a Trust Gate as after it. Every native client and
the CLI reads each answer only up to its route's cap below (the engine's `ResponseCaps`, one table for every client,
so no client picks its own). A cap is a ceiling, never a size a client expects.

**Reading.** A `Content-Length` above the cap is refused before any body byte is read. Without a length, the body is
read to the cap plus one byte and refused there. **A refusal envelope** (any status outside `2xx`) is read to
**64 KiB** on every route, or to the route's cap when that is smaller; an envelope past it is refused like an
oversized answer, and its status alone decides nothing (an unreadable `401` does not end a session).

**An answer over its cap** is refused with the client-side code `body_over_limit` (status 0: no server sent it):
- nothing of it is kept: no byte is decoded, stored, cached or acted on, and the bytes read so far are zeroed;
- the device's state is what it was before the request: the copy, the pins, the session and the verified logs;
- it is a server fault, shown as "the server's answer could not be read". It is never read as a wrong password, as
  "nothing there" (an empty list, no items, no card, no answer yet), as a refusal code of the route, or as a session
  the server ended. The request may be tried again on the route's ordinary failure path.

**How long a client waits for an answer: two kinds of limit** (rules of 2026-11-17, every client). An
answer that is small by its nature (every route but a sync, a file's upload or download, an export
and an import's requests) has a limit on its whole time, the body included: sixty seconds. An answer
whose size grows with the vault or with a file has a limit on the time without progress, thirty
seconds without a byte, and no limit on its total, so that a first sync of a large vault on a slow
line finishes. Without a limit, an answer whose first part arrived and whose body never did would
leave the screen waiting for ever. When either limit strikes, the answer is one that could not be
read, and the person reads a sentence that says so (the server stopped answering, or this took too
long), never a silent retry without end; an answer whose status arrived and whose body was cut off is
never "the server didn't answer". **No request is ever without a limit:** where a request was paused
for a refresh, its limit runs again before its answer is handed on, also when the refresh failed or
led to no second send. **An upload's limit scales with what is sent** (rule of 2026-11-17): a
browser cannot see a request's body leave, so the time without progress cannot be measured for an
upload; it waits for the answer to begin for thirty seconds plus the time its size needs at a slow
line's speed (2 KiB a second), and after that the thirty seconds without a byte apply. That is
accepted: an upload that gets no answer ends after that time (hours for the largest files), and the
person can cancel meanwhile. A save whose upload a limit ended is said as not saved, with the line
for a save whose files could not be sent: the item is not saved until its files are. **What the
web client keeps (2026-11-18):** both kinds, as above: no progress for thirty seconds ends a sync, a
push (the store's, an import's and a copy's or move's), and an attachment's upload and download;
every other call has sixty seconds for its whole answer; a caller that sets its own limit (the
policy's run, an account deletion) keeps it; and each limit has its own line (the server stopped
answering in the middle, or this took too long; either way it may or may not have been done).
**Not kept yet (2026-11-17):** the desktop's and `andvari-cli`'s transports bound every request
at sixty seconds in total, a large sync or file included; Android bounds a call at the longest an
attachment at the size ceiling may take, and the shared code's older session road bounds whole
operations; nothing there bounds the time without progress.

**The event socket** (§6) has the same rule per message: a text message, all of its fragments counted together as
they arrive, of more than **64 KiB** ends the socket with nothing of the message kept or acted on. It is not a
revocation: the bell reconnects on its ladder (§6), with a fresh ticket.

| Route | Cap | Where the number comes from |
|---|---|---|
| `GET /sync` | 256 MiB | Not paged (§4): a full snapshot carries every item the account can read. Each owner's items count against that owner's quota (100 MiB by default, §14.4), so 256 MiB holds the account's own full quota and a large share of other owners'. See the known limits below. The `quota` object (§14.4) adds at most 293 bytes to any answer, full or delta. |
| `POST /sync/push` | 8 MiB + 256 KiB | The stored items one answer echoes total at most the request's body cap, 8 MiB (§5, "Stored items in one answer"), beside up to 200 results and each item's framing. |
| `GET /items/{id}/versions` | 96 MiB | 10 kept versions × the largest item an operator may allow (`ANDVARI_ITEM_MAX_BYTES` up to 8 MiB), with framing. |
| `GET /items/deleted` | 8 MiB | One page (§5.1): at most 65,536 rows of at most 125 bytes, 8,192,012 bytes. |
| `GET /instance` | 1 MiB | The card chain (§17.1) before any Trust Gate: each card or rotation statement a frame of at most 1,125 bytes, about 1.5 KB as base64. |
| `GET /vaults/{id}/log` | 2 MiB | One page: at most 500 entries (§10.6) of at most 1,500 characters (§10.3), with the head. |
| `GET` and `PUT /account/state`, `PUT /account/recovery` | 2 MiB | A sealed state of at most 1 MiB of base64 (§3), with its frame. |
| `GET /usage` | 1 MiB | A sealed ledger of at most 512 KiB (§3). |
| Device link poll and pickup | 256 KiB | A sealed bundle of at most 64 KiB of plaintext (`inner`, about 87 KiB as base64), the `outer` and a session. |
| `GET /hibp/range/{prefix}` | 256 KiB | The padded range the HIBP service answers, relayed: about a thousand lines, about 40 KiB today. |
| The lists: devices (yours and the operator's view), recovery requests (yours and the operator's), the deletion preview, vault members, deleted vaults, link answers, `/metrics` | 1 MiB | Short rows an account or instance holds. See the known limits. |
| `GET /admin/accounts` | 32 MiB | One row per account, a few hundred bytes each, for an instance of about 100,000 accounts. A row's `quota` (§7.1) is about 170 bytes at real values, at most 293. |
| `GET /admin/audit` | 2 MiB | One page of at most 500 rows with their short `meta`. |
| `GET /attachments/{id}` | the caller's | The size the item's record claims (spec 02 §6); 256 MiB when a caller passes none. |
| `/selfhost/{file}` | 256 MiB | The self-hosting files. |
| `/downloads/{file}` | 512 MiB | An app installer. |
| `/downloads/manifest.json`, `/selfhost` | 4 MiB | The manifest and the self-hosting page. |
| Every other route | 64 KiB | One short JSON object, `ok`, or a short text: the largest are a session (§2, with its account keys and genesis) and a link's offer (at most 2,732 characters). |

**Known limits: where an honest server at its default configuration can send more than the cap.** The caps are not
raised to hide these; each is lifted by paging the answer, and until then a client refuses such an answer as above,
which leaves that account unable to complete the read on that route.

- **`GET /sync`, a full snapshot (`since=0`, or after `410 resync_required`).** Its size is about the sum, over every
  vault the account reads, of each live item's blob plus 248 bytes of framing (plus 39 bytes per attachment id), plus
  about 250 bytes per item tombstone of the last 30 days, plus one or two kilobytes per vault. It stops fitting at
  268,435,456 bytes. At the default quotas (100 MiB and 5,000 items per owner) one owner's live items take at most
  104,857,600 + 5,000 × 248 = 106,097,600 bytes, so an account that reads its own full quota and shared vaults whose
  other owners hold more than 162,337,856 bytes between them (one and a half more full quotas) cannot take a full
  snapshot. Shared vaults count against their owners, not the reader, and the server sets no limit on how many shared
  vaults an account reads, so the reader cannot prevent it. Tombstones count against no quota: about 1.07 million
  deletions in the readable vaults within 30 days fill the cap on their own (the push rate allows 24,000 mutations a
  minute per account). A delta sync (`since` > 0) carries only what changed, and is past the cap only when that much
  changed. Lifted by paging the snapshot.
- **`GET /items/deleted`**: **lifted 2026-11-16.** Deletions count against no quota, so the list is paged (§5.1): at
  most 65,536 rows of at most 125 bytes to an answer, 8,192,012 bytes.
- **The devices list** (`GET /account/devices`, `GET /admin/accounts/{userId}/devices`): **lifted 2026-11-16.** Device
  rows are never pruned while known (§16.8), and every sign-in that does not present a kept `deviceSecret` adds one,
  so the list is paged (§16.7): at most 500 rows of at most about 1.1 KB to an answer, about 550 KB.
- **`GET /links/answers`**: an answer waits until the creator's device acknowledges it, for up to 30 days, and an
  account may create 30 links a day. A row of the largest answer (2,732 characters) is about 2.9 KB, so about 360
  waiting answers fill 1 MiB. Lifted by paging the list.
- **`GET /instance`**: about 690 card and rotation frames of the largest size fill 1 MiB; the server keeps every one.
  An operator does not sign that many in practice. Lifted by a checkpoint or by paging the chain.
- **Only when an operator raises a limit:** `GET /vaults/{id}/members` (no per-vault member limit; about 2,000
  members of the longest addresses fill 1 MiB, which an instance at the default sign-up cap of 200 accounts cannot
  reach) and `GET /admin/accounts` (32 MiB is about 43,000 rows of the longest addresses and names with every
  `quota` number at its widest, about 70,000 before the row carried `quota` on 2026-11-16, against a sign-up cap the
  operator may raise to 10,000,000), and the operator's own files under `/downloads/` and
  `/selfhost/`.

## 1. Client identification & version pinning

Every request carries `X-Andvari-Client: <platform>/<semver>` with platform from §0.1's list. If policy pins `minVersion[platform]` above the caller on a
version-checked route (**V** in §0.2), the server answers **426** with the standard error shape:
`{ "error": "upgrade_required", "message": "min <platform> <minVersion>" }`. Clients key on the BODY
code, never the bare status (`message` is human-only; the actual pin comes from `/client-policy`);
they block writes and show the upgrade path (devstore / /downloads / reload).
`GET /api/v1/client-policy` (unauthenticated) returns current pins + `serverTime` + the instance
policy (§1.1); it carries a per-IP rate bucket (60/min) — it is the most-hammered anonymous route on a
public instance.

The header also decides one operator rule: a session minted by a request whose header platform is
`web` is a **web session**, and every operator route refuses it (`403 operator_web_refused`, §7).

### 1.1 Instance policy & the POLICY-TRUST BOUNDARY

`ClientPolicy` (the `/client-policy` response) is `{ minVersion, kdfParams, autoLockSeconds,
clipboardClearSeconds, offlineCacheAllowed, sessionAccessTtlSeconds, sessionRefreshTtlDays,
attachmentMaxBytes, itemAttachmentsMaxBytes, serverTime, signup, totpRequired, instanceName?,
canonicalOrigin?, selfHostDocsUrl? }`: the operator policy of §7.2 that clients apply, plus the
instance stance:

- `signup: {mode, full, ageConfirmRequired, powBits}`:
  - `mode`: `"open"` (email-verified sign-up plus links), `"links"` (register links only) or
    `"closed"` (sign-in only). It is the **effective** mode: the stricter of `ANDVARI_SIGNUP_MODE` and
    the operator's database value (§7.2), with `closed` stricter than `links`, stricter than `open`.
  - `full`: `true` when the effective cap (§14.4) is reached; clients disable "Create an account" with
    "Sign-up is full right now".
  - `ageConfirmRequired`: `ANDVARI_REQUIRE_AGE_CONFIRM = 1`.
  - `powBits`: `ANDVARI_SIGNUP_POW_BITS` (0 = no proof of work, §14.1).
- `totpRequired: Boolean` (default false) — per-instance login-factor stance (§2). A pre-prompt UI
  hint only; the reactive server errors stay authoritative.
- `instanceName: String?` — decorative label; NEVER rendered as a verified identity. The signed name
  is the instance card's (§17).
- `canonicalOrigin: String?` — the server's claimed own origin; a proxy-misconfig diagnostic, never a
  trust anchor (the instance card's `origin` is the signed one).
- `selfHostDocsUrl: String?` (default `<canonicalOrigin>/selfhost`) — rendered as a raw https URL
  only.

The durable-cache field keeps its **one wire name `offlineCacheAllowed`**. Server env (normative
names): `ANDVARI_SIGNUP_MODE` and the other sign-up variables of §14.4, `ANDVARI_INSTANCE_KIND`,
`ANDVARI_REGISTER_LINKS`, `ANDVARI_TOTP_REQUIRED`, `ANDVARI_OFFLINE_CACHE_ALLOWED` (tighten-only
floor ANDed over the operator-set policy value, default true), `ANDVARI_INSTANCE_NAME`,
`ANDVARI_CANONICAL_ORIGIN` (must satisfy the `origin` grammar of spec 01 §5.1; the server refuses to
start otherwise), `ANDVARI_SELFHOST_DOCS_URL`, `ANDVARI_FORCE_HSTS` (mandatory `1` whenever the
origin is https), `ANDVARI_LOGIN_RATE_PER_MIN` (default 5), `ANDVARI_STRICT_ENV` (the server
boot-warns on unknown/invalid `ANDVARI_*`; under strict mode it **exits**). **A setting the server
cannot read stops it at its start, whatever the setting** (rule of 2026-11-17): a value that is
present and cannot be read (a number that is not a whole number or is out of its range, a switch
other than 1, true, 0 or false in any case, a value off a closed list, an entry of
`ANDVARI_TRUSTED_PROXY_CIDRS` that is not an address block) is refused with a line that names the
setting and the value. An unset or blank value takes the default, for every setting, except the
two lists `ANDVARI_TRUSTED_PROXY_CIDRS` and `ANDVARI_TRUSTED_IP_HEADERS`: there a value that is
present but blank (or only commas and spaces) is the empty list, which trusts no proxy and reads no
forwarded header, as it always has. So a blank `ANDVARI_DB`, `ANDVARI_BLOB_DIR` or
`ANDVARI_SELFHOST_DOCS_URL` takes its default (before, a blank database path was a temporary
database lost at every restart, and a blank folder for attachments was the root of the file
system); a blank `ANDVARI_WEB_DIR` serves no web app; a blank `ANDVARI_INSTANCE_KIND`,
`ANDVARI_SIGNUP_MODE` or `ANDVARI_REGISTER_LINKS` takes its default instead of stopping the start.
The server keeps this since 2026-11-18.

**POLICY-TRUST BOUNDARY (normative).** The client reads this object from an **unauthenticated
endpoint on an untrusted server**. Governing invariant: *a field is trusted-as-declared iff it governs
the server's own behavior; it is client-floor-only iff it touches the client device's at-rest posture,
factor floors, or timer windows. A hostile server may always make the client safer, never laxer.* Each
client implements one `applyPolicy()` whose tighten-only branches are structurally incapable of
relaxing.

| Field | Class | Rule |
|---|---|---|
| `signup.*` | **TRUSTED** (server-authoritative UI hint) | Drives which sign-up UI renders; registration stays server-enforced (§14). A lie only mis-decorates the liar's own front door. |
| `totpRequired` | **TRUSTED** (UI hint) | Pre-shows the TOTP input. Authoritative path stays the reactive server errors (`totp_required` / `totp_enrollment_required`), which win over any declared value. Never gates a client-side protection. |
| `sessionAccessTtlSeconds`, `sessionRefreshTtlDays`, `attachmentMaxBytes`, `itemAttachmentsMaxBytes`, `serverTime` | **TRUSTED** (informational) | Describe the server's own enforcement; never security anchors. |
| `offlineCacheAllowed` | **CLIENT-FLOOR-ONLY** (forbid-only) | `false` ⇒ prohibition + force-wipe of the **declaring origin's own namespace only**, unconditional and prompt. **When changes wait that were not sent** (decided on 2026-11-17): the client first tries ONCE to send what waits, then wipes as specified, whatever the attempt brought. Once means one run through what waits, each request with its ordinary limit, no second try, no waiting for a connection to come back, no question to the person; the run ends at the first request that gets no answer; a session that has ended sends nothing, and the wipe then follows at once. Afterwards the client says how many changes could not be sent, once, at the first moment the person can read it; that number is kept apart from the copy so that it survives the wipe (a number and the server's name, nothing of the content); where every change was sent, the notice says that the copy was removed because the server's policy asks for it and that nothing was lost. This holds for every copy the policy wipes (the browser's offline copy and its unlock copy among them). **How the attempt runs** (rules of 2026-11-17): <ul><li>**Whose copy.** The wipe runs for the copy of the account whose session read the policy. A copy of another account kept in the same client is wiped when that account is next opened there and reads the policy itself, so that its own session makes its one attempt first.</li><li>**With the copy's own session.** Every request of the attempt is sent with the session of the copy's own account, checked at that request; where the client no longer holds that session (signed out, signed in to another account, ended by the server), the attempt ends there: nothing more is sent, the wipe follows, and the rest counts as not sent.</li><li>**One limit for the whole.** The attempt ends sixty seconds after its start, a refresh of the session included, whatever is in flight then; each request keeps its own limit of thirty seconds. Then the wipe: a wipe that a long queue or a slow server could hold off for minutes is not "try once, then wipe".</li><li>**One run per copy.** One run at a time per copy across the client's tabs (a lock), and every other way a copy is wiped (a sign-out, the offline copy turned off, an account deletion) takes the same lock. A second tab finds the copy gone and says nothing. From the moment the policy is read, nothing new is queued into that copy, and a change the person makes then is refused with a line that says why; a tab of another account goes on as before.</li><li>**Three outcomes, never two.** A change is "sent" only when the server's own answer says it took it. A change whose request went and whose answer did not arrive in time, or did not arrive at all, "may or may not have arrived", with a number and a sentence of its own. A change the server answers with a conflict is judged by what the server did with it (rule of 2026-11-18, which corrects the earlier "a conflict counts as lost", §5): a put over a newer version IS stored (the server keeps the version it displaced in the item's history) and counts as sent; an edit that restored a deleted item counts as sent; only a deletion over a newer edit is not made (the item stays as the newer edit left it) and counts as not made. The copy of a displaced version that a client normally makes for the person is not made during the attempt, since it would be a new change into a copy that is being removed; the displaced version is in the item's history at the server.</li><li>**The number** is read from the copy at the moment it is wiped, by the run that wipes it. Where the copy vanished under a run all the same, the notice counts from what the run read at its start and what the server took since, or says that it cannot tell; never "nothing was lost" for changes that waited and went with the copy. A copy that exists and cannot be opened is "cannot tell", at this wipe and in the count before a sign-out, never zero.</li><li>**A wipe that could not be made** is not said as made: the copy is not opened again, the wipe is tried again at every start and when what blocked it ends, and the notice that the copy is gone is shown only when it is. It is tried again only while the policy still forbids the copy, read anew at that start; a policy that was lifted ends the pending wipe and its notice, and the copy is used again.</li><li>**A run that the closing of the tab cut off was not the one attempt:** the next start makes it from the beginning (the server takes a change it already holds without storing it twice).</li><li>**A wipe that is owed is finished at the next start:** a wipe that was asked for (the policy's, and a sign-out's own wipe that waited for a policy's run) and that the closing of the tab cut off is finished at the next start of the app in that browser, without a session, so that a person who signed out does not find the copy still on disk. A start that cannot read the policy does not retry a held wipe and does not open the copy either: the copy stays closed until the policy can be read.</li><li>**A wipe that stays blocked** (another tab of the browser holds the copy open) says so truly: the line tells the person to close andvari's other tabs in this browser, and the account is open for changes again as soon as the wipe is made.</li></ul> **What the web client keeps (2026-11-18):** all of the attempt above, in the browser: a Web Lock per copy, which every other wipe of that copy takes too; nothing new queued from the moment the policy is read, a change then refused with its line; each request with the copy's own account, checked at that request; thirty seconds per request and sixty for the whole; the three outcomes, each with a number and a sentence of its own; a copy that cannot be opened said as "cannot tell"; a held wipe retried at every start only while the policy still forbids the copy; and the owed and blocked wipes as above. A copy of another account kept in the same browser is wiped when that account's own session reads the policy. **Accepted:** the browser store's own wipe of a stuck copy takes no lock, and the count then falls back to what can be told; a policy that forbids the offline copy leaves the browser's records of each shared vault's log (§10.3: the account's trust records of each log and the few signed entries that wait, nothing of a vault's content), as the record of the account's identity stays. **On a device** (rules of 2026-11-18; design §4.4 has each point): the same holds for every client that keeps a copy, the two apps through the shared code; `andvari-cli` keeps no copy at rest, so there is nothing to wipe in its home. From the moment a device records a forbidding policy for an account's server, a wipe is owed for that copy, by a mark outside it that holds nothing but which copy, and nothing is removed before it is counted: what waits, what the device holds as refused, what is parked with a held vault, saves kept to be finished with their files, and unfinished moves are all part of the copy and of the count, and the attempt tries each kept save too. A kept policy record that cannot be read is not a forbidding policy: nothing is deleted on its account, and the copy stays closed until the policy has been read. Logins the Android app has caught and not yet answered are not part of the copy (decided on 2026-11-18): they stay sealed on the phone until the person answers them, also when caught after the policy came into force, and only on condition that such a login cannot be opened on the phone without an unlock the server answers. Under such a policy the account's wrapped keys at rest and the quick-unlock key go, the session's tokens and the record of the account's identity stay, and an unlock proves the password against the keys the server serves. **Under a forbidding policy every unlock asks the server for the account's wrapped keys** (rules of 2026-11-19): they leave the device, with the quick-unlock key, at the moment the policy is recorded, on every road; an unlock reads them with the session and opens them on the device, and nothing derived from the password is sent. A record whose keys were at the server gets no wrapped key back at rest until a readable policy that allows it is kept, also where the kept record of the policy has become unreadable and an unlock got the keys but no answer to the policy's read; the mark that a wipe is owed is written before the keys are removed, or survives a failure of that removal; a quick-unlock enrolment whose prompt was on show when the policy was recorded looks again before it writes a key (rules of 2026-11-19). The same holds on every road that brings keys onto the device for such a record, not the unlock's alone: a sign-in, a recovery with the kit, the operator's help and a device link's pickup take their session through one place, which brings no wrapped key back at rest until a readable kept policy allows it; a registration over another account's record is refused; a refresh writes no keys; and a record marked as having its keys at the server that carries any wrap (a wrapped key, its salt, the sealed identity seed, a personal wrap, a pending wrap) is stripped of it when it is written at rest, so a password change whose answer arrives after a lock leaves no key material at rest (rules of 2026-11-19). A server's "too many requests" or "forbidden" at the keys' fetch removes nothing and is to be said as what it is, not as "unreachable"; a caught login older than thirty days is to be counted as what it is, not as "could not be read" (rules of 2026-11-19). So while the server cannot be reached there is no unlock under such a policy: nothing is tried, nothing is wiped and nothing is lost, and the one attempt and the wipe come at the first unlock the server answers; a device that is kept offline keeps a copy that nothing on the device can open (decided on 2026-11-19: no unlock and no wipe while the server cannot be reached; the one try and the wipe at the first unlock the server answers). The account's state document stays: it is sealed under the account's key, which is no longer on the device, and its counters protect the next unlock against an older state from the server. The mark that a wipe is owed is written at the moment the policy is recorded, not after the hop to the main thread. **What is said:** "never left" is never said of a request that may have left (a failure that carries an earlier attempt that was sent is "may have left"); a save the server stored is never said as not made (where the removal begins after the answer to the batch that carried it, it is settled as made), and a save stopped before it was ever queued is not made; while the copy is being removed nothing reads as "this server is stopped", every act on a shared vault refuses with the removal's line, and the apps say that line where they would offer a vault for a new item; after the run, a wipe of the person's own that waited is followed by a redraw, so that no notice of a server just forgotten or an account just deleted stays on the screen. The shared code answers whether a wipe is owed for an account at a server, so that no app deletes the copy by itself. On an iPhone a request never reports that it did not leave, so there an unreachable server's changes read as "may or may not have arrived", the safer of the two readings. **What the shared code keeps (2026-11-19):** every road that records a policy writes the mark at once, on the thread that recorded it; nothing is removed before it is counted (the queue, what the device holds as refused, what is parked with a held vault and the kept saves are counted, a part that cannot be read is "cannot tell", and a known number is never hidden behind it); an opening over an owed copy opens it halted, takes nothing new and refuses a change with its line; the one attempt with the copy's own session, sixty seconds in all and thirty for each request, with the three outcomes; "never left" as above; a save the server stored is made and one stopped before it was queued is not made; nothing reads as a stopped server during the removal, and every act on a shared vault refuses with the removal's line; one lock for every wipe, and a wipe of the person's own that waits behind the run is kept durably and followed by a redraw; the notice belongs to its account and says its numbers (not sent; may or may not have arrived; cannot tell, or at least so many and more that cannot be told) until the person dismisses it. **A limit of 2026-11-19, closed the same day:** an edit of an item that already had an earlier change waiting, stopped before it was queued (it waited behind a running sync or its files' uploads when the removal began), was said as "may or may not arrive" although it was not sent; the item engine now says whether it queued the change, and such an edit is said as not made. **Kept since 2026-11-19 (the shared code, the vault content and both apps):** the account's wrapped keys and the quick-unlock key leave the device when the policy is recorded and every unlock asks the server for them, so while the server cannot be reached there is no unlock, nothing is tried and nothing is wiped (the owner's decision of 2026-11-19 is built); the three guards above, the sign-in's road and the strip of any wrap from a record whose keys are at the server whenever it is written (the race in which a pending wrap is written into a stripped record is covered by the same strip by reading only; no test forces it); on every road walked (an unlock, a sign-in with the kept policy's record damaged and with it readable, a recovery with the kit, a password change answered after a lock, a scan of every record and a restart with no server) and by reading on the operator's help, a device link's pickup and a refresh, a login the phone caught opens without an unlock the server answers on none; caught logins stay sealed on the phone and no longer go with the copy (the notice no longer counts them), and after a removal one is sent once however many unlocks follow, is never in the vault twice, one that waits for the person's answer shows its own reason, and one whose write the server took while the read after it got no answer is neither said as gone nor sent again; saves with files that a lock cut short are part of the one attempt (files first under their ids, then the item as one more request of the same run, an item never without its files; one that cannot be sent as it was made, whose file is refused or unanswered, or that the run does not reach is counted as not sent, and one whose item was out when the run's limit struck as "may or may not have arrived"); the item engine says whether a save queued its change, so an edit stopped before that is said as not made (the limit above is closed); unfinished moves have a number of their own; the next opening reads what the switch-off carried into memory, and an owed wipe follows a followed move; while the copy is being removed the vault shows a line of its own, and a change then is refused with a line of its own; both apps draw the notice in every phase from the snapshot alone, its lines in the shared code's order with one dismiss, and the removal's line where a stopped server's would stand, with Save still offered, and leave the removal of the copy to the shared code. **Not kept yet (2026-11-19 unless dated):** a server's "too many requests" or "forbidden" at the keys' fetch is still said as a server that did not answer, which is untrue (the server answered): the session keeper hands every answer at that read that does not bring the keys as no answer, so the app interface's own results for a refusal and for a wait there, which both apps draw, are reached only from the test stand-in; a caught login older than thirty days is said as the rules above say (not established as built). **Kept since 2026-11-19:** the shared code answers the apps whether a removal is still owed for the session's own account, and the desktop reads that answer, never its disk, so another account's file on the computer neither holds the switch for keeping nor refuses its untick; when the desktop's switch "Keep me signed in" goes off, by the policy once the removal is done or by the person's untick, it removes every file in its cache folder, another account's included (the desktop keeps one account at a time and refuses a second sign-in until the kept account is signed out, so a file of another account there is a leftover that no session can open or send from, and its waiting changes are not the open session's to count); both apps draw the lock screen's line that the keys are kept at the server, the desktop above the card for the server's end and the password field (the phone draws its lines since 2026-11-19: the lock screen and the window that unlocks for a fill say that the keys are kept at the server, Settings says that caught logins stay sealed until they are answered, a catch is never refused for the policy, and a session the server ended under such a policy is not said as a copy the password opens read-only; with the server stopped nothing the phone's screens offer opens a caught login, also after a restart, shown at the phone's own level); once the removal is done the desktop's switch goes off and its kept session file goes, so after a restart the desktop lands on its first screen, and its lock screen with that line shows only after a lock within the run or while the removal is still owed. **What the apps say in three states under such a policy** (rules of 2026-11-19; kept since 2026-11-19: the shared code hands a line for each, and both apps draw the shared code's lines as handed, with none of their own): (a) **an unlock the server did not answer** says that nothing was opened and nothing was removed, that the password could not be checked because under this server's rules only the server can, and to try again when the server can be reached, never the general line for a server that cannot be reached; a right and a wrong password read the same, and with the server back the unlock opens; (b) **the server ended the session**: the lock screen's line says that the server ended the session, that this device keeps no key and no copy that opens the account, so nothing opens there until the person signs in again, that nothing was removed and that the logins andvari caught stay sealed until then, with "Sign in again"; beside a way out that signs the kept account out first, a line of its own says so; an unlock then, with the right or a wrong password, says that nothing was opened or removed and that nothing opens until the person signs in again, and the lock screen stays; nothing there says that a copy opens; (c) **the first unlock that meets the server's end** answers as that end at once: the session keeper asks whether the session ended before it asks whether the state moved. "Sign in again" comes only from a real end of the session, never from a network fault, a gateway's page or a wrong password alone. **A session that ends while the account is open** (kept in the shared code since 2026-11-20): under such a policy every end of the session (the server's, by a refused renewal or the live channel's word that the device was revoked, and this device's own, where it could not confirm the session and no try is left) leaves in memory exactly what the device keeps at rest, as a lock does: no wrapped key of the account stays, and the master password opens nothing, and no caught login opens or is said as saved, until an unlock the server answers after the person signs in again; this holds with the server silent and after a restart, and where the policy was recorded before the opening or while the account was open. Without such a policy the copy at rest still opens read-only with the password after the server's end. **Not kept yet (2026-11-20):** an account held as its server's operator and the record a sign-in call that was left puts back still keep the served keys in the session keeper's memory (no sequence is known in which either opens anything without the server); each is to be made what is kept at rest. **Two things of the vault content under such a policy** (rules of 2026-11-19): a login caught before the removal that needs no answer is saved at the removal's own opening, and is said as saved (nothing is lost; kept in the shared code since 2026-11-19: the removal carries the list of what that opening saved across the remaking of the content, in memory only, as every record under such a policy, so the footer's list of saves and its Undo still hold it; with the server silent no caught login opens and none is said as saved); and the list of deleted shared vaults reads the vault's own mark and its line without a day, as the rows do, never a day from a field that can be empty (kept since 2026-11-19 in the shared code: it marks a deleted vault on its own and hands a line without a day where the server served none, and both apps read that mark on the shared-vault rows; the list "Recently deleted" hands, per vault, that it is deleted, the day only where the server served one, and else the line without a day, and a row with no day is listed only where this device's own verified log ends in the owner's deletion; since 2026-11-19 the phone's list "Recently deleted" draws the day only where the server served one, and else the shared code's line without a day (the desktop has no such list). Also not kept yet (2026-11-19): the files of a kept save whose change already waits in the queue are not uploaded again inside the attempt. **The rule for a request already out** (2026-11-19, which corrects the earlier reading that such changes are never sent again by the attempt): the attempt waits for a request already out, within one request's limit; where it is answered, its changes are counted by that answer (taken, or refused) and not sent again; where it never left the device, they are the attempt's own; where it ended without an answer, or the wait ran out, its changes still wait and get the attempt's one try in the queue's order, and the pass goes on, ending as before at the attempt's own first unanswered request (the server takes each change once, so two requests for one change go only where the first got no answer); the write or sync whose request was out answers what became of it before the copy is removed; a change that had a request out without an answer is counted "not sent" only where the server answered for that change that it did not take it, and otherwise, where it is not seen taken, "may or may not have arrived". Kept in the shared code since 2026-11-19: a change whose request was already out when the policy was recorded is not sent beside that request; answered, it is counted by that answer; ended without an answer, it waits and gets the attempt's one try, and is counted "not sent" only where the server said so; the write whose request was out answers before the copy is removed. The web client judges a conflict by what the server did since 2026-11-19. `true` ⇒ **necessary but never sufficient**: at-rest persistence additionally requires per-device consent on web + desktop; Android's default-ON exemption is on the record (spec 05 T3). |
| `kdfParams` | **CLIENT-FLOOR-ONLY** | Existing floors unchanged, incl. the cache-read sub-floor (below-floor cached params ⇒ refuse offline unlock, spec 05 T8). The served cost is never below the server's floor (§7.2), and every new wrap (a registration of any kind, a password change, both recoveries, the quiet re-key) is made at the higher, figure by figure, of the account's cost and the served one, inside the client's limits, and at the served cost where there is no account yet, so that the routes that store a wrap (§14.3, §3, §12, §18.5), each of which refuses a cost below the served cost, on each figure, as `kdf_too_weak`, take it (rule of 2026-11-17, spec 01 §7, which says what each client does). |
| `autoLockSeconds` | **CLIENT-FLOOR-ONLY** (clamp) | Effective value clamps into `[floor, AUTO_LOCK_MAX_SECONDS = 900]`; a server-supplied 0/absent ("never lock") clamps to the ceiling — **a server cannot disable auto-lock**. Constants live in core (`ClientPolicyClamps`) with byte-pinned web/ext mirrors; all four clients test that oversized values clamp down. |
| `clipboardClearSeconds` | **CLIENT-FLOOR-ONLY** (clamp) | Clamps into `[1, CLIPBOARD_CLEAR_MAX_SECONDS = 300]`, same constant/mirror/test discipline. |
| `minVersion` | **CLIENT-FLOOR-ONLY** | Force-upgrade-only (fail-safe). |
| `instanceName`, `canonicalOrigin`, `selfHostDocsUrl` | **DECORATIVE** | Never rendered as verified identity; never shown in the Trust Gate; `selfHostDocsUrl` rendered as a raw URL only. |

The instance's identity, its `kind` and its recovery key are **not** policy fields: they come only
from the signed instance card (§17, spec 05 T10). **Policy fetch failure ⇒ conservative defaults:**
render sign-in and the link entry points, treat `signup.mode` as `closed`, `totpRequired=false` (the
server re-prompts authoritatively), durable cache OFF.

## 2. Auth & sessions

- `POST /auth/prelogin { email }` → `{ kdfSalt, kdfParams }` (rate-limited). Unknown emails get a
  fake-but-deterministic salt (spec 01 §3) + the **current default** kdfParams — never the
  compile-time default. Known accounts answer their real per-user params (clients need them pre-auth
  to derive the auth key); the residual params-divergence oracle after a policy bump is recorded in
  spec 05 R4 and heals when the account re-keys. A client sends prelogin only under the password rule
  (spec 01 §5.3): to an origin it holds a session for that account on, or one with a password pin.
- `POST /auth/login { email, authKey, device, totp? }` → `200 SessionResponse`.
  - `device` is `{ platform, name, deviceSecret, deviceId? }`: `platform` from §0.1's list, `name` a
    `text`, `deviceSecret` a `b64_32` (§0.3). `deviceId` is sent by a device that already holds a
    device row on this account (from an earlier login, registration, pickup or recovery commit).
  - **Known device.** The login is from a **known device** only when `deviceId` names a device row of
    this account that is not revoked and whose stored secret hash equals the hash of the `deviceSecret`
    sent (§0.3). No live session is needed: a signed-out device stays known. The server then creates the
    new session on that device row (the response carries the same `deviceId`) and sends no new-device
    email. Anything else — no `deviceId`, an unknown one, a wrong or missing secret, a revoked device — is
    a **new device**: refused with
    `403 link_required` when `requireLink` is on (below), and otherwise created (`how = password`, the
    secret's hash stored) with the `new_device` email. Every revoke clears a device's hash (§16.7), so a
    wrong or missing secret can never dodge `requireLink`.
  - **A device has one live session, and the server keeps that rule itself** (rules of 2026-11-17).
    When a sign-in gives a known device a new session, the server ends that device row's earlier
    sessions in the same transaction, only when the whole sign-in succeeded (a two-step code
    included), as a logout ends them: the row stays known. Nobody can end a device's sessions this
    way without that device's own secret. A client therefore sends nothing of its own to end the
    session such a sign-in replaces: after a refresh whose answer was lost, the token it holds is one
    the server has already replaced, and sending it would be taken for the reuse of a stolen token
    and end the new session too. A session the device REFUSES is still ended by the device alone, by
    its own refresh token (`end-session`, below), the session of a sign-in the person left included.
    **A browser's row is the exception:** each tab of a browser without the offline copy signs in and
    holds its own session on the browser's one row (decided on 2026-11-16), so a sign-in from the web
    ends none of the row's sessions. The exception follows the kind of row recorded when the row was
    made, not what a sign-in says of itself: a sign-in that claims another kind than its row's is
    treated by its row's kind. A recovery's commit ends every session of the account (§12, §18.5); a
    device link's pickup makes a new row and ends nothing of the old one, so there a device that kept
    the account ends that session by its own token. **What the audit log shows, and what it cannot**
    (rule of 2026-11-17): a sign-in that ends a device's earlier sessions is recorded as the end of a
    session by a sign-in, and that is all the server can know. A chain that someone else had been
    refreshing with a stolen token ends there quietly, where before the person's own next request
    would have run into the reuse rule and left its record; the reuse rule itself is unchanged for
    every token of a live session. The name of the replaced session (next point) brings that sign
    back where the client held a token the server had already replaced.
  - **The sign-in names the session it replaces, and the server ends exactly that one** (rule of
    2026-11-17, for every client): the sign-in's request may name the session it replaces by the
    refresh token the client last held for it; when the whole sign-in has succeeded, the server ends
    exactly that session in the same transaction (it must be a session of the same account on the
    same device row; anything else is ignored), also when the token named is one the server had
    already replaced, and the record of that end then says so: that is the sign of an answer that
    was lost or of someone else having used the token. On an app's or the tool's row the server ends
    the earlier sessions anyway; there the name adds the record. The name is the login body's
    optional field `replacesRefreshToken`, a string (a server without it ignores it, as it ignores
    every field it does not know). It is read only after the whole sign-in has succeeded, and only
    on a known device. The session it names is ended as it stands now: the token's whole refresh
    chain, the session the token was minted with and every session a refresh rotated it into since.
    The server keeps each session's chain in a table of its own, which a server of the version
    before ignores, so that a roll-back of the server still starts on a database the newer one has
    run on. A token the server had already replaced is not taken for a reuse here: only that chain
    ends, and the record of the end, `session_end`, says so (meta `sign_in_named_replaced`;
    otherwise `sign_in_named`; a sign-in that names no live session of its own keeps `sign_in`).
    Anything else named (another account's token, another row's, an unknown, ended or expired one,
    an empty or overlong string) is ignored and changes nothing; a value that is not a string is
    `400 bad_request`. On a browser's row only the named session ends, and its events sockets get
    `{"type":"revoked"}` and are closed; the other tabs' sessions and sockets stay. A client sends
    nothing else for the session it names, neither before the sign-in nor after it. **A sign-in
    that fails or is refused ends only a session that this sign-in itself was given**, never a pair
    the client held before it started.
  - **The kind of a device row decides wherever a session is made** (rule of 2026-11-17): the
    browser's exception above, and whether a new session is a browser's, follow the kind the row
    was made with, at a sign-in, a refresh, a registration, both recoveries' commits and a device
    link's pickup alike, never the kind a request claims for itself (on any other row the session
    takes the request's platform). A session minted on a browser's row is
    a browser's session whatever the request says (so the operator's routes refuse it, §7); a
    browser's claim on an app's row only restricts. The version check (§1) still reads the claim,
    since it is about the client's own version.
  - **Kept as they are, and said** (2026-11-17): (a) a desktop profile copied to a second computer,
    and a copied home of `andvari-cli`, are one device to the server: under the one-session rule
    each sign-in on one signs the other out; the way out is to remove that device in the device
    list, after which each signs in as a device of its own. (b) A success answer that the browser
    cannot read may have made a session that nobody holds; the browser has no token to end it with,
    and it ends by itself (an hour for its access, thirty days for its refresh). The same holds for
    a refused session whose ending got no answer. (c) A server of an earlier version, without the
    one-session rule, keeps a replaced session alive until it expires; the clients of this version
    are not made for such a server.
  - **What is kept (2026-11-18):** the server ends a known device's earlier sessions at a sign-in,
    in the sign-in's own transaction, recorded as `session_end` with meta `sign_in`, and their
    events sockets are told and closed; it reads `replacesRefreshToken` and ends the named chain as
    above, with the meta `sign_in_named` or `sign_in_named_replaced`; it keeps each session's chain
    in its own table; and the kind a row was made with decides at a sign-in, a refresh, a
    registration, both recoveries' commits and a device link's pickup. The shared code names the
    kept session's refresh token at a password sign-in when the device keeps a session of that
    account at that origin on the row the login sends, and sends nothing else for it;
    `andvari-cli` names the session its home keeps for that account, its operator's session
    included. The browser ends only the session its own sign-in's call was given, never a pair it
    held before or one another tab rotated meanwhile. Since 2026-11-18 the browser names the
    session it replaces: the pair this tab held, by the refresh token it last held for it (also
    one the server had already replaced), only where this browser's row for the address is sent
    and that row's account is the pair's account, and at every submit of the sign-in form, after a
    request for the two-step code or a wrong password too, for as long as the tab still holds that
    pair. It sends nothing else for it. **Where every tab shares one session** (the offline copy is
    on) **the browser's sign-in names none** (accepted on 2026-11-18): the one-session rule does not
    apply to a browser's row, and naming the shared pair would sign the other tabs out. A tab never
    names another tab's session. Kit recovery and registration name nothing; they are not
    sign-ins.
  - **Check order.** The per-IP bucket; the email backoff (§8); `authKey` against the verifier; the
    TOTP rules below; then, only after the password and any code have verified, **`requireLink`**: when
    the account has it set and the login is not from a known device, `403 link_required` (§16.8). So
    that answer tells nobody without the password that the account exists or has the setting on.
  - `SessionResponse = { userId, deviceId, accessToken, refreshToken, accountKeys, role, totpEnrolled,
    mustEnrollTotp, recoveryPieceId? }`. `role` is `"operator"` or `"member"` (§7). `recoveryPieceId`
    is populated only by the routes that commit a new recovery piece (register and both recovery
    commits); login and refresh leave it absent.
  - Failures are uniform `401 invalid_credentials` (no user/password distinction).
  - **TOTP matrix:** an account with server-TOTP **enrolled** has it verified on every login. A
    **missing** code → `401 totp_required` (the client's cue to render the code field). A **wrong or
    replayed** code → the uniform `401 invalid_credentials`, NOT `totp_required`: the second factor is
    guessing surface exactly like the password, so its failures join the same undifferentiated 401 and
    the same email-keyed backoff (§8), and every client already renders one "wrong email, master
    password, or one-time code" line on it. Answering `totp_required` to a wrong code would narrow the
    guess for an attacker who already has the password. An account **without** TOTP enrolled: instance
    `totpRequired=false` (§1.1) ⇒ password-only login; `totpRequired=true` ⇒ login succeeds into a
    **restricted session** — the response carries `mustEnrollTotp: true` and every authenticated route
    except TOTP setup/confirm + logout answers `403 totp_enrollment_required` until enrollment
    completes (single enforcement point beside the principal check). The enrolled-account
    `totp_required` answer still confirms a password before the code (spec 05 T11).
    **A refusal after the code is never said as a wrong password** (rule of 2026-11-17, every
    client): a client that sent a code because the server asked for one after this password, and
    then gets the uniform `401 invalid_credentials`, says what that makes most likely (the code was
    wrong or already used) and claims no more; it never says that the master password was wrong.
    The shared code hands this up as its own reason (`refused_after_code`) at a sign-in and at a
    device link's pickup, the app interface tells it as its own result, and `andvari-cli` says it
    at a sign-in and at `link-device` (2026-11-17). At a sign-in the screen goes back to the
    password and the code. **At a device link's pickup a wrong code keeps the link** (rule of
    2026-11-17): the server keeps the link approved within its time and its back-off, and the
    device asks for the password and the code again with that sentence. The shared code keeps
    this since 2026-11-18: a pickup refused after the code step answers that the password or the
    code was refused and the link stays, until the link's own time, after which it stops as a
    refusal after the code. `andvari-cli` asks for the master password and a new code again,
    never sends again a code the server just refused, and sends at most three codes in a run.
    **A password that opens this device's copy and that the server refuses at a link's pickup
    is not a wrong password** (rules of 2026-11-17 and 2026-11-18): it has a stop of its own
    (the shared code's `PROOF_REFUSED`, with the code `reauth_failed` that a refused proof has
    elsewhere, spec 01 §7; `andvari-cli` exits 7 with its own sentence), and it keeps the
    link, as a refused code does; it is told apart where no code was asked in the flow so far,
    not only in that call. The shared code keeps this since 2026-11-18: a pickup refused for a
    password that opens this device's copy, before any code was asked in the link, keeps the link
    within its time and asks again; whether a code was asked belongs to the link, not to one call,
    and once a code was asked in the link, every refusal is a refusal after the code.
    `andvari-cli` asks for the password again on such a refusal, up to three times (since
    2026-11-19; a home keeps no copy to compare a password with, so the tool cannot meet this
    refusal today). The app interface keeps this since 2026-11-19: the refusal is a result of its
    own, which keeps the link and its password screen with a sentence that the server did not take
    this password, and asks for the account's current password; a code the server refuses at the
    link's pickup leaves the link open, adds no tries of its own (the server's limits bound them,
    and each try needs the master password typed again), and returns to the password screen; a
    used code step goes back to the password; a link the server refuses for too many requests
    ends with its own line and the wait, never "unreachable", and the showing device's own end says
    its line in place of "a check failed". Each retry of a code at a link costs a full derivation
    (accepted). Both apps draw a link's "too many requests" end with the wait (empty where none is
    given) and, on the showing device, its own line in place of "a check failed", since 2026-11-19.
  - **What a client checks in the login's answer before it keeps anything** (spec 01 §7): the
    login's `accountKeys` salt and cost equal the first exchange's (a server could otherwise write a
    salt into the device's copy under which the right password reads as wrong at every later
    unlock); and, on a device that already keeps this account (a copy, a kept or locked session, a
    pending password change), the account key the served wrap opens is that account's key as the
    device knows it. A login whose salt or cost differ is the server's answer that did not make
    sense; a key that is not the kept account's is refused as `server_keys_not_known_here`; either
    way nothing kept is replaced and the new session is not kept (rules of 2026-11-17).
    **A sign-in whose answer the client refuses ends the session the server gave it** (rule of
    2026-11-18): the server has already made that session, and for a device it did not know a new
    device row, so the client ends it with the refresh token the answer carries (`end-session`)
    before it reports the refusal, and keeps the device row the answer named, so that a second try
    uses that row instead of making another. Its sentence says what happened (the server took the
    sign-in, and this device ended it again, and why), never that nothing was sent. A registration
    and a recovery with the kit treat the same refusal of an answer alike. The browser keeps this
    since 2026-11-18, for an answer whose hashing cost it does not take and for one whose salt or
    cost differ from the first exchange's.
- Tokens are opaque 256-bit random, transported as base64url, stored server-side as `sha256(token)`.
  Access: 1 h. Refresh: 30 d, **rotating** — `POST /auth/refresh { refreshToken }` → new pair, old
  refresh token single-use; reuse of a consumed refresh token revokes the whole device session (theft
  signal, audited). **A refresh whose answer was lost** (rule of 2026-11-17): a replaced refresh
  token presented again to `POST /auth/refresh` within sixty seconds of its replacement (sixty
  inclusive) is answered `200` with the same pair that refresh answered, while that pair's access
  token has authenticated no request and its session is neither ended nor refreshed; it is no
  reuse, and a racing second refresh of the same token is answered the same way. Without it, one
  lost answer signs the person out with a reuse on record that is no theft. Such an answer draws
  the caller address's `refresh` allowance (30 a minute) and is audited `refresh_grace` (the
  account, the device and the caller's address, nothing else), so that the operator and the person
  can see that a replaced token was presented again and answered. **This is a trade, said as it
  is:** inside that minute, whoever holds the replaced token gets the same live pair as the device
  and can use it beside it, until one of the two uses or refreshes it; the `refresh_grace` record
  is what shows it. After the window, once the pair was used or refreshed, or after a restart of
  the server, a repeated refresh is a reuse: every session of the device ends. The server keeps the
  pair in memory for the window only, and drops it when the window has passed (at the latest at a
  sweep each second), so that it never holds a session's tokens in plain text longer than the
  minute they can be asked for. The server keeps all of this since 2026-11-18. **The client's
  second try** (rules of 2026-11-17 and 2026-11-18, for every client, `andvari-cli` included): a
  client records that a refresh is out before the request goes, and keeps that record, with the
  time of the first try's sending, through whatever cuts the request off (a failed connection, a
  timeout, its caller cancelled, a lock, the app ended while the request was out). Only an answer
  in the server's own envelope clears the record: a gateway's page that is not the server's, and
  an answer whose body does not read (a `200` among them), leave it, since those are the cases
  where the server may have taken the refresh. A server error in the server's own envelope clears
  it (the server answers so only where its transaction did not commit). While the record stands,
  the client tries the refresh once more with the same token, once, and only within **fifty
  seconds** of the first try's sending: the second try has to arrive inside the server's sixty
  seconds, which run from the moment the server replaced the token, and ten seconds are the margin
  for the road. A `200` is the refresh's answer, a `401 refresh_reuse` is handled as before. After
  the fifty seconds the token is never sent as a refresh again, in that run or a later one, because
  the server would take it for a reuse, end every session of the device and record a theft that did
  not happen. **Where no try is left, the session ends on the device with a reason of its own**:
  it is not "the server ended this session"; the person is told that andvari could not confirm this
  device's session with its server in time, that nothing was sent again, so that no other session
  was ended, and to sign in again. The token is then kept for one use only: the next sign-in names
  it as the session it replaces (above), so that the server ends that chain as replaced; it is never
  sent as a refresh or to end a session, and it goes at a sign-out, at a sign-in that takes its
  place and at the account's removal. **A refresh that never left the device costs nothing**
  (rule of 2026-11-18): where the transport can tell that nothing left the device, the record is
  put back as it was, as it already is where the device's own guard stops the request. "Never left"
  is the transport's word, given only for a failure of the connect itself with no earlier attempt
  attached (a connection refused, no route to host, a timeout while connecting, a name that did not
  resolve; never a failure that carries an earlier attempt, never a secure setup that failed, a
  proxy's refusal or a plain socket failure), and the keeper takes it as it is (2026-11-19; spec 05
  R11 and R41 say what a wrong word would cost). Kept in the shared code since 2026-11-19: where the
  transport says that nothing of the refresh left the device, the record stands as it was before
  that try, and every other failure without an answer keeps it.
  **Accepted** (2026-11-18): the window is judged by the wall clock, so that a restart earns no
  try; a clock set back inside the window by less than the time that passed can therefore let a
  late second try go, which the server then takes for a reuse. **What is kept (2026-11-19):** the
  shared code writes the record, with the first try's sending time, and keeps it with the session
  before the request goes, so that a failed connection, a timeout, a cancelled caller and the end
  of the app all leave it; a second try is marked as such before it goes. Only an answer in the
  server's own envelope clears it: a page that is not the server's, a body that broke off or does
  not read, and an answer over the device's own size limit keep it. A first try answered `429` or
  a `5xx` in the envelope clears it; a second try answered so does not, so no third try is ever
  sent. The second try goes only within fifty seconds of the first try's sending, edge included;
  past them, or where the clock stands before the recorded time, nothing is sent and the session
  ends on the device with its own reason (the device could not confirm its session in time), kept
  through a restart: the account and its copy stay, the copy opens with the password, and the
  token is kept for the next sign-in of the same account at the same origin on the same device row
  to name; it goes with the record at a sign-out, at the take that replaces the record and at
  every removal, and it is never sent as a refresh or to `end-session`. Where the device's own
  guard stops the request before anything is sent, the record is put back as it was.
  `andvari-cli` keeps the same rule: its home saves the record with the session before the request
  goes; only an answer in the server's own envelope clears it (one over the tool's size limit does
  not); the token is sent once more only within fifty seconds, in the same run or a later one, and
  never after or a third time; past that the tool sends nothing, says so, and the next sign-in
  names the token. The app interface hands this end to the screens as its own since 2026-11-19 (a
  field of its own, on the lock screen, on an open copy and on the first screen, across a
  restart), so that no screen says "signed out by its server" for it. Both apps draw that field
  since 2026-11-19: the lock screen, an open copy and the first screen name the end as one the
  device could not confirm, and the line beside a kept account does not say that its server
  signed it out; the desktop's own two lines for work overtaken by such an end and a change cut by
  it no longer say that the server ended the session (closing the gap of 2026-11-19). The shared
  code's line for that end ends "sign in again", which beside a way out that signs that account
  out first would read as the opposite instruction; so where such a way out stands the shared code
  hands a line of its own without it, and both apps draw that line there (since 2026-11-19; the
  desktop's lock screen draws it where a wiped kit's notice names this kept account's sign-out as
  the way out, beside its "Sign out", and not under a forked server, where no sign-out is offered;
  elsewhere it uses the line where a kept account's refusal or a link's screen offers the
  sign-out). On an app's or the tool's row a sign-in that does not name the token ends that
  chain all the same (one live session per device row), recorded as an ordinary sign-in's end;
  the name adds only the record that the token had been replaced. Since 2026-11-19 the record is
  also put back where the transport can tell that nothing left the device (above). **The browser and the extension, before 2026-11-19:** neither tried again after a refresh
  that got no answer: the next refresh, whenever it came, sent the same token, which the grace
  answers inside the minute and the reuse rule after it; so a refresh whose answer was lost was sent
  again at the next request, which the server reads as a stolen token, ending every session of the
  device and recording a theft that did not happen. **The rule for the web client and the
  extension** (rules of 2026-11-19, as the shared code and the tool keep it; kept in both since
  2026-11-19, except where a sub-point says otherwise):
  - **Two sends at most, inside fifty seconds, then the client's own end.** A mark is kept with the
    pair before the token goes, and nothing is sent unless the mark was written (a mark that could
    not be written is no mark). While it stands the token is sent once more, only within fifty
    seconds of the first sending, and then never again. Where no try is left the client ends the
    session as its own end, never said as the server's end or as "expired"; its line says to sign
    in again on this browser, and why (that sign-in names the kept token, below). **The tab's own
    one more try:** a web tab that is alive makes it itself, twenty-five seconds after the first
    sending, rather than leaving it to whichever request comes next; it is made once and only inside
    the window, and never as a third send beside a request's own try where the browser has locks
    between tabs; a timer that fires late sends nothing and ends nothing. Without locks between
    tabs, or while storage is not yet the same in two tab processes, a third send can go, all inside
    the fifty seconds (accepted, spec 05 R41).
  - **An answer of the server's own** is one that carries both the error code and the message of
    the server's envelope (§0.1), in the web client and in the extension alike: a code alone, a
    gateway's page and a body that does not read leave the mark (a gateway's answer with a code alone,
    read as a refusal, would let the token go again after the server's minute). The request that set
    the renewal off comes back to its caller as an outcome of its own ("the renewal got no answer of
    the server's", "ended here, not confirmed"), and neither is ever shown as an expired session or
    as the server's end: a gateway's page on a first try ends nothing, and after no try is left no
    second, untrue end follows the true one. The place that ends a session's answer that nobody
    adopted reads only the server's own refusal as a confirmation. The line that says "this session
    expired" over unsent changes is not shown for this end, and where the kept token could not be
    written the card does not say that the server signed the browser out.
  - **Every place that sends a refresh token reads the shared mark and the kept token, not its own
    memory:** a renewal, a sign-out and the ending of a session in another tab alike. **With the
    offline copy on, a tab sends a refresh token only if the shared record holds that same pair at
    that moment.** Where the shared record is gone the tab sends nothing (no renewal, no sign-out
    with a token, no ending of a session) and ends as signed out elsewhere; where it holds another
    pair, the tab's own stale one is never sent. No record of a removed token is kept, not even its
    hash: the shared record's absence is the guard (a tab that has not yet handled another tab's
    sign-out still holds the old pair in memory, and that token sent later would be taken for a
    theft). A tab on the unlock card drops its pair when another tab ended the session, and shows
    no refusal's line before it lands. Where the record is kept with no pair, the tab lands as the
    server's end. Where the record holds another account, the tab's line says that another account
    is signed in on this browser now, so this tab's session ended here, and that a sign-in again
    takes the browser's session from that account. So with the offline copy on a browser holds one
    account's session at a time: the tab whose account the shared record no longer holds ends at
    its next renewal, and its session at the server is neither ended nor held by anyone; it lapses
    (accepted, 2026-11-19). A sign-in whose shared record could not be written (storage full)
    renews nothing: its tab keeps the session in memory, sends no refresh token, and says that the
    session could not be saved, never that another tab signed it out. The sign-out's request that
    carries only the access token still goes where the shared record is gone: it carries no refresh
    token, a sign-in's own window needs it, and all it can end is this browser's own session.
  - **The kept token.** The token of a session that ended with no try left, or that a per-tab lock
    overtook while the mark stood or after a renewal whose answer was not the server's own (a page
    as well as a failed request), is kept for the next sign-in's name and is never sent as a refresh
    or to end a session. It is kept per account, a few at most (four in one storage place of the
    browser; a fifth account's keep pushes out the oldest), and another account's sign-in or
    sign-out does not touch it. An unlock card's way out keeps the token before it resets which
    account the card is for.
  - **A person's own sign-out of an account removes that account's kept token** (rule of
    2026-11-19): nothing that may still be a live credential stays in a browser after its account
    was signed out there. The sign-out says at that moment that the end of that session could not
    be confirmed with the server, and how to end it. In the web client the line names only the two
    ways that end it: signing in again on this browser AND then signing out (a sign-out ends every
    session of this browser's row), or removing this browser from the list of devices on another
    device. A sign-in again alone does not end it, since on a browser's row a sign-in ends only the
    session it names, and the sign-out removed the name. In the extension a sign-in again ends its
    row's earlier sessions by itself (one live session per device row), so its line may say that.
    What is given up: the next sign-in here no longer names that chain, so its session at the server
    lives until it expires or one of those ways ends it, while nobody holds a token of it. On a
    browser where each tab holds its own session, a person's sign-out also makes the other tabs drop
    that account's kept token; it tells them over a channel between tabs, best effort, so a tab that
    is closed, frozen or in a browser without such a channel keeps its own kept token until its
    next sign-in, a forgetting or its closing. A removal that could not be written is tried once more; where the
    token still stays, the line says that this browser still holds data of that session and names
    the one way that then works (removing this browser from the list of devices on another device).
  - **The extension's lock and quick unlock under a standing mark.** A lock while the mark stands,
    then a quick unlock, sends nothing at the unlock (a mark that meets a lock earns no further try),
    never ends as "revoked" and never runs the sign-out's wipe: it ends as the end that could not be
    confirmed, with its notice: the quick-unlock record and the record of known logins go, as at a
    living worker's end with no try left, the caught logins are kept, and the token is kept for the
    next sign-in's name. The person is then locked, with the line said once, where a living worker keeps the copy
    readable under a standing notice (accepted as a difference); the token lives in the worker's
    memory only and does not outlive a restart of the worker, which earns no try (the next sign-in
    on the extension's row ends that row's earlier sessions anyway). The popup's notice for that end
    says how many caught logins are not saved yet and advises no step that deletes them, as the
    notice for the server's end does. A standing mark for that end in the popup is to follow. A
    worker that starts with a kept pair whose refresh token is missing (a renewal was out when the
    worker stopped) and holds an access token with no renewal of its own on the wire ends the
    session as the end that could not be confirmed at the first need of a renewal, once, sending
    nothing and keeping no token (it was lost at the restart), where every request used to fail
    without a word. The renewal's route is not version-checked, so a stale client's renewal never
    answers `426 upgrade_required`; its next version-checked request does, and that raises the
    upgrade bar.
  The extension's line at a sign-out whose end could not be confirmed names its two ways (a sign-in
  again in the extension, which ends its row's earlier sessions, or removing the extension from the
  list of devices on another device). Kept since 2026-11-19: after a quick unlock whose record held
  no refresh token (a lock overtook a renewal that got no answer), which ends with nothing sent and
  the person locked, the worker keeps a mark of that end at rest beside the idle lock's reason, so
  the locked popup says the same line at every opening, after a restart of the worker too, until
  the next unlock clears it; and the web client says exactly one change lost at such an end in a
  line of its own, two and more in the counted one.
  Refresh works on the instance's one origin for every account. Refresh refuses
  a session whose account is not `active` or whose device is revoked (`401 invalid_credentials`,
  as every session route answers for such a session, §0.1; the refresh token is not consumed).
  A refresh token is refused from its expiry instant on (`now >= refreshExpiresAt`:
  `401 refresh_expired`), and an expired token is refused without being consumed.
  **What a client does with a refused refresh** (design §4.4 "A session the server ends does not
  delete the device's copy"): it ends the session (tokens and the quick-unlock key are dropped) and
  keeps what the device holds, readable from the copy with the master password and adopted again at
  the next sign-in to the same account at the same origin. It does not delete the offline copy, the
  queue of changes not yet sent, or any record kept on the device. Only the person deletes those.
  A client sends a refresh token, a bearer or a logout only to an origin whose pin is in force
  (design §4.4 "No credential goes to an origin without a pin in force").
- `POST /auth/logout` revokes the device session. Logout, and the revocation that follows a reused
  refresh token, close that device's events sockets (§6: `{"type":"revoked"}`, then the close); the
  account's other devices keep theirs. Device revocation by the person: §16.7; by the operator: §7.1.
  There is no sign-out of every device: `POST /auth/logout` ends the calling device's sessions only;
  a password change (§3) and an operator's disable (§7.1) end every other session, and an enable does
  not revive them. An access token is checked against its session, device and account at every call,
  so an ended session's token is refused at the very next call. A refresh's new refresh token lives
  the policy's days from that refresh; a chain's age has no limit (shown by tests on 2026-11-19).
  **Its reach is the device row, on purpose** (decided 2026-11-16): it ends every session of the
  calling device, not only the one its token belongs to, and leaves the device known (unlike a revoke,
  it keeps the secret hash). The reasons:
  - The server records each session's refresh chain since 2026-11-18 (in a table of its own), but
    only a sign-in's name of the session it replaces reads it; the logout does not follow it, and an
    older session's access token stays valid until it expires (up to 1 h). "Only this token's session" would
    either miss those or have to follow that chain; the device row is the unit it can
    end exactly. The events sockets and their 30 s re-check are per device for the same reason.
  - Clients rely on it. The web client keeps one device row per account in a browser, and on a browser
    without the offline copy each tab holds its own pair on that row: a person's "Sign out" in one tab
    ends them all today, and a narrower logout would leave the other tabs signed in. The native apps
    and `andvari-cli` hold one session per origin, which both reaches end alike.
  - The case that asked for a narrower one (the extension's sign-in abandoned after a server switch,
    beside a session it keeps on the same device row) needs nothing: the abandoned tokens lived only
    in the worker's memory and are gone, the refresh token dies within its 30 days, and the device row
    shows as live anyway because of the kept session. The extension rightly sends no logout for it.
  A client that needs to end one session and keep its siblings (a per-tab lock) uses the narrower
  call below, not the logout.
- **`POST /auth/end-session { refreshToken }`** (index row 93, added 2026-11-16) ends exactly the one
  session the refresh token belongs to. It takes no bearer (the token proves the session; a locking tab's
  access token may already have expired) and answers `200 ok` whether the token was live, already
  ended, expired, consumed, malformed or never existed; only a body that is not `{refreshToken: string}`
  is `400 bad_request`. Its bucket is `end_session`, 30/min per IP, **drawn only for a call whose token
  names no live session** (2026-11-16): a body that is not the shape, and a token that is
  unknown, malformed or already ended. A token that names a session not yet revoked (consumed or not)
  is always served, whatever its address has spent, so nobody behind the same address, and no page in
  the same browser, can refuse a tab's lock by spending the bucket first. Each such call revokes the
  session its token names, so a token is served this way at most once. What it does, by the token's state:
  - **A live token** (not consumed, not revoked; expired or not): its session is revoked. The token
    never refreshes again (`401 session_revoked`), and **the access token minted with it is refused from
    that moment** (it lives in the same session, so the server knows it exactly). Audited `session_end`.
    Every other session of the device row, the row itself (no `signedOutAt`, the device stays known) and
    the account's other devices are untouched.
  - **A consumed token** (one a refresh already rotated away) is the reuse signal, exactly as at
    `/auth/refresh`: every session of the device row is revoked, audited `refresh_reuse`, and that
    device's events sockets get `revoked` and are closed. Revoking only the consumed session instead
    would let a thief who refreshed first disarm that signal for good: the person's next use of the
    consumed token would then read as an ended session, not as reuse.
  - **An unknown or already ended token**: nothing.
  - **The known limit: access tokens from before the last refresh.** `end-session` does not follow
    the refresh chain the server records since 2026-11-18, so an access token minted with an *earlier*, already
    consumed refresh token of the same tab is not ended by this call: it is honoured until its own
    expiry, at most the access lifetime (`sessionAccessTtlSeconds`, 1 h by default) after it was minted,
    and so at most that long after the lock. Its refresh token is already spent, so it cannot be renewed.
    A client that refreshes only when its access token has expired (the web client does) leaves no such
    token alive.
  - **Sockets.** The events sockets are per device (§6), so ending one session closes none. When it was
    the device row's last live session, the 30 s re-check closes that device's sockets; until then a
    socket carries only bells. A client closes its own socket at the lock.
  **What a client does at a lock that keeps no token** (the web tab on a browser without the offline
  copy): it first lets any refresh it has in flight finish, so the token it sends is the newest one it
  holds (sending a token that its own refresh has just consumed reads as reuse and ends every tab of
  that browser for the account); then it sends `end-session` with that refresh token, closes its events
  socket and drops the pair. The call is best effort: a failed or unanswered call leaves the session
  as it was, to expire with its tokens or to end at the next sign-out, and the client may say so. If a
  refresh answer arrives after the lock, it sends `end-session` with that answer's refresh token too.
  **A session a client refuses is ended with `end-session` too** (rule of 2026-11-17, spec 01 §7):
  when a login, a kit commit, an assisted commit or a device-link pickup was answered and the device
  then refuses what it got, it ends exactly that new session by its refresh token, never with the
  logout, which would end the session it keeps on the same device row. A kept session whose place a
  new sign-in of the same account takes on the same device is ended by the server (§2, login, "A
  device has one live session"), and the client sends nothing for it. The shared code, the browser
  and `andvari-cli` end refused sessions alone, the session of a call the person left included
  (2026-11-17).
  **A kit recovery (§12), a registration (§14.3), a device link (§16.6) or a recovery with the
  operator's help (§18.5) on a device that keeps another account** (or an account at another server,
  or its server's operator account) stops before anything is committed, at every step where the
  device can know, and a refusal after a commit hands the new kit to the person (rules of 2026-11-17;
  spec 01 §7 says where each flow asks and what the screens say). The shared code and `andvari-cli`
  keep this (2026-11-17); spec 01 §7 lists what the apps' screens do not draw yet.
  A lock on a client that keeps its pair to unlock from it (the offline copy, a native app's kept
  session) sends nothing: its session must survive the lock. A person's "Sign out" stays the logout,
  with its device-row reach.
- AuthN header: `Authorization: Bearer <accessToken>`.
- **Server-TOTP management** (authenticated): `GET /account/totp` → `{ enrolled, pendingSetup }`;
  `POST /account/totp/setup { currentAuthKey, code? }` → `{ secretBase32, otpauthUri }` (pending
  until confirmed); `POST /account/totp/confirm { code }`; `POST /account/totp/disable { code,
  currentAuthKey }` (sends the `two_step_off` email). Codes are RFC 6238 SHA-1/6-digit/30 s with a
  ±1-step window; an accepted step is single-use (replay-rejected), so a code that just confirmed
  enrollment cannot immediately re-authenticate — wait one step.
  - **The setup's `otpauthUri` names the account** its secret is for: label `andvari:<address>`,
    issuer `andvari`. **A two-step setup is shown only when it names this account** (NORMATIVE, every
    client that shows the setup; rule of 2026-11-17): before it shows the key or its code to scan, a
    client checks that the setup's label is this account's address under the product's name; a setup
    that names anything else is not shown, and the person is told that the server's answer could not
    be used. The reason: an authenticator app files a key under its label, and some replace an entry
    that has the same one, so a server that lies there could make a person overwrite another
    service's key; and a server that passes on another account's real setup shows nobody that
    account's secret. The label names no server, so the server itself is checked only as far as the
    issuer goes. The shared code keeps this: another address, another issuer, or a label it cannot
    read is the server's fault (`label_not_this_account`), and nothing of the answer is shown.
    **Not kept yet (2026-11-17):** the app interface gives that refusal no result of its own (it reads
    as a general failure), and the web client shows the setup as served, without the check.
  - **A wrong code is refused and recorded, and does nothing else that can be turned against the
    account's owner (rule of 2026-11-16).** The rules that follow for a session in the wrong hands:
    - **Setting two-step sign-in up always asks for the password** (rule of 2026-11-17), on every
      account and every session, right after a sign-in too: there is no fresh-session exemption,
      because whoever took a fresh session could otherwise add a factor of their own, and the owner
      could then not sign in. Every setup carries `currentAuthKey`, checked on the proofs' back-off
      (§8) before anything else about the request is looked at: a missing one, or a body that is not
      the route's shape, is `403 reauth_required`, and a wrong one `403 reauth_failed` (audited
      `totp_setup_reauth_fail`). An account that already has two-step sign-in must also send its
      current `code` to replace the secret, checked after the proof (`400 bad_totp_code` for a
      missing, wrong or replayed one), so a wrong or missing proof never tells whether the code was
      right. Confirm takes the code alone.
    - **Turning two-step sign-in off needs the password proof too** (rule of 2026-11-16): after
      `400 totp_not_enrolled`, the proof first, as for setup (`403 reauth_required`, `403
      reauth_failed` audited `reauth_fail`), then the code (`400 bad_totp_code`). A session alone,
      with guessed codes, cannot remove the second factor. The route says "not set up"
      (`totp_not_enrolled`) before it looks at the password: the session can read the same from
      `GET /account/totp`, so it tells the session nothing new (§0.1 names the refusals that may
      come before the password, and why). Account deletion takes the same order, the proof before
      the code (§13).
    - **A code tried on a signed-in session has a back-off of its own** (rule of 2026-11-16), per
      device (§8), with the password proofs' curve: the `code` of setup's rotation, of confirm and of
      disable, and the `totp` of an account deletion (§13). Each code is counted before it is looked
      at and a wrong one stays counted; while the back-off is in force the code is refused before it
      is looked at, with `429 rate_limited` and its device's real remaining wait, exactly as a proof
      is (§8, "The waits a refusal names"), and a code that
      verifies clears it. It refuses only the checking of codes, never a sign-in or a password proof.
      A code at sign-in or at device-link pickup counts on the sign-in back-off instead, as part of
      the sign-in. The routes' per-minute buckets stay; with the back-off one device can try at most
      109 codes a day over all these routes, where the buckets alone allowed 14,400.
    - **How the change reaches the clients.** The server's change ships together with the clients'
      side of it. In the shared code that side is additive: new calls take the code and the master
      password (the proof derived behind the password gate, the password wiped after), and the old
      calls that take the code alone stay, send nothing, and answer that the master password is
      needed; each app then moves its screens onto the new calls.
  - The server keeps every rule above, and the shared code, the web client and the Android and
    desktop apps send the proof at setup, at a rotation and at disable.

## 3. Account key material

- `GET /account/keys` → `AccountKeys = { kdfSalt, kdfParams, wrappedUvk, encryptedIdentitySeed,
  identityPub, recoveryConfirmed, personalWrap, genesis }`.
  - **What it asks of its caller** (established by the server's tests, 2026-11-19): any live session
    of the account, of any kind, the operator's and a web session's included, and nothing else:
    nothing of the device beyond its not being removed, no client header and no version check; it
    serves the token's own account only. Its limit is the read default (60 a minute per device, 240
    per account); a call writes no audit row and moves the device's `lastSeenAt` (below). An
    ended session, an ended device and a disabled account get the answer an unknown token gets. So
    **whoever holds a device's live session can fetch the account's wrapped keys with one call and
    then try master passwords without the server** (spec 05 R11); that is true of every client that
    signs in, with or without a policy, and only ending the session ends that road, for every
    further fetch at the very next call; a wrap already fetched stays open to guessing for good, and
    a password change does not close it, since it re-wraps the same account key. **The call is
    to move the device's `lastSeenAt`** (rule of 2026-11-19), so that a device that only fetches keys
    is seen as in use in the account's list of devices: every answered fetch moves the calling
    device's "last seen" to the call's time, as a sign-in and a refresh do, and records nothing else
    (no client version, no audit row); a call that is not answered moves nothing (kept since
    2026-11-19).
  - `recoveryConfirmed` is the §12 capture-confirmation flag — `false` ⇒ the client MUST run the
    vault-entry capture gate before granting vault access; `accountKeys` never carries the piece id
    itself.
  - `personalWrap: { vaultId, wrappedVk }` is the personal vault's key under the UVK (spec 01 §6,
    AD `andvari/v1|vk-personal|…`). It is set once, by the register body (§14.3), and no route replaces
    or sets it later (spec 02 §4).
  - `genesis` is the account genesis record: a `frame` of purpose 0x05 (spec 01 §5.4). The server
    MUST always send both `personalWrap` and `genesis` (registration sets both). A client that is
    served AccountKeys without a `genesis` refuses it with the identity fault, never a decode error.
    One served without a `personalWrap` (a withheld wrap) is not an identity fault: the account has
    "no personal vault" with the anomaly (spec 01 §6, spec 02 §4; the vector row
    `valid-no-wrap-served` in `accountgenesis.json`), and a wrap the device already cached still
    stands. Clients run
    spec 01 §5.4's checks on it at every unlock, and cache it with the AccountKeys for offline unlock.
- `GET /account/state` → `{ sealedState: string | null, seq }`; `PUT /account/state { sealedState,
  baseSeq }` → `{ sealedState, seq }` or `409 stale_state`. ONE opaque blob per user,
  `Envelope(UVK, JSON, "andvari/v1|account-state|{userId}")`. Its records and their merge rules are
  spec 02 §9 (`contacts`, `vaults`, `accepted`, `recovery`); a document key the client does not know is
  preserved (dropped only when the document would not fit its cap, spec 02 §9). The served `seq` is a compare-and-set counter only (`baseSeq` must equal
  it); the authenticated counter is the document's own `seq` inside the blob. Clients merge on every
  read and on a 409, and keep a local high-water mark of the in-blob `seq`: a served document below it,
  or a withheld blob after one was seen, is a rollback, merged so that nothing the local copy holds is
  lost. The server alone can withhold or roll back, never forge; any holder of the UVK can write
  (spec 05 R35). Native clients keep the high-water mark and their sealed copy in the durable device
  state. `sealedState` is capped at **1 MiB of base64** (`ACCOUNT_STATE_SEALED_MAX = 1,048,576`
  characters, about 768 KiB of plaintext) on `GET` and `PUT /account/state` and inside
  `PUT /account/recovery` (`400 bad_account_state` over it, or empty). That covers the largest account
  the limits allow (500 vault memberships, at most 1,000 contacts and 1,000 contact tombstones, spec
  02 §9) with about 30% to spare. Version-pinned, NOT audited. Vectors:
  `spec/test-vectors/accountstate.json`.
- `PUT /account/password { currentAuthKey, newAuthKey, newKdfSalt, newKdfParams, newWrappedUvk }` —
  atomic; server verifies currentAuthKey, swaps verifier + salt + params + wrappedUvk, revokes all
  sessions except the calling one (the changing device's other sessions included), cancels the account's assisted-recovery requests (§18.4), audits,
  and sends `password_changed`. Used for both password change
  and KDF upgrade (spec 01 §7). A wrong `currentAuthKey` is `403 reauth_failed` (§0.1). UVK is
  unchanged, so an escrow (§3.2) and the member-recovery blob (§12) both stay valid (spec 01 §4). The
  verify-then-write is a compare-and-swap on the credential:
  a credential replaced in between (a recovery, another device's change) answers
  `401 credential_changed`. **The notice on the open event sockets follows the revocation, session
  by session** (rule of 2026-11-17): a socket whose session was ended gets `{"type":"revoked"}` and is
  closed, whichever device it belongs to, and the changing session's own sockets stay, also one
  opened before the session's last refresh (a socket follows its session through each refresh).
- Recovery posture: §3.1. Escrow re-seal: §3.2. Per-member recovery setup/rotation
  (`PUT /recovery/self-setup`) and the two-phase kit recovery (`POST /recovery/self/verify` +
  `/commit`) live in §12.
- `GET /usage` → `{ sealedUsage: string | null, updatedAt }` and
  `PUT /usage { sealedUsage }` → `ok` — the usage ledger (spec 02 §8.2): ONE opaque AEAD blob
  per user, sealed under the VK(personal)-derived usageKey (spec 02 §2/§8.2) with AD
  `andvari/v1|usage|{userId}`, carrying the client-side
  "when did I last use this login" map behind the vault-health staleness ranking. The server
  stores and returns bytes and decrypts none of it.
  **`sealedUsage: null` means the account has never written a ledger — never "nothing is used".**
  Deliberately one aggregate blob and NOT per-item rows: per-item rows would expose the
  per-item behavioral timing (which login, how often, when) the design exists to withhold. The
  blob is capped server-side (`bad_usage_blob` on empty or oversized).
  Clients MUST batch — accumulate in memory and flush on a debounce and at lock / sign-out /
  page-hide, never one PUT per fill — so `updatedAt` cannot be read as an activity trace.
  Last-writer-wins: there is no conflict machinery, and a client SHOULD merge per item by
  `max(lastUsedAt)` against the copy it holds rather than blindly overwriting. **A client that
  could not GET the current blob, or could not open the one it got, MUST NOT PUT that round**
  (spec 02 §8.2's flush-round rule): a merge-less PUT is a first write only when the
  GET answered `sealedUsage: null`. The lock / sign-out flush is awaited (bounded) BEFORE
  `POST /auth/logout` revokes the session or the client forgets the pair — a PUT after either is
  a 401 and the window's uses are lost. This endpoint is
  deliberately NOT audited (an audit row per flush would rebuild the very activity trace batching
  avoids, and the write grants nothing).

### 3.1 Recovery posture

The person's recovery choice is recorded in UVK-sealed account state (`recovery = {posture, fp, at}`,
spec 02 §9), which is what every client acts on. The server keeps `users.recovery ∈ {private,
operator}` as a **mirror** for its own route checks; clients never decide anything from a served
posture (spec 04 §2).

`PUT /account/recovery { posture, escrow?, currentAuthKey, accountState: { sealedState, baseSeq } }`
→ `200 { sealedState, seq }`:

- `posture` is `"private"` or `"operator"`; `escrow` is `{ sealed, fingerprint }` (spec 04 §3) and is
  present exactly when `posture` is `operator`.
- `accountState` is the account-state document with the new `recovery` record, sealed by the client;
  the server cannot write it.
- **Checks, in order:** `currentAuthKey` (a wrong one is `403 reauth_failed`, audited like a failed
  password change); the posture:
  - `private` with an `escrow` → `400 escrow_not_allowed`;
  - `operator` while the newest stored card's `recoveryFp` is `none`, on a `public` instance (§18.6),
    or for the operator account itself → `400 operator_recovery_unavailable`;
  - `operator` with a missing or malformed escrow, or a `fingerprint` other than the newest card's
    `recoveryFp` → `400 bad_escrow`;
  - `operator` with an escrow whose `sealed` does not decode to exactly `455 + E` bytes, `E` the
    length of the unpadded base64url of the account's `emailNorm` (the one size of a version-3 copy,
    spec 04 §3) → `400 escrow_wrong_form`;
  
  then `accountState.baseSeq` against the stored counter (`409 stale_state`; nothing changes, and the
  client merges and retries).
- **Effect, in one transaction:** the escrow change (`private` deletes the escrow row with secure
  delete and a WAL truncate, and cancels the account's assisted-recovery requests, §18.4; `operator`
  stores the new escrow), the mirror, and `sealedState` with a new counter. It sends `recovery_changed` and writes an `account_recovery_change` audit row.

### 3.2 Escrow re-seal after a signed rotation

`PUT /escrow/self { sealed, fingerprint, rotations: [frame…] }` → `ok`. A session, no password: it
exists only to re-seal after a **rotation statement signed offline by the outgoing recovery seed**
(spec 04 §5). Any other change of the escrow goes through `PUT /account/recovery`.

- `rotations` are frames of purpose 0x08 (spec 01 §5.1, spec 04 §5), oldest first: the chain from
  the fingerprint of the account's current escrow to `fingerprint`. At most **64**; a longer list gets
  the same answer as a chain that does not link (below).
- **Checks, in order:** the account's posture mirror is `operator` (`400 escrow_not_allowed`); the
  escrow blob's shape (`400 bad_escrow`), then its size for the account's address as in §3.1
  (`400 escrow_wrong_form`); then each rotation, in order, must verify: purpose 0x08, its
  `instanceId` the instance's, its `fromFp` equal to the current escrow's fingerprint (for the first)
  or to the previous rotation's `toFp`, and its signer the recovery key `fromFp` names
  (`ed25519_pk_to_curve25519(signerPub)` hashes to `fromFp`); and the last `toFp` must equal
  `fingerprint`. Any failure, an empty list, or more than 64 rotations is `409 escrow_not_due`.
- **Effect:** the new blob replaces the stored one (no copy of the old blob is retained). Audited
  `escrow_self_reseal`.

## 4. Sync — pull

`GET /sync?since=<rev>` (since=0 → full) →

```jsonc
{
  "rev": 1042,                       // current global max
  "full": false,                     // true when the response is a full snapshot
  "vaults":  [ Vault… ],             // changed vaults: {vaultId, type, rev, metaBlob, createdAt, logHead?}
  "grants":  [ Grant… ],             // caller's grants only: {vaultId, userId, role, wrappedVk, rev, signedGrant?}
  "items":   [ Item… ],              // changed items in granted vaults (incl. tombstones)
  "removedGrants": [ vaultId… ],     // caller lost access → client acts per spec 02 §10.6
  "removedGrantsInfo": [ RemovedGrantInfo… ],  // companion detail, never the trigger
  "linkAnswers": 0,                  // count of answered, unacknowledged links the caller created (§15.6)
  "recoveryRequests": 0,             // count of live assisted-recovery requests on the account (§18.3)
  "accountStateSeq": 7,              // the account state's seq (§3) in the same snapshot
  "quota": {                         // the caller's OWN use and limits (§14.4), on every answer, full or delta
    "accountBytes":      {"used": 1834, "limit": 104857600},
    "items":             {"used": 12,   "limit": 5000},
    "ownedSharedVaults": {"used": 1,    "limit": 50},
    "openLinks":         {"used": 0,    "limit": 20}
  }
}
```

- **Item rows** are `{ itemId, vaultId, rev, createdAt, updatedAt, deleted, conflict, formatVersion,
  attachmentIds, blob }`, with `blob` null on a tombstone (spec 02 §1).
- **`logHead: {seq, hash}`** rides every shared vault row (§10.6): the head of its log as the server
  stores it. A device whose verified head differs fetches the log (spec 02 §10.5). Personal vaults
  have no log and no `logHead`.
- **Grants.** An owner grant carries `wrappedVk` (the owner wrap under the UVK, genesis-bound AD for
  a shared vault, spec 01 §6). A member grant carries `signedGrant` (the sealed 0x01 grant of the
  `add` that admitted it, §10.3) and `wrappedVk` empty until the member posts a self-wrap (§11.4),
  after which it carries both. There is no other key material on a grant row.
- **`linkAnswers`** and **`recoveryRequests`** are hints that tell a device to call
  `GET /links/answers` (§15.6) or `GET /account/recovery-requests` (§18.3). Each is `0` when there is
  nothing; `recoveryRequests` is always `0` on a public instance (§18.6).
- **`quota`** (added 2026-11-16, additive) is the caller's own meters: for each quota name of §14.4, `{used,
  limit}`, two whole numbers, read in the same snapshot as the rest of the answer. It is the account's and nobody
  else's; it says nothing about the room in a shared vault someone else owns. What `used` counts, where it cannot
  predict a refusal exactly, and the check a client makes before a large copy: §14.4, "What an account is told".
  A client that does not know the key ignores it, as it must every unknown field.
- **`accountStateSeq`** (added 2026-11-16, additive), on every answer, full or delta: the account
  state's `seq` (§3), read in the same snapshot, 0 before the first write. Each write of the account
  state advances it by one and nothing lowers it, so a device holding the state at a lower `seq`
  knows that another device of the account wrote it, without a `GET /account/state`. It is the
  served compare-and-set counter of §3, not the authenticated counter inside the blob. The shared
  code's sync answer takes it (absent, or anything but a whole number, is "not served"), and its
  vault-log engine, once told the counter, reads the account state only when the counter differs from
  the one this device last saw in a read or write of its own; a counter that goes back or jumps is
  read, never skipped. The shared code's sync passes the counter on to that engine before the round's
  first read of the logs, and an answer without it is passed on as "not served", which reads as
  before. A server that lies about the counter can only delay what a device learns of another
  device's change, as withholding the blob already could (spec 05 R14): the blob is sealed under the
  account's key, so the counter can make a device read less often or more often, never accept a
  record it did not open. **Not kept yet (2026-11-17):** the web client does not read the field, and
  reads the account state as before.

- Ordering: one **global monotonic rev** from the server's `changes` sequence; every
  create/update/delete of any object bumps it. Responses are consistent snapshots
  (single read transaction).
- **New-member / grant-change backfill:** a vault and its items are delivered when the
  object's rev **or the caller's grant rev on that vault** exceeds `since`. So a member
  added at a high rev whose cursor is already past the vault's/items' own revs still
  receives the vault row and all pre-existing items; a role change (which bumps the grant
  rev) likewise re-delivers that vault's items (idempotent client-side upsert). Without
  this, a new grant would sync as "exists" but be unusable.
- `removedGrants` client duty: stop using the VK for writes, and handle the local copy as spec 02
  §10.6 says: it moves to the 30-day holding area when the vault's log verifies the departure, or stays
  read-only when the loss of access is not verified. A server cannot make a device drop its offline
  copy by revoking a grant, and the same holds for edits not yet sent: queued mutations for that vault
  are **held back, not discarded**. They are dropped only when the log verifies that this account
  left or was removed (the push would be `denied` regardless), and replayed if the vault comes back.
  The 30 days count from when this device saw the departure, never from a time the server names.
- **`removedGrantsInfo`** is the companion detail for `removedGrants`: `{vaultId, reason:
  'removed'|'left'|'deleted', deletedAt?, purgeAt?}`. `reason` derives from the caller's OWN grant's
  revocation reason (a member removed *before* a later vault delete sees `removed`, not `deleted`);
  `deletedAt` and `purgeAt` ride `deleted` rows. It is a hint: what a device believes about the
  removal comes only from the vault's verified log (a `remove`, `leave` or `delete` entry, spec 02
  §10), never from this row. Notices fire ONLY for vaults present locally before the pull (no ghost
  banners on fresh devices / `since=0`). In the web client today (`web/src/vault/store.ts`) this
  also means that a pull with `since=0` and the resync after a `410` drop every shared vault the
  answer no longer grants, frozen or not, with no notice and no held copy; at the resync this
  happens also where the browser holds its offline copy of that vault at that moment (whether a pull
  with `since=0` can meet a vault the browser holds offline is not established): an honest server answers `410` to a browser
  closed longer than its history reaches, and a server that misbehaves can answer so whenever it
  likes, and so make any removal silent. **Decided, not built yet (2026-11-21, before the first
  public release):** before a resync wipes anything, the browser takes what it holds of every
  shared vault, and for each one the fresh list no longer grants it takes the ordinary road (the
  held copy from what it held, then the notice). Open: what the first full sync after a sign-in or
  a reload with no offline copy says (it holds nothing to keep), and the same question for the
  shared code's full pull on the phone and the desktop. A denied-mutation failure MUST NOT abort the pull that
  delivers `removedGrants`; denied mutations for in-grace vaults SHOULD be parked and replayed on
  restore. Clients MUST ignore unknown response fields.
- **Item history (feature: item history & restore):** `GET /items/{id}/versions` →
  `{ itemId, versions: [{ rev, blob, formatVersion, archivedAt }] }`, newest rev first — the
  archived ciphertext versions the server already keeps (spec 02 §7, last 10). Grant-checked
  against the item's own vault (unknown item and non-member both `403`-hidden, §8 — no
  existence oracle); serves a tombstoned item's versions too (the item row persists). The
  client decrypts each `blob` under the VK it holds (AD binds itemId+formatVersion, not rev)
  and restores a chosen version as an ordinary put over the live item. Additive: no schema
  bump, no formatVersion bump, no new server knowledge.
- **Durable cursor rule (spec 02 §8):** vaults/grants/items/removedGrants are all deltas
  over the same global rev, so a client that persists its cursor MUST also persist the
  grant rows, vault rows, and item envelopes it has applied (grant/vault rows never
  re-send once the cursor passes them) — otherwise it MUST discard the cursor and pull
  from 0. The offline queue survives a `410` resync and replays on top of the fresh
  snapshot; the resync MUST be transactional (the durable cache is replaced only once the
  full snapshot is in hand, never left empty by a failed re-pull).
- **Rev-regression rule (spec 05 T1):** a client MUST NOT apply a non-full response whose
  `rev` is below its cursor, nor an unsolicited `full` snapshot when it pulled with
  `since>0`; it surfaces a server-rollback warning and keeps local state (never deletes or
  overwrites local newer state). `rev` is not in item AD (spec 02 §2), so this is the
  client's defense against a server replaying old-but-AD-valid envelopes.
- `410 Gone` when `since` predates retained history (tombstone GC, spec 02 §7) →
  client discards cursor and re-pulls with `since=0`, then reconciles its offline
  queue on top.

## 5. Sync — push

`POST /sync/push`:

```jsonc
{ "mutations": [ {
    "mutationId": "uuid",            // client-generated, idempotency key
    "op": "put" | "delete",
    "itemId": "uuid", "vaultId": "uuid",
    "baseItemRev": 17,               // 0 = creating
    "item": { formatVersion, attachmentIds, blob }   // op=put only
} ] }
```

→ `200 { "rev": <newGlobalMax>, "results": [ { "mutationId", "status", "newItemRev",
"serverItem"?, "reason"?, "serverItemOmitted"? } ] }` with per-mutation status (`reason` on `rejected` only):

- `applied` — clean write (`baseItemRev` matched server state).
- `conflict` — divergence handled server-side, **write never rejected-and-dropped**:
  - put over newer put: applied; previous version archived to item_versions;
    `conflict=true`; `serverItem` = the displaced version (so the pusher can
    materialize the conflict copy immediately).
  - put over tombstone: item restored (edit beats delete), whatever the put's `baseItemRev`; the
    answer is `conflict` with `serverItem` = the tombstone as it stood (`deleted: true`,
    `blob: null`), also on a replay of the same `mutationId` and never left out for the answer's
    cap, so a client can tell the person that its change brought back an item deleted elsewhere.
    The tombstone is not archived, and the restored row is stored with `conflict=false`: a deletion
    leaves no version to copy, so no client makes a "(conflict)" copy of the item that came back
    (since 2026-11-18; a replay of a put journaled before then may carry no `serverItem`).
  - delete over newer edit: delete NOT applied (edit beats delete); `serverItem` =
    current; client drops its local tombstone.
  - delete over tombstone: `applied` (idempotent).
- Idempotent replay — when a `mutationId` has been seen before for this device
  (dedup window: the device's newest 1,000 journaled mutations, each kept at most 180 days), the server returns the ORIGINAL
  outcome (same `status`, same `newItemRev`) with no re-execution. A
  crash-retry therefore observes the identical outcome it would have on first
  success — the client's state converges the same way. (There is no distinct
  `duplicate` status code; the replayed status is whatever the original was.)
  **The journal holds no vault content (spec 02 §5):** a journal row keeps the
  status, the revs and the reason (and the ids the mutation named), never an item. A replayed
  `conflict` reads its stored item at answer time: for a `delete`, the item as it is now; for a
  `put`, the displaced version from the item's history (§4), absent once that version has left
  the history. For a put that displaced a tombstone, the row also keeps that tombstone (ids,
  revs, times, format version; a tombstone has no blob). No journal row is written for a mutation on an item that never existed (a
  `delete` of an unknown item is `applied` and answered afresh on a replay). Nothing in the
  journal outlives an item's purge or a vault's purge as ciphertext.
- **Stored items in one answer:** an answer carries each stored item (an
  `itemId` at one `rev`) at most once, and the stored items it carries total at most the push
  request's own body cap (8 MiB). A result that would carry an item past either limit carries
  none and says `"serverItemOmitted": true`; the client pulls for the item (§4).
- `denied` — role violation (reader pushing to a shared vault), no grant, or an fv
  downgrade (`item.formatVersion` below the stored row's — the monotonic-fv guard; no
  fielded client legitimately downgrades, an invariant future clients MUST preserve;
  the same check 400s `fv_downgrade` on `POST /items/{id}/restore`); nothing written;
  audited.
- `rejected` (audit 2026-09-13 H03) — a `put` the server can never apply AS
  SENT, answered per mutation with a `reason`: `unknown_attachment` (an `attachmentIds`
  entry names no stored attachment — or, since server scan 2026-10-26 F10, one that exists
  in ANOTHER vault, so the reason never confirms a foreign vault's holdings),
  `attachment_mismatch` (it exists in this vault but is bound to a different item — §9), `item_attachment_quota` (the referenced total exceeds
  `itemAttachmentsMaxBytes`), `item_too_large` (the blob exceeds the operator's per-item
  cap, `ANDVARI_ITEM_MAX_BYTES`, default 2 MiB of stored base64url), or
  `quota_exceeded` (the put would take the **vault owner's** account past its storage quota
  or its item quota, §14.4 — writers to a shared vault use the owner's quota; a put that shrinks
  or keeps an item's size, and every delete, is never refused), or
  `bad_mutation_id` (server scan 2026-10-26 F2 — a `mutationId` that is empty or longer than
  64 characters; every client mints a 36-character UUID, and the server stores the id twice
  per applied mutation for 180 days outside every quota, so an unbounded one was free storage
  growth. Checked before the idempotency lookup, never cached, and the echoed `mutationId` is
  truncated to 64 characters rather than reflected), `too_many_attachments` /
  `duplicate_attachment` / `bad_attachment_id` (server scan 2026-10-26 F1 — the
  `attachmentIds` LIST is bounded before its members are resolved: at most 256 entries, no
  repeats, each a canonical lowercase UUID; the reference check dedups before it looks ids
  up and the item quota counts only the blob, so one real id repeated two hundred thousand
  times used to pass and persist an 8 MiB list that every co-member's next full pull then
  materialised. The same three are thrown as `400` on `POST /items/{id}/restore`), or
  `bad_item_id` (2026-10, security review — a `put` OR `delete` whose `itemId` or `vaultId`
  is not a canonical lowercase UUID: an itemId is handed to every other member of the vault
  by `/items/deleted` and `/sync` and becomes a path segment of THEIR authenticated
  `/items/{id}/…` requests, so a planted `../admin/…` must never be stored. Clients also
  refuse any non-id path segment before sending, spec 02 §3.2; and since security review
  2026-10 plugin scan F1 (A10) every client checks every SERVED id — vaultId, userId, itemId,
  deviceId, a log entry's user ids — against the same canonical lowercase UUID grammar at
  decode, dropping any row that fails with a `bad-id` anomaly and refusing a session or
  identity row that fails, so a hostile server cannot smuggle a record delimiter or a second
  id inside one; spec 05 R18). Nothing written; the rest of the batch proceeds; NOT
  audited (a writer's stale reference is not an intrusion event); NEVER dedup-cached (a
  replay of the same `mutationId` is re-evaluated against the live attachment rows, so a
  client that re-uploads the file and re-sends the identical put lands). `serverItem`
  carries the server's current row when one exists (within the answer's limits below) — a tombstone when a peer deleted the
  item and its attachment rows with it — as information for the client's reconcile.
  **Client duty:** a `rejected` row is a POISON row — drop it durably, tell the user
  (the "write-rejected" notice; the editor error for a direct save), and continue the
  drain and the pull. It MUST NOT stay queued. Before this status these three refusals
  were thrown batch-wide (400/413) and no fielded client dequeued on a thrown push, so
  one dangling ref — produced by a peer deleting the item under an offline edit, by the
  24 h orphan sweep under a long-queued new item, or by a history restore over a
  since-removed file — stopped the device syncing until a sign-out that discarded every
  other queued edit. A pre-H03 client treats any status it does not know as
  "definitive — dequeue", which is why this is a status and not a new error code.

`POST /sync/push` is rate-limited per device (`ANDVARI_PUSH_RATE_PER_MIN`, default 120, with the ceiling per account of §0.1);
a `429 rate_limited` is transient — the rows stay queued. `POST /items/{id}/restore`
applies the same item cap and quota as a thrown `413 item_too_large` / `413 quota_exceeded {quota}`.

Batch limit 200 mutations; server applies the batch in order inside ONE transaction:
a thrown validation failure (a malformed request — `put_without_item`, `bad_op`,
`batch_too_large`; the 8 MiB body cap's `413 body_too_large`, fired before the handler)
rolls back the WHOLE batch, while per-mutation `denied` and `rejected` results are
recorded without aborting the rest. Clients maintain a durable outbound queue and MUST
retry with the SAME mutationIds after connectivity loss — but a thrown 400 or 413 is a
DEFINITIVE refusal of that batch, never a transport blip: a client MUST NOT re-send it
identically forever. The shipped drains bisect such a batch (re-sending halves is safe:
a refused batch applied nothing and the dedup window makes re-sends idempotent) until
the refusal isolates to single rows, which are dropped durably with the same
"write-rejected" notice; and they bound each batch by approximate encoded size (6 MiB,
below the cap) as well as by count, so only a lone row that is itself over the cap can
ever draw the 413 (H19).

**What a device keeps to send, and what it refuses (NORMATIVE, every client; rule of 2026-11-17,
which writes down what the shared code and the current app already do).** The durable outbound queue
above is the queue of a copy kept **at rest**. By where the copy is kept:
- **A copy kept at rest** (Android by default; the desktop with "keep me signed in"; the browser with
  the offline copy on; each where the server's policy allows an offline copy, §1.1) keeps a change
  that got no answer (a new item, an edit, a deletion), to send it later, and counts it among the
  changes not sent. A save the server refused for now (the session has ended, too many requests, a fault of
  the server) stays kept the same way and is sent at the next sign-in or when the server answers
  again; it is said as that, kept on this device and sent later, never as "failed".
- **A save with files that is kept to be finished later** (rules of 2026-11-17, every copy): its
  record and its set-aside files stay until the item itself has landed at the server, on every
  road, also where the session ended meanwhile; an answer that the session is not valid (`401`)
  never lets it go, and the account's next session finishes it. "Landed" is judged by the item as
  the server holds it, never by what waits in the queue: nothing of the item waits, and the server
  holds it at a revision newer than the one it held when the change was handed to the queue.
  Before a waiting change is sent whose files the server may have removed (it keeps an upload
  without its item for a day), the files are uploaded again from the set-aside copy, unless this
  unlock sent them within the last half day. Only an answer that says the change itself can never
  be taken gives it up, and the line then says that it is let go for good and names what was
  lost; the person's own deletion of the item lets it go with its files, so that it never brings
  the item back. A set-aside file that is no longer on the device is said as that. A save kept
  while its vault is closed for writing for now stays kept too.
- **A copy kept only in memory** keeps nothing it cannot send now: a save that gets no answer, or
  any other refusal, is refused, nothing stays queued behind it, and the editor still holds what was
  typed. A queue in memory never claims to keep something. An earlier change of the same item that
  was still waiting, and that the refused change had folded into itself (the coalescing below), is
  put back where it was, never dropped without a word. An import cut short on such a copy follows the
  same rule: nothing stays queued behind a line that says it failed; the line says how many items
  were saved and how many were not, and the ones that were not are not sent later.
- **What the count of changes not sent counts** (design §4.4): what a copy at rest keeps to send, the
  changes the server refused that are still kept, the vaults held on the device, and a save with
  files that is kept to finish. So the number can be above zero wherever the copy is at rest; where
  it is only in memory, the queue itself never adds to it.

**What the shared code keeps (2026-11-17):** on a copy in memory, a save refused for any reason (no
answer, an ended session, `429`, a `5xx`) leaves nothing queued, and an earlier waiting change of the
same item that it had folded is put back; the shared content counts the saves with files that are
kept to finish, and the app interface's count before a sign-out adds them; an import cut short on a
copy in memory keeps nothing queued behind a line that says it stopped (how many items were saved
and how many not; a retry sends the rest under the same ids), and on a copy at rest what could not
be sent is kept, counted and sent later; a save kept on the device is never said as failed, with a
line of its own for a session that ended, for too many requests and for a fault of the server. **An
import kept to be sent later is not drawn as a failure** (rule of 2026-11-17): the import's view
says that it was kept (`CsvImportView.kept`, since 2026-11-18), and the apps draw its line in the
plain colour. **An import that is done says so truly** (rule of 2026-11-17): where the list cannot
show its items before the next sync, the line says that they appear then and that the same file is
not to be imported again before then, since it would be added twice; the shared content keeps this
since 2026-11-18. **What the shared content keeps for a kept save (2026-11-18):** the rule above:
the record carries the server's revision of the item when its change was handed to the queue, stays
until the item has landed by the server's own row, and its files are sent again before a drain as
above. **A kept save whose queued change the server refuses for good is given up once and said**
(rule of 2026-11-18): after a sync, a kept save whose item's change the server rejected or denied
for good, with nothing of it still waiting and nothing landed, is forgotten with its files, and its
line says once that it was not saved and why; it is never sent again. A refusal for now (`401`,
`408`, `429`, a `5xx`, no answer) leaves the change queued, as above; a refusal for a file the
server does not know (`unknown_attachment`) is not given up, since the files are still on the
device and finishing afresh gets past it. The shared content keeps this since 2026-11-18.
A refusal for good leaves the content's list only once every queued kept save of its item was
judged by it (given up, landed, not given up, or refused as a file the server does not know); it
stays while one is skipped because its editor is open or a change of its item waits, and every
refusal stays while the kept records cannot be read. So where a second kept save of the same item
waited at that sync, the first is still given up and said when the second is judged (kept in the
shared content since 2026-11-19; before it, the refusal went at the next sync and the first save
was later let go without a word, read as landed because the item's revision had moved past it).
**Accepted** (2026-11-19, on the safe side): a refusal kept for an item judges every queued kept
save of that item that neither waits nor landed with its files, so a later save whose change landed
and from which an edit took its own file off before the next sync is said as given up by the
earlier refusal instead of going without a word. **The refusal survives a lock and a restart**
(rule of 2026-11-19) until every kept save of its item was judged: kept in the shared content since
2026-11-19, the refusal is kept at rest with the save until it was said, so a lock or a restart
between the refusal and the later save's landing no longer lets the first save go without a word.
The apps do not yet draw the import's kept line in the plain colour.
**A write the server applied answers as applied** (rule of 2026-11-19), always: it is never said as
failed because other changes were refused at the same push (spec 05: a save the server stored is
never said as not made). Those other changes are undone on the device as before, and each is said at
that same moment by the notice a sync's refusals get (which item, that the server refused the change
and it was undone here, and why; a line of its own for one), never only through this write's answer
and never not at all. Where the write's own change is among the refused, the write answers as
refused. Kept in the shared content since 2026-11-19: a save or a deletion that the server applied
is said as applied, and another change the server refused at the same read is undone and said in a
notice of its own that names the item. **The older notice for a change the server rejected is to
name the item too** (rule of 2026-11-19: a person told that something was undone is told what),
wherever the device can read its name. **Not kept yet (2026-11-19):** it does not, and its four lines
stay as they are until their new words are approved. A write
stuck longer than one request's limit still meets a closed content when a policy's removal begins
(left for later).

**Queue coalescing (client duty, audit 2026-09-13 H37):** `baseItemRev` is compared
against a **globally** monotonic rev (§4 — every write by any member advances it), so a
queue holding two or more `put`s for the SAME item can never have them all apply
cleanly: the first lands at a fresh global rev and every later one is stale by
construction, drawing a `conflict` whose displaced version is the pusher's own earlier
draft. A client MUST therefore, when enqueueing a `put` for an item that already has an
UNSENT `put` queued, drop the older row(s) and send the newest doc **with the OLDEST
dropped row's `baseItemRev`** under a **fresh `mutationId`**. Three parts, each load-bearing:
the oldest base rev (a fresher one — the client's optimistic counter, or a rev a PEER's
delivered edit installed — would let the write apply "cleanly" over a change nobody
copied); the fresh mutationId (replaying a dropped row's id lets the dedup window return
that row's stored result verbatim, reporting `applied` for content never sent); and
`put`-only, never across a queued `delete` for the same item, whose ordering the drain
must keep as written. Rows the server already denied (staged for §11 replay) are not
coalescable. The unavoidable residue is the lost-response window — a row that landed but
whose result was never seen is re-sent at the old base and draws exactly the conflict
copy this rule removes elsewhere; that is a degradation, never a loss.

**Conflict-copy materialization (client duty):** on seeing `conflict=true` with a
decryptable displaced version, create a new item `{name: "<name> (conflict
YYYY-MM-DD)"}` carrying the losing content, then push it plus a flag-clearing rewrite of
the winner (both normal `put`s). The copy's itemId is derived **deterministically** from
`(itemId, conflictedRev)` — specifically a UUIDv4-shaped id from the first 16 bytes of
`sha256("conflict|" + itemId + "|" + conflictedRev)` with the version/variant nibbles
forced (vector-pinned, `spec/test-vectors/conflictcopy.json`) — so that if several members
materialize the same conflict concurrently they converge on one copy id (the server's idempotent existing-item path
absorbs the duplicates) rather than each creating their own. A **`reader`-role** member
MUST NOT materialize (its push would be `denied`); the flag waits for a writer/owner.

### 5.1 Item trash: list, restore, purge

- `GET /items/deleted` → `{ items: [{ itemId, vaultId, deletedAt }] }`: the tombstoned items in
  every vault the caller holds an active grant on. A tombstone's blob is null; the client fetches an
  item's versions (§4) for its name and preview.
  **Paged (2026-11-16).** Rows come newest first, in `(deletedAt, itemId)` descending order, at most
  **65,536** to an answer. `?after=<deletedAt>:<itemId>` (the decimal `deletedAt` and the `itemId` of the
  last row of the previous answer) starts the next page after that row; an `after` of any other form is
  `400 bad_request`. The cursor names a position, not a row, so it stays valid when that item has been
  restored or purged in between. An answer of fewer than 65,536 rows is the last page. A row is at most
  125 bytes (two `uuid`s and a 13-digit time), so a page is at most 8,192,012 bytes, inside the client's
  8 MiB (§0.4); without `after` the answer is the first page, which is the whole trash for anyone with up
  to 65,536 tombstones.
  Why paging, and not a bound on the tombstones kept: deletions count against no quota, so the server
  cannot bound their number without dropping some, and the trash matters most exactly when a great many
  items were deleted at once (a mistaken bulk delete, a misbehaving or stolen device). Dropping the
  oldest would make those items unrestorable, and a device with write access could empty another
  member's trash just by deleting more. Tombstones also carry the deletion to every device's delta sync
  for their 30 days (§4), which a bound would cut short.
  **What a client does:** it asks for the first page and, while an answer holds 65,536 rows, asks again
  with `after` built from that answer's last row, joining the pages; an item seen twice (restored and
  deleted again while it paged) is shown once, with its newest `deletedAt`. It may show the first page
  while the rest arrive, since the order is newest first, but it says the list is still loading until
  the last page has come. A `400 bad_request` fails the read.
  **What a client refuses (NORMATIVE).** The list is the server's word, and a server that loops or
  pads it must not keep a client reading or show it rows twice. Any of the following fails the whole
  read, so no row of it is shown, restored or purged:
  - a page of more than 65,536 rows;
  - rows that are not strictly descending in `(deletedAt, itemId)` (a repeated row, a row out of
    order, or at the same `deletedAt` an `itemId` not below the previous one, `itemId`s compared as
    the text served);
  - a page after the first whose first row is not strictly after the cursor's row in that order (a
    page that starts at the cursor's own row, above it, or at its `deletedAt` with a higher `itemId`);
  - a cursor that cannot be built from the last row as a non-negative integer `deletedAt` and a
    `uuid` `itemId`;
  - more pages than the client's own stated cap (16 pages in the app engine);
  - a refused or unanswered page.
  A row whose `itemId` or `vaultId` is not a `uuid`, and a row of a vault this account may not read
  (another account's row, or a vault shared a moment ago that the device has not adopted yet), is
  left out, not a failure: it is never shown, restored or purged, and the order checks above still
  count it.
- `POST /items/{itemId}/restore { formatVersion, attachmentIds, blob }` → `{ rev }`. Un-tombstones the
  item with a re-encrypted version the client chose (a dedicated path, not a put, so no conflict copy
  is spawned). Writer or owner only; an unknown item or one in a vault the caller cannot write is
  `403 no_grant` (hidden-as-403, §8); a live item is `400 item_not_deleted`. The blob and attachment
  list get push's checks, thrown (§5, §9); the item cap and the owner's quota answer
  `413 item_too_large` / `413 quota_exceeded {quota}`. Version-pinned. Bucket `item_recovery`,
  400 per hour.
- `POST /items/{itemId}/purge` → `{ rev }` ("Delete forever"). Hard-deletes a tombstoned item and its
  archived versions, leaving no tombstone. Writer or owner only (`403 no_grant`); a live item is
  `400 item_not_deleted`. Not version-pinned (it writes no ciphertext). Bucket `item_destructive`,
  200 per hour.
- **A restore or a "delete for good" that did not hold** (rule of 2026-11-17). A device that restored
  an item, or deleted one for good, and at a later whole read of the trash finds it there again, says
  what is so, and names the server only when it can tell the server is at fault: when the trash lists
  the very deletion the device acted on (the same `deletedAt`) and, for a restore, the device was never
  served the item live after its restore. Otherwise the item was deleted again after this device's
  change, on another device or by another member, and the notice says that the item is in the trash
  again and accuses nobody. The shared code keeps this: its record of what it did holds ids, the kind
  of action, the server's time and whether the item was served live, and no name, so after a lock the
  notice names "an item".

## 6. Events (WS)

`GET /api/v1/events` upgrades to WebSocket. **Auth:** browser clients first call
`POST /api/v1/events/ticket` (Bearer-authenticated) → `{ ticket, expiresInSeconds }`,
then connect as `GET /api/v1/events?ticket=…`. Tickets are 256-bit random, held
server-side as sha256 hashes **in memory only**, TTL 30 s, strictly single-use (a
restart drops pending tickets; clients re-mint). `Authorization: Bearer` on the
upgrade request remains valid for non-browser callers. **Raw access tokens in the
query are NOT accepted** — long-lived bearers must never ride URLs into edge logs.
A ticket authenticates the account at mint time; if the session is revoked within the
ticket's ≤30 s TTL, the already-minted ticket may still open the bell for that window
(accepted: the socket carries only rev/revoked signalling, never vault data, and
the session's access token is rejected on its next `/sync`).
Server → client JSON frames, **exhaustively**: `{"type":"rev","rev":N}` (something changed —
pull if N > local; also rung to every socket when the instance card chain changes, **The card bell**
below) and `{"type":"revoked"}` (session killed — drop to lock screen).
Nothing else rides the socket except the bare-text `pong` echo under **Liveness** below
(a keepalive/registration proof, never a signal); it is a dirty-bell, not a data plane. Earlier versions of
this section also listed `{"type":"policy"}`; no server has ever emitted it and the one
client handler that existed for it was deleted as dead code, so it is struck rather than
reserved (audit H111). A policy change reaches clients through the ordinary
`/client-policy` poll and the `rev` bell; if a dedicated frame is ever wanted it is a new
design (backlog F54), not a promise this document already made.
**The card bell.** When the server starts serving another chain at `GET /instance` (it stored a card,
§17.2, or a rotation statement, §17.3; a refused or byte-identical one changes nothing and rings
nothing), the same transaction takes a fresh global rev, and after the commit **every** open socket of
**every** account gets the ordinary `{"type":"rev","rev":N}` with that N. Nothing else is in it: no
account, no card, no hash, no kind of change. Because N is above every rev any client has seen, a client
that pulls only when N is above its own pulls too. A client treats it only as a hint to look again: it
pulls `/sync` as for any bell, and that pull's card check (the chain fetched when its ETag changed and
verified forward from the pin, design §4.4) is the only thing that tells it whether a card changed and
what the change was. So a client that must not hold the operator account (web, extension, phone, design
§12.2 rule 7) stops using an account a handover just made the operator within a bell's latency, instead
of at its next own refresh (the web and the extension sign it out; a phone keeps its copy locked until
the person removes it, design §9.1); a move, a rename, a `kind` change or a new recovery key is likewise judged at
once. **A lying server gains nothing from the bell:** it can only make a client fetch and verify, sooner,
a chain the client would fetch and verify anyway, and withholding it leaves the client exactly where it
was without it, refreshing at its next sync. The bell is rung only by the serving process; a reset by
`andvari admin reset-instance-identity` from another process rings nothing (the empty chain it leaves
is withheld for a pinned client, §17.1), and the new card 0 rings when it is stored. Card changes are
rare operator acts on a † bucket, so the pull every connected client then makes is a rare burst.
**Frame cap:** the server accepts client frames of at most **4 KiB** (the only meaningful one
is the 4-byte `ping`); a frame header declaring more is refused from the header alone and the
socket is closed `1009` (too big). The upgrade request itself is under the 256 KiB body cap.
**Socket cap:** one device holds at most **8** event sockets; registering a ninth
closes that device's oldest socket (`1008`, reason `too_many_sockets`). A bearer upgrade draws
on the bucket `ws_bearer` (60/min, per device, §0.1); over it the socket is closed `1013` (try again
later) before it is registered. A ticket upgrade draws on no bucket of its own (`ws_ticket`
bounds minting).
**Session re-check:** an open socket re-checks every 30 s that its device still
has a live session on an active account; when it has not, the server sends `{"type":"revoked"}`
and closes the socket. This reaches a revoke made outside the server's process (`andvari admin
disable`, §7.4), which the immediate bell cannot.
**Liveness:** browser clients reconnect a dropped bell with exponential backoff (1 s
doubling to a 60 s cap, jittered), minting a fresh single-use ticket per attempt, and
pull `/sync` on every (re)open to recover bells missed while down (the notifier has no
replay). The backoff ladder resets only on a **registered** socket — the first `pong`
below, not the 101 (security review 2026-10, A17): a socket that upgrades and dies
before the server answered is a failed attempt, so a client whose sockets keep dying
within a second climbs to the 60 s cap instead of re-minting a ticket every second and
running into the `POST /events/ticket` bucket (`ws_ticket`, 60/min, per device, §0.1). The explicit
resets — tab-visible in the web client, unlock and the 5-min alarm in the extension —
still zero the ladder and dial at once; each is bounded by its trigger, not by the network. The app
engine's bell (core `EventBell`, which the Android app dials through its own socket and the desktop
app through the engine's WebSocket client) climbs the same
ladder, but starts it over only when a registered socket ended after it stayed registered for 30 s; one
that ends sooner is a failed attempt (2026-11-16). Its explicit resets are an unlock, the
return to the foreground and the network coming back. **A text frame `ping` from the client is echoed as the text frame `pong`** — an
app-level keepalive (the extension's service worker needs JS-visible traffic) that is
also the **registration proof**: the server registers a socket with its notifier only
when the route body runs, after the 101, so a change committed in that window rings
no bell for that socket. The echo loop starts after registration, so a client that
treats the FIRST `pong` — not the 101 — as "open" and pulls then, as the web client
does, closes the window rather than narrowing it (`pong` is the one non-JSON frame
the server sends; JSON-frame clients ignore it). A tab becoming visible with a dead
socket reconnects immediately, and a
401/403 at ticket mint (dead session) stops reconnection and drops to the lock screen.
**What each client does to hear of changes (2026-11-16).** The Android and desktop apps both run
on the app engine and hold the engine's bell (above): Android through its own socket, the desktop
through the engine's own WebSocket client. Neither has a timed poll of `/sync`. The engine pulls
`/sync` at each opening of the vault, at each registered (re)open of the bell, at each ring above
the highest rev it was answered at, and after a change of its own to a vault's log (§10); it reads `/client-policy`
again at every opening of the vault. On the return to the foreground (Android) or to window focus
(the desktop) the bell's ladder goes to zero and a waiting bell dials at once, and Android does the
same when the network comes back. The web client holds its own bell (above) and, while the socket
is down or a pull the bell asked for failed, polls `/sync` over plain HTTP: first about 5 s after
the socket drops (10 s after a failed pull), then every 60 s, until both are healthy again. Server
pings every 30 s. Whatever front an instance runs MUST pass WebSocket upgrades through to the app. A
front that strips them leaves the web client on its 60 s poll (correct, just slower), and leaves
the Android and desktop apps without any way to hear of another device's change while the vault is
open: they see it at their next opening of the vault, or at a pull one of their own log changes
makes.


## 7. Operator

Each instance has exactly one operator account (`users.role = 'operator'`, unique). It is created by
the setup link (§14.3, §15.1), named by the instance card (§17), and moved to another account only by
a signed card handover (§17.2). Every other account has `role = 'member'`. There is no other admin
role.

**Every operator route** needs a session of the operator account (`403 not_operator` otherwise) that
was **not** minted by a web client (`403 operator_web_refused`, §1): the operator's master password
is typed only into native apps or `andvari-cli`, never into code the server serves. Routes marked †
in §0.2 also need a fresh `currentAuthKey` in the JSON body; a † route that only reads is a `POST` so
it can carry one. Every call that changes something or hands out a recovery copy is audited; plain
reads of lists and views are not (§7.3 names both). Audit and email are transparency for an honest
operator, not controls against a hostile one (spec 05 G7).

### 7.1 Accounts and devices

- `GET /admin/accounts` → `[AccountSummary]`, one per account: `{ userId, email, displayName, role,
  status: "active"|"disabled", createdAt, lastSeenAt (null when never seen), disabledAt?, recovery: "private"|"operator",
  usedBytes, itemCount, ownedVaultCount, liveDeviceCount, quota }`. `usedBytes` and `itemCount` are counted
  over the vaults the account owns (§14.4). `liveDeviceCount` counts live devices as defined below.
  `quota` (added 2026-11-16, additive) is that account's meters, the object it reads itself on `GET /sync` (§4,
  §14.4), computed by the same code in the same answer, so a row's `quota` equals what the account would be told at
  that instant; `usedBytes` and `itemCount` are always `quota.accountBytes.used` and `quota.items.used`.
  `limit` is the limit in force: the account's override (`PUT …/quota` below) or else the instance default; the row
  does not say which. `ownedVaultCount` is not a quota meter: it counts the personal vault too and leaves out vaults
  in their grace, where `quota.ownedSharedVaults.used` counts only shared vaults, in grace included.
  **Each row is its own snapshot, the list is not one** (2026-11-16): the server reads the list's
  ids, then each row in a read of its own, so no other request waits for more than one account's meters (measured:
  one read for the whole list held the server's database lock about 310 ms at 300 accounts of 300 items each; one
  row holds it about 1.4 ms). A row is consistent in itself; rows of different accounts may be read a few
  milliseconds apart, and an account deleted while the list is read is left out. Rows come in `createdAt` order,
  ties by `userId`.
- `POST /admin/accounts/{userId}/disable { reason, currentAuthKey }` → `ok`. `reason` is `"abuse"`,
  `"request"` or `"other"`. Sets `status = disabled` and `disabledAt`, revokes every session of the
  account (its sockets get `{"type":"revoked"}`), and sends `account_disabled` with the reason
  category. A disabled account does not count against the cap (§14.4). An unknown target is
  `400 no_such_user`; the operator account itself is `400 cannot_target_self`. Disabling a disabled
  account changes nothing and answers `ok`. Audited `operator_disable`.
- `POST /admin/accounts/{userId}/enable { currentAuthKey }` → `ok`. Sets `status = active`, clears
  `disabledAt`, and sends `account_enabled`. Enabling an active account answers `ok`. Audited
  `operator_enable`.
- `POST /admin/accounts/{userId}/delete { currentAuthKey, reason? }` → `200 { deletedAt }`. Only for an account
  disabled for at least 30 days: otherwise `409 not_disabled_long_enough {disabledAt}` (`disabledAt`
  null or absent when the account is active; the two read the same).
  **The one exception (owner policy, 2026-11-15): `reason: "under_minimum_age"`**, the account holder is
  under the minimum age. It lifts the 30 days and nothing else: the account must still be disabled (the
  disable's `account_disabled` is the email that comes first, and an active account is still
  `409 not_disabled_long_enough`), and the blockers, the † proof and the route's bucket are unchanged.
  `reason` is a closed value, not free text: absent or `null` means the 30-day rule; any other value is
  `400 bad_reason`, checked before the † proof, and deletes nothing. The operator's `operator_delete` row
  then carries meta `target=<pseudonym>,reason=under_minimum_age` (without the reason, `target=<pseudonym>`);
  it is the operator's own row, so the deletion's re-keying (§13) does not touch it and it keeps the
  ordinary retention. It is additive: a client that sends no `reason` is unchanged.
  The operator account itself is `400 cannot_target_self`. It runs
  the account-deletion transaction of §13 **without leaves**: the account's grants are removed
  server-side with no log entry, and each member it leaves stays in that vault log's members with no
  grant (spec 02 §10.7). It is refused, like self-deletion, while the account owns a shared vault that
  has other members (`409 account_delete_blocked {blockers}`, the `shared_vault` kind of §13). The
  `account_deleted_by_operator` email goes to the address captured in the transaction. Audited
  `operator_delete`.
- `GET /admin/accounts/{userId}/devices[?after=<deviceId>]` → `[Device]` (§16.7's shape; `current` is
  absent), paged exactly as §16.7's list. An unknown account is `400 no_such_user`. "Live" is **derived**, not a column: the device is not revoked AND it
  still has a session that is neither revoked nor past its refresh expiry. A server that counts raw
  device rows as live is wrong even though its JSON validates.
- `POST /admin/devices/{deviceId}/revoke { currentAuthKey }` → `ok`. Revokes the device's sessions,
  clears its `deviceSecret` hash (§16.8), cancels the device links it created or approved (§16.7), sends `{"type":"revoked"}` to its sockets and the
  `device_removed` email naming the operator. An unknown id is `404 no_such_device`, audited
  `device_revoke_denied` with no deviceId. Audited `operator_device_revoke`: the record names the
  operator, the removed device and, in its details, the account the device belonged to and the
  operator's own device, so that every record of a removal says who did it and from which device, as
  the account's own removal (`account_device_revoke`, §16.7) does (rule of 2026-11-17): userId = the
  operator, deviceId = the removed device, meta `target=<the removed device's account>,by=<the
  operator's own device>` (since 2026-11-17; rows written before carry `target=` alone).
- `PUT /admin/accounts/{userId}/quota { accountBytes, items, ownedSharedVaults, openLinks,
  currentAuthKey }` → `200 Quota`. Each limit is a **required** key whose value is an `int` or `null`
  (a body that omits one is `400 bad_request`); `null` returns that limit to the
  instance default. The answer is the account's effective `Quota = { accountBytes, items,
  ownedSharedVaults, openLinks }`. An unknown account is `400 no_such_user`. Audited `operator_quota`.

### 7.2 Policy

`GET /admin/policy` → `AdminPolicy`; `PUT /admin/policy` (†) with an `AdminPolicy` plus
`currentAuthKey` → the stored `AdminPolicy`.

`AdminPolicy = { minVersion: {platform: semver}, kdfParams, autoLockSeconds, clipboardClearSeconds,
offlineCacheAllowed, sessionAccessTtlSeconds, sessionRefreshTtlDays, attachmentMaxBytes,
itemAttachmentsMaxBytes, quotaDefaults: Quota, signup: { mode, cap } }`.

- `offlineCacheAllowed` is the operator's floor, ANDed with `ANDVARI_OFFLINE_CACHE_ALLOWED`.
  `totpRequired` is an environment setting only.
- `attachmentMaxBytes` and `itemAttachmentsMaxBytes` are each at most `quotaDefaults.accountBytes`.
- **The served `kdfParams` is never below the server's floor** (`ANDVARI_MIN_KDF_MEM`,
  `ANDVARI_MIN_KDF_OPS`; rule of 2026-11-17): a client that follows the policy, a recovery
  above all (spec 01 §7), must not be refused by the floor. The cost served is the stored cost, or
  the default when none is stored, raised on each figure to the floor, wherever a cost is told: `GET /client-policy`, the first exchange for an address with
  no account (§2), and `GET /admin/policy`, the memory figure rounded up to a whole KiB. The server
  keeps this since 2026-11-17. An account's own cost is still served as it is. **A new wrap meets
  the served cost on each figure** (since 2026-11-18): a new wrap's `kdfParams` (a registration, a
  password change or quiet re-key, a recovery's commit by kit or by request) must be at least the
  cost the server serves, on each figure by itself; otherwise `400 kdf_too_weak`, with a message
  that names the figure. The policy itself (`PUT /admin/policy`) is held to the floor and the limits
  only. What follows from it, said plainly: on a server whose operator raised the policy above the
  default, a client that does not take the higher of the account's and the served cost on each
  figure cannot register, recover or change a password there; every client of this version takes
  it (spec 01 §7). With the default policy nothing changes.
- **The three limits a floor must respect** (rules of 2026-11-17). A floor the operator sets for the
  hashing cost must lie (1) inside the range the server's configuration accepts, (2) at or below the
  server's own upper limit for a stored cost (4 GiB, 64 passes: a cost above it is refused wherever
  a cost is stored), and (3) at or below what the clients accept (1 GiB, 10 passes, spec 01 §7). A
  floor outside any of them is a floor the server cannot apply: it never falls back quietly, and the
  server stops at its start with a line that names the value and the range. **A policy written
  later is held to the same limits** (rule of 2026-11-17): the operator's write of a hashing cost
  that the clients would refuse (above 10 passes or 1 GiB), or that is above the server's own limit
  (64 passes, 4 GiB), is refused `400 kdf_too_weak`, with a message that names the figure and the
  limit, as the floor's check at the start names them. The server keeps both since 2026-11-18.
- **What the operator's view shows** (said and not changed, 2026-11-17): `GET /admin/policy` shows
  the cost in force, the stored one raised to the floor. A console that sends back what it was shown
  stores the raised cost, so lowering the floor later does not bring the earlier figure back.
- **Field errors.** A field outside its bounds is `400 bad_<field>` (§0.1), and nothing is stored.
  Fields are checked in body order, and each error names its own field. The bounds:
  `autoLockSeconds` 1 to 900 and `clipboardClearSeconds` 1 to 300, the ranges every client clamps to
  (`AUTO_LOCK_MAX_SECONDS` and `CLIPBOARD_CLEAR_MAX_SECONDS` in `ClientPolicyClamps`, §1.1), so a stored
  value is the value clients apply; `sessionAccessTtlSeconds` at least 60; `sessionRefreshTtlDays` at
  least 1; `kdfParams` the KDF floor and shape (below).
- **`signup` can only tighten** (§14.4). `GET /admin/policy` shows `signup: { mode, cap }` with
  each value `null` when nothing is stored (the environment then governs). `mode` is `"open"`, `"links"` or `"closed"` and `cap` an
  `int`. A value is refused `400 not_tighter`, and nothing is stored, unless it is at least as strict
  as the **current effective value** (a mode at least as strict as the effective mode, a cap at most the
  effective cap). So the panel can never raise a stored cap or loosen a stored mode, even while the
  environment would allow it. The effective cap is `min(ANDVARI_SIGNUP_CAP, signup.cap)`, and the
  effective mode the stricter of the two. `null` leaves the stored value unchanged. `andvari admin
  signup …` on the host is the only way to raise the cap or loosen the mode; it clears the stored
  values for what it sets (§7.4).
- `PUT` validates `kdfParams` against spec 01: in range **and `memBytes % 1024 == 0`** — a
  non-KiB-multiple is refused `400 kdf_mem_not_kib_multiple` rather than persisted, because it would
  fan out through the silent KDF upgrade into a fleet where the engines disagree on the master key. The
  code is distinct from `kdf_too_weak` on purpose: it is the shape, not the strength, being refused.
  The same divisibility check applies wherever the server accepts account `kdfParams` —
  `POST /auth/register`, `PUT /account/password`, `POST /recovery/self/commit` and
  `POST /recovery/requests/{id}/commit` answer the same `400 kdf_mem_not_kib_multiple` beside their
  `kdf_too_weak` floor.
- Audited `operator_policy`.

### 7.3 Audit and status

- `GET /admin/audit?since=<ms>&type=<type>&userId=<uuid>&after=<id>` → `[{ id, at, type, userId?, deviceId?,
  ip?, meta? }]`: the filterable event log (also shipped to Loki via journald). Audit rows carry ids
  only, never an email. The audit types are spec 02 §5's list.
  **The filters are the server's.** Each one given narrows the rows the server answers: `since` to rows
  with `at >= since`, `type` to that type, `userId` to rows naming that account. A malformed one is
  refused (`400 bad_since`, `400 bad_type` for a `type` that is not 1 to 64 of `a`–`z` and `_`,
  `400 bad_user_id`), never ignored. A client that applies a filter of its own on top must say so.
  **Paged (2026-11-16).** Rows come newest first, in descending `id` order (an `id`
  only grows), at most **500** to an answer. `?after=<id>` (the `id` of the last row of the previous
  answer, a positive decimal integer; anything else is `400 bad_request`) starts the next page: the rows
  with an `id` below it that match the same filters. The cursor names a position, not a row, so it stays
  valid when the janitor has pruned that row in between. An answer of fewer than 500 rows is the last
  page (an empty one when the previous page ended exactly on the last row). Without `after` the answer
  is the first page: the newest 500 rows for those filters, which is everything only when it holds
  fewer than 500. Rows written while a client pages land above its first page, so a reader never sees
  a row twice, and sees new rows only by starting again.
  **What a client does:** it says that a page of 500 rows is full and that older rows exist; to show
  them it asks again with `after` set to that page's last `id`, with the same filters. A client that
  joins pages refuses (fails the read, shows none of it) a page of more than 500 rows, rows not
  strictly descending in `id`, a page after the first whose first `id` is not below the cursor, and
  more pages than its own stated cap. `andvari-cli operator audit` reads one page, says when older
  rows exist and gives the `--after` that reads them; `--all` follows the pages up to 20, and every
  page is checked as above, by the shared code's two calls for the first and the next page, before
  anything is shown. **Not kept yet (2026-11-17):** the desktop
  console says when a page is full and asks the operator to narrow the time, the type or the account;
  it does not read the next page.
  **What is audited, of the operator's calls.** Every one that changes something (rows 3, 4, 74 to 76,
  78, 79, 81 and 86) is audited, its refusals too where its section says so, and so is every one that
  hands out a recovery copy (`operator_escrow_read`, row 85). Plain reads are not: the lists and views of rows 73, 77, 80, 82, 83 and 84 (accounts, an account's
  devices, the policy, this list, the status and the recovery requests) write no row, and neither does
  a read of a recovery copy that hands nothing out (an account that does not exist, `400 no_such_user`;
  one without a copy, `404 no_escrow`).
- `GET /admin/status` → `AdminStatus = { serverVersion, serverTime, userCount, itemCount,
  attachmentCount, attachmentBytes, dbBytes, totpEnrolledCount, downloadsManifest, emailConfigured,
  instanceKind: "public"|"private", signup: { mode, cap, active, full }, mail: { stalled,
  oldestQueuedAt? }, auditKinds }`. `signup` carries the effective values (§14.4) and `signup.active` the number of
  accounts the cap counts. `mail.stalled` drives the operator banner (§14.5). `auditKinds` (additive,
  2026-11-16) is every kind of audit row the server can write, sorted (spec 02 §5's list), so that a
  console can offer the audit list's type from the known kinds instead of a typed one; since
  2026-11-18 it includes `refresh_grace`, `login_wait`, `reauth_wait`, `totp_verify_wait` and
  `account_delete_stale` (§2, §8). The values the meta of a `session_end` row can carry are
  those §2 names, at the sign-in, the logout and `end-session`; they are not repeated here. The shared code
  reads it (absent, or anything but a list of strings, is an older server). The desktop console offers
  the type from these kinds, and `andvari-cli operator audit --type` refuses a kind they do not name
  before it asks for the list (exit 2, naming the kinds), and asks for and shows a kind it never saw
  when they name it; with no kinds served, both go on as before.

### 7.4 Host commands (no HTTP)

`andvari admin` runs on the host with access to the database and environment, and is server-trusted
by nature (the host is T1). It reaches no route above: `status`, `accounts`, `disable`, `enable`,
`signup open|links|close|cap <n>` (edits `andvari.env`, clears the database's tighter values for what
it sets, and restarts the server), `quota`, `enrol-link [--email E] [--expires D] [--count N]`
(mints host enrol links, §15.1; refused until card 0 exists), `setup-link` (only while no operator
account exists), `operator`, `reset-instance-identity` (§17.5) and `audit`. `andvari setup` mints the
setup link the same way (§15.1). The operator's runbook is `docs/self-hosting.md`.
## 8. Misc

- `GET /api/v1/hibp/range/{5-hex-prefix}` — authenticated relay of the HIBP
  k-anonymity range API, for **item passwords only** (the Health breach scan and the item
  editor's on-demand check); response format identical to upstream (`SUFFIX:COUNT` lines).
  Client computes SHA-1 locally and compares suffixes locally; full hashes never leave the
  device. The relay is **stateless**: it stores no prefix, body or timestamp (schema v11
  dropped the old cache). **A client MUST NOT send any value derived from the master password,
  or from a backup passphrase, to this route or anywhere else on the server** (security review
  2026-10): the server holds the Argon2id verifier and `wrappedUvk`, and a 20-bit SHA-1 prefix
  lets it discard ~2^20 − 1 of every 2^20 offline guesses before paying for Argon2id. Clients
  therefore run no breach check on those two secrets; the local strength floor is the only gate.
- `GET /downloads` — web UI + `manifest.json`, the signed update channel. One object per
  platform key (`android`, `windows`, `linux`, `browserExtension`), each carrying at least
  `version` and `url` (plus `sha256`, and the extension's `firefoxUrl`); a platform whose key
  is absent or missing either field renders as "not published yet". Alongside it,
  `manifest.json.sig` — a detached Ed25519 signature over the manifest bytes, verified against
  the client's pinned key with the `seq` anti-rollback floor. `seq` (monotonic, one per publish)
  and `signedAt` are manifest-level fields, not per-platform ones. The full schema, key custody
  and ceremony are `docs/runbooks/release-signing-keys.md`; this document only fixes the route.
  (The previous one-line sketch here described a Windows-only object three platforms after that
  stopped being true — audit H111.)
- `GET /selfhost` — static self-hosting page (bundled render of
  `docs/self-hosting.md` plus downloadable `docker-compose.yml` /
  `andvari.env.template`), registered **before** the SPA fallback so
  `selfHostDocsUrl` (§1.1) always resolves. Every instance carries its own
  self-host docs.
- `GET /healthz` (200 when the DB is readable — the probe is a read-only rev
  SELECT, so an unwritable-but-readable DB still answers 200) — Kuma target.
  `GET /metrics` — Prometheus, bound to localhost for Alloy only; it includes
  `andvari_mail_outbox_oldest_seconds` and `andvari_mail_failed_total` (§14.5).
- `GET /robots.txt` → `User-agent: *` / `Disallow: /` (the instance is never indexed).
- The instance serves **no** app-association files (`/.well-known/assetlinks.json`,
  `apple-app-site-association`): links and their association files live on the product origin
  `https://andvaripass.com`, a static host (§15.1).
- Rate limits: every bucket is listed in §0.2's index; this paragraph states the rules that need
  more than a number. Prelogin is **per-IP 10/min** (fixed window); **login is a flat per-IP
  `ANDVARI_LOGIN_RATE_PER_MIN` (default 5/min)**, and device-link pickup (§16.6) draws on the same
  bucket. After 5 consecutive failures keyed on the **normalized submitted email** (existing account
  or not — extending the prelogin fake-salt anti-enumeration discipline so throttling is not an
  account oracle), an exponential delay `2^(n-5)` s capped at 900 s applies uniformly, reset on
  success; a wrong password and a missing/wrong/replayed TOTP code all count as a failure, at login
  and at pickup alike. **A password proof on a live session has a back-off of its own** (rule of
  2026-11-16): with the same curve, counted only by proofs made on the account's own sessions (every
  `currentAuthKey`: the † routes of §0.1, row 14 and row 16) and refusing only proofs. Each
  proof is counted before it is verified, a wrong one stays counted, and while that back-off is in
  force the proof is refused before any verifier work with `429 rate_limited`, whose `Retry-After`
  names the device's real remaining wait (below: a sign-in is told a fixed 60 seconds); a proof that
  verifies clears it, as a right sign-in clears the sign-in's,
  because it shows that the password is known. The sign-in back-off is armed only by sign-ins (and
  device-link pickups) and refuses only them, so no number of wrong sign-ins by a caller without a
  session refuses a signed-in account's proof, and no number of wrong proofs refuses a sign-in; a
  stolen session still cannot guess the password faster than a sign-in could. A two-step code checked
  on a signed-in session has a third back-off, with the same curve, refusing only the checking of
  codes (§2).
  **The proofs' back-off and the codes' back-off are kept per device, not per account** (rule of
  2026-11-17, which replaces "per account"): the key is the session's device (`devices.deviceId`,
  which every session of that device carries; a refresh keeps it, and a sign-in from a known device
  lands on it). A device is made only by a registration, a sign-in or a device-link pickup (the
  password, and the code where two-step sign-in is on) or a recovery commit, so a session cannot give
  itself a fresh counter. A removed device (revoked by its account or by the operator, or deleted with
  its account) takes its counters with it. The wrong proofs or codes of one device never refuse
  another device's. Why: kept per account, the counters let someone who holds a live session without
  the password keep the account's counter at its cap with about a hundred requests a day, and the
  owner, on any device and after any fresh sign-in, was then refused every action that asks for the
  password again (changing it, removing that very device, turning two-step sign-in off, deleting the
  account) until a kit recovery or the operator stepped in. Per device, a stolen session can still try
  only as many passwords or codes a day as before (109 of each), on its own counters, and takes
  nothing from the owner's other devices. The rate buckets of the routes it can reach are kept per
  device too (§0.1), so it cannot keep the owner from any route on another device either. **What one
  live session held without the password can still do:** guess the password 109 times a day on its
  own device's back-off (and, only with the password, codes 109 times a day); spend every bucket of its
  own device, which puts at most half of any account ceiling into one window, so the owner's other
  devices always keep at least two devices' budgets (only the owner's own use of more than two
  devices' worth of a bucket in one window could then tip the ceiling); everything a session does
  without the password (sync, read, push, links, device links, sockets), within its own budgets; and
  what anyone can do to the limits per caller address (spec 05 R12). **What it can no longer do:**
  refuse the owner's proofs or codes on another device, keep the owner from any route on another device
  by spending its bucket, remove a device, or set up two-step sign-in.
  **The waits a refusal names** (rule of 2026-11-17). They differ by who is asking:
  - **A signed-in session is told its own device's real wait.** The back-offs for wrong password
    proofs and wrong codes on routes that need a session are kept per device, so the session that is
    refused learns only how long its own device must wait. That tells whoever holds the session about
    the wrong tries made on that device, the rightful person's included, and nothing about the
    account's other devices. Such a `429` names the real remaining wait in `Retry-After` (up to 15
    minutes), and the clients show the number they are given.
  - **A sign-in is told a fixed 60 seconds.** The sign-in's back-off, and the device-link pickup's,
    keep `Retry-After: 60`: they answer a caller who has proven nothing, about an address anyone can
    type, and the real remaining wait would tell that caller how many wrong tries were made for that
    address lately. A client that shows this wait says "at least a minute", never "a minute"; its
    words are an entry on the owner's wording page.
  - **The day's limit of new accounts** (`429 signup_daily_max`, row 8) carries its wait in
    `Retry-After`: the time to the next midnight UTC, when the count starts again. It tells nothing
    about any account.
  - **Too many sign-up starts for one address** (the bucket `signup_start_address`, row 6) names the
    real wait of that address's window in `Retry-After`, although no session asks. It is kept as it
    is: the refusal itself already says that the address's window is full, the number tells when it
    opens again, which an honest person needs (it can be hours), and it tells nothing about any
    account.
  - A token's reuse draws no limit at all (§0.1).
  The server on the integration branch keeps each of these (2026-11-17), and `andvari-cli` says "at least
  a minute" for a sign-in's wait. **Not built yet (2026-11-17):** no other client says "at least a
  minute" for it. **A refusal by a limit leaves a trace an operator can see** (rule of 2026-11-17):
  one audit record when an address or a device runs into its wait at a sign-in, and one when an
  account deletion is refused over a moved log (§13), each once per period and not once per
  request. Kept since 2026-11-18, as four kinds, each written in a transaction of its own by the
  first refusal of its key in each period, while every other refusal writes nothing and the answer
  to the caller is unchanged: `login_wait`, a sign-in or a device link's pickup refused by its
  address's wait (fifteen minutes per address, also for an address with no account; the account
  when the address has one, the caller's address, meta `addr=<the first 8 hex of the address's
  keyed hash> at=login|pickup`); `reauth_wait`, a password proof refused by its device's wait
  (fifteen minutes per device, meta `route=`); `totp_verify_wait`, a two-step code on a session
  refused by its device's code wait (fifteen minutes per device); and `account_delete_stale`
  (§13; an hour per account). What bounds the log is the limits themselves: such a record needs an
  address or a device that is already locked, so `login_wait` stays far below the `login_fail`
  rows that armed the lock, and a device writes at most 96 of each of the two others a day. The
  periods are counted in memory, like the limits, so a restart of the server lets one more record
  through.
  A member's token never reaches the
  operator's proof (`403 not_operator` comes first) and no account's proof is checked against another
  account's verifier. The `/recovery/self/*` routes (§12) keep their unconditional **per-IP 5/min
  fixed window and NOTHING else — deliberately NO per-account/email-keyed backoff**: a per-account
  counter on the last-resort recovery path *is* a targeted lockout of the victim, and the recovery
  secret is 256-bit CSPRNG, so per-IP alone already puts online guessing out of reach. §12's uniform
  401 across unknown-email / no-row / wrong-secret is what keeps the route from being an account
  oracle instead. They are internet-reachable on every instance (posture: spec 05 R10, T11).
- Client IP (rate keys + audit rows): the **rightmost** `X-Forwarded-For` entry **of the
  LAST header line** (server scan 2026-10-26 F8: a front that appends its forwarding header
  as a separate line, as HAProxy's `option forwardfor` does, puts the real client in the
  last line after the client's own; reading the first line let a caller name its own rate
  key and audit ip. For every trusted header the last occurrence is the one read; the
  merging fronts produce one line and are unchanged) — the
  **sole default trusted header** — and **only when the direct TCP peer falls inside the
  operator-declared trusted-proxy set** (`ANDVARI_TRUSTED_PROXY_CIDRS`, default
  `127.0.0.0/8,::1/128` — loopback only, i.e. the pre-2026-09-13 rule verbatim, so every
  existing deployment is bit-for-bit unchanged; a supported front-end terminates there).
  An unset value takes that default; a value that is present but blank (or only commas
  and spaces) is the empty list, which trusts no proxy, and the same holds for
  `ANDVARI_TRUSTED_IP_HEADERS`, where blank reads no forwarded header (§1.1).
  A peer OUTSIDE that set uses the socket address and forwarded headers are ignored
  entirely (spoof-proof). Widening the set is an explicit **operator act**, never
  something the server infers from the peer it happens to see: anything inside a declared
  CIDR can name its own client IP, so a wide value trades spoof-proofing for reachability
  through a proxy that does not terminate on loopback (the Docker-bridge gateway is the
  motivating case). *(Amended 2026-09-13, audit H14 — this paragraph previously said
  "loopback", hard-coded; the default still is.)* `CF-Connecting-IP` is
  **deliberately NOT trusted by default**: only a genuine Cloudflare tunnel sets it,
  whereas other front-ends (plain reverse proxies, mesh/tunnel fronts) leave it unset and
  pass a *client-supplied* one straight through — making it forgeable on those paths, so a
  client could rotate its own rate-limit key per request and poison audit `ip` (spec 05
  T11). `X-Forwarded-For` has no such hole: probed 2026-07-13, the supported front-ends
  each put the real client in the **rightmost** entry (overwriting or appending a
  client-sent header, never trusting it), which is exactly the entry taken. An
  all-Cloudflare deployment MAY re-add `CF-Connecting-IP` through the operator-configurable
  `ANDVARI_TRUSTED_IP_HEADERS`; a deployment that is not all-Cloudflare MUST NOT.
  `/metrics` never trusts forwarded headers.
  **IPv6:** every per-IP rate key uses the client's /64 when the client IP is an
  IPv6 address (an IPv4-mapped IPv6 address counts as its IPv4 address), because one subscriber
  is routinely handed a whole /64; audit rows keep the full address.
- Errors: `{ "error": "<machine_code>", "message": "<human>" }`, with any extra fields beside them
  (§0.1); 401 uniform for auth, 403 role, 404 hidden-as-403 for cross-tenant probes, 409 never used
  for sync (conflicts are 200-with-status), 410 resync or an expired link, 413 size and quota,
  426 upgrade, 429 rate, 503 mail stalled (§14.5).

## 9. Attachments (data model: spec 02 §6)

- `POST /attachments/{attachmentId}?vaultId=…&itemId=…` → `200 AttachmentMeta = { attachmentId,
  itemId, vaultId, size, sha256, createdAt }` — writer/owner grant required; ids are canonical UUIDs. Raw body = `header (24 B) || ciphertext chunks`
  exactly as stored. The server streams to disk under the quota caps (413 over
  policy `attachmentMaxBytes` (`413 attachment_too_large`) or the vault owner's storage quota
  (`413 quota_exceeded {quota}`, §14.4)), records
  `{ size, sha256(ciphertext), header }`, and never parses content. Idempotent per
  attachmentId: identical bytes → the stored meta; different bytes →
  `400 attachment_id_taken`. An id that already exists in a vault OTHER than the one named
  by `vaultId` answers the GET route's `403 no_grant` and writes an `attachment_cross_vault`
  audit row (server scan 2026-10-26 F10); on push the same case is reported as
  `unknown_attachment`, never `attachment_mismatch`. **Accepted LOW residual:** attachment
  ids are one global namespace, so a fresh id must insert (`200`) and whoever holds a
  foreign id still learns "exists" (`403`) vs "gone" (`200`). Ids are unguessable, so only a
  former member of that vault can hold one, and an honest client never posts under another
  vault (copy/move mints fresh ids; the plan retry re-posts the same (id, item, vault)
  triple, spec 07 §4) — hence the audit row, a free anomaly signal. Closing it needs a
  vault-scoped id namespace (schema + file layout), an owner call.
- Uploads draw on their own bucket, `attachment_upload`, **600 per hour** per device (§0.1; not the
  write default, so an import is not throttled while a runaway loop is), and are additionally bounded
  per user by a concurrent-upload cap (429 when exceeded) and by in-flight `.part` bytes counted toward the vault owner's storage quota
  mid-stream (413); the commit-time quota check remains authoritative.
- `GET /attachments/{attachmentId}` — any grant on the owning vault; raw body
  identical to the upload shape. Unknown/foreign ids answer 403 (hidden-as-403, §8).
- Item pushes referencing `attachmentIds` are validated: every id must exist and be
  bound to that exact (itemId, vaultId) (`unknown_attachment` / `attachment_mismatch`),
  and the referenced total must fit `itemAttachmentsMaxBytes` (`item_attachment_quota`).
  On `POST /sync/push` a failure is the per-mutation `rejected` status carrying that
  reason (§5, H03) — the rest of the batch proceeds; on `POST /items/{id}/restore` the
  same checks are thrown (`400` / `413`), that route being a single direct request.
- Tombstoning an item deletes its blobs immediately; uploads never referenced by a
  live item are GC'd after 24 h (spec 02 §6).


## 10. Shared vaults and the vault log

Every **shared** vault has a log: an append-only, hash-chained list of signed entries, purpose 0x03
(spec 01 §5.1). Its templates, chain, state, transitions and verdicts are spec 02 §10; this section is
how the log travels. A personal vault has no log: the server refuses members on it, and clients never
build an entry for it (spec 02 §4).

Every membership, role, ownership and lifecycle change of a shared vault is one log entry, appended
through **one route** (§10.3). The server runs the shared core verifier on every append, but clients
never rely on that: each device verifies the log itself (spec 02 §10.5). All routes in this section
and §11 are authenticated, version-checked and audited with ids only, never names.

### 10.1 Kinds and who signs them

| `kind` | Signed by | Server-side role the caller needs (§10.3 step 5) | Rate bucket (§10.5) |
|---|---|---|---|
| `genesis` | the creator | none (the vault id must be unused) | `vault_create` |
| `add`, `role` | owner | `owner` | `vault_membership` |
| `remove` | owner | `owner` | `vault_destructive` |
| `offer` | owner | `owner` | `vault_destructive` |
| `delete` | owner | `owner` (a grant revoked by `vault_delete` counts) | `vault_destructive` |
| `restore` | owner | `owner` (a grant revoked by `vault_delete` counts) | `vault_recovery` |
| `cancel` | owner, or the offer's target | any member | `vault_recovery` |
| `accept` | the offer's target | any member | `vault_recovery` |
| `leave` | the member leaving | any member (a grant revoked by `vault_delete` counts) | `vault_recovery` |

### 10.2 Side data

`POST /vaults/{vaultId}/log` carries the frame and, for three kinds, data the server stores beside it:

| Field | Type | Required for | Content |
|---|---|---|---|
| `entry` | `frame`, purpose 0x03, at most 1,500 characters | every kind | the signed entry |
| `metaBlob` | `envelope`, at most 4 KiB | `genesis` | the vault's encrypted metadata (spec 02 §4) |
| `wrappedVk` | `envelope`, at most 1 KiB | `genesis`, `accept` | the signer's owner wrap of the vault key under its UVK, with the genesis-bound AD `andvari/v2\|vk-shared\|{vaultId}\|{userId}\|{genesisHash}` (spec 01 §6). For `accept` the client opens it again before posting (a round-trip check). |
| `grant` | `sealed`, at most 2,100 characters | `add` | the 0x01 grant, sealed to `memberKey` (spec 01 §6) |

A required field that is missing or fails its type is `400 bad_<field>` (`bad_meta_blob`,
`bad_wrapped_vk`, `bad_grant`). A side field the kind does not take is `400 bad_request`.

A `delete` may carry `itemsAtMost` (an `int`), unsigned and beside `entry`: the sync `rev` up to
which the caller read the vault's items (since 2026-11-18). It rides no other kind
(`400 bad_request`). A value outside the `int` grammar is `400 bad_items_at_most`; `null` or no key
is no point. An earlier server ignores the field. The field's grammar alone decides what a malformed
read point is answered with: a value the shared request class could not hold (`1.5`, a string, a
list) is `400 bad_items_at_most`, never the decoding's `400 bad_request`, also where a client's
request class carries the field as a number (rule of 2026-11-19; kept since that day: the route
reads the request without that key, and the order of its refusals is as before for every body).

### 10.3 Append

`POST /vaults/{vaultId}/log { entry, grant?, wrappedVk?, metaBlob? }` → `200 { rev, head, deleted? }`, where
`rev` is the global rev after the append and `head` the log's head as the caller may see it (§10.6).
`deleted: { deletedAt, purgeAt }` (`ms` both) is present when, after the append, the vault is in its grace
(§11.1) and `head` is the vault's current head: the answer to the `delete` itself, and to any later
append or retry during the grace. `purgeAt` is the end of the grace as stored, the value §10.6 and §11.2
give, so a client shows "restorable until" from it and never from a time it guessed. It is additive: a
client that does not know the field ignores it.

**The server checks, in this order; the first failure is the answer:**

1. **The session** (§0.1).
2. **The body caps** (§10.2).
3. **The frame.** The strict parse of spec 01 §5.1, purpose 0x03, and the frame's `vaultId` equal to
   the path's (`400 bad_frame`, `400 non_canonical`, `400 bad_statement`, `400 wrong_vault`). Then the
   kind's rate bucket (§10.5, `429 rate_limited`).
4. **The signer.** `entry.actor` is the caller, and `ed25519_pk_to_curve25519(signerPub)` equals the
   caller's stored `identityPub` (`400 bad_signer`); the Ed25519 signature verifies
   (`400 bad_signature`). This is hygiene: clients never rely on the server having checked.
5. **Retry, then access.**
   - **Retry.** A frame byte-identical to one already stored in this vault's log, with `actor` the
     caller (step 4), answers `200 { rev, head }` and changes nothing, **before** any grant check. So
     the retry of a stored `leave`, a decline included, still gets its `200` although that entry's own
     effect revoked the caller's grant.
   - **`genesis`:** there is no vault and no grant yet; the vault id must be unused by any vault,
     shared or personal, live or tombstoned (`409 vault_id_taken`). So a retried genesis answers `200`
     (the retry above), and a re-signed genesis for an existing vault id answers `409 vault_id_taken`.
     A genesis naming another owner key passes this step and is refused by the verifier
     (`403 not_vault_owner`, step 7).
   - **Every other kind:** the caller's grant on the vault is resolved first; none, or no such vault,
     is `403 no_grant`, so a non-member learns nothing. While the vault is deleted, a grant revoked with
     reason `vault_delete` counts as the caller's grant for `restore` and `delete` by the **owner**, and
     for `leave` by anyone, and for no other kind: a non-owner's `restore` or `delete`, and any other
     kind, is `403 no_grant`, decided here, before the verifier. A grant revoked for any other reason
     never counts. **After the purge** (§11.1) no grant counts: every append but a `genesis` is
     `403 no_grant`, the owner's `restore` included, while the byte-identical retry of a stored frame
     still answers `200` (the retry above). A personal vault is `400 not_shared_vault`. Then the
     caller's server-side role must allow the kind (§10.1): `403 not_vault_owner`.
   - `spec/test-vectors/logappend.json` grades all of this step.
6. **Position.** `seq` and `prev` must equal the stored head plus one (`prev` = the stored head's
   hash), or `seq = 0` and `prev` = 64 `0`s for `genesis`; otherwise
   `409 log_head_moved {seq, hash, at}`, carrying the stored head. This comes after step 5, so the head
   is never shown to a non-member.
7. **The shared core verifier** (`VaultLog.verify`, the same `:core` code every client runs) checks
   the stored chain plus the new entry under spec 02 §10.3's rules. Its verdicts reach the wire as
   §10.4 says. The server never keeps a second implementation of those rules.
8. **Kind-specific checks:**
   - every kind: `at` is at most 10 minutes ahead of the server's clock (`400 at_ahead`). The verifier
     itself is clock-free; this ceiling is the server's;
   - `add`: `member` is an `active` account with fewer than 500 shared-vault memberships
     (`409 member_limit`), and a `connections` row exists for the owner and `member`
     (`409 not_connected`, §15.8);
   - `genesis`: the caller is under its owned-shared-vault and storage quotas
     (`413 quota_exceeded {quota}`, §14.4);
   - `offer`: by the server's clock, `now < expiresAt <= now + 14 d + 10 min` (`400 bad_expiry`);
   - `accept`: by the server's clock, `now < expiresAt` of the pending offer (`409 offer_expired`),
     and the new owner stays under its quotas once the vault's bytes count against it
     (`413 quota_exceeded {quota}`);
   - `delete` with `itemsAtMost` (since 2026-11-18): when any item row of the vault, live or in the
     trash, has a `rev` above it, `409 vault_items_moved`, and nothing is stored. The check runs in
     the transaction that would store the entry, so no other write lands between them. Every change
     of an item row takes a new `rev`: a create, an edit, a conflicting put, a move into the trash,
     a restore. A purge takes none and does not refuse: what it removes was in the trash at the
     read, which the caller's read counts. An attachment counts through the put of the item that
     names it. The client reads the vault again; the same signed frame may be posted again with a
     new point. Without `itemsAtMost` the `delete` is taken as before. A byte-identical retry of a
     stored `delete` is answered `200` at step 5 whatever point it carries, so a
     `vault_items_moved` proves that the frame is not stored.

Then, in **one transaction**, the server applies the effect to its tables, stores the entry, bumps the
vault rev and rings the bell (§6) for every affected member, the removed included:

| `kind` | Effect on the server's tables |
|---|---|
| `genesis` | creates the vault (`type = shared`, `metaBlob`) and the caller's `owner` grant with `wrappedVk` |
| `add` | creates the member's grant (or re-activates a revoked one) with `role`, `signedGrant = grant` and an empty `wrappedVk`; bumps the grant rev |
| `role` | replaces the member's role; clears the pending offer if it targets that member; bumps the grant rev |
| `remove` | revokes the member's grant (reason `member_remove`); clears the pending offer if it targets that member |
| `leave` | revokes the caller's grant (reason `member_leave`); clears the pending offer if it targets the caller. On a deleted vault the caller's `vault_delete` revocation is rewritten to `member_leave`, so `restore` skips it |
| `offer` | stores the pending offer `{offerId, to, expiresAt}` |
| `cancel` | clears the pending offer |
| `accept` | the old owner's grant becomes `writer` (its `wrappedVk` kept); the new owner's grant becomes `owner` with the posted `wrappedVk`; clears the pending offer; the vault's bytes now count against the new owner's quota |
| `delete` | revokes every active grant (reason `vault_delete`, key wraps kept for restore); sets `deletedAt`, `purgeAt = now + ANDVARI_VAULT_GRACE_DAYS` (default 7) and `deleteId`; clears the pending offer |
| `restore` | re-activates every grant **still** revoked with reason `vault_delete`; clears `deletedAt`, `purgeAt` and `deleteId` |

**Idempotency and retries.**

- A byte-identical frame already stored, signed by the caller, answers `200` and changes nothing
  (step 5).
- A client keeps every frame it signed in a durable **pending-append** record until the server
  acknowledges it. After a timeout it re-posts **the same bytes**; it never re-signs with a new `at`,
  which would hand the server two valid entries for one position.
- Only after `409 log_head_moved` **and** a fetch (§10.6) that shows its frame was not stored does it
  discard the pending frame and sign a fresh entry at the new head, with `at = max(own clock,
  head.at)`.
- A frame refused with any `400` was never stored; the client discards it. On `400 at_ahead` the
  device says "Your device's clock is ahead. Set the correct time and try again." It never adopts a
  time the server suggests.

**What the web client tells the person after a change of a vault's log** (rules of 2026-11-18;
design §3.7 has the screens). An outcome is said only as far as it is known:
- **Stored** only where the server's own complete answer names the frame that was sent: its
  position and its hash. An answer whose head lies beyond the frame (the server's answer to a
  byte-identical frame it already held) counts as stored only once the log, as read afterwards,
  holds that frame; until that read, it is "cannot tell".
- **Not made** only after a read that reaches the head the server's own answer named, with the
  same hash at that position, and does not hold the frame. A read that ends before that position
  is no read for this purpose: the outcome is "cannot tell" and the change stays held. A read that
  holds another hash at that position is a fork, never "not made": the vault is frozen there
  (§10.4), and the change stays held.
- **Not sent** where nothing left the browser; **not stored** where the server's answer to the
  frame's first post refused it for now (`429`, or `409 log_head_moved` while the entry at its
  place is not verified yet); **cannot tell** for every other ending (no answer, an answer cut off,
  a `5xx`, a page that is not the server's, an answer that names another frame). A change that is
  not stored or that cannot be told is held and sent again (the server takes it once).
- **After "cannot tell" on a change of members** outside a move, the members the person is sent
  to are read from the server before they are shown; where that read fails, the line says that
  the list on the screen may be old.
- **A held change is shown as waiting** where the vault's members are shown, with what is known of
  it, **can be withdrawn**, and **is given up after a day**: it is not sent again, the log is read
  first, and what is found is said. One the server said it stored is never given up. **A change
  sent again that does not happen is said**, at that moment, with what it was (who was to be added
  or removed, in which vault) and that it did not happen; the notice names its vault, also without
  an offline copy, and its record stays at rest, marked as settled and never sent again, until the
  notice has been shown and dismissed, so that closing the tab loses nothing. Records held from an
  earlier version count their day from the first time they are seen.
- **Withdrawing, by what is known** (rule of 2026-11-18): where the server said it did not store
  the change, withdrawn means it was not made and will not be; where the answer was lost,
  withdrawn means that this browser will not send it again, the line says that it may already be
  made, and the vault's log is read from the server as soon as it can be, and the person told what
  it found (made after all, with the way to undo it, or not made). Every held change the person
  could come to regret waits this way: an addition, a removal, a change of role, a hand-over and a
  vault's deletion; a move's own steps follow the move's run and are not withdrawn one by one. **A
  vault's deletion that waits is sent again only at the person's own word**: at the unlock a notice
  names the vault and offers to delete it now or to keep it (which withdraws the deletion), and
  nothing is sent until one is chosen. **Giving a change up has the same guard as sending it**,
  and a withdrawal keeps the frame's hash and position: **where no answer named a head**, "not
  made" rests on the log as it is served then, so a change this browser gave up, withdrew or called
  not made is remembered by its hash and its position for as long as that position is free (the
  number of such records for one vault is bounded, the oldest go first, and one whose position was
  taken goes at once); if the log later holds it, the person is told, with the way to undo it, and
  that notice too is kept until it is dismissed. A signed change that reached the server can be
  appended later for as long as nothing else took its place; the person's next change of that
  vault takes the place and ends that (spec 05 R42).
- **A vault's deletion that waits is first looked for in the vault's log** (rules of 2026-11-19),
  with nothing sent by the look, before the person is asked about it: where the log holds it, it
  is made, and the person is told that the vault was deleted, with the day until which it can be
  restored, kept until dismissed; where its place was taken, it did not happen; a read that fails
  or ends short leaves the question. Only one still held is asked about, and the question has words
  of its own for a vault it cannot name. A question the person dismisses leaves the deletion
  waiting and is asked again at the next unlock inside its day. Where the day ran out between the
  question and the tap, the deletion is given up there, after a read, and the line says so and how
  to delete the vault again. "Delete it now" sends the entry as it was signed, with no point up to
  which the vault was read: the person decides at that moment to delete the vault with what was
  saved in it since, and the question says so. A sync that moves a vault's log settles a change
  that waits for that vault by a look at the log it read (nothing fetched, nothing sent; "not made"
  never from a free position).
- **A give-up judges the record as it is held once its read has ended, and the whole record**:
  a second try of the same entry that was answered during the read (stored, or with a head named
  beyond it) is not given up as "did not happen", and the head it named goes into what is
  remembered. Where an answer named a head beyond a change and a read reaches that position with
  another entry, the server's answer and its log cannot both be true: the vault is frozen and
  nothing is said of the change; short of that position nothing is said yet. "Not made" counts as
  told only once its notice is made. A move's step that sends what is held for its new vault sends
  only the move's own entries. **What is remembered for one vault is bounded at eight**: those
  already told "not made" go first, one not told yet only when none of those is left (spec 05 R42
  says the cost). Records at rest are carried by a reader that does not know every field of them
  (a record of a newer form is left as it is, never consumed).

**What the web client keeps (2026-11-18):** stored, not made, not sent, not stored and cannot tell
as above, at the first post, at the unlock's re-post and at a move's re-posts; a fork at the named
position freezes the vault; the read after "cannot tell" on a change of members outside a move; an
addition or a removal that waits is shown in the member panel and given up after a day; a change
sent again that did not happen is said with its vault and its member and kept at rest as settled
until its notice is dismissed (the settled records lie under the account's own keys, so the
account's removal from the browser takes them). A policy that forbids the offline copy does not
remove these records (accepted on 2026-11-18): they are the account's trust records of each log and
the few signed entries that wait, nothing of a vault's content. **Kept since 2026-11-19, in the web
client:** a waiting change can be withdrawn whether or not its answer was lost, and every change a
person could regret waits alike (a change of role, a hand-over and a vault's deletion among them);
withdrawing and giving up are guarded as sending is; what was given up, withdrawn or called not made
is remembered by its hash and position, bounded at eight for one vault in the order above, and a
change the server appends later is said, with the way to undo it, until dismissed; an answer that
contradicts the log freezes the vault, also where an entry the server's own answer named at its
position is later found replaced there (when, below); a give-up judges the record as held once its read has
ended; a vault's deletion that waits is never sent again by itself: it is looked for in the log
first, and only one still held is asked about, to delete it now or keep the vault; a sync that moves
a vault's log settles a waiting change by a look; a move's step sends only the move's own entries,
and a move's new vault says in its own sealed description which vault it is the target of
(`moveOf`, design §3.13); records at rest are carried by a reader that does not know every field.
**The web client's rule for the server's word** (2026-11-19, the shared code's rule below): an
answer of success whose head lies at or beyond the change's position is the server's word that it
holds the change, whatever hash it names at that position (an honest server answers success to an
append only where it appends the frame or already holds it byte for byte from the same account, so
the frame is then at its position); where a complete verified read of the vault's log then holds
another entry at that position, the vault is frozen at that read, with nothing said of the change,
and "not made" is never said after such an answer; the contradiction is also looked for when the
server's word is recorded, against the log as already verified; an answer below the position is no
answer about it. The server's word survives every other ending of the record (a refused re-send, a
withdrawal while an answer is out, the drop of a half-made vault's deletion). After the freeze
nothing of the change is sent, shown or asked: its held record is dropped, a notice that its place
was taken is taken back, and a move whose own deletion was dropped so says that the old vault is
frozen and does not reopen it. **Where the web client differs from the shared code, on purpose**
(decided on 2026-11-19): after an answer beyond the change, the web client does not call the change
stored before its own read shows it, so it says "cannot tell" and offers a withdrawal, where the
shared code says that the server says it has it and offers none; both freeze on a contradiction,
and the difference opens no road around the freeze. **A member may leave a frozen vault** (rule of
2026-11-19): it is the person's way out of a vault whose server contradicts itself, and the entry
they sign names the history their own device verified; nothing but a leave can be posted to a
frozen vault from the browser, and where the server answered that it took the leave, the browser
says so and that it can no longer check this vault's history, never "nothing changed". A declined
invitation's leave is posted again at each later unlock until the server takes it, on a frozen
vault too. Kept in the web client since 2026-11-19, for every kind of
change and for an answer at or beyond its place, also one that names another entry there: the freeze
at the complete verified read (or when the answer arrives against the log already verified); the
word kept through a refused re-send, a dropped deletion of a half-made vault and a withdrawal made
while the answer comes in; at the freeze the held change dropped, and nothing of it sent, shown,
asked, given up or counted, a finding that its place was taken taken back; a refusal that comes
from a freeze said in a line of its own that claims nothing about a change that was sent, and "not
sent" only where nothing was; a move whose own deletion was dropped stopping with a line of its
own; a member's leave of a frozen vault said as what the server answered (before 2026-11-19 the
browser froze only when something later touched the held change, kept it, and sent it again to the
frozen vault at every unlock). **Not kept yet (2026-11-19), in the shared code:** what an app is
told after a member's leave of a frozen vault is not established; it is to say what the server
answered, as the web client does. **A removal of a frozen vault that is learned at a sync is never
quiet** (rule of 2026-11-21, also after the person's own leave): the browser holds no verified log
of a frozen vault, so it can never tie a removal to its own act. Kept in the web client: a delta
sync that lists the removal of a frozen vault held before the pull moves what this browser holds of
it into the 30-day holding area, with this account's own wrap of the vault's key, and raises the
anomaly notice; the person's own leave of a frozen vault sets no quiet drop, so this holds after it
too. The held copy is what this browser held of the vault when it learned the removal: where the
server went on serving the vault after the leave, that includes items written after the person
left, which adds nothing to what a member can read with a server's help (spec 05 R7, R45). **Not kept
yet (2026-11-21):** a mark of the person's own leave of a frozen vault, bound to the vault's grant
row, for two things only: while it stands the vault the person left is not listed again; and where
it stands when the removal is learned, the notice says that the person left this vault on this
browser and that for this vault the browser cannot check whether anything else happened since, and
that a sealed copy of what the server served when the removal was learned is kept on this device
for 30 days, and where to find it (a line awaiting its words); that notice uses the mark up. The
shared code is to keep the same rule for the phone and the desktop: on a frozen vault no departure
is quiet, and a departure's quiet mark is bound to the entry it was made for, in every act (decided
on 2026-11-21, before the first public release).
**A change that brings back an item deleted elsewhere** is said once, in one notice per vault, and no
copy is made; **no line names a day until which a deleted vault can be restored unless the server
served that day** (where it served none, the line points to the list of deleted vaults, and the
client computes no day of its own: where the device has only its own estimate, the time it saw the
deletion plus its own constant, no screen is handed a day and the line says that the vault can be
restored for a limited time, because a server may keep a deleted vault for a shorter time than the
device assumes, and a day that is not true is worse than none; rule of 2026-11-19 for the shared
code's layer); a decline whose leave the server did not store says so. **A decline whose message to
the owner was not stored is signed again** (rule of 2026-11-19, for the web client and the shared
code alike): where the vault's log, read afresh at a later unlock after the first sync, still lists
this account as a member through the very addition that was declined, and no leave is already held,
the leaving is signed again then, once per unlock, and nothing more is said than that the owner may
still see the invitation until it goes through; where the log no longer lists the account, or lists
it through a later addition, nothing is signed. The web client keeps this since 2026-11-19. **Not
kept yet (2026-11-19):** the shared code does not sign such a decline again, and says nothing of
what became of it; the shared code's row of a deleted vault carries the device's own estimate where
the server served no day, and nothing tells a screen which of the two it is (the row with a day only
where served and a field of its own that says the vault is deleted is built and held until both apps
read "deleted" from that field, never from the day, since a vault whose day was not served would
otherwise show as a live vault with no way to restore it). **A vault whose deletion stands is
read-only on the device** (rule of 2026-11-19): the server ended every grant with the deletion and
refuses a write, so a save into it is refused on the device with a line of its own. Kept in the
shared code since 2026-11-19: the device queues nothing for such a vault, and a save or a move into
it, and an edit or a deletion of one of its items still on the screen, each say that the vault was
deleted, that its owner can restore it for a limited time and that nothing can be saved into it
until then; what is read from it stays, and a restore makes it writable again at once.

**The apps keep the same outcome rules** (rule of 2026-11-18, for the shared code as for the web
client), with these rules of 2026-11-19 for the shared code: a send makes the stored record of the
change "cannot tell" before it leaves, so that an engine built after a lock over the same records
never calls a change "known not stored" while an earlier session's try may still be on the wire;
the head an answer named is kept in fields of its own and never overwritten by a later refusal's
head; what is reported as waiting is first settled against what this device has already verified,
and one call reads the vault's log and settles, sending nothing, so that a person is not asked
about a deletion the server already stored; **a change the server's own answer called stored is
not offered for withdrawal** (it is made, and the device has only not read it back; the waiting
line says that the server has it, and the way to undo it is the act that undoes it once it is read
back) and is not given up as "cannot tell"; a withdrawal that took effect is answered as that,
also where the read after it is cut off by a lock; the limit on what is remembered lets go of
withdrawals already told first, then of changes given up, then of those not told yet, each oldest
first, and never of a "made after all" not yet shown while anything else can go (sixteen and
thirty-two records); the move marks its own additions and deletions as the move's, so that none
waits for a person's word or can be withdrawn by one; a vault's deletion carries the point up to
which its items were read (§10.2), and the server's refusal that they moved on drops the entry and
is never "cannot tell"; a person's answer to a share whose record cannot be told is a result of
its own (a decline whose leaving the log holds is a decline); a sign-out keeps the engine's records
of the account (its trust records among them, without which a server could show an older state of
a vault after the next sign-in, unnoticed), and an account's deletion on the device removes them
all. **Further rules of 2026-11-19 for the shared code:** a held change is "known not stored" again
only where every send of it was answered "slow down" and no later send started; an answer whose head
is below the change's position is no answer about that change (it marks nothing as stored by the
server's word and names no head for it), and the head an answer named at or beyond the change is
never taken away by a later answer (the highest stays), so a replayed older answer cannot unfreeze a
vault or keep a change "stored by the server's word"; where the server answered a change as stored
under a head at or beyond its position and a verified log that does not hold the change holds
another entry at that position, or another hash at the named head, the vault is frozen and nothing is
said of the change, and a finding "the place was taken" kept for that change is taken back; where the
verified log holds the change it is made, even if the head an answer named disagrees; a frozen
vault's held change is dropped and never sent, and the vault stays read-only on this device until
the device's records of it are removed (spec 05 R45); a refusal of a re-send never drops, as refused
for good, a change the server's own answer called stored (the record stays and is sent again as it
is, and nothing is said as refused), a refusal about the session (it has ended) leaves every held
change as it was, and a change of unknown outcome whose re-send is refused for a reason about the
entry is remembered as given up, with the reason, and settled by the next verified read, never said
as refused; the server's refusal code is kept at rest only as a code the client knows, or as "other";
a held deletion of a half-made vault the move keeps can be dropped unsent by a call that neither
reads nor sends and is remembered as its own kind, with no "not made" line; "made after all" is kept
as a finding only for the person's own deletion; the call that forgets an account is each keeper's
own (the vault-log engine's for its records), and the account's deletion on the device calls every
one of them, proved by a test that scans every key and every value; a server's "wait this long" is
clamped to a day at most, beyond which the line says "later". The layer above draws the waiting line
from what is known (the server says it is made, not read back yet, with no Withdraw; not made yet and
sent again; may already be made), shows Withdraw only where it is offered, looks before it asks
about a deletion that waits and asks only about one still held, checks the day at the tap, and
checks a restore on "made after all". **What the shared code keeps (2026-11-19):** a change to a shared vault that the server asked
the device to slow down for, where no earlier send of it could have been, is known not stored: it
is kept, said as kept, sent again byte for byte, and can be withdrawn until then; after any send
whose outcome is not known it is never again "not stored", and a later "slow down" is "cannot
tell". An answer to a share that the server did not record leaves the question as it was asked.
Since 2026-11-19 the shared code's engine also keeps: the "cannot tell" record written before each
send leaves, and "known not stored" again only after every send was answered "slow down" with no
later send started; the head an answer named kept in fields of its own, the highest staying, and an
answer below the change's position no answer about it; the freeze where a verified log contradicts
an answer that called the change stored, with nothing said and a "place was taken" finding taken
back, at the complete verified read that shows the contradiction, with nothing else called (since
2026-11-19; before it, the freeze came only when something next touched the held change); a look,
a giving-up and an append whose own read dropped the change answer that the vault is frozen; a
move whose old vault froze while the move's own deletion of it waited stops at its own first read
and again before signing, with the frozen line, sends nothing, keeps its mark and offers no fresh
start (a limit: a read from which the server withholds entries can verify the other entry's hash
without that check; the vault is read-only while withheld, and the freeze then comes at the next
complete read); and "made" wherever the verified log
holds the change; a frozen vault's held change dropped
and never sent; what is reported as held settled first against what was verified, and the look
that reads a vault's log and sends nothing; a change the server's answer called stored neither
offered for withdrawal nor given up, and sent again as signed until the log shows it; a refused
re-send that never drops such a change, a refusal about an ended session that leaves every held
change as it was, and a change of unknown outcome refused for a reason about the entry remembered
as given up and settled by the next verified read; a withdrawal that took effect answered as that
when a lock cuts off its read; the limit's order (sixteen memories and thirty-two findings per
vault; past the bound the oldest of the evicted kind is never told); the deletion's read point
carried in the request (§10.2); the call that drops a held deletion of a half-made vault, sending
and reading nothing, remembered as its own kind; the log engine's own call that forgets an
account's records (it removes every record it keeps for that account, and answers that it could
not where the store cannot list its keys); a server's wait read in one place as whole seconds from
none to a day, else none; and every record write for vault logs first checks, under one lock with
the forgetting, that the account's records still stand, so that a request already out when an
account is forgotten writes nothing when its answer comes. **Not kept yet (2026-11-19):** the move
marking its own additions and deletions as the move's and naming its deletion's read point, and an
account's deletion removing the vault-log records by the log engine's own call (built in the
layer and held until the apps read a deleted vault from a field of its own and the forgetting's fix
has merged); an engine that could not read the store when it began holds no mark that its records
stand and takes whatever mark it finds at its first write (it is to refuse instead); the call that
sends a waiting deletion now answers "waiting" after the change was given up, where it is to say
what became of it, and the layer is to read the held change and the findings again after such an
answer; a first send answered "the session has ended" reads "cannot tell" (true, and said as
that); the layer's drawing of the waiting line; and the apps do not yet show a
waiting change with what is known, withdraw it in both states with the memory of what was let go,
say a change sent again that did not happen, or send a vault's deletion that waits only at the
person's word; `andvari-cli` still says that a waiting change is kept and sent again on the next
run, also of a vault's deletion and of a change a day old, and has no command to send a waiting
deletion now or to keep the vault instead.

**A change that waits, on the phone and the desktop: rules of 2026-11-21, not built yet** (the
shared code's layer that both apps draw from; the threat model's limits are in spec 05 R45). The
points marked *(proposed)* are not decided: they describe the form this layer was first given, which
is not merged, and they are to be confirmed with it; the others were decided on 2026-11-21.
- *(Proposed.)* A screen draws a waiting change only as the log engine reports it after settling it
  against what the device has read, and drawing it sends nothing. The general re-send runs after every
  completed sync, before a screen draws a waiting change (that the automatic re-send stays was decided
  on 2026-11-21).
- **An act lands only on the change the person saw.** What a screen is handed carries the hash of
  the held change's signed entry and the account's opening it was drawn in; a withdrawal and "Delete
  it now" compare both with what is held now, in the same step as the act and with no wait between,
  and where either differs they answer that the row is stale and send and withdraw nothing. The log
  engine's own calls take the expected hash, so that no layer above can act on another change.
- **A vault's deletion that waits for the person's word** is never sent by any automatic road. It is
  asked about only after a look in the vault's log that sends nothing, within its day, in each
  opening of the account; the record of that look is kept by the deletion's entry (its hash), not by
  the vault, and holds only what still waits. "Delete it now" sends the deletion as it was signed,
  and is refused while a move of that vault runs or the move's own deletion of it waits; "Keep the
  vault" withdraws it.
- **A held addition whose ground has gone is not sent again.** On every road that sends a held
  change again (the automatic one and the one at the person's next action), the key in a held
  addition's signed entry is first compared with the device's current contact for that member;
  where the contact is gone, has another key, or is no longer compared, the addition is not sent: it
  is let go of and remembered, with a notice of its own that says so and that the server may already
  hold it (if it does, the "made after all" notice with its undo follows). A waiting addition is
  named only by the key in its entry: where the current contact has another key, the name is
  "unverified", never the contact's label.
- **The lines.** A notice that a deletion was made offers the restore only while the vault still
  reads deleted on this device, and says that it was restored since where it was. A re-send the
  server refused is said as refused and as "cannot tell", in a line of its own, never as "waited
  more than a day", and the deletion keeps its departure mark there. "The deletion that you
  withdrew" is said only of a deletion the person withdrew; one that was given up says that. A
  deletion or a change the server says it stored is drawn with a line that says that the server
  said so, that the vault's log does not show it yet, and that this device makes no other change to
  this vault meanwhile. A change that was not signed or sent because another change of the vault
  waits has a result and a line of its own, never "sent, not yet acknowledged". A waiting change and
  a notice carry the member's account id beside the name, and a role change carries the role it
  would go back to, so that an undo acts on the member the notice names. *(Proposed, a limit.)* A
  notice's vault name is the name as this device reads it now, or the words for an unnamed vault where
  it cannot read one.
- *(Proposed.)* A vault frozen because its server's answer and its log contradict each other takes no act on its
  waiting change, and the change leaves the row without a notice. A move stopped because its old
  vault froze after the move's own deletion was sent can be closed by the person's word: the close
  removes only this device's record of the move and its mark, sends nothing and changes nothing in
  either vault, and the old vault stays frozen.

**Storage:** `vault_log(vaultId, seq, hash, frame, actor, kind, at, storedAt)`, primary key
`(vaultId, seq)`. Log rows outlive the vault's purge: they are deleted one year after the purge,
while the tombstone vault row stays (§11.1), or at the purge itself for a vault no other account could still fetch
(§13).

### 10.4 Verdicts and checks on the wire

Every verifier verdict (spec 02 §10.3) and every server check maps to exactly one answer.
`not_authorized` and `fork` are client verdicts and never appear on the wire.

| Verifier verdict, or server check | Wire |
|---|---|
| `bad_frame`, `unknown_format` | `400 bad_frame` |
| `non_canonical` | `400 non_canonical` |
| `bad_statement` | `400 bad_statement` |
| `wrong_vault` (the frame's `vaultId` against the path) | `400 wrong_vault` |
| step 4: the actor or the signer is not the caller | `400 bad_signer` |
| `bad_signature` | `400 bad_signature` |
| step 5: no grant (or no such vault); a role that does not allow the kind | `403 no_grant`; `403 not_vault_owner` |
| step 5: a personal vault | `400 not_shared_vault` |
| step 5: `genesis` with a vault id in use | `409 vault_id_taken` |
| `bad_seq`, `bad_prev` (not the stored head plus one) | `409 log_head_moved {seq, hash, at}` |
| `not_authorized` from the verifier (the log names another signer for this kind) | `403 not_vault_owner` |
| `precondition` | `400 precondition` |
| `fork` | never sent: the server stores one chain, so another entry at a stored position is `409 log_head_moved` |
| `at` more than 10 minutes ahead | `400 at_ahead` |
| an offer's `expiresAt` outside the server's window | `400 bad_expiry` |
| `add` limits | `409 member_limit`; `409 not_connected` |
| `accept` at or after `expiresAt` by the server's clock | `409 offer_expired` |
| `delete` with `itemsAtMost`: an item row of the vault with a newer `rev` (§10.3 step 8) | `409 vault_items_moved`, with no other field |
| quotas | `413 quota_exceeded {quota}` |
| rate buckets | `429 rate_limited` |

Server vectors: `spec/test-vectors/logappend.json` pins step 5's access rules.

### 10.5 Rate buckets

Per device (with the ceiling per account of §0.1), by kind:

| Bucket | Kinds | Limit |
|---|---|---|
| `vault_create` | `genesis` | 10 per hour. A bulk restore paces itself on `Retry-After` (spec 07 §3). |
| `vault_destructive` | `offer`, `delete`, `remove` | 10 per hour (shared with the rename route, §11.3) |
| `vault_membership` | `add`, `role` | 60 per hour |
| `vault_recovery` | `restore`, `cancel`, `accept`, `leave` | 30 per hour |

A `429` carries `Retry-After` in seconds. Leaves appended by an account deletion (§13) are exempt
from every bucket. A `delete` refused `409 vault_items_moved` gives its draw back to the device's
`vault_destructive` budget, once; the account's ceiling keeps it (§11.1). Every other refusal after
the bucket, `log_head_moved` included, stays counted (the server keeps this since 2026-11-19).

### 10.6 Fetch, and who may read a log

- Every shared vault row in `/sync` carries `logHead: { seq, hash }` (§4).
- `GET /vaults/{vaultId}/log?after=<seq>` → `{ entries: [frame…], head, purged?: { purgedAt }, deleted?: { deletedAt, purgeAt } }`.
  - **Paging.** At most 500 entries per page, in ascending `seq`, each with `seq > after`. Without
    `after`, the page starts at `genesis` (seq 0), which is how a fresh device begins. A client
    repeats with `after` set to the last `seq` it received until it has reached `head.seq`. `after`
    must be an `int` (`400 bad_after`).
  - `head` is `{seq, hash, at}` of the last entry the caller may see. `head.at` lets a device that
    builds an entry without replaying the log still keep `at` monotonic (the deletion preview, §13).
  - `purged` is present once the vault has been purged (§11.1).
  - `deleted` is present while the vault is in its grace (deleted, not yet purged, §11.1) and `head`
    is the vault's current head, so only a caller who may see the `delete` learns of it; an account cut
    off by `remove` or `leave` before the `delete` gets no `deleted`. `deletedAt` is the server's time
    of the `delete`'s append and `purgeAt` the grace's end (§11.1). It is additive.
- **Who sees what:**
  - an active member gets the whole log;
  - **while the vault is deleted**, every account in the log's members keeps fetch access to the
    whole log (their grants are revoked with reason `vault_delete`, which counts here), so each can
    verify the `delete`, a later `leave`, and the `restore`;
  - an account cut off by `remove` or `leave` gets the entries up to and including that entry, and
    nothing after; `head` is that entry. A later `add` for it restores full access;
  - **after the purge**, every account that was in the log's members at the `delete` keeps fetch
    access to the whole log for one year (§11.1);
  - anyone else gets `403 no_grant`.
- Clients verify every page as spec 02 §10.5 says, and act on what they verified, never on `head`,
  `purged` or `logHead` alone.

### 10.7 Members

`GET /vaults/{vaultId}/members` → `[{ userId, email, displayName, role, identityPub, addedAt,
status? }]`: the vault's active grants as the server holds them. Any active member may call
(transparency); a non-member is `403 no_grant` (hidden-as-403). `status` surfaces a disabled account.

This list is the **server's** view. A client shows a member's label only where the verified log's
member key equals that person's pinned key, and otherwise "unverified member (as the server names
them)"; the audience it shows is the verified log's members (spec 02 §10.5). A member whose account
the operator deleted stays in the log's members with no grant (§7.1); the owner's app offers "Remove
from the list", which signs an ordinary `remove`.

## 11. Vault lifecycle, rename and self-wrap

The lifecycle itself (delete, restore, ownership offer, cancel, accept, leave) is entries in the log
(§10). This section adds what the server does around those entries, and the vault routes that are not
log entries.

### 11.1 Grace, purge and the tombstone

- **A deletion is refused when the vault's items moved on since the client read them** (rule of
  2026-11-18): the append of a `delete` is to carry, unsigned, the point up to which the client read
  the vault's items, and the server refuses it in the same transaction when any item of the vault,
  live or in the trash, is newer; the client then reads again. The reason: a deletion names only the
  log's head, never the items, so between a client's read of a vault (a half-made vault of a stopped
  move, design §3.13) and its deletion a member's save can still go with the vault. **The server
  keeps this since 2026-11-18:** the field is `itemsAtMost` (§10.2) and the refusal
  `409 vault_items_moved` (§10.3 step 8). **A refusal for items that moved on gives its draw on the
  deletion's rate limit back** (rule of 2026-11-18): the caller did nothing wrong and nothing was
  stored. The server keeps this since 2026-11-19: the draw is held, the refusal's rollback returns
  it once, and a stored deletion keeps its draw. **The account's own ceiling still counts such a
  refusal** (rule of 2026-11-19): it bounds a caller who sends deletions against a moved read point on
  purpose, and the work each refused call costs the server. So a member who keeps saving can make an
  owner's deletions fail for as long as they save, and after forty such refusals in an hour the
  account's own limit answers; the way out is to remove that member first (spec 05 R43). **The web
  client keeps this since 2026-11-19** for both deletions that follow a read: a vault half-made by a
  stopped move names the sync position of the read that decided it, at every sending, a deletion held
  from an earlier try included, and a refusal for items that moved on stores nothing and holds
  nothing, and the vault is read and judged again, at most three times in one dealing, after which it
  stays due as a vault not read; the move's deletion of the OLD vault names the sync position of the
  read its last checks rest on (taken from one state with them), and where it is refused nothing is
  stored or held, the old vault stays, and the move says that something changed after it was copied,
  without a number; moving again carries it. The person's own deletion of a vault names no point: it
  deletes the vault with what is in it at that moment, and what a member saved a moment before goes
  into the grace with it and comes back with a restore. **Not kept yet (2026-11-18):** the shared code
  sends no point for either deletion, so the window between the read and the deletion (a second or
  less) stays for the apps (spec 05 R43); since 2026-11-19 the engine carries the point in the
  request, and the move that names it is built and held (2026-11-19).
- A `delete` starts a grace of `ANDVARI_VAULT_GRACE_DAYS` (default 7): the server stores
  `deletedAt` = its time of the append and `purgeAt` = `deletedAt` + the grace, and every answer that
  names the grace's end gives that stored `purgeAt` (`deleted` on the append, §10.3, and on the log
  fetch, §10.6; `purgeAt` in `GET /vaults/deleted`, §11.2). During it the vault's items,
  attachments and wraps are kept, the members keep fetch access to the log (§10.6), and the owner may
  sign `restore`. A `restore` re-grants every grant still revoked with reason `vault_delete`, so
  members return with full access and need no new `add`; a member who left during the grace stays
  out.
- **Purge.** When the grace ends, the janitor (daily 04:30, and once after boot) purges the vault as
  spec 02 §7 says: its archived versions and attachments are deleted, its items become ciphertext-free
  skeletal tombstones, and every grant row is kept with its key material blanked. It keeps the vault
  row as a **tombstone** `{finalHead, purgedAt}` **together with the vault's log rows**, readable for
  one year after the purge. Every
  account in the log's members at the `delete` keeps fetch access to that log for that year;
  `GET /vaults/{vaultId}/log` then answers with `purged: { purgedAt }` and `head` = `finalHead`. No
  entry is appended after the purge: every non-genesis append is `403 no_grant`, the owner's `restore`
  included, and a byte-identical retry of a stored frame still answers `200` (§10.3 step 5,
  `spec/test-vectors/logappend.json`). A Loki alert fires on any vault with `purgeAt < now − 2 d` and no `purgedAt`.
- A year after the purge the janitor deletes the log rows. The vault row itself stays for good, as do
  the blanked grant rows, because a vault id is never reused (§10.3 step 5).
- **What a device makes of it** is spec 02 §10.6: "deleted for good" only after it verified the log
  through `finalHead` and the verified state is deleted by the owner's signed `delete` with no later
  `restore`; anything else is withholding.
- Account deletion (§13) purges the vaults the account owned with no other members at once, with no
  tombstone log.
- The janitor also clears pending offers whose `expiresAt` has passed (the verifier's own expiry rule
  makes a late `accept` impossible either way, spec 02 §10.3).

### 11.2 Deleted vaults of the caller

`GET /vaults/deleted` → `[{ vaultId, metaBlob, wrappedVk, deletedAt, purgeAt, deleteId }]`: the
in-grace vaults the caller owned when they were deleted (ciphertext it already held), for the
"Recently deleted" list from which the owner signs `restore`. `deletedAt` and `purgeAt` are the same
stored values the log's `deleted` carries (§10.3, §10.6).

### 11.3 Rename

`PUT /vaults/{vaultId}/meta { metaBlob, baseVaultRev? }` → `200 { rev }`. Owner only
(`403 not_vault_owner`, also for a non-member); shared vaults only (`400 not_shared_vault`); not while
deleted (`400 vault_deleted`); `metaBlob` ≤ 4 KiB. `baseVaultRev` below the vault's rev is
`409 stale_meta`. A rename is not a log entry: the name is ciphertext the server cannot read, and a
rename changes no one's access. Bucket `vault_destructive`. Audited `vault_rename`.

### 11.4 Member self-wrap

`PUT /vaults/{vaultId}/grant/self-wrap { wrappedVk }` → `200 { rev }`. A device that adopted a
shared vault's key from a grant posts the key wrapped under the account's UVK with the genesis-bound
AD (spec 01 §6), so the account's other devices adopt it without needing current contacts (spec 02
§10.4).

- The caller's OWN active grant only, and never an `owner` row (`403 owner_wrap_immutable`: an owner
  wrap is set by `genesis` or `accept`); a revoked or absent grant is `403 no_grant`. `wrappedVk` is
  ≤ 1 KiB.
- Stores `wrappedVk`, keeps `signedGrant` and the role, and bumps the grant rev so the caller's other
  devices receive the row. An identical re-post changes nothing.
- The server cannot check the wrap (ciphertext under the member's UVK). A client that cannot open it
  treats the vault as "key unreadable", never as a cue to use anything else.
- Bucket `vault_self_wrap` (60 per hour). Audited `vault_grant_self_wrap`.
## 12. Recovery with the kit (per-member self-service recovery)

A member who kept their recovery kit (spec 01 §2.1, spec 04 §6) resets their own master password
without anyone's help. **Two-phase**, so the server hands out no pre-auth UVK blob, exposes no
enumeration oracle, and binds the reset to one replay-bound ticket. The two unauthenticated routes
(verify and commit) are internet-reachable
on every instance (spec 05 R10) and **per-IP fixed-window rate-limited** at ≥ login tightness — and
**that is the whole limiter: no per-account/email-keyed backoff applies here** (§8: an account-keyed
counter would let anyone lock a victim out of last-resort recovery; the recovery secret's 256-bit
entropy and the constant-time verify comparison are what stop guessing, and spec 05 T11/R9 records the
same asymmetry against login). No `/recovery/prelogin` exists: the recovery secret is high-entropy and
its derivation is HKDF-only with no server salt/params (spec 01 §2.1), so there is nothing to fetch
before phase 1. A client runs this flow only from **Sign in → Forgot your master password? → Scan
your recovery kit**, after pinning the instance from the kit's `card0Hash` (spec 04 §6).

- **Phase 1 — `POST /recovery/self/verify { email, recoveryAuthKey }`** → the server verifies
  `crypto_pwhash_str_verify(recoveryVerifier, recoveryAuthKey)`. **Anti-enumeration:** an unknown
  email OR a known email with **no** `member_recovery` row runs a fixed `DUMMY_RECOVERY_VERIFIER`
  verify and returns the same uniform `401 invalid_credentials` as a bad key — timing/shape-uniform
  across all three states, mirroring login's `DUMMY_VERIFIER`; a null/absent/malformed stored verifier
  never matches. On success **only** → mint a **single-use, short-TTL, userId-bound recovery ticket**
  (same store as the §6 WS ticket) and return `{ recoveryTicket, userId, recoveryWrappedUvk,
  encryptedIdentitySeed, identityPub }`. No UVK ciphertext is ever served before this verifier gate
  passes. `userId` is needed to open `recoveryWrappedUvk` (AD
  `andvari/v1|recovery-uvk|{userId}`) and the identity seed, and for the identity-key hard-fail.
- **Phase 2 — `POST /recovery/self/commit { recoveryTicket, newAuthKey, newKdfSalt, newKdfParams,
  newWrappedUvk, newMemberRecovery: { recoveryWrappedUvk, recoveryAuthKey }, device: { platform, name,
  deviceSecret } }`** → `200 SessionResponse` plus `recoveryPieceId`.
  - Validate the ticket (live, unconsumed → consume it; otherwise `401 invalid_ticket`). The ticket
    is single use: any commit attempt that presents it consumes it, including one whose body is
    malformed or fails a later check, and the client then runs verify again. Refuse if the
    account's `status != 'active'` (`400 recovery_account_not_active` — a disabled account is
    re-enabled by the operator first); enforce the KDF floor and shape on `newKdfParams` and the salt
    bound on `newKdfSalt` (§7.2); require `newMemberRecovery` (`400 recovery_required` if absent or
    malformed).
  - Then **one transaction**: overwrite `verifier/wrappedUvk/kdfSalt/kdfParams`; **replace the
    member-recovery row** with `newMemberRecovery` (a new `pieceId`, `users.recoveryConfirmed = 0`), so
    the scanned kit stops working at once; revoke every session; clear the stored `deviceSecret` hash
    of every earlier device of the account, so every earlier device becomes unknown (§16.8: with
    `requireLink` turned on again, each must be linked again); cancel the account's assisted-recovery
    requests (§18.4); clear `users.requireLink` and two-step sign-in (TOTP); create the device and its
    session (`how = recovered`, the device's `deviceSecret` hash stored, §16.8). Emails: `recovery_applied`, `two_step_off` when TOTP was on,
    `require_link_cleared` when `requireLink` was on. Audited `recovery_self_commit`.
  - The response is the login response plus `recoveryPieceId`, the new piece's id. The client shows
    the new kit through the capture gate (`POST /recovery/self/confirm`) before the vault opens.
  - The client's recovery routes the phase-1 unwrap through the shared UVK-unlock tail so the
    **seed-derived identity-pubkey hard-fail still fires** (spec 01 §5) before commit, and MUST NOT
    regenerate UVK / identitySeed / identityPub — `newWrappedUvk` wraps the **same** (invariant) UVK,
    so an escrow blob (if any) stays valid.
- **`PUT /recovery/self-setup` (authenticated) `{ currentAuthKey, memberRecovery }`** → `200 { pieceId }`;
  `memberRecovery` is required (`400 recovery_required` when absent or malformed)
  — the kit rotation path ("Make a new recovery kit"). Requires **fresh master-password reauth**: the
  server verifies `currentAuthKey` against the login verifier exactly like `PUT /account/password`
  (§3; a wrong key is `403 reauth_failed`, §0.1) before replacing the `member_recovery` row. A
  quick-unlock / biometric session (no password in hand) cannot call it. Audited
  `recovery_self_setup`. Every setup (and every register and recovery commit) mints a fresh, opaque,
  server-side **`pieceId`** (random, `ServerCrypto.newToken`) stored on the `member_recovery` row
  together with the committing **`setupDeviceId`**. Because a setup ROTATES the piece, it also clears
  `users.recoveryConfirmed` to 0: the flag always describes the CURRENT piece.
- **`POST /recovery/self/confirm` (authenticated) `{ pieceId? }`** → `ok` — flips the durable,
  cross-device `users.recoveryConfirmed` flag to 1 after the person demonstrably typed back the three
  groups of the revealed kit (spec 04 §6). The flag flips ONLY here — never at register, setup or
  commit. **Piece binding:** a confirm carrying `pieceId` is accepted iff it equals the CURRENT row's
  `pieceId`; otherwise `409 recovery_piece_stale` — the client must discard the shown kit as invalid
  and re-run setup + reveal. A body-less confirm is accepted only when the current row's
  `setupDeviceId` is the caller's device. Audited `recovery_self_confirm` /
  `recovery_self_confirm_unbound` / `recovery_self_confirm_stale`. An empty body parses as
  `pieceId = null`.

**Errors:** `recovery_required` (register, commit, setup); `recovery_account_not_active` (commit);
`recovery_piece_stale` (`409`, confirm — stale or foreign-device piece); `invalid_ticket` (`401`,
commit); every verify failure is the uniform `401 invalid_credentials`. Audit types:
`recovery_self_commit`, `recovery_self_setup`, `recovery_self_confirm`,
`recovery_self_confirm_unbound`, `recovery_self_confirm_stale`. Stored surface: table
`member_recovery` (`pieceId`, `setupDeviceId`) and `users.recoveryConfirmed` (ZK contract: spec 02 §5).

## 13. Account deletion

Self-service, from inside the app (store policy: Google Play User Data, App Store 5.1.1(v)); design
`docs/design/2026-11-10-account-deletion.md`, amended by the onboarding and trust design (the leaves).
The operator's deletion of a long-disabled account is §7.1: the same transaction **without leaves**.
Both routes below are authenticated (a §2 restricted session is refused like every route: enroll,
then delete) and version-checked. Table `retired_ids` (below; spec 02 §5).

- **`GET /account/delete/preview`** → `{ blockers: [AccountDeleteBlocker], deletedVaults: [vaultId], leftVaults:
  [vaultId], memberships: [{ vaultId, head }], totpRequired }`. A snapshot of what a deletion would do now, so a client can show the blockers and the
  consequences before it asks for the master password: `deletedVaults` (sorted) are deleted with the account,
  which are the personal vault, every vault only the account holds, **and every vault it deleted that is still in
  its grace** (design 2026-11-10 §2 and §3.1: nobody else can restore one, so it is purged now, not at its
  `purgeAt`). **What a client says (2026-11-16):** a vault of `deletedVaults` that is in the caller's
  `GET /vaults/deleted` (§11.2) is one the person already deleted; it is not counted among the vaults "only you
  hold", but named from that list's own `metaBlob` and said apart: that it is in the recently deleted list, could
  still be restored until its `purgeAt`, and goes for good with the account now. A vault in neither the device's
  store nor that list is counted as "other vaults only you hold", as before.
  `leftVaults` (sorted) are memberships it drops, `totpRequired` means the deletion must carry the current code. The
  deletion re-checks everything inside its own transaction. No rate bucket (a read, like the members GET).
  `memberships` lists exactly the vaults that need a leave: every shared vault where the account holds a **non-owner
  grant row** that is active or revoked with reason `vault_delete` (a vault in its grace), whether or not the deleting
  device ever adopted it, each with its stored log `head` `{seq, hash, at}`.
- **`POST /account/delete { confirmEmail, currentAuthKey, totp?, leaves: [frame…] }`** → `200 { deletedAt }`.
  `leaves` holds exactly one `leave` entry (purpose 0x03, spec 02 §10) for every vault in the preview's `memberships`,
  each built at the served head with `at = max(device clock, head.at)`. The deleting device need not have verified
  that vault's log: the leave is the account's own statement, and the head check places it. **From an unverified head
  a device refuses a `head.at` more than one day ahead of its own clock**: it signs nothing, and the deletion stops
  with "One of your shared vaults reports a time far in the future. Try again later." At most 500 leaves
  (`400 bad_leaves`); the route's body cap is 1 MiB. The gate runs outside the
  writer lock, in this order, the first failure deciding (the order the server keeps, step by step):
  0. The route's bucket (`account_delete`, `429 rate_limited`), then the body's shape (§0.1), and then its leaves'
     own shape: more than 500, or one longer than a log entry may be (§10.3), is `400 bad_leaves`. These read
     nothing the server stores about the account.
  1. `confirmEmail` — the address the human typed — must equal the account's, trimmed and lowercased:
     `400 confirm_email_mismatch`. The typed confirmation therefore binds every client.
  2. `currentAuthKey` is verified against the login verifier exactly as `PUT /account/password` verifies it (§3) — the
     fresh master-password proof — on the proofs' back-off (§8: `429 rate_limited` with the device's remaining wait). A miss is
     `403 reauth_failed`, audited `account_delete_reauth_fail` — a 403, never a 401, which would send a client into a
     token refresh. A proof that matches a credential other than the one the gate read for the account (the password
     was changed or recovered between the two reads) is `401 credential_changed`, audited the same with meta
     `credential_changed`.
  3. An account with server TOTP enrolled must then send the current `totp`. A missing one is
     `400 totp_code_required`; then come the `totp_verify` bucket and the codes' back-off (§2, §8: `429`); a wrong or
     already-used step is `400 bad_totp_code`, audited `totp_verify_fail` (meta `account_delete`). These are the
     authenticated rotation gate's codes (§2), not login's 401s. The step is verified here and **consumed inside the
     transaction**, so two requests with one code cannot both pass.

  **The password is checked before the code** (rule of 2026-11-16, as for turning two-step sign-in off, §2). Checked
  first, the code would tell a session in the wrong hands whether it was right (`bad_totp_code` against
  `reauth_failed`). With the proof first, a wrong or missing proof gets the same answer whatever the code, and the code
  is neither counted, recorded nor consumed; guesses at the password are bounded by the proofs' back-off. The typed
  address comes before the proof because it tells the session only what it can read for itself (§0.1).

  Then **one transaction**: the verified credential must still be the account's and the calling session still live —
  else `401 credential_changed` (a password change, a recovery or a revocation committed in between; audited
  `account_delete_reauth_fail`, meta `credential_changed`) —, the TOTP step is consumed (a step another request
  consumed in between is `400 bad_totp_code`), the refusal rules below are evaluated, the leaves are matched to the
  memberships (a leave that does not parse, names no vault of `memberships`, or names a vault twice is `400 bad_leaves`) and appended
  (below), and only then is anything deleted. Either every change below commits or none does.

  **Refusal rules** (owner decisions) → `409 account_delete_blocked`: the §8 error fields plus `blockers`, each
  `{ kind, vaultId?, others }`, in a stable order; audited `account_delete_denied` (meta: the kinds) in the transaction,
  which commits — with the consumed TOTP step — before the refusal is returned.
  - `shared_vault` (one per vault; `vaultId`, `others`) — the account holds an **active owner grant** to `vaultId` and
    `others ≥ 1` other accounts hold active grants to it. The member deletes the vault or hands it over (§10), then
    retries; a vault in its grace window no longer blocks (it is purged with the account, below).
  - `operator` (`others = 0`) — the account is the instance's operator. The operator account cannot be deleted while it
    is the operator; a signed card handover (§17.2) makes another account the operator first.
  A client MUST show a `kind` it does not know as a blocker it cannot explain, and MUST NOT offer to proceed past it.

  **The leaves.** Inside the transaction, after the refusal rules, the server appends the leaves under §10.3's checks,
  **exempt from every rate bucket**, before it removes the grants. A missing, stale or invalid leave — any refusal
  §10.3 would give it except `at_ahead` — refuses the whole deletion with `409 account_delete_log_stale {vaultIds}`,
  naming every vault whose leave failed; the client refetches the heads (the preview) and retries. A leave whose `at` is
  more than 10 minutes ahead of the server's clock refuses it with `400 at_ahead` instead, so a device with a fast clock
  is told to fix it rather than retrying. Nothing is deleted on either refusal. Members' logs therefore always show
  the account leaving, signed by itself.

  **Effect.**
  - Every session and device of the account is deleted (which revokes them: refresh, the bearer and the §6 socket
    re-check all find nothing), with the idempotency journal of every device it had — a device row the janitor already
    pruned included (journal rows carry the pushing account since schema v17); every open socket of the account gets
    `{"type":"revoked"}` and is closed (§6 — no new frame).
  - **Every vault the account alone holds is purged now**, with the janitor's statements and no grace: its personal
    vault, every vault it owns that no other account holds an active grant to, and a vault it soft-deleted that is still
    in grace (only the deleting owner could restore it). A purged shared vault keeps **no** tombstone log when no other
    account could still fetch it; a vault in grace whose log names other members keeps its tombstone and log rows for
    a year, exactly as a janitor purge does (§11.1), so those members can still verify the owner's `delete`. Item rows become ciphertext-free tombstones (no rev bump; they
    age out through spec 02 §7's 30-day rule), archived versions and attachment rows are deleted and the blob files
    unlinked after the commit (a crash in between leaves rowless files the orphan sweep removes), every grant's key
    material on the vault is blanked, and the vault row stays as a purged tombstone (`metaBlob` blanked, `deletedBy`
    cleared) — a `vaultId` is still never recycled.
  - **Memberships elsewhere are dropped** after their leaves are appended: the account's grant rows go (spec 02 §7's
    grant-retention rule excepts a deleted account's own rows, which reference the deleted user row); the items it
    wrote there stay. Co-members get a `rev` bell. (After an operator deletion, which appends no leaves, the account
    stays in those logs' members with no grant, §7.1.)
  - The account's `connections` rows (§15.8) are deleted, for self-deletion and operator deletion alike, with its
    links rows (created or answered), device-link rows and assisted-recovery requests. An assisted-recovery request
    whose mailed code was not entered is not deleted: it becomes a decoy (its account, code MAC and cancel mark
    cleared) until it expires, so its poll does not change with the deletion (§18.4); every other request of the
    account is deleted.
  - The account's `escrow`, `member_recovery`, `usage_ledger`, `account_state`, `personal_wrap` and genesis rows are
    deleted: neither recovery path (spec 04) survives a deletion.
  - `vaults.deletedBy` is cleared wherever it still names the account. After the deletion no column of the database
    holds the account's userId or the id of any of its devices (audit, below), and its address is held only by the
    `account_deleted` (or `account_deleted_by_operator`) message in the mail outbox until it is sent, at most 24 hours
    (§14.5; spec 05 R31).
  - The user row goes last. The address can then register again, through sign-up or a link, as a **new account** — new
    userId, new keys, an empty vault; nothing of the old one is reachable from it. Log entries the old account signed
    stay in other vaults' logs, under its old userId and key.
  - **Both ids are retired for good.** The client chooses its userId at `POST /auth/register` (the AEAD ADs bind it), so
    the deleted userId and the audit pseudonym (below) are kept as lowercase-hex SHA-256 in `retired_ids`, and register
    refuses either as `409 user_id_taken`, exactly like a live one: re-registering the old id would revive every lookup
    of it, and an account registered under the pseudonym would have its own security rows erased by the 90-day purge.
    The digest answers "was this id retired?" only for someone who already holds the id, and the table keeps no date.
    The address may register again at once; a registration naming either retired id is `409 user_id_taken` under any
    address; the deleted account's tokens are answered as tokens never issued (`401 invalid_credentials`,
    `401 invalid_refresh`), and its vault, device and account ids as ids that never existed (shown by tests on
    2026-11-19).
  - Key material and ciphertext were destroyed in place, so the WAL is checkpointed and truncated after the commit (the
    spec 04 §3 rule for every key-destruction path).

  **Audit (owner decision: security events kept 90 days with the email removed).** At deletion the server mints a
  fresh random UUIDv4 **pseudonym** — not derived from the userId or the email, and stored nowhere as a mapping, so
  nothing on the server reverses it; shaped like a userId so every client's id grammar (spec 05 R18) renders it. The
  account's own rows of the retained security types (sign-in, session, credential, second-factor, recovery, denied-write,
  operator-action and deletion types, and the revocations it made — `vault_member_remove`, `vault_member_leave`,
  `vault_delete`; the list is `AccountDeletion.RETAINED_AUDIT_TYPES`) are re-keyed to the pseudonym. Its vault, item and
  sharing activity is re-keyed too when the vault the row names OUTLIVES the deletion — an item it purged from a shared
  vault's trash, a file it uploaded there, the history of a vault it handed over: the data is still there, and so is the
  record of who touched it — and deleted when the vault is one this deletion purges (`VAULT_SCOPED_AUDIT_TYPES`). Its
  lookups and recovery-capture confirmations are deleted. The userId is replaced by the pseudonym in every other
  account's row that names it in meta, and those rows keep the ordinary retention. Each of the account's device ids —
  its `devices` rows, the deviceId on its own audit rows and on its journal rows, so a device row the janitor pruned
  (90 days without a session) still counts — is replaced, in every row naming it — its own and other accounts', such as
  the operator's `operator_device_revoke` —, by a fresh random id of its own, the same in each row, so a kept record still shows
  which events came from one device; the deviceId of the account's `operator_device_revoke`/`device_revoke_denied` rows
  is the TARGET of an operator action, another account's device, and is left alone. The operator's own device named
  in an `operator_device_revoke` row's `by=` is one of the operator account's device ids (also when its device row was
  pruned) and gets that device's new id there. The deletion's own row is `account_delete`
  (userId = the pseudonym, deviceId = the deleting device's new id, meta `vaults=N,left=M`). The janitor deletes every
  row under a pseudonym **90 days after that account's deletion** (the `account_delete` row is the clock); the ordinary
  rule deletes audit rows 365 days after they were written. A row a racing request writes after the deletion naming the
  gone userId is stored without anything that names the account (userId, deviceId and ip null, meta prefixed
  `deleted_account`), and an operator route given an id that names no account or device records the attempt without the
  id (`operator_escrow_read`, `operator_disable_denied`, `device_revoke_denied`), so a screen opened before the deletion does
  not write a deleted id back. No audit row carries an email (spec 02 §5).

  **Rate limit:** `account_delete`, 5 per hour per device, with the ceiling per account of §0.1 (each attempt is a
  memory-hard verify, and each reauth route is another password guess for a session holder); a request carrying a
  code also draws on `totp_verify` (§2), per device as well. Kept per account, as it was before 2026-11-17,
  five requests an hour from a held session kept the owner from deleting the account. **A refusal over
  a moved log costs the person nothing, and the ceiling keeps every try** (rules of 2026-11-17): on
  `409 account_delete_log_stale` the server gives back what the deletion drew from the device's
  budgets (its own and the code's), since nothing about the person was decided; a give-back works
  once for a draw. The account's ceiling for deletions (20 an hour) is drawn before the password is
  judged and is never given back, whatever the refusal, so past it a try is `429` before the
  password is checked: a caller can produce that refusal at will (by leaving a
  leaf out), and without a draw that stays, a caller with the right password could send it without
  end, each try running the password's hash, and keep the server's hashing permits busy for
  everyone's sign-in. The same holds for every give-back the server has: something that is not given
  back always stands in front of the expensive work. The server keeps this since 2026-11-18.

  **Client duties.** Before the request: show what is deleted and left (the preview), any blockers with a way to resolve
  them, and require the typed address, the master password (derived through the client's fenced reauth, so a wrong one
  is caught locally), the leaves (one per `memberships` entry, built at its served head), and the code when
  `totpRequired` — or once the server answers `totp_code_required` (TOTP enrolled
  after the preview was fetched): the client then asks for the code rather than leaving no way to send one. On `200`:
  wipe this device's state for the account — session and tokens, the offline cache, every device-local record keyed by
  the userId — **including the spec 01 §5 self-identity records** (the userId-keyed pin, and the email binding when it
  names that userId), then land signed out. A transport failure, no answer within the client's deadline (the web client
  gives the request 60 s), any `5xx`, or a reply that is not the server's JSON (a proxy's error page; a `200` without
  `deletedAt`) leaves the outcome unknown — the transaction may have committed — and MUST NOT be reported as either
  success or failure; the client offers to check (the preview answers `200` while the account exists). A session end
  that arrives while the request is in flight (the `revoked` frame the deletion itself sends, a refused refresh) is held
  until the request settles — so it cannot land the client signed out before it knows the outcome — and is then always
  acted on, never dropped: after a refusal it is an ordinary sign-out; after an unknown outcome it was most likely the
  deletion's own, and the client signs out offering to forget the account on that device (the same wipe as after a
  `200`) or to sign in and check. Any OTHER session end after an unknown outcome — a `401` on the check or on a retry, a
  revocation that lands later — MUST NOT be read as the deletion: the operator's revocation or disable, a recovery and a
  password change elsewhere end a session too. The client signs out saying the account may still exist and keeps the
  spec 01 §5 self-identity records, which exist to catch exactly an account that changed under that device. All of this
  is about the account that sent the request: another account's session end is never held or offered as the
  deletion's, and a new session (an unlock, a sign-in) does not inherit an unknown outcome.

  **A confirmed deletion leaves the device as a fresh install for that server** (rule of 2026-11-17, every app; the
  released line has done so since the owner's decision of 2026-11-15). Everything the device keeps under the server's
  origin goes, as "Forget this server" removes it, whoever's it is: the copy, the keys, what waited to be sent, the
  records of the account's identity and address, the names kept for links, the quick-unlock key, the mirrors of the
  policy, and the server's own pin and address. Another origin is never touched. The next start is the first launch
  (or the first screen, where another server is still known). The same removal is "forget the account on this device",
  which the notice after a deletion whose outcome is not known offers behind a confirmation; it is not the forgetting of
  an EARLIER account under a known address (spec 01 §7), and both exist. On iOS the app with no server left tells its
  extensions so, and the Safari extension then forgets the server it had adopted from the app. The owner confirmed on
  2026-11-18 that nothing stays. The notice that the account was deleted is built before the pin goes, and its
  sentence does not presume that the server stays known. **After a deletion whose outcome is not known**, the person can
  forget the account on the device behind a confirmation: the same removal as after a confirmed deletion, for exactly
  that account at that server, and the device ends that session at its server. Afterwards the first screen says
  nothing of whether the account was deleted (rule of 2026-11-19: the device has forgotten the account and will never
  learn it, and the person was told so at the confirmation); the desktop keeps this; **not kept yet (2026-11-19):** it
  is not established as built on the phone, whose first screen said that andvari cannot tell yet. **What each removal takes** (rules of
  2026-11-19): forgetting after an unknown outcome removes exactly that account from the device and keeps what the
  device knows of the server (the account may still exist, and other accounts of that server on this device stay),
  where a confirmed deletion forgets the server too. What the device knows of that account's vaults stays, as at a
  sign-out, so that a later sign-in is protected against an older state; changes to shared vaults that were signed and
  not sent go, as the confirmation says of every change not sent (kept, they would be sent by the next action on that
  vault after a later sign-in, unasked), and the confirmation says how many there were, or that it cannot tell. The
  request to end the session is made once; where it fails, the session stays listed at the server until it expires,
  for a device that no longer holds its token, and is then ended from another device; if the account turns out to be
  deleted, "Forget this server" removes the rest. A confirmed deletion never takes another account's copy unsaid: where
  another account's copy is held at that server, it removes the deleted account's records only, the server stays
  known, and the notice does not say that the server was forgotten. A standing notice that a kit is gone for that
  account's address goes with a confirmed deletion and with "Forget this server", with its marks at rest, which carry
  the server's address so that the server's forgetting takes them like every other record of it. An account's deletion
  on the device removes everything the shared code keeps for the account, the trust records of its vault logs
  included (a sign-out keeps those, §10.3). **A confirmed deletion forgets the server only where this device keeps
  nothing of another account there** (decided on 2026-11-19, which narrows the owner's answer of 2026-11-18 for that
  one case and extends the rule above from a kept copy to every record of another account at that server: a copy, a
  device row, trust records, an address's record): otherwise the deletion removes the deleted account's records only,
  the server stays known for the other account, and the app says so. A kept record of an earlier account's identity
  key at that server, which a forgetting keeps, counts as something of another account (rule of 2026-11-19): the
  deletion of the account taken in its place keeps the server and that record, and says that the server was kept, so
  that the earlier account is never taken afterwards under another key (the shared code and the web client keep this
  since 2026-11-19, the web client because it never forgets the server at a deletion; the shared code's notice then
  says that the device holds another account's copy there, which is untrue where only a record of another account's
  key, a device's row or an address's record is kept: it is to say only that the device still keeps something of
  another account at that server, not kept yet on 2026-11-19).
  **"Forget this server" removes every record this device keeps for that server, of every account
  there** (rule of 2026-11-19), the session keeper's records of which account an address is and of each account's
  identity key included. **Forgetting after an unknown outcome keeps the device's records of which account the address
  is and of that account's identity key, as a sign-out does** (rule of 2026-11-19): the account may still exist, and a
  server can produce the unknown outcome by ending the session during the request; only a deletion the server
  confirmed removes them. **What is kept (2026-11-19):** the shared code forgets the server after a confirmed deletion
  only where this device keeps nothing of another account there; "something of another account" is another account's
  held copy, a device row or an address's record of another address at that server, or a record kept for that server
  under another account's id, and a store that cannot list its records counts as keeping something (the server stays
  known). Otherwise it removes the deleted account's records only, keeps the server and its pin, and says so in the line
  it hands the screens; the deleted account's copy is deleted once. A standing notice that a kit is gone and the kept
  session's mark are records of their server, kept under its address, and go with a confirmed deletion or the server's
  forgetting; the kept session's mark holds no server address in its value, so it reads the same after a followed move,
  which carries the kit's marks to the new address and leaves nothing under the old one. The test that nothing stays
  reads every key and every value of both stores. After an unknown outcome it offers the forgetting behind a
  confirmation that counts exactly the signed changes it removes (every held change the device keeps for the account,
  also one its index does not name; an index entry with no record holds nothing to send and is not counted), the
  signed changes to shared vaults that waited among them, and a changed count makes a new confirmation; it closes the
  copy before it removes them; the vaults' trust records stay, and the request to end the session is made once. Both
  apps draw that forgetting since 2026-11-19, on the deletion's screen, the lock screen and the first screen, in two
  steps of equal weight, neither the default nor bound to a key: the second step is only for the very offer that was
  asked, is closed at a lock, at a change of screen and whenever the shared code hands a new offer (with its count), and
  the forgetting comes only from the person's own tap or click on it, never tried again. The web client
  keeps the keeper's records after an unknown outcome (2026-11-19). The Safari extension forgets the server it took
  from the app once the app itself answers that it has none, the remembered address with it, and stands as on a first
  install; no answer, or one that is not the app's own, forgets nothing (2026-11-19). The older controller the iPhone
  app runs on forgets the deleted account's identity records after a confirmed deletion, and wipes the account whatever
  ended the session while the request was out, under the session's own origin (2026-11-19). **Not kept yet
  (2026-11-19 unless dated):** "Forget this server" leaves the keeper's records of an address's account and of an
  identity key (one stays while an address at another server names the account), and whether those records follow a
  server's move is not established (a followed move neither removes nor carries the keeper's records of an address's
  account and of an identity key); an engine for vault
  logs that could not read the store when it began can still write after a forgetting; the older controller
  keeps the server's address (2026-11-18). Closed on 2026-11-19: the shared code's forgetting after an unknown outcome
  keeps both of the keeper's records (which account the address is, and that account's identity key); a send in flight when the person confirms writes
  nothing when its answer comes (every record write of the log engine first checks, under one lock with the
  forgetting, that the account's records still stand); the web client after a deletion the server confirmed
  keeps nothing that names the account or its address (a policy wipe's notice still owed is kept under a key of its
  own and said once), keeps the server's pin, and keeps a forgotten earlier account's key record through the
  confirmed deletion of the account taken in its place, so that earlier account under another key stays refused; its
  card for a deletion whose answer was lost says what its forgetting removes and what stays, with no confirmation of
  its own (the copy has already gone with the sign-out, and what it removes are settings). That the browser keeps the
  pin is accepted as built (it stands at that server's own address, and a pin kept is a check kept) and put to the
  owner as a proposal, since his answer of 2026-11-18 says that nothing stays, for every client. A confirmed deletion no longer forgets the server
  where another account only signed out there; the count no longer misses a held change outside the index; the kept
  session's mark no longer carries the server's address; a deleted account's copy is no longer deleted twice; both
  apps draw the forgetting after an unknown outcome.

**Errors:** `confirm_email_mismatch`, `totp_code_required`, `bad_totp_code`, `bad_leaves`, `at_ahead` (400);
`reauth_failed`, `totp_enrollment_required` (403); `credential_changed` (401); `account_delete_blocked` (409, with
`blockers`); `account_delete_log_stale` (409, with `vaultIds`); `rate_limited` (429); `upgrade_required` (426). **Audit
types:** `account_delete`, `account_delete_denied`, `account_delete_reauth_fail`, `account_delete_stale` (a deletion
refused `409 account_delete_log_stale`: one record per account per hour, never one per refused request, meta
`vaults=<how many vaults the refusal named>`; §8). The account's security records kept and pseudonymised at its
deletion include `login_wait`, `reauth_wait`, `totp_verify_wait` and `account_delete_stale` (2026-11-18).

## 14. Sign-up, registration, cap and quotas

### 14.1 Sign-up: start

`POST /signup/start { email, ageConfirmed, pow? }` → `202 { "status": "sent" }`.

- `email` is an `emailText`; `ageConfirmed` a boolean; `pow`, when present, `{ date, nonce }`: `date`
  the UTC date the client hashed, as `YYYY-MM-DD`, and `nonce` an `int`.
- **Proof of work.** When `signup.powBits > 0`, the request needs `pow` such that
  `SHA-256("andvari/v2|signup-pow|" + emailNorm + "|" + date + "|" + nonce)` (UTF-8, `nonce` in
  decimal with no leading zeros) has `powBits` leading zero bits, counted from the most significant bit
  of digest byte 0, then byte 1, and so on. The server accepts today's or yesterday's UTC date and is
  otherwise stateless about it. With `powBits = 0` a `pow` is ignored.
- **Checks, in order:** the per-IP bucket (`429 rate_limited`); the effective mode is not `open`
  (`403 signup_closed`); the effective cap is reached (`403 signup_full`); the address has no
  `emailNorm` (`400 invalid_email`); its domain is on `ANDVARI_SIGNUP_BLOCKLIST`
  (`400 email_domain_blocked`, checked before any account lookup and identical for every address in
  the domain: it reveals the domain policy, never whether an address is registered); `ageConfirmed` is not `true` while `ageConfirmRequired`
  (`400 age_confirm_required`); a proof of work is required and missing (`400 pow_required`) or wrong
  (`400 bad_pow`); the per-address bucket (`429 rate_limited`); the mail outbox is stalled (§14.5,
  `503 mail_unavailable`, for every address alike).
- **Otherwise the answer is always `202 {"status":"sent"}`**, whether or not the address has an
  account:
  - the address has an account: the `signup_existing` email goes out, at most once a day per address;
  - otherwise a uniformly random 6-digit code is stored as `signup_codes(emailHash = the address's
    keyed hash (spec 02 §5), codeMac, expiresAt = now + 15 min, attempts = 0)`, with
    `codeMac = HMAC-SHA-256(signupSecret, "andvari/v2|signup-code|" + emailNorm + "|" + code)` and
    `signupSecret` the 32 bytes of `ANDVARI_SIGNUP_SECRET`, and the `signup_code` email is sent. A new
    code replaces the previous one for that address.
- Audited `signup_start` (meta: a prefix of the address hash). Clients compute a proof of work in a
  background thread with a progress note; 20 bits is about a second on a phone.
- **A request refused before anything is sent costs its caller nothing** (rule of 2026-11-17): the
  first step finds that no mail can be sent before it draws the address's and the caller's
  allowances, or gives the draws back; and a draw made inside its transaction comes back when the
  transaction fails. **A give-back never removes every limit, here too** (rule of 2026-11-17): in
  front of the start's allowances stands `signup_start_ceiling`, 30 an hour per address (ten times
  its hourly allowance), which is never given back. So a start refused with `503 mail_unavailable`
  gives back the caller's `signup_start` and `signup_start_day` and the address's draw, but not that
  ceiling, so that an operator's mail fault does not lock an honest person out and still nobody can
  send starts without end; the at-most-one-a-day notice to an existing account is spent only when
  the start's transaction commits. The server keeps this since 2026-11-18.
- **What the records keep of an address is keyed** (rule of 2026-11-17): the prefix in the audit
  rows of the sign-up's first steps (and in the system's journal), and the hash a decoy recovery
  request keeps for its day (§18.1), are of a hash keyed with a secret of the server's, so that
  they still tie rows together and tell an outsider nothing. A plain hash lets whoever reads them
  confirm a guessed address, of people with no account too. **Kept since 2026-11-18:** every record
  the server keeps of a typed address, other than an account's own address and a queued mail's
  recipient, is the address's keyed hash, `hexLower(HMAC-SHA-256(K, "andvari/v2|address|" +
  emailNorm))` with `K = HMAC-SHA-256(enumSecret, "andvari/v2|address-record-key")` (spec 02 §5):
  the sign-up's audit rows and their journal lines, sign-up codes and tickets, recovery requests
  real and decoy, mailbox values, and enrol links bound to an address. The key is derived under a
  label of its own from the secret the instance already holds for its decoy answers, so it shares
  nothing with the values that secret serves to anyone. Rows written under an earlier enumeration
  secret (after a restore beside another env file, or a changed secret) no longer tie to new rows.
  The plain hash is written nowhere; it keys the limits in memory only. A sign-up code or ticket
  from before the upgrade no longer matches (they live minutes; the person asks for a new code);
  a mailbox value and an enrol link from before it are still found in their earlier form until
  they expire.

### 14.2 Sign-up: verify

`POST /signup/verify { email, code }` → `200 { signupTicket, expiresAt }`, or a uniform
`400 bad_code` whatever the cause: no code, wrong code, expired, or attempts used up. Each wrong code
increments `attempts`; at 5 the code is dead. `signupTicket` is 32 random bytes as `b64_32`; the
server stores its SHA-256, bound to `emailHash` (the keyed hash), valid 30 minutes (`expiresAt`, `ms`), single use. A
wrong code is audited `signup_verify_fail`.

### 14.3 Register

`POST /auth/register`:

```
{ "auth": {"signupTicket": <b64_32>}
        | {"link":  {"linkId": <b64_16>, "registerToken": <b64_32>, "answer": <envelope>}}
        | {"enrol": {"linkId": <b64_16>, "registerToken": <b64_32>}}
        | {"setup": {"linkId": <b64_16>, "registerToken": <b64_32>}},
  "email": <emailText>, "displayName": <text>, "userId": <uuid>,
  "kdfSalt": <b64>, "kdfParams": {…}, "authKey": <b64>, "wrappedUvk": <envelope>,
  "identityPub": <b64_32>, "encryptedIdentitySeed": <envelope>,
  "genesis": <frame 0x05>,
  "personalVault": {"vaultId": <uuid>, "wrappedVk": <envelope>, "metaBlob": <envelope>},
  "personalWrap":  {"vaultId": <uuid>, "wrappedVk": <envelope>},
  "memberRecovery": {"recoveryWrappedUvk": <envelope>, "recoveryAuthKey": <b64>},
  "recovery": {"posture": "private"} | {"posture": "operator", "escrow": {"sealed": <sealed>, "fingerprint": <hex64>}},
  "ageConfirmed": <bool>,
  "device": {"platform": <platform>, "name": <text>, "deviceSecret": <b64_32>} }
```

`auth` has exactly one key. `answer` (a register link only) is the link answer of §15.1, at most 2,732
characters. The client chooses `userId` (the AEAD ADs bind it). Key-material caps are as before:
`wrappedUvk`, `wrappedVk` and `recoveryWrappedUvk` ≤ 1 KiB, `metaBlob` ≤ 4 KiB,
`encryptedIdentitySeed` ≤ 1 KiB.

**The server checks, in order; the first failure is the answer:**

| Step | Check | Refusals |
|---|---|---|
| 1 | Shapes and key-material caps; the KDF floor and shape on `kdfParams` (§7.2) and the salt bound on `kdfSalt`; `memberRecovery` present and well-formed | `400 bad_request`, `400 bad_<field>`, `400 kdf_too_weak`, `400 kdf_mem_not_kib_multiple`, `400 bad_kdf_salt`, `400 recovery_required` |
| 2 | The `auth` kind is allowed now. `setup`: only while **no** account has `role = operator` (before the first setup, or after `reset-instance-identity` demoted the old operator, §17.5). Setup is exempt from the mode. Every other kind waits for card 0: until the instance has a stored card. Then by the effective mode: `open` takes a ticket, a register link or an enrol link; `links` a register link or an enrol link; `closed` an enrol link only. | `403 setup_done` (setup with an operator); `409 setup_incomplete` (any other kind before card 0); `403 signup_closed` (a kind the mode does not take) |
| 3 | The ticket: known, unexpired, unused, and its `emailHash` equals the keyed hash of `emailNorm`. Or the link row: `linkId` known and not revoked, the stored `tokenHash` equal to `b64url(SHA-256(ASCII(registerToken)))`, its `kind` matching the `auth` key (`link` ↔ `register`, `enrol` ↔ `enrol`, `setup` ↔ `setup`), `state = open`, unexpired, and for an enrol link minted with `--email`, the keyed hash of `emailNorm` (or, for a link minted before 2026-11-18, `hex SHA-256(emailNorm)`) equal to its `boundEmailHash` | `400 bad_ticket` (uniform: unknown, expired, used, or for another address); `404 link_unknown` (unknown, revoked, or a token that does not match); `409 kind_mismatch`; `409 link_used`; `410 link_expired`; `403 email_mismatch` |
| 4 | Age confirmation, when `ageConfirmRequired` | `400 age_confirm_required` |
| 5 | The cap (counted inside the transaction, §14.4) and the daily maximum. Setup is exempt from both. An enrol link counts against the cap, not against the daily maximum | `403 signup_full`; `429 signup_daily_max`, with `Retry-After` the time to the next midnight UTC (§8, "The waits a refusal names") |
| 6 | The email is not taken; `userId` is new and not retired (§13); `personalVault.vaultId` is unused | `409 email_taken`; `409 user_id_taken`; `409 vault_id_taken` |
| 7 | The genesis (spec 01 §5.4): purpose 0x05 and the strict parse; `ed25519_pk_to_curve25519(signerPub)` equals `identityPub`, and so does `identityKey`; its `userId` and `personalVaultId` equal the body's; its `instanceId` is this instance's | `400 bad_genesis` |
| 8 | The recovery posture (§3.1's rules): `private` with an escrow; `operator` while the stored card's `recoveryFp` is `none` (and always before card 0, so for setup), on a `public` instance (§18.6), or with a malformed escrow or a `fingerprint` other than the card's `recoveryFp`, or a copy whose size is not the version-3 size for the account's address (§3.1) | `400 escrow_not_allowed`; `400 operator_recovery_unavailable`; `400 bad_escrow`; `400 escrow_wrong_form` |
| 9 | `personalWrap.vaultId = personalVault.vaultId = genesis.personalVaultId` | `400 personal_vault_mismatch` |

Steps 1 to 6 are checked, reading only, before the server does any memory-hard hashing (of `authKey` and of
`recoveryAuthKey`), and again inside the transaction, with the same answers in the same order. So a
registration that one of them refuses, an address already taken among them, costs the server no hashing (2026-11-17).

**Then one transaction:**

- create the user (`role = operator` for setup, `member` otherwise; the genesis; the recovery mirror),
  the personal vault (`type = personal`) and its owner grant, the personal wrap, the member-recovery row
  (a fresh `pieceId`, `recoveryConfirmed = 0`), and the escrow row when the posture is `operator`;
- consume the ticket, or move the link to `answered` with `answererUserId` = the new account and
  `answeredAt`; for a register link also store `answer` and write the `connections` row for the
  link's creator and the new account (§15.8);
- create the first device (`how = registered`, the `deviceSecret` hash) and its session.

The response is `SessionResponse` (§2) plus `recoveryPieceId`, the register-committed piece's id, which
the enrolling client presents to `POST /recovery/self/confirm` once the person has typed back the kit
(§12). Audited `register` with the `auth` kind.

### 14.4 Cap, quotas and the sign-up variables

| Variable | Values | Default |
|---|---|---|
| `ANDVARI_SIGNUP_MODE` | `open`, `links`, `closed` (§1.1). `open` refuses to start without a mail transport. | `links`; the public instance uses `open` |
| `ANDVARI_SIGNUP_CAP` | active member accounts allowed | 200 |
| `ANDVARI_SIGNUP_DAILY_MAX` | new accounts per UTC day | 25 |
| `ANDVARI_SIGNUP_SECRET` | 32 random bytes, base64url, for code MACs | generated by `andvari setup` |
| `ANDVARI_SIGNUP_POW_BITS` | leading zero bits of the proof of work (§14.1) | 0 |
| `ANDVARI_SIGNUP_BLOCKLIST` | path to a file of refused email domains, one per line | unset |
| `ANDVARI_REQUIRE_AGE_CONFIRM` | `1` requires `ageConfirmed: true` | 0; the public instance uses 1 |
| `ANDVARI_INSTANCE_KIND` | `public` or `private`; carried in the card (§17) | `private`; the public instance uses `public` |
| `ANDVARI_REGISTER_LINKS` | `operator` or `members`: who may create register links (§15.2) | `members` on private instances, `operator` on public ones |
| `ANDVARI_TEST_MODE` | `1` enables the mail sink and the test clock. The server refuses to start with it unless `ANDVARI_CANONICAL_ORIGIN` is `http://localhost[:port]` or `http://127.0.0.1[:port]`. | 0 |
| `ANDVARI_MAIL_SINK` | test mode only: a directory where each outgoing email is written as one JSON file `{template, to, subject, text}` instead of being sent | unset |
| `ANDVARI_TEST_CLOCK` | test mode only: a file holding a millisecond timestamp the server uses as "now" | unset |

**The cap** counts accounts with `role = member` and `status = active`: the operator, disabled and
deleted accounts are excluded. The effective cap is `min(ANDVARI_SIGNUP_CAP, the operator's stored
cap)` and the effective mode the stricter of the environment's and the operator's (§7.2).

**The daily maximum** counts the accounts created today (the UTC day) whose `registeredVia` (spec 02 §5)
is `ticket` or `link`; enrol and setup registrations are not counted. It counts existing account rows,
so an account deleted the same day no longer counts.

**Per-account quotas**, enforced server-side, with per-account overrides (§7.1):

| Variable | Quota name | Default | Enforced at |
|---|---|---|---|
| `ANDVARI_QUOTA_ACCOUNT_BYTES` | `accountBytes` | 104857600 (100 MiB): item ciphertext plus attachment bytes in the vaults the account **owns** | push, item restore, attachment upload, `genesis`, `accept`. Writers to a shared vault use the owner's quota. |
| `ANDVARI_QUOTA_ITEMS` | `items` | 5000 live items across owned vaults | push, item restore |
| `ANDVARI_QUOTA_OWNED_SHARED_VAULTS` | `ownedSharedVaults` | 50 | `genesis`, `accept` |
| `ANDVARI_QUOTA_OPEN_LINKS` | `openLinks` | 20 | `POST /links` |

The per-file and per-item attachment ceilings stay (`attachmentMaxBytes`, `itemAttachmentsMaxBytes`,
each at most `accountBytes`). **Over quota:** on `POST /sync/push`, each mutation that would exceed is
answered per mutation with `status: rejected, reason: quota_exceeded` and the rest of the batch
proceeds (§5); single-request routes answer `413 quota_exceeded {quota}`, `quota` being the quota name
above. Either way the app shows "This vault's owner is out of space on this server."

**What an account is told** (added 2026-11-16, additive). Every `GET /sync` answer (§4), full or delta, carries
`quota`, the caller's own meters, and each row of `GET /admin/accounts` (§7.1) carries the same object for its account:

```jsonc
"quota": {
  "accountBytes":      {"used": <int>, "limit": <int>},
  "items":             {"used": <int>, "limit": <int>},
  "ownedSharedVaults": {"used": <int>, "limit": <int>},
  "openLinks":         {"used": <int>, "limit": <int>}
}
```

- **The keys are the quota names** of the table above, so the `quota` of a `413 quota_exceeded {quota}` names the
  meter that refused. All four are always present; each value is a whole number, at least 0. A client ignores a key it
  does not know (a later quota would add one).
- **`limit` is the limit in force:** the account's own override when the operator set one (`PUT
  /admin/accounts/{userId}/quota`, §7.1, or `andvari admin quota` on the host), otherwise the instance default
  (`quotaDefaults`, §7.2). Nothing is cached: an operator's change shows at the next read.
- **Who reads it:** the account itself, on its own `/sync` (any of its sessions, a web one included), and the
  operator, in the accounts list. No answer tells an account another account's meters, not even those of the owner of
  a shared vault it writes to.
- **Size:** at most 293 bytes with its key, every number at 19 digits; about 170 at real values. No cap changes (§0.4).

**What `used` counts.** The server reads each meter with the very functions its checks use, in the answer's
snapshot. So for one request on its own, "`used` + what the request adds > `limit`" is exactly the refusal, and a
request that lands exactly on the limit is accepted.

- **`accountBytes`** counts over every vault the account owns: its personal vault, its shared vaults, and a shared vault
  it deleted that is still in its grace (until the purge). It is the sum of two things:
  - each live item's `blob` length in characters, as sent (a tombstone counts 0, and kept versions, §4, count nothing);
  - each stored attachment's `size`: the upload's body less its 24-byte header, the `size` of `AttachmentMeta` (§9).
    An attachment counts from its upload, whether or not an item refers to it yet. One that no live item refers to
    is removed after 24 hours (§9), or at once when its item is tombstoned.

  What a request adds:
  - a new item or a restore: its blob's length;
  - an update: the new length less the stored one (a put that shrinks or keeps an item's size is never refused);
  - an upload: its body length less 24;
  - an `accept` (§10.3): all of the vault's live items and attachments;
  - a `genesis`: its `metaBlob` length must fit (`used` + that length ≤ `limit`), but a vault's meta is not counted
    afterwards.
- **`items`** counts the live items in the same vaults. A new item, a restore, or a put over a tombstone adds 1; an
  update adds 0; an `accept` adds the vault's live items.
- **`ownedSharedVaults`** counts the shared vaults the account owns, live or in their grace, until purged. The
  personal vault is not counted. A `genesis` or an `accept` adds 1.
- **`openLinks`** counts the links (§15) the account created that are still open and whose `expiresAt` is after now.
  `POST /links` adds 1. A link stops counting when it is answered or revoked, and at its `expiresAt` with no request
  at all.

**A shared vault's content counts against its owner, never against the writer.** A member's push, restore or upload
into a vault it does not own is checked against that owner's meters, which the member cannot read: an account's own
`quota` predicts only writes into the vaults it owns. "Move everything to a new vault" (design §3.13) copies into a
vault the mover creates and so owns: the mover's own meters decide it.

**Where `used` cannot predict exactly:**
1. **Time.** Between the read and the write, the account's other devices, and every writer to the vaults it owns, can
   change `used`. The check at write time decides.
2. **Uploads in flight.** The bytes of uploads still streaming into the owner's vaults count against its room
   mid-stream (§9) but are not in `used`, so an upload can be refused while another is in flight even though the meter
   showed room.
3. **Links expire on their own,** so `openLinks.used` can fall between the read and the create.
4. **A limit lowered below use.** `used` can then exceed `limit`. Every request that grows a meter is refused;
   shrinking and deleting are not.
5. **A `genesis`** needs its `metaBlob` to fit but adds nothing to `used` afterwards (above).
6. **Deleting a vault frees nothing until the purge.** A shared vault deleted into its grace (`ANDVARI_VAULT_GRACE_DAYS`)
   still counts, with all its content, until it is purged. An item's tombstone frees its bytes and its item at once.

Within one push batch (§5) there is no gap: each mutation is checked on top of the ones before it that were accepted,
so the sum of the batch is what counts.

**The check before a large copy** (normative for every client that offers one: "Move everything to a new vault", an
import, a copy or a move into another vault the account owns). Read `quota` from a fresh `GET /sync`, then work out:
- **B**, the bytes the copy writes. It is the sum of the blob lengths of the items as they will be sent, plus the
  attachments' stored sizes. A client that builds the blobs first knows B exactly. The source's stored lengths give
  the same figure for the same plaintext in the same format, chunking and envelope; otherwise they are an estimate.
- **M**, the new vault's `metaBlob` length, if a new shared vault is created.
- **N**, the number of items written.
- **V**, 1 if a new shared vault is created, else 0.

The account is short if any of these holds:
- `accountBytes.used` + max(B, M) > `accountBytes.limit`;
- `items.used` + N > `items.limit`;
- `ownedSharedVaults.used` + V > `ownedSharedVaults.limit`.

When it is short, the app does not start. It says which limit, and by how much, and that the operator can raise it
(design §3.13). The old vault in "Move everything" stays counted until its purge, so the move needs its whole size free
(design §3.13). The server's refusal stays authoritative: a client still handles `quota_exceeded` part-way (point 1
above).

### 14.5 Mail

- Transport: Microsoft Graph app-only (`ANDVARI_GRAPH_TENANT`, `ANDVARI_GRAPH_CLIENT_ID`,
  `ANDVARI_GRAPH_CLIENT_SECRET`, `ANDVARI_GRAPH_SENDER`) or SMTP (`ANDVARI_SMTP_*`); in test mode, the
  sink. Without a transport (and outside `open` mode) notices are logged as not sent and the security
  actions still happen.
- **Format.** Mail is plain text with an HTML alternative of the same content. A transport that can
  send only one body sends the plain text; mail is never HTML only.
- **Durable outbox.** Every message is written to `mail_outbox` inside the transaction that caused
  it, and a sender worker retries with backoff (1 min, 5 min, 30 min, 2 h, 12 h), giving up after
  24 hours (audited `email_failed`, template name only). A permanent failure (an HTTP 4xx other than
  429, or an SMTP 5xx) is dropped at once and audited. Rows are deleted the moment they are sent; a code
  message is deleted unsent when its code expires.
- **Stalled** means the outbox is non-empty and nothing has been sent successfully for 10 minutes.
  While stalled, `POST /signup/start` and `POST /recovery/requests` answer `503 mail_unavailable`,
  uniformly; `GET /admin/status` reports `mail.stalled`; `/metrics` exposes
  `andvari_mail_outbox_oldest_seconds` and `andvari_mail_failed_total`. Security notices stay queued.
- **Per-recipient caps:** three counters per address, each counting in a window of 24 hours that
  starts at the first mail it counts (not a calendar day), each with its own budget: code messages
  (`signup_code`, `recovery_request_code`) 5; the unsolicited notices an unauthenticated request can
  cause (`signup_existing`, `recovery_request_private`) 5; every other notice (the security notices) 20,
  which the other two classes never use up. Anything over a cap is dropped and audited. The code
  mails of recovery requests taken past the address's cap with a mailbox value have a fourth budget,
  5 more per window (§18.1, rule of 2026-11-17). Separately,
  `POST /recovery/requests` has a per-address bucket of 5 per window of 24 hours keyed on the address
  hash, applied silently (§18.1).
- **Content:** no message carries a password, recovery data, a link secret, a token, a session id, or
  a vault, item, attachment or contact name, and no link that acts or signs anyone in. Links go only to static help pages under
  `https://andvaripass.com/help/`, published with the product's website: `/help/lost-password/`,
  `/help/recovery-kit/`, `/help/add-device/`, `/help/connect/`, `/help/compromised/` and
  `/help/delete-account/`. A template links only to the page that fits it: `new_device`,
  `device_removed`, `password_changed`, `two_step_off`, `recovery_changed`, `operator_escrow_read`,
  `recovery_request_open` and `require_link_cleared` to `/help/compromised/`; `signup_existing` and
  `recovery_request_private` to `/help/lost-password/`; `recovery_applied` to `/help/recovery-kit/`;
  `account_deleted` and `account_deleted_by_operator` to `/help/delete-account/`; the code messages
  carry no link. The only code ever sent is the 6-digit
  sign-up or recovery-request code, and beside the recovery-request code its mailbox value (§18.1),
  which opens nothing but one more request for the same address. A
  queued code mail holds its code, and a recovery request's code mail also its mailbox value, in
  clear until it is sent or its code expires (the durable outbox above; spec 02 `mail_outbox`). Every notice names the instance (card name and origin), what
  happened, when (UTC), the device's platform and name where relevant, and the account ID (the 32-hex
  short identity fingerprint), except every mail the server sends because of an operator-assisted
  recovery (§18), which carries none (rule of 2026-11-16): `recovery_request_code`,
  `recovery_request_open`, `recovery_request_cancelled`, `recovery_request_private`;
  `recovery_applied`, `two_step_off` and `require_link_cleared` when an assisted commit sends them; and
  `operator_escrow_read` always, because an operator reads a recovery copy for one purpose only and
  that mail reaches the person in the middle of the very flow whose check the account ID must not
  feed. The person compares the account ID against the operator's answer, so the server's own mails
  must not be its source during that flow. Every other mail keeps the account ID.
- **Templates:** `signup_code`, `signup_existing`, `new_device`, `password_changed`, `two_step_off`,
  `recovery_changed`, `device_removed`, `operator_escrow_read`, `recovery_request_code`,
  `recovery_request_open`, `recovery_request_cancelled`, `recovery_request_private`,
  `recovery_applied`, `account_disabled`, `account_enabled`, `account_deleted`,
  `account_deleted_by_operator`, `require_link_cleared`. Their subjects and bodies are
  `docs/design/2026-11-15-onboarding-trust.md` §11.3 until they are published with the product's public face.

## 15. Links

### 15.1 Kinds and formats

| Kind | Made by | Purpose |
|---|---|---|
| `connect` | an account, on a native device (`POST /links`) | two people pin each other; a recipient without an account signs up first |
| `register` | an account, on a native device (`POST /links`) | an invitation to register on an instance not in `open` mode; registering pins the two people to each other |
| `enrol` | the host (`andvari admin enrol-link`) | registers an ordinary member with no inviter (tests, demos, seeding, operator-assisted onboarding); no contact is pinned |
| `setup` | the host (`andvari setup`, `andvari admin setup-link`) | enrols the first operator (§17.5) |

**URL.** `https://andvaripass.com/l#v2.<O>.<S>.<F>`, where `O = b64url(UTF-8(origin))` of the instance,
`S = b64url(s)` for a 32-byte CSPRNG secret `s`, and `F` the creator fingerprint
`b64url(SHA-256(creator's identityPub)[0..16])`, or `-` for a host-minted link. Parsing is total
(null on any malformed input, `bad_link`): the whole URL or the fragment alone, the fragment with or
without its `#`; white space stripped first, where white space means space, tab, LF and CR only (a
form feed or a vertical tab is not stripped, so the input is `bad_link`); at most 512 characters,
counted after the white space is removed; exactly four `.`-separated parts; `O` decodes to an `origin`
and re-encodes identically; `S` decodes to exactly 32 bytes; `F` is `-` or decodes to exactly 16 bytes
and re-encodes identically. Nothing before `#` is checked: the host and path are not authenticated,
and apps act only on the fragment. The
QR carries the full URL in byte mode at error-correction level M. The page at
`https://andvaripass.com/l` is static, runs no script and reads no fragment.

**Derivations from `s`** (spec 01 §5.5): `linkId` (16 bytes, `b64_16`), `offerKey`, `answerKey`, and
for register, setup and enrol links `registerToken` (`b64_32`), stored by the server only as
`tokenHash = b64url(SHA-256(ASCII(registerToken)))`.

**Offer.** A connect or register offer is a 0x06 frame (spec 01 §5.1), sealed as
`Envelope(offerKey, frame, AD = "andvari/v2|link-offer|" + linkId)`, at most 2,732 characters. A
setup or enrol offer is canonical JSON (`setup-offer`, `enrol-offer`, spec 01 §5.1) under the same
envelope and AD. After opening, a plaintext that starts with the bytes `61 76 73 02` is a frame and
must be purpose 0x06; one that starts with `{` is host JSON and its `purpose` must be `setup-offer` or
`enrol-offer`; anything else is `unknown_format`. The offer's kind (the frame's `kind`, or `setup` or
`enrol`) **must equal** the `kind` the server reports for the link, or the client stops
(`kind_mismatch`): nothing is sent and nothing is pinned.

**Answer.** A 0x07 frame signed by the answerer, sealed as `Envelope(answerKey, frame, AD =
"andvari/v2|link-answer|" + linkId)`, at most 2,732 characters.

**The name an account goes by in its links** (rule of 2026-11-17). A connect or register offer and an
answer carry the name of the account that signs them: the person's own word to the people they
connect with (design §6.3). The server serves no account its own name for this, and both halves of
that are exact (rule of 2026-11-17): the server stores the name given at registration and serves it
in the operator's list of accounts (§7.1) and in a shared vault's list of members (§10.7), the
caller's own row included; and a device never takes the name its account goes by in links from any
of those. That name is the person's own word to the people they connect with, signed by the
person's key; it is not the server's to vouch for, and a name read back from the server would be a
name the server chose. So a device that does not
hold the name, because the account was made on another device, asks the person for it, once, before
it makes or answers a link, and keeps it; it never invents one, and never fills in the address's
first part by itself. Until it holds a name, no link is made or answered on that device and nothing
is sent. A name is checked as the `name` type before it is kept (spec 01 §5.1). The shared code
keeps this rule: making a connect link or an invitation, answering a link, and a connection a
sign-in still owes each answer that the name is needed, with nothing written or sent, and go on once
the person has given it; the name is kept across a lock. **Not kept yet (2026-11-17):** no app's
screen asks for the name yet; and `andvari-cli` on a device where the account was not made holds no
name and neither asks for it nor takes it from an option, so its links stop there as a name that
cannot be used. Where the account is registered with `andvari-cli`, the tool keeps the name it
registered with: `--name`, or the address's first part when none is given. That stands (rule of
2026-11-17): the person registered there and could give a name; the rule against inventing a name is
for a device where the account was not made.

**Comparison code.** Committed in three passes (spec 01 §5.5): the offer carries
`commit = hexLower(SHA-256("andvari/v2|code-commit|" + b64url(nonceA)))`; the answer carries `nonceB`
in the open; the creator posts `nonceA` with `POST /links/{linkId}/reveal` (§15.5). The six-digit code
is `code(side, linkId, offerHash, answerHash, nonceA, nonceB)`, one per side (`creator`, `answerer`; spec 01 §5.5): each app shows its own side's code and accepts as typed input only the other side's. Each side computes it once, from the first
value it accepted for the other side's nonce; a reveal that does not match `commit` is `bad_reveal`,
and a second, different value from anyone is an anomaly that fails the link. `compared` is set only by
a person typing the other side's code on their own device; no wire message carries it.

A typed code is compared as text: every ASCII space is removed (the code is shown as `481 207`), and
what is left must be exactly six ASCII digits, equal to the other side's code. Nothing else is
normalised, so a dropped leading zero is a mismatch. A wrong code is not a verdict string: the check
answers yes or no and the person may type again. For about one link in a million the two codes are the
same six digits; nothing special happens then, and an implementation must not refuse a typed code for
being equal to its own. Vectors: the `typedCode` rows of `spec/test-vectors/links.json`.

### 15.2 Create

`POST /links { linkId, kind, offer, expiresAt, tokenHash? }` → `201 { expiresAt, ttlMs }`: the stored
expiry and the milliseconds left by the server's clock.

- `linkId` `b64_16`; `kind` `"connect"` or `"register"` (`setup` and `enrol` are minted on the host,
  never here: `400 bad_kind`); `offer` an `envelope` ≤ 2,732 characters; `expiresAt` `ms`;
  `tokenHash` 43 characters, required for `register` and absent for `connect` (`400 bad_token_hash`).
- By the server's clock, `now < expiresAt <= now + max + 10 min`, with `max` 7 days for `connect` and
  72 hours for `register`; anything else is `400 bad_expiry`. The server stores the value as sent,
  which is also the value signed in the offer. The 10 minutes of slack are the same as the log's offer
  window. The 5-minute **minimum** is the apps' rule, not the server's: a device whose clock runs behind
  still gets its link, which simply lives a little less by the server's clock. The creating device
  counts down from `ttlMs`, never from its own clock.
- **Who may create.** `connect`: any active account. `register`: on a `private` instance with
  `ANDVARI_REGISTER_LINKS = members`, any active account; otherwise the operator only
  (`403 not_operator`).
- Limits, for every kind: at most `openLinks` links in state `open` per account (`413 quota_exceeded
  {quota}`, quota `openLinks`) and 30 creations per day per device, with the ceiling per account of
  §0.1 (`429 rate_limited`). A `linkId` already in the
  table is `409 link_id_taken`.
- A client writes its link record (the secret, `nonceA`, kind, `offerHash`, `expiresAt` and the
  attached shares) to its **own device state** durably **before** this call; the secret never leaves
  the creating device and is never in account state. Audited `link_create`.

### 15.3 Fetch

`GET /links/{linkId}`, unauthenticated, 30 per minute per IP:

| Row state | Answer |
|---|---|
| `open`, `now < expiresAt` | `200 { kind, offer, expiresAt, state: "open", creatorUserId, creatorIdentityPub, reveal: null }`; `creator*` are null for host-minted links |
| `open` with `now >= expiresAt`, or `expired` | `410 link_expired` |
| `answered` | `200 { kind, state: "answered", reveal }`, whatever its `expiresAt`, until the janitor deletes the row. The offer and its creator are no longer served. `reveal` is `nonceA` once posted, else null |
| `revoked`, or no row | `404 link_unknown` |

There are exactly these two `200` shapes: the open form and the answered form. `reveal` is not
secret (it is bound by the offer's commitment and useless without the two frames), so
it is returned to any caller. An app that finds `answered` on a link it did not answer itself shows
"already used".

### 15.4 Answer

`POST /links/{linkId}/answer { answer }` → `ok`. Authenticated as the answerer; `answer` an
`envelope` ≤ 2,732 characters. **Checks, in order:** the row exists and is not revoked
(`404 link_unknown`); its kind is `connect` (`409 kind_mismatch`); it is unexpired (`410 link_expired`);
its state is `open` (`409 link_used`: the first answer wins); the caller is not its creator
(`400 cannot_target_self`). Then, in one transaction: store `answer`, `answererUserId`, `answeredAt`,
set `state = answered`, and write the `connections` row for the creator and the answerer (§15.8).
Rings the creator's bell. Audited `link_answer`.

### 15.5 Reveal

`POST /links/{linkId}/reveal { nonce }` → `ok`. The creator, after processing the answer; `nonce` a
`b64_32`. A link the caller did not create is `404 link_unknown`. The state must be `answered` and no
reveal stored yet; a second post, or a link not answered, is `409 link_state`. The value is stored
**once**. Rings the answerer's bell.

### 15.6 The creator's inbox

- `GET /links/answers` → `[{ linkId, answer, answererUserId, answeredAt }]`: the caller's answered
  links not yet acknowledged. `/sync` carries their count as `linkAnswers` (§4).
- `POST /links/{linkId}/ack` → `ok`: the creator processed the answer; sets `deliveredAt`. A link the
  caller did not create is `404 link_unknown`; one not `answered` is `409 link_state`; a repeated ack
  answers `ok` and changes nothing.

### 15.7 Revoke

`DELETE /links/{linkId}` → `ok`. The creator revokes an **open** link (`state = revoked`). A link the
caller did not create is `404 link_unknown`; one not `open` is `409 link_state`. Audited `link_revoke`.

### 15.8 Stored rows, the janitor, and connections

Table `links`: `linkId` (primary key), `kind`, `creatorUserId` (null for host-minted links),
`createdAt`, `expiresAt`, `offer`, `tokenHash` (register, setup, enrol), `boundEmailHash` (an enrol
link minted with `--email`: hex SHA-256 of `emailNorm`), `state` (`open`, `answered`, `revoked`,
`expired`), `answererUserId`, `answer`, `answeredAt`, `deliveredAt`, `reveal`. Host-minted rows are
written directly into the database by `andvari setup` / `andvari admin` (setup: 24-hour expiry; enrol:
`--expires`).

The server sees the link id, the kind, who made it, who answered and when, sizes, the token hash and
request IPs. It never sees `s`, any key derived from it, or the contents of an offer or answer.

**Janitor.** It moves `open` rows past `expiresAt` to `expired`, and deletes every row 30 days after
it left `open`.

**Connections.** `connections(a, b)` with `a < b` (by `userId` string order) is written in the same
transaction as an answered connect link (§15.4) or a registration through a register link (§14.3).
Enrol and setup links write none. The janitor never touches it; a row goes only when either account is
deleted (§13). `add` requires one (§10.3 step 8).

### 15.9 Client checks (normative for every native client and the CLI)

The web client never creates, opens, answers or processes a link (spec 05 T6).

**Recipient**, the first failure decides, with these verdict strings in this order:

1. `bad_link` (the URL does not parse, §15.1);
2. `GET /links/{linkId}` from the link's origin: `link_unknown`, `link_expired` or `link_used` (the
   server's answer, each with its own copy; `link_used` is an `answered` link this device did not
   answer);
3. `unopenable` (the offer does not open under `offerKey` with its AD, or its envelope is larger than
   2,732 characters, which is refused before any key is derived);
4. `unknown_format` and `kind_mismatch` (recognising the offer and comparing its kind with the
   server's, §15.1). `kind_mismatch` is returned as soon as it can be known: from the form alone,
   before any parse, when the form already contradicts the server's `kind` (a signed frame where the
   server reported `setup` or `enrol`, or host JSON where it reported `connect` or `register`), and
   from a signed offer's own `kind` right after its strict parse (step 5), and from a host offer's
   own `purpose` right after it is recognised (a `setup-offer` where the server reported `enrol`, or
   the reverse); a host offer that is not recognised is `non_canonical` or `unknown_format` first;
5. for a signed offer (connect, register): the parse verdicts (spec 01 §5.1); `kind_mismatch` (the
   frame's `kind` is not the server's); `creator_mismatch`
   (`fromKey` does not hash to `F`); `signer_not_pinned_key`; `bad_signature`. For host JSON (setup,
   enrol): printable ASCII and a JSON object with a string `purpose` (RFC 8259 exactly, as spec 01
   §5.1 defines it), else `non_canonical`; a `purpose`
   other than `setup-offer` and `enrol-offer`, `unknown_format`; the template's own parse verdicts; and
   `creator_mismatch` when `F` is not `-`;
6. the field checks: `link_mismatch` (`linkId`), `origin_mismatch`, `offer_expired`
   (`expiresAt <= now`), `reported_creator_mismatch` (`from` / `fromKey` against the server's
   `creatorUserId` / `creatorIdentityPub`; nothing is sent);
7. the pinning verdicts of spec 01 §5.3 (connect and register: the chain contains `cardHash` with
   `instanceId`; setup: it is empty, `GET /instance` serving the setup block, and a setup link opened
   on an instance that already serves cards is `already_set_up`; enrol: the Trust Gate), extending
   this device's pin if it has one. At the baked origin the baked root comes first whatever the kind
   (spec 01 §5.3): then the offer's own check for connect and register; nothing more for enrol, with
   no Trust Gate; and a setup link is refused there (`withheld` on an empty chain, `already_set_up`
   on a served one).

A different key for a contact this account already pinned is the `key_changed` prompt, not a verdict:
the old pin is never replaced without a matched comparison code. Only after the person confirms is
anything sent.

**Creator**, processing `GET /links/answers`, in order: `unknown_link` (no device-state record for
`linkId`: a record dropped at expiry or revocation means the answer is ignored, whatever the server
says); `unopenable` (the answer does not open under `answerKey`); the parse verdicts;
`signer_not_pinned_key` (the signer against the answer's own `fromKey`); `bad_signature`;
`link_mismatch`; `offer_mismatch` (`offerHash` against the record's); `misaddressed` (`to` or `toKey`
is not this account); `reported_answerer_mismatch` (`from` against the server's `answererUserId`). Then
the `key_changed` check, pin with `compared = false`, post the reveal, release attached shares only once
`compared = true` or by a per-vault release behind a warning, delete the secret, and acknowledge. The
answerer's check of the reveal against `commit` is `bad_reveal`.

## 16. Device links and the devices list

A device link adds a device N to an account from an existing, signed-in device E. It carries a
session and the trust records, never the vault key: N proves the master password before any session
exists, and only to an origin it pinned **before** the link began (spec 01 §5.3, the password rule).
The web client never runs or approves a device link.

### 16.1 URL and derivations

E shows `https://andvaripass.com/d#v2.<O>.<S>`: §15.1's encoding without `F`, with **exactly three**
`.`-separated parts, the same total parsing, a 32-byte secret, the origin grammar and the 512-character
cap. `/d` is not an app link: a tapped `/d` link only reaches a static page. N acts on a `/d` link only
when it was scanned or pasted on its own "Link from your other device" screen, or given to
`andvari-cli link-device`, and only after it holds a password pin for the link's origin (otherwise the
Trust Gate with the device-link wording comes first; declining sends nothing).

From `s` (spec 01 §5.5): `linkId` (`b64_16`) and `macKey`. All MACs below are
`b64url(HMAC-SHA-256(macKey, <string>))`, a `b64_32`; inside each string keys and nonces are their
unpadded base64url text and digests lowercase hex.

| Value | Construction |
|---|---|
| `commitN` | `hexLower(SHA-256("andvari/v2\|code-commit\|" + b64url(nonceN)))` |
| claim `mac` | over `"andvari/v2\|device-link\|claim\|" + linkId + "\|" + nPub + "\|" + name + "\|" + platform + "\|" + commitN`, where `name` is the claim's `name` field as sent |
| `proof` | over `"andvari/v2\|device-link\|pickup\|" + linkId + "\|" + nPub` |
| `proofHash` | `hexLower(SHA-256(ASCII(proof)))`, over the 43-character `proof` string |
| `approveMac` | over `"andvari/v2\|device-link\|approve\|" + linkId + "\|" + hexLower(SHA-256(raw outer))`: it covers `outer` only |
| comparison code | `u32be(SHA-256("andvari/v2\|device-link\|code\|" + linkId + "\|" + nPub + "\|" + b64url(nonceN) + "\|" + b64url(nonceE))[0..4]) mod 10^6`, six digits zero-padded |

### 16.2 States, create and cancel

| State | Leaves by | Timeout |
|---|---|---|
| `open` | a claim → `claimed`; cancel or replacement → deleted | the stored `expiresAt` (at most 5 minutes from creation) |
| `claimed` | E's nonce, then N's reveal → `revealed`; cancel or replacement → deleted | 5 minutes from the claim |
| `revealed` | E's approve → `approved`; cancel or replacement → deleted | 5 minutes from the reveal |
| `approved` | N's pickup with a correct password → deleted, and the device is created; cancel or replacement → deleted | 5 minutes from the approval |

Revoking the device that created a link, or the one that approved it, also deletes the link (§16.7),
in any state.

A link past its state's timeout answers `410 link_expired` until the janitor deletes the row, and
`404 link_unknown` after; clients show both as "Linking was cancelled or expired". No device or
session exists before pickup, so a timeout leaves nothing to revoke.

- `POST /device-links { linkId, expiresAt }` → `201 { expiresAt, ttlMs }`. E's session. The expiry
  exists only on the server, so the server owns it: it stores `min(expiresAt, now + 5 min)` and
  refuses only `expiresAt <= now` (`400 bad_expiry`); the stored value is the `open` state's timeout,
  and the answer carries it with the milliseconds left. E counts down from `ttlMs`, never from its own
  clock. A `linkId` in use is `409 link_id_taken`. An account has **at most one live device link**: creating one cancels (deletes)
  every other link of the account not yet picked up, whether `open`, `claimed`, `revealed` or
  `approved`; no device or session exists before pickup, so nothing else needs undoing. Bucket 10 per
  hour. Audited `device_link_create`.
- `DELETE /device-links/{linkId}` → `ok`. E's session, in any state before pickup; a link of another
  account is `404 link_unknown`. Either side's screen then shows "Linking was cancelled".

### 16.3 E reads the link

`GET /device-links/{linkId}` (the session of the device that created the link; another device of the
account, like another account, gets `404 link_unknown`) →
`{ state, expiresAt, claim?: { nPub, name, platform, commitN, mac }, nonceE?, nonceN? }`, each optional
field present once it exists. `expiresAt` is the current state's deadline (§16.2's timeout column),
not the creation-time expiry. E verifies `mac` (a mismatch is an anomaly). **E fixes the claim when it
draws `nonceE`**: a later answer showing a different claim (`nPub`, `name`, `platform` or `commitN`)
makes E cancel the link.

### 16.4 N claims

`POST /device-links/{linkId}/claim { nPub, name, platform, commitN, mac }` → `ok`, unauthenticated,
sent only to the origin N pinned. `nPub` `b64_32` (an ephemeral X25519 key), `name` the `name` type
(unpadded base64url of 1–64 UTF-8 bytes, spec 01 §5.1), `platform` from §0.1's list, `commitN`
`hex64`, `mac` `b64_32`. The server cannot check `mac` (it has no `s`) and stores the claim as sent.
The first claim wins: a link not `open` is `409 link_claimed`. Bucket 10 per minute per IP. Audited
`device_link_claim`.

### 16.5 Nonces and reveal

- `POST /device-links/{linkId}/nonce { nonceE, proofHash }` → `ok`. The session of the device that
  created the link (another device of the account gets `404 link_unknown`, as for approve), after it has seen and
  verified the claim; `nonceE` a fresh `b64_32`, `proofHash` a `hex64` (§16.1). The state must be
  `claimed` with no nonce yet (`409 link_state` otherwise: one nonce post per link).
- `POST /device-links/{linkId}/poll { proof }` → N's view, unauthenticated:
  - before E's nonce exists: `{ state }`;
  - then `{ state, nonceE }`;
  - after E approves: `{ state, nonceE, outer, approveMac }`.

  `nonceE`, `outer` and `approveMac` are returned only when `SHA-256(proof)` equals the stored
  `proofHash`. Once `proofHash` exists, a poll, reveal or pickup with any other `proof` is
  `403 bad_proof`. **N holds the first `nonceE` it received**, reveals only after holding it, computes
  the code from that value, and treats any different `nonceE` served later as an anomaly that cancels
  the link.
- `POST /device-links/{linkId}/reveal { nonceN, proof }` → `ok`. Unauthenticated; `nonceN` `b64_32`.
  The state must be `claimed` with E's nonce stored and no reveal yet (`409 link_state`); the state
  becomes `revealed`. E checks `commit(nonceN) = commitN` (`bad_reveal`, which cancels). Audited
  `device_link_reveal`.

Both devices compute the code. N shows it; E shows "Add *name* (*platform*)? Type the six digits shown
on the new device". **The digits must be typed into E**, and are compared as text under §15's rule
(spaces removed, then exactly six digits); a mismatch cancels the link.

### 16.6 Approve and pickup

- `POST /device-links/{linkId}/approve { outer, inner, approveMac }` → `ok`. E's session, after Face ID,
  fingerprint or the master password on E. The state must be `revealed` (`409 link_state`).
  - `outer = crypto_box_seal(nPub, {"v":2,"origin":…,"userId":…,"email":…})`, a `sealed` ≤ 1,400
    characters: just enough for N to sign in (`origin` the instance's origin, `email` the `emailNorm`).
    N decodes it **strictly** — exactly these keys, `v` the number 2, `origin` in the `origin` grammar,
    `userId` a `uuid`, `email` an `emailNorm` — because it gates the password prompt. The plaintext is
    **compact JSON**, as the bundle is (§16.9). N's checks, in order: `bad_mac` first (`approveMac`
    covers the raw sealed bytes, so it is checked before anything is opened or parsed),
    `outer_unopenable` (the seal does not open), `bad_outer` (the strict decode), `origin_mismatch` (not
    the origin N pinned).
  - `inner = Envelope(bundleKey, bundle JSON (§16.9), AD = "andvari/v2|device-link-bundle|" + linkId)`,
    an `envelope` of at most 64 KiB of plaintext, with `bundleKey` derived from the account's UVK
    (spec 01 §5.5).
  - `approveMac` as §16.1.

  The server records the approval and the approving device (`approvedBy`, the device whose session
  approved) and **creates no session**. Audited `device_link_approve`.
- N opens `outer` with `nSec`, checks that its `origin` equals the origin it pinned and checks
  `approveMac` over `outer`, all **before** any password prompt. It then asks for the master password
  on a screen naming the account and the instance ("Master password for *email* on *name* (*origin*)"),
  runs prelogin for `email` at the pinned origin, and derives `authKey`.
- `POST /device-links/{linkId}/pickup { proof, authKey, totp?, device: { deviceSecret } }` →
  `200 { inner, session: SessionResponse }`, where `session` is the same `SessionResponse` a login
  answers (§2): `role`, the two-step flags and `accountKeys` are inside it, and there is no top-level
  `accountKeys`. Unauthenticated; sent only to the pinned origin. **Checks, in order:** the per-IP login bucket and the
  email backoff (§8); `proof` against `proofHash` (`403 bad_proof`); the state is `approved`
  (`409 link_state`); `authKey` exactly like a login — verifier, then the TOTP rules: an account with
  two-step sign-in answers `401 totp_required` until `totp` carries a valid code, and a wrong password
  or code is the uniform `401 invalid_credentials`, counted against the email backoff (audited
  `device_link_pickup_denied`). `requireLink` does not apply: this is a linked device. Only then, in one
  transaction, the server re-checks what it checked outside it: the account is still `active` and its
  verifier is still the one the password matched (a password changed or recovered in between answers the
  uniform `401 invalid_credentials`, counted against the email backoff), and the device that created
  the link and the device that approved it are both unrevoked (otherwise `404 link_unknown`). Then, in
  that transaction, the server creates the device (`how = linked`, `linkedFrom` = E's deviceId, name and
  platform from the claim, the `deviceSecret` hash) and its session, deletes the link row, and queues
  the `new_device` email. The answer is given once. Audited `device_link_pickup`.
- N then unlocks the UVK, which verifies the genesis as every unlock does (spec 01 §5.4), opens
  `inner` under `bundleKey` (`bundle_unopenable`), requires the seed-derived identity key to equal
  `bundle.identityPub`, requires `bundle.origin` and `bundle.instanceId` to equal the pinned card's and its verified chain to
  contain `bundle.card` at its `seq`, then imports the records (§16.9). Any failure after the session
  arrived signs that session out at once; a pin mismatch also removes the pin N made for this link and
  shows "This isn't the server your other device uses. Nothing was linked."

The server sees the link id, both devices' names and platforms, `nPub`, timing and opaque blobs.
Without `s` it cannot forge a claim, swap `nPub`, or produce an approval N accepts; without the UVK it
cannot read or forge the bundle.

### 16.7 Your devices

- `GET /account/devices` → `[Device]`, `Device = { deviceId, platform, name, clientVersion, createdAt,
  lastSeenAt, live, how: "registered"|"password"|"linked"|"recovered", linkedFrom?, current }`. `name`
  is plain text (a claim's `name` is decoded from base64url when the device is created).
  `clientVersion` and `lastSeenAt` may be null (a device that has not yet been seen after creation). `live` is
  derived as in §7.1; `current` marks the calling device.
  **Paged (2026-11-16).** Rows come in `(createdAt, deviceId)` order, oldest first, at most **500** to an
  answer. `?after=<deviceId>` (the last row of the previous answer) starts the next page after that row; an
  `after` that is not a `uuid` or names no device of the account is `400 bad_request`. An answer of fewer
  than 500 rows is the last page (an empty one when the previous page ended exactly on the last row).
  Without `after` the answer is the first page, which is the whole list for any account of up to 500
  rows. Why paging, and not pruning or leaving rows out: a device row whose secret hash is set must stay
  a known device however long ago its last session died, or `requireLink` would lock its owner out
  (design §8.7; §16.8), and a known device the person cannot see is one they cannot revoke. Every web
  sign-in from a browser that keeps no `deviceSecret` adds such a row, so the count has no bound and
  only the answer can be bounded. A row is at most about 1.1 KB (a 256-character name of 3-byte UTF-8
  characters, the longest `clientVersion`, every field set), so a page is at most about 550 KB and
  always fits the 1 MiB a client reads (§0.4).
  **What a client does:** it asks for the first page, and while an answer holds 500 rows asks again with
  `after` set to that answer's last `deviceId`, joining the pages in order. It shows the list only when
  the last page has arrived, so a row it shows as "your only live device" never hides another on a later
  page. A `400 bad_request` on a later page (the account was deleted meanwhile, or a bug) fails the whole
  read; a row seen twice (impossible from an honest server) is shown once. The same for the operator's
  view (§7.1).
- `POST /account/devices/{deviceId}/revoke { currentAuthKey }` → `ok`. Revokes another of the
  account's own devices (the calling device is `400 cannot_target_self`; an unknown one or another
  account's is `404 no_such_device`): its sessions are revoked, **its `deviceSecret` hash is cleared**
  so it is no longer a known device (§16.8), every device link it created or approved is cancelled
  (deleted, §16.2), its sockets get `{"type":"revoked"}`, and the `device_removed` email names the
  revoking device. Audited `account_device_revoke`.

### 16.8 Known devices and "New devices must be linked"

- Every request that creates a device carries `device.deviceSecret` (§0.3): register (§14.3), password
  login (§2), device-link pickup (§16.6), and the kit and assisted-recovery commits (§12, §18.5).
- A password login is from a **known device** only when `deviceId` names a device row of the account
  that is not revoked and whose stored secret hash equals the hash of the `deviceSecret` sent (§2); a
  signed-out device stays known. Anything else is a new device. Every revoke, by the person
  or the operator, clears the device's secret hash, so a revoked device is never known. A recovery
  commit, by kit or assisted (§12, §18.5), clears the secret hash of every earlier device of the
  account, so every device from before the recovery is unknown too: each signs in as a new device and,
  once `requireLink` is turned on again (the commit clears it), must be linked again.
- `users.requireLink`: when set, a password login that is not from a known device is refused with
  `403 link_required`, and only after `authKey` and any two-step code have verified (§2), so the
  answer tells nobody without the password anything. It is set with `PUT /account/require-link
  { enabled, currentAuthKey }` → `ok` (fresh password proof; audited). A kit recovery or an assisted
  recovery clears it and sends `require_link_cleared`.

### 16.9 The bundle

UTF-8 JSON, at most 64 KiB, carried as `inner`. The decoder is strict: exactly these keys (in any
order), no extra keys, no key twice at any level, every value of its type. The text is **compact
JSON**: no white space outside strings, strings escape only `"` and `\`, numbers in the `int` or `ms`
text form (`2.0`, `2e0`, `02` and `-0` are refused). After the pickup and the unlock N checks, in order:
the genesis verdicts (spec 01 §5.4) first, because the genesis is verified when the device unlocks, as
at every unlock, before the bundle is touched; then `bundle_unopenable`; `bad_bundle` (this decode; also
more than 1,000 entries in `contacts` or in `vaults`); `identity_mismatch` (the bundle's `userId`,
`identityPub` or `personalVaultId` is not the session's, the seed-derived key or the verified
genesis's); `pin_mismatch` (below).

```
{"v":2,"origin":…,"instanceId":…,"card":{"seq":…,"hash":…},"userId":…,"email":…,"identityPub":…,
 "personalVaultId":…,
 "contacts":[{"userId":…,"keyHash":…,"verifiedAt":…}],
 "vaults":[{"vaultId":…,"seq":…,"hash":…}],
 "accountState":{"seq":…,"hash":…},
 "issuedAt":…}
```

| Field | Type |
|---|---|
| `v` | the JSON number 2 |
| `origin` | `origin` |
| `instanceId`, `userId`, `personalVaultId`, each `contacts[].userId`, each `vaults[].vaultId` | `uuid` |
| `card.seq`, `vaults[].seq`, `accountState.seq` | `int` |
| `card.hash`, `vaults[].hash` | `hex64` |
| `accountState.hash` | `hex64`: SHA-256 over the ASCII bytes of the served `sealedState` string |
| `email` | the `emailNorm` string |
| `identityPub` | `b64_32` |
| `contacts[].keyHash` | `hex64`: SHA-256 over the raw 32 key bytes |
| `contacts[].verifiedAt`, `issuedAt` | `ms` |
| `contacts`, `vaults` | arrays of at most 1000 entries each |

**Builder rule.** The bundle keeps its 64 KiB. When the account has more than fits, the existing device
puts the most recently verified contacts and checkpoints in first and leaves the rest out; the new device
treats anything left out as a device signed in with only the password would (spec 02 §9). The decoder is
unchanged.

N imports: `contacts` make a contact **current** on N only where N's merged account state holds that
`userId` with the same key hash (the bundle confers currency, never contacts); `vaults` and `card` are
verified checkpoints (a served log or chain that contradicts one is a fork, one that ends below it is
withholding); `accountState` is a high-water mark of the document's in-blob `seq` (a served state below
it is a rollback, a different hash at the same `seq` a fork). It is not a recovery mirror (spec 04 §2).

## 17. The instance card

The card's template (purpose 0x04), its chain and the client's pinning rules are spec 01 §5.2 and
§5.3. The server stores the chain and serves it; it never signs a card.

### 17.1 Serving

`GET /instance` → `200 { cards: [frame…], rotations: [frame…] }`: every stored card, card 0 first, and
every stored 0x08 recovery-rotation statement (spec 04 §5), oldest first. Unauthenticated, cacheable
with an `ETag` (a matching `If-None-Match` answers `304`), bucket 60 per minute per IP.

While **no card is stored** (before setup finishes, or after `reset-instance-identity`, §17.5), it
answers `200 { cards: [], setup: { instanceId, origin, name, kind, recoveryFp } }`: the values
`andvari setup` wrote (`name` in the `name` type, `recoveryFp` a `hex64n`). They are used only by a
signed-in operator resuming an interrupted setup, and by the setup link's "no cards yet" check; they
are never a pin. A client that already pins a card and is served no cards treats it as withholding and
keeps working.

Clients fetch the chain on every policy probe or sync when its ETag changed, and verify forward from
their pin (spec 01 §5.3).

### 17.2 Signing a card

`PUT /instance/card { card, currentAuthKey }` → `200 { seq, hash }`. The operator's session (native
or CLI), with a fresh `currentAuthKey`. `card` is a 0x04 frame.

**Checks, in order:** the caller is the operator account (`403 not_operator`); the strict parse of the
frame (`400 bad_card`); the position: with cards stored, `seq` must be the stored head's plus one and
`prev` its hash (`409 card_head_moved {seq, hash}`, carrying the stored head); with none stored, the
card must be card 0 (`400 bad_card`); then `400 bad_card` for any chain, signature or field failure:

- `instanceId` constant and equal to the instance's; the signer: card 0's
  `signerPub` equals its own `operatorSignKey`, card n's equals card n−1's `operatorSignKey`;
- `operatorSignKey` is byte-equal to the Ed25519 key that signed the genesis of the account `operator`
  names (the stored genesis frame's `signerPub`; never a comparison through the X25519 image);
- **card 0** also: `instanceId`, `origin`, `kind` and `recoveryFp` equal what `andvari setup` wrote
  (`ANDVARI_CANONICAL_ORIGIN`, `ANDVARI_INSTANCE_KIND`, `ANDVARI_RECOVERY_FINGERPRINT` or `none`), and
  `operator` is the caller;
- a new `recoveryFp` is accepted with or without a stored rotation whose `toFp` equals it: the server
  cannot tell an intended rotation from an unsigned change, and clients warn about a change no stored
  rotation covers (spec 04 §5). The operator therefore stores the rotation (§17.3) before the card;
- on a `public` instance, a `recoveryFp` other than `none` (§18.6).

**Handover.** When `operator` names another account, the server switches the `operator` role to it
atomically with storing the card. That account must be `active`, must not have operator recovery on
(its posture is `private`: the operator holds the sheet that would open its own escrow),
and on a `public` instance own no shared vault (`409 handover_target_invalid`). The old operator
account becomes a member.

**The incoming operator's other sessions are not ended by the server** (decided 2026-11-16). The
account may hold sessions in clients that refuse the operator account (web, extension, phones), and the
server knows the platform each sign-in named, but it leaves them alone; the card bell (below) is all it
does. The reasons, from design §4.4 and §12.2 rule 7:
- The design gives this to the client: whenever the newest verified card names the signed-in account as
  `operator`, such a client signs it out with the operator sentence (a phone instead stops using it at
  once, keeps its copy locked and deletes nothing, sends nothing more, and lets the person remove the
  account: decided 2026-11-16, design §9.1, and built in the app engine),
  and "that needs no signal from the server", which also covers a quick unlock (it carries no role). The
  bell makes that happen at once.
- A server-ended session is §4.4's other state: the device stands "signed out by the server", the copy
  and the changes not yet sent are kept, and signing in again to the same account is promised to restore
  the session and send them. For the operator account in such a client that promise cannot be kept (the
  client refuses that sign-in), and a `revoked` frame racing the bell's pull would show the person the
  generic server-ended notice instead of the sentence that says why. Ending it server-side would give a
  wrong explanation and a broken promise, and gain nothing.
- The platform is what the client declared in `X-Andvari-Client` (§1). Ending sessions by it binds only
  honest clients, and they already end the session themselves from the card. The server's one
  platform rule stays §7's (operator routes refuse web sessions), whose reason is the code the server
  serves to a browser, not where the account is held.

**Moves.** When a card changes `origin`, the old server keeps serving the chain, so devices that still
dial it learn of the move. Audited `instance_card_update`.

**The bell.** Every stored card, card 0 included, rings every open events socket of every account with
a fresh `rev` (§6 **The card bell**): clients look at the chain again at once instead of at their next
own refresh.

### 17.3 Storing a rotation statement

`PUT /instance/rotation { statement, currentAuthKey }` → `ok` (**R**). The operator's session with a
fresh `currentAuthKey`. `statement` is a 0x08 frame (spec 04 §5) the operator produced offline with
`recovery-cli rotate`. The server stores it only if it verifies against the current recovery key:
`instanceId` this instance's, `fromFp` equal to the newest card's `recoveryFp` or to the newest
stored rotation's `toFp`, and its signer the recovery key `fromFp` names; otherwise
`400 bad_rotation`. A byte-identical stored statement answers `ok` and stores nothing. Audited
`recovery_rotation_stored`. A stored statement rings the card bell (§6), as a stored card does.

### 17.4 The recovery public key

`GET /recovery-pubkey` (**R**) → `200` with the instance recovery public key as bare base64url text
(the body is not JSON). It answers `404 not_found` when the newest card's `recoveryFp` is `none` or no
recovery key is configured. Before card 0 exists it serves the configured recovery key (private
instances only; on a public one the route is `404`, §18.6). A client checks it against the card's `recoveryFp` at full length before
it seals to it (spec 04 §2).

### 17.5 Setup and reset on the host

- `andvari setup` writes `andvari.env` (origin, kind, mode, secrets, and when operator recovery is
  chosen `ANDVARI_RECOVERY_PUBKEY` and `ANDVARI_RECOVERY_FINGERPRINT`), starts the server and writes a
  **setup link** row directly into the database (24-hour expiry). The instance id and the setup name
  live in the database (`instance_setup`), written by `andvari setup`, or created at first boot if
  setup never ran; no environment variable holds them. The first
  operator registers through it (`auth.setup`, §14.3) and then signs card 0 (§17.2). Until card 0 is
  stored, every other registration is `409 setup_incomplete`, and the host refuses to mint enrol links.
  `andvari.env` is created readable by its owner only (mode 0600) from the start, before any secret is
  written to it. Before it writes anything, setup refuses a database file that already holds anything
  (it never writes over an existing instance), checks every boot rule, and under `--test` refuses a data
  directory that is not empty: a test instance is made only in a new or empty directory, so its clock,
  mail sink and blob directory never land inside a live instance's. The mail secrets can be given in the environment (`ANDVARI_GRAPH_CLIENT_SECRET`,
  `ANDVARI_SMTP_PASS`) or in files (`--graph-client-secret-file`, `--smtp-pass-file`, the file's first
  line) instead of as `--graph-client-secret` / `--smtp-pass`, because command-line
  arguments are visible to other users of the host.
- `andvari admin reset-instance-identity`, for a lost operator: in **one transaction** it demotes the
  operator account to member, **deletes the stored cards and rotations**, and mints a new setup link.
  `GET /instance` then serves the setup block (§17.1) until a new operator signs a new card 0, with the
  **same instance id**. Accounts and vaults are untouched. Every device that pinned the old chain sees
  the new card 0 as a fork and stops (spec 01 §5.3).

## 18. Operator-assisted recovery

This section applies to **private** instances. On a `public` instance (variant R, §18.6) every route in
it answers `404 not_found`. Assisted recovery exists only for accounts whose posture is `operator`; no
temporary password exists at any point. The formats (the request code, the 0x09 payload, the 0x0A
veto) are spec 04 §7.

### 18.1 Opening a request

`POST /recovery/requests { email, rPub, pollHash, platform, mailboxValue? }` → `202 { requestId }`.
Unauthenticated. `email` an `emailText`; `rPub` a `b64_32` (a fresh X25519 key whose secret stays on
the requesting device); `pollHash` the `hex64` SHA-256 of a 32-byte `pollSecret` the device keeps;
`platform` from §0.1's list, **self-reported**: every list that shows it says so. `requestId` is a
`b64_16`. `mailboxValue`, optional (the way out below): absent or `null` is none; otherwise a string of
at most 64 characters, the mailbox value as the person typed it; anything else (not a string, or a
longer string) is `400 bad_mailbox_value`, checked with the body's shape, before `invalid_email`, and
alike for every address.

**Checks:** the per-IP bucket (5 per hour, `429`); `400 bad_mailbox_value`; `400 invalid_email`; the mail outbox stalled
(`503 mail_unavailable`, for every address alike); then the per-address bucket, 5 per window of 24
hours that starts at the first request it counts (not a calendar day), keyed on the email hash, for
known and unknown addresses alike and applied **silently**: over it the server sends
no mail, stores a decoy (below), and still answers `202 {requestId}`. Otherwise the answer is always
`202 {requestId}`, and every accepted request stores a row (spec 05 T11), so that nobody learns from
the answer which addresses have an account or which accounts use operator recovery:

- an `operator`-posture account: the request is stored `unverified` and `recovery_request_code`
  carries a 6-digit code, valid 15 minutes. The server stores only
  `codeMac = HMAC-SHA-256(serverSecret, "andvari/v2|recovery-request-code|" + requestId + "|" + code)`
  and the code's expiry, where `serverSecret` is `ANDVARI_SIGNUP_SECRET` when it is set and the
  enumeration secret (`ANDVARI_ENUM_SECRET`, spec 01 §3) otherwise. This MAC is server-internal and has
  no conformance vector;
- a `private`-posture account: a decoy is stored, and `recovery_request_private` says it has no
  operator recovery and points to the kit;
- an unknown address: a decoy is stored and nothing is sent.

A **decoy** is a request row with no account and no code: it has the same lifetime as an unverified
request and is never verifiable, so poll (`unverified`, then `expired`), verify (`400 bad_code`) and
commit (`409 request_state`) answer for it exactly as for a real request whose code was not entered.
It is never listed, counted or shown to the operator.

An unverified request expires 24 hours after creation. **One record of one shape** (rule of
2026-11-16): every accepted request, a decoy included, is audited `recovery_request_create` with one
row of one shape (no device, the caller's address, and meta `mailbox=used` when a mailbox value took
the request past the address's cap, `mailbox=not_used` when the request carried a `mailboxValue` that
took nothing, none otherwise: the way out's fifth point below), naming the account only for a real
request; the transaction does the same reads and writes for every kind of request, as evenly as it can
without storing anything for a decoy, except that only a real request stores its code's MAC and mails
the code. The device
keeps `rSec` and `pollSecret` protected like a session (Keychain or Keystore) until commit, veto, or
30 days.

**The way out through the mailbox** (rule of 2026-11-17, decided on 2026-11-17: built on the new line
before the public launch). The per-address cap lets anyone who knows a person's address use up that
address's five requests every day, so that the person's own request then goes nowhere (spec 05 R37).
Only the mailbox's holder can take this way past the cap:
1. **The code mail of every request** (`recovery_request_code`) carries, beside the request's code, a
   second value: the **mailbox value**. It is sixteen symbols of the alphabet
   `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (the capital letters without I and O, and the digits 2 to 9),
   80 bits from the server's secure random source, shown in four groups of four. A typed value is
   brought to its form **in ASCII only**: spaces, tabs and dashes are removed and the letters a to z
   are raised to A to Z; no other character is mapped, so any other character outside the alphabet
   (a letter from outside ASCII included, even one that a full case mapping would turn into letters
   of the alphabet, such as ſ, ß or a ligature) makes it a wrong value. Only its hash is stored, with
   the address's keyed hash (spec 02 §5; it is in the value's hash too) and an expiry of seven
   days; a value mailed before 2026-11-18 is still found in its earlier form, under the plain hash,
   until it expires. It is stored only when the mail that carries
   it is queued (a value no mail carries could never be used). The notice that a `private`-posture
   account gets (`recovery_request_private`) carries no value: its reader cannot get the operator's
   help by any request. The alphabet keeps symbols that can be confused when typed from a mail (S and
   5, Z and 2, B and 8, G and 6): a cost, accepted because a value is mostly copied, the mail shows it
   on a line of its own in four groups, and a smaller alphabet would need a seventeenth symbol.
2. **A request that names a mailbox value which is this address's, unused and unexpired, is taken as
   a real request even when the address's five of its window are spent**, when the address's account
   is in the `operator` posture. It uses the value up. Such requests have a ceiling of their own, five
   per address, counted in a window of 24 hours that starts at the first request it counts; the
   address's window and the value's own window run independently. Within one window of each, an
   address so receives at most five code mails of ordinary requests and five of requests taken by a
   value. Across the windows' edges more than ten such mails can reach an address inside 24 hours
   (twenty is the bound): more than ten only through requests that name values, which only someone
   who reads the mailbox can send, and never more than five in a window from a stranger, as before.
   The windows stay as they are (aligning them to the day moves the edge and does not remove it). A
   value that this ceiling refused is kept, unused. Within the address's five of its window a right
   value is not needed: the request is an ordinary one, and the value is not used up and stays
   usable. For an address whose account is in the `private` posture a request never uses a value and
   never draws on this ceiling: the way out exists for requests the operator can take, and there are
   none in that posture. The mail for a request taken by a value carries a fresh value like any other,
   and such mails have a budget of their own per recipient, five per window, beside the five of the
   code mails (§14.5), so that the mail cap does not drop the very mail this way out exists for.
3. **A wrong, used, expired or foreign value changes nothing:** the request is handled exactly as if
   no value had been given. A string that is not a value's form (once brought to its form as point 1
   says, not sixteen symbols of the alphabet) is a wrong value. Anything in the field
   that is not a string, or a string over 64 characters, is refused as a fault of the request's form,
   alike for every address. There is no limit on wrong values per address (a limit there would be the
   same gap again, one level up); the value's length is what makes guessing pointless, and the route's
   limit per caller address stays as it is.
4. **The answer never tells.** The answer to a request is byte for byte the same with a right value, a
   wrong one or none, for an address with an account and for one without, within and beyond the caps;
   the work done before answering does not differ in a way a caller can time (the comparison with the
   stored hash is made, or made up, in every case). The person learns that it worked by the mail that
   arrives.
5. **The records:** a request opened with a mailbox value says so in its audit row's details. Nothing
   an unverified request's poll shows changes.
6. **Values are forgotten** when used, when expired, and all of an address's values when that
   account is deleted (by its owner or by the operator, §13), when its recovery completes (with the
   kit or with the operator's help, §12, §18.5), and when it switches to the `private` posture
   (§3.1). A password change keeps the address's values: they open nothing but one more request, and
   the person may need one the next day.
7. **The mail says what the person needs:** the code mail gains a short paragraph: someone typed your
   address to ask for help with an account; if that was not you, you need do nothing else, but keep
   this value; if you ever ask for help yourself, enter it with your request, under the line the app
   names (the line of point 8, quoted as the apps word it); it works once, for this address, for seven
   days. The paragraph never sits under a sentence that tells the reader to ignore the mail. Telling
   the person to enter a value with every request of their own costs nothing, since a value within
   the address's five is left unused. Its words are entries on the owner's wording page; until they
   are approved, the server's template carries a marked placeholder.
8. **The device:** "Ask the operator for help" takes an optional mailbox value, behind one quiet line
   that opens the field ("have a value from a mail about a request you did not make?"); the shared
   code passes it with the request, in the field `mailboxValue`, and learns nothing from the answer. The same for every client
   that can open such a request: the shared code passes it, and `andvari-cli` takes it as an option;
   the Android and desktop apps do not show the line and the field yet, and the iPhone app is not on the engine yet. A device brings a typed value to its form exactly as point 1 says
   (ASCII only: spaces, tabs and dashes removed, the letters a to z raised, any other character a wrong
   form). It may refuse a value that is not of a value's form before anything is sent, saying only
   that it is not a value from such a mail: that tells nothing about any account.
9. **What it does not change** (spec 05 R37): a person who cannot read their mailbox cannot use the
   operator's help at all, as before (the request's code goes there); and a person whose address is
   being used this way still receives up to five unwanted mails per window, which is what the cap is
   for. Someone who reads the person's mailbox can spend both the address's five and the value's five
   themselves, and so close the way out for the person: that is part of what reading a mailbox means.
   A queued code mail holds its code and its mailbox value in clear until it is sent or its code
   expires (§14.5).

**What is kept, and what is not kept yet (2026-11-17).** The server on the integration branch keeps
all nine points: the field, its `400`, the value's making, its keyed hash and its storage only beside
a queued mail, the form in ASCII only, its use past the address's five under its own ceiling and its
own mail budget and only for an account in the `operator` posture, the same answer in every case, the
audit meta, the forgetting when a value is used or expires and when an account is deleted, its
recovery completes or it switches to the `private` posture, and a code mail whose paragraph stands
under "Nothing happens without this code." with no line that tells the reader to ignore it (the
paragraph's words are still a marked placeholder, as point 7 says). The address's bucket, the value's
ceiling and the code mail's per-recipient cap read one clock reading inside the request's transaction,
so the address's window and the code mails' window start and lapse together. The shared code passes a
value with a request and learns nothing from the answer; a typed value that is not of the form stops
on the device as `bad_mailbox_value` with nothing sent, and the step stays for the person to correct
or clear it; a blank value is none. **Not kept yet (2026-11-17):**
- the shared code brings a typed value to its form with every kind of white space removed and the full
  Unicode case mapping, so some characters from outside ASCII (ſ, ß, ligatures) become letters of the
  alphabet on the device, against point 8; the server then takes the value as the device sent it;
- no app shows the line and the field of point 8 yet. `andvari-cli` takes the value since 2026-11-17
  (`recover assist --email` reads it from `--mailbox-value-file` or `ANDVARI_MAILBOX_VALUE`, never
  from the command line; with a terminal attached and neither given it asks one question first; a
  value that cannot be one stops before anything is dialed) and adds `mailboxValue` to that one
  request.

### 18.2 Verifying the address

`POST /recovery/requests/{requestId}/verify { code }` → `200 { state: "holding", holdEndsAt }`. A wrong,
expired or used-up code — and a decoy or an unknown request — is the uniform `400 bad_code`. Limit: 5 attempts
per request. There is no per-address cap on attempts: a stranger's wrong codes on a request of their
own must not use up the owner's, and guesses stay bounded because opening requests is itself capped
per address and window (§18.1). The route also has a bucket per caller address of its own name,
`recovery_request_verify`, 20 an hour, as `POST /signup/verify` has (rules of 2026-11-16 and
2026-11-17; the kit's verify, row 32, is `recovery_verify`, a budget of its own). Every refused code is
audited `recovery_request_verify_fail`, naming the account only for a real request; a decoy, an
unknown and a malformed `requestId` do the same work and write a row of the same shape, so they answer
exactly like a real request. A request its owner cancelled before its code was entered
(§18.4) answers the right code with `409 request_state` and becomes `vetoed`; a wrong code is the
uniform `400 bad_code`. On success the request becomes `verified` and its **hold of 7 days** starts
(`holdEndsAt = now + 7 d`); every signed-in device of the account gets a bell, the account's email gets
`recovery_request_open` with the time and platform, and no account ID (§14.5). Audited `recovery_request_verify`.

### 18.3 The account's devices: list and veto

- `GET /account/recovery-requests` → `[{ requestId, state, createdAt, verifiedAt, holdEndsAt,
  platform }]`: the account's live (verified, not vetoed, not committed, not expired) requests. `state`
  is `holding`, `awaiting_operator` or `ready` (fulfilled by the operator, not yet committed), as in
  §18.4; `platform` is self-reported. An unverified request is not listed. `/sync` carries their count
  as `recoveryRequests` (§4), from the same set, so the count and the list agree. A request is shown to
  the account's signed-in devices, and can be vetoed, in each of those three states. A device shows
  "Someone asked the operator to reset your account. If this wasn't you, cancel it."
- `POST /recovery/requests/{requestId}/veto { statement }` → `ok`, **with the device's session** for
  that account. `statement` is a 0x0A frame `{"v":2,"purpose":"recovery-veto","requestId":<b64_16>,
  "userId":<uuid>,"issuedAt":<ms>}` signed by the account's identity key. **Checks:** the request is a
  live request of the session's account (`404 request_unknown`); the strict parse (`400 bad_frame`,
  `400 non_canonical`, `400 bad_statement`); then, in the shared verifier's order (spec 04 §7): the
  signer maps to the account's stored `identityPub` (`400 bad_signer`); the signature
  (`400 bad_signature`); `statement.userId` equals the session's and its `requestId` the path's
  (`400 bad_signer` for either). So a statement with a broken signature and another account's `userId`
  answers `400 bad_signature`. The request dies (`vetoed`); a veto after fulfilment discards the sealed
  payload the operator stored. `recovery_request_cancelled` names the device. Audited
  `recovery_request_veto`.

### 18.4 Polling

`POST /recovery/requests/{requestId}/poll { pollSecret }` → unauthenticated; a `pollSecret` whose hash
is not the request's (or an unknown request) is `404 request_unknown`. Every accepted `POST
/recovery/requests` stored a row (a decoy included, §18.1), so the requester's own poll is answered
alike for an operator-posture account, a private-posture one and an unknown address: `unverified`,
then `expired`. The secret travels in the body so
it stays out of URLs and access logs.

- Before fulfilment: `{ state, holdEndsAt? }`, `state` one of `unverified`, `holding` (verified, hold
  not over), `awaiting_operator` (hold over), `vetoed`, `expired`.
- Once fulfilled: `{ state: "ready", sealed, encryptedIdentitySeed, identityPub, commitHash }`. The app opens
  `sealed` with `rSec` and requires spec 04 §7's checks: the 0x09 frame, the signer mapping to the
  recovery key the **pinned card's** `recoveryFp` names, `instanceId`, `userId`, `requestId` and
  `requestKey` matching, and the identity seed opening under the UVK to the served `identityPub`.
  `commitHash` (additive) is the hash stored with the newest upload (§18.6). Before it asks its person
  for anything, the device compares it with the hash of the value it opened; a difference means the
  answer on the server is not the one it opened. It is served only past the poll secret, as `sealed` is.
  **An answer that names another account than the one this device keeps for the request's address
  is refused at the pick-up** (rule of 2026-11-17, spec 01 §7): where the device keeps an account at
  this server under that address, or knows the address there as another account, the answer's
  `userId` must be that account's, checked before the person is asked anything; otherwise no account
  is shown to check, no password is asked, no commit is sent, the request stays, and the refusal
  says that the answer names an account that is not the one this device keeps. The shared code and
  `andvari-cli` keep this (2026-11-17). **Not kept yet (2026-11-17):** neither app draws that
  refusal; the request screen stays as it was.

A verified request expires 30 days after its hold ended if never committed, fulfilled or not. That
lifetime is checked at every poll and at the commit (§18.5), not only by the janitor's sweep, so a
fulfilled request past it cannot be committed.

**Cancelled by the account's own changes.** Three events cancel every request of the account not yet
committed (unverified, verified or fulfilled), inside their own transaction: the recovery posture
changed to `private` (§3.1), a password change (§3), and any recovery commit, by kit (§12) or
assisted (§18.5). A verified or fulfilled request becomes `vetoed` at once, and its stored code MAC,
any sealed payload and its commit hash are dropped. A veto (§18.3) drops the commit hash with the
sealed payload.
**The poll of a request whose mailed code was not entered never changes with what the account's
owner does** (rule of 2026-11-16): a cancel would otherwise tell whoever opened the request, and never
read the mailbox, that the address has an account, because a decoy is never cancelled. Such a request
keeps its state (`unverified`, then `expired` at 24 hours) and is only marked cancelled; an account
deletion leaves it as a decoy. The cancel is told at the code step, to someone who has shown that they
read the mailbox: the right code is `409 request_state` and the request becomes `vetoed`, which its
poll then answers; a wrong code is the uniform `400 bad_code`. **For the device that asked, that
`409 request_state` is a final stop:** it forgets the request it kept, offers no further code for it,
and says that the request was cancelled because the account's password or recovery setting changed,
or the account was recovered, after it was asked, and that a new request can be started. The shared
code answers that `409` with the final stop `request_cancelled` and forgets the kept request; a wrong
code stays a refusal at which the step stays. **A request ended from the account's side gets one
sentence that names the possibilities** (rule of 2026-11-17), wherever a client shows it: it was
ended by one of the account's signed-in devices, or because its master password or its recovery
setting was changed meanwhile; if that was not the person, they tell whoever runs the server; they
can ask again. The server does not say which: it would tell whoever holds a request's code what the
account's owner did, and the sentence is true without it. No new field. Since 2026-11-21 (rules of
2026-11-20, for a request that whoever runs the server ended, as `andvari admin restored` does) this
sentence and the cancellation's above also name that cause: "or by whoever runs the server", naming
no restore; and after the operator's answer was opened, a commit the server refuses because the
request can no longer be finished is a result of its own in the shared code (`ReplacePasswordResult.REQUEST_ENDED`: it ran
out of time or was used, or whoever runs the server ended it; nothing was changed; a new request
starts again), while a recovery with the kit keeps "too late". The three lines are the shared code's
(design §9.6) and await their words; neither app draws the first yet.

### 18.5 Commit

`POST /recovery/requests/{requestId}/commit { pollSecret, commit, newAuthKey, newKdfSalt, newKdfParams,
newWrappedUvk, newMemberRecovery: { recoveryWrappedUvk, recoveryAuthKey }, device: { platform, name,
deviceSecret } }` → `200 SessionResponse` plus `recoveryPieceId`.

`commit` is a `b64_32`: the commit value from the version-3 answer the device opened (spec 04 §7 step
4). A reset is accepted only from a device that opened the answer (rule of 2026-11-16).

**Checks:** `pollSecret` (`404 request_unknown`); the request is fulfilled, not vetoed and, at this
moment, not past its lifetime (§18.4) (`409 request_state`); `commit` a JSON string that is a
`b64_32`, the canonical form of 32 bytes (absent, `null`, a number or any other non-string, or another
text: `400 bad_commit`); `hexLower(SHA-256("andvari/v2|recovery-request|commit|" + commit))`, over
the text as sent, which `bad_commit` has already required to be canonical, so it is the same input as
spec 01's `b64url(commit)`, equals the
`commitHash` stored with the newest upload, compared in constant time (`403 commit_mismatch`). A wrong
value changes nothing about the request (rule of 2026-11-16: the value is 32 random bytes, so a limit
of attempts protects nothing, and it would let a damaged upload, or anyone who saw a poll secret,
destroy a request that took seven days): it is audited
`recovery_request_commit_mismatch` (meta `at=check`, or `at=commit` for the comparison made again
inside the commit's transaction, which is audited too), the route keeps its per-IP bucket, and the
request stays as it was, so the right value still commits. The comparison is made again inside the
commit's transaction, so an upload that replaced the answer meanwhile refuses a value from the older one. Then the account is `active`, exactly as at
the kit commit (`400 recovery_account_not_active`); the KDF floor and shape, the salt bound, and `newMemberRecovery`, which is
required
(`400 kdf_too_weak`, `400 kdf_mem_not_kib_multiple`, `400 bad_kdf_salt`, `400 recovery_required`).
Then one transaction, as the kit commit (§12), which checks the account's status again inside it (both
commits do, so a disable that lands after the first check still refuses the commit): the new verifier, salt, params and `wrappedUvk`; the
member-recovery row **replaced** (new `pieceId`, `recoveryConfirmed = 0`); every session revoked; the
stored `deviceSecret` hash of every earlier device cleared, so every earlier device becomes unknown
(§16.8); `requireLink` and two-step sign-in cleared; the request deleted and the account's other requests
cancelled (§18.4); the device (`how = recovered`) and its session created. Emails: `recovery_applied` ("with the operator's help"), `two_step_off` and
`require_link_cleared` where they apply. Audited `recovery_request_commit`. The client shows the new
kit through the capture gate before the vault opens.

### 18.6 The operator's side, and variant R on the public instance

- `GET /admin/recovery-requests` → `[{ requestId, userId, email, accountId, rPub, platform, createdAt,
  verifiedAt, holdEndsAt, state }]`: the verified, live requests: `holding`, `awaiting_operator`, and
  `ready` (an answer is stored and not yet committed, so it can still be replaced, below). `state` is
  new and additive: a client that does not find it reads the row as `holding` or `awaiting_operator`
  from `holdEndsAt`. `email` is the account's `emailNorm`, the address the request was made for.
  `accountId` is the 32-hex short identity fingerprint as the server holds it: a client never offers it
  as a value to copy into `recovery-cli` or to check a person against (rule of 2026-11-16: nothing
  the server says is offered as something to check against), and `platform` is self-reported. Before
  a row is shown or copied, a client checks each field: `requestId` a `b64_16`, `userId` a uuid, `email` an `emailNorm`, `accountId` 32 lowercase
  hex, `rPub` a `b64_32`, `platform` one of §0.1's list, `state` one of the three above; a row that
  fails is not shown. **It never carries the request code**: the operator must get it from the person
  and type it into `recovery-cli assist`, which checks it against `rPub`.
  **The operator sees which recovery key a copy is sealed to.** Each row also carries
  `escrowFingerprint` (additive): the `hex64` recovery-key fingerprint the account's stored copy was
  stored under, as the server has it, absent when the account has no copy; the copy download (below)
  carries the same value as `fingerprint`. It is the server's word: a console uses it only to choose
  what it says (a copy sealed before the server's recovery key changed needs both sheets, spec 04 §5),
  never as a key or as a check of the copy, which the offline tool reads from the copy's own named key.
  A present value that is not `hex64` fails the row's check. The server serves both fields, and the
  shared code reads them with that check. Both consoles say it on the row: where the served value is
  present, the pinned card names a recovery key, and the two differ, the row says that the account's
  copy was sealed to the server's outgoing recovery key, before the key changed (as the server says),
  and that both recovery sheets are needed, the current one, which signs the answer, and the outgoing
  one, which opens the copy. The desktop takes the line from the shared code's operator console;
  `andvari-cli operator recovery-requests` applies the same rule itself and carries `escrowFingerprint` in its
  `--json` rows, null when the server sent none.
- `POST /admin/accounts/{userId}/escrow { currentAuthKey }` → `{ userId, sealed, encryptedIdentitySeed,
  identityPub }`. Operator-posture accounts only; an account with no escrow row is `404 no_escrow`, an
  unknown one `400 no_such_user`. A `POST` so it carries the password proof. Sends
  `operator_escrow_read`. Audited `operator_escrow_read`.
- `POST /admin/recovery-requests/{requestId}/fulfil { sealed, requestKey, commitHash, currentAuthKey }`
  → `ok`. The three values are the token `recovery-cli assist` printed, as the shared reader yields
  them (spec 04 §7 step 3): `sealed` the sealed version-3 0x09 statement (unpadded base64url),
  `requestKey` the request key the tool sealed to (a `b64_32`), `commitHash` the `hex64` hash of the
  answer's commit value. **Checks, in order:** the password proof (`403 reauth_failed`); the body's
  shape, before anything stored is read, in this order: `400 bad_sealed` for a `sealed` that is not a
  string of canonical base64url of 1 to 1,024 bytes, `400 bad_request_key` for a `requestKey` that is
  not a string `b64_32`, `400 bad_commit_hash` for a `commitHash` that is not a string `hex64` (each
  absent, `null` or not a string is that field's refusal); an unknown request
  (`404 request_unknown`); the request is verified and past its hold, or fulfilled and not yet
  committed, and in either case not vetoed and not past its lifetime (`409 request_state`);
  `requestKey` is the row's `rPub` (`400 request_key_mismatch`: an answer made for another request);
  `sealed` decodes to exactly `525 + E` bytes, `E` the length of the unpadded base64url of the
  account's `emailNorm` (`400 bad_sealed`: a cut or over-long answer, or one made for another
  address). The server stores `sealed` for the poll and `commitHash` for the commit (§18.5).
  **An upload can be repeated until the commit** (rule of 2026-11-16): a later upload replaces the
  earlier answer and hash, and resets nothing else. Every upload is
  audited `operator_recovery_fulfil`, meta `target=<userId>` and, when it replaced an answer,
  `;replaced=1`. These checks are a convenience: the device's check inside the seal (spec 04 §7 step 4)
  and the commit value (§18.5) are what bind an answer to its request.

**Variant R (decided on 2026-11-15: operator recovery is not offered on the public instance).** On an
instance whose `ANDVARI_INSTANCE_KIND` is `public`:

- routes 4, 5, 23, 29, 68–72 and 84–86 of §0.2 answer `404 not_found`;
- `posture: operator` is refused at register and at `PUT /account/recovery`
  (`400 operator_recovery_unavailable`);
- `PUT /instance/card` refuses a card with a `recoveryFp` other than `none` (`400 bad_card`);
- `/sync`'s `recoveryRequests` is always 0.

Clients enforce the same rule on their side, independently of the server: when the pinned card's
`kind` is `public` they never offer operator recovery or "Ask the operator", never seal or re-seal an
escrow, and ignore `recoveryFp` (spec 04 §2). Variant K for the public instance would change only what
Appendix A lists.

## Appendix A. Variant K on the public instance (not in force)

This appendix is **not normative** while W1 (variant R) stands, which the owner confirmed on 2026-11-15
(design 2026-11-15 §0.6). Should the owner ever choose variant K for the public instance, this list is
the whole change to this document; private
instances already behave this way.

| Area | Change for `ANDVARI_INSTANCE_KIND = public` under K |
|---|---|
| Card | `PUT /instance/card` stops refusing a public card with a `recoveryFp` (that `400 bad_card` case goes). |
| Routes | Routes 4, 5, 23, 29, 68–72 and 84–86 stop answering `404 not_found` and behave as on a private instance. |
| Refusals | Register and `PUT /account/recovery` accept `posture: operator`; `400 operator_recovery_unavailable` is then returned only when `recoveryFp = none` or for the operator account. |
| `/sync` | `recoveryRequests` counts as on a private instance. |
| Client rule | Store builds drop "`kind = public` means no escrow" (spec 04 §2), which needs a client release. |
