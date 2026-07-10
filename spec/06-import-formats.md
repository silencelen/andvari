# andvari spec 06 — import formats

Import is **100 % client-side**: parse → build item plaintext docs → encrypt →
normal `/sync/push`. The file never uploads; clients SHOULD offer to shred/clear the
source file and MUST warn it contains plaintext passwords.

## 1. Chrome / Edge CSV

Header (Chrome ≥ 2023, Edge identical): `name,url,username,password,note` (older
exports lack `note`). RFC 4180 quoting (fields may contain commas/newlines/quotes —
use a real CSV parser, never split-on-comma). Detection is set-membership, so extra
columns are tolerated — in particular andvari's own CSV export (spec 07 §1) is a
Chrome superset with a trailing `totp` column.

Mapping → login item: `name`→name (fallback: URL host), `url`→login.uris[0],
`username`→login.username, `password`→login.password, `note`→notes,
`totp`→login.totp when the column is present (andvari round-trip; browser exports
lack the column). Rows with an empty password AND empty username are skipped
(Chrome exports junk rows for saved forms).

## 2. Firefox CSV

Header: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,
timeLastUsed,timePasswordChanged` (times = unix **millis**).

Mapping: name = URL host (Firefox has no name column); `url`→uris[0];
username/password direct; `httpRealm` non-empty → append to notes ("HTTP realm:
…"); `timePasswordChanged` → seed passwordHistory retiredAt context (informative
only). `guid` is NOT preserved as itemId (always mint fresh UUIDs).

## 3. Common rules

- Encoding: UTF-8 (accept BOM). Reject files > 10 MiB or > 10 000 rows with a clear
  error.
- **Dedup rule:** exact duplicate rows (same url+username+password+totp) collapse to
  one (totp joined the key in 0.4.0 alongside the `totp` CSV column).
  Same url+username with DIFFERENT passwords imports both, second and later named
  "<name> (2)", "<name> (3)"…, and the import report flags them for manual cleanup.
- Import report (shown, not stored): imported / skipped-empty / collapsed /
  flagged-duplicate counts + per-row parse errors with line numbers.
- Everything lands in the user's personal vault; moving to shared vaults is a
  post-import manual action.
- Vector coverage: `test-vectors/import.json` carries sample Chrome and Firefox
  files (quoting edge cases: embedded commas, quotes, newlines, BOM) with expected
  parsed rows. Both implementations must parse identically.

## 4. Normative parsing algorithm

Both impls MUST follow this exactly (checked order), so they agree byte-for-byte:

1. **Limits (before decode):** raw length > 10 MiB → reject `too_large`. After parsing,
   data rows (excluding header) > 10 000 → reject `too_many_rows`.
2. **Decode:** UTF-8, lenient (invalid sequences → U+FFFD). Strip one leading BOM
   (`EF BB BF`).
3. **RFC 4180 state machine:** records end at `CRLF`, bare `LF`, **or a lone `CR`**
   (a `CR` not followed by `LF` is a record terminator, equivalent to `LF`); one
   trailing newline is ignored. `"` opens a quoted field only at field start; `""`
   inside quotes is a literal quote; quoted fields may contain commas/CR/LF.
   **Lenient rules:** a `"` inside an *unquoted* field is a literal character; content
   after a closing quote before the next delimiter → per-row error `bad_quote` (row
   skipped, import continues); **EOF while inside a quoted field** (unterminated quote)
   → per-row error `bad_quote` at the row's opening line (row skipped, prior rows still
   import).
4. **Header detection** (row 1, names trimmed + lowercased): contains
   `name,url,username,password` → Chrome/Edge (a `note` **or** `notes` column is
   optional; Chrome emits `note`); else contains `url,username,password` plus any of
   `guid|httprealm|formactionorigin` → Firefox; else reject `unrecognized_header`.
   Columns are mapped **by header name, not position**.
5. **Row errors:** field count ≠ header count → `wrong_field_count`. Errors report the
   **1-based physical line number of the row's first character** (embedded newlines
   make row index ≠ line number).
6. **Skip:** empty username AND empty password → counted `skippedEmpty`.
7. **Name fallback host extraction** (pinned; no URL library): trim → strip
   `scheme://` (`[A-Za-z][A-Za-z0-9+.-]*://`) → cut at the first `/ ? #` → drop
   userinfo up to the last `@` → if it starts `[`, host = the bracket contents (IPv6)
   else strip a trailing `:digits` → lowercase. Empty → the trimmed raw url → else
   `"Imported login"`. Chrome: only when `name` is empty; Firefox: always.
8. **Dedupe / rename** (file-internal, in row order after skips/errors): an exact
   `(url, username, password)` repeat is dropped (`collapsed++`); the same
   `(url, username)` with a *different* password imports with name `"<name> (n)"`
   (n = the 2-based index of the distinct password within the group) and is recorded in
   `flagged`.
9. **Report:** `imported`, `skippedEmpty`, `collapsed`, `flagged: [names]`,
   `errors: [{line, code}]`. Firefox `timePasswordChanged` is parsed but NOT
   materialized into `passwordHistory` in v1 (no retired password value exists).

**Idempotent retry (client duty):** the itemId + push mutationId for each planned row
are minted ONCE at plan time and reused on every retry of the SAME plan, so re-running
an interrupted import replays server-side (idempotency key = deviceId+mutationId) rather
than duplicating. Re-*parsing* the file mints a fresh plan (new ids) → duplicates; the
UI MUST warn of this. There is no dedupe against items already in the vault (v1).

### §4 addendum (0.8.0) — vault-aware plan (F75)

Supersedes the "(v1) no vault dedupe" sentence above. `plan(parsed, existing, newId)`
takes light projections of the TARGET **personal** vault (imports land there; a copy in
a shared vault is a different item), decrypted client-side and built ONLY by the ONE
core-owned builder (`CsvImport.projections` / web `buildImportProjections`) — never
ad-hoc mapping at call sites. When the vault is locked/unsynced the UI REFUSES the plan
step with honest copy; it never silently plans against empty projections. The existing
vault is NEVER mutated by an import — zero-destruction. The 2-arg `plan(parsed, newId)`
still exists and equals empty projections (the frozen `import.json` behavior).

Projections: logins `{name, uris[], username, password, totp?}`, notes `{name, notes}`,
plus `names[]` = ALL personal item display names (every type). Absent → `""`; `uris []`
and `[""]` are equivalent.

Per file row, in checked order, **kind-scoped**:

- **Skip-empty (first, junk filter):** login rows with empty username AND password →
  `skippedEmpty` (as §4.6); note rows only when name AND notes are BOTH empty (same
  counter).
- **Vault rule 1 — exact match → skip,** enumerate the row's parsed name under
  `alreadyInVault` (repeated matching rows are listed each time; vault rules run before
  the in-file collapse). Login key = (url, username, password, totp); note key =
  (name, notes) with VAULT-side notes CRLF/lone-CR→LF normalized first (the CSV reader
  already yields LF on the file side).
- **Vault rule 2 (logins only) — same site+user, different secret → import as a NEW
  item,** renamed per the rename rule below, enumerated under `passwordDiffers`, or
  under `totpDiffers` when some existing item matches (url, username, password) and
  only the TOTP differs. A row differing in BOTH goes to `passwordDiffers` only.
- **In-file exact collapse** (as §4.8, key now includes the full `uris` list and `totp`)
  and note-exact collapse on (name, notes) — `collapsed`.
- **In-file grouping / rename:** login groups key on the raw (url, username) as §4.8,
  but the group counter is SEEDED from the vault's matching (url, username) item count
  so renames continue the sequence the vault already shows (a vault "GitHub" + a file
  GitHub-with-new-password imports as "GitHub (2)"). Notes group on name alone (no
  vault seed — notes have no rule 2; a same-name different-body note imports under its
  own name). In-file renames (not attributable to a vault difference) are `flagged`.

**Keying (normative, both impls):**

- **Url equality** = the spec 02 §3.1 saved-uri normalizer's equivalence classes
  (`parseSavedUri`/`normalizeHost`): scheme/case/`www.`/port/path/userinfo-insensitive
  host classes, `androidapp://` ids their own class. The row's url is compared against
  EVERY saved uri of an existing item, not just `uris[0]`. Unparseable/empty uris on
  the vault side are dropped; an item with none left occupies a no-uri sentinel class
  which an empty/unparseable row url also maps to. Username/password compare as exact
  strings.
- **TOTP compares by PARSED parameters** — secret bytes + algorithm + digits + period
  (label/issuer ignored) — never as raw strings; both sides pass through the shared
  normalize (§9.2) first. Absent (null/`""`) equals absent; a value the parser rejects
  equals NOTHING (the row imports and the user reviews). A source file with NO totp
  column is a **wildcard** on totp in rules 1–2 (rule 2 then always reports
  `passwordDiffers`).
- **Empty-discriminator guard:** when a login row's url AND username are both empty,
  rule 1 keys on (name, password[, totp]) against existing items that are themselves
  url-less AND username-less; rule 2 never fires and the vault seeds no group — the
  row falls through to import + in-file rules (unrenamed if first).
- All composite keys (in-file and the vault maps) are tuple/NUL-joined, never
  space-joined.

**Rename rule (A9):** when a rename fires (group k ≥ 2), the "(k)" suffix bumps k until
the display name is absent from BOTH `existing.names` and the names already planned in
this run; the group counter continues from the k actually used. First occurrences
(k = 1) keep their name even if the vault already shows it.

**Report (final shape):** `imported`, `skippedEmpty`, `collapsed` counters; name lists
`flagged`, `alreadyInVault`, `passwordDiffers`, `totpDiffers`, `archivedSkipped` (§8),
`unknownTypeSkipped` (§6), `totpUnsupported` (§9.2), `noteItems` (all imported notes);
`errors` (RowError, unchanged). Skip lists carry parsed names; imported-item lists
carry the FINAL (post-rename) display names. `totpUnsupported` lists only rows that
actually import (a skipped row's unusable seed is covered by its skip bucket).

## 5. Test vectors

`test-vectors/import.json` (emitted by `tools/vector-gen` from the `:core` reference
impl) has a `files[]` array (each `{name, contentB64, expect:{format, rows, errors,
docs, report}}`) and a `reject[]` array (`{name, reason, ...}`, some recipe-constructed
— e.g. `too_many_rows`, `too_large` — to keep the file small). Both impls consume it.

**0.8.0 addendum:** `import.json` is BYTE-FROZEN. The guided-importer additions
(§§6–9 formats, §4-addendum vault-aware plan) are pinned by the separate
`test-vectors/import-foreign.json`:
`{ cases: [{name, csv, existing|null, expect: {format, report, items}}],
reject: [{name, csv, error}] }` — `csv` is a plain JSON string, `existing` is a
projections fixture, `report` carries ALL report fields, and `items` are compared
order-sensitively (plan output order; ids excluded, `login` null for note items).
Both impls consume it (`ImportForeignVectorsTest` / the web twin's test).

## 6. Bitwarden CSV (0.8.0)

Personal export header `folder,favorite,type,name,notes,fields,reprompt,login_uri,
login_username,login_password,login_totp`; org exports replace `folder,favorite` with
`collections`. **Required set (detection): `{type, name, login_uri, login_username,
login_password}`** — everything else optional; `folder`/`collections`/`reprompt`
ignored.

Row mapping by `type` (trimmed, lowercased):

- `login` → login item: `name` (empty → §4.7 host fallback on the first uri),
  **`login_uri` splits on `,` into `uris[]`** (segments trimmed, empties dropped — the
  exporter comma-joins multi-uri logins; a literal comma inside one uri is accepted
  loss), `login_username`/`login_password` verbatim, `login_totp` per §9.2, `favorite`
  per §9.3.
- `note` → **note item** (name + notes; login columns ignored), `favorite` per §9.3.
- anything else (card/identity/…) → row skipped + name enumerated under
  `unknownTypeSkipped`.

Non-empty `fields` (the export's newline-separated `k: v` custom fields) are APPENDED
to notes — for `login` AND `note` rows — as `"\n— custom fields —\n" + fields` (data
preservation over prettiness; separator is em-dashes). Note assembly order is pinned:
base notes, custom-fields block, unsupported-TOTP line (§9.2), joined by `\n`.

## 7. LastPass CSV (0.8.0)

Header `url,username,password,totp,extra,name,grouping,fav`. **Required set:
`{url, username, password, extra, name, grouping}`** — `totp` and `fav` OPTIONAL
(pre-2023 exports lack `totp` and MUST still detect `lastpass`, never `chrome`; a file
without `totp` is a totp wildcard in the §4-addendum vault rules). `grouping` ignored.

- `url == "http://sn"` (trimmed, exact) → **note item**: `name` verbatim (may be
  empty), `extra` verbatim as the body — templated `NoteType:` blobs (cards/addresses/
  bank) are NOT parsed, they import as-is (honest over clever), `fav` per §9.3.
- otherwise → login item: `name` (empty → §4.7 fallback on url), url → `uris[0]`,
  username/password verbatim, `extra` → notes, `totp` per §9.2, `fav` per §9.3.

Clients SHOULD pin the file-download export path in instructions and show an info line
when multiple parsed values match `&(amp|lt|gt|quot|#\d+);` ("looks HTML-mangled —
re-export via Advanced → Export"); never auto-decode (A10).

## 8. 1Password CSV (0.8.0)

1Password-8 export header `title,url,username,password,otpauth,favorite,archived,tags,
notes` (case-insensitive). **Required set: `{title, url, username, password,
otpauth}`** — favorite/archived/tags/notes optional; `tags` ignored. Pinned free win:
Apple/Safari's `title,url,username,password,notes,otpauth` matches this set and
imports correctly through it.

- `archived` truthy (§9.3) → row **skipped** + name (title, or the §4.7 fallback when
  empty) enumerated under `archivedSkipped` — archived items were deliberately shelved;
  silently resurrecting them is the surprise, and the report explains the skip.
- otherwise → login item: `title` (empty → fallback), url → `uris[0]`,
  username/password verbatim, `notes` → notes, `otpauth` per §9.2, `favorite` per §9.3.

Older 1Password CSV shapes vary wildly → `unrecognized_header`; clients show the
per-source hint ("export from 1Password 8+ as CSV, or use Bitwarden/CSV as an
intermediate").

## 9. Shared adapter rules (0.8.0)

### 9.1 Detection order + row kinds

Detection is **specificity-ordered REQUIRED-subset matching** on the lowercased header
set: `bitwarden → lastpass → 1password → firefox → chrome`. The order is load-bearing:
LastPass's header is a superset of Chrome's required set. andvari's own CSV export
(spec 07 §1, a Chrome superset) detects `chrome`. Extra columns are always tolerated.

`ParsedRow` gains `kind: login | note` and `favorite: boolean`. The planner maps
`kind=note` → `ItemDoc(type: "note")` (name + notes + favorite, no login). §4.6
skip-empty is kind-scoped (§4 addendum). Chrome/Firefox rows are always
`kind=login, favorite=false` — their mapping in §§1–4 is frozen (vector-pinned by
`import.json`), including totp cells passing through VERBATIM (no §9.2 normalize).

### 9.2 TOTP: one shared normalize, reject-don't-corrupt

ONE byte-exact normalize (core `Totp.normalize` + web `totp.ts` `normalizeTotp`)
shared by the item editors and the import adapters: strip ALL ASCII whitespace
(TAB LF FF CR SPACE); empty → unchanged; `otpauth://` prefix (case-insensitive) →
returned as-is; else if the string base32-decodes when uppercased (padding-tolerant) →
`"otpauth://totp/andvari?secret=" + s` with ORIGINAL case preserved; else unchanged.
**Validity** = the existing otpauth parser accepts the normalized value.

Adapters (Bitwarden/LastPass/1Password) store `login.totp` = the NORMALIZED value ONLY
when valid. An invalid cell (steam://…, otpauth://hotp/…, junk) is NEVER stored as
totp — it is preserved as a notes line `"Unsupported TOTP (kept as text): <raw>"`
(`<raw>` = the trimmed cell) and the item's final name is enumerated under
`totpUnsupported`.

### 9.3 Truthiness (favorite / archived)

One predicate for all formats: `trim().lowercase() ∈ {"1","true","y","yes"}`;
everything else — including `"0"`, `""`, `"false"` — is falsy (LastPass writes `fav=0`
on every row; JS `Boolean("0")` is the trap). Applies to Bitwarden `favorite`,
LastPass `fav` (login and sn-note rows), 1Password `favorite` and `archived`.
