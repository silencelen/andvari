# andvari spec 06 — import formats

Import is **100 % client-side**: parse → build item plaintext docs → encrypt →
normal `/sync/push`. The file never uploads; clients SHOULD offer to shred/clear the
source file and MUST warn it contains plaintext passwords.

## 1. Chrome / Edge CSV

Header (Chrome ≥ 2023, Edge identical): `name,url,username,password,note` (older
exports lack `note`). RFC 4180 quoting (fields may contain commas/newlines/quotes —
use a real CSV parser, never split-on-comma).

Mapping → login item: `name`→name (fallback: URL host), `url`→login.uris[0],
`username`→login.username, `password`→login.password, `note`→notes. Rows with an
empty password AND empty username are skipped (Chrome exports junk rows for saved
forms).

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
- **Dedup rule:** exact duplicate rows (same url+username+password) collapse to one.
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

## 5. Test vectors

`test-vectors/import.json` (emitted by `tools/vector-gen` from the `:core` reference
impl) has a `files[]` array (each `{name, contentB64, expect:{format, rows, errors,
docs, report}}`) and a `reject[]` array (`{name, reason, ...}`, some recipe-constructed
— e.g. `too_many_rows`, `too_large` — to keep the file small). Both impls consume it.
