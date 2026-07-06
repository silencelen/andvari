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
