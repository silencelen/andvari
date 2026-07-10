# Guided importers — design (2026-07-09)

Queue item 5 (ROADMAP "Guided per-source importers"). Inherits **F75's vault-aware dedupe**
half and **F56's measure-first perf pack**. Target release: 0.8.0. Everything client-side
and ZK-clean: files never leave the device; the server sees only ordinary encrypted puts.

## Scope (four workstreams, one cycle)

1. **Guided per-source picker, all three clients** — replace the bare "CSV upload" with
   named sources: *Chrome, Edge, Brave, Opera* (all emit the same Chromium CSV the parser
   already handles), *Firefox*, *Bitwarden, 1Password, LastPass* (new adapters). Each
   source = a short "how to export" instruction block + the file input. The picker
   informs INSTRUCTIONS and mismatch hints only — **header detection stays authoritative**
   (a Bitwarden file picked under "Chrome" imports fine, with a gentle "this looks like a
   Bitwarden export" note). Desktop currently has NO import flow — it gains the whole
   thing (core `CsvImport` is already multiplatform; Android's ViewModel wiring is the
   model).
2. **Three new format adapters, BOTH impls** (Kotlin `CsvImport.kt` reference + TS
   `csv.ts` twin), pinned by a NEW vector file `spec/test-vectors/import-foreign.json` —
   `import.json` stays byte-frozen. Spec 06 gains one section per format (normative).
3. **Vault-aware dedupe (F75)** — `plan` gains the target vault's existing items as an
   input on both impls; rules below.
4. **F56 perf pack, measure-first** — 10k-scale fixture, measurements, then only the
   fixes the numbers justify.

## Format adapters (normative contracts)

Common: same charset/quoting/CR rules as spec 06 §3-4 (the shared low-level CSV reader is
already format-blind); `MAX_BYTES`/`MAX_ROWS` caps unchanged; per-row errors keep the
existing `RowError` taxonomy; header matching is lowercase, order-insensitive, BOM-tolerant.

**Detection is SPECIFICITY-ORDERED subset matching** (most-specific first):
`bitwarden → lastpass → 1password → firefox → chrome`. This is load-bearing: LastPass's
header (`url,username,password,totp,extra,name,grouping,fav`) is a SUPERSET of Chrome's
required set (`name,url,username,password`), so a naive any-order subset test misreads
LastPass as Chrome. Vector-pinned: a LastPass file MUST detect `lastpass`; ambiguity cases
live in `import-foreign.json`.

- **Bitwarden CSV** (`folder,favorite,type,name,notes,fields,reprompt,login_uri,
  login_username,login_password,login_totp`):
  `type=login` → login item: uri→uris[0], username, password, `login_totp` through the
  existing TOTP normalize (accepts otpauth:// or bare base32), notes verbatim; custom
  `fields` (newline-separated `k: v` in the export) are APPENDED to notes under a
  `"— custom fields —"` separator line (data preservation over prettiness).
  `type=note` → **note item** (name + notes). `favorite` truthy (`1`/`true`) →
  `favorite: true`. Any other `type` value → skipped + enumerated by name
  (`unknownTypeSkipped`). `folder`/`reprompt` ignored (documented).
- **LastPass CSV** (`url,username,password,totp,extra,name,grouping,fav`):
  normal rows → login (extra→notes, fav truthy→favorite, totp via normalize).
  `url == "http://sn"` → **note item** (name; `extra` verbatim as notes — templated
  `NoteType:` blobs are NOT parsed, they import as-is; honest over clever). `grouping`
  ignored. Cards/addresses live inside templated sn rows → they arrive as note items
  (enumerated under notes, not silently dropped — a card the user wants becomes a card by
  hand later; parsing LastPass templates is rejected scope).
- **1Password CSV** (1Password-8 export: `title,url,username,password,otpauth,favorite,
  archived,tags,notes` — case-insensitive match on the lowercased set):
  rows → login items (otpauth→totp via normalize, favorite truthy→favorite, tags ignored).
  `archived` truthy → **skipped + enumerated** (`archivedSkipped`) — archived items were
  deliberately shelved by the user; silently resurrecting them is the surprise, importing
  none of them is the safe default the report explains. Older 1Password CSV shapes vary
  wildly → `unrecognized_header` with the per-source hint ("export from 1Password 8+ as
  CSV, or use Bitwarden/CSV as an intermediate").

New `ParsedRow` additions (both impls): `kind: "login" | "note"`, `favorite: Boolean`.
`ImportFormat` grows `"bitwarden" | "1password" | "lastpass"`. The planner maps
`kind=note` → `ItemDoc(type="note", name, notes)`.

## Vault-aware dedupe (F75) — plan rules

`plan(parsed, existing, newId)` where `existing` = light projections of the TARGET
(personal) vault's items, decrypted client-side by the caller:
logins `{url0, username, password, totp}` + notes `{name, notes}`. Comparison scope is the
personal vault ONLY (imports land there; a copy living in a shared vault is not the same
item — rejected alternative: all-vault matching, which silently suppresses wanted personal
copies). The EXISTING vault is never mutated by an import — zero-destruction.

Rules, in order, per file row (in-file rules unchanged and applied after vault rules):
1. Exact vault match — login: (url, username, password, totp) equals an existing personal
   login → **skip**, enumerate by name under `alreadyInVault`. Note: (name, notes) equals
   an existing personal note → same.
2. Same site+user, different secret — login (url, username) matches an existing personal
   login but password/totp differ → **import as a NEW item**, renamed with the existing
   `"(k)"` convention and enumerated under `differsFromVault` ("imported separately —
   review which password is current"). The existing item is untouched.
3. The in-file `exactSeen`/`groupCount` logic runs as today, with `groupCount` SEEDED from
   the existing vault's (url, username) counts so renames continue the sequence the vault
   already shows (a vault "GitHub" + a file GitHub-with-new-password imports as
   "GitHub (2)").

`ImportReport` grows `alreadyInVault: string[]`, `differsFromVault: string[]`,
`archivedSkipped: string[]`, `unknownTypeSkipped: string[]`, `noteItems: number` (count of
notes imported). All enumerated BY NAME in the UI (house rule), collapsible when long.
Report semantics are vector-pinned in `import-foreign.json` (cases carry an
`existing` fixture block).

## Guided UI (per client, house idioms)

- **Web** (`ImportPanel`): a source grid replaces the bare file button — 8 text cards
  (Chromium four + Firefox + the three managers). Selecting shows 2-4 numbered export
  steps (exact menu paths) + the file input + a "my file is from somewhere else" escape
  back to the grid. Post-parse: if detected format ≠ the picked source's expected
  format(s), a calm info line ("this file looks like a {X} export — imported it as {X}").
  Report gains the new buckets. Chromium四 all expect `chrome`.
- **Android**: a source list sheet before the existing file picker; same copy; report
  buckets added. The ViewModel's `plan` call gains the `existing` projections from the
  engine's working set.
- **Desktop**: the FULL import flow, new (source list → file dialog → preview/report →
  import), mirroring Android's ViewModel choreography over the same core `CsvImport`;
  bounded read per Android's `readBounded` precedent.

## F56 perf pack (measure-first; its own workstream)

Fixture: a seeding tool creating a 10k-login vault against a scratch local server (the
e2e harness pattern — NEVER CT122). Measure and RECORD in this doc's addendum: (a) full
since=0 pull wall-time + payload size, (b) the OR-join item query plans (`EXPLAIN QUERY
PLAN`) from Service.kt's pull, (c) orphan-GC lock hold time with the blob dir populated,
(d) web list render with 10k items (manual observation + React profiler note), (e) import
of a 10k-row file end-to-end. Fixes gated on numbers, additive-only, in priority order:
split OR-joins into UNIONed indexed queries; move blob file deletes post-commit; window
the web vault list (virtualize at >N items); a `more`/paging flag on pull ONLY if the
payload numbers demand it (wire-additive: absent flag = today's behavior).

## Constraints

Everything in `docs/PICKUP-v8.md` §binding constraints applies (ZK, additive wire,
byte-frozen existing vectors, verify.sh+e2e.sh, adversarial review per slice, .copy()/
spread-only). `import.json` untouched; the new vector file is this feature's only vector
authoring. Spec 06 edits are additive sections. The 0.7.0 card-create gates are NOT
touched by this cycle.

## Breaker amendments (NORMATIVE — supersede any conflicting text above; 2-breaker pass, 2026-07-09)

A1. **Kind-scoped plan rules.** `skippedEmpty` applies to `kind=login` ONLY (a note is
    skipped only when name AND notes are both empty). Notes get their own in-file exact
    key `(name, notes)` and a name-keyed rename rule. Without this, every LastPass/
    Bitwarden note row is annihilated (empty credentials → skippedEmpty, or collapsed as
    "exact duplicates" of each other). Vector: a multi-note file where two distinct notes
    both import.
A2. **Bitwarden `fields` append applies to `type=note` rows too** (same
    `— custom fields —` separator) — secure notes routinely carry hidden custom fields.
A3. **REQUIRED header sets, pinned** (detection = specificity-ordered REQUIRED-subset):
    bitwarden `{type,name,login_uri,login_username,login_password}`;
    lastpass `{url,username,password,extra,name,grouping}` (totp/fav OPTIONAL — pre-2023
    exports lack totp and MUST still detect lastpass, not chrome);
    1password `{title,url,username,password,otpauth}` (favorite/archived/tags/notes
    optional). Negative vectors: andvari's own CSV export detects `chrome` (never
    lastpass); 7-column LastPass detects `lastpass`; org-vault Bitwarden (collections
    instead of folder/favorite) detects `bitwarden`. Accepted free win, pinned: Apple/
    Safari's `title,url,username,password,notes,otpauth` matches the 1password set and
    imports correctly through it.
A4. **Bitwarden `login_uri` splits on `,` into `uris[]`** (the exporter comma-joins
    multi-URI logins; verbatim storage kills UriMatch). Two-URI vector; the literal-comma
    edge is documented as accepted.
A5. **TOTP: one shared normalize + reject-don't-corrupt.** Hoist a single
    `normalizeTotp` (byte-exact: strip ALL whitespace; bare base32 wraps to otpauth://)
    into core `Totp` + web `totp.ts`; the web/Android/desktop editors DELEGATE to it
    (private copies deleted). Adapters: a totp value that the shared parse rejects
    (steam://, otpauth://hotp/, junk) is NEVER stored in `login.totp` — it is preserved
    in notes under `Unsupported TOTP (kept as text): <raw>` and enumerated by name in a
    new `totpUnsupported` report bucket. Vectors: steam://, hotp, garbage, bare-base32.
A6. **Truthiness predicate, pinned once for all formats:**
    `trim().lowercase() ∈ {"1","true","y","yes"}`; everything else — including `"0"`,
    `""`, `"false"` — is falsy (LastPass writes fav=0 on EVERY row; JS `Boolean("0")` is
    the trap). Vectors: fav=0 → not favorite; archived=TRUE → archivedSkipped.
A7. **Vault-rule keying (rules 1–2), pinned:**
    - URL equality = the spec 02 §3.1 saved-uri normalizer's equivalence (normalizeHost/
      parseSavedUri classes), row url compared against EVERY saved uri of the existing
      item, not just uris[0]. Username/password stay exact-string.
    - TOTP compared by PARSED parameters (secret bytes + algorithm + digits + period),
      never raw string; a source format with NO totp column is a WILDCARD on totp in
      rules 1–2.
    - Empty-discriminator guard: when url AND username are both empty, rule 1 keys on
      (name, password[, totp]) and rule 2 NEVER fires — fall through to import + in-file
      rules.
    - All composite keys (in-file AND the seeded vault map) are tuple/NUL-joined, never
      space-joined; projections map absent→"" (uris `[]` and `[""]` are the same);
      vault-side note text is CRLF/lone-CR→LF normalized before note rule-1 comparison.
A8. **The `existing` seam is core-owned and refuses rather than degrades:** one
    projection builder filtering `vaultId == personalVaultId` used by ALL clients (never
    raw item lists at call sites); when the vault is locked/unsynced/unavailable the plan
    step REFUSES with honest copy ("couldn't check your vault — sync/unlock first"),
    never silently plans with empty `existing`.
A9. **Report/rename honesty:** `noteItems` is a NAME LIST (not a count); `totpUnsupported`
    added; rule-2 copy splits "password differs" vs "2FA secret differs"; the "(k)" rename
    bumps k until the display name is FREE in the target vault (no collisions with
    existing names); row errors render as "row N (file line M)" so multi-line-note files
    don't confuse.
A10. **LastPass mangle heuristic:** the LastPass instruction block pins the file-download
    export path, and a post-parse info line fires when multiple values match
    `/&(amp|lt|gt|quot|#\d+);/` ("this file looks HTML-mangled — re-export via
    Advanced → Export"). Never auto-decode.

## Honest costs / rejected scope

LastPass templated notes (cards/addresses/bank) import as raw note items, not typed items
— parsing LastPass templates is deferred until someone actually needs it. 1Password 1pux
(the richer zip/JSON export) is rejected this cycle — CSV covers logins; 1pux is a future
adapter on the same seam. Folder/collection/tag structures do not map to vaults —
deliberately ignored (andvari's sharing model is vaults-with-grants, not folders).
Chromium per-browser differences are instructions-only (same file format). The dedupe
never updates an existing item in place — "update the vault item from the file" is
rejected as silent destruction; the rename-and-review path is the household-safe shape.
