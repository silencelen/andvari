# andvari spec 07 — export & backup formats

Export is **100 % client-side**: decrypt → build the file → hand it to the OS. The
server is never involved, never notified, and never learns an export happened (the
only server-visible trace is ordinary attachment blob reads). Two artifacts:

- **Backup** (`.andvari`, §2) — encrypted, full-fidelity, the default. UI verb:
  **"Back up vault…"**.
- **CSV export** (`.csv`, §1) — plaintext, lossy, for migrating to another manager.
  UI verb: **"Export for another password manager…"**, warning-gated.

Clients MUST sync before snapshotting (offline → proceed with a visible "vault as of
last sync <time>" banner). Items from **every vault whose VK is held** are included —
shared vaults by default with a visible per-vault line and an opt-out toggle (a member
who can read a vault already holds its ciphertext + VK on-device; export grants no new
capability — spec 05 R7). Web sessions arriving via the break-glass public origin
SHOULD hide both export entry points (T6/T11 posture).

## 1. CSV (plaintext, lossy — the migration escape hatch)

Dialect = **Chrome superset**: header exactly `name,url,username,password,note,totp`
(lowercase). Chrome/Edge/Bitwarden importers ignore the extra `totp` column;
andvari's own importer maps it (spec 06 §1 — the mapping ships in the same change as
this writer, so an andvari→andvari CSV round-trip preserves TOTP).

Writer rules (both impls, byte-identical output — vector-pinned):

- UTF-8, **no BOM**. Record terminator **CRLF**. Header row first.
- A field is quoted **iff** it contains `,` `"` CR or LF; `"` escapes as `""`.
  Fields are never trimmed or otherwise altered — with one exception:
- **CR-normalization**: inside field *values*, CRLF and lone CR are normalized to LF
  before writing (the spec 06 §4.3 parser does this on read; normalizing on write
  makes round-trips exact by construction).
- Login items only, in vault order then `updatedAt` order (pinned so output is
  deterministic). `url` = `login.uris[0]` (may be empty), `note` = `notes`,
  `totp` = `login.totp` verbatim (otpauth URI or bare base32).
- **No formula-injection mangling** (leading `=+-@` written verbatim — mangling would
  corrupt real secrets; Chrome/Bitwarden/KeePass behave the same). Warn instead.

The export UI MUST enumerate, **by item name** (not by count): note-type items
(skipped), items with attachments (attachments not representable), items with extra
URIs (tail dropped), items with empty username AND password (a reimport would skip
them, spec 06 §1), and remind that reimporting collapses exact duplicates. Plus the
spec 06 plaintext warning, and on Android: "your Downloads folder may auto-sync to
cloud storage."

## 2. Backup container (`.andvari`) — binary-framed, encrypted

Backup files live for years and must be restorable with nothing but this document,
libsodium, and the passphrase. The framing is binary so no client ever holds more
than one attachment in memory (monolithic JSON dies on Android heaps and V8 string
limits — measured, not theoretical).

### 2.1 Layout

```
bytes 0..7    magic  = ASCII "ANDVBK01" (container framing v1; restore sniffs
              magic, never the file extension)
bytes 8..11   u32 LE = headerLen
              headerLen bytes of UTF-8 JSON — the PLAINTEXT header (§2.2)
then, repeated per section:
              u64 LE sectionLen ‖ sectionLen bytes
section 0     the items envelope (§2.4) — always present
section 1..N  one attachment stream each (§2.5), in manifest order
```

Framing carries no integrity of its own — every section is independently
authenticated (AEAD / secretstream final tag), a tampered length either fails parse
or fails a tag, and swapped sections fail their per-attachment fileKeys. Section
sizes are visible, matching the server's own plaintext-size posture (spec 02 §5).

### 2.2 Plaintext header

```jsonc
{
  "format": "andvari-backup",
  "v": 1,
  "fileId": "<uuidv4, fresh per export>",
  "kdfSalt": "<base64url, 16 B fresh random>",
  "kdfParams": { "v": 1, "alg": "argon2id13", "opsLimit": …, "memBytes": … }
}
```

Everything the key derivation needs, nothing else. There is deliberately **no
`createdAt`** in the header: an unauthenticated timestamp invites trusting it. The
authenticated `payload.exportedAt` (§2.4) is the only creation time restore may
display. Restore validation, in order, **before running Argon2**:

1. magic == `ANDVBK01`, else `unknown_format`.
2. `format` == `andvari-backup` else `unknown_format`; `v` == 1 else
   `unknown_version` (fail closed — never downgrade-parse).
3. `kdfParams.v == 1 && alg == "argon2id13"` else `unsupported_kdf`; **ceilings**
   `memBytes ≤ 256 MiB && opsLimit ≤ 16` else `unsupported_kdf` (an attacker-supplied
   file must not be able to OOM the client; there is NO floor — weakening a header
   only breaks that file's own tag).
4. Total file size ≤ 256 MiB before any JSON parse; headerLen ≤ 64 KiB.

AEAD failure downstream is reported as **"wrong passphrase or corrupted file"** —
indistinguishable by design; no Bitwarden-style validation value (a passphrase-check
oracle of marginal worth).

### 2.3 Key derivation

```
MKx       = Argon2id(passphrase as typed, kdfSalt, kdfParams)     // spec 01 §1 params
exportKey = HKDF-SHA-256(ikm = MKx, salt = empty, info = "andvari/v1/export", L = 32)
```

Same shape as spec 01 §2's auth/wrap split; `andvari/v1/export` collides with no
existing info string. The passphrase is taken **as typed** (no Unicode
normalization, spec 01 §1; warn on non-ASCII). It is user-chosen with a strength
floor (`estimateStrength ≥ 3`, both impls' shared estimator) and a mandatory confirm
field. UI guidance (not enforceable — the client retains neither the master password
nor MK after unlock): *"Tip: your master password is a fine choice — the backup is
then exactly as protected as your vault (spec 05 T8). A different passphrase belongs
on your printed recovery sheet."* After a later master-password change, old backups
keep their old passphrase — the post-export screen says so. MKx, exportKey, and the
plaintext payload buffer are zeroed (`fill(0)`) after seal/open on all platforms;
passphrase strings are explicitly out of scope (immutable on both platforms — house
practice).

### 2.4 Section 0 — items envelope

A spec 02 §2 AEAD envelope: key = exportKey, AD = `andvari/v1|export|1|{fileId}`
(the `1` is the header `v`, so a future v2 file can never be downgrade-opened under
v1 rules). Plaintext = UTF-8 JSON:

```jsonc
{
  "v": 1,
  "exportedAt": 1751850000000,          // unix ms — the AUTHENTICATED creation time
  "origin": "https://andvari.taila2dff2.ts.net",  // advisory
  "userId": "…", "identityFingerprint": "…",      // advisory (restore preview)
  "vaults": [ { "vaultId": "…", "type": "personal|shared", "name": "…", "role": "…" } ],
  "items": [ { "itemId": "…", "vaultId": "…", "formatVersion": 1,
               "updatedAt": 1751840000000,        // informational only (§3)
               "doc": { /* ItemDoc, spec 02 §3-preserving */ } } ],
  "attachments": [ { "section": 1, "attachmentId": "…", "itemId": "…",
                     "name": "…", "size": 12345, "fileKey": "<base64url 32B fresh>" } ],
  "skipped": { "undecryptable": [ { "itemId": "…", "vaultId": "…", "formatVersion": 2 } ],
               "attachmentsOverCap": [ "tax-archive.zip" ],
               "attachmentFetchFailed": [ "scan.pdf" ] }
}
```

- Docs are **spec 02 §3-preserving, not byte-verbatim** (decode → re-encode through
  the unknown-field overlay; the JS >2^53 number caveat of spec 02 §3 applies).
  Serialized with the standard item Json config (`ignoreUnknownKeys=true,
  encodeDefaults=true`); restore likewise tolerates unknown payload-level fields.
- Docs keep their `attachments[]` refs verbatim, **including original fileKeys** —
  the container is uniformly secret (it already holds every password in plaintext);
  stripping keys would break §3 preservation for zero posture gain. The manifest's
  `fileKey`s are **fresh** keys for this file's own sections, mirroring how vault
  docs carry fileKeys for server blobs.
- Items that cannot be decrypted (newer `formatVersion` — spec 02 §3 fail-closed —
  or a missing VK) are **skipped and enumerated**, never silently omitted and never
  fatal. Tombstones are naturally excluded; conflict-flagged items export as-is.

### 2.5 Sections 1..N — attachments (opt-in)

Byte-format **identical to spec 02 §6 server blobs**: secretstream, same chunking,
keyed by the manifest's fresh per-attachment `fileKey`. Producers fetch + decrypt
each attachment via the normal client path, then re-encrypt to its section
one-at-a-time (bounded memory); consumers verify/extract with the standard
attachment decrypt. v1 caps **total embedded plaintext at 64 MiB** (Android heap and
V8 string math; over-cap attachments are skipped **by name** — `attachmentsOverCap`).
A fetch failure is retried once, then skipped by name (`attachmentFetchFailed`),
never silently and never fatal. AttachmentRefs stay in the docs either way, so an
items-only backup still records what existed.

### 2.6 Write discipline

Write fully, then **verify before declaring success**: re-open the items envelope
and check every attachment section's final tag from the written bytes (or an
in-memory equivalent), single pass. Export counts as user activity for the spec 01
§8 auto-lock, or must abort cleanly — a lock mid-export MUST NOT leave a partial
file. Filename: `andvari-backup-YYYY-MM-DD.andvari`; Android uses SAF
`CreateDocument("application/octet-stream")` (a JSON MIME makes SAF mangle the
extension). Clients record `lastExportAt` locally (never server-side) and surface
"Last backup: N days ago" in Settings.

## 3. Restore (stage 2 — normative now so stage-1 files restore forever)

Restore is **total-loss disaster recovery** (server + PBS + B2 all gone). It lives
in Settings, plainly labeled: *"Only for rebuilding after total server loss — if
your server is alive, your data syncs by itself."* Sync (spec 03) covers lost
devices; PBS covers server loss; a restore on a living vault duplicates everything.

- Preflight: after open, show the **authenticated** `exportedAt`, per-vault item
  counts, attachment manifest incl. named skips — the ImportPanel preview
  discipline — before touching the vault.
- Targeting: per source-vault choice (default: the personal vault; a recreated
  shared vault may be chosen where the user has writer+). Restored items mint
  **fresh itemIds once** at plan time; `mutationId = itemId`; batches of ≤200;
  resume from the **first unacknowledged batch** on retry, never a full-plan replay
  (the spec 03 §5 dedup window is only guaranteed for 1000 mutations).
- Attachments: docs' `attachments[]` are **rewritten at plan time** — attachments
  not in the file ⇒ ref stripped + reported; attachments present ⇒ fresh
  `attachmentId` + `fileKey` minted once, ref rewritten via copy (preserving unknown
  fields on the ref), blob uploaded before the item put (spec 02 §6 order). On a
  plan retry, `400 attachment_id_taken` counts as **success** (the plan pinned
  fileKey + plaintext, so any stored copy under that id decrypts; ids are fresh
  UUIDs). Without this rewrite every push 400s (`unknown_attachment` /
  `attachment_mismatch`, spec 03).
- Exported `updatedAt` / `origin` / `userId` are informational (preview only);
  restored items get fresh server revisions and timestamps; client-observed times
  inside docs (`passwordHistory[].retiredAt`) survive verbatim.
- Until client restore ships, **`tools/backup-cli`** (offline, no HTTP — same
  discipline as recovery-cli) is the reader of record: `verify` (open + check every
  section), `dump` (items JSON to stdout), `extract` (attachments to a directory).
  The backup drill (ROADMAP) uses it.

## 4. Vectors (`test-vectors/export.json`)

- **CSV-writer cases**: docs in → exact output bytes (quoting, embedded CR/LF
  normalization, totp column, empty url) — fully deterministic, byte-compared.
- **Container cases**: FAST-class kdfParams (the vector-gen pattern — never
  production cost), fixed kdfSalt + envelope nonce (`sealWithNonce` hooks), pinned
  `payloadUtf8` → byte-exact container both impls must **produce and open**.
  Cross-impl payload serialization is NOT byte-compared (key order differs);
  own-impl round-trip is a per-impl property test. Attachment sections are
  covered by round-trip + truncation-rejection tests (secretstream is
  nondeterministic — same posture as the existing attachment vectors).
- **Reject cases**: bad magic, unknown `format`/`v`, foreign `kdfParams.alg`/`v`
  (raw-JSON-built — the typed KdfParams can't even construct them), oversized
  `memBytes`, truncated section, AD/fileId mismatch, wrong passphrase.
