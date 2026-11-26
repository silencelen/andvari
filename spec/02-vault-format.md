# andvari spec 02 — vault format

## 1. Item model

An **item** is one encrypted record in one vault. Server-side row (see §5 for the
full plaintext contract):

```
Item {
  id            uuid          # client-generated at creation
  vaultId       uuid
  rev           int64         # server-assigned, from the global changes sequence
  createdAt     int64         # server clock, unix millis
  updatedAt     int64         # server clock, unix millis
  deleted       bool          # tombstone
  conflict      bool          # set by server on conflicting write; cleared by client push
  formatVersion int           # plaintext schema version, = 1–2 (§3)
  attachmentIds string[]      # plaintext by necessity (blob GC + quotas), ids+sizes only
  blob          base64url     # AEAD envelope (§2) over the plaintext document (§3)
}
```

Client caches store the same shape plus local dirty/queue state. Client-observed
times (e.g. "password last changed") live INSIDE the encrypted document; `createdAt`/
`updatedAt` are server bookkeeping and untrusted for security decisions.

## 2. AEAD envelope

Binary layout, transported as unpadded base64url:

```
offset 0    version   1 byte   = 0x01
offset 1    alg       1 byte   = 0x01  (XChaCha20-Poly1305-IETF)
offset 2    nonce     24 bytes (random per encryption, never reused with a key)
offset 26   ct        ciphertext || 16-byte Poly1305 tag
```

Parsers MUST reject unknown version/alg bytes and envelopes shorter than 42 bytes.

**Associated data** binds every ciphertext to its identity so the server cannot swap
blobs between items, vaults, or purposes (`|`-joined UTF-8, spec 00 conventions):

| Use | Key | AD |
|---|---|---|
| Item blob | VK(vaultId) | `andvari/v1|item|{vaultId}|{itemId}|{formatVersion}` |
| UVK wrap | wrapKey | `andvari/v1|uvk|{userId}` |
| Member-recovery UVK wrap (spec 04 §per-member) | recoveryWrapKey | `andvari/v1|recovery-uvk|{userId}` |
| Identity seed | UVK | `andvari/v1|idkey|{userId}` |
| Personal-vault VK wrap | UVK | `andvari/v1|vk|{vaultId}|{userId}` |
| Vault metadata (§4) | VK(vaultId) | `andvari/v1|vaultmeta|{vaultId}` |
| Usage ledger (§8.2) | usageKey = HKDF-SHA-256(VK(personal), `andvari/v1\|usage`) | `andvari/v1|usage|{userId}` |

`rev` is deliberately NOT in AD (the server assigns it after encryption). Sealed
boxes (escrow, shared-vault grants) have no AD; their payloads are self-describing
and receivers MUST validate the internal ids against the row they arrived on.

## 3. Item plaintext document (formatVersions 1–2)

JSON (not canonical — round-trips freely), `type` inside the ciphertext:

```jsonc
{
  "type": "login" | "note",
  "name": "GitHub",
  "notes": "free text",                  // optional, all types
  "favorite": false,                     // optional
  "dupeAck": "itemId|itemId",            // optional — duplicate-checker "not duplicates" ack (2026-08-18): the
                                         // sorted-member-id signature of the acknowledged cluster; any membership
                                         // change stops it matching. Older clients preserve it as an unknown key.
  "check": {                             // optional — login verification ledger (2026-08-22, design
    "at": 1755800000000,                 //   2026-08-22-login-health): when this verdict was recorded,
    "result": "ok",                      //   ok|bad|gone|blocked, the most recent `at` that was ok, and an
    "okAt": 1755800000000,               //   optional snooze horizon. Client clocks — advisory, never a
    "until": 1758400000000               //   security input. Older clients preserve it as an unknown key.
  },
  "login": {                             // when type=login
    "username": "jacob",
    "password": "…",
    "uris": ["https://github.com/login"],
    "totp": "otpauth://totp/…?secret=BASE32&…",   // optional, full otpauth URI
    "passwordHistory": [ { "password": "…", "retiredAt": 1751700000000 } ]  // two writers, both named below
  },
  "attachments": [                       // mirrors attachmentIds; holds the SECRET half
    { "id": "uuid", "name": "scan.pdf", "size": 12345, "fileKey": "base64url(32B)" }
  ],
  "logHead": { "seq": 12, "hash": "…64 hex…" }   // optional, items in shared vaults only (§10.5)
}
```

**`logHead` (gossip of the vault log).** A writer SHOULD put the shared vault's verified log head
(§10.5) into every item it writes. Only key holders can read it and the server cannot change it.
It is a **hint to fetch, never a verdict**: any writer, or a removed member working with the
server, can put any value there. A reader that decrypts an item whose `logHead.seq` is above its own
verified head, or whose hash differs at a position it has verified, fetches the log; if nothing new
comes, the vault's details note "An item mentions history the server hasn't shown" and, while that
hint is unresolved, the member list is marked "may be incomplete". The vault's state never changes on
an item head alone. Clients that do not know the field preserve it as an unknown key.

**`login.passwordHistory` — two writers (amendments 2026-08-18, 2026-11-11); otherwise reserved.** The
shape above is fixed (so the field could be adopted without a formatVersion bump) and every
client **preserves it verbatim on rewrite**, entry-level unknown fields included (the
preservation rules below). Exactly **two paths append entries**. The first is the Health duplicate
checker's differs resolution ("Keep this one", `planKeep` — on web and Android since 0.26.0,
via the core/web twins) — when the user retires
duplicate copies, each distinct losing password is appended to the survivor as
`{password, retiredAt}` so the retired secrets outlive the losers' 30-day Trash window. The
second (iOS, 2026-11-11) is the import of a login captured by an AutoFill extension: when it
replaces the password of an existing personal-vault login, the password it replaces is
appended as `{password, retiredAt}`, so a replacement the user did not type into an editor
stays recoverable. That writer keeps each earlier password once and at most 20 entries,
dropping the oldest. No
editor, importer, ordinary save path, or conflict materializer on any client writes an
entry. The iOS app shows the field read-only in a login's detail; no other client displays
it. A reader MUST therefore still treat an
absent/empty `passwordHistory` as carrying no information — it does **not** mean the
password was never rotated — and MUST NOT present it to a user as a general retention
guarantee (entries exist only where that one flow wrote them). The shipped
no-silent-loss backstop is the server-side **item_versions** archive (§7 + spec 03
`GET /items/{id}/versions`), which is what "recover the previous password" actually rests
on; folding this field in on top of it is backlog **F62**, deliberately unbuilt
(`docs/design/2026-07-08-item-history-and-restore.md` §"F62 passwordHistory fold").
Importers inherit the same rule: a source's password-changed *timestamp* is informative
only and is never materialized into an entry, because no retired password value exists to
put in one (spec 06 §2/§4 step 9).

**`check` — the login verification ledger (2026-08-22).** A record of the last time a human
confirmed the login still works, written by the guided verification run (design
`docs/design/2026-08-22-login-health-staleness-verification.md`). Doc-level on purpose, for the
same reason `dupeAck` is: the verdict is a statement about the ITEM, not about the viewer, so
one member's confirmation quiets it on every device and for every member of a shared vault.
Shape: `{ at int, result string, okAt? int, until? int }`, all epoch millis (well inside the
2^53 preservation bound below, so they stay JSON numbers). Normative rules:

- **`result` vocabulary is OPEN.** `ok` (signed in), `bad` (credentials refused), `gone`
  (account or site no longer exists), `blocked` (could not complete — MFA, lockout, captcha).
  A reader encountering an unrecognized value MUST treat it as "checked, verdict unknown" and
  preserve it verbatim — never fail closed, and never rewrite it to a known value.
- **`okAt` carries forward.** On an `ok` verdict `okAt == at`; on any other verdict `okAt` is
  copied from the prior `check` unchanged, so "last worked in March, failed in August" survives
  without an array.
- **Absence carries no information.** A missing `check` means never verified — NOT verified long
  ago, and NOT healthy. Clients MUST NOT present an unchecked item as confirmed-good, the same
  discipline this section states for `passwordHistory`.
- **Client clocks are untrusted (§1).** `at`/`okAt`/`until` are advisory UX only; no security
  decision may read them. A reader MUST tolerate a future `at` (clock skew, or a hostile
  co-member in a shared vault) without letting it dominate an ordering.
- **One write per recorded verdict**, and a skipped item writes nothing. This bound matters:
  every write is an item overwrite, and §7 caps `item_versions` at the newest 10 per item, so a
  chatty writer here would evict real edit history. For the same reason the design deliberately
  does NOT put a per-use timestamp in this document — usage tracking lives outside the item
  document (§8.2).

**formatVersion 2 — cards (0.7.0).** fv2 adds `type` value `"card"` and one optional
top-level object `card`: `{ cardholderName?, number? (digits-only), expMonth?
("01".."12"), expYear? (4-digit), securityCode? (3–4 digits; storing it is a per-card
choice), brand? (derived from the IIN at save, display-only) }` — all strings, all
inside the ciphertext; the server row gains nothing (`formatVersion` is the existing
§1 plaintext integer, and `card` gets the same every-level unknown-field preservation
as `login`). Clients ≥ 0.7.0 MUST seal card-bearing docs (`card != null` OR
`type == "card"`) at formatVersion ≥ 2; logins/notes keep sealing at 1 (per-doc
floor), and an existing item re-seals at max(floor, the fv it was decrypted at). The
server enforces **per-item monotonic formatVersion** — a put/restore declaring a lower
fv than the stored row's is refused (`denied`, audited `fv_downgrade`) — which turns a
pre-fv2 client's card-stripping rewrite into a refused write instead of silent
ciphertext loss. Readers accept a `card` field at ANY fv they can open (e.g. an fv1
doc whose `card` rode the unknown-field overlay through a legacy backup restore): the
floor binds writers, not readers, and such an item re-floors to ≥ 2 on its next
0.7.0 edit. The top-level key space doubles as the doc-level extension registry —
`card` is CLAIMED (fv2), as are `dupeAck` (2026-08-18) and `check` (2026-08-22) — both
additive within fv1-2 with no version bump; future top-level fields MUST pick unclaimed keys
and stay additive within fv2 unless they change the meaning of existing fields.

Unknown fields MUST be preserved on rewrite (forward compatibility within a
formatVersion), at every level of the document: the top-level object, `login`, each
`login.passwordHistory[]` entry, and each `attachments[]` entry. Preservation rules:

- **Typed fields win.** If a field is known to this client version, its typed value is
  authoritative on encode; a stale unknown-field copy of the same name MUST NOT shadow it.
- **Scoped within a formatVersion.** A client MUST fail closed on any `formatVersion`
  greater than it implements — treat the item as undecryptable (keep the envelope, retry
  after upgrade), never edit it, since a rewrite would silently downgrade the version.
- **Numbers.** JavaScript clients parse JSON numbers as IEEE-754 doubles, so unknown
  numeric values outside the exactly-representable range (|n| > 2^53) are NOT
  preservation-guaranteed. Writers of future fields MUST encode 64-bit integers as
  JSON strings.
- **Partial editors.** A client that exposes only the first `login.uris` entry MUST
  preserve the tail on edit; clearing the field removes only the first entry.

TOTP presentation: RFC 6238, SHA-1, 6 digits, 30 s step unless the
otpauth URI overrides.

### 3.1 login.uris — semantics & client match rules (autofill / browser fill)

`login.uris` entries are either web URIs (scheme optional, default `https`) or the
native-app convention **`androidapp://<packageName>`** (Bitwarden-compatible).

**Normalization** (all impls, identical): lowercase the host; strip every leading
`www.`; strip a trailing dot; **path, query, fragment, userinfo, and port are ignored
for matching** (Android's `ViewNode.getWebDomain()` exposes only the domain — two
services on one host are indistinguishable, so give services distinct hostnames);
then — **amended 2026-09-13 (audit H22)** — **canonicalize to the A-label**: each label
containing a non-ASCII code point is NFC-normalized and Punycode-encoded (RFC 3492) with
the `xn--` prefix; ASCII labels pass through unchanged, so the step is idempotent. Both
sides of every comparison run the same normalizer, so a saved `bücher.de` and the
`xn--bcher-kva.de` every browser reports (`location.hostname`, the extension's
`sender.origin`, Android's `getWebDomain()`) are one string, and the PSL walk below sees
an ASCII host it can resolve. The algorithm is deliberately minimal and deterministic
rather than a full UTS46: no mapping table (full-width forms, `ẞ`→`ss`, ligatures) and
no bidi/joiner validity checks, and the four IDNA2008 deviation characters follow the
NON-transitional form modern browsers report (`straße.de` → `xn--strae-oqa.de`, never
`strasse.de` — which is why clients MUST NOT substitute a platform IDNA2003 converter such
as `java.net.IDN`). A spelling outside that subset still canonicalizes identically on every
client; it simply does not meet the browser's spelling, and encodes to a label no registry
can hold — an under-match. The one omitted mapping that would NOT stay an under-match is
`ẞ` (U+1E9E) → `ss`: lowercasing maps it to `ß`, a deviation character browsers keep, so a
saved `straẞe.de` would canonicalize to `xn--strae-oqa.de` (`straße.de`) — a real, different
registrable domain from the `strasse.de` the browser reports — and fill across origins.
Clients MUST therefore reject a host containing U+1E9E outright (unparseable, matches
nothing); `urimatch-idna.json` grades it. Encoder overflow (an absurd label) yields
"unparseable" (never matches). Surfaces that DISPLAY a normalized host (the Health
duplicate clusters) show the U-label the member typed, not the A-label key: the canonical
form is the A-label and no decoder is specified, so a client keeps the U-label from the
raw uri (`normalizeHostUnicode`, the same normalizer stopped before the A-label step).
Vectors: `spec/test-vectors/urimatch-idna.json` (`normalize` pins the output bytes, `match`
the outcome); the pre-existing vector files are byte-frozen and unchanged.

**Length limits (amended 2026-10, security review).** The A-label result must obey RFC 1035:
no label longer than 63 octets and no host longer than 253; a host that breaks either
normalizes to null and matches nothing (no DNS name can break them). Implementations refuse a
pre-encode label of more than 63 code points before running the encoder, refuse an
intermediate host of more than 512 UTF-16 units before the `www.` strip, strip trailing dots
by a linear scan (never a backtracking `\.+$`), and the PSL resolver refuses a host over 253
octets. The rule bounds the work: a co-member's planted URI was otherwise quadratic in the
punycode encoder, the trailing-dot regex and the suffix walk, on every member's device, on
every fill and every Health open. Pinned by the `limits` section of `urimatch-idna.json`.

**Captured scheme (client rule, 2026-09-13 audit H124).** A client that CREATES a uri from
a page capture (extension auto-save / site-link, Android save) stores the scheme it actually
observed: a plain-http page (loopback, intranet — the spec 05 F27 posture) stores `http://…`
(the extension keeps the http origin's non-default port too, since it is the only address
that reopens that server); everything else keeps `https://<host>`. Matching ignores the
scheme either way; this governs only what the stored uri says, i.e. where "open site" points.

**Match rules (normative; amended 2026-07-10 — one addition + two tightenings, design
`docs/design/2026-07-10-etld1-psl-matching.md`).** Hosts with an **empty label** after
normalization (`.example.com`, `a..example.com`) are unparseable and never match (the
trailing-dot strip still applies first). Clients resolve each side against the vendored
PSL snapshot (`spec/psl/`, explicit rules only — the PSL's implicit `*` fallback is NOT
applied) into one of REGISTRABLE(domain) / PUBLIC-SUFFIX / UNKNOWN, where PUBLIC-SUFFIX
covers exact, wildcard-derived, and exception-derived suffixes alike. A page host matches
a saved host iff, in order:
- **exact equality**, OR else
- **[tightening] never when either side is a bare PUBLIC-SUFFIX** — saved `github.io`
  fills no tenant under it; a page at `b.kawasaki.jp` gets no `kawasaki.jp` item;
- **[addition] both sides REGISTRABLE → registrable-domain equality** decides. Saved
  `login.example.co.uk` now matches `example.co.uk` and `accounts.example.co.uk`; saved
  `foo.github.io` never matches `bar.github.io`; **[tightening]** known-but-unequal
  registrables refuse even when the old suffix relation holds (saved
  `compute.amazonaws.com` no longer fills `ec2-x.us-east-1.compute.amazonaws.com`);
- **either side UNKNOWN → the pre-amendment rule, bit-for-bit:** the saved host has
  **≥ 2 labels** AND the page host ends with `"." + savedHost` (label-boundary subdomain
  suffix). Intranet hosts (`pihole.lan`, `nas.local`) keep today's behavior; a
  **single-label** saved host (`com`, `router`, `localhost`) stays **exact-only**.
- **IP-literal** hosts match exact-only. `androidapp://<pkg>` matches by exact package
  string, **and never a known browser package** (amended 2026-10, security review: a browser
  is a window onto every web origin, so `androidapp://<browser>` would fill every site opened in
  it — browsers fill web URIs only; a save from a browser with no trusted web domain stores no URI).
  An unparseable / empty saved URI never matches. Staleness: a suffix the snapshot
  doesn't know **at TLD level** resolves UNKNOWN and degrades to the old rules
  (under-match). The one residual over-breadth is a multi-tenant hosting domain missing
  from the **private section** under a known TLD (`foo.newpaas.app` ↔ `bar.newpaas.app`
  both resolve REGISTRABLE `newpaas.app` and R-EQ matches them) — identical to
  Bitwarden/1Password base-domain behavior; bounded by the refresh posture in
  `spec/psl/README.md`, not eliminated by it.

> **Conformance note (2026-07-10).** eTLD+1 matching is **client-version-gated** — there
> is NO formatVersion change and no wire change. Carrying the amended rules: web (deploy
> 2026-07-10, reports 0.10.0) and extension ≥ 0.8.1. Pre-dating them (old rules, including
> the bare-suffix and known-unequal fills the amendment forbids): Android ≤ 0.9.0,
> desktop ≤ 0.9.0, and the 0.2.x MSI, until the next native cut — which ships as
> **≥ 0.10.0** (the in-tree versions were bumped with this amendment so no rebuild can
> ever field a second, behaviorally-different "0.9.0"; desktop is inside that gate — no
> deb rebuilds before the cut). Until then a phone may decline a match the PC fills (and
> vice-versa for bare-suffix junk); this note is the recorded exception.

**webDomain trust.** A fill request's web domain is honored ONLY when the requesting
package is an allowlisted trusted browser; otherwise clients match by package name
only (any app can populate its own structure with an attacker-chosen `webDomain`).
A structure carrying **more than one distinct web domain** (cross-origin iframes) is
treated per-field: a dataset is built only over fields whose own frame domain matches
the saved item, and a form mixing domains yields no fill rather than filling a
credential into a foreign-origin field. (Client-side only; the spec 02 §5 server
plaintext table is unchanged — matching reads the existing `login.uris` ciphertext.)

**Field classification — one-time-code boxes (normative; amended 2026-09-13, audit H65).**
A client classifies a fill target from its SIGNALS alone (autofill hints, the HTML
`type`/`name`/`id`, Android `InputType`) and never from its value; the graded corpus is the
`classify` / `classifyCard` / `classifyCardFreeRegression` sections of
`spec/test-vectors/urimatch.json`, which every engine runs. The stored password **MUST NOT be
offered into a one-time-code box.** Before this amendment that rule (F11) fired only on the
page's own `autocomplete` token (`one-time-code` / `otpCode` / `smsOTPCode`), so a site that
masks its 2FA entry as `<input type="password" name="otp">` and declares no `autocomplete`
still got the account password offered into the code box — and on the extension, whose capture
engine reads the fill target back on submit, six digits typed there could then overwrite the
stored credential. **Amended rule: a NAME_NEGATIVE token in the field's own `name`/`id`
(`search`, `otp`, `captcha`, `code`, `query`, `phone`), or one of the two-factor spellings
`2fa` / `mfa` / `twofactor`, overrides `type="password"` and the field classifies NONE** — the
same verdict the hinted box has always received. Three limits are deliberate and each is pinned
by a vector:

- **HTML type only.** A native Android `InputType` password field named `otp` (no HTML type at
  all) keeps its frozen PASSWORD verdict. That is the recorded residual, not an oversight: the
  hint path still covers the platform's own `oneTimeCode` hint, and the HTML shape is the one a
  browser actually reports.
- **After the CSC demotion, never before.** A masked CVV (`securityCode`, `cvv_code`,
  `cardVerificationCode`) is still the card security code. The three-kind web/extension engines
  have no card verdict to return and therefore keep `password` for that one shape, which is what
  lets the extension's form-level CSC demotion reach a masked CVV; the carve-out matches only
  whole tokens, so `cscode` / `mysecuritycode` fall through to NONE on every engine.
- **The two-factor spellings are override-only.** They are NOT added to NAME_NEGATIVE, which also
  gates the frozen USERNAME legs — `<input type="email" name="2fa_recovery_email">` is still a
  username box. A separated `two_factor` is therefore not matched (in the wild it carries a
  `code` token beside it, which is).

The cost is accepted and one-directional: a genuine password box named like a code (`passcode`,
`cv_code`) stops being OFFERED a fill — the member types it — and is never mis-filled the other
way. The classifier already refused to read those names as login names on a text input, so the
amendment makes the two halves agree. **One frozen vector moves with it:**
`classifyCardFreeRegression`'s `<input type="password" name="cv_code">` goes PASSWORD → NONE;
the hinted F11 cases are unchanged and stay pinned. Client-side only — no `formatVersion`, no
wire change — and carried by the whole 0.27.0 fleet at once (core/Android/desktop, web,
extension); an older client keeps the hinted-only rule.

### 3.2 Decrypted documents are untrusted input (2026-10 amendment, security review 2026-10)

A plaintext that opens under a vault key proves only that its author HOLDS that key — and every
writer of a shared vault does (spec 05). Every client therefore checks a decrypted item document's
**shape** before anything reads it, at its one decrypt boundary (core `Account.decryptItem`, web
`Account.decryptItem`, extension `decryptItems`), and **quarantines** a failing document exactly as
it would an undecryptable envelope: kept by identity so a backup enumerates it (spec 07 §2.4), never
rendered, never matched, never edited. A malformed item can never crash or blank another member's
vault.

The rule (one implementation per engine, graded by `spec/test-vectors/itemdoc-validate.json`):

- the document is a JSON object; `type` and `name` are strings;
- `notes`, `dupeAck` are absent, null, or strings; `favorite` is absent or a boolean;
- `login`, `card`, `check` are absent, null, or objects. In `login`: `username`/`password`/`totp`
  absent, null or strings; `uris` absent or an array of strings; `passwordHistory` absent or an
  array of `{password: string, retiredAt: integer}`. In `card`: every §3 field absent, null or a
  string. In `check`: `at` an integer, `result` a string, `okAt`/`until` absent, null or integers;
- `attachments` is absent or an array of `{id, name, size, fileKey}` where `name` and `fileKey` are
  strings, **`id` matches `^[A-Za-z0-9_-]{1,128}$`** (it goes into an authenticated URL path,
  spec 03), and **`size` is an integer ≥ 0** (it is a claim, checked against the ciphertext, §6);
- "integer" means a JSON number that is integral and within ±(2^53−1);
- unknown keys at every level are allowed and never inspected (§3 forward compatibility).

A vault metaBlob's `name` (§4) is displayed only when it is a JSON string; any other value falls
back to the client's generic vault label.

## 4. Vaults

```
Vault { id uuid, type "personal"|"shared", rev, createdAt, metaBlob base64url }
```
`metaBlob` = envelope under VK with AD `andvari/v1|vaultmeta|{vaultId}`, plaintext
`{"name":"Family","icon":"…","metaV":N}` — vault display names are ciphertext; the server
knows vaults only as ids. `metaBlob` is **owner-rewritable** (rename, spec 03 §11.3) under the
same VK/AD; its plaintext carries a monotonic `metaV` counter (clients warn-and-keep-newer
when a delivered metaBlob's counter regresses); the AD deliberately excludes `rev`.

**Grants** (per member): `{ vaultId, userId, role "owner"|"writer"|"reader", rev, addedAt, revokedAt,
revokedReason, wrappedVk, signedGrant }` (spec 01 §6). An owner grant carries `wrappedVk` (the owner
wrap under the UVK); a member grant carries `signedGrant` (the sealed 0x01 grant of its `add`) and,
once the member posted a self-wrap, also `wrappedVk`. `revokedReason ∈ member_remove | member_leave |
vault_delete`; a `restore` re-activates exactly the grants still revoked with `vault_delete`, and a
`leave` during the grace rewrites the leaver's `vault_delete` to `member_leave` (spec 03 §10.3).

**Shared vault rows** carry the log head (`logSeq`, `logHash`), the lifecycle state (`deletedAt`,
`purgeAt`, `purgedAt`, `deletedBy`, `deleteId`; after the purge the tombstone `finalHead`), and the
pending ownership offer (`pendingOfferId`, `pendingOwnerId`, `pendingOfferExpiresAt`). Every one of
these mirrors the vault's signed log (§10), which is what clients act on; the columns exist for the
server's own checks. Vault rows are NEVER hard-deleted (a purged vault's log rows go a year after
its purge; its row stays), and `vaultId` is never recycled (normative). Roles are **server-enforced** on writes (crypto
cannot stop a reader who has VK from encrypting; the server rejects writes without writer role).
Membership is server-visible via the grants rows and the log; audit events record only ids and roles,
never names or decrypted content.

**The personal vault.** The account genesis (spec 01 §5.4) names it (`personalVaultId`) forever, and
the personal wrap (spec 01 §6.1) carries its key. It never has members and has no log: the server
refuses members on it, and no client builds a log entry for it. `type` is a SERVER label and MUST NOT
choose the personal vault: the default save destination, the usage-ledger key, copy-to-Personal, the
import target, the "(shared)" tag (`vaultId != personalVaultId`) and the sort order all follow the
genesis and the wrap. A served wrap that opens and names `personalVaultId` is in force on any device
with no question; a withheld or unopenable wrap leaves "no personal vault" with an anomaly (no default
destination, usage paused, a banner saying so), and a device's cached wrap (device state that outlives
the offline cache) still stands. Exactly one personal wrap ever exists, so no superseded wrap can be
replayed, and the genesis vault's key has never been given to anyone. Vectors:
`spec/test-vectors/personalwrap.json`, `accountgenesis.json`.

## 5. Server-visible plaintext — the zero-knowledge contract

The server stores/sees EXACTLY this and nothing more; the hardening gate audits
against this table. Anything not listed here appearing server-side in plaintext is a
spec violation.

| Surface | Fields |
|---|---|
| users | userId, email (`emailNorm`), displayName, kdfSalt, kdfParams, verifier(argon2id str), **wrappedUvk** (UVK ciphertext under the master key — opaque to the server, stored so a fresh device can unlock), identityPub, **encryptedIdentitySeed** (identity-seed ciphertext under the UVK — same story), **genesis** (the account genesis frame, spec 01 §5.4: public, signed), **personalVaultId** (the account's one personal vault, copied at register from the verified genesis, spec 03 §14.3: a mirror for the server's own use, as `recovery` is, and public in the genesis anyway), role (`operator`\|`member`, the operator unique), status (`active`\|`disabled`), disabledAt, **recovery** (`private`\|`operator`: the server's mirror of the posture, spec 03 §3.1), requireLink, **recoveryConfirmed** (boolean flag, plaintext metadata — the durable, cross-device capture-confirmation signal; not a secret), quota overrides, ageConfirmed (a boolean, nothing more), createdAt, **registeredVia** (`ticket`\|`link`\|`enrol`\|`setup`: the `auth` kind the account registered with; the daily account maximum of spec 03 §14.4 counts from it, not from audit rows), server-TOTP columns (totpSecret, totpPendingSecret, totpEnrolledAt, totpLastStep — a server-side authenticator secret by design, never vault data; spec 03 §2). An account deletion (spec 03 §13) deletes the row, after every row that references it |
| devices | deviceId, userId, platform (the kind the row was made as, set once when the row is made and never changed; a row made as `web` is a browser's row, whose tabs each hold a session of their own, and the one-session rule of a sign-in reads this, not what the caller says, spec 03 §2), **name (user-chosen device label, plaintext)**, clientVersion, how (`registered`\|`password`\|`linked`\|`recovered`), linkedFrom, **deviceSecretHash** (hex SHA-256 of the device's own secret, spec 03 §16.8; cleared by a revoke), createdAt, lastSeenAt, revokedAt, signedOutAt |
| sessions | sessionId, userId, deviceId, hashed access+refresh tokens, access/refresh expiries, refreshConsumedAt, **clientPlatform** (the `X-Andvari-Client` platform of the request that minted the session: every operator route refuses a `web` session, spec 03 §1), **passwordAt** (set when a password login minted the session, and carried over by a refresh; until 2026-11-17 it opened a ten-minute window in which a first two-step setup needed no password proof, and since then no rule reads it: every setup carries the proof, spec 03 §2), createdAt, revokedAt |
| session_chains | sessionId, chainId: the refresh chain a session a refresh made belongs to, named by the id of the session a sign-in, registration, recovery commit or pickup minted at the chain's start, so that a sign-in naming the session it replaces by an older token of that chain ends the chain as it stands now (spec 03 §2). A session with no row is a chain of its own (every chain's first session, and one made before 2026-11-17 or by a server that does not keep the table). No reference to `sessions`; a row whose session is gone is removed by the janitor, and an account deletion removes its sessions' rows |
| vaults | vaultId, type, rev, createdAt, metaBlob (ciphertext); for shared vaults the log head (with **logAt**, the head entry's `at`), lifecycle (deletedAt/purgeAt/purgedAt/deletedBy/deleteId, and the tombstone's head as **finalSeq**, **finalHash**, **finalAt**, copied from the log head at the purge) and the pending offer (ids + epoch times), all mirrors of the signed log (§4); **logState**, the server's cached state of the verified log, so an append need not replay the log from genesis |
| vault_log | vaultId, seq, hash, frame, actor, kind, at, storedAt (§10): every signed entry, in the clear. The server sees the full membership history — who added, removed, offered, accepted, deleted, restored or left, and when by both the signer's and its own clock. Rows outlive the vault's purge by one year (spec 03 §11.1) |
| grants | vaultId, userId, role, addedAt, wrappedVk (ciphertext under the holder's UVK), signedGrant (the member's sealed 0x01 grant, opaque), rev, revokedAt, revokedReason (revoked rows are retained — the server sees WHEN and WHY a member lost access: remove / leave / vault-delete) |
| connections | a, b (userIds, `a < b`), createdAt: who has connected with whom through a link (spec 03 §15.8). Kept until either account is deleted |
| links | linkId, kind, creatorUserId, createdAt, expiresAt, offer (envelope, opaque), tokenHash, boundEmailHash (the keyed hash of the address an enrol link was minted for, or NULL), state, answererUserId, answer (envelope, opaque), answeredAt, deliveredAt, reveal (the creator's code nonce, public by design), **stateChangedAt** (when the row left `open`: the janitor deletes it 30 days after that, spec 03 §15.8). The server sees who made a link, who answered and when, never `s` or the offer's or answer's contents |
| device_links | linkId, userId, **deviceId** (the existing device E that created the link, recorded as the new device's `linkedFrom`, spec 03 §16.6), state, expiresAt, the claim (nPub, name, platform, commitN, mac), nonceE, nonceN, proofHash, outer and inner (opaque), approveMac, **approvedBy** (the device whose session approved the link: the pickup requires it, and the creating device, to be unrevoked, and revoking either deletes the link, spec 03 §16.6, §16.7), timestamps. Deleted at pickup, cancel, timeout, or the revoke of the device that created or approved it |
| instance_setup | instanceId and the setup name (one row): written by `andvari setup`, or created at first boot if setup never ran (spec 03 §17.5); served in `GET /instance`'s setup block until card 0 is stored |
| instance_cards, recovery_rotations | the instance card frames and the 0x08 rotation statements (public, signed), with their hashes and storedAt; on each card **operatorId**, **name** and **recoveryFp**, mirrors of the verified card's fields for the server's own checks and notices; on each rotation **fromFp** and **toFp**, mirrors of the verified statement, for the rotation-chain check of spec 03 §17.3 |
| signup_codes | emailHash (the address's **keyed hash**, below), codeMac, expiresAt, attempts — never the address or the code |
| signup_tickets | ticketHash, emailHash (the keyed hash), expiresAt, usedAt |
| recovery_requests | requestId, userId (NULL on a decoy, spec 03 §18.1), emailHash (the keyed hash, a decoy's too; read back by nothing), rPub, pollHash, platform, codeMac, **codeExpiresAt** (the emailed code's expiry, spec 03 §18.1), attempts, state, createdAt, verifiedAt, holdEndsAt, sealed (the operator's sealed 0x09 answer, opaque), **commitHash** (the `hex64` hash of the answer's commit value, uploaded beside it, spec 03 §18.6; served in the poll's `ready` answer), **cancelledAt** (when the account's owner cancelled a request whose mailed code was not entered: a password change, the recovery setting switched to `private`, or a recovery; the state stays `unverified`, so the poll answers as before, and the cancel is told at the code step, spec 03 §18.2; added 2026-11-17) — private instances only. An account's deletion leaves its requests whose code was not entered as decoys (userId, codeMac and cancelledAt cleared) until they expire, so their polls answer as before; it deletes the others. Wrong commit values are audited, never counted (rule of 2026-11-16: the value is 32 random bytes, so a limit of attempts protects nothing, and it let a damaged upload or anyone who saw a poll secret cancel the request), so there is no count column |
| recovery_mailbox_values | **valueHash** (`hexLower(HMAC-SHA-256(serverSecret, "andvari/v2\|recovery-mailbox-value\|" + emailHash + "\|" + value))`, the key of spec 03 §18.1's code MAC; never the value), **emailHash** (the keyed hash of the address whose code mail carried the value), **expiresAt** (seven days after that mail) — private instances only (spec 03 §18.1, added 2026-11-17). A row is stored only beside a real request's code mail, so a decoy stores none. It goes when its value is used, when it expires (the janitor; an expired value is refused before then), and with every other row of its address when that address's account is deleted (by its owner or by the operator), its recovery (kit or assisted) completes, or it switches to the private posture; a password change keeps them. Its rows tell how many code mails went to an address in the last seven days and were not used |
| mail_outbox | id, template, **recipient address**, rendered subject, text and **html** (the HTML alternative, spec 03 §14.5), createdAt, attempts, nextAttemptAt, lastErrorClass, **discardAt** (when the row is given up unsent). A queued mail's body can contain a code, and a recovery request's code mail also its mailbox value (spec 03 §18.1): both are in clear in the row until the mail is sent or its code expires (15 minutes), so the row, body included, is deleted on delivery or on give-up: the moment a message is sent; a code message unsent when its code expires; nothing stays past 24 hours. The `account_deleted` message keeps a deleted account's address here until it is sent (spec 05 R31) |
| retired_ids | idHash (account deletion, spec 03 §13): lowercase-hex SHA-256 of a deleted account's userId and of the pseudonym its retained audit rows carry, so register can refuse both for good. A digest of a random id, no date: it tells only someone who already holds an id that the id was retired |
| items | the Item row of §1 — ids, rev, server timestamps, flags, formatVersion, attachmentIds, ciphertext blob, ciphertext byte size |
| item_versions | itemId, rev, blob, formatVersion, archivedAt (bounded to the newest 10 per item, §7) |
| changes | rev, kind, entityId, vaultId, at — the global sync feed (pure metadata; reveals per-vault write timing/volume) |
| mutations | (deviceId, mutationId) → resultJson, createdAt, userId — idempotency replay cache; resultJson holds per-mutation status/rev/reason and the ids the mutation named, no vault content (a replayed conflict reads its item at answer time, spec 03 §5); at most the device's newest 1,000 rows. userId (indexed) is the pushing account, so an account deletion (spec 03 §13) still finds rows of a pruned device |
| attachments | attachmentId, itemId, vaultId, ciphertext size, sha256(ciphertext), header, createdAt (filenames + file keys are inside item ciphertext) |
| escrow | userId, sealed blob, fingerprint (of the recovery key), updatedAt — operator-posture accounts on private instances only. Only the version-3 form is stored (spec 04 §3): every route that stores a copy refuses one whose size is not `455 + E` bytes, `E` the length of the unpadded base64url of the account's `emailNorm` (`400 escrow_wrong_form`, spec 03 §3.1, §3.2, §14.3). A row an earlier development build stored in the old form is left as it is at start: the server cannot open a copy, and the offline tool and the fleet check name it |
| account_state | userId, sealedState (UVK ciphertext, §9), seq (the compare-and-set counter), **updatedAt** (when the blob was last written: an operational timestamp like `escrow.updatedAt`, served by no route; the server sees each write as it happens anyway) |
| personal_wrap | userId, vaultId, wrappedVk (UVK ciphertext) |
| usage_ledger | userId, **sealedUsage** (the per-user "last used" map sealed under the VK(personal)-derived usageKey (§2/§8.2) — ciphertext, opaque; AD `andvari/v1\|usage\|{userId}`, §2), updatedAt — the staleness-ranking input (§8.2). ONE aggregate blob by design, never per-item rows: the server sees THAT a user's ledger changed and its size, never WHICH login |
| member_recovery | userId, **recoveryWrappedUvk** (the UVK sealed under the member's recovery-secret-derived wrap key — ciphertext, opaque; AD `andvari/v1\|recovery-uvk\|{userId}`, §2), **recoveryVerifier** (one-way `crypto_pwhash_str(recoveryAuthKey)` — a DB leak is not a replayable recovery, exactly as the login verifier), **pieceId** (opaque random id of the current kit, spec 03 §12; not a secret), **setupDeviceId**, updatedAt — the recovery-kit row (spec 04 §6); ZK-clean |
| audit | event type, userId, deviceId, ip, timestamp, coarse metadata (never names, URIs, emails, or any decrypted content). After an account deletion (spec 03 §13) the account's retained security rows, and its activity rows about vaults that outlive the deletion, carry a random **pseudonym** in place of its userId (a UUIDv4 naming no user, not derived from the userId or email, its mapping stored nowhere; purged 90 days after the deletion), its rows about vaults the deletion purged are gone, other rows' meta names the pseudonym, and a row written later for the gone userId carries no userId (meta prefixed `deleted_account`) |
| policies | the operator policy JSON (min versions, KDF policy, lock timeouts, quota defaults, the tightened sign-up values) |
| meta | key/value operational markers (schemaVersion…) |

**The keyed hash of an address** (rule of 2026-11-17, kept since 2026-11-18). Every record the server
keeps of an address a person typed, other than an account's own `email` and a queued mail's recipient,
is `hexLower(HMAC-SHA-256(K, "andvari/v2|address|" + emailNorm))` with
`K = HMAC-SHA-256(enumSecret, "andvari/v2|address-record-key")` and `enumSecret` the bytes of
`ANDVARI_ENUM_SECRET` (the 0600 env file `andvari host init` writes): the `emailHash` of `signup_codes`,
`signup_tickets`, `recovery_requests` and `recovery_mailbox_values`, the `boundEmailHash` of `links`, and the
`addr=` prefix of the `signup_start`, `signup_verify_fail` and `login_wait` audit rows and their journal lines. The same
address gives the same value, so rows still tie together; without the secret, a guessed address
confirms nothing. K is a key of its own, so the value shares nothing with the fake salts the same secret
makes for `prelogin`, which anyone can ask for. Rows written under an earlier secret (a restore beside
another env file, or a changed secret) no longer tie to new rows; nothing else changes. Rows written
before 2026-11-18 keep the plain `hex SHA-256(emailNorm)` until they expire; the server still finds a
mailbox value (seven days) and an enrol link's binding (the link's own life) in that form, and lets a
sign-up code or ticket in flight at the upgrade (fifteen and thirty minutes) be asked for again.

**Audit types** (ids only, never an email). This is the whole list: the server serves it, sorted, as
`GET /admin/status`'s `auditKinds` (spec 03 §7.3), and a test reads the server's source to pin that it
writes exactly these. Sessions and sign-in: `register`, `login`, `login_fail`, `logout`, `session_end`,
`refresh_grace` (a replaced refresh token presented again within the sixty-second grace and answered with the
same pair; one row per answer, the account, the device and the caller's address only), `refresh_reuse`,
`reauth_fail`; a refusal by a back-off, **one row per key per fifteen minutes, never one per refused request**
(rule of 2026-11-17; the first refusal in each period writes it, the others write nothing):
`login_wait` (a sign-in or a device-link pickup refused by its address's back-off; the account when the address
has one, the caller's address, meta `addr=` and the first 8 hex characters of the address's keyed hash, then
` at=login` or ` at=pickup`), `reauth_wait` (a password proof refused by its device's back-off; the account, the
device, meta `route=` and the route's row), `totp_verify_wait` (a two-step code on a session refused by its
device's back-off; meta: where, as `totp_verify_fail`'s); credentials and the second factor: `password_change`,
`password_change_fail`, `totp_enroll`, `totp_rotate`, `totp_disable`, `totp_verify_fail`,
`totp_setup_reauth_fail`, `require_link_set`; self-recovery: `recovery_self_verify_fail`,
`recovery_self_commit`, `recovery_self_setup`, `recovery_self_setup_fail`, `recovery_self_confirm`,
`recovery_self_confirm_stale`, `recovery_self_confirm_unbound`; the account: `account_delete`,
`account_delete_denied`, `account_delete_reauth_fail`, `account_delete_stale` (a deletion refused
`409 account_delete_log_stale` because a vault's log moved on; once per account per hour, never per try; meta
`vaults=` and how many vaults the refusal named), `account_recovery_change`,
`account_device_revoke`, `escrow_self_reseal`, `push_denied`; the operator: `operator_disable`,
`operator_disable_denied`, `operator_enable`, `operator_delete`, `operator_delete_denied`,
`operator_device_revoke`, `device_revoke_denied`, `operator_quota`, `operator_policy`,
`operator_escrow_read`, `operator_recovery_fulfil`, `instance_card_update`,
`recovery_rotation_stored`, `instance_identity_reset`; sign-up and links: `signup_start` (meta
`addr=` and the first 8 hex characters of the address's keyed hash), `signup_verify_fail` (the same meta), `enrol_link_mint`, `link_create`, `link_answer`,
`link_revoke`, `device_link_create`, `device_link_claim`, `device_link_reveal`,
`device_link_approve`, `device_link_pickup`, `device_link_pickup_denied`; assisted recovery:
`recovery_request_create` (every accepted request, a decoy included; the account only for a real
request, so a decoy's row has the same shape; meta `mailbox=used` when the request named a mailbox value
that took it past the address's five of its window, which only an account in the operator posture can have, `mailbox=not_used` when it named one that did not, and none when it
named none, spec 03 §18.1), `recovery_request_verify` (meta `cancelled` when the right
code came after the owner cancelled the request), `recovery_request_verify_fail` (every refused
code; the account only for a real request, so a decoy's row has the same shape), `recovery_request_veto`,
`recovery_request_commit`, `recovery_request_commit_mismatch` (meta `at=check` or `at=commit`);
vaults and items: `vault_log_append` (meta: the kind), `vault_rename`, `vault_grant_self_wrap`,
`vault_purge`, `item_restore`, `item_purge`, `attachment_upload`, `attachment_cross_vault`; mail:
`email_sent` (meta: the template name), `email_failed`, `email_dropped`.
Retention: 365 days, and a deleted account's pseudonymised rows 90 days (spec 03 §13).

Traffic analysis (who syncs when, item counts, sizes) is visible to the server by
nature and accepted (spec 05). This table describes the **fresh baseline schema** of the
onboarding-and-trust cut-over exactly — adding any table or plaintext column requires updating it
in the same change. The server creates that schema on an empty database and **refuses to start** on
a database created by a pre-cut-over build ("This database is from andvari 0.x; restore its export
into a new account instead"); no forward migration from an older schema exists (spec 07 §3). No
table caches HIBP results: the relay keeps no state (spec 03 §8).

### 5.1 Changing the baseline before the first release

The server of this design has not been released, so its baseline (`Db.SCHEMA`, marker `meta.baseline`,
now `onboarding-trust-1`) is edited in place. Databases that development builds made exist all the same
(the owner's test server holds one), and a change to the baseline that reaches none of them breaks them
quietly: the server starts and then a route fails on the column it lacks. Until the first release, **every
change to the baseline does one of these two things, in the same commit, and never neither**:

1. **It changes the marker.** A database that carries an earlier marker is then refused at start with
   "This database was made by an older development build of andvari, and this build cannot bring it up
   to its baseline (baseline '…', this build expects '…'). Start this build on a new, empty database file
   (keep the old file aside), or run the build that made it." The earlier marker is added to
   `Db.EARLIER_BASELINES`, so the refusal can say *older*; a marker no build of this design wrote is
   refused as another build's.
2. **It is one the start-up step can make.** At every start, inside the start-up transaction, the server
   brings a database that carries the current marker up to the baseline, looking before it adds: it
   creates a missing table with its indexes, adds a missing column that SQLite can add to a table with
   rows (nullable, or NOT NULL with a default; never a key, `UNIQUE`, or a NOT NULL reference), and
   rebuilds a table whose column definitions or table constraints changed (a NOT NULL dropped, a CHECK
   widened) when no other table refers to it, copying its rows; drops, by the same rebuild, a column the
   baseline retired, one named in `Db.RETIRED_COLUMNS` (a decision, made in the commit that removes the
   column, that its values are not needed), when no other table refers to the table; and it creates every
   index the baseline names that the database lacks, and makes again one defined differently. It writes one
   log line naming what it did. Anything else — a NOT NULL column without a default, a column the baseline no
   longer has and did not retire, a
   changed table that others refer to, rows the new definition does not admit — refuses the start with
   the sentence of 1 (naming what it could not bring up) and changes nothing. After the step every table
   has exactly the baseline's columns and every index it names, so a server never runs on a database
   that lacks one.

A change of the second kind adds its expected effect to `BaselineCatchUpTest`; a change of the first kind
freezes the outgoing baseline under `server/src/test/resources/baseline-history/` and moves the tests of
the older databases to the refusal. `BaselineRuleTest` holds a digest of the baseline beside its marker,
so a commit that edits the baseline without looking at this rule fails.

Steps of the second kind so far: the step of 2026-11-15 let `recovery_requests.userId` be NULL (a decoy, spec 03
§18.1), which rebuilds the table; the step of 2026-11-16 added `recovery_requests.commitHash` and `commitAttempts`,
which are added (`commitHash` only, since `commitAttempts` was retired on 2026-11-16 with the count of
wrong commit values it held, and the step drops it from a database that has it), and a request such a database already holds as answered
(`fulfilled` with no `commitHash`: an answer of the old form, which no device takes and no commit value
matches) goes back to `verified`, waiting for the operator, its stored answer dropped, at every start,
with the count in the start's log line (rule of 2026-11-16, so that the operator answers it again in the
new form); the covering index `idx_items_vault_live_size` on `items(vaultId, deleted, blobSize)`
(the use-and-limits sums of spec 03 §14.4 read it alone, never the item rows) is created; on 2026-11-17
`recovery_requests.cancelledAt` (nullable) is added, and the table `recovery_mailbox_values` is created with
its index `idx_recovery_mailbox_values_email`. Of the earlier in-place edits of 2026-11-15, the step adds `vaults.logState` and
`device_links.approvedBy` to a database made before them, and refuses one made before
`instance_cards.name` or `users.registeredVia` (NOT NULL without a default: no value to give old rows).
On 2026-11-17 the table `session_chains` is created with its index `idx_session_chains_chain`; a database
a development build of that day ran on holds the chain in a column `sessions.chainId` instead, which is
retired: its values are carried into `session_chains` first, then the rebuild drops it.

**A roll-back stays possible (rule of 2026-11-17).** A server of the version before must start on a
database this one has run on: its start-up step refuses a column of a table it knows that its baseline
does not have, and ignores tables it does not know. So a new fact is kept in a table of its own, never in
a new column of an existing table, and a new table holds no reference that would block the version
before's deletes (rows it leaves behind are tidied up by this version's janitor). `SessionChainsRollBackTest`
shows it for the version before `session_chains`: the version before's step finds nothing to change on a
database this version has run on.

Once the server is released, its databases hold people's vaults, and the baseline is frozen: every change
is a numbered, tested migration (spec 07 §3), and this section no longer applies.

## 6. Attachments

- Per-file random 32-byte `fileKey` (lives inside item ciphertext, §3).
- **The file key is the item author's choice, and a reader checks it before anything is
  downloaded.** Whoever writes an item chooses its `fileKey` (a co-member, in a shared vault). A key
  that is not 32 bytes of base64url, or that is all zeros, is refused as damaged content before the
  file is fetched: nothing is downloaded and nothing is decrypted. A key of all zeros is a key
  everyone knows, so a file "sealed" under it could be made or replaced by the server, or by anyone
  who sees the stored bytes, and would still open as if it were the author's. The shared code keeps
  this (2026-11-17); a lock while a file downloads stays a lock and is never reported as damage.
- Content encrypted with `crypto_secretstream_xchacha20poly1305`, plaintext chunked
  at **64 KiB** (last chunk 1..65536 bytes, tag FINAL; all others tag MESSAGE).
  Stored as `header (24B)` + ordered ciphertext chunks (each chunk + 17-byte ABYTES);
  the server persists header and chunks and never sees content or filename.
- Decrypters MUST fail hard on: any chunk MAC failure, FINAL before last chunk,
  missing FINAL at end (truncation), or extra data after FINAL.
- The ref's `size` (§3) is the exact plaintext length, and it is the item AUTHOR's claim —
  a co-member's, in a shared vault. **Clients treat it as a claim (2026-10, security review):**
  a download must be exactly `24 + size + 17·⌈size/65536⌉` bytes, and the client stops
  reading and refuses the attachment once a body passes that length or ends short of it; the
  backup planner (spec 07 §2.5) skips a non-positive claim and sums with overflow-safe
  arithmetic; a client that scales a transfer timeout by `size` clamps it (desktop: 64 MiB).
- Upload: blob first (`POST /attachments/{id}`), then the item update referencing it;
  orphaned blobs are GC'd after 24 h. Server enforces per-item and per-user quota
  from policy (defaults: 25 MiB/attachment, 100 MiB/item) and the vault owner's storage quota
  (spec 03 §14.4).

## 7. Tombstones, versions, conflicts

> **Status note (v5; caution satisfied 2026-07-10):** two kinds of pruning must not be
> confused. **item_versions IS capped live** — every overwrite keeps only the newest 10
> versions per item and hard-deletes the rest (`Repo.archiveVersion`), so an 11th-oldest
> version is already unrecoverable. The *tombstone/oldestRetainedRev* GC and its
> 410-resync trigger — dormant when this note was written — are **now ACTIVE** (n2
> residue hardening, design 2026-07-10 §5): item tombstones purge at 30 days and the
> daily janitor advances `oldestRetainedRev` behind a fence keyed to that same horizon.
> The shared-vault lifecycle design (docs/design/2026-07-07-shared-vault-lifecycle-skipti.md)
> recorded the (a)–(d) preconditions any activation had to satisfy; the activation
> record below states how each is met.

**Vault deletion (a signed `delete`, §10; spec 03 §11.1):** a soft-delete with a 7-day grace
(`ANDVARI_VAULT_GRACE_DAYS`) — all rows stay intact and every grant is revoked
(`revokedReason='vault_delete'`); a signed `restore` within grace un-revokes exactly the grants
still revoked that way and re-opens the vault. The vault's log rows and its tombstone
`{finalHead, purgedAt}` outlive the purge by one year, so the members at the `delete` can verify it
(§10.6). After the grace the daily **janitor** purges (per-vault tx that
re-checks `deletedAt/purgeAt` inside every destructive statement): `item_versions` and
attachment rows/files are deleted, item rows are reduced to ciphertext-free
**skeletal tombstones** (`deleted=1, blob=NULL`, no rev bump, `updatedAt` restamped to the
purge instant — they keep the `vault_mismatch` teleport fence alive, 0.2.x MSI included,
for the full 30-day tombstone horizon from purge, then age out with the ordinary tombstone
GC below; the edit-over-tombstone fence is grant-gated and never reads them post-purge),
`metaBlob` is blanked, and **every** grant's key material is wiped
(`wrappedVk=''` — the `NOT NULL` sentinel — and `signedGrant=NULL`, active and
previously-revoked alike). Vault tombstone rows and all grant rows are retained
indefinitely and `vaultId` is never recycled — that pair is what keeps a push against the
purged vault itself denied forever. **One exception (account deletion, spec 03 §13, design
2026-11-10):** a deleted account's OWN grant rows go with its user row, which they
reference. The property holds without them: a push needs an authenticated session of an
existing account, the deleted account has none, and every other account's rows on the vault
are retained. Account deletion is also the **second purge path**: the vaults the deleted
account alone held (its personal vault, solely held shared vaults, and one it soft-deleted
that is still in grace) are purged at once, with the same statements and no grace — nobody is
left who could restore them. Skeletal item rows are **not** retained indefinitely:
by the time one ages out, every cursor is vault-absent by one of two legs — (1) a cursor
predating the DELETE has sat behind the `oldestRetainedRev` fence for at least the full
grace window (410 → full resync → vault absent); (2) a cursor minted DURING the grace
window was minted by a pull that already delivered the revoked grant (`removedGrantsInfo`,
the `g.rev > since` arm), so the vault is absent locally by delivery — such a cursor may
never 410 at all on an idle server (the MAX(rev) fence floor + strict `since < fence`).
Either way a post-horizon teleport re-push degrades into the accepted re-add class (a clean INSERT
of the pusher's own re-encrypted copy into their own vault; pinned in `JanitorTest`, same
class as the >180d mutation replay). The janitor's v1 scope was **vault purge
+ ownership-offer expiry ONLY** — the general retention machinery had to stay dormant until
it could satisfy the (a)–(d) invariants of that note plus a quiet-server integration test
(delete → idle past retention → full janitor cycle → all client generations converge
without 409/410 loops). **Activation record (2026-07-10, n2 residue hardening §5): that
caution is satisfied, not repealed.** The daily janitor now prunes `changes` and advances
`oldestRetainedRev` in the SAME transaction, with the fence **keyed to the 30-day
item-tombstone horizon** — one shared constant (`Janitor.ITEM_TOMBSTONE_RETENTION_MS`), so
any cursor old enough to have missed a purged tombstone 410s into a full resync (this
closes the 30–89-day deletion-resurrection window a longer fence would have left).
Invariant (a) is implemented as a **MAX(rev) floor**: the horizon rev is
`min(oldest rev inside the window, MAX(rev))`, so on an idle server every stale row below
the newest is pruned but the MAX(rev) row is always retained and `currentRev` never
regresses; (b) holds by the same-transaction fence advance; (c) the mutation-dedup journal
retains 180 days; and (d)'s quiet-server test exists —
`JanitorTest.quietServer_convergence_afterFullSweep` (delete → idle past the fence → full
sweep → up-to-date cursor no-ops, stale cursor 410s then converges via `since=0`,
`currentRev` never regresses).

- **Delete** = tombstone (`deleted=true`, blob dropped, attachments GC'd). Tombstones
  are GC'd after **30 days** — the same horizon the `oldestRetainedRev` fence is keyed
  to (above); a client whose cursor predates the oldest retained
  change receives `410 Gone` on sync and MUST full-resync (prevents deletion
  resurrection by stale caches).
- **item_versions**: on every overwrite (and before every delete) the server archives
  the previous `{rev, blob, formatVersion}` for the item, keeping the most recent **10**
  versions. AD stays valid (bound to itemId+formatVersion, **not** rev), so an old version
  decrypts under the item's current VK with no crypto change. This is **the**
  no-silent-loss backstop — the reserved `login.passwordHistory` field (§3) is not a second
  one, since no client writes it. **Exposed (item history & restore feature):**
  `GET /items/{id}/versions` (spec 03) serves them
  grant-checked; the client decrypts each blob under the VK it holds and can restore one as
  an ordinary put. Two bounds the UI MUST state honestly: (1) at most the last **10**
  versions ("up to the last 10", never "nothing is ever lost"); (2) **history resets at VK
  rotation** — the archive is ciphertext under the *current* VK, so the queued lazy VK
  rotation (ROADMAP — "VK lazy rotation on member removal") either prunes
  item_versions for the rotated vault or re-seals it
  (design decision handed to the rotation work; see docs/design/2026-07-08-item-history-and-restore.md).
- **Conflict flow** (authoritative rules in spec 03 §5): the server never merges and
  never re-encrypts; it applies the newest write, archives the loser, and sets
  `conflict=true`. The next syncing client that can decrypt materializes a visible
  "(conflict copy)" item — new itemId, fresh envelope — then clears the flag with a
  normal push. Both mutations are built from the flagged envelope's OWN plaintext and sealed
  under that envelope's vault (INV-CONFLICT, §7.2); a flagged row whose vault disagrees with the
  item's home or its in-memory twin pushes nothing.

### 7.1 Server durability — what `applied` promises (2026-09-13 amendment, audit H84)

Normative: **a server MUST NOT answer a mutation `applied` until that transaction is durable
against power loss.** With the reference SQLite server that means WAL plus
**`PRAGMA synchronous=FULL`** — one fsync per commit.

The rule exists because `applied` is load-bearing on the *client* side, and the client is the
only copy left. A push writes the item row, its `changes` rev and the `mutations` idempotency
row in one transaction, and the client drops that mutation from its outbox the moment it reads
`applied` (spec 03 §5). Under `synchronous=NORMAL` a WAL commit is acknowledged before it is
fsynced — SQLite documents that in WAL mode with NORMAL a committed transaction "might roll
back following a power loss or system crash" — so a power cut inside the checkpoint window
takes all three rows *together*. Nothing then asks the client to re-send: the dedup row that
would have made a replay safe is gone too, but no client replays a mutation it saw acknowledged.
The write survives only in that client's local cache (in the extension, memory only — already
gone) until its next full resync, where a `since=0` pull replaces the cache with the server's
copy and the item is silently lost. An application crash is not this case: the OS page cache
survives it and NORMAL is sufficient there.

**The trade, stated so an operator can choose with eyes open.** FULL costs one fsync per commit.
At household write rates writes are the rare path (single-digit per minute; reads and no-op
pulls take no fsync at all), so the throughput cost is not measurable in use — but it is real on
slow storage, and an SD-card host will feel a bulk import. A deployment that wants NORMAL back
for a large import MAY relax it **for that run**, never for the steady state, and MUST then treat
every write in the window as un-acknowledged until the next checkpoint. Choosing NORMAL as a
standing configuration means "saved" no longer means durable, which this spec does not permit a
conforming server to promise.

`data/andvari.db` is still the only copy of the household's ciphertext; durability is not backup
(`docs/self-hosting.md` § Backup).

### 7.2 Item home and seal provenance (NORMATIVE client duties; security review 2026-10, root cause A §5, branch A1b)

The server chooses every row a client sees, so a row's `vaultId` is a hint about where an item lives, not a
fact. These invariants keep plaintext in the vault it came from. Every client implements them; the rules are
pure functions graded by `spec/test-vectors/itemhome.json` (core `ItemHome`, web `vault/itemhome.ts`, extension
`itemhome.ts`).

- **INV-HOME.** For every itemId a client records `home(itemId)`: the vaultId of the FIRST envelope it applied
  for that itemId (or of its own first seal of a fresh id). It is persisted with the offline cache (§8: native
  client-state rows `item.home.<itemId>`, web kv rows `itemHome:<itemId>`, the extension's IndexedDB store per
  origin and user since A15, storage.local before), survives a 410 resync and a restart, and is rebuilt from the cached rows on hydrate. Every
  later row for that itemId, live or tombstone, whose vaultId differs from the home is NOT applied: it goes to a
  quarantine (ciphertext, kept for diagnosis), is excluded from items, search, export, autofill and capture, and
  the pull raises ONE "the server sent an item under the wrong vault" notice. No legitimate flow re-homes an
  itemId: move and copy mint a fresh id (the copy leg) and then delete the source.
- **INV-SEAL.** Item plaintext is sealed for a push under `VK_v` only when its provenance vault is `v`:
  (a) the vault bound in the AD of the envelope it was decrypted from; (b) the vault an editor session was
  bound to when it OPENED; (c) a destination the user explicitly chose and saw (move, copy, import, the new-item
  vault picker). No wire field, lookup by itemId or label chooses the sealing key: every item seal goes through
  one helper that takes the provenance (core `Account.sealItem`, web `Account.sealItem`, the extension's gated
  `putItem`), and a seal of an itemId under any vault other than its home is refused.
- **INV-CONFLICT.** A conflict copy and the flag-clearing put are both built from `decrypt(flagged)` under
  `flagged.vaultId`. If the in-memory twin or the home names another vault, nothing is pushed and the pull's
  wrong-vault notice is raised. The push-side copy from a server-returned displaced value requires that value to
  be under the vault the losing put was pushed to (its AD vault, which is also the copy's seal vault) and the
  item's home.
- **INV-EDIT.** A save of an existing item names the vault its editor was bound to when it opened. If the item's
  home differs at save time, the save is refused ("This item changed vaults; reopen it."), never re-targeted.
- **INV-WRITE-KEY.** No item is sealed under a key that failed the vault-key commitment (spec 01 §6.2), or under
  the key of a vault that is frozen, failed or not yet accepted (§10.4), on any path: save, conflict, copy-into, import, the
  extension's capture and update targets, TOTP add. (The holding area's local re-seal, a queued write's local
  pre-edit snapshot and the revert of a refused write never leave the device and are not pushes.)

The home is device-local: the server chooses the first home on a fresh device (spec 05 R17).

## 8. Client offline cache

Native clients (Android/desktop) MAY persist, per account, in a local SQLite DB
(`vault-<userId>.db`), so the working set + sync cursor + outbound queue survive
process death. The web client MAY persist the same set in IndexedDB — the deltas are
enumerated in §8.1 (2026-07-14 amendment; this section previously closed with "the
web client keeps no at-rest cache in v1"). **Every persisted field is a subset of
the §5 server-visible table — the client-at-rest surface is ⊆ the server-at-rest
surface by construction:**

- the sync cursor (a rev number);
- item rows exactly as received on the wire (ids, revs, timestamps, flags,
  formatVersion, attachmentIds, `blob` AEAD ciphertext);
- grant rows (vaultId, userId, role, `wrappedVk` and `signedGrant` ciphertext, rev);
- vault rows (vaultId, type, rev, `metaBlob` ciphertext, createdAt);
- the outbound mutation queue (mutationId, op, ids, baseItemRev, `ItemUpload`
  ciphertext);
- for offline unlock, a copy of the server's `accountKeys` payload (kdfSalt,
  kdfParams, wrappedUvk, encryptedIdentitySeed, identityPub, recoveryConfirmed, personalWrap,
  genesis). A cached AccountKeys without a genesis is refused as damaged (spec 01 §5.4);
- the vault log entries it has verified (§10.5; public frames).

The per-vault verified state, the pinned card, the account's own records mirror and the link
records live in **device state**, which outlives the offline cache (§10.5, spec 01 §5.2).

Clients MUST NOT persist: the master password, MK, authKey, UVK, VK, identity seed,
decrypted `ItemDoc`s, attachment plaintext, or fileKeys outside item ciphertext.
Decryption happens only in memory after the user supplies the master password; lock
and relaunch drop all key material.

- The DB file gets no extra encryption in v1 (envelopes are already AEAD). Note:
  quick unlock (spec 01 §8) wraps the **UVK**, not this DB — whole-file DB wrapping
  remains a possible future hardening, independent of quick unlock.
- Clients MUST honor `ClientPolicy.offlineCacheAllowed`: when false, no durable cache
  is created and any existing cache file for the account is deleted (re-evaluated on
  every successful policy fetch).
- The cache is deleted on **sign-out** and on any **definitive server rejection**
  (device revoked, or an invalid-session 401 that survives a refresh) — the latter
  also drops the cached `accountKeys`. It is **retained on lock** (spec 05 T3 already
  accepts ciphertext-at-rest on a stolen locked device).
- **Offline unlock** accepts the master password that was current at the last online
  contact; a remote revocation or password change only takes effect at next
  connectivity (spec 05 T3).
- Native cache files SHOULD be excluded from OS cloud backup (Android
  `dataExtractionRules`/`fullBackupContent`) so no cloud copy of the ciphertext DB or
  token store exists. (The web client cannot make this exclusion — §8.1.)

### 8.1 Web client (IndexedDB — 2026-07-14 amendment)

The web client MAY persist the SAME per-account set (the list above verbatim, plus
the `lastSyncAt` stamp, the holding area, the per-vault verified log state of §10.5, and the
last-known policy bits) in a
per-account IndexedDB database (`andvari-vault-<userId>`); as built, the policy bits
live device-locally in localStorage (see the origin-gated bullet below) — the DB's
`kv:policy` slot is reserved, with no production writer yet. Design, schema, and
consistency rules: `docs/design/2026-07-13-web-offline-cache.md`. The MUST NOT
list, the `offlineCacheAllowed` rule, the sign-out/definitive-rejection wipe rule,
retained-on-lock, the no-extra-encryption-in-v1 posture, and the offline-unlock
freshness posture above apply to the web cache **verbatim**. Web-specific deltas:

- **accountKeys co-location.** The cached `accountKeys` live in the SAME DB as the
  envelopes (natives keep them beside, not inside, the vault DB) — one artifact, one
  wipe. Consequence: the 410-resync `clear()` is an ENUMERATED contract that resets
  the items/grants/vaults stores and the cursor ONLY, and MUST preserve
  accountKeys/queue/holding/floors (design §D.1) — a naive clear would break offline
  unlock after any resync-then-lock.
- **Eviction + durable writes.** IndexedDB is best-effort storage the browser may
  evict. The client requests `navigator.storage.persist()` once at first enable, and
  the offline-WRITE queued-success path is offered ONLY while
  `navigator.storage.persisted()` is true (refuse-not-degrade: an evicted queue is
  unrecoverable user data; server-derived rows are refetchable, so their eviction is
  availability loss only).
- **No OS-backup exclusion.** The browser profile cannot be excluded from OS backup
  (no web analog of `dataExtractionRules`); OS backups may then hold the ciphertext
  DB — ⊆ the spec 05 T7 backup-theft surface, accepted.
- **Consent-gated, default OFF, on every origin.** The cache is created only after an
  explicit **per-user, per-device opt-in** — the settings toggle "Keep an offline copy
  on this device", which is also the accept path of the one-time nudge. There is no
  origin test: the walk-up browser is the spec 05 T3 case whatever the address bar
  says. (*Historical:* before the 2026-07-15 endpoint-agnostic pivot the gate defaulted
  ON for "private" origins and OFF for the public one. That gate is gone, along with
  the origin classifier behind it; a one-time per-user boot migration adopts a standing
  pre-pivot cache as evidence of the old default's consent rather than destroying it —
  design 2026-07-15 §5.4.1 CONTINUITY.) Turning the toggle off wipes immediately; the
  Unlock screen shows a transparency line whenever a durable copy exists on the device.
  The last-known `offlineCacheAllowed` policy bit is persisted device-locally and
  honored on OFFLINE boot (native persisted-policy parity), so a device that last saw
  `false` refuses to re-create a cache until a later successful fetch says otherwise —
  policy and consent are ANDed, and either one saying no forbids and wipes.
- **No quick unlock** (spec 01 §8.3 unchanged): the cache stores ciphertext + wire
  metadata only and never changes what a reload demands — the full master password.
- **What the copy serves without the server (2026-11-16).** The page and its code come
  from the instance itself, and the web client keeps no offline app shell (no service
  worker). So the copy opens the vault only in a tab that is already open when the
  server cannot be reached; a reload or a fresh tab without the server cannot load the
  page at all, and the browser shows its own error. An app shell is not part of this
  release. Adding one is a design decision of its own, because a cached shell is code the
  server served earlier: the update and minimum-version rules must still win over it, it
  must be bound to the pinned origin and dropped with the pin (a fork, "Forget this
  server", a sign-out), it may cache only static files (never API answers, tokens or
  `/client-policy`), the consent gate and its wipe must cover it, an offline start may
  open only through the copy with the pin-gated identity check, the content-security
  rules must cover the worker, two tabs on different bundles must not fight over the
  session record, and the kept records (pending wrap, held frames) must stay readable by
  the previous released bundle.

### 8.2 Usage ledger (2026-08-22 amendment)

The vault-health staleness ranking (design
`docs/design/2026-08-22-login-health-staleness-verification.md`) wants "when was this login last
used". It is stored as **one sealed per-user blob**, never as a field in the item document, and
never as per-item rows. Both exclusions are load-bearing:

- **Not in the item document.** A `usedAt` there would make each use an item overwrite, and §7
  caps `item_versions` at the newest 10 per item — so roughly ten uses would evict an item's
  entire real edit history, destroying the only shipped no-silent-loss backstop (F63) in exchange
  for a convenience column. It would also turn the server-visible `changes` feed (§5) from a
  record of *edits* into a per-item *behavioral* log.
- **Not per-item rows.** One row per item would leak the same behavioral timing through row
  metadata instead of through `changes` — the same disclosure by another route.

One aggregate blob has neither problem: the server learns THAT a user's ledger changed and its
approximate size, never WHICH login moved.

**The §8 subset invariant is PRESERVED, not narrowed.** The ledger exists server-side as
ciphertext (§5 `usage_ledger`), so a client caching it is still storing a subset of the
server-visible table — the property §8 states holds unchanged.

- **Sealed under `usageKey = HKDF-SHA-256(VK(personalVault), "andvari/v1|usage")`**, AD
  `andvari/v1|usage|{userId}` (§2) — domain-separated from that VK's own AEAD use by its HKDF label,
  and the AD still binds the blob to the user's slot so a hostile
  endpoint cannot serve one member's ledger into another's.
  **Keyed from the personal VK rather than the UVK for a CLIENT reason, recorded so it is not
  "simplified" back:** the browser extension's UVK is memory-only and never persisted (spec 01
  breaker B1), and an evicted MV3 service worker restores a session holding `vaultKeys` but no
  UVK — so a UVK-bound ledger was unwritable from the client that does most of the filling.
  Every unlocked client holds the personal VK in every session. No vault key is persisted either
  (§8 MUST NOT list, unchanged), so the ledger is still readable only in memory after an unlock,
  and the server and a stolen locked device both hold opaque bytes. Spec 05 T3 is unchanged.
  An account with no personal vault simply has no ledger — clients MUST degrade to "—", not error.
  **WHICH vault that is comes from §4's rule — the personal wrap (security review 2026-10, root
  cause A) and the genesis — never from the server's label:** a client MUST NOT key the ledger from a
  shared vault, because its VK is held by every other member and `andvari/v1|usage|{userId}` is
  public — a relabelled shared vault would hand a colluding co-member the itemId → {lastUsedAt,
  useCount} log this whole single-blob design exists to keep private. No personal vault is the "—"
  degradation above and not an error.
- **Contents.** `itemId -> { lastUsedAt, useCount }`, nothing more. No password material, no
  document content, no URIs. Both fields are JSON **numbers** (integers: epoch ms and a count).
- **Reading is tolerant per ENTRY and strict per TYPE (2026-09-13, audit H92).** A reader MUST
  treat any ledger that is not a JSON object as empty, and MUST skip — individually — any entry
  that is not an object, whose `lastUsedAt` is not a finite JSON number (a string, boolean,
  object, array or `1e999` is not a number, whatever it contains), while keeping every
  well-formed entry beside it; a `useCount` that is missing or not a finite number reads as
  `1`. One malformed entry MUST NOT empty the whole ledger: with the merge-then-store flush
  above, "read as empty" on one client becomes "overwrite the household's ledger with this
  session's few entries" — the H05 clobber by another route. Unknown entry keys are dropped, not
  preserved (the blob is wholly rewritten by one writer at a time and carries no user-authored
  content). The three twins are graded on all of this by `spec/test-vectors/usageledger.json`.
- **Every unlocked client may write it**, which is the point: a fill on the phone
  counts on the laptop. A device-local ledger could not do this — the browser extension is a
  separate client with its own storage, and there is deliberately no cross-client channel
  (injecting into the vault origin is fail-closed forbidden).
  > **RESOLVED 2026-08-22 by the key binding above.** The first draft sealed under the UVK, which
  > the browser extension cannot hold across a service-worker eviction (breaker B1) — it would
  > have excluded the client that does most of the filling. Re-binding to the personal VK removed
  > the exclusion rather than working around it. The standing rule, which outlives that particular
  > problem: **a client that cannot open the ledger MUST leave it untouched** rather than write a
  > partial one over another client's.
- **The flush round, normatively (2026-09-13 amendment, audit H05 — the rule above was being
  violated by all three engines).** Every flush first reads the server copy and then lands in
  exactly one of three states; the three MUST be kept distinct, because collapsing the first two
  into "empty" is how one device's handful of buffered uses replaced a whole household's ledger:
  1. **Absent** — the GET succeeded and returned `sealedUsage: null`. The client writes its buffer
     as a first ledger. This is the ONLY case in which a write without a merge is not an overwrite.
  2. **Unreadable** — the GET failed (offline, 5xx, 401, timeout, rate-limit) OR a blob came back
     that would not open under this client's key (wrong key, AD mismatch, a future encoding). The
     client **MUST NOT PUT that round**, buffered uses or not. It re-buffers them and retries at
     the next flush. The conservative direction loses at most one session's ranking hints on a
     device that never reconnects; the other direction erased everyone's. The endpoint is
     last-writer-wins with no server-side merge and no history, so there is nothing to recover
     from after the wrong PUT.
  3. **Present** — the blob opened. The client merges its buffer over it (per-item max, below),
     prunes if and only if it is at a post-sync point (next bullet), and PUTs **only when something
     changed** — buffered uses, or a prune that dropped an entry. A quiet round costs one GET and
     no `updatedAt` bump.
  A blob that opens but parses as garbage is a PRESENT, EMPTY ledger: it authenticated under this
  user's key, so replacing it is the tolerant-parse posture ("a corrupt ledger costs one health
  column"), not a cross-client overwrite. "Cannot open" means the AEAD open, not the parse.
- **Prune (growth bound), normatively (2026-09-13 amendment, audits H35/H36).** The ledger is
  pruned — entries dropped for items that no longer exist — at ONE point only: immediately after a
  **successful full sync**, on every client, on every such sync, **regardless of whether any use
  is buffered** (a prune gated behind a non-empty buffer fires only when a sync happens to land
  inside the debounce window, i.e. effectively never). The keep-set MUST be the id of **every live
  envelope the sync delivered — decryptable or not** (a newer-formatVersion envelope this build
  fails closed on, an item in a vault whose key has not arrived) plus the ids buffered in this
  session (a use recorded after the snapshot is inherently live). Tombstones are excluded; that is
  what the prune is for. Never the decrypted working set: an item this device cannot read is live
  on the server and readable on the user's other devices, and pruning its entry ranks it "unused"
  everywhere. Never a lock / page-hide / teardown view, which can be pre-sync.
- **Teardown flush ordering (2026-09-13 amendment, audit H33; the G03 rule generalised).** The
  lock, sign-out and page-hide flushes MUST NOT be cancelled by their own teardown, and the
  teardown MUST NOT invalidate the credentials or the transport the flush's GET+PUT ride on
  before the flush has had its bounded chance — never fire-and-forget into a teardown that
  drops the tokens underneath it. Two mechanisms conform: **awaiting** the flush under a short
  bound (2 s) before the teardown proceeds (the sign-out paths, the page-hide flush), or
  handing the flush an **explicitly captured** context — the session/token pair it needs —
  and closing that transport / forgetting those tokens only when the bounded flush ends (the
  natives' and the extension's lock paths, where the session and keys drop immediately and
  only the transport's close or the token pair waits). A flush that outlives the bound is
  abandoned; the lock itself is never delayed by it. In every case the sign-out flush precedes
  the server-side session revocation.
- **Writes are batched, never per-use.** A client accumulates in memory and flushes on a debounce
  (and on lock / sign-out / page-hide), so the blob's own `updatedAt` cannot be read as a
  keystroke-level activity trace. Clients MUST NOT flush synchronously on every fill.
- **Last-writer-wins, and that is acceptable.** Two clients flushing concurrently may lose one
  side's recent entries. The data is advisory ranking input — never a security input, never
  user-authored content — so it gets no conflict machinery; a lost entry costs at most a stale
  cell in one health column. Clients SHOULD merge per-item by `max(lastUsedAt)` against the
  server copy they hold rather than blindly overwriting.
- **Absence carries no information.** A missing entry means no client has recorded a use — NOT
  that the login is unused. Clients MUST render it as "—", never as "never used".
- **Disclosure bound (spec 05).** On a stolen *unlocked* device, or to anyone who compels the
  master password, the ledger reveals which items the owner touches most. It carries no secret,
  but it is behavioral data, and it is named here rather than shipped quietly.

## 9. Account-state records

`GET/PUT /account/state` (spec 03 §3) carries ONE opaque blob per account,
`Envelope(UVK, JSON, "andvari/v1|account-state|{userId}")`, capped at 1 MiB of base64
(`ACCOUNT_STATE_SEALED_MAX = 1,048,576` characters, about 768 KiB of plaintext). Its JSON document holds
the records below and its own `seq`: the authenticated counter that "older" and "newer" refer to. The
`seq` the server serves beside the blob is only its compare-and-set token.

Every device merges a served copy with its own on each read and on `409 stale_state`. **The server
alone** can only serve an older copy (or withhold one), never a forged one. Any holder of the UVK can
write anything — the account's own devices, a hostile web bundle while the person uses the web client,
the operator of an operator-posture account who opened its escrow — and the rules below limit, but do
not prevent, what a wrong record does (spec 05 R35). A record only ever **refuses**; a missing record
never blocks anything.

| Record | Shape | Merge rule |
|---|---|---|
| `contacts` | `userId → {userId, identityPub, label: <name>, method: "link", verifiedAt, compared: bool, madeOn: <deviceId>}`, plus tombstones | Per `userId`: the newest `verifiedAt` wins, and a tombstone not older than a pin removes it (an unpin's tombstone is pushed to the removed pin's `verifiedAt`, so the newest human act wins whatever the clocks say). A different key for the same `userId` is never merged silently: the record keeping the key this device already uses stays, and the other goes to the key-change prompt (spec 03 §15.9). `compared` merges as OR between records with the same key; a record with a different key starts at `false`. `method` has the single value `"link"`; a decoder refuses any other. |
| `vaults` | `vaultId → {genesisHash, seq, hash}` | `genesisHash` is immutable: a copy with another genesis for the same `vaultId` is an anomaly, and the local record stays. Otherwise the higher `seq` wins. The same `seq` with a different `hash` is a **fork** (§10.5). A removed vault keeps its record, so a re-add of the same vault is checked against the same genesis. |
| `accepted` | `vaultId → {owner, addSeq, at, decision: "accept" \| "decline"}` | The higher `addSeq` wins per vault. For the same `addSeq`, `decline` wins whatever `at` says (a leave is final for that `add`); between two records with the same decision the newest `at` wins. A record whose `addSeq` is not the `seq` of this account's latest `add` in the verified log answers nothing, so the person is asked again (§10.4).  A device that **creates** a vault writes `{owner: its own account, addSeq: 0, decision: "accept"}` (`0` stands for the genesis: no `add` has that position). A device that signs, or verifies, a `leave` or `remove` of this account writes `"decline"` for the current `addSeq`. Both exist for the extension, which reads `decision` only and so opens no wrap, owner wraps included, of a vault without an `accept` record (spec 01 §6.5). |
| `recovery` | `{posture: "private" \| "operator", fp: <hex64> \| "none", at}` | The newest `at` wins; ties go to `private`. A device acts on an `operator` record only with its own mirror (spec 04 §2). |

**Document layout.** The sealed plaintext is one JSON object:

```
{"v":2,"userId":<uuid>,"seq":<int>,
 "contacts":{<userId>:<contact>},
 "contactTombstones":{<userId>:<removedAt ms>},
 "vaults":{<vaultId>:{"genesisHash":<hex64>,"seq":<int>,"hash":<hex64>}},
 "accepted":{<vaultId>:{"owner":<uuid>,"addSeq":<int>,"at":<ms>,"decision":"accept"|"decline"}},
 "recovery":{"posture":"private"|"operator","fp":<hex64n>,"at":<ms>}}
```

A contact's `userId` equals its map key. `recovery` is absent until a choice has been recorded. A
document with another `v`, or whose `userId` is not the account's, is refused whole; a single record
that fails its own shape (a contact whose `method` is not `"link"`, a malformed key, an unknown
`decision`) is dropped and counted, and the rest of the document is used. Writers emit each map's keys
in ascending byte order; readers accept any order. **Ties**, which exist only so that every device
reaches the same document: two contact records with the same key and the same `verifiedAt` resolve to
the larger `label`, then the larger `madeOn`; two `accepted` records with the same
`addSeq`, `at` and `decision` resolve to the larger `owner`; two `recovery` records with the same `at`
and the same posture resolve to the smaller `fp`. Every such comparison is on the field's text exactly as
stored (a `label` is its base64url string), byte by byte. Two documents are merged record by record
whatever their `seq` values; the result's `seq` is the larger of the two. An unknown key present in
both stays as the copy with the larger `seq` has it, and as the local copy has it when they are equal.
A vault record that forks (the same `seq`, another `hash`) keeps the local record and reports the
fork. A rolled-back served copy is merged the same way. At the caps the newest are kept (`verifiedAt`
for contacts, `removedAt` for tombstones), and among equals the smaller `userId`.
**A record that supersedes another is stamped later than it.** When a device writes a record meant to
replace one it holds (a new recovery choice, a contact verified again after it was removed, a tombstone
for a contact), it stamps it at `max(its clock, the held record's time + 1)`. Otherwise a device whose
clock runs behind would write a choice that loses the merge to the record it was meant to replace, and
turning operator recovery off would silently not stick.
A record that carries a field this build does not know is kept, with the field preserved as written. A
document that lacks one of the four maps is read as having that map empty; one whose `seq` is not an
`int` is refused whole. Tombstones are applied before the tombstone cap. When the document would not
fit, unknown keys go first (largest first), then the `vaults` and `accepted` records of vaults the
account has left (`decline`), oldest `at` first, then the smaller `vaultId`; `recovery` is never
dropped; a document that still does not fit is not written (`account_state_full`), and one whose `seq`
cannot be advanced is not written (`account_state_damaged`); the merged document is still read.

**Size.** An account holds **at most 1,000 contacts** (the app refuses a new one beyond that) and at
most 1,000 contact tombstones (the oldest dropped first). Each shared vault adds a `vaults` and an
`accepted` record (about 350 bytes), so the 500-membership limit needs about 175 KB; in all the largest
account the limits allow needs about 541 KB of the 786 KB of room. **Vault records are batched:** a
device writes a new vault's record at once, and later heads at most once every 10 minutes; a stale
record is still a valid lower bound for §10.4 (e).

`label` is a `name` (spec 01 §5.1), rendered only as plain text; `madeOn` is the device that made the
pin, shown in the per-device prompt (a hostile web bundle can forge it; the name the person
recognises is the real check). An unknown key in the document is preserved (it is dropped only when the merged document would not fit its
size cap, largest first, before any known record), so a newer
build's records survive an older merge. A client keeps a high-water mark of the in-blob `seq` (native:
in device state): a served document below it, or a withheld blob after one was seen, is a rollback,
merged so that nothing the local copy holds is lost. Vectors: `spec/test-vectors/accountstate.json`
(graded by core and the web twin; the extension grades the `vaults` rows).

**Contacts current on a device.** A contact syncs to every device, but a device acts on it (accepts
vaults from it, shares to it) only when it is **current** there: (a) this device processed or answered
the link; (b) it arrived in a device-link bundle with the same key hash (spec 03 §16.9); (c) the person
confirmed it on this device ("New person from your *iPhone*: *label* — Use on this device?", one tap,
which also exposes contacts a hostile web bundle wrote); or (d) on a device signed in with only the
password, the person confirmed the one-tap list ("People you've connected with", spec 05 R23). The
device keeps `pins.confirmed = {userId, keyHash}` durably in device state. A label is shown for a log
member or a grant sender only where that key equals the pinned key.

## 10. The vault log

Every **shared** vault has a log: an append-only, hash-chained list of signed entries (purpose 0x03,
spec 01 §5.1). A personal vault has none (§4). The server stores it and serves it (spec 03 §10); every
device verifies it.

### 10.1 Templates

Every entry starts with the same head, in this exact order, followed by the kind's fields and `}`:

```
{"v":2,"purpose":"vault-log","vaultId":<uuid>,"seq":<int>,"prev":<hex64>,"kind":<kind>,"actor":<uuid>,"at":<ms>
```

| `kind` | Extra fields, in order | Signed by |
|---|---|---|
| `genesis` | `"ownerKey":<b64_32>,"vkCommit":<hex64>` | the creator (`actor`) |
| `add` | `"member":<uuid>,"memberKey":<b64_32>,"role":<role>,"grantId":<b64_16>` | owner |
| `role` | `"member":<uuid>,"role":<role>` | owner |
| `remove` | `"member":<uuid>` | owner |
| `leave` | — | the member leaving (`actor`) |
| `offer` | `"to":<uuid>,"toKey":<b64_32>,"offerId":<b64_16>,"expiresAt":<ms>` | owner |
| `cancel` | `"offerId":<b64_16>` | owner or the offer's target |
| `accept` | `"offerId":<b64_16>` | the offer's target |
| `delete` | `"deleteId":<b64_16>` | owner |
| `restore` | `"deleteId":<b64_16>` | owner |

`at` is the signer's own clock, used only as §10.3 says. A signer sets `at = max(own clock, head.at)`.
Example genesis (one line, shown wrapped):

```
{"v":2,"purpose":"vault-log","vaultId":"…","seq":0,"prev":"000…000","kind":"genesis",
 "actor":"…","at":1763164800000,"ownerKey":"…43 chars…","vkCommit":"…64 hex…"}
```

### 10.2 Chain

- **Template rules:** a `genesis` has `seq = 0` and `prev` = 64 `0` characters, and every other kind
  has `seq >= 1`. A violation is `bad_statement`, at the parse.
- Every later entry has `seq = previous.seq + 1` and `prev = H(previous frame)` (spec 01 §5.1).
  Position is checked by `bad_seq` and `bad_prev` alone: a valid `genesis` frame placed later in a
  chain is `bad_seq`, and so is a first entry whose `seq` is not 0.
- `vaultId` is constant along the chain.
- The **head** is `(seq, H(frame))` of the last entry.

### 10.3 State, transitions and verdicts

Replaying entries 0..n yields a **vault state**:

```
S = { vaultId, head, owner, ownerKey, vkCommit,
      members: userId -> { key, role ∈ {owner, writer, reader} },
      pending: { offerId, to, toKey, expiresAt } | none,
      deleted: { deleteId } | none }
```

`genesis` sets `owner = actor`, `ownerKey`, `vkCommit`, `members = { actor: { ownerKey, owner } }`,
`pending = none` and `deleted = none`. Each later entry must satisfy **every** condition of its row,
checked against S before the entry; the first failure is the verdict.

| kind | Signer key must be | Preconditions | Effect |
|---|---|---|---|
| `genesis` | its own `ownerKey`, with `actor` the creator: it signs itself | first entry only (the template rules of §10.2) | sets up S, as above |
| `add` | `S.ownerKey`, with `actor = S.owner` | `deleted = none`; `member ∉ members` | `members[member] = {memberKey, role}` |
| `role` | `S.ownerKey`, with `actor = S.owner` | `deleted = none`; `member ∈ members`, `member ≠ owner` | role replaced; if `pending.to = member`, `pending = none` |
| `remove` | `S.ownerKey`, with `actor = S.owner` | `deleted = none`; `member ∈ members`, `member ≠ owner` | member deleted; if `pending.to = member`, `pending = none` |
| `leave` | `members[actor].key` | `actor ∈ members`, `actor ≠ owner`. Allowed **while the vault is deleted** | actor deleted; if `pending.to = actor`, `pending = none`. A member who leaves during the grace stays out if the vault is restored |
| `offer` | `S.ownerKey`, with `actor = S.owner` | `deleted = none`; `to ∈ members`, `to ≠ owner`; `toKey = members[to].key`; `at < expiresAt <= at + 14 d + 10 min`; `pending = none`, or `pending.expiresAt < at` | `pending = {offerId, to, toKey, expiresAt}` |
| `cancel` | `S.ownerKey` (actor owner), or `pending.toKey` (actor `pending.to`) | `pending ≠ none`; `offerId = pending.offerId` | `pending = none` |
| `accept` | `pending.toKey`, with `actor = pending.to` | `deleted = none`; `pending ≠ none`; `offerId = pending.offerId`; `at <= pending.expiresAt` | the old owner's role becomes `writer`; `owner = pending.to`, `ownerKey = pending.toKey`, the new owner's role is `owner`; `pending = none` |
| `delete` | `S.ownerKey`, with `actor = S.owner` | `deleted = none` | `deleted = {deleteId}`; `pending = none` |
| `restore` | `S.ownerKey`, with `actor = S.owner` | `deleted.deleteId = deleteId` | `deleted = none` |

**Time rules.**

- `at` never decreases along a log: every entry needs `at >= previous.at`, or it fails as
  `precondition`. So a device with a slow clock never deadlocks the vault.
- Before applying any entry whose `at > pending.expiresAt`, the verifier **clears the expired offer**
  (`pending = none`). So once the owner signs anything after the expiry, a late `accept` is impossible.
- `accept` additionally needs `at <= pending.expiresAt`; a target who backdates can only reach back to
  `head.at`, and the server refuses an accept after expiry by its own clock.
- The verifier is **clock-free**: every device reaches the same verdict on the same bytes. The ceiling
  on `at` (10 minutes ahead of the server's clock, `400 at_ahead`) is the server's check, outside the
  verifier (spec 03 §10.3). A hostile server can still store a far-future `at` and so freeze offers on
  that vault; that is denial of service (spec 05 R20).

All signer keys come from the log itself: `ownerKey` from genesis or the last `accept`, member keys
from `add`, the target key from `offer`. Verifying a log therefore needs no contact pins. Whether a
device *adopts* a vault is §10.4.

**Verdicts**, in check order:

1. `bad_frame`, `unknown_format`, `non_canonical`, `bad_statement` (the parse, spec 01 §5.1);
2. `wrong_vault`;
3. `bad_seq`;
4. `bad_prev`;
5. `not_authorized` (the signer key the row names is not the one in the frame, or `actor` is not the
   required account);
6. `bad_signature`;
7. `precondition` (a row condition failed);
8. `fork` (a different valid entry at a sequence number this device already saw).

Signer mismatches in the log are `not_authorized`, never `signer_not_pinned_key` (spec 01 §5.1).

**Undefined signer keys and expired offers.** Expired-offer clearing is applied to S **before** step 5.
At step 5, if the key the row names does not exist in S, the verdict is `precondition` and checking
stops: `accept`, or a `cancel` by the target, with `pending = none`; `leave` by an actor not in
`members`. So `accept` after expiry is always `precondition`. The shared implementation is core
`VaultLog.verify`, run by every client and by the server (spec 03 §10.3); vectors
`spec/test-vectors/vaultlog.json`.

### 10.4 Adopting a vault on a device

A device starts using a shared vault's key when **all** of these hold:

- (a) the log verifies (§10.5);
- (b) this account is in `S.members`;
- (c) the key passes the commitment (spec 01 §6.2);
- (d) one of:
  - this account is the genesis owner, the log has **no `add` of this account**, and the key comes from
    its own owner wrap (a genesis owner who left and was added again is asked like anyone else);
  - the key comes from this account's own self-wrap or owner wrap, which opens with the AD naming this
    log's genesis hash (spec 01 §6.1), **and** an `accepted` record with `decision = accept` answers this
    account's latest `add` (its `addSeq`, §9), so a server that replays an old self-wrap cannot make a
    device adopt a vault the person was re-added to without asking;
  - the key comes from a grant (spec 01 §6.3), **and** the `add` entry's actor is a contact that is
    **current on this device** (§9) with the same key, **and** the person accepted the vault (below);
- (e) the account's **vault record** (`vaults[vaultId]`, §9) agrees: the served log has the record's
  genesis hash, and it holds the record's hash at the record's `seq`. With **no record yet**, (e) holds
  and the device writes the record once the log verifies. A record never makes a log pass and is never
  lowered by what a server serves.

  When (e) alone fails, it fails in one of three ways, and they are told apart (decided on 23 November
  2026):
  - **Another beginning**: the record names another genesis hash than the served log, or the served log
    does not begin where the device's own verified log began. This is not the vault's chain: the device
    takes **no key**.
  - **Ahead**: the record is above the served head, and nothing the device holds contradicts the served
    log (the vault is **withheld**, §10.5). An honest restore of the server from an earlier day looks
    like this. The device **takes the key, and the vault is read-only** on it.
  - **Beside**: the served log carries another entry at a place after the genesis that the record or
    the device's own log knows (the vault is **frozen**, §10.5). The device **takes the key, and the
    vault is read-only** on it, for good.

  Read-only means every road that writes under the vault's key is refused, as for a frozen vault (below),
  and copying items out stays allowed. Whenever another of (a) to (d) fails, nothing is taken, whatever
  the record says. A wrong record written by a UVK holder makes every device of the account see that
  vault withheld or frozen, read-only, or refuse it (spec 05 R35).

**Accepting an incoming vault.** A vault reaching this account through a grant is **never adopted
unasked**, even from a current contact: "*Contact label* wants to share “*vault name*” with you"
[Accept] [Decline].

- The vault name is decrypted only after (a)–(c) pass, and shown as plain text.
- The answer is recorded once per account in account state, as `accepted[vaultId] = {owner, addSeq, at,
  decision}` (§9), so the account's other devices do not ask again. Reading it is one pure function:
  an `accepted` record against the account's latest `add` seq gives `accept`, `decline` or `ask`
  (vectors in `accountstate.json`; the Chrome and Firefox extension reads `decision` only, spec 01
  §6.5). `addSeq` is the `seq` of the `add`
  the person answered. **A record answers only that `add`**: after a `leave` or `remove`, a new `add`
  has a higher `seq`, so the person is asked again.
- **Decline** hides the vault on every device of the account **and signs a `leave`** (the account is a
  member once added), so the owner sees the decline and the server revokes the grant.
- The server refuses an `add` unless the owner and the new member are connected (spec 03 §10.3,
  `409 not_connected`): hygiene against strangers pushing vaults on an honest server; the accept prompt
  is the control against a hostile one.

**Otherwise** (the `add`'s actor is not a current contact with that key) the vault is listed as "*Name
as the server reports it* wants to share a vault with you. Connect with them first." Its name is not
shown and nothing is decrypted.

**Left out of AutoFill.** In an app that runs the rebuilt engine, a vault not yet accepted, frozen, failed or withheld is never written into the iOS
AutoFill snapshot (which the Safari extension also reads), nor offered by an app's filling in; a vault that later
freezes or is withheld is removed at the next refresh. A withheld vault is read (§10.4 (e)), never filled from.
This rule is not claimed for the iPhone app until that app runs the engine.
The Chrome and Firefox extension applies its own acceptance check (spec 01 §6.5).

**A frozen, failed or withheld vault** (§10.5) is read-only on every path that writes under its key: item saves
and edits, restore from trash, moving items in or out, copying items in, draining the iOS save queue
into it, renames, and every log entry except `leave`. **Copying items out stays allowed** (it writes
only under the destination's key); the copy dialog says "Items in this vault may have been changed by
someone the server let in. Check what you copy."

**After adoption.** A device that adopted a key from a grant posts its self-wrap (spec 03 §11.4), after
which the account's other devices adopt through the wrap. Once a device has adopted a vault, later
entries are judged by §10.3 alone, and the device keeps the account's vault record current.

### 10.5 Client verification

A device keeps, per shared vault, durably in device state (outliving the offline cache): the verified
head; the derived state S; and the hash of every sequence number it has seen.

On each sync where the vault row's `logHead` differs from the verified head, it fetches the log from
`after = verified.seq` (spec 03 §10.6; a fresh device starts with no `after`) and verifies each entry in
order (§10.3). It fetches the log again from the genesis, and verifies it from there against every hash
it holds (the account's vault record and a checkpoint included), where the served head is at or below
the verified head and names another hash than the one held for that sequence number, or where the first
entry served parses and sits at `verified.seq + 1` but does not name the verified head as its `prev`.
If that fetch does not come back whole (no answer, or a refusal), the vault is **failed** and its
verified state stays as it was. Otherwise the replay's first refused entry decides: one valid in every
other respect, at a sequence number where the device holds another hash, is a **fork**; any other is a
**failure**; and a replay that refuses nothing but ends below the highest sequence number held, or
beyond the served head, is **withholding**; a read again from the genesis that serves no entry at all
changes nothing: the vault keeps its verified state and its standing. Where the replay accepted any
entry, the verified state then stands at the last one, which can be below the old head.

- **A failure** leaves the verified state at the last good entry. The device raises "This shared
  vault's history doesn't check out — the server may be misbehaving." It keeps reading data already
  decrypted under a committed key, and refuses writes to the vault until the log verifies again
  (**failed**).
- **A served head below the verified head**, below the account's vault record (§9), or a log missing
  entries this device verified, is **withholding**: the device keeps its own state, the vault is
  read-only, and the device shows "The server is showing an older version of this vault's history." It
  is checked again at every sync, also when the served head equals the device's own.
- **A different entry at a sequence number already seen** is a **fork** (equivocation): the device
  **freezes** the vault (read-only) and shows the anomaly. A fork needs two validly signed entries at one
  position; an item's `logHead` (§3) is only ever a hint to fetch.
- **Checkpoints** carried by a device link (spec 03 §16.9), and the account's vault records (§9), are
  verified heads too. Comparing a served log (or card chain, spec 01 §5.2) with a held head is **one
  pure function**, shared by core and the web twin, that returns `ok`, `withheld` (the served chain
  ends below the head) or `fork` (another hash at the head's `seq`); vectors in `vaultlog.json` and
  `instancecard.json`.
- **Member lists.** A member's label is shown only where the log's member key equals that person's
  pinned key; otherwise "unverified member (as the server names them)". The list is the audience as far
  as this device has verified the log; a withheld later `add` is not shown (spec 05 R20).

### 10.6 Removal, deletion and purge on the device

- **Removal and leave.** A removal is attributed when the device verifies the `remove` (or its own
  `leave`) entry; otherwise it is shown as unverified. The vault's local data moves to the **holding
  area** for 30 days, where items can still be copied out; in the Android and desktop apps, while the
  person is added again and the device shows an invitation to that vault they can answer, the copy
  does not open until they accept (decided on 22 and 23 November 2026), and it still goes on its day.
  In the web client and in the Android and desktop apps (decided on 24 November 2026): when the person
  is added again and accepts, the held copy's items are put back, except an item the device already
  holds a served row of (readable or not) and an item whose deletion the server served while the copy
  was held, in that answer or an earlier one; such a deletion is recorded with the held copy, so it
  holds across a reload or a lock in the browser, a restart of the app and a resync, until a live row
  of the item is served, and it goes with the copy. A deletion row carries no signature, so it never removes an item
  from the held copy itself: until the vault is put back, the person removes the copy, or its 30 days
  end, the copy keeps every item, and a person who declines keeps them all.
- **Delete and restore.** A `delete` keeps every member in the log and keeps their fetch access; a
  `restore` re-grants them (spec 03 §10.6, §11.1).
- **Purge versus withholding.** A device shows "deleted for good" only after it has fetched and
  verified the log through the tombstone's `finalHead`, and the verified state is **deleted** by the
  owner's signed `delete` with no later `restore`. The server alone cannot fake the owner's `delete`;
  it can withhold a later `restore` and purge anyway, which is why the device's copy goes to the
  holding area rather than being dropped. Everything else is **withholding**: a tombstone whose log does
  not verify, does not end deleted, or ends below this device's verified head; and a vault that
  vanishes without a tombstone, including one whose tombstone year has passed.
- **The device's own copy.** On a verified purge the vault's local data moves to the holding area and
  stays there for 30 days from the moment this device verified it, or until the person removes it;
  never straight to deletion, and never dropped at a time the server names, the owner's own deletion
  included (design 2026-11-15 §3.8). On withholding the copy stays, read-only, with copy-out and "Remove from this device" (a
  local action that tells the server nothing). So the server can never make a device drop its offline
  copy by claiming a purge or by revoking a grant.

### 10.7 A member deleted by the operator

An operator deletion has no leaves (spec 03 §7.1): the deleted account stays in the log's `members`
with no grant. Members' apps show "*name*'s account was deleted by the server's operator." The owner's
app offers a one-tap **Remove from the list**, which signs an ordinary `remove`. Until then nothing
breaks: the server serves the deleted account nothing.

### 10.8 What removal does not do

No step rotates a vault's key (P6, spec 05 R7). A removed member who kept the key, working with the
server, can still read every later item, and can also **write**: items carry no author signature, and a
hostile server accepts writes it should refuse. The remove dialog says so:

> Removing someone stops the server from giving them this vault. It doesn't change the vault's key: if
> they kept a copy and the server helps them, they could still read and change what's in it. To be
> sure, move everything to a new vault.

**Move everything to a new vault** is offered there. It creates a new vault, copies the items through
the existing move path (fresh item ids and attachment keys), re-adds the remaining members, and
deletes the old vault. While both vaults exist it needs free storage equal to the old vault's size; the
app checks first and says so when the owner is short (spec 03 §14.4). The old vault is deleted last, and
only once the server stored every add, every copy was made and nothing in it changed meanwhile; a stopped
move says where it stopped. **From the moment the old vault's deletion is signed** until the server is
known to have stored it, the old vault is closed for writing on the device: every way into it (a new
item, an edit, a delete, a restore, a delete for good, an import, a file, a rename, a move or a copy
into it, a move out of it) is refused before anything is sealed, and copying out still works, so that
nothing new is put where it may vanish. The whole set of rules, in the order a person meets them, is design
2026-11-15 §3.13. **On a frozen or failed vault** it still works,
as the way out: it copies the items out and leaves the old vault frozen, signs nothing on that log, and
re-adds **only the members the owner ticks, none ticked by default** (the last verified state may
predate a `remove` this device never saw).
