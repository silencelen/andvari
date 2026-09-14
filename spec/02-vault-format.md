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
    "passwordHistory": [ { "password": "…", "retiredAt": 1751700000000 } ]  // ONE writer: the Health differs resolution (below)
  },
  "attachments": [                       // mirrors attachmentIds; holds the SECRET half
    { "id": "uuid", "name": "scan.pdf", "size": 12345, "fileKey": "base64url(32B)" }
  ]
}
```

**`login.passwordHistory` — one writer (amendment 2026-08-18); otherwise reserved.** The
shape above is fixed (so the field could be adopted without a formatVersion bump) and every
client **preserves it verbatim on rewrite**, entry-level unknown fields included (the
preservation rules below). Exactly **one path appends entries**: the Health duplicate
checker's differs resolution ("Keep this one", `planKeep` — on web and Android since 0.26.0,
via the core/web twins) — when the user retires
duplicate copies, each distinct losing password is appended to the survivor as
`{password, retiredAt}` so the retired secrets outlive the losers' 30-day Trash window. No
editor, importer, ordinary save path, or conflict materializer on any client writes an
entry, and no client displays the field. A reader MUST therefore still treat an
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
  string. An unparseable / empty saved URI never matches. Staleness: a suffix the snapshot
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

## 4. Vaults

```
Vault { id uuid, type "personal"|"shared", rev, createdAt, metaBlob base64url }
```
`metaBlob` = envelope under VK with AD `andvari/v1|vaultmeta|{vaultId}`, plaintext
`{"name":"Family","icon":"…","metaV":N}` — vault display names are ciphertext; the server
knows vaults only as ids. `metaBlob` is **owner-rewritable** (rename, spec 03 §11) under the
same VK/AD; its plaintext carries a monotonic `metaV` counter (clients warn-and-keep-newer
when a delivered metaBlob's counter regresses); the AD deliberately excludes `rev`. Grants
(per member): `{ vaultId, userId, role "owner"|"writer"|"reader", rev, revokedAt,
revokedReason, wrappedVk XOR sealedVk }` per spec 01 §6 — normally exactly one of
`wrappedVk` (owner/personal, under UVK) or `sealedVk` (member, `crypto_box_seal` to the
member identityPub) is set; the other is empty (a post-transfer owner grant MAY carry both).
`revokedReason ∈ member_remove|member_leave|vault_delete` (NULL, pre-v4, reads as
`member_remove`); vault RESTORE resurrects only `vault_delete` revocations made at the
matching `deletedAt`. Vault rows also carry lifecycle state:
`deletedAt/purgeAt/purgedAt/deletedBy/deleteId/deleteProof/restoreProof` (soft-delete +
grace + purge — vault rows are NEVER hard-deleted; `vaultId` is never recycled, normative)
and `transferSeq/pendingOwnerId/pendingOfferId/pendingOfferProof/pendingOfferExpiresAt/
pendingOfferSetAt/lastTransferOfferId/lastTransferAcceptProof`. Roles are
**server-enforced only** (crypto cannot stop a reader who has VK from encrypting; the
server rejects writes without writer role). Membership (which userId holds which role on
which vaultId) is server-visible via the grants row; membership-management audit events
record only ids and roles, never names or decrypted content.

**`type` is a SERVER label, and it MUST NOT choose the personal vault on its own (2026-09-13
amendment, audit H64).** `type` is plaintext in the vault row and is bound into no AD — the
vaultMeta AD is `andvari/v1|vaultmeta|{vaultId}` and nothing else — so after enrollment nothing a
client holds authenticates WHICH vault is its own: `personalVaultId` is rebuilt on every unlock
from the first row the server labels `personal` whose key that client happens to hold. A client
MUST therefore **refuse to adopt as its personal vault any vault whose VK arrived by MEMBER grant
(`sealedVk`)**, whatever the server calls it. The asymmetry is the whole argument: a `sealedVk` is
ANONYMOUS — anyone holding the member's public identity key can mint one — and the key inside it
is by construction one that at least one other person already has; a `wrappedVk` opens only under
that member's own UVK with AD `andvari/v1|vk|{vaultId}|{userId}`, which is unforgeable evidence
that the client itself sealed that key for itself. A personal vault is always wrapped (minted
locally at enrollment, re-wrapped and never re-sealed at password change), so the refusal costs an
honest account nothing. Fail-closed: when every held candidate is member-granted the client keeps
NO personal vault — §8.2's ledger then degrades to "—" (never an error) and a save with no
explicit destination fails loudly rather than filing the user's item into somebody else's shared
vault. Without the rule, a hostile server that withheld the real personal row and relabelled a
shared vault would have moved the §8.2 usage key onto a VK every other member of that vault holds.

> **Known residue, and why it is deferred rather than papered over.** This rule cannot tell an
> OWNER-CREATED SHARED vault from a personal one — that grant is `wrappedVk` too. Closing the gap
> means putting `"type":"personal"` inside the AUTHENTICATED vaultMeta plaintext at enrollment,
> preferring that over the server row, and having owners rewrite legacy personal meta once on a
> later unlock (`metaV` bump, unknown fields preserved, per the rename rule above). That is a wire
> change to the meta plaintext and is **DEFERRED to a spec revision**; until it lands, `type`
> stays a server-asserted hint everywhere it appears, and the refusal above is what stands between
> that hint and the usage key.

## 5. Server-visible plaintext — the zero-knowledge contract

The server stores/sees EXACTLY this and nothing more; the hardening gate audits
against this table. Anything not listed here appearing server-side in plaintext is a
spec violation.

| Surface | Fields |
|---|---|
| users | userId, email, displayName, kdfSalt, kdfParams, verifier(argon2id str), **wrappedUvk** (UVK ciphertext under the master key — opaque to the server, stored so a fresh device can unlock), identityPub, **encryptedIdentitySeed** (identity-seed ciphertext under the UVK — same story), isAdmin, status, mustChangePassword, **recoveryConfirmed** (boolean flag, plaintext metadata — the durable, cross-device capture-confirmation signal, design §F.9; not a secret; 0 until the user confirms saving their recovery phrase), **escrowPolicy** ('required'\|'waived'\|NULL pre-v8 — the member's enforced recovery posture, persisted from the invite at register; plaintext metadata for admin reconciliation, design §F.4), createdAt, server-TOTP columns (totpSecret, totpPendingSecret, totpEnrolledAt, totpLastStep — a server-side authenticator secret by design, never vault data; spec 03 §2) |
| invites | tokenHash, **invitee email in plaintext** (a person who may not have an account yet — accepted: invites are short-lived and admin-created), isAdmin, createdAt, expiresAt, usedAt, **escrowPolicy** ('required'\|'waived' — the admin's per-invite recovery posture, plaintext metadata; read server-side at register, design §F.4) |
| devices | deviceId, userId, platform, **name (user-chosen device label, plaintext)**, clientVersion, createdAt, lastSeenAt, revokedAt |
| sessions | sessionId, userId, deviceId, hashed access+refresh tokens, access/refresh expiries, refreshConsumedAt, createdAt, revokedAt |
| vaults | vaultId, type, rev, createdAt (names/icons are ciphertext); **lifecycle** — deletedAt/purgeAt/purgedAt/deletedBy/deleteId, transferSeq, pendingOwnerId/pendingOfferId/pendingOfferExpiresAt/pendingOfferSetAt/lastTransferOfferId (ids + epoch times), and opaque VK-derived MACs deleteProof/restoreProof/pendingOfferProof/lastTransferAcceptProof (PRF outputs — reveal nothing about VK) |
| grants | vaultId, userId, role, addedAt (join time, epoch ms; NULL on pre-v3 rows, COALESCEd to 0 in summaries), wrapped/sealed VK ciphertext, rev, revokedAt, revokedReason (revoked rows are retained — the server sees WHEN and WHY a member lost access: remove / leave / vault-delete), and removeProof/removeNonce (opaque VK-derived MAC + nonce, stored on a removal for durable relay to the victim — reveal nothing about VK) |
| items | the Item row of §1 — ids, rev, server timestamps, flags, formatVersion, attachmentIds, ciphertext blob, ciphertext byte size |
| item_versions | itemId, rev, blob, formatVersion, archivedAt (bounded to the newest 10 per item, §7) |
| changes | rev, kind, entityId, vaultId, at — the global sync feed (pure metadata; reveals per-vault write timing/volume) |
| mutations | (deviceId, mutationId) → resultJson, createdAt — idempotency replay cache; resultJson holds per-mutation status/rev, no vault content |
| attachments | attachmentId, itemId, vaultId, ciphertext size, sha256(ciphertext), header, createdAt (filenames + file keys are inside item ciphertext) |
| escrow | userId, sealed blob, fingerprint (of the recovery key), updatedAt |
| usage_ledger | userId, **sealedUsage** (the per-user "last used" map sealed under the VK(personal)-derived usageKey (§2/§8.2) — ciphertext, opaque; AD `andvari/v1\|usage\|{userId}`, §2), updatedAt — the staleness-ranking input (§8.2). ONE aggregate blob by design, never per-item rows: the server sees THAT a user's ledger changed and its size, never WHICH login |
| member_recovery | userId, **recoveryWrappedUvk** (the UVK sealed under the member's recovery-secret-derived wrap key — ciphertext, opaque; AD `andvari/v1\|recovery-uvk\|{userId}`, §2), **recoveryVerifier** (one-way `crypto_pwhash_str(recoveryAuthKey)` — a DB leak is not a replayable recovery, exactly as the login verifier), **pieceId** (opaque random id of the current piece — rotation/confirm binding, spec 03 §12; not a secret), **setupDeviceId** (which device committed it — legacy-confirm scoping), updatedAt — the per-member self-service recovery row (spec 04 §per-member / design §F); ZK-clean, the symmetric counterpart to `escrow` |
| audit | event type, userId, deviceId, ip, timestamp, coarse metadata (never names, URIs, emails of existing users, or any decrypted content) |
| policies | org policy JSON (min versions, KDF policy, lock timeouts…) |
| hibp_cache | sha1-prefix → upstream HIBP range body + fetchedAt (public breach data, no user linkage stored) |
| meta | key/value operational markers (schemaVersion, lastPublicRequestAt…) |

Traffic analysis (who syncs when, item counts, sizes) is visible to the server by
nature and accepted (spec 05). This table describes **schema v9 exactly** — adding any
table or plaintext column requires updating it in the same change. (v6 = design 2026-07-12
§F: the `member_recovery` table + the `invites.escrowPolicy` column. v7 = design 2026-07-12
§F.9: the `users.recoveryConfirmed` capture-confirmation flag. v8 = design 2026-07-13:
`users.escrowPolicy` (admin posture reconciliation) + `member_recovery.pieceId`/`setupDeviceId`
(confirm piece-binding). v9 = design 2026-08-22: the `usage_ledger` table.)

## 6. Attachments

- Per-file random 32-byte `fileKey` (lives inside item ciphertext, §3).
- Content encrypted with `crypto_secretstream_xchacha20poly1305`, plaintext chunked
  at **64 KiB** (last chunk 1..65536 bytes, tag FINAL; all others tag MESSAGE).
  Stored as `header (24B)` + ordered ciphertext chunks (each chunk + 17-byte ABYTES);
  the server persists header and chunks and never sees content or filename.
- Decrypters MUST fail hard on: any chunk MAC failure, FINAL before last chunk,
  missing FINAL at end (truncation), or extra data after FINAL.
- Upload: blob first (`POST /attachments/{id}`), then the item update referencing it;
  orphaned blobs are GC'd after 24 h. Server enforces per-item and per-user quota
  from policy (v1 defaults: 25 MiB/attachment, 100 MiB/item, 1 GiB/user).

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

**Vault deletion (spec 03 §11):** a soft-delete with a 7-day grace
(`ANDVARI_VAULT_GRACE_DAYS`) — all rows stay intact and every grant is revoked
(`revokedReason='vault_delete'`); RESTORE within grace un-revokes exactly those grants and
re-opens the vault. After the grace the daily **janitor** purges (per-vault tx that
re-checks `deletedAt/purgeAt` inside every destructive statement): `item_versions` and
attachment rows/files are deleted, item rows are reduced to ciphertext-free
**skeletal tombstones** (`deleted=1, blob=NULL`, no rev bump, `updatedAt` restamped to the
purge instant — they keep the `vault_mismatch` teleport fence alive, 0.2.x MSI included,
for the full 30-day tombstone horizon from purge, then age out with the ordinary tombstone
GC below; the edit-over-tombstone fence is grant-gated and never reads them post-purge),
`metaBlob` is blanked, and **every** grant's key material is wiped
(`wrappedVk=''` — the `NOT NULL` sentinel — and `sealedVk=NULL`, active and
previously-revoked alike). Vault tombstone rows and all grant rows are retained
indefinitely and `vaultId` is never recycled — that pair is what keeps a push against the
purged vault itself denied forever. Skeletal item rows are **not** retained indefinitely:
by the time one ages out, every cursor is vault-absent by one of two legs — (1) a cursor
predating the DELETE has sat behind the `oldestRetainedRev` fence for at least the full
grace window (410 → full resync → vault absent); (2) a cursor minted DURING the grace
window was minted by a pull that already delivered the revoked grant (`removedGrantsInfo`,
the `g.rev > since` arm), so the vault is absent locally by delivery — such a cursor may
never 410 at all on an idle server (the MAX(rev) fence floor + strict `since < fence`).
Either way a post-horizon teleport re-push degrades into the accepted re-add class (a clean INSERT
of the pusher's own re-encrypted copy into their own vault; pinned in `JanitorTest`, same
class as the >180d mutation replay). The janitor's v1 scope was **vault purge
+ transfer-offer expiry ONLY** — the general retention machinery had to stay dormant until
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
  normal push.

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
- grant rows (vaultId, userId, role, `wrappedVk`/`sealedVk` ciphertext, rev);
- vault rows (vaultId, type, rev, `metaBlob` ciphertext, createdAt);
- the outbound mutation queue (mutationId, op, ids, baseItemRev, `ItemUpload`
  ciphertext);
- for offline unlock, a copy of the server's `accountKeys` payload (kdfSalt,
  kdfParams, wrappedUvk, encryptedIdentitySeed, identityPub, escrowFingerprint).

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
the `lastSyncAt` stamp, the spec 03 §4 lifecycle safety state — holding area,
consumed delete-ids, verified transfer floors — and the last-known policy bits) in a
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
  `andvari/v1|usage|{userId}` (§2) — domain-separated from that VK's own AEAD use exactly as the
  lifecycle key is (spec 03 §11), and the AD still binds the blob to the user's slot so a hostile
  endpoint cannot serve one member's ledger into another's.
  **Keyed from the personal VK rather than the UVK for a CLIENT reason, recorded so it is not
  "simplified" back:** the browser extension's UVK is memory-only and never persisted (spec 01
  breaker B1), and an evicted MV3 service worker restores a session holding `vaultKeys` but no
  UVK — so a UVK-bound ledger was unwritable from the client that does most of the filling.
  Every unlocked client holds the personal VK in every session. No vault key is persisted either
  (§8 MUST NOT list, unchanged), so the ledger is still readable only in memory after an unlock,
  and the server and a stolen locked device both hold opaque bytes. Spec 05 T3 is unchanged.
  An account with no personal vault simply has no ledger — clients MUST degrade to "—", not error.
  **WHICH vault that is comes from §4's rule, never from the server's label alone (2026-09-13
  amendment, audit H64):** a client MUST NOT key the ledger from a vault whose VK arrived by
  member grant (`sealedVk`), because that VK is held by every other member of the vault and
  `andvari/v1|usage|{userId}` is public — a relabelled shared vault would hand a colluding
  co-member the itemId → {lastUsedAt, useCount} log this whole single-blob design exists to keep
  private. A held-but-refused candidate leaves the account with no personal vault, which is the
  "—" degradation above and not an error.
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
