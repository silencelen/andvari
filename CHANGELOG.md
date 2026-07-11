# andvari — changelog

## 0.11.1 — trash tucks behind icons + layout tidy-up (2026-07-10, cross-platform cut)

Your dev-note pair: trash re-surfacing now, and a full layout review whose bigger proposals
are written up for you to pick from (docs/design/2026-07-10-ia-regroup.md, Tier 2).

- **Web: Trash left the main menu.** It's now a small trash icon on the vault toolbar, next
  to Import/Export — one less top-level nav item. The Trash view itself is unchanged.
- **Web + Android: recently-deleted vaults live behind a trash icon on Sharing** instead of
  always rendering under the vault list (on Android the rarely-needed "recently removed"
  holding area tucks behind the same icon — one icon, both vault-recovery lists).
- **Names untangled:** the deleted-items view is now titled "Trash" everywhere (it shared
  the name "Recently deleted" with the vaults section on Sharing — two different things,
  one label); the Sharing section is now "Recently deleted vaults".
- **Two real bugs from the layout audit:** a notice pointed web users to "Settings →
  Recently removed", a section that doesn't exist (copy fixed); and on Android, a Trash
  screen left open when the autofill gate locked the session underneath didn't kick to the
  lock screen like every other view (it does now).
- **Android finally has an app icon:** the brand rune in the house gold on the app's own
  dark brown-black — the exact wordmark geometry and colors the web app uses, as an
  adaptive icon (with a themed/monochrome variant for Android 13+ icon theming).

## 0.11.0 — vault settings get their own place (2026-07-10, cross-platform cut)

Your dev-note, delivered: vault management no longer stacks every vault's controls under the
vault list. On the **web app** and on **Android**, each shared vault row now has a **Settings**
button that opens that vault's own settings view — rename, members (web), ownership transfer,
leave, and the delete flow all live there, with a "‹ Back to vaults" header and the platform's
Back button closing the settings first. The list itself stays clean: create-vault, recently
deleted, and incoming ownership offers remain on the list (offers stay visible even while a
settings view is open). Personal vaults have no settings button — they have no vault-level
operations.

Nothing about the flows themselves changed: the type-the-vault-name delete confirm, the
copy-items-to-Personal-first rescue, ownership-transfer consent, and member verification are
the same screens, relocated. Two genuine improvements rode along: a rescue copy now keeps
reporting its progress even if you leave and reopen the settings view mid-copy (and the
delete button stays locked until that copy finishes), and on Android a copy's progress note
now names which vault it belongs to.

Desktop is unchanged in this cut — it has no vault-management screens yet (that's a separate,
larger item on the roadmap), and it simply re-reports the new version.

## 0.10.2 — the enrollment ceremony gets real on phone and desktop (2026-07-10, cross-platform cut)

Security hardening of first-time enrollment, bringing both native apps up to the web app's
ceremony ahead of family onboarding. Existing accounts are untouched — this only changes the
"Create vault" screen.

- **You now TYPE the recovery fingerprint instead of ticking a box.** Phone and desktop
  enrollment used to display the fingerprint next to a checkbox — nothing forced an actual
  comparison with the printed sheet, which is the one check a compromised server can't fake.
  Both now ask you to type the sheet's first 16 characters before the fingerprint is shown or
  the confirmation can be ticked — exactly how the web app (and the re-seal prompt) already
  work. Separators and case don't matter; a mismatch says STOP in plain words.
- **The master-password bar on natives now matches the web app.** Phone and desktop accepted
  any 8+ characters ("password1"); all clients now require the same strength floor, with a
  live strength label and honest too-weak message while you type.
- Under the hood, the enroll submit rule is now ONE shared, tested core function across both
  native apps, so the platforms can never quietly drift apart on these checks again.

## 0.10.1 — import crash fix + import robustness (2026-07-10, cross-platform cut)

Phone and desktop pick up everything below with this cut; the web app and server have been
serving the shared parts since their per-cycle deploys and re-report 0.10.1. Separately, the
web app gained **one-scan family onboarding** today (Admin → Invite a user → "Invite with QR"
mints a 60-minute invite QR/link that lands a new member on a prefilled web enrollment) — a
web/server feature with nothing for the natives to pick up. Card creation stays dark on every
client (Option A) until the 0.2.x desktop MSI is retired.

### the import "Choose file" crash is fixed (Android)

- **Tapping "Choose file" to import no longer crashes the app.** The file picker launched
  through a code path that a stale support-library version rejected on some devices
  (`IllegalArgumentException: Can only use lower 16 bits for requestCode`, from the biometric
  library dragging in a years-old `androidx.fragment`); the app now pins a current fragment
  version aligned with the rest of AndroidX, so the picker opens normally. This affected the
  release build specifically — thank you for the crash report.

### import flow, from the same pass

- **"My file is from somewhere else" now lives on the main import list** and opens the file
  picker straight away for any CSV, instead of hiding inside each source's steps and only
  bouncing you back to the list. Header detection is authoritative, so a file from an unlisted
  source still imports as whatever it actually is. Choosing a specific source now shows a
  plain "← Choose a different source" back option.
- **A broken export can no longer freeze the app** (all clients). A file with thousands of
  unreadable rows used to render every problem row at once in the confirm dialog — a
  multi-second hang that looked like a crash. The dialog now shows the first few problem rows
  plus an honest count, and every expandable list in that dialog gained the same ceiling.
- **Oversized files get their honest message again**: a file over 10 MiB now says exactly
  that, instead of a generic "could not read the selected file". And the import pre-check now
  runs inside the same error net as the parse, closing a latent crash path if the vault locks
  mid-import.

### choose where imports land (S2)

- **Imports can now target any vault you can write to.** The import confirm step gains a
  destination picker (shown only when you actually have a choice; readers' vaults are never
  offered). Changing the destination re-checks the file against *that* vault, so the
  "already in your vault" dedupe is honest per destination, and the final summary names the
  vault the rows landed in. Once an import attempt starts — including a failed partial one —
  the destination and file are locked so Retry stays an exact, duplicate-free replay. The
  parsed file (which holds every password in it) is now wiped on lock and sign-out, and an
  import whose destination vault was deleted mid-flight tells you to KEEP the CSV instead of
  falsely reporting success.

## 0.10.0 — smarter matching + vault choice + save integrity (2026-07-10, cross-platform release)

Everything below ships together to phone and desktop with this cut; the web app and browser
extension (0.8.1) have been serving the same features since their per-cycle deploys. This cut
closes the spec 02 §3.1 conformance window — every current client now carries the eTLD+1
matching rules. Card creation stays dark on every client (Option A) until the 0.2.x desktop
MSI is retired.

### web polish + desktop save integrity (cycle 7)

- **Big vaults stay fast.** Past 500 items the web vault list now renders only the rows in
  view (a windowed list with no inner scrollbar — scrolling feels identical), so a
  10,000-item vault costs ~200 DOM nodes instead of ~70,000 rebuilt on every keystroke.
  Smaller vaults render exactly as before.
- **A failed desktop save can no longer lose your edits.** The editor stays open — fields,
  attachments, and error in place — until the save actually succeeds; Cancel is disabled
  while a save is in flight; upload progress shows per attachment. **Retrying after a
  partial failure now works**: an attachment the first attempt already uploaded is
  recognized instead of wedging every retry with a cryptic server error (new items keep
  their draft identity across retries for the same reason). Attachment saves to disk go
  through the same write-then-verify-then-move discipline exports use, and every desktop
  save dialog now asks before overwriting an existing file.
- **Consistency pass across the web app**: one shared view header, keyboard-reachable
  Health rows, inline-SVG sigils (no more font-dependent runes), your email in the app bar
  instead of a raw account id, carded boot screen, and inert rows no longer pretend to be
  clickable. Vault-list rows clip gracefully at large accessibility font sizes.
- Under the hood: the two native export planners (which had already drifted apart) are now
  one shared implementation, and the natives read export data through the sync engine's
  own read surface instead of carrying a private cache reference.

### smarter site matching — eTLD+1 / Public Suffix List (extension 0.8.1 + web; natives ride the next cut)

- **Logins now match the whole site, not just the exact host you saved.** A login saved at
  `login.example.co.uk` fills on `example.co.uk` and `accounts.example.co.uk` — registrable-domain
  (eTLD+1) matching against a vendored Public Suffix List snapshot, the same base-domain behavior
  as Bitwarden/1Password. Two things deliberately got *stricter* at the same time: a saved bare
  public suffix (`github.io`, `co.uk`) no longer fills every site under it, and a match is refused
  whenever the two sides' registrable domains are positively known and **different** — so
  `foo.github.io` can never fill `bar.github.io`, and a saved `compute.amazonaws.com` no longer
  fills every EC2 tenant host. Home-network names (`nas.local`, `pihole.lan`) are untouched: when
  the list doesn't know a domain's TLD, matching stays exactly as before. (One honest caveat,
  same as Bitwarden/1Password: a multi-tenant hosting provider missing from the list's private
  section matches across its tenants until a list refresh — spec 02 §3.1 records it.)
  Snapshot dated 2026-07-09 (10,230 rules, ICANN + private
  sections; refresh procedure in `spec/psl/README.md`); the fill decision never leaves the device.
  Design breaker-passed (1 fatal / 8 serious found *before* build and amended, A1–A12); 40 new
  shared vectors run on all three implementations — including, for the first time, natively in the
  extension — and the 25 original matching vectors are byte-frozen and keep their exact outcomes.
  Web and extension (0.8.1) carry the new rules now; Android/desktop follow at the next native cut
  (spec 02 §3.1 conformance note records the window).

### browser extension 0.8.0 — update-available signal

- **The extension now tells you when a newer build is published.** An unpacked browser extension
  can't update itself, so it checks the published `/downloads/manifest.json` about once a day (and
  on browser start), and when a newer version is out it shows a calm banner in the popup —
  "Update available — andvari X" with a "Download & reload" link to the right zip for your browser.
  No silent reinstall (the browser forbids it for unpacked extensions), no toolbar-badge takeover
  (that badge still shows how many logins match the current site). The check reads only the public
  download manifest — never the vault, never your session, and it works whether locked or not. The
  web app's Devices page now spells out the same self-update posture. *(Extension bumped 0.7.0 →
  0.8.0; the version-compare fails closed on any malformed manifest so a garbled file can't nag.)*

### skipti loose ends (F18, F19 parity, F20, LC-1)

- **Choose the vault when you create an item (F18).** Android and desktop new-item editors now
  offer a vault picker instead of silently filing everything in Personal. Only vaults you can
  write to are offered, and the picker appears only for a genuinely new item with more than one
  choice. Items now carry a vault-name tag in the list and on the detail view. Editing an existing
  item can never move it — core resolves the vault as `existing ?: picked ?: personal`.
- **Move and Copy on desktop (F19 parity).** The same safe gesture the web and Android clients
  use: the copy is created and confirmed in the destination *before* anything is deleted, so a
  failed move never loses the item. A retry reuses the gesture only while the source is unchanged;
  a permission failure ends it rather than blindly replaying.
- **See who else is in a shared vault (F20).** Any member — not just the owner — can now view the
  vault's roster, read-only. You get a calm "you were added to <vault>" notice when someone shares
  a vault with you (never on a first sync of a new device, never for a vault you own or restored),
  and a shared vault this device cannot open now says so plainly instead of silently vanishing.
- **A re-delete during restore no longer eats a parked edit (LC-1).** If a shared vault was
  deleted, restored, and deleted again while you had an unsent offline edit, that edit could be
  dropped. Denials are now staged and judged against the vault's actual state after a fresh sync
  rather than against how the write arrived, so a held vault re-parks the edit instead of
  discarding it.

## 0.9.0 — quick unlock + native robustness (2026-07-10, cross-platform release)

Biometric unlock on Android, plus the two quick-win batches that make the daily-driver clients
behave. Additive: no wire change, no schema change; the fielded 0.8.0 fleet keeps working, and
the web client is unchanged except its version string. Card creation stays dark on every client
(Option A) until the 0.2.x desktop MSI is retired.

- **Quick unlock (F84).** Android can unlock the vault with a fingerprint instead of the master
  password. The account's UVK — never the password, never a derived key — is wrapped under a
  non-exportable, auth-per-use, strong-biometric-gated AES-256-GCM key in the Android Keystore
  (StrongBox where available), bound to the account so a copied blob opens nothing. The server
  learns nothing new; a quick unlock reaches exactly what a password unlock reaches, and runs the
  same identity-key substitution check. Offered on the unlock screen, in the autofill overlay,
  and in Settings.
  Honest limits, by design: the **master password is required every 30 days** (so you don't lose
  it — for a zero-knowledge vault, a forgotten master password is an availability incident) and
  after a device reboot unless the app has since reached the server. A biometric lockout never
  destroys the enrollment; changing your fingerprints invalidates it and asks for the password.
  Windows/desktop quick unlock remains deferred.
- **KDF upgrade (F61), finally implemented.** When the org raises the password-hashing policy, a
  full-password unlock silently re-keys the account to the stronger parameters. Upgrade-only, with
  a client-side floor and ceiling so a compromised server can neither weaken the KDF nor lock you
  out by demanding an absurd cost. It never runs while a recovery temp password is live.
- **Native robustness (QW-3).** A recovery temp password no longer stays silently live on
  Android/desktop — both now show a persistent banner until it's changed. Background sync no
  longer greys out the editor mid-typing (offline stalls used to lock the UI for tens of seconds).
  Desktop gained Enter-to-submit / Escape-to-dismiss everywhere, note creation, and a shared-vault
  badge; its two-factor status stopped spinning forever beside its own error. The autofill process
  now locks on idle like the app does. A password is never offered into a one-time-code box.
- **Web daily-UX (QW-2, already live on CT122).** Master-password strength floor at enrollment and
  change; search covers notes, every website, and card names; Back steps through screens instead of
  dumping you to the lock screen; masked editor password with a confirm before Generate overwrites;
  session token lifetimes editable in Admin.
- **Security fixes found by review, worth naming.** A device that had been *revoked* kept opening
  its cached vault offline, forever, if it was only ever used through the autofill overlay — the
  overlay process never processed the revocation. It does now. And the autofill save flow could
  have its engine closed mid-save by the new idle-lock timer, failing the save and duplicating the
  item on retry.


## 0.8.0 — guided importers (2026-07-09, cross-platform release)

Queue item 5 (design: `docs/design/2026-07-09-guided-importers.md` — a 2-breaker design
pass amended the contract BEFORE build, 5 workstreams built it, and a 5-lens adversarial
review gated it). Everything client-side and zero-knowledge: import files never leave the
device; the server sees only ordinary encrypted puts.

- **Guided per-source import on all three clients.** The bare "CSV upload" became named
  flows — Chrome / Edge / Brave / Opera (one shared Chromium parser), Firefox, Bitwarden,
  1Password, LastPass — each with real export instructions. The pick tailors instructions
  and hints only; header detection stays authoritative (specificity-ordered required sets,
  so a pre-2023 LastPass file can never misroute into the Chrome parser). **Desktop gains
  the entire import flow** (it had none).
- **Three new format adapters, both impls, vector-pinned** (`import-foreign.json`; the
  original `import.json` byte-frozen and still passing identically): Bitwarden (logins +
  secure notes, custom fields preserved into notes, multi-URI splits, unknown types
  enumerated), LastPass (secure-note rows import as notes; pre-2023 7-column exports
  supported; HTML-mangle heuristic warns on copy-paste exports), 1Password 8 (archived
  items skipped + enumerated; the Apple/Safari CSV header imports through the same
  adapter). Foreign TOTP seeds only land in the TOTP field when they actually parse —
  steam:// and friends are preserved as text and enumerated, never stored as broken 2FA.
- **Vault-aware dedupe (F75).** The plan now checks the personal vault: exact matches are
  skipped ("already in your vault" — URL matching by the same normalizer autofill uses,
  TOTP compared by parsed parameters), same-site-different-secret imports as a renamed NEW
  item with "password differs" / "2FA differs" called out — the existing vault item is
  never touched, and re-importing your own export is a clean no-op. Refuse-not-degrade:
  if the vault can't be checked, the import says so instead of silently skipping the check.
- **Import report, grown up.** Every skip/rename path enumerated by name (notes imported,
  already-in-vault, differs, archived, unsupported types, unsupported TOTP), errors as
  "row N (file line M)" so multi-line notes can't desync the numbers, and one shared TOTP
  normalizer across all editors (core-hoisted).
- **F56 perf pack (measured at 10k items, fixes applied server-side, wire untouched):**
  the sync pull's OR-join lost its index bound and scanned every granted item on every
  pull — rewritten as two disjoint indexed arms (no-op pull query ~150× faster); orphan GC
  no longer holds the DB lock across filesystem work (max request stall 591 ms → ≤16 ms);
  a partial index makes the Trash janitor scan O(tombstones). Full measurements in
  `docs/design/2026-07-09-importers-perf-addendum.md`; pull paging deliberately
  recommend-only (10.4 MB / ~300 ms at 10k does not justify a wire change yet).

## 0.7.0 — cards & wallet items (2026-07-09, cross-platform release; card-create dark under Option A)

The full cards cycle in one day (design: `docs/design/2026-07-09-cards-wallet.md`,
tournament-settled), built phase-by-phase as parallel subagent workstreams with an
adversarial review gating every slice (4 review workflows, 15 confirmed findings across
them, ALL fixed same-day). Additive end to end: fielded 0.6.0 web/Android, the 0.2.x
desktop MSI, and the 0.6.1 extension keep working untouched. **Card CREATION ships dark on
every client** (`CARD_CREATE_ENABLED` ×2 + the extension's save-flow scope — the Option A
rollout gate; the flip checklist lives in the design doc and fires when the 0.2.x MSI is
retired). Server+web deployed to CT122; Android APK on devstore; Linux `.deb` + 0.7.0
extension zips on `/downloads`; Windows `.msi` = owner build (`ops/windows-build.md`).

- **Native card UI (Android + desktop).** Thin per-client editor/detail sections over a new
  shared core `CardDisplay` (brand recomputed from the IIN at every render — a stale stored
  brand is never trusted); live Luhn warn-not-block; unparseable-expiry warn on both natives;
  masked CVV with reveal; grouped-number reveal with bare-digit copy on the policy-cleared
  clipboard; expired chip; "Visa ••4242" row + history subtitles; CSV preflight now names
  skipped cards and points at vault backups (core `ExportCsv.Warnings.cardItems`).
- **Android card autofill.** A pure core `CardFill` planner — hostile-iframe zero-fill
  (only frame clusters anchored by their own card-number field receive values), LIST/TEXT
  type-pinning with two-pass option matching (a placeholder row never outranks the real one),
  a fit-guard so a declared maxlength can never truncate a fill into a wrong value, and
  presentations that never contain a full PAN or CVV — consumed by thin service glue with an
  explicit browser-trust gate (untrusted browsers get zero card datasets; cards are
  deliberately not URI-bound). Save side: Luhn-preferring capture (a gift-card code can't
  displace the real PAN), CVV-vs-password precedence, PAN-dedupe driving "Update card?"
  (live) vs "Save card?" (dark until the gate flips). Real-device Fold re-run = owner step.
- **Extension Cards popup (copy-only).** Masked card rows with number/expiry/CVV copy via
  the popup-only reveal route (content scripts have no path to card data); a CVV-negative
  save rule (a lone password-typed cvv/cvc/csc field can't be offered as a login-password
  overwrite); fv discipline done right — read ceiling 2, logins STILL seal at fv1, re-seals
  monotonic — structurally pinned from the web test suite. In-page card fill stays
  deliberately deferred behind the frame-egress contract.

- **formatVersion 2 with a per-doc floor (core + web).** Card-bearing docs seal at fv2;
  logins/notes stay fv1 (bit-compatible with the whole fielded fleet). Reseals are monotonic —
  `encryptItem` seals at `max(docFloor, the fv the item was decrypted at)` via a per-item map,
  and returns its fv so the wire field can never diverge from the AEAD AD. Web's five hardcoded
  `formatVersion: 1` sites now read the upload's own fv; `VaultItem` records the true stored fv
  (backup payloads now Android-parity even on the legacy-restore edge).
- **Server monotonic-fv guard (deployed).** A put/restore whose fv is below the stored row's is
  refused (`denied`, audited `push_denied/fv_downgrade`) with row + history untouched — the
  backstop that turns the 0.2.x desktop's automatic card-stripping conflict rewrite into a
  logged refusal instead of silent ciphertext loss. Provable no-op for all pre-card traffic;
  pinned end-to-end in e2e (forged fv1 downgrade over a real fv2 card row → denied, card intact).
- **Web card items (render/edit dark-launched).** Card editor (live IIN brand badge, Luhn
  warn-not-block, MM/YYYY selects preserving out-of-window stored years, digits-only + zero-pad
  + brand recompute at save — spread-only, unknown keys survive), detail view (brand + ••last4
  identity line, grouped reveal, copy-with-auto-clear, expired chip, masked CVV), list-row
  subtitles ("Visa ••4242"), and a calm fv-generic "N items … newer version" banner off the
  fail-closed undecryptable count (closes the web banner gap for every future format bump).
- **CardNormalize everywhere the same.** Pure TS port of core's CardNormalize (ASCII-only Luhn,
  IIN→brand, expiry adapters) consuming the same frozen `card.json` vectors; both ports now trim
  a pinned ASCII whitespace set (`trimAscii`) because platform `trim()`s disagree at the Unicode
  margins (JS strips U+FEFF, JVM strips U+001C–1F) — divergence vector-pinned in card.json.
- **CSV export honesty.** `CsvWarnings.cardItems` split out of the note catch-all; the export UI
  names skipped cards and points at `.andvari` backups (which carry cards as ordinary items).
  Spec 07 §1 updated; core's matching `cardItems` lands first thing in the Android phase.
- Autofill classifier groundwork (6 card `FieldKind`s, CVV demotion, token-bounded card keyword
  fallback firing only where the legacy verdict was NONE — card-free login verdicts bit-identical,
  204 card vectors) ships in core now; Android/desktop/extension consume it in phases 3–7.
- Adversarial review: phase 1 — 7 confirmed findings, all fixed; phase 2 — 7-lens review, 5 low
  findings confirmed → all fixed same-day, 2 refuted with traces.

## 0.6.0 — item history + undelete (2026-07-08, cross-platform release)

The "fat-finger seatbelt" release — the version bump (0.5.0 → 0.6.0) that gathers this cycle's
user-facing features into a coordinated release across web, Android, and desktop. Additive and
backward-compatible: the server's per-platform `minVersion` gate is unset, so older 0.5.0 clients
keep working. Web + server deployed to CT122; Android APK on devstore; Linux `.deb` published to
`/downloads`; Windows `.msi` follows (owner build). Every server-side piece was DB-snapshotted,
health-checked, and adversarially reviewed before ship.

- **Item history — roll back a fat-fingered password.** Every item's last 10 ciphertext versions
  (silently archived server-side since v1, previously unreachable — backlog F63) are now exposed
  via a grant-checked `GET /items/{id}/versions` and decrypted client-side under the held vault key.
  A per-item "Version history" panel (all three clients) reveals each past value and restores one
  with a tap. Honest bound: "up to the last 10 saves." Zero-knowledge intact — the server stores and
  learns nothing new. (Item AD binds `(vaultId, itemId, formatVersion)`, not rev, so an old version
  opens under the current key; history resets at a future vault-key rotation, by design.)
- **Undelete — a Trash to recover deleted items.** A grant-scoped `GET /items/deleted` lists
  tombstoned items (each named from its last archived version, since a tombstone carries no
  plaintext), and a dedicated `POST /items/{id}/restore` un-tombstones cleanly — a deliberate design
  choice over a plain put, which would flag an edit-over-tombstone conflict and spawn a spurious
  duplicate. A "Recently deleted" view on all three clients. (Attachments are not restored — their
  blobs are hard-unlinked at delete; passwords/notes/fields return. Trash retention is currently
  unbounded — a windowing decision, F49.)
- **Recovery hardening (earlier in the cycle, additive under 0.5.0).** F57 escrow re-seal across all
  three clients (a hostile server cannot redirect the UVK escrow — the new fingerprint is verified
  from the printed sheet), F59 admin escrow-download, a passed account-recovery drill, and the
  pre-migration integrity batch — together unblocking the real-secrets migration.

## v6-QW1 — TOTP-QR + devices hub + purge gauges (2026-07-08, deployed CT122)

Additive to 0.5.0 (no client-version bump — web+server only; Android/desktop unchanged at
0.5.0). Deployed to CT122 and verified (bundle sha matches repo dist, both new gauges live in
`/metrics`); adversarial review 7/7 confirmed → fixed/documented before ship.

- **Two-factor QR + a "get andvari on your devices" hub (v6-QW1, web + server).** Server-TOTP
  enrollment now renders the `otpauth://` URI as a scannable QR so a family member enrolls by
  camera instead of hand-copying a 32-character secret (a dependency-free vendored encoder,
  rendered entirely client-side — nothing new leaves the browser; the copy-URI / copy-secret
  fallbacks stay). A new Settings section points at every real client — this browser, the
  devstore Android install (with its own QR), and the Windows installer once the owner
  publishes it (it reads the `/downloads/manifest.json` the server already serves, showing an
  honest "not published yet" until then) — and hides those pointers on the public break-glass
  origin. Server-side, two additive `/metrics` gauges (`andvari_vaults_deleted_pending`,
  `andvari_vaults_purge_overdue`) expose the Skipti janitor's purge backlog so the
  design-mandated stalled-purge alert has a series to fire on.

## 0.5.0 — shared-vault lifecycle "Skipti" (2026-07-08)

Owner gripe 1 closed fleet-wide: shared vaults are no longer immortal. Server schema v4
(live on CT122, migrated with a pre-v4 snapshot), web UI deployed, Android APK
vc 16260489 on devstore; the desktop app inherits the client protections through the
shared engine (UI parity rides the future MSI rebuild). All wire changes additive —
fielded 0.4.0/0.2.x clients unaffected, no minVersion pin armed.

- **Delete a shared vault** (owner): type-the-exact-name confirm with an honest
  "what this does and doesn't erase" block, optional "Copy items to my Personal vault
  first…", 7-day grace, then a daily janitor purge that reduces items to permanent
  ciphertext-free tombstones and wipes every grant's key material.
- **Restore within grace** — Sharing → Recently deleted; brings the vault back for every
  member with everything in it, including members' parked offline edits (replayed with
  their original ids).
- **Leave a shared vault** (non-owner); owners are told to transfer or delete instead.
- **Transfer ownership** — two-phase: the owner offers (14-day expiry, one pending max),
  the recipient sees a consent screen that renders only after the offer proof verifies
  against the vault's own key, accepts by re-wrapping the vault key under their own
  account key. The old owner stays on as a writer.
- **Rename a shared vault** (owner) — name stays ciphertext to the server.
- **Move / Copy an item between vaults** — copy-leg-first with a positive server
  confirmation before the source is touched; attachments are re-encrypted under fresh
  file keys so ciphertext can't be linked across vaults.
- **Lifecycle proofs (ZK preserved):** every destructive action carries an HMAC minted
  under a key derived from the vault key, which the server never holds — clients verify
  removals/deletes/transfers as genuine owner actions; anything unverifiable lands in a
  local holding area with a warning instead of being silently dropped. The holding area
  is durable on phones (ciphertext-only at rest).
- Server hardening that rode along: uniform-403 guard order (no vault-existence oracle),
  idempotency by operation identity (a stale delete retry can never undo a restore),
  denied results never cached (parked edits re-apply after restore), removal proofs
  stored durably, the members list refused on the public break-glass origin, split
  destructive/recovery rate buckets so a delete spree can't block its own undo.

## 0.5.0-era refinement batches (v5 cycle, B1–B8 — all deployed)

Polish, fixes, and half-wired features across the shipped stack, landed as eight reviewed
batches over 2026-07-07 and carried to the whole fleet with the 0.5.0 release (the version
constant was pinned once, by batch B4).

- **Vault screen chrome (web).** The toolbar no longer overflows — the two export actions
  fold into an "Export ▾" menu (viewport-clamped, keyboard-navigable) so the search box
  keeps its width; the header survives phone widths with Lock always reachable; light-theme
  buttons and the item monogram are legible in both themes; the connectivity dot is honest
  (green only after a successful sync, grey on a sustained disconnect).
- **Android autofill resurrected.** Fixed the four reasons it produced zero suggestions on
  every browser: missing package-visibility (`<queries>`), a Chrome signing-cert pin
  truncated by one base64 character (now guarded by a core 32-byte-decode test),
  `supportsInlineSuggestions` never declared, and every failure collapsing into silence. New
  in-app **Autofill status** screen (service/vault state, last request with the "why nothing
  filled" reason and the caller's observed cert digest, and a self-expiring debug log that
  records only field types/counts/host names — never values), a **"Open andvari"** fallback
  row so a fill request is never dead-silent, and a post-unlock no-match message. Firefox and
  Samsung pins are captured on-device via the new screen (`docs/autofill-fold-debugging.md`).
- **Backups (ops).** The nightly clean-snapshot job no longer silently failed every night
  after the first (VACUUM INTO refused to overwrite — PBS/B2 had been carrying a frozen
  first-night copy); the snapshot is now `600` from creation and failures escalate to
  journald instead of unwatched cron mail.
- **Errors that tell the truth (web).** A VPN blip no longer reads as "Wrong master
  password"; a transient policy-fetch failure no longer claims the escrow ceremony isn't
  done (Retry with feedback instead); item deletes can't lie in either direction
  (permission vs connectivity vs server error, and a committed delete is never reported
  as "nothing was removed"); sharing errors drop raw wire codes; enrolling can't strand
  you on a consumed invite after a network hiccup.
- **Release & update truth.** One version constant now feeds the server, desktop, and the
  build gate (0.4.0 shipped with two modules still self-reporting 0.3.0); desktop
  identifies itself as `windows`/`linux` on the wire (it said `android`, so a desktop
  update-pin could never reach it); the "update available" banner shows above every
  desktop screen with the download link (it only showed on a screen signed-in users never
  see, and Linux compared itself against the Windows manifest); a 426 minVersion refusal
  is a real blocking "Update required" screen on desktop.
- **Safety rails.** The last active administrator can no longer be disabled (one
  unconfirmed click used to lock the whole instance, recoverable only by DB surgery) —
  refusals are audited; the admin Users list confirms before disabling; the spec's
  server-knowledge table now matches the real schema exactly; the conflict-copy and
  password-strength derivations are vector-pinned across both implementations; the
  annual escrow-drill reminder actually exists now (n8n `wf-escrowdrill-001`).
- **Session & sync integrity (web).** Token refresh is single-flighted per tab and
  coordinated across tabs (two concurrent refreshes used to trip the server's theft
  heuristic and revoke the whole device); a transient 502 during refresh no longer signs
  every tab out with a false "revoked" message; Lock and auto-lock keep the session and
  land on the lighter "Welcome back" unlock with a reason line (locking one tab locks
  them all); plain session expiry says so instead of claiming revocation; with the live
  socket down the vault polls over HTTP and offers a manual "Sync now" (it used to freeze
  silently); the client now enforces the spec's tamper checks (server identity-key
  cross-check at unlock, rollback/replay rejection, and a resync must be a full snapshot
  before local state is replaced).
- **Native data-safety.** Rotating or folding the phone mid-edit no longer wipes typed
  work (and a save finishing mid-fold closes the editor it should); unlock no longer
  freezes the UI for seconds (argon2 off the main thread); screens are excluded from
  Recents thumbnails/recordings (except the Autofill status screen, which stays
  screenshot-able on purpose); clipboard secrets are marked sensitive and cleared without
  ever clobbering something you copied later; sign-out revokes the device server-side
  even from the locked screen; a mispicked huge attachment can't crash the app; TOTP
  secrets can actually be typed by hand on all three clients (the field used to rewrite
  itself on the first keystroke); read-only members no longer see Edit/Delete buttons
  whose work the server would destroy; and items written by a future app version show as
  "N items need an app update" instead of silently vanishing from lists.

## 0.4.0 — backups & export, auto-lock, forward-compat, sync liveness

- **Back up vault** (all clients). One file, encrypted with a passphrase you choose
  (your master password is a fine choice — the backup is then exactly as protected as
  your vault). Full fidelity: every vault you can read, TOTP, password history,
  attachments (opt-in, capped), restorable years from now with nothing but the file,
  the passphrase, and the documented format (spec 07). `tools/backup-cli` verifies,
  dumps, and extracts backups offline. Restore flows in clients come next release —
  the file format is frozen and forward-safe now.
- **Export for another password manager** (all clients). Chrome-compatible CSV with a
  `totp` column (andvari's own importer round-trips it; other managers import the
  Chrome columns). The export screen names exactly what a CSV cannot carry.
- **Auto-lock enforced.** The org policy's `autoLockSeconds` now actually locks all
  three clients after inactivity (including the Android autofill path), and native
  clients honor the clipboard-clear policy instead of a hardcoded 30 s.
- **Forward compatibility fixed.** Editing an item written by a NEWER client version
  no longer silently strips fields it doesn't know (spec 02 §3 is now enforced and
  vector-tested in both implementations). This also fixes three live bugs: Android
  resetting `favorite` on every edit, both native editors wiping password history,
  and native edits truncating multi-URI logins to one URI.
- **Sync liveness.** Web reconnects its live-sync socket after drops (server deploys,
  laptop sleep) with fresh one-shot tickets; native clients sync on foreground and
  every 5 min while open, so revocations and policy changes actually arrive.
- **Safety rails.** Delete now asks for confirmation everywhere; deleting is still
  fleet-wide. New-client-version documents fail closed instead of being downgraded.
- **Ops.** `user_lookup` no longer writes the looked-up email into audit logs;
  escrow uploads are structurally validated; a typed 426 upgrade-path surfaced in the
  client API + an admin drill doc; recovery-cli gained an offline escrow-canary
  `verify` and a portable fat jar; Uptime-Kuma now watches `/healthz` via a
  heimdall-relayed push monitor (dead-mans if heimdall dies too).
- Fielded 0.3.0 clients keep working; no wire or schema changes require upgrade.

## 0.3.0 — family sharing, offline cache, CSV import, autofill

- **Family sharing.** Create shared vaults and add household members. Each member grant
  seals the vault key to that member's identity key (`crypto_box_seal`); before sending it
  you verify their short **identity code** out of band (in person / by phone) — that code is
  derived from a key the server can't forge. Web has a full Sharing screen (create, add by
  email with the fingerprint check, change role, remove); native apps open shared vaults and
  show your own identity code. Removing a member is revocation-only in v1 (they keep anything
  they already saw; key rotation is a later release).
- **Durable offline cache** (native). Android/desktop keep an encrypted on-device copy of the
  vault, so the app opens instantly and works **offline** (read + queue edits) until it
  reconnects. Only ciphertext is stored; the master password is still required to unlock.
- **CSV import.** Import from Chrome/Edge or Firefox password exports (web + native). Parsing
  is fully on-device; the file never leaves your machine. Handles quoting/dedupe/rename and
  warns that the export holds plaintext — delete it after. An interrupted import resumes
  without creating duplicates.
- **Android autofill** (fill-only). andvari can fill logins in Chrome and other apps. Matching
  is strict (exact host or a true subdomain — never a look-alike or a whole TLD) and honors a
  web domain only from a trusted browser. Locked → tap to unlock in place. Enable it in
  Settings → Passwords & autofill.
- **Security hardening.** Real client IPs behind the proxy for rate-limits/audit; per-user
  upload caps; WebSocket auth via a single-use ticket (no token in URLs); no emails in audit
  logs; tighter CSP. Desktop now defaults to the tailnet URL (auto-migrates once).
- Fielded 0.2.4 (Android) / 0.2.0 (desktop) clients keep working against the upgraded server.

## 0.2.4 — default to the tailnet server

- Default server URL is now https://andvari.taila2dff2.ts.net (reachable from any
  Tailscale device; the old .2.122 LAN IP isn't, from off-VLAN-2). Existing installs
  on the old default auto-migrate once. Changing the server now reloads the recovery
  key immediately (no restart).

## 0.2.3 — boot crash FIXED

- Fixed the ClassNotFoundException that crashed the app on launch since v0.1.0: the
  manifest referenced MainActivity/Application by relative name (resolved against the
  `com.silencelen.andvari` namespace) while the classes live in package
  `io.silencelen.andvari.app`. Now fully-qualified. The app launches to the Welcome
  screen (verified on-device). Crash reporter + ProfileInstaller changes from 0.2.1–0.2.2 kept.

## 0.2.2 (Android boot-crash diagnostic)

- Disable ProfileInstaller auto-init (a pre-Application startup step that can crash on
  some Android 15/OEM builds) — perf-only, safe to drop.
- Crash reporter now renders with a plain Android view (no Compose), so a crash in the
  Compose layer itself is still shown on the next launch to screenshot.

## 0.2.1 (Android diagnostic)

- On-screen crash reporter: if the app hits an unhandled error, the next launch shows
  the stack trace to screenshot (no adb needed). Diagnostic aid; no feature changes.

## 0.2.0

- Encrypted file attachments on items: attach from the editor, download+decrypt from
  the detail view. Per-file keys; the server only ever stores ciphertext chunks.
- Server-TOTP (Settings): enroll an authenticator as the second factor that
  break-glass/public logins require. Sign-in now prompts for a code when the server
  asks for one.
- Matches server/web 0.2.0 (admin console, password health, password change live in
  the web app).

## 0.1.0 (first release)

First Android client for the in-house andvari password manager.

- Sign in and enroll (invite + recovery-fingerprint confirmation) against the
  andvari server (default CT 122, `192.168.2.122`; configurable in the sign-in
  screen).
- Zero-knowledge: your master password derives all keys on-device; the server only
  ever sees ciphertext. A relaunch re-prompts for the master password (the vault key
  is never stored).
- Vault: search, logins and secure notes, per-item detail with copy-to-clipboard
  (auto-clears after 30s), live rolling TOTP codes, and a strong password generator.

**Note:** enrollment needs the server's escrow recovery key configured first (the
one-time offline ceremony). Until then the server disables new-account creation.
