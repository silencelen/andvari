# Cards / wallet items + card autofill — design (2026-07-09)

Queue item 4 (remaining half; the login "Save to andvari?" flow already shipped). Output of a
4-design tournament × 12 adversarial breakers × judge/synthesis (all designs adversarially broken;
every claim below re-verified against the tree and the fielded 0.2.x MSI at its build commit
`0c52a2d`). Target release: **0.7.0**.

## The degradation gate — DECIDED: formatVersion 2 (per-doc floor) + a server monotonic-fv guard

**Reject "keep formatVersion 1 + type-gate."** The decisive, code-verified fatal: the owner's
fielded **0.2.x desktop MSI is a pre-ExtrasOverlay client** — it decodes any formatVersion with
`ignoreUnknownKeys` (silently dropping an unknown `card` key, no fail-closed check) AND has an
**automatic pull-side write path** (`materializeConflict` → `putMutation(itemId, vaultId,
winner.doc, winner.rev)` to clear a conflict flag). So a card that ever becomes conflict-flagged
is re-sealed by the 0.2.x desktop from a card-stripped decode **with no user action** — silent,
undetectable ciphertext loss. ExtrasOverlay (F32/0.4.0) does not save us here because the 0.2.x
build predates it and rebuilds docs field-by-field.

**Fix: cards seal at formatVersion 2 (per-doc floor — logins/notes stay fv1), backstopped by a
~10-line server monotonic-formatVersion guard.** The bump is not for the old client to *notice*;
it is the one plaintext signal a zero-knowledge server has. At fv2, a card-stripping rewrite from
the 0.2.x desktop manifests as a `2→1` downgrade on an existing row, and the server **refuses it**
(audited `push_denied`, reason `fv_downgrade`) — silent data loss becomes a logged, refused write
with the card intact. The classic cost of a bump (blinding the safe fleet) is dissolved by the
**per-doc floor**: no fielded client loses anything on logins/notes, and cards land on the already
shipped, already tested fail-closed "N items need an app update" surface (B8).

**Guard soundness:** no fielded client emits an fv downgrade *on a card it can read as a card*. 0.6.0
web/native fail-close before an fv2 card reaches an editor (`account.ts:264`, `Account.kt:408`);
modern conflict materialization waits on undecryptable items (`SyncEngine.kt:1001`); the extension
skips `fv>1` and only writes logins (`background.ts:441/459`); restore/F19/Skipti all require a
successful decrypt first. The only downgrade emitter in the fleet is the 0.2.x MSI writing over an
fv2 card — exactly the write we want refused.

**One accepted false-positive (documented, not a data-loss path):** the legacy-restore edge below
means a 0.6.0 client CAN hold an fv1 doc that is a card-in-extras. If a 0.7.0 client then re-floors
that item to fv2, a concurrent stale 0.6.0 edit (e.g. a rename) pushes fv1<2 → `denied`
(`fv_downgrade`) rather than the pre-guard `conflict` + displaced-copy. The card ciphertext is never
lost (it rides the 0.6.0 client's extras and the live fv2 row is untouched); only that one concurrent
0.6.0 edit is refused, and it surfaces as a generic "write denied" until a client phase maps the
`fv_downgrade` reason to a clearer message. This is the deliberate, correct trade — allowing the write
would reopen the strip hole — but it IS a false positive against the "no fielded client legitimately
downgrades" invariant, narrow (needs the legacy-restore edge + a concurrent stale 0.6.0 edit during
the mixed-fleet window) and pinned by a mixed-fleet test. `denied` is an
existing per-mutation status every client generation already handles (0.2.x dequeues it + shows its
error bar, `0c52a2d` flushQueue:148-153 — no wedge, no head-of-line block).

### What each fielded client does the moment it syncs a card (all additive; nothing 404s/wedges)

- **Web 0.6.0 (CT122):** fail-closes pre-decrypt into `store.ts` undecryptableById; card invisible
  (0.7.0 adds the web needs-update banner — see below); can never load a card into an editor, so it
  cannot drop fields; all edits to its own items unaffected. Deploy order makes this window ~zero.
- **Android 0.6.0 APK:** same fail-close; ciphertext envelope retained in SqliteVaultCache;
  `needsUpdateCount` drives the shipped "N items need an app update" banner; hydrate-on-launch makes
  the card appear right after the APK update; autofill + unrelated edits unaffected.
- **Desktop 0.2.x MSI:** decrypts the fv2 card but drops the `card` object → name-only "secure note"
  ghost row; its own logins/notes untouched (fv1→fv1); any save of the card (rename included) → server
  `denied` → error bar, queue drains; the automatic conflict path mints a cardless husk copy (applied)
  + a denied flag-clear per pull while a card sits conflicted — **clutter, never loss** (empty window
  under Option A).
- **Extension 0.6.1:** skips `fv>1`, filters `type==="login"` everywhere → invisible, zero risk.
- **Server:** stores `fv=2` opaquely (existing plain INTEGER column) — nothing to trip.

## Data model

`ItemDoc` gains ONE optional typed field beside `login`: `card: CardData? = null`; `type` (already a
plain `String`, `Account.kt:118`) gains `"card"`. Type is chosen at creation only; items never change
type. Every card field is ciphertext inside the item envelope under the vault VK (AD =
`Ad.item(vaultId,itemId,fv)`); the server's spec-02 table gains **zero columns, zero plaintext**.

```
CardData = {
  cardholderName: String?,
  number: String?,        // digits-only canonical; separators stripped at save
  expMonth: String?,      // "01".."12" zero-padded
  expYear: String?,       // 4-digit
  securityCode: String?,  // 3-4 digits, OPTIONAL — CVV storage is an explicit per-card editor choice
  brand: String?,         // visa|mastercard|amex|discover|null — derived from IIN at every save
                          //   via pure core CardNormalize; display-only, recomputed so never stale
  @Transient extras
}
```

Strings (not ints) for month/year — autofill consumes text; adapters derive variants; one canonical
stored form. `CardData` gets its own `CardDataSerializer : ExtrasOverlaySerializer` (the `LoginData`
pattern, `Account.kt:128`) so future card sub-fields are additive *within fv2 forever* — no bump
treadmill. Web `account.ts` + extension type mirror this.

### formatVersion mechanics

`Account.ITEM_FORMAT_VERSION → 2` (highest READ). `encryptItem` seals at `docFloor(doc)`: card-bearing
docs at 2, logins/notes at 1; an EXISTING item reseals at `maxOf(docFloor(doc), fv-it-was-decrypted-at)`
(monotonic client rule). Web store replaces its 5 hardcoded `formatVersion: 1` sites
(`store.ts:617/773/907/942/1217`) with the same floor function; extension bumps its `ITEM_FORMAT_VERSION`
const (`background.ts:49`) to 2, test-pinned. Readers accept a `card` field at any fv they can open (the
legacy-restore edge — a 0.6.0 restoring a 0.7.0 `.andvari` backup mints fv1 cards with fields intact in
extras — is safe and re-floors to 2 on the next 0.7.0 edit).

## Autofill (core-pure, vector-tested; three consumers: Android, extension, future)

`FieldKind` grows `CC_NUMBER, CC_EXP_MONTH, CC_EXP_YEAR, CC_EXP, CC_NAME, CC_CSC`. Exactly ONE
deliberate priority change (vector-pinned); login verdicts on card-FREE forms stay **bit-identical**.

1. **Hints first (unchanged position):** `AUTOFILL_HINT_CREDIT_CARD_*` + W3C `cc-*` map to the new
   kinds; `cardnumber/creditcardnumber/creditcardsecuritycode` graduate OUT of `NEGATIVE_HINTS`
   (`FieldClassifier.kt:36`) into positive card kinds (still negative for USERNAME/PASSWORD by
   construction); postalcode/otp stay NONE.
2. **CVV demotion (kills the wrong-secret-fill fatal):** an `htmlType=="password"` input whose
   **tokenized** name/id (split on non-alphanumerics + camelCase — NOT substring) matches
   `cvv|cvc|csc|securitycode|cardverif` classifies `CC_CSC`, never PASSWORD. A pure form-level
   post-pass `CardForm.refine()` additionally demotes a password-typed field with `maxlength<=4` +
   numeric inputmode when a `CC_NUMBER` sibling exists in the same frame cluster, and computes
   `formKind` LOGIN/CARD/MIXED (CARD requires a CC_NUMBER or ≥2 card kinds in one frame domain).
3. **Card keyword fallback is token-bounded** (`cardnumber|ccnumber|ccnum|cardno`; `expmonth|expmm`;
   `expyear|expyy`; `expiry|expdate|ccexp`; `cvv|cvc|csc|securitycode`; `cardholder|nameoncard|ccname`
   — **"pan" is DROPPED**, substring hazard exceeds its value), evaluated BEFORE the `tel/number→NONE`
   early return (`FieldClassifier.kt:55` — the one reorder, so `<input type="tel" name="cardNumber">`
   classifies). Allowed htmlTypes: text/tel/number/"" (password only via demotion); NEVER from bare
   `CLASS_NUMBER`.

New pure core **`CardNormalize`** (own vector file): Luhn, IIN→brand, expiry parser (MM/YY, MM/YYYY,
MM-YY, MMYY, 1-digit month, 2-digit-year pivot), adapters (pad month, 2/4-digit year, MM/YY compose).

## Android fill + save

**Fill (per-frame-cluster — dodges the cross-frame PAN-leak fatal):** `StructureParser.ParsedField`
gains `autofillType` + `options` (still value-blind); cc fields are grouped by their own `webDomain`,
each cluster anchored on its `CC_NUMBER`; `setValue` only within the anchor cluster (a cc-hinted field
in another frame gets NOTHING — hostile-iframe fixture test). Trust gate made **explicit** (cards skip
UriMatch): `appPackage ∈ BrowserCertPins.TABLE && !trusted → zero card datasets`. Datasets from all
`type=="card"` items (deliberately not URI-bound), capped at MAX_DATASETS, presentation
`"Visa ••4242 · 12/27"` — never full PAN/CVV in any presentation (test-pinned). LIST-type nodes
(select/spinner expiry) resolved via `AutofillValue.forList(index)` by matching option text; `forText`
NEVER set on a LIST node (instrumented test); unmatched spinner → skip the field (partial-fill beats
wrong-fill).

**Save (extends the shipped SaveInfo/onSaveRequest):** login REQUIRED ids unchanged (username+password);
cc ids via `setOptionalIds`; card-only forms use `CC_NUMBER` as sole required id; OR
`SAVE_DATA_TYPE_CREDIT_CARD` when a CC_NUMBER is present. `SaveExtractor` grows card extraction through
the same `signalOf/classify(+refine)` path; CardNormalize + Luhn gate; **precedence:** a Luhn-valid
CC_NUMBER wins and discards any login capture whose password equals the extracted CVV; dedupe by
normalized PAN → match = "Update card? (expiry/CVV)", new = "Save card to andvari? Visa ••4242" →
`ItemDoc(type="card", name="<Brand> ••<last4>")` into the personal vault via the shipped unlock-if-needed
flow; confirm surface shows masked last4 only (FLAG_SECURE covers it).

## Extension 0.7.0 (deliberately narrow)

Popup **"Cards"** group (`type==="card"` from the session list; fv const bump test-pinned); copy
number/expiry/CVV via the existing secret-clipboard path with clear-timer. **NO in-page card fill this
batch** — the frame-origin egress contract (grant redeemable only by the frame that detected the card
form, origin shown in the popup row) is the documented hard precondition for that follow-up slice.
`detect.ts` gains ONLY a CVV-negative rule: a lone password-typed field token-matching `cvv/cvc/csc`
suppresses the save/update prompt (so a checkout CVV can't overwrite a stored merchant password via the
update path).

## UI ×3

- **Web:** "New card" beside New login/note; editor = name, cardholder, grouped-of-4 number (digits-only
  stored, live Luhn WARN-not-block + brand badge), MM + YYYY selects, CVV SecretField (reveal + policy
  clipboard-clear); detail = brand + ••last4, per-field copy/reveal, expired chip; row subtitle
  "Visa ••4242"; all edits **spread-only** (`account.ts:268` contract). PLUS the fv-generic "N items need
  an app update" banner off the undecryptable count — closes the web-banner gap for this and every future bump.
- **Android + desktop:** DRY per the ItemHistorySection precedent — thin `CardEditorSection`/
  `CardDetailSection` per client; `rememberSaveable` fields; `builtDoc` stays **copy()-based** (never a
  field-by-field rebuild — that is the 0.2.x bug).

## Sharing / export / health

Cards are ordinary items: grants, roles, Skipti, F19, item-history, undelete all inherit on 0.7.0
(conflict copy stays PDD-1-deterministic; history resets at VK rotation, unchanged). `.andvari` container
unchanged. CSV stays logins-only; `ExportCsv.Warnings` gains `cardItems` split out of the noteItems
catch-all so the UI says "N cards not exportable to CSV — use a .andvari backup." HIBP untouched (Health
filters `type==="login"`; PANs never leave the client). Skipti honesty block gains one line (a 0.6.0
member's copy-to-Personal-before-delete skips undecryptable cards).

## Wire/format changes (all additive)

1. Inside the encrypted doc (server-opaque): `ItemDoc + card: CardData?`; `type` value `"card"`. Not a
   wire change — the blob is ciphertext.
2. `formatVersion`: card docs seal at 2; logins/notes at 1 (per-doc floor); existing items reseal at
   `maxOf(floor, decrypted fv)`. Existing spec-02 column, no cap today — a `2` stores opaquely.
3. **Server (logic-only, no schema/migration/routes):** in `applyMutation` put path (`Service.kt:444`),
   after the `existing==null` INSERT branch and BEFORE `archiveVersion` + the conflict-overwrite UPDATE
   (`:461-465`): `if (item.formatVersion < existing.formatVersion) → audit push_denied(fv_downgrade) +
   return MutationResult(m.mutationId, "denied")`. Same check in `restoreItem` (`:364`) against the
   tombstone's fv (delete preserves fv, verified `:483`). Denied results are already never dedup-cached
   (`:430-435`), so post-rebuild replays apply cleanly.
4. `ExportCsv.Warnings + cardItems` (client-side additive).
5. `.andvari` container version stays 1; existing export vector bytes untouched.

**Proof no fielded client 404s/wedges:** no new routes/columns/response shapes; the ONLY new behavior is
returning an existing status (`denied`) on a write pattern (fv downgrade over an existing row) that
requires an `fv≥2` row to exist — and none can until a 0.7.0 client writes the first card. The server
deploy is bit-for-bit invisible to all current traffic.

## Tests (the gate, made executable)

Existing 7 crypto vector files byte-identical. `urimatch.json` classify grows card cases + a card-free-form
bit-identity regression section; NEW `card.json` (CardNormalize matrix); NEW form-level refine vectors
(CVV demotion incl. password-typed CVV, sibling rule, formKind); `itemdoc.json` additive card round-trip +
unknown-key-inside-card + old-shape decode→rename→re-encode intact. **Mixed-fleet CI suite:** (a) fv2
envelope → 0.6.0-replica fail-close + needsUpdateCount + hydrate retry; (b) server applyPut fv1-over-fv2 →
denied, row byte-identical, `archiveVersion` NOT called, deny beats the conflict-overwrite path; (c) denied
never dedup-cached → post-MSI-rebuild replay applies; (d) **the 0.2.x simulation:** replicate
`materializeConflict` (ignoreUnknownKeys decode → husk put + flag-clear put) against a card — husk applied,
flag-clear DENIED, live card intact (the fatal pinned as executable fact); (e) web store fv2 →
undecryptableById, sibling edits unaffected; (f) legacy-restore extras round-trip; (g) restoreItem
downgrade guard. Android: hostile-iframe zero-fill; untrusted-browser zero-card-datasets; no-PAN-in-
presentation; merged-form SaveInfo; LIST-never-forText; SaveExtractor card/Luhn/dedupe/CVV-precedence.
Extension: fv-const pin; CVV suppression. e2e.sh: create card on web → row fv=2 → forged fv1 downgrade put
→ denied → card still decrypts.

## Build order (backstop before the first card can exist; web-invisible window ~zero)

0. **Pre-flight:** vzdump CT122 + DB snapshot (doctrine, though schema is untouched); confirm owner MSI status.
1. **Core** (contract everything consumes): CardData + serializer; ITEM_FORMAT_VERSION=2 + docFloor +
   monotonic reseal; FieldKind ×6 + classifier changes + `CardForm.refine`; CardNormalize; all vectors +
   the mixed-fleet JVM suite incl. the 0.2.x simulation. **DONE (`4ab5049`, reviewed 7/7 fixed).**
2. **Server:** the monotonic-fv guard + audit + tests. **Deploy FIRST** (no-op for all fielded traffic).
   **DONE in `4ab5049`; deployed with the web slice (guard is the backstop, deployed together).**
3. **Web:** fv floor (5 sites) + card editor/detail/row + the generic needs-update banner + Warnings.cardItems
   + tests. Deploy with/right after server. **DONE 2026-07-09 (3-workstream build + 7-lens adversarial
   review: 5 low findings fixed — CVV digits-only at save + masked editor CVV, detail brand+••last4
   headline, pinned ASCII `trimAscii` in BOTH CardNormalize ports (+6 card.json divergence vectors:
   U+FEFF/U+001C), floor-1 monotonic test leg; 2 refuted. Integrator extras: coordinated 0.7.0 version
   bump; `VaultItem.formatVersion` records the TRUE stored fv → backups Android-parity. Card-create
   dark behind `CARD_CREATE_ENABLED=false` in web/src/vault/card.ts — the Option A flip point.)**
4. **Android UI:** CardEditor/CardDetail sections (copy()-based; Trash/History inherit). **FIRST item of
   this phase: core `ExportCsv.Warnings` + `cardItems` split + the native CSV-warning line — spec 07 §1
   now enumerates cards, web complies, core routes cards into noteItems until this lands.**
   **DONE 2026-07-09 together with step 6 (one native-UI slice: core ExportCsv.cardItems + new core
   `CardDisplay` + both natives' card editor/detail/rows/preflight-line). 4-lens adversarial review:
   1 real defect (Android silently dropped an unparseable expiry half — warn line added, desktop
   parity), found via three lenses, fixed. Deferred cosmetics recorded here: desktop's pre-existing
   Save-requires-name rule also applies to cards (web allows empty names — unify at a QW); the
   flip-time create affordance differs (Android FAB→dropdown vs desktop second button — pick at flip).**

   **OPTION A FLIP CHECKLIST (when the 0.2.x MSI is retired — flip ALL, one commit + web redeploy):**
   - web: `CARD_CREATE_ENABLED` in `web/src/vault/card.ts` (+ its pin test)
   - natives: `CardDisplay.CREATE_ENABLED` in core (+ its pin test) — gates both Compose clients' create entry points AND the Android autofill "Save card" NEW-item variant (update-existing stays live)
   - extension: no create path (copy-only popup; the save-flow writes logins only)
5. **Android autofill (the L chunk):** StructureParser clusters/formKind; DatasetBuilder card datasets;
   SaveInfo optionalIds; SaveExtractor; SaveConfirmActivity variants; all the safety fixtures; real-device
   Fold protocol re-run.
6. **Desktop:** thin Compose mirror; ships as the 0.7.0 MSI (the Option A artifact).
7. **Extension:** popup Cards group + fv const bump + detect.ts CVV-negative rule.
8. **Release:** APK/deb/MSI cut; card-create UI held dark until the Option A gate clears; announce.

Each slice ends with the standing high-effort adversarial review; verify.sh + e2e.sh green before any
deploy; `--rerun-tasks` on the android assemble after the core FieldKind signature change.

## The one owner decision — when may the first card be written, relative to the 0.2.x desktop?

The whole feature is provably safe under both; this only sets when card *creation* is enabled.

- **Option A (RECOMMENDED):** gate card creation on retiring the 0.2.x MSI (install the 0.6.x/0.7.0 MSI
  already in flight for the user test, or revoke the old desktop's session in the Devices hub). Card-create
  UI stays dark until then. Costs nothing new — sequences an owner step already planned — and the owner
  never sees ghost rows, "write denied" bars, or duplicate husk copies.
- **Option B:** ship cards immediately with guard-only protection. Provably safe (server refuses every
  destructive write), but the 0.2.x desktop shows name-only ghost rows per card, a cryptic "write denied"
  if the owner touches one, and possible duplicate husk copies if a card hits a sync conflict while that
  desktop runs.

**Policy note (decided; flagged for awareness):** CVV storage is supported but optional per card
(ciphertext like everything else; old CVVs persist in the last-10 item history like old passwords).

## Honest costs

fv2 makes cards invisible-not-degraded on stale clients (banner on 0.6.0 natives, name-only ghost on the
0.2.x MSI) — the "you can at least see the name" story is traded for enforced safety. The server guard is
the first item-write policy beyond grants; its no-false-positive proof rests on "no fielded client can
legitimately downgrade" — a standing invariant future client code must preserve (pinned in spec + tests).
Cards are deliberately not URI-bound (wallet posture): any cc form in a TRUSTED browser can summon the card
list — one deliberate tap hands PAN+CVV to a phishing checkout (frame clustering + explicit trust gate +
no-PAN presentations bound it, but the tap is the user's — industry-standard). Storing CVVs makes the vault
a complete card-not-present kit; old CVVs persist in item history. Extension gets copy-from-popup only this
cycle; in-page checkout fill is the frame-egress follow-up. Effort: core M, server S, web M, Android UI M,
Android autofill L (the cost center + real-device verification), desktop S-M, extension S — plus one
adversarial-review cycle per slice.

## Open questions (non-blocking)

- 0.6.0 Trash × fv2: confirm a deleted card renders acceptably in a 0.6.0 Trash list and a 0.6.0 restore
  fails cleanly at the fail-closed decrypt — one targeted test in the web/native slices.
- CVV editor default ships optional + empty — confirm the household is comfortable storing CVVs at all.
- Web needs-update banner copy/placement (new surface, small UX call at build time; must not shame the user
  for someone else's newer client).
- IIN brand table scope (visa/mc/amex/discover, unknown→null but still fillable) — sufficient for the household?
- Extension in-page card fill (deferred): decide after this batch whether PSP-iframe fill is worth its
  complexity for a household popup-copy workflow.
