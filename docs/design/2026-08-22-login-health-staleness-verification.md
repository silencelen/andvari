# Login health — staleness ranking + guided verification

**Status:** DESIGN, owner-ratified 2026-08-22 (three forks answered inline below).
**Asks it answers (owner, 2026-08-22):**
1. Rank logins by how long since they were used / changed, and surface the oldest and stalest.
2. A semi-automated tool to check whether a login still *works*: open the site, sign in by hand,
   come back to andvari, record the outcome.

Companions it does not re-decide: the duplicate checker
(`2026-08-13-full-surface-audit.md`, the 2026-08-18 vault-UI batch) whose differs-resolution
flow this generalizes, and `2026-07-08-item-history-and-restore.md` (F62/F63) whose
`item_versions` backstop §2 shows this feature must not churn.

---

## 1. What signals already exist, and what each is worth

| Signal | Where it lives | Cost to use | Household-wide? | Trustworthy? |
|---|---|---|---|---|
| `updatedAt` | server row, already on `VaultItem` | **free** | yes | yes — one server clock, monotonic-ish |
| `createdAt` | server row (spec 02 §1), not plumbed to web `VaultItem` | small | yes | yes |
| password age | **does not exist** | — | — | — |
| last used | **does not exist** | see §2 | see §2 | client clock, advisory |
| last verified | **does not exist** — this design adds it (§3) | small | yes | client clock, advisory |

**`updatedAt` is "last changed", never "password age".** It bumps on *any* edit — a rename, a
note tweak, a `dupeAck` dismissal write, a conflict materialization. Worse, a bulk operation
(an import, a `dupeAck` sweep) restamps a whole vault and destroys the signal wholesale. The UI
therefore labels the column **"Last changed"**, and the ranking never rests on it alone. Calling
it password age would be a lie the data cannot support, and `login.passwordHistory` cannot fix
that — it is spec-reserved with exactly one writer (`planKeep`), so an absent history means
nothing at all (spec 02 §3).

## 2. Last used — why the obvious implementation is harmful

The obvious move is a `usedAt` in the item document, synced like any other field. **Rejected on
mechanism, not on taste.** Three independent reasons, any one of which is disqualifying:

1. **It would eat the password-history backstop.** `item_versions` is capped *live* at the
   newest 10 per item, hard-deleting the rest (spec 02 §7, `Repo.archiveVersion` — "an
   11th-oldest version is already unrecoverable"). A `usedAt` write is an item overwrite, so
   **roughly ten uses would evict every real edit version of that item.** F63 — the shipped
   no-silent-loss answer to "recover the previous password", and the *only* one, since F62 took
   the reserved branch — would be silently destroyed by the health feature. Nothing about a
   health feature justifies that trade.
2. **It changes the threat model.** The `changes` feed is server-visible by nature and already
   reveals per-item write timing (spec 02 §5, spec 05). Today that means *when someone edited*.
   Writing on **use** turns it into a per-item behavioral log — which credential, how often, at
   what hour. That is a spec 05 amendment, not a footnote, and it is a poor trade for a
   convenience column.
3. **Write amplification.** Every fill on every device becomes a push plus a WS dirty-bell
   fanout to every other device, for data nobody is waiting on.

The naive *local* implementation is also already-rejected ground: the HIBP breach cache in this
very view is **in-memory only**, with a live `purgeLegacyBreachResidue()` scrubber, because an
audit (CR-08 / WC-13 §E.4) ripped out its `localStorage` version for "outliving the session the
way the old localStorage key did". A usage ledger in `localStorage` would re-introduce exactly
the class of residue that was deliberately removed — and a behavioral map is *more* sensitive
than a breach map, not less.

> **OWNER DECISION (2026-08-22), revised same day on new evidence: one SEALED PER-USER BLOB,
> server-synced.** The first decision was a device-local ledger; building it surfaced the fact
> that kills it — **the browser extension cannot reach it.** The extension is a separate client
> with its own `chrome.storage`, there is no `externally_connectable`, and injecting a content
> script into the vault origin is fail-closed forbidden (`background.ts`). Since the extension
> does most of the filling, a web-local ledger would have shown a near-empty column.
>
> The objections in this section were always specific to putting usage **in the item document**.
> A single aggregate blob — one row `{userId, AEAD blob under UVK, updatedAt}`, the shape
> `escrow` and `member_recovery` already use — dodges every one of them: no item overwrite, so
> `item_versions` is untouched; no per-item rows and nothing in `changes`, so the server sees
> THAT a ledger changed and its size, never WHICH login; and it syncs to **every** client, so a
> fill on the phone counts on the laptop.
>
> Cost, stated plainly: a **spec 02 §5 table addition (schema v9)** plus server work. Accepted.
> Writes are batched (never per-use) so the blob's own `updatedAt` is not an activity trace, and
> it is last-writer-wins — advisory ranking data gets no conflict machinery. Specified in
> spec 02 §8.2. **Bonus: the §8 subset invariant is PRESERVED rather than narrowed**, because the
> blob now exists server-side as ciphertext.

**The honest limitation that survives:** an item with no recorded use renders **"—", never
"never used"** — the same absence-carries-no-information discipline spec 02 §3 already applies to
`passwordHistory`. Until the ledger ships, that is every row.

## 3. The `check` ledger — the synced backbone

A verification verdict is a statement **about the item, not about the viewer**: if a household
member confirms the Netflix login works, it should quiet for everyone. That is verbatim the
argument spec 02 §3 already records for `dupeAck`, so the verdict takes the same shape — a
claimed top-level key in the doc-level extension registry, additive within fv1/fv2, **no
formatVersion bump**, preserved losslessly by every existing client through the extras overlay.

```jsonc
"check": {
  "at":     1755800000000,                       // when this verdict was recorded (client clock)
  "result": "ok" | "bad" | "gone" | "blocked",
  "okAt":   1755800000000,                       // optional — most recent `at` whose result was ok
  "until":  1758400000000                        // optional — snooze; do not resurface before this
}
```

Normative rules:

- **One write per recorded verdict.** "Skip" writes nothing. This is what keeps the §2.1
  `item_versions` churn bounded to something a user does maybe once a year per item.
- **`okAt` carries forward.** On an `ok` verdict `okAt == at`; on any other verdict `okAt` is
  copied from the previous `check` unchanged. So "it last worked in March, and failed in August"
  survives in one small object with no array.
- **Absent `check` means never verified** — *not* verified long ago, and *not* healthy.
- **Forward compatible on `result`.** A value this client does not know renders as "checked"
  with no verdict styling, and is preserved verbatim. Never fail closed on a vocabulary
  extension.
- **Clock skew.** `at` is a client clock and untrusted (spec 02 §1). A future `at` displays as
  "just now" and never sorts above real entries. Advisory UX only — no security decision reads it.

Rejected alternative: a server-side verification table. It would put a per-item plaintext
verification log on the server — a spec 02 §5 violation — to buy nothing the ciphertext cannot
already carry.

## 4. The guided verification run

The posture is not new. It is already owner-ratified doctrine, recorded at `duplicates.ts:55`
for the 2026-08-18 differs-resolution flow:

> the "open site" affordance … **the only honest password test is the human logging in; the
> client must never probe a site with candidate credentials itself.**

This feature generalizes that one-off affordance into a tool. The flow, one item at a time over
a worklist, resumable within the session:

```
1  Item card:  name · username · site
   [Copy username] [Copy password] [Open site ↗]        ext present → [Open & fill]
2  The user leaves, tries to sign in, comes back to the tab
3  One click records the verdict:
     Signed in            → ok       → quiets the item
     Wrong password       → bad      → offers: open the item / generate a new password
     Account or site gone → gone     → offers: delete (to the 30-day Trash, recoverable)
     Couldn't complete    → blocked  → offers: snooze 30 days      (MFA, lockout, captcha)
     Skip                 → writes NOTHING, next item
4  Next item · Done summary
```

> **OWNER DECISION (2026-08-22): four verdicts, not two.** Each maps to a different next action;
> a two-state confirm/deny cannot tell "my password is stale" from "this service shut down", so
> every follow-up would stay manual. This is what makes the list actionable rather than re-sorted.

**Hard constraints. Each has a reason; none is negotiable.**

- **Never auto-submit.** Fill-only. Auto-submitting a credential is credential-stuffing
  behaviour: it trips lockouts and rate limits, and against a wrong, parked or typosquatted URI
  it sprays the real password at an attacker. This also matches the existing card-fill posture.
- **Never probe.** No background request to the site to guess liveness. It would leak the
  vault's site list to the network and to the sites themselves, from a machine that may never
  otherwise contact them, and it would breach the egress posture the pins and the W2 harness
  exist to hold.
- **Never infer the verdict from page content.** That needs a content script reading arbitrary
  pages — a permission and threat escalation bought for a guess. The human asserts; the client records.
- **Every navigation through `safeurl`.** Vault URIs are user-authored, but in a *shared* vault
  they are authored by *another member*, which makes a `javascript:` URI a real if narrow vector.
  `Health.tsx:429` currently builds this href inline with a regex; that fold into a shared helper
  is a reuse win this change takes, not new surface.
- **Reader-role vaults run the walkthrough but refuse the record**, with the reason shown — the
  `planDismiss` refusal idiom, for the same cause: the server would reject the write anyway.
- **Offline** verdicts queue through the existing offline write queue like any other edit.
- **Run progress is session-scoped and never persisted** — the owner's 2026-08-18 rule that sort
  and filter state must not be "helpfully" persisted applies to wizard position too.

**Conflicts.** A verdict write is an ordinary edit and can lose a race with a concurrent edit
from another device, materializing a conflict copy. Rare by construction (§3's one-write-per-
verdict), and it degrades into the existing, understood conflict path rather than anything new.

## 4a. Why the ledger key is the personal VK, not the UVK (found and resolved 2026-08-22)

The synced blob was chosen **because** the extension could then contribute (§2). Building it
surfaced the constraint that made the first key binding wrong:

- `session.uvk` in the extension is **memory-only and never persisted** — spec 01 **breaker B1**,
  a deliberate custody rule, not an oversight.
- An **MV3 service worker is evicted routinely**, and the snapshot that restores the session
  carries `vaultKeys` and `items` but, by that same breaker, **no UVK**.
- A UVK-sealed ledger was therefore writable from the extension only during a session that did a
  live full password unlock and had not been evicted since — a minority of real fills, from the
  client that does most of the filling. The design would have shipped excluding the very client
  it was chosen for.

**Resolved by re-binding, not by working around it.** The ledger key is now

```
usageKey = HKDF-SHA-256(ikm = VK(personalVault), salt = "", info = "andvari/v1|usage", 32)
```

the same construction and domain-separation shape already used for the per-vault lifecycle key
(spec 03 §11). **Every unlocked client holds the personal VK in every session, evicted or not**,
so all four participate with no buffering and no new at-rest class. The AEAD associated data is
unchanged — `andvari/v1|usage|{userId}` — so the blob stays bound to the user's slot and a
hostile endpoint still cannot serve one member's ledger into another's. No vault key is persisted
either, so the at-rest story is exactly as before: the server and a stolen locked device both
hold opaque bytes.

Rejected alternative: have the extension buffer `(itemId, when)` in `storage.session` and flush
at the next UVK-bearing session. It needed no spec change, but writes would arrive late, some
would be lost to browser exit, and it would add a plaintext behavioural buffer whose disclosure
bound would have needed its own justification — all to preserve a key choice that had no
independent merit.

Degradation is clean: an account with no personal vault has no ledger, and the column reads "—".

**The rule that outlives this particular problem, now normative in spec 02 §8.2:** a client that
cannot open the ledger MUST leave it untouched rather than write a partial one over another
client's.

## 5. The Staleness view

A third tab beside **Passwords | Duplicates**, preserving the tiles-plus-one-switchable-half
idiom the owner set on 2026-08-18. Tiles gain **Unchecked** and **Failing**.

Columns: *Item · Last used here · Last changed · Last checked · [Check]*

Ordering is **explainable, not a score.** A weighted staleness number would be unarguable-with
and untrustworthy; buckets can be reasoned about:

1. Failing verdicts (`bad` / `gone` / `blocked`), most recent first — these are actionable *now*
2. Never checked, oldest `updatedAt` first
3. Checked, oldest `check.at` first

Snoozed items are filtered out behind a "show snoozed" toggle. Age buckets for scanning:
never checked · over a year · 6–12 months · under 6 months.

## 6. Spec changes this design requires

- **spec 02 §3** — claim `check` in the doc-level extension registry, with the §3 rules above
  (absent-means-never, forward-compat on `result`, one writer per verdict).
- **spec 02 §8.2 (new)** — the usage ledger: one blob sealed under the UVK, batched writes,
  last-writer-wins, absence-means-nothing, and the **disclosure bound** (a stolen *unlocked*
  device, or a compelled master password, reveals which items the owner touches most — no secret,
  but behavioural data, named rather than shipped quietly).
- **spec 02 §5 / §2** — the `usage_ledger` row and its AD, **schema v9**. This is the one place
  the design adds server-visible surface, and it is ciphertext plus a timestamp: the server never
  learns which login moved. The `check` ledger (§3) adds nothing server-visible at all.

## 7. Scope of the first cut

> **OWNER DECISION (2026-08-22): web + extension assist.**
> Web owns the Staleness tab, the `check` ledger and the wizard. The extension adds "Open & fill"
> (which needed no plumbing — an installed extension offers its ordinary autofill on arrival) and
> **records usage on every fill**, at the single post-gate success point in `reveal()`. Android and
> desktop **preserve `check` losslessly from day one for free** via the extras overlay, and get a
> read-only "Last checked" on item detail in a later cut. This mirrors the `dupeAck` precedent
> exactly: one writer, universal preservation.
>
> **Shipped state of the usage ledger:** server (schema v9 + `/usage`), web (record on password
> and TOTP copy, and on open-site in the run) and extension (record on fill) all participate.
> Android and desktop hold the personal VK too, so nothing blocks them — they simply have no
> recording call sites yet.

## 8. Tests that must pin this

- `staleness.test.ts` — bucket and ordering derivation, exported pure like `healthRows`
- `check.test.ts` — verdict transitions, `okAt` carry-forward, unknown-`result` forward compat,
  future-`at` skew clamp, reader-role refusal
- core `ItemDocRoundTripTest` + web `itemdoc.test.ts` — `check` round-trips through the extras
  overlay untouched. **This is the test that proves an old client cannot eat the field**, and it
  is the one that matters most.
- usage ledger — consent-OFF writes nothing; sign-out wipes; no `localStorage` key is created
  (the CR-08 regression guard)
- egress — no new network destination appears in the extension pins

---

## Appendix A — owner TODO, appended 2026-08-22: reuse alert at registration

> *"we want an andvari prompt during an account login registration to suggest a password / alert
> the user if its one already used for another login."*

**Half of this already ships.** `detect.ts` classifies `isSignup` (a `new-password` autocomplete
flag, or the classic unflagged password+confirm pair) and `content-ui.ts:733` already offers
**"Use a strong password"** on exactly that signal.

**The missing half is the reuse alert. BUILT 2026-08-22 — and the locked-state plan above was
deliberately NOT followed. Recorded here because the reasoning is the valuable part.**

The plan was to extend `knownlogins.ts`'s truncated-HMAC membership set from `(site, username)`
pairs to passwords, so the warning would work while locked. **That is the one thing not to
build.** `knownlogins` justified its digest set on the record as *"strictly less than the
plaintext pendings the same compartment already holds"* — true for site/username pairs. The
password version **inverts that bound**: pendings hold passwords for the one site the user just
logged into, whereas a password digest set covers the **whole vault**. Anyone able to read the
locked compartment could then confirm a *guessed* password against every credential the user
owns — a vault-wide password oracle, sitting in memory, leaking exactly the thing the product
exists to protect. Strictly MORE disclosure, not less. No spec amendment would make that a good
trade, so none was written.

**What shipped instead: the check is UNLOCKED-ONLY.** The SW compares against already-decrypted
items in its own memory and returns a **count** — no password and no item identity comes back.
Locked ⇒ `{locked: true, count: 0}`, and `reuseWarning()` returns null for it, so the UI stays
**silent rather than implying an all-clear** (silence must never read as "not reused"). While
locked the user still gets "Use a strong password", which needs no vault at all — so the locked
case loses the warning, not the remedy.

Egress is bounded by `shouldAskReuse` (pure, `reusealert.ts`, 11 tests): signup forms only, only
a new-password field, on **blur not per keystroke**, never while we are filling, never twice for
the same settled value, and never for a half-typed one. That is the same content-script→SW
channel the save capture already uses, so it adds no new flow — only a narrower one.
**spec 01 §8.4 is untouched**, which is the correct outcome: nothing new is retained across a lock.

## Appendix B — owner TODO, appended 2026-08-22: Android fills but never offers save

> **FIXED 2026-08-22.** `DatasetBuilder.saveTrigger` (pure, generic over the id type, pinned by
> `DatasetBuilderSaveTriggerTest` — 8 tests) now decides the trigger set, and `saveInfoFor`
> consumes it. Password-only trigger; username demoted to `setOptionalIds`. Nothing is
> suppressed — the feature works rather than being hidden.

> *"in certain apps, for password fields that are not really tied to a username but are tied to
> the app or context, are prompted in the keyboard integration for autofill but dont prompt for
> save, causing it to be a half working feature."*

**Root cause located** — `DatasetBuilder.saveInfoFor`, one line:

```kotlin
val required = (if (pw.isNotEmpty()) user + pw else listOfNotNull(requiredCc)).map { it.id }
```

Android shows the save UI only once **every required view has changed**. Making the username a
*required* id means that whenever `StructureParser` classifies some field as USERNAME and the
user never types into it — prefilled, irrelevant, or genuinely absent because the password is
app- or context-scoped — **the save prompt is suppressed forever while fill keeps working.**
That is exactly the reported half-working feature.

**The fix is already precedented three lines below**, in the card path, which learned this same
lesson: requiring every PAN-ish field "would silently suppress the prompt whenever one stays
empty", so it picks a single anchor as the sole required id and passes the rest via
`setOptionalIds`. The login path never received the same treatment. So: **password field(s) as
the sole required trigger; username demoted to optional**, which still delivers the username
value to `onSaveRequest` when the user did type one.

**The downstream path is already ready for this** — verified, not assumed: `SaveConfirmActivity`
handles a null/empty username throughout, and `planFor` has an explicit no-username branch
(2b, the lone-match password change). So no doc-model change is needed and nothing has to be
suppressed: **the feature can be made to work rather than hidden**, which is the better of the
two options the owner offered.

**Residual, deliberately NOT bundled** (each is independent, and the required-ids fix stands on
its own because a genuinely username-less form hits the bug too):
- whether `SAVE_FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE` is also needed for app forms that never go
  invisible — needs a real device to tell, so it is an owner-observation item, not a code guess;
- whether `StructureParser` is over-classifying USERNAME on these app forms in the first place.
  If it is, that is a second fix, and it would now show up as a spurious value arriving at
  onSaveRequest rather than as a missing prompt — a much louder failure than the silent one.

**Owner check when this ships:** the apps that were half-working should now prompt to save. If any
still does not, the residual above is the next place to look — say which app and it can be traced.
