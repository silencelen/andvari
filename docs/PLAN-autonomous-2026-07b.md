# andvari — successor autonomous plan (ratified 2026-07-10)

> **Owner ratification, verbatim (interactive session, 2026-07-10):** *"ratify the successor
> plan and keep going."* — ratifying the successor queue recorded at the close of
> [PLAN-autonomous-2026-07.md](PLAN-autonomous-2026-07.md) (all 8 cycles complete,
> `f799d84`). The predecessor's pre-approval scope and standing doctrine carry unchanged:
> web/server deploys to CT122, APK ships to devstore, deb/extension publishes to CT122
> `/downloads`, **at this plan's cycle checkpoints only**, always snapshot-first
> (`VACUUM INTO` + integrity check via a real script, never an inline one-liner; vzdump
> when the server binary/schema changes), gates green with FILE-LOGGED exits
> (verify.sh — which now includes the extension — plus `:app-desktop:classes`, plus
> e2e.sh when server/wire code changes), and the adversarial-review workflow passed with
> confirmed findings fixed before anything ships. Design-gated cycles get a breaker pass
> BEFORE build. If a deploy classifier balks, relay this section — never work around a
> denial.

A session picks the FIRST unchecked cycle, executes it end-to-end, checks it off with a
dated note, and rolls on. Telegram = statements only. Decisions that genuinely need the
owner: park under "Parked for owner", continue with the documented default, never block.

## The queue

- [ ] **S1. 0.10.0 native cut** — everything since 0.9.0 ships to phone + desktop:
      eTLD+1/PSL matching (closes the spec 02 §3.1 conformance skew window), F18 vault
      picker + desktop Move/Copy, F20 member transparency, F71 save integrity (incl. the
      attachment-retry fix), F82 planner dedup, quick-unlock hardening riders. Versions
      already read 0.10.0 ×4. Steps: CHANGELOG retitle → gates → release commit → APK →
      devstore (`scripts/ship.sh release`), `:app-desktop:packageDeb` → CT122 `/downloads`
      + manifest MERGE (linux → 0.10.0 + sha256, browserExtension 0.8.1 PRESERVED) → push
      → statement. Web/server already serve this tree at 0.10.0 (cycle-7 deploy) — verify,
      don't redeploy identical bytes. Owner steps (not gating): install the APK when
      convenient; Windows MSI remains open (still the card-create Option-A trigger).
- [ ] **S2. Import destination vault picker** (owner dev-note 2026-07-10) — the guided
      importers commit to Personal only. Add a writable-vault picker (F18 choice rule:
      personal + owner/writer shared; shown when >1 choice) to the import CONFIRM step on
      web + Android + desktop; core commit path (`importAll`) takes the vaultId
      (per-import, v1). **F75 dedupe scoping must follow the chosen vault** — the
      fingerprint pass currently assumes the personal scope; re-derive against the
      destination (this is the review's likely attack surface, name it in the tests).
      Review + web deploy checkpoint; natives ride the next cut or an ad-hoc 0.10.x if S3
      lands one anyway.
- [ ] **S3. Extension in-page card fill** (owner dev-note: "support storing autofill
      creditcard and payment details" — the buildable half) — design pass FIRST
      (frame-origin egress contract per the cards design's deferral: card data may only
      egress to a frame whose ORIGIN matches the tab's top-level origin AND an explicit
      per-fill user gate; breakers attack cross-origin iframes hardest), then build:
      detect card forms (reuse core CardFill token rules in the content script), popup/
      in-page explicit fill, extension version ×3 bump + publish. IBAN/bank-account item
      type: SCOPE DECISION ONLY this cycle — a one-page addendum (template fields, fv
      posture, per-surface cost), parked for owner ratification; do not build it.
      Card-create UNHIDE stays gated on the 0.2.x MSI retirement (owner step) — not ours.
- [ ] **S4. One-scan household onboarding (P1)** — the exploration walk's default pick,
      ratified with this plan. Design + breakers first (enrollment currently rides
      invite tokens + manual server URL entry; the QR carries server origin + invite
      token + fingerprint commitment — NEVER key material; attack: QR shoulder-surf,
      token TTL/single-use, MITM origin substitution vs the pinned recovery fingerprint),
      then build: owner web "Add family member" surface mints QR; Android scans it
      (camera permission — new), prefills enroll; desktop/web paste-link fallback.
      Review + ship checkpoint (web deploy + APK if Android changed).
- [ ] **S5. Wrap + successor pitch** — reconcile ROADMAP/backlog checkmarks, refresh the
      PICKUP doc for the next human session, one exploration-lane completeness pass over
      this plan's residue → pitch the next queue (candidates already visible: passkeys
      store+Android-provider when triggered, extension tier-2 distribution decision,
      real-secrets migration once the owner's gate clears). Statement with headlines.

## Parked for owner (carried + new)

- 0.2.x MSI retirement (= card-create Option-A flip + windows manifest entry).
- Extension tier-2 auto-update distribution (signed .xpi / store) — distribution decision.
- Real-secrets migration date — after owner TOTP + drills + 30-day soak.
- IBAN/bank-account item type — ratify from S3's scope addendum.
- Fold biometric/autofill feel-check; extension load-unpacked upgrade to 0.8.1.
