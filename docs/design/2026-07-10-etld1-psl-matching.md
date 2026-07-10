# eTLD+1 / PSL matching (cycle 6) — design

**Status:** breaker-passed (2 breakers: 1 FATAL / 8 SERIOUS / 4 MINOR → amendments A1–A12
below; §"Amendments" is NORMATIVE and overrides the original text where they conflict) → build. **Surfaces:** core `UriMatch.kt` (Android autofill), web
`urimatch.ts` (CSV import name-fallback + future web fill), extension `urimatch.ts` (the live
browser fill path) — three implementations of one normative rule, spec 02 §3.1.

## Problem

Today's match rule is exact-or-subdomain-of-saved: saved `example.com` matches
`login.example.com`, but saved `login.example.com` does **not** match `accounts.example.com`
or bare `example.com`. Anyone who saved the deep host (imports do this constantly — Bitwarden
exports carry full URLs) gets no fill on the same site's other hosts. Industry standard
(Bitwarden "base domain", 1Password) is registrable-domain equality — eTLD+1.

Naive eTLD+1 ("last two labels") is a **credential leak**: `foo.github.io` and
`bar.github.io` are different tenants, but last-2-labels reduces both to `github.io`. Correct
eTLD+1 requires the Public Suffix List, whose *private section* is precisely the
cross-tenant protection (`github.io`, `pages.dev`, `web.app`, …).

## The invariant (normative, the review must attack this)

> **No-loosening:** the new rule may only ADD matches between hosts whose *registrable
> domains are positively known and equal*. Whenever the resolver is not confident — unknown
> TLD, non-ASCII host, IP literal, bare public suffix, empty/garbled input — the match
> semantics degrade to **exactly today's rules**, byte-for-byte. Never match a different
> registrable domain; never let missing data widen a match.

All 25 frozen vectors in `spec/test-vectors/urimatch.json` keep their outcomes under the new
algorithm (verified by scan: no `expected:false` pair shares a registrable domain). That file
is byte-frozen; new vectors live in a new file.

## Decision

**Full vendored PSL snapshot (ICANN + private sections), explicit-rule-only confidence,
punycode-normalized at generation time.** The curated-list alternative was rejected: every
suffix missing from a curated list silently disables the feature for that country/provider,
and curating the private section by hand is guesswork — the full list is *safer and* more
complete for ~60 KB gzipped per surface, and the household threat model doesn't price bundle
size (tailnet distribution).

### Resolver: `registrable(host) → String?`

PSL algorithm restricted to **explicit rules only**:

1. Non-ASCII host → `null`. (No runtime IDNA. The snapshot is punycode-normalized at
   generation; browsers/Android report punycode hosts, so ASCII input matches directly.
   A user-typed unicode saved URI simply doesn't get the new rule — old rules still apply.)
2. IP literal (v4 dotted-quad or contains `:`) → `null`.
3. Walk label suffixes longest-first with three rule sets from the snapshot —
   `rules` (exact), `wildcards` (`*.foo` — any single label directly under `foo`),
   `exceptions` (`!bar.foo` — carve-out, wins immediately, public suffix = candidate minus
   its first label). Track the longest match as `suffixLen` (labels in the public suffix).
4. `suffixLen == 0` (**no explicit rule matched — do NOT apply the PSL's implicit `*`
   fallback**) → `null`. This is the fail-safe: `.local`, `.lan`, `.internal`, corporate
   TLDs, and anything newer than the snapshot resolve to *unknown*, not to a guess. A
   household NAS at `nas.local` can never eTLD-match `printer.local`.
5. `suffixLen ≥ label count` (host IS a public suffix) → `null`.
6. Else registrable = the suffix plus exactly one more label.

### Match rule change (spec 02 §3.1 addendum, additive)

New clause, after exact and before the subdomain-suffix rule:
- **registrable equality:** `registrable(saved) != null && registrable(saved) ==
  registrable(page)` → match.

One **tightening** of the old subdomain rule: it no longer applies when the saved host *is
itself an explicit public suffix* — saved `github.io` (or `co.uk`) stops matching every
tenant/domain under it. (Exact equality still matches; only the suffix wildcarding dies.
Today this requires the user to have saved a bare suffix — rare, usually import junk — but
it is the one place the OLD rule could cross a registrable-domain boundary. Frozen vectors
unaffected: none save a bare multi-label suffix.)

Normalization is unchanged and runs FIRST (lowercase, strip one `www.`, port, trailing dot).
Consequence documented: a `www.`-anchored PSL exception rule (e.g. `!www.ck`) is unreachable
post-normalization — harmless; vectors use `!city.kawasaki.jp` instead.

### Snapshot pipeline (one canonical source, three generated artifacts)

- `spec/psl/public_suffix_list.dat` — vendored upstream snapshot, dated header retained.
- `spec/psl/README.md` — provenance + refresh procedure + staleness posture.
- `scripts/gen-psl.py` — strips comments/blanks, splits ICANN+private (both kept),
  punycode-normalizes each label (`encodings.idna`), sorts/dedups, computes
  `sha256(canonical rule list)`, and emits three **generated-but-committed** files:
  - `core/.../autofill/PslData.kt` — chunked string constants (**Kotlin 64 KB string-constant
    limit — chunk ≤ 48 KB, join lazily**), `by lazy` sets.
  - `web/src/vault/pslData.ts` and `extension/src/pslData.ts` — same data, same hash.
  - Each artifact embeds `PSL_SNAPSHOT_HASH`; the new vector file records the same hash; every
    surface's vector test asserts equality → the three copies can never drift silently.
  - Generator asserts total size < 400 KB (bound against upstream bloat).
- **Staleness posture:** refresh = re-vendor the `.dat` + rerun the generator, opportunistic
  at release cuts; no network fetch at build or runtime (deterministic builds). A stale
  snapshot only ever *under-matches* (new suffix unknown → old strict rules) — except the
  inherent PSL gap: a hosting provider absent from the private section eTLD-matches across
  its tenants, exactly as Bitwarden/1Password behave; accepted and documented.

### Vectors

New file `spec/test-vectors/urimatch-etld1.json`:
- `snapshotHash` — the generator's hash (drift guard).
- `registrable`: host → registrable-or-null. Cases: `login.example.co.uk → example.co.uk`;
  `foo.github.io → foo.github.io` (private section); wildcard `*.kawasaki.jp`
  (`a.b.kawasaki.jp → a.b.kawasaki.jp`... i.e. suffix `b.kawasaki.jp`) + exception
  `!city.kawasaki.jp → city.kawasaki.jp`; `nas.local → null`; `10.0.0.5 → null`;
  `xn--` punycode positive; unicode → null; bare `co.uk → null`; `com → null`.
- `match`: the flagship pairs — `login.example.co.uk ↔ example.co.uk` true both directions;
  `foo.github.io ↔ bar.github.io` **false**; `foo.github.io ↔ www.foo.github.io` true;
  saved `github.io` vs page `foo.github.io` **false** (tightening) but `github.io ↔
  github.io` exact true; `nas.local ↔ printer.local` false; `accounts.example.com ↔
  login.example.com` true (the headline UX win).
- Runners: core `UriMatchVectorTest` (extend to load both files), web `urimatch.test.ts`,
  and the extension's new `node --test` harness gets `urimatch.vectors.test.ts` — the
  extension finally runs the shared vectors natively (cycle-5 harness payoff) instead of
  trusting the web mirror.

### Rollout

Core lands in the repo and rides the next native cut (no APK ship this cycle); web deploys at
the checkpoint; extension bumps ×3 → 0.8.1, zips published + manifest merge — which also
live-fires the cycle-5 update banner on the owner's installed 0.8.0 (deliberate).

## Amendments (breaker verdicts 2026-07-10 — NORMATIVE, override the text above)

**A1 (FATAL fix) — discriminated resolver.** `registrable() → String?` cannot express the
tightening (null conflates *unknown TLD* with *is a public suffix*, and exact-rule membership
misses all 283 wildcard-derived suffixes — saved `us-east-1.compute.amazonaws.com` would keep
filling every EC2 host in the region). The resolver returns a three-state result:
`REGISTRABLE(domain)` | `PUBLIC_SUFFIX` (the walk matched and `suffixLen ≥ labelCount` —
exact, wildcard-derived, or exception-derived alike) | `UNKNOWN` (no explicit rule / non-ASCII
/ IP / unparseable). "Public suffix" in every rule below means the PUBLIC_SUFFIX state.

**A2 — unambiguous walk order.** "Track the longest match" contradicted "exceptions win" and
would resolve ALL 8 PSL exceptions to null (a sibling wildcard at the same candidate always
out-scores the exception). Normative walk: candidates longest-first; at each candidate test
**exception → exact → wildcard** in that order; exception ⇒ `suffixLen = candidateLabels − 1`
and STOP (never overridden); exact/wildcard ⇒ `suffixLen = candidateLabels` and STOP.
Longest-first + stop-on-first-match makes the longest rule win by construction.

**A3 — final match rules (replace the original clause list).** After normalization,
androidapp/no-webHost handling, and the exact-equality check, for web-vs-web:
- **R-IP:** either side an IP literal → false (exact-only, unchanged).
- **R-SUFFIX-BARE:** either side resolves PUBLIC_SUFFIX → **false** (a bare public suffix is
  exact-only in BOTH roles — saved `github.io` fills no tenant; a page AT `b.kawasaki.jp`
  gets no `kawasaki.jp` item).
- **R-EQ:** both sides REGISTRABLE → match iff the registrable domains are **equal**. (This
  both grants the eTLD+1 win and kills every known-boundary crossing, including the old
  suffix rule's `compute.amazonaws.com` → `ec2-x.us-east-1.compute.amazonaws.com` hole —
  breaker-verified frozen-safe: every frozen `expected:true` pair is registrable-equal.)
- **R-OLD:** anything else (≥1 side UNKNOWN) → exactly today's subdomain rule (saved has ≥2
  labels AND page ends with `"." + saved`). Household/intranet hosts (`pihole.lan`,
  `grafana.internal`) resolve UNKNOWN and keep today's behavior bit-for-bit.

**A4 — invariant re-worded.** "Degrade to today's rules" applies to the UNKNOWN state only.
Bare public suffixes do NOT degrade — they tighten to exact-only (that is the point). The
"never match a different registrable domain" sentence now holds absolutely whenever both
sides are positively resolved, because R-EQ is an equality test.

**A5 — empty labels are unparseable.** `normalizeHost` returns null for any host with an
empty label after trailing-dot stripping (`.example.com`, `a..example.com`) on all three
surfaces — garbled input now truly cannot match anything. Vector-pinned.

**A6 — the hash guard must hash RUNTIME data.** Each surface's vector test recomputes
sha256 over the rule string **as loaded at runtime** (Kotlin: after the chunk join;
TS: over the exported constant) and asserts it equals both the embedded
`PSL_SNAPSHOT_HASH` and the vector file's `snapshotHash`. Canonical bytes, normatively:
punycoded rules with `!`/`*.` markers preserved, bytewise-sorted, `"\n"`-joined, UTF-8
(pure ASCII by construction). Constant-vs-constant comparison alone is tautological and
would miss chunk-join corruption — the one failure mode that loses rules silently.

**A7 — extension tests join the mandatory gates.** `scripts/verify.sh` gains
`(cd extension && npm run typecheck && npm test)`, and `extension/package.mjs` refuses to
zip if `node --test` fails (mirroring its version-drift refusal). Without this the live fill
path's PSL copy has no mandatory gate at all.

**A8 — bundle placement (content.js must stay PSL-free).** `pslData` may be imported ONLY by
a new `psl.ts` (the resolver), consumed ONLY by `background.ts`. `urimatch.ts` takes the
resolver as an explicit parameter (`matchLogins(uris, target, resolve)`) so `content.ts` →
`detect.ts` → `classify` never pulls the 144 KB blob into the per-page bundle.
`package.mjs` fails if `dist/content.js` exceeds 60 KB (today ~20.5 KB). Kotlin core calls
`Psl.resolve` directly inside `UriMatch.matches` — no resolver parameter at all (no bundle
concern on JVM/Android); only the TS mirrors take the resolver as an explicit parameter.

**A9 — Kotlin const-fold trap.** Chunks are emitted as **non-const** `private val`s and
joined at runtime (`joinToString`), because `const val` concatenation folds at compile time
back into a single >64 KiB (65,535 modified-UTF-8-byte limit) constant and fails the build.

**A10 — spec §3.1 wording.** The amendment is "one addition + two tightenings", NOT
"additive". Replace the old "eTLD+1 is a v2 loosening" sentence (which mis-reads as a
formatVersion gate) with: client-version-gated behavior, no formatVersion change, plus a
dated conformance note naming the skew window (Android/desktop keep the old rules until the
next native cut; web + extension ≥ 0.8.1 carry the new rules).

**A11 — desktop is inside the native-cut gate.** No deb rebuild between this merge and the
next cut; the conformance note lists desktop with Android.

**A12 — generator hygiene.** Lowercase every label before IDNA; fail loudly (with the
offending rule) on empty/oversized labels; document the IDNA2003-vs-UTS46 residual (a future
`ß`-class rule would silently under-match — acceptable, README-recorded). Vectors use
eternal rules (`com`, `co.uk`, `github.io`, `*.kawasaki.jp`, `!city.kawasaki.jp`) plus one
private-section wildcard (`*.compute.amazonaws.com`) with a README note that a refresh
touching it demands a semantic review, not a hash bump.
