# Guided importers — F56 perf addendum (measure-first; 2026-07-09)

WS-PERF deliverable for [2026-07-09-guided-importers.md] §"F56 perf pack". Method: build
the real `:server:shadowJar`, stand up a LOCAL scratch server exactly per `scripts/e2e.sh`
(mktemp workdir, bootstrap invite, real recovery-cli escrow ceremony — never CT122), seed
a 10k-login personal vault over the wire (50 push batches × 200 puts, ~800 B base64 blobs
≈ a real encrypted login ItemDoc), then measure. Every applied fix is additive,
server-side only, wire-untouched, and justified by a number below. Scratch drivers
(`seed_measure.py`, `pull_keepalive.py`, `GcMeasure.java`) lived in the session
scratchpad — deliberately not committed.

Environment: huginn LXC 117, OpenJDK 17, SQLite WAL + `synchronous=NORMAL`,
single-connection `Db` (one ReentrantLock serializes ALL reads and txs — which is exactly
why §3 matters). "Endpoint" numbers are wall-clock over loopback HTTP, p50; the baseline
and after endpoint runs used the same fresh-connection client so they are comparable, and
a keep-alive floor is given where connection setup dominates. "Query-only" = python
sqlite3 directly on the seeded db, p50 of 50 runs.

## 1. Baseline (10k items, HEAD 1b16e7a)

| Measurement | Result |
| --- | --- |
| Seed: 50 × 200-put batches, wire-inclusive | 10,000 items in 5.42 s (≈1,845 items/s) |
| Push batch of 200 puts (endpoint) | p50 87 ms, mean 101 ms, max 326 ms |
| Full pull `since=0` (endpoint) | 521 ms cold, ~300 ms warm; **10,419,526 bytes** (10.4 MB) |
| Incremental pull, no-op `since=rev` (endpoint) | p50 7.7 ms, 103 B |
| Incremental pull, 10-item delta (endpoint) | p50 9.4 ms, 10.5 KB |
| Incremental pull, 1,000-item delta (endpoint) | p50 38 ms, 1.04 MB |
| `GET /items/deleted` (0 tombstones, 10k live; endpoint) | p50 21.5 ms |
| Janitor tombstone scan (query-only, 200 tombstones) | 9.0 ms — `SCAN items` |
| `sweepOrphans()` — 5k orphan rows+files + 5k strays | 612 ms wall, **591 ms max concurrent-request stall** |

Import-shaped write throughput needs no fix: a 10k-row import completes in ~5.4 s of
server time at 200-put batches, per-batch p50 87 ms is well inside interactive tolerance,
and the client pipeline (parse + encrypt) will dominate in practice.

## 2. APPLIED — pull's items OR-join → disjoint UNION ALL (`Repo.pull`)

**Evidence.** `EXPLAIN QUERY PLAN` for the items query (`(i.rev>? OR g.rev>?)`):

```
SEARCH g USING INDEX idx_grants_user (userId=?)
SEARCH i USING INDEX idx_items_vault_rev (vaultId=?)      -- rev bound LOST
```

The OR disables the `rev` component of `idx_items_vault_rev`, so EVERY pull scans every
item row of every granted vault — including the no-op incremental pull that follows every
WebSocket bell. Query-only cost at 10k items: 2.7 ms per no-op pull, growing linearly
with vault size and multiplied by member count on shared-vault churn.

**Fix.** Split into two disjoint, individually indexed arms joined by `UNION ALL` (no
dedup pass — a plain `UNION` was measured 237 ms vs 53 ms on the full pull because it
dedupes 10k fat blob rows through a temp B-tree):

- arm 1: `i.rev > since` — the normal delta → `SEARCH i (vaultId=? AND rev>?)`;
- arm 2: `g.rev > since AND i.rev <= since` — the grant-rev backfill (new member / role
  change) delivering exactly the rows arm 1's bound excludes → `SEARCH i (vaultId=? AND rev<?)`.

A user holds at most one live grant per vault, and the arms partition on `i.rev`, so
`UNION ALL` returns the identical row set to the OR-join — **asserted equal on the seeded
db at `since ∈ {rev, rev-1, rev-137, rev-5000, 0}`**.

Query-only, before → after:

| since | OR-join | UNION ALL |
| --- | --- | --- |
| rev (no-op) | 2.72 ms | **0.018 ms** (~150×) |
| rev−10 | 2.80 ms | **0.074 ms** |
| rev−1000 | 8.2 ms | 3.9 ms |
| 0 (full) | 38.8 ms | 35.0 ms (par) |

Endpoint, before → after (same fresh-connection client): no-op pull p50 7.7 → 5.3 ms;
10-delta 9.4 → 5.9 ms — the residual is connection + auth + serialization overhead
(keep-alive floor on the fixed build: no-op 3.2 ms, 10-delta 5.0 ms). 1,000-delta and
full pull unchanged (payload-dominated), bytes identical.

The vaults query has the same OR shape but was left alone: its inner loop is one PK probe
per granted vault (`SEARCH v USING sqlite_autoindex_vaults_1 (vaultId=?)`), and vault
counts are single-digit — no number demands it.

## 3. APPLIED — `sweepOrphans()` filesystem work moved outside the DB lock (`AttachmentStore`)

**Evidence.** The hourly attachment-orphan GC did its directory listing (with a per-file
`lastModified()` stat) AND every file unlink inside `repo.db.tx {}` — inside the single
ReentrantLock that serializes every route's DB access, so **the max request stall equals
the whole sweep duration by construction**. Measured with a concurrent thread sampling
`db.read` latency (baseline max 2.2–2.8 ms):

| fixture | sweep wall | max concurrent `db.read` stall |
| --- | --- | --- |
| before — 5k orphan rows+files + 5k strays | 612 ms | **591 ms** |
| after — same fixture | 615 ms | 300 ms (= the in-tx ROW work only; files now unlink outside) |
| after — 0 orphan rows, 10k files on disk (the realistic big-dir shape) | 299 ms | **6.0 ms** |
| after — 50 orphan rows, 10k files | 452 ms | **16.5 ms** |

Every login/pull/push landing during the sweep waited for the whole sweep; on CT122's
slower storage the hold scales with file count × stat/unlink latency. This was also the
exact mid-tx-unlink shape the `Service.push` comment (Service.kt:341-344) already outlaws
on the push path.

**Fix** (same post-commit-unlink pattern as `Service.push` and `Janitor.purgeVault`):
snapshot `dir.listFiles()` BEFORE the tx; inside the tx only row work (candidate select,
reference checks, row deletes, `known`-set read); unlink swept files and then stray files
after commit, outside the lock. Safety unchanged: rows are the source of truth, a crash
between commit and unlink leaves stray files the next sweep removes, and fresh/in-flight
files (including `.part`) are protected by the same 24 h mtime cutoff as before. Sweep
count semantics identical (removed=10,000 on the same fixture; `AttachmentP4Test`'s
orphan-vs-live assertions still green). The remaining in-tx cost is one reference-check
query + one DELETE per OVERDUE orphan row — ~0 rows in healthy operation (see
openQuestions for the batch-delete idea if that assumption ever breaks).

## 4. APPLIED — tombstone partial index (`Db` migration v5)

**Evidence.** The F49 janitor retention scan (`SELECT itemId FROM items WHERE deleted=1
AND updatedAt<?`, daily, plus the same shape inside `purgeOldTombstones`) is EQP
`SCAN items` — a full-table scan that grows with total vault size forever, while its
result (≤30-day tombstones) stays bounded. Query-only at 10k items / 200 tombstones:
9.0 ms per sweep. `GET /items/deleted` (Trash) walks the same rows per open.

**Fix.** `CREATE INDEX idx_items_deleted_updated ON items(updatedAt) WHERE deleted=1` —
partial, so it stores only tombstones: zero write cost on the hot put path (live rows
never enter the predicate). Migration v5, `IF NOT EXISTS`, additive; verified applying
cleanly to the populated seeded v4 db on boot (schemaVersion 5, 10k items intact) and on
fresh-db boot; the v2→ and v3→ migration-chain tests now carry an items table (a
live-shaped DB has one) and assert the chain ends at 5.

| query | before | after |
| --- | --- | --- |
| janitor tombstone scan (query-only) | 9.0 ms (`SCAN items`) | **0.34 ms** (`SEARCH idx_items_deleted_updated`, ~26×) |
| Trash endpoint | 21.5 ms | 18.0 ms (planner still prefers `idx_items_vault_rev` — bounded by grant scope, acceptable) |

## 5. RECOMMEND-only (no number demands them this cycle)

- **Pull paging (`more` flag).** Full `since=0` pull at 10k items = 10.4 MB / ~0.3 s
  server-side. Household scale over LAN/Tailscale absorbs this; the wire-additive flag
  (absent = today's behavior) should ship only when a deployment approaches ~25 MB
  (~25k items) or a low-RAM client OOMs building one response body. Revisit when the
  largest real vault crosses ~20k items.
- **Web vault-list virtualization.** Not measurable here (no browser). `Vault.tsx:384`
  renders `filtered.map(...)` — one DOM row per item, no windowing. At the 10k fixture
  that is 10k+ interactive DOM nodes rebuilt on every keystroke-driven re-filter; React
  reconciliation and layout will dominate long before the (now-indexed) server does.
  Recommendation for the importer cycle: window the list (fixed row height + overscan;
  ~30-line hand-rolled, no dependency) once `filtered.length` exceeds ~500 — below that,
  plain render wins on simplicity. The import-report name-list buckets are already spec'd
  collapsible-when-long and need no windowing. The Vault.tsx owner should confirm the
  threshold with the React profiler at 2k/5k/10k.
- **Push-batch tuning** — NOT recommended: 200-put batches at p50 ~90-100 ms already give
  ~1.7-1.8k items/s end-to-end; import UX will be client-crypto-bound.

## Verification

- `:server:test` green after all three fixes (97 tests; flock'd gradle) and
  `scripts/e2e.sh` (real shadowJar + real web client + WebSocket across a SIGKILL) passed
  on the fixed build.
- Migration v4→v5 verified on the populated 10k seeded db AND a fresh db (§4).
- Pull row-set equivalence OR-join ↔ UNION ALL is a COMMITTED regression test
  (`server/.../PullQueryEquivalenceTest.kt`): the original OR-join is embedded verbatim as
  the oracle and asserted equal to the shipped UNION ALL across six `since` values over
  seeded shared/revoked/bumped-grant/tombstone/conflict rows — so a future edit that
  diverges the two fails the gate (2026-07-09 review finding [10]; the earlier scratch-only
  check is now a real test). Shipped SQL's plan confirmed indexed on both arms.
- ZK / wire audit: no route, request, or response shape changed; all three fixes are
  server-internal (one query rewrite, one lock-scope move, one index).
