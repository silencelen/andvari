# Vendored Public Suffix List snapshot

`public_suffix_list.dat` is the upstream list from
<https://publicsuffix.org/list/public_suffix_list.dat>, vendored **verbatim** (header dates
the snapshot — currently `2026-07-09_11-59-23_UTC`). It powers registrable-domain (eTLD+1)
matching in autofill (design: `docs/design/2026-07-10-etld1-psl-matching.md`, spec 02 §3.1).

## Refresh procedure

1. `curl -fsSL https://publicsuffix.org/list/public_suffix_list.dat -o spec/psl/public_suffix_list.dat`
2. `python3 scripts/gen-psl.py` — regenerates the three committed data artifacts
   (`core/.../autofill/PslData.kt`, `web/src/vault/pslData.ts`, `extension/src/pslData.ts`)
   and prints the new snapshot hash.
3. Update `snapshotHash` in `spec/test-vectors/urimatch-etld1.json` to the printed hash.
   (The vector *cases* only reference rules that never leave the list — `com`, `co.uk`,
   `github.io`, `*.kawasaki.jp`/`!city.kawasaki.jp` — so a refresh should never change case
   outcomes; if one does, STOP and treat it as a semantic review, not a refresh.)
4. Run the gates (core jvmTest + web vitest + `extension npm test` — the hash assertion in
   each catches a half-refreshed tree).

Never edit the generated files by hand; never fetch the list at build or runtime
(deterministic builds — the snapshot only moves when a human moves it).

## Staleness posture (accepted)

- A suffix **missing** from the snapshot (new TLD, new hosting provider, internal names like
  `.local`/`.lan`) resolves to *unknown* → matching degrades to the old strict
  exact-or-subdomain rules. Stale data can only **under-match**, never widen a match.
- The inherent PSL gap remains: a multi-tenant hosting domain absent from the *private*
  section eTLD-matches across its tenants — the same behavior as Bitwarden/1Password.
  Refresh opportunistically at release cuts to keep that window small.
