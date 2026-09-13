# doc-leak fixtures

Checked inputs for `scripts/ci/doc-leak-scan.sh`, exercised by
`scripts/ci/doc-leak-scan.test.sh` (which `scripts/verify.sh` runs).

Each directory is a miniature repository root: the scanner is pointed at it and must
`exit 1` for every `fail-*` and `exit 0` for every `pass-*`. They exist because the
gate they check spent a release cycle described as covering more than it did (audit
H109, a regression of G55): the fix widened the pattern from three literals to
address *classes* and the operator's machine names, and a widened pattern is only
worth anything if something proves it still fires.

`pass-clean` is the important one to keep honest — it collects the near-misses the
pattern must NOT flag (ratified `CT122`-style instance labels, `example.com`, the
real `prestige-release.ps1` filename, version strings, and IPv4 literals just
outside the private ranges). If a change to the scanner makes `pass-clean` fail,
the pattern got greedy, not better.

These files live under `scripts/`, which is outside the scanner's own scope
(`spec`, `docs`, and the root/module prose files), so the deliberate leaks in them
never trip the live run.
