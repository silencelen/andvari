#!/usr/bin/env bash
# CodeQL Kotlin emptiness tripwire (audit G18, docs/design/2026-08-30-full-surface-audit.md;
# widened by H40, docs/design/2026-09-13-full-surface-audit.md).
#
# This repo's first-party code is all Kotlin (zero committed .java), and CodeQL cannot extract
# Kotlin without a build: a java-kotlin leg with `build-mode: none` yields an EMPTY database, so it
# analyzes NOTHING while still painting a green check — a false-green over an empty DB. That leg was
# RETIRED from .github/workflows/codeql.yml, leaving Kotlin with no CodeQL SAST (only JS/TS is
# analyzed). This tripwire makes that decision non-silent: it FAILS if any workflow ever
# re-introduces a Kotlin leg without a real build-mode. Re-enable Kotlin only with a real
# `build-mode` (autobuild, or manual with `./gradlew … assemble`) on a runner that can build the
# ~8-12 GB project — never none — AND add the language to ALLOWED_LANGUAGES below, deliberately.
#
# WHY IT PARSES YAML INSTEAD OF GREPPING ONE FILE (H40). The first version of this script walked
# the lines between `matrix:` and `steps:` of codeql.yml and fired only when an include-form item
# spelled `language: java-kotlin` — i.e. only on the exact textual shape that had been deleted.
# Measured against scratch variants, every OTHER natural way of re-adding the empty leg passed it
# green: the list-form matrix (`language: [javascript-typescript, java-kotlin]`), a second job that
# hands `languages: java-kotlin` straight to the init action's `with:` (no matrix at all), CodeQL's
# accepted `java` alias, and a brand-new workflow file it never opened. A tripwire that recognises
# one spelling guards one spelling. So this one:
#   * reads EVERY workflow under .github/workflows/ (a directory, not one file), with a real YAML
#     parser (PyYAML, present on GitHub's ubuntu runners and on any dev box with python3-yaml);
#   * finds every `language` / `languages` key anywhere in the document tree — matrix include
#     items, matrix-level list-form keys, and `with:` blocks — and tokenises scalars, comma lists
#     and YAML lists alike;
#   * treats java-kotlin, java AND kotlin as the Kotlin leg (CodeQL accepts `java` as an alias);
#   * requires the SAME item/step (the mapping the key lives in) to carry a `build-mode` whose
#     every value is autobuild or manual — `none`, absent, or a list that includes `none` fails;
#   * and, independently, asserts POSITIVELY that no language token outside ALLOWED_LANGUAGES
#     appears anywhere, so a future leg written in a shape nobody anticipated still trips it.
# `${{ … }}` expressions (the init step's `languages: ${{ matrix.language }}`) are not tokens —
# their value is whatever the matrix says, and the matrix is checked directly.
#
# It asserts the workflow CONFIGURATION rather than a live database because, with the leg retired,
# there is no database to inspect. It runs from its own always-on workflow
# (.github/workflows/codeql-tripwire.yml — so a new codeql-*.yml cannot route around it) AND as
# the first step of codeql.yml's analyze job, and its fixtures are exercised by
# scripts/ci/codeql-kotlin-tripwire.test.sh, which scripts/verify.sh runs.
#
# Usage: scripts/ci/codeql-kotlin-tripwire.sh [path …]
#   Each path is a workflow file or a directory of them (*.yml / *.yaml). Default: the repo's
#   .github/workflows/. Exit 0 = clean; 1 = tripped (or the tripwire could not run — it FAILS
#   CLOSED: a tripwire that cannot parse must never print OK).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ $# -eq 0 ]; then set -- "$REPO_DIR/.github/workflows"; fi

# The ONLY languages any CodeQL leg in this repo may name. Widening this list is a deliberate,
# reviewed act — do it in the same change that gives the new leg a real build-mode.
ALLOWED_LANGUAGES="javascript-typescript"

command -v python3 >/dev/null 2>&1 || {
  echo "TRIPWIRE (G18/H40): python3 is required to parse the workflows — refusing to report OK without checking." >&2
  exit 1
}

# One argv element per file. Directories expand to their *.yml / *.yaml; a path that yields
# nothing is an error (a tripwire pointed at the wrong place must not pass vacuously).
FILES=()
for p in "$@"; do
  if [ -d "$p" ]; then
    while IFS= read -r f; do FILES+=("$f"); done < <(find "$p" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
  elif [ -f "$p" ]; then
    FILES+=("$p")
  else
    echo "TRIPWIRE (G18/H40): not found: $p" >&2; exit 1
  fi
done
[ "${#FILES[@]}" -gt 0 ] || { echo "TRIPWIRE (G18/H40): no workflow files under: $*" >&2; exit 1; }

ALLOWED_LANGUAGES="$ALLOWED_LANGUAGES" REPO_DIR="$REPO_DIR" python3 - "${FILES[@]}" <<'PY'
import os
import sys

try:
    import yaml
except ImportError:
    # Fail CLOSED. An OK printed by a tripwire that could not look is the false-green G18 exists
    # to prevent, one layer up.
    print("TRIPWIRE (G18/H40): PyYAML is not installed (apt install python3-yaml / pip install pyyaml) — refusing to report OK without parsing the workflows.", file=sys.stderr)
    sys.exit(1)

ALLOWED = {t for t in os.environ["ALLOWED_LANGUAGES"].split() if t}
REPO_DIR = os.environ["REPO_DIR"]
# CodeQL's identifiers for the Kotlin extractor. `java` is the accepted alias for java-kotlin and
# `kotlin` is what a hurried edit writes; all three select the extractor that needs a build.
KOTLIN_LEG = {"java-kotlin", "java", "kotlin"}
REAL_BUILD_MODES = {"autobuild", "manual"}


def rel(path):
    return os.path.relpath(path, REPO_DIR) if path.startswith(REPO_DIR) else path


def tokens(value):
    """Every language/build-mode token a YAML value can carry: a scalar (optionally a comma
    list — the init action accepts `languages: javascript-typescript, java-kotlin`), a YAML
    list, or a list of such scalars. `${{ … }}` expressions are skipped: they carry no literal."""
    out = []
    if value is None:
        return out
    if isinstance(value, (list, tuple)):
        for v in value:
            out.extend(tokens(v))
        return out
    if isinstance(value, (dict,)):
        # e.g. `language: {…}` — never a valid CodeQL shape, but walk it anyway so nothing hides.
        for v in value.values():
            out.extend(tokens(v))
        return out
    s = str(value).strip()
    if "${{" in s:
        return out
    for part in s.split(","):
        part = part.strip().strip('"').strip("'").lower()
        if part:
            out.append(part)
    return out


def walk(node, path, found):
    """Collect (mapping, path) for every mapping that carries a language/languages key. The
    mapping itself is the 'same item/step' whose build-mode must be real — an include item, a
    matrix block (list-form keys live directly on it), or an action's `with:` block."""
    if isinstance(node, dict):
        if "language" in node or "languages" in node:
            found.append((node, path))
        for k, v in node.items():
            walk(v, path + [str(k)], found)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, path + [f"[{i}]"], found)


tripped = []
seen_langs = {}  # token -> first location, for the positive assertion

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as fh:
        try:
            docs = list(yaml.safe_load_all(fh))
        except yaml.YAMLError as e:  # a workflow that does not parse cannot be vouched for
            tripped.append(f"{rel(path)}: cannot parse YAML ({e.__class__.__name__}) — fix the file; the tripwire will not vouch for what it cannot read")
            continue
    for doc in docs:
        found = []
        walk(doc, [], found)
        for mapping, mpath in found:
            where = f"{rel(path)}:{'/'.join(mpath) or '<root>'}"
            langs = tokens(mapping.get("language")) + tokens(mapping.get("languages"))
            for t in langs:
                seen_langs.setdefault(t, where)
            if not (set(langs) & KOTLIN_LEG):
                continue
            modes = tokens(mapping.get("build-mode"))
            if not modes:
                tripped.append(f"{where}: Kotlin leg ({', '.join(sorted(set(langs) & KOTLIN_LEG))}) with NO build-mode — defaults are not guaranteed to extract")
            elif not set(modes) <= REAL_BUILD_MODES:
                bad = sorted(set(modes) - REAL_BUILD_MODES)
                tripped.append(f"{where}: Kotlin leg ({', '.join(sorted(set(langs) & KOTLIN_LEG))}) with build-mode {bad} — only autobuild/manual extract Kotlin")

# Positive assertion: whatever shape a future leg takes, a language token outside the allow-list
# is a change to what CodeQL scans and must be made on purpose (edit ALLOWED_LANGUAGES here).
for t, where in sorted(seen_langs.items()):
    if t not in ALLOWED:
        tripped.append(f"{where}: language '{t}' is not in the tripwire's ALLOWED_LANGUAGES ({', '.join(sorted(ALLOWED))})")

if tripped:
    print("TRIPWIRE (G18/H40): a CodeQL workflow names a language leg this repo has not deliberately enabled:", file=sys.stderr)
    for line in tripped:
        print(f"  - {line}", file=sys.stderr)
    print("  build-mode:none extracts ZERO Kotlin — a green CodeQL run over an EMPTY database.", file=sys.stderr)
    print("  Give a Kotlin leg a real build-mode (autobuild, or manual with './gradlew … assemble') on a", file=sys.stderr)
    print("  runner that can build the ~8-12 GB project AND add it to ALLOWED_LANGUAGES in", file=sys.stderr)
    print("  scripts/ci/codeql-kotlin-tripwire.sh in the same change — or leave Kotlin retired. Never build-mode:none.", file=sys.stderr)
    sys.exit(1)

files = ", ".join(rel(p) for p in sys.argv[1:])
langs = ", ".join(sorted(seen_langs)) or "none"
print(f"codeql tripwire OK: {len(sys.argv) - 1} workflow file(s) checked ({files}); CodeQL languages named: {langs}; no Kotlin leg (Kotlin intentionally has no CodeQL SAST)")
PY
