#!/usr/bin/env bash
# CodeQL Kotlin emptiness tripwire (audit G18, docs/design/2026-08-30-full-surface-audit.md).
#
# This repo's first-party code is all Kotlin (zero committed .java), and CodeQL cannot extract
# Kotlin without a build: a java-kotlin leg with `build-mode: none` yields an EMPTY database, so it
# analyzes NOTHING while still painting a green check — a false-green over an empty DB. That leg was
# RETIRED from .github/workflows/codeql.yml, leaving Kotlin with no CodeQL SAST (only JS/TS is
# analyzed). This tripwire makes that decision non-silent: it FAILS if the workflow ever
# re-introduces a java-kotlin leg with `build-mode: none` (or with no build-mode at all — defaults
# are not guaranteed to extract). Re-enable Kotlin only with a real `build-mode` (autobuild, or
# manual with `./gradlew … assemble`) on a runner that can build the ~8-12 GB project — never none.
#
# It asserts the workflow CONFIGURATION rather than a live database because, with the leg retired,
# there is no database to inspect: the check runs on every CI invocation and cannot be defeated by an
# empty leg going green. It is invoked as the first step of the analyze job in codeql.yml, and can be
# run locally: scripts/ci/codeql-kotlin-tripwire.sh [path/to/codeql.yml]
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WF="${1:-$REPO_DIR/.github/workflows/codeql.yml}"

[ -f "$WF" ] || { echo "TRIPWIRE (G18): workflow not found: $WF" >&2; exit 1; }

# Walk the matrix include list (comments stripped, only between `matrix:` and `steps:`). Each list
# item ('- …') is a mapping; collect its language and build-mode regardless of key order, and flag
# the item that pairs java-kotlin with an empty (none / unspecified) build-mode.
bad=$(awk '
  /^[[:space:]]*matrix[[:space:]]*:/ { inmatrix = 1 }
  /^[[:space:]]*steps[[:space:]]*:/  { inmatrix = 0 }
  inmatrix {
    line = $0; sub(/#.*/, "", line)                     # drop trailing comments
    if (line ~ /^[[:space:]]*-[[:space:]]/) {           # start of a new list item
      if (lang == "java-kotlin" && (mode == "none" || mode == "")) hit = 1
      lang = ""; mode = ""
    }
    if (line ~ /language[[:space:]]*:/ && line !~ /languages[[:space:]]*:/) {
      v = line; sub(/.*language[[:space:]]*:[[:space:]]*/, "", v); gsub(/[[:space:]"]/, "", v); lang = v
    }
    if (line ~ /build-mode[[:space:]]*:/) {
      v = line; sub(/.*build-mode[[:space:]]*:[[:space:]]*/, "", v); gsub(/[[:space:]"]/, "", v); mode = v
    }
  }
  END {
    if (lang == "java-kotlin" && (mode == "none" || mode == "")) hit = 1
    if (hit) print "hit"
  }
' "$WF")

if [ -n "$bad" ]; then
  echo "TRIPWIRE (G18): ${WF#"$REPO_DIR"/} re-introduces a java-kotlin leg with build-mode:none (or unspecified)." >&2
  echo "  build-mode:none extracts ZERO Kotlin — a green CodeQL run over an EMPTY database." >&2
  echo "  Give the leg a real build-mode (autobuild, or manual with './gradlew … assemble') on a" >&2
  echo "  runner that can build the ~8-12 GB project, or leave Kotlin retired. Never build-mode:none." >&2
  exit 1
fi

echo "codeql tripwire OK: no empty java-kotlin leg in ${WF#"$REPO_DIR"/} (Kotlin intentionally has no CodeQL SAST)"
