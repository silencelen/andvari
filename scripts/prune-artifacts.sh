#!/usr/bin/env bash
# Prune the append-only build-artifact directories — dist/ (Android APKs) and
# extension/artifacts/ (store zips + signed XPIs). Both are gitignored working dirs that every
# release only ever ADDS to, so they grow without bound (dist/ reached 2.1 GB / 41 APKs).
#
#   scripts/prune-artifacts.sh [--keep N] [--dist|--ext] [--apply]
#
# DRY-RUN BY DEFAULT — it prints what it would remove and stops. Pass --apply to delete.
# Deletion is deliberately the operator's call, not a build-script side effect.
#
# Never removed, whatever --keep says:
#   * the artifact each live manifest points at — dist/latest.json `apk`, dist/latest-debug.json
#     `apk`, extension/artifacts/firefox-updates.json `update_link` (the auto-update channel: drop
#     that XPI and every Firefox install is stranded on its current version forever);
#   * the version extension/manifest.json currently declares (the build in flight);
#   * anything that is not a recognised artifact filename — SHA256SUMS files, the manifests
#     themselves, ceremony kits, the AMO-hash-named XPI stray. Those are listed, never touched.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEEP=5
APPLY=0
DO_DIST=0 DO_EXT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --keep)  KEEP="${2:?}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --dist)  DO_DIST=1; shift ;;
    --ext)   DO_EXT=1; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "unknown arg: $1 (see --help)" >&2; exit 2 ;;
  esac
done
[ "$DO_DIST" = 0 ] && [ "$DO_EXT" = 0 ] && { DO_DIST=1; DO_EXT=1; }  # neither => both
case "$KEEP" in ''|*[!0-9]*) echo "--keep takes a non-negative integer" >&2; exit 2 ;; esac

DOOMED=()
KEPT_UNMANAGED=()

# The one grep that reads a manifest: pull a filename out of a JSON string value. Deliberately
# tolerant (any "…/name.ext" or "name.ext") — a manifest we cannot parse must protect MORE, not
# less, so a miss here can only ever leave extra files behind.
refs_in() {
  [ -f "$1" ] || return 0
  grep -oE '"[^"]*\.(apk|zip|xpi)"' "$1" | tr -d '"' | sed 's#.*/##'
}

is_referenced() {
  local name="$1" r
  for r in "${REFERENCED[@]:-}"; do [ "$r" = "$name" ] && return 0; done
  return 1
}

plan_dir() { # plan_dir <dir> <label> — everything not classified by the caller is left alone
  local dir="$1"
  [ -d "$dir" ] || return 0
  local f
  for f in "$dir"/*; do
    [ -e "$f" ] || continue
    case " ${CLASSIFIED[*]:-} " in *" $f "*) continue ;; esac
    KEPT_UNMANAGED+=("$f")
  done
}

human() { # bytes → human, without depending on numfmt
  awk -v b="$1" 'BEGIN{s="B KiB MiB GiB";split(s,u," ");i=1;while(b>=1024&&i<4){b/=1024;i++}printf "%.1f %s", b, u[i]}'
}

REFERENCED=()
CLASSIFIED=()

# ------------------------------- dist/ (Android APKs) -------------------------------
if [ "$DO_DIST" = 1 ] && [ -d "$REPO_DIR/dist" ]; then
  echo "==> dist/ — keep newest $KEEP per variant"
  while read -r n; do [ -n "$n" ] && REFERENCED+=("$n"); done < <(
    refs_in "$REPO_DIR/dist/latest.json"; refs_in "$REPO_DIR/dist/latest-debug.json"
  )
  for variant in release debug; do
    # versionCode is the trailing integer and is monotonic (seconds since 2026-01-01), so a
    # numeric sort is the true build order — mtime is not (a restore/copy rewrites it).
    mapfile -t apks < <(
      ls -1 "$REPO_DIR/dist/Andvari-$variant-"*.apk 2>/dev/null |
        sed -E 's#.*/Andvari-'"$variant"'-([0-9]+)\.apk$#\1 &#' | sort -rn -k1,1 | cut -d' ' -f2- || true
    )
    [ "${#apks[@]}" -eq 0 ] && continue
    local_i=0
    for f in "${apks[@]}"; do
      CLASSIFIED+=("$f")
      local_i=$((local_i + 1))
      if [ "$local_i" -le "$KEEP" ] || is_referenced "$(basename "$f")"; then continue; fi
      DOOMED+=("$f")
    done
    echo "    $variant: ${#apks[@]} present"
  done
  plan_dir "$REPO_DIR/dist"
fi

# --------------------- extension/artifacts/ (store zips + signed XPIs) ---------------------
if [ "$DO_EXT" = 1 ] && [ -d "$REPO_DIR/extension/artifacts" ]; then
  echo "==> extension/artifacts/ — keep newest $KEEP versions"
  while read -r n; do [ -n "$n" ] && REFERENCED+=("$n"); done < <(refs_in "$REPO_DIR/extension/artifacts/firefox-updates.json")
  CUR_EXT=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$REPO_DIR/extension/manifest.json" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)

  # Group by the version embedded in the name; a version is kept or dropped whole, so a release's
  # chrome zip, firefox zip and signed XPI can never disagree about whether it still exists.
  mapfile -t vers < <(
    ls -1 "$REPO_DIR/extension/artifacts" 2>/dev/null |
      sed -nE 's#^andvari(-extension-(chrome|firefox))?-([0-9]+\.[0-9]+\.[0-9]+)\.(zip|xpi)$#\3#p' |
      sort -Vu -r || true
  )
  i=0
  for v in "${vers[@]}"; do
    mapfile -t files < <(ls -1 "$REPO_DIR/extension/artifacts/andvari"*"-$v".zip "$REPO_DIR/extension/artifacts/andvari"*"-$v".xpi 2>/dev/null || true)
    i=$((i + 1))
    for f in "${files[@]}"; do
      CLASSIFIED+=("$f")
      if [ "$i" -le "$KEEP" ] || [ "$v" = "$CUR_EXT" ] || is_referenced "$(basename "$f")"; then continue; fi
      DOOMED+=("$f")
    done
  done
  echo "    ${#vers[@]} versions present, current manifest declares ${CUR_EXT:-<unknown>}"
  plan_dir "$REPO_DIR/extension/artifacts"
fi

# ------------------------------------- report / act -------------------------------------
if [ "${#KEPT_UNMANAGED[@]}" -gt 0 ]; then
  echo "==> not managed by this tool (left alone — move or delete by hand):"
  for f in "${KEPT_UNMANAGED[@]}"; do echo "    ${f#"$REPO_DIR"/}"; done
fi

if [ "${#DOOMED[@]}" -eq 0 ]; then
  echo "==> nothing to prune at --keep $KEEP."
  exit 0
fi

BYTES=0
for f in "${DOOMED[@]}"; do BYTES=$((BYTES + $(stat -c%s "$f"))); done
echo "==> ${#DOOMED[@]} file(s), $(human "$BYTES") reclaimable:"
for f in "${DOOMED[@]}"; do echo "    ${f#"$REPO_DIR"/}"; done

if [ "$APPLY" != 1 ]; then
  echo "==> DRY RUN — nothing deleted. Re-run with --apply to remove the files above."
  exit 0
fi
for f in "${DOOMED[@]}"; do rm -f -- "$f"; done
echo "==> removed ${#DOOMED[@]} file(s), $(human "$BYTES") reclaimed."
