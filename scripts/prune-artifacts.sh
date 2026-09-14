#!/usr/bin/env bash
# Prune the append-only build-artifact directories — dist/ (Android APKs) and
# extension/artifacts/ (store zips + signed XPIs). Both are gitignored working dirs that every
# release only ever ADDS to, so they grow without bound (dist/ reached 2.1 GB / 41 APKs).
#
#   scripts/prune-artifacts.sh [--keep N] [--dist|--ext] [--apply]
#   scripts/prune-artifacts.sh --downloads [--keep-releases N] [--apply]
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
#
# --downloads: the SERVED directory on the instance (audit H107)
# --------------------------------------------------------------
# The two directories above are private build dirs. The reference instance's `/downloads` is a
# PUBLIC, guessable-URL directory that had no retention rule at all: every publish step only ever
# added to it, so it accumulated every deb since 0.6.0 (including unsigned pre-0.19.1 ones), the
# known-broken 0.26.2 MSI, two still-valid signed manifest pairs from seq 3-4, and ad-hoc
# `manifest.json.*` backups made in place — 4.6 GB on a 16 GB rootfs. Nothing ever forced a
# cleanup because the signed-update clients are unaffected by it (fixed path + anti-rollback
# floors), which is exactly why it needed a written rule rather than a habit.
#
# THE RULE, encoded below:
#   1. Anything the LIVE signed manifest or firefox-updates.json points at is untouchable. The
#      live manifest is fetched from the instance and is the authority; if it cannot be read, the
#      run aborts rather than guessing (a manifest we cannot parse must protect MORE, not less).
#   2. Installers for the CURRENT and the PREVIOUS release stay reachable (--keep-releases, default
#      2). That is what a "the new one is broken, give me the last one" link needs, and it is the
#      only reason to serve an old installer from a public path at all. Older ones are pruned.
#   3. Operator manifest BACKUPS leave the web root. `manifest.json.<anything>` and
#      `manifest.json.sig.<anything>` are moved to $DL_BACKUP_DIR (a sibling directory the server
#      does not serve), never deleted — the durable archive lives on huginn under
#      ~/.andvari/manifest-archive, and these are a second copy, but they are ALSO a publicly
#      fetchable, still-validly-signed older manifest pair sitting next to the live one, which is
#      not something a public directory should offer.
#   4. Anything not recognised is listed and left alone, exactly as in the local modes.
#
# It runs the reads and the moves inside the container over ssh; it is DRY-RUN by default like
# everything else here, and --apply is a separate, deliberate act.
#
# ANDVARI_DOWNLOADS_EXEC is REQUIRED for --downloads and has no default: the command prefix that
# runs a shell on your instance, e.g. `ssh you@host docker exec -i andvari` or
# `ssh you@host pct exec <ctid> --`. This repo is public, so no host of anyone's is baked in
# (R29). ANDVARI_DOWNLOADS_DIR (the served directory's path) exists for the self-test only
# (scripts/ci/prune-downloads.test.sh) and should not be set in production.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEEP=5
KEEP_RELEASES=2          # --downloads: "current + previous" is the rule; this is that 2.
APPLY=0
DO_DIST=0 DO_EXT=0 DO_DL=0

# How --downloads reaches the served directory. NO DEFAULT, deliberately (R29): this repo is
# public, and a baked `ssh root@<address> pct exec <ctid>` would be the only host-specific literal
# in scripts/ — the pattern every sibling avoids (signandvari.ps1 takes its drop host from
# $env:ANDVARI_RELEASE_DROP; prestige-release.ps1: "Nothing host-specific is baked into this public
# repo"). The doc-leak gate could not have caught it either: its scope is docs, not scripts. It is
# also the safer shape on its own merits — a --downloads run that reaches a host by accident is a
# remote mutation nobody asked for, and an operator naming the prefix has said where it goes.
DL_EXEC="${ANDVARI_DOWNLOADS_EXEC:-}"
DL_DIR="${ANDVARI_DOWNLOADS_DIR:-/opt/andvari/downloads}"
DL_BACKUP_DIR="${ANDVARI_DOWNLOADS_BACKUP_DIR:-/opt/andvari/manifest-backups}"

while [ $# -gt 0 ]; do
  case "$1" in
    --keep)  KEEP="${2:?}"; shift 2 ;;
    --keep-releases) KEEP_RELEASES="${2:?}"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --dist)  DO_DIST=1; shift ;;
    --ext)   DO_EXT=1; shift ;;
    --downloads) DO_DL=1; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "unknown arg: $1 (see --help)" >&2; exit 2 ;;
  esac
done
# Neither local mode named => both. --downloads is NEVER implied: it talks to another host, and a
# default that reaches over the network is not a default anyone should get by accident.
[ "$DO_DIST" = 0 ] && [ "$DO_EXT" = 0 ] && [ "$DO_DL" = 0 ] && { DO_DIST=1; DO_EXT=1; }
case "$KEEP" in ''|*[!0-9]*) echo "--keep takes a non-negative integer" >&2; exit 2 ;; esac
case "$KEEP_RELEASES" in ''|*[!0-9]*) echo "--keep-releases takes a non-negative integer" >&2; exit 2 ;; esac
[ "$KEEP_RELEASES" -ge 1 ] || { echo "--keep-releases must be at least 1 — the live release's installers are never pruned" >&2; exit 2; }

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

# ----------------------------- /downloads on the instance -----------------------------
if [ "$DO_DL" = 1 ]; then
  echo "==> $DL_DIR (served, public) — keep everything the live manifest references + the newest $KEEP_RELEASES release(s) per track"

  [ -n "$DL_EXEC" ] || {
    cat >&2 <<'EOM'
    --downloads needs ANDVARI_DOWNLOADS_EXEC: the command prefix that runs a shell on the
    instance. There is deliberately no default — this is a public repo and the prefix names
    your host. Examples:

      ANDVARI_DOWNLOADS_EXEC='ssh you@host docker exec -i andvari'
      ANDVARI_DOWNLOADS_EXEC='ssh you@host pct exec <ctid> --'

    Record the real prefix wherever your other release credentials live, not here.
EOM
    exit 2
  }
  # Word-split on purpose: this is a command PREFIX ("ssh host pct exec 122 --"), not one word.
  # shellcheck disable=SC2206
  DL_EXEC_ARGV=( $DL_EXEC )
  dl_sh() { "${DL_EXEC_ARGV[@]}" sh -c "$1"; }

  DL_LIST="$(dl_sh "ls -1A -- '$DL_DIR'")" \
    || { echo "    cannot list $DL_DIR — instance unreachable, or the container path is wrong. Nothing done." >&2; exit 1; }
  # The live manifest is the authority for rule 1. Not being able to read it is a STOP, not a
  # licence to guess: the whole point of the rule is that we never delete a file a client can
  # still be told to fetch.
  DL_MANIFEST="$(dl_sh "cat -- '$DL_DIR/manifest.json'")" \
    || { echo "    cannot read $DL_DIR/manifest.json — refusing to prune a directory whose live references are unknown." >&2; exit 1; }
  DL_FFUPD="$(dl_sh "cat -- '$DL_DIR/firefox-updates.json' 2>/dev/null" || true)"

  # Referenced = every artifact filename appearing in either live document, plus the documents
  # themselves. Same deliberately-tolerant extraction as refs_in(): over-matching only ever
  # protects more.
  DL_REFERENCED=$'manifest.json\nmanifest.json.sig\nfirefox-updates.json\n'
  # `|| true` on both greps below: "no match" is exit 1, and under `set -e -o pipefail` a
  # legitimately-empty result would abort the run. An empty reference set is a real state (a
  # manifest naming nothing) and it must degrade to "protect nothing extra", not to a crash.
  DL_REFERENCED+="$(printf '%s\n%s\n' "$DL_MANIFEST" "$DL_FFUPD" \
                      | grep -oE '"[^"]*\.(apk|zip|xpi|deb|msi|asc)"' | tr -d '"' | sed 's#.*/##' | sort -u || true)"
  dl_is_referenced() { printf '%s\n' "$DL_REFERENCED" | grep -qxF "$1"; }

  DL_MOVE=() DL_DELETE=() DL_UNMANAGED=() DL_KEEP=()
  DL_FLEET_VERS=() DL_EXT_VERS=()

  # Pass 1 — classify every entry and collect the version sets.
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    # Anything with a character outside this set is never named in a command we build. It is
    # reported and left alone; a public directory should not contain such a name anyway.
    if ! [[ "$f" =~ ^[A-Za-z0-9._-]+$ ]]; then DL_UNMANAGED+=("$f"); continue; fi
    case "$f" in
      manifest.json|manifest.json.sig|firefox-updates.json) DL_KEEP+=("$f"); continue ;;
      # Rule 3 — an operator's in-place backup of the signed pair. Note the ordering: the
      # manifest.json.sig.* pattern has to be tested BEFORE manifest.json.* or the sig backups
      # fall into the wrong bucket (they would still be moved, but the report would lie).
      manifest.json.sig.*|manifest.json.*) DL_MOVE+=("$f"); continue ;;
    esac
    if [[ "$f" =~ ^andvari-extension-(chrome|firefox)-([0-9]+\.[0-9]+\.[0-9]+)\.(zip|xpi)$ ]]; then
      DL_EXT_VERS+=("${BASH_REMATCH[2]}")
    elif [[ "$f" =~ ^andvari-([0-9]+\.[0-9]+\.[0-9]+)\.(deb|msi|apk)(\.asc)?$ ]]; then
      DL_FLEET_VERS+=("${BASH_REMATCH[1]}")
    else
      DL_UNMANAGED+=("$f")
    fi
  done <<< "$DL_LIST"

  # The newest KEEP_RELEASES versions on each track survive whole: a release's deb, its signature
  # and its MSI are kept or dropped together, so /downloads can never offer half a release.
  # `|| true` again, and it is load-bearing here: an EMPTY track (no extension artifacts served at
  # all) makes the pipeline exit 1, which would have aborted the whole run before any of the
  # fleet-track work was applied. An absent track means an empty keep-set, nothing more.
  dl_keepset() { printf '%s\n' "$@" | grep -v '^$' | sort -Vur | head -n "$KEEP_RELEASES" || true; }
  DL_FLEET_KEEP="$(dl_keepset ${DL_FLEET_VERS+"${DL_FLEET_VERS[@]}"} || true)"
  DL_EXT_KEEP="$(dl_keepset ${DL_EXT_VERS+"${DL_EXT_VERS[@]}"} || true)"

  # Pass 2 — decide, now that the keep-sets exist.
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [[ "$f" =~ ^[A-Za-z0-9._-]+$ ]] || continue
    v="" keepset=""
    if [[ "$f" =~ ^andvari-extension-(chrome|firefox)-([0-9]+\.[0-9]+\.[0-9]+)\.(zip|xpi)$ ]]; then
      v="${BASH_REMATCH[2]}"; keepset="$DL_EXT_KEEP"
    elif [[ "$f" =~ ^andvari-([0-9]+\.[0-9]+\.[0-9]+)\.(deb|msi|apk)(\.asc)?$ ]]; then
      v="${BASH_REMATCH[1]}"; keepset="$DL_FLEET_KEEP"
    else
      continue
    fi
    if dl_is_referenced "$f"; then DL_KEEP+=("$f")                       # rule 1 — live
    elif printf '%s\n' "$keepset" | grep -qxF "$v"; then DL_KEEP+=("$f") # rule 2 — current/previous
    else DL_DELETE+=("$f"); fi
  done <<< "$DL_LIST"

  echo "    ${#DL_KEEP[@]} kept, ${#DL_MOVE[@]} backup file(s) to move out of the web root, ${#DL_DELETE[@]} to delete, ${#DL_UNMANAGED[@]} not managed"
  [ -n "$DL_FLEET_KEEP" ] && echo "    fleet releases kept: $(printf '%s ' $DL_FLEET_KEEP)"
  [ -n "$DL_EXT_KEEP" ]   && echo "    extension releases kept: $(printf '%s ' $DL_EXT_KEEP)"
  for f in ${DL_MOVE+"${DL_MOVE[@]}"};      do echo "    MOVE   $f -> $DL_BACKUP_DIR/"; done
  for f in ${DL_DELETE+"${DL_DELETE[@]}"};  do echo "    DELETE $f"; done
  for f in ${DL_UNMANAGED+"${DL_UNMANAGED[@]}"}; do echo "    leave  $f (not a recognised artifact name)"; done

  if [ "${#DL_MOVE[@]}" -eq 0 ] && [ "${#DL_DELETE[@]}" -eq 0 ]; then
    echo "    nothing to do in $DL_DIR."
  elif [ "$APPLY" != 1 ]; then
    echo "==> DRY RUN — $DL_DIR untouched. Re-run with --apply."
  else
    # One remote invocation, `set -e`, moves before deletes: if the move half fails, nothing has
    # been deleted yet. Every name went through the charset check above, so single-quoting is
    # exact. mv -n rather than -f: a backup name that somehow already exists in the archive is a
    # collision worth stopping on, not one worth overwriting.
    cmd="set -e; mkdir -p '$DL_BACKUP_DIR'"
    for f in ${DL_MOVE+"${DL_MOVE[@]}"};     do cmd="$cmd; mv -n -- '$DL_DIR/$f' '$DL_BACKUP_DIR/$f'"; done
    for f in ${DL_DELETE+"${DL_DELETE[@]}"}; do cmd="$cmd; rm -f -- '$DL_DIR/$f'"; done
    dl_sh "$cmd" || { echo "    remote prune FAILED — re-run to reconcile; the operations are idempotent." >&2; exit 1; }
    echo "==> moved ${#DL_MOVE[@]}, deleted ${#DL_DELETE[@]} in $DL_DIR."
  fi
fi

# ------------------------------------- report / act -------------------------------------
if [ "${#KEPT_UNMANAGED[@]}" -gt 0 ]; then
  echo "==> not managed by this tool (left alone — move or delete by hand):"
  for f in "${KEPT_UNMANAGED[@]}"; do echo "    ${f#"$REPO_DIR"/}"; done
fi

if [ "${#DOOMED[@]}" -eq 0 ]; then
  { [ "$DO_DIST" = 1 ] || [ "$DO_EXT" = 1 ]; } && echo "==> nothing to prune at --keep $KEEP."
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
