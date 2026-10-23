#!/usr/bin/env bash
# shellcheck disable=SC2016  # the matcher's self-check lines are literal shell and markdown text
# Tests for the self-host deploy kit (security review 2026-10). No fixtures, no docker, no network:
# section 1 reads the live tree, section 2 runs the real entrypoint's functions against a scratch
# directory with the two root-only calls stubbed.
#
#   1. Every `docker run … recovery-cli` in deploy/ or docs/ passes `--log-driver none` before the
#      image name. recovery-cli keygen prints the org recovery SEED and recover prints a member's
#      temporary password; docker copies a container's stdout to the daemon's log driver even when
#      the run is attached, so without the flag the seed lands in json-file logs, the journal or a
#      log shipper (`--network none` stops only the container itself from sending data).
#   2. The entrypoint's server start leaves /data owner-only: the directory 0700, any existing
#      database file (-wal/-shm included) 0600, and umask 077 in force when the server is exec'd,
#      so the files SQLite and the server create later are 0600 too. bringup.sh creates ./data
#      0700 before the first `compose up` instead of letting docker create it 0755.
#
# DEPLOY_SRC=<dir> runs section 2 against another copy of deploy/ (used to show it failing against
# the pre-fix entrypoint). Needs: sh (dash or another POSIX sh), stat, mktemp.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY="${DEPLOY_SRC:-$ROOT/deploy}"
FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# ============================================== 1. recovery-cli never runs with a log driver ====
echo "==> deploy: every docker run of recovery-cli in deploy/ and docs/ passes --log-driver none"

# logical_lines <file> — the file with backslash-continued lines joined, each prefixed "<line>:".
logical_lines() {
  awk '{ if (buf == "") start = NR
         if (sub(/\\[[:space:]]*$/, "")) { buf = buf $0 " "; next }
         print start ":" buf $0; buf = "" }
       END { if (buf != "") print start ":" buf }' "$1"
}

# A run of recovery-cli: `docker run` or `docker container run`, any options, then recovery-cli.
RUN_RE='docker[[:space:]]+(container[[:space:]]+)?run[[:space:]][^`]*recovery-cli'
# ...and the flag must come BEFORE recovery-cli: an option after the image name is an argument to
# the container's command, not to docker.
SAFE_RE='docker[[:space:]]+(container[[:space:]]+)?run[[:space:]][^`]*--log-driver[[:space:]=]+none([[:space:]][^`]*)?[[:space:]]recovery-cli'

# The matcher's own self-check, so a narrowed pattern cannot pass the tree vacuously.
check_line() { printf '%s\n' "$1" | grep -qE "$RUN_RE" || return 2; printf '%s\n' "$1" | grep -qE "$SAFE_RE"; }
expect() {
  local want="$1" line="$2" got=0
  check_line "$line" || got=$?
  [ "$got" = "$want" ] || fail "matcher self-check: wanted $want, got $got for: $line"
}
expect 1 'SHEET="$(docker run --rm --network none "$IMAGE" recovery-cli keygen)"'
expect 0 'SHEET="$(docker run --rm --network none --log-driver none "$IMAGE" recovery-cli keygen)"'
expect 0 '`docker run --rm --log-driver=none --network none ghcr.io/x/andvari:latest recovery-cli keygen`'
expect 1 '`docker run --rm --log-driver json-file ghcr.io/x/andvari:latest recovery-cli keygen`'
expect 1 '`docker container run --rm ghcr.io/x/andvari:1 recovery-cli recover --log-driver none`'
expect 2 'docker compose up -d'
joined="$(printf 'docker run --rm \\\n  --network none \\\n  img recovery-cli keygen\n' > "$W/cont.sh"; logical_lines "$W/cont.sh")"
expect 1 "${joined#*:}"

found=0; bad=0
while IFS= read -r -d '' f; do
  while IFS= read -r ll; do
    lineno="${ll%%:*}"; text="${ll#*:}"
    rc=0; check_line "$text" || rc=$?
    case "$rc" in
      0) found=$((found + 1)) ;;
      1) found=$((found + 1)); bad=$((bad + 1)); fail "${f#"$ROOT"/}:$lineno runs recovery-cli without --log-driver none before the image" ;;
    esac
  done < <(logical_lines "$f")
done < <(find "$ROOT/deploy" "$ROOT/docs" -type f \( -name '*.sh' -o -name '*.md' -o -name '*.yml' -o -name '*.template' -o -name 'docker-entrypoint.sh' \) -print0)
# bringup.sh's ceremony, the entrypoint's usage line and the two in self-hosting.md: four today.
if [ "$found" -lt 4 ]; then
  fail "found only $found docker-run recovery-cli invocations in deploy/ + docs/ (expected 4+) — did the matcher stop matching?"
elif [ "$bad" = 0 ]; then
  echo "    $found invocation(s), every one with --log-driver none"
fi

# ======================================================= 2. /data is owner-only at start ======
echo "==> deploy: the entrypoint leaves /data 0700, the database 0600, and starts the server under umask 077"
D="$W/data"
mkdir -m 755 "$D"
for f in andvari.db andvari.db-wal andvari.db-shm; do : > "$D/$f"; chmod 644 "$D/$f"; done
# The real entrypoint, sourced as a library: chown is stubbed (there is no `andvari` account on a
# build host) and drop_priv records the umask the server would inherit, then creates what the
# server creates on its first write (a fresh -journal and the blob directory with one file).
# `set -- false` first: an entrypoint without the library guard falls through to its dispatch, and
# this makes that dispatch exec `false` (a FAIL here) rather than start anything or touch /data.
if sh -c '
  set -eu
  E="$1"; T="$2"; set -- false
  ANDVARI_ENTRYPOINT_LIB=1; export ANDVARI_ENTRYPOINT_LIB
  . "$E"
  chown() { :; }
  drop_priv() { umask > "$T/umask.seen"; : > "$T/data/andvari.db-journal"; mkdir "$T/data/blobs"; : > "$T/data/blobs/a1"; }
  start_server "$T/data"
' entrypoint "$DEPLOY/docker-entrypoint.sh" "$W" > "$W/entry.log" 2>&1; then
  mode() { stat -c %a "$1" 2>/dev/null || echo missing; }
  [ "$(mode "$D")" = 700 ] || fail "/data is $(mode "$D"), want 700"
  for f in andvari.db andvari.db-wal andvari.db-shm; do
    [ "$(mode "$D/$f")" = 600 ] || fail "existing $f is $(mode "$D/$f"), want 600"
  done
  [ "$(cat "$W/umask.seen" 2>/dev/null)" = 0077 ] || fail "the server starts under umask $(cat "$W/umask.seen" 2>/dev/null || echo '?'), want 0077"
  [ "$(mode "$D/andvari.db-journal")" = 600 ] || fail "a file the server creates is $(mode "$D/andvari.db-journal"), want 600"
  [ "$(mode "$D/blobs")" = 700 ] || fail "a directory the server creates is $(mode "$D/blobs"), want 700"
else
  sed 's/^/      /' "$W/entry.log" >&2
  fail "the entrypoint could not be sourced as a library and started against a scratch /data (no start_server?)"
fi

# bringup.sh creates ./data owner-only before the first `compose up -d`.
B="$DEPLOY/bringup.sh"
mk=$(grep -nE 'mkdir[[:space:]]+-m[[:space:]]*0?700[[:space:]]+("?\./)?data"?' "$B" | head -1 | cut -d: -f1)
up=$(grep -nE '^[[:space:]]*compose[[:space:]]+up[[:space:]]+-d' "$B" | head -1 | cut -d: -f1)
if [ -z "$mk" ] || [ -z "$up" ] || [ "$mk" -ge "$up" ]; then
  fail "bringup.sh must create ./data with mkdir -m 700 before 'compose up -d' (mkdir line ${mk:-none}, up line ${up:-none})"
fi

if [ "$FAILED" = 0 ]; then echo "    deploy-hardening: all checks passed"; fi
exit "$FAILED"
