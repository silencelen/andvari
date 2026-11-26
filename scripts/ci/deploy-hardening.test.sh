#!/usr/bin/env bash
# shellcheck disable=SC2016  # the matcher's self-check lines are literal shell and markdown text
# Tests for the self-host deploy kit (security review 2026-10). No fixtures, no docker, no network:
# section 1 reads the live tree, section 2 runs the real entrypoint's functions and its `setup` and
# `admin` branches against a scratch directory with the root-only calls stubbed.
#
#   1. Every `docker run … recovery-cli` in deploy/, docs/, the Dockerfile, .github/ or any other
#      repo-root file passes `--log-driver none` before the image name (the Dockerfile's own header
#      example once missed the flag, which is why the root files and the workflows are read too), and
#      none of them but the dated design records documents a `docker compose run` of recovery-cli:
#      `compose run` has no per-run log-driver option, so what the container prints goes to the
#      service's logging, json-file by default. recovery-cli keygen prints the org recovery SEED, and
#      assist asks for it at its prompt; docker copies a container's stdout to the daemon's log driver even when
#      the run is attached, so without the flag the seed lands in json-file logs, the journal or a
#      log shipper (`--network none` stops only the container itself from sending data).
#   2. The entrypoint's server start leaves /data owner-only: the directory 0700, any existing
#      database file (-wal/-shm included) 0600, and umask 077 in force when the server is exec'd,
#      so the files SQLite and the server create later are 0600 too. Its `setup` branch is the
#      bring-up (`andvari setup` writes andvari.env, creates the database and mints the setup link)
#      and `admin` runs the host commands on that database: both prepare /data the same way before
#      the command runs, so a bind-mounted ./data that docker created 0755 on the host is 0700
#      before the first database is written into it. A chmod that fails (a read-only or
#      root-squashed mount) warns and carries on in the root branch as it does in the non-root one,
#      rather than killing the entrypoint under `set -e`.
#   3. docs/self-hosting.md does not call the database harmless to a thief (it holds the TOTP seeds
#      and login verifiers), and says what rootless docker means for the data folder's owner on the
#      host.
#   4. Every `docker run` of `setup` or `admin` in andvari.env.template, docs/self-hosting.md and
#      the Dockerfile's header mounts the folder docker-compose.yml mounts at /data, so setup, the
#      host commands and the server use one database; setup writes andvari.env into that folder (the
#      one the container's user may write), and the template and the guide move it to where Compose
#      reads it; every such line that prints a link (the setup link, an enrol link) passes
#      `--log-driver none` before the image; a line that reads an --env-file outside /data mounts a
#      file there, and `admin signup`, which rewrites it, not read-only. docker-compose.yml publishes
#      the app's port on 127.0.0.1 unless ANDVARI_BIND says otherwise, and every ANDVARI_* name the
#      template names is in Config.kt's KNOWN_ENV.
#   5. The nightly snapshot is the server's own command, `andvari admin backup` (its tests are in the
#      server's suite): neither docs/self-hosting.md nor a file under deploy/ names a host script
#      backup.sh. The snapshot runs inside the server's running container (`docker compose exec`), so
#      no snapshot is taken while the server is stopped, as the server's user and without a terminal:
#      every line of the guide, README.md and deploy/ that runs it is that one line, character for
#      character, and docker-compose.yml mounts the settings file the line names.
#   6. scripts/publish-image.sh takes only a version of three numbers without leading zeros, and its
#      plan pushes the image under that one tag: no `latest`, no shorter or second tag.
#   7. The Dockerfile's licence label names the licences of what the image holds, as LICENSING.md
#      splits them: AGPL-3.0-or-later AND GPL-3.0-or-later.
#
# DEPLOY_SRC=<dir> runs sections 1, 2 and 5 against another copy of deploy/, and HARDENING_ROOT=<dir>
# reads the docs, the Dockerfile and the root files of another tree (both used to show the checks
# failing against a broken copy). Needs: sh (dash or another POSIX sh), awk, sed, stat, mktemp and
# find.
set -uo pipefail

ROOT="${HARDENING_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DEPLOY="${DEPLOY_SRC:-$ROOT/deploy}"
FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# ============================================== 1. recovery-cli never runs with a log driver ====
echo "==> deploy: every docker run of recovery-cli in deploy/, docs/, the Dockerfile, .github/ and root files passes --log-driver none"

# logical_lines <file> — the file with backslash-continued lines joined, each prefixed "<line>:".
# Only lines that mention both docker and recovery-cli are printed: the scan forks per printed
# line, and docs/ holds tens of thousands of lines that can never match.
logical_lines() {
  awk '{ if (buf == "") start = NR
         if (sub(/\\[[:space:]]*$/, "")) { buf = buf $0 " "; next }
         l = buf $0; buf = ""
         if (l ~ /docker/ && l ~ /recovery-cli/) print start ":" l }
       END { if (buf != "" && buf ~ /docker/ && buf ~ /recovery-cli/) print start ":" buf }' "$1"
}

# A run of recovery-cli: `docker run` or `docker container run`, any options, then recovery-cli.
RUN_RE='docker[[:space:]]+(container[[:space:]]+)?run[[:space:]][^`]*recovery-cli'
# ...and the flag must come BEFORE recovery-cli: an option after the image name is an argument to
# the container's command, not to docker.
SAFE_RE='docker[[:space:]]+(container[[:space:]]+)?run[[:space:]][^`]*--log-driver[[:space:]=]+none([[:space:]][^`]*)?[[:space:]]recovery-cli'
# A compose run of recovery-cli (`docker compose …` or `docker-compose …`, any global options before
# `run`): never safe, since `compose run` cannot turn the log driver off for one run. It answers 3,
# so the scan can leave the dated design records under docs/design/ out of this one rule: they
# describe what was planned on their date (one planned the bring-up's ceremony this way) and are
# history, not instructions, as doc-leak-scan.sh states for them too.
COMPOSE_RUN_RE='docker([[:space:]]+|-)compose[[:space:]]([^`]*[[:space:]])?run[[:space:]][^`]*recovery-cli'

# The matcher's own self-check, so a narrowed pattern cannot pass the tree vacuously.
# check_line answers 0 (a safe docker run), 1 (a docker run without the flag before the image),
# 2 (no run of recovery-cli at all) or 3 (a compose run of recovery-cli).
check_line() {
  if printf '%s\n' "$1" | grep -qE "$COMPOSE_RUN_RE"; then return 3; fi
  printf '%s\n' "$1" | grep -qE "$RUN_RE" || return 2
  printf '%s\n' "$1" | grep -qE "$SAFE_RE"
}
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
expect 3 '`docker compose run --rm andvari recovery-cli keygen`'
expect 3 'docker-compose -f deploy/docker-compose.yml run --rm --no-deps andvari recovery-cli keygen'
expect 3 'docker compose -f docker-compose.yml -f docker-compose.caddy.yml run --rm andvari recovery-cli keygen'
expect 2 'docker compose up -d'
expect 2 '`docker compose run --rm andvari setup --origin https://vault.example.org`'
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
      3) case "${f#"$ROOT"/}" in
           docs/design/*) ;;
           *) bad=$((bad + 1)); fail "${f#"$ROOT"/}:$lineno runs recovery-cli through docker compose run, which cannot turn the log driver off: use docker run --rm --network none --log-driver none <image> recovery-cli" ;;
         esac ;;
    esac
  done < <(logical_lines "$f")
done < <(
  find "$DEPLOY" "$ROOT/docs" -type f \( -name '*.sh' -o -name '*.md' -o -name '*.yml' -o -name '*.template' -o -name 'docker-entrypoint.sh' \) -print0
  # The Dockerfile header documents the ceremony too, and so may any other root file (README,
  # SECURITY, CONTRIBUTING, …) or a workflow. Every regular file at the root is read.
  find "$ROOT" -maxdepth 1 -type f -print0
  [ -d "$ROOT/.github" ] && find "$ROOT/.github" -type f \( -name '*.yml' -o -name '*.yaml' -o -name '*.md' \) -print0
)
grep -q 'recovery-cli' "$ROOT/Dockerfile" || fail "the Dockerfile no longer mentions recovery-cli — re-check what the scan above is for"
# The entrypoint's usage line, the two in self-hosting.md (the recovery key of the install's operator
# recovery and the day-2 recovery note) and the Dockerfile's header: four since `andvari setup`
# replaced the bring-up script, whose own ceremony was the fifth.
if [ "$found" -lt 4 ]; then
  fail "found only $found docker-run recovery-cli invocations (expected 4+) — did the matcher stop matching?"
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

# The ROOT branch's chmod is guarded like the non-root one. Forced here (id answers 0, chown and
# chmod are stubbed to fail on the data directory): the entrypoint must warn and still start the
# server under umask 077, not die under set -e.
R="$W/rootdata"; mkdir -m 755 "$R"
if sh -c '
  set -eu
  E="$1"; T="$2"; set -- false
  ANDVARI_ENTRYPOINT_LIB=1; export ANDVARI_ENTRYPOINT_LIB
  . "$E"
  id() { echo 0; }
  chown() { :; }
  chmod() { case "$2" in "$T/rootdata") return 1 ;; *) command chmod "$@" ;; esac; }
  drop_priv() { umask > "$T/root-umask.seen"; }
  start_server "$T/rootdata"
' entrypoint "$DEPLOY/docker-entrypoint.sh" "$W" > "$W/root.log" 2>&1; then
  [ "$(cat "$W/root-umask.seen" 2>/dev/null)" = 0077 ] || fail "after a failed chmod as root the server did not start under umask 077"
  grep -q "WARN" "$W/root.log" || fail "a failed chmod as root was not reported (no WARN line)"
else
  sed 's/^/      /' "$W/root.log" >&2
  fail "a failed chmod 700 in the entrypoint's ROOT branch killed it under set -e — guard it like the non-root branch"
fi

# `setup` (the bring-up, which writes the first database) and `admin` (the host commands) make /data
# owner-only before the command runs. Each branch is run as the entrypoint holds it: the case arm
# that names the command is read out of the file, its /data pointed at a scratch directory that
# docker would have created 0755 (with a database an older image left 0644), and run after the
# file's functions with chown stubbed and drop_priv recording the umask and the command it would
# exec. A `java` or `setpriv` reached any other way finds only a recorder on PATH, never the real one.
echo "==> deploy: the entrypoint's setup and admin branches make /data 0700 and the database 0600 before the command runs, under umask 077"
# arm_of <command> — the body of the dispatch's case arm whose pattern list names <command>.
arm_of() {
  awk -v cmd="$1" '
    !on && /^[[:space:]]*[a-z|-]+\)[[:space:]]*$/ {
      label = $0; gsub(/[[:space:])]/, "", label)
      n = split(label, names, "|")
      for (i = 1; i <= n; i++) if (names[i] == cmd) { on = 1; next }
    }
    on && /^[[:space:]]*;;[[:space:]]*$/ { exit }
    on { print }
  ' "$DEPLOY/docker-entrypoint.sh"
}
mkdir -p "$W/shim"
for b in java setpriv; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/direct-exec.seen"\nexit 1\n' "$b" "$W" > "$W/shim/$b"
  chmod 755 "$W/shim/$b"
done
for cmd in setup admin; do
  S="$W/$cmd-data"; mkdir -m 755 "$S"
  for f in andvari.db andvari.db-wal; do : > "$S/$f"; chmod 644 "$S/$f"; done
  arm="$(arm_of "$cmd")"
  if [ -z "$arm" ]; then
    fail "the entrypoint has no case arm for '$cmd' (the dispatch would exec it verbatim, with /data as docker left it)"
    continue
  fi
  printf '%s\n' "$arm" | grep -q '/data' || { fail "the entrypoint's '$cmd' arm never names /data — re-check what this test is for"; continue; }
  arm="$(printf '%s\n' "$arm" | sed "s#/data#$S#g")"
  if env -u ANDVARI_DB PATH="$W/shim:$PATH" sh -c '
    set -eu
    E="$1"; T="$2"; C="$3"; ARM="$4"; shift 4
    ANDVARI_ENTRYPOINT_LIB=1; export ANDVARI_ENTRYPOINT_LIB
    . "$E"
    chown() { :; }
    drop_priv() { umask > "$T/$C-umask.seen"; printf "%s\n" "$*" > "$T/$C-exec.seen"; }
    eval "$ARM"
  ' entrypoint "$DEPLOY/docker-entrypoint.sh" "$W" "$cmd" "$arm" "$cmd" --env-file /conf/andvari.env > "$W/$cmd.log" 2>&1; then
    mode() { stat -c %a "$1" 2>/dev/null || echo missing; }
    [ "$(mode "$S")" = 700 ] || fail "after the entrypoint's '$cmd' branch /data is $(mode "$S"), want 700"
    for f in andvari.db andvari.db-wal; do
      [ "$(mode "$S/$f")" = 600 ] || fail "after the entrypoint's '$cmd' branch the existing $f is $(mode "$S/$f"), want 600"
    done
    [ "$(cat "$W/$cmd-umask.seen" 2>/dev/null)" = 0077 ] \
      || fail "the entrypoint's '$cmd' branch runs its command under umask $(cat "$W/$cmd-umask.seen" 2>/dev/null || echo '? (drop_priv never called)'), want 0077"
    grep -q " $cmd --env-file /conf/andvari.env\$" "$W/$cmd-exec.seen" 2>/dev/null \
      || fail "the entrypoint's '$cmd' branch did not hand '$cmd' and its arguments to drop_priv (saw: $(cat "$W/$cmd-exec.seen" 2>/dev/null || echo nothing))"
  else
    sed 's/^/      /' "$W/$cmd.log" >&2
    fail "the entrypoint's '$cmd' branch failed against a scratch /data"
  fi
done
[ -e "$W/direct-exec.seen" ] && fail "a branch ran java or setpriv without drop_priv: $(cat "$W/direct-exec.seen")"

# ======================================================= 3. the operator docs say what is at stake ===
echo "==> deploy: self-hosting.md does not call the database harmless, and covers rootless docker"
SH="$ROOT/docs/self-hosting.md"
if tr '\n' ' ' < "$SH" | grep -qiE 'useless[[:space:]]+to[[:space:]]+a[[:space:]]+thief'; then
  fail "docs/self-hosting.md still calls a stolen backup useless to a thief, next to the note that the database holds TOTP seeds and login verifiers"
fi
grep -qi 'rootless' "$SH" || fail "docs/self-hosting.md does not say what rootless docker means for the data folder's owner on the host"

# ================================== 4. setup, the host commands and the server use one data folder ===
echo "==> deploy: every docker run of setup or admin mounts docker-compose.yml's data folder at /data, and the ones that print a link pass --log-driver none"
# The setup line once mounted a named volume at /data while docker-compose.yml mounts ./data, so the
# server started on another, empty database; it also wrote andvari.env into a folder of the host that
# the container's user (uid 10001) may not write. Setup writes the database and andvari.env into the
# data folder (which the entrypoint gives that user), and `mv` puts andvari.env where Compose reads it.
DC="$DEPLOY/docker-compose.yml"
TPL="$DEPLOY/andvari.env.template"
# The compose file's one mount of /data, as `- <source>:/data`.
compose_src="$(sed -n 's/^[[:space:]]*-[[:space:]]*"\{0,1\}\([^"[:space:]#]*\):\/data"\{0,1\}[[:space:]]*$/\1/p' "$DC")"
[ "$(printf '%s\n' "$compose_src" | grep -c .)" = 1 ] || fail "docker-compose.yml should mount exactly one host folder at /data (found: ${compose_src:-none})"
grep -qE '^[[:space:]]*env_file:[[:space:]]*andvari\.env[[:space:]]*$' "$DC" || fail "docker-compose.yml no longer reads env_file: andvari.env beside it"

# host_lines <file> — every logical line (comment marks stripped, backslash continuations joined) that
# runs docker, each prefixed "<line>:".
host_lines() {
  awk '{ l = $0; sub(/^[[:space:]]*#+[[:space:]]*/, "", l)
         if (buf == "") start = NR
         if (sub(/\\[[:space:]]*$/, "", l)) { buf = buf l " "; next }
         l = buf l; buf = ""
         if (l ~ /docker/) print start ":" l }' "$1"
}

# run_part <line> opts|rest — the docker options of a `docker run` (everything between `run` and the image), or
# everything after the image. An option after the image is an argument to the container's command, not to docker.
run_part() {
  printf '%s\n' "$1" | awk -v want="$2" '{
    n = split($0, t, /[[:space:]]+/); i = 1
    while (i <= n && t[i] != "run") i++
    i++; opts = ""
    while (i <= n && t[i] ~ /^-/) {
      opts = opts " " t[i]
      if (t[i] ~ /^(-v|--volume|-e|--env|--env-file|--log-driver|--log-opt|--network|--net|--mount|--name|-p|--publish|-w|--workdir|-u|--user|--entrypoint|--platform|-l|--label|-h|--hostname)$/) { i++; opts = opts " " t[i] }
      i++
    }
    rest = ""; for (j = i + 1; j <= n; j++) rest = rest " " t[j]
    print (want == "opts" ? opts : rest) " "
  }'
}

# check_data_line <line> <compose data source> answers 0 (it mounts that folder at /data and, where it prints a
# link, keeps it out of the logs), 1 (another folder or a named volume at /data, or none), 2 (it prints a link
# without --log-driver none before the image), 3 (no docker run of setup or admin), 4 (setup writes
# andvari.env outside the data folder, where the container's user may not write), 5 (it reads an --env-file
# outside /data that no -v mounts there), or 6 (`admin signup`, which rewrites andvari.env, mounts it read-only).
check_data_line() {
  local line="$1" want="$2" src opts rest envp mnt
  printf '%s\n' "$line" | grep -qE 'docker[[:space:]]+(container[[:space:]]+)?run[[:space:]].*[[:space:]](setup|admin)([[:space:]]|$)' || return 3
  src="$(printf '%s\n' "$line" | grep -oE -- '-v[[:space:]]+"?[^"[:space:]]+:/data"?([[:space:]]|$)' | sed -e 's/^-v[[:space:]]*"\{0,1\}//' -e 's/:\/data"\{0,1\}[[:space:]]*$//')"
  src="$(printf '%s\n' "$src" | sed -e 's#^\$PWD/#./#' -e 's#^\${PWD}/#./#')"
  [ -n "$src" ] && [ "$src" = "$want" ] || return 1
  opts="$(run_part "$line" opts)"; rest="$(run_part "$line" rest)"
  local prints=0
  if printf '%s\n' "$rest" | grep -qE '(^|[[:space:]])setup([[:space:]]|$)' && ! printf '%s\n' "$rest" | grep -qE -- '--status'; then prints=1; fi
  if printf '%s\n' "$rest" | grep -qE '(^|[[:space:]])admin[[:space:]]+(enrol-link|setup-link|reset-instance-identity)([[:space:]]|$)'; then prints=1; fi
  if [ "$prints" = 1 ]; then
    printf '%s\n' "$opts" | grep -qE -- '(^|[[:space:]])--log-driver([[:space:]]+|=)none[[:space:]]' || return 2
  fi
  if printf '%s\n' "$line" | grep -qE '[[:space:]]setup([[:space:]]|$)' && ! printf '%s\n' "$line" | grep -qE -- '--status|--reset-setup|--help'; then
    printf '%s\n' "$line" | grep -qE -- '--env-file[[:space:]=]+/data/' || return 4
  fi
  envp="$(printf '%s\n' "$rest" | grep -oE -- '--env-file([[:space:]]+|=)[^[:space:]]+' | head -n 1 | sed -E 's/^--env-file([[:space:]]+|=)//')"
  if [ -n "$envp" ] && [ "${envp#/data/}" = "$envp" ]; then
    # The -v mounts among docker's options, as <target>[:<mode>], quotes and the source dropped.
    mnt="$(printf '%s\n' "$opts" | grep -oE -- '(-v|--volume)[[:space:]]+"?[^"[:space:]]+"?' | sed -E -e 's/^(-v|--volume)[[:space:]]+"?//' -e 's/"$//' | awk -F: -v p="$envp" '$2 == p { print $2 ($3 == "" ? "" : ":" $3) }' | head -n 1)"
    [ -n "$mnt" ] || return 5
    if printf '%s\n' "$rest" | grep -qE '(^|[[:space:]])admin[[:space:]]+signup([[:space:]]|$)' && [ "${mnt%:ro}" != "$mnt" ]; then return 6; fi
  fi
  return 0
}
expect_data() {
  local want="$1" line="$2" got=0
  check_data_line "$line" ./data || got=$?
  [ "$got" = "$want" ] || fail "data-folder matcher self-check: wanted $want, got $got for: $line"
}
expect_data 1 'docker run --rm -it -v "$PWD:/conf" -v andvari-data:/data img:1 setup --env-file /conf/andvari.env --origin https://vault.example.org'
expect_data 2 'docker run --rm -v "$PWD/data:/data" img:1 setup --env-file /data/andvari.env --origin https://vault.example.org'
expect_data 4 'docker run --rm --log-driver none -v "$PWD:/conf" -v "$PWD/data:/data" img:1 setup --env-file /conf/andvari.env --origin https://vault.example.org'
expect_data 0 'docker run --rm --log-driver none -v "$PWD/data:/data" img:1 setup --env-file /data/andvari.env --origin https://vault.example.org'
expect_data 0 'docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" img:1 setup --status --env-file /andvari.env'
expect_data 2 'docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" img:1 admin enrol-link --email a@example.org --env-file /andvari.env'
expect_data 1 'docker run --rm --log-driver none -v ./other:/data img:1 admin enrol-link --env-file /andvari.env'
expect_data 3 'docker compose up -d'
expect_data 2 'docker run --rm -v "$PWD/data:/data" img:1 --log-driver none setup --env-file /data/andvari.env --origin https://vault.example.org'
expect_data 5 'docker run --rm --log-driver none -v "$PWD/data:/data" img:1 admin enrol-link --email a@example.org --env-file /andvari.env'
expect_data 5 'docker run --rm -v "$PWD/data:/data" img:1 setup --status --env-file /andvari.env -v "$PWD/andvari.env:/andvari.env:ro"'
expect_data 6 'docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env:ro" img:1 admin signup links --env-file /andvari.env'
expect_data 0 'docker run --rm -v "$PWD/data:/data" -v "$PWD/andvari.env:/andvari.env" img:1 admin signup links --env-file /andvari.env'

# The Dockerfile's header shows the same lines: it once mounted a named volume at /data and a /conf folder
# under the image's old name, the very fault this section was written for.
tpl_found=0; data_found=0; df_found=0
for f in "$TPL" "$ROOT/docs/self-hosting.md" "$ROOT/Dockerfile"; do
  while IFS= read -r ll; do
    lineno="${ll%%:*}"; text="${ll#*:}"
    rc=0; check_data_line "$text" "$compose_src" || rc=$?
    case "$rc" in
      0) data_found=$((data_found + 1)); [ "$f" = "$TPL" ] && tpl_found=$((tpl_found + 1)); [ "$f" = "$ROOT/Dockerfile" ] && df_found=$((df_found + 1)) ;;
      1) fail "${f#"$ROOT"/}:$lineno mounts another folder than docker-compose.yml's $compose_src at /data: $text" ;;
      2) fail "${f#"$ROOT"/}:$lineno prints a link without --log-driver none before the image: $text" ;;
      4) fail "${f#"$ROOT"/}:$lineno has setup write andvari.env outside the data folder, where the container's user may not write: $text" ;;
      5) fail "${f#"$ROOT"/}:$lineno reads an --env-file outside /data that no -v before the image mounts there: $text" ;;
      6) fail "${f#"$ROOT"/}:$lineno runs admin signup, which rewrites andvari.env, on a read-only mount of it: $text" ;;
    esac
  done < <(host_lines "$f")
done
[ "$tpl_found" -ge 1 ] || fail "andvari.env.template has no setup line that the check could read (expected one)"
[ "$df_found" -ge 1 ] || fail "the Dockerfile's header has no docker run of setup or admin that the check could read (expected one)"
[ "$data_found" -ge 2 ] || fail "found only $data_found docker runs of setup or admin (expected 2+) — did the matcher stop matching?"
grep -qE '^#?[[:space:]]*mv[[:space:]]+data/andvari\.env[[:space:]]+andvari\.env[[:space:]]*$' "$TPL" \
  || fail "andvari.env.template's setup no longer moves data/andvari.env to andvari.env, where docker-compose.yml reads it"
grep -qE '^mv[[:space:]]+data/andvari\.env[[:space:]]+andvari\.env[[:space:]]*$' "$SH" \
  || fail "docs/self-hosting.md's setup no longer moves data/andvari.env to andvari.env, where docker-compose.yml reads it"
[ "$FAILED" = 0 ] && echo "    $data_found docker run(s) of setup or admin, every one on $compose_src"

# The app's port is published on 127.0.0.1 unless the operator sets ANDVARI_BIND: every entry under a
# `ports:` of docker-compose.yml must start with ${ANDVARI_BIND:-127.0.0.1}: (a bare "8080:8080" publishes on
# every address of the host, in front of any TLS front).
port_entries() {
  awk '/^[[:space:]]*ports:[[:space:]]*$/ { inp = 1; next }
       inp && /^[[:space:]]*#/ { next }
       inp && /^[[:space:]]*-/ { l = $0; sub(/^[[:space:]]*-[[:space:]]*/, "", l); gsub(/"/, "", l); sub(/[[:space:]]+#.*$/, "", l); sub(/[[:space:]]*$/, "", l); print l; next }
       { inp = 0 }' "$1"
}
check_ports() {
  local entries e
  entries="$(port_entries "$1")"
  [ -n "$entries" ] || return 1
  while IFS= read -r e; do
    case "$e" in '${ANDVARI_BIND:-127.0.0.1}:'*) ;; *) return 1 ;; esac
  done <<< "$entries"
  return 0
}
printf 'services:\n  andvari:\n    ports:\n      - "${ANDVARI_BIND:-127.0.0.1}:${ANDVARI_HOST_PORT:-8080}:8080"\n' > "$W/ports-ok.yml"
printf 'services:\n  andvari:\n    ports:\n      - "8080:8080"\n' > "$W/ports-all.yml"
printf 'services:\n  andvari:\n    ports:\n      - "${ANDVARI_BIND:-127.0.0.1}:8080:8080"\n      - "0.0.0.0:8443:8443"\n' > "$W/ports-second.yml"
check_ports "$W/ports-ok.yml" || fail "port-line self-check: a 127.0.0.1 default was refused"
check_ports "$W/ports-all.yml" && fail "port-line self-check: \"8080:8080\" (every address) passed"
check_ports "$W/ports-second.yml" && fail "port-line self-check: a second port on 0.0.0.0 passed"
check_ports "$DC" || fail "docker-compose.yml publishes a port that does not default to 127.0.0.1 (each entry under ports: must start with \${ANDVARI_BIND:-127.0.0.1}:): $(port_entries "$DC" | tr '\n' ' ')"

# Every ANDVARI_* name the template names is one the server reads: the list is Config.kt's own KNOWN_ENV, read
# here, so a renamed or invented variable in the template fails (the server would only warn about it).
CONFIG_KT="$ROOT/server/src/main/kotlin/io/silencelen/andvari/server/Config.kt"
known_env() {
  awk '/val KNOWN_ENV: Set<String> = setOf\(/ { on = 1; next } on && /^[[:space:]]*\)/ { exit } on' "$1" \
    | grep -oE '"ANDVARI_[A-Z0-9_]+"' | tr -d '"' | sort -u
}
# unknown_vars <file> <file of known names> — the ANDVARI_* names the file mentions that are not known.
unknown_vars() {
  grep -oE 'ANDVARI_[A-Z0-9_]+' "$1" | sort -u | while IFS= read -r v; do grep -qxF "$v" "$2" || echo "$v"; done
}
known_env "$CONFIG_KT" > "$W/known-env.txt"
[ "$(grep -c . "$W/known-env.txt")" -ge 40 ] || fail "read only $(grep -c . "$W/known-env.txt") names from Config.kt's KNOWN_ENV (expected 40+): did its form change?"
printf 'ANDVARI_SIGNUP_MODE=links\nANDVARI_PUBLIC_HOSTNAME=vault.example.org\n' > "$W/tpl-bad.env"
[ "$(unknown_vars "$W/tpl-bad.env" "$W/known-env.txt")" = ANDVARI_PUBLIC_HOSTNAME ] \
  || fail "template-name self-check: ANDVARI_PUBLIC_HOSTNAME, which the server does not read, was not found"
bad_names="$(unknown_vars "$TPL" "$W/known-env.txt" | tr '\n' ' ')"
[ -z "$bad_names" ] || fail "andvari.env.template names variables the server does not read (not in Config.kt's KNOWN_ENV): $bad_names"

# ============================== 5. the nightly snapshot is the server's command, not a host script ===
echo "==> deploy: neither the guide nor the deploy kit names a host script backup.sh: the snapshot is andvari admin backup"
# A host script for the snapshot ran as root in data/backup/, a folder the server's user owns (the entrypoint
# gives /data to it at every start), and opened the database without the server's guard against a leftover
# write-ahead file. The snapshot is `andvari admin backup` now, tested in the server's own suite
# (ServerBackupTest, ServerBackupProcessTest); nothing the operator reads or downloads may send them back to
# such a script. A file named backup.sh is not read.
while IFS= read -r -d '' f; do
  hits="$(grep -n 'backup\.sh' "$f" | tr '\n' ' ')"
  [ -z "$hits" ] || fail "${f#"$ROOT"/} names backup.sh, the withdrawn host script (the snapshot is andvari admin backup): $hits"
done < <(find "$ROOT/docs/self-hosting.md" "$DEPLOY" -type f ! -name backup.sh -print0)

echo "==> deploy: every snapshot line is the one line that runs andvari admin backup inside the running server's container, as its user, without a terminal"
# A snapshot taken in a container of its own (`docker compose run`) could run while the server was stopped, in
# the middle of a restore, and give the nightly name to the database being replaced. Inside the server's own
# container (`docker compose exec`) there is nothing to run in while the server is stopped. The line runs the
# image's start script as the server's user (as that user it changes no file's owner), without a terminal,
# and reads the settings file the compose file mounts read-only for it.
SNAP='docker compose exec -T -u andvari andvari /usr/local/bin/docker-entrypoint.sh admin backup --env-file /etc/andvari.env'
NIGHTLY_PREFIX='17 3 * * * cd /root/andvari && '
# snapshot_line_ok <logical line> answers 0 when it is the snapshot line, alone or as the end of the nightly line.
snapshot_line_ok() {
  local l="$1"
  l="${l#"${l%%[![:space:]]*}"}"
  l="${l#"$NIGHTLY_PREFIX"}"
  [ "$l" = "$SNAP" ]
}
snapshot_line_ok "$SNAP" || fail "snapshot-line self-check: the snapshot line was refused"
snapshot_line_ok "$NIGHTLY_PREFIX$SNAP" || fail "snapshot-line self-check: the nightly line was refused"
snapshot_line_ok 'docker compose run --rm -v "$PWD/andvari.env:/andvari.env:ro" andvari admin backup --env-file /andvari.env' \
  && fail "snapshot-line self-check: the snapshot in a container of its own (docker compose run) passed"
snapshot_line_ok 'docker compose exec -u andvari andvari /usr/local/bin/docker-entrypoint.sh admin backup --env-file /etc/andvari.env' \
  && fail "snapshot-line self-check: a line without -T (a terminal, which cron does not have) passed"
snapshot_line_ok 'docker compose exec -T andvari /usr/local/bin/docker-entrypoint.sh admin backup --env-file /etc/andvari.env' \
  && fail "snapshot-line self-check: a line without -u andvari (the container's root) passed"
snapshot_line_ok "$SNAP --keep 3" && fail "snapshot-line self-check: a line with another ending passed"
snap_guide=0
for f in "$ROOT/docs/self-hosting.md" "$ROOT/README.md" "$DEPLOY"/*; do
  [ -f "$f" ] || continue
  while IFS= read -r hl; do
    lineno="${hl%%:*}"; text="${hl#*:}"
    printf '%s\n' "$text" | grep -qE 'docker[[:space:]].*admin[[:space:]]+backup' || continue
    if snapshot_line_ok "$text"; then
      [ "$f" = "$ROOT/docs/self-hosting.md" ] && snap_guide=$((snap_guide + 1))
    else
      fail "${f#"$ROOT"/}:$lineno runs the snapshot another way than the one line (want: $SNAP): $text"
    fi
  done < <(host_lines "$f")
done
[ "$snap_guide" -ge 3 ] || fail "docs/self-hosting.md holds $snap_guide snapshot line(s), want 3 or more (Backup, the nightly line, Updates step 1): did the matcher stop matching?"
settings_mount='./andvari.env:/etc/andvari.env:ro'
grep -qE '^[[:space:]]*-[[:space:]]*"?'"${settings_mount//./\\.}"'"?[[:space:]]*$' "$DC" \
  || fail "docker-compose.yml does not mount ./andvari.env read-only at /etc/andvari.env, the settings file the snapshot line names"
[ "$FAILED" = 0 ] && echo "    $snap_guide snapshot line(s) in the guide, every one the same line"

# ============================== 6. publish-image.sh publishes only a version, never a moving tag ===
echo "==> deploy: publish-image.sh refuses anything but a version of three numbers, before it logs in or builds, and plans its one tag only"
PUB="$ROOT/scripts/publish-image.sh"
# A part with a leading zero is refused too: 01.0.0 would be a second tag of the version 1.0.0.
for v in latest --latest 1.0 1.0.0-rc1 1.0.0.1 'v1.0.0 ' 01.0.0 v01.0.0 1.00.0 1.0.01; do
  prc=0; bash "$PUB" "$v" --dry-run > "$W/pub.out" 2> "$W/pub.err" || prc=$?
  [ "$prc" != 0 ] || fail "publish-image.sh took '$v' as a version"
  grep -q 'is not a version' "$W/pub.err" || fail "publish-image.sh did not say why it refused '$v': $(tr '\n' ' ' < "$W/pub.err")"
  [ -s "$W/pub.out" ] && fail "publish-image.sh went on after refusing '$v': $(tr '\n' ' ' < "$W/pub.out")"
done
for v in v1.0.0 1.10.0 10.0.0; do
  prc=0; bash "$PUB" "$v" --dry-run > "$W/pub.out" 2> "$W/pub.err" || prc=$?
  { [ "$prc" = 0 ] && grep -q "andvari-server:${v#v}" "$W/pub.out"; } || fail "publish-image.sh $v --dry-run did not plan the push of andvari-server:${v#v} (status $prc): $(tr '\n' ' ' < "$W/pub.err")"
done
# One tag, on both paths of the script: a dry run with a stand-in docker first in PATH, which answers the
# script's own questions to docker (whether buildx is there, the builder, the host's architecture) and logs
# every call. The planned build carries exactly one -t, the version's own; no other tag of the image is named;
# and the dry run asks docker nothing else but the look at the registry, which changes nothing.
FD="$W/fakedocker"; mkdir -p "$FD"
cat > "$FD/docker" <<'EOF'
#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$1 ${2:-}" in
  "buildx version" | "buildx inspect") exit 0 ;;
  "buildx imagetools") echo "ERROR: $4: not found" >&2; exit 1 ;;
  "version -f") echo amd64; exit 0 ;;
  *) echo "stand-in docker: not expected in a dry run: $*" >&2; exit 3 ;;
esac
EOF
chmod 755 "$FD/docker"
for path in buildx single-arch; do
  : > "$W/docker.log"
  set -- 1.0.0 --dry-run; [ "$path" = single-arch ] && set -- 1.0.0 --dry-run --single-arch
  prc=0; PATH="$FD:$PATH" FAKE_DOCKER_LOG="$W/docker.log" bash "$PUB" "$@" > "$W/pub.out" 2> "$W/pub.err" || prc=$?
  [ "$prc" = 0 ] || fail "publish-image.sh 1.0.0 --dry-run ($path) ended with status $prc: $(tr '\n' ' ' < "$W/pub.err")"
  builds="$(grep -cE '^DRY-RUN: docker (buildx )?build ' "$W/pub.out")"
  [ "$builds" = 1 ] || fail "publish-image.sh ($path) planned $builds builds, want 1: $(tr '\n' ' ' < "$W/pub.out")"
  tags="$(grep -E '^DRY-RUN: docker (buildx )?build ' "$W/pub.out" | grep -oE -- '(^|[[:space:]])(-t|--tag)(=|[[:space:]]+)[^[:space:]]+' | sed -E 's/^[[:space:]]*(-t|--tag)(=|[[:space:]]+)//' | tr '\n' ' ')"
  [ "$tags" = "ghcr.io/silencelen/andvari-server:1.0.0 " ] || fail "publish-image.sh ($path) tags the image as: ${tags:-nothing}(want ghcr.io/silencelen/andvari-server:1.0.0 alone)"
  others="$(grep -oE 'andvari-server:[^[:space:]@)]+' "$W/pub.out" | sort -u | grep -vxF 'andvari-server:1.0.0' | tr '\n' ' ')"
  [ -z "$others" ] || fail "publish-image.sh ($path) names another tag of the image: $others"
  asked="$(grep -vE '^(buildx version|buildx inspect andvari-builder|buildx imagetools inspect ghcr\.io/silencelen/andvari-server:1\.0\.0|version -f .*)$' "$W/docker.log" | tr '\n' ' ')"
  [ -z "$asked" ] || fail "publish-image.sh ($path) asked docker more than a dry run needs: $asked"
  tail -n 1 "$W/pub.out" | grep -q 'nothing was pushed' || fail "publish-image.sh ($path) dry run's last line does not say that nothing was pushed: $(tail -n 1 "$W/pub.out")"
  grep -q '^==> published:' "$W/pub.out" && fail "publish-image.sh ($path) dry run says it published: $(grep '^==> published:' "$W/pub.out")"
done

# The look at the registry before a real run pushes anything: `docker buildx imagetools inspect <image>:<version>`.
# Only its clear answer that the tag does not exist lets the run go on; a tag that answers stops it, and so does any
# other outcome (no login, no network, words the script does not know) and a host without buildx. A stand-in docker
# answers the look as LOOK says and logs every call; a stand-in gh that fails keeps a real login out of the run.
LD="$W/lookdocker"; mkdir -p "$LD"
cat > "$LD/docker" <<'EOF'
#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
  "buildx version") [ "$LOOK" = nobuildx ] && exit 1; exit 0 ;;
  "buildx inspect andvari-builder") exit 0 ;;
  "version -f "*) echo amd64; exit 0 ;;
  "login "*) cat > /dev/null; exit 0 ;;
  *"imagetools inspect"*"--format"*) exit 1 ;;
  "buildx imagetools inspect "*)
    case "$LOOK" in
      exists) echo "Name:      $4"; echo "MediaType: application/vnd.oci.image.index.v1+json"; exit 0 ;;
      absent) echo "ERROR: $4: not found" >&2; exit 1 ;;
      ranout) exit 124 ;;
      registry)
        # The registry held in a file: the tag exists once a push has written it.
        if [ -f "$REGISTRY_FILE" ]; then echo "Name:      $4"; exit 0; fi
        echo "ERROR: $4: not found" >&2; exit 1 ;;
      *) echo "ERROR: failed to authorize: failed to fetch anonymous token: 403 Forbidden" >&2; exit 1 ;;
    esac ;;
  "buildx build "* | "build "* | "push "*)
    # A push into the file registry takes a while, as a real build does: long enough for a second run to meet it.
    if [ "$LOOK" = registry ]; then sleep 2; touch "$REGISTRY_FILE"; fi
    exit 0 ;;
  *) echo "stand-in docker: not expected: $*" >&2; exit 3 ;;
esac
EOF
printf '#!/bin/sh\nexit 1\n' > "$LD/gh"
chmod 755 "$LD/docker" "$LD/gh"
REF=ghcr.io/silencelen/andvari-server:1.0.0
for look in exists absent denied ranout nobuildx; do
  for dry in real dry; do
    : > "$W/docker.log"
    set -- 1.0.0; [ "$dry" = dry ] && set -- 1.0.0 --dry-run
    prc=0; PATH="$LD:$PATH" TMPDIR="$W" FAKE_DOCKER_LOG="$W/docker.log" LOOK="$look" GHCR_TOKEN='' bash "$PUB" "$@" > "$W/pub.out" 2> "$W/pub.err" || prc=$?
    pushed="$(grep -E '^(buildx build |build |push )' "$W/docker.log" | tr '\n' ' ')"
    looked="$(grep -cE '^buildx imagetools inspect [^ ]+$' "$W/docker.log")"
    if [ "$dry" = dry ]; then
      # A dry run makes the same look (a look changes nothing), pushes nothing and says what a real run would do.
      [ "$prc" = 0 ] || fail "publish-image.sh --dry-run (look: $look) ended with status $prc: $(tr '\n' ' ' < "$W/pub.err")"
      want_looked=1; [ "$look" = nobuildx ] && want_looked=0
      [ "$looked" = "$want_looked" ] || fail "publish-image.sh --dry-run (look: $look) looked $looked times, want $want_looked"
      [ -z "$pushed" ] || fail "publish-image.sh --dry-run (look: $look) called docker to build or push: $pushed"
      last="$(tail -n 1 "$W/pub.out")"
      echo "$last" | grep -q 'nothing was pushed' || fail "publish-image.sh --dry-run (look: $look) last line: $last"
      grep -q "imagetools inspect $REF" "$W/pub.out" || fail "publish-image.sh --dry-run (look: $look) does not show the look a real run makes"
      case "$look" in
        exists) echo "$last" | grep -q 'a real run would stop here: .* is already published' || fail "publish-image.sh --dry-run (tag published) does not say a real run would stop: $last" ;;
        nobuildx) echo "$last" | grep -q 'a real run would stop here: the look at the registry needs docker buildx' || fail "publish-image.sh --dry-run (no buildx) does not say a real run would stop: $last" ;;
        absent) grep -qE '^DRY-RUN: docker buildx build ' "$W/pub.out" || fail "publish-image.sh --dry-run (tag not found) planned no build" ;;
        *)
          grep -q 'this look did not answer that .* does not exist (a dry run does not log in itself' "$W/pub.out" || fail "publish-image.sh --dry-run (look: $look) does not say what its look could not tell" ;
          echo "$last" | grep -q 'this dry run could not learn whether .* is published; a real run .* makes the look again, and stops there, building nothing, unless' \
            || fail "publish-image.sh --dry-run (look: $look) last line does not say what a real run does: $last"
          echo "$last" | grep -q 'a real run would publish' && fail "publish-image.sh --dry-run (look: $look) last line says a real run would publish: $last" ;;
      esac
    elif [ "$look" = absent ]; then
      [ "$prc" = 0 ] || fail "publish-image.sh (look: tag not found) ended with status $prc: $(tr '\n' ' ' < "$W/pub.err")"
      grep -qE "^buildx build .*-t $REF .*--push" "$W/docker.log" || fail "publish-image.sh (look: tag not found) did not push: $(tr '\n' ' ' < "$W/docker.log")"
      first="$(grep -nE '^buildx imagetools inspect [^ ]+$' "$W/docker.log" | head -n 1 | cut -d: -f1)"
      build="$(grep -nE '^buildx build ' "$W/docker.log" | head -n 1 | cut -d: -f1)"
      { [ -n "$first" ] && [ -n "$build" ] && [ "$first" -lt "$build" ]; } || fail "publish-image.sh (look: tag not found) did not look before the push: $(tr '\n' ' ' < "$W/docker.log")"
    else
      [ "$prc" != 0 ] || fail "publish-image.sh (look: $look) ended with status 0"
      [ -z "$pushed" ] || fail "publish-image.sh (look: $look) called docker to build or push: $pushed"
      if ! { grep -q "$REF" "$W/pub.err" && grep -q 'Nothing was pushed' "$W/pub.err"; }; then
        fail "publish-image.sh (look: $look) did not name $REF and say that nothing was pushed: $(tr '\n' ' ' < "$W/pub.err")"
      fi
      [ "$look" = denied ] && { grep -q '403 Forbidden' "$W/pub.err" || fail "publish-image.sh (look: denied) did not show the registry's own words: $(tr '\n' ' ' < "$W/pub.err")"; }
      [ "$look" = ranout ] && { grep -q 'the look ran out of its 60 seconds' "$W/pub.err" || fail "publish-image.sh (look ran out) did not say so: $(tr '\n' ' ' < "$W/pub.err")"; }
      grep -q '^==> published:' "$W/pub.out" && fail "publish-image.sh (look: $look) says it published"
    fi
  done
done

# Two real runs at once on one host, the registry held in a file: one pushes, the other finds the lock held and stops
# at once, building nothing; a run after them is refused as already published. Their lock file lies in a folder of
# this test's own (TMPDIR).
TWO="$W/two"; mkdir -p "$TWO"
: > "$W/docker.log"
two_runs() {
  PATH="$LD:$PATH" TMPDIR="$TWO" FAKE_DOCKER_LOG="$W/docker.log" LOOK=registry REGISTRY_FILE="$TWO/registry" GHCR_TOKEN='' \
    bash "$PUB" 1.0.0 > "$TWO/$1.out" 2> "$TWO/$1.err"
  echo "$?" > "$TWO/$1.rc"
}
two_runs a &
two_runs b &
wait
pushes="$(grep -c '^buildx build ' "$W/docker.log")"
[ "$pushes" = 1 ] || fail "two runs of publish-image.sh at once pushed $pushes times, want 1: $(tr '\n' ' ' < "$W/docker.log")"
statuses="$(cat "$TWO/a.rc") $(cat "$TWO/b.rc")"
case "$statuses" in
  "0 1" | "1 0") ;;
  *) fail "two runs of publish-image.sh at once ended with statuses $statuses, want one 0 and one 1" ;;
esac
grep -h 'holds .*andvari-publish-image.lock on this host; this run built and pushed nothing' "$TWO/a.err" "$TWO/b.err" > /dev/null \
  || fail "the second of two runs did not say that another run holds the lock: $(cat "$TWO/a.err" "$TWO/b.err" | tr '\n' ' ')"
[ -f "$TWO/andvari-publish-image.lock" ] || fail "publish-image.sh left no lock file (it is never removed)"
: > "$W/docker.log"
prc=0; PATH="$LD:$PATH" TMPDIR="$TWO" FAKE_DOCKER_LOG="$W/docker.log" LOOK=registry REGISTRY_FILE="$TWO/registry" GHCR_TOKEN='' \
  bash "$PUB" 1.0.0 > "$TWO/c.out" 2> "$TWO/c.err" || prc=$?
if [ "$prc" = 0 ] || ! grep -q 'is already published' "$TWO/c.err"; then
  fail "a run after the push was not refused as already published (status $prc): $(tr '\n' ' ' < "$TWO/c.err")"
fi
grep -qE '^(buildx build |build |push )' "$W/docker.log" && fail "a run after the push built or pushed: $(tr '\n' ' ' < "$W/docker.log")"

# ============================== 7. the image's licence label ===
# The image holds the server (AGPL-3.0-or-later) and the web app, the shared core and the recovery tool
# (GPL-3.0-or-later), as LICENSING.md splits them: its label names both, joined by AND.
echo "==> deploy: the image's licence label names the server's and the clients' licences"
grep -qE '^[[:space:]]*org\.opencontainers\.image\.licenses="AGPL-3\.0-or-later AND GPL-3\.0-or-later"[[:space:]]*\\?$' "$ROOT/Dockerfile" \
  || fail "the Dockerfile's org.opencontainers.image.licenses label is not \"AGPL-3.0-or-later AND GPL-3.0-or-later\": $(grep -o 'image\.licenses="[^"]*"' "$ROOT/Dockerfile" | tr '\n' ' ')"

if [ "$FAILED" = 0 ]; then echo "    deploy-hardening: all checks passed"; fi
exit "$FAILED"
