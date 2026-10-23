#!/bin/sh
# andvari container entrypoint — server by default, recovery-cli as a subcommand
# (design 2026-07-15 §8.1: one image carries both).
#
#   <no args> | server        run the andvari server
#   recovery-cli [args...]    run the OFFLINE escrow/recovery tool
#                             (use `docker run --rm --network none --log-driver none ... recovery-cli keygen`:
#                             keygen prints the org recovery seed and recover a temporary password, and
#                             docker copies an attached container's stdout to its log driver unless
#                             that is turned off)
#   anything else             exec'd verbatim (debug shell etc.)
#
# Started as root it fixes /data ownership (bind mounts arrive host-owned) and
# drops to the unprivileged `andvari` user via setpriv (util-linux, no extra dep).
set -eu

JAVA_SERVER_OPTS="${JAVA_OPTS:--XX:MaxRAMPercentage=75}"

drop_priv() {
  if [ "$(id -u)" = "0" ]; then
    exec setpriv --reuid andvari --regid andvari --clear-groups "$@"
  fi
  exec "$@"
}

# prepare_data_dir <dir> <db path> — the state directory, owner-only (security review 2026-10).
# The SQLite database holds the members' TOTP seeds in plaintext next to the login and recovery
# verifiers, and a bind mount arrives with whatever mode docker or the operator gave it (0755 when
# docker creates the source itself). So: ownership fixed when we are root, the directory 0700, and
# any database file an older image left 0644 (-wal, -shm, -journal included) tightened to 0600.
# Files created later are 0600 through the umask start_server sets. Nothing else in the container
# reads /data: the server is the only process that opens the database, and the downloads files an
# operator places under /data/downloads are only read by it.
prepare_data_dir() {
  dir="$1"
  db="$2"
  mkdir -p "$dir"
  if [ "$(id -u)" = "0" ]; then
    chown -R andvari:andvari "$dir"
  fi
  # Guarded in both branches (A14 review Wd): under `set -e` an unguarded chmod that fails (a read-only
  # or root-squashed bind mount) would kill the entrypoint before the server starts.
  if ! chmod 700 "$dir" 2>/dev/null; then
    echo "WARN: could not restrict $dir to its owner (chmod 700) — fix the bind mount's mode on the host" >&2
  fi
  for f in "$db"*; do
    if [ -f "$f" ] && ! chmod 600 "$f" 2>/dev/null; then
      echo "WARN: could not restrict $f to its owner (chmod 600)" >&2
    fi
  done
}

start_server() {
  prepare_data_dir "$1" "${ANDVARI_DB:-$1/andvari.db}"
  # Before drop_priv, so the server inherits it: the database, its -wal/-shm and every blob are
  # created 0600, directories 0700.
  umask 077
  # shellcheck disable=SC2086  # JAVA_SERVER_OPTS is deliberately word-split
  drop_priv java $JAVA_SERVER_OPTS -jar /opt/andvari/andvari-server.jar
}

# Test seam: scripts/ci/deploy-hardening.test.sh sources this file with ANDVARI_ENTRYPOINT_LIB=1 to
# run start_server against a scratch directory. Sourced that way it defines the functions above and
# stops here.
if [ "${ANDVARI_ENTRYPOINT_LIB:-0}" = 1 ]; then
  return 0
fi

case "${1:-server}" in
  server)
    start_server /data
    ;;
  recovery-cli)
    shift
    drop_priv java -jar /opt/andvari/andvari-recovery-cli.jar "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
