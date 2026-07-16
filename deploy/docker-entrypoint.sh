#!/bin/sh
# andvari container entrypoint — server by default, recovery-cli as a subcommand
# (design 2026-07-15 §8.1: one image carries both).
#
#   <no args> | server        run the andvari server
#   recovery-cli [args...]    run the OFFLINE escrow/recovery tool
#                             (use `docker run --rm --network none ... recovery-cli keygen`)
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

case "${1:-server}" in
  server)
    if [ "$(id -u)" = "0" ]; then
      mkdir -p /data
      chown -R andvari:andvari /data
    fi
    # shellcheck disable=SC2086  # JAVA_SERVER_OPTS is deliberately word-split
    drop_priv java $JAVA_SERVER_OPTS -jar /opt/andvari/andvari-server.jar
    ;;
  recovery-cli)
    shift
    drop_priv java -jar /opt/andvari/andvari-recovery-cli.jar "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
