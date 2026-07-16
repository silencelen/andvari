#!/usr/bin/env bash
# =============================================================================
# andvari desktop — Phase 0 headless AT-SPI presence probe
# design 2026-07-13-platform-fit.md §3 ("Phase 0 — headless AT-SPI presence probe")
# =============================================================================
#
# WHAT THIS ANSWERS (no human, no screen reader): does the Compose-for-Desktop
# JVM register an accessible-application node on the AT-SPI bus? Orca reads that
# SAME bus, so:
#   * PASS = an accessible application node for the andvari JVM appears in
#            org.a11y.atspi.Registry (exposing children with roles/names)   → Orca *might* speak
#   * FAIL = the andvari app is ABSENT from the registry                    → Orca is CONCLUSIVELY silent
# A FAIL here needs no screen reader to be conclusive: nothing is on the bus to read.
#
# It ALSO probes whether a JVM/CMP enabling flag changes the outcome — JetBrains
# has historically gated desktop a11y behind system properties, so we try:
#   * -Djavax.accessibility.assistive_technologies=org.GNOME.Accessibility.AtkWrapper
#   * -Dcompose.accessibility.enable=true   (best-effort; recorded, not trusted)
#   * assistive_technologies via the JVM accessibility.properties mechanism
#
# THIS BOX (huginn LXC 117) HAS NO DISPLAY/Xvfb/at-spi2-core, so running it here
# is expected to bail at the dependency check. It is written to be runnable on a
# Linux GUI box (a GNOME VM). Record what it observed in docs/accessibility.md.
#
# Usage:
#   ./a11y-probe.sh                 # auto: prefer a packaged .deb-installed binary, else `gradlew run`
#   ANDVARI_BIN=/opt/andvari/bin/andvari ./a11y-probe.sh     # point at an installed launcher
#   ANDVARI_RUN_GRADLE=1 ./a11y-probe.sh                     # force `./gradlew :app-desktop:run`
#
# Exit codes: 0 = probe ran and an app node WAS found (PASS)
#             1 = probe ran and the app node was ABSENT (FAIL — the expected Linux outcome)
#             2 = could not run the probe here (missing Xvfb / at-spi2-core / dbus) — inconclusive
# =============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LAUNCH_SECONDS="${LAUNCH_SECONDS:-25}"   # how long to let the app settle before dumping the tree

say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "----------------------------------------------------------------------"; }

# ---- 1. dependency gate (this is where huginn bails — no GUI stack) ----------
missing=()
for dep in Xvfb dbus-run-session busctl; do
  command -v "$dep" >/dev/null 2>&1 || missing+=("$dep")
done
# at-spi2-core ships the registry daemon; the exact binary name varies by distro.
ATSPI_REG=""
for cand in /usr/libexec/at-spi2-registryd /usr/lib/at-spi2-core/at-spi2-registryd \
            /usr/lib/at-spi2/at-spi2-registryd /usr/libexec/at-spi2-registryd; do
  [ -x "$cand" ] && ATSPI_REG="$cand" && break
done
[ -z "$ATSPI_REG" ] && missing+=("at-spi2-core (at-spi2-registryd)")
HAVE_PYATSPI=0
python3 -c 'import pyatspi' >/dev/null 2>&1 && HAVE_PYATSPI=1

if [ "${#missing[@]}" -gt 0 ]; then
  hr; say "INCONCLUSIVE — this host lacks the GUI a11y stack to run the probe:"
  for m in "${missing[@]}"; do say "    - missing: $m"; done
  say ""
  say "Run this on a Linux GNOME box after:"
  say "    sudo apt-get install -y xvfb at-spi2-core dbus python3-pyatspi   # busctl ships with systemd"
  say "Then re-run: $0"
  hr
  exit 2
fi

# ---- 2. locate the app launcher ---------------------------------------------
RUN_MODE=""
if [ "${ANDVARI_RUN_GRADLE:-0}" = "1" ]; then
  RUN_MODE="gradle"
elif [ -n "${ANDVARI_BIN:-}" ] && [ -x "${ANDVARI_BIN}" ]; then
  RUN_MODE="bin"
elif command -v andvari >/dev/null 2>&1; then
  ANDVARI_BIN="$(command -v andvari)"; RUN_MODE="bin"
else
  RUN_MODE="gradle"  # dev fallback — slower to start; bump LAUNCH_SECONDS if needed
fi
say "launch mode: $RUN_MODE  ${ANDVARI_BIN:+($ANDVARI_BIN)}"

# ---- 3. the actual probe, inside Xvfb + a private D-Bus session -------------
# Everything below runs under `dbus-run-session` so the AT-SPI bus is the one WE
# start (org.a11y.Bus), isolated from any real desktop session.
run_probe() {
  local label="$1"; shift
  local -a JVM_A11Y_ARGS=("$@")   # extra -D flags to feed the JVM under test

  hr
  say "PROBE: $label"
  say "   JVM a11y args: ${JVM_A11Y_ARGS[*]:-<none>}"

  # Export the JVM args so both launch paths pick them up.
  export JAVA_TOOL_OPTIONS="${JVM_A11Y_ARGS[*]}"
  # For gradlew run, CMP forwards these via the application plugin JVM args too.
  export ANDVARI_JVM_A11Y="${JVM_A11Y_ARGS[*]}"

  xvfb-run -a --server-args="-screen 0 1280x1024x24" dbus-run-session -- bash -c '
    set -u
    export GTK_MODULES="${GTK_MODULES:-}"        # deliberately NOT forcing gail/atk — see §3
    export ACCESSIBILITY_ENABLED=1
    export QT_ACCESSIBILITY=1                    # harmless for a JVM app; documents intent
    # Start the AT-SPI registry daemon on our private bus.
    "'"$ATSPI_REG"'" >/tmp/atspi-reg.log 2>&1 &
    REG_PID=$!
    sleep 2

    # Launch andvari.
    if [ "'"$RUN_MODE"'" = "bin" ]; then
      "'"${ANDVARI_BIN:-andvari}"'" >/tmp/andvari-app.log 2>&1 &
    else
      ( cd "'"$REPO_ROOT"'" && \
        flock /tmp/andvari-gradle.lock ./gradlew --console=plain \
          -Dorg.gradle.jvmargs="-Xmx2g" :app-desktop:run >/tmp/andvari-app.log 2>&1 ) &
    fi
    APP_PID=$!
    sleep '"$LAUNCH_SECONDS"'

    echo "=== busctl: names on the a11y bus ==="
    busctl --user list 2>/dev/null | grep -i a11y || echo "(no a11y names listed)"
    echo "=== busctl tree org.a11y.atspi.Registry ==="
    busctl --user tree org.a11y.atspi.Registry 2>&1 | head -100 || echo "(registry tree unavailable)"

    if command -v python3 >/dev/null 2>&1 && python3 -c "import pyatspi" >/dev/null 2>&1; then
      echo "=== pyatspi desktop enumeration ==="
      python3 - <<PYEOF
import pyatspi
d = pyatspi.Registry.getDesktop(0)
print("desktop child count:", d.childCount)
found = False
for app in d:
    try:
        name = app.name
    except Exception:
        name = "<unreadable>"
    print("  app:", repr(name), "role:", app.getRoleName(), "children:", app.childCount)
    if name and ("andvari" in name.lower() or "MainKt" in name or "java" in name.lower()):
        found = True
print("ANDVARI_NODE_FOUND:", found)
PYEOF
    else
      echo "(pyatspi not importable — relying on busctl tree above)"
    fi

    kill "$APP_PID"  2>/dev/null
    kill "$REG_PID"  2>/dev/null
    wait 2>/dev/null
  '
}

# ---- 4. run the matrix: baseline, then each enabling flag -------------------
OUT="$(mktemp)"
{
  run_probe "baseline (no a11y flag)"
  run_probe "assistive_technologies=AtkWrapper" \
    "-Djavax.accessibility.assistive_technologies=org.GNOME.Accessibility.AtkWrapper"
  run_probe "compose.accessibility.enable=true" \
    "-Dcompose.accessibility.enable=true"
  run_probe "both flags" \
    "-Djavax.accessibility.assistive_technologies=org.GNOME.Accessibility.AtkWrapper" \
    "-Dcompose.accessibility.enable=true"
} | tee "$OUT"

hr
if grep -q "ANDVARI_NODE_FOUND: True" "$OUT" || \
   grep -qi "org.a11y.atspi.Application" "$OUT"; then
  say "RESULT: PASS — an accessible application node appeared for andvari."
  say "        Proceed to Phase 1 (attended Orca)."
  rm -f "$OUT"; exit 0
else
  say "RESULT: FAIL — no andvari node on the AT-SPI registry under any probed flag."
  say "        This is CONCLUSIVE that Orca has nothing to read (it reads the same bus)."
  say "        Record the tree dump above as evidence in docs/accessibility.md."
  rm -f "$OUT"; exit 1
fi
