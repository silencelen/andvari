#!/usr/bin/env bash
# Build an andvari Android APK (release by default) and write dist/latest.json.
# Release signing reads the build host's ~/.andvari/keystore.properties (absent → unsigned).
# versionCode = seconds since 2026-01-01 (monotonic across build hosts).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VARIANT="${1:-release}"
LOCK=/tmp/andvari-gradle.lock
EPOCH_2026=1767225600
# ONE build instant, three encodings in latest.json (versionCode, timestamp, builtAt). Derive them
# all from this single stamp — reading the clock again at manifest-write time let builtAt drift
# minutes past the versionCode on a slow build.
BUILT_AT_EPOCH=$(date +%s)
VERSIONCODE=$(( BUILT_AT_EPOCH - EPOCH_2026 ))

case "$VARIANT" in
  release) TASK=":app-android:assembleRelease"; APK_DIR="release" ;;
  debug)   TASK=":app-android:assembleDebug";   APK_DIR="debug" ;;
  *) echo "usage: build.sh [release|debug]"; exit 1 ;;
esac

echo "[build] $VARIANT versionCode=$VERSIONCODE"
(cd "$REPO_DIR" && ANDVARI_VERSIONCODE="$VERSIONCODE" flock "$LOCK" ./gradlew "$TASK" -q)

SRC_APK="$(ls -1t "$REPO_DIR"/app-android/build/outputs/apk/$APK_DIR/*.apk | head -1)"
# A release build with no keystore is unsigned — refuse to ship it. apksigner is the ONLY authority:
# the old `META-INF/*.RSA` pre-check was a v1/jar-signing artifact that modern v2/v3-only signing
# never emits, so it matched nothing and short-circuited the real check. The path is discovered
# rather than pinned (an SDK bump used to break it), and "tool missing" is now a distinct error from
# "APK unsigned" — swallowing apksigner's stderr made the two indistinguishable.
if [ "$VARIANT" = "release" ]; then
  APKSIGNER="${APKSIGNER:-$(command -v apksigner || true)}"
  for d in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" /opt/android-sdk "$HOME/Android/Sdk"; do
    [ -n "$APKSIGNER" ] && break
    [ -n "$d" ] || continue
    APKSIGNER="$(ls -1 "$d"/build-tools/*/apksigner 2>/dev/null | sort -V | tail -1 || true)"
  done
  [ -n "$APKSIGNER" ] || {
    echo "[build] ERROR: apksigner not found — cannot prove the release APK is signed." >&2
    echo "        set APKSIGNER=/path/to/apksigner, or ANDROID_HOME to an SDK with build-tools." >&2
    exit 1
  }
  if ! "$APKSIGNER" verify "$SRC_APK" >/dev/null; then
    echo "[build] ERROR: release APK is UNSIGNED (keystore.properties missing?) — refusing." >&2
    exit 1
  fi
fi

VERSIONNAME="$(grep 'versionName =' "$REPO_DIR/app-android/build.gradle.kts" | head -1 | grep -oE '"[^"]+"' | tr -d '"')"
mkdir -p "$REPO_DIR/dist"
DIST_APK="$REPO_DIR/dist/Andvari-$VARIANT-$VERSIONCODE.apk"
cp "$SRC_APK" "$DIST_APK"
SHA="$(sha256sum "$DIST_APK" | cut -d' ' -f1)"

MANIFEST="$REPO_DIR/dist/latest.json"
[ "$VARIANT" = "debug" ] && MANIFEST="$REPO_DIR/dist/latest-debug.json"
cat > "$MANIFEST" <<EOF
{
  "versionCode": $VERSIONCODE,
  "versionName": "$VERSIONNAME",
  "apk": "$(basename "$DIST_APK")",
  "sha256": "$SHA",
  "timestamp": $BUILT_AT_EPOCH,
  "builtAt": "$(date -u -d "@$BUILT_AT_EPOCH" +%Y-%m-%dT%H:%M:%SZ)",
  "sizeBytes": $(stat -c%s "$DIST_APK")
}
EOF
echo "[build] $DIST_APK ($(du -h "$DIST_APK" | cut -f1)), manifest $MANIFEST"
