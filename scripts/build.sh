#!/usr/bin/env bash
# Build an andvari Android APK (release by default) and write dist/latest.json.
# Release signing uses huginn:/root/.andvari/keystore.properties (absent → unsigned).
# versionCode = seconds since 2026-01-01 (devstore convention; monotonic).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VARIANT="${1:-release}"
LOCK=/tmp/andvari-gradle.lock
EPOCH_2026=1767225600
VERSIONCODE=$(( $(date +%s) - EPOCH_2026 ))

case "$VARIANT" in
  release) TASK=":app-android:assembleRelease"; APK_DIR="release" ;;
  debug)   TASK=":app-android:assembleDebug";   APK_DIR="debug" ;;
  *) echo "usage: build.sh [release|debug]"; exit 1 ;;
esac

echo "[build] $VARIANT versionCode=$VERSIONCODE"
(cd "$REPO_DIR" && ANDVARI_VERSIONCODE="$VERSIONCODE" flock "$LOCK" ./gradlew "$TASK" -q)

SRC_APK="$(ls -1t "$REPO_DIR"/app-android/build/outputs/apk/$APK_DIR/*.apk | head -1)"
[ "$VARIANT" = "release" ] && ! unzip -l "$SRC_APK" | grep -q "META-INF/ANDVARI_.*\.RSA\|META-INF/.*\.RSA" && {
  # A release build with no keystore is unsigned — refuse to ship it.
  if ! /opt/android-sdk/build-tools/35.0.0/apksigner verify "$SRC_APK" >/dev/null 2>&1; then
    echo "[build] ERROR: release APK is UNSIGNED (keystore.properties missing?) — refusing." >&2
    exit 1
  fi
}

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
  "builtAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "sizeBytes": $(stat -c%s "$DIST_APK")
}
EOF
echo "[build] $DIST_APK ($(du -h "$DIST_APK" | cut -f1)), manifest $MANIFEST"
