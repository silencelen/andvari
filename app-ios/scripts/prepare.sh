#!/usr/bin/env bash
# Everything Xcode needs before `xcodegen generate`: libsodium, the Kotlin framework for one
# Kotlin target (iosArm64 or iosSimulatorArm64), and the Safari extension's web files.
# macOS only. Usage: app-ios/scripts/prepare.sh <kotlin target>
set -euo pipefail
TARGET="${1:?usage: prepare.sh iosArm64|iosSimulatorArm64}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

scripts/ci/build-libsodium-ios.sh
Capitalized="$(printf '%s' "${TARGET:0:1}" | tr '[:lower:]' '[:upper:]')${TARGET:1}"
./gradlew --no-daemon -Dorg.gradle.jvmargs=-Xmx5g ":core:linkReleaseFramework${Capitalized}"

# UITEST=1 (the UI-test workflow only): the Safari files are the UI-test build, which adds the test site's stand-in
# payment provider to the card-entry origins (extension/build.mjs). Every other caller gets the release files, which
# ios-unsigned.yml checks name no test domain.
( cd extension && npm ci --no-audit --no-fund && RELEASE=1 TARGET=safari UITEST="${UITEST:-0}" node build.mjs )
WEB="$REPO/app-ios/AndvariSafari/web"
rm -rf "$WEB"
mkdir -p "$WEB"
cp -R extension/dist/. "$WEB/"
# Desktop install notes and Chrome's offscreen clipboard document are not part of the Safari build.
rm -f "$WEB/INSTALL.txt" "$WEB/offscreen.html" "$WEB/offscreen.js"
