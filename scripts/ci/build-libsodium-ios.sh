#!/usr/bin/env bash
# Builds libsodium from its official signed release for the two iOS targets, into
# core/build/libsodium/<kotlin target>/{include,lib}, where core/build.gradle.kts expects it.
# The tarball is pinned by SHA-256 (its minisign signature was checked when the pin was set).
# macOS only. The result is compiled into the app; nothing here is fetched at runtime.
set -euo pipefail

VERSION=1.0.22
SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
MIN_IOS=17.0

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO/core/build/libsodium"
STAMP="$OUT/.stamp-$VERSION"
[ -f "$STAMP" ] && { echo "libsodium $VERSION already built"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
TARBALL="$WORK/libsodium.tar.gz"
curl -sSfL "https://download.libsodium.org/libsodium/releases/libsodium-$VERSION.tar.gz" -o "$TARBALL"
echo "$SHA256  $TARBALL" | shasum -a 256 -c -

build() { # <kotlin target> <sdk> <clang target>
  local target="$1" sdk="$2" triple="$3" src="$WORK/$1"
  mkdir -p "$src"
  tar -xzf "$TARBALL" -C "$src" --strip-components=1
  local sysroot; sysroot="$(xcrun --sdk "$sdk" --show-sdk-path)"
  ( cd "$src"
    ./configure --host=aarch64-apple-darwin --disable-shared --enable-static --disable-dependency-tracking \
      --prefix="$OUT/$target" \
      CC="$(xcrun --sdk "$sdk" -f clang)" \
      CFLAGS="-O3 -target $triple -isysroot $sysroot" \
      LDFLAGS="-target $triple -isysroot $sysroot" > configure.log 2>&1 || { tail -40 configure.log; exit 1; }
    make -j"$(sysctl -n hw.ncpu)" install > make.log 2>&1 || { tail -40 make.log; exit 1; } )
  lipo -info "$OUT/$target/lib/libsodium.a"
}

rm -rf "$OUT"
mkdir -p "$OUT"
build iosArm64          iphoneos        "arm64-apple-ios$MIN_IOS"
build iosSimulatorArm64 iphonesimulator "arm64-apple-ios$MIN_IOS-simulator"
touch "$STAMP"
