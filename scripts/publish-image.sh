#!/usr/bin/env bash
# Publish the andvari container image to GHCR — run BY HAND from huginn or devserv.
#
#   scripts/publish-image.sh <version> [--latest] [--single-arch] [--dry-run]
#   e.g. scripts/publish-image.sh 0.19.0 --latest
#
# DELIBERATELY NOT CI (design 2026-07-15 §8.1): GitHub Actions billing on this
# account is broken (see memory/aspensplayground-ci-billing-block-2026-07-04), so
# the public image ghcr.io/silencelen/andvari is built + pushed from the build
# hosts, exactly like the APK/deb releases. Do not wire this into workflows.
#
# Requirements on the build host:
#   * docker with buildx (multi-arch) — --single-arch falls back to plain build/push
#   * auth: GHCR_TOKEN env (a PAT with write:packages), or a logged-in `gh` CLI
#     (gh auth token is used), or an already-authenticated docker login ghcr.io
#   * run from the repo root (top-level Dockerfile)
#
# Multi-arch note: the Dockerfile pins its build stages to $BUILDPLATFORM, so the
# gradle/npm compile runs ONCE natively; only the runtime layer is per-arch.
# arm64 runtime depends on the deps' bundled natives (lazysodium/sqlite-jdbc ship
# aarch64) — smoke `docker run --platform linux/arm64 ... recovery-cli` after the
# first arm64 publish.
#
# ONE-TIME OWNER STEP after the very first push: the GHCR package is created
# PRIVATE by default — flip ghcr.io/silencelen/andvari to PUBLIC in GitHub →
# Packages → andvari → Package settings → Change visibility (owner decision on
# record: private repo + public image, design §11.1). Self-hosters cannot pull
# until this is done.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -f Dockerfile ] || { echo "ERROR: run from the repo root (Dockerfile not found)" >&2; exit 1; }

VERSION="${1:-}"; shift || true
[ -n "$VERSION" ] || { echo "usage: scripts/publish-image.sh <version> [--latest] [--single-arch] [--dry-run]" >&2; exit 1; }
case "$VERSION" in v*) VERSION="${VERSION#v}" ;; esac

IMAGE=ghcr.io/silencelen/andvari
PLATFORMS="linux/amd64,linux/arm64"
TAG_LATEST=0 SINGLE_ARCH=0 DRY_RUN=0
for a in "$@"; do
  case "$a" in
    --latest)      TAG_LATEST=1 ;;
    --single-arch) SINGLE_ARCH=1 ;;
    --dry-run)     DRY_RUN=1 ;;
    *) echo "ERROR: unknown flag $a" >&2; exit 1 ;;
  esac
done

# --- auth (skipped on --dry-run — never authenticate for real when only printing commands) ---
if [ "${DRY_RUN:-0}" != 1 ]; then
  if [ -n "${GHCR_TOKEN:-}" ]; then
    printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u silencelen --password-stdin
  elif command -v gh >/dev/null 2>&1 && gh auth token >/dev/null 2>&1; then
    gh auth token | docker login ghcr.io -u silencelen --password-stdin
  else
    echo "NOTE: no GHCR_TOKEN and no gh auth — assuming docker is already logged in to ghcr.io" >&2
  fi
fi

TAGS=(-t "$IMAGE:$VERSION")
[ "$TAG_LATEST" = 1 ] && TAGS+=(-t "$IMAGE:latest")

run() { if [ "$DRY_RUN" = 1 ]; then echo "DRY-RUN: $*"; else "$@"; fi }

if [ "$SINGLE_ARCH" = 1 ] || ! docker buildx version >/dev/null 2>&1; then
  echo "==> single-arch build + push ($(docker version -f '{{.Server.Arch}}' 2>/dev/null || echo host-arch))"
  run docker build "${TAGS[@]}" .
  run docker push "$IMAGE:$VERSION"
  if [ "$TAG_LATEST" = 1 ]; then run docker push "$IMAGE:latest"; fi
else
  echo "==> buildx multi-arch build + push: $PLATFORMS"
  docker buildx inspect andvari-builder >/dev/null 2>&1 \
    || run docker buildx create --name andvari-builder --driver docker-container
  run docker buildx build --builder andvari-builder --platform "$PLATFORMS" \
      "${TAGS[@]}" --provenance=false --push .
fi

echo "==> published: $IMAGE:$VERSION$( [ "$TAG_LATEST" = 1 ] && echo " (+ :latest)" )"
echo "    smoke: docker run --rm $IMAGE:$VERSION recovery-cli   # prints usage"
echo "    remember the one-time package-visibility flip if this was the first push (header of this script)"
