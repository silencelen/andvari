#!/usr/bin/env bash
# Publish the andvari container image to GHCR — run BY HAND from a build host.
#
#   scripts/publish-image.sh <version> [--latest] [--single-arch] [--dry-run]
#   e.g. scripts/publish-image.sh 0.19.0 --latest
#
# DELIBERATELY NOT CI (design 2026-07-15 §8.1): hosted-runner minutes are not
# available for this project, so the image ghcr.io/silencelen/andvari is built +
# pushed from a build host, exactly like the APK/deb releases. Do not wire this
# into workflows.
#
# "Published" is not yet "pullable by a stranger" — see the ONE-TIME OWNER STEP
# below. Until that flip happens the docs must not call the image public, and
# they do not (README + docs/self-hosting.md say it needs a login and give the
# --build path instead; audit H43). When you do flip it, update both.
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
META="$(mktemp -t andvari-image-meta.XXXXXX)"; trap 'rm -f "$META"' EXIT

if [ "$SINGLE_ARCH" = 1 ] || ! docker buildx version >/dev/null 2>&1; then
  echo "==> single-arch build + push ($(docker version -f '{{.Server.Arch}}' 2>/dev/null || echo host-arch))"
  run docker build "${TAGS[@]}" .
  run docker push "$IMAGE:$VERSION"
  if [ "$TAG_LATEST" = 1 ]; then run docker push "$IMAGE:latest"; fi
else
  echo "==> buildx multi-arch build + push: $PLATFORMS"
  docker buildx inspect andvari-builder >/dev/null 2>&1 \
    || run docker buildx create --name andvari-builder --driver docker-container
  # H99 (2026-09-13 audit): provenance was explicitly DISABLED here, so the pushed index carried
  # no SLSA attestation and no SBOM — a self-hoster could pull an image they could not tie to the
  # source they can read. `mode=max` records the full build definition (Dockerfile, base-image
  # digests, build args); `sbom=true` attaches the per-release SBOM the W3 trust-attestation
  # strategy promised. Both ride inside the OCI index as attestation manifests, so
  # `docker buildx imagetools inspect` shows them and plain pulls are unaffected.
  # --metadata-file captures the pushed index digest — the ONE identifier that names these exact
  # bytes across registries and tags — so it can be printed and recorded below.
  run docker buildx build --builder andvari-builder --platform "$PLATFORMS" \
      "${TAGS[@]}" --provenance=mode=max --sbom=true --metadata-file "$META" --push .
fi

echo "==> published: $IMAGE:$VERSION$( [ "$TAG_LATEST" = 1 ] && echo " (+ :latest)" )"
# Print + record the immutable identity of what was just pushed. A tag can be re-pointed; a digest
# cannot. The line goes into the GitHub release body / SHA256SUMS by the release ceremony
# (docs/runbooks/release-signing-keys.md), so a self-hoster can pin
# `image: ghcr.io/silencelen/andvari:<ver>@sha256:…` in deploy/docker-compose.yml and verify the
# provenance with `docker buildx imagetools inspect <ref> --format '{{json .Provenance}}'`.
if [ "$DRY_RUN" = 1 ]; then
  echo "    DRY-RUN: would print the pushed index digest here (from $META / imagetools inspect)"
else
  DIGEST=""
  if [ -f "$META" ]; then DIGEST=$(jq -r '."containerimage.digest" // empty' "$META" 2>/dev/null || true); fi
  # Single-arch path (plain docker push) writes no metadata file; ask the registry instead.
  [ -n "$DIGEST" ] || DIGEST=$(docker buildx imagetools inspect "$IMAGE:$VERSION" --format '{{.Manifest.Digest}}' 2>/dev/null || true)
  if [ -n "$DIGEST" ]; then
    echo "    digest: $IMAGE@$DIGEST"
    echo "    pin as: image: $IMAGE:$VERSION@$DIGEST   # deploy/docker-compose.yml (ANDVARI_VERSION=$VERSION@$DIGEST also works)"
    echo "    record that digest line in the release notes + SHA256SUMS — it is the image's only verifiable identity"
    mkdir -p build && echo "$IMAGE:$VERSION@$DIGEST" > "build/image-digest-$VERSION.txt" \
      && echo "    written: build/image-digest-$VERSION.txt (gitignored release artefact — attach it to the release)"
  else
    echo "    WARNING: could not determine the pushed digest — run: docker buildx imagetools inspect $IMAGE:$VERSION" >&2
  fi
fi
echo "    smoke: docker run --rm $IMAGE:$VERSION recovery-cli   # prints usage"
echo "    remember the one-time package-visibility flip if this was the first push (header of this script)"
