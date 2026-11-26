#!/usr/bin/env bash
# Publish the andvari container image to GHCR — run BY HAND from a build host.
#
#   scripts/publish-image.sh <version> [--single-arch] [--dry-run]
#   e.g. scripts/publish-image.sh 1.0.0
#
# From 1.0.0 on the image is ghcr.io/silencelen/andvari-server, and every version is
# pushed under its own tag only: there is no `latest`. The old name
# ghcr.io/silencelen/andvari stays at 0.30.0, so a 0.30.0 server updating by that
# name never pulls a server that refuses its database. --latest is refused.
#
# DELIBERATELY NOT CI (design 2026-07-15 §8.1): hosted-runner minutes are not
# available for this project, so the image ghcr.io/silencelen/andvari-server is built +
# pushed from a build host, exactly like the APK/deb releases. Do not wire this
# into workflows.
#
# "Published" is not yet "pullable by a stranger" — see the ONE-TIME OWNER STEP
# below. Until that flip happens README.md says the image needs a GitHub login;
# update it when you flip it. docs/self-hosting.md names the image and gives the
# build from source either way.
#
# Requirements on the build host:
#   * docker with buildx: every real run needs it for the look at the registry; --single-arch then builds and pushes with plain docker
#   * auth: GHCR_TOKEN env (a PAT with write:packages), or a logged-in `gh` CLI
#     (gh auth token is used), or an already-authenticated docker login ghcr.io
#   * run from the repo root (top-level Dockerfile)
#   * flock: one run at a time per lock file, ${TMPDIR:-/tmp}/andvari-publish-image.lock, so two runs on one
#     host under different TMPDIR values do not see each other. Never publish one version from two machines:
#     the lock holds on one machine only.
#
# Multi-arch note: the Dockerfile pins its build stages to $BUILDPLATFORM, so the
# gradle/npm compile runs ONCE natively; only the runtime layer is per-arch.
# arm64 runtime depends on the deps' bundled natives (lazysodium/sqlite-jdbc ship
# aarch64) — smoke `docker run --platform linux/arm64 ... recovery-cli` after the
# first arm64 publish.
#
# ONE-TIME OWNER STEP after the very first push: the GHCR package is created
# PRIVATE by default — flip ghcr.io/silencelen/andvari-server to PUBLIC in GitHub →
# Packages → andvari-server → Package settings → Change visibility. Self-hosters
# cannot pull until this is done.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ -f Dockerfile ] || { echo "ERROR: run from the repo root (Dockerfile not found)" >&2; exit 1; }

VERSION="${1:-}"; shift || true
[ -n "$VERSION" ] || { echo "usage: scripts/publish-image.sh <version> [--single-arch] [--dry-run]" >&2; exit 1; }
case "$VERSION" in v*) VERSION="${VERSION#v}" ;; esac
# The image is pushed under the version's own tag alone, never `latest` or a shorter tag, and never again once
# it is published: before anything is built or pushed, a real run looks at the registry for that tag (below), and
# only the registry's clear answer that the tag does not exist lets it go on.
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: '$VERSION' is not a version: a version is three numbers with dots between them (such as 1.0.0), and the image is pushed under that tag alone" >&2; exit 1; }
[[ "$VERSION" =~ (^|\.)0[0-9] ]] && { echo "ERROR: '$VERSION' is not a version: no part of a version begins with 0 unless it is 0 (1.0.0, not 01.0.0), so that one version never gets two tags" >&2; exit 1; }

IMAGE=ghcr.io/silencelen/andvari-server
PLATFORMS="linux/amd64,linux/arm64"
SINGLE_ARCH=0 DRY_RUN=0
for a in "$@"; do
  case "$a" in
    --latest)      echo "ERROR: --latest is not offered: every version is published under its own tag only, so an update is always a version the operator named in .env" >&2; exit 1 ;;
    --single-arch) SINGLE_ARCH=1 ;;
    --dry-run)     DRY_RUN=1 ;;
    *) echo "ERROR: unknown flag $a" >&2; exit 1 ;;
  esac
done

# --- one real run at a time: two runs that both looked before either pushed would both push ---
# The lock is held on a file that is never removed, from here (before the look at the registry) until the process
# ends, after its push; the system lets go of it with the process however it ends, so no stale state stays behind.
if [ "$DRY_RUN" != 1 ]; then
  command -v flock >/dev/null 2>&1 \
    || { echo "ERROR: one run at a time needs flock, which this host does not have. Nothing was pushed." >&2; exit 1; }
  LOCK_FILE="${TMPDIR:-/tmp}/andvari-publish-image.lock"
  exec 9>>"$LOCK_FILE"
  flock -n 9 \
    || { echo "ERROR: another run of publish-image.sh holds $LOCK_FILE on this host; this run built and pushed nothing." >&2; exit 1; }
fi

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

# --- the look: is this version's tag already published? (decided on 22 November 2026) ---
# `docker buildx imagetools inspect <image>:<version>` answering means the tag exists: stop. Only one answer lets
# the run go on: a failed look whose words hold the line "ERROR: <image>:<version>: not found", buildx's report of a
# tag the registry does not have. That wording is taken from buildx as this script expects it and has not been tried
# against the registry from this script: if buildx words it otherwise, the run stops here, which is the safe side.
# Every other outcome (no login, no network, words this script does not know, a look that ran out of its 60 seconds,
# a host without buildx) is no answer, and the run stops with the registry's own words. A dry run makes the same look
# (a look changes nothing) and says what a real run would do; it does not log in, so where its look gets no answer it
# says so and goes on with its plan.
REF="$IMAGE:$VERSION"
LOOK_SAID="" LOOK_STATUS=0
# 0: the registry has no such tag; 1: the tag is published; 2: no buildx; 3: no answer (LOOK_SAID, LOOK_STATUS).
look_at_the_registry() {
  docker buildx version >/dev/null 2>&1 || return 2
  local limit=()
  # A look that never answers would hold the run: it gets 60 seconds where `timeout` is there (its status is then 124).
  command -v timeout >/dev/null 2>&1 && limit=(timeout 60)
  LOOK_SAID="$("${limit[@]}" docker buildx imagetools inspect "$REF" 2>&1)" || LOOK_STATUS=$?
  [ "$LOOK_STATUS" = 0 ] && return 1
  printf '%s\n' "$LOOK_SAID" | grep -qxF "ERROR: $REF: not found" && return 0
  return 3
}
echo "==> the look at the registry: docker buildx imagetools inspect $REF"
look=0; look_at_the_registry || look=$?
case "$look" in
  0) echo "==> the registry has no $REF yet: going on" ;;
  1)
    if [ "$DRY_RUN" = 1 ]; then
      echo "==> dry run: nothing was pushed; a real run would stop here: $REF is already published, and a published version is never pushed again"
      exit 0
    fi
    echo "ERROR: $REF is already published (the registry answered the look for that tag), and a published version is never pushed again. Nothing was pushed." >&2
    exit 1 ;;
  2)
    if [ "$DRY_RUN" = 1 ]; then
      echo "==> dry run: nothing was pushed; a real run would stop here: the look at the registry needs docker buildx, which this host does not have"
      exit 0
    fi
    echo "ERROR: the look at the registry for $REF needs docker buildx (docker buildx imagetools inspect), which this host does not have. Nothing was pushed." >&2
    exit 1 ;;
  *)
    ran_out=""; [ "$LOOK_STATUS" = 124 ] && ran_out=" (the look ran out of its 60 seconds)"
    echo "The registry's words for the look at $REF (status $LOOK_STATUS)$ran_out:" >&2
    printf '%s\n' "$LOOK_SAID" | sed 's/^/    /' >&2
    if [ "$DRY_RUN" = 1 ]; then
      echo "==> dry run: this look did not answer that $REF does not exist (a dry run does not log in itself; docker used any login it already holds)"
    else
      echo "ERROR: the look at the registry did not answer that $REF does not exist, so this run cannot tell whether that version is published. Nothing was pushed." >&2
      exit 1
    fi ;;
esac

TAGS=(-t "$IMAGE:$VERSION")

run() { if [ "$DRY_RUN" = 1 ]; then echo "DRY-RUN: $*"; else "$@"; fi }
META="$(mktemp -t andvari-image-meta.XXXXXX)"; trap 'rm -f "$META"' EXIT

if [ "$SINGLE_ARCH" = 1 ] || ! docker buildx version >/dev/null 2>&1; then
  echo "==> single-arch build + push ($(docker version -f '{{.Server.Arch}}' 2>/dev/null || echo host-arch))"
  run docker build "${TAGS[@]}" .
  run docker push "$IMAGE:$VERSION"
else
  echo "==> buildx multi-arch build + push: $PLATFORMS"
  docker buildx inspect andvari-builder >/dev/null 2>&1 \
    || run docker buildx create --name andvari-builder --driver docker-container
  # Until 2026-09-13 provenance was explicitly DISABLED here, so the pushed index carried
  # no SLSA attestation and no SBOM — a self-hoster could pull an image they could not tie to the
  # source they can read. `mode=max` records the full build definition (Dockerfile, base-image
  # digests, build args); `sbom=true` attaches the per-release SBOM the trust-attestation
  # strategy promised. Both ride inside the OCI index as attestation manifests, so
  # `docker buildx imagetools inspect` shows them and plain pulls are unaffected.
  # --metadata-file captures the pushed index digest — the ONE identifier that names these exact
  # bytes across registries and tags — so it can be printed and recorded below.
  run docker buildx build --builder andvari-builder --platform "$PLATFORMS" \
      "${TAGS[@]}" --provenance=mode=max --sbom=true --metadata-file "$META" --push .
fi

if [ "$DRY_RUN" = 1 ]; then
  echo "    DRY-RUN: would print the pushed index digest here (from $META / imagetools inspect)"
  if [ "$look" = 0 ]; then
    echo "==> dry run: nothing was pushed; a real run would publish $IMAGE:$VERSION"
  else
    echo "==> dry run: nothing was pushed, and this dry run could not learn whether $IMAGE:$VERSION is published; a real run logs in where it has a token (GHCR_TOKEN or gh), makes the look again, and stops there, building nothing, unless that look answers that the tag does not exist"
  fi
  exit 0
fi
echo "==> published: $IMAGE:$VERSION"
# Print + record the immutable identity of what was just pushed. A tag can be re-pointed; a digest
# cannot. The line goes into the GitHub release body / SHA256SUMS by the release ceremony
# (docs/runbooks/release-signing-keys.md), so a self-hoster can pin
# `image: ghcr.io/silencelen/andvari-server:<ver>@sha256:…` in deploy/docker-compose.yml and verify the
# provenance with `docker buildx imagetools inspect <ref> --format '{{json .Provenance}}'`.
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
echo "    smoke: docker run --rm $IMAGE:$VERSION recovery-cli   # prints usage"
echo "    remember the one-time package-visibility flip if this was the first push (header of this script)"
