#!/usr/bin/env bash
# Emit release-spec.json — the machine-readable description of the artifacts THIS host has
# already published to /downloads, so the owner-side signing ceremony never hand-types a
# checksum.
#
#   scripts/release-spec.sh --version 0.21.0 --ext-version 0.20.0 [--out FILE] [--publish]
#
# Why this exists
# ---------------
# The update manifest is signed on the owner's workstation (the private Ed25519 key never
# leaves it — see docs/design/*signed-updates*). That workstation therefore has to be TOLD
# what the Linux/extension entries are, and every hand-copied sha256 is a chance to publish
# a manifest that points at bytes nobody can install. This script computes them from the
# real files on the build host and emits exactly the entry shapes the manifest uses, so the
# workstation script can splice them in verbatim and only has to author the `windows` entry
# (the MSI it builds itself) plus `seq`/`signedAt`.
#
# Output (specVersion 1):
#   { specVersion, generatedAt, intendedKeys[], linux{}, browserExtension{} }
# `intendedKeys` names the manifest keys this spec is authoritative for. The operator-side
# watcher that publishes the signed bundle uses it as an allow-list: any OTHER manifest key
# must come back byte-identical to what is already live, so a release that means to bump the
# deb cannot quietly rewrite the extension entry.
#
# HARD FAILS if an artifact is missing or its recorded sha256 disagrees with SHA256SUMS —
# a spec with a hole in it is worse than no spec, because the hole is only discovered by a
# client that can no longer update.
#
# `--publish` copies the spec to the download host WITH THE `artifacts` BLOCK STRIPPED —
# that block holds build-host filesystem paths, operator detail that must never appear at a
# public URL (the full spec stays in the local file). THIS FILE IS PUBLIC: the transport
# lives in exactly one function (publish_spec, below) and takes its target from the
# environment — there is no host, path or credential anywhere in this repo.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The unlisted Chrome Web Store listing (item id is public — it is in the install URL).
# Override with --chrome-store-url if the listing ever moves.
CHROME_STORE_URL_DEFAULT="https://chromewebstore.google.com/detail/andvari/ndhkgfgkbnfieehncjgegcjhfdbhmmbn"

VERSION="" EXT_VERSION="" OUT="" DO_PUBLISH=0
CHROME_STORE_URL="$CHROME_STORE_URL_DEFAULT"

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version)          VERSION="${2:?--version needs a value}"; shift 2 ;;
    --ext-version)      EXT_VERSION="${2:?--ext-version needs a value}"; shift 2 ;;
    --out)              OUT="${2:?--out needs a value}"; shift 2 ;;
    --chrome-store-url) CHROME_STORE_URL="${2:?--chrome-store-url needs a value}"; shift 2 ;;
    --publish)          DO_PUBLISH=1; shift ;;
    -h|--help)          usage; exit 0 ;;
    *) echo "unknown arg: $1 (see --help)" >&2; exit 2 ;;
  esac
done

die() { echo "release-spec: ERROR: $*" >&2; exit 1; }

[ -n "$VERSION" ]     || die "--version <fleet version, e.g. 0.21.0> is required"
[ -n "$EXT_VERSION" ] || die "--ext-version <extension version, e.g. 0.20.0> is required"
command -v jq        >/dev/null 2>&1 || die "jq is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

OUT="${OUT:-$REPO_DIR/release-spec.json}"

# ---------------------------------------------------------------------------
# locate + hash
# ---------------------------------------------------------------------------

# Resolve exactly one file for a glob, or fail loudly. Zero matches and two matches are
# BOTH fatal: "two matches" means a stale build revision is lying around and picking one
# arbitrarily would sign a checksum for the wrong bytes.
resolve_one() {
  local what="$1" pattern="$2"
  local matches=()
  # shellcheck disable=SC2206  # deliberate glob expansion
  matches=( $pattern )
  if [ "${#matches[@]}" -eq 0 ] || [ ! -e "${matches[0]}" ]; then
    die "$what not found — no file matches $pattern (build it before generating the spec)"
  fi
  if [ "${#matches[@]}" -gt 1 ]; then
    die "$what is ambiguous — $pattern matched ${#matches[@]} files (${matches[*]}); remove the stale ones"
  fi
  printf '%s\n' "${matches[0]}"
}

hash_of() { sha256sum "$1" | cut -d' ' -f1; }

# Cross-check against the SHA256SUMS the packaging step wrote, when it exists. A disagreement
# means the artifact was rebuilt after it was hashed (or after it was published) — publishing
# a manifest for it would point every client at bytes that are not the ones on the server.
# Says out loud whether a cross-check actually happened: a silent return-0 here once made
# "no cross-check available" indistinguishable from "cross-checked and matched".
crosscheck_sums() {
  local file="$1" want_name="$2" got="$3" sums="$4"
  if [ ! -f "$sums" ]; then
    echo "release-spec: NOTE: no cross-check for $want_name — $(basename "$sums") does not exist" >&2
    return 0
  fi
  local expect
  # `{print $1; exit}` instead of `| head -1`: under pipefail the head pipe can kill awk
  # with SIGPIPE and fail the script with no message.
  expect="$(awk -v n="$want_name" '$2 == n || $2 == "*" n {print $1; exit}' "$sums")"
  if [ -z "$expect" ]; then
    echo "release-spec: NOTE: no cross-check for $want_name — no entry in $(basename "$sums")" >&2
    return 0
  fi
  [ "$expect" = "$got" ] || die "sha256 mismatch for $file — $(basename "$sums") says $expect but the file hashes to $got (rebuild happened after packaging; re-run the packaging step)"
  echo "release-spec: cross-checked $want_name against $(basename "$sums") — match" >&2
}

DEB_LOCAL="$(resolve_one "linux .deb for $VERSION" "$REPO_DIR/app-desktop/build/compose/binaries/main/deb/andvari_${VERSION}-*_amd64.deb")"
EXT_DIR="$REPO_DIR/extension/artifacts"
CHROME_LOCAL="$EXT_DIR/andvari-extension-chrome-${EXT_VERSION}.zip"
FIREFOX_LOCAL="$EXT_DIR/andvari-extension-firefox-${EXT_VERSION}.xpi"

[ -f "$CHROME_LOCAL" ]  || die "chrome extension zip not found: $CHROME_LOCAL (run: cd extension && node package.mjs)"
[ -f "$FIREFOX_LOCAL" ] || die "firefox signed xpi not found: $FIREFOX_LOCAL (run: scripts/publish-extension.sh --firefox — the manifest must point at the AMO-SIGNED .xpi, never the raw .zip)"

DEB_SHA="$(hash_of "$DEB_LOCAL")"
CHROME_SHA="$(hash_of "$CHROME_LOCAL")"
FIREFOX_SHA="$(hash_of "$FIREFOX_LOCAL")"

EXT_SUMS="$EXT_DIR/SHA256SUMS-${EXT_VERSION}.txt"
crosscheck_sums "$CHROME_LOCAL"  "$(basename "$CHROME_LOCAL")"  "$CHROME_SHA"  "$EXT_SUMS"
crosscheck_sums "$FIREFOX_LOCAL" "$(basename "$FIREFOX_LOCAL")" "$FIREFOX_SHA" "$EXT_SUMS"
echo "release-spec: NOTE: no cross-check for the deb — packaging writes no SHA256SUMS for it; its sha256 comes from hashing the file directly" >&2

# Published names differ from build-output names: the compose plugin emits Debian's
# andvari_<ver>-<rev>_amd64.deb, /downloads serves andvari-<ver>.deb.
DEB_PUBLISHED="andvari-${VERSION}.deb"

# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------
# `linux` and `browserExtension` are emitted with EXACTLY the manifest's key names and
# nesting so they can be spliced in without reshaping. Local paths and the extension
# checksums ride along under `artifacts` — advisory detail for the operator, not manifest
# content (the manifest has no sha256 for the extension entries).
TMP_OUT="$(mktemp "${OUT}.XXXXXX")"
trap 'rm -f "$TMP_OUT"' EXIT

jq -n \
  --arg generatedAt   "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg version       "$VERSION" \
  --arg debUrl        "/downloads/${DEB_PUBLISHED}" \
  --arg debSha        "$DEB_SHA" \
  --arg extVersion    "$EXT_VERSION" \
  --arg chromeStore   "$CHROME_STORE_URL" \
  --arg chromeUrl     "/downloads/$(basename "$CHROME_LOCAL")" \
  --arg firefoxUrl    "/downloads/$(basename "$FIREFOX_LOCAL")" \
  --arg debLocal      "$DEB_LOCAL" \
  --arg chromeLocal   "$CHROME_LOCAL" \
  --arg firefoxLocal  "$FIREFOX_LOCAL" \
  --arg chromeSha     "$CHROME_SHA" \
  --arg firefoxSha    "$FIREFOX_SHA" \
  '{
     specVersion: 1,
     generatedAt: $generatedAt,
     intendedKeys: ["linux", "browserExtension"],
     linux: {
       version: $version,
       url: $debUrl,
       sha256: $debSha
     },
     browserExtension: {
       version: $extVersion,
       chromeStoreUrl: $chromeStore,
       chromeUrl: $chromeUrl,
       firefoxUrl: $firefoxUrl
     },
     artifacts: {
       deb:     { localPath: $debLocal,     sha256: $debSha },
       chrome:  { localPath: $chromeLocal,  sha256: $chromeSha },
       firefox: { localPath: $firefoxLocal, sha256: $firefoxSha }
     }
   }' > "$TMP_OUT"

jq -e . "$TMP_OUT" >/dev/null || die "generated spec is not valid JSON (this is a bug)"
# mktemp is 0600; the spec is public information destined for a public download dir, and a
# 0600 file breaks a non-root reader of the drop copy. Widen before the atomic rename.
chmod 644 "$TMP_OUT"
mv "$TMP_OUT" "$OUT"
trap - EXIT

echo "release-spec: wrote $OUT" >&2
echo "release-spec:   linux            $VERSION      $DEB_PUBLISHED  ($DEB_SHA)" >&2
echo "release-spec:   browserExtension $EXT_VERSION  $(basename "$CHROME_LOCAL") + $(basename "$FIREFOX_LOCAL")" >&2

# ---------------------------------------------------------------------------
# transport — THE ONLY PLACE THIS SCRIPT TOUCHES A REMOTE HOST
# ---------------------------------------------------------------------------
# This repo is public, so nothing here may name a host, a path or a container. Both
# mechanisms are supplied entirely by the environment:
#
#   ANDVARI_SPEC_PUBLISH_HOOK  a command run as: "$HOOK" <local-file> <remote-basename>
#                              Preferred. Lets an operator wrap whatever their download
#                              host actually needs (ssh/pct/scp/rsync/S3) without this
#                              script knowing anything about it.
#   ANDVARI_SPEC_PUBLISH_DEST  an scp destination directory, e.g. user@host:/path/to/downloads/
#                              Fallback for the simple case.
#
# Set one of them, or run without --publish and move the spec yourself.
publish_spec() {
  local src="$1" name pub
  name="$(basename "$src")"

  # The local spec's `artifacts` block carries BUILD-HOST FILESYSTEM PATHS — operator
  # detail that must never appear at a public URL. Publish a copy with it stripped; the
  # full spec stays local for the operator and the watcher (which compares minus this
  # block). Belt-and-braces grep so a future emit change cannot leak paths silently.
  pub="$(mktemp)"
  if ! jq 'del(.artifacts)' "$src" > "$pub"; then
    rm -f "$pub"
    die "failed to strip the artifacts block from $name for publishing"
  fi
  if grep -q 'localPath' "$pub"; then
    rm -f "$pub"
    die "the to-be-published spec still contains localPath entries after stripping — refusing to publish (this is a bug)"
  fi
  chmod 644 "$pub"

  if [ -n "${ANDVARI_SPEC_PUBLISH_HOOK:-}" ]; then
    echo "release-spec: publishing $name (artifacts block stripped) via ANDVARI_SPEC_PUBLISH_HOOK" >&2
    "$ANDVARI_SPEC_PUBLISH_HOOK" "$pub" "$name" \
      || { rm -f "$pub"; die "publish hook failed for $name"; }
    rm -f "$pub"
    return 0
  fi

  if [ -n "${ANDVARI_SPEC_PUBLISH_DEST:-}" ]; then
    echo "release-spec: publishing $name (artifacts block stripped) via scp to \$ANDVARI_SPEC_PUBLISH_DEST" >&2
    scp -q "$pub" "${ANDVARI_SPEC_PUBLISH_DEST%/}/$name" \
      || { rm -f "$pub"; die "scp to \$ANDVARI_SPEC_PUBLISH_DEST failed for $name"; }
    rm -f "$pub"
    return 0
  fi

  rm -f "$pub"
  die "--publish needs a target: set ANDVARI_SPEC_PUBLISH_HOOK (a command taking <file> <name>) or ANDVARI_SPEC_PUBLISH_DEST (an scp destination dir)"
}

if [ "$DO_PUBLISH" = 1 ]; then
  publish_spec "$OUT"
  echo "release-spec: published $(basename "$OUT")" >&2
fi
