#!/usr/bin/env bash
# Assemble and publish the GitHub release for one andvari version.
#
#   scripts/gh-release.sh --version 0.26.3 --ext-version 0.26.0 \
#       [--stage DIR] [--msi FILE] [--apk FILE | --no-android] [--extra FILE]… \
#       [--notes-file FILE] [--draft] [--dry-run]
#
# Why this exists
# ---------------
# Every other published surface has a script: /downloads is described by release-spec.sh and
# signed by prestige-release.ps1, the extension stores by publish-extension.sh, the container by
# publish-image.sh. The GitHub release — the one download page a stranger actually lands on — was
# assembled by hand with `gh release create` / `gh release upload`, so its asset layout was
# retyped every time and drifted (audit H102):
#
#   v0.26.3   andvari_0.26.3-1_amd64.deb   (Debian's build-output name)
#             andvari-0.26.3.deb.asc       (a signature for the SERVED name — the pair does not
#                                           obviously belong together on the page)
#   v0.26.2   andvari_0.26.2-1_amd64.deb + andvari_0.26.2-1_amd64.deb.asc  (the other convention)
#   runbook   gpg --verify andvari-<ver>.deb.asc andvari-<ver>.deb          (matching neither)
#
# The bytes were always right; what a visitor could not do was tell which two files pair up. So
# this script fixes ONE convention — the served names, the same ones /downloads uses and the same
# ones the signing runbook tells people to verify — and derives everything else from the files.
#
# It also closes the two 0.26.2 record gaps (audit H104):
#   * SHA256SUMS is generated over EXACTLY the asset set being uploaded, so an artifact that
#     arrives late (the AMO-signed .xpi comes back from Mozilla after the rest is packaged) is
#     either in the release AND in SHA256SUMS or in neither. The 0.26.2 SUMS listed the two
#     extension .zips and omitted the .xpi the live manifest points at — the one Firefox install
#     artifact, with no published digest anywhere.
#   * SHA256SUMS itself is signed (`SHA256SUMS-<ver>.txt.asc`) with the same GPG release key that
#     signs the deb, which is what makes the file worth reading at all. Unsigned checksums served
#     from the same page as the artifacts prove nothing to a stranger.
#   * Re-uploading DIFFERENT bytes under a filename that already exists on the release is
#     refused. 0.26.2 published two byte-different MSIs under one name (manifest seq 10 → 11
#     re-cut); clients were fine (they verify the signed manifest's hash) but anyone who had
#     written down the seq-10 digest was left with an unexplained mismatch. A re-cut gets a new
#     filename (stage it as andvari-<ver>-2.msi, or cut a new version) — never new bytes under
#     the old one. The generated SHA256SUMS pair is the one exception: it is derived from the
#     asset set and its detached signature carries a timestamp, so it is re-uploaded (clobbered)
#     on every run; only real artifacts get the byte-identity refusal.
#
# --no-android: saying "no APK this time" OUT LOUD (audit H105)
# --------------------------------------------------------------
# devstore (the phone's installer) pulls the newest release matching the app's tagPrefix and
# hard-requires a `latest.json` asset. A release that deliberately ships no Android build — 0.26.3
# was a desktop-only fix — therefore trips the same "no latest.json — SKIPPING" warning that exists
# to catch a FORGOTTEN latest.json, every 15 minutes, forever. An alarm that fires for a correct
# state is not an alarm any more: the one failure mode that can silently strand a release becomes
# indistinguishable from routine noise.
#
# So the release says which one it is. --no-android writes the marker line
#
#     android: none (deliberate)
#
# into the release body, and devstore-sync (netplan scripts/active/devstore-sync.sh) reads it: the
# app is left at its current APK with an INFO line and no warning. Without the marker the warning
# stands, which is the point — the flag is an assertion by a human, not a default.
#
# What it does NOT do: build anything, sign the deb, sign the update manifest, or touch
# /downloads. Those have their own scripts and, for the Windows half, their own host.
#
# Requirements: gh (authenticated), gpg with the release key, sha256sum. --dry-run needs none of
# them and touches no network: it stages, hashes, prints the plan and stops.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="" EXT_VERSION="" STAGE="" MSI="" APK="" NOTES="" DRY=0 DRAFT=0 NO_ANDROID=0
EXTRA=()

# The exact line devstore-sync greps for. Both sides must agree on it literally; if it ever
# changes, change it in netplan scripts/active/devstore-sync.sh in the same commit.
ANDROID_NONE_MARKER='android: none (deliberate)'

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; }
die() { echo "gh-release: ERROR: $*" >&2; exit 1; }
note() { echo "gh-release: $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version)         VERSION="${2:?--version needs a value}"; shift 2 ;;
    --ext-version)     EXT_VERSION="${2:?--ext-version needs a value}"; shift 2 ;;
    --stage)           STAGE="${2:?--stage needs a value}"; shift 2 ;;
    --msi)             MSI="${2:?--msi needs a value}"; shift 2 ;;
    --apk)             APK="${2:?--apk needs a value}"; shift 2 ;;
    --no-android)      NO_ANDROID=1; shift ;;
    --extra)           EXTRA+=("${2:?--extra needs a value}"); shift 2 ;;
    --notes-file)      NOTES="${2:?--notes-file needs a value}"; shift 2 ;;
    --draft)           DRAFT=1; shift ;;
    --dry-run)         DRY=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) die "unknown arg: $1 (see --help)" ;;
  esac
done

[ -n "$VERSION" ] || die "--version <fleet version, e.g. 0.26.3> is required"
# The two are contradictory assertions about the same release, and the marker would outlive the
# APK in the body. Refuse rather than pick one.
[ -n "$APK" ] && [ "$NO_ANDROID" = 1 ] && die "--apk and --no-android are mutually exclusive — this release either ships an Android build or deliberately does not"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
TAG="v$VERSION"
STAGE="${STAGE:-$REPO_DIR/build/gh-release/$VERSION}"

# ---------------------------------------------------------------------------
# 1. collect — build-output name in, SERVED name out
# ---------------------------------------------------------------------------
# The compose plugin emits Debian's andvari_<ver>-<rev>_amd64.deb; /downloads serves
# andvari-<ver>.deb (release-spec.sh:131-133 owns that rename and the manifest points at it).
# The GitHub release now uses the served name for both the deb and its signature, so the page,
# /downloads, SHA256SUMS and the runbook's `gpg --verify` line all say one thing.
DEB_SERVED="andvari-${VERSION}.deb"
DEB_BUILD_GLOB="$REPO_DIR/app-desktop/build/compose/binaries/main/deb/andvari_${VERSION}-*_amd64.deb"

resolve_one() { # <what> <glob> — zero matches and two matches are both fatal (stale build)
  local what="$1" pattern="$2" matches=()
  # shellcheck disable=SC2206  # deliberate glob expansion
  matches=( $pattern )
  if [ "${#matches[@]}" -eq 0 ] || [ ! -e "${matches[0]}" ]; then
    die "$what not found — nothing matches $pattern"
  fi
  [ "${#matches[@]}" -eq 1 ] || die "$what is ambiguous — $pattern matched ${#matches[@]} files (${matches[*]}); remove the stale ones"
  printf '%s\n' "${matches[0]}"
}

mkdir -p "$STAGE"

# stage <source> <published-name>  — copy in under the name the release will carry.
# Refuses to stage two different files under one name: that is the 0.26.2 MSI mistake caught one
# step earlier than the upload check, and the message is clearer here.
stage() {
  local src="$1" name="$2" dst="$STAGE/$2"
  [ -f "$src" ] || die "missing artifact: $src"
  if [ -e "$dst" ] && ! cmp -s "$src" "$dst"; then
    die "staging conflict: $name already staged from different bytes ($(sha256sum "$dst" | cut -c1-16)… vs $(sha256sum "$src" | cut -c1-16)…) — clear $STAGE or give the re-cut its own name"
  fi
  cp -f "$src" "$dst"
  printf '%s\n' "$name"
}

ASSETS=()
add() { ASSETS+=("$1"); }

# The deb and its detached signature: both required, both under the served name. A release
# without the signature is not one this script will publish — the runbook tells users to verify.
DEB_LOCAL="$(resolve_one "linux .deb for $VERSION" "$DEB_BUILD_GLOB")"
add "$(stage "$DEB_LOCAL" "$DEB_SERVED")"
DEB_ASC=""
for cand in "$STAGE/$DEB_SERVED.asc" "$DEB_LOCAL.asc" "$(dirname "$DEB_LOCAL")/$DEB_SERVED.asc"; do
  [ -f "$cand" ] && { DEB_ASC="$cand"; break; }
done
[ -n "$DEB_ASC" ] || die "no detached signature for the deb — sign it first:
    gpg --armor --detach-sign --output $STAGE/$DEB_SERVED.asc $STAGE/$DEB_SERVED
  (key 741CF143…, docs/runbooks/release-signing-keys.md §3)"
add "$(stage "$DEB_ASC" "$DEB_SERVED.asc")"

# Windows and Android are built elsewhere (the MSI on the signing workstation), so they are
# explicit paths rather than a glob into a build dir that will not exist on this host.
[ -n "$MSI" ] && add "$(stage "$MSI" "andvari-${VERSION}.msi")"
[ -n "$APK" ] && add "$(stage "$APK" "$(basename "$APK")")"

# The extension rides its own version track. Whatever publish-extension.sh actually produced for
# that version gets uploaded — including the AMO-SIGNED .xpi, which is the whole point: it is the
# Firefox install artifact and 0.26.2 published it with no digest anywhere public.
if [ -n "$EXT_VERSION" ]; then
  EXT_DIR="$REPO_DIR/extension/artifacts"
  found_ext=0
  for f in "$EXT_DIR/andvari-extension-chrome-${EXT_VERSION}.zip" \
           "$EXT_DIR/andvari-extension-firefox-${EXT_VERSION}.zip" \
           "$EXT_DIR/andvari-extension-firefox-${EXT_VERSION}.xpi"; do
    [ -f "$f" ] && { add "$(stage "$f" "$(basename "$f")")"; found_ext=1; }
  done
  [ "$found_ext" = 1 ] || note "WARNING: --ext-version $EXT_VERSION given but no artifacts in extension/artifacts/ — the release will carry no extension files"
  if [ ! -f "$EXT_DIR/andvari-extension-firefox-${EXT_VERSION}.xpi" ]; then
    note "WARNING: no AMO-signed .xpi for $EXT_VERSION. If the manifest's firefoxUrl points at one, it MUST be here — that is audit H104."
  fi
fi

for f in ${EXTRA+"${EXTRA[@]}"}; do add "$(stage "$f" "$(basename "$f")")"; done

# Neither an APK nor a deliberate opt-out: this is the ambiguous case the marker exists to remove.
# Not fatal — plenty of releases are cut before the APK is built — but say it here, where it can
# still be answered, rather than leaving devstore to warn about it every 15 minutes.
if [ -z "$APK" ] && [ "$NO_ANDROID" != 1 ]; then
  note "WARNING: no --apk and no --no-android. devstore will keep warning that $TAG has no latest.json,"
  note "         which is the alarm for a FORGOTTEN Android build. If that is deliberate, pass --no-android."
fi

# ---------------------------------------------------------------------------
# 2. SHA256SUMS over exactly the asset set — then sign it
# ---------------------------------------------------------------------------
SUMS="SHA256SUMS-${VERSION}.txt"
(cd "$STAGE" && sha256sum "${ASSETS[@]}" > "$SUMS")
note "wrote $STAGE/$SUMS over ${#ASSETS[@]} asset(s)"

# Cross-check the deb against what the signed update manifest was told, when release-spec.json is
# on this host. Two publications of the same version that disagree about the deb's bytes is the
# failure this catches, and it is free to check.
SPEC="$REPO_DIR/release-spec.json"
if [ -f "$SPEC" ] && command -v jq >/dev/null 2>&1; then
  spec_ver="$(jq -r '.linux.version // empty' "$SPEC")"
  spec_sha="$(jq -r '.linux.sha256 // empty' "$SPEC")"
  if [ "$spec_ver" = "$VERSION" ] && [ -n "$spec_sha" ]; then
    got="$(sha256sum "$STAGE/$DEB_SERVED" | cut -d' ' -f1)"
    [ "$got" = "$spec_sha" ] || die "the deb being uploaded ($got) is NOT the one release-spec.json describes for /downloads ($spec_sha) — one of the two is stale; do not publish both"
    note "cross-checked $DEB_SERVED against release-spec.json — same bytes as /downloads"
  else
    note "release-spec.json is for ${spec_ver:-<none>}, not $VERSION — no cross-check"
  fi
else
  note "no release-spec.json on this host — no /downloads cross-check (run release-spec.sh first if this is the build host)"
fi

if [ "$DRY" = 1 ]; then
  note "--dry-run: staged and hashed, nothing signed, nothing uploaded. Planned $TAG assets:"
  (cd "$STAGE" && printf '  %s\n' "${ASSETS[@]}" "$SUMS" "$SUMS.asc") >&2
  [ "$NO_ANDROID" = 1 ] && note "--dry-run: would append to the $TAG release body: $ANDROID_NONE_MARKER"
  exit 0
fi

command -v gpg >/dev/null 2>&1 || die "gpg is required to sign $SUMS"
command -v gh  >/dev/null 2>&1 || die "gh is required to publish the release"
rm -f "$STAGE/$SUMS.asc"
gpg --armor --detach-sign --output "$STAGE/$SUMS.asc" "$STAGE/$SUMS" || die "signing $SUMS failed"
gpg --verify "$STAGE/$SUMS.asc" "$STAGE/$SUMS" >/dev/null 2>&1 || die "the signature we just made does not verify — refusing to publish"
note "signed $SUMS (detached, armored)"
ASSETS+=("$SUMS" "$SUMS.asc")

# ---------------------------------------------------------------------------
# 3. publish — create the release if it does not exist, then upload
# ---------------------------------------------------------------------------
# NEVER different bytes under an existing name (H104). gh's --clobber would happily do it, so the
# digest of anything already on the release is checked first and a difference is fatal.
if gh release view "$TAG" >/dev/null 2>&1; then
  note "release $TAG exists — checking existing assets before uploading"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  existing="$(gh release view "$TAG" --json assets --jq '.assets[].name')"
  for name in "${ASSETS[@]}"; do
    # The sums pair is REGENERATED from the artifact set every run and `gpg --detach-sign` stamps
    # a creation time, so its bytes never repeat — comparing it here made the script die on its
    # own second run (recheck R28). It is meant to change; --clobber below replaces it.
    case "$name" in "$SUMS"|"$SUMS.asc") continue ;; esac
    printf '%s\n' "$existing" | grep -qxF "$name" || continue
    ( cd "$tmp" && gh release download "$TAG" --pattern "$name" --clobber >/dev/null 2>&1 ) || {
      note "could not download the published $name to compare — refusing to overwrite it blind"; exit 1; }
    if ! cmp -s "$tmp/$name" "$STAGE/$name"; then
      die "$name is already published with DIFFERENT bytes — refusing.
  A same-name re-publish leaves everyone who recorded the old digest with an unexplained
  mismatch (audit H104, the 0.26.2 MSI). Re-cut under a NEW filename and say so in the notes."
    fi
  done
else
  note "creating release $TAG"
  create_args=(release create "$TAG" --title "andvari $VERSION")
  [ "$DRAFT" = 1 ] && create_args+=(--draft)
  if [ -n "$NOTES" ]; then create_args+=(--notes-file "$NOTES"); else create_args+=(--generate-notes); fi
  gh "${create_args[@]}"
fi

# The marker goes in as soon as the release exists, not after the upload: an upload that fails
# half-way still leaves a published release, and one without the marker is one devstore warns about.
# Idempotent — a re-run finds the line already there and leaves the body alone (so the operator's
# own notes are never rewritten twice).
if [ "$NO_ANDROID" = 1 ]; then
  body="$(gh release view "$TAG" --json body --jq '.body // ""')" || die "could not read the $TAG release body"
  # Anchored, case-insensitive, whole-line: the marker is a machine token, and matching it loosely
  # would let a sentence *about* the marker in someone's release notes count as the marker itself.
  # [[:space:]] covers the CR of GitHub's CRLF bodies.
  if printf '%s\n' "$body" | grep -qiE '^[[:space:]]*android:[[:space:]]*none[[:space:]]*\(deliberate\)[[:space:]]*$'; then
    note "release body already carries: $ANDROID_NONE_MARKER"
  else
    if [ -n "$body" ]; then
      printf '%s\n\n%s\n' "$body" "$ANDROID_NONE_MARKER" > "$STAGE/.release-body.md"
    else
      printf '%s\n' "$ANDROID_NONE_MARKER" > "$STAGE/.release-body.md"
    fi
    gh release edit "$TAG" --notes-file "$STAGE/.release-body.md" >/dev/null \
      || die "could not write the Android marker into the $TAG release body — devstore will warn about this release until it is there"
    note "release body now carries: $ANDROID_NONE_MARKER"
  fi
fi

(cd "$STAGE" && gh release upload "$TAG" "${ASSETS[@]}" --clobber)
note "uploaded ${#ASSETS[@]} asset(s) to $TAG"
note "verify as a stranger would:"
note "  gh release download $TAG && sha256sum -c $SUMS && gpg --verify $SUMS.asc $SUMS"
note "  gpg --verify $DEB_SERVED.asc $DEB_SERVED"
