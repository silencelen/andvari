#!/usr/bin/env bash
# Build the Linux desktop artifacts for ONE andvari release — the Debian .deb AND the Arch pacman
# package — from a single gradle invocation, GPG-sign both, and stage them under the served names.
#
#   scripts/build-linux.sh [--skip-gradle] [--no-sign] [--stage DIR] [--release N]
#   scripts/build-linux.sh --print-depends      # just the Arch depends derived from the built deb
#
# Why this exists
# ---------------
# The deb used to be built by hand (`gradlew :app-desktop:packageDeb`) and signed by hand
# (`gpg --armor --detach-sign …`) — two commands retyped per release, and no second artifact to
# keep in step with them. The household now also runs Arch-family desktops (Omarchy reports
# `ID=omarchy` / `ID_LIKE=arch`), and the rule is that every Linux build produces a pacman package
# BESIDE the deb — same bytes under /opt/andvari, same signing key, same manifest ceremony. Two
# artifacts that must describe the same build need ONE place that builds them, which is this script:
#
#   1. gradle `:app-desktop:packageDeb :app-desktop:createDistributable` in ONE invocation, so the
#      deb and the app-image are the same build. That is then PROVEN, not assumed: a manifest of the
#      WHOLE image — every jar by its entries' CRCs, every other file by sha256, every symlink by
#      target — must be identical between the deb's /opt/andvari and the app-image, or the script
#      stops. (Comparing only the app-desktop jar once let a stale image with a different core jar
#      through — security review 2026-10.) Under --skip-gradle the image must also declare this
#      version in its jpackage state file, so a leftover image of another release is refused even
#      before the manifest comparison.
#   2. scripts/package-arch.sh turns the app-image into andvari-<ver>-<rel>-x86_64.pkg.tar.zst with
#      the deb's /opt/andvari layout, /usr/bin/andvari, the .desktop entry and the GPL-3.0 licence
#      file — the deb's metadata (description, maintainer, licence) is REUSED, never retyped, and
#      its `Depends:` line is TRANSLATED into Arch package names (table below; an unknown Debian
#      name is a hard stop, so a JDK bump that links a new library cannot ship an under-declared
#      package).
#   3. Both artifacts get a detached ARMORED GPG signature (`.asc`) under the same release key the
#      deb has always carried (docs/runbooks/release-signing-keys.md §3). ARMORED `.asc`, never a
#      binary `.sig`: pacman auto-verifies a `<pkg>.sig` sidecar against ITS OWN keyring and would
#      refuse the install, because the household release key is deliberately not in pacman's
#      keyring. The `.asc` is for humans (`gpg --verify`), exactly like the deb's.
#
# Outputs (build-output names — where release-spec.sh and gh-release.sh look):
#   app-desktop/build/compose/binaries/main/deb/andvari_<ver>-<rev>_amd64.deb
#   app-desktop/build/compose/binaries/main/deb/andvari-<ver>.deb.asc
#   app-desktop/build/compose/binaries/main/arch/andvari-<ver>-<rel>-x86_64.pkg.tar.zst (+ .sha256)
#   app-desktop/build/compose/binaries/main/arch/andvari-<ver>-x86_64.pkg.tar.zst.asc
# and copies under the SERVED names in the stage dir (default $HOME/.andvari/release-<ver>):
#   andvari-<ver>.deb + .asc        andvari-<ver>-x86_64.pkg.tar.zst + .asc
#
# Installing on Arch stays manual (`sudo pacman -U andvari-<ver>-x86_64.pkg.tar.zst`); no client
# runs an installer on Linux and nothing here changes that.
#
# Requirements: gradle (unless --skip-gradle), dpkg-deb, bsdtar + zstd (package-arch.sh), gpg with
# the release key (unless --no-sign).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_NAME=andvari
PKG_URL="https://github.com/silencelen/andvari"
BIN_DIR="$REPO_DIR/app-desktop/build/compose/binaries/main"
DEB_DIR="$BIN_DIR/deb"
IMG_DIR="$BIN_DIR/app/$PKG_NAME"
ARCH_DIR="$BIN_DIR/arch"
# The deb release key (public fingerprint, runbook §3). Override for a rotation rehearsal only.
GPG_KEY="${ANDVARI_GPG_KEY:-741CF143A5E1EDF3B9CBE923D1CC699A598417FC}"
# One gradle at a time on the build host — the same lock build.sh takes.
LOCK="${ANDVARI_GRADLE_LOCK:-/tmp/andvari-gradle.lock}"

SKIP_GRADLE=0 NO_SIGN=0 STAGE="" RELEASE=1 PRINT_DEPENDS=0

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; }
die() { echo "build-linux: ERROR: $*" >&2; exit 1; }
note() { echo "build-linux: $*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-gradle)   SKIP_GRADLE=1; shift ;;
    --no-sign)       NO_SIGN=1; shift ;;
    --stage)         STAGE="${2:?--stage needs a value}"; shift 2 ;;
    --release)       RELEASE="${2:?--release needs a value}"; shift 2 ;;
    --print-depends) PRINT_DEPENDS=1; SKIP_GRADLE=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) die "unknown arg: $1 (see --help)" ;;
  esac
done
[[ "$RELEASE" =~ ^[0-9]+$ ]] || die "--release must be an integer (pacman pkgrel)"
command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is required (apt install dpkg)"

# ---------------------------------------------------------------------------
# version — the desktop's packageVersion, which verify.sh keeps in lockstep with :core
# ---------------------------------------------------------------------------
VERSION="$(grep -oE 'packageVersion = "[0-9]+\.[0-9]+\.[0-9]+"' "$REPO_DIR/app-desktop/build.gradle.kts" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
[ -n "$VERSION" ] || die "could not read packageVersion from app-desktop/build.gradle.kts"
CORE_VERSION="$(grep -oE 'ANDVARI_CLIENT_VERSION = "[0-9]+\.[0-9]+\.[0-9]+"' "$REPO_DIR/core/src/commonMain/kotlin/io/silencelen/andvari/core/client/AndvariApi.kt" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)"
[ "$VERSION" = "$CORE_VERSION" ] || die "version skew: app-desktop packageVersion is $VERSION but core ANDVARI_CLIENT_VERSION is ${CORE_VERSION:-<unreadable>} — run scripts/verify.sh and fix the bump first"

DEB_SERVED="$PKG_NAME-$VERSION.deb"
PKG_SERVED="$PKG_NAME-$VERSION-x86_64.pkg.tar.zst"
PKG_BUILT="$PKG_NAME-$VERSION-$RELEASE-x86_64.pkg.tar.zst"

# ---------------------------------------------------------------------------
# 1. gradle — deb + app-image in ONE invocation
# ---------------------------------------------------------------------------
if [ "$SKIP_GRADLE" = 0 ]; then
  note "gradle :app-desktop:packageDeb :app-desktop:createDistributable (version $VERSION, lock $LOCK)"
  # The two targets share every input, so one invocation yields one build. Stale outputs are
  # cleared first: jpackage overwrites, but a leftover deb of another revision would make
  # release-spec.sh's resolve_one refuse (two matches), and a leftover app-image is the stale
  # build the proof below exists to catch.
  rm -rf "$DEB_DIR" "$IMG_DIR"
  (
    cd "$REPO_DIR"
    GRADLE_OPTS="-Dorg.gradle.daemon=false ${GRADLE_OPTS:-}" \
      flock "$LOCK" ./gradlew --no-daemon --console=plain \
        :app-desktop:packageDeb :app-desktop:createDistributable
  ) || die "gradle failed"
fi

# ---------------------------------------------------------------------------
# 2. locate the deb
# ---------------------------------------------------------------------------
resolve_one() { # <what> <glob>
  local what="$1" pattern="$2" matches=()
  # shellcheck disable=SC2206  # deliberate glob expansion
  matches=( $pattern )
  if [ "${#matches[@]}" -eq 0 ] || [ ! -e "${matches[0]}" ]; then
    die "$what not found — nothing matches $pattern (run without --skip-gradle)"
  fi
  [ "${#matches[@]}" -eq 1 ] || die "$what is ambiguous — $pattern matched ${#matches[@]} files (${matches[*]}); remove the stale ones"
  printf '%s\n' "${matches[0]}"
}
DEB_LOCAL="$(resolve_one "linux .deb for $VERSION" "$DEB_DIR/${PKG_NAME}_${VERSION}-*_amd64.deb")"
# ---------------------------------------------------------------------------
# 3. deb metadata → Arch metadata (reused, translated, never retyped); then the app-image
# ---------------------------------------------------------------------------
# Debian package → Arch package. The deb's Depends line is what jpackage's scanner found the
# bundled runtime linking against (libjpeg, giflib, lcms2, libpng, harfbuzz … are the JDK's
# AWT/2D natives; the X/GL/ALSA set is Compose). glibc is a base dependency on every Arch
# install and is omitted, as makepkg convention has it. An unknown name is FATAL — extend the
# table rather than guess, so a new library can never ship undeclared.
arch_name_for() {
  case "$1" in
    libc6)                       printf '' ;;                 # base: glibc
    libgcc-s1|libstdc++6)        printf 'gcc-libs' ;;
    zlib1g)                      printf 'zlib' ;;
    libasound2|libasound2t64)    printf 'alsa-lib' ;;
    libbrotli1)                  printf 'brotli' ;;
    libbsd0)                     printf 'libbsd' ;;
    libbz2-1.0)                  printf 'bzip2' ;;
    libexpat1)                   printf 'expat' ;;
    libfontconfig1)              printf 'fontconfig' ;;
    libfreetype6)                printf 'freetype2' ;;
    libgif7)                     printf 'giflib' ;;
    libgl1|libglvnd0|libglx0|libegl1|libopengl0) printf 'libglvnd' ;;
    libglib2.0-0|libglib2.0-0t64) printf 'glib2' ;;
    libgraphite2-3)              printf 'graphite' ;;
    libharfbuzz0b)               printf 'harfbuzz' ;;
    libjpeg8|libjpeg-turbo8)     printf 'libjpeg-turbo' ;;
    liblcms2-2)                  printf 'lcms2' ;;
    libmd0)                      printf 'libmd' ;;
    libpcre2-8-0)                printf 'pcre2' ;;
    libpng16-16|libpng16-16t64)  printf 'libpng' ;;
    libx11-6)                    printf 'libx11' ;;
    libxau6)                     printf 'libxau' ;;
    libxcb1)                     printf 'libxcb' ;;
    libxdmcp6)                   printf 'libxdmcp' ;;
    libxext6)                    printf 'libxext' ;;
    libxi6)                      printf 'libxi' ;;
    libxrender1)                 printf 'libxrender' ;;
    libxtst6)                    printf 'libxtst' ;;
    xdg-utils)                   printf 'xdg-utils' ;;
    *) return 1 ;;
  esac
}

DEB_DEPENDS="$(dpkg-deb -f "$DEB_LOCAL" Depends)"
[ -n "$DEB_DEPENDS" ] || die "the deb declares no Depends: line — jpackage's dependency scan did not run?"
ARCH_DEPENDS=()
UNKNOWN=()
while IFS= read -r dep; do
  # "libfoo1 (>= 2.3)" → "libfoo1"; "a | b" alternatives take the first.
  dep="${dep%%|*}"; dep="${dep%%(*}"; dep="$(printf '%s' "$dep" | tr -d '[:space:]')"
  [ -n "$dep" ] || continue
  if a="$(arch_name_for "$dep")"; then
    [ -n "$a" ] && ARCH_DEPENDS+=("$a")
  else
    UNKNOWN+=("$dep")
  fi
done < <(printf '%s\n' "$DEB_DEPENDS" | tr ',' '\n')
[ "${#UNKNOWN[@]}" -eq 0 ] || die "no Arch name known for Debian package(s): ${UNKNOWN[*]} — extend arch_name_for() in $0 (do not guess; look the library up on archlinux.org/packages)"
ARCH_DEPENDS_STR="$(printf '%s\n' "${ARCH_DEPENDS[@]}" | LC_ALL=C sort -u | paste -sd' ')"

if [ "$PRINT_DEPENDS" = 1 ]; then
  echo "$ARCH_DEPENDS_STR"
  exit 0
fi

# --- the app-image, and the proof it is the deb's build ---------------------------------
[ -x "$IMG_DIR/bin/$PKG_NAME" ] || die "app-image $IMG_DIR has no bin/$PKG_NAME — run without --skip-gradle (createDistributable)"
command -v unzip >/dev/null 2>&1 || die "unzip is required for the same-build proof (apt install unzip)"

# --skip-gradle reuses whatever image is on disk, so it must at least be THIS release's image.
# jpackage records the app version in lib/app/.jpackage.xml.
if [ "$SKIP_GRADLE" = 1 ]; then
  IMG_VER="$(grep -oE '<app-version>[^<]*</app-version>' "$IMG_DIR/lib/app/.jpackage.xml" 2>/dev/null | sed -E 's#</?app-version>##g' || true)"
  [ "$IMG_VER" = "$VERSION" ] \
    || die "--skip-gradle with a stale app-image: $IMG_DIR declares version '${IMG_VER:-<none>}', this release is $VERSION. Run without --skip-gradle."
  DEB_VER="$(dpkg-deb -f "$DEB_LOCAL" Version)"
  [ "${DEB_VER%%-*}" = "$VERSION" ] || die "--skip-gradle: the deb is version $DEB_VER, this release is $VERSION"
fi

# image_manifest <root> — one line per file of an app-image tree, sorted, comparable across the
# deb's copy and the createDistributable copy:
#   * a jar is identified by its ENTRIES (name, CRC-32, size), not its bytes or its file name.
#     packageDeb and createDistributable each re-pack some jars (the skiko runtime stub) with fresh
#     zip timestamps, so two copies of one build differ in bytes and in the content-hashed name
#     while carrying identical contents. The `-<hash>.jar` suffix is dropped from the path for the
#     same reason;
#   * the launcher config is compared with those jar hashes stripped (it lists the same names);
#   * every other file by sha256, every symlink by its target;
#   * packaging metadata only one side carries is excluded: the deb's .desktop copy under lib/ and
#     share/doc/copyright, and the app-image's lib/app/.jpackage.xml.
image_manifest() {
  local root="$1" rel f key
  ( cd "$root" && find . \( -type f -o -type l \) -printf '%P\n' | LC_ALL=C sort ) | while IFS= read -r rel; do
    case "$rel" in
      "lib/$PKG_NAME-$PKG_NAME.desktop"|share/doc/copyright|lib/app/.jpackage.xml) continue ;;
    esac
    f="$root/$rel"
    key="$(printf '%s' "$rel" | sed -E 's/-[0-9a-f]{16,40}\.jar$/.jar/')"
    if [ -L "$f" ]; then
      printf '%s link %s\n' "$key" "$(readlink "$f")"
    elif [[ "$rel" == *.jar ]]; then
      # `unzip -lv` columns: Length Method Size Cmpr Date Time CRC-32 Name — keep name, CRC, length.
      printf '%s jar %s\n' "$key" "$(unzip -lv "$f" | awk '$7 ~ /^[0-9a-f]{8}$/ && NF >= 8 { name = $8; for (i = 9; i <= NF; i++) name = name " " $i; print name, $7, $1 }' | LC_ALL=C sort | sha256sum | cut -d' ' -f1)"
    elif [[ "$rel" == lib/app/*.cfg ]]; then
      printf '%s cfg %s\n' "$key" "$(sed -E 's/-[0-9a-f]{16,40}\.jar/.jar/g' "$f" | sha256sum | cut -d' ' -f1)"
    else
      printf '%s file %s\n' "$key" "$(sha256sum "$f" | cut -d' ' -f1)"
    fi
  done
}

DEB_X="$(mktemp -d)"; trap 'rm -rf "$DEB_X"' EXIT
dpkg-deb -x "$DEB_LOCAL" "$DEB_X/root" || die "could not unpack $DEB_LOCAL for the same-build proof"
[ -d "$DEB_X/root/opt/$PKG_NAME" ] || die "the deb has no /opt/$PKG_NAME — not the layout package-arch.sh repacks"
image_manifest "$DEB_X/root/opt/$PKG_NAME" > "$DEB_X/manifest-deb"
image_manifest "$IMG_DIR"                  > "$DEB_X/manifest-img"
grep -q '^lib/app/app-desktop\.jar jar ' "$DEB_X/manifest-deb" \
  || die "could not find the app-desktop jar in the deb — the same-build proof has nothing to anchor on"
if ! cmp -s "$DEB_X/manifest-deb" "$DEB_X/manifest-img"; then
  diff "$DEB_X/manifest-deb" "$DEB_X/manifest-img" | sed 's/^/    /' | head -40 >&2 || true
  die "the deb and the app-image are DIFFERENT builds (lines above: < deb, > app-image) — the app-image is stale. Run without --skip-gradle so both come from one gradle invocation."
fi
note "deb and app-image carry the same image, file for file ($(wc -l < "$DEB_X/manifest-deb") entries, jars by content) — one build"

MAINTAINER="$(dpkg-deb -f "$DEB_LOCAL" Maintainer)"
DESC="$(dpkg-deb -f "$DEB_LOCAL" Description | head -1)"
[ -n "$MAINTAINER" ] && [ -n "$DESC" ] || die "the deb has no Maintainer/Description — refusing to package with blanks"

# ---------------------------------------------------------------------------
# 4. the Arch package
# ---------------------------------------------------------------------------
note "package-arch: $PKG_BUILT (depends: $ARCH_DEPENDS_STR)"
PKG_LOCAL="$(bash "$REPO_DIR/scripts/package-arch.sh" \
  --app-image "$IMG_DIR" --name "$PKG_NAME" --version "$VERSION" --release "$RELEASE" \
  --desc "$DESC" --url "$PKG_URL" \
  --license GPL-3.0-or-later --license-file "$REPO_DIR/LICENSE" \
  --display-name "$PKG_NAME" --categories "Utility;" \
  --depends "$ARCH_DEPENDS_STR" --packager "$MAINTAINER" \
  --out "$ARCH_DIR")" || die "package-arch.sh failed"
[ -f "$PKG_LOCAL" ] && [ "$(basename "$PKG_LOCAL")" = "$PKG_BUILT" ] || die "package-arch.sh produced '$PKG_LOCAL', expected $ARCH_DIR/$PKG_BUILT"

# ---------------------------------------------------------------------------
# 5. sign — detached, ARMORED, under the SERVED name, beside each build output
# ---------------------------------------------------------------------------
sign_as() { # <artifact> <served-name>
  local src="$1" served="$2" asc
  asc="$(dirname "$src")/$served.asc"
  rm -f "$asc"
  gpg --batch --yes --local-user "$GPG_KEY" --armor --detach-sign --output "$asc" "$src" \
    || die "signing $served failed (key $GPG_KEY — runbook §3)"
  gpg --verify "$asc" "$src" >/dev/null 2>&1 || die "the signature just written for $served does not verify — refusing to continue"
  grep -q -- '-----BEGIN PGP SIGNATURE-----' "$asc" || die "$asc is not ASCII-armored — pacman would read a binary sidecar as its own signature"
  printf '%s\n' "$asc"
}
DEB_ASC="" PKG_ASC=""
if [ "$NO_SIGN" = 0 ]; then
  command -v gpg >/dev/null 2>&1 || die "gpg is required to sign (or pass --no-sign for a local test build)"
  DEB_ASC="$(sign_as "$DEB_LOCAL" "$DEB_SERVED")"
  PKG_ASC="$(sign_as "$PKG_LOCAL" "$PKG_SERVED")"
  note "signed both artifacts (armored .asc, key $GPG_KEY)"
else
  note "--no-sign: NOT signing — a release needs the .asc files; re-run without --no-sign"
fi

# ---------------------------------------------------------------------------
# 6. stage under the served names
# ---------------------------------------------------------------------------
STAGE="${STAGE:-$HOME/.andvari/release-$VERSION}"
mkdir -p "$STAGE"
cp -f "$DEB_LOCAL" "$STAGE/$DEB_SERVED"
cp -f "$PKG_LOCAL" "$STAGE/$PKG_SERVED"
[ -z "$DEB_ASC" ] || cp -f "$DEB_ASC" "$STAGE/$DEB_SERVED.asc"
[ -z "$PKG_ASC" ] || cp -f "$PKG_ASC" "$STAGE/$PKG_SERVED.asc"

echo "build-linux: $VERSION staged in $STAGE (served names):"
printf '  %-44s %12s  %s\n' NAME BYTES SHA256
for f in "$DEB_SERVED" "$DEB_SERVED.asc" "$PKG_SERVED" "$PKG_SERVED.asc"; do
  [ -f "$STAGE/$f" ] || continue
  printf '  %-44s %12s  %s\n' "$f" "$(stat -c %s "$STAGE/$f")" "$(sha256sum "$STAGE/$f" | cut -d' ' -f1)"
done
echo "build-linux: next — publish each file (andvari-publish-download hook), then scripts/release-spec.sh --version $VERSION …"
