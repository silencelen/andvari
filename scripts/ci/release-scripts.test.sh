#!/usr/bin/env bash
# Fixture-driven tests for the build-host release scripts (security review 2026-10).
#
# Each of these scripts runs once per release, on the build host, with real keys and real store
# credentials, so a regression in one is found at the worst moment or not at all. Every section
# below drives the REAL script inside a scratch repo tree (the scripts find their repo through
# their own location) with stubbed external tools, and asserts one property:
#
#   package-arch.sh     (c02) a package built by a NON-root user still records every member, in the
#                             tar and in .MTREE, as root:root — libalpm installs the recorded owner.
#   build-linux.sh      (c06) the "deb and app-image are one build" proof covers the WHOLE image: a
#                             stale image that differs only in a non-app-desktop jar is refused, a
#                             --skip-gradle image of another version is refused, and two copies of
#                             one build whose jars were re-packed with fresh timestamps still pass.
#   gh-release.sh       (c07) SHA256SUMS is signed by the PINNED release key even when gpg's default
#                             key is another one, and every .asc is verified against that key
#                             BEFORE the release is created: a stale .asc, or one by another key,
#                             stops the run with nothing published. It also prints the ceremony
#                             line `signandvari <ver> -Commit <sha>`.
#   publish-extension.sh (q22) the minted Chrome Web Store access token is never on curl's argv.
#   recovery-drill.sh   (q21) "RECOVERY DRILL PASSED" is printed only when vitest reports at least
#                             one passing test; an all-skipped run fails.
#
# RELEASE_SCRIPTS_SRC=<dir> runs the sections against another copy of scripts/ (used to show each
# one failing against the pre-fix scripts). Needs: bsdtar, zstd, dpkg-deb, gpg, unzip, python3,
# setpriv (the non-root package build is skipped, loudly, without it or when not run as root).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="${RELEASE_SCRIPTS_SRC:-$ROOT/scripts}"
FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

W="$(mktemp -d)"; chmod 755 "$W"
cleanup() { rm -rf "$W"; }
trap cleanup EXIT

# fakerepo <dir> <script>... — a repo skeleton carrying copies of the named scripts.
fakerepo() {
  local d="$1"; shift
  mkdir -p "$d/scripts"
  for s in "$@"; do cp "$SRC/$s" "$d/scripts/$s"; done
}

# mkjar <path> <stamp YYYY> <name=content>... — a real zip, entries dated <stamp>.
mkjar() {
  python3 - "$@" <<'PY'
import sys, zipfile
path, year, *entries = sys.argv[1:]
with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
    for e in entries:
        name, content = e.split("=", 1)
        zi = zipfile.ZipInfo(name, date_time=(int(year), 1, 2, 3, 4, 6))
        z.writestr(zi, content)
PY
}

# ============================================================== package-arch.sh (c02) =========
echo "==> release scripts: package-arch.sh records root:root when built by a non-root user"
if [ "$(id -u)" = 0 ] && command -v setpriv >/dev/null 2>&1; then
  PA="$W/pa"; mkdir -p "$PA/img/bin" "$PA/img/lib/app" "$PA/out" "$PA/tmp"
  cp "$SRC/package-arch.sh" "$PA/package-arch.sh"
  printf '#!/bin/sh\necho hi\n' > "$PA/img/bin/owntest"; chmod 755 "$PA/img/bin/owntest"
  printf 'jar\n' > "$PA/img/lib/app/owntest.jar"
  chmod -R a+rX "$PA"; chown -R 65534:65534 "$PA/out" "$PA/tmp"
  if out="$(cd "$PA" && setpriv --reuid=65534 --regid=65534 --clear-groups env HOME="$PA/tmp" TMPDIR="$PA/tmp" \
            bash "$PA/package-arch.sh" --app-image "$PA/img" --name owntest --version 1.0.0 \
              --desc "ownership test" --url https://example.invalid --out "$PA/out" 2>&1)"; then
    P="$PA/out/owntest-1.0.0-1-x86_64.pkg.tar.zst"
    bad="$(bsdtar --numeric-owner -tvf "$P" | awk '$3 != "0" || $4 != "0"')"
    [ -z "$bad" ] || fail "package-arch.sh as uid 65534 recorded non-root owners in the tar:
$bad"
    bad="$(bsdtar -tvf "$P" | awk '$3 != "root" || $4 != "root"')"
    [ -z "$bad" ] || fail "package-arch.sh as uid 65534 recorded non-root owner NAMES in the tar"
    bsdtar -xOf "$P" .MTREE | gzip -dc | grep -oE '(^| )(uid|gid)=[0-9]+' | grep -vqE '=0$' \
      && fail "package-arch.sh as uid 65534 recorded a non-root uid/gid in .MTREE (pacman -Qkk would call it consistent)"
  else
    fail "package-arch.sh failed when run as uid 65534: $out"
  fi
  # The script's own --self-test, as the same non-root user: it now asserts ownership itself.
  (cd "$PA" && setpriv --reuid=65534 --regid=65534 --clear-groups env HOME="$PA/tmp" TMPDIR="$PA/tmp" \
     bash "$PA/package-arch.sh" --self-test >/dev/null 2>&1) || fail "package-arch.sh --self-test fails as a non-root user"
else
  echo "    SKIP: not root or no setpriv — the non-root package build cannot be exercised here."
fi

# ============================================================== build-linux.sh (c06) ==========
echo "==> release scripts: build-linux.sh proves the deb and the app-image are one build, whole"
BL="$W/bl"; fakerepo "$BL" build-linux.sh package-arch.sh
mkdir -p "$BL/app-desktop" "$BL/core/src/commonMain/kotlin/io/silencelen/andvari/core/client"
printf 'packageVersion = "9.9.9"\n' > "$BL/app-desktop/build.gradle.kts"
printf 'const val ANDVARI_CLIENT_VERSION = "9.9.9"\n' > "$BL/core/src/commonMain/kotlin/io/silencelen/andvari/core/client/AndvariApi.kt"
printf 'GPL text\n' > "$BL/LICENSE"
BIN="$BL/app-desktop/build/compose/binaries/main"

# image <dir> <core-content> <stamp> <hash-suffix> — one app-image tree.
image() {
  local d="$1" core="$2" stamp="$3" h="$4"
  rm -rf "$d"; mkdir -p "$d/bin" "$d/lib/app" "$d/lib/runtime/lib"
  printf '#!/bin/sh\nexec true\n' > "$d/bin/andvari"; chmod 755 "$d/bin/andvari"
  mkjar "$d/lib/app/app-desktop-0123456789abcdef0123456789abcdef.jar" 2026 "Main.class=main-v1"
  mkjar "$d/lib/app/core-jvm-fedcba9876543210fedcba9876543210.jar" 2026 "Core.class=$core"
  # re-packed per target with a fresh timestamp and therefore a fresh name hash (the skiko stub)
  mkjar "$d/lib/app/skiko-awt-runtime-linux-x64-0.8.18-$h.jar" "$stamp" "META-INF/MANIFEST.MF=Manifest-Version: 1.0"
  printf '[Application]\napp.classpath=$APPDIR/skiko-awt-runtime-linux-x64-0.8.18-%s.jar\n' "$h" > "$d/lib/app/andvari.cfg"
  printf 'runtime\n' > "$d/lib/runtime/lib/libjvm.so"
  ln -s libjvm.so "$d/lib/runtime/lib/libjvm-link.so"
}
# mkdeb <image-dir> — a deb carrying that image under /opt/andvari, plus the deb-only metadata.
mkdeb() {
  local img="$1" r="$W/debroot"
  rm -rf "$r"; mkdir -p "$r/DEBIAN" "$r/opt" "$BIN/deb"
  cp -a "$img" "$r/opt/andvari"
  printf '[Desktop Entry]\n' > "$r/opt/andvari/lib/andvari-andvari.desktop"
  mkdir -p "$r/opt/andvari/share/doc"; printf 'copyright\n' > "$r/opt/andvari/share/doc/copyright"
  cat > "$r/DEBIAN/control" <<CTL
Package: andvari
Version: 9.9.9-1
Architecture: amd64
Maintainer: Test <t@example.invalid>
Depends: libc6, zlib1g
Description: andvari test build
CTL
  rm -f "$BIN"/deb/*.deb
  dpkg-deb --root-owner-group -b "$r" "$BIN/deb/andvari_9.9.9-1_amd64.deb" >/dev/null
}
jpstate() { printf '<jpackage-state><app-version>%s</app-version></jpackage-state>\n' "$1" > "$BIN/app/andvari/lib/app/.jpackage.xml"; }
bl() { (cd "$BL" && HOME="$W/home" ANDVARI_GRADLE_LOCK="$W/gradle.lock" \
        bash scripts/build-linux.sh --skip-gradle --no-sign --stage "$W/bl-stage" 2>&1); }

# (a) one build: the deb's copy and the app-image differ only by the per-target skiko re-pack.
image "$W/img-deb" core-v1 2026 a3100d18fbdbed5ddfea8111cbc29d7
mkdeb "$W/img-deb"
image "$BIN/app/andvari" core-v1 2025 72be21dd83d18946fd6e9b8e1e9bbe6; jpstate 9.9.9
out="$(bl)" || fail "build-linux.sh refused two copies of ONE build (jars re-packed with new timestamps):
$out"
# (b) a stale image: same app-desktop jar, a DIFFERENT core jar.
image "$BIN/app/andvari" core-v0-STALE 2025 72be21dd83d18946fd6e9b8e1e9bbe6; jpstate 9.9.9
out="$(bl)" && fail "build-linux.sh packaged a stale app-image whose core jar differs from the deb's"
printf '%s\n' "$out" | grep -q 'DIFFERENT builds' || fail "the stale-core refusal does not say why:
$out"
# (c) --skip-gradle with an image that declares another version.
image "$BIN/app/andvari" core-v1 2025 72be21dd83d18946fd6e9b8e1e9bbe6; jpstate 9.9.8
out="$(bl)" && fail "build-linux.sh --skip-gradle accepted an app-image that declares version 9.9.8"
printf '%s\n' "$out" | grep -q 'stale app-image' || fail "the stale-version refusal does not say why:
$out"

# ============================================================== gh-release.sh (c07) ===========
echo "==> release scripts: gh-release.sh signs with the pinned key and verifies every .asc first"
if command -v gpg >/dev/null 2>&1; then
  GR="$W/gr"; fakerepo "$GR" gh-release.sh
  export GNUPGHOME="$W/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
  gpg --batch --quiet --passphrase '' --quick-gen-key 'release <rel@example.invalid>' ed25519 sign 1d 2>/dev/null
  gpg --batch --quiet --passphrase '' --quick-gen-key 'other <other@example.invalid>' ed25519 sign 1d 2>/dev/null
  fpr() { gpg --batch --with-colons --list-keys "$1" | awk -F: '$1 == "fpr" { print $10; exit }'; }
  gpg --batch --quiet --check-trustdb >/dev/null 2>&1 || true
  K_REL="$(fpr rel@example.invalid)"; K_OTHER="$(fpr other@example.invalid)"
  # gpg's DEFAULT key is the wrong one — the configuration c07 is about.
  printf 'default-key %s\n' "$K_OTHER" > "$GNUPGHOME/gpg.conf"
  signas() { gpg --batch --yes --quiet --local-user "$1" --armor --detach-sign --output "$3" "$2"; }

  GBIN="$GR/app-desktop/build/compose/binaries/main"; mkdir -p "$GBIN/deb" "$GBIN/arch"
  printf 'deb bytes\n' > "$GBIN/deb/andvari_9.9.9-1_amd64.deb"
  printf 'pkg bytes\n' > "$GBIN/arch/andvari-9.9.9-1-x86_64.pkg.tar.zst"
  ( cd "$GR" && git -c init.defaultBranch=main init -q && git add -A \
      && git -c user.name=t -c user.email=t@example.invalid commit -qm r && git tag v9.9.9 )
  GR_COMMIT="$(git -C "$GR" rev-parse HEAD)"

  # gh stub: the release does not exist yet; create/upload are recorded, uploads are kept.
  mkdir -p "$W/ghbin" "$W/uploaded"
  cat > "$W/ghbin/gh" <<STUB
#!/usr/bin/env bash
printf '%s\n' "gh \$*" >> "$W/gh.log"
case "\$1 \$2" in
  "release view") case "\$*" in *--json\ body*) echo ""; exit 0 ;; esac; exit 1 ;;
  "release create") exit 0 ;;
  "release upload") shift 3; for f in "\$@"; do [ "\$f" = --clobber ] || cp -f "\$f" "$W/uploaded/"; done ;;
esac
exit 0
STUB
  chmod 755 "$W/ghbin/gh"
  gr() { rm -rf "$W/gr-stage"; : > "$W/gh.log"; rm -f "$W/uploaded"/*
         (cd "$GR" && PATH="$W/ghbin:$PATH" GH_REPO=test/test ANDVARI_GPG_KEY="$K_REL" \
          bash scripts/gh-release.sh --version 9.9.9 --no-android --stage "$W/gr-stage" 2>&1); }
  signer_of() { gpg --batch --status-fd 1 --verify "$1" "$2" 2>/dev/null | awk '$2 == "VALIDSIG" { print $NF }'; }

  # (a) everything signed by the release key: published, and SUMS is by the release key.
  signas "$K_REL" "$GBIN/deb/andvari_9.9.9-1_amd64.deb" "$GBIN/deb/andvari-9.9.9.deb.asc"
  signas "$K_REL" "$GBIN/arch/andvari-9.9.9-1-x86_64.pkg.tar.zst" "$GBIN/arch/andvari-9.9.9-x86_64.pkg.tar.zst.asc"
  out="$(gr)" || fail "gh-release.sh refused a correctly signed release:
$out"
  if [ -f "$W/uploaded/SHA256SUMS-9.9.9.txt.asc" ]; then
    s="$(signer_of "$W/uploaded/SHA256SUMS-9.9.9.txt.asc" "$W/uploaded/SHA256SUMS-9.9.9.txt")"
    [ "$s" = "$K_REL" ] || fail "SHA256SUMS was signed by ${s:-nothing}, not the release key $K_REL (gpg's default key decided)"
  else
    fail "SHA256SUMS-9.9.9.txt.asc was not uploaded"
  fi
  printf '%s\n' "$out" | grep -q "signandvari 9.9.9 -Commit $GR_COMMIT" \
    || fail "gh-release.sh did not print the ceremony line 'signandvari 9.9.9 -Commit $GR_COMMIT'"

  # (b) a stale .asc: the package bytes changed after it was signed (a --skip-gradle --no-sign re-run).
  printf 'pkg bytes, rebuilt\n' > "$GBIN/arch/andvari-9.9.9-1-x86_64.pkg.tar.zst"
  out="$(gr)" && fail "gh-release.sh published an Arch package beside a signature of OTHER bytes"
  grep -q 'release create\|release upload' "$W/gh.log" && fail "gh-release.sh created/uploaded before refusing the stale .asc"
  signas "$K_REL" "$GBIN/arch/andvari-9.9.9-1-x86_64.pkg.tar.zst" "$GBIN/arch/andvari-9.9.9-x86_64.pkg.tar.zst.asc"

  # (c) a good signature by ANOTHER key in the keyring.
  signas "$K_OTHER" "$GBIN/deb/andvari_9.9.9-1_amd64.deb" "$GBIN/deb/andvari-9.9.9.deb.asc"
  out="$(gr)" && fail "gh-release.sh published a deb signature made by a key that is not the release key"
  grep -q 'release create\|release upload' "$W/gh.log" && fail "gh-release.sh created/uploaded before refusing the foreign .asc"
  printf '%s\n' "$out" | grep -q "NOT by the release key" || fail "the foreign-key refusal does not say why:
$out"
  gpgconf --kill gpg-agent >/dev/null 2>&1 || true   # the scratch keyring's agent, not the host's
  unset GNUPGHOME
else
  echo "    SKIP: gpg not installed — gh-release.sh signing not exercised."
fi

# ============================================================== publish-extension.sh (q22) ====
echo "==> release scripts: publish-extension.sh keeps the Web Store token off curl's argv"
PE="$W/pe"; fakerepo "$PE" publish-extension.sh
mkdir -p "$PE/extension/artifacts" "$W/curlbin"
printf '{ "version": "9.9.9" }\n' > "$PE/extension/manifest.json"
printf 'zip\n' > "$PE/extension/artifacts/andvari-extension-chrome-9.9.9.zip"
cat > "$W/store.env" <<'ENV'
CWS_CLIENT_ID=client-id
CWS_CLIENT_SECRET=client-secret
CWS_REFRESH_TOKEN=refresh-token
CWS_ITEM_ID=item123
ENV
TOKEN=ya29.TOKEN-SENTINEL-c0ffee
cat > "$W/curlbin/curl" <<STUB
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$W/curl.argv"
cfg=""
for a in "\$@"; do [ "\$a" = "-" ] && cfg="\$(cat)"; done
printf '%s\n---\n' "\$cfg" >> "$W/curl.stdin"
case "\$* \$cfg" in
  *oauth2.googleapis.com*) echo '{"access_token":"$TOKEN"}' ;;
  *upload/chromewebstore*) echo '{"uploadState":"SUCCESS"}' ;;
  *publish*)               echo '{"status":["OK"],"statusDetail":["ok"]}' ;;
esac
STUB
chmod 755 "$W/curlbin/curl"
: > "$W/curl.argv"; : > "$W/curl.stdin"
out="$(cd "$PE" && PATH="$W/curlbin:$PATH" ANDVARI_STORE_ENV="$W/store.env" ANDVARI_CWS_QUEUE="$W/cwsq" HOME="$W/home" \
       bash scripts/publish-extension.sh --chrome 2>&1)" || fail "publish-extension.sh --chrome failed against the stub store:
$out"
grep -qF "$TOKEN" "$W/curl.argv" && fail "the Web Store access token appeared on curl's argv (world-readable /proc/<pid>/cmdline):
$(grep -F "$TOKEN" "$W/curl.argv" | sed "s/$TOKEN/<TOKEN>/g")"
[ "$(grep -cF "Authorization: Bearer $TOKEN" "$W/curl.stdin")" -ge 2 ] \
  || fail "the upload and publish calls no longer carry the token (expected it in two stdin configs)"
grep -qE 'client-secret|refresh-token' "$W/curl.argv" && fail "a long-lived store secret appeared on curl's argv (H63)"

# ============================================================== recovery-drill.sh (q21) =======
echo "==> release scripts: recovery-drill.sh prints PASSED only for a drill that ran a test"
RD="$W/rd"; fakerepo "$RD" recovery-drill.sh
mkdir -p "$RD/web" "$RD/server/build/libs" "$RD/tools/recovery-cli/build/libs" "$W/rdbin"
: > "$RD/server/build/libs/andvari-server-9.9.9.jar"
: > "$RD/tools/recovery-cli/build/libs/andvari-recovery-cli-9.9.9.jar"
printf '#!/bin/sh\nexit 0\n' > "$RD/gradlew"; chmod 755 "$RD/gradlew"
cat > "$W/rdbin/java" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *keygen*) printf 'Recovery seed (base64url)\n  c2VlZA\nANDVARI_RECOVERY_PUBKEY=pub\nANDVARI_RECOVERY_FINGERPRINT=0123456789abcdef0123\n' ;;
  *) exec sleep 30 ;;
esac
STUB
printf '#!/bin/sh\nexit 0\n' > "$W/rdbin/curl"
cat > "$W/rdbin/npx" <<'STUB'
#!/usr/bin/env bash
case "${STUB_VITEST:-}" in
  skipped) printf ' Test Files  1 skipped (1)\n      Tests  1 skipped (1)\n' ;;
  passed)  printf ' Test Files  1 passed (1)\n      Tests  1 passed (1)\n' ;;
esac
exit 0
STUB
chmod 755 "$W/rdbin"/*
rd() { (cd "$RD" && PATH="$W/rdbin:$PATH" STUB_VITEST="$1" ANDVARI_GRADLE_LOCK="$W/gradle.lock" \
        bash scripts/recovery-drill.sh 2>&1); }
out="$(rd skipped)"; rc=$?
printf '%s\n' "$out" | grep -q 'RECOVERY DRILL PASSED' && fail "recovery-drill.sh printed PASSED for a run whose only test was SKIPPED"
[ "$rc" -ne 0 ] || fail "recovery-drill.sh exited 0 for an all-skipped vitest run"
out="$(rd passed)" || fail "recovery-drill.sh failed a run that reported a passing test:
$out"
printf '%s\n' "$out" | grep -q 'RECOVERY DRILL PASSED' || fail "recovery-drill.sh did not print PASSED for a passing run"

if [ "$FAILED" = 0 ]; then
  echo "    release-scripts tests OK"
else
  echo "    release-scripts tests FAILED ($SRC)" >&2
  exit 1
fi
