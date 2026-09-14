#!/usr/bin/env bash
# Self-test for `prune-artifacts.sh --downloads` — the /downloads retention rule (audit H107).
#
# Why this exists at all: that mode DELETES files from a public directory on another host, and the
# only thing standing between "keeps the last two releases" and "deletes the live installer" is a
# handful of regexes and a keep-set. A rule nobody can exercise is a rule nobody can trust, so the
# mode takes its container-shell prefix and its directory from ANDVARI_DOWNLOADS_EXEC /
# ANDVARI_DOWNLOADS_DIR (test-harness only, per the script header) and this file drives it against
# a fake /downloads on the local filesystem with `env` as the "container shell".
#
# What is asserted, in the order the rules are stated in prune-artifacts.sh:
#   1. anything the LIVE manifest or firefox-updates.json points at is never touched — including
#      an OLD version that is still referenced, which is the case that would hurt most;
#   2. the newest N releases stay whole (deb + .asc + msi together), older ones go, and the two
#      tracks (fleet / extension) are kept independently — the extension's version is far behind
#      the fleet's in real life and a single shared keep-set would prune the live extension;
#   3. manifest.json.* / manifest.json.sig.* backups LEAVE the web root (moved, never deleted) and
#      the live pair stays;
#   4. unrecognised names are reported and left alone;
#   5. no --apply => nothing changes on disk at all.
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/prune-artifacts.sh"
FAILED=0
fail() { echo "    FAIL: $*" >&2; FAILED=1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DL="$WORK/downloads"
BAK="$WORK/manifest-backups"
mkdir -p "$DL"

# A /downloads shaped like the real one at the time of the audit: many releases deep, two
# still-valid signed manifest pairs left behind as .bak copies, and the extension track sitting
# several fleet versions back.
touch "$DL"/andvari-0.6.0.deb \
      "$DL"/andvari-0.19.1.deb "$DL"/andvari-0.19.1.deb.asc \
      "$DL"/andvari-0.26.1.deb "$DL"/andvari-0.26.1.deb.asc "$DL"/andvari-0.26.1.msi \
      "$DL"/andvari-0.26.2.deb "$DL"/andvari-0.26.2.deb.asc "$DL"/andvari-0.26.2.msi \
      "$DL"/andvari-0.26.3.deb "$DL"/andvari-0.26.3.deb.asc "$DL"/andvari-0.26.3.msi \
      "$DL"/andvari-extension-chrome-0.25.0.zip "$DL"/andvari-extension-firefox-0.25.0.xpi \
      "$DL"/andvari-extension-chrome-0.26.0.zip "$DL"/andvari-extension-firefox-0.26.0.xpi \
      "$DL"/manifest.json.bak "$DL"/manifest.json.sig.bak \
      "$DL"/manifest.json.seq4 "$DL"/manifest.json.sig.seq4 \
      "$DL"/SHA256SUMS-0.26.3.txt "$DL"/'weird name.deb'

cat > "$DL/manifest.json" <<'JSON'
{
  "seq": 12,
  "linux":   { "version": "0.26.3", "url": "/downloads/andvari-0.26.3.deb" },
  "windows": { "version": "0.26.3", "url": "/downloads/andvari-0.26.3.msi" },
  "browserExtension": {
    "version": "0.26.0",
    "chromeUrl":  "/downloads/andvari-extension-chrome-0.26.0.zip",
    "firefoxUrl": "/downloads/andvari-extension-firefox-0.26.0.xpi"
  }
}
JSON
: > "$DL/manifest.json.sig"
# The Firefox auto-update channel still points at an OLD xpi — rule 1 must beat rule 2 here, or
# every Firefox install is stranded on its current version forever.
cat > "$DL/firefox-updates.json" <<'JSON'
{ "addons": { "andvari@silencelen": { "updates": [
  { "version": "0.25.0", "update_link": "https://example.org/downloads/andvari-extension-firefox-0.25.0.xpi" }
] } } }
JSON

run() { # run <extra args…>
  ANDVARI_DOWNLOADS_EXEC="env" \
  ANDVARI_DOWNLOADS_DIR="$DL" \
  ANDVARI_DOWNLOADS_BACKUP_DIR="$BAK" \
  bash "$SCRIPT" --downloads "$@" 2>&1
}

echo "==> prune-downloads: dry run changes nothing"
BEFORE="$(cd "$DL" && ls -1A | sort)"
OUT="$(run)" || fail "dry run exited non-zero: $OUT"
[ "$(cd "$DL" && ls -1A | sort)" = "$BEFORE" ] || fail "the dry run modified $DL"
[ -d "$BAK" ] && fail "the dry run created the backup dir"
printf '%s\n' "$OUT" | grep -q 'DRY RUN' || fail "dry run did not say so:\n$OUT"

echo "==> prune-downloads: --apply enforces the rule"
OUT="$(run --apply)" || fail "apply exited non-zero: $OUT"

must_exist() { [ -e "$DL/$1" ] || fail "$1 was removed but must be kept ($2)"; }
must_be_gone() { [ -e "$DL/$1" ] && fail "$1 survived but must be pruned ($2)"; }

# Rule 1 — live references, including the old-but-referenced xpi.
must_exist manifest.json                              "the live manifest"
must_exist manifest.json.sig                          "the live signature"
must_exist firefox-updates.json                       "the auto-update channel"
must_exist andvari-0.26.3.deb                         "referenced by the live manifest"
must_exist andvari-0.26.3.msi                         "referenced by the live manifest"
must_exist andvari-extension-chrome-0.26.0.zip        "referenced by the live manifest"
must_exist andvari-extension-firefox-0.25.0.xpi       "referenced by firefox-updates.json — dropping it strands every Firefox install"

# Rule 2 — current + previous, whole, per track.
must_exist andvari-0.26.2.deb                         "previous release"
must_exist andvari-0.26.2.deb.asc                     "previous release's signature — a release is kept whole"
must_exist andvari-0.26.2.msi                         "previous release"
must_exist andvari-extension-chrome-0.25.0.zip        "previous extension release (its own track)"
must_be_gone andvari-0.26.1.deb                       "three releases back"
must_be_gone andvari-0.26.1.deb.asc                   "three releases back"
must_be_gone andvari-0.26.1.msi                       "three releases back"
must_be_gone andvari-0.19.1.deb                       "ancient"
must_be_gone andvari-0.6.0.deb                        "ancient and unsigned"

# Rule 3 — backups leave the web root, and are not destroyed.
for b in manifest.json.bak manifest.json.sig.bak manifest.json.seq4 manifest.json.sig.seq4; do
  must_be_gone "$b" "an operator backup must not sit in the public web root"
  [ -e "$BAK/$b" ] || fail "$b was deleted instead of moved to the backup dir"
done

# Rule 4 — unrecognised names are reported, never touched.
must_exist SHA256SUMS-0.26.3.txt                      "not a managed artifact name"
must_exist 'weird name.deb'                           "outside the safe charset — reported, never named in a command"
printf '%s\n' "$OUT" | grep -q 'weird name.deb' || fail "the unsafe name was not reported"

echo "==> prune-downloads: a track with no artifacts at all does not abort the run"
# Regression pin for the bug this test found on its first run: the keep-set pipeline exits 1 when
# a track is empty (grep matches nothing), and under `set -e -o pipefail` that aborted the whole
# run BEFORE any fleet-track pruning — silently, with a zero-length report. An instance that has
# never served an extension zip is an ordinary instance, not an error.
DL2="$WORK/downloads2"; BAK2="$WORK/bak2"; mkdir -p "$DL2"
touch "$DL2"/andvari-0.24.0.deb "$DL2"/andvari-0.26.2.deb "$DL2"/andvari-0.26.3.deb
printf '{"linux":{"url":"/downloads/andvari-0.26.3.deb"}}' > "$DL2/manifest.json"
: > "$DL2/manifest.json.sig"
OUT2="$(ANDVARI_DOWNLOADS_EXEC="env" ANDVARI_DOWNLOADS_DIR="$DL2" ANDVARI_DOWNLOADS_BACKUP_DIR="$BAK2" \
        bash "$SCRIPT" --downloads --apply 2>&1)" || fail "run aborted on an extension-less directory: $OUT2"
[ -e "$DL2/andvari-0.26.3.deb" ] || fail "extension-less run removed the live deb"
[ -e "$DL2/andvari-0.26.2.deb" ] || fail "extension-less run removed the previous release"
[ -e "$DL2/andvari-0.24.0.deb" ] && fail "extension-less run did not prune the old release (did it abort early?)"

if [ "$FAILED" = 0 ]; then
  echo "prune-downloads self-test OK"
else
  echo "prune-downloads self-test FAILED" >&2
  exit 1
fi
