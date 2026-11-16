#!/usr/bin/env bash
# Fails when the files under <dir> (the Safari extension's, in a built app) name the UI-test domain or any payment
# provider's test or sandbox host (extension/src/cardproviders.ts, CARD_PROVIDER_TEST_ORIGINS, read from the source so a
# host added there is checked too). Only the UI-test and DEBUG=1 builds of the extension list them; an app built for
# Release, which is what an archive is, must never carry one (round-13 review). Used by the Safari target's Release
# build phase (project.yml) and by ios-unsigned.yml.
set -euo pipefail
DIR="${1:?usage: check-no-test-hosts.sh <dir>}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO/extension/src/cardproviders.ts"
hosts="$(awk '/^export const CARD_PROVIDER_TEST_ORIGINS/{f=1} f&&/^\];/{exit} f' "$SRC" | grep -o 'origin: "https://[^"]*"' | sed -e 's|^origin: "https://||' -e 's|"$||')"
[ -n "$hosts" ] || { echo "error: could not read the payment providers' test hosts from $SRC"; exit 1; }
found=0
for h in andvari-uitest $hosts; do
  if grep -rIlF -- "$h" "$DIR"; then
    echo "error: the Safari extension's files name $h, which only the UI-test and DEBUG=1 builds may list"
    found=1
  fi
done
exit "$found"
