#!/usr/bin/env bash
# Publish the andvari browser extension to BOTH stores from a build host (huginn):
#   * Chrome Web Store  — unlisted, via the Publish API (OAuth2)
#   * Firefox AMO       — self-distribution / unlisted, via `web-ext sign`
#
#   scripts/publish-extension.sh [--version X.Y.Z] [--chrome] [--firefox] [--dry-run]
#
# Default = BOTH browsers, version read from extension/manifest.json.
# This is the local-publish pattern (like ship.sh / publish-image.sh) — deliberately
# NOT CI (this account's GitHub Actions billing is broken). Zips must already be built
# (extension/package.mjs). NOTE: each store STILL REVIEWS the update before it goes
# live — this automates the upload + submit, not Google's/Mozilla's review wait.
#
# Credentials live OUTSIDE this repo (which is destined to go public):
#   ~/.andvari/store-publish.env  (chmod 600) — see scripts/store-publish.env.template
#   and docs/runbooks/extension-store-publishing.md § Automated publishing.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ANDVARI_STORE_ENV:-$HOME/.andvari/store-publish.env}"
# Chrome push queue (standard process 2026-07-17): a version rejected with ITEM_NOT_UPDATABLE
# (store busy reviewing a prior one) is written here — single line, newest wins — for an
# operator-side watcher to push when the store frees up. Harmless if nothing reads it.
CWS_QUEUE_FILE="${ANDVARI_CWS_QUEUE:-$HOME/.andvari/cws-push-queue}"
DO_CHROME=0 DO_FIREFOX=0 DRY=0 VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?}"; shift 2 ;;
    --chrome)  DO_CHROME=1; shift ;;
    --firefox) DO_FIREFOX=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; exit 0 ;;
    *) echo "unknown arg: $1 (see --help)" >&2; exit 2 ;;
  esac
done
[ "$DO_CHROME" = 0 ] && [ "$DO_FIREFOX" = 0 ] && { DO_CHROME=1; DO_FIREFOX=1; }  # neither => both

[ -f "$ENV_FILE" ] || {
  echo "ERROR: no creds file $ENV_FILE" >&2
  echo "  copy scripts/store-publish.env.template there, chmod 600, and fill it in." >&2
  echo "  one-time setup: docs/runbooks/extension-store-publishing.md § Automated publishing" >&2
  exit 1
}
# shellcheck source=/dev/null
set -a; . "$ENV_FILE"; set +a

# version: prefer flag, else the single source of truth (manifest.json)
VERSION="${VERSION:-$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$REPO_DIR/extension/manifest.json" | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')}"
[ -n "$VERSION" ] || { echo "ERROR: could not determine extension version" >&2; exit 1; }

CHROME_ZIP="$REPO_DIR/extension/artifacts/andvari-extension-chrome-$VERSION.zip"
FIREFOX_ZIP="$REPO_DIR/extension/artifacts/andvari-extension-firefox-$VERSION.zip"
echo "[publish-ext] version $VERSION  chrome=$DO_CHROME firefox=$DO_FIREFOX dry-run=$DRY"

# ---------------------------- Chrome Web Store ----------------------------
publish_chrome() {
  : "${CWS_CLIENT_ID:?set in $ENV_FILE}" "${CWS_CLIENT_SECRET:?set in $ENV_FILE}"
  : "${CWS_REFRESH_TOKEN:?set in $ENV_FILE}" "${CWS_ITEM_ID:?set in $ENV_FILE}"
  [ -f "$CHROME_ZIP" ] || { echo "ERROR: missing $CHROME_ZIP — run: (cd extension && node package.mjs)" >&2; return 1; }
  echo "[chrome] item $CWS_ITEM_ID  package $(basename "$CHROME_ZIP")"
  if [ "$DRY" = 1 ]; then echo "[chrome] DRY-RUN: would mint token, upload $(basename "$CHROME_ZIP"), publish item $CWS_ITEM_ID"; return; fi

  local tok=""
  tok=$(curl -sf -X POST https://oauth2.googleapis.com/token \
        -d client_id="$CWS_CLIENT_ID" -d client_secret="$CWS_CLIENT_SECRET" \
        -d refresh_token="$CWS_REFRESH_TOKEN" -d grant_type=refresh_token 2>/dev/null | jq -r '.access_token // empty') || true
  [ -n "$tok" ] || { echo "[chrome] ERROR: OAuth token exchange failed — check CWS_* creds" >&2; return 1; }

  echo "[chrome] uploading package…"
  local up state
  up=$(curl -s -X PUT -T "$CHROME_ZIP" \
        -H "Authorization: Bearer $tok" -H "x-goog-api-version: 2" \
        "https://www.googleapis.com/upload/chromewebstore/v1.1/items/$CWS_ITEM_ID") || true
  state=$(echo "$up" | jq -r '.uploadState // "?"' 2>/dev/null || echo "?")
  if [ "$state" != "SUCCESS" ]; then
    # Store busy (a prior version still in review) → QUEUE this version for the auto-push
    # watcher instead of failing: newest-wins, a later enqueue simply overwrites the file.
    # (Standard process 2026-07-17: releases outpace Chrome review; the watcher drains the queue.)
    if echo "$up" | grep -q ITEM_NOT_UPDATABLE; then
      printf '%s\n' "$VERSION" > "$CWS_QUEUE_FILE"
      echo "[chrome] store is mid-review (ITEM_NOT_UPDATABLE) — QUEUED $VERSION at $CWS_QUEUE_FILE (newest wins; the watcher pushes it when the store frees up)."
      return 0
    fi
    echo "[chrome] ERROR: upload state=$state → $up" >&2
    return 1
  fi

  echo "[chrome] publishing (submit for review)…"
  local pub
  pub=$(curl -s -X POST -H "Authorization: Bearer $tok" -H "x-goog-api-version: 2" -H "Content-Length: 0" \
        "https://www.googleapis.com/chromewebstore/v1.1/items/$CWS_ITEM_ID/publish") || true
  if echo "$pub" | jq -e '.error' >/dev/null 2>&1; then
    echo "[chrome] PUBLISH BLOCKED: $(echo "$pub" | jq -r '.error.message')" >&2
    echo "[chrome] NOTE: the $VERSION package IS uploaded as the draft — fix the above in the dashboard, then re-run '--chrome' to publish (no re-upload needed)." >&2
    return 1
  fi
  echo "[chrome] response: $(echo "$pub" | jq -c '{status,statusDetail}' 2>/dev/null || echo "$pub")"
  # A successful push supersedes anything still waiting: drop a queued version at or below this one.
  if [ -f "$CWS_QUEUE_FILE" ] && [ "$(cat "$CWS_QUEUE_FILE" 2>/dev/null)" = "$VERSION" ]; then rm -f "$CWS_QUEUE_FILE"; fi
  echo "[chrome] uploaded + submitted. Google review is pending before the update goes live."
}

# ------------------ Firefox AMO (self-distribution / unlisted) ------------------
publish_firefox() {
  : "${AMO_JWT_ISSUER:?set in $ENV_FILE}" "${AMO_JWT_SECRET:?set in $ENV_FILE}"
  [ -f "$FIREFOX_ZIP" ] || { echo "ERROR: missing $FIREFOX_ZIP — run: (cd extension && node package.mjs)" >&2; return 1; }
  command -v npx >/dev/null || { echo "[firefox] ERROR: npx (Node) required for web-ext" >&2; return 1; }

  local tmp out addon; tmp="$(mktemp -d)"; out="$REPO_DIR/extension/artifacts"
  unzip -oq "$FIREFOX_ZIP" -d "$tmp"
  addon=$(jq -r '.browser_specific_settings.gecko.id // "?"' "$tmp/manifest.json" 2>/dev/null)
  echo "[firefox] sign (AMO, channel=unlisted)  addon $addon  source $(basename "$FIREFOX_ZIP")"

  if [ "$DRY" = 1 ]; then echo "[firefox] DRY-RUN: would 'web-ext sign --channel=unlisted' the $VERSION firefox build"; rm -rf "$tmp"; return; fi

  npx --yes web-ext@latest sign \
      --channel=unlisted \
      --api-key="$AMO_JWT_ISSUER" --api-secret="$AMO_JWT_SECRET" \
      --source-dir="$tmp" --artifacts-dir="$out" \
    || { echo "[firefox] ERROR: web-ext sign failed" >&2; rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"

  local xpi named; xpi=$(ls -1t "$out"/*.xpi 2>/dev/null | head -1)
  named="$out/andvari-extension-firefox-$VERSION.xpi"
  [ "$xpi" = "$named" ] || cp "$xpi" "$named"

  # Auto-update channel: the manifest bakes gecko.update_url → /downloads/firefox-updates.json.
  # Assert the SIGNED bytes actually carry it (a build regression here silently strands every
  # install on its current version forever), then emit the updates.json to host alongside the xpi.
  local m; m=$(unzip -p "$named" manifest.json 2>/dev/null)
  local upd; upd=$(echo "$m" | jq -r '.browser_specific_settings.gecko.update_url // empty')
  local ver; ver=$(echo "$m" | jq -r '.version // empty')
  [ "$ver" = "$VERSION" ] || { echo "[firefox] ERROR: signed xpi version '$ver' != $VERSION" >&2; return 1; }
  if [ -z "$upd" ]; then
    echo "[firefox] WARNING: signed xpi has NO update_url — installs of this build will never auto-update." >&2
  else
    local origin="${upd%/downloads/firefox-updates.json}"
    jq -n --arg id "$(echo "$m" | jq -r '.browser_specific_settings.gecko.id')" \
          --arg ver "$VERSION" \
          --arg link "$origin/downloads/andvari-extension-firefox-$VERSION.xpi" \
          '{addons: {($id): {updates: [{version: $ver, update_link: $link}]}}}' \
          > "$out/firefox-updates.json"
    echo "[firefox] update channel: $out/firefox-updates.json (serve at $upd)"
  fi
  echo "[firefox] signed XPI: $named"
  echo "[firefox] host the .xpi AND firefox-updates.json at the instance's downloads dir"
  echo "          (ANDVARI_DOWNLOADS_DIR) — installs poll updates.json and self-update to newer signed builds."
}

# Run every requested leg even if an earlier one hard-fails (a chrome block must not
# strand the firefox sign — bitten 2026-07-17); exit nonzero if any leg truly failed.
RC=0
[ "$DO_CHROME"  = 1 ] && { publish_chrome  || RC=1; }
[ "$DO_FIREFOX" = 1 ] && { publish_firefox || RC=1; }
[ "$RC" = 0 ] && echo "[publish-ext] done (version $VERSION)." || echo "[publish-ext] finished WITH FAILURES (version $VERSION) — see above." >&2
exit "$RC"
