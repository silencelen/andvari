#!/usr/bin/env bash
# Downloads what an "iOS UI tests" run kept and prints its summary, for a reader with no Mac.
# Usage: app-ios/scripts/uitest-report.sh [--text] <run id> [directory]     (needs gh, signed in)
# Afterwards: <directory>/uitest-summary.json, <directory>/screenshots/<Class>.<test>__NN_<step>.png,
# <directory>/server.log, <directory>/xcodebuild-test.log and <directory>/AndvariUITests.xcresult.
# --text fetches only the run's text (the summary, the logs and the UI trees under <directory>/trees): a few megabytes
# where the screenshots and the result bundle are hundreds.
set -euo pipefail
ARTIFACT=ios-uitest
if [ "${1:-}" = "--text" ]; then
  ARTIFACT=ios-uitest-text
  shift
fi
RUN="${1:?usage: uitest-report.sh [--text] <run id> [directory]}"
OUT="${2:-uitest-run-$RUN}"
REPO="${UITEST_REPO:-silencelen/andvari}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$OUT"
gh run download "$RUN" --repo "$REPO" --name "$ARTIFACT" --dir "$OUT"
gh run view "$RUN" --repo "$REPO" --json conclusion,headBranch,headSha,url \
  --jq '"run \(.url)  \(.headBranch) \(.headSha[0:8])  conclusion: \(.conclusion)"'
python3 "$HERE/../uitest/summarize.py" "$OUT/uitest-summary.json" || true
echo "screenshots: $OUT/screenshots ($(find "$OUT/screenshots" -name '*.png' 2> /dev/null | wc -l | tr -d ' ') files)"
