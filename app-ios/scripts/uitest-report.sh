#!/usr/bin/env bash
# Downloads what an "iOS UI tests" run kept and prints its summary, for a reader with no Mac.
# Usage: app-ios/scripts/uitest-report.sh <run id> [directory]     (needs gh, signed in)
# Afterwards: <directory>/uitest-summary.json, <directory>/screenshots/<Class>.<test>__NN_<step>.png,
# <directory>/server.log, <directory>/xcodebuild-test.log and <directory>/AndvariUITests.xcresult.
set -euo pipefail
RUN="${1:?usage: uitest-report.sh <run id> [directory]}"
OUT="${2:-uitest-run-$RUN}"
REPO="${UITEST_REPO:-silencelen/andvari}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$OUT"
gh run download "$RUN" --repo "$REPO" --name ios-uitest --dir "$OUT"
gh run view "$RUN" --repo "$REPO" --json conclusion,headBranch,headSha,url \
  --jq '"run \(.url)  \(.headBranch) \(.headSha[0:8])  conclusion: \(.conclusion)"'
python3 "$HERE/../uitest/summarize.py" "$OUT/uitest-summary.json" || true
echo "screenshots: $OUT/screenshots ($(find "$OUT/screenshots" -name '*.png' 2> /dev/null | wc -l | tr -d ' ') files)"
