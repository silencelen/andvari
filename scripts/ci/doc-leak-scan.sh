#!/usr/bin/env bash
# doc-leak-scan — the §5.5 endpoint-agnostic prose gate.
#
# Published clients bake no reference-instance hostname (§5.5 of
# docs/design/2026-07-15-multi-tenant-endpoints.md, "Baked-default swap + tailnet-leak removal").
# The client halves of that rule are pinned by tests (web/src/ui/Devices.test.ts,
# extension/src/serverurl.test.ts); this is the prose half, and prose is the surface a stranger
# reads FIRST. It began as three grep literals inline in scripts/verify.sh and is a script of its
# own now for one reason: a gate with no self-test is a claim, and this one had already been
# described as more than it was (audit H109 / regression of G55 — the CHANGELOG said the scan
# "covers the whole public tree" while it read docs/ plus five root files for three literals, and
# the normative spec, unscanned, named the operator's private hosts in MUST-level text).
#
#   Usage: scripts/ci/doc-leak-scan.sh [<root>]      (default: the repository root)
#   Exit:  0 = clean · 1 = a leak, an empty scope, or a missing root
#
# ---- what counts as a leak -----------------------------------------------------------------
# Two classes, both of which had live instances when this was written:
#
#   1. Addresses. The original three literals (taila2dff2, .ts.net, 192.168.2.122) plus the
#      CLASSES they belong to — RFC1918 and CGNAT/tailnet IPv4 — because the literal set only ever
#      matched the leaks that had already been found once. A private address in public prose is
#      never right: docs outlive an endpoint, and the reader cannot route to it anyway.
#
#   2. The operator's own machine names. `huginn`, `heimdall`, `hermod`, `muninn`, `skybox`,
#      `brokkr`, `ratatoskr` and the Windows release workstation `PRESTIGE` are one household's
#      hostnames; `LXC 117` and `/root/netplan` are that household's container ids and filesystem
#      layout. In a normative spec they are worse than noise — spec/04 §1 told every reader that a
#      key "MUST NEVER exist on ... huginn disks", a MUST that is meaningless outside one house.
#      PRESTIGE is matched case-SENSITIVELY so the script filename `prestige-release.ps1` (a real,
#      shipped, correctly-named artifact) does not trip it.
#
# Deliberately NOT patterns:
#   * `CT122` and its siblings. docs/ROADMAP.md ratifies these as "that one instance's host
#     labels, not part of the product" and explains the convention in its own reading guide; they
#     appear in ~20 dated campaign records. Making them leaks would mean either rewriting that
#     history or exempting the files that carry it — neither of which makes a stranger's read of
#     the product better. (The audit fix text offered them; this is the narrowing, stated here so
#     the next auditor is measuring against a decision rather than an oversight.)
#   * example.com and example.org — the correct placeholders, used everywhere on purpose.
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
[ -d "$ROOT" ] || { echo "doc-leak-scan: no such directory: $ROOT" >&2; exit 1; }

# The current-facing prose surface. spec/ is here because it is NORMATIVE: it is the document a
# reimplementer is told to follow, and it was the one part of the public tree the gate never read.
SCOPE=(spec docs README.md SECURITY.md CONTRIBUTING.md LICENSING.md extension/README.md)

# Exempt, each for a stated reason. Everything else in scope is held to the rule — including the
# user guide that triggered the original gate, because the point of a gate is to hold the file
# that already got this wrong once.
#   docs/design/**          dated point-in-time design records; they describe the pre-pivot
#                           tailnet topology because that is what was true on their date.
#   docs/hardening/**       ditto: dated audit records of a specific deployment under test.
#   docs/compliance/**      ditto: dated review records.
#   docs/PLAN-autonomous-*  ditto: dated campaign plans, closed.
#   docs/ROADMAP.md         dated campaign record, and the file that defines the instance-label
#                           convention the rest of the tree follows.
#   wave4-endpoint-promotion.md   the tailnet front IS the subject of that migration runbook.
#   release-signing-keys.md the ceremony runs on two specific named machines and the operator
#                           following it needs to know which; naming them is the runbook's job.
# (CHANGELOG.md is not in scope at all: dated historical entries, same argument, whole file.)
# (Anchored with the trailing ':' of grep -n's `path:line:` prefix, not '$' — the whole matched
# line follows it.)
EXEMPT='^docs/design/|^docs/hardening/|^docs/compliance/|^docs/PLAN-autonomous-|^docs/ROADMAP\.md:|^docs/runbooks/wave4-endpoint-promotion\.md:|^docs/runbooks/release-signing-keys\.md:'

IPV4='\b(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3})\b'
HOSTS='\b(huginn|heimdall|hermod|muninn|skybox|brokkr|ratatoskr)\b|PRESTIGE|\bLXC ?[0-9]{3}\b|/root/netplan'
NETS='taila2dff2|\.ts\.net|\.tailscale\b'
LEAK_RE="$IPV4|$HOSTS|$NETS"

# Only scan what exists — fixtures carry a slice of the layout, not all of it — but refuse to pass
# on an empty scope. A gate that scanned nothing and exited 0 is the failure mode this whole file
# is about (the node --test lesson in scripts/verify.sh, applied to itself).
present=()
for p in "${SCOPE[@]}"; do [ -e "$ROOT/$p" ] && present+=("$p"); done
if [ "${#present[@]}" -eq 0 ]; then
  echo "doc-leak-scan: none of the scoped paths exist under $ROOT — refusing to pass vacuously" >&2
  exit 1
fi

HITS=$(cd "$ROOT" && grep -rnE "$LEAK_RE" "${present[@]}" --include='*.md' 2>/dev/null | grep -vE "$EXEMPT") || true
if [ -n "$HITS" ]; then
  echo "    §5.5 DOC LEAK: reference-instance address or private host name in current-facing prose:" >&2
  printf '%s\n' "$HITS" | sed 's/^/      /' >&2
  echo "    Name the instance generically, or use example.com — docs outlive an endpoint, and a" >&2
  echo "    normative spec is read by people who have never heard of your machines." >&2
  exit 1
fi
exit 0
