#!/usr/bin/env bash
# andvari self-host bring-up — THE one command (design 2026-07-15 §8.2).
#
#   ./bringup.sh                     interactive: prompts for origin + name
#   ./bringup.sh --origin https://vault.example.org --instance-name "our vault" \
#                [--admin-email you@example.org] [--caddy] [--yes]
#   ./bringup.sh --build             build the image from THIS source checkout
#                                    (default is pull ghcr.io/silencelen/andvari)
#
# What it does (idempotent — safe to re-run; it REFUSES to overwrite an
# existing andvari.env):
#   1. writes andvari.env from andvari.env.template — canonical origin,
#      signup-mode invite-only, TOTP not required, offline cache allowed,
#      instance name, ANDVARI_STRICT_ENV=1, break-glass hostname left unset
#   2. generates ANDVARI_ENUM_SECRET
#   3. runs the escrow ceremony (`recovery-cli keygen`, network-less container)
#      and pins ANDVARI_RECOVERY_PUBKEY / _FINGERPRINT — enrollment stays
#      refused until these exist, so bring-up never skips past a dead instance
#   4. mints ANDVARI_BOOTSTRAP_TOKEN, `docker compose up -d`, waits for
#      /healthz, smoke-checks GET /api/v1/client-policy for the declared
#      policy fields, prints the first-admin enroll URL
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ENV_FILE=andvari.env
TEMPLATE=andvari.env.template
DOTENV=.env
IMAGE_REPO=ghcr.io/silencelen/andvari
BASE_URL=http://127.0.0.1:8080

ORIGIN="" INSTANCE_NAME="" ADMIN_EMAIL="" ASSUME_YES=0 USE_CADDY=0 DO_BUILD=0

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

# ---------- helpers ----------------------------------------------------------

b64url() { base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='; }
gen_secret() { head -c "${1:-32}" /dev/urandom | b64url; }

# get_env KEY -> value from andvari.env ('' if absent/blank)
get_env() { [ -f "$ENV_FILE" ] && sed -n "s/^$1=//p" "$ENV_FILE" | head -1 || true; }

# set_env KEY VALUE — replace the first `KEY=` or commented `# KEY=` line,
# append if absent. awk + ENVIRON: portable (no GNU sed -i / 0,/re/), and the
# value needs no escaping.
set_env() {
  local tmp; tmp=$(mktemp)
  K="$1" V="$2" awk '
    BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
    !done && $0 ~ ("^#? ?" k "=") { print k "=" v; done = 1; next }
    { print }
    END { if (!done) print k "=" v }
  ' "$ENV_FILE" > "$tmp"
  mv "$tmp" "$ENV_FILE" && chmod 600 "$ENV_FILE"
}

set_dotenv() { # KEY VALUE into .env (compose interpolation vars)
  local k="$1" v="$2" tmp
  touch "$DOTENV"
  tmp=$(mktemp)
  grep -vE "^${k}=" "$DOTENV" > "$tmp" || true
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  mv "$tmp" "$DOTENV"
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

host_of() { local h="${1#*://}"; h="${h%%/*}"; printf '%s' "${h%%:*}"; }

is_local_host() { # loopback / RFC1918 / mDNS-class names (dev/LAN parity)
  case "$1" in
    localhost|127.*|::1|10.*|192.168.*|*.local|*.lan|*.internal|*.home.arpa) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    *) return 1 ;;
  esac
}

canonicalize_origin() { # -> echoes canonical origin or dies
  local o; o=$(lower "$1"); o="${o%/}"
  case "$o" in
    https://*) o="${o%:443}" ;;
    http://*)  o="${o%:80}"  ;;
    *) die "origin must start with http:// or https:// (got: $1)" ;;
  esac
  printf '%s' "$o" | grep -Eq '^https?://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$' \
    || die "origin must be a canonical scheme://host[:non-default-port] — lowercase, no path, no trailing slash (got: $o)"
  case "$o" in
    http://*) is_local_host "$(host_of "$o")" \
      || die "plain http is only allowed for loopback/RFC1918/.local-class hosts — an internet-facing instance needs https (got: $o)" ;;
  esac
  printf '%s' "$o"
}

compose() {
  # COMPOSE_FILE in .env (written by --caddy) makes plain invocations include
  # the overlay too; docker compose reads .env from this directory itself.
  docker compose "$@"
}

# ---------- arg parse ---------------------------------------------------------

while [ $# -gt 0 ]; do
  case "$1" in
    --origin)        ORIGIN="$2"; shift 2 ;;
    --origin=*)      ORIGIN="${1#*=}"; shift ;;
    --instance-name) INSTANCE_NAME="$2"; shift 2 ;;
    --instance-name=*) INSTANCE_NAME="${1#*=}"; shift ;;
    --admin-email)   ADMIN_EMAIL="$2"; shift 2 ;;
    --admin-email=*) ADMIN_EMAIL="${1#*=}"; shift ;;
    --caddy)         USE_CADDY=1; shift ;;
    --build)         DO_BUILD=1; shift ;;
    --yes|-y)        ASSUME_YES=1; shift ;;
    -h|--help)       usage 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

# ---------- preflight ---------------------------------------------------------

command -v docker >/dev/null 2>&1 || die "docker is required — https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required (the 'docker compose' plugin, not legacy docker-compose)"
command -v curl >/dev/null 2>&1 || die "curl is required"
[ -f "$TEMPLATE" ] || die "$TEMPLATE not found — run from the deploy/ directory (or a /selfhost download of it)"

# ---------- optional source build (default: pull from GHCR) -------------------

if [ "$DO_BUILD" = 1 ]; then
  [ -f ../Dockerfile ] || die "--build needs a source checkout (../Dockerfile not found); the default path is pulling $IMAGE_REPO"
  say "==> building $IMAGE_REPO:local from ../ (this compiles the server + web — several minutes)"
  docker build -t "$IMAGE_REPO:local" ..
  set_dotenv ANDVARI_VERSION local
fi
ANDVARI_VERSION="$( [ -f "$DOTENV" ] && sed -n 's/^ANDVARI_VERSION=//p' "$DOTENV" | head -1 || true )"
IMAGE="$IMAGE_REPO:${ANDVARI_VERSION:-latest}"

# ---------- 1+2. env file -----------------------------------------------------

if [ -f "$ENV_FILE" ]; then
  say "==> $ENV_FILE already exists — refusing to overwrite it (idempotent re-run: will finish bring-up with the existing config)"
else
  if [ -z "$ORIGIN" ]; then
    [ "$ASSUME_YES" = 1 ] && die "--yes needs --origin"
    say "The canonical origin is the ONE address members' apps will connect to,"
    say "e.g. https://vault.example.org — set up its DNS + TLS story after this script."
    printf 'Instance origin: '
    read -r ORIGIN
  fi
  ORIGIN=$(canonicalize_origin "$ORIGIN")
  if [ -z "$INSTANCE_NAME" ] && [ "$ASSUME_YES" != 1 ]; then
    printf 'Instance display name [%s]: ' "$(host_of "$ORIGIN")"
    read -r INSTANCE_NAME
  fi
  [ -n "$INSTANCE_NAME" ] || INSTANCE_NAME="$(host_of "$ORIGIN")"

  umask 077
  cp "$TEMPLATE" "$ENV_FILE" && chmod 600 "$ENV_FILE"
  set_env ANDVARI_CANONICAL_ORIGIN "$ORIGIN"
  set_env ANDVARI_INSTANCE_NAME "$INSTANCE_NAME"
  # Template defaults already carry the self-host stance (design §8.2):
  #   ANDVARI_SIGNUP_MODE=invite-only  ANDVARI_TOTP_REQUIRED=false
  #   ANDVARI_OFFLINE_CACHE_ALLOWED=true  ANDVARI_STRICT_ENV=1
  #   ANDVARI_PUBLIC_HOSTNAME unset (single-origin default)
  set_env ANDVARI_ENUM_SECRET "$(gen_secret 32)"
  say "==> wrote $ENV_FILE (chmod 600)"
fi

ORIGIN="$(get_env ANDVARI_CANONICAL_ORIGIN)"
[ -n "$ORIGIN" ] || die "$ENV_FILE has no ANDVARI_CANONICAL_ORIGIN — fix or remove the file and re-run"
[ -n "$(get_env ANDVARI_ENUM_SECRET)" ] || set_env ANDVARI_ENUM_SECRET "$(gen_secret 32)"

# compose-side vars (.env): caddy domain; LAN bind for plain-http origins
set_dotenv ANDVARI_DOMAIN "$(host_of "$ORIGIN")"
case "$ORIGIN" in
  http://*)
    set_dotenv ANDVARI_BIND 0.0.0.0
    warn "plain-http LAN mode: publishing the app on 0.0.0.0:8080; clients will show a plain-http caution. Never expose this to the internet." ;;
esac
if [ "$USE_CADDY" = 1 ]; then
  case "$ORIGIN" in
    https://*) : ;;
    *) die "--caddy needs an https origin (caddy exists to terminate TLS for it)" ;;
  esac
  set_dotenv COMPOSE_FILE "docker-compose.yml:docker-compose.caddy.yml"
  say "==> caddy overlay armed (COMPOSE_FILE in .env): auto-HTTPS for $(host_of "$ORIGIN") — ports 80/443 must be reachable and DNS must point here"
fi

# ---------- 3. escrow ceremony ------------------------------------------------

if [ -z "$(get_env ANDVARI_RECOVERY_PUBKEY)" ] || [ -z "$(get_env ANDVARI_RECOVERY_FINGERPRINT)" ]; then
  say "==> escrow ceremony: generating the org recovery key (recovery-cli keygen)"
  say "    The container runs with --network none; the private seed exists only in"
  say "    the sheet printed below — it is NOT written to disk by this script."
  [ "$DO_BUILD" = 1 ] || docker pull "$IMAGE" >/dev/null || die "could not pull $IMAGE"
  SHEET="$(docker run --rm --network none "$IMAGE" recovery-cli keygen)" || die "recovery-cli keygen failed"
  printf '\n%s\n\n' "$SHEET"
  PUBKEY="$(printf '%s\n' "$SHEET"  | sed -n 's/^[[:space:]]*ANDVARI_RECOVERY_PUBKEY=//p'      | head -1)"
  FINGERPRINT="$(printf '%s\n' "$SHEET" | sed -n 's/^[[:space:]]*ANDVARI_RECOVERY_FINGERPRINT=//p' | head -1)"
  [ -n "$PUBKEY" ] && [ -n "$FINGERPRINT" ] || die "could not parse the pubkey/fingerprint out of the keygen sheet"
  say "    ACTION REQUIRED — this sheet is the ONLY way back into a lost account:"
  say "      * print it twice (or copy it by hand), copy the seed to a USB stick"
  say "      * store sheets + USB in two separate secure places"
  say "      * never photograph it to a networked device; never store it digitally"
  say "      * afterwards, clear this terminal's scrollback (e.g. clear + printf '\\e[3J')"
  say "    (Ideal-practice note: ops/breakglass.md runs keygen on an air-gapped machine."
  say "     You can do that instead and paste the two ANDVARI_RECOVERY_* values into"
  say "     $ENV_FILE yourself before re-running this script.)"
  if [ "$ASSUME_YES" != 1 ]; then
    printf "    Type 'saved' once the sheet is safely printed/copied: "
    read -r REPLY
    [ "$REPLY" = "saved" ] || die "aborting — the recovery sheet MUST be saved before the instance goes live"
  fi
  set_env ANDVARI_RECOVERY_PUBKEY "$PUBKEY"
  set_env ANDVARI_RECOVERY_FINGERPRINT "$FINGERPRINT"
  unset SHEET
else
  say "==> escrow pins already present in $ENV_FILE — skipping the ceremony"
fi

# ---------- 4. bootstrap token, up, healthz, policy smoke ---------------------

BOOTSTRAP_TOKEN="$(get_env ANDVARI_BOOTSTRAP_TOKEN)"
if [ -z "$BOOTSTRAP_TOKEN" ]; then
  BOOTSTRAP_TOKEN="$(gen_secret 24)"
  set_env ANDVARI_BOOTSTRAP_TOKEN "$BOOTSTRAP_TOKEN"
fi

say "==> docker compose up -d"
compose up -d

say "==> waiting for $BASE_URL/healthz"
ok=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 2 "$BASE_URL/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
if [ "$ok" != 1 ]; then
  warn "server did not become healthy in 60 s — recent logs:"
  compose logs --tail 40 andvari >&2 || true
  die "healthz never answered (ANDVARI_STRICT_ENV=1 kills boot on a bad variable — check the log above)"
fi
say "    healthz OK"

say "==> smoke: GET /api/v1/client-policy declares this instance's policy"
POLICY_JSON="$(curl -fsS "$BASE_URL/api/v1/client-policy")" || die "client-policy fetch failed"
WANT_MODE="$(get_env ANDVARI_SIGNUP_MODE)"; WANT_MODE="${WANT_MODE:-invite-only}"
WANT_TOTP="$(get_env ANDVARI_TOTP_REQUIRED)"; WANT_TOTP="${WANT_TOTP:-false}"
if command -v python3 >/dev/null 2>&1; then
  POLICY_JSON="$POLICY_JSON" ORIGIN="$ORIGIN" WANT_MODE="$WANT_MODE" WANT_TOTP="$WANT_TOTP" python3 - <<'PY' || die "client-policy did not declare the configured policy (an image predating the 2026-07-15 pivot? pull a newer tag)"
import json, os, sys
p = json.loads(os.environ["POLICY_JSON"])
want = {
    "signupMode": os.environ["WANT_MODE"],
    "totpRequired": os.environ["WANT_TOTP"].lower() == "true",
    "canonicalOrigin": os.environ["ORIGIN"],
}
bad = [f"{k}: got {p.get(k)!r}, want {v!r}" for k, v in want.items() if p.get(k) != v]
if "offlineCacheAllowed" not in p:
    bad.append("offlineCacheAllowed missing")
if not p.get("instanceName"):
    bad.append("instanceName missing/empty")
if bad:
    print("client-policy mismatch: " + "; ".join(bad), file=sys.stderr)
    sys.exit(1)
print("    policy OK:", json.dumps({k: p.get(k) for k in
      ("signupMode", "totpRequired", "instanceName", "canonicalOrigin", "selfHostDocsUrl")}))
PY
else
  printf '%s' "$POLICY_JSON" | grep -q '"signupMode"' \
    || die "client-policy carries no signupMode — image predates the 2026-07-15 pivot (python3 unavailable for a deeper check)"
  say "    policy fields present (install python3 for exact assertions)"
fi

# ---------- done: first-admin enrollment --------------------------------------

say ""
say "======================================================================"
say " andvari is up at $ORIGIN"
say "======================================================================"
if [ -n "$ADMIN_EMAIL" ]; then
  PAYLOAD="$(printf '{"v":1,"o":"%s","t":"%s","e":"%s"}' "$ORIGIN" "$BOOTSTRAP_TOKEN" "$ADMIN_EMAIL" | b64url)"
  say " First-admin enroll URL (72 h, single use):"
  say "   $ORIGIN/enroll#a1.$PAYLOAD"
else
  say " First admin: open $ORIGIN, choose enroll, and redeem the bootstrap"
  say " invite token below with YOUR email (valid 72 h while no user exists):"
  say "   $BOOTSTRAP_TOKEN"
fi
say " Have the printed recovery sheet at hand — enrollment confirms the"
say " recovery fingerprint from it."
say ""
say " Point any andvari app/extension at $ORIGIN (Settings -> Server)."
say ""
say " After the first admin has enrolled:"
say "   * blank out ANDVARI_BOOTSTRAP_TOKEN in $ENV_FILE, then: docker compose up -d"
case "$ORIGIN" in
  https://*)
    if [ "$USE_CADDY" = 1 ]; then
      say "   * TLS: caddy is fetching certificates for $(host_of "$ORIGIN") automatically"
    else
      say "   * TLS: put your own front (proxy/cloudflared/tailscale serve) in front of"
      say "     127.0.0.1:8080 for $(host_of "$ORIGIN"), or re-run with --caddy;"
      say "     set ANDVARI_FORCE_HSTS=1 in $ENV_FILE once https works end-to-end"
    fi ;;
esac
say " Updates: docker compose pull && docker compose up -d"
say " Docs: docs/self-hosting.md (also served at $ORIGIN/selfhost)"
