#!/usr/bin/env bash
# Starts everything the iOS UI tests talk to, on loopback, with a throwaway data directory:
# the andvari server (unmodified, from this checkout), one seeded account, and the static test site
# over https and http. Usage: app-ios/uitest/start-backend.sh <work dir>
# Leaves <work dir>/server.log, site.log, ca.pem and pids; stop with stop-backend.sh.
set -euo pipefail
WORK="${1:?usage: start-backend.sh <work dir>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=env.sh
. "$HERE/env.sh"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"

SERVER_JAR="$REPO/server/build/libs/andvari-server.jar"
SEED_JAR="$REPO/tools/uitest-seed/build/libs/andvari-uitest-seed.jar"
if [ ! -f "$SERVER_JAR" ] || [ ! -f "$SEED_JAR" ]; then
  (cd "$REPO" && ./gradlew --no-daemon :server:shadowJar :tools:uitest-seed:shadowJar)
fi

# The server: its declared policy is the shipped default (offline cache allowed, invite-only, TOTP not required).
java -jar "$SEED_JAR" env "$WORK/server.env"
set -a
# shellcheck disable=SC1091
. "$WORK/server.env"
set +a
export ANDVARI_HOST=127.0.0.1 ANDVARI_PORT="$UITEST_SERVER_PORT" ANDVARI_STRICT_ENV=1
export ANDVARI_DB="$WORK/data/andvari.db" ANDVARI_BLOB_DIR="$WORK/data/blobs"
export ANDVARI_CANONICAL_ORIGIN="$UITEST_SERVER_ORIGIN" ANDVARI_INSTANCE_NAME="uitest"
# The sign-in tests sign in more often than a person would in a minute.
export ANDVARI_LOGIN_RATE_PER_MIN=120
mkdir -p "$WORK/data"
nohup java -jar "$SERVER_JAR" > "$WORK/server.log" 2>&1 &
echo $! > "$WORK/server.pid"
for _ in $(seq 1 60); do
  curl -fsS "$UITEST_SERVER_ORIGIN/healthz" > /dev/null 2>&1 && break
  kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null || { cat "$WORK/server.log"; echo "the server exited"; exit 1; }
  sleep 1
done
curl -fsS "$UITEST_SERVER_ORIGIN/healthz" > /dev/null || { cat "$WORK/server.log"; echo "the server never answered"; exit 1; }
java -jar "$SEED_JAR" seed "$UITEST_SERVER_ORIGIN" "$ANDVARI_BOOTSTRAP_TOKEN" "$UITEST_EMAIL" "$UITEST_PASSWORD" "$UITEST_SITE_ORIGIN" "$UITEST_HTTP_ORIGIN"

# The site's certificate: a CA and a leaf made here, never stored. The simulator is told to trust ca.pem.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=andvari uitest CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2> /dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$UITEST_SITE_HOST" -keyout "$WORK/site.key" -out "$WORK/site.csr" 2> /dev/null
printf 'subjectAltName=DNS:%s,DNS:'"$UITEST_OTHER_HOST"'\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$UITEST_SITE_HOST" > "$WORK/site.ext"
openssl x509 -req -in "$WORK/site.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
  -extfile "$WORK/site.ext" -out "$WORK/site.pem" 2> /dev/null

nohup python3 "$HERE/serve-site.py" "$HERE/site" "$UITEST_SITE_PORT" "$UITEST_HTTP_PORT" "$WORK/site.pem" "$WORK/site.key" > "$WORK/site.log" 2>&1 &
echo $! > "$WORK/site.pid"
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null "http://127.0.0.1:$UITEST_HTTP_PORT/index.html" 2> /dev/null \
    && curl -fsSk -o /dev/null "https://127.0.0.1:$UITEST_SITE_PORT/index.html" 2> /dev/null && break
  kill -0 "$(cat "$WORK/site.pid")" 2> /dev/null || { cat "$WORK/site.log"; echo "the test site exited"; exit 1; }
  sleep 1
done
curl -fsSk -o /dev/null "https://127.0.0.1:$UITEST_SITE_PORT/index.html" || { cat "$WORK/site.log"; echo "the test site never answered"; exit 1; }
echo "backend up: $UITEST_SERVER_ORIGIN, $UITEST_SITE_ORIGIN, $UITEST_HTTP_ORIGIN"
