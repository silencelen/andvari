# andvari — self-host container image (design 2026-07-15 §8).
#
# One image = server shadowJar + built web assets + recovery-cli as a subcommand:
#   docker run ... ghcr.io/silencelen/andvari:<ver>                    # runs the server
#   docker run --rm --network none ghcr.io/silencelen/andvari:<ver> \
#       recovery-cli keygen                                            # escrow ceremony
#
# Multi-arch (amd64/arm64) friendly: the two build stages are pinned to
# $BUILDPLATFORM (jars and vite output are architecture-independent), so a
# `docker buildx build --platform linux/amd64,linux/arm64` compiles ONCE on the
# build host and only the runtime stage is per-target-arch. Published from
# huginn/devserv via scripts/publish-image.sh — NOT from CI (GH Actions billing).
#
# Build mirrors ops/deploy.sh: gradle :server:shadowJar + web `npm run build`.
# NOTE :core is Kotlin Multiplatform with an androidTarget(), so Gradle
# CONFIGURATION needs an Android SDK even though only JVM jars are built here —
# the jar stage installs cmdline-tools + platform android-35 (core compileSdk).

# ---------- web assets (tsc + vite) ----------
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
# `npm run build` = `tsc --noEmit && vite build`, and tsc type-checks the test
# files too — web/src/extension-pins.test.ts imports ../../extension/src/* and
# the vector tests point at ../../spec/test-vectors, so both siblings must
# exist relative to /src/web for the check to pass (as it does on the build
# hosts). vite itself only bundles the app graph.
COPY extension/ /src/extension/
COPY spec/test-vectors/ /src/spec/test-vectors/
RUN npm run build   # → dist/

# ---------- server + recovery-cli shadowJars ----------
FROM --platform=$BUILDPLATFORM eclipse-temurin:17-jdk-jammy@sha256:723151f3fc88ca2060153ee08ab8dbbea7983d6ed6f2622fe440acf178737c94 AS jars
# Android SDK: needed only so AGP can configure :core's androidTarget. No
# Android compile task runs. Licenses are accepted so AGP may fetch any extra
# component it wants at configuration time.
ARG ANDROID_CLT=commandlinetools-linux-11076708_latest.zip
ENV ANDROID_HOME=/opt/android-sdk
RUN apt-get update && apt-get install -y --no-install-recommends curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p "$ANDROID_HOME/cmdline-tools" \
    && curl -fsSL "https://dl.google.com/android/repository/$ANDROID_CLT" -o /tmp/clt.zip \
    && unzip -q /tmp/clt.zip -d "$ANDROID_HOME/cmdline-tools" \
    && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
    && rm /tmp/clt.zip \
    && yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null \
    && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
         "platforms;android-35" "build-tools;35.0.0" >/dev/null
WORKDIR /src
# Gradle wrapper + build grammar first (layer-cache friendly).
COPY gradlew gradle.properties settings.gradle.kts build.gradle.kts ./
COPY gradle/ gradle/
# Only the modules this image builds. app-android/app-desktop and the other
# tools are dropped from settings so their (heavier) configuration never runs.
COPY core/ core/
COPY server/ server/
COPY tools/recovery-cli/ tools/recovery-cli/
# core's Test tasks declare spec/test-vectors as an input dir; keep it present.
COPY spec/test-vectors/ spec/test-vectors/
# server's processResources bundles the self-host docs + deploy files into the jar's
# selfhost/ classpath (SERVER-4 / §8.1); absent ⇒ /selfhost serves a stub, never the SPA
# fallback. ops/deploy.sh has the full checkout, but the GHCR image build needs them here.
COPY docs/self-hosting.md docs/self-hosting.md
COPY deploy/docker-compose.yml deploy/docker-compose.caddy.yml deploy/andvari.env.template deploy/bringup.sh deploy/
RUN sed -i -e '/":app-android"/d' -e '/":app-desktop"/d' \
           -e '/":tools:vector-gen"/d' -e '/":tools:backup-cli"/d' \
           -e '/":tools:update-signer"/d' settings.gradle.kts \
    && ! grep -q 'app-android' settings.gradle.kts \
    && rm -f local.properties \
    && ./gradlew --no-daemon :server:shadowJar :tools:recovery-cli:shadowJar

# ---------- runtime ----------
FROM eclipse-temurin:17-jre-jammy@sha256:475d8e96b4b2bfe08999e5e854755c773af1581acdf959a4545d88f0696a2339
LABEL org.opencontainers.image.source="https://github.com/silencelen/andvari" \
      org.opencontainers.image.description="andvari — zero-knowledge household password manager (server + web UI + offline recovery-cli)" \
      org.opencontainers.image.licenses="UNLICENSED"
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 10001 andvari && useradd -u 10001 -g andvari -M -d /opt/andvari -s /usr/sbin/nologin andvari \
    && mkdir -p /opt/andvari /data
COPY --from=jars /src/server/build/libs/andvari-server*.jar /opt/andvari/andvari-server.jar
COPY --from=jars /src/tools/recovery-cli/build/libs/andvari-recovery-cli*.jar /opt/andvari/andvari-recovery-cli.jar
COPY --from=web /src/web/dist/ /opt/andvari/web/
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && chown -R andvari:andvari /opt/andvari /data

# Container-internal defaults; the compose env_file overrides/extends these.
# /data is the ONE state dir (SQLite db + blob dir) — bind-mount it.
ENV ANDVARI_HOST=0.0.0.0 \
    ANDVARI_PORT=8080 \
    ANDVARI_DB=/data/andvari.db \
    ANDVARI_BLOB_DIR=/data/blobs \
    ANDVARI_WEB_DIR=/opt/andvari/web

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["server"]
