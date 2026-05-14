# syntax=docker/dockerfile:1.7
#
# Custom Keycloak image bundling Herdo's `remember-me` SPI authenticator.
# See CLAUDE.md for the project rationale.
#
# Three stages:
#   1. builder  -- Maven compiles the vendored plugin source against Keycloak's BOM.
#   2. kcbuild  -- `kc.sh build` re-augments the Quarkus image with the new provider.
#   3. runtime  -- fresh Keycloak base + the augmented /opt/keycloak/ tree.

# ---- Build args -------------------------------------------------------------
# KC_VERSION must match the Keycloak Operator version deployed by the consuming
# Kubernetes manifest. Bump this repo and the consuming deployment in lockstep
# (see CLAUDE.md: "Example consumer: AnkiMCP" for one concrete instance of this
# coordination rule).
ARG KC_VERSION=26.5.7
# Upstream plugin commit (Herdo/keycloak-remember-me-authenticator). Surfaced
# as an OCI label so a deployed image can be traced back to its source revision.
ARG PLUGIN_GIT_SHA=de35b36


# ---- Stage 1: Maven builder -------------------------------------------------
# eclipse-temurin-21 matches the Keycloak 26 supported LTS (and pom.xml's
# <release>21</release>). Pinned to a specific Maven patch (3.9.15) for
# reproducible builds: the floating `3.9-eclipse-temurin-21` tag could shift
# under us between rebuilds. We deliberately do NOT pin by digest -- patch-
# level is enough here (Maven re-resolves all deps from Central anyway, so a
# JDK micro-bump can't change the resulting JAR), and digest pinning would
# require lockstep updates with every base-image security refresh.
FROM maven:3.9.15-eclipse-temurin-21 AS builder

WORKDIR /build

# Copy pom first so the dependency-resolution layer caches independently of
# any Java source change. Combined with the BuildKit cache mount on ~/.m2,
# repeated CI builds avoid re-downloading the Keycloak BOM (~hundreds of MB).
COPY src/pom.xml ./pom.xml
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp dependency:go-offline

# Now bring in the actual sources and build the JAR. Tests are intentionally
# skipped -- both compilation AND execution -- via -Dmaven.test.skip=true.
# (-DskipTests would still compile test sources, dragging in test-scope deps
# like mockito-junit-jupiter for no benefit: test classes never end up in the
# production JAR.) The real test pass happens in the CI integration-test job
# outside Docker (`mvn verify`); `kc.sh build` in stage 2 acts as an extra
# integration check (it refuses to register a malformed provider).
COPY src/src/ ./src/
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -ntp -Dmaven.test.skip=true package

# Sanity-check the expected artifact name (pom.xml <finalName>) so a future
# pom change that breaks this contract fails the Docker build loudly here
# rather than silently producing a Keycloak image without the provider.
RUN test -f /build/target/keycloak-remember-me-authenticator.jar


# ---- Stage 2: Keycloak augmentation (kc.sh build) ---------------------------
# Same base tag as the runtime stage -- the augmented /opt/keycloak/ tree must
# be binary-compatible with the runtime's Quarkus version.
FROM quay.io/keycloak/keycloak:${KC_VERSION} AS kcbuild

# Drop the JAR into the providers directory. `kc.sh build` discovers and bakes
# providers from this path during Quarkus augmentation.
COPY --from=builder /build/target/keycloak-remember-me-authenticator.jar \
                    /opt/keycloak/providers/

# Re-augment. Producing an "optimized" image per Keycloak's containers guide:
# https://www.keycloak.org/server/containers
RUN /opt/keycloak/bin/kc.sh build


# ---- Stage 3: Runtime -------------------------------------------------------
# Fresh base, then overlay the augmented tree from stage 2. We deliberately
# don't FROM kcbuild directly: copying /opt/keycloak/ from a clean base keeps
# the final image free of any transient files `kc.sh build` may have written
# outside /opt/keycloak (build logs, tmp data, etc.).
FROM quay.io/keycloak/keycloak:${KC_VERSION}

# Re-declare ARGs needed for LABEL expansion (ARGs don't cross stage boundaries).
ARG KC_VERSION
ARG PLUGIN_GIT_SHA
# Set by CI (git SHA + RFC3339 timestamp). Defaults keep local builds buildable
# without flags; CI overrides for traceability.
ARG VCS_REF=local
ARG BUILD_DATE=unknown
# Source repo URL for OCI image.source label. CI injects the real GitHub coords
# via `--build-arg IMAGE_SOURCE=https://github.com/${{ github.repository }}` so
# the label is always correct regardless of fork/transfer. Default is a
# sentinel to make a stray local build obviously unpublishable.
ARG IMAGE_SOURCE=https://github.com/REPLACE-ME/keycloak-bundled

COPY --from=kcbuild /opt/keycloak/ /opt/keycloak/

# OCI image labels -- consumed by GHCR, registry UIs, and `docker inspect`.
LABEL org.opencontainers.image.title="keycloak-bundled" \
      org.opencontainers.image.description="Keycloak ${KC_VERSION} with Herdo's remember-me SPI authenticator baked in." \
      org.opencontainers.image.source="${IMAGE_SOURCE}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="quay.io/keycloak/keycloak:${KC_VERSION}" \
      org.opencontainers.image.version="${KC_VERSION}-rememberme-${PLUGIN_GIT_SHA}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Inherit ENTRYPOINT, CMD, USER, and WORKDIR from the upstream Keycloak image.
# (Upstream sets USER 1000 / keycloak; don't override.)
