# keycloak-bundled

Custom Keycloak OCI image that bundles Herdo's `remember-me` SPI authenticator so every authentication path produces a persistent SSO cookie.

## Why

Keycloak's built-in "Remember Me" checkbox lives on the username/password form. Social-login users (Google, GitHub, any external IdP) are redirected away before they ever see that form, so their `KEYCLOAK_IDENTITY` cookie is issued without a `Max-Age` and dies on browser close — even when the realm's `ssoSessionMaxLifespanRememberMe` is set to weeks. Herdo's authenticator closes the gap by unconditionally setting `remember_me=true` on the auth session after authentication, regardless of the flow. The pattern is endorsed by Keycloak's lead maintainer in [keycloak#37372](https://github.com/keycloak/keycloak/issues/37372).

## What's in the image

- `quay.io/keycloak/keycloak:<KC_VERSION>` as the base.
- A vendored build of [Herdo/keycloak-remember-me-authenticator](https://github.com/Herdo/keycloak-remember-me-authenticator), rebuilt against the matching Keycloak BOM and dropped into `/opt/keycloak/providers/`.
- An "optimized" server: `kc.sh build` runs at image-build time so Quarkus augmentation is already done on container start.

No secrets live in this repo. The image is pushed to GHCR (GitHub Container Registry) using the workflow's auto-provisioned `${{ secrets.GITHUB_TOKEN }}` and `${{ github.actor }}` — no PAT, robot account, or repo-level secret is configured.

## Build locally

### Prerequisites

- Docker with BuildKit (Buildx) enabled.
- Optional, only if you want to run `mvn package` against `src/` outside Docker: JDK 21 and Maven 3.9+.

### Build

```bash
docker build \
  --build-arg KC_VERSION=26.6.4 \
  --build-arg PLUGIN_GIT_SHA=de35b36 \
  --build-arg VCS_REF=$(git rev-parse HEAD) \
  --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
  --build-arg IMAGE_SOURCE=https://github.com/<owner>/keycloak-bundled \
  -t keycloak-bundled:dev \
  .
```

Build args (all declared in the `Dockerfile`):

| Arg | Default | Purpose |
| --- | --- | --- |
| `KC_VERSION` | `26.6.4` | Keycloak base image tag. Must match the Keycloak Operator version deployed by the consuming Kubernetes manifest. |
| `PLUGIN_GIT_SHA` | `de35b36` | Upstream Herdo commit, surfaced as an OCI label for traceability. |
| `VCS_REF` | `local` | Git SHA of this repo. CI sets it; local builds may leave the default. |
| `BUILD_DATE` | `unknown` | RFC3339 timestamp. CI sets it. |
| `IMAGE_SOURCE` | `https://github.com/REPLACE-ME/keycloak-bundled` | Source URL for the OCI `image.source` label. CI injects the real value. |

## Run locally

```bash
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  keycloak-bundled:dev \
  start-dev
```

The container inherits the upstream Keycloak entrypoint, so any flags or environment variables documented at <https://www.keycloak.org/server/all-config> apply unchanged. The `start-dev` argument above is for smoke testing only — production deployments invoke `start` and rely on the pre-built optimized server.

Note: `kc.sh start-dev` re-augments the Quarkus image at boot, which bypasses the baked-in build done in stage 2 of the Dockerfile. To exercise the actual image as it runs in production, use `kc.sh start --optimized` (requires `KEYCLOAK_ADMIN`/`KEYCLOAK_ADMIN_PASSWORD` env + a real DB, or `--hostname-strict=false` for quick checks).

## CI / publishing

`.github/workflows/build.yml` runs on push to `main`, on `v*` tag pushes, and on manual `workflow_dispatch` (with optional `kc_version` / `plugin_git_sha` overrides). It builds the image with Buildx and pushes three tags to GHCR:

- `ghcr.io/<owner>/keycloak-bundled:<KC_VERSION>-<YYYY.MM.DD>-<sha7>` — immutable, one per build, suitable for pinning.
- `ghcr.io/<owner>/keycloak-bundled:<KC_VERSION>-<YYYY.MM.DD>` — overwritten on same-day rebuilds.
- `ghcr.io/<owner>/keycloak-bundled:latest` — moving pointer to the most recent build.

GHCR push uses the workflow's auto-provisioned `${{ secrets.GITHUB_TOKEN }}` plus `${{ github.actor }}` for auth (the workflow declares `permissions.packages: write`). No PAT or repo-level secret needs to be configured.

## Downstream coordination

The image is intended to be consumed by a Kubernetes deployment that runs Keycloak via the Keycloak Operator and points the Keycloak CR's `spec.image` at `ghcr.io/<owner>/keycloak-bundled:<tag>`. Two things must stay in lockstep between this repo and the consuming project:

- **Keycloak version.** When the Keycloak Operator is bumped in the consuming deployment, `KC_VERSION` here must be bumped in the same release window so the StatefulSet and the bundled extension share an ABI. Recommended order: bump and publish here first, then bump the Operator downstream. (For instance, the original consumer is `anki-mcp-infrastructure`, which tracks the same Keycloak version this repo builds against.)
- **Realm-level `rememberMe`.** Starting with Keycloak 26.4.1, the authenticator alone is insufficient — the realm must also have `rememberMe: true`, otherwise sessions get invalidated. See [keycloak#43328](https://github.com/keycloak/keycloak/issues/43328). The flag and the two flow executions (Browser post-auth, Post Broker Login) are managed in the consuming project's realm configuration (typically a realm JSON reconciled by `keycloak-config-cli`).

## Plugin attribution

The SPI plugin is vendored from [Herdo/keycloak-remember-me-authenticator](https://github.com/Herdo/keycloak-remember-me-authenticator) at commit [`de35b3603de348c44a532c011079d3e687ab10b6`](https://github.com/Herdo/keycloak-remember-me-authenticator/commit/de35b3603de348c44a532c011079d3e687ab10b6), copyright (c) 2023 Stefan Over, MIT-licensed. The Java sources under `src/src/main/java` are verbatim; only `pom.xml` has been rewritten to target the current Keycloak BOM. See `src/NOTICE` for the full provenance record and `src/LICENSE` for the MIT terms.

## License

This repository's wrapper code (Dockerfile, GitHub Actions workflow, README, vendored `pom.xml`) is MIT-licensed — see top-level `LICENSE`. The vendored plugin source under `src/` is also MIT-licensed by Herdo (Stefan Over) — see `src/LICENSE`. Both are MIT, no conflict.
