# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Custom Keycloak server image build for the AnkiMCP platform. Wraps the official Keycloak image with a vendored copy of the [keycloak-remember-me-authenticator](https://github.com/Herdo/keycloak-remember-me-authenticator) SPI plugin so that **every** authentication (direct username/password AND social login via Google/GitHub) produces a persistent SSO cookie. No checkbox interaction required from the user.

**Sole output of this repo:** an OCI image pushed to GHCR (GitHub Container Registry).

**Image tag pattern:** `ghcr.io/<owner>/keycloak-bundled:<keycloak-version>-<YYYY.MM.DD>-<sha7>` (immutable) plus `<keycloak-version>-<YYYY.MM.DD>` (floating per-day) plus `:latest`.

**Consumed by:** `anki-mcp-infrastructure` → `apps/keycloak/templates/keycloak.yaml` (`spec.image` on the Keycloak CR).

## Why this repo exists

Keycloak's "Remember Me" checkbox renders on its own username/password login page. Social-login users (Google, GitHub) are redirected away to the IdP **before** they see this form, so they never get the opportunity to opt in — their `KEYCLOAK_IDENTITY` cookie is set without `Max-Age`, becoming a session cookie that dies when the browser closes. Even with the realm's SSO session set to 30 days, social-login users effectively re-login every browser restart.

Herdo's `keycloak-remember-me-authenticator` SPI plugin fixes this by setting the `remember_me=true` auth-session note unconditionally after authentication, regardless of the auth path. Result: every cookie gets `Max-Age = ssoSessionMaxLifespanRememberMe`. Gmail-style persistence.

This pattern is **officially endorsed by Keycloak's lead maintainer (Stian Thorgersen)** in [keycloak#37372](https://github.com/keycloak/keycloak/issues/37372), which was closed `wontfix` in November 2025 with the comment: *"configure a custom post broker login flow with a custom authenticator which sets the rememberMe flag of the current AuthenticationSession."*

## The plugin

- **Upstream source:** https://github.com/Herdo/keycloak-remember-me-authenticator (MIT)
- **Code surface:** ~20 lines of Java across two files
- **SPI surface stability:** the `Authenticator` SPI hasn't changed across Keycloak 20–26
- **Confirmed compatibility:** K26.1.0 and K26.4.2 by independent user reports
- **Known concerns:**
  - Stale `pom.xml` dependencies (upstream issue #9) — **strategy: vendor + rebuild against current Keycloak BOM rather than using the prebuilt 2023 JAR release.**
  - Single-maintainer repo with limited recent activity — bus-factor mitigated by code triviality (20 lines = half-day to re-vendor if upstream disappears).

## Target repo structure

```
anki-mcp-keycloak/
  CLAUDE.md                # this file
  README.md                # public-facing (or internal) project description
  Dockerfile               # multi-stage: maven build → kc.sh build → runtime
  src/                     # vendored plugin source, rebuilt against current Keycloak BOM
    pom.xml
    src/main/java/...
    src/main/resources/META-INF/services/org.keycloak.authentication.AuthenticatorFactory
  .github/workflows/
    build.yml              # GitHub Actions: build image + push to GHCR
  .gitignore               # Java/Maven + macOS + standard
```

## Pending work (for the next agent)

The work to land this image:

1. **Vendor the plugin source** under `src/`. Clone Herdo's repo and copy the Java files, then:
   - Update `pom.xml` to target the current Keycloak BOM (currently 26.5.7; see "Coordinated infra repo" below).
   - Strip stale dependencies (upstream pom.xml issue #9).
   - Confirm it builds cleanly with Maven 3.9+.
   - Preserve the MIT license header and add a NOTICE/README crediting Herdo.

2. **Write the Dockerfile** (multi-stage):
   - **Stage 1 — Maven builder:** `maven:3.9-eclipse-temurin-21` (or matching Keycloak's JDK requirement), copy `src/`, run `mvn package`, output a JAR.
   - **Stage 2 — Keycloak build:** `quay.io/keycloak/keycloak:<KC_VERSION>`, copy JAR from stage 1 into `/opt/keycloak/providers/`, run `/opt/keycloak/bin/kc.sh build`.
   - **Stage 3 — Runtime:** `quay.io/keycloak/keycloak:<KC_VERSION>`, copy the entire built `/opt/keycloak/` from stage 2.
   - Final image: `ENTRYPOINT` matches upstream Keycloak's entrypoint.

3. **GitHub Actions workflow** (`.github/workflows/build.yml`):
   - Triggers: push to `main`, manual `workflow_dispatch`, tags `v*`.
   - Steps: checkout → set up buildx → docker login to GHCR using the auto-provisioned `${{ secrets.GITHUB_TOKEN }}` (no PAT needed; `permissions.packages: write` in the workflow) → build + push.
   - Tag scheme example: `ghcr.io/${{ github.repository_owner }}/keycloak-bundled:<KC_VERSION>-<YYYY.MM.DD>-<sha7>`. Three tags are pushed per build: the immutable `<KC_VERSION>-<YYYY.MM.DD>-<sha7>`, the floating-date `<KC_VERSION>-<YYYY.MM.DD>`, and `latest`.
   - Bake `KC_VERSION` and `PLUGIN_VERSION` as Dockerfile build args; CI passes them.

4. **README.md** — concise, explains:
   - What this image is (Keycloak base + remember-me plugin).
   - Why it exists (social-login UX gap).
   - That no secrets live in this repo (GHCR uses the workflow's auto-provisioned token — no per-repo secret to manage).
   - Build/run instructions for local dev.

5. **Downstream coordination with `anki-mcp-infrastructure`** (separate repo, separate PR/commit there):
   - Edit `apps/keycloak/templates/keycloak.yaml` → set `spec.image: ghcr.io/<owner>/keycloak-bundled:<tag>` on the Keycloak CR.
   - Edit `apps/keycloak/realm-ankimcp.json`:
     - Flip `rememberMe: true` at realm level. **REQUIRED in K26.4.1+** or sessions get invalidated — see [keycloak#43328](https://github.com/keycloak/keycloak/issues/43328). The plugin alone is NOT enough; the realm flag must also be on.
     - Add a new authenticator execution to the Browser flow (post-authentication) that invokes the `remember-me` provider.
     - Add the same to the Post Broker Login flow (so social-login users get the same treatment).
     - Confirm/adjust `ssoSessionMaxLifespanRememberMe` and `ssoSessionIdleTimeoutRememberMe` to target persistence (currently 30 days for both; consider 90 days for `MaxLifespan` if you want longer-lived sessions).
   - The `keycloak-config-cli` PostSync hook will reconcile these realm changes on the next ArgoCD sync.

## Open decisions (resolve before pushing to GitHub)

- **Repo visibility: public or private? — RESOLVED: public.** Contents have no secrets (GHCR push uses the workflow's auto-provisioned token, nothing is committed). Public was chosen so we can use GHCR's free hosting for public repos, get unlimited Actions minutes, and allow easier contribution-back to Herdo. No security trade-off either way for this content.
- **Exact image tag scheme — RESOLVED.** Locked-in scheme: `<KC_VERSION>-<YYYY.MM.DD>-<sha7>` (immutable, one per build, suitable for pinning) plus `<KC_VERSION>-<YYYY.MM.DD>` (floating per-day) plus `latest`. CI pushes all three on every build.
- **Plugin maintenance strategy.** Vendoring (current plan) means manual rebuild against new Keycloak BOMs on each version bump. Tracking upstream JAR releases is more fragile (Herdo may not release timely). Vendoring is recommended.

## Coordinated infra repo

The infrastructure repo `anki-mcp-infrastructure` deploys Keycloak via the Keycloak Operator and reconciles realm configuration via a `keycloak-config-cli` PostSync hook. After this image build lands and is pushed to GHCR, the infra repo's Keycloak `image` field (set to `ghcr.io/<owner>/keycloak-bundled:<tag>`) plus realm JSON need the updates listed in "Pending work" item #5 above.

**Keycloak version currently deployed:** `26.5.7`. This is held intentionally — `adorsys/keycloak-config-cli` has no `6.5.0-26.6.x` build yet, so the operator can't be bumped to 26.6+ until adorsys ships a compatible config-cli image. This repo should track the same Keycloak version.

**Version-bump coordination rule:** when Keycloak gets bumped in `anki-mcp-infrastructure` (Keycloak Operator bump → bundled server image bump), this image MUST be rebuilt against the new Keycloak version in lockstep. Otherwise the Keycloak StatefulSet (running new version) will fall out of sync with this custom image (containing the extension built against the old version). Recommended workflow: bump Keycloak here first, push the new image, then bump the operator in the infra repo.

## References

- Plugin source: https://github.com/Herdo/keycloak-remember-me-authenticator
- Keycloak SPI development guide: https://www.keycloak.org/docs/latest/server_development/index.html
- Keycloak server configuration provider docs: https://www.keycloak.org/server/configuration-provider
- Upstream `wontfix` issue endorsing this plugin pattern: https://github.com/keycloak/keycloak/issues/37372
- K26.4.1+ rememberMe behavior change: https://github.com/keycloak/keycloak/issues/43328
- Existing infra repo: `/Users/anatoly/Developer/projects/ankimcp/anki-mcp-infrastructure` (sibling repo via local path)
