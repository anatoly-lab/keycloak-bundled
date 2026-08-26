# Design: `resource-audience` protocol mapper (Keycloak 26.7.2)

Date: 2026-08-25 · Status: **draft, for approval** · Repo: `keycloak-bundled`
Source of truth for all `file:line` below: `docs/research/2026-08-25-resource-audience-mapper-delta.md` (verified against Keycloak tag `26.7.2`, commit `289376b1`).

---

## 1. Bottom line

- A second SPI in this image: an `AbstractOIDCProtocolMapper` that reads the RFC 8707 `resource` value captured at `/authorize` and **appends** it to the access token's `aud`. That is what lets thousands of dynamic `https://<id>.mcpwarp.io/mcp` resources get their own audience without one Keycloak client scope per resource (the ankimcp pattern, which does not scale).
- The value is read from the **client-session note** `resource` — set at `/authorize` (`AuthorizationEndpoint.java:350`), persisted at code exchange (`TokenManager.java:473-476`), and therefore still present on every refresh (`AbstractRefreshTokenProvider.java:121`). A refresh-token holder cannot retarget `aud`.
- Attachment is via a realm-**default** client scope `mcpwarp-resource`. There is a real risk that DCR strips realm defaults (`RepresentationToModel.updateClientScopes:663-689`). **We resolve that empirically with integration test #1 before writing a line of mapper code.**
- Native `--features=resource-indicators` (experimental in 26.7.2) stays **OFF**: it only resolves `urn:client:<id>` / per-client `resource_url`, and its post-processor calls `accessToken().audience(...)` which **replaces** the whole `aud` array (`ResourceIndicatorsPostProcessor.java:21-68`).
- **ankimcp safety is the hard constraint.** Same realm, same image, prod. The mapper is inert by construction for any client that does not carry the scope — it is never invoked for one. For a client that does carry the scope, `strict=true` (the default) means it is not merely inert: it can reject token issuance outright when `resource` is missing or invalid (see §3/§4). Worst case for a non-scope client is that it adds nothing; that guarantee does not extend to scope-carrying clients.

---

## 2. Decisions made (closed — not up for re-litigation)

**(a) Only the `/authorize` client note is a source of truth.** 26.7.2 *does* parse `resource` at `/token` and exposes it as a `ClientSessionContext` attribute on every grant (`OAuth2GrantTypeBase.java:116`, `RefreshTokenGrantType.java:65,82`, `AbstractRefreshTokenProvider.java:150`) — the older "/token drops it" research note was wrong. We still never use it as a *source*. The note is the value the user consented to at the authorization step; the token-endpoint param is attacker-reachable by anyone holding a refresh token. Handling when the token param is present: equal to the note → proceed normally; **mismatch → non-strict: ignore the param, log a warning + increment a counter; strict: reject token issuance** with the closest available error (`invalid_target`, the same code `/authorize` uses for a bad resource — see `AuthorizationEndpointChecker.java:288-296`). Mismatch is logged/metered in both modes, because it is the signal that a client is trying something.

**(b) Attachment via a realm-DEFAULT client scope `mcpwarp-resource`.** Realm defaults *are* attached to DCR clients via the `ClientProtocolUpdatedEvent` listener (`AbstractLoginProtocolFactory.java:47-56,81-97`). But `RepresentationToModel.createClient:411` then calls `updateClientScopes` (`:663-689`), which strips every scope not in the requested set whenever the rep carries `defaultClientScopes` or `optionalClientScopes` — and `DescriptionConverter.toInternal:87-91` fills `optionalClientScopes` from the DCR body's `scope` field. So a client registering with `scope: "openid profile email"` may lose the realm default. **This is settled by experiment, not by reading more source:** IT #1 (below) runs the DCR matrix and must show the scope attached and a token minted with `aud` in all three cases. Contingency *only if it fails*: a custom `ClientRegistrationPolicy` SPI that force-adds the scope post-registration. Independently, the realm's DCR **Allowed Client Scopes** policy (`allowed-client-templates`) must permit `mcpwarp-resource`; `allow-default-scopes: true` covers realm default+optional scopes (`ClientScopesClientRegistrationPolicy.java:123-134`), but ankimcp learned the hard way that `openid` is *not* covered and must be listed explicitly — keep that entry.

**(c) `--features=resource-indicators` stays OFF.** It shipped in 26.7.2 as `Type.EXPERIMENTAL` (`Profile.java:199`), so it is off by default and we do not turn it on. Two reasons: it cannot mint an audience that is not already in the token (`ResourceIndicatorsPostProcessor.java:56-90` — `urn:client:<id>`, or a URL matched against a client's `resource_url` attribute), which is useless for thousands of dynamic URLs; and its post-processor calls `audience(...)` (**replace**, `JsonWebToken.java:211`) rather than `addAudience` (**append+dedupe**, `:216-231`), so enabling it alongside this mapper would clobber our `aud`. Note the *syntax* validation of `resource` at `/authorize` is **not** feature-gated and runs regardless (`ResourceIndicatorValidation.java:14-38`: absolute URI, no fragment, no query, non-null path) — `https://<id>.mcpwarp.io/mcp` passes; a malformed value gets a 400 `invalid_target` before any mapper runs, which is fine and free validation.

**(d) Same Maven module as remember-me, own package.** `src/pom.xml` stays a single module; the Dockerfile keeps one JAR name, the workflow keeps one BOM assertion, and `kc.sh build` flattens `providers/` into one classpath anyway. Our code goes under `io.mcpwarp.keycloak` (**not** `com.herdo` — that package is vendored MIT code and the NOTICE must stay accurate), registered through a **new** file `META-INF/services/org.keycloak.protocol.ProtocolMapper` alongside the existing `…AuthenticatorFactory` file (separate files, no conflict). `src/pom.xml` gains `org.keycloak:keycloak-services` at `provided` scope — in 26.7.2 `AbstractOIDCProtocolMapper` and the mapper interfaces live in the `services` module, not `server-spi-private` (version managed by `keycloak-parent`, root `pom.xml:1082-1086`).

---

## 3. Design

**Bottom line:** one class, ~120 lines, access token only, reads one note, validates it against a regex allowlist, calls `addAudience`. If anything is missing or wrong it returns silently.

- **Provider id:** `resource-audience` (this is the id in the SPI kill switch and in the realm JSON's `protocolMapper` field).
- **Class:** `io.mcpwarp.keycloak.mappers.ResourceAudienceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, TokenIntrospectionTokenMapper`. `ProtocolMapper extends Provider, ProviderFactory, ConfiguredProvider` (`ProtocolMapper.java:32`), so one class is both provider and factory — `getId()`, `getDisplayCategory()`, `getDisplayType()`, `getHelpText()`, `getConfigProperties()`; `getProtocol()` comes from the base class.
- **Compiled config cache:** a small static `ConcurrentHashMap<String /*pattern text*/, Pattern>` so we do not recompile the allowlist per token.

**`transformAccessToken` flow** (we override `setClaim(IDToken, ProtocolMapperModel, UserSessionModel, KeycloakSession, ClientSessionContext)` at `AbstractOIDCProtocolMapper.java:156`; the base `transformAccessToken` at `:89-99` already gates on `access.token.claim`):

1. Read the note: `ctx.getClientSession().getNote("resource")` — literal key `resource` (`OIDCLoginProtocol.java:90` → `OAuth2Constants.java:133`, no prefix). Null/blank → **non-strict:** return, do nothing; **strict (the default):** reject (`invalid_target`). This only ever fires for a client that carries the `mcpwarp-resource` scope in the first place — the mapper is never invoked for a client without the scope (mapper resolution is per-attached-scope), so ankimcp and every other non-MCP client is untouched regardless of `strict`. The consequence is deliberate: with the default `strict=true`, a scope-carrying client that forgets `resource` fails loudly at the token endpoint instead of silently getting an unaudienced token.
2. Read this request's `resource` param: `ctx.getAttribute(OAuth2Constants.RESOURCE, String.class)`. Null → skip to 4 (the attribute is explicitly set to `null` when absent, so it is never a fallback).
3. If present and `!equals(note)` → log WARN + counter. **strict=true:** throw the mapper's reject path (`invalid_target`); **strict=false:** ignore the param and continue with the note.
4. Validate the note against `allowedResourcePatterns`: full-match (`Matcher.matches()`) against any one pattern. No match → log at INFO + counter; **strict=true:** reject; **strict=false:** return without adding an audience (token still issues, just unaudienced — the resource server will 401 it, which is the correct outcome).
5. `token.addAudience(resource)` — append + dedupe (`JsonWebToken.java:216-231`), the same call the built-in `AudienceProtocolMapper.java:112` makes. **Never** `audience(...)` (replaces, `:211`) and **never** `setOtherClaims("aud", …)` (`aud` is a typed field, `JsonWebToken.java:63` — an otherClaims entry would serialize wrong). Exactly one resource per token, by construction: one note, one `addAudience`.

Only if `claimName` is set to something other than `aud`: step 5 writes `setOtherClaims(claimName, resource)` instead. That path exists for debugging, not for production.

**Token types.** Access token **only** (+ introspection, so an RS doing remote introspection sees the same audience as local JWT verification). **Not** ID token, **not** userinfo — the built-in `AudienceProtocolMapper` implements `OIDCIDTokenMapper` but defaults ID-token inclusion to `false` (`AudienceProtocolMapper.java:36,67-72`); an audience in an ID token is meaningless-to-harmful (the ID token's `aud` is the client). If someone later argues for the ID token, they need a written reason.

**Failure behavior.**
- The mapper **never throws for a client without the scope** — it is never invoked for them at all (mapper resolution is per-attached-scope, `ProtocolMapperUtils.getSortedProtocolMappers` at `TokenManager.java:824-830`). This is a structural guard, not a `strict`-flag guard: with the default `strict=true`, a client that *does* carry the scope but omits `resource` is rejected at step 1 (see §3) — the safety of every non-MCP client rests entirely on the scope never being attached to it, not on `strict` happening to be lenient.
- **Regex compile error:** validated at *config* time by implementing `ProtocolMapper#validateConfig` — an admin/config-cli write with a bad pattern is rejected with `ProtocolMapperConfigException` so it never reaches runtime. Defense in depth at runtime: a `PatternSyntaxException` from the cache loader is caught, logged ERROR once per pattern, and treated as "pattern does not match" (i.e. no audience added, non-strict; reject, strict). Never an unhandled exception on the token path.
- Everything else (null user session, missing client session) → return quietly.

---

## 4. Config surface

**Bottom line:** three properties; `allowedResourcePatterns` and `claimName` default safe/inert, `strict` defaults to `true` (fail fast/loud — see rationale in the table below). Environment-specific URL patterns live in realm config, never in Java.

| name | `ProviderConfigProperty` type | default | validation |
|---|---|---|---|
| `allowedResourcePatterns` | `TEXT_TYPE` (`ProviderConfigProperty.java:75` — multi-line textarea, one regex per line) | *(empty = deny all)* | each non-blank line must compile as a `java.util.regex.Pattern`; `validateConfig` rejects otherwise. Empty config ⇒ mapper adds nothing (fail-closed). |
| `claimName` | `STRING_TYPE` (`:42`) | `aud` | non-blank. `aud` selects the typed-field `addAudience` path; anything else writes `otherClaims`. |
| `strict` | `BOOLEAN_TYPE` (`:30`) | `true` | — defaults to fail fast/loud: a misconfigured or missing `resource` is rejected at the token endpoint rather than silently issued as an unaudienced (and therefore 401-at-the-RS) token. Every environment this mapper's scope is attached in is tested live before it reaches prod, so a loud failure during that testing is cheap and a silent one is not. **Consequence:** any client carrying `mcpwarp-resource` that doesn't send `resource` at `/authorize` is refused token issuance — see step 1 below. This is why the scope must only ever be attached to MCP clients, never left on as a realm default that ordinary (non-MCP) clients could pick up. |

`TEXT_TYPE` over `MULTIVALUED_STRING_TYPE` (`:47`) deliberately: multivalued values are stored joined by `##` in the mapper config, which is unreadable in a realm JSON full of regexes and a footgun if a pattern ever contains `#`.

Example patterns:

- dev: `^https://[a-z0-9][a-z0-9-]{0,61}\.dev\.mcpwarp\.io/mcp$` plus `^http://localhost:\d{1,5}/mcp$`
- prod: `^https://[a-z0-9][a-z0-9-]{0,61}\.mcpwarp\.io/mcp$` (add one line per verified custom domain in v2)

Anchor every pattern (`^…$`) even though step 4 uses `matches()`; explicit anchors survive a future switch to `find()`.

**Per-mapper kill switch (document, do not set):** `--spi-protocol-mapper--resource-audience--enabled=false` (SPI name `protocol-mapper`, `ProtocolMapperSpi.java:36`; generic per-factory gate `scope.getBoolean("enabled", true)` in `DefaultKeycloakSessionFactory.java:336-338`). This is a **build-time** option, so it belongs on the `kc.sh build` line in the Dockerfile stage 2 — not on `start`. We ship it commented out with a note; flipping it is a rebuild + image bump, which is the emergency lever if this mapper ever misbehaves in prod.

---

## 5. Realm config snippet (keycloak-config-cli) — **DRAFT**

**Bottom line:** one client scope carrying one mapper, added to `defaultDefaultClientScopes`, plus one line in the DCR Allowed Client Scopes policy. Not yet validated against config-cli `6.5.1-26.5.5`; treat as a sketch until IT #1 passes.

```jsonc
// realm .clientScopes[]
{
  "name": "mcpwarp-resource",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "Access the MCP server you selected"
  },
  "protocolMappers": [{
    "name": "mcpwarp-resource-audience",
    "protocol": "openid-connect",
    "protocolMapper": "resource-audience",          // our getId()
    "consentRequired": false,
    "config": {
      "access.token.claim": "true",
      "introspection.token.claim": "true",
      "id.token.claim": "false",
      "claimName": "aud",
      "strict": "true",
      "allowedResourcePatterns": "^https://[a-z0-9][a-z0-9-]{0,61}\\.mcpwarp\\.io/mcp$"
    }
  }]
}
```

```jsonc
// realm root — DEFAULT, not optional (decision (b))
"defaultDefaultClientScopes": ["... existing ...", "mcpwarp-resource"]
```

```jsonc
// realm .components["org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"]
// BOTH the "anonymous" and "authenticated" variants of allowed-client-templates
{
  "name": "Allowed Client Scopes",
  "providerId": "allowed-client-templates",
  "subType": "anonymous",
  "config": {
    "allow-default-scopes": ["true"],
    // `openid` MUST stay listed explicitly — allow-default-scopes never covers it
    // (ankimcp keycloak-realm-setup.md, verified 26.6.4). A denial here returns a
    // 403 with no ACAO header and looks like a CORS bug in the browser.
    "allowed-client-scopes": ["openid", "profile", "email", "mcpwarp-resource"]
  }
}
```

Note for the ankimcp realm specifically: its per-service scopes (`studio-mcp`, `tunnel-mcp`) stay in `defaultOptionalClientScopes` and are untouched. `mcpwarp-resource` is a *different* scope with a *different* mapper; the two mechanisms coexist because both use `addAudience`.

---

## 6. Test plan

**Bottom line:** IT #1 is a spike that gates the whole design — run it before writing the mapper. Everything else is ordinary unit + Testcontainers work in the existing harness.

**Unit tests** (`*Test.java`, Surefire — note the repo currently has **zero** unit tests; this adds the first):
1. Note present + matching pattern → `addAudience` called once with the exact string.
2. Note absent → no mutation, no exception (the ankimcp guard, at unit level).
3. Note present, no pattern matches → non-strict: no audience, no throw; strict: rejects.
4. Token param equals note → same as (1). Token param differs → non-strict: audience = note; strict: rejects.
5. `addAudience` semantics: pre-existing `aud` entries survive and the new one is appended, no duplicate when the resource is already present.
6. `validateConfig` rejects an uncompilable pattern; empty `allowedResourcePatterns` = deny-all.
7. `claimName` override writes `otherClaims` and leaves `aud` untouched.

**Integration tests** (`*IT.java`, Failsafe, Testcontainers against the published image):

1a. **`DcrDefaultScopeMatrixIT` — DCR scope survival, runs pre-mapper, before mapper code exists.** POST `/realms/<r>/clients-registrations/openid-connect` three ways: (a) `scope: "openid profile email"`, (b) no `scope` field, (c) `scope: "openid profile email mcpwarp-resource"`. For each: assert via the admin API that `mcpwarp-resource` is among the client's scopes (default or optional). **If any row fails, decision (b)'s contingency (a `ClientRegistrationPolicy` that force-adds the scope) is in scope before anything ships.**

1b. **Full auth-code flow, minted token `aud`, post-mapper.** Once the mapper exists, drive a full auth-code flow against a DCR-created client with `resource=https://x.mcpwarp.io/mcp` and assert the minted access token's `aud` contains it.
2. `aud` == the `/authorize` `resource`, for a normal (non-DCR) client with the scope.
3. **ankimcp regression guard:** a client *without* `mcpwarp-resource`, doing a plain login with and without a `resource` param — token issues, login succeeds, `aud` unchanged from the pre-mapper baseline. This is the test that protects prod.
4. Refresh keeps `aud`: exchange the code, refresh, assert the refreshed access token still carries the audience (the note is on the persisted client session, `TokenManager.java:473-476`).
5. Token-param mismatch: refresh with `resource=https://evil.mcpwarp.io/mcp` → non-strict: `aud` is still the original; strict: token endpoint errors.
6. Strict vs non-strict on a non-matching resource (e.g. `https://x.example.com/mcp`): non-strict → token issued with no added audience; strict → rejected.
7. Malformed `resource` (with a fragment) → `/authorize` returns 400 `invalid_target` before the mapper runs (`ResourceIndicatorValidation.java:14-38`), confirming we inherit that validation for free.

**Fit with the existing harness.** `RememberMeAuthenticatorIT` already boots the published image via `GenericContainer(System.getProperty("image.ref", …))` and configures realms/clients/users/flows over the admin REST API with RestAssured. New tests go in a sibling class `io.mcpwarp.keycloak.it.ResourceAudienceMapperIT` in the same module, same pattern, own realm (`audtest`) so nothing collides. **No CI change is needed:** the `integration-test` job already runs `mvn -B -ntp verify -Dimage.ref="${KC_IMAGE}"` against the immutable SHA tag (`.github/workflows/build.yml:762`), and Failsafe picks up `*IT.java` automatically. Expect the job to get a few minutes slower — the container is reused within a class, so keep the new tests in one class.

---

## 7. ankimcp risk analysis

**Bottom line:** four ways this could hurt prod; each has a specific guard, and three of the four are structurally impossible rather than merely tested.

| Risk | Mechanism | Guard |
|---|---|---|
| ankimcp tokens gain a bogus `aud`, **or ankimcp logins start failing outright** | The scope is a realm **default**, so *every* client in the realm gets it — and with `strict=true` (§4), a scope-carrying client that sends no `resource` is now **rejected**, not silently passed through | With non-strict, this row was purely structural (null note → step 1 returns). With the `strict=true` default, decision (b)'s "attach via realm-default scope" is only safe if the ankimcp realm's `defaultDefaultClientScopes` **never actually carries `mcpwarp-resource`** for that realm — i.e. the config-cli snippet in §5 is applied per-realm/per-deployment, not blindly copied. This must be verified before rollout (§8 step 4), not assumed. Plus IT #3. Belt-and-braces alternative: give mcpwarp its own realm (§10) so the ankimcp realm never carries the scope at all. |
| ankimcp `aud` is *clobbered* | Another mapper replacing the array | Structural: we only call `addAudience` (append+dedupe). The existing `oidc-audience-mapper`s (`studio-mcp`, `tunnel-mcp`) and the built-in `AudienceResolveProtocolMapper` also append. **To verify once:** no mapper in the prod realm calls `audience(...)`, and `resource-indicators` stays off (decision (c)). |
| A login **fails** because of the mapper | An exception on the token path | Only reachable for a client carrying `mcpwarp-resource` — the mapper never runs for anyone else, and `strict` (default `true`) can only ever throw for a scope-carrying client. ankimcp is protected because the scope is never attached to an ankimcp client, not because of the `strict` default. Regex problems are caught at config-write time by `validateConfig`. IT #3 asserts login succeeds. |
| DCR breaks for ankimcp's MCP clients | Adding `mcpwarp-resource` to the Allowed Client Scopes policy, or the realm-default scope changing what DCR attaches | The policy change is additive (one entry added to a list). The realm-default question is exactly what IT #1 measures — and if adding a realm default turns out to change what DCR clients receive, we learn it in CI, not in prod. Note ankimcp's own scopes are **optional**, not default, so their behavior is unchanged either way. |

One more, operational: this image is shared. A bad build of the mapper is a bad build of the whole Keycloak image ankimcp runs. Mitigation is the existing gate — smoke-test + smoke-test-optimized + integration-test all pass before the tag is promoted — plus the build-time kill switch in §4 as the break-glass.

---

## 8. Rollout

**Bottom line:** ordinary image-tag bump; the lockstep rule from `CLAUDE.md` still applies even though the Keycloak version does not change.

1. **Build** — merge to `main`; CI builds and pushes `26.7.2-<YYYY.MM.DD>-<sha7>`, `26.7.2-<YYYY.MM.DD>`, `latest`, then runs smoke + optimized-smoke + integration jobs against the immutable tag.
2. **Verify pre-deploy** — integration job green, including IT #1a, #1b, and #3. Do not proceed on a skipped test.
3. **Bump** — in `anki-mcp-infrastructure`, set `spec.image` on the Keycloak CR (`apps/keycloak/templates/keycloak.yaml`) to the immutable SHA tag. Keycloak version is unchanged (26.7.2), so no Operator bump is needed this time — but the lockstep rule stands for the next KC bump.
4. **Realm sync** — the `keycloak-config-cli` PostSync hook applies the §5 realm changes. Verify config-cli `6.5.1-26.5.5` accepts the new `clientScopes` entry and the policy edit; a custom `protocolMapper` id is opaque to config-cli, so this should be a no-op risk, but confirm on the first sync.
5. **Verify post-deploy** — (a) an ankimcp login still works and its token `aud` is byte-identical to the pre-deploy baseline; (b) an mcpwarp DCR client with `resource=` gets the expected `aud`; (c) `kc.sh show-config`/provider listing shows `resource-audience` registered.

**Rollback** — set `spec.image` back to the previous immutable tag and let the Operator roll the StatefulSet; the realm JSON change is additive and harmless with the old image (an unknown `protocolMapper` id on a client scope is inert), so a realm revert is optional and can follow at leisure. If the mapper is registered but misbehaving and a full rollback is unwanted: rebuild with `--spi-protocol-mapper--resource-audience--enabled=false` on the `kc.sh build` line and bump to that tag.

---

## 9. Migration to native RFC 8707

**Bottom line:** we drop the mapper the day Keycloak's `ResourceIndicatorsPostProcessor` can mint an audience for an arbitrary URL it has never seen; until then, the two must never be on simultaneously.

- **Watch:** `Profile.java`'s `RESOURCE_INDICATORS` graduating from `Type.EXPERIMENTAL` to preview/supported; and `ResourceIndicatorsPostProcessor.java:56-90` gaining a resolution path that does **not** require the audience to already be present in the token or a pre-registered per-client `resource_url` (`ResourceIndicatorConstants.java:7`). Upstream trackers: keycloak#14355 (umbrella), #41526 (MCP), PR #46763 (what shipped).
- **The double-`aud` hazard is not real, it is worse than that:** the native post-processor calls `accessToken().audience(...)` — a **replace**. If both are on, whichever runs last wins and the native one runs after mappers, so it would silently *erase* our audience, not duplicate it. There is no "both on" middle state to test in.
- **Drop procedure, in order:** (1) confirm the native path mints the right `aud` on a staging realm with the mapper's scope removed from that client; (2) remove `mcpwarp-resource` from `defaultDefaultClientScopes` and delete the scope; (3) enable `--features=resource-indicators` in the Dockerfile's `kc.sh build`; (4) rebuild, bump, verify; (5) delete the mapper class, its services file, and its tests in a follow-up PR. Never (3) before (2).

---

## 10. Open questions

1. **Does DCR keep the realm-default scope?** The one blocking unknown. Answered by IT #1, not by discussion.
2. **`TokenIntrospectionTokenMapper` — needed?** Only if the Go tunnel ever does remote introspection instead of local JWT verification. Costs one interface; include it unless there is a reason not to.

**Resolved, not open:** `strict` defaults to `true` everywhere (code default and realm config) — see §4. **Downstream, not this repo's decision:** whether mcpwarp gets a dedicated realm or shares the ankimcp prod realm (§7's risk analysis) is an `anki-mcp-infrastructure` deployment call, not a change to this repo's code — this repo's mapper and scope work the same either way.
