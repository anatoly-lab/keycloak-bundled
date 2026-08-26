# Design: `resource-audience` protocol mapper (Keycloak 26.7.2)

Date: 2026-08-25 · Status: **draft, for approval** · Repo: `keycloak-bundled`
Source of truth for all `file:line` below: `docs/research/2026-08-25-resource-audience-mapper-delta.md` (verified against Keycloak tag `26.7.2`, commit `289376b1`), plus the SPI contract citations in §3a (verified against the same tag).

**Update 2026-08-26 (post-gate):** IT #1 ran in CI on the real 26.7.2 image (PR #14) and falsified the realm-default-scope hope in decision (b). See the "Empirical gate result" table below and §3a. The contingency called out in the original decision (b) — a `ClientRegistrationPolicy` that force-adds the scope — **is now the design**, not a fallback.

---

## 1. Bottom line

- A second SPI in this image: an `AbstractOIDCProtocolMapper` that reads the RFC 8707 `resource` value captured at `/authorize` and **appends** it to the access token's `aud`. That is what lets thousands of dynamic `https://<id>.mcpwarp.io/mcp` resources get their own audience without one Keycloak client scope per resource (the ankimcp pattern, which does not scale).
- The value is read from the **client-session note** `resource` — set at `/authorize` (`AuthorizationEndpoint.java:350`), persisted at code exchange (`TokenManager.java:473-476`), and therefore still present on every refresh (`AbstractRefreshTokenProvider.java:121`). A refresh-token holder cannot retarget `aud`.
- **A second, small SPI does the attaching:** a `ClientRegistrationPolicy` provider (`resource-audience-scope`) force-adds the `mcpwarp-resource` client scope to every DCR-registered client in `afterRegister`/`afterUpdate` — i.e. after Keycloak's own `updateClientScopes` has already run and stripped whatever realm defaults it wants to strip. Realm-default attachment alone is **empirically dead** for real MCP clients (see the gate result below); the policy is not a contingency, it is the mechanism.
- Native `--features=resource-indicators` (experimental in 26.7.2) stays **OFF**: it only resolves `urn:client:<id>` / per-client `resource_url`, and its post-processor calls `accessToken().audience(...)` which **replaces** the whole `aud` array (`ResourceIndicatorsPostProcessor.java:21-68`).
- **Topology, not just ankimcp safety, is now the hard constraint.** mcpwarp runs its **own** Keycloak instance, separate from ankimcp (Anatoly, 2026-08-26). That collapses most of the original risk analysis: the policy and the mapper are both per-realm configuration, and ankimcp's instance running this image with neither configured means both are structurally inert there — the JAR being on the classpath does nothing without a realm wiring it in. See §7 for what's left of the ankimcp analysis and §10 for the sharing costs if that topology ever changes.
- With the policy forcing the scope onto every DCR client and `strict=true` (the default) on the mapper, a client that doesn't send `resource` at `/authorize` gets its token issuance rejected — safe on a dedicated instance where every DCR client is an MCP client, unsafe on a shared instance where DCR could register something else. This is exactly why the topology decision above matters.

**Empirical gate result (IT #1, PR #14, real 26.7.2 image):**

| DCR request `scope` field | `mcpwarp-resource` lands as |
|---|---|
| `"openid profile email"` (omits the scope) | **ABSENT** — stripped entirely |
| no `scope` field at all | DEFAULT — realm-default attachment survives |
| `"openid profile email mcpwarp-resource"` | **OPTIONAL** — reclassified from default to optional |

Real MCP clients always send an explicit `scope` field (case 1 or 3) — no real client omits it. So realm-default attachment never gives a real client the scope as DEFAULT. Decision (b) below is rewritten around the policy.

---

## 2. Decisions made (closed — not up for re-litigation)

**(a) Only the `/authorize` client note is a source of truth.** 26.7.2 *does* parse `resource` at `/token` and exposes it as a `ClientSessionContext` attribute on every grant (`OAuth2GrantTypeBase.java:116`, `RefreshTokenGrantType.java:65,82`, `AbstractRefreshTokenProvider.java:150`) — the older "/token drops it" research note was wrong. We still never use it as a *source*. The note is the value the user consented to at the authorization step; the token-endpoint param is attacker-reachable by anyone holding a refresh token. Handling when the token param is present: equal to the note → proceed normally; **mismatch → non-strict: ignore the param, log a warning; strict: reject token issuance** with the closest available error (`invalid_target`, the same code `/authorize` uses for a bad resource — see `AuthorizationEndpointChecker.java:288-296`). Mismatch is logged in both modes, because it is the signal that a client is trying something.

**(b) Attachment via a `ClientRegistrationPolicy` SPI provider that force-adds `mcpwarp-resource`.** Realm defaults *are* attached to DCR clients via the `ClientProtocolUpdatedEvent` listener (`AbstractLoginProtocolFactory.java:47-56,81-97`) — but `RepresentationToModel.createClient:411` then calls `updateClientScopes` (`:663-689`), which strips every scope not in the requested set whenever the rep carries `defaultClientScopes` or `optionalClientScopes`, and `DescriptionConverter.toInternal:87-91` fills `optionalClientScopes` from the DCR body's `scope` field. **IT #1 confirmed this empirically against the real 26.7.2 image (PR #14, gate result in §1):** a client registering with an explicit `scope` field — which is every real MCP client — never ends up with the scope as DEFAULT from realm-default attachment alone. What was framed as "decision (b)'s contingency" is therefore the actual mechanism:

- A `ClientRegistrationPolicy` provider, id **`resource-audience-scope`** (paired naming with the mapper's `resource-audience`), registered as both the `anonymous` and `authenticated` policy subtypes (design doc §5).
- `afterRegister(ClientRegistrationContext context, ClientModel clientModel)` — called by `ClientRegistrationPolicyManager.triggerAfterRegister` from `AbstractClientRegistrationProvider.create` **after** `ClientManager.createClient` has already run `updateClientScopes` (`services/.../clientregistration/AbstractClientRegistrationProvider.java:86,104`, confirmed by source order in the 26.7.2 tree) — looks up the configured client scope by name on the realm (`RealmModel.getClientScopesStream()`, `server-spi/.../RealmModel.java:777`) and, if it isn't already attached as DEFAULT, calls `clientModel.removeClientScope(scope)` (no-op if not currently attached) followed by `clientModel.addClientScope(scope, /* defaultScope */ true)` (`server-spi/.../ClientModel.java:232`) — the remove-then-add sequence, not a plain unconditional add (see §3a for why). Runs for every DCR client, anonymous and authenticated.
- `afterUpdate(ClientRegistrationContext context, ClientModel clientModel)` — same force-add, because a later DCR `PUT` runs `RepresentationToModel.updateClientScopes` again (`AbstractClientRegistrationProvider.java:176-178`, followed by `triggerAfterUpdate` at `:214`) and can strip the scope the exact same way a `POST` can. Without this, a client that registered with the scope intact could lose it on its first metadata update.
- Config: one property, `clientScope` (`STRING_TYPE`), default `mcpwarp-resource`. The named scope **must already exist in the realm** — the policy does not create it (the client scope + its mapper are still realm config, §5). `validateConfiguration` (part of `ClientRegistrationPolicyFactory` via `ComponentFactory`) should reject a config naming a scope that doesn't exist, mirroring `ClientScopesClientRegistrationPolicyFactory.validateConfiguration` (`services/.../policy/impl/ClientScopesClientRegistrationPolicyFactory.java:107-112`).
- Independently, the realm's DCR **Allowed Client Scopes** policy (`allowed-client-templates`) must still permit `mcpwarp-resource` explicitly, so a client that *does* ask for the scope in its `scope` field (case iii) isn't 403'd before the new policy ever runs; `allow-default-scopes: true` covers realm default+optional scopes (`ClientScopesClientRegistrationPolicy.java:123-134`), but ankimcp learned the hard way that `openid` is *not* covered and must be listed explicitly — keep that entry too.

**Why force-add rather than just fixing the Allowed Client Scopes policy or re-ordering the realm-default listener:** the strip happens inside `RepresentationToModel.updateClientScopes`, which runs unconditionally whenever the DCR body carries a `scope`/`defaultClientScopes`/`optionalClientScopes` field — there is no realm-level policy knob that changes that method's behavior. The only extension point that runs *after* it is `ClientRegistrationPolicy#afterRegister`/`#afterUpdate`.

**(c) `--features=resource-indicators` stays OFF.** It shipped in 26.7.2 as `Type.EXPERIMENTAL` (`Profile.java:199`), so it is off by default and we do not turn it on. Two reasons: it cannot mint an audience that is not already in the token (`ResourceIndicatorsPostProcessor.java:56-90` — `urn:client:<id>`, or a URL matched against a client's `resource_url` attribute), which is useless for thousands of dynamic URLs; and its post-processor calls `audience(...)` (**replace**, `JsonWebToken.java:211`) rather than `addAudience` (**append+dedupe**, `:216-231`), so enabling it alongside this mapper would clobber our `aud`. Note the *syntax* validation of `resource` at `/authorize` is **not** feature-gated and runs regardless (`ResourceIndicatorValidation.java:14-38`: absolute URI, no fragment, no query, non-null path) — `https://<id>.mcpwarp.io/mcp` passes; a malformed value gets a 400 `invalid_target` before any mapper runs, which is fine and free validation.

**(d) Same Maven module as remember-me, own package.** `src/pom.xml` stays a single module; the Dockerfile keeps one JAR name, the workflow keeps one BOM assertion, and `kc.sh build` flattens `providers/` into one classpath anyway. Our code goes under `io.mcpwarp.keycloak` (**not** `com.herdo` — that package is vendored MIT code and the NOTICE must stay accurate), registered through a **new** file `META-INF/services/org.keycloak.protocol.ProtocolMapper` alongside the existing `…AuthenticatorFactory` file (separate files, no conflict). `src/pom.xml` gains `org.keycloak:keycloak-services` at `provided` scope — in 26.7.2 `AbstractOIDCProtocolMapper` and the mapper interfaces live in the `services` module, not `server-spi-private` (version managed by `keycloak-parent`, root `pom.xml:1082-1086`).

---

## 3. Design

**Bottom line:** one class, ~120 lines, access token only, reads one note, validates it against a regex allowlist, calls `addAudience`. If anything is missing or wrong it returns silently.

- **Provider id:** `resource-audience` (this is the id in the SPI kill switch and in the realm JSON's `protocolMapper` field).
- **Class:** `io.mcpwarp.keycloak.mappers.ResourceAudienceMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper`. `ProtocolMapper extends Provider, ProviderFactory, ConfiguredProvider` (`ProtocolMapper.java:32`), so one class is both provider and factory — `getId()`, `getDisplayCategory()`, `getDisplayType()`, `getHelpText()`, `getConfigProperties()`; `getProtocol()` comes from the base class. **Not** `TokenIntrospectionTokenMapper` — see §10 open question 2 (resolved).
- **No compiled-pattern cache:** the allowlist is recompiled with `Pattern.compile` on every call. An unbounded static cache keyed on raw pattern text would grow without limit if config strings vary across realms/mappers, and Keycloak already caches the `ProtocolMapperModel`/config, so per-token recompilation of a handful of small regexes is cheap enough not to be worth the bookkeeping (code review P2).

**`transformAccessToken` flow** (we override `setClaim(IDToken, ProtocolMapperModel, UserSessionModel, KeycloakSession, ClientSessionContext)` at `AbstractOIDCProtocolMapper.java:156`; the base `transformAccessToken` at `:89-99` already gates on `access.token.claim`):

1. Read the note: `ctx.getClientSession().getNote("resource")` — literal key `resource` (`OIDCLoginProtocol.java:90` → `OAuth2Constants.java:133`, no prefix). Null/blank → **non-strict:** return, do nothing; **strict (the default):** reject (`invalid_target`). This only ever fires for a client that carries the `mcpwarp-resource` scope in the first place — the mapper is never invoked for a client without the scope (mapper resolution is per-attached-scope), so ankimcp and every other non-MCP client is untouched regardless of `strict`. The consequence is deliberate: with the default `strict=true`, a scope-carrying client that forgets `resource` fails loudly at the token endpoint instead of silently getting an unaudienced token.
2. Read this request's `resource` param: `ctx.getAttribute(OAuth2Constants.RESOURCE, String.class)`. Null → skip to 4 (the attribute is explicitly set to `null` when absent, so it is never a fallback).
3. If present and `!equals(note)` → log WARN. **strict=true:** throw the mapper's reject path (`invalid_target`); **strict=false:** ignore the param and continue with the note.
4. Validate the note against `allowedResourcePatterns`: full-match (`Matcher.matches()`) against any one pattern. No match → log at INFO; **strict=true:** reject; **strict=false:** return without adding an audience (token still issues, just unaudienced — the resource server will 401 it, which is the correct outcome).
5. `token.addAudience(resource)` — append + dedupe (`JsonWebToken.java:216-231`), the same call the built-in `AudienceProtocolMapper.java:112` makes. **Never** `audience(...)` (replaces, `:211`) and **never** `setOtherClaims("aud", …)` (`aud` is a typed field, `JsonWebToken.java:63` — an otherClaims entry would serialize wrong). Exactly one resource per token, by construction: one note, one `addAudience`.

Only if `claimName` is set to something other than `aud`: step 5 writes `setOtherClaims(claimName, resource)` instead. That path exists for debugging, not for production.

**Token types.** Access token **only**. **Not** introspection — see §10 open question 2 (resolved): `AccessTokenIntrospectionProvider` already copies the original `aud` from the issued token, so this mapper implementing `TokenIntrospectionTokenMapper` would just mean a strict-mode reject re-runs during introspection and surfaces as an unhandled 500, not a clean error. **Not** ID token, **not** userinfo — the built-in `AudienceProtocolMapper` implements `OIDCIDTokenMapper` but defaults ID-token inclusion to `false` (`AudienceProtocolMapper.java:36,67-72`); an audience in an ID token is meaningless-to-harmful (the ID token's `aud` is the client). If someone later argues for the ID token, they need a written reason.

**Failure behavior.**
- The mapper **never throws for a client without the scope** — it is never invoked for them at all (mapper resolution is per-attached-scope, `ProtocolMapperUtils.getSortedProtocolMappers` at `TokenManager.java:824-830`). This is a structural guard, not a `strict`-flag guard: with the default `strict=true`, a client that *does* carry the scope but omits `resource` is rejected at step 1 (see §3) — the safety of every non-MCP client rests entirely on the scope never being attached to it, not on `strict` happening to be lenient.
- **Regex compile error:** validated at *config* time by implementing `ProtocolMapper#validateConfig` — an admin/config-cli write with a bad pattern is rejected with `ProtocolMapperConfigException` so it never reaches runtime. Defense in depth at runtime: a `PatternSyntaxException` from `Pattern.compile` (recompiled per call, §3 — there is no cache) is caught, logged ERROR (once per token that hits the bad pattern, not deduplicated), and treated as "pattern does not match" (i.e. no audience added, non-strict; reject, strict). Never an unhandled exception on the token path.
- Everything else (null user session, missing client session) → return quietly.

---

## 3a. Design — the `resource-audience-scope` `ClientRegistrationPolicy`

**Bottom line:** one class, ~60 lines, no token-path code at all — it runs twice per client lifecycle (register, update) and does one thing: make sure the client scope is attached as DEFAULT.

**SPI contract, verified against Keycloak tag `26.7.2` (commit `289376b1`):**

- `ClientRegistrationPolicy` (`services/src/main/java/org/keycloak/services/clientregistration/policy/ClientRegistrationPolicy.java:32`) — interface, extends `Provider`. Six methods: `beforeRegister(ClientRegistrationContext)`, `afterRegister(ClientRegistrationContext, ClientModel)`, `beforeUpdate(ClientRegistrationContext, ClientModel)`, `afterUpdate(ClientRegistrationContext, ClientModel)`, `beforeView(ClientRegistrationProvider, ClientModel)`, `beforeDelete(ClientRegistrationProvider, ClientModel)`, plus a default `getAllowedOrigins()` (CORS) and a default no-op `close()`. Only `afterRegister`/`afterUpdate` are needed for this policy.
- `ClientRegistrationPolicyFactory` (`services/src/main/java/org/keycloak/services/clientregistration/policy/ClientRegistrationPolicyFactory.java:29`) — `extends ComponentFactory<ClientRegistrationPolicy, ClientRegistrationPolicy>`, adding one method: `getConfigProperties(KeycloakSession)`. `ComponentFactory` (not shown here, standard Keycloak component SPI) is what gives us `getId()`, `create(KeycloakSession, ComponentModel)`, and `validateConfiguration(KeycloakSession, RealmModel, ComponentModel)`.
- `ClientRegistrationContext.getClient()` returns the **requested** `ClientRepresentation` (`services/src/main/java/org/keycloak/services/clientregistration/ClientRegistrationContext.java:28`) — this is the DCR request body, already parsed. `afterRegister`'s second parameter, `ClientModel clientModel`, is the **persisted** model — this is what we mutate.
- Call-site order confirmed in `AbstractClientRegistrationProvider` (services module):
  - **Create:** `ClientManager.createClient(session, realm, client)` (`:86`, this is what runs `RepresentationToModel.createClient` → `updateClientScopes`) happens **before** `ClientRegistrationPolicyManager.triggerAfterRegister(context, registrationAuth, clientModel)` (`:104`). So `afterRegister` is guaranteed to run after the strip.
  - **Update:** `RepresentationToModel.updateClient/updateClientProtocolMappers/updateClientScopes` (`:176-178`) happens **before** `ClientRegistrationPolicyManager.triggerAfterUpdate(context, registrationAuth, client)` (`:214`). Same guarantee on the update path.
- Attaching the scope: `RealmModel.getClientScopesStream()` (`server-spi/src/main/java/org/keycloak/models/RealmModel.java:777`) to find the configured scope by name (there is no `getClientScopeByName`, only `getClientScopeById:809`, so this is a `.filter(s -> name.equals(s.getName())).findFirst()`), then `ClientModel.addClientScope(ClientScopeModel clientScope, boolean defaultScope)` (`server-spi/src/main/java/org/keycloak/models/ClientModel.java:232`) with `defaultScope=true`. **Not** a plain idempotent add: `addClientScope` is a no-op if the scope is already attached as OPTIONAL (`JpaRealmProvider.addClientScopes` filters on existing names across both the default and optional lists), so promoting an OPTIONAL attachment to DEFAULT requires an explicit `removeClientScope` + `addClientScope` sequence — see the corrected flow below.
- Registration/subtype pattern: providers are registered per **`RegistrationAuth`** subtype, and the subtype string is exactly `RegistrationAuth.ANONYMOUS/AUTHENTICATED name().toLowerCase()` → `"anonymous"` / `"authenticated"` (`services/src/main/java/org/keycloak/services/clientregistration/policy/ClientRegistrationPolicyManager.java:153-155`, `getComponentTypeKey`). Keycloak's own seeded "Allowed Client Scopes" policy (`ClientScopesClientRegistrationPolicyFactory.PROVIDER_ID = "allowed-client-templates"`, `services/.../policy/impl/ClientScopesClientRegistrationPolicyFactory.java:43`) is created for **both** subtypes on realm creation (`DefaultClientRegistrationPolicies.addAnonymousPolicies` and `.addAuthPolicies`, both calling `addGenericPolicies`, `services/.../policy/DefaultClientRegistrationPolicies.java:78-118`) — our policy follows the same both-subtypes pattern, confirming the design doc's original plan (§5) was already correct on this point.
- `providerType` for the realm-JSON component (§5) is `ClientRegistrationPolicy.class.getName()`, i.e. the literal string `org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy` — confirmed by `DefaultClientRegistrationPolicies.createModelInstance` (`:73`, `model.setProviderType(ClientRegistrationPolicy.class.getName())`), matching what the existing `DcrScopeStrippingCharacterizationIT`/`ResourceAudienceScopePolicyIT` tests already query for.

**`afterRegister`/`afterUpdate` flow (identical body, one shared private method):**

1. Read `config.clientScope` (default `mcpwarp-resource`).
2. `realm.getClientScopesStream().filter(s -> clientScopeName.equals(s.getName())).findFirst()` — if absent, log ERROR (misconfiguration: the scope must exist in the realm, per §4) and return without throwing (a DCR client should not fail to register because of a config-cli ordering issue; the scope will simply be missing from the token until the realm config catches up).
3. Check `clientModel.getClientScopes(true).containsKey(clientScopeName)` — if already present in the DEFAULT map, do nothing (already correct). Otherwise `clientModel.removeClientScope(scope)` (no-op if not currently attached at all) followed by `clientModel.addClientScope(scope, true)`. A plain `addClientScope(scope, true)` is **not** idempotent-safe when the scope is already attached as OPTIONAL: `JpaRealmProvider.addClientScopes` filters candidates on existing names across *both* the default and optional lists, so calling it again silently no-ops instead of promoting the scope to DEFAULT — the explicit remove-then-add sequence is required to actually move it.

**Failure behavior.** Never throws from `afterRegister`/`afterUpdate` — both are `void` on the interface, with no declared exception, so any policy that throws here would surface as an unhandled 500 on every DCR call for the lifetime of the misconfiguration. Missing scope → log + no-op, as above.

**Registration file.** `META-INF/services/org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyFactory`, third file alongside the two already in this JAR. SPI name is `client-registration-policy` (`ClientRegistrationPolicySpi.java:35`), marked `isInternal() = true` (`:29-31`) — this only affects whether Keycloak surfaces the SPI in its own internal-SPI bookkeeping/docs, not whether third-party `ServiceLoader`-registered factories work; `ClientScopesClientRegistrationPolicyFactory` (Keycloak's own built-in) is registered exactly the same way, so a vendored provider follows the identical path.

---

## 4. Config surface

**Bottom line:** three properties; `allowedResourcePatterns` and `claimName` default safe/inert, `strict` defaults to `true` (fail fast/loud — see rationale in the table below). Environment-specific URL patterns live in realm config, never in Java.

| name | `ProviderConfigProperty` type | default | validation |
|---|---|---|---|
| `allowedResourcePatterns` | `TEXT_TYPE` (`ProviderConfigProperty.java:75` — multi-line textarea, one regex per line) | *(empty = deny all)* | each non-blank line must compile as a `java.util.regex.Pattern`; `validateConfig` rejects otherwise. Empty config ⇒ mapper adds nothing (fail-closed). |
| `claimName` | `STRING_TYPE` (`:42`) | `aud` | non-blank. `aud` selects the typed-field `addAudience` path; anything else writes `otherClaims`. |
| `strict` | `BOOLEAN_TYPE` (`:30`) | `true` | — defaults to fail fast/loud: a misconfigured or missing `resource` is rejected at the token endpoint rather than silently issued as an unaudienced (and therefore 401-at-the-RS) token. Every environment this mapper's scope is attached in is tested live before it reaches prod, so a loud failure during that testing is cheap and a silent one is not. **Consequence:** any client carrying `mcpwarp-resource` that doesn't send `resource` at `/authorize` is refused token issuance — see step 1 below. This is why the scope must only ever be attached to MCP clients, never left on as a realm default that ordinary (non-MCP) clients could pick up. |

`TEXT_TYPE` over `MULTIVALUED_STRING_TYPE` (`:47`) deliberately: multivalued values are stored joined by `##` in the mapper config, which is unreadable in a realm JSON full of regexes and a footgun if a pattern ever contains `#`.

**CORS limitation on strict rejection.** A strict-mode reject throws a plain `ErrorResponseException` from inside the mapper, which builds a response with no CORS headers — a mapper has no access to the CORS response-building machinery the token endpoint normally applies to its own error responses. For a browser-based client hitting `/token` cross-origin, this means a strict rejection shows up as a CORS error in the browser, not a clean `invalid_target` the client's HTTP layer can parse. This isn't fixable from inside a `ProtocolMapper` — it would need a change at the token-endpoint layer itself. Non-browser clients (anything not bound by CORS, e.g. a server-side confidential client or the Go tunnel) see the real `invalid_target` response as intended.

Example patterns:

- dev: `^https://[a-z0-9][a-z0-9-]{0,61}\.dev\.mcpwarp\.io/mcp$` plus `^http://localhost:\d{1,5}/mcp$`
- prod: `^https://[a-z0-9][a-z0-9-]{0,61}\.mcpwarp\.io/mcp$` (add one line per verified custom domain in v2)

Anchor every pattern (`^…$`) even though step 4 uses `matches()`; explicit anchors survive a future switch to `find()`.

**Per-mapper kill switch (document, do not set):** `--spi-protocol-mapper--resource-audience--enabled=false` (SPI name `protocol-mapper`, `ProtocolMapperSpi.java:36`; generic per-factory gate `scope.getBoolean("enabled", true)` in `DefaultKeycloakSessionFactory.java:336-338`). This is a **build-time** option, so it belongs on the `kc.sh build` line in the Dockerfile stage 2 — not on `start`. We ship it commented out with a note; flipping it is a rebuild + image bump, which is the emergency lever if this mapper ever misbehaves in prod.

### 4a. `resource-audience-scope` policy config

**Bottom line:** one property, `clientScope`, default `mcpwarp-resource`.

| name | `ProviderConfigProperty` type | default | validation |
|---|---|---|---|
| `clientScope` | `STRING_TYPE` (`ProviderConfigProperty.java:42`) | `mcpwarp-resource` | non-blank. `validateConfiguration` (the `ComponentFactory` hook, same shape as `ClientScopesClientRegistrationPolicyFactory.validateConfiguration`, `services/.../policy/impl/ClientScopesClientRegistrationPolicyFactory.java:107-112`) checks the named scope exists on the realm at config-write time; the runtime `afterRegister`/`afterUpdate` path additionally tolerates a scope that no longer exists (log + no-op, §3a) in case it's deleted after the policy is configured. |

No per-provider kill switch documented separately — the policy uses the same generic `scope.getBoolean("enabled", true)` mechanism as any component factory, under SPI `client-registration-policy`. Since this policy only affects DCR-registered clients (§7), disabling it stops new/updated DCR clients from getting the scope but does not retroactively remove it from clients that already have it.

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
      "id.token.claim": "false",
      "lightweight.claim": "true",
      "claimName": "aud",
      "strict": "true",
      "allowedResourcePatterns": "^https://[a-z0-9][a-z0-9-]{0,61}\\.mcpwarp\\.io/mcp$"
    }
  }]
}
```

```jsonc
// realm root — kept as a realm default too, harmless belt-and-braces for the
// no-scope-field DCR case (empirical gate case 2) and for any non-DCR client
// created directly via the admin API/console.
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
    // `mcpwarp-resource` MUST also be listed explicitly, so a DCR body that
    // explicitly requests it (empirical gate case 3) isn't 403'd before the
    // resource-audience-scope policy below ever gets a chance to run.
    "allowed-client-scopes": ["openid", "profile", "email", "mcpwarp-resource"]
  }
}
```

```jsonc
// realm .components["org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"]
// THE mechanism (decision (b)) — BOTH "anonymous" and "authenticated" subtypes,
// same pattern Keycloak uses for its own "Allowed Client Scopes" policy above
// (DefaultClientRegistrationPolicies.addAnonymousPolicies/.addAuthPolicies,
// both call addGenericPolicies — see §3a). Force-adds mcpwarp-resource as a
// DEFAULT scope on every DCR client in afterRegister/afterUpdate, regardless
// of what updateClientScopes already stripped.
{
  "name": "Resource Audience Scope",
  "providerId": "resource-audience-scope",          // our getId()
  "subType": "anonymous",                            // repeat with subType "authenticated"
  "config": {
    "clientScope": ["mcpwarp-resource"]
  }
}
```

Note for the ankimcp realm specifically: its per-service scopes (`studio-mcp`, `tunnel-mcp`) stay in `defaultOptionalClientScopes` and are untouched. `mcpwarp-resource` is a *different* scope with a *different* mapper; the two mechanisms coexist because both use `addAudience`. **In practice this doesn't matter for ankimcp today** — see §7: mcpwarp runs its own instance, so none of this §5 snippet is ever applied to the ankimcp realm at all.

---

## 6. Test plan

**Bottom line:** the DCR gate spike already ran (§1) and is now a permanent characterization test, green. The policy gets its own IT class, no longer `@Disabled` now that the provider is implemented (§8). Everything else is ordinary unit + Testcontainers work in the existing harness.

**Unit tests** (`*Test.java`, Surefire — note the repo currently has **zero** unit tests; this adds the first):
1. Note present + matching pattern → `addAudience` called once with the exact string.
2. Note absent → no mutation, no exception (the ankimcp guard, at unit level).
3. Note present, no pattern matches → non-strict: no audience, no throw; strict: rejects.
4. Token param equals note → same as (1). Token param differs → non-strict: audience = note; strict: rejects.
5. `addAudience` semantics: pre-existing `aud` entries survive and the new one is appended, no duplicate when the resource is already present.
6. `validateConfig` rejects an uncompilable pattern; empty `allowedResourcePatterns` = deny-all.
7. `claimName` override writes `otherClaims` and leaves `aud` untouched.
8. (policy) `afterRegister`/`afterUpdate` call `addClientScope(scope, true)` exactly once per invocation; missing configured scope on the realm → log + no-op, no throw.
9. (policy) `validateConfiguration` rejects a `clientScope` naming a scope that doesn't exist on the realm.

**Integration tests** (`*IT.java`, Failsafe, Testcontainers against the published image):

1. **`DcrScopeStrippingCharacterizationIT`** (renamed from `DcrDefaultScopeMatrixIT` — the gate spike; **ran in CI on PR #14, result recorded in §1, test is now GREEN and permanent**). POST `/realms/<r>/clients-registrations/openid-connect` three ways: (a) `scope: "openid profile email"` → asserts ABSENT, (b) no `scope` field → asserts DEFAULT, (c) `scope: "openid profile email mcpwarp-resource"` → asserts OPTIONAL. Documents Keycloak's own DCR scope-stripping behavior as a guardrail: a failure here means Keycloak's behavior changed, which is the trigger to re-evaluate whether the `resource-audience-scope` policy is still needed or needs adjusting (see the class Javadoc).

2. **`ResourceAudienceScopePolicyIT`** (new, no longer `@Disabled` now that the `resource-audience-scope` provider is implemented — see §8). Same three DCR shapes as #1, but asserts `mcpwarp-resource` ends as **DEFAULT in all three** (the policy overrides whatever `updateClientScopes` stripped). Plus a fourth case: DCR `PUT` update that omits the scope from its `scope` field — asserts the scope is re-added as DEFAULT by `afterUpdate`. Shares realm/scope/policy/DCR plumbing with #1 via a small package-private helper, `DcrTestSupport`, rather than duplicating it (both classes register clients against a throwaway realm and read scopes back over the admin API — same shape, different assertions and a different set of `ClientRegistrationPolicy` components on the realm).

3. **Full auth-code flow, minted token `aud`, post-mapper.** Once the mapper exists, drive a full auth-code flow against a DCR-created client with `resource=https://x.mcpwarp.io/mcp` and assert the minted access token's `aud` contains it.
4. `aud` == the `/authorize` `resource`, for a normal (non-DCR) client with the scope.
5. **ankimcp regression guard:** a client *without* `mcpwarp-resource`, doing a plain login with and without a `resource` param — token issues, login succeeds, `aud` unchanged from the pre-mapper baseline. This is the test that protects prod — see §7 for why it's now more of a belt-and-braces check than a load-bearing one.
6. Refresh keeps `aud`: exchange the code, refresh, assert the refreshed access token still carries the audience (the note is on the persisted client session, `TokenManager.java:473-476`).
7. Token-param mismatch: refresh with `resource=https://evil.mcpwarp.io/mcp` → non-strict: `aud` is still the original; strict: token endpoint errors.
8. Strict vs non-strict on a non-matching resource (e.g. `https://x.example.com/mcp`): non-strict → token issued with no added audience; strict → rejected.
9. Malformed `resource` (with a fragment) → for a valid `client_id`/`redirect_uri`, `/authorize` rejects it **before the mapper runs**, but not as a 400: `AuthorizationEndpointChecker.checkValidResource()` (`AuthorizationEndpointChecker.java:288-296`) throws `AuthorizationCheckException(BAD_REQUEST, INVALID_TARGET, ...)`, and `AuthorizationEndpoint.authorize()` catches that from the same try block as `checkResponseType`/`checkOIDCParams` (`AuthorizationEndpoint.java:192-197`) via `redirectErrorToClient(...)`, which appends `error=invalid_target` (plus `state`) to `redirect_uri` and returns a **302** (`AuthorizationEndpoint.java:320-336`). The `throwAsErrorPageException` path that renders an HTML 400 page only applies to the earlier `checkRedirectUri()` failure (`AuthorizationEndpoint.java:165-166`), i.e. when there's no safe place to redirect to. So the correct assertion is: 302, `Location` starts with `redirect_uri`, and contains `error=invalid_target` — not a 400.

**Fit with the existing harness.** `RememberMeAuthenticatorIT` already boots the published image via `GenericContainer(System.getProperty("image.ref", …))` and configures realms/clients/users/flows over the admin REST API with RestAssured. New tests go in sibling classes under `io.mcpwarp.keycloak.it`, same pattern, own realms (`dcrtest`, `audpolicytest`, and eventually `audtest` for the mapper's own E2E class) so nothing collides. **No CI change is needed:** the `integration-test`/`pr-build` jobs already run `mvn -B -ntp verify -Dimage.ref="${KC_IMAGE}"`, and Failsafe picks up `*IT.java` automatically. Expect the job to get a few minutes slower — each container is reused within its own class, so keep each IT class's tests together.

---

## 7. ankimcp risk analysis

**Bottom line — this section is now almost entirely moot.** mcpwarp runs its **own** Keycloak instance, separate from ankimcp (Anatoly, 2026-08-26). The mapper, the `mcpwarp-resource` client scope, and the `resource-audience-scope` policy are all **per-realm configuration**, not per-image behavior — the JAR being on ankimcp's classpath (it runs the same bundled image) does nothing unless ankimcp's own realm config wires the scope/mapper/policy in, which it never does. Every risk in the original analysis below reduced to "does ankimcp's realm carry this config" — and on separate instances, the answer is structurally no, not "verified not to."

What's actually left:

| Risk | Why it's now structural, not just tested |
|---|---|
| ankimcp tokens gain a bogus `aud`, or ankimcp logins start failing | Ankimcp's realm never gets the `mcpwarp-resource` client scope, the `resource-audience` mapper, or the `resource-audience-scope` policy — none of §5's realm-config snippet is ever applied to ankimcp's realm config repo. There is no shared realm for a misconfiguration to leak across. |
| ankimcp `aud` is clobbered by another mapper | Unrelated to the topology question, still worth stating: the mapper only ever calls `addAudience` (append+dedupe), never `audience(...)` (replace) — see decision (c) and §3 step 5. This would matter even on a shared instance. |
| A login fails because of the mapper | Same as above — only reachable for a client carrying the scope, and ankimcp clients never do, on any instance. |
| This image is shared infrastructure | Still true and still the one real operational risk: a bad build of the mapper or the policy is a bad build of the whole Keycloak image, and ankimcp runs that same image (with the SPI dormant). Mitigation is unchanged — smoke-test + smoke-test-optimized + integration-test all pass before the tag is promoted, plus the build-time kill switches (§4, §4a) as break-glass. |

**If mcpwarp ever shares ankimcp's instance in the future** (not planned, but worth stating the cost): the only *requirement* is a dedicated `mcpwarp` realm — the mapper and the policy are per-realm config, so as long as ankimcp's realm never carries `mcpwarp-resource`/`resource-audience`/`resource-audience-scope`, the two products don't interfere even on one instance. The costs of sharing at that point: (1) users become per-realm, so ankimcp and mcpwarp would need a brokering setup for any shared-account story, not a single user table; (2) upgrade/outage blast radius is shared — a bad Keycloak upgrade or an outage on the shared instance takes down both products at once, where separate instances only take down one.

**One more scoping fact, independent of topology:** the `resource-audience-scope` policy only ever runs on the DCR code path (`ClientRegistrationPolicyManager.triggerAfterRegister`/`triggerAfterUpdate`, §3a). A web-app client created directly via a realm JSON import (or the admin console/API) never goes through Dynamic Client Registration at all, so it never gets `mcpwarp-resource` attached and is never subject to the mapper's `strict=true` rejection. Only DCR-registered MCP clients are ever in scope for either SPI — this holds regardless of instance topology.

---

## 8. Rollout

**Bottom line:** ordinary image-tag bump; the lockstep rule from `CLAUDE.md` still applies even though the Keycloak version does not change. This mapper and policy are built for mcpwarp's own consumption — the concrete steps below describe rolling them out to **the consuming deployment (mcpwarp's own Keycloak instance; repo TBD)**, not ankimcp's. See §7 for why ankimcp's instance is untouched by any of this regardless.

1. **Build** — merge to `main`; CI builds and pushes `26.7.2-<YYYY.MM.DD>-<sha7>`, `26.7.2-<YYYY.MM.DD>`, `latest`, then runs smoke + optimized-smoke + integration jobs against the immutable tag.
2. **Verify pre-deploy** — integration job green, including `DcrScopeStrippingCharacterizationIT`, `ResourceAudienceScopePolicyIT`, and `ResourceAudienceMapperIT` (all exist today, `src/src/test/java/io/mcpwarp/keycloak/it/`). `ResourceAudienceMapperIT` is the mapper's own end-to-end class (§6 test plan items 3-8): an `audtest`-realm suite driving a real auth-code + PKCE flow against a DCR-registered client (strict scope, force-attached by the `resource-audience-scope` policy) and an admin-API client carrying a non-strict scope instance, covering aud == resource on a match, refresh preserving aud, a matching `/token`-time resource param, a mismatched `/token`-time resource param rejected under `strict`, a non-matching `/authorize`-time resource rejected under `strict`, the non-strict equivalent issuing a token with the bad value absent from `aud`, and the ankimcp-style regression guard (an admin-API client without the scope, `aud` unaffected by a `resource` param either way). Do not proceed on a skipped test.
3. **Bump** — in the consuming deployment, set `spec.image` on its Keycloak CR to the immutable SHA tag. Keycloak version is unchanged (26.7.2), so no Operator bump is needed this time — but the lockstep rule stands for the next KC bump.
4. **Realm sync** — whatever the consuming deployment uses to reconcile realm config (e.g. a `keycloak-config-cli` PostSync hook, if it follows the same pattern as ankimcp) applies the §5 realm changes. Verify the tool accepts the new `clientScopes` entry and the policy component; a custom `protocolMapper`/`providerId` is opaque to most such tools, so this should be a no-op risk, but confirm on the first sync.
5. **Verify post-deploy** — (a) an mcpwarp DCR client with `resource=` gets the expected `aud`; (b) `kc.sh show-config`/provider listing shows `resource-audience` and `resource-audience-scope` registered; (c) if this Keycloak instance also serves any non-MCP client, confirm its login and token `aud` are unaffected (§7's "one more scoping fact": only DCR-registered clients are ever in scope for either SPI).

**Rollback** — set `spec.image` back to the previous immutable tag and let the Operator roll the StatefulSet; the realm JSON change is additive and harmless with the old image (an unknown `protocolMapper` id on a client scope is inert), so a realm revert is optional and can follow at leisure. If the mapper is registered but misbehaving and a full rollback is unwanted: rebuild with `--spi-protocol-mapper--resource-audience--enabled=false` on the `kc.sh build` line and bump to that tag.

---

## 9. Migration to native RFC 8707

**Bottom line:** we drop the mapper the day Keycloak's `ResourceIndicatorsPostProcessor` can mint an audience for an arbitrary URL it has never seen; until then, the two must never be on simultaneously.

- **Watch:** `Profile.java`'s `RESOURCE_INDICATORS` graduating from `Type.EXPERIMENTAL` to preview/supported; and `ResourceIndicatorsPostProcessor.java:56-90` gaining a resolution path that does **not** require the audience to already be present in the token or a pre-registered per-client `resource_url` (`ResourceIndicatorConstants.java:7`). Upstream trackers: keycloak#14355 (umbrella), #41526 (MCP), PR #46763 (what shipped).
- **The double-`aud` hazard is not real, it is worse than that:** the native post-processor calls `accessToken().audience(...)` — a **replace**. If both are on, whichever runs last wins and the native one runs after mappers, so it would silently *erase* our audience, not duplicate it. There is no "both on" middle state to test in.
- **Drop procedure, in order:** (1) confirm the native path mints the right `aud` on a staging realm with the mapper's scope removed from that client; (2) remove `mcpwarp-resource` from `defaultDefaultClientScopes` and delete the scope; (3) enable `--features=resource-indicators` in the Dockerfile's `kc.sh build`; (4) rebuild, bump, verify; (5) delete the mapper class, its services file, and its tests in a follow-up PR. Never (3) before (2).

---

## 10. Open questions

1. ~~**Does DCR keep the realm-default scope?**~~ **RESOLVED, 2026-08-26.** No — see the empirical gate result in §1 and `DcrScopeStrippingCharacterizationIT`. Realm-default attachment survives only when the DCR body omits `scope` entirely, which no real client does. This is why §2 decision (b) and §3a now specify a `ClientRegistrationPolicy` as the mechanism, not a contingency.
2. ~~**`TokenIntrospectionTokenMapper` — needed?**~~ **RESOLVED, 2026-08-26: no.** Introspection is out of scope for this mapper — Keycloak's `AccessTokenIntrospectionProvider` already preserves the original `aud` from the issued access token, so this mapper doesn't need to run again to get the audience into the introspection response. Implementing the interface would only add a failure mode: a strict-mode reject inside `setClaim` firing during introspection surfaces as an unhandled HTTP 500 (the interface has no declared exception / clean-error path the way the token endpoint does), not the `invalid_target` error a client would see at `/token`. The mapper implements `OIDCAccessTokenMapper` only.

**Resolved, not open:** `strict` defaults to `true` everywhere (code default and realm config) — see §4. **Resolved, 2026-08-26 (Anatoly):** mcpwarp runs its own Keycloak instance, separate from ankimcp — this is the deployment topology this design assumes throughout (§1, §7). If that ever changes, the only requirement carried forward is a dedicated `mcpwarp` realm on the shared instance (§7); the mapper and policy work identically either way since both are per-realm config, not per-image behavior.
