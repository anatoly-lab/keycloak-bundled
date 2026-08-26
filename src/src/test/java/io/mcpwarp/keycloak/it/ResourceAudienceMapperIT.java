package io.mcpwarp.keycloak.it;

import io.mcpwarp.keycloak.mappers.ResourceAudienceMapper;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.path.json.JsonPath;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end coverage for the {@code resource-audience} {@link ResourceAudienceMapper}
 * (docs/design/2026-08-25-resource-audience-mapper.md §3, §6 test-plan items 3-8). This
 * is the class called out as "not yet written" in §8 of the design doc — the mapper is a
 * security control (it gates token issuance in strict mode) with, until this class, zero
 * end-to-end coverage; only unit tests exercise it in isolation.
 *
 * <p>Drives a real authorization-code + PKCE flow over HTTP against the published image
 * (same {@code image.ref} pattern as {@link com.herdo.keycloak.it.RememberMeAuthenticatorIT}
 * and {@link ResourceAudienceScopePolicyIT}), decodes the minted access token's JWT payload
 * without signature verification (we only need to read {@code aud}; verifying the signature
 * would require fetching and parsing JWKS for no additional assurance about mapper
 * behaviour), and asserts on {@code aud} plus the token endpoint's HTTP status/error body.
 *
 * <p><b>Scope wiring, by design.</b> One realm ({@code audtest}) carries two client scopes,
 * each with one {@code resource-audience} mapper instance:
 * <ul>
 *   <li>{@code mcpwarp-resource} — {@code strict=true} (the default), attached to a
 *       DCR-registered public client via the {@code resource-audience-scope}
 *       {@code ClientRegistrationPolicy} (mirrors {@link ResourceAudienceScopePolicyIT}'s
 *       registration pattern) so this class also exercises the two SPIs working together,
 *       the way a real MCP deployment wires them (design doc §1/§3a).</li>
 *   <li>{@code mcpwarp-resource-nonstrict} — {@code strict=false}, attached directly via the
 *       admin API to a client created via the admin API (NOT DCR). It is deliberately kept
 *       off the DCR path: the {@code resource-audience-scope} policy in this realm only
 *       targets {@code mcpwarp-resource}, so a DCR-registered client would always end up
 *       carrying the strict scope too, which would defeat the non-strict test case (5b) by
 *       having the strict mapper reject the same token the non-strict mapper would have
 *       issued.</li>
 * </ul>
 * A third, plain admin-API client carries neither scope — the regression guard (case 6)
 * protecting non-MCP clients (e.g. ankimcp, design doc §7).
 *
 * <p><b>Doubt flagged for the reader (not verified by running this suite — no local
 * Keycloak available):</b> the assertion that a strict-mode reject serializes as JSON
 * {@code {"error":"invalid_target", ...}} is based on {@code ErrorResponseException}'s
 * constructor parameter names ({@code error}, {@code errorDescription} — confirmed via
 * {@code javap} against the vendored {@code keycloak-services-26.7.2.jar}) and on Keycloak's
 * conventional OAuth error envelope; it was not confirmed against a live token-endpoint
 * response body.
 */
@Testcontainers
class ResourceAudienceMapperIT {

    private static final String IMAGE_REF =
            System.getProperty("image.ref", "ghcr.io/anatoly-lab/keycloak-bundled:latest");

    private static final String TEST_REALM = "audtest";
    private static final String TEST_USER = "audtest-user";
    private static final String TEST_PASSWORD = "audtest-password";

    private static final String STRICT_SCOPE_NAME = "mcpwarp-resource";
    private static final String NONSTRICT_SCOPE_NAME = "mcpwarp-resource-nonstrict";

    private static final String SCOPE_POLICY_PROVIDER_ID = "resource-audience-scope";

    /** Same shape as the design doc's example patterns (§4): anchored, one mcpwarp.io subdomain. */
    private static final String ALLOWED_PATTERN = "^https://[a-z0-9-]+\\.mcpwarp\\.io/mcp$";

    private static final String MATCHING_RESOURCE = "https://abc.mcpwarp.io/mcp";
    private static final String OTHER_MATCHING_RESOURCE = "https://xyz.mcpwarp.io/mcp";
    private static final String EVIL_RESOURCE = "https://evil.example/mcp";

    private static final int BODY_EXCERPT_LENGTH = 4_000;

    private static String strictDcrClientId;
    private static String nonStrictAdminClientId;
    private static String baselineAdminClientId;

    @Container
    @SuppressWarnings("resource")
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(IMAGE_REF)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", DcrTestSupport.ADMIN_USER)
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", DcrTestSupport.ADMIN_PASSWORD)
            .withEnv("KC_HEALTH_ENABLED", "true")
            .withCommand("start-dev")
            .withLogConsumer(frame -> System.out.print("[KC] " + frame.getUtf8String()))
            .withExposedPorts(8080, 9000)
            .waitingFor(
                    Wait.forHttp("/health/ready")
                            .forPort(9000)
                            .withStartupTimeout(Duration.ofMinutes(3)));

    // =======================================================================
    //  Realm / scope / policy / client bootstrap
    // =======================================================================

    @BeforeAll
    static void setUp() {
        RestAssured.baseURI = "http://" + KEYCLOAK.getHost();
        RestAssured.port = KEYCLOAK.getMappedPort(8080);

        String adminToken = DcrTestSupport.adminAccessToken();
        DcrTestSupport.createRealm(adminToken, TEST_REALM);

        String strictScopeId = DcrTestSupport.createResourceScope(adminToken, TEST_REALM, STRICT_SCOPE_NAME);
        addResourceAudienceMapper(adminToken, strictScopeId, true);

        String nonStrictScopeId = DcrTestSupport.createResourceScope(adminToken, TEST_REALM, NONSTRICT_SCOPE_NAME);
        addResourceAudienceMapper(adminToken, nonStrictScopeId, false);

        // Allowed Client Scopes DCR policy only ever needs to permit the scope a DCR body
        // could explicitly request; mcpwarp-resource-nonstrict never goes through DCR (see
        // class Javadoc), so only the strict scope needs listing here.
        DcrTestSupport.configureAnonymousDcrPolicies(adminToken, TEST_REALM, STRICT_SCOPE_NAME);
        addResourceAudienceScopePolicy(adminToken, "anonymous");
        addResourceAudienceScopePolicy(adminToken, "authenticated");

        createTestUser(adminToken);

        // --- Strict client: DCR-registered, gets mcpwarp-resource force-added as DEFAULT
        //     by the resource-audience-scope policy (design doc §3a), same mechanism
        //     ResourceAudienceScopePolicyIT verifies directly.
        Response dcrRegistration = DcrTestSupport.registerDcrClient(TEST_REALM, "openid profile email");
        assertThat(dcrRegistration.statusCode())
                .withFailMessage("DCR registration for the strict-scope client must succeed (201). Body: %s",
                        dcrRegistration.getBody().asString())
                .isEqualTo(201);
        strictDcrClientId = dcrRegistration.jsonPath().getString("client_id");
        String strictInternalId = DcrTestSupport.lookUpInternalClientId(adminToken, TEST_REALM, strictDcrClientId);

        // Anonymous DCR clients come out of registration with consentRequired=true (the
        // seeded Consent Required policy), which would otherwise land the browser flow below
        // on the consent screen instead of redirecting straight back with a code. Production
        // keeps that policy; this test only bypasses it via the admin API to avoid driving
        // the consent screen.
        disableConsentRequired(adminToken, strictInternalId);

        List<String> strictClientDefaultScopes = DcrTestSupport.clientScopeNames(
                adminToken, TEST_REALM, strictInternalId, "default-client-scopes");
        assertThat(strictClientDefaultScopes)
                .withFailMessage(
                        "Positive control: the resource-audience-scope policy must have force-added '%s' as a "
                                + "DEFAULT scope on the DCR-registered client before any test in this class runs "
                                + "(see ResourceAudienceScopePolicyIT for the mechanism under test in isolation). "
                                + "Got default scopes: %s",
                        STRICT_SCOPE_NAME, strictClientDefaultScopes)
                .contains(STRICT_SCOPE_NAME);

        // --- Non-strict client: admin-API created (bypasses DCR/the policy entirely), scope
        //     attached directly so it NEVER also carries the strict scope.
        nonStrictAdminClientId = "audtest-nonstrict-client";
        createAdminClient(adminToken, nonStrictAdminClientId);
        String nonStrictInternalId = DcrTestSupport.lookUpInternalClientId(adminToken, TEST_REALM, nonStrictAdminClientId);
        attachDefaultClientScope(adminToken, nonStrictInternalId, nonStrictScopeId);

        // --- Baseline client: admin-API created, no resource-audience scope at all — the
        //     regression guard for non-MCP clients (design doc §7).
        baselineAdminClientId = "audtest-baseline-client";
        createAdminClient(adminToken, baselineAdminClientId);
    }

    private static void addResourceAudienceMapper(String adminToken, String scopeId, boolean strict) {
        Map<String, Object> config = Map.of(
                "access.token.claim", "true",
                "id.token.claim", "false",
                "lightweight.claim", "true",
                ResourceAudienceMapper.CLAIM_NAME, ResourceAudienceMapper.DEFAULT_CLAIM_NAME,
                ResourceAudienceMapper.STRICT, String.valueOf(strict),
                ResourceAudienceMapper.ALLOWED_RESOURCE_PATTERNS, ALLOWED_PATTERN);

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "name", "mcpwarp-resource-audience",
                        "protocol", "openid-connect",
                        "protocolMapper", ResourceAudienceMapper.PROVIDER_ID,
                        "consentRequired", false,
                        "config", config))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/client-scopes/" + scopeId + "/protocol-mappers/models")
                .then()
                .statusCode(201);
    }

    /**
     * Registers the {@code resource-audience-scope} policy for {@code STRICT_SCOPE_NAME},
     * for both the {@code anonymous} and {@code authenticated} DCR subtypes — the same
     * both-subtypes pattern {@link ResourceAudienceScopePolicyIT} uses (design doc §3a: DCR
     * requests can be either, and Keycloak's own "Allowed Client Scopes" policy is seeded
     * the same way).
     */
    private static void addResourceAudienceScopePolicy(String adminToken, String subType) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "name", "Resource Audience Scope",
                        "providerId", SCOPE_POLICY_PROVIDER_ID,
                        "providerType", "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
                        "subType", subType,
                        "config", Map.of("clientScope", List.of(STRICT_SCOPE_NAME))))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/components")
                .then()
                .statusCode(201);
    }

    private static void createTestUser(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                // emailVerified/firstName/lastName up front avoids the VERIFY_PROFILE
                // required-action intercepting the login flow, same as RememberMeAuthenticatorIT.
                .body(Map.of(
                        "username", TEST_USER,
                        "enabled", true,
                        "emailVerified", true,
                        "email", TEST_USER + "@example.invalid",
                        "firstName", "Aud",
                        "lastName", "Test",
                        "credentials", List.of(Map.of(
                                "type", "password",
                                "value", TEST_PASSWORD,
                                "temporary", false))))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/users")
                .then()
                .statusCode(201);
    }

    private static void createAdminClient(String adminToken, String clientId) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "clientId", clientId,
                        "enabled", true,
                        "publicClient", true,
                        "standardFlowEnabled", true,
                        "redirectUris", List.of(DcrTestSupport.TEST_REDIRECT_URI)))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/clients")
                .then()
                .statusCode(201);
    }

    /**
     * GET-then-PUT the client representation with {@code consentRequired=false} — Keycloak's
     * client PUT endpoint replaces the full representation, so a partial body would clobber
     * everything else DCR set up.
     */
    @SuppressWarnings("unchecked")
    private static void disableConsentRequired(String adminToken, String internalClientId) {
        Map<String, Object> clientRep = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM + "/clients/" + internalClientId)
                .then()
                .statusCode(200)
                .extract()
                .as(Map.class);
        clientRep.put("consentRequired", false);

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(clientRep)
                .when()
                .put("/admin/realms/" + TEST_REALM + "/clients/" + internalClientId)
                .then()
                .statusCode(204);

        // Positive control: confirm the flip actually took before any login flow runs.
        boolean consentRequired = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM + "/clients/" + internalClientId)
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getBoolean("consentRequired");
        assertThat(consentRequired)
                .withFailMessage("consentRequired must be false after the PUT above")
                .isFalse();
    }

    private static void attachDefaultClientScope(String adminToken, String internalClientId, String scopeId) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .when()
                .put("/admin/realms/" + TEST_REALM + "/clients/" + internalClientId + "/default-client-scopes/" + scopeId)
                .then()
                .statusCode(204);
    }

    // =======================================================================
    //  Test cases
    // =======================================================================

    /** Case 1: aud == resource when the resource matches the allowlist pattern. */
    @Test
    void audMatchesResourceWhenPatternMatches() {
        AuthCodeResult authCode = loginViaBrowserFlow(strictDcrClientId, MATCHING_RESOURCE, "state-case1");
        Response tokenResponse = exchangeToken(strictDcrClientId, authCode, null);

        assertThat(tokenResponse.statusCode())
                .withFailMessage("Token exchange must succeed (200) for a resource matching the allowlist. Body: %s",
                        tokenResponse.getBody().asString())
                .isEqualTo(200);

        List<String> aud = audienceValues(decodeAccessTokenPayload(tokenResponse.jsonPath().getString("access_token")));
        assertThat(aud)
                .withFailMessage(
                        "aud must contain the resource '%s' requested at /authorize when it matches the mapper's "
                                + "allowlist pattern ('%s'). Got aud=%s",
                        MATCHING_RESOURCE, ALLOWED_PATTERN, aud)
                .contains(MATCHING_RESOURCE);
    }

    /** Case 2: refresh_token grant preserves aud (the note lives on the persisted client session). */
    @Test
    void refreshTokenGrantPreservesAud() {
        AuthCodeResult authCode = loginViaBrowserFlow(strictDcrClientId, MATCHING_RESOURCE, "state-case2");
        Response tokenResponse = exchangeToken(strictDcrClientId, authCode, null);
        assertThat(tokenResponse.statusCode())
                .withFailMessage("Initial token exchange must succeed (200). Body: %s", tokenResponse.getBody().asString())
                .isEqualTo(200);

        String refreshTokenValue = tokenResponse.jsonPath().getString("refresh_token");
        assertThat(refreshTokenValue).as("refresh_token").isNotBlank();

        Response refreshResponse = refreshToken(strictDcrClientId, refreshTokenValue);
        assertThat(refreshResponse.statusCode())
                .withFailMessage("Refresh-token grant must succeed (200). Body: %s", refreshResponse.getBody().asString())
                .isEqualTo(200);

        List<String> refreshedAud = audienceValues(
                decodeAccessTokenPayload(refreshResponse.jsonPath().getString("access_token")));
        assertThat(refreshedAud)
                .withFailMessage(
                        "Refreshed access token's aud must still contain '%s' — the resource-audience mapper reads "
                                + "the client-session note, which persists across a refresh (design doc §1). Got "
                                + "refreshed aud=%s",
                        MATCHING_RESOURCE, refreshedAud)
                .contains(MATCHING_RESOURCE);
    }

    /** Case 3: a /token resource param equal to the /authorize-time note still succeeds normally. */
    @Test
    void tokenResourceParamEqualToNoteStillSucceeds() {
        AuthCodeResult authCode = loginViaBrowserFlow(strictDcrClientId, MATCHING_RESOURCE, "state-case3");
        Response tokenResponse = exchangeToken(strictDcrClientId, authCode, MATCHING_RESOURCE);

        assertThat(tokenResponse.statusCode())
                .withFailMessage(
                        "/token resource param equal to the /authorize-time note ('%s') must succeed normally, "
                                + "not be treated as a mismatch. Body: %s",
                        MATCHING_RESOURCE, tokenResponse.getBody().asString())
                .isEqualTo(200);

        List<String> aud = audienceValues(decodeAccessTokenPayload(tokenResponse.jsonPath().getString("access_token")));
        assertThat(aud).contains(MATCHING_RESOURCE);
    }

    /** Case 4: a /token resource param DIFFERENT from the /authorize-time note, strict mapper -> 400 invalid_target. */
    @Test
    void tokenResourceParamMismatchStrictRejects() {
        AuthCodeResult authCode = loginViaBrowserFlow(strictDcrClientId, MATCHING_RESOURCE, "state-case4");
        Response tokenResponse = exchangeToken(strictDcrClientId, authCode, OTHER_MATCHING_RESOURCE);

        assertThat(tokenResponse.statusCode())
                .withFailMessage(
                        "/token resource ('%s') differing from the /authorize-time note ('%s') must be rejected "
                                + "(400 invalid_target) by a strict mapper (design doc §2 decision (a)). Body: %s",
                        OTHER_MATCHING_RESOURCE, MATCHING_RESOURCE, tokenResponse.getBody().asString())
                .isEqualTo(400);
        assertThat(tokenResponse.jsonPath().getString("error"))
                .withFailMessage("Expected error=invalid_target. Body: %s", tokenResponse.getBody().asString())
                .isEqualTo("invalid_target");
    }

    /** Case 5a: non-matching resource at /authorize time, strict mapper -> token endpoint call fails 400 invalid_target. */
    @Test
    void nonMatchingResourceAtAuthorizeStrictRejectsAtToken() {
        AuthCodeResult authCode = loginViaBrowserFlow(strictDcrClientId, EVIL_RESOURCE, "state-case5a");
        Response tokenResponse = exchangeToken(strictDcrClientId, authCode, null);

        assertThat(tokenResponse.statusCode())
                .withFailMessage(
                        "A resource ('%s') not matching the allowlist pattern ('%s') must be rejected "
                                + "(400 invalid_target) by a strict mapper. Body: %s",
                        EVIL_RESOURCE, ALLOWED_PATTERN, tokenResponse.getBody().asString())
                .isEqualTo(400);
        assertThat(tokenResponse.jsonPath().getString("error"))
                .withFailMessage("Expected error=invalid_target. Body: %s", tokenResponse.getBody().asString())
                .isEqualTo("invalid_target");
    }

    /** Case 5b: non-strict variant of the same non-matching-resource case -> token IS issued, evil aud absent. */
    @Test
    void nonMatchingResourceNonStrictIssuesTokenWithoutEvilAud() {
        AuthCodeResult authCode = loginViaBrowserFlow(nonStrictAdminClientId, EVIL_RESOURCE, "state-case5b");
        Response tokenResponse = exchangeToken(nonStrictAdminClientId, authCode, null);

        assertThat(tokenResponse.statusCode())
                .withFailMessage(
                        "A non-strict mapper must still issue a token (200) for a non-matching resource — the "
                                + "resource is simply not added to aud, per design doc §3 step 4. Body: %s",
                        tokenResponse.getBody().asString())
                .isEqualTo(200);

        List<String> aud = audienceValues(decodeAccessTokenPayload(tokenResponse.jsonPath().getString("access_token")));
        assertThat(aud)
                .withFailMessage(
                        "A non-strict mapper must NOT add a non-matching resource ('%s') to aud. Got aud=%s",
                        EVIL_RESOURCE, aud)
                .doesNotContain(EVIL_RESOURCE);
    }

    /**
     * Case 6 (regression guard): a client created via the admin API directly (never carries
     * the resource-audience scope, since that only ever gets attached via DCR + the policy,
     * or explicitly as done for the non-strict client above) sending a resource param ->
     * token issued normally, aud unaffected by the resource param one way or the other.
     */
    @Test
    void adminCreatedClientWithoutScopeUnaffectedByResourceParam() {
        AuthCodeResult withoutResource = loginViaBrowserFlow(baselineAdminClientId, null, "state-case6a");
        Response baselineTokenResponse = exchangeToken(baselineAdminClientId, withoutResource, null);
        assertThat(baselineTokenResponse.statusCode())
                .withFailMessage("Baseline login (no resource param) must succeed (200). Body: %s",
                        baselineTokenResponse.getBody().asString())
                .isEqualTo(200);
        List<String> baselineAud = audienceValues(
                decodeAccessTokenPayload(baselineTokenResponse.jsonPath().getString("access_token")));

        AuthCodeResult withResource = loginViaBrowserFlow(baselineAdminClientId, MATCHING_RESOURCE, "state-case6b");
        Response resourceTokenResponse = exchangeToken(baselineAdminClientId, withResource, null);
        assertThat(resourceTokenResponse.statusCode())
                .withFailMessage("Login with a resource param on a client without the mapper's scope must still "
                                + "succeed (200) — the mapper is never invoked for this client at all "
                                + "(mapper resolution is per-attached-scope, design doc §3). Body: %s",
                        resourceTokenResponse.getBody().asString())
                .isEqualTo(200);
        List<String> resourceAud = audienceValues(
                decodeAccessTokenPayload(resourceTokenResponse.jsonPath().getString("access_token")));

        assertThat(resourceAud)
                .withFailMessage(
                        "A client without the resource-audience-carrying scope attached must have an unaffected "
                                + "aud regardless of a resource param at /authorize — this is the regression guard "
                                + "protecting non-MCP clients (e.g. ankimcp) per design doc §7. Baseline aud (no "
                                + "resource param)=%s, aud with resource param=%s",
                        baselineAud, resourceAud)
                .isEqualTo(baselineAud);
    }

    /**
     * Case 7: a resource URI carrying a fragment is rejected at /authorize itself, before the
     * mapper is ever consulted — Keycloak's own {@code AuthorizationEndpointChecker} rejects
     * fragments in target URIs with {@code invalid_target} (RFC 8707 disallows fragments in
     * resource indicators). A 400 here commonly renders as an HTML error page rather than a
     * JSON body (unlike a /token 400), so only assert status when the body isn't JSON.
     */
    @Test
    void resourceWithFragmentAtAuthorizeIsRejected() {
        Response authPage = given()
                .redirects().follow(false)
                .queryParam("client_id", strictDcrClientId)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", DcrTestSupport.TEST_REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "state-case7")
                .queryParam("code_challenge", codeChallengeS256(randomCodeVerifier()))
                .queryParam("code_challenge_method", "S256")
                .queryParam("resource", MATCHING_RESOURCE + "#frag")
                .when()
                .get("/realms/" + TEST_REALM + "/protocol/openid-connect/auth");

        assertThat(authPage.statusCode())
                .withFailMessage(
                        "/authorize with a resource URI containing a fragment must be rejected (400) by "
                                + "Keycloak's own AuthorizationEndpointChecker, before the resource-audience mapper "
                                + "is ever consulted. Body excerpt: %s",
                        bodyExcerpt(authPage))
                .isEqualTo(400);

        if (authPage.contentType() != null && authPage.contentType().contains("json")) {
            assertThat(authPage.jsonPath().getString("error"))
                    .withFailMessage("Expected error=invalid_target. Body: %s", authPage.getBody().asString())
                    .isEqualTo("invalid_target");
        }
    }

    // =======================================================================
    //  Helpers — PKCE authorization-code flow
    // =======================================================================

    private record AuthCodeResult(String code, String codeVerifier) {
    }

    private static String randomCodeVerifier() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String codeChallengeS256(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 must be available on any JVM", e);
        }
    }

    /**
     * Drives /authorize (with PKCE) through the login form and back to the redirect_uri,
     * returning the authorization code and the PKCE verifier the caller needs to exchange it.
     * Does NOT follow the final redirect — only its {@code Location} header is read.
     */
    private static AuthCodeResult loginViaBrowserFlow(String clientId, String resourceAtAuthorize, String state) {
        String codeVerifier = randomCodeVerifier();
        String codeChallenge = codeChallengeS256(codeVerifier);

        var authorizeRequest = given()
                .redirects().follow(false)
                .queryParam("client_id", clientId)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", DcrTestSupport.TEST_REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", state)
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256");
        if (resourceAtAuthorize != null) {
            authorizeRequest = authorizeRequest.queryParam("resource", resourceAtAuthorize);
        }

        Response authPage = authorizeRequest
                .when()
                .get("/realms/" + TEST_REALM + "/protocol/openid-connect/auth");

        assertThat(authPage.statusCode())
                .withFailMessage(
                        "OIDC /authorize must return 200 with the login form HTML, got %d. Body excerpt: %s",
                        authPage.statusCode(), bodyExcerpt(authPage))
                .isEqualTo(200);

        String formAction = extractLoginFormAction(authPage);

        Response loginResult = given()
                .redirects().follow(false)
                .cookies(authPage.getDetailedCookies())
                .contentType(ContentType.URLENC)
                .formParam("username", TEST_USER)
                .formParam("password", TEST_PASSWORD)
                .when()
                .post(formAction);

        assertThat(loginResult.statusCode())
                .withFailMessage(
                        "Expected a 302 redirect back to %s after the credential POST, got %d. Body excerpt: %s",
                        DcrTestSupport.TEST_REDIRECT_URI, loginResult.statusCode(), bodyExcerpt(loginResult))
                .isEqualTo(302);

        String location = loginResult.getHeader("Location");
        assertThat(location)
                .withFailMessage("302 Location must redirect to %s with an OIDC code, was: %s",
                        DcrTestSupport.TEST_REDIRECT_URI, location)
                .isNotNull()
                .contains("code=");

        return new AuthCodeResult(extractCodeFromLocation(location), codeVerifier);
    }

    private static Response exchangeToken(String clientId, AuthCodeResult authCode, String resourceAtToken) {
        var tokenRequest = given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "authorization_code")
                .formParam("client_id", clientId)
                .formParam("code", authCode.code())
                .formParam("redirect_uri", DcrTestSupport.TEST_REDIRECT_URI)
                .formParam("code_verifier", authCode.codeVerifier());
        if (resourceAtToken != null) {
            tokenRequest = tokenRequest.formParam("resource", resourceAtToken);
        }
        return tokenRequest
                .when()
                .post("/realms/" + TEST_REALM + "/protocol/openid-connect/token");
    }

    private static Response refreshToken(String clientId, String refreshTokenValue) {
        return given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "refresh_token")
                .formParam("client_id", clientId)
                .formParam("refresh_token", refreshTokenValue)
                .when()
                .post("/realms/" + TEST_REALM + "/protocol/openid-connect/token");
    }

    /**
     * Parses the login form's {@code action} attribute out of Keycloak's freemarker-rendered
     * login page, tolerating either single- or double-quoted HTML attributes. Anchored on
     * {@code id="kc-form-login"} (or {@code id='kc-form-login'}) the same way
     * {@code RememberMeAuthenticatorIT} does, to avoid matching any other form on the page.
     */
    private static final Pattern LOGIN_FORM_ACTION = Pattern.compile(
            "<form\\b[^>]*\\bid=(?:\"kc-form-login\"|'kc-form-login')[^>]*\\baction=(?:\"([^\"]*)\"|'([^']*)')",
            Pattern.CASE_INSENSITIVE);

    private static String extractLoginFormAction(Response authPage) {
        String body = authPage.getBody().asString();
        Matcher matcher = LOGIN_FORM_ACTION.matcher(body);
        assertThat(matcher.find())
                .withFailMessage(
                        "Could not locate <form id=\"kc-form-login\" ... action=\"...\"> in the Keycloak login "
                                + "page. Body excerpt: %s",
                        body.substring(0, Math.min(body.length(), BODY_EXCERPT_LENGTH)))
                .isTrue();
        String rawAction = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
        // Keycloak HTML-escapes ampersands in the action URL (e.g. session_code=x&amp;execution=y).
        String action = rawAction.replace("&amp;", "&");
        // Strip scheme+host: the action is an absolute URL whose host:port may not be the one
        // REST Assured's baseURI currently points at (Testcontainers maps to a random port).
        int schemeEnd = action.indexOf("://");
        if (schemeEnd >= 0) {
            int pathStart = action.indexOf('/', schemeEnd + 3);
            return pathStart >= 0 ? action.substring(pathStart) : "/";
        }
        return action;
    }

    private static final Pattern CODE_PARAM = Pattern.compile("[?&]code=([^&]+)");

    private static String extractCodeFromLocation(String location) {
        Matcher matcher = CODE_PARAM.matcher(location);
        assertThat(matcher.find())
                .withFailMessage("Redirect Location must contain a 'code' query param. Location was: %s", location)
                .isTrue();
        return URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8);
    }

    /**
     * Base64url-decodes a JWT's payload segment (no signature verification — this test only
     * needs to read claims, and verifying the signature would additionally require fetching
     * and parsing the realm's JWKS for no extra assurance about mapper behaviour).
     */
    private static JsonPath decodeAccessTokenPayload(String jwt) {
        assertThat(jwt).as("access_token").isNotBlank();
        String[] parts = jwt.split("\\.");
        assertThat(parts.length)
                .withFailMessage("access_token must be a JWT with 3 dot-separated segments, got %d: %s",
                        parts.length, jwt)
                .isEqualTo(3);
        String base64Payload = parts[1];
        String padded = base64Payload + "=".repeat((4 - base64Payload.length() % 4) % 4);
        byte[] decoded = Base64.getUrlDecoder().decode(padded);
        return JsonPath.from(new String(decoded, StandardCharsets.UTF_8));
    }

    /**
     * Normalises the {@code aud} claim to a {@code List<String>} regardless of whether
     * Keycloak serialised it as a single JSON string (one audience) or a JSON array (more
     * than one) — {@code JsonWebToken}'s custom audience serializer does the former for a
     * single-entry array.
     */
    private static List<String> audienceValues(JsonPath payload) {
        Object raw = payload.get("aud");
        if (raw == null) {
            return List.of();
        }
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).collect(Collectors.toList());
        }
        return List.of(String.valueOf(raw));
    }

    private static String bodyExcerpt(Response response) {
        String body = response.getBody().asString();
        return body.substring(0, Math.min(body.length(), BODY_EXCERPT_LENGTH));
    }
}
