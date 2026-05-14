package com.herdo.keycloak.it;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.http.Cookie;
import io.restassured.http.Cookies;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end integration tests for the bundled Keycloak image
 * ({@code ghcr.io/anatoly314/keycloak-bundled}).
 *
 * Three assertions:
 *   1. {@link #keycloakBasicFunctionalityIntact()} — the augmented image still
 *      exposes Keycloak's standard OIDC surface (proves we have not broken the
 *      vanilla server while vendoring the SPI).
 *   2. {@link #pluginSetsMaxAgeOnIdentityCookieAfterLogin()} — the literal bug
 *      this whole repo fixes on the direct-login path: after a browser-flow
 *      login in a realm with {@code rememberMe: true} AND the
 *      remember-me-authenticator wired into the browser flow, the
 *      {@code KEYCLOAK_IDENTITY} cookie returned to the browser is a
 *      persistent cookie (has a {@code Max-Age} attribute set to
 *      {@code ssoSessionMaxLifespanRememberMe}) rather than a session-only
 *      cookie.
 *   3. {@link #pluginSetsMaxAgeOnIdentityCookieAfterIdpLogin()} — same bug,
 *      same assertion, but on the external-IdP / social-login path (the
 *      reason this plugin exists in the first place). Uses a second realm in
 *      the SAME container as a stand-in IdP; the remember-me-authenticator is
 *      wired into a post-broker-login flow per the pattern endorsed by
 *      Keycloak's lead maintainer in keycloak#37372.
 *
 * The image under test is supplied via the Maven system property
 * {@code image.ref}, whose value is a complete image reference
 * (registry/name:tag), e.g. {@code ghcr.io/anatoly314/keycloak-bundled:1.0.0}.
 * CI passes the immutable SHA-tagged ref produced by the {@code build-and-push}
 * job's output. Falls back to {@code ghcr.io/anatoly314/keycloak-bundled:latest}
 * for local developer runs.
 *
 * Keycloak {@code start-dev} bootstrap typically takes 30–60 s on a warm host;
 * the wait strategy allows up to 3 min to absorb a cold pull and JIT warm-up.
 */
@Testcontainers
class RememberMeAuthenticatorIT {

    // ---- container / image ------------------------------------------------

    private static final String PROVIDER_ID = "remember-me-authenticator";
    private static final String IMAGE_REF = System.getProperty("image.ref", "ghcr.io/anatoly314/keycloak-bundled:latest");

    // ---- master-realm admin -----------------------------------------------

    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";

    // ---- test realm -------------------------------------------------------

    private static final String TEST_REALM = "rmtest";
    private static final String TEST_CLIENT = "rmtest-client";
    private static final String TEST_USER = "rmtest-user";
    private static final String TEST_PASSWORD = "test-password";
    private static final String TEST_REDIRECT_URI = "http://localhost/callback";
    private static final String TEST_BROWSER_FLOW = "rmtest-browser";

    // ---- IdP-brokering test fixtures (Test 3) -----------------------------
    //
    // Two realms playing different roles in the same Keycloak container:
    //   * IDP_REALM     — acts as the upstream OIDC IdP (Google/GitHub stand-in).
    //                     Hosts the human user and a confidential client that
    //                     the SP-side IdP config authenticates as.
    //   * SP_REALM      — the consuming realm. Has an OIDC client (for the
    //                     test driver to log in via), an Identity Provider
    //                     pointing back at IDP_REALM, and the post-broker-login
    //                     flow that wires in the remember-me-authenticator.
    //
    // The IdP redirects between the two realms happen via the same Keycloak
    // base URL the test JVM uses, so the broker callback URL is reachable from
    // both browser (= test JVM) and Keycloak's own broker code (= localhost
    // inside the container). Keycloak's hostname-v2 dynamically resolves
    // scheme/host/port from the incoming request when KC_HOSTNAME is unset
    // (see GenericContainer setup above), so absolute URLs work in both
    // directions.

    private static final String IDP_REALM = "idp-realm";
    private static final String IDP_USER = "idp-test-user";
    private static final String IDP_USER_PASSWORD = "idp-test-password";
    /**
     * The confidential client inside {@link #IDP_REALM} that the SP-side IdP
     * configuration authenticates as. The client secret is set explicitly so
     * the SP-side {@code clientSecret} config field has a known value.
     */
    private static final String IDP_BROKER_CLIENT = "rmtest-broker-client";
    private static final String IDP_BROKER_CLIENT_SECRET = "idp-broker-secret";

    private static final String SP_REALM = "rmtest-idp";
    private static final String SP_CLIENT = "rmtest-idp-client";
    private static final String SP_REDIRECT_URI = "http://localhost/callback-idp";
    /**
     * Alias of the Identity Provider inside {@link #SP_REALM} that points at
     * {@link #IDP_REALM}. This alias becomes part of the broker callback URL
     * ({@code /realms/{SP_REALM}/broker/{IDP_ALIAS}/endpoint}, per
     * {@code IdentityBrokerService} {@code @Path("{provider_alias}/endpoint")}
     * in Keycloak 26.5.7), which is also the {@code redirectUris} entry on
     * the IdP-realm-side broker client.
     */
    private static final String IDP_ALIAS = "idp-via-keycloak";
    private static final String POST_BROKER_FLOW = "post-idp-login-remember-me";

    /**
     * 30 days in seconds. Chosen as a distinct, recognisable value to assert
     * against — it would be unlikely to collide with any default cookie age
     * Keycloak might emit if the plugin silently no-op'd.
     */
    private static final long REMEMBER_ME_MAX_AGE_SECONDS = 2_592_000L;

    /**
     * Tolerance window for the {@code Max-Age} assertion. Keycloak computes
     * the cookie's Max-Age from the issuance instant; in practice the value
     * we see on the wire is at most a couple of seconds below the configured
     * lifespan, and never above it. ±60 s gives headroom for slow CI hosts
     * without weakening the assertion meaningfully (a session cookie would
     * have {@code Max-Age == -1} and a vanilla SSO cookie would be orders of
     * magnitude off).
     */
    private static final long MAX_AGE_TOLERANCE_SECONDS = 60L;

    /**
     * Captures the first ~4000 chars of an HTML response body for inclusion
     * in assertion failure messages. Keycloak's login-pf error template is
     * ~2–3 KB; 4 KB is enough to include the actual error message block
     * (typically near the top of {@code <body>} in a
     * {@code <span id="kc-page-title">} or {@code class="kc-feedback-text"}
     * element) while still keeping CI log noise bounded.
     */
    private static final int BODY_EXCERPT_LENGTH = 4_000;

    /**
     * Number of trailing characters of the Keycloak container's combined
     * stdout/stderr to dump into assertion failure messages. ~10 KB captures
     * the last few seconds of server activity (which is where the cause of
     * a 4xx from {@code /auth} will be logged) without flooding CI output.
     */
    private static final int CONTAINER_LOG_TAIL_CHARS = 10_000;

    @Container
    @SuppressWarnings("resource")
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(IMAGE_REF)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
            // KC_HEALTH_ENABLED is required for Keycloak 25+ to expose /health/ready
            // on the management port (9000). Without it the wait strategy below
            // hits a closed port and times out. The CI smoke job sets the same.
            .withEnv("KC_HEALTH_ENABLED", "true")
            // No KC_HOSTNAME / KEYCLOAK_FRONTEND_URL on purpose. Keycloak's
            // hostname-v2 (default in 25+) dynamically resolves scheme/host/port
            // from the incoming request when KC_HOSTNAME is unset, which is
            // exactly what Testcontainers needs: container 8080 is mapped to a
            // random host port, so any baked-in frontend URL would either be
            // ignored (legacy v1 option in 26) or cause issuer/redirect-URL
            // mismatches surfacing as 400 from /auth. Confirmed against
            // Keycloak 26.5 docs (guides/server/hostname.adoc, hostname-v2):
            // "If the port is not part of the URL, it is dynamically resolved
            // from the incoming request headers."
            // start-dev avoids the full DB requirement; sufficient for behavioural tests.
            .withCommand("start-dev")
            // Stream the container's stdout/stderr to the surefire/failsafe
            // console so Keycloak's own log lines (which include the reason
            // for any 4xx from /auth, e.g. "Invalid parameter: redirect_uri",
            // "Client not enabled", etc.) appear in CI output. We use a
            // plain System.out-based consumer rather than Slf4jLogConsumer
            // because slf4j-simple/log4j-slf4j may not be on the test
            // runtime classpath (testcontainers ships only the slf4j API).
            // Lambda receives OutputFrame; getUtf8String() already includes
            // the trailing newline emitted by Keycloak's logger.
            .withLogConsumer(frame -> System.out.print("[KC] " + frame.getUtf8String()))
            .withExposedPorts(8080, 9000)
            // /health/ready is served on the management port (9000) once Keycloak is fully up.
            .waitingFor(
                    Wait.forHttp("/health/ready")
                            .forPort(9000)
                            .withStartupTimeout(Duration.ofMinutes(3)));

    @BeforeAll
    static void configureRestAssured() {
        RestAssured.baseURI = "http://" + KEYCLOAK.getHost();
        RestAssured.port = KEYCLOAK.getMappedPort(8080);
    }

    // =======================================================================
    //  Test 1 — basic Keycloak OIDC surface intact
    // =======================================================================

    @Test
    void keycloakBasicFunctionalityIntact() {
        Map<String, Object> discovery = given()
                .accept(ContentType.JSON)
                .when()
                .get("/realms/master/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getMap("$");

        assertThat(discovery)
                .as("OIDC discovery document must expose the standard endpoint fields")
                .containsKeys("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri");

        Map<String, Object> jwks = given()
                .accept(ContentType.JSON)
                .when()
                .get("/realms/master/protocol/openid-connect/certs")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getMap("$");

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        assertThat(keys)
                .as("JWKS endpoint must return a non-empty 'keys' array with each key carrying a 'kty'")
                .isNotEmpty()
                .allMatch(k -> k.get("kty") != null);

        String accessToken = adminAccessToken();
        assertThat(accessToken)
                .as("Admin access token must look like a JWT (three base64url segments separated by '.')")
                .matches("^[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-]+$");
    }

    // =======================================================================
    //  Test 2 — plugin sets Max-Age on KEYCLOAK_IDENTITY after browser login
    // =======================================================================

    @Test
    void pluginSetsMaxAgeOnIdentityCookieAfterLogin() {
        String adminToken = adminAccessToken();

        // rememberMe: true is REQUIRED in Keycloak 26.4.1+ per keycloak#43328 —
        // without it the cookie stays session-scoped even with the plugin
        // active. The plugin sets the auth-session note; Keycloak's
        // AuthenticationManager then only respects it if the realm flag is on.
        createRealm(adminToken);
        createClient(adminToken);
        createUser(adminToken);
        wireRememberMeIntoBrowserFlow(adminToken);

        Response authPage = beginBrowserLogin();
        String formAction = extractLoginFormAction(authPage);

        Response loginResult = submitCredentials(formAction, authPage.getDetailedCookies());

        assertThat(loginResult.statusCode())
                .withFailMessage(
                        "Expected 302 redirect back to %s after credential POST, got %d. "
                                + "If 200 with HTML, the credentials likely did not authenticate "
                                + "(check realm/user/credential setup). Body excerpt: %s",
                        TEST_REDIRECT_URI, loginResult.statusCode(), bodyExcerpt(loginResult))
                .isEqualTo(302);
        assertThat(loginResult.getHeader("Location"))
                .withFailMessage(
                        "302 Location must redirect to %s with an OIDC code, was: %s",
                        TEST_REDIRECT_URI, loginResult.getHeader("Location"))
                .startsWith(TEST_REDIRECT_URI)
                .contains("code=")
                .contains("state=test-state");

        Cookie identity = loginResult.getDetailedCookies().get("KEYCLOAK_IDENTITY");
        assertThat(identity)
                .withFailMessage(
                        "Login response must Set-Cookie KEYCLOAK_IDENTITY (the SSO cookie). "
                                + "Cookies actually set: %s. This usually means the browser "
                                + "flow did not reach the post-authentication step that issues "
                                + "the identity cookie.",
                        loginResult.getDetailedCookies())
                .isNotNull();

        long maxAge = identity.getMaxAge();
        long lowerBound = REMEMBER_ME_MAX_AGE_SECONDS - MAX_AGE_TOLERANCE_SECONDS;
        long upperBound = REMEMBER_ME_MAX_AGE_SECONDS;
        assertThat(maxAge)
                .withFailMessage(
                        "KEYCLOAK_IDENTITY Max-Age must be ~%d s (ssoSessionMaxLifespanRememberMe). "
                                + "Got %d. Max-Age == -1 means the cookie is session-scoped, "
                                + "which is the literal bug this plugin fixes — either the "
                                + "remember-me execution is not wired into the browser flow, or "
                                + "the realm's rememberMe flag is not true (required from "
                                + "Keycloak 26.4.1+ per keycloak#43328).",
                        REMEMBER_ME_MAX_AGE_SECONDS, maxAge)
                .isBetween(lowerBound, upperBound);
    }

    // =======================================================================
    //  Test 3 — plugin sets Max-Age on KEYCLOAK_IDENTITY after IdP login
    // =======================================================================

    /**
     * Mirrors {@link #pluginSetsMaxAgeOnIdentityCookieAfterLogin()} but
     * exercises the social-login / external-IdP code path — the literal
     * reason this plugin exists. Per Keycloak 26.5.7 source review,
     * {@code IdentityProviderAuthenticator.redirect()} short-circuits the
     * Browser flow when an IdP is involved (the forms sub-flow never runs),
     * and {@code AuthenticationProcessor.resetFlow()} wipes auth notes for
     * first-time IdP users. The correct hook is therefore the Post-Broker-Login
     * flow, called out as the supported pattern by Keycloak's lead maintainer
     * in keycloak#37372 (closed wontfix, Nov 2025) and documented as
     * "Post Login Flow" in Keycloak's identity-broker configuration guide.
     *
     * <p>Setup: the same Keycloak container hosts two realms — {@code idp-realm}
     * stands in for an external IdP (Google/GitHub equivalent), and
     * {@code rmtest-idp} stands in for the consuming SP and configures
     * {@code idp-realm} as a generic OIDC Identity Provider, with the
     * remember-me-authenticator wired into a post-broker-login flow bound to
     * that IdP's {@code postBrokerLoginFlowAlias}.
     *
     * <p>Drive: 5 HTTP hops, each redirect chased manually to inspect
     * intermediate state. The {@code KEYCLOAK_IDENTITY} cookie under test is
     * set on the last hop (the broker callback's 302 back to the SP client's
     * {@code redirect_uri}), which is where the assertion lives.
     */
    @Test
    void pluginSetsMaxAgeOnIdentityCookieAfterIdpLogin() {
        String adminToken = adminAccessToken();

        // --- Upstream IdP (idp-realm) ----------------------------------
        createIdpRealm(adminToken);
        createIdpBrokerClient(adminToken);
        createIdpUser(adminToken);

        // --- Consuming SP (rmtest-idp) ---------------------------------
        createSpRealm(adminToken);
        createSpClient(adminToken);
        createIdentityProviderPointingAtIdpRealm(adminToken);
        createPostBrokerLoginFlowWithRememberMe(adminToken);
        bindPostBrokerFlowToIdp(adminToken);

        // --- Hop 1: SP /auth with kc_idp_hint -> 302 to IdP /auth ------
        Response spAuthRedirect = beginIdpBrokeredLogin();
        String idpAuthUrl = spAuthRedirect.getHeader("Location");
        assertThat(idpAuthUrl)
                .withFailMessage(
                        "Expected SP /auth (with kc_idp_hint=%s) to 302 the browser to the "
                                + "upstream IdP's /auth endpoint, got null Location. Status was %d. "
                                + "Body excerpt: %s",
                        IDP_ALIAS, spAuthRedirect.statusCode(), bodyExcerpt(spAuthRedirect))
                .contains("/realms/" + IDP_REALM + "/protocol/openid-connect/auth");

        // --- Hop 2: GET the IdP /auth -> 200 with login form -----------
        Response idpLoginPage = followToIdpLoginPage(idpAuthUrl);
        String idpFormAction = extractLoginFormAction(idpLoginPage);

        // --- Hop 3: POST credentials to IdP -> 302 to broker callback --
        Response idpCredsResult = submitCredentialsTo(
                idpFormAction, idpLoginPage.getDetailedCookies(), IDP_USER, IDP_USER_PASSWORD);
        String brokerCallbackUrl = idpCredsResult.getHeader("Location");
        assertThat(idpCredsResult.statusCode())
                .withFailMessage(
                        "Expected IdP credential POST to redirect (302/303) back to the SP broker callback "
                                + "/realms/%s/broker/%s/endpoint, got %d. Body excerpt: %s",
                        SP_REALM, IDP_ALIAS, idpCredsResult.statusCode(), bodyExcerpt(idpCredsResult))
                .isIn(302, 303);
        assertThat(brokerCallbackUrl)
                .withFailMessage(
                        "Broker callback Location must point at /realms/%s/broker/%s/endpoint, was: %s",
                        SP_REALM, IDP_ALIAS, brokerCallbackUrl)
                .contains("/realms/" + SP_REALM + "/broker/" + IDP_ALIAS + "/endpoint");

        // --- Hop 4: GET broker callback -> 302 to SP client redirect_uri.
        //
        // This is where Keycloak processes the IdP token, reconciles the user
        // into SP_REALM (first-broker-login), runs the post-broker-login flow
        // (where remember-me-authenticator fires and sets the auth-session
        // remember_me note), and finally attaches the SSO cookie before
        // emitting the 302. The KEYCLOAK_IDENTITY Set-Cookie therefore lives
        // on the 302 response from THIS hop.
        //
        // Cookie scoping note: the SP realm's AUTH_SESSION_ID was set on
        // Hop 1's 302 response (REST Assured preserves cookies across
        // .cookies(...) handoff). We pass it forward explicitly. The
        // IdP realm's AUTH_SESSION_ID is on a different cookie name? No —
        // both realms set a cookie called AUTH_SESSION_ID, but only the
        // SP-realm one applies to the SP-realm paths involved here. To
        // avoid cross-realm cookie collisions (both cookies have host
        // localhost, only realm path differs), pass JUST the cookies from
        // the SP-realm side: AUTH_SESSION_ID from Hop 1 plus whatever
        // KEYCLOAK_SESSION* etc were carried.
        Response brokerCallbackResult = followBrokerCallback(
                brokerCallbackUrl, spAuthRedirect.getDetailedCookies());

        assertThat(brokerCallbackResult.statusCode())
                .withFailMessage(
                        "Expected broker callback to redirect (302/303) the browser back to %s with an OIDC "
                                + "code, got %d. If 200 with HTML, the SP realm probably surfaced "
                                + "the first-broker-login review-profile page (which means the "
                                + "default first-broker-login flow stopped to prompt the user). "
                                + "Body excerpt: %s",
                        SP_REDIRECT_URI, brokerCallbackResult.statusCode(),
                        bodyExcerpt(brokerCallbackResult))
                .isIn(302, 303);
        assertThat(brokerCallbackResult.getHeader("Location"))
                .withFailMessage(
                        "Broker callback final 302 Location must redirect to %s with an OIDC code, was: %s",
                        SP_REDIRECT_URI, brokerCallbackResult.getHeader("Location"))
                .startsWith(SP_REDIRECT_URI)
                .contains("code=")
                .contains("state=idp-test-state");

        // --- Cookie assertion: SAME assertion as the direct-login test --
        Cookie identity = brokerCallbackResult.getDetailedCookies().get("KEYCLOAK_IDENTITY");
        assertThat(identity)
                .withFailMessage(
                        "Broker callback's final 302 must Set-Cookie KEYCLOAK_IDENTITY on the SP realm. "
                                + "Cookies actually set: %s. If absent, the post-broker-login flow "
                                + "may not have reached attachSession() — check the container logs "
                                + "for first-broker-login required-action prompts (review profile, "
                                + "verify email, etc.).",
                        brokerCallbackResult.getDetailedCookies())
                .isNotNull();

        long maxAge = identity.getMaxAge();
        long lowerBound = REMEMBER_ME_MAX_AGE_SECONDS - MAX_AGE_TOLERANCE_SECONDS;
        long upperBound = REMEMBER_ME_MAX_AGE_SECONDS;
        assertThat(maxAge)
                .withFailMessage(
                        "After IdP-brokered login, KEYCLOAK_IDENTITY Max-Age must be ~%d s "
                                + "(ssoSessionMaxLifespanRememberMe). Got %d. Max-Age == -1 means "
                                + "the cookie is session-scoped, which is the IdP-path manifestation "
                                + "of the bug this plugin fixes — either the post-broker-login flow "
                                + "is not bound to the IdP (postBrokerLoginFlowAlias), the "
                                + "remember-me-authenticator is not REQUIRED inside that flow, or "
                                + "the SP realm's rememberMe flag is not true (required from "
                                + "Keycloak 26.4.1+ per keycloak#43328).",
                        REMEMBER_ME_MAX_AGE_SECONDS, maxAge)
                .isBetween(lowerBound, upperBound);
    }

    // =======================================================================
    //  Helpers — realm/client/user/flow setup
    // =======================================================================

    /**
     * Resource Owner Password Credentials grant against the master realm's
     * built-in {@code admin-cli} public client. The {@code admin-cli} client
     * is bootstrapped by Keycloak with direct grants enabled, which is why
     * this works without any additional configuration.
     */
    private static String adminAccessToken() {
        String token = given()
                .contentType(ContentType.URLENC)
                .formParam("grant_type", "password")
                .formParam("client_id", "admin-cli")
                .formParam("username", ADMIN_USER)
                .formParam("password", ADMIN_PASSWORD)
                .when()
                .post("/realms/master/protocol/openid-connect/token")
                .then()
                .statusCode(200)
                .extract()
                .path("access_token");
        assertThat(token).as("admin access_token").isNotBlank();
        return token;
    }

    private static void createRealm(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "realm", TEST_REALM,
                        "enabled", true,
                        "rememberMe", true,
                        "ssoSessionMaxLifespanRememberMe", REMEMBER_ME_MAX_AGE_SECONDS,
                        "ssoSessionIdleTimeoutRememberMe", REMEMBER_ME_MAX_AGE_SECONDS))
                .when()
                .post("/admin/realms")
                .then()
                .statusCode(201);
    }

    private static void createClient(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "clientId", TEST_CLIENT,
                        "enabled", true,
                        "publicClient", true,
                        "standardFlowEnabled", true,
                        "redirectUris", List.of(TEST_REDIRECT_URI)))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/clients")
                .then()
                .statusCode(201);
    }

    private static void createUser(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                // Keycloak's default realm has VERIFY_PROFILE as a required
                // action; it intercepts the login flow with a profile-completion
                // page if email/firstName/lastName are missing. Supplying them
                // up-front lets the login proceed straight to the redirect.
                .body(Map.of(
                        "username", TEST_USER,
                        "enabled", true,
                        "emailVerified", true,
                        "email", TEST_USER + "@example.invalid",
                        "firstName", "Test",
                        "lastName", "User",
                        "credentials", List.of(Map.of(
                                "type", "password",
                                "value", TEST_PASSWORD,
                                "temporary", false))))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/users")
                .then()
                .statusCode(201);
    }

    /**
     * Wires the remember-me-authenticator into a copy of the built-in browser
     * flow and points the realm at that copy. We work on a copy because
     * built-in flows are immutable in Keycloak 26 (the admin UI surfaces this
     * as the "built-in" badge; the REST API rejects mutations with 400).
     *
     * <p><b>Placement matters.</b> The default browser flow's top level is:
     * <pre>
     *   auth-cookie                  (ALTERNATIVE)
     *   identity-provider-redirector (ALTERNATIVE)
     *   forms                        (ALTERNATIVE sub-flow)
     *     ├── username-password-form (REQUIRED)
     *     └── Browser - Conditional 2FA (CONDITIONAL sub-flow)
     * </pre>
     * Adding a REQUIRED execution at the TOP level breaks the flow: Keycloak's
     * DefaultAuthenticationFlow logs
     * "REQUIRED and ALTERNATIVE elements at same level! Those alternative
     * executions will be ignored" and the auth-cookie / IdP / forms branches
     * never run, so credentials can't be validated. The plugin must be added
     * <em>inside</em> the {@code forms} sub-flow (after the username/password
     * form), which is the "post-authentication" placement called out in
     * CLAUDE.md.
     *
     * <p><b>Sub-flow alias source-of-truth.</b> Per Keycloak 26.5 source
     * ({@code AuthenticationManagementResource#recurseExecutions}), the
     * {@code AuthenticationExecutionInfoRepresentation} returned by GET
     * /executions exposes a sub-flow's alias via the {@code displayName}
     * field (the rep has no {@code subFlowAlias} / {@code flowAlias} field —
     * its {@code alias} field is reserved for authenticator-config aliases
     * on configurable leaf executions). The {@code authenticationFlow: true}
     * marker disambiguates a sub-flow row from a leaf authenticator.
     *
     * <p><b>Copied sub-flow naming.</b> Per {@code AuthenticationManagementResource#copy},
     * when the built-in {@code browser} flow is copied to {@code rmtest-browser},
     * each nested sub-flow's alias is rewritten as
     * {@code <newName> + " " + <originalSubFlowAlias>}, so the {@code forms}
     * sub-flow becomes {@code "rmtest-browser forms"} (and
     * {@code "Browser - Conditional 2FA"} becomes
     * {@code "rmtest-browser Browser - Conditional 2FA"}). The forms sub-flow
     * is therefore identified here as the {@code authenticationFlow: true}
     * row whose {@code displayName} ends with " forms" (matching the built-in
     * {@code LOGIN_FORMS_FLOW = "forms"} constant in
     * {@code DefaultAuthenticationFlows}).
     *
     * Sequence:
     *   1. POST .../flows/browser/copy → create {@code rmtest-browser}
     *   2. GET .../flows/{rmtest-browser}/executions → locate the forms
     *      sub-flow's alias (via {@code displayName}). Fail loudly with the
     *      full executions JSON if it can't be found — better than silently
     *      falling back to the top-level flow, which is what produced the
     *      original "REQUIRED and ALTERNATIVE elements at same level" bug.
     *   3. POST .../flows/{formsSubFlowAlias}/executions/execution with body
     *      {@code {"provider":"remember-me-authenticator"}}. Confirmed against
     *      Keycloak source (AuthenticationManagementResource#addExecutionToFlow):
     *      the body key is {@code provider}, NOT {@code authenticator} or
     *      {@code providerId}. Keycloak initialises the requirement to
     *      {@code DISABLED} when the factory exposes >1 choice (ours exposes
     *      three), so we have to flip it ourselves in step 5.
     *   4. GET .../flows/{rmtest-browser}/executions → locate the new
     *      execution by {@code providerId}. (We GET on the TOP-LEVEL flow
     *      because the PUT update endpoint operates on the parent top-level
     *      flow and resolves executions by id, and the recursive listing on
     *      the top-level flow includes nested executions too.)
     *   5. PUT .../flows/{rmtest-browser}/executions with the execution
     *      representation and {@code requirement: "REQUIRED"}.
     *   6. PUT .../realms/{rmtest} setting {@code browserFlow} to the new
     *      alias so the OIDC /auth endpoint actually invokes our flow.
     */
    private static void wireRememberMeIntoBrowserFlow(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of("newName", TEST_BROWSER_FLOW))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/authentication/flows/browser/copy")
                .then()
                .statusCode(201);

        // Step 2 — locate the forms sub-flow alias inside the copied flow.
        List<Map<String, Object>> executionsBeforeAdd = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM
                        + "/authentication/flows/" + TEST_BROWSER_FLOW + "/executions")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        String formsSubFlowAlias = executionsBeforeAdd.stream()
                .filter(e -> Boolean.TRUE.equals(e.get("authenticationFlow")))
                .map(e -> (String) e.get("displayName"))
                .filter(name -> name != null && name.endsWith(" forms"))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "Could not locate the 'forms' sub-flow inside " + TEST_BROWSER_FLOW
                                + ". Expected exactly one execution with authenticationFlow=true "
                                + "and displayName ending in ' forms' (per Keycloak's copyFlow "
                                + "naming convention: '<newName> <originalSubFlowAlias>'). "
                                + "If this fails, Keycloak's flow representation or the default "
                                + "browser flow shape has changed and this test needs an update. "
                                + "Full executions response: " + executionsBeforeAdd));

        // Step 3 — add the plugin execution INSIDE the forms sub-flow, not at
        // the top level. Wrong placement (top level) makes Keycloak ignore the
        // ALTERNATIVE branches (auth-cookie, IdP redirector, forms) and the
        // user can never actually authenticate.
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of("provider", PROVIDER_ID))
                .when()
                .post("/admin/realms/" + TEST_REALM
                        + "/authentication/flows/" + formsSubFlowAlias
                        + "/executions/execution")
                .then()
                .statusCode(201);

        // Step 4 — locate the newly-added execution. The recursive listing on
        // the top-level flow includes nested executions, so we still GET on
        // TEST_BROWSER_FLOW. We filter by providerId AND a non-zero level to
        // be defensive (the new execution must be nested, not at top level).
        List<Map<String, Object>> executions = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM
                        + "/authentication/flows/" + TEST_BROWSER_FLOW + "/executions")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        Map<String, Object> rememberMeExecution = executions.stream()
                .filter(e -> PROVIDER_ID.equals(e.get("providerId")))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "remember-me-authenticator execution not found after adding it to "
                                + "sub-flow " + formsSubFlowAlias + ". Executions returned: "
                                + executions));

        // Safety check: the new execution must be NESTED (level >= 1). A
        // level of 0 means we accidentally put it at the top of the browser
        // flow, which is the exact misconfiguration we're guarding against.
        Object levelValue = rememberMeExecution.get("level");
        int level = levelValue instanceof Number ? ((Number) levelValue).intValue() : -1;
        if (level < 1) {
            throw new AssertionError(
                    "remember-me-authenticator execution was added at level " + level
                            + " (expected >= 1 i.e. nested inside the forms sub-flow). "
                            + "Top-level REQUIRED placement breaks Keycloak's "
                            + "DefaultAuthenticationFlow ('REQUIRED and ALTERNATIVE elements "
                            + "at same level'). Sub-flow alias resolved to '"
                            + formsSubFlowAlias + "'. Full executions: " + executions);
        }

        // Mutate to REQUIRED and PUT back. Keycloak's update endpoint reads
        // 'requirement' as a String and parses with Requirement.valueOf().
        rememberMeExecution.put("requirement", "REQUIRED");

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(rememberMeExecution)
                .when()
                .put("/admin/realms/" + TEST_REALM
                        + "/authentication/flows/" + TEST_BROWSER_FLOW + "/executions")
                .then()
                .statusCode(204);

        // Fetch the realm representation, flip browserFlow, PUT it back.
        // We can't send a partial body — Keycloak's RealmRepresentation
        // updater treats missing fields as "set to null/default" for some
        // fields (notably authentication flow bindings). Round-trip is safe.
        Map<String, Object> realmRep = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM)
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getMap("$");

        realmRep.put("browserFlow", TEST_BROWSER_FLOW);

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(realmRep)
                .when()
                .put("/admin/realms/" + TEST_REALM)
                .then()
                .statusCode(204);
    }

    // =======================================================================
    //  Helpers — browser-flow login simulation
    // =======================================================================

    private static Response beginBrowserLogin() {
        Response response = given()
                .redirects().follow(false)
                .queryParam("client_id", TEST_CLIENT)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", TEST_REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "test-state")
                .queryParam("nonce", "test-nonce")
                .when()
                .get("/realms/" + TEST_REALM + "/protocol/openid-connect/auth");

        assertThat(response.statusCode())
                .withFailMessage(
                        "OIDC /auth endpoint must return 200 with the login form HTML, got %d.%n"
                                + "=== Body (first %d chars) ===%n%s%n"
                                + "=== Keycloak container logs (last %d chars) ===%n%s%n",
                        response.statusCode(),
                        BODY_EXCERPT_LENGTH,
                        bodyExcerpt(response),
                        CONTAINER_LOG_TAIL_CHARS,
                        tailLogs(KEYCLOAK, CONTAINER_LOG_TAIL_CHARS))
                .isEqualTo(200);
        assertThat(response.getDetailedCookies().get("AUTH_SESSION_ID"))
                .withFailMessage(
                        "Expected AUTH_SESSION_ID cookie to be set on the login page. "
                                + "Cookies actually set: %s",
                        response.getDetailedCookies())
                .isNotNull();
        return response;
    }

    /**
     * Parses the login form's {@code action} attribute out of Keycloak's
     * freemarker-rendered login page. Keycloak's stock {@code login.ftl}
     * renders {@code <form id="kc-form-login" ... action="...">}; the regex
     * is anchored on that id to avoid matching any other form on the page
     * (e.g. social-login link buttons in some themes are wrapped in
     * {@code <form>} tags too).
     *
     * Regex was chosen over REST Assured's {@code htmlPath()} because the
     * stock Keycloak login page is HTML5 with unclosed {@code <link>} and
     * {@code <meta>} tags that {@code htmlPath()}'s underlying XML parser
     * occasionally chokes on; a single tightly-scoped regex is more robust
     * here.
     */
    private static final Pattern LOGIN_FORM_ACTION = Pattern.compile(
            "<form\\b[^>]*\\bid=\"kc-form-login\"[^>]*\\baction=\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);

    private static String extractLoginFormAction(Response authPage) {
        String body = authPage.getBody().asString();
        Matcher m = LOGIN_FORM_ACTION.matcher(body);
        assertThat(m.find())
                .withFailMessage(
                        "Could not locate <form id=\"kc-form-login\" ... action=\"...\"> in "
                                + "Keycloak login page. Body excerpt: %s",
                        body.substring(0, Math.min(body.length(), BODY_EXCERPT_LENGTH)))
                .isTrue();
        // Keycloak emits HTML-escaped ampersands in the action URL
        // (e.g. session_code=xxx&amp;execution=yyy). Decode so the POST
        // targets the correct query-string.
        String action = m.group(1).replace("&amp;", "&");
        // Keycloak emits an absolute URL whose host:port comes from either
        // KEYCLOAK_FRONTEND_URL or the request Host header. Testcontainers
        // maps :8080 inside the container to a random host port; we don't
        // want to hit the (unreachable) in-container port from the test
        // JVM. Strip to the path+query so REST Assured re-applies the
        // current baseURI (= the mapped port).
        int schemeEnd = action.indexOf("://");
        if (schemeEnd >= 0) {
            int pathStart = action.indexOf('/', schemeEnd + 3);
            return pathStart >= 0 ? action.substring(pathStart) : "/";
        }
        return action;
    }

    private static Response submitCredentials(String formAction, Cookies sessionCookies) {
        return submitCredentialsTo(formAction, sessionCookies, TEST_USER, TEST_PASSWORD);
    }

    /**
     * Parameterised credential POST. Used by both the direct-login test
     * (against {@link #TEST_USER}) and the IdP-brokered-login test (against
     * the {@link #IDP_USER} living in {@link #IDP_REALM}). Same wire shape;
     * REST Assured carries the form-page cookies forward.
     */
    private static Response submitCredentialsTo(
            String formAction, Cookies sessionCookies, String username, String password) {
        return given()
                .redirects().follow(false)
                .cookies(sessionCookies)
                .contentType(ContentType.URLENC)
                .formParam("username", username)
                .formParam("password", password)
                .when()
                .post(formAction);
    }

    // =======================================================================
    //  Helpers — IdP-brokering setup (Test 3)
    // =======================================================================

    /**
     * Base URL of the Keycloak container as seen from BOTH the test JVM and
     * the container itself (because of Docker on macOS the container's
     * outbound localhost loops back through the host network, so the same
     * host:mappedPort string works from both directions when Keycloak makes
     * its server-to-server broker token call). This URL is baked into the
     * IdP-realm broker client's {@code redirectUris} and into the SP-realm
     * IdP config's {@code authorizationUrl}/{@code tokenUrl}/etc — Keycloak
     * has to be able to dial the URL it generates for the SP redirect AND
     * the URLs in the IdP config; both pivot off this same string.
     */
    private static String keycloakBaseUrl() {
        return "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
    }

    private static void createIdpRealm(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of("realm", IDP_REALM, "enabled", true))
                .when()
                .post("/admin/realms")
                .then()
                .statusCode(201);
    }

    /**
     * Creates the confidential client inside {@link #IDP_REALM} that the
     * SP-realm IdP configuration will authenticate as during the Authorization
     * Code Flow (Hop 3 -> Hop 4 in the test). The {@code redirectUris} entry
     * is the broker callback URL on the SP side, per
     * {@code IdentityBrokerService#getEndpoint} ({@code @Path("{provider_alias}/endpoint")})
     * in Keycloak 26.5.7 — i.e. {@code /realms/{SP_REALM}/broker/{IDP_ALIAS}/endpoint}.
     */
    private static void createIdpBrokerClient(String adminToken) {
        String brokerCallback = keycloakBaseUrl()
                + "/realms/" + SP_REALM + "/broker/" + IDP_ALIAS + "/endpoint";
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "clientId", IDP_BROKER_CLIENT,
                        "enabled", true,
                        "publicClient", false,
                        "secret", IDP_BROKER_CLIENT_SECRET,
                        "standardFlowEnabled", true,
                        "redirectUris", List.of(brokerCallback)))
                .when()
                .post("/admin/realms/" + IDP_REALM + "/clients")
                .then()
                .statusCode(201);
    }

    private static void createIdpUser(String adminToken) {
        // Same VERIFY_PROFILE-avoidance shape as createUser() — populate
        // email/firstName/lastName so the IdP-side login form doesn't get
        // intercepted by the realm's default required action.
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "username", IDP_USER,
                        "enabled", true,
                        "emailVerified", true,
                        "email", IDP_USER + "@example.invalid",
                        "firstName", "Idp",
                        "lastName", "User",
                        "credentials", List.of(Map.of(
                                "type", "password",
                                "value", IDP_USER_PASSWORD,
                                "temporary", false))))
                .when()
                .post("/admin/realms/" + IDP_REALM + "/users")
                .then()
                .statusCode(201);
    }

    private static void createSpRealm(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                // Same rememberMe + lifespan flags as TEST_REALM — required
                // by keycloak#43328 to land Max-Age on the cookie even when
                // the plugin sets the auth-session note.
                .body(Map.of(
                        "realm", SP_REALM,
                        "enabled", true,
                        "rememberMe", true,
                        "ssoSessionMaxLifespanRememberMe", REMEMBER_ME_MAX_AGE_SECONDS,
                        "ssoSessionIdleTimeoutRememberMe", REMEMBER_ME_MAX_AGE_SECONDS))
                .when()
                .post("/admin/realms")
                .then()
                .statusCode(201);
    }

    private static void createSpClient(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "clientId", SP_CLIENT,
                        "enabled", true,
                        "publicClient", true,
                        "standardFlowEnabled", true,
                        "redirectUris", List.of(SP_REDIRECT_URI)))
                .when()
                .post("/admin/realms/" + SP_REALM + "/clients")
                .then()
                .statusCode(201);
    }

    /**
     * Creates an OIDC-providerId Identity Provider in {@link #SP_REALM} that
     * brokers to {@link #IDP_REALM}. The config keys below are the exact
     * camelCase strings consumed by {@code OAuth2IdentityProviderConfig}
     * ({@code authorizationUrl}, {@code tokenUrl}, {@code userInfoUrl},
     * {@code clientId}, {@code clientSecret}, {@code defaultScope}) and
     * {@code OIDCIdentityProviderConfig} ({@code jwksUrl}, {@code useJwksUrl},
     * {@code logoutUrl}) in Keycloak 26.5.7. {@code useJwksUrl=true} +
     * {@code jwksUrl} lets the SP fetch the IdP realm's signing keys at
     * runtime rather than requiring them inline.
     */
    private static void createIdentityProviderPointingAtIdpRealm(String adminToken) {
        String idpBase = keycloakBaseUrl() + "/realms/" + IDP_REALM + "/protocol/openid-connect";
        Map<String, String> config = new HashMap<>();
        config.put("clientId", IDP_BROKER_CLIENT);
        config.put("clientSecret", IDP_BROKER_CLIENT_SECRET);
        config.put("authorizationUrl", idpBase + "/auth");
        config.put("tokenUrl", idpBase + "/token");
        config.put("userInfoUrl", idpBase + "/userinfo");
        config.put("jwksUrl", idpBase + "/certs");
        config.put("logoutUrl", idpBase + "/logout");
        config.put("useJwksUrl", "true");
        config.put("validateSignature", "true");
        config.put("defaultScope", "openid");
        // Trust email from the upstream IdP so first-broker-login doesn't
        // halt on a "verify email" required action. Without this, Keycloak's
        // built-in first-broker-login flow inserts a verification step and
        // the test's broker-callback hop returns 200 (HTML) instead of 302.
        config.put("trustEmail", "true");

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "alias", IDP_ALIAS,
                        "providerId", "oidc",
                        "enabled", true,
                        "trustEmail", true,
                        "config", config))
                .when()
                .post("/admin/realms/" + SP_REALM + "/identity-provider/instances")
                .then()
                .statusCode(201);
    }

    /**
     * Creates the dedicated post-broker-login flow in {@link #SP_REALM} and
     * wires the remember-me-authenticator into it as a single REQUIRED
     * execution. Same shape as
     * {@link #wireRememberMeIntoBrowserFlow(String)}'s execution-add step,
     * but we don't need the sub-flow gymnastics here — a brand-new top-level
     * flow has no built-in branches to collide with, so REQUIRED at the top
     * level is fine.
     *
     * <p>Keycloak's flow-create API expects {@code providerId: "basic-flow"}
     * for a regular (non-client-auth) authentication flow; confirmed against
     * {@code AuthenticationManagementResource#createFlow} in 26.5.7. The
     * follow-up execution-add uses the same {@code {"provider": "..."}}
     * body shape as the browser-flow case, and the requirement defaults to
     * {@code DISABLED} (the factory exposes >1 requirement choice), so we
     * flip it to REQUIRED via the same PUT round-trip pattern.
     */
    private static void createPostBrokerLoginFlowWithRememberMe(String adminToken) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "alias", POST_BROKER_FLOW,
                        "providerId", "basic-flow",
                        "topLevel", true,
                        "builtIn", false))
                .when()
                .post("/admin/realms/" + SP_REALM + "/authentication/flows")
                .then()
                .statusCode(201);

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of("provider", PROVIDER_ID))
                .when()
                .post("/admin/realms/" + SP_REALM
                        + "/authentication/flows/" + POST_BROKER_FLOW + "/executions/execution")
                .then()
                .statusCode(201);

        List<Map<String, Object>> executions = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + SP_REALM
                        + "/authentication/flows/" + POST_BROKER_FLOW + "/executions")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        Map<String, Object> rememberMeExecution = executions.stream()
                .filter(e -> PROVIDER_ID.equals(e.get("providerId")))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "remember-me-authenticator execution not found in " + POST_BROKER_FLOW
                                + " after adding it. Executions returned: " + executions));

        rememberMeExecution.put("requirement", "REQUIRED");

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(rememberMeExecution)
                .when()
                .put("/admin/realms/" + SP_REALM
                        + "/authentication/flows/" + POST_BROKER_FLOW + "/executions")
                .then()
                .statusCode(204);
    }

    /**
     * Round-trips the IdP representation and sets {@code postBrokerLoginFlowAlias}
     * to the flow we just built. Partial PUT is unsafe here (same reason as
     * the realm-rep PUT in {@link #wireRememberMeIntoBrowserFlow(String)} —
     * fields missing from the body get nulled in the persisted rep), so we
     * GET, mutate, PUT.
     */
    private static void bindPostBrokerFlowToIdp(String adminToken) {
        Map<String, Object> idpRep = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + SP_REALM + "/identity-provider/instances/" + IDP_ALIAS)
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getMap("$");

        idpRep.put("postBrokerLoginFlowAlias", POST_BROKER_FLOW);

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(idpRep)
                .when()
                .put("/admin/realms/" + SP_REALM + "/identity-provider/instances/" + IDP_ALIAS)
                .then()
                .statusCode(204);
    }

    // =======================================================================
    //  Helpers — IdP-brokered browser-flow login simulation (Test 3)
    // =======================================================================

    /**
     * Hop 1 of the IdP-brokered login. GETs the SP realm's /auth endpoint
     * with {@code kc_idp_hint=IDP_ALIAS} so Keycloak's identity-provider
     * redirector triggers IMMEDIATELY without rendering the SP login form
     * (Keycloak 26.5 server-admin guide, "Client-suggested Identity Provider":
     * "OIDC applications can bypass the login page by hinting at the identity
     * provider via the {@code kc_idp_hint} query parameter on the
     * authorization endpoint"). Returns the raw 302 response — caller picks
     * the Location header and chases it.
     */
    private static Response beginIdpBrokeredLogin() {
        Response response = given()
                .redirects().follow(false)
                .queryParam("client_id", SP_CLIENT)
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", SP_REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "idp-test-state")
                .queryParam("nonce", "idp-test-nonce")
                .queryParam("kc_idp_hint", IDP_ALIAS)
                .when()
                .get("/realms/" + SP_REALM + "/protocol/openid-connect/auth");

        assertThat(response.statusCode())
                .withFailMessage(
                        "Expected SP /auth (with kc_idp_hint=%s) to redirect (302/303) to the IdP, got %d.%n"
                                + "=== Body (first %d chars) ===%n%s%n"
                                + "=== Keycloak container logs (last %d chars) ===%n%s%n",
                        IDP_ALIAS, response.statusCode(),
                        BODY_EXCERPT_LENGTH, bodyExcerpt(response),
                        CONTAINER_LOG_TAIL_CHARS, tailLogs(KEYCLOAK, CONTAINER_LOG_TAIL_CHARS))
                .isIn(302, 303);
        return response;
    }

    /**
     * Hop 2: follow the SP -> IdP 302 to the IdP realm's /auth endpoint and
     * collect the IdP-realm AUTH_SESSION_ID cookie that the IdP sets when
     * rendering its login page. The returned Response's
     * {@code detailedCookies()} are scoped to the IdP realm and become the
     * cookie bag for Hop 3's credential POST.
     */
    private static Response followToIdpLoginPage(String idpAuthUrl) {
        String relative = stripToPathAndQuery(idpAuthUrl);
        Response response = given()
                .redirects().follow(false)
                .when()
                .get(relative);

        assertThat(response.statusCode())
                .withFailMessage(
                        "Expected the IdP realm's /auth to render the login form (HTTP 200), got %d. "
                                + "URL hit: %s. Body excerpt: %s",
                        response.statusCode(), relative, bodyExcerpt(response))
                .isEqualTo(200);
        assertThat(response.getDetailedCookies().get("AUTH_SESSION_ID"))
                .withFailMessage(
                        "Expected AUTH_SESSION_ID cookie on the IdP login page (realm: %s). "
                                + "Cookies actually set: %s",
                        IDP_REALM, response.getDetailedCookies())
                .isNotNull();
        return response;
    }

    /**
     * Hop 4: follow the IdP -> SP broker-callback redirect. This hop is where
     * Keycloak (acting as SP) does the server-to-server token exchange with
     * the IdP, reconciles the user, runs the post-broker-login flow (which is
     * where the plugin fires), attaches the session, and emits the final 302
     * to the original client's redirect_uri. The KEYCLOAK_IDENTITY cookie
     * with the asserted Max-Age is set on this hop's response.
     *
     * <p>{@code spCookies} are the cookies from Hop 1's response (the SP
     * realm's AUTH_SESSION_ID etc.). The IdP-side AUTH_SESSION_ID is on a
     * different cookie path ({@code /realms/idp-realm/...}) and is irrelevant
     * to this hop — passing it would be harmless but we don't, for clarity.
     */
    private static Response followBrokerCallback(String brokerCallbackUrl, Cookies spCookies) {
        String relative = stripToPathAndQuery(brokerCallbackUrl);
        return given()
                .redirects().follow(false)
                .cookies(spCookies)
                .when()
                .get(relative);
    }

    /**
     * Shared with {@link #extractLoginFormAction(Response)}: Keycloak emits
     * absolute URLs (host:port from request Host header) that the test JVM
     * can't dial directly when those URLs reference the container's
     * in-container port. Strip to path+query so REST Assured re-applies the
     * mapped-port base URI.
     */
    private static String stripToPathAndQuery(String absoluteUrl) {
        int schemeEnd = absoluteUrl.indexOf("://");
        if (schemeEnd < 0) {
            return absoluteUrl;
        }
        int pathStart = absoluteUrl.indexOf('/', schemeEnd + 3);
        return pathStart >= 0 ? absoluteUrl.substring(pathStart) : "/";
    }

    // =======================================================================
    //  Helpers — diagnostics
    // =======================================================================

    private static String bodyExcerpt(Response response) {
        String body = response.getBody().asString();
        if (body == null) {
            return "<null>";
        }
        return body.length() <= BODY_EXCERPT_LENGTH
                ? body
                : body.substring(0, BODY_EXCERPT_LENGTH) + "...<truncated>";
    }

    /**
     * Returns the last {@code maxChars} characters of the container's
     * cumulative stdout+stderr. {@link GenericContainer#getLogs()} returns
     * everything emitted since startup, which after several minutes of
     * Keycloak bootstrap noise is far too much to surface in an assertion
     * failure message — the interesting bits (the actual error logged in
     * response to the failing request) are always at the tail. Safe to call
     * even if log retrieval throws; we never want a diagnostics helper to
     * mask the original assertion failure.
     */
    private static String tailLogs(GenericContainer<?> container, int maxChars) {
        try {
            String logs = container.getLogs();
            if (logs == null || logs.isEmpty()) {
                return "<no container logs available>";
            }
            return logs.length() <= maxChars
                    ? logs
                    : "...<truncated head>...\n" + logs.substring(logs.length() - maxChars);
        } catch (RuntimeException e) {
            return "<failed to retrieve container logs: " + e.getClass().getSimpleName()
                    + ": " + e.getMessage() + ">";
        }
    }
}
