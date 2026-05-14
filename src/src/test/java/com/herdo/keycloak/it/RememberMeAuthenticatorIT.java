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
 * Two assertions:
 *   1. {@link #keycloakBasicFunctionalityIntact()} — the augmented image still
 *      exposes Keycloak's standard OIDC surface (proves we have not broken the
 *      vanilla server while vendoring the SPI).
 *   2. {@link #pluginSetsMaxAgeOnIdentityCookieAfterLogin()} — the literal bug
 *      this whole repo fixes: after a browser-flow login in a realm with
 *      {@code rememberMe: true} AND the remember-me-authenticator wired into
 *      the browser flow, the {@code KEYCLOAK_IDENTITY} cookie returned to the
 *      browser is a persistent cookie (has a {@code Max-Age} attribute set to
 *      {@code ssoSessionMaxLifespanRememberMe}) rather than a session-only
 *      cookie.
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
     * Captures the first ~400 chars of an HTML response body for inclusion
     * in assertion failure messages. The full body is overwhelmingly large
     * (Keycloak login page is ~10 KB) and unhelpful in CI logs.
     */
    private static final int BODY_EXCERPT_LENGTH = 400;

    @Container
    @SuppressWarnings("resource")
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(IMAGE_REF)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
            // KC_HEALTH_ENABLED is required for Keycloak 25+ to expose /health/ready
            // on the management port (9000). Without it the wait strategy below
            // hits a closed port and times out. The CI smoke job sets the same.
            .withEnv("KC_HEALTH_ENABLED", "true")
            .withEnv("KEYCLOAK_FRONTEND_URL", "http://localhost:8080")
            // start-dev avoids the full DB requirement; sufficient for behavioural tests.
            .withCommand("start-dev")
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
                .body(Map.of(
                        "username", TEST_USER,
                        "enabled", true,
                        "emailVerified", true,
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
     * Sequence:
     *   1. POST .../flows/browser/copy → create {@code rmtest-browser}
     *   2. POST .../flows/{rmtest-browser}/executions/execution with body
     *      {@code {"provider":"remember-me-authenticator"}}. Confirmed against
     *      Keycloak source (AuthenticationManagementResource#addExecutionToFlow):
     *      the body key is {@code provider}, NOT {@code authenticator} or
     *      {@code providerId}. Keycloak initialises the requirement to
     *      {@code DISABLED} when the factory exposes >1 choice (ours exposes
     *      three), so we have to flip it ourselves in step 3.
     *   3. GET .../flows/{rmtest-browser}/executions → locate the new
     *      execution by {@code providerId} (this GET returns
     *      {@code AuthenticationExecutionInfoRepresentation} which uses
     *      {@code providerId}; the POST above used {@code provider} — same
     *      value, different field names on each direction).
     *   4. PUT .../flows/{rmtest-browser}/executions with the execution
     *      representation and {@code requirement: "REQUIRED"}.
     *   5. PUT .../realms/{rmtest} setting {@code browserFlow} to the new
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

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of("provider", PROVIDER_ID))
                .when()
                .post("/admin/realms/" + TEST_REALM
                        + "/authentication/flows/" + TEST_BROWSER_FLOW
                        + "/executions/execution")
                .then()
                .statusCode(201);

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
                        "remember-me-authenticator execution not found after adding it to flow "
                                + TEST_BROWSER_FLOW + ". Executions returned: " + executions));

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
                        "OIDC /auth endpoint must return 200 with the login form HTML, "
                                + "got %d. Body excerpt: %s",
                        response.statusCode(), bodyExcerpt(response))
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
        return given()
                .redirects().follow(false)
                .cookies(sessionCookies)
                .contentType(ContentType.URLENC)
                .formParam("username", TEST_USER)
                .formParam("password", TEST_PASSWORD)
                .when()
                .post(formAction);
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
}
