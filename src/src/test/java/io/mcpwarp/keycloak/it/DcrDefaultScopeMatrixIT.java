package io.mcpwarp.keycloak.it;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Gating spike for the {@code resource-audience} protocol mapper design
 * (docs/design/2026-08-25-resource-audience-mapper.md, decision (b) / open
 * question 1): does Dynamic Client Registration keep a realm-DEFAULT client
 * scope attached to the client it creates, or does
 * {@code RepresentationToModel.updateClientScopes} strip it whenever the DCR
 * request body carries a {@code scope} field (research delta doc,
 * "DCR and realm DEFAULT client scopes")?
 *
 * No mapper code exists yet: {@code mcpwarp-resource} is created here as an
 * empty client scope (no protocol mappers) purely to observe DCR's scope
 * handling. This test answers the design doc's open question 1 empirically,
 * before a line of mapper code is written; it does not exercise token
 * issuance or {@code aud} — that is a follow-up IT once the mapper exists.
 *
 * Boots the real bundled image the same way
 * {@link com.herdo.keycloak.it.RememberMeAuthenticatorIT} does: the image
 * reference comes from the {@code image.ref} system property, defaulting to
 * {@code ghcr.io/anatoly-lab/keycloak-bundled:latest} for local runs. CI
 * passes the immutable SHA-tagged ref (see {@code .github/workflows/build.yml},
 * {@code integration-test} job).
 *
 * DCR policy setup mirrors the pattern documented for anonymous DCR in the
 * ankimcp deployment
 * (anki-mcp-saas/docs/mcp-auth-unification/keycloak-realm-setup.md, "Browser
 * DCR — CORS + anonymous policies"): a permissive Trusted Hosts policy
 * ({@code host-sending-registration-request-must-match} off, since the
 * registering "host" here is this test's HTTP client, not a predictable
 * browser IP) plus an Allowed Client Scopes policy that lists {@code openid}
 * EXPLICITLY. That doc's key finding — reproduced here because it is easy to
 * get wrong — is that {@code allow-default-scopes: true} covers realm
 * default/optional client scopes but never covers {@code openid} itself (it
 * isn't a real client scope), so a DCR request whose {@code scope} field
 * contains {@code openid} is silently policy-denied (with no CORS header,
 * masquerading as a browser CORS error) unless {@code openid} is listed
 * explicitly.
 */
@Testcontainers
class DcrDefaultScopeMatrixIT {

    private static final String IMAGE_REF =
            System.getProperty("image.ref", "ghcr.io/anatoly-lab/keycloak-bundled:latest");

    private static final String ADMIN_USER = "admin";
    private static final String ADMIN_PASSWORD = "admin";

    private static final String TEST_REALM = "dcrtest";
    private static final String SCOPE_NAME = "mcpwarp-resource";
    private static final String TEST_REDIRECT_URI = "http://localhost/callback";

    // Matrix outcome per case, in test-declaration order, so it survives as one
    // compact block instead of being lost in [KC] container log spam (@AfterAll
    // below prints it after all three @Tests have run, still before container
    // shutdown — JUnit runs @AfterAll while the @Container extension is still up).
    private static final Map<String, String> MATRIX_RESULTS = new LinkedHashMap<>();

    @Container
    @SuppressWarnings("resource")
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(IMAGE_REF)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", ADMIN_USER)
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD)
            .withEnv("KC_HEALTH_ENABLED", "true")
            // No KC_HOSTNAME — see RememberMeAuthenticatorIT for the rationale
            // (hostname-v2 resolves scheme/host/port from the incoming
            // request, which is what a randomly-mapped Testcontainers port
            // needs; this test never exercises a login flow, but the admin
            // REST API and the DCR endpoint are equally sensitive to it).
            .withCommand("start-dev")
            .withLogConsumer(frame -> System.out.print("[KC] " + frame.getUtf8String()))
            .withExposedPorts(8080, 9000)
            .waitingFor(
                    Wait.forHttp("/health/ready")
                            .forPort(9000)
                            .withStartupTimeout(Duration.ofMinutes(3)));

    @BeforeAll
    static void setUp() {
        // Static RestAssured.baseURI/port is process-global state, so this assumes
        // Surefire/Failsafe runs test classes sequentially, not in parallel — shared
        // with RememberMeAuthenticatorIT, which sets the same statics.
        RestAssured.baseURI = "http://" + KEYCLOAK.getHost();
        RestAssured.port = KEYCLOAK.getMappedPort(8080);

        String adminToken = adminAccessToken();
        createRealm(adminToken);
        String scopeId = createResourceScope(adminToken);
        markScopeAsRealmDefault(adminToken, scopeId);
        configureAnonymousDcrPolicies(adminToken);
    }

    @AfterAll
    static void printMatrix() {
        StringBuilder sb = new StringBuilder("\n===== DCR default-scope matrix (" + SCOPE_NAME + ") =====\n");
        MATRIX_RESULTS.forEach((caseLabel, outcome) -> sb.append(caseLabel).append(" -> ").append(outcome).append('\n'));
        sb.append("=========================================================");
        System.out.println(sb);
    }

    // =======================================================================
    //  Tests — one DCR shape per case, matrix result stays readable
    // =======================================================================

    @Test
    void dcrWithScopeOmittingMcpwarpResource() {
        assertScopeSurvivesDcr("scope=\"openid profile email\" (no mcpwarp-resource)",
                "openid profile email");
    }

    @Test
    void dcrWithNoScopeField() {
        assertScopeSurvivesDcr("no scope field in DCR body", null);
    }

    @Test
    void dcrWithScopeIncludingMcpwarpResource() {
        assertScopeSurvivesDcr("scope=\"openid profile email mcpwarp-resource\"",
                "openid profile email mcpwarp-resource");
    }

    // =======================================================================
    //  Helpers — DCR + admin-API assertion
    // =======================================================================

    /**
     * Registers an MCP-shaped public client via DCR (redirect_uris,
     * {@code token_endpoint_auth_method=none}, authorization_code +
     * refresh_token) with the given {@code scope} field, then asserts that
     * {@code mcpwarp-resource} survives onto the client — as a default scope
     * (the realm-default attachment decision (b) relies on) or, failing
     * that, as an optional scope. Only total absence fails the test; landing
     * in optional-not-default is reported so the matrix result stays
     * readable across the three cases.
     */
    private static void assertScopeSurvivesDcr(String caseLabel, String scopeParam) {
        Response registration = registerDcrClient(scopeParam);
        assertThat(registration.statusCode())
                .withFailMessage(
                        "[%s] DCR POST /clients-registrations/openid-connect must succeed (201). "
                                + "Got %d. Body: %s",
                        caseLabel, registration.statusCode(), registration.getBody().asString())
                .isEqualTo(201);

        String registeredClientId = registration.jsonPath().getString("client_id");
        assertThat(registeredClientId)
                .withFailMessage("[%s] DCR response must carry a client_id. Body: %s",
                        caseLabel, registration.getBody().asString())
                .isNotBlank();

        String adminToken = adminAccessToken();
        String internalId = lookUpInternalClientId(adminToken, registeredClientId);

        List<String> defaultScopes = clientScopeNames(adminToken, internalId, "default-client-scopes");
        List<String> optionalScopes = clientScopeNames(adminToken, internalId, "optional-client-scopes");

        boolean inDefault = defaultScopes.contains(SCOPE_NAME);
        boolean inOptional = optionalScopes.contains(SCOPE_NAME);

        String outcome = inDefault ? "DEFAULT" : inOptional ? "OPTIONAL" : "ABSENT";
        MATRIX_RESULTS.put(caseLabel, outcome);

        if (inDefault) {
            System.out.println("[" + caseLabel + "] " + SCOPE_NAME + " -> DEFAULT client scopes.");
        } else if (inOptional) {
            System.out.println("[" + caseLabel + "] " + SCOPE_NAME
                    + " -> OPTIONAL client scopes (DCR reclassified the realm-default scope, "
                    + "did not drop it). Reported, not failed.");
        }

        assertThat(inDefault || inOptional)
                .withFailMessage(
                        "[%s] DCR-created client lost '%s' entirely — present in neither default "
                                + "(%s) nor optional (%s) client scopes. This is the exact failure mode "
                                + "design decision (b) flags: RepresentationToModel.updateClientScopes "
                                + "strips realm-default scopes not present in the DCR request's 'scope' "
                                + "field. If this fails, the ClientRegistrationPolicy contingency in the "
                                + "design doc is now in scope.",
                        caseLabel, SCOPE_NAME, defaultScopes, optionalScopes)
                .isTrue();
    }

    private static Response registerDcrClient(String scopeParam) {
        Map<String, Object> body = new HashMap<>();
        body.put("client_name", "dcr-matrix-client-" + System.nanoTime());
        body.put("redirect_uris", List.of(TEST_REDIRECT_URI));
        body.put("token_endpoint_auth_method", "none");
        body.put("grant_types", List.of("authorization_code", "refresh_token"));
        body.put("response_types", List.of("code"));
        if (scopeParam != null) {
            body.put("scope", scopeParam);
        }

        return given()
                .contentType(ContentType.JSON)
                .body(body)
                .when()
                .post("/realms/" + TEST_REALM + "/clients-registrations/openid-connect");
    }

    private static String lookUpInternalClientId(String adminToken, String registeredClientId) {
        List<Map<String, Object>> matches = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .queryParam("clientId", registeredClientId)
                .when()
                .get("/admin/realms/" + TEST_REALM + "/clients")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        assertThat(matches)
                .withFailMessage("Admin API must find exactly one client with clientId=%s, found: %s",
                        registeredClientId, matches)
                .hasSize(1);
        return (String) matches.get(0).get("id");
    }

    private static List<String> clientScopeNames(String adminToken, String internalClientId, String scopeKind) {
        List<Map<String, Object>> scopes = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM + "/clients/" + internalClientId + "/" + scopeKind)
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        List<String> names = new ArrayList<>();
        for (Map<String, Object> scope : scopes) {
            names.add((String) scope.get("name"));
        }
        return names;
    }

    // =======================================================================
    //  Helpers — one-time realm/scope/policy setup
    // =======================================================================

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
                .body(Map.of("realm", TEST_REALM, "enabled", true))
                .when()
                .post("/admin/realms")
                .then()
                .statusCode(201);
    }

    /**
     * Creates {@code mcpwarp-resource} with NO protocol mappers — the
     * {@code resource-audience} mapper doesn't exist yet (this phase is
     * gating-test-only, per the design doc). Only the scope's DCR-survival
     * behaviour is under test here.
     */
    private static String createResourceScope(String adminToken) {
        Response created = given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "name", SCOPE_NAME,
                        // "protocol" is mandatory, not cosmetic: AbstractLoginProtocolFactory
                        // .addDefaultClientScopes filters realm defaults by protocol, so omitting
                        // it would make all three cases fail spuriously once marked realm-default.
                        "protocol", "openid-connect",
                        "attributes", Map.of(
                                "include.in.token.scope", "true",
                                "display.on.consent.screen", "false")))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/client-scopes")
                .then()
                .statusCode(201)
                .extract()
                .response();

        String location = created.getHeader("Location");
        assertThat(location)
                .withFailMessage("client-scope creation must return a Location header with the new scope's id")
                .isNotBlank();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private static void markScopeAsRealmDefault(String adminToken, String scopeId) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .when()
                .put("/admin/realms/" + TEST_REALM + "/default-default-client-scopes/" + scopeId)
                .then()
                .statusCode(204);

        // Positive control: confirm the realm actually carries the scope as a
        // default before any DCR happens, so a later ABSENT/OPTIONAL result in the
        // matrix can only be attributed to DCR's scope handling, not to setup.
        List<Map<String, Object>> realmDefaults = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + TEST_REALM + "/default-default-client-scopes")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        List<String> realmDefaultNames = new ArrayList<>();
        for (Map<String, Object> scope : realmDefaults) {
            realmDefaultNames.add((String) scope.get("name"));
        }
        assertThat(realmDefaultNames)
                .withFailMessage("Realm default-default-client-scopes must contain '%s' before DCR runs, got: %s",
                        SCOPE_NAME, realmDefaultNames)
                .contains(SCOPE_NAME);
    }

    /**
     * Configures the realm's anonymous Client Registration Policies the way
     * ankimcp's browser-DCR setup does (see class Javadoc for the source and
     * the "openid gotcha"):
     *
     * <ul>
     *   <li>Trusted Hosts — {@code host-sending-registration-request-must-match:
     *       false} (this test's HTTP client is not a predictable/trustable
     *       remote address, same rationale ankimcp documents for
     *       browser-originated DCR); {@code client-uris-must-match: true}
     *       kept on (the SSRF guard), with {@code localhost} trusted since
     *       every {@code redirect_uris} entry in this test uses it.</li>
     *   <li>Allowed Client Scopes — {@code allow-default-scopes: true}
     *       (covers {@code mcpwarp-resource} once it's a realm default
     *       scope) PLUS {@code openid}, {@code profile}, {@code email}
     *       listed EXPLICITLY, because {@code allow-default-scopes} never
     *       covers {@code openid} — it isn't a real client scope, so a DCR
     *       {@code scope} field containing it is policy-denied unless
     *       {@code openid} is named here.</li>
     * </ul>
     *
     * A fresh realm created via {@code POST /admin/realms} always carries a
     * seeded anonymous+authenticated policy pair per provider — verified for
     * 26.7.2 source: {@code RealmManager.setupClientRegistrations} calls
     * {@code DefaultClientRegistrationPolicies.addDefaultPolicies}, which
     * creates both {@code trusted-hosts} and {@code allowed-client-templates}
     * components (providerType {@code
     * org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy},
     * subType {@code anonymous}) unconditionally on realm creation. We
     * PUT-update the existing anonymous component.
     */
    private static void configureAnonymousDcrPolicies(String adminToken) {
        updateAnonymousPolicy(adminToken, "trusted-hosts", config -> {
            config.put("trusted-hosts", List.of("localhost"));
            // Must be off: the test JVM reaches the container via the Docker bridge
            // gateway, not loopback, so TrustedHostClientRegistrationPolicy.verifyHost
            // would 403 the DCR request otherwise.
            config.put("host-sending-registration-request-must-match", List.of("false"));
            config.put("client-uris-must-match", List.of("true"));
        });

        updateAnonymousPolicy(adminToken, "allowed-client-templates", config -> {
            config.put("allow-default-scopes", List.of("true"));
            config.put("allowed-client-scopes", List.of("openid", "profile", "email", SCOPE_NAME));
        });
    }

    @SuppressWarnings("unchecked")
    private static void updateAnonymousPolicy(
            String adminToken, String providerId, Consumer<Map<String, Object>> configMutator) {
        List<Map<String, Object>> components = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .queryParam("type", "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy")
                .when()
                .get("/admin/realms/" + TEST_REALM + "/components")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath()
                .getList("$");

        Map<String, Object> anonymousPolicy = components.stream()
                .filter(c -> providerId.equals(c.get("providerId")) && "anonymous".equals(c.get("subType")))
                .findFirst()
                .orElse(null);

        assertThat(anonymousPolicy)
                .withFailMessage("Realm must be seeded with an anonymous '%s' client registration policy "
                                + "(RealmManager.setupClientRegistrations); found none among: %s",
                        providerId, components)
                .isNotNull();

        Map<String, Object> config = (Map<String, Object>) anonymousPolicy.get("config");
        if (config == null) {
            config = new HashMap<>();
            anonymousPolicy.put("config", config);
        }
        configMutator.accept(config);

        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(anonymousPolicy)
                .when()
                .put("/admin/realms/" + TEST_REALM + "/components/" + anonymousPolicy.get("id"))
                .then()
                .statusCode(204);
    }
}
