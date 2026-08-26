package io.mcpwarp.keycloak.it;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Characterization test for Keycloak 26.7.2's own Dynamic Client Registration
 * scope-survival behaviour — it documents a fact about Keycloak, not about
 * anything in this repo's code (no mapper/policy exists yet).
 *
 * <h2>Why this test exists</h2>
 *
 * The {@code resource-audience} protocol mapper design
 * (docs/design/2026-08-25-resource-audience-mapper.md) originally hoped to
 * attach its client scope via a plain realm-DEFAULT client scope, relying on
 * {@code AbstractLoginProtocolFactory}'s {@code ClientProtocolUpdatedEvent}
 * listener to attach realm defaults to every DCR-created client. This test
 * was written to check that hope empirically before writing a line of mapper
 * code, and it ran in CI against the real bundled image (PR #14). The result
 * falsified the hope: {@code RepresentationToModel.updateClientScopes}
 * (services/.../models/utils/RepresentationToModel.java:663-689) strips every
 * scope not in the DCR request's {@code scope} field whenever that field (or
 * {@code defaultClientScopes}/{@code optionalClientScopes}) is present at
 * all — which is every real MCP client, since DCR clients always send a
 * {@code scope} field. Realm-default attachment is therefore dead for real
 * MCP clients registering via DCR.
 *
 * <p>The design now uses a {@code ClientRegistrationPolicy} SPI provider
 * (provider id {@code resource-audience-scope}, see
 * {@link ResourceAudienceScopePolicyIT}) that force-adds the scope in {@code
 * afterRegister}/{@code afterUpdate} — i.e. after {@code updateClientScopes}
 * has already run and stripped it. This test's job going forward is to keep
 * documenting Keycloak's own scope-stripping behaviour as a guardrail: if a
 * future Keycloak upgrade changes what this test observes (e.g. case i
 * stopped stripping the scope, or the DCR wire format changed), that is a
 * signal that the {@code ClientRegistrationPolicy} might no longer be
 * necessary, or its {@code afterUpdate} handling needs re-checking — go
 * re-read the design doc's §3/§10 before touching the policy.
 *
 * <h2>The observed matrix (26.7.2, verified in CI on PR #14)</h2>
 *
 * <table>
 *   <caption>DCR body {@code scope} field vs. where {@code mcpwarp-resource} lands</caption>
 *   <tr><th>DCR request {@code scope}</th><th>Outcome</th></tr>
 *   <tr><td>{@code "openid profile email"} (omits the scope)</td><td>ABSENT — stripped entirely</td></tr>
 *   <tr><td>no {@code scope} field at all</td><td>DEFAULT — realm-default attachment survives</td></tr>
 *   <tr><td>{@code "openid profile email mcpwarp-resource"}</td><td>OPTIONAL — reclassified from default to optional</td></tr>
 * </table>
 *
 * No client scope registering with an explicit {@code scope} field ever ends
 * up with {@code mcpwarp-resource} as a DEFAULT scope from realm-default
 * attachment alone — case (ii) is the only survival case, and it requires the
 * DCR client to omit {@code scope} entirely, which no real OAuth/MCP client
 * does. Hence the policy.
 *
 * <p>Boots the real bundled image the same way
 * {@link com.herdo.keycloak.it.RememberMeAuthenticatorIT} does: the image
 * reference comes from the {@code image.ref} system property, defaulting to
 * {@code ghcr.io/anatoly-lab/keycloak-bundled:latest} for local runs. CI
 * passes the immutable SHA-tagged ref (see {@code .github/workflows/build.yml},
 * {@code integration-test} job).
 *
 * <p>DCR policy setup mirrors the pattern documented for anonymous DCR in the
 * ankimcp deployment (anki-mcp-saas/docs/mcp-auth-unification/keycloak-realm-setup.md,
 * "Browser DCR — CORS + anonymous policies"). See {@link DcrTestSupport} for
 * the shared plumbing, also used by {@link ResourceAudienceScopePolicyIT}.
 */
@Testcontainers
class DcrScopeStrippingCharacterizationIT {

    private static final String IMAGE_REF =
            System.getProperty("image.ref", "ghcr.io/anatoly-lab/keycloak-bundled:latest");

    private static final String TEST_REALM = "dcrtest";
    private static final String SCOPE_NAME = "mcpwarp-resource";

    private enum Outcome { DEFAULT, OPTIONAL, ABSENT }

    // Matrix outcome per case, in test-declaration order, so it survives as one
    // compact block instead of being lost in [KC] container log spam (@AfterAll
    // below prints it after all three @Tests have run, still before container
    // shutdown — JUnit runs @AfterAll while the @Container extension is still up).
    private static final Map<String, Outcome> MATRIX_RESULTS = new LinkedHashMap<>();

    @Container
    @SuppressWarnings("resource")
    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>(IMAGE_REF)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", DcrTestSupport.ADMIN_USER)
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", DcrTestSupport.ADMIN_PASSWORD)
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

        String adminToken = DcrTestSupport.adminAccessToken();
        DcrTestSupport.createRealm(adminToken, TEST_REALM);
        String scopeId = DcrTestSupport.createResourceScope(adminToken, TEST_REALM, SCOPE_NAME);
        DcrTestSupport.markScopeAsRealmDefault(adminToken, TEST_REALM, scopeId, SCOPE_NAME);
        DcrTestSupport.configureAnonymousDcrPolicies(adminToken, TEST_REALM, SCOPE_NAME);
    }

    @AfterAll
    static void printMatrix() {
        StringBuilder sb = new StringBuilder("\n===== DCR default-scope matrix (" + SCOPE_NAME + ") =====\n");
        MATRIX_RESULTS.forEach((caseLabel, outcome) -> sb.append(caseLabel).append(" -> ").append(outcome).append('\n'));
        sb.append("=========================================================");
        System.out.println(sb);
    }

    // =======================================================================
    //  Tests — one DCR shape per case, asserting the EXACT observed outcome.
    //  A failure here means Keycloak's DCR scope handling changed — go
    //  re-read the class Javadoc and docs/design/2026-08-25-resource-audience-
    //  mapper.md §10 before touching the ClientRegistrationPolicy.
    // =======================================================================

    @Test
    void scopeOmittingMcpwarpResourceIsStrippedEntirely() {
        assertOutcome("scope=\"openid profile email\" (no mcpwarp-resource)",
                "openid profile email", Outcome.ABSENT);
    }

    @Test
    void noScopeFieldLeavesRealmDefaultAttached() {
        assertOutcome("no scope field in DCR body", null, Outcome.DEFAULT);
    }

    @Test
    void scopeIncludingMcpwarpResourceIsReclassifiedAsOptional() {
        assertOutcome("scope=\"openid profile email mcpwarp-resource\"",
                "openid profile email mcpwarp-resource", Outcome.OPTIONAL);
    }

    // =======================================================================
    //  Helper — DCR + admin-API assertion
    // =======================================================================

    private static void assertOutcome(String caseLabel, String scopeParam, Outcome expected) {
        Response registration = DcrTestSupport.registerDcrClient(TEST_REALM, scopeParam);
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

        String adminToken = DcrTestSupport.adminAccessToken();
        String internalId = DcrTestSupport.lookUpInternalClientId(adminToken, TEST_REALM, registeredClientId);

        List<String> defaultScopes = DcrTestSupport.clientScopeNames(adminToken, TEST_REALM, internalId, "default-client-scopes");
        List<String> optionalScopes = DcrTestSupport.clientScopeNames(adminToken, TEST_REALM, internalId, "optional-client-scopes");

        boolean inDefault = defaultScopes.contains(SCOPE_NAME);
        boolean inOptional = optionalScopes.contains(SCOPE_NAME);
        Outcome actual = inDefault ? Outcome.DEFAULT : inOptional ? Outcome.OPTIONAL : Outcome.ABSENT;
        MATRIX_RESULTS.put(caseLabel, actual);

        assertThat(actual)
                .withFailMessage(
                        "[%s] Expected %s but observed %s (default scopes: %s, optional scopes: %s). "
                                + "This test documents Keycloak's own DCR scope-stripping behaviour "
                                + "(RepresentationToModel.updateClientScopes) — if this genuinely changed, "
                                + "Keycloak's behaviour changed and the resource-audience-scope "
                                + "ClientRegistrationPolicy needs re-evaluating, not this assertion.",
                        caseLabel, expected, actual, defaultScopes, optionalScopes)
                .isEqualTo(expected);
    }
}
