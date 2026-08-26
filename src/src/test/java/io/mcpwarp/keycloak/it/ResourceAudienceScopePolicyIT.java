package io.mcpwarp.keycloak.it;

import io.restassured.RestAssured;
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

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for the {@code resource-audience-scope} {@link
 * org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy}
 * (docs/design/2026-08-25-resource-audience-mapper.md §3/§5) — NOT YET
 * IMPLEMENTED. {@link DcrScopeStrippingCharacterizationIT} established the
 * problem this policy solves: a realm-DEFAULT client scope does not
 * reliably survive DCR, so the policy force-adds it in {@code afterRegister}
 * (and re-adds it in {@code afterUpdate}, since a later DCR PUT can strip it
 * again the same way).
 *
 * <p>The policy provider now exists (provider id {@code resource-audience-scope},
 * {@link io.mcpwarp.keycloak.policy.ResourceAudienceScopePolicy}), so this class
 * is no longer {@code @Disabled} — the test bodies below were written against
 * the final expected behaviour, not against a stub, and now exercise the real
 * implementation once it's baked into the bundled image under test.
 *
 * <p>Reuses {@link DcrTestSupport} for realm/scope/policy/DCR plumbing — same
 * helpers {@link DcrScopeStrippingCharacterizationIT} uses, so the two
 * classes only differ in which {@code ClientRegistrationPolicy} components
 * are on the realm and what they assert.
 */
@Testcontainers
class ResourceAudienceScopePolicyIT {

    private static final String IMAGE_REF =
            System.getProperty("image.ref", "ghcr.io/anatoly-lab/keycloak-bundled:latest");

    private static final String TEST_REALM = "audpolicytest";
    private static final String SCOPE_NAME = "mcpwarp-resource";

    /**
     * Provider id of the {@code ClientRegistrationPolicy} under test — must
     * match the design doc §3 ("Provider id: {@code resource-audience-scope},
     * or similar consistent with the mapper's {@code resource-audience}") and
     * whatever the eventual {@code ClientRegistrationPolicyFactory#getId()}
     * returns.
     */
    private static final String POLICY_PROVIDER_ID = "resource-audience-scope";

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

    @BeforeAll
    static void setUp() {
        RestAssured.baseURI = "http://" + KEYCLOAK.getHost();
        RestAssured.port = KEYCLOAK.getMappedPort(8080);

        String adminToken = DcrTestSupport.adminAccessToken();
        DcrTestSupport.createRealm(adminToken, TEST_REALM);
        String scopeId = DcrTestSupport.createResourceScope(adminToken, TEST_REALM, SCOPE_NAME);
        DcrTestSupport.markScopeAsRealmDefault(adminToken, TEST_REALM, scopeId, SCOPE_NAME);
        // The Allowed Client Scopes policy must still permit mcpwarp-resource
        // explicitly (design doc §5) so an explicit-scope DCR body (case iii)
        // isn't 403'd before the resource-audience-scope policy ever runs.
        DcrTestSupport.configureAnonymousDcrPolicies(adminToken, TEST_REALM, SCOPE_NAME);
        addResourceAudienceScopePolicy(adminToken, "anonymous");
        addResourceAudienceScopePolicy(adminToken, "authenticated");
    }

    /**
     * Adds the {@code resource-audience-scope} component, config {@code
     * clientScope=mcpwarp-resource} (the default per design doc §4), for the
     * given {@code ClientRegistrationPolicy} subtype. Registered for both
     * {@code anonymous} and {@code authenticated} subtypes, mirroring
     * Keycloak's own "Allowed Client Scopes" policy pattern (design doc §5).
     */
    private static void addResourceAudienceScopePolicy(String adminToken, String subType) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType("application/json")
                .body(Map.of(
                        "name", "Resource Audience Scope",
                        "providerId", POLICY_PROVIDER_ID,
                        "providerType", "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
                        "subType", subType,
                        "config", Map.of("clientScope", List.of(SCOPE_NAME))))
                .when()
                .post("/admin/realms/" + TEST_REALM + "/components")
                .then()
                .statusCode(201);
    }

    // =======================================================================
    //  Tests — same three DCR shapes as DcrScopeStrippingCharacterizationIT,
    //  but now mcpwarp-resource must end as DEFAULT in ALL THREE, because the
    //  policy force-adds it in afterRegister regardless of what
    //  updateClientScopes already stripped.
    // =======================================================================

    @Test
    void scopeOmittingMcpwarpResourceStillEndsAsDefault() {
        assertScopeIsDefaultAfterDcr("openid profile email");
    }

    @Test
    void noScopeFieldEndsAsDefault() {
        assertScopeIsDefaultAfterDcr(null);
    }

    @Test
    void scopeIncludingMcpwarpResourceEndsAsDefaultNotOptional() {
        // Case (iii) is the interesting one: without the policy this lands as
        // OPTIONAL (DcrScopeStrippingCharacterizationIT). With the policy,
        // afterRegister forces it back to DEFAULT even though the client
        // explicitly requested it.
        assertScopeIsDefaultAfterDcr("openid profile email mcpwarp-resource");
    }

    /**
     * DCR PUT update case: a client that already exists (created via one of
     * the shapes above, or directly) sends a {@code PUT
     * /clients-registrations/openid-connect/{client_id}} whose {@code scope}
     * field omits {@code mcpwarp-resource}. Per {@code
     * AbstractClientRegistrationProvider#update} (services/.../clientregistration/AbstractClientRegistrationProvider.java:176-178,214),
     * {@code RepresentationToModel.updateClientScopes} runs again on update
     * and would strip the scope the same way it does on create — the policy's
     * {@code afterUpdate} hook must re-add it, exactly like {@code
     * afterRegister} does on create.
     */
    @Test
    void dcrPutUpdateReAddsScopeAfterStrip() {
        Response registration = DcrTestSupport.registerDcrClient(TEST_REALM, "openid profile email mcpwarp-resource");
        assertThat(registration.statusCode()).isEqualTo(201);

        String clientId = registration.jsonPath().getString("client_id");
        String registrationAccessToken = registration.jsonPath().getString("registration_access_token");
        assertThat(registrationAccessToken).as("registration_access_token").isNotBlank();

        Map<String, Object> updateBody = Map.of(
                "client_id", clientId,
                "redirect_uris", List.of(DcrTestSupport.TEST_REDIRECT_URI),
                "token_endpoint_auth_method", "none",
                "grant_types", List.of("authorization_code", "refresh_token"),
                "response_types", List.of("code"),
                // Deliberately omits mcpwarp-resource, same shape as case (i).
                "scope", "openid profile email");

        Response update = given()
                .header("Authorization", "Bearer " + registrationAccessToken)
                .contentType("application/json")
                .body(updateBody)
                .when()
                .put("/realms/" + TEST_REALM + "/clients-registrations/openid-connect/" + clientId);
        assertThat(update.statusCode())
                .withFailMessage("DCR PUT update must succeed (200). Body: %s", update.getBody().asString())
                .isEqualTo(200);

        String adminToken = DcrTestSupport.adminAccessToken();
        String internalId = DcrTestSupport.lookUpInternalClientId(adminToken, TEST_REALM, clientId);
        List<String> defaultScopes = DcrTestSupport.clientScopeNames(adminToken, TEST_REALM, internalId, "default-client-scopes");

        assertThat(defaultScopes)
                .withFailMessage(
                        "After a DCR PUT update that strips mcpwarp-resource from the requested scope, "
                                + "the resource-audience-scope policy's afterUpdate hook must re-add it as "
                                + "a DEFAULT scope. Got default scopes: %s", defaultScopes)
                .contains(SCOPE_NAME);
    }

    // =======================================================================
    //  Helper
    // =======================================================================

    private static void assertScopeIsDefaultAfterDcr(String scopeParam) {
        Response registration = DcrTestSupport.registerDcrClient(TEST_REALM, scopeParam);
        assertThat(registration.statusCode())
                .withFailMessage("DCR POST must succeed (201). Body: %s", registration.getBody().asString())
                .isEqualTo(201);

        String registeredClientId = registration.jsonPath().getString("client_id");
        String adminToken = DcrTestSupport.adminAccessToken();
        String internalId = DcrTestSupport.lookUpInternalClientId(adminToken, TEST_REALM, registeredClientId);

        List<String> defaultScopes = DcrTestSupport.clientScopeNames(adminToken, TEST_REALM, internalId, "default-client-scopes");
        assertThat(defaultScopes)
                .withFailMessage(
                        "resource-audience-scope policy must force '%s' into DEFAULT client scopes "
                                + "regardless of the DCR request's scope field. Got: %s",
                        SCOPE_NAME, defaultScopes)
                .contains(SCOPE_NAME);
    }
}
