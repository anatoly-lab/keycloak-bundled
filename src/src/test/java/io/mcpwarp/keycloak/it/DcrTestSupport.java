package io.mcpwarp.keycloak.it;

import io.restassured.http.ContentType;
import io.restassured.response.Response;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shared realm/scope/DCR-policy/admin-API plumbing for the two DCR-scope ITs:
 * {@link DcrScopeStrippingCharacterizationIT} (documents Keycloak's own
 * scope-survival behaviour, no mapper/policy code involved) and
 * {@link ResourceAudienceScopePolicyIT} (exercises the {@code
 * resource-audience-scope} {@code ClientRegistrationPolicy}, once it exists).
 * Both classes register an MCP-shaped public client via DCR against a
 * throwaway realm and then read the client's default/optional client-scope
 * lists back over the admin REST API — this class is just that plumbing,
 * factored out so it isn't duplicated between the two test classes.
 *
 * <p>Callers own their own {@code RestAssured.baseURI}/{@code port} (set in a
 * {@code @BeforeAll}, same as {@link com.herdo.keycloak.it.RememberMeAuthenticatorIT})
 * and their own Testcontainers container — this class only issues HTTP calls
 * against whatever base URI is currently configured.
 */
final class DcrTestSupport {

    static final String ADMIN_USER = "admin";
    static final String ADMIN_PASSWORD = "admin";
    static final String TEST_REDIRECT_URI = "http://localhost/callback";

    private DcrTestSupport() {
    }

    static String adminAccessToken() {
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

    static void createRealm(String adminToken, String realmName) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of("realm", realmName, "enabled", true))
                .when()
                .post("/admin/realms")
                .then()
                .statusCode(201);
    }

    /**
     * Creates {@code scopeName} with NO protocol mappers — neither IT needs
     * mapper behaviour, only scope-survival/attachment behaviour.
     */
    static String createResourceScope(String adminToken, String realmName, String scopeName) {
        Response created = given()
                .header("Authorization", "Bearer " + adminToken)
                .contentType(ContentType.JSON)
                .body(Map.of(
                        "name", scopeName,
                        // "protocol" is mandatory, not cosmetic: AbstractLoginProtocolFactory
                        // .addDefaultClientScopes filters realm defaults by protocol, so omitting
                        // it would make DCR-attachment cases fail spuriously once marked realm-default.
                        "protocol", "openid-connect",
                        "attributes", Map.of(
                                "include.in.token.scope", "true",
                                "display.on.consent.screen", "false")))
                .when()
                .post("/admin/realms/" + realmName + "/client-scopes")
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

    static void markScopeAsRealmDefault(String adminToken, String realmName, String scopeId, String scopeName) {
        given()
                .header("Authorization", "Bearer " + adminToken)
                .when()
                .put("/admin/realms/" + realmName + "/default-default-client-scopes/" + scopeId)
                .then()
                .statusCode(204);

        // Positive control: confirm the realm actually carries the scope as a
        // default before any DCR happens, so a later result can only be
        // attributed to DCR/policy handling, not to setup.
        List<Map<String, Object>> realmDefaults = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + realmName + "/default-default-client-scopes")
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
                        scopeName, realmDefaultNames)
                .contains(scopeName);
    }

    /**
     * Configures the realm's anonymous Client Registration Policies the way
     * ankimcp's browser-DCR setup does (see
     * {@link DcrScopeStrippingCharacterizationIT} class Javadoc for the source
     * and the "openid gotcha"): a permissive Trusted Hosts policy ({@code
     * host-sending-registration-request-must-match} off, since the
     * registering "host" here is this test's HTTP client, not a predictable
     * browser IP) plus an Allowed Client Scopes policy that lists {@code
     * openid} EXPLICITLY (Keycloak's own {@code
     * ClientScopesClientRegistrationPolicy.getAllowedScopeNames} covers realm
     * default/optional scopes via {@code allow-default-scopes: true}, but
     * never covers {@code openid} — it isn't a real client scope).
     *
     * <p>A fresh realm created via {@code POST /admin/realms} always carries a
     * seeded anonymous+authenticated policy pair per provider — 26.7.2 source:
     * {@code RealmManager.setupClientRegistrations} (services/.../managers/RealmManager.java:849-850)
     * calls {@code DefaultClientRegistrationPolicies.addDefaultPolicies}
     * (services/.../clientregistration/policy/DefaultClientRegistrationPolicies.java:57-118),
     * which creates both {@code trusted-hosts} and {@code allowed-client-templates}
     * components (providerType {@code
     * org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy},
     * subType {@code anonymous}) unconditionally on realm creation. We
     * PUT-update the existing anonymous component.
     */
    static void configureAnonymousDcrPolicies(String adminToken, String realmName, String... additionalAllowedScopes) {
        updateAnonymousPolicy(adminToken, realmName, "trusted-hosts", config -> {
            config.put("trusted-hosts", List.of("localhost"));
            // Must be off: the test JVM reaches the container via the Docker bridge
            // gateway, not loopback, so TrustedHostClientRegistrationPolicy.verifyHost
            // would 403 the DCR request otherwise.
            config.put("host-sending-registration-request-must-match", List.of("false"));
            config.put("client-uris-must-match", List.of("true"));
        });

        List<String> allowedScopes = new ArrayList<>(List.of("openid", "profile", "email"));
        allowedScopes.addAll(List.of(additionalAllowedScopes));

        updateAnonymousPolicy(adminToken, realmName, "allowed-client-templates", config -> {
            config.put("allow-default-scopes", List.of("true"));
            config.put("allowed-client-scopes", allowedScopes);
        });
    }

    @SuppressWarnings("unchecked")
    static void updateAnonymousPolicy(
            String adminToken, String realmName, String providerId, Consumer<Map<String, Object>> configMutator) {
        List<Map<String, Object>> components = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .queryParam("type", "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy")
                .when()
                .get("/admin/realms/" + realmName + "/components")
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
                .put("/admin/realms/" + realmName + "/components/" + anonymousPolicy.get("id"))
                .then()
                .statusCode(204);
    }

    static Response registerDcrClient(String realmName, String scopeParam) {
        Map<String, Object> body = new HashMap<>();
        body.put("client_name", "dcr-client-" + System.nanoTime());
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
                .post("/realms/" + realmName + "/clients-registrations/openid-connect");
    }

    static String lookUpInternalClientId(String adminToken, String realmName, String registeredClientId) {
        List<Map<String, Object>> matches = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .queryParam("clientId", registeredClientId)
                .when()
                .get("/admin/realms/" + realmName + "/clients")
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

    static List<String> clientScopeNames(
            String adminToken, String realmName, String internalClientId, String scopeKind) {
        List<Map<String, Object>> scopes = given()
                .header("Authorization", "Bearer " + adminToken)
                .accept(ContentType.JSON)
                .when()
                .get("/admin/realms/" + realmName + "/clients/" + internalClientId + "/" + scopeKind)
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
}
