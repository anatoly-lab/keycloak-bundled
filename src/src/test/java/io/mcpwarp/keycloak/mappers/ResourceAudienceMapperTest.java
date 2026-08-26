package io.mcpwarp.keycloak.mappers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ResourceAudienceMapper}, per the test plan in
 * docs/design/2026-08-25-resource-audience-mapper.md §6 (items 1-3, 5-7).
 */
@ExtendWith(MockitoExtension.class)
class ResourceAudienceMapperTest {

    private static final String RESOURCE = "https://server-1.mcpwarp.io/mcp";
    private static final String ALLOW_MCPWARP = "^https://[a-z0-9-]+\\.mcpwarp\\.io/mcp$";

    @Mock
    private KeycloakSession session;
    @Mock
    private UserSessionModel userSession;
    @Mock
    private ClientSessionContext clientSessionCtx;
    @Mock
    private AuthenticatedClientSessionModel clientSession;
    @Mock
    private ClientModel client;
    @Mock
    private KeycloakContext keycloakContext;

    private final ResourceAudienceMapper mapper = new ResourceAudienceMapper();

    private ProtocolMapperModel modelWith(Map<String, String> config) {
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(config);
        return model;
    }

    private Map<String, String> baseConfig(String allowedPatterns, String strict, String claimName) {
        Map<String, String> config = new HashMap<>();
        // AbstractOIDCProtocolMapper#transformAccessToken gates on this before calling
        // setClaim at all (OIDCAttributeMapperHelper.includeInAccessToken) — must be
        // explicitly "true", there is no config-absent default.
        config.put("access.token.claim", "true");
        config.put(ResourceAudienceMapper.ALLOWED_RESOURCE_PATTERNS, allowedPatterns);
        if (strict != null) {
            config.put(ResourceAudienceMapper.STRICT, strict);
        }
        if (claimName != null) {
            config.put(ResourceAudienceMapper.CLAIM_NAME, claimName);
        }
        return config;
    }

    private void stubNote(String resource) {
        lenient().when(clientSessionCtx.getClientSession()).thenReturn(clientSession);
        lenient().when(clientSession.getNote(OAuth2Constants.RESOURCE)).thenReturn(resource);
        lenient().when(clientSession.getClient()).thenReturn(client);
        lenient().when(client.getClientId()).thenReturn("test-client");
        // AbstractOIDCProtocolMapper#getShouldUseLightweightToken reaches through
        // session.getContext().getClient() unconditionally before setClaim runs.
        lenient().when(session.getContext()).thenReturn(keycloakContext);
        lenient().when(keycloakContext.getClient()).thenReturn(client);
    }

    // ---- 1. Note present + matching pattern -> addAudience called once ----

    @Test
    void notePresentAndMatchingPattern_addsAudience() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).containsExactly(RESOURCE);
    }

    // ---- 2. Note absent -> no mutation, no exception in non-strict; reject in strict ----

    @Test
    void noteAbsent_nonStrict_noMutationNoThrow() {
        stubNote(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "false", null));
        AccessToken token = new AccessToken();

        assertDoesNotThrow(() -> mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx));
        assertThat(token.getAudience()).isNull();
    }

    @Test
    void noteAbsent_strict_rejects() {
        stubNote(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();

        assertThatThrownBy(() -> mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx))
                .isInstanceOf(ErrorResponseException.class);
    }

    // ---- 3. Note present, no pattern matches -> non-strict: no audience; strict: reject ----

    @Test
    void noPatternMatches_nonStrict_noAudienceNoThrow() {
        stubNote("https://evil.example.com/mcp");
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "false", null));
        AccessToken token = new AccessToken();

        assertDoesNotThrow(() -> mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx));
        assertThat(token.getAudience()).isNull();
    }

    @Test
    void noPatternMatches_strict_rejects() {
        stubNote("https://evil.example.com/mcp");
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();

        assertThatThrownBy(() -> mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx))
                .isInstanceOf(ErrorResponseException.class);
    }

    // ---- 4. Token param equals note -> same as (1); differs -> non-strict ignores, strict rejects ----

    @Test
    void tokenParamEqualsNote_addsAudience() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(RESOURCE);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).containsExactly(RESOURCE);
    }

    @Test
    void tokenParamMismatch_nonStrict_usesNoteIgnoresParam() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class))
                .thenReturn("https://evil.mcpwarp.io/mcp");
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "false", null));
        AccessToken token = new AccessToken();

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).containsExactly(RESOURCE);
    }

    @Test
    void tokenParamMismatch_strict_rejects() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class))
                .thenReturn("https://evil.mcpwarp.io/mcp");
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();

        assertThatThrownBy(() -> mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx))
                .isInstanceOf(ErrorResponseException.class);
    }

    // ---- 5. addAudience semantics: pre-existing aud survives, no duplicate ----

    @Test
    void appendsWithoutClobberingExistingAudience() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();
        token.addAudience("pre-existing-client");

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).containsExactlyInAnyOrder("pre-existing-client", RESOURCE);
    }

    @Test
    void addAudienceDeduplicates() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));
        AccessToken token = new AccessToken();
        token.addAudience(RESOURCE);

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).containsExactly(RESOURCE);
    }

    // ---- 6. validateConfig rejects an uncompilable pattern; empty = deny-all ----

    @Test
    void validateConfig_rejectsBadRegex() {
        ProtocolMapperModel model = modelWith(baseConfig("(unclosed", "true", null));

        assertThatThrownBy(() -> mapper.validateConfig(session, null, null, model))
                .isInstanceOf(ProtocolMapperConfigException.class);
    }

    @Test
    void validateConfig_acceptsValidRegex() {
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", null));

        assertDoesNotThrow(() -> mapper.validateConfig(session, null, null, model));
    }

    @Test
    void emptyAllowedPatterns_denyAll_nonStrict() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig("", "false", null));
        AccessToken token = new AccessToken();

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).isNull();
    }

    // ---- 7. claimName override writes otherClaims, leaves aud untouched ----

    @Test
    void claimNameOverride_writesOtherClaimsNotAud() {
        stubNote(RESOURCE);
        when(clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class)).thenReturn(null);
        ProtocolMapperModel model = modelWith(baseConfig(ALLOW_MCPWARP, "true", "resource_claim"));
        AccessToken token = new AccessToken();

        mapper.transformAccessToken(token, model, session, userSession, clientSessionCtx);

        assertThat(token.getAudience()).isNull();
        assertThat(token.getOtherClaims()).containsEntry("resource_claim", RESOURCE);
    }

    // ---- lightweight access token claim defaults to "true" (P1-5) ----

    @Test
    void configProperties_lightweightClaimDefaultsToTrue() {
        ProviderConfigProperty lightweightProperty = mapper.getConfigProperties().stream()
                .filter(property -> OIDCAttributeMapperHelper.INCLUDE_IN_LIGHTWEIGHT_ACCESS_TOKEN.equals(property.getName()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("lightweight.claim config property not found"));

        assertThat(lightweightProperty.getDefaultValue()).isEqualTo("true");
    }
}
