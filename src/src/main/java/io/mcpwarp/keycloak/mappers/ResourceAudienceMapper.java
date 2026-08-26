package io.mcpwarp.keycloak.mappers;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperContainerModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapperConfigException;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ErrorResponseException;

import jakarta.ws.rs.core.Response;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Appends the RFC 8707 {@code resource} value captured at {@code /authorize} to the
 * access token's {@code aud}, per docs/design/2026-08-25-resource-audience-mapper.md
 * §3/§4. Reads the client-session note {@code resource} (the literal note key stored
 * by {@code AuthorizationEndpoint}, verified against Keycloak tag 26.7.2 — no prefix),
 * never the per-request {@code /token} attribute as a source of truth, and never
 * throws for a client that doesn't carry this mapper's scope in the first place
 * (mapper resolution is per-attached-scope, so this class is simply never invoked
 * for such a client).
 */
public class ResourceAudienceMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {

    private static final Logger LOGGER = Logger.getLogger(ResourceAudienceMapper.class);

    public static final String PROVIDER_ID = "resource-audience";

    public static final String ALLOWED_RESOURCE_PATTERNS = "allowedResourcePatterns";
    public static final String CLAIM_NAME = "claimName";
    public static final String STRICT = "strict";

    public static final String DEFAULT_CLAIM_NAME = "aud";
    public static final boolean DEFAULT_STRICT = true;

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty allowedPatterns = new ProviderConfigProperty();
        allowedPatterns.setName(ALLOWED_RESOURCE_PATTERNS);
        allowedPatterns.setLabel("Allowed resource patterns");
        allowedPatterns.setHelpText("One regex per line, matched with Matcher.matches() against the "
                + "resource value. Empty = deny all (fail-closed).");
        allowedPatterns.setType(ProviderConfigProperty.TEXT_TYPE);
        CONFIG_PROPERTIES.add(allowedPatterns);

        ProviderConfigProperty claimName = new ProviderConfigProperty();
        claimName.setName(CLAIM_NAME);
        claimName.setLabel("Claim name");
        claimName.setHelpText("Claim to write the resource into. 'aud' (default) uses the typed "
                + "addAudience() path; anything else writes otherClaims and is for debugging only.");
        claimName.setType(ProviderConfigProperty.STRING_TYPE);
        claimName.setDefaultValue(DEFAULT_CLAIM_NAME);
        CONFIG_PROPERTIES.add(claimName);

        ProviderConfigProperty strict = new ProviderConfigProperty();
        strict.setName(STRICT);
        strict.setLabel("Strict");
        strict.setHelpText("Reject token issuance (invalid_target) on a missing/mismatched/"
                + "non-matching resource instead of silently issuing an unaudienced token.");
        strict.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        strict.setDefaultValue(String.valueOf(DEFAULT_STRICT));
        CONFIG_PROPERTIES.add(strict);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, ResourceAudienceMapper.class);

        // addIncludeInTokensConfig defaults lightweight.claim to "false"; AbstractOIDCProtocolMapper
        // skips setClaim entirely for a lightweight-access-token client unless it's "true". This
        // mapper's whole purpose is putting an audience on the access token, so default it on.
        for (ProviderConfigProperty property : CONFIG_PROPERTIES) {
            if (OIDCAttributeMapperHelper.INCLUDE_IN_LIGHTWEIGHT_ACCESS_TOKEN.equals(property.getName())) {
                property.setDefaultValue("true");
            }
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Resource Audience";
    }

    @Override
    public String getHelpText() {
        return "Appends the RFC 8707 'resource' value captured at /authorize to the token's "
                + "audience, validated against a configured regex allowlist.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void validateConfig(KeycloakSession session, RealmModel realm, ProtocolMapperContainerModel client,
                                ProtocolMapperModel mapperModel) throws ProtocolMapperConfigException {
        for (String pattern : allowedPatternLines(mapperModel)) {
            try {
                Pattern.compile(pattern);
            } catch (PatternSyntaxException e) {
                throw new ProtocolMapperConfigException("invalid-resource-pattern",
                        "Invalid regex in " + ALLOWED_RESOURCE_PATTERNS + ": " + pattern, e);
            }
        }
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                             KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        if (!(token instanceof AccessToken)) {
            // Never wired to the ID token per design (§3), but guard defensively.
            return;
        }
        AccessToken accessToken = (AccessToken) token;
        boolean strict = isStrict(mappingModel);

        if (clientSessionCtx.getClientSession() == null) {
            return;
        }

        String note = clientSessionCtx.getClientSession().getNote(OAuth2Constants.RESOURCE);
        if (note == null || note.isBlank()) {
            if (strict) {
                reject("Missing 'resource' for a client carrying the resource-audience mapper's scope.");
            }
            return;
        }

        // /token-time attribute is never a source of truth (design doc §2 decision (a)) —
        // only used to detect a mismatch against the /authorize-time note.
        String requestResource = clientSessionCtx.getAttribute(OAuth2Constants.RESOURCE, String.class);
        if (requestResource != null && !requestResource.equals(note)) {
            LOGGER.warnf("resource-audience mapper: /token resource '%s' does not match the "
                    + "/authorize-time note '%s' for client '%s'", requestResource, note,
                    clientSessionCtx.getClientSession().getClient().getClientId());
            if (strict) {
                reject("'resource' at /token does not match the value consented to at /authorize.");
            }
            // non-strict: ignore the mismatched /token param entirely and fall through to
            // process using the /authorize-time note, per design doc §2 decision (a).
        }

        if (!matchesAllowlist(mappingModel, note)) {
            LOGGER.infof("resource-audience mapper: resource '%s' does not match any configured "
                    + "allowlist pattern for client '%s'", note,
                    clientSessionCtx.getClientSession().getClient().getClientId());
            if (strict) {
                reject("'resource' does not match any configured allowlist pattern.");
            }
            return;
        }

        String claimName = claimName(mappingModel);
        if (DEFAULT_CLAIM_NAME.equals(claimName)) {
            accessToken.addAudience(note);
        } else {
            accessToken.setOtherClaims(claimName, note);
        }
    }

    private static void reject(String errorDescription) {
        // No CORS headers on this response — a mapper has no access to the CORS response
        // builder used by the token endpoint, so a strict-mode reject from a browser-based
        // client surfaces there as a CORS error, not a clean invalid_target (design doc §4).
        throw new ErrorResponseException(
                org.keycloak.OAuthErrorException.INVALID_TARGET, errorDescription, Response.Status.BAD_REQUEST);
    }

    private static boolean isStrict(ProtocolMapperModel mappingModel) {
        String value = mappingModel.getConfig().get(STRICT);
        return value == null ? DEFAULT_STRICT : Boolean.parseBoolean(value);
    }

    private static String claimName(ProtocolMapperModel mappingModel) {
        String value = mappingModel.getConfig().get(CLAIM_NAME);
        return (value == null || value.isBlank()) ? DEFAULT_CLAIM_NAME : value;
    }

    private static List<String> allowedPatternLines(ProtocolMapperModel mappingModel) {
        String raw = mappingModel.getConfig() == null ? null : mappingModel.getConfig().get(ALLOWED_RESOURCE_PATTERNS);
        List<String> lines = new ArrayList<>();
        if (raw == null) {
            return lines;
        }
        for (String line : raw.split("\\R")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                lines.add(trimmed);
            }
        }
        return lines;
    }

    private static boolean matchesAllowlist(ProtocolMapperModel mappingModel, String resource) {
        for (String patternText : allowedPatternLines(mappingModel)) {
            Pattern pattern;
            try {
                pattern = Pattern.compile(patternText);
            } catch (PatternSyntaxException e) {
                // Defense in depth only: validateConfig should have already rejected this
                // at config-write time (design doc §3, "Regex compile error").
                LOGGER.errorf(e, "resource-audience mapper: pattern '%s' fails to compile at runtime; "
                        + "treating as non-matching", patternText);
                continue;
            }
            if (pattern.matcher(resource).matches()) {
                return true;
            }
        }
        return false;
    }
}
