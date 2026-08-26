package io.mcpwarp.keycloak.policy;

import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientregistration.policy.AbstractClientRegistrationPolicyFactory;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;

import java.util.Collections;
import java.util.List;

/**
 * Factory for {@link ResourceAudienceScopePolicy}, provider id {@code resource-audience-scope}
 * (docs/design/2026-08-25-resource-audience-mapper.md §3a/§4a). One config property,
 * {@code clientScope}, default {@code mcpwarp-resource} — the named scope must already exist
 * on the realm; {@link #validateConfiguration} rejects a config naming a scope that doesn't,
 * mirroring {@code ClientScopesClientRegistrationPolicyFactory.validateConfiguration}.
 */
public class ResourceAudienceScopePolicyFactory extends AbstractClientRegistrationPolicyFactory {

    public static final String PROVIDER_ID = "resource-audience-scope";

    public static final String CLIENT_SCOPE = "clientScope";
    public static final String DEFAULT_CLIENT_SCOPE = "mcpwarp-resource";

    @Override
    public ClientRegistrationPolicy create(KeycloakSession session, ComponentModel model) {
        return new ResourceAudienceScopePolicy(model);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Force-adds the configured client scope as a DEFAULT scope on every DCR-registered "
                + "client, after Keycloak's own scope-stripping has run.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(CLIENT_SCOPE);
        property.setLabel("Client scope");
        property.setHelpText("Name of the client scope to force-attach as DEFAULT. Must already "
                + "exist on the realm.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(DEFAULT_CLIENT_SCOPE);
        return Collections.singletonList(property);
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
            throws ComponentValidationException {
        String scopeName = clientScopeName(model);
        boolean exists = realm.getClientScopesStream().map(ClientScopeModel::getName).anyMatch(scopeName::equals);
        if (!exists) {
            throw new ComponentValidationException("Client scope not found on realm: " + scopeName);
        }
    }

    static String clientScopeName(ComponentModel model) {
        String configured = model.getConfig().getFirst(CLIENT_SCOPE);
        return (configured == null || configured.isBlank()) ? DEFAULT_CLIENT_SCOPE : configured;
    }
}
