package io.mcpwarp.keycloak.policy;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.clientregistration.ClientRegistrationContext;
import org.keycloak.services.clientregistration.ClientRegistrationProvider;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy;
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyException;

/**
 * Force-adds the configured client scope (default {@code mcpwarp-resource}) as a DEFAULT
 * scope on every DCR-registered client, in {@code afterRegister} and {@code afterUpdate} —
 * i.e. after {@code RepresentationToModel.updateClientScopes} has already run and possibly
 * stripped it. See docs/design/2026-08-25-resource-audience-mapper.md §3a/§5: realm-default
 * attachment alone does not survive DCR for any client that sends an explicit {@code scope}
 * field, which is every real MCP client (confirmed empirically, see
 * DcrScopeStrippingCharacterizationIT).
 *
 * <p>Never throws from {@code afterRegister}/{@code afterUpdate} — both are {@code void} with
 * no declared exception on the {@link ClientRegistrationPolicy} interface, so a thrown
 * exception here would surface as an unhandled 500 on every DCR call for the lifetime of the
 * misconfiguration. A missing configured scope is logged and treated as a no-op instead.
 */
public class ResourceAudienceScopePolicy implements ClientRegistrationPolicy {

    private static final Logger LOGGER = Logger.getLogger(ResourceAudienceScopePolicy.class);

    private final ComponentModel model;

    public ResourceAudienceScopePolicy(ComponentModel model) {
        this.model = model;
    }

    @Override
    public void beforeRegister(ClientRegistrationContext context) throws ClientRegistrationPolicyException {
    }

    @Override
    public void afterRegister(ClientRegistrationContext context, ClientModel clientModel) {
        forceAddScope(clientModel);
    }

    @Override
    public void beforeUpdate(ClientRegistrationContext context, ClientModel clientModel)
            throws ClientRegistrationPolicyException {
    }

    @Override
    public void afterUpdate(ClientRegistrationContext context, ClientModel clientModel) {
        forceAddScope(clientModel);
    }

    @Override
    public void beforeView(ClientRegistrationProvider provider, ClientModel clientModel)
            throws ClientRegistrationPolicyException {
    }

    @Override
    public void beforeDelete(ClientRegistrationProvider provider, ClientModel clientModel)
            throws ClientRegistrationPolicyException {
    }

    private void forceAddScope(ClientModel clientModel) {
        String scopeName = ResourceAudienceScopePolicyFactory.clientScopeName(model);
        RealmModel realm = clientModel.getRealm();
        ClientScopeModel scope = realm.getClientScopesStream()
                .filter(s -> scopeName.equals(s.getName()))
                .findFirst()
                .orElse(null);

        if (scope == null) {
            LOGGER.errorf("resource-audience-scope policy: configured client scope '%s' does not exist "
                    + "on realm '%s'; not attaching it to client '%s'. The scope must be created as realm "
                    + "config before this policy can attach it.", scopeName, realm.getName(), clientModel.getClientId());
            return;
        }

        // addClientScope(scope, true) is a no-op if the scope is already attached as
        // OPTIONAL — JpaRealmProvider.addClientScopes filters on existing names across
        // both the default and optional lists, so a plain add never promotes it. Must
        // explicitly remove-then-add-as-default instead (design doc §3a).
        if (!clientModel.getClientScopes(true).containsKey(scopeName)) {
            clientModel.removeClientScope(scope); // no-op if not currently attached at all
            clientModel.addClientScope(scope, true);
        }
    }
}
