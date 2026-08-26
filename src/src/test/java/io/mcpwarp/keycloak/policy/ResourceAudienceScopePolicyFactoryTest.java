package io.mcpwarp.keycloak.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * Unit test for {@link ResourceAudienceScopePolicyFactory#validateConfiguration}, per the
 * test plan in docs/design/2026-08-25-resource-audience-mapper.md §6 (item 9): rejects a
 * {@code clientScope} naming a scope that doesn't exist on the realm.
 */
@ExtendWith(MockitoExtension.class)
class ResourceAudienceScopePolicyFactoryTest {

    @Mock
    private KeycloakSession session;
    @Mock
    private RealmModel realm;
    @Mock
    private ClientScopeModel scope;

    private final ResourceAudienceScopePolicyFactory factory = new ResourceAudienceScopePolicyFactory();

    private ComponentModel modelWithScopeName(String scopeName) {
        ComponentModel model = new ComponentModel();
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        if (scopeName != null) {
            config.add(ResourceAudienceScopePolicyFactory.CLIENT_SCOPE, scopeName);
        }
        model.setConfig(config);
        return model;
    }

    @Test
    void validateConfiguration_rejectsUnknownScope() {
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());
        ComponentModel model = modelWithScopeName("does-not-exist");

        assertThrows(ComponentValidationException.class,
                () -> factory.validateConfiguration(session, realm, model));
    }

    @Test
    void validateConfiguration_acceptsExistingScope() {
        when(scope.getName()).thenReturn("mcpwarp-resource");
        when(realm.getClientScopesStream()).thenReturn(Stream.of(scope));
        ComponentModel model = modelWithScopeName("mcpwarp-resource");

        assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
    }

    @Test
    void validateConfiguration_defaultScopeName_usedWhenConfigAbsent() {
        when(scope.getName()).thenReturn(ResourceAudienceScopePolicyFactory.DEFAULT_CLIENT_SCOPE);
        when(realm.getClientScopesStream()).thenReturn(Stream.of(scope));
        ComponentModel model = modelWithScopeName(null);

        assertDoesNotThrow(() -> factory.validateConfiguration(session, realm, model));
    }
}
