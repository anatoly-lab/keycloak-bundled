package io.mcpwarp.keycloak.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.Map;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ResourceAudienceScopePolicy}, per the test plan in
 * docs/design/2026-08-25-resource-audience-mapper.md §6 (item 8): {@code afterRegister}/
 * {@code afterUpdate} promote the configured scope to DEFAULT — a plain
 * {@code addClientScope(scope, true)} is a no-op when the scope is already attached as
 * OPTIONAL, so the policy must {@code removeClientScope} then {@code addClientScope}
 * instead (§3a) — and a missing configured scope on the realm is a log + no-op, never
 * a throw.
 */
@ExtendWith(MockitoExtension.class)
class ResourceAudienceScopePolicyTest {

    private static final String SCOPE_NAME = "mcpwarp-resource";

    @Mock
    private ClientModel clientModel;
    @Mock
    private RealmModel realm;
    @Mock
    private ClientScopeModel scope;

    private ComponentModel modelWithScopeName(String scopeName) {
        ComponentModel model = new ComponentModel();
        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        if (scopeName != null) {
            config.add(ResourceAudienceScopePolicyFactory.CLIENT_SCOPE, scopeName);
        }
        model.setConfig(config);
        return model;
    }

    private void stubRealmWithScope() {
        lenient().when(clientModel.getRealm()).thenReturn(realm);
        lenient().when(scope.getName()).thenReturn(SCOPE_NAME);
        lenient().when(realm.getClientScopesStream()).thenReturn(Stream.of(scope));
    }

    /** Stubs {@code getClientScopes(true)}/{@code getClientScopes(false)} as if the scope
     * is currently attached OPTIONAL (present only in the {@code false}/non-default map). */
    private void stubScopeCurrentlyOptional() {
        lenient().when(clientModel.getClientScopes(true)).thenReturn(Collections.emptyMap());
        lenient().when(clientModel.getClientScopes(false)).thenReturn(Map.of(SCOPE_NAME, scope));
    }

    private void stubScopeCurrentlyDefault() {
        lenient().when(clientModel.getClientScopes(true)).thenReturn(Map.of(SCOPE_NAME, scope));
    }

    private void stubScopeCurrentlyAbsent() {
        lenient().when(clientModel.getClientScopes(true)).thenReturn(Collections.emptyMap());
        lenient().when(clientModel.getClientScopes(false)).thenReturn(Collections.emptyMap());
    }

    @Test
    void afterRegister_scopeAbsentFromClient_addsAsDefault() {
        stubRealmWithScope();
        stubScopeCurrentlyAbsent();
        ComponentModel model = modelWithScopeName(null); // default clientScope name
        ResourceAudienceScopePolicy policy = new ResourceAudienceScopePolicy(model);

        policy.afterRegister(null, clientModel);

        InOrder inOrder = inOrder(clientModel);
        inOrder.verify(clientModel).removeClientScope(eq(scope));
        inOrder.verify(clientModel).addClientScope(eq(scope), eq(true));
    }

    @Test
    void afterRegister_scopeAlreadyDefault_noRemoveOrAddCalls() {
        stubRealmWithScope();
        stubScopeCurrentlyDefault();
        ComponentModel model = modelWithScopeName(SCOPE_NAME);
        ResourceAudienceScopePolicy policy = new ResourceAudienceScopePolicy(model);

        policy.afterRegister(null, clientModel);

        verify(clientModel, never()).removeClientScope(org.mockito.ArgumentMatchers.any());
        verify(clientModel, never()).addClientScope(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyBoolean());
    }

    @Test
    void afterUpdate_scopePresentAsOptional_movesToDefault() {
        stubRealmWithScope();
        stubScopeCurrentlyOptional();
        ComponentModel model = modelWithScopeName(SCOPE_NAME);
        ResourceAudienceScopePolicy policy = new ResourceAudienceScopePolicy(model);

        policy.afterUpdate(null, clientModel);

        InOrder inOrder = inOrder(clientModel);
        inOrder.verify(clientModel).removeClientScope(eq(scope));
        inOrder.verify(clientModel).addClientScope(eq(scope), eq(true));
    }

    @Test
    void missingConfiguredScopeOnRealm_logsAndNoOp_neverThrows() {
        lenient().when(clientModel.getRealm()).thenReturn(realm);
        when(realm.getClientScopesStream()).thenReturn(Stream.empty());
        ComponentModel model = modelWithScopeName(SCOPE_NAME);
        ResourceAudienceScopePolicy policy = new ResourceAudienceScopePolicy(model);

        policy.afterRegister(null, clientModel);

        verify(clientModel, never()).addClientScope(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyBoolean());
    }

    @Test
    void customClientScopeConfig_looksUpConfiguredNameNotDefault() {
        String customName = "other-scope";
        lenient().when(clientModel.getRealm()).thenReturn(realm);
        ClientScopeModel customScope = org.mockito.Mockito.mock(ClientScopeModel.class);
        lenient().when(customScope.getName()).thenReturn(customName);
        when(realm.getClientScopesStream()).thenReturn(Stream.of(customScope));
        lenient().when(clientModel.getClientScopes(true)).thenReturn(Collections.emptyMap());
        ComponentModel model = modelWithScopeName(customName);
        ResourceAudienceScopePolicy policy = new ResourceAudienceScopePolicy(model);

        policy.afterRegister(null, clientModel);

        verify(clientModel).addClientScope(eq(customScope), eq(true));
    }
}
