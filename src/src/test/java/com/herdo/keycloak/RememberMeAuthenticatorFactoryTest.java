package com.herdo.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@ExtendWith(MockitoExtension.class)
class RememberMeAuthenticatorFactoryTest {

    @Mock
    private KeycloakSession session;

    @Mock
    private KeycloakSessionFactory sessionFactory;

    @Mock
    private Config.Scope scope;

    private RememberMeAuthenticatorFactory factory;

    @BeforeEach
    void setUp() {
        factory = new RememberMeAuthenticatorFactory();
    }

    @Test
    void getId_returnsExpectedProviderId() {
        assertThat(factory.getId()).isEqualTo("remember-me-authenticator");
    }

    @Test
    void create_returnsNonNullAuthenticator() {
        Authenticator authenticator = factory.create(session);

        assertThat(authenticator).isNotNull();
    }

    @Test
    void create_returnsSameInstanceOnSubsequentCalls() {
        Authenticator first = factory.create(session);
        Authenticator second = factory.create(session);

        assertThat(first).isSameAs(second);
    }

    @Test
    void getRequirementChoices_includesRequiredAndAlternativeAndDisabled() {
        List<AuthenticationExecutionModel.Requirement> choices =
                Arrays.asList(factory.getRequirementChoices());

        assertThat(choices)
                .contains(
                        AuthenticationExecutionModel.Requirement.REQUIRED,
                        AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                        AuthenticationExecutionModel.Requirement.DISABLED);
    }

    @Test
    void isConfigurable_returnsFalse() {
        assertThat(factory.isConfigurable()).isFalse();
    }

    @Test
    void isUserSetupAllowed_returnsFalse() {
        assertThat(factory.isUserSetupAllowed()).isFalse();
    }

    @Test
    void init_doesNotThrow() {
        assertThatCode(() -> factory.init(scope)).doesNotThrowAnyException();
    }

    @Test
    void postInit_doesNotThrow() {
        assertThatCode(() -> factory.postInit(sessionFactory)).doesNotThrowAnyException();
    }

    @Test
    void close_doesNotThrow() {
        assertThatCode(() -> factory.close()).doesNotThrowAnyException();
    }
}
