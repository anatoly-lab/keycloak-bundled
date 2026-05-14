package com.herdo.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RememberMeAuthenticatorTest {

    @Mock
    private AuthenticationFlowContext context;

    @Mock
    private AuthenticationSessionModel authSession;

    @Mock
    private EventBuilder eventBuilder;

    @Mock
    private KeycloakSession session;

    @Mock
    private RealmModel realm;

    @Mock
    private UserModel user;

    private RememberMeAuthenticator authenticator;

    @BeforeEach
    void setUp() {
        authenticator = new RememberMeAuthenticator();
    }

    @Test
    void authenticate_setsRememberMeNoteOnAuthSession() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getEvent()).thenReturn(eventBuilder);
        when(eventBuilder.detail(Details.REMEMBER_ME, "true")).thenReturn(eventBuilder);

        authenticator.authenticate(context);

        verify(authSession).setAuthNote(Details.REMEMBER_ME, "true");
    }

    @Test
    void authenticate_setsRememberMeDetailOnEvent() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getEvent()).thenReturn(eventBuilder);
        when(eventBuilder.detail(Details.REMEMBER_ME, "true")).thenReturn(eventBuilder);

        authenticator.authenticate(context);

        verify(eventBuilder).detail(Details.REMEMBER_ME, "true");
    }

    @Test
    void authenticate_callsSuccessOnContext() {
        when(context.getAuthenticationSession()).thenReturn(authSession);
        when(context.getEvent()).thenReturn(eventBuilder);
        when(eventBuilder.detail(Details.REMEMBER_ME, "true")).thenReturn(eventBuilder);

        authenticator.authenticate(context);

        verify(context).success();
    }

    @Test
    void requiresUser_returnsFalse() {
        assertThat(authenticator.requiresUser()).isFalse();
    }

    @Test
    void configuredFor_returnsTrue() {
        assertThat(authenticator.configuredFor(session, realm, user)).isTrue();
    }

    @Test
    void action_doesNotInteractWithContext() {
        authenticator.action(context);

        verifyNoInteractions(context);
    }

    @Test
    void close_doesNotThrow() {
        assertThatCode(() -> authenticator.close()).doesNotThrowAnyException();
    }

    @Test
    void setRequiredActions_doesNotInteractWithSessionOrRealm() {
        authenticator.setRequiredActions(session, realm, user);

        verifyNoInteractions(session, realm);
    }
}
