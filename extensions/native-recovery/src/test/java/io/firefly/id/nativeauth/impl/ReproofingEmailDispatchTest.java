package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.NativePhases;
import jakarta.enterprise.context.ContextNotActiveException;
import jakarta.persistence.*;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.email.*;
import org.keycloak.email.freemarker.FreeMarkerEmailTemplateProvider;
import org.keycloak.models.*;
import org.keycloak.theme.Theme;
import org.keycloak.theme.freemarker.FreeMarkerProvider;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.representations.userprofile.config.UPConfig;
import java.util.*;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ReproofingEmailDispatchTest {
    @Test @SuppressWarnings("unchecked")
    void realEmailTemplateProviderCanPopulateAttributesAndDeliverExactCommittedDestination() throws Exception {
        var session = mock(KeycloakSession.class); var context = mock(KeycloakContext.class); var realm = mock(RealmModel.class);
        when(session.getContext()).thenReturn(context); when(context.getRequestHeaders()).thenReturn(mock(jakarta.ws.rs.core.HttpHeaders.class)); when(context.getRealm()).thenReturn(realm); when(realm.getId()).thenReturn("realm"); when(realm.getName()).thenReturn("customers");
        Map<String,String> configuration = Map.of("enabled","true","population","HUMAN","allowed-origin","https://id.test","issuer","https://id.test/realms/customers","core-workload-client-id","core","domain-workload-client-id","domain","ttl-seconds","600");
        when(realm.getAttribute(anyString())).thenAnswer(call -> configuration.get(call.getArgument(0,String.class).replace("firefly.reproofing.","")));
        var em = mock(EntityManager.class); var jpa = mock(JpaConnectionProvider.class); when(session.getProvider(JpaConnectionProvider.class)).thenReturn(jpa); when(jpa.getEntityManager()).thenReturn(em);
        var clock = mock(Query.class, RETURNS_SELF); when(em.createNativeQuery(anyString())).thenReturn(clock); when(clock.getSingleResult()).thenReturn(1700000000000L);
        var notification = new ReproofingNotificationImpl(); notification.id="execution"; notification.realmId="realm"; notification.subject="customer"; notification.status="PENDING"; notification.destinationEncrypted="encrypted-prior-destination";
        var pending = mock(TypedQuery.class, RETURNS_SELF); when(em.createQuery(anyString(),eq(ReproofingNotificationImpl.class))).thenReturn(pending); when(pending.getResultList()).thenReturn(List.of(notification),List.of());
        when(em.find(ReproofingNotificationImpl.class,"execution")).thenReturn(notification); when(em.find(ReproofingNotificationImpl.class,"execution",LockModeType.PESSIMISTIC_WRITE)).thenReturn(notification);
        var user = mock(UserModel.class); when(user.getEmail()).thenReturn("current@example.test"); var users = mock(UserProvider.class); when(session.users()).thenReturn(users); when(users.getUserById(realm,"customer")).thenReturn(user);
        var profile = mock(UserProfileProvider.class); when(session.getProvider(UserProfileProvider.class)).thenReturn(profile); when(profile.getConfiguration()).thenReturn(mock(UPConfig.class));
        when(context.resolveLocale(user,false)).thenReturn(Locale.ENGLISH); when(context.getUri()).thenThrow(new ContextNotActiveException());
        var theme = mock(Theme.class); var messages = new Properties(); messages.setProperty("ffidCredentialsReplacedSubject","Credentials replaced"); when(theme.getEnhancedMessages(realm,Locale.ENGLISH)).thenReturn(messages); when(theme.getProperties()).thenReturn(new Properties());
        var renderer = mock(FreeMarkerProvider.class); when(session.getProvider(FreeMarkerProvider.class)).thenReturn(renderer);
        when(renderer.processTemplate(anyMap(),anyString(),eq(theme))).thenAnswer(call -> {
            Map<String,Object> attributes=call.getArgument(0); assertEquals(Locale.ENGLISH,attributes.get("locale")); assertNotNull(attributes.get("msg")); assertNotNull(attributes.get("user"));
            return call.getArgument(1,String.class).startsWith("text/") ? "text fixture" : "html fixture";
        });
        var transport = mock(EmailSenderProvider.class); when(session.getProvider(EmailSenderProvider.class)).thenReturn(transport); when(realm.getSmtpConfig()).thenReturn(Map.of("host","smtp.example.test"));
        var email = new FixtureEmailProviderImpl(session,theme); when(session.getProvider(EmailTemplateProvider.class)).thenReturn(email);
        try (var phases=mockStatic(NativePhases.class); var rpc=mockStatic(ReproofingRpcImpl.class); var crypto=mockStatic(ReproofingEngineImpl.class)) {
            phases.when(() -> NativePhases.run(eq(session),any())).thenAnswer(call -> ((Function<KeycloakSession,Object>)call.getArgument(1)).apply(session));
            crypto.when(() -> ReproofingEngineImpl.open("notification:execution","encrypted-prior-destination")).thenReturn("prior@example.test");
            assertEquals(1,new ReproofingDispatcherImpl(session).dispatch());
        }
        assertEquals("DELIVERED",notification.status); assertEquals(1,notification.attempts); assertTrue(notification.deliveredAt>0);
        verify(transport).send(eq(realm.getSmtpConfig()),eq("prior@example.test"),eq("Credentials replaced"),eq("text fixture"),eq("html fixture"));
    }
    private static final class FixtureEmailProviderImpl extends FreeMarkerEmailTemplateProvider {
        private final Theme theme;
        FixtureEmailProviderImpl(KeycloakSession session,Theme theme) { super(session); this.theme=theme; }
        @Override protected Theme getTheme() { return theme; }
    }
}
