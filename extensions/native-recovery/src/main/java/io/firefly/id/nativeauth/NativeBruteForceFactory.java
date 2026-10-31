package io.firefly.id.nativeauth;

import org.keycloak.Config;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.services.managers.*;
import jakarta.ws.rs.core.UriInfo;
import java.util.Set;

/** Version-pinned internal SPI. Admission locks the existing local user row before native failure state. */
public final class NativeBruteForceFactory implements BruteForceProtectorFactory {
    private final DefaultBruteForceProtectorFactory fallbackFactory = new DefaultBruteForceProtectorFactory();
    @Override public String getId() { return "firefly-native-recovery"; }
    @Override public BruteForceProtector create(KeycloakSession session) {
        BruteForceProtector fallback = fallbackFactory.create(session);
        BruteForceProtector managedProtector = new DefaultBruteForceProtector(session.getKeycloakSessionFactory()) {
            private boolean managed(RealmModel realm) { return realm.getAttribute("firefly.native-recovery.population") != null; }
            @Override protected UserLoginFailureModel getUserFailureModel(KeycloakSession current, RealmModel realm, String subject) {
                if (managed(realm)) { NativeProfile.of(realm); new NativeStore(current).local(subject, false); }
                return super.getUserFailureModel(current, realm, subject);
            }
            @Override public boolean isPermanentlyLockedOut(KeycloakSession current, RealmModel realm, UserModel user) {
                if (managed(realm) && !new NativeStore(current).local(user.getId(), true).isEnabled()) return true;
                return super.isPermanentlyLockedOut(current, realm, user);
            }
            @Override protected void processLogin(RealmModel realm, UserModel user, ClientConnection connection, UriInfo uri, boolean success, Set<String> categories) {
                if (success) success(session, realm, user.getId(), categories);
                else failure(session, realm, user.getId(), connection.getRemoteHost(), Time.currentTimeMillis(), categories);
            }
            @Override public void failure(KeycloakSession current, RealmModel realm, String subject, String address, long time, Set<String> categories) {
                if (managed(realm)) {
                    var user = new NativeStore(current).local(subject, false);
                    current.setAttribute(NativeLockCapture.TRANSITION + subject, user.isEnabled());
                    if (!user.isEnabled()) return;
                }
                super.failure(current, realm, subject, address, time, categories);
            }
            @Override protected void success(KeycloakSession current, RealmModel realm, String subject, Set<String> categories) {
                if (managed(realm) && !new NativeStore(current).local(subject, false).isEnabled()) return;
                super.success(current, realm, subject, categories);
            }
            @Override protected void sendEvent(KeycloakSession current, RealmModel realm, UserLoginFailureModel failure, EventType type) {
                if (managed(realm) && type == EventType.USER_DISABLED_BY_PERMANENT_LOCKOUT) NativeLockCapture.capture(current, failure.getUserId());
                super.sendEvent(current, realm, failure, type);
            }
        };
        return new BruteForceProtector() {
            private BruteForceProtector selected(RealmModel realm, UserModel user) {
                return realm.getAttribute("firefly.native-recovery.population") != null
                        && org.keycloak.storage.StorageId.isLocalStorage(user.getId()) && !user.isFederated() && !user.isServiceAccount()
                        && !new NativeStore(session).isAdministrator(user)
                        ? managedProtector : fallback;
            }
            @Override public void failedLogin(RealmModel realm, UserModel user, ClientConnection connection, UriInfo uri, Set<String> categories) { selected(realm, user).failedLogin(realm, user, connection, uri, categories); }
            @Override public void successfulLogin(RealmModel realm, UserModel user, ClientConnection connection, UriInfo uri, Set<String> categories) { selected(realm, user).successfulLogin(realm, user, connection, uri, categories); }
            @Override public boolean isTemporarilyDisabled(KeycloakSession current, RealmModel realm, UserModel user) { return selected(realm, user).isTemporarilyDisabled(current, realm, user); }
            @Override public boolean isPermanentlyLockedOut(KeycloakSession current, RealmModel realm, UserModel user) { return selected(realm, user).isPermanentlyLockedOut(current, realm, user); }
            @Override public void cleanUpPermanentLockout(KeycloakSession current, RealmModel realm, UserModel user) { selected(realm, user).cleanUpPermanentLockout(current, realm, user); }
            @Override public void close() { managedProtector.close(); fallback.close(); }
        };
    }
    @Override public void init(Config.Scope config) { fallbackFactory.init(config); }
    @Override public void postInit(KeycloakSessionFactory factory) { fallbackFactory.postInit(factory); }
    @Override public void close() { fallbackFactory.close(); }
}
