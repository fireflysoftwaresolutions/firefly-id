package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.NativePhases;
import org.keycloak.models.KeycloakSession;
import org.keycloak.email.EmailTemplateProvider;
import jakarta.persistence.LockModeType;
import java.util.Map;
import static io.firefly.id.nativeauth.NativeSecurity.require;

/** Explicit bounded worker; durable leases survive process death without retaining request sessions. */
final class ReproofingDispatcherImpl {
    private final KeycloakSession request;
    ReproofingDispatcherImpl(KeycloakSession request) { this.request = request; }
    record Lease(String id, String token, boolean dispatch) { }
    static boolean owns(ReproofingNotificationImpl notification, String token) { return notification != null && "SENDING".equals(notification.status) && token != null && token.equals(notification.leaseToken); }
    static boolean expireFinalLease(ReproofingNotificationImpl notification, long now) {
        if (notification == null || !"SENDING".equals(notification.status) || notification.attempts < 8 || notification.nextAttemptAt > now) return false;
        notification.status = "FAILED"; notification.leaseToken = null; return true;
    }
    int dispatch() {
        String header = request.getContext().getRequestHeaders().getHeaderString("Authorization");
        NativePhases.run(request, child -> { ReproofingRpcImpl.workload(child, header, "dispatch"); return null; });
        int processed = 0;
        for (int n = 0; n < 10; n++) {
            Lease lease = NativePhases.run(request, child -> {
                var store = new ReproofingStoreImpl(child); long now = store.now();
                var rows = store.em.createQuery("select n from ReproofingNotificationImpl n where n.realmId = :realm and n.status in ('PENDING','SENDING') and n.nextAttemptAt <= :now and (n.attempts < 8 or (n.status = 'SENDING' and n.attempts = 8)) order by n.nextAttemptAt", ReproofingNotificationImpl.class)
                        .setParameter("realm", store.config.realm.getId()).setParameter("now", now).setLockMode(LockModeType.PESSIMISTIC_WRITE).setMaxResults(1).getResultList();
                if (rows.isEmpty()) return null; var notification = rows.get(0);
                if (expireFinalLease(notification, now)) return new Lease(notification.id, null, false);
                require(notification.attempts < 8); notification.attempts++; notification.status = "SENDING"; notification.nextAttemptAt = now + 60_000L; notification.leaseToken = java.util.UUID.randomUUID().toString(); return new Lease(notification.id, notification.leaseToken, true);
            });
            if (lease == null) break;
            if (!lease.dispatch()) { processed++; continue; }
            String id = lease.id();
            boolean delivered;
            try {
                NativePhases.run(request, child -> {
                    var store = new ReproofingStoreImpl(child); var notification = store.em.find(ReproofingNotificationImpl.class, id);
                    require(notification != null && notification.realmId.equals(store.config.realm.getId()));
                    var user = child.users().getUserById(store.config.realm, notification.subject); require(user != null);
                    String destination = ReproofingEngineImpl.open("notification:" + id, notification.destinationEncrypted);
                    try { child.getProvider(EmailTemplateProvider.class).setRealm(store.config.realm).setUser(user)
                            .send("ffidCredentialsReplacedSubject", "firefly-credentials-replaced.ftl", Map.of(), destination); }
                    catch (org.keycloak.email.EmailException unavailable) { throw new IllegalStateException("Notification unavailable"); }
                    return null;
                });
                delivered = true;
            } catch (Exception unavailable) { delivered = false; }
            final boolean success = delivered;
            NativePhases.run(request, child -> {
                var store = new ReproofingStoreImpl(child); var notification = store.em.find(ReproofingNotificationImpl.class, id, LockModeType.PESSIMISTIC_WRITE);
                if (!owns(notification, lease.token())) return null;
                if (success) { notification.status = "DELIVERED"; notification.deliveredAt = store.now(); }
                else { notification.status = notification.attempts >= 8 ? "FAILED" : "PENDING"; notification.nextAttemptAt = store.now() + Math.min(3600_000L, 30_000L * (1L << notification.attempts)); }
                return null;
            });
            processed++;
        }
        return processed;
    }
}
