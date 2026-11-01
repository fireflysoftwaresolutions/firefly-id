package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.NativePhasesImpl;
import io.firefly.id.nativeauth.ReproofingContracts.NotificationStatus;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import java.time.Instant;

/** Read-only aggregate: one database statement supplies the realm snapshot and its clock. */
final class ReproofingNotificationStatusImpl {
    private final KeycloakSession request;
    ReproofingNotificationStatusImpl(KeycloakSession request) { this.request = request; }
    NotificationStatus status() {
        String header = request.getContext().getRequestHeaders().getHeaderString("Authorization");
        return NativePhasesImpl.run(request, child -> {
            ReproofingRpcImpl.authenticate(child, header, "notification-status");
            return read(child);
        });
    }
    static NotificationStatus read(KeycloakSession session) {
        var row = (Object[]) session.getProvider(JpaConnectionProvider.class).getEntityManager().createNativeQuery("""
                with snapshot as (select cast(extract(epoch from current_timestamp) * 1000 as bigint) as now)
                select snapshot.now,
                    count(n.id) filter (where n.status = 'PENDING'),
                    count(n.id) filter (where n.status = 'SENDING'),
                    count(n.id) filter (where n.status = 'PENDING' and n.attempts > 0),
                    count(n.id) filter (where n.status = 'DELIVERED'),
                    count(n.id) filter (where n.status = 'FAILED'),
                    count(n.id) filter (where n.status is null or n.status not in ('PENDING','SENDING','DELIVERED','FAILED')),
                    count(n.id) filter (where n.status in ('PENDING','SENDING') and n.next_attempt_at <= snapshot.now),
                    coalesce(max(greatest(0, snapshot.now - n.next_attempt_at) / 1000)
                        filter (where n.status in ('PENDING','SENDING') and n.next_attempt_at <= snapshot.now), 0)
                from snapshot left join ff_reproofing_notification n on n.realm_id = :realm
                group by snapshot.now
                """).setParameter("realm", session.getContext().getRealm().getId()).getSingleResult();
        return new NotificationStatus(Instant.ofEpochMilli(number(row[0])), number(row[1]), number(row[2]), number(row[3]),
                number(row[4]), number(row[5]), number(row[6]), number(row[7]), number(row[8]));
    }
    private static long number(Object value) { return ((Number) value).longValue(); }
}
