package io.firefly.id.nativeauth;

import jakarta.persistence.*;

@Entity
@Table(name="ff_native_audit")
public class NativeAudit {
    @Id
    @Column(name="id", length=1024)
    public String id;
    @Column(name="realm_id", length=1024)
    public String realmId;
    @Column(name="subject", length=1024)
    public String subject;
    @Column(name="event_type", length=1024)
    public String eventType;
    @Column(name="reference_id", length=1024)
    public String referenceId;
    @Column(name="occurred_at")
    public long occurredAt;
    @Column(name="actor_realm_id", length=1024) public String actorRealmId;
    @Column(name="actor_subject", length=1024) public String actorSubject;
    @Column(name="actor_client_id", length=1024) public String actorClientId;
    @Column(name="admin_event_id", length=1024) public String adminEventId;
    @Override public String toString() { return "NativeAudit[REDACTED]"; }
}
