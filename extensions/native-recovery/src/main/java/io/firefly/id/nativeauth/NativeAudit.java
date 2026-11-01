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
    @Column(name="actor_issuer", length=512) public String actorIssuer;
    @Column(name="support_grant_digest", length=128) public String supportGrantDigest;
    @Column(name="support_nonce_digest", length=128) public String supportNonceDigest;
    @Column(name="support_case_id", length=512) public String supportCaseId;
    @Column(name="support_call_id", length=512) public String supportCallId;
    @Column(name="support_tenant", length=512) public String supportTenant;
    @Column(name="support_customer_link", length=512) public String supportCustomerLink;
    @Column(name="support_action", length=64) public String supportAction;
    @Column(name="support_purpose", length=64) public String supportPurpose;
    @Column(name="support_pin_generation", length=128) public String supportPinGeneration;
    @Override public String toString() { return "NativeAudit[REDACTED]"; }
}
