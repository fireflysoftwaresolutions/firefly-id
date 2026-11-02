package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;

@Entity
@Table(name="ff_reproofing_execution")
public class ReproofingExecutionImpl {
    @Id
    @Column(name="id", length=64)
    public String id;
    @Column(name="realm_id", length=512)
    public String realmId;
    @Column(name="ceremony_id", length=128)
    public String ceremonyId;
    @Column(name="case_id", length=64)
    public String caseId;
    @Column(name="authorization_id", length=64)
    public String authorizationId;
    @Column(name="binding_json", length=8192)
    public String bindingJson;
    @Column(name="authorization_json", length=8192)
    public String authorizationJson;
    @Column(name="committed_at")
    public long committedAt;
    @Column(name="recorded")
    public boolean recorded;
    @Column(name="record_attempts")
    public int recordAttempts;
    @Override public String toString() { return "ReproofingExecutionImpl[REDACTED]"; }
}
