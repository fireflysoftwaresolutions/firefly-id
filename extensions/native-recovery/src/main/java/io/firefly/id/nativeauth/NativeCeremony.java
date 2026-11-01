package io.firefly.id.nativeauth;

import jakarta.persistence.*;

@Entity
@Table(name="ff_native_ceremony")
public class NativeCeremony {
    @Id
    @Column(name="id", length=1024)
    public String id;
    @Column(name="realm_id", length=1024)
    public String realmId;
    @Column(name="subject", length=1024)
    public String subject;
    @Column(name="csrf_digest", length=1024)
    public String csrfDigest;
    @Column(name="expires_at")
    public long expiresAt;
    @Column(name="stage", length=1024)
    public String stage;
    @Column(name="failed", nullable=false)
    public boolean failed;
    @Column(name="generation", length=1024)
    public String generation;
    @Column(name="binding_json", length=8192)
    public String bindingJson;
    @Column(name="owner_link", length=1024)
    public String ownerLink;
    @Column(name="operation_id", length=1024)
    public String operationId;
    @Column(name="knowledge_challenge_id", length=1024)
    public String knowledgeChallengeId;
    @Column(name="possession_challenge_id", length=1024)
    public String possessionChallengeId;
    @Override public String toString() { return "NativeCeremony[REDACTED]"; }
}
