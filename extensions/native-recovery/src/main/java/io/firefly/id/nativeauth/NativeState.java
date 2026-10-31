package io.firefly.id.nativeauth;

import jakarta.persistence.*;

@Entity
@Table(name="ff_native_state")
public class NativeState {
    @Id
    @Column(name="id", length=1024)
    public String id;
    @Column(name="realm_id", length=1024)
    public String realmId;
    @Column(name="subject", length=1024)
    public String subject;
    @Column(name="generation", length=1024)
    public String generation;
    @Column(name="credential_revision", length=1024)
    public String credentialRevision;
    @Column(name="locked")
    public boolean locked;
    @Column(name="hold")
    public boolean hold;
    @Column(name="bootstrap_attempts")
    public int bootstrapAttempts;
    @Column(name="knowledge_attempts")
    public int knowledgeAttempts;
    @Column(name="possession_attempts")
    public int possessionAttempts;
    @Column(name="locked_at")
    public long lockedAt;
    @Column(name="pin_credential_id", length=1024)
    public String pinCredentialId;
    @Column(name="pin_key_version", length=1024)
    public String pinKeyVersion;
    @Column(name="pin_generation", length=1024)
    public String pinGeneration;
    @Column(name="pin_failures")
    public int pinFailures;
    @Column(name="pin_held")
    public boolean pinHeld;
    @Column(name="pin_created_at")
    public long pinCreatedAt;
    @Column(name="pin_replaced_at")
    public long pinReplacedAt;
    @Column(name="pin_revoked_at")
    public long pinRevokedAt;
    @Column(name="pin_reserved") public int pinReserved;
    @Override public String toString() { return "NativeState[REDACTED]"; }
}
