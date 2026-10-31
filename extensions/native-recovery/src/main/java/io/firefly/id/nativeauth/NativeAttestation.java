package io.firefly.id.nativeauth;

import jakarta.persistence.*;

@Entity
@Table(name="ff_native_attestation")
public class NativeAttestation {
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
    @Column(name="ceremony_id", length=1024)
    public String ceremonyId;
    @Column(name="operation_id", length=1024)
    public String operationId;
    @Column(name="challenge_id", length=1024)
    public String challengeId;
    @Column(name="reservation_id", length=1024)
    public String reservationId;
    @Column(name="provider_challenge_id", length=1024)
    public String providerChallengeId;
    @Column(name="category", length=1024)
    public String category;
    @Column(name="credential_id", length=1024)
    public String credentialId;
    @Column(name="expires_at")
    public long expiresAt;
    @Column(name="verified") public boolean verified;
    @Column(name="completed") public boolean completed;
    @Override public String toString() { return "NativeAttestation[REDACTED]"; }
}
