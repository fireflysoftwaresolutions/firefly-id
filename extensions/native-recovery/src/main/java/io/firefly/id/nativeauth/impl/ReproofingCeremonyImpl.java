package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;

@Entity
@Table(name="ff_reproofing_ceremony")
public class ReproofingCeremonyImpl {
    @Id
    @Column(name="id", length=128)
    public String id;
    @Column(name="realm_id", length=512)
    public String realmId;
    @Column(name="subject", length=512)
    public String subject;
    @Column(name="binding_json", length=8192)
    public String bindingJson;
    @Column(name="csrf_digest", length=128)
    public String csrfDigest;
    @Column(name="stage", length=32)
    public String stage;
    @Column(name="expires_at")
    public long expiresAt;
    @Column(name="case_id", length=64)
    public String caseId;
    @Column(name="authorization_json", length=8192)
    public String authorizationJson;
    @Column(name="verification_url", length=2048)
    public String verificationUrl;
    @Column(name="encrypted_totp", length=2048)
    public String encryptedTotp;
    @Column(name="notification_destination", length=512)
    public String notificationDestination;
    @Column(name="failed")
    public boolean failed;
    @Override public String toString() { return "ReproofingCeremonyImpl[REDACTED]"; }
}
