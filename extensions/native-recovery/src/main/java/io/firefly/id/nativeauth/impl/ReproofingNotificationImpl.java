package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;

@Entity
@Table(name="ff_reproofing_notification")
public class ReproofingNotificationImpl {
    @Id
    @Column(name="id", length=64)
    public String id;
    @Column(name="realm_id", length=512)
    public String realmId;
    @Column(name="subject", length=512)
    public String subject;
    @Column(name="destination_encrypted", length=2048)
    public String destinationEncrypted;
    @Column(name="destination_digest", length=128)
    public String destinationDigest;
    @Column(name="created_at")
    public long createdAt;
    @Column(name="next_attempt_at")
    public long nextAttemptAt;
    @Column(name="delivered_at")
    public long deliveredAt;
    @Column(name="attempts")
    public int attempts;
    @Column(name="status", length=32)
    public String status;
    @Override public String toString() { return "ReproofingNotificationImpl[REDACTED]"; }
}
