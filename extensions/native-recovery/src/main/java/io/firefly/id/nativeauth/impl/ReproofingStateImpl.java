package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;

@Entity
@Table(name="ff_reproofing_state")
public class ReproofingStateImpl {
    @Id
    @Column(name="id", length=128)
    public String id;
    @Column(name="realm_id", length=512)
    public String realmId;
    @Column(name="subject", length=512)
    public String subject;
    @Column(name="epoch", length=128)
    public String epoch;
    @Column(name="failures")
    public int failures;
    @Column(name="invalidation_version")
    public long invalidationVersion;
    @Override public String toString() { return "ReproofingStateImpl[REDACTED]"; }
}
