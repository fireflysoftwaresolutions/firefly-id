package io.firefly.id.nativeauth.impl;

import jakarta.persistence.*;

@Entity
@Table(name="ff_reproofing_realm_policy")
public class ReproofingRealmPolicyEntityImpl {
    @Id @Column(name="id", length=512) public String id;
    @Column(name="revision", nullable=false) public long revision;
    @Override public String toString() { return "ReproofingRealmPolicy[REDACTED]"; }
}
