package io.firefly.id.nativeauth;

import jakarta.persistence.*;
@Entity @Table(name="ff_native_support_proof")
public class NativeSupportProof {
    @Id @Column(length=128) public String id;
    @Column(name="grant_digest",length=128,unique=true) public String grantDigest;
    @Column(name="realm_id",length=64) public String realmId;
    @Column(length=128) public String subject;
    @Column(name="pin_generation",length=128) public String pinGeneration;
    @Column(name="expires_at") public long expiresAt;
    public boolean verified;
    @Override public String toString() { return "NativeSupportProof[REDACTED]"; }
}
