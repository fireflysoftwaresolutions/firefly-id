package io.firefly.id.nativeauth;

import jakarta.persistence.*;
@Entity @Table(name="ff_native_support_proof")
public class NativeSupportProof {
    @Id @Column(length=128) public String id;
    @Column(name="grant_digest",length=128,unique=true,updatable=false) public String grantDigest;
    @Column(name="nonce_digest",length=128,unique=true,updatable=false) public String nonceDigest;
    @Column(name="realm_id",length=64,updatable=false) public String realmId;
    @Column(length=128,updatable=false) public String subject;
    @Column(name="target_issuer",length=512,updatable=false) public String targetIssuer;
    @Column(name="pin_generation",length=128,updatable=false) public String pinGeneration;
    @Column(name="pin_credential_id",length=1024,updatable=false) public String pinCredentialId;
    @Column(name="pin_key_version",length=64,updatable=false) public String pinKeyVersion;
    @Column(name="staff_issuer",length=512,updatable=false) public String staffIssuer;
    @Column(name="staff_subject",length=512,updatable=false) public String staffSubject;
    @Column(name="case_id",length=512,updatable=false) public String caseId;
    @Column(name="call_id",length=512,updatable=false) public String callId;
    @Column(length=512,updatable=false) public String tenant;
    @Column(name="customer_link",length=512,updatable=false) public String customerLink;
    @Column(name="permitted_action",length=64,updatable=false) public String permittedAction;
    @Column(length=64,updatable=false) public String purpose;
    @Column(name="expires_at",updatable=false) public long expiresAt;
    @Column(name="reserved_at",updatable=false) public Long reservedAt;
    @Column(length=16) public String status;
    @Column(name="consumed_at") public Long consumedAt;
    public boolean verified;
    @Override public String toString() { return "NativeSupportProof[REDACTED]"; }
}
