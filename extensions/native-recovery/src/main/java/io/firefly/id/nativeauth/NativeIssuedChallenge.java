package io.firefly.id.nativeauth;

import jakarta.persistence.*;
@Entity @Table(name="ff_native_issued_challenge")
public class NativeIssuedChallenge {
    @Id @Column(length=128) public String id;
    @Column(name="ceremony_id",length=128) public String ceremonyId;
    @Column(name="operation_id",length=64) public String operationId;
    @Column(name="reservation_id",length=64,unique=true) public String reservationId;
    @Column(length=32) public String category;
    @Column(name="credential_id",length=128) public String credentialId;
    @Column(name="expires_at") public long expiresAt;
    @Override public String toString() { return "NativeIssuedChallenge[REDACTED]"; }
}
