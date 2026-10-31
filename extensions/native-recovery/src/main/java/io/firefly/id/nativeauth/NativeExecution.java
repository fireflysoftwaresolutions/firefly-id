package io.firefly.id.nativeauth;

import jakarta.persistence.*;

@Entity
@Table(name="ff_native_execution")
public class NativeExecution {
    @Id
    @Column(name="id", length=1024)
    public String id;
    @Column(name="realm_id", length=1024)
    public String realmId;
    @Column(name="subject", length=1024)
    public String subject;
    @Column(name="generation", length=1024)
    public String generation;
    @Column(name="operation_id", length=1024)
    public String operationId;
    @Column(name="binding_digest", length=1024)
    public String bindingDigest;
    @Column(name="outcome", length=1024)
    public String outcome;
    @Column(name="completed_at")
    public long completedAt;
    @Override public String toString() { return "NativeExecution[REDACTED]"; }
}
