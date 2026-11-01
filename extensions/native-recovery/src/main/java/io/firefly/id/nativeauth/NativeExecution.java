package io.firefly.id.nativeauth;

import jakarta.persistence.*;
import org.keycloak.util.JsonSerialization;
import java.time.Instant;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static io.firefly.id.nativeauth.NativeSecurityImpl.*;

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
    @Column(name="ceremony_id", length=1024, unique=true)
    public String ceremonyId;
    @Column(name="binding_json", length=8192)
    public String bindingJson;
    @Column(name="authorization_expires_at", length=64)
    public String authorizationExpiresAt;
    @Column(name="record_attempts")
    public int recordAttempts;
    @Column(name="recorded")
    public boolean recorded;
    @Column(name="outcome", length=1024)
    public String outcome;
    @Column(name="completed_at")
    public long completedAt;
    static NativeExecution committed(NativeCeremony ceremony, Authorization authorization, String outcome, long now) {
        require(authorization != null && authorization.binding().equals(NativeActorImpl.binding(ceremony))
                && authorization.operationId().toString().equals(ceremony.operationId));
        NativeExecution journal = new NativeExecution(); journal.id = authorization.executionId().toString();
        journal.realmId = ceremony.realmId; journal.subject = ceremony.subject; journal.generation = ceremony.generation;
        journal.ceremonyId = ceremony.id; journal.operationId = ceremony.operationId; journal.bindingJson = NativeActorImpl.json(authorization.binding());
        journal.bindingDigest = digest(journal.bindingJson); journal.authorizationExpiresAt = authorization.expiresAt().toString();
        journal.outcome = outcome; journal.completedAt = now; return journal;
    }
    Authorization authorization(NativeCeremony ceremony) {
        require(ceremonyId != null && ceremonyId.equals(ceremony.id) && realmId.equals(ceremony.realmId)
                && subject.equals(ceremony.subject) && generation.equals(ceremony.generation) && operationId.equals(ceremony.operationId)
                && bindingJson != null && bindingDigest.equals(digest(bindingJson)) && "SUCCEEDED".equals(outcome));
        try {
            Binding binding = JsonSerialization.readValue(bindingJson, Binding.class);
            require(binding.equals(NativeActorImpl.binding(ceremony)));
            return new Authorization(UUID.fromString(operationId), UUID.fromString(id), binding, Instant.parse(authorizationExpiresAt));
        } catch (Exception invalidJournal) { throw new NativeRefusal(); }
    }
    void requireAuthorization(NativeCeremony ceremony, Authorization expected) { require(authorization(ceremony).equals(expected)); }
    boolean reserveRecording(NativeCeremony ceremony, long now) {
        authorization(ceremony);
        // Keep the original signed capsule's second-granularity expiry, including on restart.
        require(ceremony.expiresAt / 1000 > now / 1000);
        if (recorded || recordAttempts >= 3) return false;
        recordAttempts++; return true;
    }
    @Override public String toString() { return "NativeExecution[REDACTED]"; }
}
