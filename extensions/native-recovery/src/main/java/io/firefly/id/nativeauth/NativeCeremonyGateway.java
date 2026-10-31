package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import java.util.UUID;
import static io.firefly.id.nativeauth.NativeContracts.*;

/** Real Domain/Core transport supplied by product integration. Every call runs without a native transaction. */
public interface NativeCeremonyGateway {
    Started begin(String restrictedActorAssertion);
    Reservation reserve(String restrictedActorAssertion, UUID operationId, UUID challengeId);
    void complete(String restrictedActorAssertion, Reservation reservation, String opaqueAttestation);
    Authorization consume(String restrictedActorAssertion, UUID operationId);
    Authorization verifyAuthorization(String restrictedActorAssertion, Authorization expected);
    void recordExecution(String restrictedActorAssertion, Authorization authorization, String outcome);
    interface Factory {
        /** Qualification requires real authenticated owner callbacks; no sandbox success factory is admissible. */
        default boolean isQualified() { return false; }
        NativeCeremonyGateway create(KeycloakSession session);
    }
}
