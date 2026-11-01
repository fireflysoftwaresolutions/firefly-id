package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class NativeActor {
    static String sign(KeycloakSession session, NativeCeremony ceremony) {
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
        Binding binding = binding(ceremony);
        AccessToken token = new AccessToken();
        token.id(ceremony.id); token.subject(binding.actorSubject()); token.issuer(profile.issuer());
        token.iat(Instant.now().getEpochSecond()); token.exp(ceremony.expiresAt / 1000);
        token.type("firefly-restricted-recovery"); token.issuedFor(profile.clientId());
        token.audience(profile.domainAudience(), profile.coreAudience());
        token.setOtherClaims("client_id", profile.clientId()); token.setOtherClaims("principal_kind", profile.population());
        token.setOtherClaims("tenant_id", binding.tenant()); token.setOtherClaims("recovery_only", true);
        token.setOtherClaims("recovery_purpose", PURPOSE); token.setOtherClaims("recovery_ceremony_id", ceremony.id);
        token.setOtherClaims("recovery_lock_generation", ceremony.generation);
        token.setOtherClaims("recovery_realm", session.getContext().getRealm().getName());
        token.setScope("firefly.recovery");
        token.setOtherClaims("HUMAN".equals(profile.population()) ? "party_id" : "staff_actor_id", ceremony.ownerLink);
        return session.tokens().encode(token);
    }
    static NativeCeremony verify(KeycloakSession session, String assertion, Binding expected) {
        require(assertion != null && assertion.length() <= 16384);
        AccessToken token;
        try { token = session.tokens().decode(assertion, AccessToken.class); } catch (Exception error) { throw new NativeRefusal(); }
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
        require(token != null && token.getExp() != null && token.getExp() > Instant.now().getEpochSecond()
                && token.getIat() != null && token.getIat() <= Instant.now().getEpochSecond() + 10
                && token.isActive(0) && "firefly-restricted-recovery".equals(token.getType())
                && profile.issuer().equals(token.getIssuer()) && profile.clientId().equals(token.getIssuedFor())
                && token.getAudience() != null && Set.copyOf(Arrays.asList(token.getAudience())).equals(Set.of(profile.domainAudience(), profile.coreAudience())));
        var claims = token.getOtherClaims();
        require(Boolean.TRUE.equals(claims.get("recovery_only")) && PURPOSE.equals(claims.get("recovery_purpose"))
                && "firefly.recovery".equals(token.getScope()) && profile.clientId().equals(claims.get("client_id"))
                && profile.population().equals(claims.get("principal_kind")) && !claims.containsKey("roles") && !claims.containsKey("authorities"));
        require(!claims.containsKey("HUMAN".equals(profile.population()) ? "staff_actor_id" : "party_id"));
        Object ceremonyId = claims.get("recovery_ceremony_id"); require(ceremonyId instanceof String);
        NativeCeremony ceremony = new NativeStoreImpl(session).ceremony((String) ceremonyId);
        require(token.getExp() == ceremony.expiresAt / 1000 && token.getIat() >= token.getExp() - profile.ttlSeconds()
                && token.getId().equals(ceremony.id) && token.getSubject().equals(ceremony.subject)
                && ceremony.generation.equals(claims.get("recovery_lock_generation"))
                && session.getContext().getRealm().getName().equals(claims.get("recovery_realm"))
                && ceremony.ownerLink.equals(claims.get("HUMAN".equals(profile.population()) ? "party_id" : "staff_actor_id"))
                && binding(ceremony).equals(expected) && expected.tenant().equals(claims.get("tenant_id")));
        return ceremony;
    }
    static Binding binding(NativeCeremony ceremony) {
        try { return JsonSerialization.readValue(ceremony.bindingJson, Binding.class); } catch (Exception error) { throw new NativeRefusal(); }
    }
    static String json(Object value) {
        try { return JsonSerialization.writeValueAsString(value); } catch (Exception error) { throw new NativeRefusal(); }
    }
}
