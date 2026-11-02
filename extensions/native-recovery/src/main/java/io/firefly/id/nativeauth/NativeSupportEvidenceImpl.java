package io.firefly.id.nativeauth;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import static io.firefly.id.nativeauth.NativeSecurityImpl.*;

/** Pure checks and transitions; callers hold customer, state, then proof locks in one transaction. */
final class NativeSupportEvidenceImpl {
    private NativeSupportEvidenceImpl() { }
    static void validate(NativeSupportAuthorization.Grant grant, String issuer, String realm, Instant now) {
        require(grant != null && now != null);
        bounded(grant.nonce(), 512); bounded(grant.targetIssuer(), 512); bounded(grant.realm(), 512);
        bounded(grant.subject(), 128); bounded(grant.tenant(), 512); bounded(grant.customerLink(), 512);
        bounded(grant.staffIssuer(), 512); bounded(grant.staffSubject(), 512);
        bounded(grant.caseId(), 512); bounded(grant.callId(), 512);
        bounded(grant.permittedAction(), 64); bounded(grant.purpose(), 64);
        require(!issuerIdentity(grant.targetIssuer()).equals(issuerIdentity(grant.staffIssuer())));
        require(issuer.equals(grant.targetIssuer()) && realm.equals(grant.realm())
                && "VERIFY_SUPPORT_PIN".equals(grant.permittedAction())
                && "TELEPHONE_SUPPORT_KNOWLEDGE".equals(grant.purpose())
                && grant.expiresAt() != null && grant.expiresAt().isAfter(now)
                && !grant.expiresAt().isAfter(now.plusSeconds(120)));
    }
    private static void bounded(String value, int maximum) {
        require(value != null && !value.isBlank() && value.equals(value.strip()) && value.length() <= maximum
                && value.codePoints().noneMatch(Character::isISOControl));
    }
    private static String issuerIdentity(String value) {
        try {
            URI uri = URI.create(value);
            require("https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
                    && uri.getRawQuery() == null && uri.getRawFragment() == null
                    && (uri.getPort() == -1 || uri.getPort() > 0 && uri.getPort() <= 65535));
            String path = new URI(null, null, uri.getPath(), null).normalize().getPath();
            while (path.endsWith("/")) path = path.substring(0, path.length() - 1);
            return uri.getHost().toLowerCase(Locale.ROOT) + ":" + (uri.getPort() == -1 ? 443 : uri.getPort()) + path;
        } catch (Exception invalid) { throw new NativeRefusal(); }
    }
    static String nonceDigest(String realmId, String configuredIssuer, String nonce) {
        return digest(NativeActorImpl.json(List.of("support-nonce-v1", realmId, configuredIssuer, nonce)));
    }
    static String grantDigest(NativeSupportAuthorization.Grant grant) { return digest(NativeActorImpl.json(grant)); }
    static NativeSupportProof reserve(NativeSupportAuthorization.Grant grant, String realmId, NativeState state, Instant now) {
        requireActive(state);
        require(grant.expiresAt().isAfter(now));
        require(state.pinFailures + state.pinReserved < 3 && realmId.equals(state.realmId) && grant.subject().equals(state.subject));
        var proof = new NativeSupportProof(); proof.id = randomToken();
        proof.nonceDigest = nonceDigest(realmId, grant.targetIssuer(), grant.nonce()); proof.grantDigest = grantDigest(grant);
        proof.realmId = realmId; proof.subject = grant.subject(); proof.targetIssuer = grant.targetIssuer();
        proof.pinGeneration = state.pinGeneration; proof.pinCredentialId = state.pinCredentialId; proof.pinKeyVersion = state.pinKeyVersion;
        proof.staffIssuer = grant.staffIssuer(); proof.staffSubject = grant.staffSubject(); proof.caseId = grant.caseId(); proof.callId = grant.callId();
        proof.tenant = grant.tenant(); proof.customerLink = grant.customerLink(); proof.permittedAction = grant.permittedAction(); proof.purpose = grant.purpose();
        proof.expiresAt = grant.expiresAt().toEpochMilli(); proof.reservedAt = now.toEpochMilli(); proof.status = "RESERVED";
        state.pinReserved++; return proof;
    }
    static void requireActive(NativeState state) {
        require(state != null && !state.locked && !state.hold && !state.pinHeld && state.pinRevokedAt == 0
                && state.pinFailures >= 0 && state.pinFailures < 3 && state.pinReserved >= 0 && state.pinReserved <= 3 && state.pinFailures + state.pinReserved <= 3
                && state.pinCredentialId != null && state.pinGeneration != null && state.pinKeyVersion != null);
    }
    static void requireLive(NativeSupportProof proof, NativeSupportAuthorization.Grant grant, String realmId,
            NativeState state, boolean enabled, String tenant, String customerLink, Instant now) {
        requireActive(state);
        require(enabled && grant.tenant().equals(tenant) && grant.customerLink().equals(customerLink)
                && realmId.equals(state.realmId) && grant.subject().equals(state.subject));
        require(proof != null && proof.status != null && proof.reservedAt != null && proof.consumedAt == null
                && realmId.equals(proof.realmId) && grant.subject().equals(proof.subject)
                && grantDigest(grant).equals(proof.grantDigest)
                && nonceDigest(realmId, grant.targetIssuer(), grant.nonce()).equals(proof.nonceDigest)
                && state.pinGeneration.equals(proof.pinGeneration) && state.pinCredentialId.equals(proof.pinCredentialId)
                && state.pinKeyVersion.equals(proof.pinKeyVersion)
                && grant.expiresAt().isAfter(now) && proof.expiresAt > now.toEpochMilli()
                && proof.expiresAt == grant.expiresAt().toEpochMilli()
                && grant.targetIssuer().equals(proof.targetIssuer) && grant.staffIssuer().equals(proof.staffIssuer)
                && grant.staffSubject().equals(proof.staffSubject) && grant.caseId().equals(proof.caseId)
                && grant.callId().equals(proof.callId) && grant.tenant().equals(proof.tenant)
                && grant.customerLink().equals(proof.customerLink) && grant.permittedAction().equals(proof.permittedAction)
                && grant.purpose().equals(proof.purpose));
    }
    static void complete(NativeSupportProof proof, NativeState state, boolean accepted) {
        requireActive(state);
        require(proof != null && "RESERVED".equals(proof.status) && !proof.verified && proof.consumedAt == null
                && Objects.equals(state.pinGeneration, proof.pinGeneration) && state.pinReserved > 0);
        proof.verified = accepted; proof.status = accepted ? "VERIFIED" : "REJECTED"; state.pinReserved--;
        if (!accepted) { state.pinFailures++; if (state.pinFailures == 3) state.pinHeld = true; }
    }
    static void consume(NativeSupportProof proof, NativeSupportAuthorization.Grant grant, String realmId,
            NativeState state, boolean enabled, String tenant, String customerLink, Instant now) {
        requireLive(proof, grant, realmId, state, enabled, tenant, customerLink, now);
        require("VERIFIED".equals(proof.status) && proof.verified);
        proof.status = "CONSUMED"; proof.consumedAt = now.toEpochMilli();
    }
}
