package io.firefly.id.nativeauth;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.models.credential.OTPCredentialModel;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import static io.firefly.id.nativeauth.NativeSecurity.*;

final class NativeCredentials {
    static boolean totp(KeycloakSession session, UserModel user, String credentialId, String code) {
        require(code != null && code.matches("[0-9]{6,8}") && !session.getContext().getRealm().getOTPPolicy().isCodeReusable());
        CredentialModel credential = user.credentialManager().getStoredCredentialById(credentialId); require(credential != null);
        OTPCredentialModel model = OTPCredentialModel.createFromCredentialModel(credential);
        require(OTPCredentialModel.TOTP.equals(model.getOTPCredentialData().getSubType()));
        if (!user.credentialManager().isValid(new UserCredentialModel(credentialId, OTPCredentialModel.TYPE, code))) return false;
        byte[] key = model.getDecodedSecret();
        try {
            Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
            String id = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal((credentialId + ":" + code).getBytes(StandardCharsets.UTF_8)));
            NativeStoreImpl store = new NativeStoreImpl(session); NativeTotpReplay replay = store.em.find(NativeTotpReplay.class, id);
            long now = System.currentTimeMillis();
            if (replay != null && replay.expiresAt > now) return false;
            if (replay == null) { replay = new NativeTotpReplay(); replay.id = id; store.em.persist(replay); }
            long lifespan = (long) model.getOTPCredentialData().getPeriod() * (2L * session.getContext().getRealm().getOTPPolicy().getLookAheadWindow() + 1L) * 1000L;
            replay.expiresAt = now + lifespan; return true;
        } catch (Exception error) { throw new NativeRefusal(); }
        finally { Arrays.fill(key, (byte) 0); }
    }
}
