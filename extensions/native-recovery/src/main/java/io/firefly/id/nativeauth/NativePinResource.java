package io.firefly.id.nativeauth;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AuthenticationManager;
import static io.firefly.id.nativeauth.NativeSecurity.*;

public final class NativePinResource {
    private static final String COOKIE = "FF_NATIVE_PIN";
    private final KeycloakSession session;
    NativePinResource(KeycloakSession session) { this.session = session; }
    private String subject() {
        require("https".equals(session.getContext().getUri().getBaseUri().getScheme()));
        require("HUMAN".equals(NativeProfile.of(session.getContext().getRealm()).population()));
        var auth = AuthenticationManager.authenticateIdentityCookie(session, session.getContext().getRealm(), true);
        require(auth != null && auth.user() != null && auth.user().isEnabled() && !auth.user().isServiceAccount()); return auth.user().getId();
    }
    @GET @Produces(MediaType.TEXT_HTML)
    public Response status() {
        try { String subject = subject(); return view(subject, "STATUS", failed(subject) ? "ffidPinFailed" : null); }
        catch (Exception refusal) { return refused(); }
    }
    @GET @Path("set") @Produces(MediaType.TEXT_HTML)
    public Response set() { try { return view(subject(), "SET", null); } catch (Exception refusal) { return refused(); } }
    @GET @Path("revoke") @Produces(MediaType.TEXT_HTML)
    public Response revoke() { try { return view(subject(), "REVOKE", null); } catch (Exception refusal) { return refused(); } }
    @POST @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Produces(MediaType.TEXT_HTML)
    public Response update(@FormParam("csrf") String csrf, @FormParam("password") String password, @FormParam("otp") String otp,
            @FormParam("pin") String pin, @FormParam("pinConfirm") String confirmation) {
        try {
            String subject = subject(); NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            requireOrigin(session.getContext().getRequestHeaders().getHeaderString("Origin"), profile.origin());
            var cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE); require(cookie != null);
            boolean revoke = NativePhases.run(session, child -> {
                NativeStore store = new NativeStore(child); NativeCeremony ceremony = store.ceremony(cookie.getValue());
                require(subject.equals(ceremony.subject) && matches(csrf, ceremony.csrfDigest)
                        && ("PIN_SET".equals(ceremony.stage) || "PIN_REVOKE".equals(ceremony.stage)));
                boolean result = "PIN_REVOKE".equals(ceremony.stage); ceremony.csrfDigest = null; ceremony.stage = "USED"; return result;
            });
            boolean success;
            try { success = new NativePinEngine(session).replace(subject, password, otp, pin, confirmation, revoke); }
            catch (Exception unavailable) { success = false; }
            boolean failed = !success;
            NativePhases.run(session, child -> {
                NativeCeremony ceremony = new NativeStore(child).storedCeremony(cookie.getValue());
                setFeedback(ceremony, subject, failed); return null;
            });
            return Response.seeOther(java.net.URI.create(profile.issuer() + "/" + NativeContracts.EXTENSION + "/support-pin"))
                    .header("Cache-Control", "no-store").build();
        } catch (Exception refusal) { return refused(); }
    }
    static void setFeedback(NativeCeremony ceremony, String subject, boolean failed) {
        require(subject.equals(ceremony.subject) && "USED".equals(ceremony.stage)); ceremony.failed = failed;
    }
    private boolean failed(String subject) {
        var cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE);
        if (cookie == null) return false;
        try {
            return NativePhases.run(session, child -> {
                NativeCeremony ceremony = new NativeStore(child).ceremony(cookie.getValue());
                return subject.equals(ceremony.subject) && "USED".equals(ceremony.stage) && ceremony.failed;
            });
        } catch (NativeRefusal expired) { return false; }
    }
    private Response view(String subject, String stage, String message) {
        String csrf = "STATUS".equals(stage) ? "" : randomToken();
        String ceremonyId = "STATUS".equals(stage) ? null : NativePhases.run(session, child -> {
            NativeStore store = new NativeStore(child); var user = store.local(subject, true); require(user.isEnabled());
            NativeCeremony c = new NativeCeremony(); c.id = randomToken(); c.realmId = child.getContext().getRealm().getId(); c.subject = subject;
            c.csrfDigest = digest(csrf); c.stage = "REVOKE".equals(stage) ? "PIN_REVOKE" : "PIN_SET";
            c.expiresAt = System.currentTimeMillis() + 120000; store.em.persist(c); return c.id;
        });
        NativeContracts.PinStatus status = new NativePinEngine(session).status(subject);
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm()); String base = profile.issuer() + "/" + NativeContracts.EXTENSION + "/support-pin";
        Response response = session.getProvider(LoginFormsProvider.class).setAttribute("stage", stage).setAttribute("csrf", csrf)
                .setAttribute("actionUrl", "STATUS".equals(stage) ? base + "/set" : base).setAttribute("accountUrl", profile.issuer() + "/account")
                .setAttribute("revokeUrl", base + "/revoke").setAttribute("pinStatus", status.status())
                .setAttribute("replacedAt", status.replacedAt() == null ? null : status.replacedAt().toString())
                .setAttribute("messageKey", message).setAttribute("nativeCredentialForm", true).createForm("firefly-support-pin.ftl");
        var builder = Response.fromResponse(response).header("Cache-Control", "no-store");
        if (ceremonyId != null) builder.cookie(new NewCookie.Builder(COOKIE).value(ceremonyId)
                .path("/realms/" + session.getContext().getRealm().getName() + "/" + NativeContracts.EXTENSION + "/support-pin").secure(true).httpOnly(true)
                .sameSite(NewCookie.SameSite.STRICT).maxAge(120).build());
        return builder.build();
    }
    private Response refused() {
        Response response = session.getProvider(LoginFormsProvider.class).setError("ffidPinFailed").createErrorPage(Response.Status.FORBIDDEN);
        return Response.fromResponse(response).header("Cache-Control", "no-store").build();
    }
}
