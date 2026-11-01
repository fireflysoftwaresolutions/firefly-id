package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.ReproofingContracts.NativeRequest;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.services.util.LocaleUtil;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import static io.firefly.id.nativeauth.NativeSecurity.*;

public final class ReproofingResourceImpl {
    private static final String COOKIE = "FF_REPROOFING";
    private final KeycloakSession session;
    public ReproofingResourceImpl(KeycloakSession session) { this.session = session; }
    @GET @Produces(MediaType.TEXT_HTML)
    public Response page() {
        try {
            secure(); var engine = new ReproofingEngineImpl(session); var cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE);
            if (cookie != null) { try { return render(engine.resume(cookie.getValue()), false); } catch (Exception expired) { /* A new ceremony never renews an old grant or subject epoch. */ } }
            return render(engine.create(), true);
        } catch (Exception refused) { return unavailable(); }
    }
    @POST @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Produces(MediaType.TEXT_HTML)
    public Response submit() {
        String id = null;
        try {
            secure(); var config = new ReproofingConfigImpl(session.getContext().getRealm());
            requireOrigin(session.getContext().getRequestHeaders().getHeaderString("Origin"), config.value("allowed-origin"));
            var cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE); require(cookie != null); id = cookie.getValue();
            var fields = form(session.getContext().getHttpRequest().getDecodedFormParameters(), session.getContext().getRequestHeaders().getLength());
            var engine = new ReproofingEngineImpl(session); String stage = engine.csrf(id, fields.get("csrf"));
            try {
                switch (stage) {
                    case "IDENTIFY" -> engine.identify(id, fields.get("username"));
                    case "VERIFY" -> engine.confirm(id);
                    case "ENROLL" -> { if (engine.replace(id, fields.get("password"), fields.get("passwordConfirm"), fields.get("otp"))) { try { engine.reconcile(id); } catch (Exception auditPending) { /* Exact committed journal remains available for audit-only retry. */ } } }
                    case "COMPLETE" -> engine.reconcile(id);
                    default -> throw new IllegalStateException("Recovery unavailable");
                }
            } catch (Exception unavailable) { engine.failed(id); }
            return Response.seeOther(java.net.URI.create(config.root())).header("Cache-Control", "no-store").build();
        } catch (Exception refused) { return unavailable(); }
    }
    @POST @Path("rpc/{route}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response rpc(@PathParam("route") String route, InputStream body) {
        try {
            secure(); byte[] bytes = body.readNBytes(16385); require(bytes.length <= 16384);
            Object result = "dispatch".equals(route) ? Map.of("processed", new ReproofingDispatcherImpl(session).dispatch())
                    : new ReproofingRpcImpl(session).call(route, ReproofingWireImpl.read(new String(bytes, StandardCharsets.UTF_8), NativeRequest.class));
            return Response.ok(ReproofingWireImpl.json(result)).header("Cache-Control", "no-store").build();
        } catch (Exception refused) { return Response.status(403).entity(Map.of("error", "recovery_unavailable")).header("Cache-Control", "no-store").build(); }
    }
    static Map<String, String> form(MultivaluedMap<String, String> decoded, int contentLength) {
        require(contentLength >= 0 && contentLength <= 16384 && decoded != null && !decoded.isEmpty() && decoded.size() <= 5);
        Map<String, String> fields = new java.util.HashMap<>(); int bytes = 0;
        for (var entry : decoded.entrySet()) {
            String name = entry.getKey(); var values = entry.getValue();
            require(java.util.Set.of("csrf", "username", "password", "passwordConfirm", "otp").contains(name)
                    && values != null && values.size() == 1 && values.get(0) != null);
            String value = values.get(0); require(value.length() <= 16384);
            bytes = Math.addExact(bytes, name.getBytes(StandardCharsets.UTF_8).length + value.getBytes(StandardCharsets.UTF_8).length + 1);
            require(bytes <= 16384); fields.put(name, value);
        }
        return fields;
    }
    private void secure() { require("https".equals(session.getContext().getUri().getBaseUri().getScheme())); new ReproofingConfigImpl(session.getContext().getRealm()); }
    private Response render(ReproofingEngineImpl.View view, boolean cookie) {
        LocaleUtil.processLocaleParam(session, session.getContext().getRealm(), null); var config = new ReproofingConfigImpl(session.getContext().getRealm());
        Response response = session.getProvider(LoginFormsProvider.class).setAttribute("stage", view.stage()).setAttribute("csrf", view.csrf())
                .setAttribute("verificationUrl", view.verificationUrl()).setAttribute("enrollmentSecret", view.secret()).setAttribute("passwordMinimum", view.passwordMinimum())
                .setAttribute("actionUrl", config.root()).setAttribute("signInUrl", config.value("issuer") + "/account")
                .setAttribute("recordPending", view.recordPending()).setAttribute("nativeCredentialForm", true).setAttribute("messageKey", view.failed() ? "ffidLostFailed" : null).createForm("firefly-lost-credentials.ftl");
        var builder = Response.fromResponse(response).header("Cache-Control", "no-store").header("Pragma", "no-cache").header("Referrer-Policy", "same-origin");
        if (cookie) builder.cookie(new NewCookie.Builder(COOKIE).value(view.id()).path("/realms/" + config.realm.getName() + "/firefly-recovery/lost-credentials")
                .secure(true).httpOnly(true).sameSite(NewCookie.SameSite.STRICT).maxAge(config.ttl()).build());
        return builder.build();
    }
    private Response unavailable() {
        LocaleUtil.processLocaleParam(session, session.getContext().getRealm(), null);
        var response = session.getProvider(LoginFormsProvider.class).setError("ffidLostFailed").createErrorPage(Response.Status.BAD_REQUEST);
        return Response.fromResponse(response).header("Cache-Control", "no-store").build();
    }
}
