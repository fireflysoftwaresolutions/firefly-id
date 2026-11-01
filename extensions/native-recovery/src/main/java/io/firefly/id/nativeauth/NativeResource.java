package io.firefly.id.nativeauth;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import jakarta.ws.rs.ext.Provider;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import java.util.ServiceLoader;
import static io.firefly.id.nativeauth.NativeContracts.*;
import static io.firefly.id.nativeauth.NativeSecurity.*;

/** Synchronous native pages. Every HTTP callback runs after the preceding native phase committed. */
@Provider
public final class NativeResource {
    private static final String COOKIE = "FF_NATIVE_RECOVERY";
    private final KeycloakSession session;
    public NativeResource(KeycloakSession session) { this.session = session; }
    @GET @Produces(MediaType.TEXT_HTML)
    public Response page() {
        try { require("https".equals(session.getContext().getUri().getBaseUri().getScheme()));
            var existing = session.getContext().getRequestHeaders().getCookies().get(COOKIE);
            if (existing != null) {
                try { return render(new NativeEngine(session).resume(existing.getValue()), false); }
                catch (NativeRefusal expired) { /* A fresh ceremony gets a fresh CSRF state. */ }
            }
            return render(new NativeEngine(session).create(), true);
        }
        catch (Exception refusal) { return unavailable(); }
    }
    @GET @Path("complete") @Produces(MediaType.TEXT_HTML)
    public Response completed() {
        try {
            require("https".equals(session.getContext().getUri().getBaseUri().getScheme()));
            var existing = session.getContext().getRequestHeaders().getCookies().get(COOKIE);
            if (existing != null) {
                try { return render(new NativeEngine(session).completion(existing.getValue()), false); }
                catch (NativeRefusal unavailable) { /* The generic result never grants or renews recovery authority. */ }
            }
            return render(new NativeEngine.View(null, null, NativeEngine.COMPLETE, false), false);
        } catch (Exception refusal) { return unavailable(); }
    }
    @POST @Consumes(MediaType.APPLICATION_FORM_URLENCODED) @Produces(MediaType.TEXT_HTML)
    public Response submit(@FormParam("username") String username, @FormParam("password") String password,
            @FormParam("otp") String otp, @FormParam("csrf") String csrf) {
        NativeEngine engine = new NativeEngine(session); NativeEngine.View view;
        try {
            require("https".equals(session.getContext().getUri().getBaseUri().getScheme()));
            NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
            requireOrigin(session.getContext().getRequestHeaders().getHeaderString("Origin"), profile.origin());
            String id = cookie();
            String stage = NativePhases.run(session, child -> new NativeStore(child).ceremony(id).stage);
            require(NativeEngine.PASSWORD.equals(stage) || NativeEngine.TOTP.equals(stage) || NativeEngine.COMPLETE.equals(stage));
            view = engine.consumeCsrf(id, csrf, stage);
            if (NativeEngine.COMPLETE.equals(stage)) return complete(engine, id, view.csrf());
            if (NativeEngine.PASSWORD.equals(stage)) {
                require(username != null && username.length() <= 254 && password != null && password.length() <= 1024);
                try {
                    NativeEngine.Prepared actor = engine.bootstrap(id, username, password);
                    if (actor != null) {
                        NativeCeremonyGateway gateway = gateway(); Started started = gateway.begin(actor.assertion()); engine.started(id, started);
                        Reservation reservation = gateway.reserve(actor.assertion(), started.operationId(), started.knowledgeChallengeId());
                        String attestation = engine.attest(id, reservation, password);
                        if (attestation != null) gateway.complete(actor.assertion(), reservation, attestation);
                    }
                } catch (Exception generic) { /* Keep the unknown and ineligible first step indistinguishable. */ }
                engine.stage(id, NativeEngine.TOTP, view.csrf(), false);
                return redirect();
            }
            require(NativeEngine.TOTP.equals(stage) && otp != null && otp.matches("[0-9]{6,8}"));
            try {
                NativeEngine.Prepared actor = engine.prepared(id); require(actor != null);
                NativeCeremonyGateway gateway = gateway(); Started started = engine.started(id);
                NativeEngine.CompletedFactor previous = engine.completedPossession(id);
                Reservation reservation = previous == null ? gateway.reserve(actor.assertion(), started.operationId(), started.possessionChallengeId()) : previous.reservation();
                String attestation = previous == null ? engine.attest(id, reservation, otp) : previous.attestation(); require(attestation != null);
                gateway.complete(actor.assertion(), reservation, attestation);
                Authorization receipt = gateway.consume(actor.assertion(), started.operationId());
                Authorization verified = gateway.verifyAuthorization(actor.assertion(), receipt); require(receipt.equals(verified));
                engine.execute(id, verified);
                return complete(engine, id, view.csrf());
            } catch (Exception generic) {
                engine.stage(id, NativeEngine.TOTP, view.csrf(), true); return redirect();
            }
        } catch (Exception generic) { return unavailable(); }
    }
    @POST @Path("rpc/{route}") @Consumes(MediaType.APPLICATION_JSON) @Produces(MediaType.APPLICATION_JSON)
    public Response rpc(@PathParam("route") String route, Rpc rpc) {
        try { return Response.ok(NativeWire.json(new NativeRpcService(session).call(route, rpc))).header("Cache-Control", "no-store").build(); }
        catch (Exception refusal) { return Response.status(403).entity(java.util.Map.of("error", "native_recovery_refused")).header("Cache-Control", "no-store").build(); }
    }
    @Path("support-pin") public NativePinResource supportPin() { return new NativePinResource(session); }
    private NativeCeremonyGateway gateway() {
        var factories = ServiceLoader.load(NativeCeremonyGateway.Factory.class, getClass().getClassLoader()).stream().map(ServiceLoader.Provider::get).filter(NativeCeremonyGateway.Factory::isQualified).toList();
        require(factories.size() == 1); var gateway = factories.get(0).create(session); require(gateway != null); return gateway;
    }
    private Response complete(NativeEngine engine, String id, String csrf) {
        boolean recorded = false;
        try { recorded = engine.reconcile(id, gateway()); }
        catch (Exception transport) { /* Leave the exact committed receipt available for bounded audit-only resume. */ }
        engine.stage(id, NativeEngine.COMPLETE, csrf, !recorded); return redirect(true);
    }
    private String cookie() {
        var cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE); require(cookie != null); return cookie.getValue();
    }
    private Response redirect() {
        return redirect(false);
    }
    private Response redirect(boolean complete) {
        String target = NativeProfile.of(session.getContext().getRealm()).issuer() + "/" + NativeContracts.EXTENSION;
        return Response.seeOther(java.net.URI.create(target + (complete ? "/complete" : ""))).header("Cache-Control", "no-store").build();
    }
    private Response render(NativeEngine.View view, boolean setCookie) {
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
        Response response = session.getProvider(LoginFormsProvider.class).setAttribute("stage", view.stage()).setAttribute("csrf", view.csrf())
                .setAttribute("actionUrl", profile.issuer() + "/" + NativeContracts.EXTENSION).setAttribute("signInUrl", profile.issuer() + "/account")
                .setAttribute("auditRetry", view.ceremonyId() != null && NativeEngine.COMPLETE.equals(view.stage()) && new NativeEngine(session).recordPending(view.ceremonyId()))
                .setAttribute("messageKey", view.failed() ? "ffidRecoveryFailed" : null)
                .setAttribute("nativeCredentialForm", true).createForm("firefly-recovery.ftl");
        var builder = Response.fromResponse(response).header("Cache-Control", "no-store");
        if (setCookie) builder.cookie(new NewCookie.Builder(COOKIE).value(view.ceremonyId()).path("/realms/" + session.getContext().getRealm().getName() + "/" + NativeContracts.EXTENSION)
                .httpOnly(true).secure(true).sameSite(NewCookie.SameSite.STRICT).maxAge(profile.ttlSeconds()).build());
        return builder.build();
    }
    private Response unavailable() {
        Response response = session.getProvider(LoginFormsProvider.class).setError("ffidRecoveryFailed").createErrorPage(Response.Status.BAD_REQUEST);
        return Response.fromResponse(response).header("Cache-Control", "no-store").build();
    }
}
