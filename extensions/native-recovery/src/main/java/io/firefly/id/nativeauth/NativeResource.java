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
                try { return render(new NativeEngine(session).resume(existing.getValue()), null, false); }
                catch (NativeRefusal expired) { /* A fresh ceremony gets a fresh CSRF state. */ }
            }
            return render(new NativeEngine(session).create(), null, true);
        }
        catch (Exception refusal) { return unavailable(); }
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
            require(NativeEngine.PASSWORD.equals(stage) || NativeEngine.TOTP.equals(stage));
            view = engine.consumeCsrf(id, csrf, stage);
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
                return render(engine.stage(id, NativeEngine.TOTP, view.csrf()), null, false);
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
                Execution execution = engine.execute(id, verified);
                try { gateway.recordExecution(actor.assertion(), verified, execution.outcome()); }
                catch (Exception transport) { /* Native committed journal remains authoritative for reconciliation. */ }
                return render(engine.stage(id, NativeEngine.COMPLETE, view.csrf()), null, false);
            } catch (Exception generic) { return render(engine.stage(id, NativeEngine.TOTP, view.csrf()), "ffidRecoveryFailed", false); }
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
    private String cookie() {
        var cookie = session.getContext().getRequestHeaders().getCookies().get(COOKIE); require(cookie != null); return cookie.getValue();
    }
    private Response render(NativeEngine.View view, String message, boolean setCookie) {
        NativeProfile profile = NativeProfile.of(session.getContext().getRealm());
        Response response = session.getProvider(LoginFormsProvider.class).setAttribute("stage", view.stage()).setAttribute("csrf", view.csrf())
                .setAttribute("actionUrl", profile.issuer() + "/" + NativeContracts.EXTENSION).setAttribute("signInUrl", profile.issuer() + "/account")
                .setAttribute("messageKey", message).createForm("firefly-recovery.ftl");
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
