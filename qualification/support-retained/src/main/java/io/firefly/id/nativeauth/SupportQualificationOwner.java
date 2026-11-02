package io.firefly.id.nativeauth;

import org.keycloak.models.KeycloakSession;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/** Synthetic authority; this independent JAR must never enter the production reactor or image. */
public final class SupportQualificationOwner implements NativeSupportAuthorization.Factory {
    static final String REALM = "support-retained-fixture";
    static final Map<String, Permit> PERMITS = new ConcurrentHashMap<>();
    static final class Gate {
        final CountDownLatch reached;
        final CountDownLatch release = new CountDownLatch(1);
        Gate(int count) { reached = new CountDownLatch(count); }
        void await() {
            reached.countDown();
            try { check(release.await(25, TimeUnit.SECONDS)); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new NativeRefusal(); }
        }
    }
    static final class Permit {
        final NativeSupportAuthorization.Grant grant;
        final AtomicInteger calls = new AtomicInteger();
        final Gate gate;
        final boolean interrupt;
        Permit(NativeSupportAuthorization.Grant grant, Gate gate, boolean interrupt) {
            this.grant = grant; this.gate = gate; this.interrupt = interrupt;
        }
    }
    static void check(boolean value) { if (!value) throw new NativeRefusal(); }
    static boolean admitted() { return admitted(System.getenv()); }
    static boolean admitted(Map<String, String> environment) {
        String run = environment.get("FIREFLY_SUPPORT_QUALIFICATION_RUN");
        String secret = environment.get("FIREFLY_SUPPORT_QUALIFICATION_SECRET");
        return "owned-github-hosted-only".equals(environment.get("FIREFLY_SUPPORT_QUALIFICATION"))
                && run != null && run.matches("[0-9]+-[0-9]+")
                && ("firefly-support-retained-" + run + "-identity").equals(environment.get("HOSTNAME"))
                && secret != null && secret.matches("[A-Za-z0-9_-]{40,128}");
    }
    @Override public boolean isQualified() { return admitted(); }
    @Override public NativeSupportAuthorization create(KeycloakSession session) {
        check(admitted() && REALM.equals(session.getContext().getRealm().getName()));
        return context -> {
            check(admitted());
            Permit permit = PERMITS.get(context); check(permit != null);
            if (permit.calls.incrementAndGet() > 1) {
                if (permit.gate != null) permit.gate.await();
                check(!permit.interrupt);
            }
            return permit.grant;
        };
    }
}
