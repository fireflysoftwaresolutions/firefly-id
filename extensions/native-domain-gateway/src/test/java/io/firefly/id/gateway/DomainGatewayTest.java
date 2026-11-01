package io.firefly.id.gateway;

import com.fasterxml.jackson.databind.SerializationFeature;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.keycloak.util.JsonSerialization;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicReference;

import static io.firefly.id.nativeauth.NativeContracts.*;
import static org.junit.jupiter.api.Assertions.*;

class DomainGatewayTest {
    @TempDir static Path directory;
    private static SSLContext serverTls;
    private static SSLContext clientTls;
    private HttpsServer server;
    private HttpClient client;
    private ExecutorService executor;
    private DomainGatewayImpl gateway;
    private final AtomicReference<Reply> reply = new AtomicReference<>();
    private final CopyOnWriteArrayList<Observed> requests = new CopyOnWriteArrayList<>();
    private record Reply(int status, byte[] body, String redirect) { }
    private record Observed(String authorization, String path, byte[] body) { }

    @BeforeAll static void certificates() throws Exception {
        byte[] random = new byte[32]; new SecureRandom().nextBytes(random);
        String password = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Path store = directory.resolve("server.p12");
        var keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", password, "-noprompt")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(keytool.waitFor(20, java.util.concurrent.TimeUnit.SECONDS));
        assertEquals(0, keytool.exitValue());
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var stream = Files.newInputStream(store)) { keys.load(stream, password.toCharArray()); }
        var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keys, password.toCharArray());
        serverTls = SSLContext.getInstance("TLS"); serverTls.init(keyManagers.getKeyManagers(), null, null);
        KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
        trust.setCertificateEntry("server", keys.getCertificate("server"));
        var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trust);
        clientTls = SSLContext.getInstance("TLS"); clientTls.init(null, trustManagers.getTrustManagers(), null);
    }

    @BeforeEach void start() throws Exception {
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(serverTls));
        server.setExecutor(executor);
        server.createContext("/", exchange -> {
            requests.add(new Observed(exchange.getRequestHeaders().getFirst("Authorization"),
                    exchange.getRequestURI().getPath(), exchange.getRequestBody().readAllBytes()));
            Reply value = reply.get();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            if (value.redirect() != null) exchange.getResponseHeaders().set("Location", value.redirect());
            exchange.sendResponseHeaders(value.status(), value.status() == 204 ? -1 : value.body().length > 65_536 ? 0 : value.body().length);
            if (value.status() != 204) exchange.getResponseBody().write(value.body());
            exchange.close();
        });
        server.start();
        client = HttpClient.newBuilder().sslContext(clientTls).followRedirects(HttpClient.Redirect.NEVER).build();
        gateway = new DomainGatewayImpl(URI.create("https://localhost:" + server.getAddress().getPort()), client);
    }

    @AfterEach void stop() { if (server != null) server.stop(0); if (client != null) client.close(); if (executor != null) executor.shutdownNow(); }

    @Test void refusesUnsafeEndpointsAndRedirectFollowingClients() {
        for (String address : new String[]{"http://localhost", "https://user:secret@localhost", "https://localhost/path",
                "https://localhost?token=value", "https://localhost#fragment"}) {
            assertThrows(IllegalStateException.class, () -> new DomainGatewayImpl(URI.create(address)));
        }
        try (var redirected = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build()) {
            assertThrows(IllegalStateException.class, () -> new DomainGatewayImpl(URI.create("https://localhost"), redirected));
        }
    }

    @Test void acceptsExactStartAndReservationWithoutSendingCredentialFields() throws Exception {
        UUID operation = UUID.randomUUID(), knowledge = UUID.randomUUID(), possession = UUID.randomUUID();
        respond(201, new Started(operation, knowledge, possession));
        assertEquals(operation, gateway.begin("restricted-actor-a").operationId());
        Instant expires = Instant.now().plusSeconds(90);
        Reservation reserved = new Reservation(operation, knowledge, UUID.randomUUID(), "native-challenge", "KNOWLEDGE", expires);
        respond(201, reserved);
        assertEquals(reserved, gateway.reserve("restricted-actor-a", operation, knowledge));
        assertEquals("Bearer restricted-actor-a", requests.getLast().authorization());
        var body = JsonSerialization.mapper.readTree(requests.getLast().body());
        assertEquals(1, body.size()); assertEquals(knowledge.toString(), body.get("challengeId").asText());
        assertEquals("/api/v1/sca/recovery-operations/" + operation + "/verifications/reservations", requests.getLast().path());
    }

    @Test void rejectsSwappedReservationAndAuthorizationWithoutExposingResponse() throws Exception {
        UUID operation = UUID.randomUUID(), challenge = UUID.randomUUID();
        respond(201, new Reservation(UUID.randomUUID(), challenge, UUID.randomUUID(), "native", "KNOWLEDGE", Instant.now().plusSeconds(30)));
        assertSafe(() -> gateway.reserve("private-actor", operation, challenge));
        Authorization expected = new Authorization(operation, UUID.randomUUID(), binding(), Instant.now().plusSeconds(30));
        respond(200, new Authorization(operation, UUID.randomUUID(), expected.binding(), expected.expiresAt()));
        assertSafe(() -> gateway.verifyAuthorization("private-actor", expected));
    }

    @Test void requiresAcknowledgementAndSerializesExpiryAsUtcText() throws Exception {
        UUID operation = UUID.randomUUID(), challenge = UUID.randomUUID();
        var reserved = new Reservation(operation, challenge, UUID.randomUUID(), "native", "POSSESSION", Instant.now().plusSeconds(30));
        respond(202, Map.of("operationId", operation, "status", "ACKNOWLEDGED"));
        gateway.complete("restricted", reserved, "opaque-provider-reference");
        assertFalse(JsonSerialization.mapper.readTree(requests.getLast().body()).has("accepted"));
        var authorization = new Authorization(operation, UUID.randomUUID(), binding(), Instant.now().minusSeconds(1));
        respond(204, null);
        gateway.recordExecution("restricted", authorization, "SUCCEEDED");
        assertTrue(JsonSerialization.mapper.readTree(requests.getLast().body()).get("expiresAt").isTextual());
    }

    @Test void consumptionRefusesAnExpiredReceiptEvenWithAnAcceptedHttpResponse() throws Exception {
        var live = new Authorization(UUID.randomUUID(), UUID.randomUUID(), binding(), Instant.now().plusSeconds(60));
        respond(200, live);
        assertEquals(live, gateway.consume("restricted", live.operationId()));
        var expired = new Authorization(live.operationId(), live.executionId(), live.binding(), Instant.now().minusSeconds(1));
        respond(200, expired);
        assertSafe(() -> gateway.consume("restricted", expired.operationId()));
    }

    @Test void verificationRefusesAnExactButExpiredReceipt() throws Exception {
        var live = new Authorization(UUID.randomUUID(), UUID.randomUUID(), binding(), Instant.now().plusSeconds(60));
        respond(200, live);
        assertEquals(live, gateway.verifyAuthorization("restricted", live));
        var expired = new Authorization(live.operationId(), live.executionId(), live.binding(), Instant.now().minusSeconds(1));
        respond(200, expired);
        assertSafe(() -> gateway.verifyAuthorization("restricted", expired));
    }

    @Test void refusesRedirectAndOversizedChunkedResponse() {
        reply.set(new Reply(307, new byte[0], "https://untrusted.invalid/collect"));
        assertSafe(() -> gateway.begin("private-actor"));
        assertEquals(1, requests.size());
        reply.set(new Reply(201, new byte[65_537], null));
        assertSafe(() -> gateway.begin("private-actor"));
    }

    private void respond(int status, Object body) throws Exception {
        reply.set(new Reply(status, body == null ? new byte[0] : JsonSerialization.mapper.copy()
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS).writeValueAsBytes(body), null));
    }
    private static Binding binding() { return new Binding("https://id.test/realms/customers", "opaque", "recovery", null,
            "subject", "https://id.test/realms/customers", "customers", "subject", "HUMAN", PURPOSE, "generation"); }
    private static void assertSafe(org.junit.jupiter.api.function.Executable call) {
        var failure = assertThrows(IllegalStateException.class, call);
        assertEquals("Recovery owner transport unavailable", failure.getMessage()); assertNull(failure.getCause());
    }
}
