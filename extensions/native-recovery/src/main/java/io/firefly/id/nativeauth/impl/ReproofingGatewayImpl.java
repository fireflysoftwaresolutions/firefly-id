package io.firefly.id.nativeauth.impl;

import io.firefly.id.nativeauth.ReproofingContracts.*;
import java.net.URI;
import java.net.http.*;
import java.time.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.io.ByteArrayOutputStream;
import java.util.*;
import java.util.concurrent.*;
import static io.firefly.id.nativeauth.NativeSecurity.require;

/** A credential-free, bounded private transport to the independent Domain owner. */
final class ReproofingGatewayImpl {
    private static final String ROOT = "/api/v1/identity-recovery/cases";
    private final ReproofingConfigImpl config;
    ReproofingGatewayImpl(ReproofingConfigImpl config) { this.config = config; }
    Journey begin(Binding binding) {
        var tree = post(ROOT, Map.of("binding", binding), com.fasterxml.jackson.databind.JsonNode.class);
        require(tree != null && tree.has("case"));
        Case value = ReproofingWireImpl.read(tree.get("case").toString(), Case.class); check(value, binding);
        String url = tree.path("verificationUrl").isTextual() ? tree.path("verificationUrl").asText() : null;
        if (url != null) {
            require(url.length() <= 2048); URI uri = URI.create(url), origin = ReproofingConfigImpl.origin(config.value("provider-origin"));
            require("https".equals(uri.getScheme()) && uri.getRawUserInfo() == null && uri.getRawFragment() == null && origin.getHost().equals(uri.getHost()) && origin.getPort() == uri.getPort());
        }
        return new Journey(value, url);
    }
    Case confirm(UUID caseId, Binding binding) {
        Case value = post(ROOT + "/" + caseId + "/confirm", Map.of("binding", binding), Case.class); check(value, binding); require(caseId.equals(value.caseId())); return value;
    }
    Authorization consume(Authorization expected) { return authorization(expected, "consume"); }
    Authorization verify(Authorization expected) { return authorization(expected, "verify"); }
    private Authorization authorization(Authorization expected, String action) {
        require(expected != null && expected.expiresAt() != null && expected.expiresAt().isAfter(Instant.now()));
        Authorization value = post(ROOT + "/" + expected.caseId() + "/authorizations/" + action,
                Map.of("binding", expected.binding(), "authorizationId", expected.authorizationId(), "executionId", expected.executionId()), Authorization.class);
        require(expected.equals(value)); return value;
    }
    void record(Authorization expected) {
        post(ROOT + "/" + expected.caseId() + "/executions", Map.of("binding", expected.binding(), "authorizationId", expected.authorizationId(), "executionId", expected.executionId(), "outcome", "CREDENTIALS_REPLACED"), Void.class);
    }
    private void check(Case value, Binding binding) {
        require(value != null && value.caseId() != null && binding.equals(value.binding()) && value.providerStartId() != null && value.expiresAt() != null);
        if (value.authorization() != null) require(value.caseId().equals(value.authorization().caseId()) && binding.equals(value.authorization().binding()) && value.authorization().executionId() != null && value.authorization().authorizationId() != null && value.authorization().expiresAt() != null && !value.authorization().expiresAt().isAfter(value.expiresAt()));
    }
    private <T> T post(String path, Object value, Class<T> type) {
        CompletableFuture<HttpResponse<byte[]>> exchange = null;
        byte[] secretBytes = null;
        try {
            String file = System.getenv("FIREFLY_REPROOFING_DOMAIN_SECRET_FILE"); require(file != null);
            Path secretPath = Path.of(file); require(!Files.isSymbolicLink(secretPath) && Files.size(secretPath) > 0 && Files.size(secretPath) <= 4096);
            secretBytes = Files.readAllBytes(secretPath); String secret = new String(secretBytes, StandardCharsets.UTF_8).strip();
            require(!secret.isBlank() && secret.chars().noneMatch(Character::isISOControl));
            String credential = Base64.getEncoder().encodeToString((config.value("domain-client-id") + ":" + secret).getBytes(StandardCharsets.UTF_8));
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).followRedirects(HttpClient.Redirect.NEVER).build();
            byte[] body = ReproofingWireImpl.json(value).getBytes(StandardCharsets.UTF_8); require(body.length <= 16384);
            HttpRequest request = HttpRequest.newBuilder(ReproofingConfigImpl.origin(config.value("domain-origin")).resolve(path)).timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Basic " + credential).header("Content-Type", "application/json").header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            exchange = client.sendAsync(request, info -> new BoundedBodyImpl()); var response = exchange.get(5, TimeUnit.SECONDS);
            require(response.statusCode() >= 200 && response.statusCode() < 300);
            if (type == Void.class) return null;
            require(response.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
            return ReproofingWireImpl.JSON.readValue(response.body(), type);
        } catch (InterruptedException error) { if (exchange != null) exchange.cancel(true); Thread.currentThread().interrupt(); throw new IllegalStateException("Recovery unavailable"); }
        catch (Exception error) { if (exchange != null) exchange.cancel(true); throw new IllegalStateException("Recovery unavailable"); }
        finally { if (secretBytes != null) Arrays.fill(secretBytes, (byte) 0); }
    }
    private static final class BoundedBodyImpl implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        @Override public CompletionStage<byte[]> getBody() { return result; }
        @Override public void onSubscribe(Flow.Subscription value) {
            if (subscription != null) { value.cancel(); return; }
            subscription = value;
            value.request(1);
        }
        @Override public void onNext(List<ByteBuffer> chunks) {
            if (result.isDone()) { subscription.cancel(); return; }
            for (ByteBuffer chunk : chunks) {
                if (chunk.remaining() > 65_536 - bytes.size()) {
                    subscription.cancel();
                    result.completeExceptionally(new IllegalStateException("Recovery unavailable"));
                    return;
                }
                byte[] copy = new byte[chunk.remaining()];
                chunk.get(copy);
                bytes.writeBytes(copy);
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable ignored) { result.completeExceptionally(new IllegalStateException("Recovery unavailable")); }
        @Override public void onComplete() { result.complete(bytes.toByteArray()); }
    }
}
