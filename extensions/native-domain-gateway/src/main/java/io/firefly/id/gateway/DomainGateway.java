package io.firefly.id.gateway;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.firefly.id.nativeauth.NativeCeremonyGateway;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static io.firefly.id.nativeauth.NativeContracts.*;

/** Server-side transport to the actual Domain owner; no credential is sent through this gateway. */
public final class DomainGateway implements NativeCeremonyGateway {
    private static final String ROOT = "/api/v1/sca/recovery-operations";
    private static final int MAX_RESPONSE = 65_536;
    private static final ObjectMapper JSON = JsonSerialization.mapper.copy()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    private final URI origin;
    private final HttpClient client;

    public DomainGateway(URI origin) {
        this(origin, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    DomainGateway(URI origin, HttpClient client) {
        if (origin == null || !"https".equals(origin.getScheme()) || origin.getHost() == null
                || origin.getUserInfo() != null || origin.getQuery() != null || origin.getFragment() != null
                || !(origin.getPath().isEmpty() || "/".equals(origin.getPath()))
                || client == null || client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw unavailable();
        }
        this.origin = origin;
        this.client = client;
    }

    @Override public Started begin(String actor) {
        Started value = post(actor, ROOT, null, 201, Started.class);
        require(value != null && value.operationId() != null && value.knowledgeChallengeId() != null
                && value.possessionChallengeId() != null && !value.knowledgeChallengeId().equals(value.possessionChallengeId()));
        return value;
    }

    @Override public Reservation reserve(String actor, UUID operation, UUID challenge) {
        require(operation != null && challenge != null);
        Reservation value = post(actor, path(operation, "/verifications/reservations"),
                Map.of("challengeId", challenge), 201, Reservation.class);
        require(value != null && operation.equals(value.operationId()) && challenge.equals(value.challengeId())
                && value.reservationId() != null && nonblank(value.providerChallengeId())
                && Set.of("KNOWLEDGE", "POSSESSION").contains(value.category()));
        future(value.expiresAt());
        return value;
    }

    @Override public void complete(String actor, Reservation reservation, String attestation) {
        require(reservation != null && nonblank(attestation) && attestation.length() <= 16_384);
        Acknowledgement response = post(actor, path(reservation.operationId(), "/verifications/complete"),
                Map.of("challengeId", reservation.challengeId(), "reservationId", reservation.reservationId(),
                        "attestation", attestation), 202, Acknowledgement.class);
        require(response != null && reservation.operationId().equals(response.operationId())
                && "ACKNOWLEDGED".equals(response.status()));
    }

    @Override public Authorization consume(String actor, UUID operation) {
        Authorization value = post(actor, path(operation, "/authorizations"), null, 200, Authorization.class);
        require(value != null && operation.equals(value.operationId()) && value.executionId() != null && value.binding() != null);
        future(value.expiresAt());
        return value;
    }

    @Override public Authorization verifyAuthorization(String actor, Authorization expected) {
        require(expected != null && expected.executionId() != null && expected.expiresAt() != null);
        Authorization value = post(actor, path(expected.operationId(), "/authorizations/verify"),
                Map.of("executionId", expected.executionId(), "expiresAt", expected.expiresAt()), 200, Authorization.class);
        require(expected.equals(value));
        future(value.expiresAt());
        return value;
    }

    @Override public void recordExecution(String actor, Authorization authorization, String outcome) {
        require(authorization != null && authorization.executionId() != null && authorization.expiresAt() != null
                && Set.of("SUCCEEDED", "FAILED", "UNKNOWN").contains(outcome));
        post(actor, path(authorization.operationId(), "/executions"),
                Map.of("executionId", authorization.executionId(), "expiresAt", authorization.expiresAt(), "outcome", outcome),
                204, Void.class);
    }

    private <T> T post(String actor, String path, Object request, int expectedStatus, Class<T> type) {
        require(nonblank(actor) && actor.length() <= 32_768 && actor.chars().noneMatch(Character::isISOControl));
        CompletableFuture<HttpResponse<byte[]>> exchange = null;
        try {
            byte[] body = request == null ? new byte[0] : JSON.writeValueAsBytes(request);
            HttpRequest call = HttpRequest.newBuilder(origin.resolve(path)).timeout(Duration.ofSeconds(5))
                    .header("Authorization", "Bearer " + actor).header("Content-Type", "application/json")
                    .header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofByteArray(body)).build();
            exchange = client.sendAsync(call, info -> new BoundedBody());
            HttpResponse<byte[]> response = exchange.get(5, TimeUnit.SECONDS);
            byte[] bytes = response.body();
            require(response.statusCode() == expectedStatus);
            if (type == Void.class) {
                require(bytes.length == 0);
                return null;
            }
            require(response.headers().firstValue("Content-Type").orElse("")
                    .toLowerCase(java.util.Locale.ROOT).startsWith("application/json"));
            return JSON.readValue(bytes, type);
        } catch (InterruptedException error) {
            if (exchange != null) exchange.cancel(true);
            Thread.currentThread().interrupt();
            throw unavailable();
        } catch (IOException | IllegalArgumentException | ExecutionException | TimeoutException error) {
            if (exchange != null) exchange.cancel(true);
            throw unavailable();
        }
    }

    private static String path(UUID operation, String suffix) {
        require(operation != null);
        return ROOT + "/" + operation + suffix;
    }
    private static boolean nonblank(String value) { return value != null && !value.isBlank(); }
    private static void future(Instant value) {
        Instant now = Instant.now();
        require(value != null && value.isAfter(now) && !value.isAfter(now.plusSeconds(301)));
    }
    private static void require(boolean condition) { if (!condition) throw unavailable(); }
    private static IllegalStateException unavailable() { return new IllegalStateException("Recovery owner transport unavailable"); }
    private record Acknowledgement(UUID operationId, String status) { }

    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
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
                if (chunk.remaining() > MAX_RESPONSE - bytes.size()) {
                    subscription.cancel();
                    result.completeExceptionally(unavailable());
                    return;
                }
                byte[] copy = new byte[chunk.remaining()];
                chunk.get(copy);
                bytes.writeBytes(copy);
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable ignored) { result.completeExceptionally(unavailable()); }
        @Override public void onComplete() { result.complete(bytes.toByteArray()); }
    }
}
