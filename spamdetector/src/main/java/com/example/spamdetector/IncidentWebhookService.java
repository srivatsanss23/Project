package com.example.spamdetector;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Service
public class IncidentWebhookService {

    private static final Logger log = LoggerFactory.getLogger(IncidentWebhookService.class);

    @Value("${shieldguard.webhook.alert-url:}")
    private String alertWebhookUrl;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public IncidentWebhookService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public void dispatchIncidentAlert(SpamResponse response, String messageSnippet) {
        if (alertWebhookUrl == null || alertWebhookUrl.isBlank()) {
            return;
        }

        if (response.getScore() < 80 && !"CRITICAL".equalsIgnoreCase(response.getRiskLevel())) {
            return; // Only dispatch for severe/critical threats
        }

        CompletableFuture.runAsync(() -> {
            try {
                Map<String, Object> incident = Map.of(
                        "event", "SHIELDGUARD_SECURITY_INCIDENT",
                        "severity", response.getRiskLevel(),
                        "threatScore", response.getScore(),
                        "verdict", response.getPrediction(),
                        "summary", response.getReasons().isEmpty() ? "Threat Detected" : response.getReasons().get(0),
                        "snippet", messageSnippet,
                        "timestamp", Instant.now().toString()
                );

                String json = objectMapper.writeValueAsString(incident);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(alertWebhookUrl))
                        .header("Content-Type", "application/json")
                        .timeout(Duration.ofSeconds(3))
                        .POST(HttpRequest.BodyPublishers.ofString(json))
                        .build();

                httpClient.sendAsync(request, HttpResponse.BodyHandlers.discarding());
                log.info("Incident webhook dispatched successfully to SIEM/Alert sink");

            } catch (Exception e) {
                log.debug("Incident alert webhook could not be delivered: {}", e.getMessage());
            }
        });
    }
}
