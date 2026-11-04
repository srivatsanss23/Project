package com.example.spamdetector;

import com.fasterxml.jackson.databind.JsonNode;
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
import java.util.*;

@Service
public class ExternalThreatIntelClient {

    private static final Logger log = LoggerFactory.getLogger(ExternalThreatIntelClient.class);

    @Value("${shieldguard.safebrowsing.api-key:}")
    private String safeBrowsingApiKey;

    @Value("${shieldguard.virustotal.api-key:}")
    private String virusTotalApiKey;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public record ExternalThreatReport(
            String url,
            boolean isMalicious,
            String sourceApi, // "Google Safe Browsing", "VirusTotal", "Local Threat DB"
            int confidenceScore,
            String details
    ) {}

    public ExternalThreatIntelClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public List<ExternalThreatReport> checkUrls(List<String> urls) {
        if (urls == null || urls.isEmpty()) {
            return Collections.emptyList();
        }

        List<ExternalThreatReport> reports = new ArrayList<>();

        for (String url : urls) {
            // 1. Google Safe Browsing Check (if key configured)
            if (safeBrowsingApiKey != null && !safeBrowsingApiKey.isBlank()) {
                ExternalThreatReport gsbReport = checkGoogleSafeBrowsing(url);
                if (gsbReport != null) {
                    reports.add(gsbReport);
                    continue;
                }
            }

            // 2. VirusTotal Check (if key configured)
            if (virusTotalApiKey != null && !virusTotalApiKey.isBlank()) {
                ExternalThreatReport vtReport = checkVirusTotal(url);
                if (vtReport != null) {
                    reports.add(vtReport);
                    continue;
                }
            }
        }

        return reports;
    }

    private ExternalThreatReport checkGoogleSafeBrowsing(String url) {
        try {
            String endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + safeBrowsingApiKey;

            Map<String, Object> payload = Map.of(
                    "client", Map.of("clientId", "shieldguard-defense", "clientVersion", "3.0.0"),
                    "threatInfo", Map.of(
                            "threatTypes", List.of("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                            "platformTypes", List.of("ANY_PLATFORM"),
                            "threatEntryTypes", List.of("URL"),
                            "threatEntries", List.of(Map.of("url", url))
                    )
            );

            String requestJson = objectMapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .header("Content-Type", "application/json")
                    .timeout(Duration.ofSeconds(4))
                    .POST(HttpRequest.BodyPublishers.ofString(requestJson))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode matches = root.path("matches");
                if (matches.isArray() && matches.size() > 0) {
                    String threatType = matches.get(0).path("threatType").asText("MALWARE");
                    return new ExternalThreatReport(url, true, "Google Safe Browsing API v4", 95,
                            "Google Safe Browsing database flagged URL as: " + threatType);
                } else {
                    return new ExternalThreatReport(url, false, "Google Safe Browsing API v4", 0, "Clean according to Google Safe Browsing");
                }
            }
        } catch (Exception e) {
            log.warn("Google Safe Browsing API call failed: {}", e.getMessage());
        }
        return null;
    }

    private ExternalThreatReport checkVirusTotal(String targetUrl) {
        try {
            // VirusTotal uses base64 URL ID without trailing '='
            String urlId = Base64.getUrlEncoder().withoutPadding().encodeToString(targetUrl.getBytes());
            String endpoint = "https://www.virustotal.com/api/v3/urls/" + urlId;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .header("x-apikey", virusTotalApiKey)
                    .timeout(Duration.ofSeconds(4))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode stats = root.path("data").path("attributes").path("last_analysis_stats");
                int malicious = stats.path("malicious").asInt(0);
                int suspicious = stats.path("suspicious").asInt(0);

                if (malicious > 0 || suspicious > 1) {
                    return new ExternalThreatReport(targetUrl, true, "VirusTotal API v3", 90,
                            "Flagged by " + malicious + " antivirus security engines on VirusTotal");
                } else {
                    return new ExternalThreatReport(targetUrl, false, "VirusTotal API v3", 0, "No engines flagged URL on VirusTotal");
                }
            }
        } catch (Exception e) {
            log.warn("VirusTotal API call failed: {}", e.getMessage());
        }
        return null;
    }

    public boolean isAnyApiKeyConfigured() {
        return (safeBrowsingApiKey != null && !safeBrowsingApiKey.isBlank()) ||
               (virusTotalApiKey != null && !virusTotalApiKey.isBlank());
    }
}
