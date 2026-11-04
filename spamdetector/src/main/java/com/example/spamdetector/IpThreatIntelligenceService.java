package com.example.spamdetector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class IpThreatIntelligenceService {

    private static final Logger log = LoggerFactory.getLogger(IpThreatIntelligenceService.class);
    private static final Pattern IP_PATTERN = Pattern.compile("(?i)\\b((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    // Cache to prevent redundant external API lookups
    private final Map<String, IpIntelligenceResult> cache = new HashMap<>();

    public record IpIntelligenceResult(
            String ip,
            boolean isPrivate,
            String country,
            String city,
            String isp,
            String asn,
            boolean isHostingOrCloud,
            String riskSummary
    ) {}

    public IpThreatIntelligenceService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public List<IpIntelligenceResult> analyzeIpsInText(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        List<IpIntelligenceResult> results = new ArrayList<>();
        Matcher matcher = IP_PATTERN.matcher(text);

        while (matcher.find()) {
            String ip = matcher.group();
            results.add(lookupIp(ip));
        }

        return results;
    }

    public IpIntelligenceResult lookupIp(String ip) {
        if (cache.containsKey(ip)) {
            return cache.get(ip);
        }

        if (isPrivateIp(ip)) {
            IpIntelligenceResult privateResult = new IpIntelligenceResult(
                    ip,
                    true,
                    "Internal / Private Network",
                    "Local LAN",
                    "Private Subnet",
                    "RFC 1918",
                    false,
                    "Internal IP address referenced in message (suspicious if impersonating a public bank/service)"
            );
            cache.put(ip, privateResult);
            return privateResult;
        }

        // Live external API call to free geolocation and ASN intelligence API
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://ip-api.com/json/" + ip + "?fields=status,message,country,city,isp,org,as,query"))
                    .timeout(Duration.ofSeconds(3))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(response.body());
                if ("success".equalsIgnoreCase(root.path("status").asText())) {
                    String country = root.path("country").asText("Unknown");
                    String city = root.path("city").asText("Unknown");
                    String isp = root.path("isp").asText("Unknown");
                    String asn = root.path("as").asText("Unknown");

                    boolean isHosting = isp.toLowerCase().contains("hosting") ||
                                        isp.toLowerCase().contains("cloud") ||
                                        isp.toLowerCase().contains("amazon") ||
                                        isp.toLowerCase().contains("digitalocean") ||
                                        isp.toLowerCase().contains("ovh") ||
                                        isp.toLowerCase().contains("linode") ||
                                        isp.toLowerCase().contains("vultr");

                    String risk = isHosting
                            ? "Public cloud/datacenter IP (" + isp + ", " + country + ") commonly used for disposable phishing relays"
                            : "Hosted in " + city + ", " + country + " via " + isp;

                    IpIntelligenceResult result = new IpIntelligenceResult(ip, false, country, city, isp, asn, isHosting, risk);
                    cache.put(ip, result);
                    return result;
                }
            }
        } catch (Exception e) {
            log.debug("External IP lookup failed for {}: {}", ip, e.getMessage());
        }

        IpIntelligenceResult fallback = new IpIntelligenceResult(ip, false, "Unknown", "Unknown", "Unknown", "Unknown", false, "External IP detected");
        cache.put(ip, fallback);
        return fallback;
    }

    private boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") ||
               ip.startsWith("192.168.") ||
               ip.startsWith("127.") ||
               (ip.startsWith("172.") && isClassBPrivate(ip));
    }

    private boolean isClassBPrivate(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length >= 2) {
            try {
                int second = Integer.parseInt(parts[1]);
                return second >= 16 && second <= 31;
            } catch (NumberFormatException ignored) {}
        }
        return false;
    }
}
