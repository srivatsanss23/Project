package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UrlInspectionService {

    private static final Pattern URL_PATTERN = Pattern.compile("(?i)\\b(https?://[^\\s<>\"'{}|\\\\^`]+|www\\.[^\\s<>\"'{}|\\\\^`]+)");
    private static final Pattern IP_URL_PATTERN = Pattern.compile("https?://(\\d{1,3}\\.){3}\\d{1,3}(:\\d+)?(/.*)?");

    private static final Set<String> SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl", "tiny.cc", "cutt.ly"
    );

    private static final Set<String> HIGH_RISK_TLDS = Set.of(
            ".xyz", ".top", ".click", ".zip", ".mov", ".country", ".work", ".biz", ".download", ".loan", ".gq", ".cf", ".tk", ".ml"
    );

    private static final Set<String> PHISHING_URL_TOKENS = Set.of(
            "login", "verify", "secure", "update", "banking", "wallet", "support", "account", "signin", "password", "confirm"
    );

    public record UrlFinding(
            String originalUrl,
            boolean isIpHost,
            boolean isShortened,
            boolean isSuspiciousTld,
            boolean hasPhishingKeyword,
            int riskScore,
            List<String> warnings
    ) {}

    public List<UrlFinding> inspectUrls(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        List<UrlFinding> findings = new ArrayList<>();
        Matcher matcher = URL_PATTERN.matcher(text);

        while (matcher.find()) {
            String rawUrl = matcher.group();
            String normalizedUrl = rawUrl.toLowerCase();
            if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
                normalizedUrl = "https://" + normalizedUrl;
            }

            boolean isIpHost = IP_URL_PATTERN.matcher(normalizedUrl).matches();
            boolean isShortened = false;
            boolean isSuspiciousTld = false;
            boolean hasPhishingKeyword = false;
            List<String> warnings = new ArrayList<>();
            int risk = 10; // Baseline risk for having an external link

            try {
                URI uri = new URI(normalizedUrl);
                String host = uri.getHost() != null ? uri.getHost().toLowerCase() : "";

                if (isIpHost) {
                    risk += 35;
                    warnings.add("Link uses raw IP address instead of domain (" + host + ")");
                }

                for (String shortener : SHORTENERS) {
                    if (host.equals(shortener) || host.endsWith("." + shortener)) {
                        isShortened = true;
                        risk += 20;
                        warnings.add("Obfuscated short URL detected (" + host + ")");
                        break;
                    }
                }

                for (String tld : HIGH_RISK_TLDS) {
                    if (host.endsWith(tld)) {
                        isSuspiciousTld = true;
                        risk += 25;
                        warnings.add("Link uses high-risk suspicious TLD (" + tld + ")");
                        break;
                    }
                }

                String path = uri.getPath() != null ? uri.getPath().toLowerCase() : "";
                for (String token : PHISHING_URL_TOKENS) {
                    if (path.contains(token) || host.contains(token)) {
                        hasPhishingKeyword = true;
                        risk += 15;
                        warnings.add("URL contains credential/phishing keyword: '" + token + "'");
                        break;
                    }
                }
            } catch (Exception e) {
                risk += 15;
                warnings.add("Malformed URL detected: " + rawUrl);
            }

            findings.add(new UrlFinding(
                    rawUrl,
                    isIpHost,
                    isShortened,
                    isSuspiciousTld,
                    hasPhishingKeyword,
                    Math.min(risk, 50),
                    warnings
            ));
        }

        return findings;
    }
}
