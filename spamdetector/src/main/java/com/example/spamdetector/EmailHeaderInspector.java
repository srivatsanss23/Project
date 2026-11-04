package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class EmailHeaderInspector {

    private static final Pattern HEADER_LINE = Pattern.compile("(?im)^([a-zA-Z0-9_-]+):\\s*(.*)$");
    private static final Pattern EMAIL_ADDR = Pattern.compile("(?i)[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})");

    public record EmailHeaderReport(
            boolean isEmailFormat,
            String fromHeader,
            String replyToHeader,
            String returnPathHeader,
            String subjectHeader,
            boolean isSenderSpoofed,
            String spfStatus, // PASS, FAIL, NONE
            String dkimStatus, // PASS, FAIL, NONE
            String dmarcStatus, // PASS, FAIL, NONE
            List<String> relayHops,
            int headerRiskScore,
            List<String> warnings
    ) {}

    public EmailHeaderReport analyzeHeaders(String rawText) {
        if (rawText == null || rawText.isBlank()) {
            return new EmailHeaderReport(false, null, null, null, null, false, "NONE", "NONE", "NONE", Collections.emptyList(), 0, Collections.emptyList());
        }

        Map<String, List<String>> headers = new HashMap<>();
        String[] lines = rawText.split("\\r?\\n");
        String currentKey = null;

        for (String line : lines) {
            if (line.isBlank()) {
                // Header section ends at first empty line in standard RFC-822
                break;
            }

            Matcher matcher = HEADER_LINE.matcher(line);
            if (matcher.find()) {
                currentKey = matcher.group(1).toLowerCase();
                String value = matcher.group(2).trim();
                headers.computeIfAbsent(currentKey, k -> new ArrayList<>()).add(value);
            } else if (currentKey != null && (line.startsWith(" ") || line.startsWith("\t"))) {
                // Multiline header fold
                int lastIdx = headers.get(currentKey).size() - 1;
                headers.get(currentKey).set(lastIdx, headers.get(currentKey).get(lastIdx) + " " + line.trim());
            }
        }

        boolean isEmailFormat = headers.containsKey("from") || headers.containsKey("received") || headers.containsKey("subject");
        if (!isEmailFormat) {
            return new EmailHeaderReport(false, null, null, null, null, false, "NONE", "NONE", "NONE", Collections.emptyList(), 0, Collections.emptyList());
        }

        String from = getFirst(headers, "from");
        String replyTo = getFirst(headers, "reply-to");
        String returnPath = getFirst(headers, "return-path");
        String subject = getFirst(headers, "subject");
        String authResults = getFirst(headers, "authentication-results");

        List<String> warnings = new ArrayList<>();
        int score = 0;
        boolean spoofed = false;

        // 1. Compare From domain vs Reply-To domain
        String fromDomain = extractDomain(from);
        String replyToDomain = extractDomain(replyTo);
        String returnPathDomain = extractDomain(returnPath);

        if (fromDomain != null && replyToDomain != null && !fromDomain.equalsIgnoreCase(replyToDomain)) {
            spoofed = true;
            score += 35;
            warnings.add("From domain (" + fromDomain + ") does not match Reply-To domain (" + replyToDomain + ") — High Spoofing Indicator");
        }

        if (fromDomain != null && returnPathDomain != null && !fromDomain.equalsIgnoreCase(returnPathDomain)) {
            spoofed = true;
            score += 25;
            warnings.add("From domain (" + fromDomain + ") does not match Return-Path bounce domain (" + returnPathDomain + ")");
        }

        // 2. Parse SPF, DKIM, DMARC
        String spf = "NONE";
        String dkim = "NONE";
        String dmarc = "NONE";

        if (authResults != null) {
            String lowerAuth = authResults.toLowerCase();
            if (lowerAuth.contains("spf=fail") || lowerAuth.contains("spf=softfail")) {
                spf = "FAIL";
                score += 30;
                warnings.add("SPF authentication failed (Unauthorized sending MTA)");
            } else if (lowerAuth.contains("spf=pass")) {
                spf = "PASS";
            }

            if (lowerAuth.contains("dkim=fail")) {
                dkim = "FAIL";
                score += 30;
                warnings.add("DKIM cryptographic signature verification failed");
            } else if (lowerAuth.contains("dkim=pass")) {
                dkim = "PASS";
            }

            if (lowerAuth.contains("dmarc=fail")) {
                dmarc = "FAIL";
                score += 35;
                warnings.add("DMARC alignment policy failed — Message should be quarantined or rejected");
            } else if (lowerAuth.contains("dmarc=pass")) {
                dmarc = "PASS";
            }
        }

        // 3. Extract Received Hops
        List<String> relayHops = headers.getOrDefault("received", Collections.emptyList());

        return new EmailHeaderReport(
                true,
                from,
                replyTo,
                returnPath,
                subject,
                spoofed,
                spf,
                dkim,
                dmarc,
                relayHops,
                Math.min(score, 100),
                warnings
        );
    }

    private String getFirst(Map<String, List<String>> map, String key) {
        List<String> list = map.get(key);
        return (list != null && !list.isEmpty()) ? list.get(0) : null;
    }

    private String extractDomain(String emailStr) {
        if (emailStr == null) return null;
        Matcher m = EMAIL_ADDR.matcher(emailStr);
        return m.find() ? m.group(1).toLowerCase() : null;
    }
}
