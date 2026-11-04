package com.example.spamdetector;

import java.util.List;

public record IocExtractionReport(
        List<String> defangedUrls,      // e.g. hxxp://bit[.]ly/claim
        List<String> extractedDomains,   // e.g. paypa1-security.com
        List<String> extractedIps,       // e.g. 192.168.1.100
        List<String> extractedEmails,    // e.g. attacker[at]mailinator.com
        String messageSha256Hash,        // SHA-256 digital artifact hash
        int totalIocsFound
) {}
