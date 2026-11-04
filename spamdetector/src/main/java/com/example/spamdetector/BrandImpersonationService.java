package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class BrandImpersonationService {

    private static final List<String> TARGETED_BRANDS = List.of(
            "paypal", "microsoft", "apple", "amazon", "netflix", "chase",
            "wellsfargo", "bankofamerica", "coinbase", "binance", "dhl", "fedex", "google", "meta"
    );

    // Common typosquatted/lookalike patterns
    private static final Map<String, List<String>> COMMON_LOOKALIKES = Map.of(
            "paypal", List.of("paypa1", "pay-pal", "paypal-security", "paypal-service", "paypaI"),
            "apple", List.of("app1e", "apple-id", "icloud-verify", "apple-support"),
            "microsoft", List.of("micros0ft", "ms-verify", "office365-security", "microsoft-login"),
            "netflix", List.of("netfllix", "net-flix", "netflix-billing", "netflix-update"),
            "amazon", List.of("amaz0n", "amazon-delivery", "amazon-prime-alert"),
            "chase", List.of("chase-online", "chase-bank-verify", "chase-alert")
    );

    public record BrandFinding(
            String targetBrand,
            String detectedVariant,
            String riskType, // "TYPOSQUATTING", "LOOKALIKE_DOMAIN", "HIGH_RISK_IMPERSONATION"
            int penaltyScore,
            String description
    ) {}

    public List<BrandFinding> detectImpersonation(String text, List<UrlInspectionService.UrlFinding> urlFindings) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        List<BrandFinding> findings = new ArrayList<>();
        String lower = text.toLowerCase();

        // 1. Check known lookalike and typosquatting variants
        for (Map.Entry<String, List<String>> entry : COMMON_LOOKALIKES.entrySet()) {
            String brand = entry.getKey();
            for (String lookalike : entry.getValue()) {
                if (lower.contains(lookalike)) {
                    findings.add(new BrandFinding(
                            brand,
                            lookalike,
                            "TYPOSQUATTING",
                            35,
                            "Detected known deceptive brand typosquat / spoof pattern: '" + lookalike + "' impersonating " + brand.toUpperCase()
                    ));
                }
            }
        }

        // 2. Check URLs for brand names combined with phishing words (e.g., 'paypal-security-update.com')
        for (UrlInspectionService.UrlFinding url : urlFindings) {
            String urlLower = url.originalUrl().toLowerCase();
            for (String brand : TARGETED_BRANDS) {
                if (urlLower.contains(brand)) {
                    // Check if it's NOT the genuine official domain (e.g. not paypal.com, not apple.com)
                    boolean isGenuine = urlLower.contains("." + brand + ".com") ||
                                        urlLower.contains("://" + brand + ".com") ||
                                        urlLower.contains("." + brand + ".org");

                    if (!isGenuine && (urlLower.contains("-") || urlLower.contains("login") || urlLower.contains("verify") || urlLower.contains("secure"))) {
                        findings.add(new BrandFinding(
                                brand,
                                url.originalUrl(),
                                "LOOKALIKE_DOMAIN",
                                40,
                                "Deceptive brand impersonation domain detected: '" + url.originalUrl() + "' attempting to mimic " + brand.toUpperCase()
                        ));
                    }
                }
            }
        }

        // 3. Brand mention paired with high urgency/credentials in text
        for (String brand : TARGETED_BRANDS) {
            Pattern brandPattern = Pattern.compile("(?i)\\b" + Pattern.quote(brand) + "\\b");
            Matcher brandMatcher = brandPattern.matcher(text);

            if (brandMatcher.find() && (lower.contains("suspended") || lower.contains("unauthorized") || lower.contains("verify your password") || lower.contains("within 24 hours"))) {
                findings.add(new BrandFinding(
                        brand,
                        brand,
                        "HIGH_RISK_IMPERSONATION",
                        25,
                        "Brand name (" + brand.toUpperCase() + ") referenced alongside urgent account coercion"
                ));
            }
        }

        return findings;
    }
}
