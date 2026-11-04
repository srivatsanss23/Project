package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Cybersecurity Threat Intelligence & SOC Observables Service:
 * 1. MITRE ATT&CK Matrix Mapping (T1566 Initial Access, T1027 Defense Evasion, etc.)
 * 2. Automated IOC Extraction with Safe Defanging (hxxp, [.] domains) & SHA-256 Fingerprinting
 * 3. STIX 2.1 Threat Bundle Generation for SIEM / SOAR Ingestion
 */
@Service
public class CyberThreatIntelService {

    private static final Pattern URL_PATTERN = Pattern.compile("(?i)\\bhttps?://[^\\s<>\"'\\[\\]{}|\\\\^`]+");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("(?i)\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b");

    /**
     * Map detected characteristics into official MITRE ATT&CK Enterprise Matrix Techniques
     */
    public List<MitreAttackTechnique> mapMitreAttacks(SpamResponse response, String rawText) {
        List<MitreAttackTechnique> techniques = new ArrayList<>();

        if (response.getScore() < 25) {
            return techniques; // Clean or benign
        }

        // T1566.002: Spearphishing Link
        boolean hasLinks = (response.getCategoryScores() != null && response.getCategoryScores().getOrDefault("Links", 0) > 0)
                || URL_PATTERN.matcher(rawText).find();
        if (hasLinks) {
            techniques.add(new MitreAttackTechnique(
                    "T1566.002",
                    "Phishing: Spearphishing Link",
                    "Initial Access",
                    "Adversary sends targeted spam or deceptive communication containing a malicious hyperlink designed to steal credentials or deliver secondary payloads.",
                    response.getScore() >= 55 ? "HIGH" : "MEDIUM"
            ));
        }

        // T1566.001: Spearphishing Attachment / Credential Harvest
        int credScore = response.getCategoryScores() != null ? response.getCategoryScores().getOrDefault("Credentials", 0) : 0;
        if (credScore >= 25 || rawText.toLowerCase().contains("password") || rawText.toLowerCase().contains("login")) {
            techniques.add(new MitreAttackTechnique(
                    "T1056.003",
                    "Input Capture: Web Portal Credential Harvesting",
                    "Credential Access",
                    "Social engineering lures compel the victim into entering authentication credentials, OTPs, or passwords into attacker-controlled infrastructure.",
                    credScore >= 40 ? "HIGH" : "MEDIUM"
            ));
        }

        // T1036: Masquerading (Brand Spoofing & Typosquatting)
        if (response.getBrandFindings() != null && !response.getBrandFindings().isEmpty()) {
            techniques.add(new MitreAttackTechnique(
                    "T1036.007",
                    "Masquerading: Double Extension & Brand Typosquatting",
                    "Defense Evasion",
                    "Adversary manipulates domain lookalikes (e.g. 'paypa1.com') and visual mimicry to trick recipients into trusting untrusted domains.",
                    "HIGH"
            ));
        }

        // T1027: Obfuscated Files or Information (Adversarial Homoglyphs / Zero-Width / Leet-speak)
        if (response.getLinguisticProfile() != null && response.getLinguisticProfile().linguisticAnomalyScore() >= 25) {
            techniques.add(new MitreAttackTechnique(
                    "T1027.013",
                    "Obfuscated Files or Information: Steganography & Encoded Unicode Perturbation",
                    "Defense Evasion",
                    "Adversary injects Cyrillic homoglyphs, invisible zero-width code points, or leet-speak character substitutions to evade automated spam filter signatures.",
                    "HIGH"
            ));
        }

        // T1566: Email Header Spoofing (SPF/DKIM Mismatch)
        if (response.getEmailHeaderReport() != null && response.getEmailHeaderReport().isSenderSpoofed()) {
            techniques.add(new MitreAttackTechnique(
                    "T1566",
                    "Phishing: Sender Address Spoofing (RFC-5322 Inconsistency)",
                    "Initial Access",
                    "Adversary forges display name or From: headers while routing replies to disparate attacker infrastructure, failing SPF/DKIM alignment.",
                    "HIGH"
            ));
        }

        return techniques;
    }

    /**
     * Extracts IOCs and securely defangs them so analysts can copy them safely without accidental execution
     */
    public IocExtractionReport extractIocs(String text) {
        if (text == null || text.isBlank()) {
            return new IocExtractionReport(List.of(), List.of(), List.of(), List.of(), calculateSha256(""), 0);
        }

        List<String> defangedUrls = new ArrayList<>();
        List<String> domains = new ArrayList<>();
        List<String> ips = new ArrayList<>();
        List<String> emails = new ArrayList<>();

        // URLs
        Matcher urlMatcher = URL_PATTERN.matcher(text);
        while (urlMatcher.find()) {
            String rawUrl = urlMatcher.group();
            String defanged = defangUrl(rawUrl);
            defangedUrls.add(defanged);

            try {
                java.net.URI uri = java.net.URI.create(rawUrl);
                String host = uri.getHost();
                if (host != null && !host.isBlank() && !domains.contains(host)) {
                    domains.add(host.replace(".", "[.]"));
                }
            } catch (Exception ignored) {}
        }

        // IPs
        Matcher ipMatcher = IP_PATTERN.matcher(text);
        while (ipMatcher.find()) {
            String ip = ipMatcher.group();
            if (!ips.contains(ip)) {
                ips.add(ip.replace(".", "[.]"));
            }
        }

        // Emails
        Matcher emailMatcher = EMAIL_PATTERN.matcher(text);
        while (emailMatcher.find()) {
            String em = emailMatcher.group();
            if (!emails.contains(em)) {
                emails.add(em.replace("@", "[at]").replace(".", "[.]"));
            }
        }

        String sha256 = calculateSha256(text);
        int total = defangedUrls.size() + domains.size() + ips.size() + emails.size();

        return new IocExtractionReport(
                defangedUrls,
                domains,
                ips,
                emails,
                sha256,
                total
        );
    }

    /**
     * Builds a valid STIX 2.1 Threat Report JSON bundle representing the incident
     */
    public Map<String, Object> generateStixBundle(SpamResponse response, String rawText, List<MitreAttackTechnique> techniques, IocExtractionReport iocs) {
        String bundleId = "bundle--" + UUID.randomUUID();
        String incidentId = "incident--" + UUID.randomUUID();
        String identityId = "identity--" + UUID.randomUUID();

        Map<String, Object> identity = Map.of(
                "type", "identity",
                "spec_version", "2.1",
                "id", identityId,
                "name", "SpamGuard AI Threat Engine",
                "identity_class", "system"
        );

        Map<String, Object> indicator = Map.of(
                "type", "indicator",
                "spec_version", "2.1",
                "id", "indicator--" + UUID.randomUUID(),
                "created", new Date().toInstant().toString(),
                "name", "SpamGuard Detection: " + response.getPrediction() + " (Score " + response.getScore() + "/100)",
                "description", "Malicious or deceptive communication detected via multi-model ensemble",
                "indicator_types", List.of("malicious-activity", "phishing"),
                "pattern", "[file:hashes.'SHA-256' = '" + iocs.messageSha256Hash() + "']",
                "pattern_type", "stix"
        );

        List<Map<String, Object>> attackPatterns = new ArrayList<>();
        for (MitreAttackTechnique t : techniques) {
            attackPatterns.add(Map.of(
                    "type", "attack-pattern",
                    "spec_version", "2.1",
                    "id", "attack-pattern--" + UUID.randomUUID(),
                    "name", t.name(),
                    "description", t.description(),
                    "external_references", List.of(Map.of(
                            "source_name", "mitre-attack",
                            "external_id", t.id(),
                            "url", "https://attack.mitre.org/techniques/" + t.id().replace(".", "/")
                    ))
            ));
        }

        List<Object> objects = new ArrayList<>();
        objects.add(identity);
        objects.add(indicator);
        objects.addAll(attackPatterns);

        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("type", "bundle");
        bundle.put("id", bundleId);
        bundle.put("spec_version", "2.1");
        bundle.put("objects", objects);

        return bundle;
    }

    private String defangUrl(String url) {
        return url.replace("http://", "hxxp://")
                  .replace("https://", "hxxps://")
                  .replace(".", "[.]");
    }

    private String calculateSha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "0000000000000000000000000000000000000000000000000000000000000000";
        }
    }
}
