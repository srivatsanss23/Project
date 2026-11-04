package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SpamService {

    private final TextNormalizer textNormalizer;
    private final UrlInspectionService urlInspectionService;
    private final NaiveBayesSpamClassifier naiveBayesClassifier;
    private final TfIdfSpamClassifier tfIdfClassifier;
    private final LogisticRegressionSpamClassifier logisticRegressionClassifier;
    private final LinguisticAnalysisService linguisticAnalysisService;
    private final CyberThreatIntelService cyberThreatIntelService;
    private final DisposableEmailService disposableEmailService;
    private final IpThreatIntelligenceService ipThreatService;
    private final AiSemanticAnalysisService aiSemanticService;
    private final BrandImpersonationService brandService;
    private final EmailHeaderInspector emailHeaderInspector;
    private final ScanRecordRepository scanRecordRepository;
    private final ExternalThreatIntelClient externalThreatClient;
    private final CustomRuleEngineService customRuleService;
    private final IncidentWebhookService incidentWebhookService;

    // Categorized dictionaries
    private static final Map<String, List<String>> KEYWORD_CATEGORIES = new LinkedHashMap<>();

    static {
        KEYWORD_CATEGORIES.put("CREDENTIAL_HARVESTING", List.of(
                "password", "passcode", "verify account", "confirm account", "security alert",
                "unauthorized access", "login immediately", "identity verification", "ssn",
                "bank account", "routing number", "credit card", "security code", "cvv", "otp", "pin"
        ));

        KEYWORD_CATEGORIES.put("URGENCY", List.of(
                "urgent", "immediately", "immediate action required", "within 24 hours",
                "expires today", "final notice", "account suspended", "act now", "limited time",
                "last chance", "don't miss out", "time sensitive", "critical alert"
        ));

        KEYWORD_CATEGORIES.put("FINANCIAL_SCAM", List.of(
                "lottery", "jackpot", "cash prize", "wire transfer", "bitcoin", "crypto",
                "claim prize", "tax refund", "free cash", "inheritance", "guaranteed return",
                "investment opportunity", "gift card", "claim now", "won $", "won £", "won €"
        ));

        KEYWORD_CATEGORIES.put("PROMOTIONAL", List.of(
                "100% free", "buy now", "click here", "subscribe now", "exclusive deal",
                "winner", "won", "special promotion", "congratulations", "miracle"
        ));
    }

    private static final Pattern CURRENCY_PATTERN = Pattern.compile("(?i)([$€£¥₹]|\\b(usd|eur|gbp|inr|btc|crypto)\\b)");
    private static final Pattern REPEATED_PUNCTUATION = Pattern.compile("[!?$]{2,}");
    private static final Pattern PHONE_PATTERN = Pattern.compile("(?i)\\b(\\+?\\d{1,3}[-.\s]?)?\\(?\\d{3}\\)?[-.\s]?\\d{3}[-.\s]?\\d{4}\\b");

    public SpamService(TextNormalizer textNormalizer,
                       UrlInspectionService urlInspectionService,
                       NaiveBayesSpamClassifier naiveBayesClassifier,
                       TfIdfSpamClassifier tfIdfClassifier,
                       LogisticRegressionSpamClassifier logisticRegressionClassifier,
                       LinguisticAnalysisService linguisticAnalysisService,
                       CyberThreatIntelService cyberThreatIntelService,
                       DisposableEmailService disposableEmailService,
                       IpThreatIntelligenceService ipThreatService,
                       AiSemanticAnalysisService aiSemanticService,
                       BrandImpersonationService brandService,
                       EmailHeaderInspector emailHeaderInspector,
                       ScanRecordRepository scanRecordRepository,
                       ExternalThreatIntelClient externalThreatClient,
                       CustomRuleEngineService customRuleService,
                       IncidentWebhookService incidentWebhookService) {
        this.textNormalizer = textNormalizer;
        this.urlInspectionService = urlInspectionService;
        this.naiveBayesClassifier = naiveBayesClassifier;
        this.tfIdfClassifier = tfIdfClassifier;
        this.logisticRegressionClassifier = logisticRegressionClassifier;
        this.linguisticAnalysisService = linguisticAnalysisService;
        this.cyberThreatIntelService = cyberThreatIntelService;
        this.disposableEmailService = disposableEmailService;
        this.ipThreatService = ipThreatService;
        this.aiSemanticService = aiSemanticService;
        this.brandService = brandService;
        this.emailHeaderInspector = emailHeaderInspector;
        this.scanRecordRepository = scanRecordRepository;
        this.externalThreatClient = externalThreatClient;
        this.customRuleService = customRuleService;
        this.incidentWebhookService = incidentWebhookService;
    }

    public SpamResponse classify(String rawText) {
        long startTime = System.currentTimeMillis();

        if (rawText == null || rawText.trim().isEmpty()) {
            return new SpamResponse(
                    "UNKNOWN",
                    0,
                    "LOW",
                    List.of("Empty or whitespace-only message provided"),
                    Collections.emptyList(),
                    Collections.emptyMap(),
                    new NaiveBayesSpamClassifier.NaiveBayesResult(0.0, 0, "HAM", Collections.emptyList(), Collections.emptyList(), 0),
                    new TfIdfSpamClassifier.TfIdfResult(0.0, 0.0, 0, "HAM", Collections.emptyList()),
                    new LogisticRegressionSpamClassifier.LogisticRegressionResult(0, 0.0, 0.0, Collections.emptyList()),
                    new LinguisticAnalysisService.LinguisticProfile(0.0, 0.0, 0.0, 0.0, 0.0, 100.0, 0, List.of("Empty message")),
                    Collections.emptyList(),
                    Collections.emptyList(),
                    new AiSemanticAnalysisService.AiAnalysisResult(false, "Offline", "LEGITIMATE", 0, "Empty message"),
                    Collections.emptyList(),
                    new EmailHeaderInspector.EmailHeaderReport(false, null, null, null, null, false, "NONE", "NONE", "NONE", Collections.emptyList(), 0, Collections.emptyList()),
                    Collections.emptyList(),
                    new IocExtractionReport(Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), Collections.emptyList(), "0", 0),
                    Instant.now(),
                    0
            );
        }

        String normalizedText = textNormalizer.normalize(rawText);
        List<String> reasons = new ArrayList<>();
        List<FlaggedToken> flaggedTokens = new ArrayList<>();
        Map<String, Integer> categoryScores = new LinkedHashMap<>();

        int credentialsScore = 0;
        int urgencyScore = 0;
        int financialScore = 0;
        int promoScore = 0;
        int formattingScore = 0;
        int linkScore = 0;

        // 1. Keyword Categorical Analysis with Word Boundary Regex
        for (Map.Entry<String, List<String>> entry : KEYWORD_CATEGORIES.entrySet()) {
            String category = entry.getKey();
            List<String> keywords = entry.getValue();
            List<String> matchedWords = new ArrayList<>();

            for (String keyword : keywords) {
                Pattern pattern = Pattern.compile("(?i)\\b" + Pattern.quote(keyword) + "\\b");
                Matcher matcher = pattern.matcher(normalizedText);

                while (matcher.find()) {
                    matchedWords.add(keyword);
                    flaggedTokens.add(new FlaggedToken(
                            rawText.substring(Math.min(matcher.start(), rawText.length()), Math.min(matcher.end(), rawText.length())),
                            category,
                            matcher.start(),
                            matcher.end()
                    ));
                }
            }

            if (!matchedWords.isEmpty()) {
                switch (category) {
                    case "CREDENTIAL_HARVESTING" -> {
                        credentialsScore += Math.min(matchedWords.size() * 25, 60);
                        reasons.add("Critical credential or security keywords: " + String.join(", ", new LinkedHashSet<>(matchedWords)));
                    }
                    case "URGENCY" -> {
                        urgencyScore += Math.min(matchedWords.size() * 15, 35);
                        reasons.add("High-pressure urgency indicators: " + String.join(", ", new LinkedHashSet<>(matchedWords)));
                    }
                    case "FINANCIAL_SCAM" -> {
                        financialScore += Math.min(matchedWords.size() * 20, 50);
                        reasons.add("Financial or lottery solicitation words: " + String.join(", ", new LinkedHashSet<>(matchedWords)));
                    }
                    case "PROMOTIONAL" -> {
                        promoScore += Math.min(matchedWords.size() * 10, 25);
                        reasons.add("Promotional / bait keywords: " + String.join(", ", new LinkedHashSet<>(matchedWords)));
                    }
                }
            }
        }

        // 2. URL and Link Analysis
        List<UrlInspectionService.UrlFinding> urlFindings = urlInspectionService.inspectUrls(normalizedText);
        List<String> rawUrls = new ArrayList<>();
        for (UrlInspectionService.UrlFinding finding : urlFindings) {
            rawUrls.add(finding.originalUrl());
            linkScore += finding.riskScore();
            int idx = rawText.indexOf(finding.originalUrl());
            if (idx >= 0) {
                flaggedTokens.add(new FlaggedToken(finding.originalUrl(), "LINK", idx, idx + finding.originalUrl().length()));
            }
            reasons.addAll(finding.warnings());
        }
        linkScore = Math.min(linkScore, 50);

        // 3. External Threat Intelligence API (Safe Browsing & VirusTotal)
        List<ExternalThreatIntelClient.ExternalThreatReport> extThreats = externalThreatClient.checkUrls(rawUrls);
        for (ExternalThreatIntelClient.ExternalThreatReport rep : extThreats) {
            if (rep.isMalicious()) {
                linkScore += 40;
                reasons.add("Live Threat API Alert (" + rep.sourceApi() + "): " + rep.details());
            }
        }

        // 4. Custom Enterprise Rules
        List<CustomRuleEngineService.RuleMatch> ruleMatches = customRuleService.evaluateCustomRules(normalizedText);
        for (CustomRuleEngineService.RuleMatch rm : ruleMatches) {
            credentialsScore += rm.scoreDelta();
            reasons.add(rm.description());
        }

        // 5. Brand Impersonation & Typosquatting Defense
        List<BrandImpersonationService.BrandFinding> brandFindings = brandService.detectImpersonation(normalizedText, urlFindings);
        for (BrandImpersonationService.BrandFinding brand : brandFindings) {
            credentialsScore += brand.penaltyScore();
            reasons.add(brand.description());
            int idx = rawText.toLowerCase().indexOf(brand.detectedVariant().toLowerCase());
            if (idx >= 0) {
                flaggedTokens.add(new FlaggedToken(brand.detectedVariant(), "BRAND_SPOOF", idx, idx + brand.detectedVariant().length()));
            }
        }

        // 6. RFC-822 Email Header & Spoofing Inspector
        EmailHeaderInspector.EmailHeaderReport headerReport = emailHeaderInspector.analyzeHeaders(rawText);
        if (headerReport.isEmailFormat()) {
            if (headerReport.isSenderSpoofed() || headerReport.headerRiskScore() > 0) {
                credentialsScore += headerReport.headerRiskScore();
                reasons.addAll(headerReport.warnings());
            }
        }

        // 7. Open Source Disposable Email Blocklist Check
        List<DisposableEmailService.EmailFinding> emailFindings = disposableEmailService.scanEmails(normalizedText);
        for (DisposableEmailService.EmailFinding email : emailFindings) {
            if (email.isDisposable()) {
                credentialsScore += 25;
                reasons.add(email.warning());
                int idx = rawText.indexOf(email.fullEmail());
                if (idx >= 0) {
                    flaggedTokens.add(new FlaggedToken(email.fullEmail(), "DISPOSABLE_EMAIL", idx, idx + email.fullEmail().length()));
                }
            }
        }

        // 8. Live External API: IP Threat & Geolocation Intelligence
        List<IpThreatIntelligenceService.IpIntelligenceResult> ipThreats = ipThreatService.analyzeIpsInText(normalizedText);
        for (IpThreatIntelligenceService.IpIntelligenceResult ipRes : ipThreats) {
            reasons.add("IP Intel (" + ipRes.ip() + "): " + ipRes.riskSummary());
            if (ipRes.isPrivate()) {
                linkScore += 20;
            } else if (ipRes.isHostingOrCloud()) {
                linkScore += 15;
            }
        }

        // 9. Open Source Machine Learning Models: Tri-Model Ensemble (NB + TF-IDF + Logistic Regression)
        NaiveBayesSpamClassifier.NaiveBayesResult mlResult = naiveBayesClassifier.predict(normalizedText);
        TfIdfSpamClassifier.TfIdfResult tfIdfResult = tfIdfClassifier.predict(normalizedText);
        LogisticRegressionSpamClassifier.LogisticRegressionResult lrResult = logisticRegressionClassifier.predict(normalizedText);

        if (mlResult.mlScore() >= 60) {
            reasons.add("Naive Bayes Probability: " + mlResult.mlScore() + "% spam likelihood (Signals: " + String.join(", ", mlResult.topSpamWords()) + ")");
        }
        if (tfIdfResult.tfIdfScore() >= 55) {
            reasons.add("TF-IDF Vector Space Similarity: " + tfIdfResult.tfIdfScore() + "% cosine similarity to spam centroid (Keywords: " + String.join(", ", tfIdfResult.topTfIdfKeywords()) + ")");
        }
        if (lrResult.lrScore() >= 55) {
            reasons.add("Logistic Regression Probability: " + lrResult.lrScore() + "% spam likelihood (Top tokens: " + String.join(", ", lrResult.topContributingTokens()) + ")");
        }

        // 10. Information-Theoretic & Linguistic Stylometry Analysis
        LinguisticAnalysisService.LinguisticProfile linguisticProfile = linguisticAnalysisService.analyze(rawText);
        if (linguisticProfile.linguisticAnomalyScore() > 20) {
            formattingScore += (int) (linguisticProfile.linguisticAnomalyScore() * 0.4);
            reasons.addAll(linguisticProfile.stylisticIndicators());
        }

        // 11. AI Semantic Intent Analysis
        AiSemanticAnalysisService.AiAnalysisResult aiResult = aiSemanticService.analyzeIntent(rawText);
        if ("SPAM".equalsIgnoreCase(aiResult.semanticVerdict()) || "SUSPICIOUS".equalsIgnoreCase(aiResult.semanticVerdict())) {
            reasons.add("AI Intent Engine (" + aiResult.providerName() + "): " + aiResult.intentExplanation());
        }

        // 12. Currency & Formatting
        Matcher currencyMatcher = CURRENCY_PATTERN.matcher(rawText);
        int currencyMatches = 0;
        while (currencyMatcher.find()) {
            currencyMatches++;
            flaggedTokens.add(new FlaggedToken(currencyMatcher.group(), "FINANCIAL", currencyMatcher.start(), currencyMatcher.end()));
        }
        if (currencyMatches > 0) {
            financialScore += Math.min(currencyMatches * 10, 20);
            reasons.add("Currency symbols / money references detected (" + currencyMatches + " occurrence(s))");
        }

        long upperLetters = rawText.chars().filter(Character::isUpperCase).count();
        long totalLetters = rawText.chars().filter(Character::isLetter).count();
        if (totalLetters > 8 && ((double) upperLetters / totalLetters) > 0.35) {
            formattingScore += 15;
            reasons.add("Excessive uppercase lettering (" + Math.round(((double) upperLetters / totalLetters) * 100) + "% capital letters)");
        }

        Matcher punctMatcher = REPEATED_PUNCTUATION.matcher(rawText);
        if (punctMatcher.find()) {
            formattingScore += 10;
            reasons.add("Excessive punctuation marks (e.g., '!!', '$$')");
        }

        Matcher phoneMatcher = PHONE_PATTERN.matcher(rawText);
        if (phoneMatcher.find() && (urgencyScore > 0 || credentialsScore > 0)) {
            formattingScore += 15;
            reasons.add("Call-back phone number detected in high-urgency context");
        }

        categoryScores.put("Credentials", Math.max(credentialsScore, 0));
        categoryScores.put("Urgency", urgencyScore);
        categoryScores.put("Financial", financialScore);
        categoryScores.put("Promotional", promoScore);
        categoryScores.put("Links", linkScore);
        categoryScores.put("Formatting", formattingScore);

        int heuristicRaw = credentialsScore + urgencyScore + financialScore + promoScore + formattingScore + linkScore;
        int heuristicScore = Math.max(0, Math.min(heuristicRaw, 100));

        // Academic Multi-Model Tri-Model Stacking Ensemble Formula:
        int ensembleScore = (int) Math.round(
                (heuristicScore * 0.25) +
                (mlResult.mlScore() * 0.20) +
                (tfIdfResult.tfIdfScore() * 0.15) +
                (lrResult.lrScore() * 0.20) +
                (linguisticProfile.linguisticAnomalyScore() * 0.10) +
                (Math.min(linkScore, 50) * 0.10)
        );

        int finalScore = Math.min(Math.max(ensembleScore, heuristicScore), 100);

        String verdict;
        String riskLevel;

        if (finalScore >= 55) {
            verdict = "SPAM";
            riskLevel = finalScore >= 80 ? "CRITICAL" : "HIGH";
        } else if (finalScore >= 30) {
            verdict = "SUSPICIOUS";
            riskLevel = "MEDIUM";
        } else {
            verdict = "LEGITIMATE";
            riskLevel = "LOW";
        }

        if (reasons.isEmpty()) {
            reasons.add("No significant spam or phishing indicators detected");
        }

        long executionTimeMs = System.currentTimeMillis() - startTime;

        // Draft response to allow MITRE ATT&CK and IOC correlation
        SpamResponse tempResponse = new SpamResponse(
                verdict,
                finalScore,
                riskLevel,
                reasons,
                flaggedTokens,
                categoryScores,
                mlResult,
                tfIdfResult,
                lrResult,
                linguisticProfile,
                ipThreats,
                emailFindings,
                aiResult,
                brandFindings,
                headerReport,
                Collections.emptyList(),
                null,
                Instant.now(),
                executionTimeMs
        );

        // Cybersecurity Major Enhancements:
        // 1. MITRE ATT&CK Matrix Mapping
        List<MitreAttackTechnique> mitreTechniques = cyberThreatIntelService.mapMitreAttacks(tempResponse, rawText);
        // 2. Automated IOC Extraction with Safe Defanging
        IocExtractionReport iocReport = cyberThreatIntelService.extractIocs(rawText);

        SpamResponse response = new SpamResponse(
                verdict,
                finalScore,
                riskLevel,
                reasons,
                flaggedTokens,
                categoryScores,
                mlResult,
                tfIdfResult,
                lrResult,
                linguisticProfile,
                ipThreats,
                emailFindings,
                aiResult,
                brandFindings,
                headerReport,
                mitreTechniques,
                iocReport,
                Instant.now(),
                executionTimeMs
        );

        try {
            if (scanRecordRepository != null) {
                String snippet = rawText.length() > 120 ? rawText.substring(0, 120) + "..." : rawText;
                String topReason = !reasons.isEmpty() ? reasons.get(0) : "Normal message";
                scanRecordRepository.save(new ScanRecord(
                        snippet,
                        verdict,
                        finalScore,
                        riskLevel,
                        headerReport.isEmailFormat() ? "EMAIL_HEADER" : "TEXT",
                        topReason,
                        mlResult.spamProbability(),
                        executionTimeMs,
                        Instant.now()
                ));
            }
        } catch (Exception ignored) {}

        try {
            if (incidentWebhookService != null) {
                String snippet = rawText.length() > 120 ? rawText.substring(0, 120) + "..." : rawText;
                incidentWebhookService.dispatchIncidentAlert(response, snippet);
            }
        } catch (Exception ignored) {}

        return response;
    }
}
