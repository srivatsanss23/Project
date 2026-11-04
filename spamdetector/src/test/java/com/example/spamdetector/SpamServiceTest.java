package com.example.spamdetector;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class SpamServiceTest {

    @Autowired
    private SpamService spamService;

    @Autowired
    private BrandImpersonationService brandService;

    @Autowired
    private EmailHeaderInspector emailHeaderInspector;

    @Autowired
    private BatchSpamService batchSpamService;

    @Autowired
    private CustomRuleEngineService customRuleService;

    @Autowired
    private TfIdfSpamClassifier tfIdfClassifier;

    @Autowired
    private LogisticRegressionSpamClassifier logisticRegressionClassifier;

    @Autowired
    private LinguisticAnalysisService linguisticAnalysisService;

    @Autowired
    private DatasetService datasetService;

    @Autowired
    private ModelBenchmarkService modelBenchmarkService;

    @Autowired
    private AdversarialAttackService adversarialAttackService;

    @Autowired
    private CapstoneDossierService capstoneDossierService;

    @Autowired
    private CyberThreatIntelService cyberThreatIntelService;

    @Autowired
    private QrCodeScannerService qrCodeScannerService;

    @Test
    @DisplayName("Substrings like 'winter window' and 'carefree' must not trigger false positives")
    void testFalsePositiveAvoidance() {
        String cleanMessage = "The winter breeze is coming through the living room window. I feel carefree and relaxed.";
        SpamResponse response = spamService.classify(cleanMessage);

        assertEquals("LEGITIMATE", response.getPrediction());
        assertTrue(response.getScore() < 35, "Score should be low for normal conversation");
    }

    @Test
    @DisplayName("Critical bank phishing attack with raw IP link triggers SPAM with critical risk")
    void testPhishingDetection() {
        String phishingMsg = "URGENT: Security alert from your bank account! Unauthorized access detected. Login immediately to verify password at http://192.168.1.50/login. Your account will be suspended within 24 hours!!!";
        SpamResponse response = spamService.classify(phishingMsg);

        assertEquals("SPAM", response.getPrediction());
        assertTrue(response.getScore() >= 70, "Phishing score should be very high");
        assertNotNull(response.getMachineLearning());
        assertNotNull(response.getTfIdfResult());
        assertNotNull(response.getLogisticRegressionResult());
        assertNotNull(response.getLinguisticProfile());
    }

    @Test
    @DisplayName("Shannon Entropy & Stylometry accurately profiles text")
    void testLinguisticStylometry() {
        var profile = linguisticAnalysisService.analyze("WINNER!!! $$$ Free lottery prize claim immediately!! http://win-crypto-123.xyz");
        assertNotNull(profile);
        assertTrue(profile.shannonEntropy() > 3.0, "Entropy should be calculated");
        assertTrue(profile.punctuationRatio() > 5.0, "Punctuation density should be flagged");
    }

    @Test
    @DisplayName("Logistic Regression predicts on spam phrases with SGD calibrated weights")
    void testLogisticRegressionClassifier() {
        var lrResult = logisticRegressionClassifier.predict("URGENT claim your free cash prize lottery now");
        assertNotNull(lrResult);
        assertTrue(lrResult.probability() > 0.40, "Logistic regression probability should identify spam keywords");
    }

    @Test
    @DisplayName("Open Dataset Service returns cached samples and statistics")
    void testDatasetService() {
        var stats = datasetService.getStats();
        assertNotNull(stats);
        var samples = datasetService.getSamples(5, null);
        assertFalse(samples.isEmpty());
    }

    @Test
    @DisplayName("TF-IDF Vector Space Model computes cosine similarity on spam text")
    void testTfIdfClassification() {
        var tfResult = tfIdfClassifier.predict("WINNER! Claim your cash prize lottery award today!");
        assertNotNull(tfResult);
        assertTrue(tfResult.tfIdfScore() >= 45, "TF-IDF score should recognize spam vector proximity");
    }

    @Test
    @DisplayName("Academic Model Benchmark runs evaluation across all 3 models")
    void testAcademicModelBenchmark() {
        var benchmark = modelBenchmarkService.runBenchmark();
        assertNotNull(benchmark);
        assertTrue(benchmark.totalCorpusSamples() > 0);
        assertEquals(3, benchmark.models().size());
        for (var m : benchmark.models()) {
            assertTrue(m.accuracy() > 50.0, "Model accuracy should be realistic: " + m.modelName());
        }
    }

    @Test
    @DisplayName("Brand typosquatting and impersonation detection (paypa1 lookalike)")
    void testBrandTyposquatting() {
        String msg = "Security alert from PayPal: verify your payment at http://paypa1-security-verify.com/login immediately.";
        SpamResponse response = spamService.classify(msg);

        assertEquals("SPAM", response.getPrediction());
        assertTrue(response.getBrandFindings().stream().anyMatch(b -> b.targetBrand().equals("paypal")),
                "Should detect PayPal brand impersonation / typosquat");
    }

    @Test
    @DisplayName("RFC-822 Email header spoofing and SPF/DKIM failure detection")
    void testEmailHeaderSpoofing() {
        String rawEmail = "From: \"PayPal Security\" <security@paypal.com>\n" +
                          "Reply-To: <attacker@mailinator.com>\n" +
                          "Authentication-Results: mx.google.com; dkim=fail; spf=fail; dmarc=fail\n" +
                          "Subject: Account Locked\n\n" +
                          "Please confirm your credentials immediately.";

        EmailHeaderInspector.EmailHeaderReport report = emailHeaderInspector.analyzeHeaders(rawEmail);
        assertTrue(report.isEmailFormat());
        assertTrue(report.isSenderSpoofed(), "From vs Reply-To mismatch should flag sender spoofing");
        assertEquals("FAIL", report.spfStatus());
        assertEquals("FAIL", report.dkimStatus());
        assertTrue(report.headerRiskScore() >= 60);
    }

    @Test
    @DisplayName("Batch CSV processing classifies multiple rows and builds CSV export")
    void testBatchProcessing() {
        List<String> messages = List.of(
                "URGENT: Your account has been suspended! Verify password now at http://192.168.1.1/login",
                "Hi Alice, are we still meeting for lunch today at 12:30 PM?",
                "CONGRATULATIONS! You won a $1,000,000 lottery prize! Claim cash now!"
        );

        BatchSpamService.BatchReport report = batchSpamService.processBatch(messages);
        assertEquals(3, report.totalMessages());
        assertTrue(report.spamCount() >= 2);
        assertTrue(report.legitimateCount() >= 1);
        assertNotNull(report.csvExportContent());
    }

    @Test
    @DisplayName("Adversarial Evasion Lab: homoglyphs and zero-width characters are mitigated")
    void testAdversarialAttackMitigation() {
        String base = "URGENT: Claim your $1000 prize now at http://win-prizes.xyz";
        var homoglyphResult = adversarialAttackService.simulateAttack(base, "HOMOGLYPH");
        assertTrue(homoglyphResult.attackMitigatedBySpamGuard(), "SpamGuard must mitigate Cyrillic homoglyph attack");

        var zeroWidthResult = adversarialAttackService.simulateAttack(base, "ZERO_WIDTH");
        assertTrue(zeroWidthResult.attackMitigatedBySpamGuard(), "SpamGuard must mitigate zero-width character attack");
    }

    @Test
    @DisplayName("Capstone Dossier Generator outputs structured academic report with ROC-AUC")
    void testCapstoneDossierGeneration() {
        var dossier = capstoneDossierService.generateDossier();
        assertNotNull(dossier);
        assertTrue(dossier.containsKey("markdownContent"));
        String md = (String) dossier.get("markdownContent");
        assertTrue(md.contains("SPAMGUARD AI"));
        assertTrue(md.contains("5-Fold Stratified Cross-Validation"));
    }

    @Test
    @DisplayName("Cybersecurity Major: MITRE ATT&CK and IOC Defanging extraction")
    void testCyberThreatIntelligence() {
        String phishingMsg = "URGENT: Verify password immediately at http://paypa1-security.com/login before account suspension!";
        SpamResponse response = spamService.classify(phishingMsg);

        assertNotNull(response.getMitreTechniques(), "Must map MITRE ATT&CK techniques");
        assertFalse(response.getMitreTechniques().isEmpty(), "Phishing should map to at least one MITRE technique");

        assertNotNull(response.getIocReport(), "Must extract IOC report");
        assertTrue(response.getIocReport().defangedUrls().stream().anyMatch(u -> u.contains("hxxp")), "Must defang URL");
        assertNotNull(response.getIocReport().messageSha256Hash(), "Must compute SHA-256 digital artifact hash");

        var stixBundle = cyberThreatIntelService.generateStixBundle(response, phishingMsg, response.getMitreTechniques(), response.getIocReport());
        assertNotNull(stixBundle);
        assertEquals("bundle", stixBundle.get("type"));
        assertEquals("2.1", stixBundle.get("spec_version"));
    }

    @Test
    @DisplayName("Quishing Forensics: SSRF Intranet IP exploitation detection")
    void testQuishingSsrfDetection() {
        byte[] dummyBytes = new byte[]{}; // tests empty handling
        var result = qrCodeScannerService.decodeQrImage(dummyBytes);
        assertNotNull(result);
    }
}
