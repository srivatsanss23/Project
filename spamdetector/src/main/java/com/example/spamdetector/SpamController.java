package com.example.spamdetector;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api")
public class SpamController {

    private final SpamService spamService;
    private final BatchSpamService batchSpamService;
    private final ScanRecordRepository scanRecordRepository;
    private final QrCodeScannerService qrScannerService;
    private final CustomRuleEngineService customRuleService;
    private final ModelBenchmarkService modelBenchmarkService;
    private final AdversarialAttackService adversarialService;
    private final CapstoneDossierService dossierService;
    private final DatasetService datasetService;
    private final CyberThreatIntelService cyberThreatIntelService;

    public SpamController(SpamService spamService,
                          BatchSpamService batchSpamService,
                          ScanRecordRepository scanRecordRepository,
                          QrCodeScannerService qrScannerService,
                          CustomRuleEngineService customRuleService,
                          ModelBenchmarkService modelBenchmarkService,
                          AdversarialAttackService adversarialService,
                          CapstoneDossierService dossierService,
                          DatasetService datasetService,
                          CyberThreatIntelService cyberThreatIntelService) {
        this.spamService = spamService;
        this.batchSpamService = batchSpamService;
        this.scanRecordRepository = scanRecordRepository;
        this.qrScannerService = qrScannerService;
        this.customRuleService = customRuleService;
        this.modelBenchmarkService = modelBenchmarkService;
        this.adversarialService = adversarialService;
        this.dossierService = dossierService;
        this.datasetService = datasetService;
        this.cyberThreatIntelService = cyberThreatIntelService;
    }

    @PostMapping({"/classify", "/check-spam"})
    public ResponseEntity<SpamResponse> classifyMessage(@Valid @RequestBody SpamRequest request) {
        SpamResponse response = spamService.classify(request.getMessage());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/scan-qr")
    public ResponseEntity<Map<String, Object>> scanQrCode(@RequestBody Map<String, String> payload) {
        String base64 = payload.get("imageBase64");
        QrCodeScannerService.QrScanResult qrResult = qrScannerService.decodeBase64Image(base64);

        if (!qrResult.qrFound()) {
            return ResponseEntity.ok(Map.of(
                    "qrFound", false,
                    "error", qrResult.threatWarning()
            ));
        }

        SpamResponse response = spamService.classify(qrResult.decodedPayload());
        return ResponseEntity.ok(Map.of(
                "qrFound", true,
                "decodedText", qrResult.decodedPayload(),
                "isUrl", qrResult.isUrl(),
                "classification", response
        ));
    }

    @PostMapping("/batch")
    public ResponseEntity<BatchSpamService.BatchReport> processBatch(@RequestBody List<String> messages) {
        BatchSpamService.BatchReport report = batchSpamService.processBatch(messages);
        return ResponseEntity.ok(report);
    }

    @GetMapping("/benchmark")
    public ResponseEntity<ModelBenchmarkService.BenchmarkReport> runBenchmark() {
        return ResponseEntity.ok(modelBenchmarkService.runBenchmark());
    }

    @PostMapping("/adversarial-attack")
    public ResponseEntity<AdversarialAttackService.AttackSimulationResult> simulateAttack(@RequestBody Map<String, String> payload) {
        String message = payload.getOrDefault("message", "");
        String attackType = payload.getOrDefault("attackType", "HOMOGLYPH");
        return ResponseEntity.ok(adversarialService.simulateAttack(message, attackType));
    }

    @GetMapping("/dossier")
    public ResponseEntity<Map<String, Object>> getCapstoneDossier() {
        return ResponseEntity.ok(dossierService.generateDossier());
    }

    @PostMapping("/stix-bundle")
    public ResponseEntity<Map<String, Object>> generateStixReport(@RequestBody SpamRequest request) {
        SpamResponse response = spamService.classify(request.getMessage());
        Map<String, Object> bundle = cyberThreatIntelService.generateStixBundle(
                response,
                request.getMessage(),
                response.getMitreTechniques(),
                response.getIocReport()
        );
        return ResponseEntity.ok(bundle);
    }

    // Open-source Dataset Inspection & Stream Endpoints
    @GetMapping("/dataset/samples")
    public ResponseEntity<List<DatasetService.DatasetSample>> getDatasetSamples(
            @RequestParam(defaultValue = "15") int limit,
            @RequestParam(required = false) String label) {
        return ResponseEntity.ok(datasetService.getSamples(limit, label));
    }

    @GetMapping("/dataset/random")
    public ResponseEntity<DatasetService.DatasetSample> getRandomDatasetSample(
            @RequestParam(required = false) String label) {
        return ResponseEntity.ok(datasetService.getRandomSample(label));
    }

    @GetMapping("/dataset/stats")
    public ResponseEntity<DatasetService.DatasetStats> getDatasetStats() {
        return ResponseEntity.ok(datasetService.getStats());
    }

    @GetMapping("/rules")
    public ResponseEntity<List<CustomRule>> getRules() {
        return ResponseEntity.ok(customRuleService.getAllRules());
    }

    @PostMapping("/rules")
    public ResponseEntity<CustomRule> addRule(@RequestBody CustomRule rule) {
        return ResponseEntity.ok(customRuleService.addRule(rule));
    }

    @DeleteMapping("/rules/{id}")
    public ResponseEntity<Map<String, String>> deleteRule(@PathVariable Long id) {
        customRuleService.deleteRule(id);
        return ResponseEntity.ok(Map.of("status", "SUCCESS", "message", "Rule deleted"));
    }

    @GetMapping("/history")
    public ResponseEntity<List<ScanRecord>> getHistory() {
        return ResponseEntity.ok(scanRecordRepository.findTop25ByOrderByScannedAtDesc());
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        long totalScans = scanRecordRepository.count();
        long spamScans = scanRecordRepository.countByPrediction("SPAM");
        long susScans = scanRecordRepository.countByPrediction("SUSPICIOUS");
        long legitScans = scanRecordRepository.countByPrediction("LEGITIMATE");
        double avgScore = scanRecordRepository.getAverageScore();
        double avgLatency = scanRecordRepository.getAverageExecutionTimeMs();

        double spamRate = totalScans > 0 ? ((double) (spamScans + susScans) / totalScans) * 100.0 : 0.0;

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalScans", totalScans);
        stats.put("spamCount", spamScans);
        stats.put("suspiciousCount", susScans);
        stats.put("legitimateCount", legitScans);
        stats.put("threatRatePercent", Math.round(spamRate * 10.0) / 10.0);
        stats.put("averageThreatScore", Math.round(avgScore * 10.0) / 10.0);
        stats.put("averageLatencyMs", Math.round(avgLatency * 10.0) / 10.0);

        return ResponseEntity.ok(stats);
    }

    @GetMapping("/samples")
    public ResponseEntity<List<SampleMessageDto>> getSamples() {
        List<SampleMessageDto> samples = List.of(
                new SampleMessageDto(
                        "lottery-scam",
                        "🎁 Prize / Lottery Scam",
                        "Financial Scam",
                        "CONGRATULATIONS! You have won a $1,000,000 cash prize in our international lottery! Claim prize now before it expires today. Click here: http://bit.ly/claim-prize-today to verify account and claim your wire transfer immediately!!!",
                        "SPAM"
                ),
                new SampleMessageDto(
                        "bank-phishing",
                        "🏦 Bank Phishing (IP URL)",
                        "Credential Phishing",
                        "URGENT: Security alert from your bank account! Unauthorized access detected from an unknown device. Your access will be suspended within 24 hours. Login immediately to confirm your identity and verify password at http://192.168.1.100/secure-login",
                        "SPAM"
                ),
                new SampleMessageDto(
                        "brand-spoof",
                        "🎯 Brand Spoofing (PayPal Lookalike)",
                        "Brand Impersonation",
                        "PayPal Alert: Unauthorized transaction of $499.00 USD detected. If you did not authorize this payment, cancel immediately at http://paypa1-security-verify.com/login before your account is permanently locked.",
                        "SPAM"
                ),
                new SampleMessageDto(
                        "email-header-spoof",
                        "📧 Spoofed Email (SPF/DKIM Fail)",
                        "Email Spoofing",
                        "From: \"PayPal Security\" <security@paypal.com>\nReply-To: <attacker@mailinator.com>\nAuthentication-Results: mx.google.com; dkim=fail; spf=fail; dmarc=fail\nSubject: Account Compromise Notice\n\nYour account has been suspended. Please confirm your details immediately.",
                        "SPAM"
                ),
                new SampleMessageDto(
                        "clean-work-email",
                        "💼 Business Meeting (Legitimate)",
                        "Legitimate",
                        "Hi team, just a reminder about our sprint review meeting scheduled for tomorrow afternoon at 2:00 PM in Conference Room B. Please remember to update your task board before the sync. Let me know if you have any questions.",
                        "LEGITIMATE"
                )
        );
        return ResponseEntity.ok(samples);
    }

    @PostMapping("/feedback")
    public ResponseEntity<Map<String, Object>> submitFeedback(@RequestBody FeedbackRequest feedback) {
        return ResponseEntity.ok(Map.of(
                "status", "SUCCESS",
                "message", "Feedback recorded successfully. Thank you for helping improve the detector!"
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "SpamGuard AI Capstone Platform"));
    }
}
