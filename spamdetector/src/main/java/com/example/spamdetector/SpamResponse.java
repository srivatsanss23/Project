package com.example.spamdetector;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public class SpamResponse {
    private String prediction;
    private int score;
    private String riskLevel;
    private List<String> reasons;
    private List<FlaggedToken> flaggedTokens;
    private Map<String, Integer> categoryScores;

    // Academic NLP & Machine Learning Tri-Model Ensemble
    private NaiveBayesSpamClassifier.NaiveBayesResult machineLearning;
    private TfIdfSpamClassifier.TfIdfResult tfIdfResult;
    private LogisticRegressionSpamClassifier.LogisticRegressionResult logisticRegressionResult;

    // Information-Theoretic & Linguistic Stylometry
    private LinguisticAnalysisService.LinguisticProfile linguisticProfile;

    // Threat Intelligence & Spoofing
    private List<IpThreatIntelligenceService.IpIntelligenceResult> ipIntelligence;
    private List<DisposableEmailService.EmailFinding> emailFindings;
    private AiSemanticAnalysisService.AiAnalysisResult aiSemanticAnalysis;
    private List<BrandImpersonationService.BrandFinding> brandFindings;
    private EmailHeaderInspector.EmailHeaderReport emailHeaderReport;

    // Cybersecurity Major SOC Observables: MITRE ATT&CK & IOCs
    private List<MitreAttackTechnique> mitreTechniques;
    private IocExtractionReport iocReport;

    private Instant analyzedAt;
    private long executionTimeMs;

    public SpamResponse() {}

    public SpamResponse(String prediction, int score, String riskLevel, List<String> reasons,
                        List<FlaggedToken> flaggedTokens, Map<String, Integer> categoryScores,
                        NaiveBayesSpamClassifier.NaiveBayesResult machineLearning,
                        TfIdfSpamClassifier.TfIdfResult tfIdfResult,
                        LogisticRegressionSpamClassifier.LogisticRegressionResult logisticRegressionResult,
                        LinguisticAnalysisService.LinguisticProfile linguisticProfile,
                        List<IpThreatIntelligenceService.IpIntelligenceResult> ipIntelligence,
                        List<DisposableEmailService.EmailFinding> emailFindings,
                        AiSemanticAnalysisService.AiAnalysisResult aiSemanticAnalysis,
                        List<BrandImpersonationService.BrandFinding> brandFindings,
                        EmailHeaderInspector.EmailHeaderReport emailHeaderReport,
                        List<MitreAttackTechnique> mitreTechniques,
                        IocExtractionReport iocReport,
                        Instant analyzedAt, long executionTimeMs) {
        this.prediction = prediction;
        this.score = score;
        this.riskLevel = riskLevel;
        this.reasons = reasons;
        this.flaggedTokens = flaggedTokens;
        this.categoryScores = categoryScores;
        this.machineLearning = machineLearning;
        this.tfIdfResult = tfIdfResult;
        this.logisticRegressionResult = logisticRegressionResult;
        this.linguisticProfile = linguisticProfile;
        this.ipIntelligence = ipIntelligence;
        this.emailFindings = emailFindings;
        this.aiSemanticAnalysis = aiSemanticAnalysis;
        this.brandFindings = brandFindings;
        this.emailHeaderReport = emailHeaderReport;
        this.mitreTechniques = mitreTechniques;
        this.iocReport = iocReport;
        this.analyzedAt = analyzedAt;
        this.executionTimeMs = executionTimeMs;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public List<String> getReasons() {
        return reasons;
    }

    public void setReasons(List<String> reasons) {
        this.reasons = reasons;
    }

    public List<FlaggedToken> getFlaggedTokens() {
        return flaggedTokens;
    }

    public void setFlaggedTokens(List<FlaggedToken> flaggedTokens) {
        this.flaggedTokens = flaggedTokens;
    }

    public Map<String, Integer> getCategoryScores() {
        return categoryScores;
    }

    public void setCategoryScores(Map<String, Integer> categoryScores) {
        this.categoryScores = categoryScores;
    }

    public NaiveBayesSpamClassifier.NaiveBayesResult getMachineLearning() {
        return machineLearning;
    }

    public void setMachineLearning(NaiveBayesSpamClassifier.NaiveBayesResult machineLearning) {
        this.machineLearning = machineLearning;
    }

    public TfIdfSpamClassifier.TfIdfResult getTfIdfResult() {
        return tfIdfResult;
    }

    public void setTfIdfResult(TfIdfSpamClassifier.TfIdfResult tfIdfResult) {
        this.tfIdfResult = tfIdfResult;
    }

    public LogisticRegressionSpamClassifier.LogisticRegressionResult getLogisticRegressionResult() {
        return logisticRegressionResult;
    }

    public void setLogisticRegressionResult(LogisticRegressionSpamClassifier.LogisticRegressionResult logisticRegressionResult) {
        this.logisticRegressionResult = logisticRegressionResult;
    }

    public LinguisticAnalysisService.LinguisticProfile getLinguisticProfile() {
        return linguisticProfile;
    }

    public void setLinguisticProfile(LinguisticAnalysisService.LinguisticProfile linguisticProfile) {
        this.linguisticProfile = linguisticProfile;
    }

    public List<IpThreatIntelligenceService.IpIntelligenceResult> getIpIntelligence() {
        return ipIntelligence;
    }

    public void setIpIntelligence(List<IpThreatIntelligenceService.IpIntelligenceResult> ipIntelligence) {
        this.ipIntelligence = ipIntelligence;
    }

    public List<DisposableEmailService.EmailFinding> getEmailFindings() {
        return emailFindings;
    }

    public void setEmailFindings(List<DisposableEmailService.EmailFinding> emailFindings) {
        this.emailFindings = emailFindings;
    }

    public AiSemanticAnalysisService.AiAnalysisResult getAiSemanticAnalysis() {
        return aiSemanticAnalysis;
    }

    public void setAiSemanticAnalysis(AiSemanticAnalysisService.AiAnalysisResult aiSemanticAnalysis) {
        this.aiSemanticAnalysis = aiSemanticAnalysis;
    }

    public List<BrandImpersonationService.BrandFinding> getBrandFindings() {
        return brandFindings;
    }

    public void setBrandFindings(List<BrandImpersonationService.BrandFinding> brandFindings) {
        this.brandFindings = brandFindings;
    }

    public EmailHeaderInspector.EmailHeaderReport getEmailHeaderReport() {
        return emailHeaderReport;
    }

    public void setEmailHeaderReport(EmailHeaderInspector.EmailHeaderReport emailHeaderReport) {
        this.emailHeaderReport = emailHeaderReport;
    }

    public List<MitreAttackTechnique> getMitreTechniques() {
        return mitreTechniques;
    }

    public void setMitreTechniques(List<MitreAttackTechnique> mitreTechniques) {
        this.mitreTechniques = mitreTechniques;
    }

    public IocExtractionReport getIocReport() {
        return iocReport;
    }

    public void setIocReport(IocExtractionReport iocReport) {
        this.iocReport = iocReport;
    }

    public Instant getAnalyzedAt() {
        return analyzedAt;
    }

    public void setAnalyzedAt(Instant analyzedAt) {
        this.analyzedAt = analyzedAt;
    }

    public long getExecutionTimeMs() {
        return executionTimeMs;
    }

    public void setExecutionTimeMs(long executionTimeMs) {
        this.executionTimeMs = executionTimeMs;
    }
}
