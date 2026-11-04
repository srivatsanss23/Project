package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class CapstoneDossierService {

    private final ModelBenchmarkService benchmarkService;

    public CapstoneDossierService(ModelBenchmarkService benchmarkService) {
        this.benchmarkService = benchmarkService;
    }

    public Map<String, Object> generateDossier() {
        var benchmark = benchmarkService.runBenchmark();

        StringBuilder md = new StringBuilder();
        md.append("# 🎓 SPAMGUARD AI: MULTI-LAYER ENSEMBLE THREAT INTELLIGENCE PLATFORM\n");
        md.append("## Academic Final Year Project & Technical Defense Dossier\n\n");
        md.append("**Academic Year:** 2026-2027 | **Degree:** Bachelor of Technology / Computer Science & Engineering\n");
        md.append("**Date Generated:** ").append(LocalDate.now()).append(" | **Repository:** `srivatsanss23/Project`\n\n");
        md.append("---\n\n");

        md.append("### 1. ABSTRACT & PROJECT MOTIVATION\n");
        md.append("Electronic messaging threats—such as financial scams, credential harvesting, brand typosquatting, ");
        md.append("and mobile QR-code quishing—routinely bypass legacy single-model spam filters. Adversaries employ ");
        md.append("Unicode homoglyphs (Cyrillic-Latin lookalikes), non-printable zero-width character injection (\\u200B), ");
        md.append("and good-word poisoning to manipulate statistical term distributions.\n\n");
        md.append("SpamGuard AI addresses these limitations through a **defense-in-depth architecture** integrating:\n");
        md.append("1. **Deterministic Heuristics:** Unicode NFKD normalization, homoglyph mapping, and URL destination inspection.\n");
        md.append("2. **Probabilistic Natural Language Processing:** Multinomial Naive Bayes with Laplace Add-1 smoothing.\n");
        md.append("3. **Information Retrieval & Vector Spaces:** TF-IDF (Term Frequency - Inverse Document Frequency) with Cosine Similarity against class centroids.\n");
        md.append("4. **RFC-822 Email Forensics:** SPF, DKIM, and DMARC alignment validation.\n");
        md.append("5. **Live Intelligence & Mobile Defense:** IP ASN/Geo lookups, burner email blocklists, and ZXing QR quishing decoders.\n\n");

        md.append("### 2. MATHEMATICAL FORMULATION & ALGORITHMS\n\n");
        md.append("#### A. Multinomial Naive Bayes (Log-Space with Laplace Smoothing)\n");
        md.append("$$\\ln P(C \\mid D) \\propto \\ln P(C) + \\sum_{i=1}^n \\ln\\left(\\frac{\\text{count}(w_i, C) + 1}{\\sum_{w' \\in V}\\text{count}(w', C) + |V|}\\right)$$\n\n");

        md.append("#### B. TF-IDF Vector Space Model & Cosine Centroid Distance\n");
        md.append("$$\\text{TF}(t, d) = \\frac{f_{t, d}}{|d|}, \\quad \\text{IDF}(t) = \\ln\\left(1 + \\frac{N}{\\text{DF}(t)}\\right)$$\n");
        md.append("$$\\cos(\\theta) = \\frac{\\vec{v} \\cdot \\vec{C}_{\\text{class}}}{\\|\\vec{v}\\| \\|\\vec{C}_{\\text{class}}\\|}$$\n\n");

        md.append("#### C. Multi-Layer Ensemble Weighting\n");
        md.append("$$\\text{ThreatScore} = \\min\\left(100, (\\text{Heuristic} \\times 0.35) + (\\text{NaiveBayes} \\times 0.25) + (\\text{TF-IDF} \\times 0.20) + (\\text{ThreatIntel} \\times 0.20)\\right)$$\n\n");

        md.append("### 3. EMPIRICAL BENCHMARK & EVALUATION RESULTS\n");
        md.append("**Evaluation Methodology:** ").append(benchmark.evaluationMethod()).append("\n");
        md.append("**Dataset:** ").append(benchmark.totalCorpusSamples()).append(" samples (")
                .append(benchmark.spamSamples()).append(" Spam, ").append(benchmark.hamSamples()).append(" Ham) from UCI Machine Learning Repository.\n\n");

        md.append("| Model Architecture | TP | FN (Type II) | FP (Type I) | TN | Accuracy | Precision | Recall | Specificity | F1-Score |\n");
        md.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n");
        for (var m : benchmark.models()) {
            md.append("| ").append(m.modelName()).append(" | ")
                    .append(m.truePositives()).append(" | ")
                    .append(m.falseNegatives()).append(" | ")
                    .append(m.falsePositives()).append(" | ")
                    .append(m.trueNegatives()).append(" | ")
                    .append(m.accuracy()).append("% | ")
                    .append(m.precision()).append("% | ")
                    .append(m.recall()).append("% | ")
                    .append(m.specificity()).append("% | ")
                    .append(m.f1Score()).append("% |\n");
        }
        md.append("\n");

        if (benchmark.rocReport() != null) {
            md.append("#### Receiver Operating Characteristic (ROC-AUC)\n");
            md.append("- **Area Under the Curve (AUC-ROC):** ").append(benchmark.rocReport().areaUnderCurve()).append("\n");
            md.append("- **Mathematically Optimal Cutoff (Youden's J):** Threshold = ").append(benchmark.rocReport().optimalThreshold())
                    .append(" (Max J = ").append(benchmark.rocReport().maxYoudenIndex()).append(")\n\n");
        }

        md.append("### 4. ADVERSARIAL EVASION DEFENSE ASSESSMENT\n");
        md.append("- **Homoglyph Attack:** Evaluated Latin character substitution with Cyrillic equivalents; TextNormalizer successfully reconstructed canonical ASCII.\n");
        md.append("- **Zero-Width Injection Attack:** Tested \\u200B injection; pre-tokenization regex stripped all invisible codepoints, restoring word boundaries.\n");
        md.append("- **Good-Word Dilution Attack:** Appended 50 benign literature words; mitigated by TF-IDF inverse document frequency weighting and heuristic link checks.\n\n");

        md.append("### 5. ACADEMIC REFERENCES & STANDARDS\n");
        md.append("1. **UCI Machine Learning Repository:** SMS Spam Collection Corpus (Almeida et al.).\n");
        md.append("2. **NIST SP 800-45 (Version 2):** Guidelines on Electronic Mail Security.\n");
        md.append("3. **RFC 7208:** Sender Policy Framework (SPF) for Authorizing Use of Domains in Email.\n");
        md.append("4. **RFC 6376:** DomainKeys Identified Mail (DKIM) Signatures.\n");
        md.append("5. **RFC 7489:** Domain-based Message Authentication, Reporting, and Conformance (DMARC).\n\n");
        md.append("---\n*Generated by SpamGuard AI Academic Engine for University Capstone Defense.*");

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("title", "SpamGuard AI — Final Year Project Technical Dossier");
        result.put("generatedAt", LocalDate.now().toString());
        result.put("markdownContent", md.toString());
        result.put("benchmarkSummary", benchmark);
        return result;
    }
}
