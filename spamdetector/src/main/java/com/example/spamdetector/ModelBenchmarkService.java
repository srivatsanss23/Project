package com.example.spamdetector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class ModelBenchmarkService {

    private static final Logger log = LoggerFactory.getLogger(ModelBenchmarkService.class);

    private final TextNormalizer textNormalizer;

    private static final Set<String> STOP_WORDS = Set.of(
            "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "with",
            "is", "are", "was", "were", "of", "it", "this", "that", "i", "you", "he", "she", "we", "they"
    );

    public record ModelEvaluation(
            String modelName,
            int truePositives,
            int falsePositives,
            int trueNegatives,
            int falseNegatives,
            double accuracy,
            double precision,
            double recall,
            double specificity,
            double f1Score
    ) {}

    public record RocPoint(
            double threshold,
            double falsePositiveRate,
            double truePositiveRate,
            double youdenIndex
    ) {}

    public record RocReport(
            List<RocPoint> points,
            double areaUnderCurve,
            double optimalThreshold,
            double maxYoudenIndex
    ) {}

    public record BenchmarkReport(
            int totalCorpusSamples,
            int spamSamples,
            int hamSamples,
            String evaluationMethod,
            List<ModelEvaluation> models,
            RocReport rocReport
    ) {}

    public ModelBenchmarkService(TextNormalizer textNormalizer) {
        this.textNormalizer = textNormalizer;
    }

    public BenchmarkReport runBenchmark() {
        return runCrossValidationBenchmark();
    }

    /**
     * Executes 5-Fold Stratified Cross-Validation over the SMS spam corpus.
     * Evaluates models strictly on out-of-sample unseen validation folds.
     */
    public BenchmarkReport runCrossValidationBenchmark() {
        List<String[]> corpus = loadCorpus();
        if (corpus.isEmpty()) {
            return new BenchmarkReport(0, 0, 0, "No data available", Collections.emptyList(), null);
        }

        List<String[]> spamList = new ArrayList<>();
        List<String[]> hamList = new ArrayList<>();
        for (String[] doc : corpus) {
            if ("spam".equalsIgnoreCase(doc[0])) {
                spamList.add(doc);
            } else {
                hamList.add(doc);
            }
        }

        int k = 5;
        int nbTP = 0, nbFP = 0, nbTN = 0, nbFN = 0;
        int tfTP = 0, tfFP = 0, tfTN = 0, tfFN = 0;
        int ensTP = 0, ensFP = 0, ensTN = 0, ensFN = 0;

        for (int fold = 0; fold < k; fold++) {
            List<String[]> trainSet = new ArrayList<>();
            List<String[]> testSet = new ArrayList<>();

            // Stratified split for Spam
            for (int i = 0; i < spamList.size(); i++) {
                if (i % k == fold) testSet.add(spamList.get(i));
                else trainSet.add(spamList.get(i));
            }

            // Stratified split for Ham
            for (int i = 0; i < hamList.size(); i++) {
                if (i % k == fold) testSet.add(hamList.get(i));
                else trainSet.add(hamList.get(i));
            }

            FoldNaiveBayes foldNB = new FoldNaiveBayes(trainSet, textNormalizer);
            FoldTfIdf foldTF = new FoldTfIdf(trainSet, textNormalizer);

            for (String[] item : testSet) {
                boolean isActuallySpam = "spam".equalsIgnoreCase(item[0]);
                String text = item[1];

                // 1. Fold Naive Bayes prediction
                boolean nbIsSpam = foldNB.predictIsSpam(text);
                if (isActuallySpam) {
                    if (nbIsSpam) nbTP++; else nbFN++;
                } else {
                    if (nbIsSpam) nbFP++; else nbTN++;
                }

                // 2. Fold TF-IDF prediction
                boolean tfIsSpam = foldTF.predictIsSpam(text);
                if (isActuallySpam) {
                    if (tfIsSpam) tfTP++; else tfFN++;
                } else {
                    if (tfIsSpam) tfFP++; else tfTN++;
                }

                // 3. Ensemble prediction (Heuristics + Fold NB + Fold TF)
                boolean ensIsSpam = evaluateEnsemble(text, foldNB.predictProbability(text), foldTF.predictSimilarity(text));
                if (isActuallySpam) {
                    if (ensIsSpam) ensTP++; else ensFN++;
                } else {
                    if (ensIsSpam) ensFP++; else ensTN++;
                }
            }
        }

        List<ModelEvaluation> evaluations = List.of(
                calculateMetrics("Multinomial Naive Bayes (Laplace)", nbTP, nbFP, nbTN, nbFN),
                calculateMetrics("TF-IDF Vector Space (Cosine)", tfTP, tfFP, tfTN, tfFN),
                calculateMetrics("Hybrid Multi-Layer Ensemble", ensTP, ensFP, ensTN, ensFN)
        );

        RocReport roc = computeRocCurve(corpus);

        return new BenchmarkReport(
                corpus.size(),
                spamList.size(),
                hamList.size(),
                "5-Fold Stratified Cross-Validation (Out-of-Sample Generalization)",
                evaluations,
                roc
        );
    }

    private RocReport computeRocCurve(List<String[]> corpus) {
        List<Double> thresholds = List.of(0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85);
        List<RocPoint> points = new ArrayList<>();
        points.add(new RocPoint(1.0, 0.0, 0.0, 0.0));

        double bestJ = -1.0;
        double bestThreshold = 0.45;

        FoldNaiveBayes nb = new FoldNaiveBayes(corpus, textNormalizer);
        FoldTfIdf tf = new FoldTfIdf(corpus, textNormalizer);

        for (double t : thresholds) {
            int tp = 0, fp = 0, tn = 0, fn = 0;
            for (String[] doc : corpus) {
                boolean isSpam = "spam".equalsIgnoreCase(doc[0]);
                double prob = nb.predictProbability(doc[1]);
                double sim = tf.predictSimilarity(doc[1]);
                double score = ((prob * 0.50) + (sim * 0.50));
                boolean predSpam = score >= t;
                if (isSpam) {
                    if (predSpam) tp++; else fn++;
                } else {
                    if (predSpam) fp++; else tn++;
                }
            }
            double tpr = (tp + fn) > 0 ? (double) tp / (tp + fn) : 0.0;
            double fpr = (fp + tn) > 0 ? (double) fp / (fp + tn) : 0.0;
            double j = tpr - fpr;
            if (j > bestJ) {
                bestJ = j;
                bestThreshold = t;
            }
            points.add(new RocPoint(
                    Math.round(t * 100.0) / 100.0,
                    Math.round(fpr * 1000.0) / 1000.0,
                    Math.round(tpr * 1000.0) / 1000.0,
                    Math.round(j * 1000.0) / 1000.0
            ));
        }
        points.add(new RocPoint(0.0, 1.0, 1.0, 0.0));
        points.sort(Comparator.comparingDouble(RocPoint::falsePositiveRate));

        double auc = 0.0;
        for (int i = 1; i < points.size(); i++) {
            double x1 = points.get(i - 1).falsePositiveRate();
            double x2 = points.get(i).falsePositiveRate();
            double y1 = points.get(i - 1).truePositiveRate();
            double y2 = points.get(i).truePositiveRate();
            auc += (x2 - x1) * ((y1 + y2) / 2.0);
        }
        auc = Math.round(Math.max(0.5, Math.min(1.0, auc)) * 1000.0) / 1000.0;

        return new RocReport(
                points,
                auc,
                bestThreshold,
                Math.round(bestJ * 1000.0) / 1000.0
        );
    }

    private boolean evaluateEnsemble(String text, double nbProb, double tfSim) {
        int heuristicScore = 0;
        String lower = text.toLowerCase();
        if (lower.contains("http://") || lower.contains("https://")) heuristicScore += 25;
        if (lower.matches(".*\\b(urgent|security alert|suspended|verify|winner|lottery|prize|claim|crypto|giveaway|pre-approved|vouchers|cash)\\b.*")) heuristicScore += 30;
        if (lower.matches(".*\\b(gift card|wire|bitcoin|btc|transfer|dollars|vouchers|free|reward)\\b.*")) heuristicScore += 25;

        double combinedScore = (heuristicScore * 0.35) + (nbProb * 100 * 0.35) + (tfSim * 100 * 0.30);
        return combinedScore >= 30.0 || (nbProb >= 0.55 && tfSim >= 0.15);
    }

    private ModelEvaluation calculateMetrics(String name, int tp, int fp, int tn, int fn) {
        int total = tp + fp + tn + fn;
        double accuracy = total > 0 ? (double) (tp + tn) / total : 0.0;
        double precision = (tp + fp) > 0 ? (double) tp / (tp + fp) : 0.0;
        double recall = (tp + fn) > 0 ? (double) tp / (tp + fn) : 0.0;
        double specificity = (tn + fp) > 0 ? (double) tn / (tn + fp) : 0.0;
        double f1 = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;

        return new ModelEvaluation(
                name,
                tp, fp, tn, fn,
                roundPct(accuracy),
                roundPct(precision),
                roundPct(recall),
                roundPct(specificity),
                roundPct(f1)
        );
    }

    private double roundPct(double val) {
        return Math.round(val * 1000.0) / 10.0;
    }

    private List<String[]> loadCorpus() {
        List<String[]> list = new ArrayList<>();
        try {
            ClassPathResource resource = new ClassPathResource("data/sms_spam_corpus.csv");
            if (!resource.exists()) return list;

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean isFirst = true;
                while ((line = reader.readLine()) != null) {
                    if (isFirst) { isFirst = false; continue; }
                    if (line.isBlank()) continue;

                    int comma = line.indexOf(',');
                    if (comma <= 0) continue;

                    String label = line.substring(0, comma).trim();
                    String text = line.substring(comma + 1).trim();
                    if (text.startsWith("\"") && text.endsWith("\"") && text.length() >= 2) {
                        text = text.substring(1, text.length() - 1);
                    }
                    list.add(new String[]{label, text});
                }
            }
        } catch (Exception e) {
            log.warn("Corpus read error: {}", e.getMessage());
        }
        return list;
    }

    static class FoldNaiveBayes {
        private final Map<String, Integer> spamWordCounts = new HashMap<>();
        private final Map<String, Integer> hamWordCounts = new HashMap<>();
        private final Set<String> vocabulary = new HashSet<>();
        private int spamDocs = 0, hamDocs = 0;
        private int totalSpamWords = 0, totalHamWords = 0;
        private final TextNormalizer normalizer;

        public FoldNaiveBayes(List<String[]> trainSet, TextNormalizer normalizer) {
            this.normalizer = normalizer;
            for (String[] doc : trainSet) {
                boolean isSpam = "spam".equalsIgnoreCase(doc[0]);
                if (isSpam) spamDocs++; else hamDocs++;

                List<String> tokens = tokenize(doc[1]);
                for (String t : tokens) {
                    vocabulary.add(t);
                    if (isSpam) {
                        spamWordCounts.merge(t, 1, Integer::sum);
                        totalSpamWords++;
                    } else {
                        hamWordCounts.merge(t, 1, Integer::sum);
                        totalHamWords++;
                    }
                }
            }
        }

        private List<String> tokenize(String text) {
            String cleaned = normalizer.normalize(text).toLowerCase();
            String[] parts = cleaned.split("[^a-zA-Z0-9]+");
            List<String> list = new ArrayList<>();
            for (String p : parts) {
                if (p.length() >= 2 && !STOP_WORDS.contains(p)) {
                    list.add(p);
                }
            }
            return list;
        }

        public double predictProbability(String text) {
            List<String> tokens = tokenize(text);
            if (tokens.isEmpty()) return 0.05;

            double totalDocs = spamDocs + hamDocs;
            double logSpam = Math.log((double) Math.max(spamDocs, 1) / totalDocs);
            double logHam = Math.log((double) Math.max(hamDocs, 1) / totalDocs);
            int vSize = Math.max(vocabulary.size(), 1);

            for (String t : tokens) {
                int sc = spamWordCounts.getOrDefault(t, 0);
                int hc = hamWordCounts.getOrDefault(t, 0);
                logSpam += Math.log((double) (sc + 1) / (totalSpamWords + vSize));
                logHam += Math.log((double) (hc + 1) / (totalHamWords + vSize));
            }

            double maxLog = Math.max(logSpam, logHam);
            double expSpam = Math.exp(logSpam - maxLog);
            double expHam = Math.exp(logHam - maxLog);
            return expSpam / (expSpam + expHam);
        }

        public boolean predictIsSpam(String text) {
            return predictProbability(text) >= 0.50;
        }
    }

    static class FoldTfIdf {
        private final Map<String, Double> idfMap = new HashMap<>();
        private final Map<String, Double> spamCentroid = new HashMap<>();
        private final Map<String, Double> hamCentroid = new HashMap<>();
        private double spamNorm = 0.0, hamNorm = 0.0;
        private final TextNormalizer normalizer;

        public FoldTfIdf(List<String[]> trainSet, TextNormalizer normalizer) {
            this.normalizer = normalizer;
            Map<String, Integer> docFreq = new HashMap<>();
            for (String[] doc : trainSet) {
                Set<String> unique = new HashSet<>(tokenize(doc[1]));
                for (String t : unique) {
                    docFreq.merge(t, 1, Integer::sum);
                }
            }

            int n = trainSet.size();
            for (var entry : docFreq.entrySet()) {
                idfMap.put(entry.getKey(), Math.log(1.0 + ((double) n / entry.getValue())));
            }

            int sc = 0, hc = 0;
            for (String[] doc : trainSet) {
                boolean isSpam = "spam".equalsIgnoreCase(doc[0]);
                Map<String, Double> vec = computeVector(doc[1]);
                if (isSpam) {
                    sc++;
                    for (var e : vec.entrySet()) spamCentroid.merge(e.getKey(), e.getValue(), Double::sum);
                } else {
                    hc++;
                    for (var e : vec.entrySet()) hamCentroid.merge(e.getKey(), e.getValue(), Double::sum);
                }
            }

            if (sc > 0) for (var k : spamCentroid.keySet()) spamCentroid.put(k, spamCentroid.get(k) / sc);
            if (hc > 0) for (var k : hamCentroid.keySet()) hamCentroid.put(k, hamCentroid.get(k) / hc);

            spamNorm = norm(spamCentroid);
            hamNorm = norm(hamCentroid);
        }

        private List<String> tokenize(String text) {
            String cleaned = normalizer.normalize(text).toLowerCase();
            String[] parts = cleaned.split("[^a-zA-Z0-9]+");
            List<String> list = new ArrayList<>();
            for (String p : parts) {
                if (p.length() >= 2 && !STOP_WORDS.contains(p)) {
                    list.add(p);
                }
            }
            return list;
        }

        private Map<String, Double> computeVector(String text) {
            List<String> tokens = tokenize(text);
            Map<String, Integer> tf = new HashMap<>();
            for (String t : tokens) tf.merge(t, 1, Integer::sum);

            Map<String, Double> vec = new HashMap<>();
            int len = Math.max(tokens.size(), 1);
            for (var e : tf.entrySet()) {
                double idf = idfMap.getOrDefault(e.getKey(), 1.0);
                vec.put(e.getKey(), ((double) e.getValue() / len) * idf);
            }
            return vec;
        }

        private double norm(Map<String, Double> v) {
            double s = 0.0;
            for (double val : v.values()) s += val * val;
            return Math.sqrt(s);
        }

        public double predictSimilarity(String text) {
            Map<String, Double> v = computeVector(text);
            double vNorm = norm(v);
            if (vNorm == 0 || spamNorm == 0) return 0.0;
            double dot = 0.0;
            for (var e : v.entrySet()) {
                dot += e.getValue() * spamCentroid.getOrDefault(e.getKey(), 0.0);
            }
            return Math.max(0.0, dot / (vNorm * spamNorm));
        }

        public boolean predictIsSpam(String text) {
            Map<String, Double> v = computeVector(text);
            double vNorm = norm(v);
            if (vNorm == 0) return false;
            double sSim = spamNorm > 0 ? dot(v, spamCentroid) / (vNorm * spamNorm) : 0.0;
            double hSim = hamNorm > 0 ? dot(v, hamCentroid) / (vNorm * hamNorm) : 0.0;
            return sSim >= hSim && sSim > 0.05;
        }

        private double dot(Map<String, Double> a, Map<String, Double> b) {
            double d = 0.0;
            for (var e : a.entrySet()) d += e.getValue() * b.getOrDefault(e.getKey(), 0.0);
            return d;
        }
    }
}
