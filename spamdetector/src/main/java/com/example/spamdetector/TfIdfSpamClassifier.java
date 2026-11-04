package com.example.spamdetector;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class TfIdfSpamClassifier {

    private static final Logger log = LoggerFactory.getLogger(TfIdfSpamClassifier.class);

    private final Map<String, Double> idfMap = new HashMap<>();
    private final Map<String, Double> spamCentroid = new HashMap<>();
    private final Map<String, Double> hamCentroid = new HashMap<>();
    private double spamCentroidNorm = 0.0;
    private double hamCentroidNorm = 0.0;
    private boolean trained = false;

    private static final Set<String> STOP_WORDS = Set.of(
            "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "with",
            "is", "are", "was", "were", "of", "it", "this", "that", "i", "you", "he", "she", "we", "they"
    );

    public record TfIdfResult(
            double spamSimilarity,
            double hamSimilarity,
            int tfIdfScore, // 0 - 100
            String predictedLabel, // "SPAM" or "HAM"
            List<String> topTfIdfKeywords
    ) {}

    @PostConstruct
    public void trainModel() {
        try {
            ClassPathResource resource = new ClassPathResource("data/sms_spam_corpus.csv");
            if (!resource.exists()) return;

            List<String[]> docs = new ArrayList<>();
            Map<String, Integer> docFreq = new HashMap<>();

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean isFirstLine = true;
                while ((line = reader.readLine()) != null) {
                    if (isFirstLine) { isFirstLine = false; continue; }
                    if (line.isBlank()) continue;

                    int comma = line.indexOf(',');
                    if (comma <= 0) continue;

                    String label = line.substring(0, comma).trim().toLowerCase();
                    String text = line.substring(comma + 1).trim();
                    if (text.startsWith("\"") && text.endsWith("\"") && text.length() >= 2) {
                        text = text.substring(1, text.length() - 1);
                    }

                    docs.add(new String[]{label, text});

                    Set<String> uniqueTokens = new HashSet<>(tokenize(text));
                    for (String token : uniqueTokens) {
                        docFreq.merge(token, 1, Integer::sum);
                    }
                }
            }

            int nDocs = docs.size();
            for (Map.Entry<String, Integer> entry : docFreq.entrySet()) {
                // Smooth IDF: log(1 + N / DF)
                double idf = Math.log(1.0 + ((double) nDocs / entry.getValue()));
                idfMap.put(entry.getKey(), idf);
            }

            int spamCount = 0;
            int hamCount = 0;

            // Compute Centroids
            for (String[] doc : docs) {
                String label = doc[0];
                Map<String, Double> vec = computeTfIdfVector(doc[1]);

                if ("spam".equals(label)) {
                    spamCount++;
                    for (Map.Entry<String, Double> e : vec.entrySet()) {
                        spamCentroid.merge(e.getKey(), e.getValue(), Double::sum);
                    }
                } else {
                    hamCount++;
                    for (Map.Entry<String, Double> e : vec.entrySet()) {
                        hamCentroid.merge(e.getKey(), e.getValue(), Double::sum);
                    }
                }
            }

            if (spamCount > 0) {
                for (String k : spamCentroid.keySet()) {
                    spamCentroid.put(k, spamCentroid.get(k) / spamCount);
                }
            }
            if (hamCount > 0) {
                for (String k : hamCentroid.keySet()) {
                    hamCentroid.put(k, hamCentroid.get(k) / hamCount);
                }
            }

            spamCentroidNorm = computeNorm(spamCentroid);
            hamCentroidNorm = computeNorm(hamCentroid);
            trained = true;

            log.info("TF-IDF Vector Space Model trained on {} documents across {} terms", nDocs, idfMap.size());

        } catch (Exception e) {
            log.error("Failed to train TF-IDF Model", e);
        }
    }

    public TfIdfResult predict(String text) {
        if (!trained || text == null || text.isBlank()) {
            return new TfIdfResult(0.0, 0.0, 0, "HAM", Collections.emptyList());
        }

        Map<String, Double> queryVec = computeTfIdfVector(text);
        double queryNorm = computeNorm(queryVec);

        if (queryNorm == 0.0) {
            return new TfIdfResult(0.0, 0.0, 0, "HAM", Collections.emptyList());
        }

        double spamSim = computeCosineSim(queryVec, queryNorm, spamCentroid, spamCentroidNorm);
        double hamSim = computeCosineSim(queryVec, queryNorm, hamCentroid, hamCentroidNorm);

        // Normalize similarity to 0 - 100 score
        double total = spamSim + hamSim;
        double spamRatio = total > 0 ? (spamSim / total) : 0.0;
        int score = (int) Math.round(spamRatio * 100);

        String label = spamSim > hamSim ? "SPAM" : "HAM";

        // Top TF-IDF keywords
        List<String> topTerms = queryVec.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(4)
                .map(Map.Entry::getKey)
                .toList();

        return new TfIdfResult(
                Math.round(spamSim * 1000.0) / 1000.0,
                Math.round(hamSim * 1000.0) / 1000.0,
                score,
                label,
                topTerms
        );
    }

    private Map<String, Double> computeTfIdfVector(String text) {
        List<String> tokens = tokenize(text);
        Map<String, Double> tfMap = new HashMap<>();

        for (String t : tokens) {
            tfMap.merge(t, 1.0, Double::sum);
        }

        int totalTokens = Math.max(tokens.size(), 1);
        Map<String, Double> tfIdfVec = new HashMap<>();

        for (Map.Entry<String, Double> entry : tfMap.entrySet()) {
            String term = entry.getKey();
            double tf = entry.getValue() / totalTokens;
            double idf = idfMap.getOrDefault(term, 1.0);
            tfIdfVec.put(term, tf * idf);
        }

        return tfIdfVec;
    }

    private double computeCosineSim(Map<String, Double> v1, double norm1, Map<String, Double> v2, double norm2) {
        if (norm1 == 0.0 || norm2 == 0.0) return 0.0;

        double dot = 0.0;
        for (Map.Entry<String, Double> e : v1.entrySet()) {
            Double val2 = v2.get(e.getKey());
            if (val2 != null) {
                dot += e.getValue() * val2;
            }
        }

        return dot / (norm1 * norm2);
    }

    private double computeNorm(Map<String, Double> vec) {
        double sum = 0.0;
        for (double v : vec.values()) {
            sum += v * v;
        }
        return Math.sqrt(sum);
    }

    private List<String> tokenize(String text) {
        String[] words = text.toLowerCase().split("[^a-zA-Z0-9]+");
        List<String> valid = new ArrayList<>();
        for (String w : words) {
            if (w.length() > 2 && !STOP_WORDS.contains(w)) {
                valid.add(w);
            }
        }
        return valid;
    }
}
