package com.example.spamdetector;

import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Supervised Logistic Regression Classifier with Stochastic Gradient Descent (SGD)
 * and L2 Regularization, designed for text spam classification.
 * Outputs calibrated probabilities via the Sigmoid (logistic) function.
 */
@Component
public class LogisticRegressionSpamClassifier {

    public record LogisticRegressionResult(
            int lrScore, // 0 - 100
            double probability, // 0.0 - 1.0
            double rawLogit,
            List<String> topContributingTokens
    ) {}

    private final Map<String, Double> weights = new HashMap<>();
    private double bias = -0.5; // slight negative prior for spam

    @PostConstruct
    public void init() {
        trainOnCorpus();
    }

    public synchronized void trainOnCorpus() {
        try {
            ClassPathResource resource = new ClassPathResource("data/sms_spam_corpus.csv");
            if (!resource.exists()) return;

            List<TrainingSample> samples = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean isFirst = true;
                while ((line = reader.readLine()) != null) {
                    if (isFirst) {
                        isFirst = false;
                        continue;
                    }
                    String[] parts = line.split(",", 2);
                    if (parts.length == 2) {
                        String label = parts[0].trim().toLowerCase();
                        String text = parts[1].trim();
                        double target = ("spam".equals(label)) ? 1.0 : 0.0;
                        samples.add(new TrainingSample(text, target));
                    }
                }
            }

            if (samples.isEmpty()) return;

            // Simple SGD with 25 epochs
            double learningRate = 0.05;
            double lambdaL2 = 0.001; // regularization
            int epochs = 25;

            for (int epoch = 0; epoch < epochs; epoch++) {
                Collections.shuffle(samples);
                for (TrainingSample sample : samples) {
                    Map<String, Integer> termFreqs = getTermFrequencies(sample.text);
                    double logit = bias;
                    for (Map.Entry<String, Integer> entry : termFreqs.entrySet()) {
                        logit += weights.getOrDefault(entry.getKey(), 0.0) * entry.getValue();
                    }
                    double prediction = sigmoid(logit);
                    double error = sample.target - prediction;

                    // Update bias
                    bias += learningRate * error;

                    // Update weights
                    for (Map.Entry<String, Integer> entry : termFreqs.entrySet()) {
                        String token = entry.getKey();
                        double w = weights.getOrDefault(token, 0.0);
                        // Gradient with L2 weight decay
                        double grad = (error * entry.getValue()) - (lambdaL2 * w);
                        weights.put(token, w + (learningRate * grad));
                    }
                }
            }

        } catch (Exception e) {
            // Fallback safe initialization
        }
    }

    public LogisticRegressionResult predict(String text) {
        if (text == null || text.isBlank()) {
            return new LogisticRegressionResult(0, 0.0, bias, List.of());
        }

        Map<String, Integer> termFreqs = getTermFrequencies(text);
        double logit = bias;
        Map<String, Double> contributions = new HashMap<>();

        for (Map.Entry<String, Integer> entry : termFreqs.entrySet()) {
            String token = entry.getKey();
            double w = weights.getOrDefault(token, 0.0);
            double contribution = w * entry.getValue();
            logit += contribution;
            if (Math.abs(contribution) > 0.05) {
                contributions.put(token, contribution);
            }
        }

        double probability = sigmoid(logit);
        int score = (int) Math.round(probability * 100.0);

        List<String> topSpamTokens = contributions.entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .sorted((a, b) -> Double.compare(b.getValue(), a.getValue()))
                .limit(5)
                .map(Map.Entry::getKey)
                .toList();

        return new LogisticRegressionResult(
                score,
                Math.round(probability * 1000.0) / 1000.0,
                Math.round(logit * 100.0) / 100.0,
                topSpamTokens
        );
    }

    private double sigmoid(double z) {
        if (z < -45.0) return 0.0;
        if (z > 45.0) return 1.0;
        return 1.0 / (1.0 + Math.exp(-z));
    }

    private Map<String, Integer> getTermFrequencies(String text) {
        Map<String, Integer> freqs = new HashMap<>();
        String[] tokens = text.toLowerCase().split("\\W+");
        for (String t : tokens) {
            if (t.length() >= 2) {
                freqs.put(t, freqs.getOrDefault(t, 0) + 1);
            }
        }
        return freqs;
    }

    private record TrainingSample(String text, double target) {}
}
