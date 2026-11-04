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
public class NaiveBayesSpamClassifier {

    private static final Logger log = LoggerFactory.getLogger(NaiveBayesSpamClassifier.class);

    private final Map<String, Integer> spamWordCounts = new HashMap<>();
    private final Map<String, Integer> hamWordCounts = new HashMap<>();
    private final Set<String> vocabulary = new HashSet<>();

    private int spamMessageCount = 0;
    private int hamMessageCount = 0;
    private int totalSpamWords = 0;
    private int totalHamWords = 0;
    private boolean trained = false;

    private static final Set<String> STOP_WORDS = Set.of(
            "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "with",
            "is", "are", "was", "were", "of", "it", "this", "that", "i", "you", "he", "she", "we", "they"
    );

    public record NaiveBayesResult(
            double spamProbability,
            int mlScore, // 0 - 100
            String predictedLabel, // "SPAM" or "HAM"
            List<String> topSpamWords,
            List<FeatureAttribution> featureAttributions,
            int corpusSize
    ) {}

    @PostConstruct
    public void trainFromOpenSourceCorpus() {
        try {
            ClassPathResource resource = new ClassPathResource("data/sms_spam_corpus.csv");
            if (!resource.exists()) {
                log.warn("Open-source SMS Spam corpus not found at data/sms_spam_corpus.csv");
                return;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean isFirstLine = true;

                while ((line = reader.readLine()) != null) {
                    if (isFirstLine) {
                        isFirstLine = false;
                        continue;
                    }
                    if (line.isBlank()) continue;

                    // Parse CSV: label,"text"
                    String label;
                    String text;
                    int firstComma = line.indexOf(',');
                    if (firstComma <= 0) continue;

                    label = line.substring(0, firstComma).trim().toLowerCase();
                    text = line.substring(firstComma + 1).trim();
                    if (text.startsWith("\"") && text.endsWith("\"") && text.length() >= 2) {
                        text = text.substring(1, text.length() - 1);
                    }

                    List<String> tokens = tokenize(text);
                    if (label.equals("spam")) {
                        spamMessageCount++;
                        for (String token : tokens) {
                            spamWordCounts.merge(token, 1, Integer::sum);
                            totalSpamWords++;
                            vocabulary.add(token);
                        }
                    } else {
                        hamMessageCount++;
                        for (String token : tokens) {
                            hamWordCounts.merge(token, 1, Integer::sum);
                            totalHamWords++;
                            vocabulary.add(token);
                        }
                    }
                }
            }

            trained = true;
            log.info("Naive Bayes classifier trained successfully on open-source corpus: {} messages ({} spam, {} ham), vocabulary size: {}",
                    (spamMessageCount + hamMessageCount), spamMessageCount, hamMessageCount, vocabulary.size());

        } catch (Exception e) {
            log.error("Failed to train Naive Bayes classifier on open source corpus", e);
        }
    }

    public NaiveBayesResult predict(String message) {
        if (!trained || message == null || message.isBlank()) {
            return new NaiveBayesResult(0.0, 0, "HAM", Collections.emptyList(), Collections.emptyList(), spamMessageCount + hamMessageCount);
        }

        List<String> tokens = tokenize(message);
        if (tokens.isEmpty()) {
            return new NaiveBayesResult(0.0, 0, "HAM", Collections.emptyList(), Collections.emptyList(), spamMessageCount + hamMessageCount);
        }

        double totalMessages = spamMessageCount + hamMessageCount;
        double logPriorSpam = Math.log((double) spamMessageCount / totalMessages);
        double logPriorHam = Math.log((double) hamMessageCount / totalMessages);

        double logLikelihoodSpam = logPriorSpam;
        double logLikelihoodHam = logPriorHam;
        int vocabSize = Math.max(vocabulary.size(), 1);

        Map<String, Double> wordSpamScores = new HashMap<>();
        List<Map.Entry<String, Double>> logOddsList = new ArrayList<>();
        double totalAbsOdds = 0.0;

        for (String token : tokens) {
            int spamCount = spamWordCounts.getOrDefault(token, 0);
            int hamCount = hamWordCounts.getOrDefault(token, 0);

            // Laplace smoothing: (count + 1) / (totalWords + vocabSize)
            double probWordGivenSpam = (double) (spamCount + 1) / (totalSpamWords + vocabSize);
            double probWordGivenHam = (double) (hamCount + 1) / (totalHamWords + vocabSize);

            double wordLogOdds = Math.log(probWordGivenSpam) - Math.log(probWordGivenHam);
            logOddsList.add(Map.entry(token, wordLogOdds));
            totalAbsOdds += Math.abs(wordLogOdds);

            logLikelihoodSpam += Math.log(probWordGivenSpam);
            logLikelihoodHam += Math.log(probWordGivenHam);

            if (spamCount > hamCount) {
                wordSpamScores.put(token, probWordGivenSpam / probWordGivenHam);
            }
        }

        // Softmax / normalized probability calculation to prevent underflow
        double maxLog = Math.max(logLikelihoodSpam, logLikelihoodHam);
        double expSpam = Math.exp(logLikelihoodSpam - maxLog);
        double expHam = Math.exp(logLikelihoodHam - maxLog);
        double probSpam = expSpam / (expSpam + expHam);

        int mlScore = (int) Math.round(probSpam * 100);
        String label = (probSpam >= 0.5) ? "SPAM" : "HAM";

        // Top 4 words contributing most to spam probability
        List<String> topWords = wordSpamScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(4)
                .map(Map.Entry::getKey)
                .toList();

        // Top 8 feature attributions sorted by log-odds absolute magnitude
        logOddsList.sort((a, b) -> Double.compare(Math.abs(b.getValue()), Math.abs(a.getValue())));
        List<FeatureAttribution> attributions = new ArrayList<>();
        for (var entry : logOddsList.stream().limit(8).toList()) {
            double odds = Math.round(entry.getValue() * 100.0) / 100.0;
            String pull = odds >= 0 ? "SPAM" : "HAM";
            double relWeight = totalAbsOdds > 0 ? Math.round((Math.abs(entry.getValue()) / totalAbsOdds) * 1000.0) / 10.0 : 0.0;
            attributions.add(new FeatureAttribution(entry.getKey(), odds, pull, relWeight));
        }

        return new NaiveBayesResult(
                Math.round(probSpam * 1000.0) / 1000.0,
                mlScore,
                label,
                topWords,
                attributions,
                spamMessageCount + hamMessageCount
        );
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

    public boolean isTrained() {
        return trained;
    }
}
