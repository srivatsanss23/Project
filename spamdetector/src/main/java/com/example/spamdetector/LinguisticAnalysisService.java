package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Information-Theoretic & Linguistic Stylometry Analyzer
 * Computes Shannon Entropy, Lexical Richness (Type-Token Ratio),
 * Punctuation Density, and Character Distribution Anomaly scores.
 */
@Service
public class LinguisticAnalysisService {

    public record LinguisticProfile(
            double shannonEntropy,
            double lexicalDiversityTtr, // Type-Token Ratio
            double punctuationRatio,
            double digitRatio,
            double uppercaseRatio,
            double readabilityScore, // Flesch Reading Ease approximation
            int linguisticAnomalyScore, // 0 - 100 penalty
            List<String> stylisticIndicators
    ) {}

    public LinguisticProfile analyze(String text) {
        if (text == null || text.isBlank()) {
            return new LinguisticProfile(0.0, 0.0, 0.0, 0.0, 0.0, 100.0, 0, List.of("Empty text"));
        }

        int totalChars = text.length();
        long letters = text.chars().filter(Character::isLetter).count();
        long digits = text.chars().filter(Character::isDigit).count();
        long uppercase = text.chars().filter(Character::isUpperCase).count();
        long punctuation = text.chars().filter(c -> !Character.isLetterOrDigit(c) && !Character.isWhitespace(c)).count();

        // 1. Shannon Entropy: H(X) = - sum(p(x) * log2(p(x)))
        Map<Character, Integer> freqMap = new HashMap<>();
        for (char c : text.toCharArray()) {
            freqMap.put(c, freqMap.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        for (int freq : freqMap.values()) {
            double p = (double) freq / totalChars;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        // 2. Token extraction & Type-Token Ratio (Lexical Diversity)
        String[] tokens = text.toLowerCase().split("\\W+");
        List<String> cleanTokens = new ArrayList<>();
        for (String t : tokens) {
            if (!t.isBlank()) cleanTokens.add(t);
        }
        int totalTokens = cleanTokens.size();
        Set<String> uniqueTokens = new HashSet<>(cleanTokens);
        double ttr = totalTokens > 0 ? (double) uniqueTokens.size() / totalTokens : 0.0;

        // 3. Ratios
        double digitRatio = totalChars > 0 ? (double) digits / totalChars : 0.0;
        double uppercaseRatio = letters > 0 ? (double) uppercase / letters : 0.0;
        double punctuationRatio = totalChars > 0 ? (double) punctuation / totalChars : 0.0;

        // 4. Readability score (Flesch formula proxy: 206.835 - 1.015*(words/sentences) - 84.6*(syllables/words))
        String[] sentences = text.split("[.!?]+");
        int numSentences = Math.max(1, sentences.length);
        double avgSentenceLength = totalTokens > 0 ? (double) totalTokens / numSentences : 1.0;
        double approxSyllables = Math.max(1.0, totalChars * 0.3);
        double syllablesPerWord = totalTokens > 0 ? approxSyllables / totalTokens : 1.5;
        double readability = 206.835 - (1.015 * avgSentenceLength) - (84.6 * Math.min(syllablesPerWord, 3.0));
        readability = Math.max(0.0, Math.min(100.0, readability));

        // 5. Compute Stylistic Anomaly Score (0 - 100)
        int anomalyScore = 0;
        List<String> indicators = new ArrayList<>();

        // High entropy with high non-alpha chars often signals encrypted/encoded/random payloads
        if (entropy > 4.5 && (digitRatio + punctuationRatio > 0.25)) {
            anomalyScore += 30;
            indicators.add(String.format("High Shannon Entropy (%.2f bits/symbol) with dense non-alphanumeric noise", entropy));
        } else if (entropy < 2.5 && totalChars > 30) {
            anomalyScore += 15;
            indicators.add(String.format("Unusually low information entropy (%.2f bits/symbol) indicating repetition", entropy));
        }

        if (digitRatio > 0.20) {
            anomalyScore += 25;
            indicators.add(String.format("High digit ratio (%.1f%%) indicative of serial codes, financial lures or accounts", digitRatio * 100));
        }

        if (uppercaseRatio > 0.40 && letters > 10) {
            anomalyScore += 20;
            indicators.add(String.format("Aggressive capital letter frequency (%.1f%%)", uppercaseRatio * 100));
        }

        if (punctuationRatio > 0.18) {
            anomalyScore += 15;
            indicators.add(String.format("Dense punctuation ratio (%.1f%%)", punctuationRatio * 100));
        }

        if (ttr < 0.40 && totalTokens > 15) {
            anomalyScore += 15;
            indicators.add(String.format("Low lexical diversity (Type-Token Ratio: %.2f) indicating high redundancy", ttr));
        }

        anomalyScore = Math.min(100, anomalyScore);

        return new LinguisticProfile(
                Math.round(entropy * 100.0) / 100.0,
                Math.round(ttr * 100.0) / 100.0,
                Math.round(punctuationRatio * 1000.0) / 10.0,
                Math.round(digitRatio * 1000.0) / 10.0,
                Math.round(uppercaseRatio * 1000.0) / 10.0,
                Math.round(readability * 10.0) / 10.0,
                anomalyScore,
                indicators
        );
    }
}
