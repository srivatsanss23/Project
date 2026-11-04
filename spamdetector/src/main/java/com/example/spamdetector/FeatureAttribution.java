package com.example.spamdetector;

public record FeatureAttribution(
        String token,
        double logOdds,
        String pullDirection, // "SPAM" or "HAM"
        double relativeWeight  // 0 - 100 percentage of decision pull
) {}
