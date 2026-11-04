package com.example.spamdetector;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Service to inspect, query, and stream samples from open-source spam corpora
 * (SMS Spam Collection & Public SpamAssassin reference corpus).
 */
@Service
public class DatasetService {

    public record DatasetSample(
            int id,
            String label,
            String text,
            int charCount,
            int wordCount,
            String sourceDataset
    ) {}

    public record DatasetStats(
            int totalSamples,
            int spamCount,
            int hamCount,
            double spamRatioPercentage,
            String corpusName
    ) {}

    private final List<DatasetSample> cachedSamples = new ArrayList<>();
    private DatasetStats stats;

    public DatasetService() {
        loadCorpus();
    }

    private synchronized void loadCorpus() {
        try {
            ClassPathResource resource = new ClassPathResource("data/sms_spam_corpus.csv");
            if (!resource.exists()) return;

            int idCounter = 1;
            int spam = 0;
            int ham = 0;

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                boolean header = true;
                while ((line = reader.readLine()) != null) {
                    if (header) {
                        header = false;
                        continue;
                    }
                    String[] parts = line.split(",", 2);
                    if (parts.length == 2) {
                        String label = parts[0].trim().toUpperCase();
                        String text = parts[1].trim();
                        if ("SPAM".equals(label)) spam++;
                        else ham++;

                        int wordCount = text.split("\\s+").length;
                        cachedSamples.add(new DatasetSample(
                                idCounter++,
                                label,
                                text,
                                text.length(),
                                wordCount,
                                "Open-Source SMS & SpamAssassin Reference Corpus"
                        ));
                    }
                }
            }

            int total = spam + ham;
            double ratio = total > 0 ? (double) spam / total * 100.0 : 0.0;
            this.stats = new DatasetStats(total, spam, ham, Math.round(ratio * 10.0) / 10.0, "UCI / SpamAssassin Benchmark Corpus");

        } catch (Exception e) {
            this.stats = new DatasetStats(0, 0, 0, 0.0, "Unavailable");
        }
    }

    public List<DatasetSample> getSamples(int limit, String filterLabel) {
        return cachedSamples.stream()
                .filter(s -> filterLabel == null || filterLabel.isBlank() || s.label().equalsIgnoreCase(filterLabel))
                .limit(Math.min(limit, 100))
                .toList();
    }

    public DatasetSample getRandomSample(String filterLabel) {
        List<DatasetSample> filtered = cachedSamples.stream()
                .filter(s -> filterLabel == null || filterLabel.isBlank() || s.label().equalsIgnoreCase(filterLabel))
                .toList();
        if (filtered.isEmpty()) return null;
        return filtered.get(new Random().nextInt(filtered.size()));
    }

    public DatasetStats getStats() {
        return stats;
    }
}
