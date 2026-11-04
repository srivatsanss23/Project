package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class BatchSpamService {

    private final SpamService spamService;

    public record BatchItemResult(
            int index,
            String messageSnippet,
            String prediction,
            int score,
            String riskLevel,
            String topReason
    ) {}

    public record BatchReport(
            int totalMessages,
            int spamCount,
            int suspiciousCount,
            int legitimateCount,
            double averageScore,
            List<BatchItemResult> items,
            String csvExportContent
    ) {}

    public BatchSpamService(SpamService spamService) {
        this.spamService = spamService;
    }

    public BatchReport processBatch(List<String> rawLines) {
        if (rawLines == null || rawLines.isEmpty()) {
            return new BatchReport(0, 0, 0, 0, 0.0, Collections.emptyList(), "");
        }

        List<BatchItemResult> items = new ArrayList<>();
        int spamCount = 0;
        int suspiciousCount = 0;
        int legitCount = 0;
        int totalScore = 0;

        StringBuilder csvOut = new StringBuilder();
        csvOut.append("id,prediction,score,risk_level,top_reason,message_snippet\n");

        int index = 1;
        for (String line : rawLines) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;

            // Strip optional quotes
            if (trimmed.startsWith("\"") && trimmed.endsWith("\"") && trimmed.length() >= 2) {
                trimmed = trimmed.substring(1, trimmed.length() - 1);
            }

            SpamResponse response = spamService.classify(trimmed);

            totalScore += response.getScore();
            if ("SPAM".equals(response.getPrediction())) spamCount++;
            else if ("SUSPICIOUS".equals(response.getPrediction())) suspiciousCount++;
            else legitCount++;

            String topReason = (response.getReasons() != null && !response.getReasons().isEmpty())
                    ? response.getReasons().get(0)
                    : "Normal";

            String snippet = trimmed.length() > 80 ? trimmed.substring(0, 80) + "..." : trimmed;

            items.add(new BatchItemResult(index, snippet, response.getPrediction(), response.getScore(), response.getRiskLevel(), topReason));

            csvOut.append(index).append(",")
                    .append(response.getPrediction()).append(",")
                    .append(response.getScore()).append(",")
                    .append(response.getRiskLevel()).append(",")
                    .append("\"").append(topReason.replace("\"", "\"\"")).append("\",")
                    .append("\"").append(snippet.replace("\"", "\"\"")).append("\"\n");

            index++;
        }

        int total = items.size();
        double avgScore = total > 0 ? (double) totalScore / total : 0.0;

        return new BatchReport(
                total,
                spamCount,
                suspiciousCount,
                legitCount,
                Math.round(avgScore * 10.0) / 10.0,
                items,
                csvOut.toString()
        );
    }
}
