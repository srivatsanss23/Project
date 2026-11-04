package com.example.spamdetector;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "scan_records")
public class ScanRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 500)
    private String messagePreview;

    @Column(nullable = false, length = 30)
    private String prediction;

    private int score;

    @Column(length = 20)
    private String riskLevel;

    @Column(length = 30)
    private String sourceChannel; // "TEXT", "EMAIL_HEADER", "BATCH_CSV"

    @Column(length = 500)
    private String topReason;

    private double mlProbability;

    private long executionTimeMs;

    private Instant scannedAt;

    public ScanRecord() {}

    public ScanRecord(String messagePreview, String prediction, int score, String riskLevel,
                      String sourceChannel, String topReason, double mlProbability,
                      long executionTimeMs, Instant scannedAt) {
        this.messagePreview = messagePreview;
        this.prediction = prediction;
        this.score = score;
        this.riskLevel = riskLevel;
        this.sourceChannel = sourceChannel;
        this.topReason = topReason;
        this.mlProbability = mlProbability;
        this.executionTimeMs = executionTimeMs;
        this.scannedAt = scannedAt;
    }

    public Long getId() {
        return id;
    }

    public String getMessagePreview() {
        return messagePreview;
    }

    public void setMessagePreview(String messagePreview) {
        this.messagePreview = messagePreview;
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

    public String getSourceChannel() {
        return sourceChannel;
    }

    public void setSourceChannel(String sourceChannel) {
        this.sourceChannel = sourceChannel;
    }

    public String getTopReason() {
        return topReason;
    }

    public void setTopReason(String topReason) {
        this.topReason = topReason;
    }

    public double getMlProbability() {
        return mlProbability;
    }

    public void setMlProbability(double mlProbability) {
        this.mlProbability = mlProbability;
    }

    public long getExecutionTimeMs() {
        return executionTimeMs;
    }

    public void setExecutionTimeMs(long executionTimeMs) {
        this.executionTimeMs = executionTimeMs;
    }

    public Instant getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(Instant scannedAt) {
        this.scannedAt = scannedAt;
    }
}
