package com.example.spamdetector;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "custom_threat_rules")
public class CustomRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 30)
    private String ruleType; // "BLOCK_DOMAIN", "ALLOW_DOMAIN", "BLOCK_KEYWORD", "REGEX"

    @Column(nullable = false, length = 255)
    private String pattern;

    @Column(length = 255)
    private String description;

    private int scoreAdjustment; // e.g. +50 for block, -50 for whitelist

    private Instant createdAt;

    public CustomRule() {}

    public CustomRule(String ruleType, String pattern, String description, int scoreAdjustment) {
        this.ruleType = ruleType;
        this.pattern = pattern;
        this.description = description;
        this.scoreAdjustment = scoreAdjustment;
        this.createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getRuleType() {
        return ruleType;
    }

    public void setRuleType(String ruleType) {
        this.ruleType = ruleType;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getScoreAdjustment() {
        return scoreAdjustment;
    }

    public void setScoreAdjustment(int scoreAdjustment) {
        this.scoreAdjustment = scoreAdjustment;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
