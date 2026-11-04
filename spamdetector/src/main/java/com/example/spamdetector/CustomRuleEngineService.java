package com.example.spamdetector;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
public class CustomRuleEngineService {

    private final CustomRuleRepository ruleRepository;

    public record RuleMatch(
            String ruleType,
            String pattern,
            String description,
            int scoreDelta
    ) {}

    public CustomRuleEngineService(CustomRuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @PostConstruct
    public void seedDefaultRules() {
        if (ruleRepository.count() == 0) {
            ruleRepository.save(new CustomRule("BLOCK_DOMAIN", "bad-actor-phish.net", "Known active malicious phishing campaign", 50));
            ruleRepository.save(new CustomRule("ALLOW_DOMAIN", "internal-company.org", "Internal trusted company domain whitelist", -50));
            ruleRepository.save(new CustomRule("BLOCK_KEYWORD", "claim your wire transfer", "High-volume financial wire scam phrase", 30));
        }
    }

    public List<RuleMatch> evaluateCustomRules(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        List<RuleMatch> matches = new ArrayList<>();
        List<CustomRule> rules = ruleRepository.findAll();
        String lowerText = text.toLowerCase();

        for (CustomRule rule : rules) {
            String pattern = rule.getPattern().toLowerCase();
            switch (rule.getRuleType()) {
                case "BLOCK_DOMAIN" -> {
                    if (lowerText.contains(pattern)) {
                        matches.add(new RuleMatch(rule.getRuleType(), pattern, "Matched custom blocked domain: " + pattern, rule.getScoreAdjustment()));
                    }
                }
                case "ALLOW_DOMAIN" -> {
                    if (lowerText.contains(pattern)) {
                        matches.add(new RuleMatch(rule.getRuleType(), pattern, "Matched trusted whitelist domain: " + pattern, rule.getScoreAdjustment()));
                    }
                }
                case "BLOCK_KEYWORD" -> {
                    if (lowerText.contains(pattern)) {
                        matches.add(new RuleMatch(rule.getRuleType(), pattern, "Matched custom blacklisted keyword: '" + pattern + "'", rule.getScoreAdjustment()));
                    }
                }
                case "REGEX" -> {
                    try {
                        if (Pattern.compile(rule.getPattern(), Pattern.CASE_INSENSITIVE).matcher(text).find()) {
                            matches.add(new RuleMatch(rule.getRuleType(), rule.getPattern(), "Matched custom regex pattern: " + rule.getDescription(), rule.getScoreAdjustment()));
                        }
                    } catch (Exception ignored) {}
                }
            }
        }

        return matches;
    }

    public List<CustomRule> getAllRules() {
        return ruleRepository.findAll();
    }

    public CustomRule addRule(CustomRule rule) {
        return ruleRepository.save(rule);
    }

    public void deleteRule(Long id) {
        ruleRepository.deleteById(id);
    }
}
