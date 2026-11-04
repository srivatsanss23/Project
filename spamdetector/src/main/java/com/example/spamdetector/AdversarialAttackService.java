package com.example.spamdetector;

import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AdversarialAttackService {

    private final SpamService spamService;
    private final TextNormalizer textNormalizer;

    public record AttackSimulationResult(
            String attackType,
            String originalMessage,
            String perturbedMessage,
            int naiveVulnerableScore,
            String naiveVulnerableVerdict,
            int defendedScore,
            String defendedVerdict,
            boolean evasionSucceededOnNaive,
            boolean attackMitigatedBySpamGuard,
            String technicalDefenseAnalysis
    ) {}

    public AdversarialAttackService(SpamService spamService, TextNormalizer textNormalizer) {
        this.spamService = spamService;
        this.textNormalizer = textNormalizer;
    }

    public AttackSimulationResult simulateAttack(String originalText, String attackType) {
        if (originalText == null || originalText.isBlank()) {
            originalText = "URGENT: Security alert from your bank! Login immediately at http://192.168.1.100 to verify account balance.";
        }

        String perturbed;
        String defenseExplanation;

        switch (attackType.toUpperCase()) {
            case "HOMOGLYPH":
            case "HOMOGLYPH_SUBSTITUTION":
                perturbed = applyHomoglyphAttack(originalText);
                defenseExplanation = "Attackers replace ASCII Latin characters with identical-looking Cyrillic/Greek Unicode points (e.g. Cyrillic 'а', 'е', 'о'). SpamGuard's TextNormalizer uses NFKD canonical decomposition and a homoglyph transliteration map to normalize characters before tokenization.";
                break;

            case "ZERO_WIDTH":
            case "ZERO_WIDTH_INJECTION":
                perturbed = applyZeroWidthAttack(originalText);
                defenseExplanation = "Attackers inject non-printable zero-width characters (\\u200B zero-width space, \\uFEFF byte-order mark) inside keywords like 'U\\u200BR\\u200BG\\u200BE\\u200BN\\u200BT'. SpamGuard regex-strips zero-width and control codepoints, restoring the contiguous word boundary.";
                break;

            case "GOOD_WORD":
            case "HAM_POISONING":
                perturbed = applyGoodWordPoisoning(originalText);
                defenseExplanation = "Attackers append dozens of benign academic or classical literature terms ('Shakespeare / Good-word attack') to dilute spam frequency distributions. SpamGuard defeats this via structural URL inspection, TF-IDF term weighting that discounts high-frequency ham words, and threat intelligence.";
                break;

            case "LEET_SPEAK":
            case "LEET_SPEAK_CAMOUFLAGE":
            default:
                perturbed = applyLeetSpeakAttack(originalText);
                defenseExplanation = "Attackers replace characters with common leet-speak substitutions ('cl@im', 'pr1ze', 'b@nk'). SpamGuard's multi-layer defense pairs heuristic fuzzy matching with sub-word tokenization and URL destination inspection.";
                break;
        }

        // 1. Simulate Naive Vulnerable Filter (Plain regex without Unicode normalization or URL inspection)
        int naiveScore = simulateNaiveFilter(perturbed);
        String naiveVerdict = naiveScore >= 50 ? "SPAM" : "LEGITIMATE (EVADED)";

        // 2. Run through SpamGuard Capstone Defended Pipeline
        SpamResponse defendedResponse = spamService.classify(perturbed);
        int defendedScore = defendedResponse.getScore();
        String defendedVerdict = defendedResponse.getPrediction();

        boolean naiveEvaded = naiveScore < 50;
        boolean defendedBlocked = defendedScore >= 40 || !"LEGITIMATE".equals(defendedVerdict);

        return new AttackSimulationResult(
                attackType,
                originalText,
                perturbed,
                naiveScore,
                naiveVerdict,
                defendedScore,
                defendedVerdict,
                naiveEvaded,
                defendedBlocked,
                defenseExplanation
        );
    }

    private String applyHomoglyphAttack(String text) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            switch (c) {
                case 'a': sb.append('\u0430'); break; // Cyrillic 'а'
                case 'A': sb.append('\u0410'); break;
                case 'e': sb.append('\u0435'); break; // Cyrillic 'е'
                case 'E': sb.append('\u0415'); break;
                case 'o': sb.append('\u043E'); break; // Cyrillic 'о'
                case 'O': sb.append('\u041E'); break;
                case 'p': sb.append('\u0440'); break; // Cyrillic 'р'
                case 'P': sb.append('\u0420'); break;
                case 'c': sb.append('\u0441'); break; // Cyrillic 'с'
                case 'C': sb.append('\u0421'); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    private String applyZeroWidthAttack(String text) {
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (char c : text.toCharArray()) {
            sb.append(c);
            if (Character.isLetter(c) && (++count % 2 == 0)) {
                sb.append('\u200B'); // Zero-width space
            }
        }
        return sb.toString();
    }

    private String applyGoodWordPoisoning(String text) {
        return text + "\n\n---\n" +
                "Meeting minutes: Team discussed academic coursework literature review, quarterly research thesis, " +
                "university faculty conference schedule, library reference materials, laboratory symposium, " +
                "peer-reviewed publication documentation, curriculum development, and graduate student fellowship awards.";
    }

    private String applyLeetSpeakAttack(String text) {
        return text
                .replace("a", "@").replace("A", "@")
                .replace("e", "3").replace("E", "3")
                .replace("i", "1").replace("I", "1")
                .replace("o", "0").replace("O", "0")
                .replace("s", "$").replace("S", "$");
    }

    /**
     * Simulates a naive, unhardened spam filter that relies on naive string matches without normalization.
     */
    private int simulateNaiveFilter(String text) {
        int score = 0;
        // Naive keywords with strict ASCII regex (will fail on homoglyphs, zero-width chars, leet-speak)
        if (text.matches(".*\\b(urgent|security|winner|prize|lottery)\\b.*")) score += 30;
        if (text.matches(".*\\b(claim|bank|account|suspended|password)\\b.*")) score += 30;
        if (text.contains("http://") && text.contains(".com")) score += 20;
        return score;
    }
}
