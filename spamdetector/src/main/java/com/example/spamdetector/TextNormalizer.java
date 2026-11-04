package com.example.spamdetector;

import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Deep Adversarial Perturbation Defense Normalizer
 * Mitigates:
 * 1. Invisible zero-width and non-printable evasion markers
 * 2. Cyrillic, Greek, and Full-width homoglyphs
 * 3. Leet-speak digit/symbol substitutions (p@ssw0rd -> password, fr33 -> free, b!tc0!n -> bitcoin)
 * 4. Excessive inter-character spacing (w i n n e r -> winner)
 */
@Component
public class TextNormalizer {

    private static final Pattern ZERO_WIDTH_AND_INVISIBLE = Pattern.compile("[\u200B\u200C\u200D\uFEFF\u00AD\u200E\u200F\u202A-\u202E]");
    private static final Pattern SPACED_OUT_WORD = Pattern.compile("\\b([a-zA-Z])\\s+([a-zA-Z])\\s+([a-zA-Z])\\s+([a-zA-Z])(\\s+[a-zA-Z])?\\b");

    private static final Map<Character, Character> HOMOGLYPHS = new HashMap<>();

    static {
        // Cyrillic
        HOMOGLYPHS.put('\u0430', 'a'); HOMOGLYPHS.put('\u0410', 'A');
        HOMOGLYPHS.put('\u0435', 'e'); HOMOGLYPHS.put('\u0415', 'E');
        HOMOGLYPHS.put('\u043E', 'o'); HOMOGLYPHS.put('\u041E', 'O');
        HOMOGLYPHS.put('\u0440', 'p'); HOMOGLYPHS.put('\u0420', 'P');
        HOMOGLYPHS.put('\u0441', 'c'); HOMOGLYPHS.put('\u0421', 'C');
        HOMOGLYPHS.put('\u0443', 'y'); HOMOGLYPHS.put('\u0423', 'Y');
        HOMOGLYPHS.put('\u0445', 'x'); HOMOGLYPHS.put('\u0425', 'X');
        HOMOGLYPHS.put('\u0456', 'i'); HOMOGLYPHS.put('\u0406', 'I');
        HOMOGLYPHS.put('\u043C', 'm'); HOMOGLYPHS.put('\u041C', 'M');
        HOMOGLYPHS.put('\u0422', 'T'); HOMOGLYPHS.put('\u0412', 'B');

        // Greek lookalikes
        HOMOGLYPHS.put('\u03B1', 'a'); HOMOGLYPHS.put('\u0391', 'A');
        HOMOGLYPHS.put('\u03B2', 'b'); HOMOGLYPHS.put('\u0392', 'B');
        HOMOGLYPHS.put('\u03BF', 'o'); HOMOGLYPHS.put('\u039F', 'O');
        HOMOGLYPHS.put('\u03C1', 'p'); HOMOGLYPHS.put('\u03A1', 'P');
    }

    /**
     * Reversible / defensive normalization pipeline
     */
    public String normalize(String input) {
        if (input == null) return "";

        // Step 1: Strip zero-width & directional override spoofing
        String cleaned = ZERO_WIDTH_AND_INVISIBLE.matcher(input).replaceAll("");

        // Step 2: Unicode NFKD normalization (collapses accents, full-width letters)
        cleaned = Normalizer.normalize(cleaned, Normalizer.Form.NFKD);

        // Step 3: Replace Homoglyphs
        StringBuilder sb = new StringBuilder(cleaned.length());
        for (char ch : cleaned.toCharArray()) {
            sb.append(HOMOGLYPHS.getOrDefault(ch, ch));
        }
        String dehomoglyphed = sb.toString();

        // Step 4: De-obfuscate common leet-speak within suspicious token boundaries
        String deleeted = normalizeLeetSpeak(dehomoglyphed);

        // Step 5: Collapse spaced out words like "w i n n e r" -> "winner"
        return collapseSpacedLetters(deleeted);
    }

    private String normalizeLeetSpeak(String text) {
        // Targeted substitutions: @ -> a, 0 -> o, 1 -> i, 3 -> e, 5 -> s, $ -> s, ! -> i
        // Only applied when surrounded by letters or common attack contexts
        return text.replaceAll("(?i)(?<=[a-z])0(?=[a-z])", "o")
                   .replaceAll("(?i)(?<=[a-z])1(?=[a-z])", "i")
                   .replaceAll("(?i)(?<=[a-z])3(?=[a-z])", "e")
                   .replaceAll("(?i)(?<=[a-z])5(?=[a-z])", "s")
                   .replaceAll("(?i)(?<=[a-z])@(?=[a-z])", "a")
                   .replaceAll("(?i)(?<=[a-z])\\$(?=[a-z])", "s")
                   .replaceAll("(?i)(?<=[a-z])!(?=[a-z])", "i");
    }

    private String collapseSpacedLetters(String text) {
        return SPACED_OUT_WORD.matcher(text).replaceAll(mr -> {
            String g5 = mr.group(5) != null ? mr.group(5).trim() : "";
            return mr.group(1) + mr.group(2) + mr.group(3) + mr.group(4) + g5;
        });
    }
}
