package com.example.spamdetector;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

@Service
public class AiSemanticAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(AiSemanticAnalysisService.class);

    @Value("${spamdetector.ai.enabled:false}")
    private boolean enabled;

    @Value("${spamdetector.ai.api-key:}")
    private String apiKey;

    @Value("${spamdetector.ai.provider:gemini}")
    private String provider;

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public record AiAnalysisResult(
            boolean apiCalled,
            String providerName,
            String semanticVerdict,
            int confidenceScore,
            String intentExplanation
    ) {}

    public AiSemanticAnalysisService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(4))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    public AiAnalysisResult analyzeIntent(String text) {
        if (text == null || text.isBlank()) {
            return new AiAnalysisResult(false, "Offline Heuristics", "LEGITIMATE", 0, "No content provided");
        }

        // Live API Call if enabled and API key is configured
        if (enabled && apiKey != null && !apiKey.isBlank()) {
            try {
                if ("gemini".equalsIgnoreCase(provider)) {
                    return callGeminiApi(text);
                } else if ("openai".equalsIgnoreCase(provider)) {
                    return callOpenAiApi(text);
                }
            } catch (Exception e) {
                log.warn("External AI API call failed, falling back to local semantic evaluator: {}", e.getMessage());
            }
        }

        // Intelligent local semantic evaluator (Simulated zero-shot intent analysis)
        return evaluateLocally(text);
    }

    private AiAnalysisResult callGeminiApi(String text) throws Exception {
        String endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + apiKey;

        String prompt = "You are a cyber security spam and phishing classifier. Analyze the following message and return ONLY a JSON object: "
                + "{\"verdict\": \"SPAM\" | \"SUSPICIOUS\" | \"LEGITIMATE\", \"confidence\": 0-100, \"explanation\": \"short one sentence summary\"}\n\n"
                + "Message: \"" + text.replace("\"", "\\\"") + "\"";

        Map<String, Object> payload = Map.of(
                "contents", new Object[]{
                        Map.of("parts", new Object[]{Map.of("text", prompt)})
                }
        );

        String jsonBody = objectMapper.writeValueAsString(payload);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            JsonNode root = objectMapper.readTree(response.body());
            String rawOutput = root.path("candidates").get(0).path("content").path("parts").get(0).path("text").asText();

            // Strip markdown backticks if returned
            rawOutput = rawOutput.replaceAll("```json|```", "").trim();
            JsonNode parsed = objectMapper.readTree(rawOutput);

            String verdict = parsed.path("verdict").asText("SUSPICIOUS");
            int confidence = parsed.path("confidence").asInt(75);
            String explanation = parsed.path("explanation").asText("Identified social engineering indicators");

            return new AiAnalysisResult(true, "Google Gemini Live API", verdict, confidence, explanation);
        }

        throw new RuntimeException("Gemini API error status: " + response.statusCode());
    }

    private AiAnalysisResult callOpenAiApi(String text) throws Exception {
        String endpoint = "https://api.openai.com/v1/chat/completions";

        Map<String, Object> payload = Map.of(
                "model", "gpt-4o-mini",
                "messages", new Object[]{
                        Map.of("role", "system", "content", "You are a spam detector. Reply ONLY in JSON with verdict, confidence, explanation."),
                        Map.of("role", "user", "content", text)
                },
                "temperature", 0.0
        );

        String jsonBody = objectMapper.writeValueAsString(payload);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            JsonNode root = objectMapper.readTree(response.body());
            String rawOutput = root.path("choices").get(0).path("message").path("content").asText();
            rawOutput = rawOutput.replaceAll("```json|```", "").trim();
            JsonNode parsed = objectMapper.readTree(rawOutput);

            return new AiAnalysisResult(true, "OpenAI API", parsed.path("verdict").asText("SPAM"), parsed.path("confidence").asInt(80), parsed.path("explanation").asText());
        }

        throw new RuntimeException("OpenAI API error status: " + response.statusCode());
    }

    private AiAnalysisResult evaluateLocally(String text) {
        String lower = text.toLowerCase();
        boolean hasUrgency = lower.contains("urgent") || lower.contains("immediately") || lower.contains("within 24 hours") || lower.contains("suspended");
        boolean hasBait = lower.contains("winner") || lower.contains("cash") || lower.contains("prize") || lower.contains("100% free") || lower.contains("lottery");
        boolean hasAuth = lower.contains("password") || lower.contains("verify") || lower.contains("login") || lower.contains("bank");

        if ((hasUrgency && hasAuth) || (hasBait && hasUrgency)) {
            return new AiAnalysisResult(false, "Built-in Intent Engine", "SPAM", 88,
                    "Detected aggressive psychological coercion and social engineering urgency.");
        } else if (hasBait || hasUrgency || hasAuth) {
            return new AiAnalysisResult(false, "Built-in Intent Engine", "SUSPICIOUS", 60,
                    "Detected emotional trigger words typical of promotional unsolicited messaging.");
        } else {
            return new AiAnalysisResult(false, "Built-in Intent Engine", "LEGITIMATE", 15,
                    "Contextual tone appears conversational and non-threatening.");
        }
    }
}
