package com.example.spamdetector;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DisposableEmailService {

    private static final Logger log = LoggerFactory.getLogger(DisposableEmailService.class);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("(?i)\\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\\.[A-Z]{2,})\\b");

    private final Set<String> disposableDomains = new HashSet<>();

    public record EmailFinding(
            String fullEmail,
            String domain,
            boolean isDisposable,
            String warning
    ) {}

    @PostConstruct
    public void loadDisposableDomains() {
        try {
            ClassPathResource resource = new ClassPathResource("data/disposable_domains.txt");
            if (!resource.exists()) {
                log.warn("Disposable domains blocklist not found at data/disposable_domains.txt");
                return;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String domain = line.trim().toLowerCase();
                    if (!domain.isEmpty() && !domain.startsWith("#")) {
                        disposableDomains.add(domain);
                    }
                }
            }

            log.info("Loaded {} open-source disposable email domains into blocklist", disposableDomains.size());
        } catch (Exception e) {
            log.error("Failed to load disposable domains blocklist", e);
        }
    }

    public List<EmailFinding> scanEmails(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }

        List<EmailFinding> findings = new ArrayList<>();
        Matcher matcher = EMAIL_PATTERN.matcher(text);

        while (matcher.find()) {
            String email = matcher.group();
            String domain = matcher.group(1).toLowerCase();

            boolean isDisposable = disposableDomains.contains(domain);
            String warning = isDisposable
                    ? "Sender or contact email uses a known disposable/burner domain (" + domain + ")"
                    : null;

            findings.add(new EmailFinding(email, domain, isDisposable, warning));
        }

        return findings;
    }
}
