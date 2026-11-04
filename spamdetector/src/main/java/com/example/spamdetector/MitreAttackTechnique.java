package com.example.spamdetector;

import java.util.List;

public record MitreAttackTechnique(
        String id,            // e.g. "T1566.002"
        String name,          // e.g. "Spearphishing Link"
        String tactic,        // e.g. "Initial Access"
        String description,
        String detectionConfidence // "HIGH", "MEDIUM", "LOW"
) {}
