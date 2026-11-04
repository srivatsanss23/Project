package com.example.spamdetector;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CustomRuleRepository extends JpaRepository<CustomRule, Long> {
    List<CustomRule> findByRuleType(String ruleType);
}
