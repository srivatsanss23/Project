package com.example.spamdetector;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRecordRepository extends JpaRepository<ScanRecord, Long> {

    List<ScanRecord> findTop25ByOrderByScannedAtDesc();

    long countByPrediction(String prediction);

    @Query("SELECT COALESCE(AVG(s.score), 0) FROM ScanRecord s")
    Double getAverageScore();

    @Query("SELECT COALESCE(AVG(s.executionTimeMs), 0) FROM ScanRecord s")
    Double getAverageExecutionTimeMs();
}
