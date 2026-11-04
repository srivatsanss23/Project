package com.example.spamdetector;

public class FeedbackRequest {
    private String message;
    private String predictedLabel;
    private String feedbackType; // "CONFIRMED", "FALSE_POSITIVE", "FALSE_NEGATIVE"
    private String notes;

    public FeedbackRequest() {}

    public FeedbackRequest(String message, String predictedLabel, String feedbackType, String notes) {
        this.message = message;
        this.predictedLabel = predictedLabel;
        this.feedbackType = feedbackType;
        this.notes = notes;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getPredictedLabel() {
        return predictedLabel;
    }

    public void setPredictedLabel(String predictedLabel) {
        this.predictedLabel = predictedLabel;
    }

    public String getFeedbackType() {
        return feedbackType;
    }

    public void setFeedbackType(String feedbackType) {
        this.feedbackType = feedbackType;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}
