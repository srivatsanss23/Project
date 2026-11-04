package com.example.spamdetector;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class SpamRequest {

    @NotBlank(message = "Message cannot be empty")
    @Size(max = 10000, message = "Message must not exceed 10,000 characters")
    private String message;

    public SpamRequest() {}

    public SpamRequest(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
