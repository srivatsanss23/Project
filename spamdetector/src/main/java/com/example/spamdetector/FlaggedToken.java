package com.example.spamdetector;

public class FlaggedToken {
    private String token;
    private String category;
    private int startIndex;
    private int endIndex;

    public FlaggedToken() {}

    public FlaggedToken(String token, String category, int startIndex, int endIndex) {
        this.token = token;
        this.category = category;
        this.startIndex = startIndex;
        this.endIndex = endIndex;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public int getStartIndex() {
        return startIndex;
    }

    public void setStartIndex(int startIndex) {
        this.startIndex = startIndex;
    }

    public int getEndIndex() {
        return endIndex;
    }

    public void setEndIndex(int endIndex) {
        this.endIndex = endIndex;
    }
}
