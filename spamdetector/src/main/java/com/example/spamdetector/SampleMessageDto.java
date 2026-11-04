package com.example.spamdetector;

public class SampleMessageDto {
    private String id;
    private String title;
    private String category;
    private String content;
    private String expectedVerdict;

    public SampleMessageDto() {}

    public SampleMessageDto(String id, String title, String category, String content, String expectedVerdict) {
        this.id = id;
        this.title = title;
        this.category = category;
        this.content = content;
        this.expectedVerdict = expectedVerdict;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public String getExpectedVerdict() {
        return expectedVerdict;
    }

    public void setExpectedVerdict(String expectedVerdict) {
        this.expectedVerdict = expectedVerdict;
    }
}
