package com.example.spamdetector;

public class SpamRequest {
    private String message;
    public SpamRequest() {}
    public String getMessage(){
        return message;
    }
    public void setMessage(String message){
        this.message=message;
    }
}
