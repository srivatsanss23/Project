package com.example.spamdetector;
import org.springframework.stereotype.Service;
import java.util.*;   
import java.util.regex.Pattern;
@Service 
public class SpamService {
    private static final Set<String> SPAM_KEYWORDS=Set.of("win", "winner","won", "prize", "free", "click", "buy now", "subscribe", "limited time offer","cash","credit","password","bank");
    private static final Pattern URL_PATTERN=Pattern.compile("https?://\\S+|www\\.\\S+");
    private static final Pattern Currency_PATTERN=Pattern.compile("[$€£¥₹]");
    public Map<String,Object> classify(String rawText){
        if(rawText==null||rawText.trim().isEmpty()){
            return Map.of("prediction","UNKOWN","score",0,"reasons",List.of("Empty message provided"));
        }
        int score=0;
        List<String> reasons=new ArrayList<>();
        String lowerCaseText=rawText.toLowerCase();
        List<String> detectedSpamKeywords=new ArrayList<>();
        for(String word:SPAM_KEYWORDS){
            if(lowerCaseText.contains(word)){
                detectedSpamKeywords.add(word);
            }
        }
        if(!detectedSpamKeywords.isEmpty()){
            score+=detectedSpamKeywords.size();
            reasons.add("Detected spam keywords: "+String.join(", ",detectedSpamKeywords));
        }
        if(URL_PATTERN.matcher(rawText).find()){
            score+=25;
            reasons.add("Detected URL in the message");
        }
        if(Currency_PATTERN.matcher(rawText).find()){
            score+=15;
            reasons.add("Detected currency symbols in the message");
        }
        long upperLetters=rawText.chars().filter(Character::isUpperCase).count();
        long totalLetters=rawText.chars().filter(Character::isLetter).count();
        if(totalLetters>8&&((double)upperLetters/totalLetters)>0.4){
            score+=20;
            reasons.add("Excessive use of uppercase letters");
        }
        int finalScore=Math.min(score,100);
        String verdict=(finalScore>=40)?"SPAM":"LEGITIMATE";
        return Map.of(
            "prediction",verdict,
            "score",finalScore,
            "reasons",reasons
        );
    }
}
