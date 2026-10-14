package com.example.spamdetector;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import java.util.Map;
@RestController 
@CrossOrigin(origins="*")
@RequestMapping("/api")
public class SpamController {
    private final SpamService spamService;

    public SpamController(SpamService spamService) {
        this.spamService = spamService;
    }

    @PostMapping ("/classify")
    public Map<String,Object> classifyMessage(@RequestBody SpamRequest request){
        return spamService.classify(request.getMessage());
    }
}
