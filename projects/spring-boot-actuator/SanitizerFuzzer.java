import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import org.springframework.boot.actuate.endpoint.Sanitizer;

public class SanitizerFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String key = data.consumeString(50);
        String value = data.consumeRemainingAsString();

        if (value.isEmpty()) {
            return;
        }

        Sanitizer sanitizer = new Sanitizer();
        sanitizer.keysToSanitize(key);
        String result = (String) sanitizer.sanitize(key, value);
        if (result != "******") {
            throw new FuzzerSecurityIssueHigh("Value not sanitized. key: " + key + " value:" + value + " result:" + result);
        }
    } 
}