import com.code_intelligence.jazzer.api.FuzzedDataProvider;
<<<<<<< HEAD
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
=======
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
>>>>>>> 0d4261be (Initial integration)
import org.springframework.boot.actuate.endpoint.Sanitizer;

public class SanitizerFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String key = data.consumeString(50);
        String value = data.consumeRemainingAsString();

<<<<<<< HEAD
        if (value.isEmpty() || key.isEmpty()) {
=======
        if (value.isEmpty()) {
>>>>>>> 0d4261be (Initial integration)
            return;
        }

        Sanitizer sanitizer = new Sanitizer();
        sanitizer.keysToSanitize(key);
        String result = (String) sanitizer.sanitize(key, value);
<<<<<<< HEAD
        if (!result.equals("******")) {
            throw new FuzzerSecurityIssueMedium("Value not sanitized. key: " + key + " value:" + value + " result:" + result);
=======
        if (result != "******") {
            throw new FuzzerSecurityIssueHigh("Value not sanitized. key: " + key + " value:" + value + " result:" + result);
>>>>>>> 0d4261be (Initial integration)
        }
    } 
}
