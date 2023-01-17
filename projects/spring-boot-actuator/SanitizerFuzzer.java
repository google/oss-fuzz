import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueMedium;
import org.springframework.boot.actuate.endpoint.SanitizableData;
import org.springframework.boot.actuate.endpoint.Sanitizer;

public class SanitizerFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String key = data.consumeString(50);
        String value = data.consumeRemainingAsString();

        if (value.isEmpty() || key.isEmpty()) {
            return;
        }

        Sanitizer sanitizer = new Sanitizer();
        String result = (String) sanitizer.sanitize(new SanitizableData(null, key, value), false);
        if (!result.equals("******")) {
            throw new FuzzerSecurityIssueMedium("Value not sanitized. key: " + key + " value:" + value + " result:" + result);
        }
    } 
}