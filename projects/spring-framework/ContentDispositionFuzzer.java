import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.springframework.http.ContentDisposition;
import org.springframework.util.Assert;

public class ContentDispositionFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String value = data.consumeRemainingAsString();
        try {
            ContentDisposition content = ContentDisposition.parse(value);
        } catch (IllegalArgumentException e) {}
    }
}
