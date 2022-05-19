import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import com.google.common.net.MediaType;
import java.lang.IllegalArgumentException;

public class MediaTypeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
	    String value = data.consumeRemainingAsString();

        try { 
            MediaType.create(value, value);
            MediaType.parse(value).type();
            MediaType.create(value, value).withParameter(value, value);
        } catch (IllegalArgumentException e) { }
	} 
}