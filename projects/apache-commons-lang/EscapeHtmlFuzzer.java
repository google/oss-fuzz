import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.commons.lang3.StringEscapeUtils;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.util.regex.*;

public class EscapeHtmlFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        String safeHtml = StringEscapeUtils.escapeHtml3(data.consumeString(50));
        assert !safeHtml.contains("</script") 
            : new FuzzerSecurityIssueHigh("XSS Injection: Output contains </script");
        
        safeHtml = StringEscapeUtils.escapeHtml4(data.consumeString(50));
        assert !safeHtml.contains("</script") 
            : new FuzzerSecurityIssueHigh("XSS Injection: Output contains </script");
    }
}