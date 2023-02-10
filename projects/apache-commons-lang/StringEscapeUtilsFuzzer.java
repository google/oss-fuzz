import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import org.apache.commons.lang3.StringEscapeUtils;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueHigh;
import java.util.regex.*;

public class StringEscapeUtilsFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Pattern escapeAllQuotePattern = Pattern.compile("[^\\\\]\\'|[^\\\\]\\\"");
        Pattern escapeDoubleQuotePattern = Pattern.compile("[^\\\\]\\\"");
        Pattern escapeCsvPattern = Pattern.compile(Pattern.quote("[^\\\"],|,[^\\\"]|[^\\\"]\\n|\\n[^\\\"]"));

        String safeJson = StringEscapeUtils.escapeJson(data.consumeString(50));
        assert !escapeDoubleQuotePattern.matcher(safeJson).matches() : new FuzzerSecurityIssueHigh("JSON double quote injection");

        String safeJava = StringEscapeUtils.escapeJava(data.consumeString(50));
        assert !escapeDoubleQuotePattern.matcher(safeJava).matches() : new FuzzerSecurityIssueHigh("Java double quote injection");

        String safeEcma = StringEscapeUtils.escapeEcmaScript(data.consumeString(50));
        assert !escapeAllQuotePattern.matcher(safeEcma).matches() : new FuzzerSecurityIssueHigh("Ecma quote injection");

        String safeCsv = StringEscapeUtils.escapeCsv(data.consumeString(50));
        assert !escapeCsvPattern.matcher(safeCsv).matches() : new FuzzerSecurityIssueHigh("CSV injection");
    }
}