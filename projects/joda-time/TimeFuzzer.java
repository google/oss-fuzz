import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import org.joda.time.*;

public class TimeFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        try {
            DateTimeZone.forID(data.consumeRemainingAsString());
        } catch (IllegalArgumentException e) {}

        return;
    }
}

