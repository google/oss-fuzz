import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.lang.CharSequence;

import org.springframework.security.crypto.codec.Utf8;

public class Utf8Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        final String initialString = data.consumeString(Integer.MAX_VALUE);
        final byte[] encodedBytes;

        try {
            encodedBytes = Utf8.encode(initialString);

            if (! initialString.equals(Utf8.decode(encodedBytes))) {
                throw new FuzzerSecurityIssueLow("Utf8 value has changed during encoding and decoding");
            }
        } catch (IllegalArgumentException err) {
            // ignore expected exceptions
        }
    }
}
