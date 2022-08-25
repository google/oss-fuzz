import com.code_intelligence.jazzer.api.FuzzerSecurityIssueLow;

import java.lang.CharSequence;

import org.springframework.security.crypto.codec.Hex;

public class HexFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        final byte[] initialByteArray = data;
        final char[] encodedChars;

        try {
            encodedChars = Hex.encode(initialByteArray);

            if (! initialByteArray.toString().equals(Hex.decode(encodedChars.toString()))) {
                throw new FuzzerSecurityIssueLow("Hex value has changed during encoding and decoding");
            }
        } catch (IllegalArgumentException err) {
            // ignore expected exceptions
        }
    }
}
